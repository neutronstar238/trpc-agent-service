#!/usr/bin/env python3
"""Independent HTTPS-probe backend for the live Feishu/WeCom gate.

The public HTTPS terminator is intentionally kept outside this process (the
deployment template uses nginx).  This process owns the Ed25519 signing key,
reads the existing yqzl secret files, and invokes an operator-supplied
provider runner.  It never manufactures provider observations: a missing or
invalid runner result is returned as a signed ``not_run`` response.

The runner receives only metadata and secret *file paths* through its
environment/stdin.  Its stdout must be one strict JSON object containing a
``provider_evidence`` object.  The evidence is validated and sanitized with
the same contract used by ``scripts.im_online_gate`` before it is signed.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Direct invocation from the yqzl checkout remains supported.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.im_online_gate import (
    CHANNEL_ACCOUNT_VARIABLE,
    REQUIRED_CASES,
    _validate_provider_evidence,
)
from scripts.im_online_gate import (
    _fingerprint as _gate_fingerprint,
)

ROOT = Path(__file__).resolve().parents[2]
PROBE_PATH = "/probe"
HEALTH_LIVE_PATH = "/health/live"
HEALTH_READY_PATH = "/health/ready"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
MAX_REQUEST_BYTES = 64 * 1024
MAX_RUNNER_OUTPUT_BYTES = 256 * 1024
MAX_RUNNER_TIMEOUT_SECONDS = 15 * 60
NONCE_CACHE_CAPACITY = 4096
NONCE_CACHE_TTL = timedelta(hours=24)
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$")
SAFE_CODE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")
IMAGE_RE = re.compile(r"^sha256:[0-9a-fA-F]{64}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
PLACEHOLDER_MARKERS = ("replace-with", "change-me", "placeholder", "synthetic")
REQUEST_FIELDS = frozenset(
    {
        "run_id",
        "channel",
        "nonce",
        "cases",
        "expected_image_digest",
        "credential_fingerprints",
        "probe_identity_sha256",
        "account_fingerprint",
    }
)


class ProbeConfigurationError(RuntimeError):
    """Raised without embedding secret values or secret file contents."""


class ProbeRequestError(ValueError):
    """Raised for an invalid or unauthenticated probe request."""


def _strict_json(raw: str | bytes) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant {value} is forbidden")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r} is forbidden")
            result[key] = value
        return result

    return json.loads(
        raw,
        parse_constant=reject_constant,
        object_pairs_hook=reject_duplicate_keys,
    )


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _safe_hash(value: str, *, label: str) -> str:
    if not HASH_RE.fullmatch(value) or value.lower() in {"0" * 64, "f" * 64}:
        raise ProbeConfigurationError(f"{label} must be a non-zero SHA-256 value")
    return value.lower()


def _safe_image_digest(value: str) -> str:
    if not IMAGE_RE.fullmatch(value) or value.lower() in {
        "sha256:" + "0" * 64,
        "sha256:" + "f" * 64,
    }:
        raise ProbeConfigurationError("probe image digest must be a non-zero sha256 digest")
    return value.lower()


def _safe_id(value: object, *, label: str, pattern: re.Pattern[str] = SAFE_ID_RE) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ProbeRequestError(f"{label} is invalid")
    return value


def _safe_config_id(value: str, *, label: str) -> str:
    if SAFE_CODE_RE.fullmatch(value) is None or any(
        marker in value.lower() for marker in PLACEHOLDER_MARKERS
    ):
        raise ProbeConfigurationError(f"{label} is invalid")
    return value


def _safe_path(
    value: str,
    *,
    label: str,
    must_exist: bool = True,
    private: bool = False,
) -> Path:
    path = Path(value)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or any(parent.is_symlink() for parent in path.parents)
    ):
        raise ProbeConfigurationError(f"{label} must be an absolute non-symlink path")
    try:
        resolved = path.resolve(strict=must_exist)
    except (OSError, RuntimeError) as error:
        raise ProbeConfigurationError(f"{label} is unavailable") from error
    if must_exist:
        try:
            mode = resolved.stat().st_mode
        except OSError as error:
            raise ProbeConfigurationError(f"{label} is unavailable") from error
        if not stat.S_ISREG(mode) or mode & 0o022:
            raise ProbeConfigurationError(f"{label} must be a non-writable regular file")
        if private and mode & 0o027:
            raise ProbeConfigurationError(f"{label} must not be readable by other users")
    return resolved


def _read_private_seed(path: Path) -> Ed25519PrivateKey:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ProbeConfigurationError("probe signing key is unavailable") from error
    if len(raw) > 4096:
        raise ProbeConfigurationError("probe signing key is too large")
    try:
        seed = base64.b64decode(b"".join(raw.split()), validate=True)
    except (binascii.Error, ValueError) as error:
        raise ProbeConfigurationError("probe signing key is not valid base64") from error
    if len(seed) != 32 or seed in {b"\x00" * 32, b"\xff" * 32}:
        raise ProbeConfigurationError("probe signing key must encode one non-zero 32-byte seed")
    return Ed25519PrivateKey.from_private_bytes(seed)


def _read_secret(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ProbeConfigurationError("provider secret file is unavailable") from error
    if not raw or len(raw) > 4096:
        raise ProbeConfigurationError("provider secret file size is invalid")
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ProbeConfigurationError("provider secret file is not UTF-8") from error
    if not value or any(ord(character) < 33 or ord(character) > 0x7E for character in value):
        raise ProbeConfigurationError("provider secret file contains invalid characters")
    return value


def _fingerprint(value: str, *, label: str) -> str:
    return _gate_fingerprint(value, label=label)


@dataclass(frozen=True)
class ProbeConfig:
    bind_host: str
    port: int
    runner: Path | None
    runner_timeout_seconds: float
    driver_timeout_seconds: float
    signing_key_path: Path
    key_id: str
    image_digest: str
    identity_sha256: str
    account_ids: Mapping[str, str]
    credential_paths: Mapping[str, Mapping[str, Path]]
    runner_secret_paths: Mapping[str, Mapping[str, Path]]
    driver_paths: Mapping[str, Path]

    @classmethod
    def from_environment(cls) -> ProbeConfig:
        host = os.getenv("TRPC_IM_PROBE_BIND_HOST", "127.0.0.1").strip()
        if not host or any(character.isspace() or character in "\r\n\x00" for character in host):
            raise ProbeConfigurationError("TRPC_IM_PROBE_BIND_HOST is invalid")
        if host not in LOOPBACK_HOSTS:
            raise ProbeConfigurationError(
                "TRPC_IM_PROBE_BIND_HOST must be a loopback address; terminate HTTPS separately"
            )
        try:
            port = int(os.getenv("TRPC_IM_PROBE_PORT", "8750"))
        except ValueError as error:
            raise ProbeConfigurationError("TRPC_IM_PROBE_PORT is invalid") from error
        if not 1 <= port <= 65535:
            raise ProbeConfigurationError("TRPC_IM_PROBE_PORT is outside the valid range")
        try:
            timeout = float(os.getenv("TRPC_IM_PROBE_RUNNER_TIMEOUT_SECONDS", "180"))
        except ValueError as error:
            raise ProbeConfigurationError(
                "TRPC_IM_PROBE_RUNNER_TIMEOUT_SECONDS is invalid"
            ) from error
        if not 0.001 <= timeout <= MAX_RUNNER_TIMEOUT_SECONDS:
            raise ProbeConfigurationError(
                "TRPC_IM_PROBE_RUNNER_TIMEOUT_SECONDS is outside the safe range"
            )
        try:
            driver_timeout = float(os.getenv("TRPC_IM_PROBE_DRIVER_TIMEOUT_SECONDS", str(timeout)))
        except ValueError as error:
            raise ProbeConfigurationError(
                "TRPC_IM_PROBE_DRIVER_TIMEOUT_SECONDS is invalid"
            ) from error
        if not 0.001 <= driver_timeout <= MAX_RUNNER_TIMEOUT_SECONDS:
            raise ProbeConfigurationError(
                "TRPC_IM_PROBE_DRIVER_TIMEOUT_SECONDS is outside the safe range"
            )

        key_path = _safe_path(
            os.getenv("TRPC_IM_PROBE_SIGNING_KEY_FILE", ""),
            label="TRPC_IM_PROBE_SIGNING_KEY_FILE",
            private=True,
        )
        _read_private_seed(key_path)
        key_id = _safe_config_id(
            os.getenv("TRPC_IM_PROBE_KEY_ID", ""), label="TRPC_IM_PROBE_KEY_ID"
        )
        image_digest = _safe_image_digest(os.getenv("TRPC_IM_PROBE_IMAGE_DIGEST", ""))
        identity_sha256 = _safe_hash(
            os.getenv("TRPC_IM_PROBE_IDENTITY_SHA256", ""), label="TRPC_IM_PROBE_IDENTITY_SHA256"
        )

        account_ids = {
            "feishu": os.getenv("TRPC_IM_PROBE_FEISHU_APP_ID", "").strip(),
            "wecom": os.getenv("TRPC_IM_PROBE_WECOM_BOT_ID", "").strip(),
        }
        if re.fullmatch(r"cli_[A-Za-z0-9]+", account_ids["feishu"]) is None or any(
            marker in account_ids["feishu"].lower() for marker in PLACEHOLDER_MARKERS
        ):
            raise ProbeConfigurationError("TRPC_IM_PROBE_FEISHU_APP_ID is invalid")
        if SAFE_ID_RE.fullmatch(account_ids["wecom"]) is None or any(
            marker in account_ids["wecom"].lower() for marker in PLACEHOLDER_MARKERS
        ):
            raise ProbeConfigurationError("TRPC_IM_PROBE_WECOM_BOT_ID is invalid")

        required_paths = {
            "feishu": {
                "FEISHU_APP_SECRET": "TRPC_IM_PROBE_FEISHU_APP_SECRET_FILE",
                "FEISHU_VERIFICATION_TOKEN": "TRPC_IM_PROBE_FEISHU_VERIFICATION_TOKEN_FILE",
                "FEISHU_ENCRYPT_KEY": "TRPC_IM_PROBE_FEISHU_ENCRYPT_KEY_FILE",
            },
            "wecom": {"WECOM_BOT_SECRET": "TRPC_IM_PROBE_WECOM_BOT_SECRET_FILE"},
        }
        credential_paths: dict[str, dict[str, Path]] = {}
        for channel, variables in required_paths.items():
            credential_paths[channel] = {
                variable: _safe_path(os.getenv(env_name, ""), label=env_name, private=True)
                for variable, env_name in variables.items()
            }

        runner_text = os.getenv("TRPC_IM_PROBE_RUNNER", "").strip()
        runner = None
        driver_paths: dict[str, Path] = {}
        if runner_text:
            runner = _safe_path(runner_text, label="TRPC_IM_PROBE_RUNNER")
            try:
                runner.relative_to(ROOT.resolve())
            except ValueError:
                pass
            else:
                raise ProbeConfigurationError(
                    "TRPC_IM_PROBE_RUNNER must be installed outside the application checkout"
                )
            try:
                if not os.access(runner, os.X_OK):
                    raise ProbeConfigurationError("TRPC_IM_PROBE_RUNNER is not executable")
            except OSError as error:
                raise ProbeConfigurationError("TRPC_IM_PROBE_RUNNER is unavailable") from error
            for channel in ("feishu", "wecom"):
                env_name = f"TRPC_IM_PROBE_{channel.upper()}_DRIVER"
                driver = _safe_path(os.getenv(env_name, ""), label=env_name)
                try:
                    if not os.access(driver, os.X_OK):
                        raise ProbeConfigurationError(f"{env_name} is not executable")
                except OSError as error:
                    raise ProbeConfigurationError(f"{env_name} is unavailable") from error
                driver_paths[channel] = driver

        runner_secret_paths: dict[str, dict[str, Path]] = {"feishu": {}, "wecom": {}}
        optional_paths = {
            "feishu": {
                "TRPC_IM_PROBE_FEISHU_OLD_APP_SECRET_FILE": "FEISHU_OLD_APP_SECRET_FILE",
                "TRPC_IM_PROBE_FEISHU_NEW_APP_SECRET_FILE": "FEISHU_NEW_APP_SECRET_FILE",
            },
            "wecom": {
                "TRPC_IM_PROBE_WECOM_OLD_BOT_SECRET_FILE": "WECOM_OLD_BOT_SECRET_FILE",
                "TRPC_IM_PROBE_WECOM_NEW_BOT_SECRET_FILE": "WECOM_NEW_BOT_SECRET_FILE",
            },
        }
        for channel, variables in optional_paths.items():
            for env_name, runner_name in variables.items():
                value = os.getenv(env_name, "").strip()
                if value:
                    runner_secret_paths[channel][runner_name] = _safe_path(
                        value, label=env_name, private=True
                    )

        return cls(
            bind_host=host,
            port=port,
            runner=runner,
            runner_timeout_seconds=timeout,
            driver_timeout_seconds=driver_timeout,
            signing_key_path=key_path,
            key_id=key_id,
            image_digest=image_digest,
            identity_sha256=identity_sha256,
            account_ids=account_ids,
            credential_paths=credential_paths,
            runner_secret_paths=runner_secret_paths,
            driver_paths=driver_paths,
        )


def _credential_fingerprints(config: ProbeConfig, channel: str) -> dict[str, str]:
    account_variable = CHANNEL_ACCOUNT_VARIABLE[channel]
    values: dict[str, str] = {account_variable: config.account_ids[channel]}
    for variable, path in config.credential_paths[channel].items():
        values[variable] = _read_secret(path)
    return {variable: _fingerprint(value, label=variable) for variable, value in values.items()}


def _validate_request(
    payload: object,
    config: ProbeConfig,
) -> tuple[dict[str, Any], dict[str, str]]:
    if not isinstance(payload, dict) or set(payload) != REQUEST_FIELDS:
        raise ProbeRequestError("probe request schema is invalid")
    channel = payload.get("channel")
    if channel not in {"feishu", "wecom"}:
        raise ProbeRequestError("probe channel is invalid")
    channel = cast(str, channel)
    run_id = _safe_id(payload.get("run_id"), label="run_id")
    nonce = _safe_id(payload.get("nonce"), label="nonce", pattern=NONCE_RE)
    expected_image = payload.get("expected_image_digest")
    if expected_image != config.image_digest:
        raise ProbeRequestError("probe image digest does not match this deployment")
    identity = payload.get("probe_identity_sha256")
    if identity != config.identity_sha256:
        raise ProbeRequestError("probe identity does not match this deployment")
    cases = payload.get("cases")
    if cases != list(REQUIRED_CASES):
        raise ProbeRequestError("probe case set is not the required contract")
    expected_fingerprints = _credential_fingerprints(config, channel)
    observed_fingerprints = payload.get("credential_fingerprints")
    if (
        not isinstance(observed_fingerprints, dict)
        or observed_fingerprints != expected_fingerprints
    ):
        raise ProbeRequestError("credential fingerprints do not match this deployment")
    expected_account = _fingerprint(
        config.account_ids[channel], label=CHANNEL_ACCOUNT_VARIABLE[channel]
    )
    if payload.get("account_fingerprint") != expected_account:
        raise ProbeRequestError("account fingerprint does not match this deployment")
    return {
        "run_id": run_id,
        "channel": channel,
        "nonce": nonce,
        "expected_image_digest": config.image_digest,
        "probe_identity_sha256": config.identity_sha256,
    }, expected_fingerprints


def _runner_environment(
    config: ProbeConfig,
    request: Mapping[str, Any],
) -> dict[str, str]:
    channel = str(request["channel"])
    account_variable = CHANNEL_ACCOUNT_VARIABLE[channel]
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "LANG": "C.UTF-8",
        "TRPC_IM_PROBE_APPLICATION_ROOT": str(ROOT),
        "TRPC_IM_PROBE_CHANNEL": channel,
        "TRPC_IM_PROBE_RUN_ID": str(request["run_id"]),
        "TRPC_IM_PROBE_RUN_NONCE": str(request["nonce"]),
        "TRPC_IM_PROBE_EXPECTED_IMAGE_DIGEST": str(request["expected_image_digest"]),
        "TRPC_IM_PROBE_DRIVER_TIMEOUT_SECONDS": str(config.driver_timeout_seconds),
        f"TRPC_IM_PROBE_{account_variable}": config.account_ids[channel],
        f"TRPC_IM_PROBE_{channel.upper()}_DRIVER": str(config.driver_paths[channel]),
    }
    for variable, path in config.credential_paths[channel].items():
        variable_name = variable.removeprefix(channel.upper() + "_")
        environment[f"TRPC_IM_PROBE_{channel.upper()}_{variable_name}_FILE"] = str(path)
    for runner_name, path in config.runner_secret_paths[channel].items():
        environment[f"TRPC_IM_PROBE_{runner_name}"] = str(path)
    return environment


def _run_provider_runner(
    config: ProbeConfig,
    request: Mapping[str, Any],
) -> dict[str, Any] | None:
    if config.runner is None:
        return None
    runner_input = json.dumps(
        {
            "schema_version": 1,
            "channel": request["channel"],
            "run_id": request["run_id"],
            "run_nonce": request["nonce"],
            "expected_image_digest": request["expected_image_digest"],
            "cases": list(REQUIRED_CASES),
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return _run_bounded_json_process(
        [str(config.runner)],
        input_bytes=runner_input.encode("utf-8"),
        timeout=config.runner_timeout_seconds,
        environment=_runner_environment(config, request),
    )


def _run_bounded_json_process(
    command: Sequence[str],
    *,
    input_bytes: bytes | None,
    timeout: float,
    environment: Mapping[str, str],
) -> dict[str, Any] | None:
    try:
        with tempfile.TemporaryFile(mode="w+b") as runner_output:
            process = subprocess.Popen(  # noqa: S603 - fixed executable, no shell
                list(command),
                stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                stdout=runner_output,
                stderr=subprocess.DEVNULL,
                env=dict(environment),
            )
            try:
                process.communicate(input=input_bytes, timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                return None
            runner_output.seek(0)
            raw_output = runner_output.read(MAX_RUNNER_OUTPUT_BYTES + 1)
    except OSError:
        return None
    if process.returncode != 0 or len(raw_output) > MAX_RUNNER_OUTPUT_BYTES:
        return None
    try:
        decoded = raw_output.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        result = _strict_json(decoded)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        return None
    return result if isinstance(result, dict) else None


def _runner_ready(config: ProbeConfig, channel: str) -> bool:
    if config.runner is None or channel not in config.driver_paths:
        return False
    request = {
        "channel": channel,
        "run_id": "probe-readiness-check",
        "nonce": "probe_readiness_check_0001",
        "expected_image_digest": config.image_digest,
    }
    result = _run_bounded_json_process(
        [str(config.runner), "--check", "--channel", channel],
        input_bytes=None,
        timeout=min(config.runner_timeout_seconds, 10.0),
        environment=_runner_environment(config, request),
    )
    return result == {"status": "ready"}


def _runtime_attestation(config: ProbeConfig, request: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": "pass",
        "run_nonce": request["nonce"],
        "image_digest": request["expected_image_digest"],
        "identity_fingerprint": config.identity_sha256,
    }


def _failure_cases() -> dict[str, dict[str, str]]:
    return {case: {"status": "not_run"} for case in REQUIRED_CASES}


def _signed_response(config: ProbeConfig, payload: Mapping[str, Any]) -> dict[str, Any]:
    private_key = _read_private_seed(config.signing_key_path)
    signature = private_key.sign(_canonical_json(payload))
    result = dict(payload)
    result["signature_attestation"] = {
        "algorithm": "ed25519",
        "key_id": config.key_id,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return result


class ProbeService:
    """Single-request-at-a-time probe service with one-shot run/channel keys."""

    def __init__(self, config: ProbeConfig) -> None:
        self.config = config
        self._seen: OrderedDict[tuple[str, str], datetime] = OrderedDict()
        self._seen_lock = Lock()
        self._runner_lock = Lock()

    def _consume_nonce(self, key: tuple[str, str]) -> None:
        now = datetime.now(UTC)
        cutoff = now - NONCE_CACHE_TTL
        with self._seen_lock:
            while self._seen:
                oldest_key, oldest_at = next(iter(self._seen.items()))
                if oldest_at >= cutoff:
                    break
                self._seen.pop(oldest_key)
            if key in self._seen:
                raise ProbeRequestError("probe nonce was already consumed for this channel")
            self._seen[key] = now
            while len(self._seen) > NONCE_CACHE_CAPACITY:
                self._seen.popitem(last=False)

    def ready(self) -> bool:
        if self.config.runner is None:
            return False
        paths_ready = len(self.config.driver_paths) == 2 and all(
            path.exists()
            for paths in (*self.config.credential_paths.values(), self.config.driver_paths)
            for path in paths.values()
        )
        return paths_ready and all(
            _runner_ready(self.config, channel) for channel in ("feishu", "wecom")
        )

    def handle(self, payload: object) -> dict[str, Any]:
        request, credential_fingerprints = _validate_request(payload, self.config)
        key = (str(request["channel"]), str(request["nonce"]))
        self._consume_nonce(key)

        started = datetime.now(UTC)
        response: dict[str, Any] = {
            "schema_version": 1,
            "runtime": _runtime_attestation(self.config, request),
            "credential_attestation": {
                "status": "pass",
                "run_nonce": request["nonce"],
                "fingerprints": credential_fingerprints,
            },
            "cases": _failure_cases(),
        }
        with self._runner_lock:
            runner_result = _run_provider_runner(self.config, request)
        provider_evidence = runner_result.get("provider_evidence") if runner_result else None
        if isinstance(provider_evidence, dict):
            candidate = {
                "credential_attestation": response["credential_attestation"],
                "provider_evidence": provider_evidence,
            }
            sanitized, errors = _validate_provider_evidence(
                str(request["channel"]),
                candidate,
                run_nonce=str(request["nonce"]),
                credential_fingerprints=credential_fingerprints,
                run_started_at=started,
            )
            if sanitized is not None and not errors:
                response["provider_evidence"] = sanitized
                response["cases"] = {case: {"status": "pass"} for case in REQUIRED_CASES}
            else:
                response["error_code"] = "provider_evidence_invalid"
        elif self.config.runner is None:
            response["error_code"] = "provider_runner_unconfigured"
        else:
            response["error_code"] = "provider_runner_failed"
        return _signed_response(self.config, response)


class _ProbeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], service: ProbeService) -> None:
        super().__init__(address, _ProbeRequestHandler)
        self.service = service


class _ProbeRequestHandler(BaseHTTPRequestHandler):
    server: _ProbeHTTPServer

    def log_message(self, _format: str, *_args: object) -> None:
        # Never log request bodies, run IDs, provider IDs, or response payloads.
        return

    def _write_json(self, status: int, payload: Mapping[str, Any]) -> None:
        body = json.dumps(
            payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == HEALTH_LIVE_PATH:
            self._write_json(200, {"status": "pass"})
        elif self.path == HEALTH_READY_PATH:
            ready = self.server.service.ready()
            self._write_json(200 if ready else 503, {"status": "pass" if ready else "not_ready"})
        else:
            self._write_json(404, {"status": "not_found"})

    def do_POST(self) -> None:
        if self.path != PROBE_PATH:
            self._write_json(404, {"status": "not_found"})
            return
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length or "-1")
        except ValueError:
            length = -1
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._write_json(413, {"status": "not_run", "reason": "request_size_invalid"})
            return
        try:
            payload = _strict_json(self.rfile.read(length))
            result = self.server.service.handle(payload)
        except (ProbeRequestError, ProbeConfigurationError, ValueError, json.JSONDecodeError):
            self._write_json(400, {"status": "not_run", "reason": "request_invalid"})
            return
        except Exception:
            self._write_json(500, {"status": "not_run", "reason": "probe_internal_error"})
            return
        self._write_json(200, result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate configuration and exit")
    args = parser.parse_args()
    try:
        config = ProbeConfig.from_environment()
    except ProbeConfigurationError as error:
        print(f"probe configuration failed: {error}", file=sys.stderr)
        return 2
    service = ProbeService(config)
    if args.check:
        return 0 if service.ready() else 3
    server = _ProbeHTTPServer((config.bind_host, config.port), service)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
