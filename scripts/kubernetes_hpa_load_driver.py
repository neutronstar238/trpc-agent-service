#!/usr/bin/env python3
"""Create and remove one bounded Kubernetes Job for the HPA runtime gate.

The gate deliberately supplies a dedicated kubeconfig and a distinct context.
This process is the only component allowed to create the short-lived load Job;
it never reports HPA numbers.  The parent gate re-reads the Job through its
administrative API client and treats the JSON emitted here as an identifier
hint only.

The image and command are explicit operator inputs.  The command must be a
JSON array (not a shell string) and must implement the application-specific
bounded backlog operation in the image.  ``load`` waits for a successful,
single-completion Job; ``clear`` deletes that exact nonce-labelled Job.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping
from typing import Any

MAX_TIMEOUT_SECONDS = 300.0
MAX_COMMAND_ARGS = 64
MAX_COMMAND_ARG_BYTES = 512
MAX_IMAGE_BYTES = 512
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
NAMESPACE_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
IMAGE_RE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")

OWNER_LABEL = "trpc.io/hpa-gate"
OWNER_VALUE = "bounded-job-driver"
RUN_LABEL = "trpc.io/hpa-run"
PHASE_LABEL = "trpc.io/hpa-phase"
CLUSTER_LABEL = "trpc.io/hpa-cluster"


def _strict_json(value: str) -> Any:
    def duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = item
        return result

    return json.loads(
        value,
        object_pairs_hook=duplicate,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON value: {token}")
        ),
    )


def _error(message: str) -> dict[str, Any]:
    return {"schema_version": 1, "status": "fail", "reason": message}


def _emit(payload: Mapping[str, Any]) -> int:
    sys.stdout.write(json.dumps(dict(payload), separators=(",", ":"), sort_keys=True) + "\n")
    return 0 if payload.get("status") == "pass" else 1


def _timeout() -> float:
    raw = os.getenv("TRPC_K8S_HPA_DRIVER_TIMEOUT_SECONDS", "120")
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError("TRPC_K8S_HPA_DRIVER_TIMEOUT_SECONDS is invalid") from exc
    if not math.isfinite(value) or value <= 0 or value > MAX_TIMEOUT_SECONDS:
        raise ValueError("driver timeout must be in (0, 300]")
    return value


def _context() -> str | None:
    value = os.getenv("TRPC_K8S_HPA_CONTEXT", "").strip()
    if not value:
        return None
    if len(value) > 128 or any(ch.isspace() or ch in "\x00\r\n" for ch in value):
        raise ValueError("TRPC_K8S_HPA_CONTEXT is invalid")
    return value


def _configuration() -> dict[str, str | list[str]]:
    namespace = os.getenv("TRPC_K8S_HPA_NAMESPACE", "").strip()
    nonce = os.getenv("TRPC_K8S_HPA_RUN_NONCE", "").strip().lower()
    fingerprint = os.getenv("TRPC_K8S_HPA_CLUSTER_FINGERPRINT", "").strip().lower()
    phase = os.getenv("TRPC_K8S_HPA_PHASE", "").strip().lower()
    subject = os.getenv("TRPC_K8S_HPA_DRIVER_SUBJECT", "").strip()
    image = os.getenv("TRPC_K8S_HPA_DRIVER_JOB_IMAGE", "").strip()
    command_text = os.getenv("TRPC_K8S_HPA_DRIVER_JOB_COMMAND", "").strip()
    if NAMESPACE_RE.fullmatch(namespace) is None:
        raise ValueError("HPA driver namespace is invalid")
    if NONCE_RE.fullmatch(nonce) is None:
        raise ValueError("HPA driver run nonce is invalid")
    if HASH_RE.fullmatch(fingerprint) is None:
        raise ValueError("HPA driver cluster fingerprint is invalid")
    if phase not in {"load", "clear"}:
        raise ValueError("HPA driver phase is invalid")
    if not subject.startswith("system:serviceaccount:"):
        raise ValueError("HPA driver subject is invalid")
    if (
        not image
        or len(image.encode("utf-8")) > MAX_IMAGE_BYTES
        or IMAGE_RE.fullmatch(image) is None
    ):
        raise ValueError("HPA driver Job image must be an immutable sha256 reference")
    if not command_text:
        raise ValueError("HPA driver Job command is required")
    try:
        command = _strict_json(command_text)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("HPA driver Job command must be a JSON array") from exc
    if (
        not isinstance(command, list)
        or not command
        or len(command) > MAX_COMMAND_ARGS
        or any(
            not isinstance(arg, str)
            or not arg
            or len(arg.encode("utf-8")) > MAX_COMMAND_ARG_BYTES
            or any(ch in arg for ch in ("\x00", "\r", "\n"))
            for arg in command
        )
    ):
        raise ValueError("HPA driver Job command is not a bounded argument array")
    return {
        "namespace": namespace,
        "nonce": nonce,
        "fingerprint": fingerprint,
        "phase": phase,
        "subject": subject,
        "image": image,
        "command": command,
    }


def _kubectl(
    arguments: list[str], *, timeout: float, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("kubectl")
    if executable is None:
        raise RuntimeError("kubectl is not installed")
    kubeconfig = os.getenv("KUBECONFIG", "").strip()
    if not kubeconfig:
        raise RuntimeError("dedicated KUBECONFIG is missing")
    command = [executable, "--kubeconfig", kubeconfig]
    context = _context()
    if context:
        command.extend(["--context", context])
    command.extend(arguments)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "KUBECONFIG": kubeconfig,
        "HOME": os.environ.get("HOME", ""),
        "USERPROFILE": os.environ.get("USERPROFILE", ""),
    }
    # Windows kubectl needs these OS runtime variables to initialize its
    # socket/provider stack. Keep the environment explicit and add only
    # values that are actually present; no arbitrary parent secrets leak in.
    for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    try:
        return subprocess.run(  # noqa: S603 - explicit kubectl argv, no shell
            command,
            check=False,
            capture_output=True,
            text=True,
            input=input_text,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("kubectl command timed out") from exc


def _json_output(result: subprocess.CompletedProcess[str], description: str) -> Mapping[str, Any]:
    if result.returncode != 0:
        raise RuntimeError(f"{description} failed")
    try:
        value = _strict_json(result.stdout)
    except (ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{description} returned invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise RuntimeError(f"{description} returned a non-object")
    return value


def _cluster_fingerprint(timeout: float) -> str:
    payload = _json_output(
        _kubectl(["version", "--request-timeout=10s", "-o", "json"], timeout=timeout),
        "Kubernetes version",
    )
    server = payload.get("serverVersion")
    server_map = server if isinstance(server, Mapping) else {}
    identity = "|".join(
        str(server_map.get(key, "")) for key in ("gitVersion", "gitCommit", "platform")
    )
    if not identity.strip("|"):
        identity = "unknown-api-server"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _whoami(timeout: float, expected_subject: str) -> None:
    payload = _json_output(
        _kubectl(["auth", "whoami", "-o", "json"], timeout=timeout),
        "SelfSubjectReview",
    )
    status = payload.get("status")
    user_info = status.get("userInfo") if isinstance(status, Mapping) else None
    username = user_info.get("username") if isinstance(user_info, Mapping) else None
    if username != expected_subject:
        raise RuntimeError("driver kubeconfig identity does not match declared ServiceAccount")


def _job_name(nonce: str) -> str:
    return f"trpc-hpa-load-{nonce[:20]}"


def _labels(config: Mapping[str, str | list[str]]) -> dict[str, str]:
    fingerprint = str(config["fingerprint"])
    return {
        OWNER_LABEL: OWNER_VALUE,
        RUN_LABEL: str(config["nonce"]),
        PHASE_LABEL: "load",
        CLUSTER_LABEL: fingerprint[:63],
    }


def _job_manifest(config: Mapping[str, str | list[str]]) -> dict[str, Any]:
    namespace = str(config["namespace"])
    labels = _labels(config)
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": _job_name(str(config["nonce"])),
            "namespace": namespace,
            "labels": labels,
        },
        "spec": {
            "completions": 1,
            "parallelism": 1,
            "backoffLimit": 0,
            "activeDeadlineSeconds": min(300, max(30, int(_timeout()))),
            "ttlSecondsAfterFinished": 600,
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "enableServiceLinks": False,
                    "hostNetwork": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 999,
                        "runAsGroup": 999,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "bounded-load",
                            "image": str(config["image"]),
                            "imagePullPolicy": "IfNotPresent",
                            "command": list(config["command"]),
                            "env": [
                                {"name": "TRPC_HPA_RUN_NONCE", "value": str(config["nonce"])},
                                {"name": "TRPC_HPA_TARGET_NAMESPACE", "value": namespace},
                                {
                                    "name": "TRPC_HPA_CLUSTER_FINGERPRINT",
                                    "value": str(config["fingerprint"]),
                                },
                            ],
                            "resources": {
                                "requests": {"cpu": "10m", "memory": "32Mi"},
                                "limits": {"cpu": "250m", "memory": "128Mi"},
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        }
                    ],
                },
            },
        },
    }


def _get_job(config: Mapping[str, str | list[str]], timeout: float) -> Mapping[str, Any] | None:
    result = _kubectl(
        [
            "get",
            "job",
            _job_name(str(config["nonce"])),
            "--namespace",
            str(config["namespace"]),
            "-o",
            "json",
        ],
        timeout=timeout,
    )
    if result.returncode != 0:
        if "notfound" in result.stderr.lower() or "not found" in result.stderr.lower():
            return None
        raise RuntimeError("HPA load Job could not be read")
    return _json_output(result, "HPA load Job")


def _validate_job(
    payload: Mapping[str, Any], config: Mapping[str, str | list[str]]
) -> tuple[str, dict[str, str]]:
    metadata = payload.get("metadata")
    metadata_map = metadata if isinstance(metadata, Mapping) else {}
    uid = metadata_map.get("uid")
    if not isinstance(uid, str) or not uid or len(uid) > 128 or any(ch.isspace() for ch in uid):
        raise RuntimeError("HPA load Job has no safe UID")
    if (
        metadata_map.get("name") != _job_name(str(config["nonce"]))
        or metadata_map.get("namespace") != config["namespace"]
    ):
        raise RuntimeError("HPA load Job identity does not match run nonce")
    labels = metadata_map.get("labels")
    expected = _labels(config)
    if not isinstance(labels, Mapping) or any(
        labels.get(key) != value for key, value in expected.items()
    ):
        raise RuntimeError("HPA load Job labels are not bound to this run")
    return uid, expected


def _load(config: Mapping[str, str | list[str]], timeout: float) -> dict[str, Any]:
    _whoami(timeout, str(config["subject"]))
    actual_fingerprint = _cluster_fingerprint(timeout)
    if actual_fingerprint != config["fingerprint"]:
        raise RuntimeError("driver API server fingerprint does not match the gate")
    existing = _get_job(config, timeout)
    if existing is not None:
        uid, labels = _validate_job(existing, config)
        status = existing.get("status")
        status_map = status if isinstance(status, Mapping) else {}
        if status_map.get("succeeded") != 1:
            raise RuntimeError("a previous nonce-labelled HPA load Job is still active")
        return {
            "schema_version": 1,
            "status": "pass",
            "phase": "load",
            "namespace": config["namespace"],
            "run_nonce": config["nonce"],
            "cluster_fingerprint": actual_fingerprint,
            "job_name": _job_name(str(config["nonce"])),
            "job_uid": uid,
            "job_labels": labels,
            "api_observed": True,
            "job_succeeded": 1,
            "reused": True,
        }
    manifest = json.dumps(_job_manifest(config), separators=(",", ":"))
    applied = _kubectl(["create", "-f", "-"], timeout=timeout, input_text=manifest)
    if applied.returncode != 0:
        raise RuntimeError("bounded HPA load Job could not be created")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        payload = _get_job(config, min(10.0, max(1.0, deadline - time.monotonic())))
        if payload is None:
            raise RuntimeError("bounded HPA load Job disappeared before completion")
        uid, labels = _validate_job(payload, config)
        status = payload.get("status")
        status_map = status if isinstance(status, Mapping) else {}
        if status_map.get("succeeded") == 1:
            return {
                "schema_version": 1,
                "status": "pass",
                "phase": "load",
                "namespace": config["namespace"],
                "run_nonce": config["nonce"],
                "cluster_fingerprint": actual_fingerprint,
                "job_name": _job_name(str(config["nonce"])),
                "job_uid": uid,
                "job_labels": labels,
                "api_observed": True,
                "job_succeeded": 1,
                "reused": False,
            }
        if status_map.get("failed", 0) > 0:
            raise RuntimeError("bounded HPA load Job failed")
        time.sleep(min(1.0, max(0.05, deadline - time.monotonic())))
    raise RuntimeError("bounded HPA load Job did not complete before its deadline")


def _clear(config: Mapping[str, str | list[str]], timeout: float) -> dict[str, Any]:
    _whoami(timeout, str(config["subject"]))
    actual_fingerprint = _cluster_fingerprint(timeout)
    if actual_fingerprint != config["fingerprint"]:
        raise RuntimeError("driver API server fingerprint does not match the gate")
    existing = _get_job(config, timeout)
    if existing is None:
        return {
            "schema_version": 1,
            "status": "pass",
            "phase": "clear",
            "namespace": config["namespace"],
            "run_nonce": config["nonce"],
            "cluster_fingerprint": actual_fingerprint,
            "job_name": _job_name(str(config["nonce"])),
            "job_uid": None,
            "job_labels": _labels(config),
            "api_observed": True,
            "job_deleted": True,
            "already_absent": True,
        }
    uid, labels = _validate_job(existing, config)
    deleted = _kubectl(
        [
            "delete",
            "job",
            _job_name(str(config["nonce"])),
            "--namespace",
            str(config["namespace"]),
            "--ignore-not-found",
            "--wait=false",
        ],
        timeout=timeout,
    )
    if deleted.returncode != 0:
        raise RuntimeError("bounded HPA load Job could not be deleted")
    deadline = time.monotonic() + min(timeout, 30.0)
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        observed = _get_job(config, max(0.1, min(10.0, remaining)))
        if observed is None:
            return {
                "schema_version": 1,
                "status": "pass",
                "phase": "clear",
                "namespace": config["namespace"],
                "run_nonce": config["nonce"],
                "cluster_fingerprint": actual_fingerprint,
                "job_name": _job_name(str(config["nonce"])),
                "job_uid": uid,
                "job_labels": labels,
                "api_observed": True,
                "job_deleted": True,
                "already_absent": False,
            }
        observed_uid, _ = _validate_job(observed, config)
        if observed_uid != uid:
            raise RuntimeError("bounded HPA load Job identity changed during clear")
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.25, remaining))
    raise RuntimeError("bounded HPA load Job deletion was not observed")


def main() -> int:
    try:
        config = _configuration()
        timeout = _timeout()
        result = _load(config, timeout) if config["phase"] == "load" else _clear(config, timeout)
        return _emit(result)
    except (RuntimeError, ValueError, OSError) as exc:
        return _emit(_error(str(exc)))


if __name__ == "__main__":
    raise SystemExit(main())
