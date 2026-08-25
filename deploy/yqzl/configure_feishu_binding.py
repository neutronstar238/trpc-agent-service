#!/usr/bin/env python3
"""Configure the tx.nstarzx.cn Feishu binding without exposing credentials.

Run this script as root on yqzl and pass one JSON object on stdin. Credentials
therefore never appear in argv or process listings. The control plane stores
only file SecretRefs; secret values are written atomically with mode 0640.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DOMAIN = "tx.nstarzx.cn"
ADMIN_BASE_URL = "http://127.0.0.1:8741/v1"
SECRET_DIRECTORY = Path(f"/www/wwwroot/{DOMAIN}/secrets")
CONFIG_DIRECTORY = Path(f"/www/wwwroot/{DOMAIN}/config")


class ConfigurationError(RuntimeError):
    """A safe configuration failure that never includes credential values."""


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant-id", default="nstarzx-feishu")
    parser.add_argument("--display-name", default="nstarzx Feishu")
    parser.add_argument("--app-id", default="support")
    parser.add_argument(
        "--binding-id-file",
        type=Path,
        default=CONFIG_DIRECTORY / "feishu_binding_id",
    )
    return parser.parse_args()


def _read_credentials() -> dict[str, str]:
    try:
        value = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ConfigurationError("stdin must contain valid credential JSON") from exc
    if not isinstance(value, dict):
        raise ConfigurationError("credential input must be an object")
    names = (
        "feishu_app_id",
        "feishu_app_secret",
        "feishu_verification_token",
        "feishu_encrypt_key",
    )
    credentials = {key: str(value.get(key, "")).strip() for key in names}
    invalid = [
        key
        for key, item in credentials.items()
        if not item or len(item) > 256 or any(ord(char) < 33 for char in item)
    ]
    if not re.fullmatch(r"cli_[A-Za-z0-9]+", credentials["feishu_app_id"]):
        invalid.append("feishu_app_id")
    if invalid:
        raise ConfigurationError(
            "invalid credential format for: " + ", ".join(sorted(set(invalid)))
        )
    return credentials


def _write_secret(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    user = pwd.getpwnam("root")
    group = grp.getgrnam("trpcagent")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.write("\n")
        os.chown(temporary_name, user.pw_uid, group.gr_gid)
        os.chmod(temporary_name, 0o640)
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _request(
    token: str,
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    etag: str | None = None,
    idempotency_key: str | None = None,
) -> tuple[dict[str, Any], str | None]:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if etag is not None:
        headers["If-Match"] = etag
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    request = urllib.request.Request(  # noqa: S310 - fixed loopback endpoint.
        f"{ADMIN_BASE_URL}{path}", data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            payload = json.loads(response.read())
            return payload, response.headers.get("ETag")
    except urllib.error.HTTPError as exc:
        raise ConfigurationError(f"Admin API {method} {path} returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ConfigurationError("Admin API is unavailable") from exc


def _get_tenant(token: str, tenant_id: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        return _request(token, "GET", f"/tenants/{tenant_id}")
    except ConfigurationError as exc:
        if "HTTP 404" in str(exc):
            return None, None
        raise


def _stable_key(prefix: str, value: dict[str, Any]) -> str:
    digest = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:24]
    return f"yqzl-{prefix}-{digest}"


def main() -> int:
    if os.geteuid() != 0:
        raise ConfigurationError("this script must run as root")
    args = _arguments()
    credentials = _read_credentials()
    binding_id = args.binding_id_file.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", binding_id):
        raise ConfigurationError("binding ID file is missing or invalid")

    for name in ("app_secret", "verification_token", "encrypt_key"):
        _write_secret(
            SECRET_DIRECTORY / f"feishu_{name}",
            credentials[f"feishu_{name}"],
        )
    token = (SECRET_DIRECTORY / "development_token").read_text(encoding="utf-8").strip()
    if not token:
        raise ConfigurationError("development admin token is unavailable")

    tenant, _ = _get_tenant(token, args.tenant_id)
    if tenant is None:
        create_body = {"tenant_id": args.tenant_id, "display_name": args.display_name}
        _request(
            token,
            "POST",
            "/tenants",
            body=create_body,
            idempotency_key=_stable_key("tenant", create_body),
        )

    _, etag = _get_tenant(token, args.tenant_id)
    if etag is None:
        raise ConfigurationError("tenant ETag is unavailable")
    config_body = {
        "app_id": args.app_id,
        "config": {
            "model": {"provider": "offline", "model": "deterministic"},
            "storage": {"profile_id": "default"},
            "instructions": "Reply helpfully and do not expose tenant or secret data.",
        },
    }
    _request(
        token,
        "POST",
        f"/tenants/{args.tenant_id}/config-revisions",
        body=config_body,
        etag=etag,
        idempotency_key=_stable_key("config", config_body),
    )

    _, etag = _get_tenant(token, args.tenant_id)
    if etag is None:
        raise ConfigurationError("tenant ETag is unavailable after config creation")
    binding_body = {
        "app_id": args.app_id,
        "channel": "feishu",
        "account_id": credentials["feishu_app_id"],
        "secret_refs": {
            "app_secret": {"uri": f"file://{SECRET_DIRECTORY}/feishu_app_secret"},
            "verification_token": {"uri": f"file://{SECRET_DIRECTORY}/feishu_verification_token"},
            "encrypt_key": {"uri": f"file://{SECRET_DIRECTORY}/feishu_encrypt_key"},
        },
        "capabilities": ["media", "proactive"],
        "enabled": True,
    }
    binding, _ = _request(
        token,
        "PUT",
        f"/tenants/{args.tenant_id}/channel-bindings/{binding_id}",
        body=binding_body,
        etag=etag,
        idempotency_key=_stable_key("binding", binding_body),
    )

    print(
        json.dumps(
            {
                "status": "configured",
                "tenant_id": args.tenant_id,
                "app_id": args.app_id,
                "binding_id": binding_id,
                "binding_enabled": bool(binding.get("enabled")),
                "callback_url": f"https://{DOMAIN}/v1/channels/feishu/{binding_id}/callback",
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConfigurationError as exc:
        print(f"configuration failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
