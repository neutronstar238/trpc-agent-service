#!/usr/bin/env python3
"""Project an allowlisted Secret set into one Kubernetes namespace."""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

_NAMESPACE_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_SECRET_NAME_RE = re.compile(
    r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$"
)
_RUNTIME_NAMES = frozenset(
    {
        "trpc-service-secrets",
        "trpc-worker-secrets",
        "trpc-migration-secrets",
        "trpc-metrics-secrets",
    }
)
_SUPPORT_NAME = "runtime-support-secrets"
_MINIO_NAME = "trpc-runtime-minio"
_HPA_NAME = "trpc-hpa-secrets"
_PULL_SECRET_TYPE = "kubernetes.io/dockerconfigjson"  # noqa: S105 - Kubernetes type name
_FIXTURE_NAMES = (
    "TRPC_PERF_FIXTURE_UNUSED_APP_SECRET",
    "TRPC_PERF_FIXTURE_UNUSED_VERIFICATION_TOKEN",
    "TRPC_PERF_FIXTURE_UNUSED_ENCRYPT_KEY",
)
_SUPPORT_KEYS = frozenset(
    {
        "postgres-admin-password",
        "runtime-password",
        "worker-password",
        "migration-password",
        "metrics-password",
        "hpa-password",
    }
)
_SERVICE_KEYS = frozenset(
    {
        "TRPC_SERVICE_DATABASE_DSN",
        "TRPC_SERVICE_REDIS_URL",
        "TRPC_SERVICE_SESSION_HMAC_KEY",
        "TRPC_SERVICE_EMERGENCY_QUEUE_KEY",
        "TRPC_SERVICE_S3_ACCESS_KEY",
        "TRPC_SERVICE_S3_SECRET_KEY",
        "TRPC_SERVICE_S3_SECRET_KEY_REF",
    }
)
_WORKER_KEYS = frozenset(
    {
        "TRPC_SERVICE_WORKER_DATABASE_DSN_REF",
        "TRPC_SERVICE_WORKER_DATABASE_DSN",
        "TRPC_SERVICE_WORKER_DATABASE_PASSWORD_REF",
        "TRPC_SERVICE_WORKER_DATABASE_PASSWORD",
    }
)
_MIGRATION_KEYS = frozenset({"TRPC_SERVICE_DATABASE_DSN"})
_METRICS_KEYS = frozenset({"TRPC_SERVICE_METRICS_DATABASE_DSN"})
_HPA_KEYS = frozenset({"TRPC_HPA_DATABASE_DSN"})
_MINIO_KEYS = frozenset({"MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD"})
_PULL_KEYS = frozenset({".dockerconfigjson"})
_SECRET_KEYS_BY_NAME = {
    "trpc-service-secrets": _SERVICE_KEYS,
    "trpc-worker-secrets": _WORKER_KEYS,
    "trpc-migration-secrets": _MIGRATION_KEYS,
    "trpc-metrics-secrets": _METRICS_KEYS,
    _SUPPORT_NAME: _SUPPORT_KEYS,
    _MINIO_NAME: _MINIO_KEYS,
    _HPA_NAME: _HPA_KEYS,
}
_SECRET_REQUIRED_KEYS_BY_NAME = {
    **_SECRET_KEYS_BY_NAME,
    "trpc-service-secrets": _SERVICE_KEYS - {"TRPC_SERVICE_S3_SECRET_KEY_REF"},
}
_PROFILES = {
    "runtime": _RUNTIME_NAMES,
    "support": frozenset({_SUPPORT_NAME, _MINIO_NAME}),
    "hpa": frozenset({_HPA_NAME}),
}


def project_secrets(
    path: Path,
    namespace: str,
    profile: str,
    *,
    image_pull_secret: str | None = None,
) -> list[dict[str, Any]]:
    """Return only the exact Secret documents required by one runtime profile."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("Secret manifest is missing or unsafe")
    if _NAMESPACE_RE.fullmatch(namespace) is None:
        raise ValueError("target namespace is invalid")
    if profile not in _PROFILES:
        raise ValueError("Secret projection profile is invalid")
    if image_pull_secret is not None and (
        len(image_pull_secret) > 253 or _SECRET_NAME_RE.fullmatch(image_pull_secret) is None
    ):
        raise ValueError("image pull Secret name is invalid")
    if image_pull_secret in _SECRET_KEYS_BY_NAME:
        raise ValueError("image pull Secret name collides with a runtime Secret")
    documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    wanted = set(_PROFILES[profile])
    if image_pull_secret:
        wanted.add(image_pull_secret)
    selected: dict[str, dict[str, Any]] = {}
    for document in documents:
        if not isinstance(document, dict) or document.get("kind") != "Secret":
            continue
        metadata = document.get("metadata")
        if not isinstance(metadata, Mapping):
            continue
        name = metadata.get("name")
        if name not in wanted:
            continue
        if name in selected:
            raise ValueError("required Secret is duplicated")
        projected: dict[str, Any] = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": name, "namespace": namespace},
        }
        allowed_keys = _PULL_KEYS if name == image_pull_secret else _SECRET_KEYS_BY_NAME.get(name)
        if allowed_keys is None:
            raise ValueError("selected Secret has no key contract")
        resource_type = document.get("type")
        if resource_type is not None:
            projected["type"] = resource_type
        for field in ("data", "stringData"):
            value = document.get(field)
            if isinstance(value, Mapping):
                projected[field] = {key: item for key, item in value.items() if key in allowed_keys}
        selected[str(name)] = projected
    if set(selected) != wanted:
        raise ValueError("required Secret set is incomplete")
    if profile == "runtime":
        fixture_values = {name: os.getenv(name, "") for name in _FIXTURE_NAMES}
        if any(fixture_values.values()) and not all(fixture_values.values()):
            raise ValueError("runtime fixture Secret values are incomplete")
        if all(fixture_values.values()):
            service = selected["trpc-service-secrets"]
            data = service.get("data")
            if isinstance(data, dict):
                for name in _FIXTURE_NAMES:
                    data.pop(name, None)
            string_data = service.get("stringData")
            projected_string_data = dict(string_data) if isinstance(string_data, Mapping) else {}
            projected_string_data.update(fixture_values)
            service["stringData"] = projected_string_data
    for name, required_keys in _SECRET_REQUIRED_KEYS_BY_NAME.items():
        if name not in selected:
            continue
        projected = selected[name]
        data = projected.get("data")
        string_data = projected.get("stringData")
        available = set(data) if isinstance(data, Mapping) else set()
        available.update(string_data if isinstance(string_data, Mapping) else {})
        if (
            isinstance(data, Mapping)
            and isinstance(string_data, Mapping)
            and set(data).intersection(string_data)
        ):
            raise ValueError(f"{name} Secret defines a key in both data and stringData")
        if any(
            not isinstance(value, str) or not value
            for values in (data, string_data)
            if isinstance(values, Mapping)
            for value in values.values()
        ):
            raise ValueError(f"{name} Secret contains an empty or invalid value")
        if required_keys.issubset(available):
            continue
        if name == _SUPPORT_NAME:
            raise ValueError("runtime support Secret keys are incomplete")
        if name == _MINIO_NAME:
            raise ValueError("MinIO Secret keys are incomplete")
        if name == _HPA_NAME:
            raise ValueError("HPA Secret keys are incomplete")
        raise ValueError(f"{name} Secret keys are incomplete")
    if image_pull_secret:
        pull = selected[image_pull_secret]
        data = pull.get("data")
        if pull.get("type") != _PULL_SECRET_TYPE or not isinstance(data, Mapping):
            raise ValueError("image pull Secret contract is invalid")
        if (
            ".dockerconfigjson" not in data
            or not isinstance(data[".dockerconfigjson"], str)
            or not data[".dockerconfigjson"]
        ):
            raise ValueError("image pull Secret contract is invalid")
    return [selected[name] for name in sorted(selected)]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--profile", choices=tuple(_PROFILES), required=True)
    parser.add_argument("--image-pull-secret")
    args = parser.parse_args(argv)
    try:
        projected = project_secrets(
            args.manifest,
            args.namespace,
            args.profile,
            image_pull_secret=args.image_pull_secret,
        )
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
        parser.error(str(error))
    yaml.safe_dump_all(projected, sys.stdout, sort_keys=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
