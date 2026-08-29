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

_NAMESPACE_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_RUNTIME_NAMES = frozenset(
    {
        "trpc-service-secrets",
        "trpc-worker-secrets",
        "trpc-migration-secrets",
        "trpc-metrics-secrets",
    }
)
_SUPPORT_NAME = "runtime-support-secrets"
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
    }
)


def project_secrets(path: Path, namespace: str, profile: str) -> list[dict[str, Any]]:
    """Return only the exact Secret documents required by one runtime profile."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("Secret manifest is missing or unsafe")
    if _NAMESPACE_RE.fullmatch(namespace) is None:
        raise ValueError("target namespace is invalid")
    documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    wanted = _RUNTIME_NAMES if profile == "runtime" else frozenset({_SUPPORT_NAME})
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
        projected = dict(document)
        projected_metadata = dict(metadata)
        projected_metadata["namespace"] = namespace
        projected["metadata"] = projected_metadata
        selected[str(name)] = projected
    if set(selected) != set(wanted):
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
    if profile == "support":
        support = selected[_SUPPORT_NAME]
        data = support.get("data")
        string_data = support.get("stringData")
        available = set(data) if isinstance(data, Mapping) else set()
        available.update(string_data if isinstance(string_data, Mapping) else {})
        if not _SUPPORT_KEYS.issubset(available):
            raise ValueError("runtime support Secret keys are incomplete")
    return [selected[name] for name in sorted(selected)]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--profile", choices=("runtime", "support"), required=True)
    args = parser.parse_args(argv)
    try:
        projected = project_secrets(args.manifest, args.namespace, args.profile)
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
        parser.error(str(error))
    yaml.safe_dump_all(projected, sys.stdout, sort_keys=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
