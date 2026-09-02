#!/usr/bin/env python3
"""Provision the private HPA database credential without printing its value."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote

import yaml

_NAMESPACE_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_SUPPORT_SECRET = "runtime-support-secrets"  # noqa: S105 - Secret object name only
_HPA_SECRET = "trpc-hpa-secrets"  # noqa: S105 - Secret object name only
_PASSWORD_KEY = "hpa-password"  # noqa: S105 - Secret key name only
_DSN_KEY = "TRPC_HPA_DATABASE_DSN"


def _secret_name(document: object) -> str | None:
    if not isinstance(document, Mapping) or document.get("kind") != "Secret":
        return None
    metadata = document.get("metadata")
    name = metadata.get("name") if isinstance(metadata, Mapping) else None
    return name if isinstance(name, str) and name else None


def _decode_password(secret: Mapping[str, Any]) -> str | None:
    string_data = secret.get("stringData")
    if isinstance(string_data, Mapping) and _PASSWORD_KEY in string_data:
        value = string_data[_PASSWORD_KEY]
        return value if isinstance(value, str) else None
    data = secret.get("data")
    if isinstance(data, Mapping) and _PASSWORD_KEY in data:
        value = data[_PASSWORD_KEY]
        if not isinstance(value, str):
            return None
        try:
            return base64.b64decode(value, validate=True).decode("utf-8")
        except (ValueError, UnicodeError):
            return None
    return None


def provision(path: Path, *, support_namespace: str) -> dict[str, object]:
    """Add/update the HPA login material and return value-free metadata."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("Secret manifest is missing or unsafe")
    if _NAMESPACE_RE.fullmatch(support_namespace) is None:
        raise ValueError("support namespace is invalid")
    documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    names: dict[str, int] = {}
    for index, document in enumerate(documents):
        name = _secret_name(document)
        if name is None:
            raise ValueError("Secret manifest may contain only named Secret objects")
        if name in names:
            raise ValueError("Secret manifest contains a duplicate Secret")
        names[name] = index
    if _SUPPORT_SECRET not in names:
        raise ValueError("runtime support Secret is missing")
    support = documents[names[_SUPPORT_SECRET]]
    if not isinstance(support, dict):
        raise ValueError("runtime support Secret is invalid")
    password = _decode_password(support)
    created_password = password is None
    if password is None:
        password = secrets.token_urlsafe(48)
    if len(password) < 32 or any(character in "\x00\r\n" for character in password):
        raise ValueError("HPA password does not satisfy the private manifest contract")
    support_data = support.get("data")
    encoded_support_data = dict(support_data) if isinstance(support_data, Mapping) else {}
    encoded_support_data[_PASSWORD_KEY] = base64.b64encode(password.encode("utf-8")).decode("ascii")
    support["data"] = encoded_support_data
    support_string_data = support.get("stringData")
    if isinstance(support_string_data, Mapping):
        sanitized_string_data = dict(support_string_data)
        sanitized_string_data.pop(_PASSWORD_KEY, None)
        if sanitized_string_data:
            support["stringData"] = sanitized_string_data
        else:
            support.pop("stringData", None)

    host = f"postgres.{support_namespace}.svc.cluster.local"
    dsn = f"postgresql://trpc_hpa:{quote(password, safe='')}@{host}:5432/trpc_service"
    hpa_document = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": _HPA_SECRET},
        "type": "Opaque",
        "data": {_DSN_KEY: base64.b64encode(dsn.encode("utf-8")).decode("ascii")},
    }
    created_secret = _HPA_SECRET not in names
    if created_secret:
        documents.append(hpa_document)
    else:
        documents[names[_HPA_SECRET]] = hpa_document

    rendered = yaml.safe_dump_all(documents, sort_keys=False)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if temporary.exists():
            temporary.unlink()
    return {
        "status": "pass",
        "changed": created_password or created_secret,
        "support_secret": _SUPPORT_SECRET,
        "support_key": _PASSWORD_KEY,
        "hpa_secret": _HPA_SECRET,
        "hpa_key": _DSN_KEY,
        "values_recorded": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--support-namespace", required=True)
    args = parser.parse_args(argv)
    try:
        result = provision(args.manifest, support_namespace=args.support_namespace)
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
        parser.error(str(error))
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
