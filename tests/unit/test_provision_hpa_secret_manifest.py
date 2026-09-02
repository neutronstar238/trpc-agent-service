from __future__ import annotations

import base64
from pathlib import Path

import yaml

from scripts.provision_hpa_secret_manifest import provision


def test_provision_adds_hpa_material_without_returning_values(tmp_path: Path) -> None:
    manifest = tmp_path / "secrets.yaml"
    manifest.write_text(
        yaml.safe_dump_all(
            [
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {"name": "runtime-support-secrets"},
                    "data": {"runtime-password": "YQ=="},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {"name": "xuanyuan-pull"},
                    "type": "kubernetes.io/dockerconfigjson",
                    "data": {".dockerconfigjson": "YQ=="},
                },
            ],
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    result = provision(manifest, support_namespace="trpc-cell-fabric-support")
    documents = list(yaml.safe_load_all(manifest.read_text(encoding="utf-8")))
    support = next(
        item for item in documents if item["metadata"]["name"] == "runtime-support-secrets"
    )
    hpa = next(item for item in documents if item["metadata"]["name"] == "trpc-hpa-secrets")
    password = base64.b64decode(support["data"]["hpa-password"]).decode("utf-8")
    dsn = base64.b64decode(hpa["data"]["TRPC_HPA_DATABASE_DSN"]).decode("utf-8")

    assert len(password) >= 32
    assert dsn.startswith("postgresql://trpc_hpa:")
    assert "@postgres.trpc-cell-fabric-support.svc.cluster.local:5432/trpc_service" in dsn
    assert password not in repr(result)
    assert "postgresql://" not in repr(result)
    assert result["values_recorded"] is False


def test_provision_is_idempotent_and_keeps_the_same_password(tmp_path: Path) -> None:
    manifest = tmp_path / "secrets.yaml"
    manifest.write_text(
        yaml.safe_dump_all(
            [
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {"name": "runtime-support-secrets"},
                    "stringData": {"hpa-password": "x" * 48},
                }
            ]
        ),
        encoding="utf-8",
    )

    first = provision(manifest, support_namespace="trpc-cell-fabric-support")
    first_contents = manifest.read_text(encoding="utf-8")
    second = provision(manifest, support_namespace="trpc-cell-fabric-support")

    assert first["changed"] is True
    assert second["changed"] is False
    assert manifest.read_text(encoding="utf-8") == first_contents
