from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
import yaml


def _module() -> ModuleType:
    path = Path("runs/multitenant/project_kubernetes_secrets.py").resolve()
    spec = importlib.util.spec_from_file_location("project_kubernetes_secrets", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _manifest(path: Path) -> None:
    keys_by_name = {
        "trpc-service-secrets": {
            "TRPC_SERVICE_DATABASE_DSN",
            "TRPC_SERVICE_REDIS_URL",
            "TRPC_SERVICE_SESSION_HMAC_KEY",
            "TRPC_SERVICE_EMERGENCY_QUEUE_KEY",
            "TRPC_SERVICE_S3_ACCESS_KEY",
            "TRPC_SERVICE_S3_SECRET_KEY",
            "TRPC_SERVICE_S3_SECRET_KEY_REF",
        },
        "trpc-worker-secrets": {
            "TRPC_SERVICE_WORKER_DATABASE_DSN_REF",
            "TRPC_SERVICE_WORKER_DATABASE_DSN",
            "TRPC_SERVICE_WORKER_DATABASE_PASSWORD_REF",
            "TRPC_SERVICE_WORKER_DATABASE_PASSWORD",
        },
        "trpc-migration-secrets": {"TRPC_SERVICE_DATABASE_DSN"},
        "trpc-metrics-secrets": {"TRPC_SERVICE_METRICS_DATABASE_DSN"},
    }
    documents = [
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": name},
            "data": {key: "YQ==" for key in keys},
        }
        for name, keys in keys_by_name.items()
    ]
    documents.append(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "runtime-support-secrets"},
            "data": {
                "postgres-admin-password": "YQ==",
                "runtime-password": "YQ==",
                "worker-password": "YQ==",
                "migration-password": "YQ==",
                "metrics-password": "YQ==",
                "hpa-password": "YQ==",
            },
        }
    )
    documents.extend(
        [
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "trpc-runtime-minio"},
                "data": {"MINIO_ROOT_USER": "YQ==", "MINIO_ROOT_PASSWORD": "YQ=="},
            },
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "trpc-hpa-secrets"},
                "data": {"TRPC_HPA_DATABASE_DSN": "YQ=="},
            },
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "xuanyuan-pull"},
                "type": "kubernetes.io/dockerconfigjson",
                "data": {".dockerconfigjson": "YQ=="},
            },
        ]
    )
    path.write_text(yaml.safe_dump_all(documents), encoding="utf-8")


def test_projection_is_exact_and_rewrites_namespace(tmp_path: Path) -> None:
    module = _module()
    manifest = tmp_path / "secrets.yaml"
    _manifest(manifest)

    runtime = module.project_secrets(manifest, "trpc-service", "runtime")
    support = module.project_secrets(manifest, "trpc-runtime-support", "support")
    hpa = module.project_secrets(
        manifest,
        "trpc-runtime-driver",
        "hpa",
        image_pull_secret="xuanyuan-pull",
    )

    assert len(runtime) == 4
    assert {item["metadata"]["namespace"] for item in runtime} == {"trpc-service"}
    assert [item["metadata"]["name"] for item in support] == [
        "runtime-support-secrets",
        "trpc-runtime-minio",
    ]
    assert [item["metadata"]["name"] for item in hpa] == [
        "trpc-hpa-secrets",
        "xuanyuan-pull",
    ]
    assert {item["metadata"]["namespace"] for item in hpa} == {"trpc-runtime-driver"}


def test_runtime_projection_overlays_complete_fixture_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    manifest = tmp_path / "secrets.yaml"
    _manifest(manifest)
    for name in module._FIXTURE_NAMES:
        monkeypatch.setenv(name, f"synthetic-{name.lower()}")

    runtime = module.project_secrets(manifest, "trpc-service", "runtime")
    service = next(item for item in runtime if item["metadata"]["name"] == "trpc-service-secrets")

    assert set(service["stringData"]) >= set(module._FIXTURE_NAMES)
    assert all(
        service["stringData"][name].startswith("synthetic-") for name in module._FIXTURE_NAMES
    )


def test_projection_filters_extra_sensitive_keys_from_every_profile(
    tmp_path: Path,
) -> None:
    module = _module()
    manifest = tmp_path / "secrets.yaml"
    _manifest(manifest)
    documents = list(yaml.safe_load_all(manifest.read_text(encoding="utf-8")))
    for document in documents:
        name = document.get("metadata", {}).get("name")
        if name == "trpc-service-secrets":
            document["data"]["TRPC_SERVICE_DEVELOPMENT_TOKEN"] = "YQ=="
            document["stringData"] = {"TRPC_SERVICE_DATABASE_PASSWORD": "YQ=="}
        elif name == "trpc-worker-secrets":
            document["data"]["TRPC_SERVICE_DATABASE_DSN"] = "YQ=="
        elif name == "runtime-support-secrets":
            document["data"]["TRPC_SERVICE_SESSION_HMAC_KEY"] = "YQ=="
        elif name == "trpc-runtime-minio":
            document["data"]["MINIO_ROOT_ACCESS_TOKEN"] = "YQ=="
        elif name == "trpc-hpa-secrets":
            document["data"]["TRPC_SERVICE_DATABASE_DSN"] = "YQ=="
        elif name == "xuanyuan-pull":
            document["data"]["REGISTRY_PASSWORD"] = "YQ=="
    manifest.write_text(yaml.safe_dump_all(documents), encoding="utf-8")

    runtime = module.project_secrets(manifest, "trpc-service", "runtime")
    support = module.project_secrets(manifest, "trpc-runtime-support", "support")
    hpa = module.project_secrets(
        manifest,
        "trpc-runtime-driver",
        "hpa",
        image_pull_secret="xuanyuan-pull",
    )

    for projected in (*runtime, *support, *hpa):
        name = projected["metadata"]["name"]
        allowed = (
            module._PULL_KEYS if name == "xuanyuan-pull" else module._SECRET_KEYS_BY_NAME[name]
        )
        for field in ("data", "stringData"):
            assert set(projected.get(field, {})) <= allowed
    service = next(item for item in runtime if item["metadata"]["name"] == "trpc-service-secrets")
    assert "TRPC_SERVICE_DEVELOPMENT_TOKEN" not in service["data"]
    assert "TRPC_SERVICE_DATABASE_PASSWORD" not in service["stringData"]
    pull = next(item for item in hpa if item["metadata"]["name"] == "xuanyuan-pull")
    assert set(pull["data"]) == {".dockerconfigjson"}


def test_runtime_projection_rejects_missing_required_key(tmp_path: Path) -> None:
    module = _module()
    manifest = tmp_path / "secrets.yaml"
    _manifest(manifest)
    documents = list(yaml.safe_load_all(manifest.read_text(encoding="utf-8")))
    service = next(
        item for item in documents if item.get("metadata", {}).get("name") == "trpc-service-secrets"
    )
    service["data"].pop("TRPC_SERVICE_S3_SECRET_KEY")
    manifest.write_text(yaml.safe_dump_all(documents), encoding="utf-8")

    with pytest.raises(ValueError, match="trpc-service-secrets Secret keys are incomplete"):
        module.project_secrets(manifest, "trpc-service", "runtime")


def test_runtime_projection_allows_optional_s3_secret_reference_key_to_be_absent(
    tmp_path: Path,
) -> None:
    module = _module()
    manifest = tmp_path / "secrets.yaml"
    _manifest(manifest)
    documents = list(yaml.safe_load_all(manifest.read_text(encoding="utf-8")))
    service = next(
        item for item in documents if item.get("metadata", {}).get("name") == "trpc-service-secrets"
    )
    service["data"].pop("TRPC_SERVICE_S3_SECRET_KEY_REF")
    manifest.write_text(yaml.safe_dump_all(documents), encoding="utf-8")

    projected = module.project_secrets(manifest, "trpc-service", "runtime")

    projected_service = next(
        item for item in projected if item["metadata"]["name"] == "trpc-service-secrets"
    )
    assert "TRPC_SERVICE_S3_SECRET_KEY_REF" not in projected_service["data"]


def test_projection_rejects_empty_or_ambiguous_secret_values(tmp_path: Path) -> None:
    module = _module()
    manifest = tmp_path / "secrets.yaml"
    _manifest(manifest)
    documents = list(yaml.safe_load_all(manifest.read_text(encoding="utf-8")))
    service = next(
        item for item in documents if item.get("metadata", {}).get("name") == "trpc-service-secrets"
    )
    service["data"]["TRPC_SERVICE_DATABASE_DSN"] = ""
    manifest.write_text(yaml.safe_dump_all(documents), encoding="utf-8")
    with pytest.raises(ValueError, match="empty or invalid value"):
        module.project_secrets(manifest, "trpc-service", "runtime")

    _manifest(manifest)
    documents = list(yaml.safe_load_all(manifest.read_text(encoding="utf-8")))
    service = next(
        item for item in documents if item.get("metadata", {}).get("name") == "trpc-service-secrets"
    )
    service["stringData"] = {"TRPC_SERVICE_DATABASE_DSN": "duplicate"}
    manifest.write_text(yaml.safe_dump_all(documents), encoding="utf-8")
    with pytest.raises(ValueError, match="both data and stringData"):
        module.project_secrets(manifest, "trpc-service", "runtime")


def test_support_projection_rejects_missing_required_key(tmp_path: Path) -> None:
    module = _module()
    manifest = tmp_path / "secrets.yaml"
    _manifest(manifest)
    documents = list(yaml.safe_load_all(manifest.read_text(encoding="utf-8")))
    support = next(
        item
        for item in documents
        if item.get("metadata", {}).get("name") == "runtime-support-secrets"
    )
    support["data"].pop("metrics-password")
    manifest.write_text(yaml.safe_dump_all(documents), encoding="utf-8")

    with pytest.raises(ValueError, match="keys are incomplete"):
        module.project_secrets(manifest, "trpc-runtime-support", "support")


def test_hpa_projection_rejects_missing_dsn_key(tmp_path: Path) -> None:
    module = _module()
    manifest = tmp_path / "secrets.yaml"
    _manifest(manifest)
    documents = list(yaml.safe_load_all(manifest.read_text(encoding="utf-8")))
    hpa = next(
        item for item in documents if item.get("metadata", {}).get("name") == "trpc-hpa-secrets"
    )
    hpa["data"].clear()
    manifest.write_text(yaml.safe_dump_all(documents), encoding="utf-8")

    with pytest.raises(ValueError, match="HPA Secret keys are incomplete"):
        module.project_secrets(manifest, "trpc-runtime-driver", "hpa")


def test_projection_rejects_invalid_pull_secret_contract(tmp_path: Path) -> None:
    module = _module()
    manifest = tmp_path / "secrets.yaml"
    _manifest(manifest)
    documents = list(yaml.safe_load_all(manifest.read_text(encoding="utf-8")))
    pull = next(
        item for item in documents if item.get("metadata", {}).get("name") == "xuanyuan-pull"
    )
    pull["type"] = "Opaque"
    manifest.write_text(yaml.safe_dump_all(documents), encoding="utf-8")

    with pytest.raises(ValueError, match="image pull Secret contract is invalid"):
        module.project_secrets(
            manifest,
            "trpc-runtime-driver",
            "hpa",
            image_pull_secret="xuanyuan-pull",
        )


def test_projection_rejects_overlong_pull_secret_name(tmp_path: Path) -> None:
    module = _module()
    manifest = tmp_path / "secrets.yaml"
    _manifest(manifest)

    with pytest.raises(ValueError, match="image pull Secret name is invalid"):
        module.project_secrets(
            manifest,
            "trpc-runtime-driver",
            "hpa",
            image_pull_secret="a." * 127 + "aa",
        )


@pytest.mark.parametrize("namespace", ("has.dot", "UPPER", "a" * 64))
def test_projection_rejects_invalid_kubernetes_namespace(tmp_path: Path, namespace: str) -> None:
    module = _module()
    manifest = tmp_path / "secrets.yaml"
    _manifest(manifest)

    with pytest.raises(ValueError, match="target namespace is invalid"):
        module.project_secrets(manifest, namespace, "runtime")


def test_projection_strips_server_owned_metadata(tmp_path: Path) -> None:
    module = _module()
    manifest = tmp_path / "secrets.yaml"
    _manifest(manifest)
    documents = list(yaml.safe_load_all(manifest.read_text(encoding="utf-8")))
    documents[0]["metadata"].update(
        {
            "uid": "server-owned",
            "resourceVersion": "7",
            "managedFields": [{"manager": "other"}],
            "ownerReferences": [{"name": "other"}],
        }
    )
    manifest.write_text(yaml.safe_dump_all(documents), encoding="utf-8")

    runtime = module.project_secrets(manifest, "trpc-runtime-gate-a1b2c3d4e5", "runtime")

    assert runtime[0]["metadata"] == {
        "name": runtime[0]["metadata"]["name"],
        "namespace": "trpc-runtime-gate-a1b2c3d4e5",
    }
