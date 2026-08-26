from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from scripts.deployment_config import (
    DeploymentConfigError,
    load_runtime_gate_config,
    secret_manifest_metadata,
)
from scripts.deployment_preflight import build_preflight
from scripts.evidence_lineage import source_fingerprint

ROOT = Path(__file__).resolve().parents[2]
NONCE = "n" * 32


def _write_inputs(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    release_id = "acceptance-1"
    nonce_hash = hashlib.sha256(NONCE.encode()).hexdigest()
    initial = "ghcr.io/example/runtime@sha256:" + "1" * 64
    upgrade = "ghcr.io/example/runtime@sha256:" + "2" * 64
    binding = {
        "release_binding": {"release_id": release_id, "nonce_sha256": nonce_hash},
        "source_fingerprint": source_fingerprint(ROOT),
        "images": {
            "initial": {"reference": initial},
            "upgrade": {"reference": upgrade},
        },
    }
    (tmp_path / "binding.json").write_text(json.dumps(binding), encoding="utf-8")
    (tmp_path / "admin.kubeconfig").write_text("admin", encoding="utf-8")
    (tmp_path / "driver.kubeconfig").write_text("driver", encoding="utf-8")
    (tmp_path / "secrets.yaml").write_text(
        """
apiVersion: v1
kind: Secret
metadata: {name: trpc-service-secrets}
stringData:
  TRPC_SERVICE_DATABASE_DSN: secret
  TRPC_SERVICE_REDIS_URL: secret
  TRPC_SERVICE_SESSION_HMAC_KEY: secret
  TRPC_SERVICE_EMERGENCY_QUEUE_KEY: secret
  TRPC_SERVICE_S3_ACCESS_KEY: secret
  TRPC_SERVICE_S3_SECRET_KEY: secret
---
apiVersion: v1
kind: Secret
metadata: {name: trpc-worker-secrets}
stringData:
  TRPC_SERVICE_WORKER_DATABASE_DSN_REF: env://worker
  TRPC_SERVICE_WORKER_DATABASE_DSN: secret
  TRPC_SERVICE_WORKER_DATABASE_PASSWORD_REF: env://password
  TRPC_SERVICE_WORKER_DATABASE_PASSWORD: secret
---
apiVersion: v1
kind: Secret
metadata: {name: trpc-migration-secrets}
stringData: {TRPC_SERVICE_DATABASE_DSN: secret}
---
apiVersion: v1
kind: Secret
metadata: {name: ghcr-pull}
type: kubernetes.io/dockerconfigjson
data: {.dockerconfigjson: c2VjcmV0}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    config = tmp_path / "runtime-gate.yaml"
    driver_path = (ROOT / "scripts" / "kubernetes_hpa_load_driver.py").as_posix()
    config.write_text(
        f"""
schema_version: 1
release:
  id: {release_id}
  nonce_env: TEST_RELEASE_NONCE
  image_binding: binding.json
kubernetes:
  kubeconfig: admin.kubeconfig
  context: admin-context
  timeout_seconds: 900
  secret_manifest: secrets.yaml
  image_pull_secret: ghcr-pull
  node:
    name: acceptance-node
    label: trpc-runtime-gate=acceptance
    drain_confirmation: I_UNDERSTAND_ISOLATED_NODE_DRAIN
  hpa:
    driver: {driver_path}
    kubeconfig: driver.kubeconfig
    context: driver-context
    subject: system:serviceaccount:runtime-driver:hpa-driver
    job_image: {initial}
    job_command: [python, -c, 'print("load")']
compose:
  ports:
    postgres: 35432
    redis: 36379
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return config, {"TEST_RELEASE_NONCE": NONCE}


def test_load_config_projects_all_runtime_environment(tmp_path: Path) -> None:
    config_path, source = _write_inputs(tmp_path)

    config = load_runtime_gate_config(config_path)
    environment = config.environment(source)

    assert environment["TRPC_RELEASE_ID"] == "acceptance-1"
    assert environment["TRPC_RELEASE_NONCE"] == NONCE
    assert environment["TRPC_K8S_RUNTIME_IMAGE"].endswith("1" * 64)
    assert environment["TRPC_K8S_RUNTIME_UPGRADE_IMAGE"].endswith("2" * 64)
    assert environment["TRPC_K8S_RUNTIME_IMAGE_PULL_SECRET"] == "ghcr-pull"
    assert environment["TRPC_K8S_RUNTIME_HPA_JOB_IMAGE"].endswith("1" * 64)
    assert environment["TRPC_K8S_RUNTIME_HPA_DRIVER_SHA256"] == hashlib.sha256(
        (ROOT / "scripts" / "kubernetes_hpa_load_driver.py").read_bytes()
    ).hexdigest()
    assert environment["POSTGRES_PORT"] == "35432"
    assert environment["REDIS_PORT"] == "36379"


def test_pull_registry_rewrites_only_runtime_registry_host(tmp_path: Path) -> None:
    config_path, source = _write_inputs(tmp_path)
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(
            "  image_pull_secret: ghcr-pull\n",
            "  image_pull_secret: ghcr-pull\n"
            "  pull_registry: elt91uy73y2gh25fs7-ghcr.xuanyuan.run\n",
        ),
        encoding="utf-8",
    )

    config = load_runtime_gate_config(config_path)
    environment = config.environment(source)

    assert environment["TRPC_K8S_RUNTIME_IMAGE"] == (
        "elt91uy73y2gh25fs7-ghcr.xuanyuan.run/example/runtime@sha256:" + "1" * 64
    )
    assert environment["TRPC_K8S_RUNTIME_UPGRADE_IMAGE"] == (
        "elt91uy73y2gh25fs7-ghcr.xuanyuan.run/example/runtime@sha256:" + "2" * 64
    )
    assert environment["TRPC_K8S_RUNTIME_HPA_JOB_IMAGE"] == (
        "ghcr.io/example/runtime@sha256:" + "1" * 64
    )


def test_pull_registry_must_be_a_host_without_path(tmp_path: Path) -> None:
    config_path, _ = _write_inputs(tmp_path)
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(
            "  image_pull_secret: ghcr-pull\n",
            "  image_pull_secret: ghcr-pull\n  pull_registry: https://registry.example/pull\n",
        ),
        encoding="utf-8",
    )

    with pytest.raises(DeploymentConfigError, match="pull_registry"):
        load_runtime_gate_config(config_path)


def test_duplicate_and_unknown_keys_are_rejected(tmp_path: Path) -> None:
    config_path, _ = _write_inputs(tmp_path)
    original = config_path.read_text(encoding="utf-8")
    config_path.write_text(
        original.replace("schema_version: 1", "schema_version: 1\nschema_version: 1"),
        encoding="utf-8",
    )
    with pytest.raises(DeploymentConfigError, match="duplicate configuration key"):
        load_runtime_gate_config(config_path)

    config_path.write_text(original + "unknown: true\n", encoding="utf-8")
    with pytest.raises(DeploymentConfigError, match="unknown fields"):
        load_runtime_gate_config(config_path)


def test_binding_nonce_and_source_must_match(tmp_path: Path) -> None:
    config_path, _ = _write_inputs(tmp_path)
    config = load_runtime_gate_config(config_path)
    with pytest.raises(DeploymentConfigError, match="nonce"):
        config.environment({"TEST_RELEASE_NONCE": "x" * 32})

    binding_path = tmp_path / "binding.json"
    binding = json.loads(binding_path.read_text(encoding="utf-8"))
    binding["source_fingerprint"]["value"] = "0" * 64
    binding_path.write_text(json.dumps(binding), encoding="utf-8")
    with pytest.raises(DeploymentConfigError, match="source fingerprint"):
        config.environment({"TEST_RELEASE_NONCE": NONCE})


def test_secret_metadata_never_returns_values(tmp_path: Path) -> None:
    config_path, _ = _write_inputs(tmp_path)
    config = load_runtime_gate_config(config_path)
    metadata = secret_manifest_metadata(config.secret_manifest)

    assert ".dockerconfigjson" in metadata["ghcr-pull"]
    assert "c2VjcmV0" not in repr(metadata)


def test_preflight_aggregates_files_secrets_and_ports(tmp_path: Path) -> None:
    config_path, source = _write_inputs(tmp_path)

    report, projected = build_preflight(config_path, environment=source)

    assert report["gate"] == "pass"
    assert report["secrets_recorded"] is False
    assert report["config_content_sha256"] == hashlib.sha256(
        config_path.read_bytes()
    ).hexdigest()
    assert projected is not None
    assert all(check["status"] == "pass" for check in report["checks"])
    serialized = json.dumps(report)
    assert "c2VjcmV0" not in serialized
    assert NONCE not in serialized


def test_preflight_reports_all_missing_files_without_secret_data(tmp_path: Path) -> None:
    config_path, source = _write_inputs(tmp_path)
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(
            f"driver: {(ROOT / 'scripts' / 'kubernetes_hpa_load_driver.py').as_posix()}",
            "driver: missing-driver.py",
        ),
        encoding="utf-8",
    )
    for name in (
        "binding.json",
        "admin.kubeconfig",
        "secrets.yaml",
        "driver.kubeconfig",
    ):
        (tmp_path / name).unlink()

    report, projected = build_preflight(config_path, environment=source)

    assert report["gate"] == "fail"
    assert projected is None
    assert {check["name"] for check in report["checks"] if check["status"] == "fail"} == {
        "image_binding",
        "admin_kubeconfig",
        "secret_manifest",
        "hpa_driver",
        "hpa_kubeconfig",
        "image_reference_contract",
        "release_binding",
        "secret_manifest_contract",
        "hpa_driver_identity",
        "hpa_kubeconfig_separation",
    }


def test_preflight_rejects_pull_secret_type_and_hardcoded_namespace(tmp_path: Path) -> None:
    config_path, source = _write_inputs(tmp_path)
    secret_path = tmp_path / "secrets.yaml"
    contents = secret_path.read_text(encoding="utf-8")
    contents = contents.replace(
        "metadata: {name: trpc-service-secrets}",
        "metadata: {name: trpc-service-secrets, namespace: default}",
    ).replace("type: kubernetes.io/dockerconfigjson", "type: Opaque")
    secret_path.write_text(contents, encoding="utf-8")

    report, projected = build_preflight(config_path, environment=source)

    check = next(item for item in report["checks"] if item["name"] == "secret_manifest_contract")
    assert report["gate"] == "fail"
    assert projected is None
    assert check["hardcoded_namespace_names"] == ["trpc-service-secrets"]
    assert check["image_pull_secret_type_valid"] is False


def test_preflight_rejects_kubeconfig_hardlink_alias(tmp_path: Path) -> None:
    config_path, source = _write_inputs(tmp_path)
    driver_kubeconfig = tmp_path / "driver.kubeconfig"
    driver_kubeconfig.unlink()
    os.link(tmp_path / "admin.kubeconfig", driver_kubeconfig)

    report, projected = build_preflight(config_path, environment=source)

    check = next(item for item in report["checks"] if item["name"] == "hpa_kubeconfig_separation")
    assert report["gate"] == "fail"
    assert projected is None
    assert check["distinct_paths"] is True
    assert check["distinct_bytes"] is False
    assert check["distinct_inodes"] is False


def test_preflight_returns_structured_failure_for_invalid_document(tmp_path: Path) -> None:
    config_path = tmp_path / "runtime-gate.yaml"
    config_path.write_text("schema_version: [", encoding="utf-8")

    report, projected = build_preflight(config_path, environment={})

    assert report["gate"] == "fail"
    assert projected is None
    assert report["checks"] == [
        {
            "name": "configuration",
            "status": "fail",
            "reason": "runtime gate config is not readable YAML",
        }
    ]
