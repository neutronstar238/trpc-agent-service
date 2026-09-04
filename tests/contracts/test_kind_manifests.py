from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
KIND = ROOT / "deploy" / "kind"


def _documents(path: Path) -> list[dict[str, object]]:
    values: list[dict[str, object]] = []
    for item in yaml.safe_load_all(path.read_text(encoding="utf-8")):
        if isinstance(item, dict):
            values.append(item)
    return values


def test_kind_config_has_one_control_plane_and_three_workers() -> None:
    config = yaml.safe_load((KIND / "cluster.yaml").read_text(encoding="utf-8"))
    roles = [node["role"] for node in config["nodes"]]
    node_labels = [
        patch.split('node-labels: "', 1)[1].split('"', 1)[0]
        for node in config["nodes"]
        for patch in node.get("kubeadmConfigPatches", [])
        if 'node-labels: "' in patch
    ]

    assert config["kind"] == "Cluster"
    assert roles.count("control-plane") == 1
    assert roles.count("worker") == 3
    assert node_labels == [
        "trpc.io/node-role=control-plane",
        "trpc.io/node-role=agent-worker,trpc.io/kind-pool=gateway",
        "trpc.io/node-role=agent-worker,trpc.io/kind-pool=gateway",
        "trpc.io/node-role=agent-worker,trpc.io/kind-pool=support",
    ]
    assert all(
        "node-labels" in patch
        for node in config["nodes"]
        for patch in node.get("kubeadmConfigPatches", [])
    )


def test_kustomization_reuses_base_and_declares_kind_support_services() -> None:
    kustomization = yaml.safe_load((KIND / "kustomization.yaml").read_text(encoding="utf-8"))

    resources = set(kustomization["resources"])
    assert "../kustomize/base" in resources
    assert {"kind-postgres.yaml", "kind-redis.yaml", "kind-fake-services.yaml"} <= resources
    image = kustomization["images"][0]
    assert image["newName"].startswith("docker.io/")
    assert image["newTag"] == "kind"


def test_kind_manifests_contain_runtime_and_failure_fixture_objects() -> None:
    objects: set[tuple[str, str]] = set()
    for path in KIND.glob("*.yaml"):
        for document in _documents(path):
            kind = document.get("kind")
            metadata = document.get("metadata")
            if isinstance(kind, str) and isinstance(metadata, dict):
                name = metadata.get("name")
                if isinstance(name, str):
                    objects.add((kind, name))

    assert ("Deployment", "trpc-gateway") in objects
    assert ("StatefulSet", "kind-postgres") in objects
    assert ("StatefulSet", "kind-redis") in objects
    assert ("StatefulSet", "kind-fake-provider") in objects
    assert ("StatefulSet", "kind-fake-im") in objects
    assert ("Job", "trpc-schema-migration") not in objects


def test_kind_workloads_do_not_use_host_network_or_privileged_containers() -> None:
    for path in KIND.glob("*.yaml"):
        for document in _documents(path):
            spec = document.get("spec")
            if not isinstance(spec, dict):
                continue
            template = spec.get("template")
            pod_spec = template.get("spec") if isinstance(template, dict) else None
            if not isinstance(pod_spec, dict):
                continue
            assert pod_spec.get("hostNetwork") is not True
            containers = pod_spec.get("containers", [])
            for container in containers:
                if isinstance(container, dict):
                    security = container.get("securityContext", {})
                    assert not isinstance(security, dict) or security.get("privileged") is not True


def test_kind_workers_are_forced_across_three_nodes() -> None:
    worker = next(
        document
        for document in _documents(KIND / "kind-replicas-patch.yaml")
        if document.get("kind") == "Deployment"
        and document.get("metadata", {}).get("name") == "trpc-worker"
    )
    pod_spec = worker["spec"]["template"]["spec"]
    required = pod_spec["affinity"]["podAntiAffinity"][
        "requiredDuringSchedulingIgnoredDuringExecution"
    ]
    spread = pod_spec["topologySpreadConstraints"]

    assert worker["spec"]["replicas"] == 3
    assert pod_spec["nodeSelector"] == {"trpc.io/node-role": "agent-worker"}
    assert required[0]["topologyKey"] == "kubernetes.io/hostname"
    assert spread[0]["whenUnsatisfiable"] == "DoNotSchedule"


def test_kind_gateway_is_forced_across_two_worker_nodes() -> None:
    gateway = next(
        document
        for document in _documents(KIND / "kind-replicas-patch.yaml")
        if document.get("kind") == "Deployment"
        and document.get("metadata", {}).get("name") == "trpc-gateway"
    )
    pod_spec = gateway["spec"]["template"]["spec"]
    gateway_selector = {
        "app.kubernetes.io/name": "trpc-gateway",
        "app.kubernetes.io/part-of": "trpc-agent-service",
    }
    required = pod_spec["affinity"]["podAntiAffinity"][
        "requiredDuringSchedulingIgnoredDuringExecution"
    ]
    spread = pod_spec["topologySpreadConstraints"]

    assert gateway["spec"]["replicas"] == 2
    assert pod_spec["nodeSelector"] == {
        "trpc.io/node-role": "agent-worker",
        "trpc.io/kind-pool": "gateway",
    }
    assert required == [
        {
            "labelSelector": {"matchLabels": gateway_selector},
            "topologyKey": "kubernetes.io/hostname",
        }
    ]
    assert spread == [
        {
            "maxSkew": 1,
            "topologyKey": "kubernetes.io/hostname",
            "whenUnsatisfiable": "DoNotSchedule",
            "labelSelector": {"matchLabels": gateway_selector},
        }
    ]


def test_kind_gateway_and_worker_rollouts_avoid_hard_spread_deadlock() -> None:
    kubectl = shutil.which("kubectl")
    assert kubectl is not None
    # The executable and arguments are fixed to the local kind overlay.
    rendered = subprocess.run(  # noqa: S603
        [kubectl, "kustomize", str(KIND)],
        check=True,
        capture_output=True,
        text=True,
    )
    deployments = {
        document["metadata"]["name"]: document
        for document in yaml.safe_load_all(rendered.stdout)
        if isinstance(document, dict)
        and document.get("kind") == "Deployment"
        and isinstance(document.get("metadata"), dict)
        and isinstance(document["metadata"].get("name"), str)
    }

    for name in ("trpc-gateway", "trpc-worker"):
        strategy = deployments[name]["spec"]["strategy"]
        assert strategy["type"] == "RollingUpdate"
        assert strategy["rollingUpdate"] == {
            "maxSurge": 0,
            "maxUnavailable": 1,
        }


def test_kind_shared_backends_are_required_anti_affine_with_gateway() -> None:
    gateway_selector = {
        "app.kubernetes.io/name": "trpc-gateway",
        "app.kubernetes.io/part-of": "trpc-agent-service",
    }
    workloads = (
        ("kind-postgres.yaml", "kind-postgres"),
        ("kind-redis.yaml", "kind-redis"),
        ("kind-fake-services.yaml", "kind-fake-provider"),
    )
    for filename, name in workloads:
        workload = next(
            document
            for document in _documents(KIND / filename)
            if document.get("kind") == "StatefulSet"
            and document.get("metadata", {}).get("name") == name
        )
        pod_spec = workload["spec"]["template"]["spec"]
        required = pod_spec["affinity"]["podAntiAffinity"][
            "requiredDuringSchedulingIgnoredDuringExecution"
        ]
        assert pod_spec["nodeSelector"] == {
            "trpc.io/node-role": "agent-worker",
            "trpc.io/kind-pool": "support",
        }
        assert required == [
            {
                "labelSelector": {"matchLabels": gateway_selector},
                "topologyKey": "kubernetes.io/hostname",
            }
        ]


def test_kind_support_images_are_pinned_to_registry_manifest_digests() -> None:
    expected = {
        ("kind-postgres.yaml", "postgres"): (
            "pgvector/pgvector@sha256:"
            "ccc6e83d6e35e931dc7c5def2022729d5a6c370318d099181995567ff1fb4d6b"
        ),
        ("kind-redis.yaml", "redis"): (
            "redis@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf"
        ),
        ("kind-fake-services.yaml", "provider"): (
            "python@sha256:b64631e04e4920160c50fbe8d8df828f7f35f06f425cb44aa09bca53e708a35a"
        ),
        ("kind-fake-services.yaml", "im"): (
            "python@sha256:b64631e04e4920160c50fbe8d8df828f7f35f06f425cb44aa09bca53e708a35a"
        ),
    }
    observed: dict[tuple[str, str], str] = {}
    for filename in {filename for filename, _ in expected}:
        for document in _documents(KIND / filename):
            spec = document.get("spec")
            template = spec.get("template") if isinstance(spec, dict) else None
            pod_spec = template.get("spec") if isinstance(template, dict) else None
            containers = pod_spec.get("containers", []) if isinstance(pod_spec, dict) else []
            for container in containers:
                if not isinstance(container, dict):
                    continue
                name = container.get("name")
                image = container.get("image")
                if isinstance(name, str) and isinstance(image, str):
                    observed[(filename, name)] = image

    assert observed == expected
    assert all(re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", image) for image in observed.values())


def test_kind_postgres_init_covers_all_migration_authority_roles() -> None:
    document = _documents(KIND / "kind-postgres.yaml")[0]
    data = document.get("data")
    assert isinstance(data, dict)
    sql = data.get("00-roles.sql")
    assert isinstance(sql, str)

    required_roles = {
        "trpc_migration",
        "trpc_runtime",
        "trpc_worker",
        "trpc_metrics",
        "trpc_hpa",
        "trpc_cell_reconciler",
        "trpc_evolution_authority",
        "trpc_tool_reconciler",
        "trpc_scheduler",
        "trpc_cell_executor",
    }
    missing = {role for role in required_roles if f"rolname = '{role}'" not in sql}
    assert not missing


def test_kind_worker_secret_publishes_secret_references() -> None:
    worker: dict[str, object] | None = None
    for document in _documents(KIND / "kind-secrets.yaml"):
        metadata = document.get("metadata")
        if isinstance(metadata, dict) and metadata.get("name") == "trpc-worker-secrets":
            worker = document
            break
    assert worker is not None
    values = worker.get("stringData")
    assert isinstance(values, dict)
    assert values["TRPC_SERVICE_WORKER_DATABASE_DSN_REF"] == (
        "env://TRPC_SERVICE_WORKER_DATABASE_DSN"
    )
    assert values["TRPC_SERVICE_WORKER_DATABASE_PASSWORD_REF"] == (
        "env://TRPC_SERVICE_WORKER_DATABASE_PASSWORD"
    )


def test_kind_runtime_secret_uses_exactly_32_byte_emergency_key() -> None:
    service: dict[str, object] | None = None
    for document in _documents(KIND / "kind-secrets.yaml"):
        metadata = document.get("metadata")
        if isinstance(metadata, dict) and metadata.get("name") == "trpc-service-secrets":
            service = document
            break
    assert service is not None
    values = service.get("stringData")
    assert isinstance(values, dict)
    emergency_key = values.get("TRPC_SERVICE_EMERGENCY_QUEUE_KEY")
    assert isinstance(emergency_key, str)
    assert len(emergency_key.encode("utf-8")) == 32


def test_kind_feishu_fixture_uses_registered_environment_references() -> None:
    secret_text = (KIND / "kind-secrets.yaml").read_text(encoding="utf-8")
    config_text = (KIND / "kind-config-patch.yaml").read_text(encoding="utf-8")

    assert "TRPC_FEISHU_KIND_VERIFICATION_TOKEN: kind-feishu-verification-token" in secret_text
    assert "TRPC_FEISHU_KIND_ENCRYPT_KEY: kind-feishu-encrypt-key" in secret_text
    assert (
        "TRPC_FEISHU_VERIFICATION_TOKEN_REF: env://TRPC_FEISHU_KIND_VERIFICATION_TOKEN"
        in secret_text
    )
    assert "TRPC_FEISHU_ENCRYPT_KEY_REF: env://TRPC_FEISHU_KIND_ENCRYPT_KEY" in secret_text
    assert "TRPC_SERVICE_TENANT_SECRET_ENV_NAMES:" in config_text
    assert "TRPC_FEISHU_KIND_VERIFICATION_TOKEN" in config_text
    assert "TRPC_FEISHU_KIND_ENCRYPT_KEY" in config_text
    assert "literal://" not in secret_text


def test_kind_probe_secrets_are_split_by_authority() -> None:
    secrets: dict[str, dict[str, object]] = {}
    for document in _documents(KIND / "kind-secrets.yaml"):
        metadata = document.get("metadata")
        values = document.get("stringData")
        if (
            isinstance(metadata, dict)
            and isinstance(metadata.get("name"), str)
            and isinstance(values, dict)
        ):
            secrets[metadata["name"]] = values

    assert set(secrets["trpc-tool-reconciler-secrets"]) == {"TRPC_KIND_TOOL_RECONCILER_DSN"}
    assert set(secrets["trpc-evolution-authority-secrets"]) == {"TRPC_KIND_EVOLUTION_DATABASE_DSN"}
    assert set(secrets["trpc-redis-probe-secrets"]) == {"TRPC_SERVICE_REDIS_URL"}
    assert "trpc-probe-secrets" not in secrets

    authority_keys = {
        "TRPC_KIND_TOOL_RECONCILER_DSN",
        "TRPC_KIND_EVOLUTION_DATABASE_DSN",
    }
    for name, values in secrets.items():
        if name not in {
            "trpc-tool-reconciler-secrets",
            "trpc-evolution-authority-secrets",
        }:
            assert authority_keys.isdisjoint(values)
    assert all("literal://" not in str(values) for values in secrets.values())


def test_kind_acceptance_driver_has_postgres_redis_ingress_and_egress() -> None:
    policies = _documents(KIND / "kind-network-policy.yaml")
    driver_policy: dict[str, object] | None = None
    datastore_policy: dict[str, object] | None = None
    for document in policies:
        metadata = document.get("metadata")
        if not isinstance(metadata, dict):
            continue
        if metadata.get("name") == "kind-allow-driver-to-support":
            driver_policy = document
        if metadata.get("name") == "kind-allow-datastore-ingress":
            datastore_policy = document
    assert driver_policy is not None
    assert datastore_policy is not None

    driver_spec = driver_policy.get("spec")
    datastore_spec = datastore_policy.get("spec")
    assert isinstance(driver_spec, dict)
    assert isinstance(datastore_spec, dict)
    driver_egress = driver_spec.get("egress")
    datastore_ingress = datastore_spec.get("ingress")
    assert isinstance(driver_egress, list)
    assert isinstance(datastore_ingress, list)
    egress_text = str(driver_egress)
    ingress_text = str(datastore_ingress)
    assert "kind-postgres" in egress_text and "5432" in egress_text
    assert "kind-redis" in egress_text and "6379" in egress_text
    assert "trpc-gateway" in egress_text and "8080" in egress_text
    assert "acceptance-driver" in ingress_text


def test_kind_fake_provider_supports_body_response_loss_injection() -> None:
    documents = _documents(KIND / "kind-fake-services.yaml")
    provider: dict[str, object] | None = None
    for document in documents:
        metadata = document.get("metadata")
        if isinstance(metadata, dict) and metadata.get("name") == "kind-fake-provider-code":
            provider = document
            break
    assert provider is not None
    data = provider.get("data")
    assert isinstance(data, dict)
    code = data.get("server.py")
    assert isinstance(code, str)
    assert 'payload.get("simulate_timeout") is True' in code
    assert 'self.headers.get("X-Simulate-Timeout") == "true"' in code
