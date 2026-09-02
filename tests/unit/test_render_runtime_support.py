"""Focused tests for deterministic runtime-support manifest rendering."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from scripts import render_runtime_support as renderer

POSTGRES_IMAGE = "postgres:16@sha256:" + "a" * 64
REDIS_IMAGE = "redis:7@sha256:" + "b" * 64


def _support() -> SimpleNamespace:
    return SimpleNamespace(
        data_node="ack-data-0",
        postgres_image=POSTGRES_IMAGE,
        redis_image=REDIS_IMAGE,
        postgres_host_path="/srv/trpc/postgres",
        redis_host_path="/srv/trpc/redis",
        minio_host_path="/srv/trpc/minio",
    )


def _provider_config(namespace: str) -> SimpleNamespace:
    support = _support()
    support.namespace = namespace
    support.minio_image = "registry.example/minio@sha256:" + "c" * 64
    support.minio_client_image = "registry.example/mc@sha256:" + "d" * 64
    support.prometheus_image = "registry.example/prometheus@sha256:" + "e" * 64
    support.prometheus_adapter_image = "registry.example/adapter@sha256:" + "f" * 64
    support.external_metric_compatibility_namespaces = ()
    return SimpleNamespace(
        support=support,
        image_pull_secret="runtime-pull",
        performance=SimpleNamespace(namespace="trpc-service"),
    )


def _write_templates(tmp_path: Path) -> tuple[Path, Path, str, str]:
    support_template = tmp_path / "ack-runtime-support.yaml"
    minio_template = tmp_path / "ack-runtime-minio.yaml"
    support_text = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
spec:
  template:
    spec:
      nodeSelector:
        kubernetes.io/hostname: old-node
        zone: data
      containers:
        - name: postgres
          image: postgres:15
        - name: metrics-sidecar
          image: metrics:1
      initContainers:
        - name: postgres-bootstrap
          image: postgres:15
      volumes:
        - name: postgres-data
          emptyDir: {}
        - name: postgres-config
          configMap:
            name: postgres-config
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
spec:
  template:
    spec:
      containers:
        - name: redis
          image: redis:7
      volumes:
        - name: redis-data
          persistentVolumeClaim:
            claimName: redis
"""
    minio_text = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: minio
spec:
  template:
    spec:
      containers:
        - name: minio
          image: minio:latest
      volumes:
        - name: minio-storage
          emptyDir: {}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: untouched
data:
  node: old-node
"""
    support_template.write_text(support_text, encoding="utf-8")
    minio_template.write_text(minio_text, encoding="utf-8")
    return support_template, minio_template, support_text, minio_text


def test_render_updates_nodes_images_and_data_volumes_without_mutating_templates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    support_template, minio_template, support_text, minio_text = _write_templates(tmp_path)
    monkeypatch.setattr(
        renderer,
        "_load_runtime_gate_config",
        lambda _path: SimpleNamespace(support=_support()),
    )

    output_dir = tmp_path / "rendered"
    output_paths = renderer.render_runtime_support(
        tmp_path / "runtime-gate.yaml",
        support_template=support_template,
        minio_template=minio_template,
        output_dir=output_dir,
    )

    assert output_paths == (
        output_dir / "ack-runtime-support.yaml",
        output_dir / "ack-runtime-minio.yaml",
    )
    assert support_template.read_text(encoding="utf-8") == support_text
    assert minio_template.read_text(encoding="utf-8") == minio_text

    rendered_support = list(yaml.safe_load_all(output_paths[0].read_text(encoding="utf-8")))
    rendered_minio = list(yaml.safe_load_all(output_paths[1].read_text(encoding="utf-8")))
    postgres = rendered_support[0]["spec"]["template"]["spec"]
    redis = rendered_support[1]["spec"]["template"]["spec"]
    minio = rendered_minio[0]["spec"]["template"]["spec"]

    assert postgres["nodeSelector"] == {
        "kubernetes.io/hostname": "ack-data-0",
        "zone": "data",
    }
    assert postgres["containers"][0]["image"] == POSTGRES_IMAGE
    assert postgres["containers"][1]["image"] == "metrics:1"
    assert postgres["initContainers"][0]["image"] == POSTGRES_IMAGE
    assert postgres["volumes"] == [
        {
            "name": "postgres-data",
            "hostPath": {
                "path": "/srv/trpc/postgres",
                "type": "DirectoryOrCreate",
            },
        },
        {"name": "postgres-config", "configMap": {"name": "postgres-config"}},
    ]
    assert redis["nodeSelector"] == {"kubernetes.io/hostname": "ack-data-0"}
    assert redis["containers"][0]["image"] == REDIS_IMAGE
    assert redis["volumes"][0] == {
        "name": "redis-data",
        "hostPath": {"path": "/srv/trpc/redis", "type": "DirectoryOrCreate"},
    }
    assert minio["nodeSelector"] == {"kubernetes.io/hostname": "ack-data-0"}
    assert minio["volumes"][0] == {
        "name": "minio-storage",
        "hostPath": {"path": "/srv/trpc/minio", "type": "DirectoryOrCreate"},
    }
    assert rendered_minio[1]["data"]["node"] == "old-node"


def test_redis_without_a_volume_gets_a_data_host_path() -> None:
    documents = [
        {
            "kind": "Deployment",
            "metadata": {"name": "redis"},
            "spec": {"template": {"spec": {"containers": [{"name": "redis", "image": "redis:7"}]}}},
        }
    ]

    rendered = renderer.render_documents(documents, _support())
    pod_spec = rendered[0]["spec"]["template"]["spec"]
    assert pod_spec["volumes"] == [
        {
            "name": "data",
            "hostPath": {"path": "/srv/trpc/redis", "type": "DirectoryOrCreate"},
        }
    ]
    assert pod_spec["containers"][0]["volumeMounts"] == [{"name": "data", "mountPath": "/data"}]


def test_ack_support_template_has_explicit_backend_ingress_sources() -> None:
    documents = renderer._read_documents(renderer.DEFAULT_SUPPORT_TEMPLATE)
    policies = {
        document["metadata"]["name"]: document
        for document in documents
        if isinstance(document, dict) and document.get("kind") == "NetworkPolicy"
    }

    assert set(policies) == {
        "trpc-support-postgres-ingress",
        "trpc-support-redis-ingress",
    }

    bootstrap = next(
        document
        for document in documents
        if isinstance(document, dict)
        and document.get("kind") == "Job"
        and document.get("metadata", {}).get("name") == "postgres-bootstrap"
    )
    bootstrap_script = bootstrap["spec"]["template"]["spec"]["containers"][0]["args"][0]
    assert "\n SQL\n" not in bootstrap_script
    assert bootstrap_script.count("\nSQL\n") == 2

    redis = next(
        document
        for document in documents
        if isinstance(document, dict)
        and document.get("kind") == "Deployment"
        and document.get("metadata", {}).get("name") == "redis"
    )
    redis_capabilities = redis["spec"]["template"]["spec"]["containers"][0]["securityContext"][
        "capabilities"
    ]
    assert redis_capabilities["drop"] == ["ALL"]
    assert set(redis_capabilities["add"]) == {"CHOWN", "SETGID", "SETUID"}
    expected_namespaces = [
        {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "trpc-cell-fabric"}}},
        {
            "namespaceSelector": {
                "matchLabels": {"kubernetes.io/metadata.name": "trpc-runtime-support"}
            }
        },
        {
            "namespaceSelector": {
                "matchLabels": {"kubernetes.io/metadata.name": "trpc-runtime-driver"}
            }
        },
        {
            "namespaceSelector": {
                "matchLabels": {"trpc.io/managed-by": "trpc-kubernetes-runtime-gate"}
            }
        },
    ]
    expected = {
        "trpc-support-postgres-ingress": ("trpc-runtime-postgres", 5432),
        "trpc-support-redis-ingress": ("trpc-runtime-redis", 6379),
    }
    for name, (pod_label, port) in expected.items():
        policy = policies[name]
        assert policy["metadata"]["namespace"] == "trpc-runtime-support"
        assert policy["spec"] == {
            "podSelector": {"matchLabels": {"app": pod_label}},
            "policyTypes": ["Ingress"],
            "ingress": [
                {
                    "from": expected_namespaces,
                    "ports": [{"protocol": "TCP", "port": port}],
                }
            ],
        }
    assert "trpc-service" not in json.dumps(policies, sort_keys=True)

    support = _support()
    support.namespace = "trpc-cell-fabric-support"
    rendered = renderer.render_documents(documents, support)
    rendered_policies = {
        document["metadata"]["name"]: document
        for document in rendered
        if isinstance(document, dict) and document.get("kind") == "NetworkPolicy"
    }
    for policy in rendered_policies.values():
        assert policy["metadata"]["namespace"] == "trpc-cell-fabric-support"
        sources = policy["spec"]["ingress"][0]["from"]
        assert sources[1] == {
            "namespaceSelector": {
                "matchLabels": {"kubernetes.io/metadata.name": "trpc-cell-fabric-support"}
            }
        }
        assert sources[0] == expected_namespaces[0]
        assert sources[2:] == expected_namespaces[2:]


def test_provider_names_stage_cutover_and_original_scrape_are_isolated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    default_dir = tmp_path / "default"
    monkeypatch.setattr(
        renderer,
        "_load_runtime_gate_config",
        lambda _path: _provider_config("trpc-runtime-support"),
    )
    default_support, _ = renderer.render_runtime_support(
        tmp_path / "runtime-gate.yaml",
        output_dir=default_dir,
        mode="full",
    )

    custom_namespace = "trpc-cell-fabric-support"
    stage_dir = tmp_path / "stage"
    monkeypatch.setattr(
        renderer,
        "_load_runtime_gate_config",
        lambda _path: _provider_config(custom_namespace),
    )
    staged_support, _ = renderer.render_runtime_support(
        tmp_path / "runtime-gate.yaml",
        output_dir=stage_dir,
        mode="stage",
    )

    def documents(path: Path) -> list[dict[str, object]]:
        return [
            document
            for document in yaml.safe_load_all(path.read_text(encoding="utf-8"))
            if isinstance(document, dict)
        ]

    provider_kinds = {"ClusterRole", "ClusterRoleBinding", "RoleBinding"}
    default_documents = documents(default_support)
    stage_documents = documents(staged_support)
    default_resources = [
        document
        for document in default_documents
        if document.get("kind") in provider_kinds
        and document.get("metadata", {}).get("name", "").startswith("trpc-runtime-prometheus")
    ]
    stage_resources = [
        document
        for document in stage_documents
        if document.get("kind") in provider_kinds
        and document.get("metadata", {}).get("labels", {}).get(renderer._PROVIDER_LABEL_KEY)
        == renderer._PROVIDER_LABEL_VALUE
    ]
    default_names = {document["metadata"]["name"] for document in default_resources}
    stage_names = {document["metadata"]["name"] for document in stage_resources}
    assert default_names.isdisjoint(stage_names)
    assert len(stage_resources) == len(renderer._PROVIDER_RESOURCE_BASES)
    assert all(
        len(name) <= 63 and renderer._NAMESPACE_RE.fullmatch(name) is not None
        for name in stage_names
    )
    assert stage_names == {
        renderer._provider_resource_name(custom_namespace, base_name)
        for _kind_name, base_name in renderer._PROVIDER_RESOURCE_BASES
    }
    for resource in stage_resources:
        labels = resource["metadata"]["labels"]
        assert labels["app.kubernetes.io/managed-by"] == renderer._PROVIDER_MANAGED_BY
        assert labels[renderer._PROVIDER_LABEL_KEY] == renderer._PROVIDER_LABEL_VALUE
        assert labels[renderer._PROVIDER_NAMESPACE_LABEL_KEY] == custom_namespace
    discovery_binding = next(
        resource
        for resource in stage_resources
        if resource["metadata"]["name"]
        == renderer._provider_resource_name(custom_namespace, "trpc-runtime-prometheus-discovery")
        and resource["kind"] == "ClusterRoleBinding"
    )
    assert discovery_binding["roleRef"]["name"] == renderer._provider_resource_name(
        custom_namespace, "trpc-runtime-prometheus-discovery"
    )

    assert all(document.get("kind") != "APIService" for document in stage_documents)
    cutover_documents = documents(stage_dir / "runtime-support-cutover.yaml")
    assert len(cutover_documents) == 1
    cutover = cutover_documents[0]
    assert cutover["kind"] == "APIService"
    assert cutover["metadata"]["name"] == "v1beta1.external.metrics.k8s.io"
    assert cutover["spec"]["service"] == {
        "name": "prometheus-adapter",
        "namespace": custom_namespace,
        "port": 443,
    }
    default_api_services = [
        document for document in default_documents if document.get("kind") == "APIService"
    ]
    assert len(default_api_services) == 1
    assert all(document.get("kind") != "APIService" for document in stage_documents)
    config_map = next(
        document
        for document in stage_documents
        if document.get("kind") == "ConfigMap"
        and document.get("metadata", {}).get("name") == "prometheus-config"
    )
    prometheus = yaml.safe_load(config_map["data"]["prometheus.yml"])
    production = next(
        job
        for job in prometheus["scrape_configs"]
        if job["job_name"] == "trpc-session-ready-backlog-production"
    )
    assert production["static_configs"][0]["targets"] == [
        "trpc-backlog-exporter.trpc-service.svc:9100"
    ]


def test_render_rebinds_support_namespace_and_preserves_external_namespace() -> None:
    support = _support()
    support.namespace = "cell-runtime-support"
    documents = [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "trpc-runtime-support"},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "postgres", "namespace": "trpc-runtime-support"},
            "spec": {"template": {"metadata": {"labels": {"component": "postgres"}}, "spec": {}}},
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "auth-reader", "namespace": "kube-system"},
            "subjects": [
                {"kind": "ServiceAccount", "name": "adapter", "namespace": "trpc-runtime-support"},
                {"kind": "ServiceAccount", "name": "system", "namespace": "kube-system"},
            ],
        },
        {
            "apiVersion": "apiregistration.k8s.io/v1",
            "kind": "APIService",
            "metadata": {"name": "v1beta1.external.metrics.k8s.io"},
            "spec": {
                "service": {"name": "prometheus-adapter", "namespace": "trpc-runtime-support"}
            },
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "allow-support"},
            "spec": {
                "ingress": [
                    {
                        "from": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": "trpc-runtime-support"
                                    }
                                }
                            },
                            {
                                "namespaceSelector": {
                                    "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                                }
                            },
                        ]
                    }
                ]
            },
        },
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "connection"},
            "data": {
                "url": "http://postgres.trpc-runtime-support.svc.cluster.local:5432",
                "external": "kube-system.svc.cluster.local",
            },
        },
    ]

    rendered = renderer.render_documents(documents, support)

    assert documents[0]["metadata"]["name"] == "trpc-runtime-support"
    assert rendered[0]["metadata"]["name"] == "cell-runtime-support"
    assert rendered[1]["metadata"]["namespace"] == "cell-runtime-support"
    assert "namespace" not in rendered[1]["spec"]["template"]["metadata"]
    assert rendered[2]["metadata"]["namespace"] == "kube-system"
    assert [subject["namespace"] for subject in rendered[2]["subjects"]] == [
        "cell-runtime-support",
        "kube-system",
    ]
    assert rendered[3]["spec"]["service"]["namespace"] == "cell-runtime-support"
    selectors = rendered[4]["spec"]["ingress"][0]["from"]
    assert selectors[0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"] == (
        "cell-runtime-support"
    )
    assert selectors[1]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"] == (
        "kube-system"
    )
    assert (
        rendered[5]["data"]["url"] == "http://postgres.cell-runtime-support.svc.cluster.local:5432"
    )
    assert rendered[5]["data"]["external"] == "kube-system.svc.cluster.local"


def test_legacy_synthetic_backlog_resources_are_removed_from_nested_lists() -> None:
    documents = [
        {
            "apiVersion": "v1",
            "kind": "List",
            "items": [
                {"kind": "ConfigMap", "metadata": {"name": "backlog-metric-source"}},
                {"kind": "Service", "metadata": {"name": "backlog-metric-source"}},
                {"kind": "ServiceAccount", "metadata": {"name": "backlog-observer"}},
                {
                    "kind": "ClusterRole",
                    "metadata": {"name": "trpc-runtime-backlog-observer"},
                },
                {"kind": "ConfigMap", "metadata": {"name": "keep-me"}},
            ],
        },
        {"kind": "Deployment", "metadata": {"name": "backlog-metric-source"}},
        {"kind": "Service", "metadata": {"name": "keep-me"}},
    ]

    renderer._drop_synthetic_backlog_resources(documents)

    assert [item["metadata"]["name"] for item in documents[0]["items"]] == ["keep-me"]
    assert [item["metadata"]["name"] for item in documents[1:]] == ["keep-me"]


def test_render_binds_support_provider_images_pull_secret_and_prometheus_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    support_template = tmp_path / "support.yaml"
    minio_template = tmp_path / "minio.yaml"
    support_template.write_text(
        """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backlog-metric-source
spec:
  template:
    spec:
      imagePullSecrets:
        - name: ghcr-pull
      containers:
        - name: source
          image: quay.io/example/source:latest
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
spec:
  template:
    spec:
      imagePullSecrets:
        - name: ghcr-pull
      containers:
        - name: prometheus
          image: quay.io/example/prometheus:latest
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus-adapter
spec:
  template:
    spec:
      imagePullSecrets:
        - name: ghcr-pull
      containers:
        - name: adapter
          image: quay.io/example/adapter:latest
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
data:
  prometheus.yml: |
    global:
      scrape_interval: 5s
    scrape_configs:
      - job_name: trpc-runtime-backlog
        static_configs:
          - targets: [backlog-metric-source:9100]
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-adapter-config
data:
  config.yaml: |
    externalRules:
      - seriesQuery: 'trpc_session_ready_backlog{namespace!=""}'
        resources:
          overrides:
            namespace:
              resource: namespace
        name:
          matches: '^trpc_session_ready_backlog$'
          as: trpc_session_ready_backlog
        metricsQuery: 'max(<<.Series>>{<<.LabelMatchers>>}) by (namespace)'
""",
        encoding="utf-8",
    )
    minio_template.write_text(
        """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: minio
spec:
  template:
    spec:
      imagePullSecrets:
        - name: ghcr-pull
      initContainers:
        - name: prepare-data
          image: quay.io/example/minio:latest
      containers:
        - name: minio
          image: quay.io/example/minio:latest
---
apiVersion: batch/v1
kind: Job
metadata:
  name: minio-bucket-bootstrap
spec:
  template:
    spec:
      imagePullSecrets:
        - name: ghcr-pull
      containers:
        - name: bootstrap
          image: quay.io/example/mc:latest
""",
        encoding="utf-8",
    )
    support = _support()
    support.minio_image = "registry.example/minio@sha256:" + "c" * 64
    support.minio_client_image = "registry.example/mc@sha256:" + "d" * 64
    support.prometheus_image = "registry.example/prometheus@sha256:" + "e" * 64
    support.prometheus_adapter_image = "registry.example/adapter@sha256:" + "f" * 64
    support.external_metric_compatibility_namespaces = ("trpc-service-legacy",)
    config = SimpleNamespace(
        support=support,
        image_pull_secret="runtime-pull",
        performance=SimpleNamespace(namespace="trpc-service"),
        resolved_image_references=lambda: {
            "initial": "registry.example/trpc-agent-service@sha256:" + "a" * 64
        },
    )
    monkeypatch.setattr(renderer, "_load_runtime_gate_config", lambda _path: config)

    support_output, minio_output = renderer.render_runtime_support(
        tmp_path / "runtime-gate.yaml",
        support_template=support_template,
        minio_template=minio_template,
        output_dir=tmp_path / "rendered",
    )
    rendered_support = list(yaml.safe_load_all(support_output.read_text(encoding="utf-8")))
    rendered_minio = list(yaml.safe_load_all(minio_output.read_text(encoding="utf-8")))

    deployment_images = {
        document["metadata"]["name"]: renderer._pod_specs(document)[0]["containers"][0]["image"]
        for document in rendered_support + rendered_minio
        if isinstance(document, dict) and document.get("kind") == "Deployment"
    }
    assert deployment_images == {
        "prometheus": "registry.example/prometheus@sha256:" + "e" * 64,
        "prometheus-adapter": "registry.example/adapter@sha256:" + "f" * 64,
        "minio": "registry.example/minio@sha256:" + "c" * 64,
    }
    minio_pod = next(
        renderer._pod_specs(document)[0]
        for document in rendered_minio
        if isinstance(document, dict)
        and document.get("kind") == "Deployment"
        and document.get("metadata", {}).get("name") == "minio"
    )
    assert {container["image"] for container in minio_pod["initContainers"]} == {
        "registry.example/minio@sha256:" + "c" * 64
    }
    bootstrap = next(
        renderer._pod_specs(document)[0]
        for document in rendered_minio
        if isinstance(document, dict)
        and document.get("kind") == "Job"
        and document.get("metadata", {}).get("name") == "minio-bucket-bootstrap"
    )
    assert bootstrap["containers"][0]["image"] == "registry.example/mc@sha256:" + "d" * 64
    for document in rendered_support + rendered_minio:
        for pod_spec in renderer._pod_specs(document):
            assert pod_spec["imagePullSecrets"] == [{"name": "runtime-pull"}]

    config_map = next(
        document
        for document in rendered_support
        if isinstance(document, dict)
        and document.get("kind") == "ConfigMap"
        and document.get("metadata", {}).get("name") == "prometheus-config"
    )
    prometheus = yaml.safe_load(config_map["data"]["prometheus.yml"])
    production_jobs = [
        job
        for job in prometheus["scrape_configs"]
        if job.get("job_name") == "trpc-session-ready-backlog-production"
    ]
    assert production_jobs == [
        {
            "job_name": "trpc-session-ready-backlog-production",
            "static_configs": [
                {
                    "targets": [
                        "trpc-backlog-exporter.trpc-service.svc:9100",
                        "trpc-backlog-exporter.trpc-service-legacy.svc:9100",
                    ]
                }
            ],
            "metric_relabel_configs": [
                {
                    "source_labels": ["__name__"],
                    "regex": "^trpc_session_ready_backlog$",
                    "action": "keep",
                }
            ],
        }
    ]
    assert all(
        "backlog-metric-source" not in json.dumps(document, sort_keys=True)
        for document in rendered_support
    )
    assert not any(
        document.get("metadata", {}).get("name") == "backlog-metric-source"
        for document in rendered_support
        if isinstance(document, dict)
    )
    dynamic = next(
        job
        for job in prometheus["scrape_configs"]
        if job["job_name"] == "trpc-runtime-gate-backlog"
    )
    assert dynamic["kubernetes_sd_configs"] == [{"role": "endpoints"}]
    relabels = dynamic["relabel_configs"]
    assert {
        "source_labels": ["__meta_kubernetes_namespace"],
        "regex": "^trpc-runtime-gate-[0-9a-f]{10}$",
        "action": "keep",
    } in relabels
    assert {
        "source_labels": ["__meta_kubernetes_service_name"],
        "regex": "^trpc-backlog-exporter$",
        "action": "keep",
    } in relabels
    assert {
        "source_labels": ["__meta_kubernetes_service_label_trpc_io_managed_by"],
        "regex": "^trpc-kubernetes-runtime-gate$",
        "action": "keep",
    } in relabels
    assert {
        "source_labels": ["__meta_kubernetes_service_label_trpc_io_run_nonce"],
        "regex": "^[0-9a-f]{32}$",
        "action": "keep",
    } in relabels
    assert {
        "source_labels": ["__meta_kubernetes_service_label_trpc_io_cluster_fingerprint"],
        "regex": "^[0-9a-f]{63}$",
        "action": "keep",
    } in relabels
    assert dynamic["metric_relabel_configs"] == [
        {
            "source_labels": ["__name__"],
            "regex": "^trpc_session_ready_backlog$",
            "action": "keep",
        }
    ]
    assert not any(
        "replacement" in relabel for relabel in relabels + dynamic["metric_relabel_configs"]
    )
    prometheus_sa = next(
        document
        for document in rendered_support
        if isinstance(document, dict)
        and document.get("kind") == "ServiceAccount"
        and document.get("metadata", {}).get("name") == "prometheus"
    )
    assert prometheus_sa["metadata"]["namespace"] == "trpc-runtime-support"
    discovery_role = next(
        document
        for document in rendered_support
        if isinstance(document, dict)
        and document.get("kind") == "ClusterRole"
        and document.get("metadata", {}).get("name") == "trpc-runtime-prometheus-discovery"
    )
    assert discovery_role["rules"] == [
        {
            "apiGroups": [""],
            "resources": ["namespaces", "services", "endpoints", "pods"],
            "verbs": ["get", "list", "watch"],
        }
    ]
    assert not any(
        resource in discovery_role["rules"][0]["resources"] for resource in ("jobs", "secrets")
    )
    prometheus_deployment = next(
        document
        for document in rendered_support
        if isinstance(document, dict)
        and document.get("kind") == "Deployment"
        and document.get("metadata", {}).get("name") == "prometheus"
    )
    assert renderer._pod_specs(prometheus_deployment)[0]["serviceAccountName"] == "prometheus"
    assert renderer._pod_specs(prometheus_deployment)[0]["automountServiceAccountToken"] is True
    adapter_config = next(
        document
        for document in rendered_support
        if isinstance(document, dict)
        and document.get("kind") == "ConfigMap"
        and document.get("metadata", {}).get("name") == "prometheus-adapter-config"
    )
    adapter = yaml.safe_load(adapter_config["data"]["config.yaml"])
    assert (
        adapter["externalRules"][0]["metricsQuery"]
        == "max(<<.Series>>{<<.LabelMatchers>>}) by (namespace)"
    )
    expected_prometheus_hash = hashlib.sha256(
        json.dumps(
            config_map["data"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    expected_adapter_hash = hashlib.sha256(
        json.dumps(
            adapter_config["data"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    prometheus_deployment = next(
        document
        for document in rendered_support
        if isinstance(document, dict)
        and document.get("kind") == "Deployment"
        and document.get("metadata", {}).get("name") == "prometheus"
    )
    adapter_deployment = next(
        document
        for document in rendered_support
        if isinstance(document, dict)
        and document.get("kind") == "Deployment"
        and document.get("metadata", {}).get("name") == "prometheus-adapter"
    )
    assert prometheus_deployment["spec"]["template"]["metadata"]["annotations"] == {
        "trpc.io/prometheus-config-sha256": expected_prometheus_hash
    }
    assert adapter_deployment["spec"]["template"]["metadata"]["annotations"] == {
        "trpc.io/prometheus-adapter-config-sha256": expected_adapter_hash
    }
    assert "ghcr.io" not in support_output.read_text(encoding="utf-8")
    assert "quay.io" not in minio_output.read_text(encoding="utf-8")


def test_missing_support_is_rejected() -> None:
    with pytest.raises(
        renderer.RuntimeSupportRenderError,
        match=r"missing kubernetes\.support",
    ):
        renderer.render_documents([{"kind": "ConfigMap"}], None)


def test_safe_loader_preserves_documents_and_rejects_python_tags(tmp_path: Path) -> None:
    template = tmp_path / "template.yaml"
    template.write_text("---\na: 1\n---\nb: 2\n", encoding="utf-8")
    assert len(renderer._read_documents(template)) == 2

    template.write_text("!!python/object/apply:os.system ['echo unsafe']\n", encoding="utf-8")
    with pytest.raises(renderer.RuntimeSupportRenderError, match="invalid Kubernetes YAML"):
        renderer._read_documents(template)


def test_cli_reports_rendered_paths_without_applying_manifests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    support_template, minio_template, _, _ = _write_templates(tmp_path)
    monkeypatch.setattr(
        renderer,
        "_load_runtime_gate_config",
        lambda _path: SimpleNamespace(support=_support()),
    )
    output_dir = tmp_path / "cli-output"

    assert (
        renderer.main(
            [
                "--config",
                str(tmp_path / "runtime-gate.yaml"),
                "--support-template",
                str(support_template),
                "--minio-template",
                str(minio_template),
                "--output-dir",
                str(output_dir),
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert set(payload) == {"support", "minio"}
    assert Path(payload["support"]).exists()
    assert Path(payload["minio"]).exists()


def test_output_path_guard_prevents_template_overwrite(tmp_path: Path) -> None:
    template = tmp_path / "template.yaml"
    with pytest.raises(renderer.RuntimeSupportRenderError, match="refusing to overwrite"):
        renderer._output_paths(template, tmp_path / "other.yaml", tmp_path)


def test_render_performance_overlay_binds_config_image_and_namespace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workload = SimpleNamespace(
        node_label="trpc-role=workload",
        gateway=SimpleNamespace(replicas=4, database_pool_min_size=5, database_pool_max_size=6),
        worker=SimpleNamespace(
            database_pool_min_size=2,
            database_pool_max_size=8,
            offline_agent_delay_seconds=3.0,
        ),
        outbox=SimpleNamespace(replicas=1, database_pool_min_size=2, database_pool_max_size=4),
        recovery=SimpleNamespace(
            replicas=1, database_pool_min_size=1, database_pool_max_size=2, poll_seconds=1.0
        ),
    )
    performance = SimpleNamespace(
        enabled=True,
        namespace="perf-acceptance",
        worker_concurrency=50,
        max_inflight=64,
        db_pool_size=32,
        workers=4,
        workload=workload,
        environment=lambda: {
            "TRPC_PERF_K8S_ENABLED": "true",
            "TRPC_PERF_K8S_NAMESPACE": "perf-acceptance",
            "TRPC_PERF_K8S_MAX_INFLIGHT": "64",
            "TRPC_PERF_K8S_DB_POOL_SIZE": "32",
            "TRPC_PERF_K8S_WORKERS": "4",
            "TRPC_PERF_K8S_WORKER_CONCURRENCY": "50",
        },
    )
    config = SimpleNamespace(
        support=SimpleNamespace(namespace="cell-runtime-support"),
        node_name="ack-workload-0",
        performance=performance,
        object_store_endpoint="http://minio.trpc-runtime-support.svc.cluster.local:9000",
        object_store_bucket="trpc-artifacts",
        resolved_image_references=lambda: {
            "initial": "elt91uy73y2gh25fs7.xuanyuan.run/zixuan760/trpc-agent-service@sha256:"
            + "a" * 64,
        },
    )
    monkeypatch.setattr(renderer, "_load_runtime_gate_config", lambda _path: config)

    output = renderer.render_performance_overlay(
        tmp_path / "runtime-gate.yaml",
        output_dir=tmp_path / "rendered-performance",
    )

    assert output.name == "rendered-performance"
    overlay = yaml.safe_load((output / "kustomization.yaml").read_text(encoding="utf-8"))
    assert overlay["namespace"] == "perf-acceptance"
    assert overlay["images"][0]["newName"].startswith("elt91uy73y2gh25fs7.xuanyuan.run/")
    assert overlay["images"][0]["digest"] == "sha256:" + "a" * 64
    config_patch = yaml.safe_load(
        (output / "performance-config-patch.yaml").read_text(encoding="utf-8")
    )
    assert config_patch["data"]["TRPC_PERF_K8S_WORKER_CONCURRENCY"] == "50"
    assert config_patch["data"]["TRPC_SERVICE_WORKER_CONCURRENCY"] == "50"
    assert config_patch["data"]["TRPC_SERVICE_ENVIRONMENT"] == "test"
    assert config_patch["data"]["TRPC_SERVICE_CAPTURE_CONTENT"] == "false"
    assert config_patch["data"]["TRPC_SERVICE_OTLP_ENDPOINT"] == ""
    assert config_patch["data"]["TRPC_SERVICE_PROMETHEUS_ENABLED"] == "false"
    assert config_patch["data"]["TRPC_SERVICE_S3_ENDPOINT"] == (
        "http://minio.cell-runtime-support.svc.cluster.local:9000"
    )
    assert config_patch["data"]["TRPC_SERVICE_S3_BUCKET"] == "trpc-artifacts"
    workload_documents = list(
        yaml.safe_load_all((output / "performance-workload-patch.yaml").read_text(encoding="utf-8"))
    )
    workload_by_name = {
        item["metadata"]["name"]: item for item in workload_documents if isinstance(item, dict)
    }
    assert workload_by_name["trpc-gateway"]["spec"]["template"]["spec"]["nodeSelector"] == {
        "kubernetes.io/hostname": "ack-workload-0",
        "trpc-role": "workload",
    }
    assert workload_by_name["trpc-backlog-exporter"]["spec"]["template"]["spec"][
        "nodeSelector"
    ] == {
        "kubernetes.io/hostname": "ack-workload-0",
        "trpc-role": "workload",
    }
    assert workload_by_name["trpc-schema-migration"]["spec"]["template"]["spec"][
        "nodeSelector"
    ] == {
        "kubernetes.io/hostname": "ack-workload-0",
        "trpc-role": "workload",
    }
    assert workload_by_name["trpc-gateway"]["spec"]["template"]["spec"]["containers"][0]["env"] == [
        {"name": "TRPC_SERVICE_DATABASE_POOL_MIN_SIZE", "value": "5"},
        {"name": "TRPC_SERVICE_DATABASE_POOL_MAX_SIZE", "value": "6"},
    ]
    assert workload_by_name["trpc-worker"]["spec"]["template"]["spec"]["containers"][0]["env"][
        -1
    ] == {
        "name": "TRPC_SERVICE_OFFLINE_AGENT_DELAY_SECONDS",
        "value": "3.0",
    }
    replicas = list(
        yaml.safe_load_all((output / "performance-replicas-patch.yaml").read_text(encoding="utf-8"))
    )
    replicas_by_name = {
        item["metadata"]["name"]: item["spec"]["replicas"]
        for item in replicas
        if isinstance(item, dict) and item.get("kind") == "Deployment"
    }
    assert replicas_by_name == {
        "trpc-gateway": 4,
        "trpc-worker": 4,
        "trpc-outbox-dispatcher": 1,
        "trpc-session-recovery": 1,
        "trpc-admin": 0,
        "trpc-artifact-gc": 0,
        "trpc-channel-dispatcher": 0,
        "trpc-post-turn-projector": 0,
        "trpc-wecom-connector": 0,
    }
    assert (output / "performance-network-policy.yaml").is_file()
    assert (output / "base" / "kustomization.yaml").is_file()

    for policy_path in (
        output / "performance-network-policy.yaml",
        output / "base" / "network-policy.yaml",
    ):
        policy_text = policy_path.read_text(encoding="utf-8")
        assert "kubernetes.io/metadata.name: cell-runtime-support" in policy_text
        assert "kubernetes.io/metadata.name: trpc-runtime-support" not in policy_text


def test_render_performance_overlay_requires_explicit_enablement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        renderer,
        "_load_runtime_gate_config",
        lambda _path: SimpleNamespace(performance=SimpleNamespace(enabled=False)),
    )

    with pytest.raises(renderer.RuntimeSupportRenderError, match="enabled must be true"):
        renderer.render_performance_overlay(
            tmp_path / "runtime-gate.yaml",
            output_dir=tmp_path / "rendered-performance",
        )
