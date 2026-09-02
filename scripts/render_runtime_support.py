#!/usr/bin/env python3
"""Render the ACK runtime-support Kubernetes manifests.

The manifests in ``runs/multitenant`` are templates.  This renderer reads the
shared deployment configuration, applies node, image, and node-local storage
values in memory, then writes deterministic YAML to a separate directory.  It
does not invoke ``kubectl`` or modify a template in place.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shutil
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

DEFAULT_SUPPORT_TEMPLATE = Path("runs") / "multitenant" / "ack-runtime-support.yaml"
DEFAULT_MINIO_TEMPLATE = Path("runs") / "multitenant" / "ack-runtime-minio.yaml"
DEFAULT_OUTPUT_DIR = Path("runs") / "multitenant" / "rendered"
DEFAULT_PERFORMANCE_TEMPLATE = Path("deploy") / "kustomize" / "overlays" / "performance"
DEFAULT_PERFORMANCE_OUTPUT_DIR = DEFAULT_OUTPUT_DIR / "performance"
DEFAULT_SUPPORT_NAMESPACE = "trpc-runtime-support"

_REQUIRED_SUPPORT_FIELDS = (
    "data_node",
    "postgres_image",
    "redis_image",
    "postgres_host_path",
    "redis_host_path",
    "minio_host_path",
)
_DATA_VOLUME_KEYS = {
    "csi",
    "emptyDir",
    "ephemeral",
    "hostPath",
    "nfs",
    "persistentVolumeClaim",
}
_NON_DATA_VOLUME_KEYS = {"configMap", "downwardAPI", "projected", "secret"}
_NAMESPACE_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
_SUPPORT_IMAGE_FIELDS = (
    "minio_image",
    "minio_client_image",
    "prometheus_image",
    "prometheus_adapter_image",
)
_SUPPORT_CONFIG_ROLLOUTS = {
    "prometheus": ("prometheus-config", "trpc.io/prometheus-config-sha256"),
    "prometheus-adapter": (
        "prometheus-adapter-config",
        "trpc.io/prometheus-adapter-config-sha256",
    ),
}
_RUNTIME_SUPPORT_MODES = frozenset({"full", "stage"})
_DEFAULT_CUTOVER_OUTPUT_NAME = "runtime-support-cutover.yaml"
_PROVIDER_MANAGED_BY = "trpc-runtime-support-renderer"
_PROVIDER_LABEL_KEY = "trpc.io/provider"
_PROVIDER_LABEL_VALUE = "trpc-runtime-metrics"
_PROVIDER_NAMESPACE_LABEL_KEY = "trpc.io/support-namespace"

# These resources are cluster-scoped (except the auth-reader RoleBinding), so
# their historical fixed names cause two support providers to overwrite one
# another.  The renderer keeps the legacy names in the default namespace for
# clean-cluster compatibility and derives names for every additional provider.
_PROVIDER_RESOURCE_BASES = (
    ("clusterrole", "trpc-runtime-prometheus-discovery"),
    ("clusterrolebinding", "trpc-runtime-prometheus-discovery"),
    ("clusterrole", "trpc-runtime-prometheus-adapter"),
    ("clusterrolebinding", "trpc-runtime-prometheus-adapter"),
    ("clusterrolebinding", "trpc-runtime-prometheus-adapter-auth-delegator"),
    ("rolebinding", "trpc-runtime-prometheus-adapter-auth-reader"),
)

# The old support template used a Job-observation sidecar that manufactured a
# backlog value from the existence of the HPA driver Job.  That signal is not
# a workload metric and must never be present in a production support
# manifest.  Keep the names here so rendering an older template remains
# fail-closed even before the template itself is upgraded.
_SYNTHETIC_BACKLOG_RESOURCES = frozenset(
    {
        ("configmap", "backlog-metric-source"),
        ("deployment", "backlog-metric-source"),
        ("service", "backlog-metric-source"),
        ("serviceaccount", "backlog-observer"),
        ("clusterrole", "trpc-runtime-backlog-observer"),
        ("clusterrolebinding", "trpc-runtime-backlog-observer"),
    }
)
_SYNTHETIC_BACKLOG_JOB_NAMES = frozenset({"trpc-runtime-backlog"})
_PROMETHEUS_DISCOVERY_SERVICE_ACCOUNT = "prometheus"
_PROMETHEUS_DISCOVERY_ROLE = "trpc-runtime-prometheus-discovery"
_PROMETHEUS_RUNTIME_GATE_JOB = "trpc-runtime-gate-backlog"
_PROMETHEUS_PRODUCTION_JOB = "trpc-session-ready-backlog-production"
_RUNTIME_GATE_NAMESPACE_REGEX = r"^trpc-runtime-gate-[0-9a-f]{10}$"
_RUNTIME_GATE_NONCE_REGEX = r"^[0-9a-f]{32}$"
# Kubernetes label values are capped at 63 characters.  The runtime overlay
# deliberately stores the first 63 characters of the SHA-256 cluster
# fingerprint on the exporter Service.
_RUNTIME_GATE_CLUSTER_FINGERPRINT_REGEX = r"^[0-9a-f]{63}$"
_BACKLOG_METRIC_REGEX = r"^trpc_session_ready_backlog$"

# These are cluster-scoped Kubernetes kinds.  The support renderer must not
# add metadata.namespace to them, even though the support resources around
# them are namespaced.  APIService is cluster-scoped, but its spec.service
# reference is intentionally rewritten below.
_CLUSTER_SCOPED_KINDS = {
    "apiservice",
    "clusterrole",
    "clusterrolebinding",
    "customresourcedefinition",
    "mutatingwebhookconfiguration",
    "namespace",
    "node",
    "persistentvolume",
    "podsecuritypolicy",
    "priorityclass",
    "runtimeclass",
    "selfsubjectrulesreview",
    "selfsubjectaccessreview",
    "storageclass",
    "tokenreview",
    "validatingwebhookconfiguration",
}


class RuntimeSupportRenderError(ValueError):
    """Raised when configuration or a manifest cannot be rendered safely."""


def _load_runtime_gate_config(config_path: Path) -> Any:
    """Load the shared schema lazily, keeping this module usable in isolation."""
    from scripts.deployment_config import load_runtime_gate_config

    return load_runtime_gate_config(config_path)


def _field(value: Any, name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _support_values(config: Any) -> dict[str, str]:
    support = _field(config, "support")
    if support is None:
        raise RuntimeSupportRenderError(
            "runtime config is missing kubernetes.support; all runtime-support fields are required"
        )

    values: dict[str, str] = {"namespace": _support_namespace(config)}
    invalid: list[str] = []
    for name in _REQUIRED_SUPPORT_FIELDS:
        value = _field(support, name)
        if not isinstance(value, str) or not value.strip():
            invalid.append(name)
        else:
            values[name] = value
    if invalid:
        raise RuntimeSupportRenderError(
            "runtime config kubernetes.support has missing or invalid fields: " + ", ".join(invalid)
        )
    return values


def _support_namespace(config: Any) -> str:
    """Return and validate the configured support-service namespace.

    The checked-in support templates historically used
    ``trpc-runtime-support``.  Keeping that value as a safe default lets old
    acceptance configurations continue to render while making a custom ACK
    namespace explicit whenever one is supplied.
    """

    support = _field(config, "support")
    raw_namespace = _field(support, "namespace") if support is not None else None
    namespace = DEFAULT_SUPPORT_NAMESPACE if raw_namespace is None else raw_namespace
    if (
        not isinstance(namespace, str)
        or not namespace.strip()
        or len(namespace.strip()) > 63
        or _NAMESPACE_RE.fullmatch(namespace.strip()) is None
    ):
        raise RuntimeSupportRenderError(
            "runtime config kubernetes.support.namespace must be a valid DNS label "
            "within 63 characters"
        )
    return namespace.strip()


def _replace_support_namespace_string(value: str, namespace: str) -> str:
    """Replace support namespace tokens without touching unrelated namespaces."""

    if value == DEFAULT_SUPPORT_NAMESPACE:
        return namespace
    return value.replace(
        f".{DEFAULT_SUPPORT_NAMESPACE}.svc.cluster.local",
        f".{namespace}.svc.cluster.local",
    ).replace(
        f".{DEFAULT_SUPPORT_NAMESPACE}.svc",
        f".{namespace}.svc",
    )


def _render_support_namespace_references(
    documents: Iterable[Any],
    *,
    namespace: str,
    rewrite_resource_metadata: bool,
) -> None:
    """Rewrite support namespace references in a copied manifest tree.

    ``rewrite_resource_metadata`` is true for the dedicated support/MinIO
    templates, where every namespaced object belongs to the support namespace.
    It is false for the performance overlay's copied runtime base: those
    workloads remain in the performance namespace, while NetworkPolicy
    selectors, service DNS names, and APIService service references still
    need to point at the configured support namespace.
    """

    def visit(value: Any, *, resource_root: bool = False) -> None:
        if isinstance(value, list):
            for item in value:
                visit(item, resource_root=resource_root)
            return
        if not isinstance(value, dict):
            return

        is_resource = resource_root or (
            isinstance(value.get("apiVersion"), str)
            and isinstance(value.get("kind"), str)
            and isinstance(value.get("metadata"), dict)
        )
        metadata = value.get("metadata")
        if rewrite_resource_metadata and is_resource and isinstance(metadata, dict):
            resource_kind = _kind(value)
            if resource_kind == "namespace":
                if metadata.get("name") == DEFAULT_SUPPORT_NAMESPACE:
                    metadata["name"] = namespace
            elif resource_kind not in _CLUSTER_SCOPED_KINDS:
                raw_resource_namespace = metadata.get("namespace")
                if raw_resource_namespace in (None, DEFAULT_SUPPORT_NAMESPACE):
                    metadata["namespace"] = namespace

        # A RoleBinding may live in kube-system while its ServiceAccount lives
        # in the support namespace.  Only rewrite the subject reference, not
        # the RoleBinding's own external namespace.
        subjects = value.get("subjects")
        if isinstance(subjects, list):
            for subject in subjects:
                if (
                    isinstance(subject, dict)
                    and subject.get("namespace") == DEFAULT_SUPPORT_NAMESPACE
                ):
                    subject["namespace"] = namespace

        # APIService itself is cluster-scoped.  Its adapter Service is not.
        if _kind(value) == "apiservice":
            spec = value.get("spec")
            service = spec.get("service") if isinstance(spec, dict) else None
            if isinstance(service, dict):
                service_name = service.get("name")
                if service_name == "prometheus-adapter":
                    service["namespace"] = namespace

        namespace_selector = value.get("namespaceSelector")
        if isinstance(namespace_selector, dict):
            labels = namespace_selector.get("matchLabels")
            if (
                isinstance(labels, dict)
                and labels.get("kubernetes.io/metadata.name") == DEFAULT_SUPPORT_NAMESPACE
            ):
                labels["kubernetes.io/metadata.name"] = namespace

        for key, child in list(value.items()):
            if isinstance(child, str):
                value[key] = _replace_support_namespace_string(child, namespace)
            elif key == "items" and isinstance(child, list):
                for item in child:
                    visit(item, resource_root=True)
            else:
                visit(child)

    for document in documents:
        visit(document, resource_root=True)


def _read_documents(path: Path) -> list[Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            documents = list(yaml.safe_load_all(handle))
    except OSError as exc:
        raise RuntimeSupportRenderError(f"cannot read Kubernetes template {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RuntimeSupportRenderError(f"invalid Kubernetes YAML in {path}: {exc}") from exc
    if not documents:
        raise RuntimeSupportRenderError(f"Kubernetes template {path} is empty")
    return documents


def _write_documents(documents: Iterable[Any], path: Path) -> None:
    try:
        content = yaml.safe_dump_all(
            list(documents),
            allow_unicode=True,
            default_flow_style=False,
            explicit_start=True,
            sort_keys=True,
            width=120,
        )
        path.write_text(content, encoding="utf-8")
    except (OSError, yaml.YAMLError) as exc:
        raise RuntimeSupportRenderError(
            f"cannot write rendered Kubernetes YAML {path}: {exc}"
        ) from exc


def _kind(document: Mapping[str, Any]) -> str:
    value = document.get("kind")
    return value.strip().lower() if isinstance(value, str) else ""


def _name(document: Mapping[str, Any]) -> str:
    metadata = document.get("metadata")
    value = metadata.get("name") if isinstance(metadata, Mapping) else None
    return value.strip().lower() if isinstance(value, str) else ""


def _service_name_matches(name: str, service: str) -> bool:
    return name == service or name.startswith(service + "-") or name.startswith(service)


def _pod_specs(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Find workload ``template.spec`` maps, including nested List items."""
    result: list[dict[str, Any]] = []
    root_kind = _kind(document)

    def visit(value: Any, path: tuple[object, ...], inherited_kind: str) -> None:
        if isinstance(value, Mapping):
            current_kind = _kind(value) or inherited_kind
            if path[-2:] == ("template", "spec") and isinstance(value, dict):
                result.append(value)
            elif current_kind == "pod" and path[-1:] == ("spec",) and isinstance(value, dict):
                result.append(value)
            for key, child in value.items():
                visit(child, (*path, key), current_kind)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, (*path, index), inherited_kind)

    visit(document, (), root_kind)
    return result


def _set_node_selector(pod_spec: dict[str, Any], data_node: str) -> None:
    selector = pod_spec.get("nodeSelector")
    if not isinstance(selector, dict):
        selector = {}
        pod_spec["nodeSelector"] = selector

    hostname_keys = [
        key
        for key in selector
        if isinstance(key, str) and (key == "hostname" or key.endswith("/hostname"))
    ]
    if not hostname_keys:
        hostname_keys = ["kubernetes.io/hostname"]
    for key in hostname_keys:
        selector[key] = data_node


def _containers(pod_spec: Mapping[str, Any], field: str) -> list[dict[str, Any]]:
    raw = pod_spec.get(field)
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def _all_containers(pod_spec: Mapping[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for field in ("containers", "initContainers", "ephemeralContainers"):
        result.extend(_containers(pod_spec, field))
    return result


def _container_name(container: Mapping[str, Any]) -> str:
    name = container.get("name")
    return name.strip().lower().replace("_", "-") if isinstance(name, str) else ""


def _set_named_bootstrap_images(pod_spec: Mapping[str, Any], image: str) -> None:
    for container in _all_containers(pod_spec):
        if _container_name(container) == "postgres-bootstrap":
            container["image"] = image


def _set_postgres_image(pod_spec: Mapping[str, Any], image: str) -> None:
    containers = _containers(pod_spec, "containers")
    matches = [
        container
        for container in containers
        if _container_name(container) in {"postgres", "postgresql"}
    ]
    if not matches and len(containers) == 1:
        matches = containers
    for container in matches:
        container["image"] = image


def _set_redis_image(pod_spec: Mapping[str, Any], image: str) -> None:
    for container in _containers(pod_spec, "containers"):
        if _container_name(container) == "redis":
            container["image"] = image


def _is_data_volume(volume: Mapping[str, Any]) -> bool:
    source_keys = set(volume) - {"name"}
    if source_keys & _NON_DATA_VOLUME_KEYS:
        return False
    if source_keys & _DATA_VOLUME_KEYS:
        return True
    name = volume.get("name")
    if not isinstance(name, str):
        return False
    normalized = name.lower().replace("_", "-")
    return any(token in normalized for token in ("data", "storage", "postgres", "redis", "minio"))


def _host_path_volume(name: str, host_path: str) -> dict[str, Any]:
    return {
        "name": name,
        "hostPath": {"path": host_path, "type": "DirectoryOrCreate"},
    }


def _replace_data_volumes(pod_spec: dict[str, Any], host_path: str) -> bool:
    raw_volumes = pod_spec.get("volumes")
    volumes = raw_volumes if isinstance(raw_volumes, list) else []
    changed = False
    for volume in volumes:
        if not isinstance(volume, dict) or not _is_data_volume(volume):
            continue
        name = volume.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        volume.clear()
        volume.update(_host_path_volume(name, host_path))
        changed = True
    if changed:
        pod_spec["volumes"] = volumes
    return changed


def _ensure_data_volume(pod_spec: dict[str, Any], host_path: str) -> None:
    """Give the Redis deployment a real /data hostPath when its template lacks one."""
    raw_volumes = pod_spec.get("volumes")
    volumes = raw_volumes if isinstance(raw_volumes, list) else []
    data_volumes = [
        volume for volume in volumes if isinstance(volume, dict) and _is_data_volume(volume)
    ]
    if data_volumes:
        _replace_data_volumes(pod_spec, host_path)
    else:
        volumes.append(_host_path_volume("data", host_path))
        pod_spec["volumes"] = volumes

    mounts = pod_spec.get("containers")
    if not isinstance(mounts, list):
        return
    for container in mounts:
        if not isinstance(container, dict):
            continue
        raw_mounts = container.get("volumeMounts")
        volume_mounts = raw_mounts if isinstance(raw_mounts, list) else []
        if any(
            isinstance(mount, Mapping) and mount.get("name") == "data" for mount in volume_mounts
        ):
            continue
        volume_mounts.append({"name": "data", "mountPath": "/data"})
        container["volumeMounts"] = volume_mounts


def _render_document(document: Any, values: Mapping[str, str]) -> None:
    if isinstance(document, list):
        for item in document:
            _render_document(item, values)
        return
    if not isinstance(document, dict):
        return

    kind = _kind(document)
    name = _name(document)
    pod_specs = _pod_specs(document)
    for pod_spec in pod_specs:
        _set_node_selector(pod_spec, values["data_node"])
        _set_named_bootstrap_images(pod_spec, values["postgres_image"])

    if kind == "deployment":
        if _service_name_matches(name, "postgres"):
            for pod_spec in pod_specs:
                _set_postgres_image(pod_spec, values["postgres_image"])
                _replace_data_volumes(pod_spec, values["postgres_host_path"])
        elif _service_name_matches(name, "redis"):
            for pod_spec in pod_specs:
                _set_redis_image(pod_spec, values["redis_image"])
                _ensure_data_volume(pod_spec, values["redis_host_path"])
        elif _service_name_matches(name, "minio"):
            for pod_spec in pod_specs:
                _replace_data_volumes(pod_spec, values["minio_host_path"])
    elif name == "postgres-bootstrap":
        for pod_spec in pod_specs:
            for container in _all_containers(pod_spec):
                container["image"] = values["postgres_image"]

    items = document.get("items")
    if isinstance(items, list):
        for item in items:
            _render_document(item, values)


def render_documents(documents: Iterable[Any], support: Any) -> list[Any]:
    """Render loaded YAML documents without mutating the caller's objects."""
    config = type("Config", (), {"support": support})()
    values = _support_values(config)
    rendered = copy.deepcopy(list(documents))
    _render_support_namespace_references(
        rendered,
        namespace=values["namespace"],
        rewrite_resource_metadata=True,
    )
    for document in rendered:
        _render_document(document, values)
    return rendered


def _support_runtime_bindings(config: Any) -> dict[str, str] | None:
    """Return optional support image/Secret bindings from the shared config.

    Older support-only test configurations predate the provider images.  The
    validated runtime configuration supplies all of these fields; returning
    ``None`` for an entirely absent block keeps the low-level renderer useful
    for those template tests without allowing a partially specified binding.
    """

    support = _field(config, "support")
    image_values = {
        name: _field(support, name) if support is not None else None
        for name in _SUPPORT_IMAGE_FIELDS
    }
    pull_secret = _field(config, "image_pull_secret")
    if all(value is None for value in (*image_values.values(), pull_secret)):
        return None
    invalid = [
        name
        for name, value in (*image_values.items(), ("image_pull_secret", pull_secret))
        if not isinstance(value, str) or not value.strip()
    ]
    if invalid:
        raise RuntimeSupportRenderError(
            "runtime config support image bindings are missing or invalid: " + ", ".join(invalid)
        )
    return {
        **{name: value.strip() for name, value in image_values.items() if isinstance(value, str)},
        "image_pull_secret": pull_secret.strip(),
    }


def _drop_synthetic_backlog_resources(documents: list[Any]) -> None:
    """Remove legacy Job-existence metric resources from rendered support.

    This is intentionally performed in the renderer as well as in the
    checked-in template.  A caller may supply an older copied template, and
    production rendering must not accidentally publish a synthetic backlog
    source merely because that template was not refreshed.
    """

    def keep(value: Any) -> bool:
        if not isinstance(value, dict):
            return True
        identity = (_kind(value), _name(value))
        if identity in _SYNTHETIC_BACKLOG_RESOURCES:
            return False
        items = value.get("items")
        if isinstance(items, list):
            value["items"] = [item for item in items if keep(item)]
        return True

    documents[:] = [document for document in documents if keep(document)]


def _find_resource(documents: Iterable[Any], *, kind: str, name: str) -> dict[str, Any] | None:
    """Find a resource in top-level documents or Kubernetes List items."""

    for document in documents:
        if not isinstance(document, dict):
            continue
        if _kind(document) == kind and _name(document) == name:
            return document
        items = document.get("items")
        if isinstance(items, list):
            found = _find_resource(items, kind=kind, name=name)
            if found is not None:
                return found
    return None


def _provider_resource_name(namespace: str, base_name: str) -> str:
    """Derive a stable, DNS-safe cluster resource name for a support provider."""

    if namespace == DEFAULT_SUPPORT_NAMESPACE:
        return base_name
    suffix = hashlib.sha256(namespace.encode("utf-8")).hexdigest()[:16]
    prefix_limit = 63 - len(suffix) - 1
    prefix = base_name[:prefix_limit].rstrip("-")
    if not prefix:
        raise RuntimeSupportRenderError("provider resource name prefix is empty")
    return f"{prefix}-{suffix}"


def _provider_resource_labels(namespace: str) -> dict[str, str]:
    return {
        "app.kubernetes.io/managed-by": _PROVIDER_MANAGED_BY,
        _PROVIDER_LABEL_KEY: _PROVIDER_LABEL_VALUE,
        _PROVIDER_NAMESPACE_LABEL_KEY: namespace,
    }


def _set_provider_resource_identity(documents: list[Any], *, namespace: str) -> None:
    """Namespace-bind discovery/adapter RBAC names and labels.

    ClusterRole and ClusterRoleBinding names are global.  A support provider
    rendered into a non-default namespace therefore gets a deterministic hash
    suffix, while the default acceptance provider retains its historical names.
    The RoleBinding lives in ``kube-system`` but is part of the same provider
    identity and is handled identically.
    """

    name_map = {
        base_name: _provider_resource_name(namespace, base_name)
        for _kind_name, base_name in _PROVIDER_RESOURCE_BASES
    }
    resources: list[tuple[str, str, dict[str, Any]]] = []
    for kind, base_name in _PROVIDER_RESOURCE_BASES:
        resource = _find_resource(documents, kind=kind, name=base_name)
        if resource is not None:
            resources.append((kind, base_name, resource))

    for kind, base_name, resource in resources:
        metadata = resource.setdefault("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
            resource["metadata"] = metadata
        metadata["name"] = name_map[base_name]
        labels = metadata.setdefault("labels", {})
        if not isinstance(labels, dict):
            labels = {}
            metadata["labels"] = labels
        labels.update(_provider_resource_labels(namespace))

        if kind != "clusterrolebinding":
            continue
        role_ref = resource.get("roleRef")
        if not isinstance(role_ref, dict):
            continue
        role_name = role_ref.get("name")
        if isinstance(role_name, str) and role_name in name_map:
            role_ref["name"] = name_map[role_name]


def _cutover_output_path(output_dir: Path, cutover_output: str | Path | None) -> Path:
    if cutover_output is not None:
        return Path(cutover_output)
    return output_dir / _DEFAULT_CUTOVER_OUTPUT_NAME


def _split_stage_documents(documents: list[Any]) -> tuple[list[Any], list[dict[str, Any]]]:
    """Remove APIService objects from stage output and retain them for cutover."""

    cutover: list[dict[str, Any]] = []

    def visit(value: Any) -> tuple[bool, Any]:
        if isinstance(value, dict):
            if _kind(value) == "apiservice":
                cutover.append(copy.deepcopy(value))
                return False, value
            items = value.get("items")
            if isinstance(items, list):
                retained_items: list[Any] = []
                for item in items:
                    keep, retained = visit(item)
                    if keep:
                        retained_items.append(retained)
                value["items"] = retained_items
            return True, value
        if isinstance(value, list):
            retained_values: list[Any] = []
            for item in value:
                keep, retained = visit(item)
                if keep:
                    retained_values.append(retained)
            return True, retained_values
        return True, value

    staged: list[Any] = []
    for document in documents:
        keep, retained = visit(document)
        if keep:
            staged.append(retained)
    return staged, cutover


def _ensure_prometheus_discovery_rbac(documents: list[Any], *, namespace: str) -> None:
    """Bind Prometheus to the minimal Kubernetes SD read surface.

    The discovery job uses the ``endpoints`` role, which needs read access to
    namespaces, Services, Endpoints and (on clusters that enrich endpoint
    targets from Pods) Pods.  No Job/Pod mutation or Secret access is granted
    here; the adapter keeps its separate, existing ServiceAccount.
    """

    config = _find_resource(documents, kind="configmap", name="prometheus-config")
    deployment = _find_resource(documents, kind="deployment", name="prometheus")
    if config is None or deployment is None:
        return

    service_account = _find_resource(
        documents, kind="serviceaccount", name=_PROMETHEUS_DISCOVERY_SERVICE_ACCOUNT
    )
    if service_account is None:
        documents.append(
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {
                    "name": _PROMETHEUS_DISCOVERY_SERVICE_ACCOUNT,
                    "namespace": namespace,
                },
            }
        )
    else:
        metadata = service_account.setdefault("metadata", {})
        if isinstance(metadata, dict):
            metadata["namespace"] = namespace

    role = _find_resource(documents, kind="clusterrole", name=_PROMETHEUS_DISCOVERY_ROLE)
    role_payload = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": _PROMETHEUS_DISCOVERY_ROLE},
        "rules": [
            {
                "apiGroups": [""],
                "resources": ["namespaces", "services", "endpoints", "pods"],
                "verbs": ["get", "list", "watch"],
            }
        ],
    }
    if role is None:
        documents.append(role_payload)
    else:
        role["rules"] = role_payload["rules"]

    binding = _find_resource(documents, kind="clusterrolebinding", name=_PROMETHEUS_DISCOVERY_ROLE)
    binding_payload = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": _PROMETHEUS_DISCOVERY_ROLE},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": _PROMETHEUS_DISCOVERY_ROLE,
        },
        "subjects": [
            {
                "kind": "ServiceAccount",
                "name": _PROMETHEUS_DISCOVERY_SERVICE_ACCOUNT,
                "namespace": namespace,
            }
        ],
    }
    if binding is None:
        documents.append(binding_payload)
    else:
        binding["roleRef"] = binding_payload["roleRef"]
        binding["subjects"] = binding_payload["subjects"]

    for pod_spec in _pod_specs(deployment):
        pod_spec["serviceAccountName"] = _PROMETHEUS_DISCOVERY_SERVICE_ACCOUNT
        pod_spec["automountServiceAccountToken"] = True


def _set_support_runtime_bindings(document: Any, bindings: Mapping[str, str]) -> None:
    """Bind support provider images and pull Secret without changing templates."""

    if not isinstance(document, Mapping):
        return
    kind = _kind(document)
    name = _name(document)
    if kind in {"deployment", "job"}:
        image = None
        if kind == "job" and name == "minio-bucket-bootstrap":
            image = bindings["minio_client_image"]
        elif _service_name_matches(name, "minio"):
            image = bindings["minio_image"]
        elif name == "prometheus":
            image = bindings["prometheus_image"]
        elif name == "prometheus-adapter":
            image = bindings["prometheus_adapter_image"]
        if image is not None:
            for pod_spec in _pod_specs(document):
                containers = (
                    _all_containers(pod_spec)
                    if name == "minio"
                    else _containers(pod_spec, "containers")
                )
                for container in containers:
                    container["image"] = image

    pull_secret = bindings.get("image_pull_secret")
    if pull_secret:
        for pod_spec in _pod_specs(document):
            pod_spec["imagePullSecrets"] = [{"name": pull_secret}]

    items = document.get("items")
    if isinstance(items, list):
        for item in items:
            _set_support_runtime_bindings(item, bindings)


def _config_data_sha256(data: Mapping[str, Any]) -> str:
    """Hash ConfigMap data canonically for a deterministic rollout trigger."""

    encoded = json.dumps(
        dict(data),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _set_support_config_rollout_annotations(documents: Iterable[Any]) -> None:
    """Restart Prometheus support workloads when their ConfigMap data changes."""

    resources: list[dict[str, Any]] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            resources.append(value)
            items = value.get("items")
            if isinstance(items, list):
                for item in items:
                    collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    for document in documents:
        collect(document)

    config_hashes: dict[str, str] = {}
    for config_name, _annotation_key in _SUPPORT_CONFIG_ROLLOUTS.values():
        config = next(
            (
                resource
                for resource in resources
                if _kind(resource) == "configmap" and _name(resource) == config_name
            ),
            None,
        )
        data = config.get("data") if isinstance(config, dict) else None
        if isinstance(data, Mapping):
            config_hashes[config_name] = _config_data_sha256(data)

    for deployment_name, (config_name, annotation_key) in _SUPPORT_CONFIG_ROLLOUTS.items():
        digest = config_hashes.get(config_name)
        if digest is None:
            continue
        for deployment in resources:
            if _kind(deployment) != "deployment" or _name(deployment) != deployment_name:
                continue
            spec = deployment.get("spec")
            template = spec.get("template") if isinstance(spec, dict) else None
            if not isinstance(template, dict):
                continue
            metadata = template.setdefault("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
                template["metadata"] = metadata
            annotations = metadata.setdefault("annotations", {})
            if not isinstance(annotations, dict):
                annotations = {}
                metadata["annotations"] = annotations
            annotations[annotation_key] = digest


def _inject_prometheus_scrape_target(
    documents: list[Any],
    *,
    namespace: str,
    compatibility_namespaces: Sequence[str] = (),
) -> None:
    """Configure authoritative performance and disposable-gate scraping.

    The fixed performance namespace is a direct, explicit target.  Disposable
    runtime-gate namespaces cannot be known at render time, so Prometheus uses
    Kubernetes Endpoints discovery and keeps only the exporter Service objects
    carrying the runtime-gate owner, run-nonce and cluster-fingerprint labels.
    All other discovered targets are dropped before scraping.  There is no
    fallback value: a failed/503 scrape remains an absent or ``up=0`` target,
    never a fabricated zero backlog.
    """

    namespaces = (namespace, *compatibility_namespaces)
    if len(set(namespaces)) != len(namespaces) or any(
        not _NAMESPACE_RE.fullmatch(item) for item in namespaces
    ):
        raise RuntimeSupportRenderError(
            "external metric scrape namespaces must be unique Kubernetes namespaces"
        )
    targets = [f"trpc-backlog-exporter.{item}.svc:9100" for item in namespaces]
    config_maps = [
        document
        for document in documents
        if isinstance(document, dict)
        and _kind(document) == "configmap"
        and _name(document) == "prometheus-config"
    ]
    if len(config_maps) != 1:
        raise RuntimeSupportRenderError(
            "runtime-support template must contain one prometheus-config ConfigMap"
        )
    data = config_maps[0].get("data")
    if not isinstance(data, dict):
        raise RuntimeSupportRenderError("prometheus-config has no data mapping")
    config_text = data.get("prometheus.yml")
    if not isinstance(config_text, str) or not config_text.strip():
        raise RuntimeSupportRenderError("prometheus-config is missing prometheus.yml")
    try:
        prometheus = yaml.safe_load(config_text)
    except yaml.YAMLError as exc:
        raise RuntimeSupportRenderError("prometheus.yml is not valid YAML") from exc
    if not isinstance(prometheus, dict):
        raise RuntimeSupportRenderError("prometheus.yml must be a mapping")
    raw_jobs = prometheus.get("scrape_configs")
    if not isinstance(raw_jobs, list):
        raise RuntimeSupportRenderError("prometheus.yml has no scrape_configs")

    jobs: list[dict[str, Any]] = []
    for raw_job in raw_jobs:
        if not isinstance(raw_job, dict):
            raise RuntimeSupportRenderError("prometheus.yml contains an invalid scrape job")
        job = copy.deepcopy(raw_job)
        job_name = job.get("job_name")
        if job_name in _SYNTHETIC_BACKLOG_JOB_NAMES:
            continue
        if job_name in {_PROMETHEUS_PRODUCTION_JOB, _PROMETHEUS_RUNTIME_GATE_JOB}:
            continue

        # Remove any legacy source reference even when it is nested in a
        # copied scrape configuration.  A whole legacy job is discarded so a
        # stale metric relabel rule cannot survive with an empty target list.
        def contains_synthetic_reference(value: Any) -> bool:
            if isinstance(value, str):
                return "backlog-metric-source" in value
            if isinstance(value, Mapping):
                return any(contains_synthetic_reference(item) for item in value.values())
            if isinstance(value, list):
                return any(contains_synthetic_reference(item) for item in value)
            return False

        if contains_synthetic_reference(job):
            continue
        jobs.append(job)

    jobs.append(
        {
            "job_name": _PROMETHEUS_PRODUCTION_JOB,
            "static_configs": [{"targets": targets}],
            "metric_relabel_configs": [
                {
                    "source_labels": ["__name__"],
                    "regex": _BACKLOG_METRIC_REGEX,
                    "action": "keep",
                }
            ],
        }
    )
    jobs.append(
        {
            "job_name": _PROMETHEUS_RUNTIME_GATE_JOB,
            "kubernetes_sd_configs": [{"role": "endpoints"}],
            "relabel_configs": [
                {
                    "source_labels": ["__meta_kubernetes_namespace"],
                    "regex": _RUNTIME_GATE_NAMESPACE_REGEX,
                    "action": "keep",
                },
                {
                    "source_labels": ["__meta_kubernetes_service_name"],
                    "regex": r"^trpc-backlog-exporter$",
                    "action": "keep",
                },
                {
                    "source_labels": ["__meta_kubernetes_service_label_trpc_io_managed_by"],
                    "regex": r"^trpc-kubernetes-runtime-gate$",
                    "action": "keep",
                },
                {
                    "source_labels": ["__meta_kubernetes_service_label_trpc_io_run_nonce"],
                    "regex": _RUNTIME_GATE_NONCE_REGEX,
                    "action": "keep",
                },
                {
                    "source_labels": [
                        "__meta_kubernetes_service_label_trpc_io_cluster_fingerprint"
                    ],
                    "regex": _RUNTIME_GATE_CLUSTER_FINGERPRINT_REGEX,
                    "action": "keep",
                },
                {
                    "source_labels": ["__meta_kubernetes_endpoint_port_name"],
                    "regex": r"^metrics$",
                    "action": "keep",
                },
                {
                    "source_labels": ["__meta_kubernetes_endpoint_ready"],
                    "regex": r"^true$",
                    "action": "keep",
                },
                {
                    "source_labels": [
                        "__meta_kubernetes_namespace",
                        "__meta_kubernetes_service_label_trpc_io_run_nonce",
                    ],
                    "regex": r"^trpc-runtime-gate-[0-9a-f]{10};[0-9a-f]{32}$",
                    "action": "keep",
                },
                {
                    "source_labels": ["__meta_kubernetes_namespace"],
                    "target_label": "namespace",
                    "action": "replace",
                },
                {
                    "source_labels": ["__meta_kubernetes_service_label_trpc_io_run_nonce"],
                    "target_label": "run_nonce",
                    "action": "replace",
                },
                {
                    "source_labels": [
                        "__meta_kubernetes_service_label_trpc_io_cluster_fingerprint"
                    ],
                    "target_label": "cluster_fingerprint",
                    "action": "replace",
                },
            ],
            "metric_relabel_configs": [
                {
                    "source_labels": ["__name__"],
                    "regex": _BACKLOG_METRIC_REGEX,
                    "action": "keep",
                }
            ],
        }
    )
    prometheus["scrape_configs"] = jobs
    data["prometheus.yml"] = yaml.safe_dump(
        prometheus,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=120,
    )


def _output_paths(
    support_template: Path,
    minio_template: Path,
    output_dir: Path,
) -> tuple[Path, Path]:
    support_output = output_dir / support_template.name
    minio_output = output_dir / minio_template.name
    template_paths = {support_template.resolve(), minio_template.resolve()}
    for output_path in (support_output, minio_output):
        if output_path.resolve() in template_paths:
            raise RuntimeSupportRenderError(
                f"refusing to overwrite Kubernetes template {output_path}; "
                "choose a separate --output-dir"
            )
    if support_output == minio_output:
        raise RuntimeSupportRenderError("support and MinIO output paths must be different")
    return support_output, minio_output


def render_runtime_support(
    config: str | Path,
    *,
    support_template: str | Path = DEFAULT_SUPPORT_TEMPLATE,
    minio_template: str | Path = DEFAULT_MINIO_TEMPLATE,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    mode: str = "full",
    cutover_output: str | Path | None = None,
) -> tuple[Path, Path]:
    """Render both templates and return ``(support_yaml, minio_yaml)`` paths.

    ``full`` keeps the APIService in the support manifest for a clean-cluster
    deployment.  ``stage`` omits it and writes a separate one-object cutover
    manifest, allowing a second provider to be reviewed before switching the
    cluster-scoped external-metrics registration.
    """

    if mode not in _RUNTIME_SUPPORT_MODES:
        raise RuntimeSupportRenderError(
            f"runtime-support render mode must be one of {sorted(_RUNTIME_SUPPORT_MODES)}"
        )
    if cutover_output is not None and mode != "stage":
        raise RuntimeSupportRenderError("cutover-output requires --mode stage")
    config_path = Path(config)
    support_template_path = Path(support_template)
    minio_template_path = Path(minio_template)
    output_dir_path = Path(output_dir)

    loaded_config = _load_runtime_gate_config(config_path)
    values = _support_values(loaded_config)
    support_documents = render_documents(_read_documents(support_template_path), values)
    minio_documents = render_documents(_read_documents(minio_template_path), values)
    _drop_synthetic_backlog_resources(support_documents)
    support_bindings = _support_runtime_bindings(loaded_config)
    if support_bindings is not None:
        for document in (*support_documents, *minio_documents):
            _set_support_runtime_bindings(document, support_bindings)
    performance = _field(loaded_config, "performance")
    support = _field(loaded_config, "support")
    performance_namespace = _field(performance, "namespace") if performance is not None else None
    if performance_namespace is not None:
        if not isinstance(performance_namespace, str) or not performance_namespace.strip():
            raise RuntimeSupportRenderError(
                "kubernetes.performance.namespace must be a non-empty string"
            )
        _inject_prometheus_scrape_target(
            support_documents,
            namespace=performance_namespace.strip(),
            compatibility_namespaces=tuple(
                _field(support, "external_metric_compatibility_namespaces") or ()
            ),
        )
    _ensure_prometheus_discovery_rbac(
        support_documents,
        namespace=values["namespace"],
    )
    _set_provider_resource_identity(
        support_documents,
        namespace=values["namespace"],
    )
    if support_bindings is not None:
        _set_support_config_rollout_annotations(support_documents)
    support_output, minio_output = _output_paths(
        support_template_path,
        minio_template_path,
        output_dir_path,
    )
    cutover_output_path = (
        _cutover_output_path(output_dir_path, cutover_output) if mode == "stage" else None
    )
    if cutover_output_path is not None:
        if cutover_output_path.resolve() in {
            support_output.resolve(),
            minio_output.resolve(),
            support_template_path.resolve(),
            minio_template_path.resolve(),
        }:
            raise RuntimeSupportRenderError(
                f"refusing to overwrite support or MinIO output/template {cutover_output_path}"
            )
        support_documents, support_cutover = _split_stage_documents(support_documents)
        minio_documents, minio_cutover = _split_stage_documents(minio_documents)
        cutover_documents = [*support_cutover, *minio_cutover]
        if len(cutover_documents) != 1:
            raise RuntimeSupportRenderError(
                "stage mode requires exactly one APIService for the cutover manifest"
            )
    else:
        cutover_documents = []
    try:
        output_dir_path.mkdir(parents=True, exist_ok=True)
        if cutover_output_path is not None:
            cutover_output_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeSupportRenderError(
            f"cannot create rendered-manifest directory {output_dir_path}: {exc}"
        ) from exc
    _write_documents(support_documents, support_output)
    _write_documents(minio_documents, minio_output)
    if cutover_output_path is not None:
        _write_documents(cutover_documents, cutover_output_path)
    return support_output, minio_output


def _performance_config(config: Any) -> Any:
    performance = _field(config, "performance")
    if performance is None:
        raise RuntimeSupportRenderError(
            "runtime config is missing kubernetes.performance; the performance overlay is opt-in"
        )
    if _field(performance, "enabled") is not True:
        raise RuntimeSupportRenderError(
            "kubernetes.performance.enabled must be true to render the performance overlay"
        )
    return performance


def _performance_image(config: Any) -> tuple[str, str]:
    try:
        references = config.resolved_image_references()
        reference = references["initial"]
        repository, digest = reference.rsplit("@", 1)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise RuntimeSupportRenderError(
            "runtime config does not provide an immutable initial performance image"
        ) from exc
    if not repository or not digest.startswith("sha256:"):
        raise RuntimeSupportRenderError(
            "runtime config does not provide an immutable initial performance image"
        )
    return repository, digest


def _performance_manifest_values(config: Any, performance: Any) -> dict[str, str]:
    try:
        values = dict(performance.environment())
    except AttributeError as exc:
        raise RuntimeSupportRenderError(
            "runtime config performance block cannot be projected"
        ) from exc
    object_store_endpoint = _field(config, "object_store_endpoint")
    object_store_bucket = _field(config, "object_store_bucket")
    if not isinstance(object_store_endpoint, str) or not object_store_endpoint:
        raise RuntimeSupportRenderError(
            "runtime config performance rendering requires kubernetes.object_store.endpoint"
        )
    if not isinstance(object_store_bucket, str) or not object_store_bucket:
        raise RuntimeSupportRenderError(
            "runtime config performance rendering requires kubernetes.object_store.bucket"
        )
    repository, digest = _performance_image(config)
    values.update(
        {
            "TRPC_SERVICE_ENVIRONMENT": "test",
            "TRPC_SERVICE_CAPTURE_CONTENT": "false",
            "TRPC_SERVICE_OTLP_ENDPOINT": "",
            "TRPC_SERVICE_PROMETHEUS_ENABLED": "false",
            "TRPC_SERVICE_S3_ENDPOINT": object_store_endpoint,
            "TRPC_SERVICE_S3_BUCKET": object_store_bucket,
            "TRPC_K8S_RUNTIME_IMAGE": f"{repository}@{digest}",
            "TRPC_PERF_K8S_IMAGE": f"{repository}@{digest}",
            "TRPC_PERF_K8S_IMAGE_DIGEST": digest,
            "TRPC_SERVICE_WORKER_CONCURRENCY": str(_field(performance, "worker_concurrency")),
        }
    )
    return values


def _performance_workload_patch(documents: list[Any], performance: Any, config: Any) -> None:
    """Bind the configured workload placement and role env to Deployment patches."""

    workload = _field(performance, "workload")
    if workload is None:
        raise RuntimeSupportRenderError(
            "runtime config kubernetes.performance.workload is required"
        )
    node_label = _field(workload, "node_label")
    if not isinstance(node_label, str) or "=" not in node_label:
        raise RuntimeSupportRenderError(
            "runtime config kubernetes.performance.workload.node_label is invalid"
        )
    node_key, node_value = node_label.split("=", 1)
    node_name = _field(config, "node_name")
    if not isinstance(node_name, str) or not node_name.strip():
        raise RuntimeSupportRenderError("runtime config kubernetes.node.name is invalid")
    node_selector = {node_key: node_value, "kubernetes.io/hostname": node_name.strip()}
    if node_key == "kubernetes.io/hostname" and node_value != node_name.strip():
        raise RuntimeSupportRenderError(
            "runtime workload node label conflicts with kubernetes.node.name"
        )
    roles = {
        "trpc-gateway": (
            "gateway",
            {
                "TRPC_SERVICE_DATABASE_POOL_MIN_SIZE": _field(
                    _field(workload, "gateway"), "database_pool_min_size"
                ),
                "TRPC_SERVICE_DATABASE_POOL_MAX_SIZE": _field(
                    _field(workload, "gateway"), "database_pool_max_size"
                ),
            },
        ),
        "trpc-worker": (
            "worker",
            {
                "TRPC_SERVICE_DATABASE_POOL_MIN_SIZE": _field(
                    _field(workload, "worker"), "database_pool_min_size"
                ),
                "TRPC_SERVICE_DATABASE_POOL_MAX_SIZE": _field(
                    _field(workload, "worker"), "database_pool_max_size"
                ),
                "TRPC_SERVICE_OFFLINE_AGENT_DELAY_SECONDS": _field(
                    _field(workload, "worker"), "offline_agent_delay_seconds"
                ),
            },
        ),
        "trpc-outbox-dispatcher": (
            "outbox-dispatcher",
            {
                "TRPC_SERVICE_DATABASE_POOL_MIN_SIZE": _field(
                    _field(workload, "outbox"), "database_pool_min_size"
                ),
                "TRPC_SERVICE_DATABASE_POOL_MAX_SIZE": _field(
                    _field(workload, "outbox"), "database_pool_max_size"
                ),
            },
        ),
        "trpc-session-recovery": (
            "session-recovery",
            {
                "TRPC_SERVICE_DATABASE_POOL_MIN_SIZE": _field(
                    _field(workload, "recovery"), "database_pool_min_size"
                ),
                "TRPC_SERVICE_DATABASE_POOL_MAX_SIZE": _field(
                    _field(workload, "recovery"), "database_pool_max_size"
                ),
                "TRPC_SERVICE_RECOVERY_POLL_SECONDS": _field(
                    _field(workload, "recovery"), "poll_seconds"
                ),
            },
        ),
    }
    for document in documents:
        if not isinstance(document, dict):
            continue
        name = _name(document)
        kind = _kind(document)
        if not (
            (kind == "deployment" and name in {*roles, "trpc-backlog-exporter"})
            or (kind == "job" and name == "trpc-schema-migration")
        ):
            continue
        spec = document.setdefault("spec", {})
        template = spec.setdefault("template", {})
        pod_spec = template.setdefault("spec", {})
        pod_spec["nodeSelector"] = node_selector
        if name not in roles:
            continue
        container_name, raw_environment = roles[name]
        if any(value is None for value in raw_environment.values()):
            raise RuntimeSupportRenderError(
                f"runtime config workload settings are incomplete for {name}"
            )
        containers = pod_spec.setdefault("containers", [])
        container = next(
            (
                item
                for item in containers
                if isinstance(item, dict) and item.get("name") == container_name
            ),
            None,
        )
        if container is None:
            raise RuntimeSupportRenderError(
                f"performance workload patch is missing container {container_name}"
            )
        container["env"] = [
            {"name": key, "value": str(value)} for key, value in raw_environment.items()
        ]


def _render_performance_file(
    source: Path,
    target: Path,
    *,
    config: Any,
    performance: Any,
    image_repository: str,
    image_digest: str,
    relative_base: str,
    support_namespace: str,
) -> None:
    documents = _read_documents(source)
    rendered = copy.deepcopy(documents)
    if source.name == "kustomization.yaml":
        document = rendered[0] if rendered and isinstance(rendered[0], dict) else None
        if document is not None:
            document["namespace"] = str(_field(performance, "namespace"))
            resources = document.get("resources")
            if isinstance(resources, list):
                document["resources"] = [
                    relative_base if item == "../../base" else item for item in resources
                ]
            images = document.get("images")
            if isinstance(images, list) and images and isinstance(images[0], dict):
                images[0]["newName"] = image_repository
                images[0]["digest"] = image_digest
    elif source.name == "namespace.yaml":
        document = rendered[0] if rendered and isinstance(rendered[0], dict) else None
        metadata = document.get("metadata") if isinstance(document, dict) else None
        if isinstance(metadata, dict):
            metadata["name"] = str(_field(performance, "namespace"))
    elif source.name == "performance-config-patch.yaml":
        document = rendered[0] if rendered and isinstance(rendered[0], dict) else None
        if isinstance(document, dict):
            document["data"] = _performance_manifest_values(config, performance)
    elif source.name == "performance-replicas-patch.yaml":
        workload = _field(performance, "workload")
        gateway = _field(workload, "gateway") if workload is not None else None
        gateway_replicas = _field(gateway, "replicas")
        worker_replicas = _field(performance, "workers")
        outbox = _field(workload, "outbox") if workload is not None else None
        recovery = _field(workload, "recovery") if workload is not None else None
        replicas = {
            "trpc-gateway": gateway_replicas,
            "trpc-worker": worker_replicas,
            "trpc-outbox-dispatcher": _field(outbox, "replicas"),
            "trpc-session-recovery": _field(recovery, "replicas"),
        }
        if any(value is None for value in replicas.values()):
            raise RuntimeSupportRenderError(
                "runtime config performance replica settings are incomplete"
            )
        for document in rendered:
            if not isinstance(document, dict) or _kind(document) != "deployment":
                continue
            name = _name(document)
            if name in replicas:
                spec = document.setdefault("spec", {})
                spec["replicas"] = int(replicas[name])
    elif source.name == "performance-workload-patch.yaml":
        _performance_workload_patch(rendered, performance, config)
    _render_support_namespace_references(
        rendered,
        namespace=support_namespace,
        rewrite_resource_metadata=False,
    )
    _write_documents(rendered, target)


def _render_performance_base_file(source: Path, *, support_namespace: str) -> None:
    """Rewrite support references in a copied base file in place."""

    documents = copy.deepcopy(_read_documents(source))
    _render_support_namespace_references(
        documents,
        namespace=support_namespace,
        rewrite_resource_metadata=False,
    )
    _write_documents(documents, source)


def render_performance_overlay(
    config: str | Path,
    *,
    template_dir: str | Path = DEFAULT_PERFORMANCE_TEMPLATE,
    output_dir: str | Path = DEFAULT_PERFORMANCE_OUTPUT_DIR,
) -> Path:
    """Render an immutable, config-bound performance Kustomize overlay.

    The output is a copy of the checked-in opt-in overlay.  Its image host and
    digest come from the release binding after the configured pull-registry
    rewrite, so every candidate workload uses one identical immutable image.
    """

    config_path = Path(config)
    template_path = Path(template_dir).expanduser().resolve()
    output_path = Path(output_dir).expanduser().resolve()
    if not template_path.is_dir():
        raise RuntimeSupportRenderError(f"performance overlay template is missing: {template_path}")
    if output_path == template_path:
        raise RuntimeSupportRenderError(
            f"refusing to overwrite performance overlay template {template_path}"
        )
    loaded_config = _load_runtime_gate_config(config_path)
    performance = _performance_config(loaded_config)
    image_repository, image_digest = _performance_image(loaded_config)
    support_namespace = _support_namespace(loaded_config)
    base_path = (template_path.parent.parent / "base").resolve()
    rendered_base = output_path / "base"
    relative_base = "base"
    try:
        output_path.mkdir(parents=True, exist_ok=True)
        shutil.copytree(base_path, rendered_base, dirs_exist_ok=True)
        for copied_file in sorted(rendered_base.rglob("*.yaml")):
            _render_performance_base_file(copied_file, support_namespace=support_namespace)
        for source in sorted(template_path.glob("*.yaml")):
            _render_performance_file(
                source,
                output_path / source.name,
                config=loaded_config,
                performance=performance,
                image_repository=image_repository,
                image_digest=image_digest,
                relative_base=relative_base,
                support_namespace=support_namespace,
            )
    except OSError as exc:
        raise RuntimeSupportRenderError(
            f"cannot render performance overlay directory {output_path}: {exc}"
        ) from exc
    return output_path


render_performance_topology = render_performance_overlay


render_runtime_manifests = render_runtime_support
render_manifests = render_runtime_support


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render ACK runtime-support Kubernetes YAML without applying it."
    )
    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="shared runtime-gate config YAML",
    )
    parser.add_argument(
        "--support-template",
        type=Path,
        default=DEFAULT_SUPPORT_TEMPLATE,
        help=f"Postgres/Redis support template (default: {DEFAULT_SUPPORT_TEMPLATE})",
    )
    parser.add_argument(
        "--minio-template",
        type=Path,
        default=DEFAULT_MINIO_TEMPLATE,
        help=f"MinIO template (default: {DEFAULT_MINIO_TEMPLATE})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"separate directory for rendered YAML (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--mode",
        choices=sorted(_RUNTIME_SUPPORT_MODES),
        default="full",
        help="full applies APIService with the support resources; stage writes it separately",
    )
    parser.add_argument(
        "--cutover-output",
        type=Path,
        default=None,
        help=(
            "optional one-object APIService output path; only valid with --mode stage "
            f"(default: <output-dir>/{_DEFAULT_CUTOVER_OUTPUT_NAME})"
        ),
    )
    parser.add_argument(
        "--performance-output-dir",
        type=Path,
        default=None,
        help=(
            "optional output directory for the explicitly enabled performance overlay; "
            "the checked-in template is never modified"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        support_output, minio_output = render_runtime_support(
            args.config,
            support_template=args.support_template,
            minio_template=args.minio_template,
            output_dir=args.output_dir,
            mode=args.mode,
            cutover_output=args.cutover_output,
        )
        performance_output = (
            render_performance_overlay(
                args.config,
                output_dir=args.performance_output_dir,
            )
            if args.performance_output_dir is not None
            else None
        )
    except (OSError, RuntimeSupportRenderError, ValueError, yaml.YAMLError) as exc:
        print(f"render failed: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "support": str(support_output),
                "minio": str(minio_output),
                **(
                    {"cutover": str(_cutover_output_path(args.output_dir, args.cutover_output))}
                    if args.mode == "stage"
                    else {}
                ),
                **({"performance": str(performance_output)} if performance_output else {}),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    if __package__ in {None, ""}:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    raise SystemExit(main())
