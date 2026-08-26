#!/usr/bin/env python3
"""Strict, secret-safe configuration for the production runtime gate.

The file intentionally contains only references to credentials.  Raw release
nonces, kubeconfig contents, registry tokens, DSNs, and Secret values remain in
environment variables or external files.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from scripts.evidence_lineage import source_fingerprint

ROOT = Path(__file__).resolve().parents[1]
IMAGE_REFERENCE_RE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
REGISTRY_HOST_RE = re.compile(
    r"^(?:localhost|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::[1-9][0-9]{0,4})?$"
)
KUBERNETES_NAME_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$")
RELEASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
RELEASE_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{32,256}$")
NODE_LABEL_RE = re.compile(r"^trpc-runtime-gate=[A-Za-z0-9_.-]+$")
SUBJECT_RE = re.compile(r"^system:serviceaccount:[a-z0-9.-]+:[a-z0-9.-]+$")
HPA_JOB_COMMAND_MAX_ARGS = 64
HPA_JOB_COMMAND_MAX_ITEM_BYTES = 512
HPA_DRIVER_MAX_BYTES = 1024 * 1024
PORT_ENVIRONMENTS = {
    "gateway": "GATEWAY_PORT",
    "admin": "ADMIN_PORT",
    "postgres": "POSTGRES_PORT",
    "redis": "REDIS_PORT",
    "minio": "MINIO_PORT",
    "minio_console": "MINIO_CONSOLE_PORT",
    "toxiproxy_api": "TOXIPROXY_API_PORT",
    "toxiproxy_postgres": "TOXIPROXY_POSTGRES_PORT",
    "toxiproxy_redis": "TOXIPROXY_REDIS_PORT",
    "toxiproxy_s3": "TOXIPROXY_S3_PORT",
    "prometheus": "PROMETHEUS_PORT",
    "jaeger": "JAEGER_UI_PORT",
}
REQUIRED_SECRET_KEYS = {
    "trpc-service-secrets": {
        "TRPC_SERVICE_DATABASE_DSN",
        "TRPC_SERVICE_REDIS_URL",
        "TRPC_SERVICE_SESSION_HMAC_KEY",
        "TRPC_SERVICE_EMERGENCY_QUEUE_KEY",
        "TRPC_SERVICE_S3_ACCESS_KEY",
        "TRPC_SERVICE_S3_SECRET_KEY",
    },
    "trpc-worker-secrets": {
        "TRPC_SERVICE_WORKER_DATABASE_DSN_REF",
        "TRPC_SERVICE_WORKER_DATABASE_DSN",
        "TRPC_SERVICE_WORKER_DATABASE_PASSWORD_REF",
        "TRPC_SERVICE_WORKER_DATABASE_PASSWORD",
    },
    "trpc-migration-secrets": {"TRPC_SERVICE_DATABASE_DSN"},
}


class DeploymentConfigError(ValueError):
    """Raised when the unified runtime configuration is invalid."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise DeploymentConfigError("configuration keys must be strings")
        if key in result:
            raise DeploymentConfigError(f"duplicate configuration key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(  # type: ignore[arg-type]
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _mapping(
    value: object,
    *,
    path: str,
    allowed: set[str],
    required: set[str] = frozenset(),
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DeploymentConfigError(f"{path} must be a mapping")
    keys = set(value)
    unknown = sorted(keys - allowed)
    missing = sorted(required - keys)
    if unknown:
        raise DeploymentConfigError(f"{path} has unknown fields: {', '.join(unknown)}")
    if missing:
        raise DeploymentConfigError(f"{path} is missing fields: {', '.join(missing)}")
    return value


def _string(value: object, *, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DeploymentConfigError(f"{path} must be a non-empty string")
    return value.strip()


def _resolved_path(value: object, *, path: str, base: Path) -> Path:
    raw = _string(value, path=path)
    candidate = Path(os.path.expandvars(raw)).expanduser()
    if not candidate.is_absolute():
        candidate = base / candidate
    return candidate.resolve()


def _timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DeploymentConfigError("kubernetes.timeout_seconds must be numeric")
    timeout = float(value)
    if not 0 < timeout <= 3600:
        raise DeploymentConfigError("kubernetes.timeout_seconds must be within 0..3600")
    return timeout


def _port(value: object, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1024 <= value <= 65535:
        raise DeploymentConfigError(f"compose.ports.{name} must be an integer within 1024..65535")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _image_references(binding_path: Path) -> tuple[str, str, Mapping[str, Any]]:
    try:
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DeploymentConfigError("release.image_binding must be readable JSON") from error
    if not isinstance(binding, Mapping):
        raise DeploymentConfigError("release.image_binding must contain a JSON object")
    images = binding.get("images")
    if not isinstance(images, Mapping):
        raise DeploymentConfigError("release.image_binding has no images mapping")
    references: list[str] = []
    for name in ("initial", "upgrade"):
        image = images.get(name)
        reference = image.get("reference") if isinstance(image, Mapping) else None
        if (
            not isinstance(reference, str)
            or IMAGE_REFERENCE_RE.fullmatch(reference) is None
            or "/" not in reference.split("@", 1)[0]
        ):
            raise DeploymentConfigError(
                f"release.image_binding images.{name}.reference must be an "
                "immutable registry reference"
            )
        references.append(reference)
    if references[0] == references[1]:
        raise DeploymentConfigError("initial and upgrade image references must differ")
    return references[0], references[1], binding


def _validate_registry_host(value: str, *, path: str) -> str:
    """Validate a registry host without accepting a repository path or URL."""

    if REGISTRY_HOST_RE.fullmatch(value) is None:
        raise DeploymentConfigError(
            f"{path} must be a registry host without scheme or repository path"
        )
    if value.endswith("."):
        raise DeploymentConfigError(f"{path} must not end with a dot")
    return value


def _rewrite_image_registry(reference: str, pull_registry: str | None) -> str:
    """Replace only the registry host and preserve repository path and digest."""

    if IMAGE_REFERENCE_RE.fullmatch(reference) is None:
        raise DeploymentConfigError("image reference must be an immutable sha256 reference")
    repository, digest = reference.rsplit("@", 1)
    if "/" not in repository:
        raise DeploymentConfigError("image reference must include a registry host and repository")
    _, image_path = repository.split("/", 1)
    if not image_path:
        raise DeploymentConfigError("image reference repository path is empty")
    if pull_registry is None:
        return reference
    return f"{pull_registry}/{image_path}@{digest}"


@dataclass(frozen=True)
class RuntimeGateConfig:
    """Validated configuration and its secret-safe environment projection."""

    path: Path
    release_id: str
    nonce_env: str
    image_binding: Path
    kubeconfig: Path
    context: str
    timeout_seconds: float
    secret_manifest: Path
    image_pull_secret: str
    pull_registry: str | None
    node_name: str
    node_label: str
    drain_confirmation: str
    hpa_driver: Path
    hpa_kubeconfig: Path
    hpa_context: str
    hpa_subject: str
    hpa_job_image: str
    hpa_job_command: tuple[str, ...]
    ports: Mapping[str, int]

    def canonical_image_references(self) -> dict[str, str]:
        """Return the exact immutable references recorded by the release binding."""

        initial, upgrade, _ = _image_references(self.image_binding)
        return {"initial": initial, "upgrade": upgrade}

    def resolved_image_references(self) -> dict[str, str]:
        """Return runtime references after the optional pull-host rewrite."""

        return {
            name: _rewrite_image_registry(reference, self.pull_registry)
            for name, reference in self.canonical_image_references().items()
        }

    def environment(self, source: Mapping[str, str] | None = None) -> dict[str, str]:
        values = os.environ if source is None else source
        nonce = values.get(self.nonce_env, "")
        if RELEASE_NONCE_RE.fullmatch(nonce) is None:
            raise DeploymentConfigError(
                f"release nonce environment {self.nonce_env} is missing or invalid"
            )
        binding = _image_references(self.image_binding)[2]
        resolved_images = self.resolved_image_references()
        release_binding = binding.get("release_binding")
        binding_release = (
            release_binding.get("release_id") if isinstance(release_binding, Mapping) else None
        )
        if binding_release != self.release_id:
            raise DeploymentConfigError("image binding release_id does not match configuration")
        expected_nonce_hash = hashlib.sha256(nonce.encode()).hexdigest()
        binding_nonce_hash = (
            release_binding.get("nonce_sha256")
            if isinstance(release_binding, Mapping)
            else None
        )
        if binding_nonce_hash != expected_nonce_hash:
            raise DeploymentConfigError("image binding release nonce does not match configuration")
        binding_source = binding.get("source_fingerprint")
        binding_source_value = (
            binding_source.get("value") if isinstance(binding_source, Mapping) else None
        )
        checkout_source = source_fingerprint(ROOT).get("value")
        if binding_source_value != checkout_source:
            raise DeploymentConfigError("image binding source fingerprint does not match checkout")
        environment = {
            "KUBECONFIG": str(self.kubeconfig),
            "TRPC_RELEASE_ID": self.release_id,
            "TRPC_RELEASE_NONCE": nonce,
            "TRPC_K8S_RUNTIME_TESTS_ENABLED": "true",
            "TRPC_K8S_RUNTIME_CONTEXT": self.context,
            "TRPC_K8S_RUNTIME_TIMEOUT_SECONDS": str(self.timeout_seconds),
            "TRPC_K8S_RUNTIME_IMAGE": resolved_images["initial"],
            "TRPC_K8S_RUNTIME_UPGRADE_IMAGE": resolved_images["upgrade"],
            "TRPC_K8S_RUNTIME_SECRET_MANIFEST": str(self.secret_manifest),
            "TRPC_K8S_RUNTIME_IMAGE_PULL_SECRET": self.image_pull_secret,
            "TRPC_K8S_RUNTIME_HPA_DRIVER": str(self.hpa_driver),
            "TRPC_K8S_RUNTIME_HPA_DRIVER_SHA256": _sha256(self.hpa_driver),
            "TRPC_K8S_RUNTIME_HPA_DRIVER_KUBECONFIG": str(self.hpa_kubeconfig),
            "TRPC_K8S_RUNTIME_HPA_DRIVER_SUBJECT": self.hpa_subject,
            "TRPC_K8S_RUNTIME_HPA_DRIVER_CONTEXT": self.hpa_context,
            "TRPC_K8S_RUNTIME_HPA_JOB_IMAGE": self.hpa_job_image,
            "TRPC_K8S_RUNTIME_HPA_JOB_COMMAND": json.dumps(
                self.hpa_job_command, separators=(",", ":")
            ),
            "TRPC_K8S_RUNTIME_NODE_NAME": self.node_name,
            "TRPC_K8S_RUNTIME_NODE_LABEL": self.node_label,
            "TRPC_K8S_RUNTIME_NODE_DRAIN_CONFIRM": self.drain_confirmation,
        }
        environment.update(
            {PORT_ENVIRONMENTS[name]: str(value) for name, value in self.ports.items()}
        )
        return environment


def load_runtime_gate_config(path: Path) -> RuntimeGateConfig:
    """Load a single strict YAML document without resolving Secret values."""

    resolved = path.expanduser().resolve()
    try:
        raw = yaml.load(resolved.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)  # noqa: S506
    except (OSError, yaml.YAMLError) as error:
        raise DeploymentConfigError("runtime gate config is not readable YAML") from error
    root = _mapping(
        raw,
        path="config",
        allowed={"schema_version", "release", "kubernetes", "compose"},
        required={"schema_version", "release", "kubernetes"},
    )
    if root["schema_version"] != 1:
        raise DeploymentConfigError("schema_version must be 1")
    base = resolved.parent
    release = _mapping(
        root["release"],
        path="release",
        allowed={"id", "nonce_env", "image_binding"},
        required={"id", "nonce_env", "image_binding"},
    )
    release_id = _string(release["id"], path="release.id")
    if RELEASE_ID_RE.fullmatch(release_id) is None:
        raise DeploymentConfigError("release.id is invalid")
    nonce_env = _string(release["nonce_env"], path="release.nonce_env")
    if re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", nonce_env) is None:
        raise DeploymentConfigError("release.nonce_env must name an environment variable")
    kubernetes = _mapping(
        root["kubernetes"],
        path="kubernetes",
        allowed={
            "kubeconfig",
            "context",
            "timeout_seconds",
            "secret_manifest",
            "image_pull_secret",
            "pull_registry",
            "node",
            "hpa",
        },
        required={
            "kubeconfig",
            "context",
            "timeout_seconds",
            "secret_manifest",
            "image_pull_secret",
            "node",
            "hpa",
        },
    )
    image_pull_secret = _string(
        kubernetes["image_pull_secret"], path="kubernetes.image_pull_secret"
    )
    if KUBERNETES_NAME_RE.fullmatch(image_pull_secret) is None:
        raise DeploymentConfigError("kubernetes.image_pull_secret is invalid")
    raw_pull_registry = kubernetes.get("pull_registry")
    pull_registry = None
    if raw_pull_registry is not None:
        pull_registry = _validate_registry_host(
            _string(raw_pull_registry, path="kubernetes.pull_registry"),
            path="kubernetes.pull_registry",
        )
    node = _mapping(
        kubernetes["node"],
        path="kubernetes.node",
        allowed={"name", "label", "drain_confirmation"},
        required={"name", "label", "drain_confirmation"},
    )
    node_name = _string(node["name"], path="kubernetes.node.name")
    node_label = _string(node["label"], path="kubernetes.node.label")
    if KUBERNETES_NAME_RE.fullmatch(node_name) is None or NODE_LABEL_RE.fullmatch(
        node_label
    ) is None:
        raise DeploymentConfigError("kubernetes.node name or label is invalid")
    drain_confirmation = _string(
        node["drain_confirmation"], path="kubernetes.node.drain_confirmation"
    )
    if drain_confirmation != "I_UNDERSTAND_ISOLATED_NODE_DRAIN":
        raise DeploymentConfigError("kubernetes.node.drain_confirmation is invalid")
    hpa = _mapping(
        kubernetes["hpa"],
        path="kubernetes.hpa",
        allowed={"driver", "kubeconfig", "context", "subject", "job_image", "job_command"},
        required={"driver", "kubeconfig", "context", "subject", "job_image", "job_command"},
    )
    subject = _string(hpa["subject"], path="kubernetes.hpa.subject")
    if SUBJECT_RE.fullmatch(subject) is None:
        raise DeploymentConfigError("kubernetes.hpa.subject is invalid")
    hpa_job_image = _string(hpa["job_image"], path="kubernetes.hpa.job_image")
    if IMAGE_REFERENCE_RE.fullmatch(hpa_job_image) is None:
        raise DeploymentConfigError(
            "kubernetes.hpa.job_image must be an immutable sha256 reference"
        )
    job_command = hpa["job_command"]
    if (
        not isinstance(job_command, Sequence)
        or isinstance(job_command, (str, bytes))
        or not 1 <= len(job_command) <= HPA_JOB_COMMAND_MAX_ARGS
        or any(
            not isinstance(item, str)
            or not item
            or len(item.encode("utf-8")) > HPA_JOB_COMMAND_MAX_ITEM_BYTES
            or any(character in item for character in ("\x00", "\r", "\n"))
            for item in job_command
        )
    ):
        raise DeploymentConfigError("kubernetes.hpa.job_command must be a bounded argv list")
    compose = _mapping(
        root.get("compose", {}),
        path="compose",
        allowed={"ports"},
    )
    ports_raw = _mapping(
        compose.get("ports", {}),
        path="compose.ports",
        allowed=set(PORT_ENVIRONMENTS),
    )
    ports = {name: _port(value, name=name) for name, value in ports_raw.items()}
    if len(set(ports.values())) != len(ports):
        raise DeploymentConfigError("compose.ports values must be unique")
    return RuntimeGateConfig(
        path=resolved,
        release_id=release_id,
        nonce_env=nonce_env,
        image_binding=_resolved_path(
            release["image_binding"], path="release.image_binding", base=base
        ),
        kubeconfig=_resolved_path(
            kubernetes["kubeconfig"], path="kubernetes.kubeconfig", base=base
        ),
        context=_string(kubernetes["context"], path="kubernetes.context"),
        timeout_seconds=_timeout(kubernetes["timeout_seconds"]),
        secret_manifest=_resolved_path(
            kubernetes["secret_manifest"], path="kubernetes.secret_manifest", base=base
        ),
        image_pull_secret=image_pull_secret,
        pull_registry=pull_registry,
        node_name=node_name,
        node_label=node_label,
        drain_confirmation=drain_confirmation,
        hpa_driver=_resolved_path(hpa["driver"], path="kubernetes.hpa.driver", base=base),
        hpa_kubeconfig=_resolved_path(
            hpa["kubeconfig"], path="kubernetes.hpa.kubeconfig", base=base
        ),
        hpa_context=_string(hpa["context"], path="kubernetes.hpa.context"),
        hpa_subject=subject,
        hpa_job_image=hpa_job_image,
        hpa_job_command=tuple(job_command),
        ports=ports,
    )


def secret_manifest_contract(path: Path) -> dict[str, dict[str, Any]]:
    """Return the Secret metadata contract without exposing any values."""

    try:
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError) as error:
        raise DeploymentConfigError("kubernetes.secret_manifest is not readable YAML") from error
    metadata: dict[str, dict[str, Any]] = {}
    for document in documents:
        if not isinstance(document, Mapping) or document.get("kind") != "Secret":
            raise DeploymentConfigError(
                "kubernetes.secret_manifest may contain only Secret objects"
            )
        resource_metadata = document.get("metadata")
        name = resource_metadata.get("name") if isinstance(resource_metadata, Mapping) else None
        if not isinstance(name, str) or KUBERNETES_NAME_RE.fullmatch(name) is None:
            raise DeploymentConfigError(
                "kubernetes.secret_manifest contains an invalid Secret name"
            )
        if name in metadata:
            raise DeploymentConfigError(f"duplicate Secret in manifest: {name}")
        namespace = resource_metadata.get("namespace")
        if namespace is not None and (
            not isinstance(namespace, str)
            or KUBERNETES_NAME_RE.fullmatch(namespace) is None
        ):
            raise DeploymentConfigError(
                f"Secret {name} contains an invalid metadata.namespace"
            )
        resource_type = document.get("type", "Opaque")
        if not isinstance(resource_type, str) or not resource_type:
            raise DeploymentConfigError(f"Secret {name} contains an invalid type")
        data = document.get("data", {})
        string_data = document.get("stringData", {})
        if not isinstance(data, Mapping) or not isinstance(string_data, Mapping):
            raise DeploymentConfigError(f"Secret {name} data must be a mapping")
        metadata[name] = {
            "keys": {str(key) for key in data} | {str(key) for key in string_data},
            "namespace": namespace or "",
            "type": resource_type,
        }
    return metadata


def secret_manifest_metadata(path: Path) -> dict[str, set[str]]:
    """Return Secret names and key names without exposing any values."""

    contract = secret_manifest_contract(path)
    return {name: set(entry["keys"]) for name, entry in contract.items()}
