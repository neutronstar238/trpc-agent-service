#!/usr/bin/env python3
"""Preflight and optionally execute the local multi-node Kubernetes gate.

The gate is deliberately conservative:

* without ``--execute`` it only renders ``deploy/kind`` and inspects the
  resulting objects; it never talks to Docker, kind or a Kubernetes API;
* ``--execute`` is required before a cluster can be created or changed and is
  restricted to the exact ``kind-<cluster-name>`` context;
* the report binds the checkout SHA, source fingerprint, immutable image
  digest (when available) and Kubernetes cluster UID;
* a local kind pass is never reported as an ACK/production pass.

The live scenarios run the candidate image itself as short-lived acceptance
driver Pods.  Drivers exercise the real gateway/repositories and use the
fake provider only as a cross-Pod side-effect oracle.  Every driver receives
configuration through Secret/ConfigMap ``envFrom`` and is deleted by exact Pod
name after its final keyless JSON line is collected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only without the dev extra
    yaml = None

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.evidence_lineage import source_fingerprint
from scripts.report_io import atomic_write_json

ROOT = Path(__file__).resolve().parents[1]
KIND_DIR = ROOT / "deploy" / "kind"
KIND_CONFIG = KIND_DIR / "cluster.yaml"
DEFAULT_CLUSTER_NAME = "trpc-cell-kind"
DEFAULT_NAMESPACE = "trpc-cell-kind"
DEFAULT_IMAGE = "docker.io/example/trpc-agent-service:kind"
DEFAULT_RENDER_OUTPUT = ROOT / "runs" / "multitenant" / "kind-ack-manifests.yaml"
DEFAULT_REPORT = ROOT / "runs" / "multitenant" / "kind-ack-gate.json"
DEFAULT_ROLLOUT_TIMEOUT_SECONDS = 360.0
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-fA-F]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
CLUSTER_NAME_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
SAFE_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9./_:@-]{0,255}$")
DEFAULT_KUSTOMIZE_IMAGE = "docker.io/example/trpc-agent-service:kind"
IMAGE_SOURCE_FINGERPRINT_LABEL = "io.trpc.agent-service.source-fingerprint"
SOURCE_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
KIND_NODE_ROLE_LABEL = "trpc.io/node-role"
KIND_POOL_LABEL = "trpc.io/kind-pool"
KIND_WORKER_POOL_NAMES = frozenset({"gateway", "support"})
SCHEMA_MIGRATION_JOB_NAME = "trpc-schema-migration"
EXPECTED_ALEMBIC_HEAD = "0028_evolution_least_privilege"
ALEMBIC_REVISION_RE = re.compile(r"^[0-9]{4}_[a-z0-9_]+$")
REQUIRED_DEPLOYMENTS = {
    "trpc-gateway": 2,
    "trpc-worker": 3,
    "trpc-admin": 1,
    "trpc-outbox-dispatcher": 2,
    "trpc-channel-dispatcher": 2,
    "trpc-post-turn-projector": 1,
    "trpc-session-recovery": 2,
    "trpc-backlog-exporter": 1,
}
REQUIRED_OBJECTS = {
    ("StatefulSet", "kind-postgres"),
    ("StatefulSet", "kind-redis"),
    ("StatefulSet", "kind-fake-provider"),
    ("StatefulSet", "kind-fake-im"),
    ("Service", "postgres"),
    ("Service", "redis"),
    ("Service", "kind-fake-provider"),
    ("Service", "kind-fake-im"),
    ("Job", "trpc-schema-migration"),
}
SCENARIO_PLAN = {
    "candidate_im_gateway_probe": {
        "assertion": (
            "candidate image proves Feishu callback idempotency, RLS and signature rejection"
        ),
        "fault": "100 concurrent encrypted callbacks and one invalid signature",
    },
    "candidate_runtime_probe": {
        "assertion": (
            "candidate repositories prove duplicate IM and effect reconciliation against PostgreSQL"
        ),
        "fault": "cross-Pod provider response loss and concurrent duplicate delivery",
    },
    "candidate_evolution_probe": {
        "assertion": "candidate evolution control proves certificate, CAS and rollback invariants",
        "fault": "tampered, expired, cross-tenant and stale promotion evidence",
    },
    "candidate_redis_probe": {
        "assertion": (
            "production RedisStreamQueue proves publish idempotency, PEL takeover and exact ACK"
        ),
        "fault": "duplicate publish, abandoned PEL owner and XAUTOCLAIM transfer",
    },
    "worker_pod_replacement": {
        "assertion": "a replacement worker becomes ready without a second provider call",
        "fault": "worker process/pod failure",
    },
    "provider_endpoint_recovery": {
        "assertion": "provider restart restores endpoint and preserves idempotency state",
        "fault": "temporary provider endpoint outage",
    },
    "postgres_pod_replacement": {
        "assertion": (
            "PostgreSQL replacement keeps the same PVC and persistent rows "
            "while applications recover"
        ),
        "fault": "database Pod failure and connection pool recovery",
    },
}


@dataclass(frozen=True, slots=True)
class CommandResult:
    status: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    reason: str | None = None


def _run(
    argv: list[str],
    *,
    cwd: Path = ROOT,
    input_text: str | None = None,
    timeout: float = 120.0,
) -> CommandResult:
    """Run a fixed argv without a shell and discard unbounded failure output."""

    if not argv:
        return CommandResult("fail", reason="empty command")
    executable = shutil.which(argv[0])
    if executable is None:
        return CommandResult("not_run", reason=f"{argv[0]} is not installed")
    try:
        completed = subprocess.run(  # noqa: S603 - argv is built from fixed commands
            [executable, *argv[1:]],
            cwd=cwd,
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return CommandResult("fail", reason=f"{argv[0]} timed out")
    except OSError as error:
        return CommandResult("fail", reason=f"{argv[0]} failed: {type(error).__name__}")
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    return CommandResult(
        "pass" if completed.returncode == 0 else "fail",
        completed.returncode,
        stdout if completed.returncode == 0 else stdout[-20000:],
        stderr[-2000:],
        None if completed.returncode == 0 else f"{argv[0]} exited {completed.returncode}",
    )


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _git_sha() -> str | None:
    for name in ("GITHUB_SHA", "CI_COMMIT_SHA"):
        value = os.environ.get(name, "").strip()
        if GIT_SHA_RE.fullmatch(value):
            return value.lower()
    result = _run(["git", "rev-parse", "--verify", "HEAD"], timeout=5)
    value = result.stdout.strip()
    return value.lower() if result.status == "pass" and GIT_SHA_RE.fullmatch(value) else None


def _source_lineage() -> dict[str, Any]:
    value = source_fingerprint(ROOT)
    if not isinstance(value, dict):
        return {"status": "unavailable"}
    return {
        "algorithm": value.get("algorithm"),
        "status": value.get("status"),
        "value": value.get("value"),
        "file_count": value.get("file_count"),
        "total_bytes": value.get("total_bytes"),
    }


def _registry_for(reference: str) -> str:
    first = reference.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return first
    return "docker.io"


def _image_identity(
    reference: str, *, loaded: bool = False, digest: str | None = None
) -> dict[str, Any]:
    """Return safe image metadata; never inspect or report registry credentials."""

    value = reference.strip()
    valid_shape = bool(value) and bool(SAFE_IMAGE_RE.fullmatch(value))
    parsed_digest: str | None = None
    if "@" in value:
        _, parsed = value.rsplit("@", 1)
        if IMAGE_DIGEST_RE.fullmatch(parsed):
            parsed_digest = parsed.lower()
        else:
            valid_shape = False
    effective_digest = (
        digest.lower() if digest and IMAGE_DIGEST_RE.fullmatch(digest) else parsed_digest
    )
    if digest and effective_digest is None:
        valid_shape = False
    return {
        "reference": value,
        "registry": _registry_for(value) if value else None,
        "digest": effective_digest,
        "immutable": effective_digest is not None or loaded,
        "source": "local-loaded" if loaded else "registry",
        "shape_valid": valid_shape,
    }


def _image_contract(image: str, *, execute: bool, load_image: bool) -> tuple[str, tuple[str, ...]]:
    metadata = _image_identity(image, loaded=load_image)
    reasons: list[str] = []
    if not metadata["shape_valid"]:
        reasons.append("image reference contains invalid characters or digest syntax")
    if execute and not metadata["immutable"]:
        reasons.append("execute mode requires a digest reference or --load-image")
    if reasons:
        return "fail", tuple(reasons)
    if not metadata["immutable"]:
        return "not_run", (
            "preflight image is tag-only; execute mode will require digest or --load-image",
        )
    return "pass", ()


def _load_yaml_documents(text: str) -> list[dict[str, Any]]:
    if yaml is None:
        raise RuntimeError("PyYAML is required to inspect rendered Kubernetes objects")
    documents: list[dict[str, Any]] = []
    try:
        for document in yaml.safe_load_all(text):
            if isinstance(document, dict) and document.get("kind") and document.get("metadata"):
                documents.append(document)
    except Exception as error:
        raise RuntimeError("Kustomize returned invalid YAML") from error
    return documents


def _render(image: str, output: Path) -> tuple[CommandResult, list[dict[str, Any]]]:
    """Render through kubectl without contacting a Kubernetes API."""

    result = _run(["kubectl", "kustomize", str(KIND_DIR)], timeout=120)
    if result.status != "pass":
        return result, []
    rendered = result.stdout.replace(f"image: {DEFAULT_KUSTOMIZE_IMAGE}", f"image: {image.strip()}")
    try:
        documents = _load_yaml_documents(rendered)
    except (RuntimeError, ValueError) as error:
        return CommandResult(
            "fail", reason=f"rendered manifest is invalid: {type(error).__name__}"
        ), []
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    return CommandResult("pass"), documents


def _manifest_inventory(documents: list[dict[str, Any]]) -> dict[str, Any]:
    objects: set[tuple[str, str]] = set()
    deployments: dict[str, int] = {}
    namespaces: list[str] = []
    insecure: list[str] = []
    for document in documents:
        kind = document.get("kind")
        metadata = document.get("metadata")
        if not isinstance(kind, str) or not isinstance(metadata, dict):
            continue
        name = metadata.get("name")
        if not isinstance(name, str):
            continue
        objects.add((kind, name))
        if kind == "Namespace":
            namespaces.append(name)
        if kind == "Deployment":
            spec = document.get("spec")
            replicas = spec.get("replicas", 1) if isinstance(spec, dict) else 1
            if isinstance(replicas, int):
                deployments[name] = replicas
        pod_spec = None
        spec = document.get("spec")
        if isinstance(spec, dict):
            template = spec.get("template")
            if isinstance(template, dict):
                pod_spec = template.get("spec")
        if isinstance(pod_spec, dict) and pod_spec.get("hostNetwork"):
            insecure.append(f"{kind}/{name}:hostNetwork")
        containers = pod_spec.get("containers") if isinstance(pod_spec, dict) else None
        if isinstance(containers, list):
            for container in containers:
                if isinstance(container, dict) and container.get("securityContext", {}).get(
                    "privileged"
                ):
                    insecure.append(f"{kind}/{name}:privileged")
    missing_objects = sorted(REQUIRED_OBJECTS - objects)
    missing_deployments = sorted(
        name
        for name, replicas in REQUIRED_DEPLOYMENTS.items()
        if name not in deployments or replicas < 1
    )
    return {
        "object_count": len(objects),
        "objects": sorted(f"{kind}/{name}" for kind, name in objects),
        "namespaces": namespaces,
        "deployments": deployments,
        "missing_objects": [f"{kind}/{name}" for kind, name in missing_objects],
        "missing_deployments": missing_deployments,
        "insecure_objects": insecure,
    }


def _topology_contract() -> tuple[str, tuple[str, ...], dict[str, Any]]:
    if yaml is None:
        return "not_run", ("PyYAML is required to inspect cluster.yaml",), {}
    try:
        config = yaml.safe_load(KIND_CONFIG.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        return "fail", (f"kind config could not be read: {type(error).__name__}",), {}
    nodes = config.get("nodes") if isinstance(config, dict) else None
    if not isinstance(nodes, list):
        return "fail", ("kind config has no nodes list",), {}
    roles = [node.get("role") for node in nodes if isinstance(node, dict)]
    counts = {role: roles.count(role) for role in {"control-plane", "worker"}}
    reasons: list[str] = []
    if counts.get("control-plane") != 1:
        reasons.append("kind topology requires exactly one control-plane")
    if counts.get("worker") != 3:
        reasons.append("kind topology requires exactly three workers")
    return ("fail" if reasons else "pass", tuple(reasons), {"roles": roles, "counts": counts})


def _preflight(
    image: str, render_output: Path, *, execute: bool, load_image: bool
) -> dict[str, Any]:
    reasons: list[str] = []
    files = (
        KIND_CONFIG,
        KIND_DIR / "kustomization.yaml",
        KIND_DIR / "namespace.yaml",
        KIND_DIR / "kind-config-patch.yaml",
        KIND_DIR / "kind-replicas-patch.yaml",
        KIND_DIR / "kind-secrets.yaml",
        KIND_DIR / "kind-postgres.yaml",
        KIND_DIR / "kind-redis.yaml",
        KIND_DIR / "kind-fake-services.yaml",
        KIND_DIR / "kind-network-policy.yaml",
    )
    files_status = "pass" if all(path.is_file() for path in files) else "fail"
    if files_status != "pass":
        reasons.append("kind deployment directory is incomplete")
    topology_status, topology_reasons, topology = _topology_contract()
    reasons.extend(topology_reasons)
    image_status, image_reasons = _image_contract(image, execute=execute, load_image=load_image)
    if image_status == "fail":
        reasons.extend(image_reasons)
    render_result, documents = _render(image, render_output)
    inventory = _manifest_inventory(documents) if documents else {}
    if render_result.status != "pass":
        reasons.append(render_result.reason or "Kustomize render failed")
    elif inventory.get("missing_objects") or inventory.get("missing_deployments"):
        reasons.append("rendered kind manifest is missing required runtime objects")
    if inventory.get("insecure_objects"):
        reasons.append("rendered kind manifest contains an insecure workload")
    render_status = render_result.status
    if render_status == "not_run" and not reasons:
        reasons.append(render_result.reason or "Kustomize renderer unavailable")
    return {
        "status": "fail" if reasons else "pass",
        "rejection_reasons": list(dict.fromkeys(reasons)),
        "checks": {
            "kind_files": {"status": files_status},
            "topology": {"status": topology_status, **topology},
            "image": {"status": image_status, **_image_identity(image, loaded=load_image)},
            "kustomize_render": {
                "status": render_status,
                "output": str(render_output),
                "reason": render_result.reason,
                "inventory": inventory,
            },
        },
    }


def _kubectl(
    context: str, arguments: list[str], *, input_text: str | None = None, timeout: float = 120
) -> CommandResult:
    return _run(
        ["kubectl", "--context", context, *arguments], input_text=input_text, timeout=timeout
    )


def _kind_cluster_exists(cluster_name: str) -> tuple[bool, str | None]:
    result = _run(["kind", "get", "clusters"], timeout=15)
    if result.status != "pass":
        return False, result.reason
    return cluster_name in {line.strip() for line in result.stdout.splitlines()}, None


def _cluster_uid(context: str) -> tuple[str | None, str | None]:
    result = _kubectl(context, ["get", "namespace", "kube-system", "-o", "json"], timeout=20)
    if result.status != "pass":
        return None, result.reason or "cluster UID query failed"
    try:
        payload = json.loads(result.stdout)
        uid = payload.get("metadata", {}).get("uid")
    except (json.JSONDecodeError, AttributeError):
        uid = None
    return (uid, None) if isinstance(uid, str) and uid else (None, "cluster UID was not returned")


def _cluster_node_contract(context: str) -> tuple[dict[str, int], str | None]:
    """Verify the live cluster still has exactly the declared 1+3 topology."""

    result = _kubectl(context, ["get", "nodes", "-o", "json"], timeout=20)
    if result.status != "pass":
        return {}, result.reason or "cluster node inventory failed"
    try:
        items = json.loads(result.stdout).get("items", [])
    except (json.JSONDecodeError, AttributeError):
        return {}, "cluster node inventory was invalid JSON"
    if not isinstance(items, list):
        return {}, "cluster node inventory was not a list"
    control_plane = 0
    for item in items:
        labels = item.get("metadata", {}).get("labels", {}) if isinstance(item, dict) else {}
        if isinstance(labels, dict) and "node-role.kubernetes.io/control-plane" in labels:
            control_plane += 1
    counts = {
        "control_plane": control_plane,
        "workers": len(items) - control_plane,
        "total": len(items),
    }
    if counts != {"control_plane": 1, "workers": 3, "total": 4}:
        return (
            counts,
            "live kind cluster topology is not exactly one control-plane and three workers",
        )
    return counts, None


def _parse_kind_node_inventory(text: str) -> tuple[dict[str, Any], str | None]:
    try:
        payload = json.loads(text)
    except (AttributeError, json.JSONDecodeError):
        return {}, "kind node inventory was invalid JSON"
    if not isinstance(payload, Mapping):
        return {}, "kind node inventory was not an object"
    items = payload.get("items")
    if not isinstance(items, list):
        return {}, "kind node inventory was not a list"

    control_plane_nodes: list[str] = []
    worker_nodes: list[str] = []
    unclassified_nodes: list[str] = []
    malformed_nodes: list[str] = []
    control_plane_pools: dict[str, Any] = {}
    worker_pools: dict[str, Any] = {}
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            malformed_nodes.append(f"item-{index}")
            continue
        metadata = item.get("metadata")
        if not isinstance(metadata, Mapping):
            malformed_nodes.append(f"item-{index}")
            continue
        name = metadata.get("name")
        labels = metadata.get("labels")
        if not isinstance(name, str) or not name or not isinstance(labels, Mapping):
            malformed_nodes.append(name if isinstance(name, str) and name else f"item-{index}")
            continue
        role = labels.get(KIND_NODE_ROLE_LABEL)
        is_control_plane = (
            "node-role.kubernetes.io/control-plane" in labels or role == "control-plane"
        )
        is_worker = role == "agent-worker"
        pool = labels.get(KIND_POOL_LABEL)
        if is_control_plane:
            control_plane_nodes.append(name)
            control_plane_pools[name] = pool
            if is_worker:
                malformed_nodes.append(f"{name}:control-plane-worker")
        elif is_worker:
            worker_nodes.append(name)
            worker_pools[name] = pool
        else:
            unclassified_nodes.append(name)

    return {
        "control_plane_nodes": sorted(control_plane_nodes),
        "worker_nodes": sorted(worker_nodes),
        "unclassified_nodes": sorted(unclassified_nodes),
        "malformed_nodes": sorted(malformed_nodes),
        "control_plane_pools": control_plane_pools,
        "worker_pools": worker_pools,
    }, None


def _read_kind_node_inventory(context: str) -> tuple[dict[str, Any], str | None]:
    result = _kubectl(context, ["get", "nodes", "-o", "json"], timeout=30)
    if result.status != "pass":
        return {}, result.reason or "kind node inventory was unavailable"
    return _parse_kind_node_inventory(result.stdout)


def _kind_node_pool_contract(
    context: str, cluster_name: str, *, execute: bool
) -> tuple[str, dict[str, Any], str | None]:
    """Label and verify the deterministic worker pools for one exact kind context."""

    if not execute:
        return "not_run", {}, "kind node pool labeling requires --execute"
    expected_context = f"kind-{cluster_name}"
    if context != expected_context or not context.startswith("kind-"):
        return "fail", {}, "node pool labeling requires the exact kind context"

    before, reason = _read_kind_node_inventory(context)
    if reason:
        return "fail", {}, reason
    control_plane_nodes = before["control_plane_nodes"]
    worker_nodes = before["worker_nodes"]
    invalid = before["malformed_nodes"] + before["unclassified_nodes"]
    if len(control_plane_nodes) != 1 or len(worker_nodes) != 3 or invalid:
        evidence = {
            "control_plane_nodes": control_plane_nodes,
            "worker_nodes": worker_nodes,
            "unclassified_nodes": before["unclassified_nodes"],
            "malformed_nodes": before["malformed_nodes"],
        }
        return (
            "fail",
            evidence,
            "kind node inventory must contain exactly one control-plane and three workers",
        )
    if any(value in KIND_WORKER_POOL_NAMES for value in before["control_plane_pools"].values()):
        return (
            "fail",
            {
                "control_plane_nodes": control_plane_nodes,
                "control_plane_pools": before["control_plane_pools"],
                "worker_nodes": worker_nodes,
            },
            "control-plane must not carry a worker pool label",
        )

    expected_pools = {
        node: "gateway" if index < 2 else "support" for index, node in enumerate(worker_nodes)
    }
    label_commands: list[dict[str, str]] = []
    for node, pool in expected_pools.items():
        result = _kubectl(
            context,
            ["label", "node", node, f"{KIND_POOL_LABEL}={pool}", "--overwrite"],
            timeout=30,
        )
        label_commands.append({"node": node, "pool": pool, "status": result.status})
        if result.status != "pass":
            return (
                "fail",
                {
                    "control_plane_nodes": control_plane_nodes,
                    "worker_nodes": worker_nodes,
                    "expected_pools": expected_pools,
                    "label_commands": label_commands,
                },
                result.reason or f"failed to label worker node {node}",
            )

    after, reason = _read_kind_node_inventory(context)
    if reason:
        return (
            "fail",
            {"expected_pools": expected_pools, "label_commands": label_commands},
            reason,
        )
    if (
        after["control_plane_nodes"] != control_plane_nodes
        or after["worker_nodes"] != worker_nodes
        or after["unclassified_nodes"]
        or after["malformed_nodes"]
        or after["worker_pools"] != expected_pools
    ):
        return (
            "fail",
            {
                "control_plane_nodes": after["control_plane_nodes"],
                "worker_nodes": after["worker_nodes"],
                "expected_pools": expected_pools,
                "observed_pools": after["worker_pools"],
                "label_commands": label_commands,
            },
            "worker node pool labels did not match the deterministic assignment",
        )
    if any(value in KIND_WORKER_POOL_NAMES for value in after["control_plane_pools"].values()):
        return (
            "fail",
            {
                "control_plane_nodes": control_plane_nodes,
                "control_plane_pools": after["control_plane_pools"],
                "worker_pools": after["worker_pools"],
                "label_commands": label_commands,
            },
            "control-plane must not carry a worker pool label",
        )
    return (
        "pass",
        {
            "label": KIND_POOL_LABEL,
            "control_plane_nodes": control_plane_nodes,
            "worker_nodes": worker_nodes,
            "worker_pools": expected_pools,
            "label_commands": label_commands,
        },
        None,
    )


def _docker_image_metadata(
    image: str,
) -> tuple[str | None, str | None, str | None]:
    """Read only the immutable ID and source label needed for image lineage.

    Docker's inspect output is deliberately reduced to two scalar fields.  No
    full metadata, environment, labels or command output is ever propagated
    into the gate report because an image can contain credentials in any of
    those fields.
    """

    result = _run(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            f'{{{{.Id}}}}|{{{{index .Config.Labels "{IMAGE_SOURCE_FINGERPRINT_LABEL}"}}}}',
            image,
        ],
        timeout=30,
    )
    if result.status != "pass":
        return None, None, result.reason or "local image inspection failed"
    value = result.stdout.strip()
    digest, separator, fingerprint = value.partition("|")
    if not separator or IMAGE_DIGEST_RE.fullmatch(digest) is None:
        return None, None, "local image ID is not a sha256 digest"
    if SOURCE_FINGERPRINT_RE.fullmatch(fingerprint) is None:
        return None, None, "local image source fingerprint label is missing or invalid"
    return digest.lower(), fingerprint, None


def _docker_image_digest(image: str) -> tuple[str | None, str | None]:
    """Compatibility wrapper returning only the immutable image ID."""

    digest, _fingerprint, reason = _docker_image_metadata(image)
    return digest, reason


def _load_local_image(cluster_name: str, image: str) -> tuple[str, str | None, str | None]:
    digest, observed_fingerprint, reason = _docker_image_metadata(image)
    if reason:
        return "fail", None, reason
    expected_lineage = _source_lineage()
    expected_fingerprint = expected_lineage.get("value")
    if (
        expected_lineage.get("status") != "available"
        or not isinstance(expected_fingerprint, str)
        or SOURCE_FINGERPRINT_RE.fullmatch(expected_fingerprint) is None
    ):
        return "fail", None, "current checkout source fingerprint is unavailable"
    if observed_fingerprint != expected_fingerprint:
        return "fail", None, "local image source fingerprint does not match current checkout"
    result = _run(["kind", "load", "docker-image", image, "--name", cluster_name], timeout=300)
    return result.status, digest, result.reason


def _runtime_wait_targets(documents: list[dict[str, Any]]) -> tuple[tuple[str, str], ...]:
    """Return readiness targets in manifest order with kind-only fallbacks."""

    targets: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, name: str) -> None:
        target = (kind, name)
        if target not in seen:
            seen.add(target)
            targets.append(target)

    for document in documents:
        kind = document.get("kind")
        metadata = document.get("metadata", {})
        name = metadata.get("name") if isinstance(metadata, dict) else None
        if not isinstance(kind, str) or not isinstance(name, str):
            continue
        if kind in {"Deployment", "StatefulSet"}:
            replicas = document.get("spec", {}).get("replicas", 1)
            if isinstance(replicas, int) and replicas >= 1:
                add(kind, name)
        elif kind == "Job" and name == "trpc-schema-migration":
            add(kind, name)

    # Keep the support fixtures and migration job covered even if an older
    # renderer omits their documents; preflight inventory still rejects that
    # manifest before execute mode can apply it.
    for name in (
        "kind-postgres",
        "kind-redis",
        "kind-fake-provider",
        "kind-fake-im",
    ):
        add("StatefulSet", name)
    add("Job", "trpc-schema-migration")
    return tuple(targets)


def _wait_for_runtime_target(
    context: str, namespace: str, target: tuple[str, str], timeout: float
) -> CommandResult:
    kind, name = target
    if kind == "Job":
        arguments = [
            "-n",
            namespace,
            "wait",
            "--for=condition=complete",
            f"job/{name}",
            f"--timeout={int(timeout)}s",
        ]
    else:
        arguments = [
            "-n",
            namespace,
            "rollout",
            "status",
            f"{kind.lower()}/{name}",
            f"--timeout={int(timeout)}s",
        ]
    return _kubectl(context, arguments, timeout=timeout + 10)


def _wait_for_runtime(
    context: str, namespace: str, documents: list[dict[str, Any]], timeout: float
) -> tuple[str, tuple[str, ...]]:
    """Wait support, migration, then application resources in bounded phases."""

    targets = _runtime_wait_targets(documents)
    support_targets = tuple(target for target in targets if target[0] == "StatefulSet")
    migration_targets = tuple(target for target in targets if target[0] == "Job")
    application_targets = tuple(target for target in targets if target[0] == "Deployment")

    def wait_batch(batch: tuple[tuple[str, str], ...]) -> tuple[str, tuple[str, ...]]:
        if not batch:
            return "pass", ()
        outcomes: dict[tuple[str, str], CommandResult] = {}
        with ThreadPoolExecutor(max_workers=max(1, min(16, len(batch)))) as executor:
            futures = {
                executor.submit(
                    _wait_for_runtime_target, context, namespace, target, timeout
                ): target
                for target in batch
            }
            for future in as_completed(futures):
                target = futures[future]
                try:
                    outcomes[target] = future.result()
                except Exception as error:  # pragma: no cover - defensive worker boundary
                    outcomes[target] = CommandResult(
                        "fail", reason=f"readiness command raised {type(error).__name__}"
                    )
        reasons: list[str] = []
        for kind, name in batch:
            if outcomes[(kind, name)].status == "pass":
                continue
            if kind == "Job":
                reasons.append("schema migration job did not complete")
            else:
                reasons.append(f"{kind.lower()}/{name} did not become ready")
        return ("fail" if reasons else "pass", tuple(reasons))

    status, reasons = wait_batch(support_targets)
    if status != "pass":
        return status, reasons
    status, reasons = wait_batch(migration_targets)
    if status != "pass":
        return status, reasons
    if application_targets:
        restart = _restart_application_deployments(context, namespace, application_targets)
        if restart.status != "pass":
            return "fail", ("application rollout restart after migration failed",)
    return wait_batch(application_targets)


def _restart_application_deployments(
    context: str, namespace: str, targets: tuple[tuple[str, str], ...]
) -> CommandResult:
    names = [f"deployment/{name}" for kind, name in targets if kind == "Deployment"]
    if not names:
        return CommandResult("pass")
    return _kubectl(context, ["-n", namespace, "rollout", "restart", *names], timeout=60)


_PROBE_SCRIPTS = {
    "candidate_im_gateway_probe": ("scripts/kind_im_gateway_probe.py", ()),
    "candidate_runtime_probe": (
        "scripts/kind_runtime_probe.py",
        ("all", "--json", "--keep-fixtures"),
    ),
    "candidate_evolution_probe": (
        "scripts/kind_evolution_probe.py",
        ("--execute", "--json"),
    ),
    "candidate_redis_probe": ("scripts/kind_redis_probe.py", ("--json",)),
}
_PROBE_SECRET_REFS = {
    "scripts/kind_im_gateway_probe.py": ("trpc-service-secrets",),
    "scripts/kind_runtime_probe.py": (
        "trpc-service-secrets",
        "trpc-worker-secrets",
        "trpc-tool-reconciler-secrets",
    ),
    "scripts/kind_evolution_probe.py": (
        "trpc-worker-secrets",
        "trpc-evolution-authority-secrets",
    ),
    "scripts/kind_redis_probe.py": ("trpc-redis-probe-secrets",),
}
_PROBE_REMOTE_WORKLOADS = {
    "scripts/kind_im_gateway_probe.py": ("trpc-gateway",),
    "scripts/kind_runtime_probe.py": ("kind-postgres", "kind-fake-provider"),
    "scripts/kind_evolution_probe.py": ("kind-postgres",),
    "scripts/kind_redis_probe.py": ("kind-redis",),
}
_CANDIDATE_PROBE_CONTRACTS: dict[str, dict[str, Any]] = {
    "scripts/kind_im_gateway_probe.py": {
        "runner_name": "candidate-im-gateway",
        "probe": "kind_im_gateway_probe",
        "scenario": "real_feishu_gateway_postgres_idempotency",
        "assertion": SCENARIO_PLAN["candidate_im_gateway_probe"]["assertion"],
        "checks": ("duplicate_callbacks", "tenant_isolation", "signature_rejection"),
    },
    "scripts/kind_runtime_probe.py": {
        "runner_name": "candidate-runtime",
        "probe": "kind_runtime_probe",
        "scenario": "kind_runtime_postgres_reconciliation",
        "assertion": SCENARIO_PLAN["candidate_runtime_probe"]["assertion"],
        "checks": ("tool_reconciliation", "im_idempotency"),
    },
    "scripts/kind_evolution_probe.py": {
        "runner_name": "candidate-evolution",
        "probe": "kind_evolution_postgres",
        "scenario": "kind_evolution_postgres_control",
        "assertion": SCENARIO_PLAN["candidate_evolution_probe"]["assertion"],
        "checks": (
            "database_identity_and_schema",
            "concurrent_cas",
            "certificate_approval_one_time",
            "outbox_lease_takeover",
            "receipt_rollback",
            "stale_aba_rejection",
            "cross_tenant_rejection",
        ),
    },
    "scripts/kind_redis_probe.py": {
        "runner_name": "candidate-redis",
        "probe": "kind_redis_probe",
        "scenario": "publish_idempotency_pel_takeover",
        "assertion": SCENARIO_PLAN["candidate_redis_probe"]["assertion"],
        "checks": (
            "publish_once",
            "consumer_a_pel",
            "consumer_b_takeover",
            "stale_owner_defer_rejected",
            "consumer_b_ack_pel_empty",
            "cleanup",
        ),
    },
}
_EVOLUTION_CASES = (
    "database_identity_and_schema",
    "concurrent_cas",
    "certificate_approval_one_time",
    "outbox_lease_takeover",
    "receipt_rollback",
    "stale_aba_rejection",
    "cross_tenant_rejection",
)
_SENSITIVE_PROBE_FIELDS = ("dsn", "password", "secret", "token", "encrypt_key", "private_key")


def _evolution_probe_environment(pod_name: str) -> list[dict[str, str]]:
    """Return unique, non-secret evolution identifiers for one probe Pod."""

    suffix = pod_name.rsplit("-", 1)[-1]
    token = f"kind-{suffix}"
    tenant = f"kind-evolution-{suffix}"
    values = {
        "TRPC_EVOLUTION_PROBE_TENANT_ID": tenant,
        "TRPC_EVOLUTION_PROBE_APP_ID": "evolution-probe",
        "TRPC_EVOLUTION_PROBE_CELL_ID": "probe-cell",
        "TRPC_EVOLUTION_PROBE_SESSION_ID": "probe-session",
        "TRPC_EVOLUTION_PROBE_RUN_TOKEN": token,
    }
    return [{"name": name, "value": value} for name, value in values.items()]


def _candidate_probe_manifest(
    *, pod_name: str, namespace: str, image: str, script: str, script_args: tuple[str, ...]
) -> dict[str, Any]:
    """Build a candidate-image Pod without placing credentials in argv."""

    secret_refs = _PROBE_SECRET_REFS.get(script)
    remote_workloads = _PROBE_REMOTE_WORKLOADS.get(script)
    if secret_refs is None or remote_workloads is None:
        raise ValueError("candidate probe script is not allow-listed")
    env: list[dict[str, str]] = []
    if script == "scripts/kind_im_gateway_probe.py":
        env.append({"name": "TRPC_KIND_GATEWAY_URL", "value": "http://trpc-gateway:8080"})
    elif script == "scripts/kind_runtime_probe.py":
        env.extend(
            [
                {
                    "name": "TRPC_KIND_PROVIDER_EXECUTE_URL",
                    "value": "http://kind-fake-provider:8080/v1/effects",
                },
                {
                    "name": "TRPC_KIND_PROVIDER_STATUS_URL",
                    "value": "http://kind-fake-provider:8080/v1/effects/{execution_key}",
                },
                {
                    "name": "TRPC_KIND_PROVIDER_METRICS_URL",
                    "value": "http://kind-fake-provider:8080/v1/metrics",
                },
                {"name": "TRPC_KIND_PROBE_DUPLICATE_COUNT", "value": "100"},
            ]
        )
    elif script == "scripts/kind_evolution_probe.py":
        env.extend(_evolution_probe_environment(pod_name))
    env_from = [{"configMapRef": {"name": "trpc-service-config"}}]
    env_from.extend({"secretRef": {"name": name}} for name in secret_refs)
    anti_affinity = [
        {
            "labelSelector": {"matchLabels": {"app.kubernetes.io/name": workload}},
            "topologyKey": "kubernetes.io/hostname",
        }
        for workload in remote_workloads
    ]
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "kind-acceptance-driver",
                "trpc.io/component": "acceptance-driver",
                "trpc.io/probe": script.rsplit("/", 1)[-1].removesuffix(".py"),
            },
        },
        "spec": {
            "serviceAccountName": "trpc-service",
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "nodeSelector": {"trpc.io/node-role": "agent-worker"},
            "affinity": {
                "podAntiAffinity": {
                    "requiredDuringSchedulingIgnoredDuringExecution": anti_affinity,
                }
            },
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 10001,
                "runAsGroup": 10001,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [
                {
                    "name": "acceptance-driver",
                    "image": image,
                    "imagePullPolicy": "IfNotPresent",
                    "command": ["python"],
                    "args": [script, *script_args],
                    "envFrom": env_from,
                    "env": env,
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    "volumeMounts": [
                        {"name": "tmp", "mountPath": "/tmp"}  # noqa: S108
                    ],
                }
            ],
            "volumes": [{"name": "tmp", "emptyDir": {}}],
        },
    }


def _redact_probe_payload(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {str(name): _redact_probe_payload(item, str(name)) for name, item in value.items()}
    if isinstance(value, list):
        return [_redact_probe_payload(item, key) for item in value]
    if isinstance(value, str) and any(marker in key.lower() for marker in _SENSITIVE_PROBE_FIELDS):
        return "<redacted>"
    return value


def _is_count(value: Any, expected: int | None = None) -> bool:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return False
    return expected is None or value == expected


def _is_fingerprint(value: Any) -> bool:
    return isinstance(value, str) and SOURCE_FINGERPRINT_RE.fullmatch(value) is not None


def _pass_check_contract(
    checks: Any, required: tuple[str, ...], reasons: list[str]
) -> Mapping[str, Any] | None:
    if not isinstance(checks, Mapping):
        reasons.append("checks is missing or not an object")
        return None
    for name in required:
        value = checks.get(name)
        if not isinstance(value, Mapping) or value.get("status") != "pass":
            reasons.append(f"check {name} is missing or did not pass")
    return checks


def _validate_im_probe_payload(payload: Mapping[str, Any], reasons: list[str]) -> None:
    if not _is_count(payload.get("callbacks_sent"), 102):
        reasons.append("callbacks_sent must be exactly 102")
    callback_counts = payload.get("duplicate_callback_status_counts")
    if callback_counts != {"200": 100}:
        reasons.append("duplicate callback status counts must be exactly 100 HTTP 200 responses")
    if payload.get("second_tenant_status") != 200:
        reasons.append("second tenant callback status must be HTTP 200")
    if payload.get("invalid_signature_status") != 403:
        reasons.append("invalid signature status must be HTTP 403")
    if payload.get("rejection_reasons") != []:
        reasons.append("probe rejection_reasons must be empty")
    if payload.get("secrets_reported") is not False:
        reasons.append("probe must prove that secrets were not reported")

    tenant_digests: list[str] = []
    expected_counts = ("inbound", "accepted_audit", "mailboxes", "mailbox_items", "ready_events")
    for tenant_name in ("tenant_a", "tenant_b"):
        tenant = payload.get(tenant_name)
        if not isinstance(tenant, Mapping):
            reasons.append(f"{tenant_name} counts are missing or not an object")
            continue
        if any(not _is_count(tenant.get(name), 1) for name in expected_counts):
            reasons.append(f"{tenant_name} exactly-once counts are incomplete")
        digest = tenant.get("session_digest")
        if not _is_fingerprint(digest):
            reasons.append(f"{tenant_name} session digest is missing or invalid")
        elif isinstance(digest, str):
            tenant_digests.append(digest)
    if len(tenant_digests) == 2 and tenant_digests[0] == tenant_digests[1]:
        reasons.append("tenant session digests must be distinct")


def _validate_runtime_probe_payload(payload: Mapping[str, Any], reasons: list[str]) -> None:
    if payload.get("command") != "all":
        reasons.append("runtime probe command must be all")
    if payload.get("rejection_reasons") != []:
        reasons.append("probe rejection_reasons must be empty")
    if not _is_count(payload.get("provider_execute_calls"), 1):
        reasons.append("provider_execute_calls must be exactly 1")
    if (
        not _is_count(payload.get("provider_status_queries"))
        or payload["provider_status_queries"] < 1
    ):
        reasons.append("provider_status_queries must be at least 1")

    checks = payload.get("checks")
    if not isinstance(checks, Mapping):
        return
    reconciliation = checks.get("tool_reconciliation")
    if isinstance(reconciliation, Mapping):
        reconciliation_checks = reconciliation.get("checks")
        required = (
            "applied_query_only",
            "unknown_blocks_replay",
            "stale_attempt_rejected",
            "cross_tenant_evidence_rejected",
            "claim_cas_rejected",
        )
        if not isinstance(reconciliation_checks, Mapping):
            reasons.append("tool_reconciliation checks are missing or not an object")
        else:
            for name in required:
                item = reconciliation_checks.get(name)
                if not isinstance(item, Mapping) or item.get("status") != "pass":
                    reasons.append(f"tool_reconciliation check {name} is missing or did not pass")
            applied = reconciliation_checks.get("applied_query_only")
            if isinstance(applied, Mapping):
                if not _is_count(applied.get("evidence_rows"), 1):
                    reasons.append("applied reconciliation evidence_rows must be exactly 1")
                if not _is_count(applied.get("provider_execution_delta"), 1):
                    reasons.append("provider execution delta must be exactly 1")
                if not _is_count(applied.get("provider_execute_calls"), 1):
                    reasons.append("applied reconciliation provider calls must be exactly 1")
                if not _is_count(applied.get("status_queries")) or applied["status_queries"] < 1:
                    reasons.append("applied reconciliation status queries must be at least 1")
    im = checks.get("im_idempotency")
    if isinstance(im, Mapping):
        expected_counts = {
            "duplicate_callbacks": 100,
            "first_acceptances": 1,
            "duplicate_results": 99,
            "primary_inbound_ids": 1,
            "primary_session_ids": 1,
        }
        for name, expected in expected_counts.items():
            if not _is_count(im.get(name), expected):
                reasons.append(f"runtime IM count {name} is invalid")
        if im.get("secondary_same_message_accepted") is not True:
            reasons.append("runtime secondary tenant message must be accepted")
        expected_rows = {"inbound": 1, "audit": 1, "outbox": 1, "mailbox": 1}
        if im.get("primary_rows") != expected_rows or im.get("secondary_rows") != expected_rows:
            reasons.append("runtime IM row counts must be exactly once per tenant")
        primary_hash = im.get("tenant_sha256")
        secondary_hash = im.get("secondary_tenant_sha256")
        if not _is_fingerprint(primary_hash) or not _is_fingerprint(secondary_hash):
            reasons.append("runtime tenant fingerprints are missing or invalid")
        elif primary_hash == secondary_hash:
            reasons.append("runtime tenant fingerprints must be distinct")


def _validate_evolution_probe_payload(payload: Mapping[str, Any], reasons: list[str]) -> None:
    if payload.get("provider_calls") != 0:
        reasons.append("evolution probe provider_calls must be exactly 0")
    if payload.get("rejection_reasons") != []:
        reasons.append("probe rejection_reasons must be empty")
    database = payload.get("database")
    if (
        not isinstance(database, Mapping)
        or database.get("role_verified") is not True
        or database.get("required_tables") is not True
    ):
        reasons.append("evolution database identity and required tables were not verified")
    fixture = payload.get("fixture")
    if (
        not isinstance(fixture, Mapping)
        or fixture.get("status") != "pass"
        or fixture.get("role") != "trpc_worker"
        or not _is_count(fixture.get("capsule_count"), 2)
    ):
        reasons.append("evolution fixture must prove two worker-owned capsules")

    cases = payload.get("cases")
    if not isinstance(cases, list):
        reasons.append("evolution cases are missing or not a list")
        return
    case_by_name: dict[str, Mapping[str, Any]] = {}
    for item in cases:
        if isinstance(item, Mapping) and isinstance(item.get("name"), str):
            case_by_name[item["name"]] = item
    if set(case_by_name) != set(_EVOLUTION_CASES) or len(case_by_name) != len(cases):
        reasons.append("evolution case set is incomplete or contains duplicates")
    for name in _EVOLUTION_CASES:
        item = case_by_name.get(name)
        if item is None or item.get("passed") is not True:
            reasons.append(f"evolution case {name} is missing or did not pass")

    concurrent = case_by_name.get("concurrent_cas")
    if isinstance(concurrent, Mapping) and any(
        not _is_count(concurrent.get(field), 1)
        for field in (
            "winner_count",
            "conflict_count",
            "durable_certificate_uses",
            "durable_approval_uses",
        )
    ):
        reasons.append("evolution concurrent CAS counts are invalid")
    one_time = case_by_name.get("certificate_approval_one_time")
    if isinstance(one_time, Mapping) and any(
        one_time.get(field) is not True
        for field in (
            "duplicate_certificate_rejected",
            "duplicate_approval_rejected",
            "authority_duplicate_rejected",
        )
    ):
        reasons.append("evolution certificate/approval one-time assertions are incomplete")
    outbox = case_by_name.get("outbox_lease_takeover")
    if isinstance(outbox, Mapping):
        if (
            outbox.get("stale_ack_before_expiry") is not False
            or outbox.get("stale_ack_after_takeover") is not False
            or outbox.get("acknowledged") is not True
            or outbox.get("duplicate_ack") is not False
        ):
            reasons.append("evolution outbox owner/epoch assertions are incomplete")
        epochs = outbox.get("lease_epochs")
        if (
            not isinstance(epochs, list)
            or len(epochs) != 3
            or any(not _is_count(value) for value in epochs)
            or not all(epochs[index] < epochs[index + 1] for index in range(2))
        ):
            reasons.append("evolution outbox lease epochs must increase three times")
    rollback = case_by_name.get("receipt_rollback")
    if isinstance(rollback, Mapping) and (
        not _is_count(rollback.get("rollback_version"), 2)
        or rollback.get("duplicate_rollback_rejected") is not True
        or rollback.get("tampered_receipt_rejected") is not True
    ):
        reasons.append("evolution rollback assertions are incomplete")
    stale = case_by_name.get("stale_aba_rejection")
    if isinstance(stale, Mapping) and (
        stale.get("stale_cas_rejected") is not True
        or stale.get("stale_certificate_rejected") is not True
        or not _is_count(stale.get("final_control_version"), 2)
    ):
        reasons.append("evolution stale ABA assertions are incomplete")
    cross_tenant = case_by_name.get("cross_tenant_rejection")
    if isinstance(cross_tenant, Mapping) and (
        cross_tenant.get("store_scope_rejected") is not True
        or cross_tenant.get("certificate_scope_rejected") is not True
    ):
        reasons.append("evolution cross-tenant assertions are incomplete")


def _validate_redis_probe_payload(payload: Mapping[str, Any], reasons: list[str]) -> None:
    if payload.get("rejection_reasons") != []:
        reasons.append("probe rejection_reasons must be empty")
    checks = payload.get("checks")
    if not isinstance(checks, Mapping):
        return
    expected: dict[str, dict[str, object]] = {
        "publish_once": {
            "first_publish": True,
            "duplicate_suppressed": True,
            "stream_entries": 1,
        },
        "consumer_a_pel": {"delivered": 1, "pending": 1},
        "consumer_b_takeover": {"reclaimed": 1},
        "stale_owner_defer_rejected": {"accepted": False},
        "consumer_b_ack_pel_empty": {"pending": 0},
    }
    for check_name, fields in expected.items():
        check = checks.get(check_name)
        if not isinstance(check, Mapping):
            continue
        for field, expected_value in fields.items():
            if check.get(field) != expected_value:
                reasons.append(f"Redis check {check_name}.{field} is invalid")


def _validate_candidate_probe_payload(probe_name: str, script: str, payload: Any) -> str | None:
    """Validate the immutable contract for one candidate-image acceptance probe."""

    contract = _CANDIDATE_PROBE_CONTRACTS.get(script)
    reasons: list[str] = []
    if contract is None:
        return "candidate probe result contract failed: script is not allow-listed"
    if probe_name != contract["runner_name"]:
        reasons.append("probe runner name does not match script")
    if not isinstance(payload, Mapping):
        return "candidate probe result contract failed: result is not an object"
    if payload.get("schema_version") != 1:
        reasons.append("schema_version must be 1")
    if payload.get("status") != "pass":
        reasons.append("status must be pass")
    if payload.get("probe") != contract["probe"]:
        reasons.append("probe identity does not match script")
    if payload.get("scenario") != contract["scenario"]:
        reasons.append("scenario identity does not match script")
    if payload.get("assertion") != contract["assertion"]:
        reasons.append("assertion does not match scenario plan")

    lineage = _source_lineage()
    expected_source = lineage.get("value") if lineage.get("status") == "available" else None
    observed_source: Any = payload.get("source_fingerprint")
    if isinstance(observed_source, Mapping):
        if observed_source.get("status") != "available":
            observed_source = None
        else:
            observed_source = observed_source.get("value")
    if not _is_fingerprint(expected_source):
        reasons.append("current checkout source fingerprint is unavailable")
    elif observed_source != expected_source:
        reasons.append("source fingerprint does not match current checkout")

    _pass_check_contract(payload.get("checks"), contract["checks"], reasons)
    if script == "scripts/kind_im_gateway_probe.py":
        _validate_im_probe_payload(payload, reasons)
    elif script == "scripts/kind_runtime_probe.py":
        _validate_runtime_probe_payload(payload, reasons)
    elif script == "scripts/kind_evolution_probe.py":
        _validate_evolution_probe_payload(payload, reasons)
    else:
        _validate_redis_probe_payload(payload, reasons)
    if reasons:
        return "candidate probe result contract failed: " + "; ".join(reasons)
    return None


def _wait_for_candidate_pod(
    context: str, namespace: str, pod_name: str, timeout: float
) -> CommandResult:
    """Poll the Pod phase and stop immediately when it reaches Failed.

    ``kubectl wait --for=...=Succeeded`` does not return until its timeout for
    a Pod that has already failed.  That makes an invalid image or probe
    configuration consume the entire gate window.  A small phase poll keeps
    the same bounded deadline while exposing failures as soon as Kubernetes
    records them.
    """

    deadline = time.monotonic() + max(0.1, timeout)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return CommandResult("fail", reason="candidate probe Pod timed out")
        result = _kubectl(
            context,
            ["-n", namespace, "get", f"pod/{pod_name}", "-o", "json"],
            timeout=min(20.0, max(1.0, remaining)),
        )
        if result.status != "pass":
            return CommandResult(
                "fail", reason=result.reason or "candidate probe Pod status was unavailable"
            )
        try:
            payload = json.loads(result.stdout)
            phase = payload.get("status", {}).get("phase")
        except (AttributeError, json.JSONDecodeError):
            return CommandResult("fail", reason="candidate probe Pod status was invalid JSON")
        if phase == "Succeeded":
            return CommandResult("pass")
        if phase == "Failed":
            return CommandResult("fail", reason="candidate probe Pod reported Failed")
        time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))


def _candidate_probe_placement(
    context: str, namespace: str, pod_name: str, script: str
) -> tuple[str, dict[str, Any], str | None]:
    result = _kubectl(context, ["-n", namespace, "get", "pods", "-o", "json"], timeout=30)
    if result.status != "pass":
        return "fail", {}, "candidate probe placement inventory was unavailable"
    try:
        items = json.loads(result.stdout).get("items", [])
    except (AttributeError, json.JSONDecodeError):
        return "fail", {}, "candidate probe placement inventory was invalid"
    if not isinstance(items, list):
        return "fail", {}, "candidate probe placement inventory was not a list"
    driver_node: str | None = None
    nodes_by_workload: dict[str, set[str]] = {}
    for item in items:
        if not isinstance(item, Mapping):
            continue
        metadata = item.get("metadata")
        spec = item.get("spec")
        if not isinstance(metadata, Mapping) or not isinstance(spec, Mapping):
            continue
        name = metadata.get("name")
        node = spec.get("nodeName")
        labels = metadata.get("labels")
        if not isinstance(node, str) or not node or not isinstance(labels, Mapping):
            continue
        if name == pod_name:
            driver_node = node
        workload = labels.get("app.kubernetes.io/name")
        if isinstance(workload, str):
            nodes_by_workload.setdefault(workload, set()).add(node)
    remote_workloads = _PROBE_REMOTE_WORKLOADS.get(script, ())
    remote_nodes = {
        workload: sorted(nodes_by_workload.get(workload, set())) for workload in remote_workloads
    }
    missing = [workload for workload, nodes in remote_nodes.items() if not nodes]
    cross_node = (
        driver_node is not None
        and not missing
        and all(driver_node not in nodes for nodes in remote_nodes.values())
    )
    evidence = {
        "driver_node": driver_node,
        "remote_workload_nodes": remote_nodes,
        "cross_node": cross_node,
    }
    if not cross_node:
        return "fail", evidence, "candidate probe did not traverse a node boundary"
    return "pass", evidence, None


def _run_candidate_probe(
    context: str,
    namespace: str,
    image: str,
    probe_name: str,
    script: str,
    script_args: tuple[str, ...],
) -> tuple[str, dict[str, Any], str | None]:
    """Run one keyless probe Pod and delete exactly that Pod afterward."""

    suffix = uuid.uuid4().hex[:10]
    pod_name = f"kind-gate-{probe_name.removeprefix('candidate_').replace('_', '-')}-{suffix}"
    manifest = _candidate_probe_manifest(
        pod_name=pod_name,
        namespace=namespace,
        image=image,
        script=script,
        script_args=script_args,
    )
    applied = _kubectl(
        context,
        ["apply", "-f", "-"],
        input_text=json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        timeout=60,
    )
    wait_result = CommandResult("fail", reason="candidate probe Pod was not created")
    logs_result = CommandResult("fail", reason="candidate probe Pod logs unavailable")
    cleanup_result = CommandResult("fail", reason="candidate probe Pod cleanup not attempted")
    placement_status = "fail"
    placement_evidence: dict[str, Any] = {}
    placement_reason: str | None = "candidate probe placement was not inspected"
    try:
        if applied.status == "pass":
            wait_result = _wait_for_candidate_pod(context, namespace, pod_name, timeout=180.0)
            # A failed Pod still has the evidence needed to diagnose a false
            # gate result.  Collect placement and the final keyless log line
            # before the finally block removes this exact Pod.
            placement_status, placement_evidence, placement_reason = _candidate_probe_placement(
                context, namespace, pod_name, script
            )
            logs_result = _kubectl(
                context,
                ["-n", namespace, "logs", f"pod/{pod_name}", "--tail=1"],
                timeout=30,
            )
    finally:
        cleanup_result = _kubectl(
            context,
            [
                "-n",
                namespace,
                "delete",
                "pod",
                pod_name,
                "--ignore-not-found=true",
                "--wait=true",
            ],
            timeout=60,
        )

    evidence: dict[str, Any] = {
        "script": script,
        "pod_cleanup": {"status": cleanup_result.status == "pass"},
        "placement": {
            "status": placement_status,
            "evidence": placement_evidence,
            "reason": placement_reason,
        },
    }
    payload: dict[str, Any] = {}
    if logs_result.status == "pass":
        try:
            last_line = logs_result.stdout.strip().splitlines()[-1]
            decoded = json.loads(last_line)
            if isinstance(decoded, dict):
                payload = _redact_probe_payload(decoded)
        except (IndexError, json.JSONDecodeError):
            payload = {}
    evidence["probe"] = payload
    contract_reason = _validate_candidate_probe_payload(probe_name, script, payload)
    evidence["probe_contract"] = {
        "status": "pass" if contract_reason is None else "fail",
        "reason": contract_reason,
    }
    if applied.status != "pass":
        return "fail", evidence, applied.reason or "candidate probe Pod could not be created"
    if wait_result.status != "pass":
        return "fail", evidence, "candidate probe Pod did not complete successfully"
    if placement_status != "pass":
        return "fail", evidence, placement_reason or "candidate probe placement check failed"
    if logs_result.status != "pass" or not payload:
        return "fail", evidence, "candidate probe returned no keyless JSON line"
    if payload.get("status") != "pass":
        return "fail", evidence, "candidate probe reported failure"
    if contract_reason is not None:
        return "fail", evidence, contract_reason
    if cleanup_result.status != "pass":
        return "fail", evidence, "candidate probe Pod cleanup failed"
    return "pass", evidence, None


def _candidate_im_scenario(
    context: str, namespace: str, image: str
) -> tuple[str, dict[str, Any], str | None]:
    script, args = _PROBE_SCRIPTS["candidate_im_gateway_probe"]
    return _run_candidate_probe(context, namespace, image, "candidate-im-gateway", script, args)


def _candidate_runtime_scenario(
    context: str, namespace: str, image: str
) -> tuple[str, dict[str, Any], str | None]:
    script, args = _PROBE_SCRIPTS["candidate_runtime_probe"]
    return _run_candidate_probe(context, namespace, image, "candidate-runtime", script, args)


def _candidate_evolution_scenario(
    context: str, namespace: str, image: str
) -> tuple[str, dict[str, Any], str | None]:
    script, args = _PROBE_SCRIPTS["candidate_evolution_probe"]
    return _run_candidate_probe(context, namespace, image, "candidate-evolution", script, args)


def _candidate_redis_scenario(
    context: str, namespace: str, image: str
) -> tuple[str, dict[str, Any], str | None]:
    script, args = _PROBE_SCRIPTS["candidate_redis_probe"]
    return _run_candidate_probe(context, namespace, image, "candidate-redis", script, args)


def _delete_pod_and_wait(
    context: str, namespace: str, selector: str, resource: str
) -> tuple[str, str | None]:
    before = _kubectl(
        context, ["-n", namespace, "get", "pods", "-l", selector, "-o", "json"], timeout=20
    )
    if before.status != "pass":
        return "fail", "could not find a pod for failure injection"
    try:
        items = json.loads(before.stdout).get("items", [])
        pod_name = items[0]["metadata"]["name"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
        return "fail", "pod inventory was empty"
    deleted = _kubectl(
        context, ["-n", namespace, "delete", "pod", pod_name, "--wait=true"], timeout=60
    )
    if deleted.status != "pass":
        return "fail", "pod deletion failed"
    ready = _kubectl(
        context, ["-n", namespace, "rollout", "status", resource, "--timeout=180s"], timeout=190
    )
    return (
        ("pass", None)
        if ready.status == "pass"
        else ("fail", "replacement workload did not become ready")
    )


def _network_recovery_scenario(
    context: str, namespace: str
) -> tuple[str, dict[str, Any], str | None]:
    before = _kubectl(
        context,
        ["-n", namespace, "get", "pod/kind-fake-provider-0", "-o", "json"],
        timeout=20,
    )
    if before.status != "pass":
        return "fail", {}, "provider Pod could not be inspected before recovery"
    before_uid = _object_uid(before.stdout)
    before_metrics = _provider_metrics(context, namespace, "kind-fake-provider-0")
    if before_uid is None or before_metrics is None:
        return "fail", {}, "provider identity or metrics were unavailable before recovery"
    deleted = _kubectl(
        context,
        ["-n", namespace, "delete", "pod", "kind-fake-provider-0", "--wait=true"],
        timeout=60,
    )
    if deleted.status != "pass":
        return "fail", {}, "provider Pod deletion failed"
    ready = _kubectl(
        context,
        ["-n", namespace, "rollout", "status", "statefulset/kind-fake-provider", "--timeout=180s"],
        timeout=190,
    )
    if ready.status != "pass":
        return "fail", {}, "provider replacement workload did not become ready"
    after = _kubectl(
        context,
        ["-n", namespace, "get", "pod/kind-fake-provider-0", "-o", "json"],
        timeout=20,
    )
    after_uid = _object_uid(after.stdout) if after.status == "pass" else None
    after_metrics = _provider_metrics(context, namespace, "kind-fake-provider-0")
    if after_uid is None or after_metrics is None:
        return "fail", {}, "provider identity or metrics were unavailable after recovery"
    preserved = all(
        after_metrics.get(key) == before_metrics.get(key)
        for key in ("effects", "provider_calls", "active", "control_version")
    )
    evidence = {
        "provider_restarted": True,
        "pod_uid_changed": after_uid != before_uid,
        "provider_metrics_preserved": preserved,
        "effects": after_metrics.get("effects"),
        "provider_calls": after_metrics.get("provider_calls"),
    }
    if after_uid == before_uid or not preserved:
        return "fail", evidence, "provider replacement did not preserve idempotency state"
    return "pass", evidence, None


def _object_uid(text: str) -> str | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    value = payload.get("metadata", {}).get("uid") if isinstance(payload, dict) else None
    return value if isinstance(value, str) and value else None


def _postgres_scalar(context: str, namespace: str, statement: str) -> str | None:
    result = _kubectl(
        context,
        [
            "-n",
            namespace,
            "exec",
            "kind-postgres-0",
            "--",
            "psql",
            "-U",
            "trpc",
            "-d",
            "trpc_service",
            "-At",
            "-c",
            statement,
        ],
        timeout=20,
    )
    if result.status != "pass":
        return None
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return lines[-1] if lines else None


def _delete_schema_migration_job(
    context: str, cluster_name: str, namespace: str, *, execute: bool
) -> tuple[str, dict[str, Any], str | None]:
    """Remove the fixed migration Job before apply so a new spec can run."""

    if not execute:
        return "not_run", {}, "schema migration Job deletion requires --execute"
    if context != f"kind-{cluster_name}" or not context.startswith("kind-"):
        return "fail", {}, "schema migration Job deletion requires the exact kind context"
    if namespace != DEFAULT_NAMESPACE:
        return "fail", {}, "schema migration Job deletion requires the dedicated kind namespace"

    result = _kubectl(
        context,
        [
            "-n",
            namespace,
            "delete",
            "job",
            SCHEMA_MIGRATION_JOB_NAME,
            "--ignore-not-found=true",
            "--wait=true",
        ],
        timeout=60,
    )
    evidence = {
        "job": SCHEMA_MIGRATION_JOB_NAME,
        "namespace": namespace,
        "status": result.status,
    }
    if result.status != "pass":
        return "fail", evidence, "schema migration Job deletion failed"
    return "pass", evidence, None


def _schema_head_contract(context: str, namespace: str) -> tuple[str, dict[str, Any], str | None]:
    """Verify the live database has the single migration head from this checkout."""

    result = _kubectl(
        context,
        [
            "-n",
            namespace,
            "exec",
            "kind-postgres-0",
            "--",
            "psql",
            "-U",
            "trpc",
            "-d",
            "trpc_service",
            "-At",
            "-c",
            "SELECT version_num FROM public.alembic_version ORDER BY version_num;",
        ],
        timeout=30,
    )
    raw_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    safe_heads = [line for line in raw_lines if ALEMBIC_REVISION_RE.fullmatch(line)]
    evidence = {
        "pod": "kind-postgres-0",
        "expected_head": EXPECTED_ALEMBIC_HEAD,
        "observed_heads": safe_heads,
        "observed_count": len(raw_lines),
        "status": result.status,
    }
    if result.status != "pass":
        return "fail", evidence, "Alembic schema head query failed"
    if raw_lines != [EXPECTED_ALEMBIC_HEAD]:
        return "fail", evidence, "Alembic schema head does not match repository head"
    return "pass", evidence, None


def _nonnegative_int(value: str | None) -> int | None:
    if value is None or not value.isdigit():
        return None
    return int(value)


def _pod_inventory(context: str, namespace: str, selector: str) -> dict[str, str]:
    result = _kubectl(
        context,
        ["-n", namespace, "get", "pods", "-l", selector, "-o", "json"],
        timeout=20,
    )
    if result.status != "pass":
        return {}
    try:
        items = json.loads(result.stdout).get("items", [])
    except (AttributeError, json.JSONDecodeError):
        return {}
    if not isinstance(items, list):
        return {}
    inventory: dict[str, str] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata")
        if not isinstance(metadata, dict):
            continue
        name = metadata.get("name")
        uid = metadata.get("uid")
        if isinstance(name, str) and isinstance(uid, str) and name and uid:
            inventory[name] = uid
    return inventory


def _provider_metrics(context: str, namespace: str, pod_name: str) -> dict[str, Any] | None:
    code = (
        "import json, urllib.request; "
        "print(json.dumps(json.load(urllib.request.urlopen("
        "'http://127.0.0.1:8080/v1/metrics', timeout=5))))"
    )
    result = _kubectl(
        context,
        ["-n", namespace, "exec", pod_name, "--", "python", "-c", code],
        timeout=20,
    )
    if result.status != "pass":
        return None
    try:
        value = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _postgres_restart_scenario(
    context: str, namespace: str, image: str = DEFAULT_IMAGE
) -> tuple[str, dict[str, Any], str | None]:
    before = _kubectl(
        context,
        ["-n", namespace, "get", "pod/kind-postgres-0", "-o", "json"],
        timeout=20,
    )
    before_uid = _object_uid(before.stdout) if before.status == "pass" else None
    pvc_before = _kubectl(
        context,
        ["-n", namespace, "get", "pvc/data-kind-postgres-0", "-o", "json"],
        timeout=20,
    )
    pvc_before_uid = _object_uid(pvc_before.stdout) if pvc_before.status == "pass" else None
    persisted_rows_before = _nonnegative_int(
        _postgres_scalar(
            context,
            namespace,
            "SELECT count(*) FROM inbound_messages WHERE tenant_id LIKE 'kind-im-%';",
        )
    )
    if before_uid is None or pvc_before_uid is None or persisted_rows_before is None:
        return "fail", {}, "PostgreSQL Pod or PVC was unavailable before recovery"
    if persisted_rows_before < 2:
        return "fail", {}, "PostgreSQL persistence sentinel rows were unavailable before recovery"
    deleted = _kubectl(
        context,
        ["-n", namespace, "delete", "pod", "kind-postgres-0", "--wait=true"],
        timeout=60,
    )
    if deleted.status != "pass":
        return "fail", {}, "PostgreSQL Pod deletion failed"
    ready = _kubectl(
        context,
        ["-n", namespace, "rollout", "status", "statefulset/kind-postgres", "--timeout=180s"],
        timeout=190,
    )
    if ready.status != "pass":
        return "fail", {}, "PostgreSQL replacement did not become ready"
    after = _kubectl(
        context,
        ["-n", namespace, "get", "pod/kind-postgres-0", "-o", "json"],
        timeout=20,
    )
    after_uid = _object_uid(after.stdout) if after.status == "pass" else None
    pvc_after = _kubectl(
        context,
        ["-n", namespace, "get", "pvc/data-kind-postgres-0", "-o", "json"],
        timeout=20,
    )
    pvc_after_uid = _object_uid(pvc_after.stdout) if pvc_after.status == "pass" else None
    persisted_rows_after = _nonnegative_int(
        _postgres_scalar(
            context,
            namespace,
            "SELECT count(*) FROM inbound_messages WHERE tenant_id LIKE 'kind-im-%';",
        )
    )
    health = _kubectl(
        context,
        [
            "-n",
            namespace,
            "exec",
            "kind-postgres-0",
            "--",
            "pg_isready",
            "-U",
            "trpc",
            "-d",
            "trpc_service",
        ],
        timeout=20,
    )
    schema_head = _kubectl(
        context,
        [
            "-n",
            namespace,
            "exec",
            "kind-postgres-0",
            "--",
            "psql",
            "-U",
            "trpc",
            "-d",
            "trpc_service",
            "-At",
            "-c",
            "SELECT to_regclass('public.tenants') IS NOT NULL AND "
            "to_regclass('public.cell_branch_heads') IS NOT NULL;",
        ],
        timeout=20,
    )
    application_targets = tuple(("Deployment", name) for name in REQUIRED_DEPLOYMENTS)
    application_outcomes: dict[tuple[str, str], CommandResult] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(16, len(application_targets)))) as executor:
        futures = {
            executor.submit(_wait_for_runtime_target, context, namespace, target, 180.0): target
            for target in application_targets
        }
        for future in as_completed(futures):
            target = futures[future]
            try:
                application_outcomes[target] = future.result()
            except Exception as error:  # pragma: no cover - defensive process boundary
                application_outcomes[target] = CommandResult(
                    "fail", reason=f"readiness command raised {type(error).__name__}"
                )
    application_ready = all(
        application_outcomes.get(target, CommandResult("fail")).status == "pass"
        for target in application_targets
    )
    callback_status = "not_run"
    callback_evidence: dict[str, Any] = {}
    callback_reason: str | None = None
    if application_ready:
        callback_status, callback_evidence, callback_reason = _candidate_im_scenario(
            context, namespace, image
        )
    evidence = {
        "pod_uid_changed": after_uid is not None and after_uid != before_uid,
        "pvc_preserved": pvc_after_uid == pvc_before_uid,
        "pvc_uid_sha256": (
            hashlib.sha256(pvc_before_uid.encode()).hexdigest() if pvc_before_uid else None
        ),
        "persistent_rows_before": persisted_rows_before,
        "persistent_rows_after": persisted_rows_after,
        "persistent_rows_preserved": persisted_rows_after == persisted_rows_before,
        "health_smoke": health.status == "pass",
        "schema_head_smoke": schema_head.status == "pass"
        and schema_head.stdout.strip().lower().endswith("t"),
        "application_deployments_ready": application_ready,
        "application_deployments_checked": len(application_targets),
        "db_backed_callback": {
            "status": callback_status,
            "evidence": callback_evidence,
            "reason": callback_reason,
        },
    }
    if not all(
        (
            evidence["pod_uid_changed"],
            evidence["pvc_preserved"],
            evidence["persistent_rows_preserved"],
            evidence["health_smoke"],
            evidence["schema_head_smoke"],
            evidence["application_deployments_ready"],
            callback_status == "pass",
        )
    ):
        return "fail", evidence, "PostgreSQL recovery smoke or PVC preservation failed"
    return "pass", evidence, None


def _worker_restart_scenario(
    context: str, namespace: str
) -> tuple[str, dict[str, Any], str | None]:
    selector = "app.kubernetes.io/name=trpc-worker"
    before_workers = _pod_inventory(context, namespace, selector)
    before_provider = _provider_metrics(context, namespace, "kind-fake-provider-0")
    if not before_workers or before_provider is None:
        return "fail", {}, "worker or provider state was unavailable before recovery"
    deleted_name, deleted_uid = next(iter(before_workers.items()))
    deleted = _kubectl(
        context,
        ["-n", namespace, "delete", "pod", deleted_name, "--wait=true"],
        timeout=60,
    )
    if deleted.status != "pass":
        return "fail", {}, "worker Pod deletion failed"
    ready = _kubectl(
        context,
        ["-n", namespace, "rollout", "status", "deployment/trpc-worker", "--timeout=180s"],
        timeout=190,
    )
    if ready.status != "pass":
        return "fail", {}, "replacement worker did not become ready"
    after_workers = _pod_inventory(context, namespace, selector)
    after_provider = _provider_metrics(context, namespace, "kind-fake-provider-0")
    if not after_workers or after_provider is None:
        return "fail", {}, "worker or provider state was unavailable after recovery"
    provider_keys = ("effects", "provider_calls")
    provider_before = {key: before_provider.get(key) for key in provider_keys}
    provider_after = {key: after_provider.get(key) for key in provider_keys}
    preserved = provider_before == provider_after and all(
        isinstance(value, int) and not isinstance(value, bool) for value in provider_after.values()
    )
    replacement_uid = any(
        name not in before_workers and uid != deleted_uid for name, uid in after_workers.items()
    )
    evidence = {
        "worker_restarted": True,
        "worker_pod_uid_changed": replacement_uid,
        "provider_metrics_preserved": preserved,
        "provider_counts_before": provider_before,
        "provider_counts_after": provider_after,
    }
    if not replacement_uid or not preserved:
        return "fail", evidence, "worker replacement changed provider idempotency state"
    return "pass", evidence, None


def _workload_distribution(context: str, namespace: str) -> tuple[str, dict[str, Any], str | None]:
    result = _kubectl(context, ["-n", namespace, "get", "pods", "-o", "json"], timeout=30)
    if result.status != "pass":
        return "fail", {}, "workload distribution could not be inspected"
    try:
        items = json.loads(result.stdout).get("items", [])
    except (AttributeError, json.JSONDecodeError):
        return "fail", {}, "workload distribution returned invalid JSON"
    if not isinstance(items, list):
        return "fail", {}, "workload distribution was not a list"
    by_node: dict[str, dict[str, int]] = {}
    pod_count = 0
    worker_nodes: set[str] = set()
    gateway_nodes: set[str] = set()
    backend_nodes: dict[str, set[str]] = {
        "kind-postgres": set(),
        "kind-redis": set(),
        "kind-fake-provider": set(),
    }
    for item in items:
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata")
        spec = item.get("spec")
        if not isinstance(metadata, dict) or not isinstance(spec, dict):
            continue
        labels = metadata.get("labels")
        labels = labels if isinstance(labels, dict) else {}
        workload = labels.get("app.kubernetes.io/name") or labels.get("trpc.io/component")
        node_name = spec.get("nodeName") or "<unscheduled>"
        if not isinstance(workload, str) or not isinstance(node_name, str):
            continue
        node_workloads = by_node.setdefault(node_name, {})
        node_workloads[workload] = node_workloads.get(workload, 0) + 1
        if workload == "trpc-worker" and node_name != "<unscheduled>":
            worker_nodes.add(node_name)
        if workload == "trpc-gateway" and node_name != "<unscheduled>":
            gateway_nodes.add(node_name)
        if workload in backend_nodes and node_name != "<unscheduled>":
            backend_nodes[workload].add(node_name)
        pod_count += 1
    if pod_count == 0:
        return "fail", {}, "workload distribution contained no schedulable Pods"
    evidence = {
        "pod_count": pod_count,
        "worker_node_count": len(worker_nodes),
        "required_worker_nodes": 3,
        "gateway_nodes": sorted(gateway_nodes),
        "backend_nodes": {name: sorted(nodes) for name, nodes in backend_nodes.items()},
        "gateway_backend_cross_node": all(
            len(nodes) == 1 and nodes.isdisjoint(gateway_nodes) for nodes in backend_nodes.values()
        ),
        "by_node": by_node,
    }
    if len(worker_nodes) != 3:
        return "fail", evidence, "three worker replicas were not spread across three nodes"
    if len(gateway_nodes) != 2:
        return "fail", evidence, "two gateway replicas were not spread across two nodes"
    if not evidence["gateway_backend_cross_node"]:
        return "fail", evidence, "gateway and shared backends were not separated by node"
    return "pass", evidence, None


def _execute(
    *,
    cluster_name: str,
    context: str,
    namespace: str,
    image: str,
    load_image: bool,
    render_output: Path,
    preflight: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    reasons: list[str] = []
    cluster_created = False
    cluster_uid: str | None = None
    local_image_digest: str | None = None
    node_counts: dict[str, int] = {}
    node_pools: dict[str, Any] = {"status": "not_run"}
    if context != f"kind-{cluster_name}" or not context.startswith("kind-"):
        reasons.append("execute context must be exactly kind-<cluster-name>")
    if namespace != DEFAULT_NAMESPACE:
        reasons.append("execute namespace must be the dedicated kind namespace")
    exists, exists_reason = _kind_cluster_exists(cluster_name)
    if exists_reason:
        reasons.append(exists_reason)
    if not reasons and not exists:
        created = _run(
            [
                "kind",
                "create",
                "cluster",
                "--name",
                cluster_name,
                "--config",
                str(KIND_CONFIG),
                "--wait",
                "120s",
            ],
            timeout=180,
        )
        if created.status != "pass":
            reasons.append(created.reason or "kind cluster creation failed")
        else:
            cluster_created = True
    elif not reasons and exists:
        # Reusing an exact kind context is safe; no other context is accepted.
        pass
    if not reasons and load_image:
        image_status, local_image_digest, image_reason = _load_local_image(cluster_name, image)
        if image_status != "pass":
            reasons.append(image_reason or "local image load failed")
    if not reasons:
        cluster_uid, uid_reason = _cluster_uid(context)
        if uid_reason:
            reasons.append(uid_reason)
    if not reasons:
        node_counts, node_reason = _cluster_node_contract(context)
        if node_reason:
            reasons.append(node_reason)
    if not reasons:
        node_pool_status, node_pool_evidence, node_pool_reason = _kind_node_pool_contract(
            context, cluster_name, execute=True
        )
        node_pools = {
            "status": node_pool_status,
            "evidence": node_pool_evidence,
            "reason": node_pool_reason,
        }
        if node_pool_status != "pass":
            reasons.append(node_pool_reason or "kind worker node pool contract failed")
    render_result, documents = _render(image, render_output)
    if render_result.status != "pass":
        reasons.append(render_result.reason or "render failed during execute")
    schema_migration: dict[str, Any] = {"status": "not_run"}
    if not reasons:
        migration_status, migration_evidence, migration_reason = _delete_schema_migration_job(
            context, cluster_name, namespace, execute=True
        )
        schema_migration = {
            "status": migration_status,
            "evidence": migration_evidence,
            "reason": migration_reason,
        }
        if migration_status != "pass":
            reasons.append(migration_reason or "schema migration Job deletion failed")
    if not reasons:
        applied = _kubectl(
            context,
            ["apply", "-f", "-"],
            input_text=render_output.read_text(encoding="utf-8"),
            timeout=180,
        )
        if applied.status != "pass":
            reasons.append(applied.reason or "kind manifest apply failed")
    runtime_status = "not_run"
    if not reasons:
        runtime_status, runtime_reasons = _wait_for_runtime(context, namespace, documents, timeout)
        reasons.extend(runtime_reasons)
    schema_migration_head: dict[str, Any] = {
        "status": "not_run",
        "evidence": {"expected_head": EXPECTED_ALEMBIC_HEAD},
    }
    if not reasons:
        head_status, head_evidence, head_reason = _schema_head_contract(context, namespace)
        schema_migration_head = {
            "status": head_status,
            "evidence": head_evidence,
            "reason": head_reason,
        }
        if head_status != "pass":
            reasons.append(head_reason or "Alembic schema head verification failed")
    workload_distribution: dict[str, Any] = {"status": "not_run"}
    if not reasons:
        distribution_status, distribution_evidence, distribution_reason = _workload_distribution(
            context, namespace
        )
        workload_distribution = {
            "status": distribution_status,
            "evidence": distribution_evidence,
            "reason": distribution_reason,
        }
        if distribution_status != "pass":
            reasons.append("workload distribution inspection failed")
    scenarios: dict[str, dict[str, Any]] = {}
    if not reasons:
        scenario_functions = (
            (
                "candidate_im_gateway_probe",
                lambda context_value, namespace_value: _candidate_im_scenario(
                    context_value, namespace_value, image
                ),
            ),
            (
                "candidate_runtime_probe",
                lambda context_value, namespace_value: _candidate_runtime_scenario(
                    context_value, namespace_value, image
                ),
            ),
            (
                "candidate_evolution_probe",
                lambda context_value, namespace_value: _candidate_evolution_scenario(
                    context_value, namespace_value, image
                ),
            ),
            (
                "candidate_redis_probe",
                lambda context_value, namespace_value: _candidate_redis_scenario(
                    context_value, namespace_value, image
                ),
            ),
            ("worker_pod_replacement", _worker_restart_scenario),
            ("provider_endpoint_recovery", _network_recovery_scenario),
            (
                "postgres_pod_replacement",
                lambda context_value, namespace_value: _postgres_restart_scenario(
                    context_value, namespace_value, image
                ),
            ),
        )
        for name, function in scenario_functions:
            status, evidence, reason = function(context, namespace)
            scenarios[name] = {
                "status": status,
                "evidence": evidence,
                "reason": reason,
            }
            if status != "pass":
                reasons.append(f"scenario {name} failed")
    return {
        "status": "pass" if not reasons else "fail",
        "rejection_reasons": list(dict.fromkeys(reasons)),
        "image_digest": local_image_digest,
        "cluster": {
            "name": cluster_name,
            "context": context,
            "uid": cluster_uid,
            "status": "observed" if cluster_uid else "not_run",
            "nodes": node_counts,
            "created_by_gate": cluster_created,
            "namespace": namespace,
        },
        "runtime": {"status": runtime_status},
        "schema_migration": schema_migration,
        "schema_migration_head": schema_migration_head,
        "workload_distribution": workload_distribution,
        "node_pools": node_pools,
        "scenarios": scenarios,
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    image = args.image or DEFAULT_IMAGE
    render_output = Path(args.render_output).resolve()
    preflight = _preflight(image, render_output, execute=args.execute, load_image=args.load_image)
    report: dict[str, Any] = {
        "schema_version": 1,
        "kind": "kind_ack_gate",
        "generated_at": _now(),
        "mode": "execute" if args.execute else "preflight",
        "lineage": {
            "git_sha": _git_sha(),
            "source_fingerprint": _source_lineage(),
            "image": _image_identity(image, loaded=args.load_image),
        },
        "topology": {
            "kind_config": str(KIND_CONFIG),
            "control_plane": 1,
            "workers": 3,
            "namespace": args.namespace,
            "context": args.context,
        },
        "cluster": {
            "name": args.cluster_name,
            "context": args.context,
            "uid": None,
            "status": "not_run",
        },
        "preflight": preflight,
        "schema_migration": {"status": "not_run"},
        "schema_migration_head": {
            "status": "not_run",
            "evidence": {"expected_head": EXPECTED_ALEMBIC_HEAD},
        },
        "workload_distribution": {"status": "not_run"},
        "node_pools": {"status": "not_run"},
        "scenarios": {},
        "scenario_plan": SCENARIO_PLAN,
        "local_k8s_gate": "not_run",
        "ack_compatibility": "not_run",
        "production_gate": "not_run",
        "gate": "not_run",
        "rejection_reasons": list(preflight["rejection_reasons"]),
    }
    if args.execute and preflight["status"] == "pass":
        execution = _execute(
            cluster_name=args.cluster_name,
            context=args.context,
            namespace=args.namespace,
            image=image,
            load_image=args.load_image,
            render_output=render_output,
            preflight=preflight,
            timeout=args.timeout_seconds,
        )
        report["cluster"] = execution["cluster"]
        if execution.get("image_digest"):
            report["lineage"]["image"]["digest"] = execution["image_digest"]
            report["lineage"]["image"]["immutable"] = True
        report["runtime"] = execution["runtime"]
        report["schema_migration"] = execution["schema_migration"]
        report["schema_migration_head"] = execution["schema_migration_head"]
        report["workload_distribution"] = execution["workload_distribution"]
        report["node_pools"] = execution["node_pools"]
        report["scenarios"] = execution["scenarios"]
        report["local_k8s_gate"] = execution["status"]
        report["gate"] = execution["status"]
        report["rejection_reasons"] = list(
            dict.fromkeys(report["rejection_reasons"] + execution["rejection_reasons"])
        )
    elif not args.execute and preflight["status"] == "pass":
        report["rejection_reasons"].append(
            "preflight passed; --execute is required for the local Kubernetes gate"
        )
    if report["gate"] == "pass":
        report["summary"] = "local kind runtime gate passed; ACK and production remain not_run"
    else:
        report["summary"] = "kind gate did not produce a local runtime pass"
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute", action="store_true", help="create/apply to the exact kind context"
    )
    parser.add_argument("--cluster-name", default=DEFAULT_CLUSTER_NAME)
    parser.add_argument("--context", default=None, help="defaults to kind-<cluster-name>")
    parser.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    parser.add_argument(
        "--image", default=DEFAULT_IMAGE, help="DockerHub/registry reference or local image"
    )
    parser.add_argument(
        "--load-image",
        action="store_true",
        help="in execute mode, load --image from the local Docker daemon into kind",
    )
    parser.add_argument("--render-output", type=Path, default=DEFAULT_RENDER_OUTPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    # Three workers roll one at a time and each retains the production-like
    # 90-second termination budget.  The default must cover that serialized
    # lifecycle plus readiness probes on a busy desktop Docker runtime.
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_ROLLOUT_TIMEOUT_SECONDS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not CLUSTER_NAME_RE.fullmatch(args.cluster_name):
        print("cluster name must be a lowercase DNS label", file=sys.stderr)
        return 2
    if args.context is None:
        args.context = f"kind-{args.cluster_name}"
    if not args.context.startswith("kind-"):
        print("context must start with kind-", file=sys.stderr)
        return 2
    if args.namespace != DEFAULT_NAMESPACE:
        print(f"namespace must be {DEFAULT_NAMESPACE}", file=sys.stderr)
        return 2
    report = build_report(args)
    rendered = atomic_write_json(args.output, report).rstrip("\n")
    print(rendered)
    return 0 if report["gate"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
