#!/usr/bin/env python3
"""Create and remove one bounded Kubernetes Job for the HPA runtime gate.

The gate deliberately supplies a dedicated kubeconfig and a distinct context.
This process is the only component allowed to create the short-lived load Job;
it never reports HPA numbers.  The parent gate re-reads the Job through its
administrative API client and treats the JSON emitted here as an identifier
hint only.

The image and command are explicit operator inputs.  The command must be a
JSON array (not a shell string) and must implement the application-specific
bounded backlog operation in the image.  ``load`` accepts a live
single-completion Job (or a successfully completed compatibility command);
``clear`` creates a separate nonce-labelled cleanup Job, validates its
database receipt while its Pod is still available, and then deletes both Jobs.
``TRPC_K8S_HPA_DRIVER_IMAGE_PULL_SECRET`` may name a pre-created private
registry pull Secret; the driver receives only that non-sensitive name.  The
bounded probe itself uses the dedicated ``trpc_hpa`` database role through the
``trpc-hpa-secrets`` Secret; it never receives the worker DSN.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from typing import Any

MAX_TIMEOUT_SECONDS = 300.0
MAX_COMMAND_ARGS = 64
MAX_COMMAND_ARG_BYTES = 512
MAX_IMAGE_BYTES = 512
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
DNS_1123_LABEL = r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?"
NAMESPACE_RE = re.compile(rf"^{DNS_1123_LABEL}$")
SECRET_NAME_RE = re.compile(rf"{DNS_1123_LABEL}(?:\.{DNS_1123_LABEL})*")
SERVICE_ACCOUNT_SUBJECT_RE = re.compile(
    rf"^system:serviceaccount:({DNS_1123_LABEL}):({DNS_1123_LABEL})$"
)
IMAGE_RE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
NODE_NAME_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$")
LABEL_RE = re.compile(
    r"^[A-Za-z0-9](?:[-A-Za-z0-9./_]*[A-Za-z0-9])?="
    r"[A-Za-z0-9](?:[-A-Za-z0-9._]*[A-Za-z0-9])?$"
)

OWNER_LABEL = "trpc.io/hpa-gate"
OWNER_VALUE = "bounded-job-driver"
RUN_LABEL = "trpc.io/hpa-run"
PHASE_LABEL = "trpc.io/hpa-phase"
CLUSTER_LABEL = "trpc.io/hpa-cluster"
TRUSTED_PART_LABEL = "app.kubernetes.io/part-of"
TRUSTED_PART_VALUE = "trpc-agent-service"

HPA_NODE_NAME_ENV = "TRPC_K8S_HPA_DRIVER_NODE_NAME"
HPA_NODE_LABEL_ENV = "TRPC_K8S_HPA_DRIVER_NODE_LABEL"
HPA_TAINT_KEY_ENV = "TRPC_K8S_HPA_DRIVER_TAINT_KEY"
HPA_TAINT_VALUE_ENV = "TRPC_K8S_HPA_DRIVER_TAINT_VALUE"
HPA_TAINT_EFFECT_ENV = "TRPC_K8S_HPA_DRIVER_TAINT_EFFECT"
HPA_DATABASE_DSN_ENV = "TRPC_HPA_DATABASE_DSN"
HPA_DATABASE_SECRET_NAME = "trpc-hpa-secrets"  # noqa: S105 - Kubernetes Secret name, not a credential
HPA_DATABASE_SECRET_KEY = HPA_DATABASE_DSN_ENV
HPA_JOB_NAMESPACE_ENV = "TRPC_K8S_HPA_JOB_NAMESPACE"
HPA_PHASE_ENV = "TRPC_HPA_PHASE"
HPA_PROBE_ARGUMENT = "--backlog-probe"
HPA_CLEANUP_ARGUMENT = "--backlog-cleanup"
HPA_PROBE_TENANT_PREFIX = "hpa-"
HPA_PROBE_APP_ID = "hpa-probe"
# Forty fixture rows put a three-replica HPA above Kubernetes' default 10%
# tolerance for an AverageValue target of ten, while still requesting only a
# fourth worker that is schedulable on the dedicated ACK workload node.
HPA_PROBE_ROWS = 40

# This is the receipt contract returned by the versioned database cleanup
# function.  The SQL function owns the actual table list and deletion order;
# this closed list lets the image validate a complete, tenant-scoped receipt
# without querying any table directly.
_HPA_PROBE_CLEANUP_TABLES = (
    "cell_effect_receipts",
    "cell_effect_ledger",
    "cell_tool_intents",
    "cell_branch_heads",
    "cell_placement_reservations",
    "cell_approval_nonces",
    "cell_events",
    "agent_cells",
    "agent_capsules",
    "session_mailbox_items",
    "delivery_attempts",
    "outbox_events",
    "turn_intents",
    "session_events",
    "session_summaries",
    "tool_executions",
    "session_turns",
    "inbound_messages",
    "outbound_messages",
    "knowledge_embeddings",
    "knowledge_items",
    "artifacts",
    "memories",
    "dead_letters",
    "confirmation_challenges",
    "audit_logs",
    "tenant_budget_usage",
    "fault_stage_controls",
    "migration_write_barriers",
    "migration_leases",
    "migration_checkpoints",
    "admin_idempotency",
    "channel_identities",
    "channel_bindings",
    "config_revisions",
    "storage_profiles",
    "tenant_policies",
    "session_mailboxes",
    "sessions",
    "agent_apps",
    "migration_scope_manifests",
    "tenants",
)

_HPA_PREPARE_QUERY = "SELECT public.prepare_hpa_fixture($1, $2)"
_HPA_CLEANUP_QUERY = "SELECT public.cleanup_hpa_fixture($1)"

_TRANSIENT_KUBECTL_ERRORS = (
    "context deadline exceeded",
    "connection reset",
    "connection was forcibly closed",
    "eof",
    "i/o timeout",
    "request canceled",
    "tls handshake timeout",
    "timed out",
    "timeout",
    "unexpected end of json input",
)


class _TransientKubectlError(RuntimeError):
    """A transport failure whose server-side outcome is ambiguous."""


def _strict_json(value: str) -> Any:
    def duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = item
        return result

    return json.loads(
        value,
        object_pairs_hook=duplicate,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON value: {token}")
        ),
    )


def _error(message: str) -> dict[str, Any]:
    return {"schema_version": 1, "status": "fail", "reason": message}


def _emit(payload: Mapping[str, Any]) -> int:
    sys.stdout.write(json.dumps(dict(payload), separators=(",", ":"), sort_keys=True) + "\n")
    return 0 if payload.get("status") == "pass" else 1


def _timeout() -> float:
    raw = os.getenv("TRPC_K8S_HPA_DRIVER_TIMEOUT_SECONDS", "300")
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError("TRPC_K8S_HPA_DRIVER_TIMEOUT_SECONDS is invalid") from exc
    if not math.isfinite(value) or value <= 0 or value > MAX_TIMEOUT_SECONDS:
        raise ValueError("driver timeout must be in (0, 300]")
    return value


def _context() -> str | None:
    value = os.getenv("TRPC_K8S_HPA_CONTEXT", "").strip()
    if not value:
        return None
    if len(value) > 128 or any(ch.isspace() or ch in "\x00\r\n" for ch in value):
        raise ValueError("TRPC_K8S_HPA_CONTEXT is invalid")
    return value


def _configuration() -> dict[str, str | list[str]]:
    namespace = os.getenv("TRPC_K8S_HPA_NAMESPACE", "").strip()
    job_namespace = os.getenv(HPA_JOB_NAMESPACE_ENV, "").strip() or namespace
    nonce = os.getenv("TRPC_K8S_HPA_RUN_NONCE", "").strip().lower()
    fingerprint = os.getenv("TRPC_K8S_HPA_CLUSTER_FINGERPRINT", "").strip().lower()
    phase = os.getenv("TRPC_K8S_HPA_PHASE", "").strip().lower()
    subject = os.getenv("TRPC_K8S_HPA_DRIVER_SUBJECT", "").strip()
    image = os.getenv("TRPC_K8S_HPA_DRIVER_JOB_IMAGE", "").strip()
    command_text = os.getenv("TRPC_K8S_HPA_DRIVER_JOB_COMMAND", "").strip()
    image_pull_secret = os.getenv("TRPC_K8S_HPA_DRIVER_IMAGE_PULL_SECRET", "").strip()
    node_name = os.getenv(HPA_NODE_NAME_ENV, "").strip().lower()
    node_label = os.getenv(HPA_NODE_LABEL_ENV, "").strip()
    taint_key = os.getenv(HPA_TAINT_KEY_ENV, "").strip()
    taint_value = os.getenv(HPA_TAINT_VALUE_ENV, "").strip()
    taint_effect = os.getenv(HPA_TAINT_EFFECT_ENV, "").strip()
    if NAMESPACE_RE.fullmatch(namespace) is None:
        raise ValueError("HPA driver namespace is invalid")
    if NAMESPACE_RE.fullmatch(job_namespace) is None:
        raise ValueError("HPA driver Job namespace is invalid")
    if NONCE_RE.fullmatch(nonce) is None:
        raise ValueError("HPA driver run nonce is invalid")
    if HASH_RE.fullmatch(fingerprint) is None:
        raise ValueError("HPA driver cluster fingerprint is invalid")
    if phase not in {"load", "clear"}:
        raise ValueError("HPA driver phase is invalid")
    subject_match = SERVICE_ACCOUNT_SUBJECT_RE.fullmatch(subject)
    if subject_match is None:
        raise ValueError("HPA driver subject is invalid")
    if subject_match.group(1) != job_namespace:
        raise ValueError("HPA driver subject namespace must match the Job namespace")
    if (
        not image
        or len(image.encode("utf-8")) > MAX_IMAGE_BYTES
        or IMAGE_RE.fullmatch(image) is None
    ):
        raise ValueError("HPA driver Job image must be an immutable sha256 reference")
    if not command_text:
        raise ValueError("HPA driver Job command is required")
    if image_pull_secret and (
        len(image_pull_secret) > 253 or SECRET_NAME_RE.fullmatch(image_pull_secret) is None
    ):
        raise ValueError("HPA driver image pull Secret name is invalid")
    placement = (node_name, node_label, taint_key, taint_value, taint_effect)
    if any(placement) and not all(placement):
        raise ValueError("HPA driver placement configuration is incomplete")
    if all(placement):
        if NODE_NAME_RE.fullmatch(node_name) is None:
            raise ValueError("HPA driver node name is invalid")
        if LABEL_RE.fullmatch(node_label) is None:
            raise ValueError("HPA driver node label is invalid")
        if any(
            not value or len(value) > 253 or any(ch.isspace() or ch in "\x00\r\n" for ch in value)
            for value in (taint_key, taint_value)
        ):
            raise ValueError("HPA driver taint is invalid")
        if taint_effect not in {"NoSchedule", "PreferNoSchedule", "NoExecute"}:
            raise ValueError("HPA driver taint effect is invalid")
        label_key, label_value = node_label.split("=", 1)
        if label_key != taint_key or label_value != taint_value:
            raise ValueError("HPA driver node label and taint must bind the same role")
    try:
        command = _strict_json(command_text)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("HPA driver Job command must be a JSON array") from exc
    if (
        not isinstance(command, list)
        or not command
        or len(command) > MAX_COMMAND_ARGS
        or any(
            not isinstance(arg, str)
            or not arg
            or len(arg.encode("utf-8")) > MAX_COMMAND_ARG_BYTES
            or any(ch in arg for ch in ("\x00", "\r", "\n"))
            for arg in command
        )
    ):
        raise ValueError("HPA driver Job command is not a bounded argument array")
    return {
        "namespace": namespace,
        "job_namespace": job_namespace,
        "nonce": nonce,
        "fingerprint": fingerprint,
        "phase": phase,
        "subject": subject,
        "image": image,
        "command": command,
        "image_pull_secret": image_pull_secret,
        "node_name": node_name,
        "node_label": node_label,
        "taint_key": taint_key,
        "taint_value": taint_value,
        "taint_effect": taint_effect,
    }


def _kubectl(
    arguments: list[str], *, timeout: float, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("kubectl")
    if executable is None:
        raise RuntimeError("kubectl is not installed")
    kubeconfig = os.getenv("KUBECONFIG", "").strip()
    if not kubeconfig:
        raise RuntimeError("dedicated KUBECONFIG is missing")
    command = [executable, "--kubeconfig", kubeconfig]
    context = _context()
    if context:
        command.extend(["--context", context])
    command.extend(arguments)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "KUBECONFIG": kubeconfig,
        "HOME": os.environ.get("HOME", ""),
        "USERPROFILE": os.environ.get("USERPROFILE", ""),
    }
    # Windows kubectl needs these OS runtime variables to initialize its
    # socket/provider stack. Keep the environment explicit and add only
    # values that are actually present; no arbitrary parent secrets leak in.
    for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    try:
        return subprocess.run(  # noqa: S603 - explicit kubectl argv, no shell
            command,
            check=False,
            capture_output=True,
            text=True,
            input=input_text,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise _TransientKubectlError("kubectl command timed out") from exc


def _transient_kubectl_failure(result: subprocess.CompletedProcess[str]) -> bool:
    text = f"{result.stdout}\n{result.stderr}".lower()
    return any(marker in text for marker in _TRANSIENT_KUBECTL_ERRORS)


def _retry_transient(operation: Callable[[], Any]) -> Any:
    last_error: _TransientKubectlError | None = None
    for attempt in range(3):
        try:
            return operation()
        except _TransientKubectlError as error:
            last_error = error
            if attempt < 2:
                time.sleep(0.25)
    assert last_error is not None
    raise last_error


def _json_output(result: subprocess.CompletedProcess[str], description: str) -> Mapping[str, Any]:
    if result.returncode != 0:
        raise RuntimeError(f"{description} failed")
    try:
        value = _strict_json(result.stdout)
    except (ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{description} returned invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise RuntimeError(f"{description} returned a non-object")
    return value


def _cluster_fingerprint(timeout: float) -> str:
    result = _kubectl(["version", "--request-timeout=10s", "-o", "json"], timeout=timeout)
    if result.returncode != 0 and _transient_kubectl_failure(result):
        raise _TransientKubectlError("Kubernetes version read was interrupted")
    payload = _json_output(result, "Kubernetes version")
    server = payload.get("serverVersion")
    server_map = server if isinstance(server, Mapping) else {}
    identity = "|".join(
        str(server_map.get(key, "")) for key in ("gitVersion", "gitCommit", "platform")
    )
    if not identity.strip("|"):
        identity = "unknown-api-server"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _whoami(timeout: float, expected_subject: str) -> None:
    result = _kubectl(["auth", "whoami", "-o", "json"], timeout=timeout)
    if result.returncode != 0 and _transient_kubectl_failure(result):
        raise _TransientKubectlError("SelfSubjectReview was interrupted")
    payload = _json_output(result, "SelfSubjectReview")
    status = payload.get("status")
    user_info = status.get("userInfo") if isinstance(status, Mapping) else None
    username = user_info.get("username") if isinstance(user_info, Mapping) else None
    if username != expected_subject:
        raise RuntimeError("driver kubeconfig identity does not match declared ServiceAccount")


def _job_name(nonce: str) -> str:
    return f"trpc-hpa-load-{nonce[:20]}"


def _labels(config: Mapping[str, str | list[str]], *, phase: str = "load") -> dict[str, str]:
    fingerprint = str(config["fingerprint"])
    return {
        OWNER_LABEL: OWNER_VALUE,
        RUN_LABEL: str(config["nonce"]),
        PHASE_LABEL: phase,
        CLUSTER_LABEL: fingerprint[:63],
        # The support NetworkPolicy admits only runtime-labelled Pods.  Keep
        # this label on both Job and Pod so the bounded probe can use the
        # least-privilege database egress path.
        TRUSTED_PART_LABEL: TRUSTED_PART_VALUE,
    }


def _configured_placement(config: Mapping[str, str | list[str]]) -> dict[str, Any] | None:
    """Return the immutable node binding, if this driver has one configured."""

    node_name = str(config.get("node_name", "")).strip()
    node_label = str(config.get("node_label", "")).strip()
    taint_key = str(config.get("taint_key", "")).strip()
    taint_value = str(config.get("taint_value", "")).strip()
    taint_effect = str(config.get("taint_effect", "")).strip()
    if not any((node_name, node_label, taint_key, taint_value, taint_effect)):
        return None
    if not all((node_name, node_label, taint_key, taint_value, taint_effect)):
        raise RuntimeError("HPA driver placement configuration is incomplete")
    label_key, label_value = node_label.split("=", 1)
    return {
        "node_name": node_name,
        "node_selector": {label_key: label_value, "kubernetes.io/hostname": node_name},
        "toleration": {
            "key": taint_key,
            "operator": "Equal",
            "value": taint_value,
            "effect": taint_effect,
        },
    }


def _job_manifest(config: Mapping[str, str | list[str]]) -> dict[str, Any]:
    target_namespace = str(config["namespace"])
    job_namespace = str(config.get("job_namespace", target_namespace))
    labels = _labels(config)
    template_spec: dict[str, Any] = {
        "restartPolicy": "Never",
        "automountServiceAccountToken": False,
        "enableServiceLinks": False,
        "hostNetwork": False,
        "terminationGracePeriodSeconds": 30,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 999,
            "runAsGroup": 999,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [
            {
                "name": "bounded-load",
                "image": str(config["image"]),
                "imagePullPolicy": "IfNotPresent",
                "command": list(config["command"]),
                "env": [
                    {"name": "TRPC_HPA_RUN_NONCE", "value": str(config["nonce"])},
                    {"name": "TRPC_HPA_TARGET_NAMESPACE", "value": target_namespace},
                    {
                        "name": "TRPC_HPA_CLUSTER_FINGERPRINT",
                        "value": str(config["fingerprint"]),
                    },
                    # The long-running probe is deliberately always the load
                    # phase.  Clear uses a separate receipt-producing Job;
                    # SIGTERM cleanup remains an idempotent safety net.
                    {"name": HPA_PHASE_ENV, "value": "load"},
                    {
                        "name": HPA_DATABASE_DSN_ENV,
                        "valueFrom": {
                            "secretKeyRef": {
                                "name": HPA_DATABASE_SECRET_NAME,
                                "key": HPA_DATABASE_SECRET_KEY,
                            }
                        },
                    },
                ],
                "resources": {
                    "requests": {"cpu": "10m", "memory": "32Mi"},
                    "limits": {"cpu": "250m", "memory": "128Mi"},
                },
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
            }
        ],
    }
    placement = _configured_placement(config)
    if placement is not None:
        template_spec["nodeSelector"] = placement["node_selector"]
        template_spec["tolerations"] = [
            placement["toleration"],
        ]
    manifest: dict[str, Any] = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": _job_name(str(config["nonce"])),
            "namespace": job_namespace,
            "labels": labels,
        },
        "spec": {
            "completions": 1,
            "parallelism": 1,
            "backoffLimit": 0,
            "activeDeadlineSeconds": min(300, max(30, int(_timeout()))),
            "ttlSecondsAfterFinished": 600,
            "template": {
                "metadata": {"labels": labels},
                "spec": template_spec,
            },
        },
    }
    image_pull_secret = str(config.get("image_pull_secret", "")).strip()
    if image_pull_secret:
        manifest["spec"]["template"]["spec"]["imagePullSecrets"] = [{"name": image_pull_secret}]
    return manifest


def _cleanup_job_name(nonce: str) -> str:
    return f"trpc-hpa-cleanup-{nonce[:20]}"


def _cleanup_job_manifest(config: Mapping[str, str | list[str]]) -> dict[str, Any]:
    """Build a one-shot cleanup Job in the driver namespace.

    The cleanup Job uses the same immutable image and dedicated database
    Secret as the long-running probe, but has its own nonce-labelled Job and
    Pod.  This lets the host read the database receipt before deleting either
    Job, so cleanup never depends on a deleted Pod's stdout.
    """

    manifest = copy.deepcopy(_job_manifest(config))
    cleanup_labels = _labels(config, phase="cleanup")
    manifest["metadata"]["name"] = _cleanup_job_name(str(config["nonce"]))
    manifest["metadata"]["labels"] = cleanup_labels
    template = manifest["spec"]["template"]
    template["metadata"]["labels"] = cleanup_labels
    container = template["spec"]["containers"][0]
    container["command"] = ["python", "scripts/kubernetes_hpa_load_driver.py", HPA_CLEANUP_ARGUMENT]
    container_env = container["env"]
    for item in container_env:
        if item.get("name") == HPA_PHASE_ENV:
            item["value"] = "clear"
            break
    return manifest


def _get_job(config: Mapping[str, str | list[str]], timeout: float) -> Mapping[str, Any] | None:
    return _get_named_job(config, _job_name(str(config["nonce"])), timeout)


def _get_named_job(
    config: Mapping[str, str | list[str]], name: str, timeout: float
) -> Mapping[str, Any] | None:
    result = _kubectl(
        [
            "get",
            "job",
            name,
            "--namespace",
            str(config.get("job_namespace", config["namespace"])),
            "-o",
            "json",
        ],
        timeout=timeout,
    )
    if result.returncode != 0:
        if "notfound" in result.stderr.lower() or "not found" in result.stderr.lower():
            return None
        if _transient_kubectl_failure(result):
            raise _TransientKubectlError("HPA Job read was interrupted")
        raise RuntimeError("HPA Job could not be read")
    return _json_output(result, "HPA Job")


def _validate_job(
    payload: Mapping[str, Any],
    config: Mapping[str, str | list[str]],
    *,
    name: str | None = None,
    phase: str = "load",
) -> tuple[str, dict[str, str]]:
    metadata = payload.get("metadata")
    metadata_map = metadata if isinstance(metadata, Mapping) else {}
    uid = metadata_map.get("uid")
    if not isinstance(uid, str) or not uid or len(uid) > 128 or any(ch.isspace() for ch in uid):
        raise RuntimeError("HPA load Job has no safe UID")
    if metadata_map.get("name") != (name or _job_name(str(config["nonce"]))) or metadata_map.get(
        "namespace"
    ) != config.get("job_namespace", config["namespace"]):
        raise RuntimeError("HPA load Job identity does not match run nonce")
    labels = metadata_map.get("labels")
    expected = _labels(config, phase=phase)
    if not isinstance(labels, Mapping) or any(
        labels.get(key) != value for key, value in expected.items()
    ):
        raise RuntimeError("HPA load Job labels are not bound to this run")
    placement = _configured_placement(config)
    if placement is not None:
        spec = payload.get("spec")
        spec_map = spec if isinstance(spec, Mapping) else {}
        template = spec_map.get("template")
        template_map = template if isinstance(template, Mapping) else {}
        template_spec = template_map.get("spec")
        template_spec_map = template_spec if isinstance(template_spec, Mapping) else {}
        if template_spec_map.get("nodeSelector") != placement["node_selector"]:
            raise RuntimeError("HPA load Job node selector is not bound to the configured node")
        tolerations = template_spec_map.get("tolerations")
        if tolerations != [placement["toleration"]]:
            raise RuntimeError("HPA load Job toleration is not bound to the configured role")
    return uid, expected


def _load(config: Mapping[str, str | list[str]], timeout: float) -> dict[str, Any]:
    _retry_transient(lambda: _whoami(timeout, str(config["subject"])))
    actual_fingerprint = _retry_transient(lambda: _cluster_fingerprint(timeout))
    if actual_fingerprint != config["fingerprint"]:
        raise RuntimeError("driver API server fingerprint does not match the gate")
    existing = _retry_transient(lambda: _get_job(config, timeout))
    if existing is not None:
        uid, labels = _validate_job(existing, config)
        status = existing.get("status")
        status_map = status if isinstance(status, Mapping) else {}
        active = status_map.get("active")
        succeeded = status_map.get("succeeded")
        if active != 1 and succeeded != 1:
            if status_map.get("failed", 0) > 0:
                raise RuntimeError("a previous nonce-labelled HPA load Job failed")
            raise RuntimeError("a previous nonce-labelled HPA load Job is not active")
        return {
            "schema_version": 1,
            "status": "pass",
            "phase": "load",
            "namespace": config["namespace"],
            "target_namespace": config["namespace"],
            "job_namespace": config.get("job_namespace", config["namespace"]),
            "run_nonce": config["nonce"],
            "cluster_fingerprint": actual_fingerprint,
            "job_name": _job_name(str(config["nonce"])),
            "job_uid": uid,
            "job_labels": labels,
            "api_observed": True,
            "job_active": 1 if active == 1 else 0,
            "job_succeeded": 1 if succeeded == 1 else 0,
            "reused": True,
        }
    manifest = json.dumps(_job_manifest(config), separators=(",", ":"))
    applied = _kubectl(["create", "-f", "-"], timeout=timeout, input_text=manifest)
    if applied.returncode != 0:
        raise RuntimeError("bounded HPA load Job could not be created")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        payload = _retry_transient(
            lambda: _get_job(config, min(10.0, max(1.0, deadline - time.monotonic())))
        )
        if payload is None:
            raise RuntimeError("bounded HPA load Job disappeared before completion")
        uid, labels = _validate_job(payload, config)
        status = payload.get("status")
        status_map = status if isinstance(status, Mapping) else {}
        active = status_map.get("active")
        succeeded = status_map.get("succeeded")
        if active == 1 or succeeded == 1:
            return {
                "schema_version": 1,
                "status": "pass",
                "phase": "load",
                "namespace": config["namespace"],
                "target_namespace": config["namespace"],
                "job_namespace": config.get("job_namespace", config["namespace"]),
                "run_nonce": config["nonce"],
                "cluster_fingerprint": actual_fingerprint,
                "job_name": _job_name(str(config["nonce"])),
                "job_uid": uid,
                "job_labels": labels,
                "api_observed": True,
                "job_active": 1 if active == 1 else 0,
                "job_succeeded": 1 if succeeded == 1 else 0,
                "reused": False,
            }
        if status_map.get("failed", 0) > 0:
            raise RuntimeError("bounded HPA load Job failed")
        time.sleep(min(1.0, max(0.05, deadline - time.monotonic())))
    raise RuntimeError("bounded HPA load Job did not complete before its deadline")


def _delete_named_job(
    config: Mapping[str, str | list[str]],
    name: str,
    expected_uid: str,
    timeout: float,
) -> None:
    """Delete one nonce-bound Job and API-confirm its absence."""

    deadline = time.monotonic() + min(timeout, 30.0)
    arguments = [
        "delete",
        "job",
        name,
        "--namespace",
        str(config.get("job_namespace", config["namespace"])),
        "--ignore-not-found",
        "--wait=false",
    ]
    delete_failed = False
    attempts = 0
    while attempts < 3:
        attempts += 1
        try:
            result = _kubectl(arguments, timeout=max(0.1, min(10.0, timeout)))
            if result.returncode == 0:
                delete_failed = False
                break
            if not _transient_kubectl_failure(result):
                raise RuntimeError("bounded HPA Job could not be deleted")
            delete_failed = True
        except _TransientKubectlError:
            delete_failed = True
        if time.monotonic() >= deadline:
            break
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        try:
            observed = _get_named_job(config, name, max(0.1, min(10.0, remaining)))
        except _TransientKubectlError:
            observed = None
            # Transport failure is not absence evidence.  Keep polling, but
            # never report success until NotFound is actually observed.
            time.sleep(min(0.25, max(0.05, remaining)))
            continue
        if observed is None:
            return
        observed_uid, _ = _validate_job(
            observed,
            config,
            name=name,
            phase="cleanup" if name == _cleanup_job_name(str(config["nonce"])) else "load",
        )
        if observed_uid != expected_uid:
            raise RuntimeError("bounded HPA Job identity changed during clear")
        if delete_failed and attempts < 3:
            attempts += 1
            try:
                result = _kubectl(arguments, timeout=max(0.1, min(10.0, remaining)))
                if result.returncode != 0 and not _transient_kubectl_failure(result):
                    raise RuntimeError("bounded HPA Job could not be deleted")
                delete_failed = result.returncode != 0
            except _TransientKubectlError:
                delete_failed = True
        time.sleep(min(0.25, max(0.05, remaining)))
    if delete_failed:
        raise RuntimeError("bounded HPA Job delete failed and absence was not observed")
    raise RuntimeError("bounded HPA Job deletion was not observed")


def _cleanup_pod_receipt(
    config: Mapping[str, str | list[str]],
    cleanup_job: Mapping[str, Any],
    timeout: float,
) -> dict[str, Any]:
    """Read the completed cleanup Pod while it is still API-visible."""

    metadata = cleanup_job.get("metadata")
    metadata_map = metadata if isinstance(metadata, Mapping) else {}
    job_uid = metadata_map.get("uid")
    if not isinstance(job_uid, str) or not job_uid:
        raise RuntimeError("HPA cleanup Job has no safe UID")
    job_name = _cleanup_job_name(str(config["nonce"]))
    result = _kubectl(
        [
            "get",
            "pods",
            "--namespace",
            str(config.get("job_namespace", config["namespace"])),
            "-l",
            f"job-name={job_name}",
            "-o",
            "json",
        ],
        timeout=timeout,
    )
    if result.returncode != 0:
        if _transient_kubectl_failure(result):
            raise _TransientKubectlError("HPA cleanup Pod read was interrupted")
        raise RuntimeError("HPA cleanup Pod list could not be read")
    payload = _json_output(result, "HPA cleanup Pod list")
    items = payload.get("items")
    if not isinstance(items, list):
        raise RuntimeError("HPA cleanup Pod list is invalid")
    expected_labels = _labels(config, phase="cleanup")
    matching: list[Mapping[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        item_metadata = item.get("metadata")
        item_metadata_map = item_metadata if isinstance(item_metadata, Mapping) else {}
        labels = item_metadata_map.get("labels")
        owners = item_metadata_map.get("ownerReferences")
        if (
            isinstance(labels, Mapping)
            and all(labels.get(key) == value for key, value in expected_labels.items())
            and isinstance(owners, list)
            and any(
                isinstance(owner, Mapping)
                and owner.get("kind") == "Job"
                and owner.get("uid") == job_uid
                and owner.get("controller") is True
                for owner in owners
            )
        ):
            matching.append(item)
    if len(matching) != 1:
        if not matching and not items:
            # A completed Job can become visible before its Pod is returned by
            # the list endpoint.  Retry that narrow propagation window; more
            # than one candidate is an identity violation and fails closed.
            raise _TransientKubectlError("HPA cleanup Pod is not visible yet")
        raise RuntimeError("HPA cleanup Job must have exactly one nonce-labelled Pod")
    pod = matching[0]
    pod_metadata = pod.get("metadata")
    pod_metadata_map = pod_metadata if isinstance(pod_metadata, Mapping) else {}
    pod_name = pod_metadata_map.get("name")
    if pod_metadata_map.get("namespace") != config.get("job_namespace", config["namespace"]):
        raise RuntimeError("HPA cleanup Pod namespace does not match its Job")
    status = pod.get("status")
    status_map = status if isinstance(status, Mapping) else {}
    if not isinstance(pod_name, str) or not pod_name or status_map.get("phase") != "Succeeded":
        raise RuntimeError("HPA cleanup Pod did not succeed")
    logs = _kubectl(
        [
            "logs",
            pod_name,
            "--namespace",
            str(config.get("job_namespace", config["namespace"])),
            "--container",
            "bounded-load",
        ],
        timeout=timeout,
    )
    if logs.returncode != 0:
        if _transient_kubectl_failure(logs):
            raise _TransientKubectlError("HPA cleanup receipt read was interrupted")
        raise RuntimeError("HPA cleanup receipt could not be read")
    try:
        value = _strict_json(logs.stdout.strip())
    except (ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("HPA cleanup receipt is invalid") from exc
    return _decode_hpa_receipt(value, phase="clear", nonce=str(config["nonce"]))


def _wait_for_cleanup_receipt(
    config: Mapping[str, str | list[str]], timeout: float
) -> tuple[str, dict[str, Any]]:
    """Create/reuse the one-shot cleanup Job and read its durable receipt."""

    name = _cleanup_job_name(str(config["nonce"]))
    existing = _retry_transient(lambda: _get_named_job(config, name, timeout))
    if existing is None:
        created = _kubectl(
            ["create", "-f", "-"],
            timeout=timeout,
            input_text=json.dumps(_cleanup_job_manifest(config), separators=(",", ":")),
        )
        if created.returncode != 0 and "alreadyexists" not in created.stderr.lower():
            raise RuntimeError("HPA cleanup Job could not be created")
    deadline = time.monotonic() + min(timeout, 60.0)
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        poll_timeout = max(0.1, min(10.0, remaining))

        def read_cleanup_job(request_timeout: float = poll_timeout) -> Mapping[str, Any] | None:
            return _get_named_job(config, name, request_timeout)

        cleanup_job = _retry_transient(read_cleanup_job)
        if cleanup_job is None:
            raise RuntimeError("HPA cleanup Job disappeared before receipt")
        _validate_job(cleanup_job, config, name=name, phase="cleanup")
        status = cleanup_job.get("status")
        status_map = status if isinstance(status, Mapping) else {}
        if status_map.get("failed", 0) > 0:
            raise RuntimeError("HPA cleanup Job failed")
        if status_map.get("succeeded") == 1:
            try:
                return str(cleanup_job["metadata"]["uid"]), _cleanup_pod_receipt(
                    config, cleanup_job, max(0.1, min(10.0, remaining))
                )
            except _TransientKubectlError:
                pass
        time.sleep(min(0.25, max(0.05, remaining)))
    raise RuntimeError("HPA cleanup receipt was not observed before its deadline")


def _clear(config: Mapping[str, str | list[str]], timeout: float) -> dict[str, Any]:
    _retry_transient(lambda: _whoami(timeout, str(config["subject"])))
    actual_fingerprint = _retry_transient(lambda: _cluster_fingerprint(timeout))
    if actual_fingerprint != config["fingerprint"]:
        raise RuntimeError("driver API server fingerprint does not match the gate")
    existing = _retry_transient(lambda: _get_job(config, timeout))
    load_uid: str | None = None
    load_labels = _labels(config)
    if existing is not None:
        load_uid, load_labels = _validate_job(existing, config)

    # Cleanup is a separate immutable Job.  Its Pod stays available until the
    # receipt is validated, and only then are the cleanup and load Jobs
    # removed.  The load probe's SIGTERM handler remains an idempotent safety
    # net for deletion races and node termination.
    cleanup_uid, cleanup_receipt = _wait_for_cleanup_receipt(config, timeout)
    _delete_named_job(config, _cleanup_job_name(str(config["nonce"])), cleanup_uid, timeout)
    if load_uid is not None:
        _delete_named_job(config, _job_name(str(config["nonce"])), load_uid, timeout)

    return {
        "schema_version": 1,
        "status": "pass",
        "phase": "clear",
        "namespace": config["namespace"],
        "target_namespace": config["namespace"],
        "job_namespace": config.get("job_namespace", config["namespace"]),
        "run_nonce": config["nonce"],
        "cluster_fingerprint": actual_fingerprint,
        "job_name": _job_name(str(config["nonce"])),
        "job_uid": load_uid,
        "job_labels": load_labels,
        "cleanup_job_name": _cleanup_job_name(str(config["nonce"])),
        "cleanup_job_uid": cleanup_uid,
        "cleanup_receipt": cleanup_receipt,
        "residual": cleanup_receipt["residual"],
        "api_observed": True,
        "job_deleted": True,
        "already_absent": load_uid is None,
    }


def _hpa_probe_tenant(nonce: str) -> str:
    return f"{HPA_PROBE_TENANT_PREFIX}{nonce}"


def _decode_hpa_receipt(value: Any, *, phase: str, nonce: str) -> dict[str, Any]:
    """Validate the opaque JSONB receipt returned by the database boundary."""

    if phase not in {"prepare", "clear"}:
        raise ValueError("HPA probe receipt phase is invalid")
    if isinstance(value, str):
        try:
            value = _strict_json(value)
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("HPA probe database receipt is invalid") from exc
    if not isinstance(value, Mapping):
        raise RuntimeError("HPA probe database receipt is not an object")
    receipt = dict(value)
    if (
        receipt.get("schema_version") != 1
        or receipt.get("status") != "pass"
        or receipt.get("phase") != phase
        or receipt.get("run_nonce") != nonce
        or receipt.get("tenant_id") != _hpa_probe_tenant(nonce)
    ):
        raise RuntimeError("HPA probe database receipt is not nonce-bound")
    if phase == "prepare":
        seeded_rows = receipt.get("seeded_rows")
        if isinstance(seeded_rows, bool) or not isinstance(seeded_rows, int) or seeded_rows < 1:
            raise RuntimeError("HPA probe database receipt has invalid seeded row count")
        # Keep the image boundary closed: database JSONB may gain diagnostic
        # fields over time, but only this fixed receipt contract is emitted to
        # the caller or copied into runtime evidence.
        return {
            "schema_version": 1,
            "status": "pass",
            "phase": "prepare",
            "run_nonce": nonce,
            "tenant_id": _hpa_probe_tenant(nonce),
            "seeded_rows": seeded_rows,
        }
    else:
        deleted = receipt.get("deleted")
        residual = receipt.get("residual")
        if (
            not isinstance(deleted, Mapping)
            or set(deleted) != set(_HPA_PROBE_CLEANUP_TABLES)
            or not isinstance(residual, Mapping)
            or set(residual) != set(_HPA_PROBE_CLEANUP_TABLES)
            or not isinstance(receipt.get("already_absent"), bool)
        ):
            raise RuntimeError("HPA probe cleanup receipt is incomplete")
        for table in _HPA_PROBE_CLEANUP_TABLES:
            deleted_count = deleted.get(table)
            count = residual.get(table)
            if (
                isinstance(deleted_count, bool)
                or not isinstance(deleted_count, int)
                or deleted_count < 0
            ):
                raise RuntimeError("HPA probe cleanup receipt has invalid deleted row count")
            if isinstance(count, bool) or not isinstance(count, int) or count != 0:
                raise RuntimeError("HPA probe cleanup left residual rows")
        return {
            "schema_version": 1,
            "status": "pass",
            "phase": "clear",
            "run_nonce": nonce,
            "tenant_id": _hpa_probe_tenant(nonce),
            "already_absent": receipt["already_absent"],
            "deleted": {table: deleted[table] for table in _HPA_PROBE_CLEANUP_TABLES},
            "residual": {table: residual[table] for table in _HPA_PROBE_CLEANUP_TABLES},
        }


async def _hpa_probe_prepare(connection: Any, nonce: str) -> dict[str, Any]:
    """Create a bounded fixture through the versioned SQL API only."""

    value = await connection.fetchval(_HPA_PREPARE_QUERY, nonce, HPA_PROBE_ROWS)
    return _decode_hpa_receipt(value, phase="prepare", nonce=nonce)


async def _hpa_probe_seed(connection: Any, nonce: str) -> int:
    """Compatibility wrapper returning the number seeded by the DB function."""

    return int((await _hpa_probe_prepare(connection, nonce))["seeded_rows"])


async def _hpa_probe_cleanup(connection: Any, nonce: str) -> dict[str, Any]:
    """Request the complete nonce-scoped cleanup receipt from PostgreSQL."""

    if NONCE_RE.fullmatch(nonce) is None:
        raise ValueError("HPA probe run nonce is invalid")
    value = await connection.fetchval(_HPA_CLEANUP_QUERY, nonce)
    return _decode_hpa_receipt(value, phase="clear", nonce=nonce)


async def _hpa_probe_async(nonce: str) -> None:
    """Seed rows, remain live for HPA observation, and clean up on SIGTERM."""

    import asyncpg

    database_dsn = os.getenv(HPA_DATABASE_DSN_ENV, "").strip()
    if not database_dsn:
        raise ValueError(f"{HPA_DATABASE_DSN_ENV} is required")
    database_dsn = database_dsn.replace("postgresql+asyncpg://", "postgresql://", 1)
    connection = await asyncpg.connect(
        database_dsn,
        timeout=10,
        command_timeout=20,
        server_settings={"application_name": "trpc-hpa-bounded-backlog"},
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for event in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(event, stop.set)
        except (NotImplementedError, RuntimeError):
            # The production image runs on Linux; this keeps direct Windows
            # invocation/test collection portable.
            pass
    try:
        async with connection.transaction():
            # The versioned function atomically removes any stale fixture
            # for this nonce and creates the new one.  Python never receives
            # table privileges or embeds tenant-derived SQL.
            await _hpa_probe_prepare(connection, nonce)
        await stop.wait()
    finally:
        try:
            async with connection.transaction():
                receipt = await _hpa_probe_cleanup(connection, nonce)
            sys.stdout.write(json.dumps(receipt, separators=(",", ":"), sort_keys=True) + "\n")
            sys.stdout.flush()
        finally:
            await connection.close()


def _run_hpa_probe() -> int:
    """Run the in-image process used by the bounded HPA trigger Job."""

    nonce = os.getenv("TRPC_HPA_RUN_NONCE", "").strip().lower()
    if NONCE_RE.fullmatch(nonce) is None:
        raise ValueError("HPA probe run nonce is invalid")
    if os.getenv(HPA_PHASE_ENV, "").strip().lower() != "load":
        raise ValueError("HPA probe must run with load phase")
    try:
        asyncio.run(_hpa_probe_async(nonce))
    except (asyncio.CancelledError, KeyboardInterrupt):
        raise
    except Exception as exc:
        # Never include a DSN or driver/database error text in a Job log or
        # gate report; retain only the exception class for diagnosis.
        raise RuntimeError(f"bounded HPA backlog probe failed ({type(exc).__name__})") from exc
    return 0


async def _hpa_cleanup_async(nonce: str) -> None:
    """Run the one-shot cleanup command used by the cleanup Job."""

    import asyncpg

    database_dsn = os.getenv(HPA_DATABASE_DSN_ENV, "").strip()
    if not database_dsn:
        raise ValueError(f"{HPA_DATABASE_DSN_ENV} is required")
    database_dsn = database_dsn.replace("postgresql+asyncpg://", "postgresql://", 1)
    connection = await asyncpg.connect(
        database_dsn,
        timeout=10,
        command_timeout=20,
        server_settings={"application_name": "trpc-hpa-bounded-cleanup"},
    )
    try:
        async with connection.transaction():
            receipt = await _hpa_probe_cleanup(connection, nonce)
        sys.stdout.write(json.dumps(receipt, separators=(",", ":"), sort_keys=True) + "\n")
        sys.stdout.flush()
    finally:
        await connection.close()


def _run_hpa_cleanup() -> int:
    """Run the in-image one-shot cleanup process."""

    nonce = os.getenv("TRPC_HPA_RUN_NONCE", "").strip().lower()
    if NONCE_RE.fullmatch(nonce) is None:
        raise ValueError("HPA cleanup run nonce is invalid")
    if os.getenv(HPA_PHASE_ENV, "").strip().lower() != "clear":
        raise ValueError("HPA cleanup must run with clear phase")
    try:
        asyncio.run(_hpa_cleanup_async(nonce))
    except (asyncio.CancelledError, KeyboardInterrupt):
        raise
    except Exception as exc:
        raise RuntimeError(f"bounded HPA cleanup failed ({type(exc).__name__})") from exc
    return 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == HPA_PROBE_ARGUMENT:
        try:
            return _run_hpa_probe()
        except (RuntimeError, ValueError, OSError) as exc:
            # The probe is normally long-running and emits no JSON.  Keep
            # failures terse and secret-free for Kubernetes Job diagnostics.
            sys.stderr.write(f"{type(exc).__name__}: {exc}\n")
            return 1
    if len(sys.argv) == 2 and sys.argv[1] == HPA_CLEANUP_ARGUMENT:
        try:
            return _run_hpa_cleanup()
        except (RuntimeError, ValueError, OSError) as exc:
            sys.stderr.write(f"{type(exc).__name__}: {exc}\n")
            return 1
    try:
        config = _configuration()
        timeout = _timeout()
        result = _load(config, timeout) if config["phase"] == "load" else _clear(config, timeout)
        return _emit(result)
    except (RuntimeError, ValueError, OSError) as exc:
        return _emit(_error(str(exc)))


if __name__ == "__main__":
    raise SystemExit(main())
