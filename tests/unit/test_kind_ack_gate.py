from __future__ import annotations

import json
import shutil
import subprocess
import threading
import time
from argparse import Namespace
from pathlib import Path
from typing import Any, NoReturn

import pytest

import scripts.kind_ack_gate as gate


def _runtime_probe_payload(source: str = "b" * 64) -> dict[str, Any]:
    reconciliation_checks = {
        "applied_query_only": {
            "status": "pass",
            "evidence_rows": 1,
            "provider_execution_delta": 1,
            "provider_execute_calls": 1,
            "status_queries": 1,
        },
        "unknown_blocks_replay": {"status": "pass"},
        "stale_attempt_rejected": {"status": "pass"},
        "cross_tenant_evidence_rejected": {"status": "pass"},
        "claim_cas_rejected": {"status": "pass"},
    }
    return {
        "schema_version": 1,
        "probe": "kind_runtime_probe",
        "scenario": "kind_runtime_postgres_reconciliation",
        "assertion": gate.SCENARIO_PLAN["candidate_runtime_probe"]["assertion"],
        "source_fingerprint": source,
        "command": "all",
        "status": "pass",
        "checks": {
            "tool_reconciliation": {"status": "pass", "checks": reconciliation_checks},
            "im_idempotency": {
                "status": "pass",
                "duplicate_callbacks": 100,
                "first_acceptances": 1,
                "duplicate_results": 99,
                "primary_inbound_ids": 1,
                "primary_session_ids": 1,
                "primary_rows": {"inbound": 1, "audit": 1, "outbox": 1, "mailbox": 1},
                "secondary_same_message_accepted": True,
                "secondary_rows": {"inbound": 1, "audit": 1, "outbox": 1, "mailbox": 1},
                "tenant_sha256": "c" * 64,
                "secondary_tenant_sha256": "d" * 64,
            },
        },
        "provider_execute_calls": 1,
        "provider_status_queries": 1,
        "rejection_reasons": [],
        "token": "x",
    }


def _im_probe_payload(source: str = "b" * 64) -> dict[str, Any]:
    tenant_counts = {
        "inbound": 1,
        "accepted_audit": 1,
        "mailboxes": 1,
        "mailbox_items": 1,
        "ready_events": 1,
        "session_digest": "c" * 64,
    }
    return {
        "schema_version": 1,
        "probe": "kind_im_gateway_probe",
        "scenario": "real_feishu_gateway_postgres_idempotency",
        "assertion": gate.SCENARIO_PLAN["candidate_im_gateway_probe"]["assertion"],
        "source_fingerprint": source,
        "status": "pass",
        "checks": {
            "duplicate_callbacks": {"status": "pass"},
            "tenant_isolation": {"status": "pass"},
            "signature_rejection": {"status": "pass"},
        },
        "callbacks_sent": 102,
        "duplicate_callback_status_counts": {"200": 100},
        "second_tenant_status": 200,
        "invalid_signature_status": 403,
        "tenant_a": tenant_counts,
        "tenant_b": {**tenant_counts, "session_digest": "d" * 64},
        "rejection_reasons": [],
        "secrets_reported": False,
    }


def _evolution_probe_payload(source: str = "b" * 64) -> dict[str, Any]:
    cases = [
        {"name": "database_identity_and_schema", "passed": True},
        {
            "name": "concurrent_cas",
            "passed": True,
            "winner_count": 1,
            "conflict_count": 1,
            "durable_certificate_uses": 1,
            "durable_approval_uses": 1,
        },
        {
            "name": "certificate_approval_one_time",
            "passed": True,
            "duplicate_certificate_rejected": True,
            "duplicate_approval_rejected": True,
            "authority_duplicate_rejected": True,
        },
        {
            "name": "outbox_lease_takeover",
            "passed": True,
            "stale_ack_before_expiry": False,
            "stale_ack_after_takeover": False,
            "acknowledged": True,
            "duplicate_ack": False,
            "lease_epochs": [1, 2, 3],
        },
        {
            "name": "receipt_rollback",
            "passed": True,
            "rollback_version": 2,
            "duplicate_rollback_rejected": True,
            "tampered_receipt_rejected": True,
        },
        {
            "name": "stale_aba_rejection",
            "passed": True,
            "stale_cas_rejected": True,
            "stale_certificate_rejected": True,
            "final_control_version": 2,
        },
        {
            "name": "cross_tenant_rejection",
            "passed": True,
            "store_scope_rejected": True,
            "certificate_scope_rejected": True,
        },
    ]
    check_names = gate._CANDIDATE_PROBE_CONTRACTS["scripts/kind_evolution_probe.py"]["checks"]
    return {
        "schema_version": 1,
        "probe": "kind_evolution_postgres",
        "scenario": "kind_evolution_postgres_control",
        "assertion": gate.SCENARIO_PLAN["candidate_evolution_probe"]["assertion"],
        "source_fingerprint": source,
        "status": "pass",
        "checks": {name: {"status": "pass"} for name in check_names},
        "provider_calls": 0,
        "rejection_reasons": [],
        "database": {"role_verified": True, "required_tables": True},
        "fixture": {"status": "pass", "role": "trpc_worker", "capsule_count": 2},
        "cases": cases,
    }


def _redis_probe_payload(source: str = "b" * 64) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "probe": "kind_redis_probe",
        "scenario": "publish_idempotency_pel_takeover",
        "assertion": gate.SCENARIO_PLAN["candidate_redis_probe"]["assertion"],
        "source_fingerprint": {"status": "available", "value": source},
        "status": "pass",
        "checks": {
            "publish_once": {
                "status": "pass",
                "first_publish": True,
                "duplicate_suppressed": True,
                "stream_entries": 1,
            },
            "consumer_a_pel": {"status": "pass", "delivered": 1, "pending": 1},
            "consumer_b_takeover": {"status": "pass", "reclaimed": 1},
            "stale_owner_defer_rejected": {"status": "pass", "accepted": False},
            "consumer_b_ack_pel_empty": {"status": "pass", "pending": 0},
            "cleanup": {"status": "pass"},
        },
        "rejection_reasons": [],
    }


def _placement_payload(pod_name: str, script: str, *, cross_node: bool = True) -> str:
    driver_node = "worker-a"
    remote_node = "worker-b" if cross_node else driver_node
    items: list[dict[str, Any]] = [
        {
            "metadata": {
                "name": pod_name,
                "labels": {"app.kubernetes.io/name": "kind-acceptance-driver"},
            },
            "spec": {"nodeName": driver_node},
        }
    ]
    for workload in gate._PROBE_REMOTE_WORKLOADS[script]:
        items.append(
            {
                "metadata": {
                    "name": f"{workload}-0",
                    "labels": {"app.kubernetes.io/name": workload},
                },
                "spec": {"nodeName": remote_node},
            }
        )
    return json.dumps({"items": items})


def test_run_tolerates_missing_subprocess_streams(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Completed:
        returncode = 1
        stdout = None
        stderr = None

    monkeypatch.setattr(shutil, "which", lambda _name: "kind")
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: Completed())

    result = gate._run(["kind", "version"])

    assert result.status == "fail"
    assert result.stdout == ""
    assert result.stderr == ""


def test_image_identity_extracts_registry_digest_without_credentials() -> None:
    value = gate._image_identity("docker.io/acme/trpc-agent-service@sha256:" + "a" * 64)

    assert value == {
        "reference": "docker.io/acme/trpc-agent-service@sha256:" + "a" * 64,
        "registry": "docker.io",
        "digest": "sha256:" + "a" * 64,
        "immutable": True,
        "source": "registry",
        "shape_valid": True,
    }
    assert "password" not in repr(value).lower()


def test_execute_requires_immutable_or_explicit_local_load() -> None:
    assert (
        gate._image_contract(
            "docker.io/acme/trpc-agent-service:dev",
            execute=False,
            load_image=False,
        )[0]
        == "not_run"
    )
    status, reasons = gate._image_contract(
        "docker.io/acme/trpc-agent-service:dev",
        execute=True,
        load_image=False,
    )
    assert status == "fail"
    assert "digest" in " ".join(reasons)
    assert (
        gate._image_contract(
            "trpc-agent-service:dev",
            execute=True,
            load_image=True,
        )[0]
        == "pass"
    )


def test_load_image_rejects_source_fingerprint_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "sha256:" + "a" * 64
    monkeypatch.setattr(gate, "_docker_image_metadata", lambda _image: (digest, "b" * 64, None))
    monkeypatch.setattr(
        gate,
        "_source_lineage",
        lambda: {"status": "available", "value": "c" * 64},
    )

    status, observed_digest, reason = gate._load_local_image("kind-test", "candidate:tag")

    assert status == "fail"
    assert observed_digest is None
    assert reason == "local image source fingerprint does not match current checkout"


def test_load_image_requires_matching_source_fingerprint_before_kind_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "sha256:" + "a" * 64
    fingerprint = "b" * 64
    invoked: list[list[str]] = []
    monkeypatch.setattr(gate, "_docker_image_metadata", lambda _image: (digest, fingerprint, None))
    monkeypatch.setattr(
        gate,
        "_source_lineage",
        lambda: {"status": "available", "value": fingerprint},
    )

    def fake_run(argv: list[str], **_kwargs: object) -> gate.CommandResult:
        invoked.append(argv)
        return gate.CommandResult("pass")

    monkeypatch.setattr(
        gate,
        "_run",
        fake_run,
    )

    status, observed_digest, reason = gate._load_local_image("kind-test", "candidate:tag")

    assert status == "pass"
    assert observed_digest == digest
    assert reason is None
    assert invoked == [["kind", "load", "docker-image", "candidate:tag", "--name", "kind-test"]]


def test_topology_contract_requires_one_control_plane_and_three_workers() -> None:
    status, reasons, topology = gate._topology_contract()

    assert status == "pass"
    assert reasons == ()
    assert topology["counts"] == {"control-plane": 1, "worker": 3}


def test_live_node_contract_accepts_exact_one_plus_three_topology(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nodes = {
        "items": [
            {"metadata": {"labels": {"node-role.kubernetes.io/control-plane": ""}}},
            {"metadata": {"labels": {"trpc.io/node-role": "agent-worker"}}},
            {"metadata": {"labels": {"trpc.io/node-role": "agent-worker"}}},
            {"metadata": {"labels": {"trpc.io/node-role": "agent-worker"}}},
        ]
    }
    monkeypatch.setattr(
        gate,
        "_kubectl",
        lambda *_args, **_kwargs: gate.CommandResult(
            "pass", stdout=__import__("json").dumps(nodes)
        ),
    )

    counts, reason = gate._cluster_node_contract("kind-test")

    assert counts == {"control_plane": 1, "workers": 3, "total": 4}
    assert reason is None


def _kind_node(name: str, role: str, pool: str | None = None) -> dict[str, Any]:
    labels = {gate.KIND_NODE_ROLE_LABEL: role}
    if role == "control-plane":
        labels["node-role.kubernetes.io/control-plane"] = ""
    if pool is not None:
        labels[gate.KIND_POOL_LABEL] = pool
    return {"metadata": {"name": name, "labels": labels}}


def test_kind_node_pool_contract_labels_sorted_workers_with_explicit_overwrite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nodes = {
        "items": [
            _kind_node("kind-demo-control-plane", "control-plane"),
            _kind_node("worker-z", "agent-worker", "support"),
            _kind_node("worker-a", "agent-worker", "legacy"),
            _kind_node("worker-m", "agent-worker"),
        ]
    }
    label_calls: list[list[str]] = []

    def fake_kubectl(_context: str, arguments: list[str], **_kwargs: object) -> gate.CommandResult:
        if arguments == ["get", "nodes", "-o", "json"]:
            return gate.CommandResult("pass", stdout=json.dumps(nodes))
        assert arguments[:2] == ["label", "node"]
        assert arguments[-1] == "--overwrite"
        node_name = arguments[2]
        label_key, pool = arguments[3].split("=", 1)
        assert label_key == gate.KIND_POOL_LABEL
        label_calls.append(arguments.copy())
        for item in nodes["items"]:
            if item["metadata"]["name"] == node_name:
                item["metadata"]["labels"][label_key] = pool
                break
        else:
            raise AssertionError(f"unknown node {node_name}")
        return gate.CommandResult("pass")

    monkeypatch.setattr(gate, "_kubectl", fake_kubectl)

    status, evidence, reason = gate._kind_node_pool_contract("kind-demo", "demo", execute=True)

    assert status == "pass"
    assert reason is None
    assert evidence["worker_nodes"] == ["worker-a", "worker-m", "worker-z"]
    assert evidence["worker_pools"] == {
        "worker-a": "gateway",
        "worker-m": "gateway",
        "worker-z": "support",
    }
    assert label_calls == [
        ["label", "node", "worker-a", "trpc.io/kind-pool=gateway", "--overwrite"],
        ["label", "node", "worker-m", "trpc.io/kind-pool=gateway", "--overwrite"],
        ["label", "node", "worker-z", "trpc.io/kind-pool=support", "--overwrite"],
    ]


@pytest.mark.parametrize(
    ("execute", "context", "expected_status"),
    [
        (False, "kind-demo", "not_run"),
        (True, "kind-other", "fail"),
    ],
)
def test_kind_node_pool_contract_is_scoped_to_execute_and_exact_context(
    monkeypatch: pytest.MonkeyPatch,
    execute: bool,
    context: str,
    expected_status: str,
) -> None:
    calls: list[list[str]] = []

    def fail_if_called(_context: str, arguments: list[str], **_kwargs: object) -> NoReturn:
        calls.append(arguments)
        raise AssertionError("node labeling must not run outside exact execute scope")

    monkeypatch.setattr(gate, "_kubectl", fail_if_called)

    status, evidence, reason = gate._kind_node_pool_contract(context, "demo", execute=execute)

    assert status == expected_status
    assert evidence == {}
    assert reason is not None
    assert calls == []


@pytest.mark.parametrize(
    ("nodes", "expected_reason"),
    [
        (
            {
                "items": [
                    _kind_node("kind-demo-control-plane", "control-plane"),
                    _kind_node("worker-a", "agent-worker"),
                    _kind_node("worker-b", "agent-worker"),
                ]
            },
            "exactly one control-plane and three workers",
        ),
        (
            {
                "items": [
                    _kind_node("kind-demo-control-plane", "control-plane", "gateway"),
                    _kind_node("worker-a", "agent-worker"),
                    _kind_node("worker-b", "agent-worker"),
                    _kind_node("worker-c", "agent-worker"),
                ]
            },
            "control-plane must not carry a worker pool label",
        ),
    ],
)
def test_kind_node_pool_contract_fails_closed_before_labeling_invalid_inventory(
    monkeypatch: pytest.MonkeyPatch,
    nodes: dict[str, Any],
    expected_reason: str,
) -> None:
    label_calls: list[list[str]] = []

    def fake_kubectl(_context: str, arguments: list[str], **_kwargs: object) -> gate.CommandResult:
        if arguments == ["get", "nodes", "-o", "json"]:
            return gate.CommandResult("pass", stdout=json.dumps(nodes))
        label_calls.append(arguments)
        return gate.CommandResult("pass")

    monkeypatch.setattr(gate, "_kubectl", fake_kubectl)

    status, evidence, reason = gate._kind_node_pool_contract("kind-demo", "demo", execute=True)

    assert status == "fail"
    assert reason is not None and expected_reason in reason
    assert evidence["worker_nodes"] in (
        ["worker-a", "worker-b"],
        ["worker-a", "worker-b", "worker-c"],
    )
    assert label_calls == []


def test_execute_reports_node_pool_failure_and_does_not_run_workloads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    render_output = tmp_path / "rendered.yaml"
    render_output.write_text("apiVersion: v1\nkind: List\n", encoding="utf-8")
    monkeypatch.setattr(gate, "_kind_cluster_exists", lambda _name: (True, None))
    monkeypatch.setattr(gate, "_cluster_uid", lambda _context: ("cluster-uid", None))
    monkeypatch.setattr(
        gate,
        "_cluster_node_contract",
        lambda _context: ({"control_plane": 1, "workers": 3, "total": 4}, None),
    )
    monkeypatch.setattr(
        gate,
        "_kind_node_pool_contract",
        lambda *_args, **_kwargs: (
            "fail",
            {"expected_pools": {"worker-a": "gateway"}},
            "worker node pool labels did not match the deterministic assignment",
        ),
    )
    monkeypatch.setattr(gate, "_render", lambda *_args: (gate.CommandResult("pass"), []))

    result = gate._execute(
        cluster_name="demo",
        context="kind-demo",
        namespace="trpc-cell-kind",
        image="docker.io/example/trpc-agent-service:kind",
        load_image=False,
        render_output=render_output,
        preflight={},
        timeout=5,
    )

    assert result["status"] == "fail"
    assert result["node_pools"]["status"] == "fail"
    assert result["node_pools"]["evidence"] == {"expected_pools": {"worker-a": "gateway"}}
    assert any(
        "worker node pool labels did not match" in reason for reason in result["rejection_reasons"]
    )
    assert result["workload_distribution"] == {"status": "not_run"}
    assert result["scenarios"] == {}


def test_manifest_inventory_requires_app_and_support_objects() -> None:
    documents = [
        {"kind": "Deployment", "metadata": {"name": "trpc-worker"}, "spec": {"replicas": 3}},
        {"kind": "Service", "metadata": {"name": "kind-fake-im"}},
    ]

    inventory = gate._manifest_inventory(documents)

    assert "trpc-gateway" in inventory["missing_deployments"]
    assert "StatefulSet/kind-postgres" in inventory["missing_objects"]


def test_runtime_readiness_checks_run_as_one_concurrent_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    documents = [
        {"kind": "Deployment", "metadata": {"name": "trpc-gateway"}, "spec": {"replicas": 1}},
        {"kind": "Deployment", "metadata": {"name": "trpc-worker"}, "spec": {"replicas": 1}},
        {"kind": "StatefulSet", "metadata": {"name": "kind-postgres"}, "spec": {"replicas": 1}},
        {"kind": "Job", "metadata": {"name": "trpc-schema-migration"}},
    ]
    targets = gate._runtime_wait_targets(documents)
    active = 0
    max_active = 0
    calls: list[tuple[str, tuple[str, str] | tuple[tuple[str, str], ...]]] = []
    lock = threading.Lock()

    def fake_wait(
        _context: str, _namespace: str, target: tuple[str, str], _timeout: float
    ) -> gate.CommandResult:
        nonlocal active, max_active
        with lock:
            active += 1
            max_active = max(max_active, active)
            calls.append(("wait", target))
        time.sleep(0.01)
        with lock:
            active -= 1
        return gate.CommandResult("pass")

    def fake_restart(
        _context: str, _namespace: str, application_targets: tuple[tuple[str, str], ...]
    ) -> gate.CommandResult:
        calls.append(("restart", application_targets))
        return gate.CommandResult("pass")

    monkeypatch.setattr(gate, "_wait_for_runtime_target", fake_wait)
    monkeypatch.setattr(gate, "_restart_application_deployments", fake_restart)

    status, reasons = gate._wait_for_runtime("kind-test", "trpc-cell-kind", documents, 5)

    assert status == "pass"
    assert reasons == ()
    assert len([event for event in calls if event[0] == "wait"]) == len(targets)
    assert max_active >= 2
    restart_index = next(index for index, event in enumerate(calls) if event[0] == "restart")
    assert all(event[1][0] != "Deployment" for event in calls[:restart_index] if event[0] == "wait")
    assert all(
        event[1][0] == "Deployment" for event in calls[restart_index + 1 :] if event[0] == "wait"
    )


def test_candidate_probe_manifest_is_keyless_and_hardened() -> None:
    manifest = gate._candidate_probe_manifest(
        pod_name="kind-gate-candidate-evolution-0123456789",
        namespace="trpc-cell-kind",
        image="docker.io/example/trpc-agent-service@sha256:" + "a" * 64,
        script="scripts/kind_evolution_probe.py",
        script_args=("--execute", "--json"),
    )
    container = manifest["spec"]["containers"][0]
    env = {item["name"]: item.get("value") for item in container["env"]}
    env_from = {next(iter(item.values()))["name"] for item in container["envFrom"]}

    assert container["command"] == ["python"]
    assert container["args"] == ["scripts/kind_evolution_probe.py", "--execute", "--json"]
    assert env_from == {
        "trpc-service-config",
        "trpc-worker-secrets",
        "trpc-evolution-authority-secrets",
    }
    assert "trpc-tool-reconciler-secrets" not in env_from
    assert "trpc-redis-probe-secrets" not in env_from
    assert "TRPC_KIND_PROBE_CLEANUP_DSN" not in env
    assert "TRPC_KIND_PROVIDER_STATUS_URL" not in env
    assert env["TRPC_EVOLUTION_PROBE_TENANT_ID"].endswith("-0123456789")
    assert "TRPC_EVOLUTION_PROBE_SOURCE_CAPSULE_DIGEST" not in env
    assert "TRPC_EVOLUTION_PROBE_CANDIDATE_CAPSULE_DIGEST" not in env
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }


@pytest.mark.parametrize(
    ("script", "expected_secrets", "remote_workloads"),
    [
        (
            "scripts/kind_im_gateway_probe.py",
            {"trpc-service-secrets"},
            {"trpc-gateway"},
        ),
        (
            "scripts/kind_runtime_probe.py",
            {
                "trpc-service-secrets",
                "trpc-worker-secrets",
                "trpc-tool-reconciler-secrets",
            },
            {"kind-postgres", "kind-fake-provider"},
        ),
        (
            "scripts/kind_evolution_probe.py",
            {"trpc-worker-secrets", "trpc-evolution-authority-secrets"},
            {"kind-postgres"},
        ),
        (
            "scripts/kind_redis_probe.py",
            {"trpc-redis-probe-secrets"},
            {"kind-redis"},
        ),
    ],
)
def test_candidate_probe_manifest_uses_least_privilege_and_cross_node_affinity(
    script: str, expected_secrets: set[str], remote_workloads: set[str]
) -> None:
    manifest = gate._candidate_probe_manifest(
        pod_name="kind-gate-probe-0123456789",
        namespace="trpc-cell-kind",
        image="candidate:local",
        script=script,
        script_args=(),
    )
    container = manifest["spec"]["containers"][0]
    secret_names = {
        item["secretRef"]["name"] for item in container["envFrom"] if "secretRef" in item
    }
    terms = manifest["spec"]["affinity"]["podAntiAffinity"][
        "requiredDuringSchedulingIgnoredDuringExecution"
    ]
    selected = {term["labelSelector"]["matchLabels"]["app.kubernetes.io/name"] for term in terms}

    assert secret_names == expected_secrets
    assert selected == remote_workloads
    assert manifest["spec"]["nodeSelector"] == {"trpc.io/node-role": "agent-worker"}


def test_failed_candidate_probe_returns_without_waiting_for_success_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gate,
        "_kubectl",
        lambda *_args, **_kwargs: gate.CommandResult(
            "pass", stdout='{"status":{"phase":"Failed"}}'
        ),
    )

    result = gate._wait_for_candidate_pod("kind-test", "trpc-cell-kind", "probe", 180)

    assert result.status == "fail"
    assert result.reason == "candidate probe Pod reported Failed"


def test_candidate_probe_collects_last_json_line_and_cleans_exact_pod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    applied_manifest: dict[str, Any] = {}
    payload = _runtime_probe_payload()
    monkeypatch.setattr(
        gate,
        "_source_lineage",
        lambda: {"status": "available", "value": payload["source_fingerprint"]},
    )

    def fake_kubectl(
        _context: str, arguments: list[str], *, input_text: str | None = None, **_kwargs: object
    ) -> gate.CommandResult:
        nonlocal applied_manifest
        calls.append(arguments)
        if arguments[:2] == ["apply", "-f"]:
            assert input_text is not None
            applied_manifest = json.loads(input_text)
            return gate.CommandResult("pass")
        if "get" in arguments and "pod/" in " ".join(arguments):
            return gate.CommandResult("pass", stdout='{"status":{"phase":"Succeeded"}}')
        if arguments[2:4] == ["get", "pods"]:
            return gate.CommandResult(
                "pass",
                stdout=_placement_payload(
                    applied_manifest["metadata"]["name"], "scripts/kind_runtime_probe.py"
                ),
            )
        if arguments[2:4] == ["logs", "pod/kind-gate-runtime-0123456789"]:
            return gate.CommandResult("pass", stdout="noise\n" + json.dumps(payload) + "\n")
        if arguments[2:4] == ["delete", "pod"]:
            return gate.CommandResult("pass")
        if "logs" in arguments:
            return gate.CommandResult("pass", stdout="noise\n" + json.dumps(payload) + "\n")
        return gate.CommandResult("fail", reason="unexpected kubectl call")

    monkeypatch.setattr(gate, "_kubectl", fake_kubectl)
    status, evidence, reason = gate._run_candidate_probe(
        "kind-test",
        "trpc-cell-kind",
        "docker.io/example/trpc-agent-service:kind",
        "candidate-runtime",
        "scripts/kind_runtime_probe.py",
        ("all", "--json", "--keep-fixtures"),
    )

    assert status == "pass"
    assert reason is None
    assert evidence["pod_cleanup"]["status"] is True
    assert evidence["probe"]["status"] == "pass"
    assert evidence["probe"]["token"] == "<redacted>"
    assert evidence["probe_contract"] == {"status": "pass", "reason": None}
    delete_calls = [call for call in calls if "delete" in call]
    assert len(delete_calls) == 1
    deleted_name = delete_calls[0][delete_calls[0].index("pod") + 1]
    assert deleted_name == applied_manifest["metadata"]["name"]


def test_failed_candidate_probe_collects_redacted_log_and_placement_before_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    applied_manifest: dict[str, Any] = {}
    payload = _runtime_probe_payload()
    payload["token"] = "postgresql://user:super-secret@db/private"
    monkeypatch.setattr(
        gate,
        "_source_lineage",
        lambda: {"status": "available", "value": payload["source_fingerprint"]},
    )

    def fake_kubectl(
        _context: str,
        arguments: list[str],
        *,
        input_text: str | None = None,
        **_kwargs: object,
    ) -> gate.CommandResult:
        nonlocal applied_manifest
        calls.append(arguments.copy())
        if arguments[:2] == ["apply", "-f"]:
            assert input_text is not None
            applied_manifest = json.loads(input_text)
            return gate.CommandResult("pass")
        if arguments[2:4] == ["get", "pod/" + applied_manifest["metadata"]["name"]]:
            return gate.CommandResult("pass", stdout='{"status":{"phase":"Failed"}}')
        if arguments[2:4] == ["get", "pods"]:
            return gate.CommandResult(
                "pass",
                stdout=_placement_payload(
                    applied_manifest["metadata"]["name"], "scripts/kind_runtime_probe.py"
                ),
            )
        if arguments[2:4] == ["logs", "pod/" + applied_manifest["metadata"]["name"]]:
            return gate.CommandResult("pass", stdout="noise\n" + json.dumps(payload) + "\n")
        if arguments[2:4] == ["delete", "pod"]:
            return gate.CommandResult("pass")
        raise AssertionError(f"unexpected kubectl call: {arguments}")

    monkeypatch.setattr(gate, "_kubectl", fake_kubectl)
    status, evidence, reason = gate._run_candidate_probe(
        "kind-test",
        "trpc-cell-kind",
        "docker.io/example/trpc-agent-service:kind",
        "candidate-runtime",
        "scripts/kind_runtime_probe.py",
        ("all", "--json", "--keep-fixtures"),
    )

    assert status == "fail"
    assert reason == "candidate probe Pod did not complete successfully"
    assert evidence["placement"]["status"] == "pass"
    assert evidence["probe"]["status"] == "pass"
    assert evidence["probe"]["token"] == "<redacted>"
    assert "super-secret" not in json.dumps(evidence)
    placement_index = next(
        index for index, call in enumerate(calls) if call[2:4] == ["get", "pods"]
    )
    logs_index = next(
        index
        for index, call in enumerate(calls)
        if call[2:4] == ["logs", "pod/" + applied_manifest["metadata"]["name"]]
    )
    cleanup_index = next(
        index for index, call in enumerate(calls) if call[2:4] == ["delete", "pod"]
    )
    assert placement_index < cleanup_index
    assert logs_index < cleanup_index


@pytest.mark.parametrize(
    ("runner_name", "script", "script_args"),
    [
        ("candidate-im-gateway", "scripts/kind_im_gateway_probe.py", ()),
        ("candidate-runtime", "scripts/kind_runtime_probe.py", ("all", "--json")),
        ("candidate-evolution", "scripts/kind_evolution_probe.py", ("--execute", "--json")),
        ("candidate-redis", "scripts/kind_redis_probe.py", ("--json",)),
    ],
)
def test_candidate_probe_rejects_status_only_payload_for_every_script(
    monkeypatch: pytest.MonkeyPatch,
    runner_name: str,
    script: str,
    script_args: tuple[str, ...],
) -> None:
    applied_manifest: dict[str, Any] = {}
    monkeypatch.setattr(
        gate,
        "_source_lineage",
        lambda: {"status": "available", "value": "b" * 64},
    )

    def fake_kubectl(
        _context: str,
        arguments: list[str],
        *,
        input_text: str | None = None,
        **_kwargs: object,
    ) -> gate.CommandResult:
        nonlocal applied_manifest
        if arguments[:2] == ["apply", "-f"]:
            assert input_text is not None
            applied_manifest = json.loads(input_text)
            return gate.CommandResult("pass")
        if "get" in arguments and "pod/" in " ".join(arguments):
            return gate.CommandResult("pass", stdout='{"status":{"phase":"Succeeded"}}')
        if arguments[2:4] == ["get", "pods"]:
            return gate.CommandResult(
                "pass",
                stdout=_placement_payload(applied_manifest["metadata"]["name"], script),
            )
        if "logs" in arguments:
            return gate.CommandResult("pass", stdout='{"status":"pass"}\n')
        if "delete" in arguments:
            return gate.CommandResult("pass")
        return gate.CommandResult("fail", reason="unexpected kubectl call")

    monkeypatch.setattr(gate, "_kubectl", fake_kubectl)
    status, evidence, reason = gate._run_candidate_probe(
        "kind-test",
        "trpc-cell-kind",
        "docker.io/example/trpc-agent-service:kind",
        runner_name,
        script,
        script_args,
    )

    assert status == "fail"
    assert reason is not None and "result contract failed" in reason
    assert evidence["probe"] == {"status": "pass"}
    assert evidence["probe_contract"]["status"] == "fail"
    assert evidence["pod_cleanup"]["status"] is True


def test_candidate_probe_contract_requires_checkout_source_fingerprint() -> None:
    payload = _runtime_probe_payload(source="c" * 64)

    assert (
        gate._validate_candidate_probe_payload(
            "candidate-runtime",
            "scripts/kind_runtime_probe.py",
            payload,
        )
        is not None
    )


def test_candidate_probe_contract_accepts_complete_script_specific_payloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = "b" * 64
    monkeypatch.setattr(gate, "_source_lineage", lambda: {"status": "available", "value": source})

    payloads = (
        ("candidate-im-gateway", "scripts/kind_im_gateway_probe.py", _im_probe_payload(source)),
        ("candidate-runtime", "scripts/kind_runtime_probe.py", _runtime_probe_payload(source)),
        (
            "candidate-evolution",
            "scripts/kind_evolution_probe.py",
            _evolution_probe_payload(source),
        ),
        ("candidate-redis", "scripts/kind_redis_probe.py", _redis_probe_payload(source)),
    )
    for runner_name, script, payload in payloads:
        assert gate._validate_candidate_probe_payload(runner_name, script, payload) is None


@pytest.mark.parametrize("cross_node", [True, False])
def test_candidate_probe_placement_requires_actual_node_boundary(
    monkeypatch: pytest.MonkeyPatch, cross_node: bool
) -> None:
    pod_name = "kind-gate-runtime-placement"
    monkeypatch.setattr(
        gate,
        "_kubectl",
        lambda *_args, **_kwargs: gate.CommandResult(
            "pass",
            stdout=_placement_payload(
                pod_name, "scripts/kind_runtime_probe.py", cross_node=cross_node
            ),
        ),
    )

    status, evidence, reason = gate._candidate_probe_placement(
        "kind-test", "trpc-cell-kind", pod_name, "scripts/kind_runtime_probe.py"
    )

    assert status == ("pass" if cross_node else "fail")
    assert evidence["cross_node"] is cross_node
    assert (reason is None) is cross_node


def test_worker_replacement_evidence_proves_provider_counts_are_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventories = iter(({"worker-old": "uid-old"}, {"worker-new": "uid-new"}))
    metrics = iter(
        (
            {"effects": 1, "provider_calls": 1},
            {"effects": 1, "provider_calls": 1},
        )
    )
    monkeypatch.setattr(gate, "_pod_inventory", lambda *_args, **_kwargs: next(inventories))
    monkeypatch.setattr(gate, "_provider_metrics", lambda *_args, **_kwargs: next(metrics))
    monkeypatch.setattr(
        gate,
        "_kubectl",
        lambda *_args, **_kwargs: gate.CommandResult("pass"),
    )

    status, evidence, reason = gate._worker_restart_scenario("kind-test", "trpc-cell-kind")

    assert status == "pass"
    assert reason is None
    assert evidence["worker_pod_uid_changed"] is True
    assert evidence["provider_metrics_preserved"] is True
    assert evidence["provider_counts_before"] == evidence["provider_counts_after"]


@pytest.mark.parametrize(
    ("pvc_after_uid", "rows_after", "expected_status"),
    [("pvc-stable", 2, "pass"), ("pvc-replaced", 2, "fail"), ("pvc-stable", 1, "fail")],
)
def test_postgres_replacement_requires_same_pvc_and_persistent_rows(
    monkeypatch: pytest.MonkeyPatch,
    pvc_after_uid: str,
    rows_after: int,
    expected_status: str,
) -> None:
    pod_uids = iter(("pod-before", "pod-after"))
    pvc_uids = iter(("pvc-stable", pvc_after_uid))

    def fake_kubectl(_context: str, arguments: list[str], **_kwargs: object) -> gate.CommandResult:
        joined = " ".join(arguments)
        if "get pod/kind-postgres-0" in joined:
            return gate.CommandResult(
                "pass", stdout=json.dumps({"metadata": {"uid": next(pod_uids)}})
            )
        if "get pvc/data-kind-postgres-0" in joined:
            return gate.CommandResult(
                "pass", stdout=json.dumps({"metadata": {"uid": next(pvc_uids)}})
            )
        if "to_regclass" in joined:
            return gate.CommandResult("pass", stdout="t\n")
        return gate.CommandResult("pass")

    row_counts = iter(("2", str(rows_after)))
    monkeypatch.setattr(gate, "_kubectl", fake_kubectl)
    monkeypatch.setattr(gate, "_postgres_scalar", lambda *_args: next(row_counts))
    monkeypatch.setattr(
        gate, "_wait_for_runtime_target", lambda *_args, **_kwargs: gate.CommandResult("pass")
    )
    monkeypatch.setattr(gate, "_candidate_im_scenario", lambda *_args: ("pass", {}, None))

    status, evidence, reason = gate._postgres_restart_scenario(
        "kind-test", "trpc-cell-kind", "candidate:local"
    )

    assert status == expected_status
    assert evidence["pvc_preserved"] is (pvc_after_uid == "pvc-stable")
    assert evidence["persistent_rows_preserved"] is (rows_after == 2)
    assert "pvc-stable" not in json.dumps(evidence)
    assert (reason is None) is (expected_status == "pass")


@pytest.mark.parametrize(
    ("node_names", "expected_status"),
    [(["worker-1", "worker-2", "worker-3"], "pass"), (["worker-1"] * 3, "fail")],
)
def test_workload_distribution_requires_workers_on_three_nodes(
    monkeypatch: pytest.MonkeyPatch,
    node_names: list[str],
    expected_status: str,
) -> None:
    worker_items = [
        {
            "metadata": {
                "labels": {"app.kubernetes.io/name": "trpc-worker"},
            },
            "spec": {"nodeName": node_name},
        }
        for node_name in node_names
    ]
    fixed_items = [
        {
            "metadata": {"labels": {"app.kubernetes.io/name": "trpc-gateway"}},
            "spec": {"nodeName": node_name},
        }
        for node_name in ("gateway-node-a", "gateway-node-b")
    ]
    fixed_items.extend(
        {
            "metadata": {"labels": {"app.kubernetes.io/name": workload}},
            "spec": {"nodeName": "backend-node"},
        }
        for workload in ("kind-postgres", "kind-redis", "kind-fake-provider")
    )
    pods = {"items": [*worker_items, *fixed_items]}
    monkeypatch.setattr(
        gate,
        "_kubectl",
        lambda *_args, **_kwargs: gate.CommandResult("pass", stdout=json.dumps(pods)),
    )

    status, evidence, reason = gate._workload_distribution("kind-test", "trpc-cell-kind")

    assert status == expected_status
    assert evidence["worker_node_count"] == len(set(node_names))
    assert (reason is None) is (expected_status == "pass")


def test_execute_collects_failures_from_all_independent_scenarios(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    render_output = tmp_path / "rendered.yaml"
    render_output.write_text("apiVersion: v1\nkind: List\n", encoding="utf-8")
    monkeypatch.setattr(gate, "_kind_cluster_exists", lambda _name: (True, None))
    monkeypatch.setattr(gate, "_cluster_uid", lambda _context: ("cluster-uid", None))
    monkeypatch.setattr(
        gate,
        "_cluster_node_contract",
        lambda _context: ({"control_plane": 1, "workers": 3, "total": 4}, None),
    )
    monkeypatch.setattr(
        gate,
        "_kind_node_pool_contract",
        lambda *_args, **_kwargs: ("pass", {"worker_pools": {}}, None),
    )
    monkeypatch.setattr(
        gate,
        "_schema_head_contract",
        lambda *_args: (
            "pass",
            {"expected_head": gate.EXPECTED_ALEMBIC_HEAD},
            None,
        ),
    )
    monkeypatch.setattr(
        gate,
        "_render",
        lambda _image, _output: (gate.CommandResult("pass"), []),
    )
    monkeypatch.setattr(gate, "_wait_for_runtime", lambda *_args: ("pass", ()))
    monkeypatch.setattr(
        gate,
        "_workload_distribution",
        lambda *_args: ("pass", {"pod_count": 1, "by_node": {"worker-1": {"app": 1}}}, None),
    )
    monkeypatch.setattr(gate, "_candidate_im_scenario", lambda *_args: ("fail", {}, "im"))
    monkeypatch.setattr(gate, "_candidate_runtime_scenario", lambda *_args: ("fail", {}, "runtime"))
    monkeypatch.setattr(gate, "_candidate_evolution_scenario", lambda *_args: ("fail", {}, "evo"))
    monkeypatch.setattr(gate, "_candidate_redis_scenario", lambda *_args: ("fail", {}, "redis"))
    monkeypatch.setattr(gate, "_worker_restart_scenario", lambda *_args: ("fail", {}, "worker"))
    monkeypatch.setattr(gate, "_network_recovery_scenario", lambda *_args: ("fail", {}, "provider"))
    monkeypatch.setattr(gate, "_postgres_restart_scenario", lambda *_args: ("fail", {}, "postgres"))
    monkeypatch.setattr(gate, "_kubectl", lambda *_args, **_kwargs: gate.CommandResult("pass"))

    result = gate._execute(
        cluster_name="trpc-cell-kind",
        context="kind-trpc-cell-kind",
        namespace="trpc-cell-kind",
        image="docker.io/example/trpc-agent-service:kind",
        load_image=False,
        render_output=render_output,
        preflight={},
        timeout=5,
    )

    assert result["status"] == "fail"
    assert set(result["scenarios"]) == {
        "candidate_im_gateway_probe",
        "candidate_runtime_probe",
        "candidate_evolution_probe",
        "candidate_redis_probe",
        "worker_pod_replacement",
        "provider_endpoint_recovery",
        "postgres_pod_replacement",
    }
    assert len(result["rejection_reasons"]) == 7
    assert result["node_pools"]["status"] == "pass"
    assert result["schema_migration"]["status"] == "pass"
    assert result["schema_migration_head"]["status"] == "pass"


def test_execute_rejects_a_namespace_outside_the_dedicated_harness(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    render_output = tmp_path / "rendered.yaml"
    render_output.write_text("apiVersion: v1\nkind: List\n", encoding="utf-8")
    monkeypatch.setattr(gate, "_kind_cluster_exists", lambda _name: (True, None))

    result = gate._execute(
        cluster_name="trpc-cell-kind",
        context="kind-trpc-cell-kind",
        namespace="default",
        image="docker.io/example/trpc-agent-service:kind",
        load_image=False,
        render_output=render_output,
        preflight={},
        timeout=5,
    )

    assert result["status"] == "fail"
    assert result["rejection_reasons"] == ["execute namespace must be the dedicated kind namespace"]
    assert result["schema_migration"]["status"] == "not_run"


def test_preflight_report_is_render_only_and_does_not_create_a_cluster(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    objects = [
        {"kind": "Namespace", "metadata": {"name": "trpc-cell-kind"}},
        *[
            {
                "kind": "Deployment",
                "metadata": {"name": name},
                "spec": {"replicas": replicas},
            }
            for name, replicas in gate.REQUIRED_DEPLOYMENTS.items()
        ],
        *[{"kind": kind, "metadata": {"name": name}} for kind, name in gate.REQUIRED_OBJECTS],
    ]
    rendered_calls: list[str] = []

    def fake_render(image: str, output: Path) -> tuple[gate.CommandResult, list[dict[str, Any]]]:
        rendered_calls.append(image)
        return gate.CommandResult("pass"), objects

    monkeypatch.setattr(gate, "_render", fake_render)
    monkeypatch.setattr(gate, "_git_sha", lambda: "a" * 40)
    monkeypatch.setattr(
        gate,
        "_source_lineage",
        lambda: {"status": "available", "value": "b" * 64},
    )
    args = Namespace(
        execute=False,
        cluster_name="trpc-cell-kind",
        context="kind-trpc-cell-kind",
        namespace="trpc-cell-kind",
        image=gate.DEFAULT_IMAGE,
        load_image=False,
        render_output=tmp_path / "rendered.yaml",
        output=tmp_path / "report.json",
        timeout_seconds=5.0,
    )

    report = gate.build_report(args)

    assert report["mode"] == "preflight"
    assert report["preflight"]["status"] == "pass"
    assert report["gate"] == "not_run"
    assert report["local_k8s_gate"] == "not_run"
    assert report["production_gate"] == "not_run"
    assert report["rejection_reasons"] == [
        "preflight passed; --execute is required for the local Kubernetes gate"
    ]
    assert report["cluster"] == {
        "name": "trpc-cell-kind",
        "context": "kind-trpc-cell-kind",
        "uid": None,
        "status": "not_run",
    }
    assert rendered_calls == [gate.DEFAULT_IMAGE]

    exit_code = gate.main(["--output", str(tmp_path / "main-report.json")])
    main_report = json.loads((tmp_path / "main-report.json").read_text(encoding="utf-8"))
    assert exit_code == 1
    assert main_report["preflight"]["status"] == "pass"
    assert main_report["local_k8s_gate"] == "not_run"
    assert main_report["gate"] == "not_run"


def test_default_rollout_timeout_covers_serial_worker_termination_budget() -> None:
    args = gate._parser().parse_args([])
    assert args.timeout_seconds == gate.DEFAULT_ROLLOUT_TIMEOUT_SECONDS
    assert args.timeout_seconds >= 3 * 90 + 60


def test_main_rejects_non_kind_context_before_any_external_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoked: list[list[str]] = []

    def fail_if_called(argv: list[str], **_kwargs: object) -> NoReturn:
        invoked.append(argv)
        raise AssertionError("external command must not run")

    monkeypatch.setattr(gate, "_run", fail_if_called)

    assert gate.main(["--context", "prod", "--output", "runs/test.json"]) == 2
    assert invoked == []


def test_main_rejects_non_dedicated_namespace_before_any_external_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoked: list[list[str]] = []

    def fail_if_called(argv: list[str], **_kwargs: object) -> NoReturn:
        invoked.append(argv)
        raise AssertionError("external command must not run")

    monkeypatch.setattr(gate, "_run", fail_if_called)

    assert gate.main(["--namespace", "default", "--output", "runs/test.json"]) == 2
    assert invoked == []
