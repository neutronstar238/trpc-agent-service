from __future__ import annotations

import asyncio
import json

import pytest

import scripts.kubernetes_hpa_load_driver as hpa_driver


def test_kubectl_environment_keeps_os_runtime_values_without_parent_secrets(monkeypatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(hpa_driver.shutil, "which", lambda _name: "kubectl.exe")
    monkeypatch.setenv("KUBECONFIG", "driver-kubeconfig")
    for name, value in {
        "PATH": r"C:\Windows\System32",
        "HOME": r"C:\Users\runner",
        "USERPROFILE": r"C:\Users\runner",
        "SYSTEMROOT": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "TEMP": r"C:\Users\runner\AppData\Local\Temp",
        "TMP": r"C:\Users\runner\AppData\Local\Temp",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-inherit")
    monkeypatch.setenv("TRPC_SERVICE_DATABASE_DSN", "postgresql://secret")

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["env"] = kwargs["env"]
        return type("Completed", (), {"returncode": 0, "stdout": "{}", "stderr": ""})()

    monkeypatch.setattr(hpa_driver.subprocess, "run", fake_run)
    result = hpa_driver._kubectl(
        ["auth", "whoami", "-o", "json"],
        timeout=5,
    )

    assert result.returncode == 0
    assert captured["command"] == [
        "kubectl.exe",
        "--kubeconfig",
        "driver-kubeconfig",
        "auth",
        "whoami",
        "-o",
        "json",
    ]
    environment = captured["env"]
    assert isinstance(environment, dict)
    assert set(environment) == {
        "PATH",
        "KUBECONFIG",
        "HOME",
        "USERPROFILE",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
    }
    assert environment["KUBECONFIG"] == "driver-kubeconfig"
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert "TRPC_SERVICE_DATABASE_DSN" not in environment


def test_kubectl_environment_omits_missing_os_runtime_values(monkeypatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(hpa_driver.shutil, "which", lambda _name: "kubectl.exe")
    monkeypatch.setenv("KUBECONFIG", "driver-kubeconfig")
    for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
        monkeypatch.delenv(name, raising=False)

    def fake_run(_command, **kwargs):
        captured["env"] = kwargs["env"]
        return type("Completed", (), {"returncode": 0, "stdout": "{}", "stderr": ""})()

    monkeypatch.setattr(hpa_driver.subprocess, "run", fake_run)
    hpa_driver._kubectl(["version", "-o", "json"], timeout=5)

    environment = captured["env"]
    assert isinstance(environment, dict)
    assert not {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"} & set(environment)


def test_load_creates_job_without_patch_permission(monkeypatch) -> None:
    calls: list[list[str]] = []
    config = {
        "namespace": "runtime-gate",
        "nonce": "a" * 32,
        "fingerprint": "b" * 64,
        "phase": "load",
        "subject": "system:serviceaccount:driver:driver",
        "image": "registry.example/redis@sha256:" + "c" * 64,
        "command": ["/bin/sh", "-c", "sleep 1"],
    }
    monkeypatch.setattr(hpa_driver, "_whoami", lambda *_args: None)
    monkeypatch.setattr(hpa_driver, "_cluster_fingerprint", lambda _timeout: "b" * 64)
    job_payload = {
        "metadata": {
            "name": hpa_driver._job_name(config["nonce"]),
            "namespace": config["namespace"],
            "uid": "job-uid",
            "labels": hpa_driver._labels(config),
        },
        "status": {"succeeded": 1},
    }
    observed_jobs = iter((None, job_payload))
    monkeypatch.setattr(hpa_driver, "_get_job", lambda _config, _timeout: next(observed_jobs))

    def fake_kubectl(arguments, *, timeout, input_text=None):
        del timeout
        calls.append(arguments)
        assert input_text is not None
        manifest = json.loads(input_text)
        assert manifest["kind"] == "Job"
        assert manifest["spec"]["template"]["spec"]["securityContext"] == {
            "runAsNonRoot": True,
            "runAsUser": 999,
            "runAsGroup": 999,
            "seccompProfile": {"type": "RuntimeDefault"},
        }
        return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(hpa_driver, "_kubectl", fake_kubectl)
    result = hpa_driver._load(config, 5)

    assert result["status"] == "pass"
    assert calls == [["create", "-f", "-"]]


def test_job_manifest_uses_configured_image_pull_secret() -> None:
    config = {
        "namespace": "runtime-gate",
        "nonce": "a" * 32,
        "fingerprint": "b" * 64,
        "phase": "load",
        "subject": "system:serviceaccount:driver:driver",
        "image": "ghcr.io/acme/backlog@sha256:" + "c" * 64,
        "command": ["python", "-m", "backlog"],
        "image_pull_secret": "ghcr-pull",
    }
    manifest = hpa_driver._job_manifest(config)
    assert manifest["spec"]["template"]["spec"]["imagePullSecrets"] == [{"name": "ghcr-pull"}]
    assert ".dockerconfigjson" not in json.dumps(manifest)


def test_default_hpa_timeout_covers_cold_pull_and_job_deadline(monkeypatch) -> None:
    monkeypatch.delenv("TRPC_K8S_HPA_DRIVER_TIMEOUT_SECONDS", raising=False)
    config = {
        "namespace": "runtime-gate",
        "nonce": "a" * 32,
        "fingerprint": "b" * 64,
        "phase": "load",
        "subject": "system:serviceaccount:driver:driver",
        "image": "ghcr.io/acme/backlog@sha256:" + "c" * 64,
        "command": ["python", "-m", "backlog"],
    }

    assert hpa_driver._timeout() == hpa_driver.MAX_TIMEOUT_SECONDS
    assert hpa_driver._job_manifest(config)["spec"]["activeDeadlineSeconds"] == 300


def test_job_manifest_binds_load_driver_to_configured_node_and_role() -> None:
    config = {
        "namespace": "runtime-gate",
        "nonce": "a" * 32,
        "fingerprint": "b" * 64,
        "phase": "load",
        "subject": "system:serviceaccount:driver:driver",
        "image": "ghcr.io/acme/backlog@sha256:" + "c" * 64,
        "command": ["python", "scripts/kubernetes_hpa_load_driver.py", "--backlog-probe"],
        "node_name": "cn-shenzhen.10.134.38.156",
        "node_label": "trpc-role=load-driver",
        "taint_key": "trpc-role",
        "taint_value": "load-driver",
        "taint_effect": "NoSchedule",
    }

    manifest = hpa_driver._job_manifest(config)
    template = manifest["spec"]["template"]
    pod_spec = template["spec"]
    assert pod_spec["nodeSelector"] == {
        "trpc-role": "load-driver",
        "kubernetes.io/hostname": "cn-shenzhen.10.134.38.156",
    }
    assert pod_spec["tolerations"] == [
        {
            "key": "trpc-role",
            "operator": "Equal",
            "value": "load-driver",
            "effect": "NoSchedule",
        }
    ]
    assert template["metadata"]["labels"]["app.kubernetes.io/part-of"] == ("trpc-agent-service")
    env = {item["name"]: item for item in pod_spec["containers"][0]["env"]}
    assert env[hpa_driver.HPA_PHASE_ENV] == {"name": hpa_driver.HPA_PHASE_ENV, "value": "load"}
    assert env[hpa_driver.HPA_DATABASE_DSN_ENV]["valueFrom"] == {
        "secretKeyRef": {
            "name": hpa_driver.HPA_DATABASE_SECRET_NAME,
            "key": hpa_driver.HPA_DATABASE_SECRET_KEY,
        }
    }


def test_backlog_probe_seeds_32_bounded_mailbox_and_outbox_rows() -> None:
    class FakeConnection:
        def __init__(self) -> None:
            self.fetchval_calls: list[tuple[str, tuple[object, ...]]] = []

        async def fetchval(self, query: str, *args: object) -> object:
            self.fetchval_calls.append((query, args))
            return {
                "schema_version": 1,
                "status": "pass",
                "phase": "prepare",
                "run_nonce": args[0],
                "tenant_id": f"hpa-{args[0]}",
                "seeded_rows": args[1],
            }

    nonce = "a" * 32
    connection = FakeConnection()

    seeded = asyncio.run(hpa_driver._hpa_probe_seed(connection, nonce))

    assert hpa_driver.HPA_PROBE_ROWS == 40
    assert (hpa_driver.HPA_PROBE_ROWS + 9) // 10 == 4
    assert hpa_driver.HPA_PROBE_ROWS * 10 > 3 * 10 * 11
    assert seeded == 40
    assert connection.fetchval_calls == [(hpa_driver._HPA_PREPARE_QUERY, (nonce, 40))]
    assert hpa_driver._HPA_PROBE_CLEANUP_TABLES.index("outbox_events") < (
        hpa_driver._HPA_PROBE_CLEANUP_TABLES.index("tenants")
    )


def test_probe_cleanup_requires_a_complete_zero_residual_receipt() -> None:
    nonce = "a" * 32

    class FakeConnection:
        async def fetchval(self, query: str, *args: object) -> object:
            assert query == hpa_driver._HPA_CLEANUP_QUERY
            assert args == (nonce,)
            return {
                "schema_version": 1,
                "status": "pass",
                "phase": "clear",
                "run_nonce": nonce,
                "tenant_id": "hpa-" + nonce,
                "already_absent": False,
                "deleted": {table: 0 for table in hpa_driver._HPA_PROBE_CLEANUP_TABLES},
                "residual": {table: 0 for table in hpa_driver._HPA_PROBE_CLEANUP_TABLES},
            }

    receipt = asyncio.run(hpa_driver._hpa_probe_cleanup(FakeConnection(), nonce))

    assert receipt["residual"] == {table: 0 for table in hpa_driver._HPA_PROBE_CLEANUP_TABLES}


def test_probe_cleanup_fails_closed_for_partial_or_nonzero_receipt() -> None:
    nonce = "a" * 32

    class FakeConnection:
        async def fetchval(self, _query: str, *_args: object) -> object:
            return {
                "schema_version": 1,
                "status": "pass",
                "phase": "clear",
                "run_nonce": nonce,
                "tenant_id": "hpa-" + nonce,
                "already_absent": False,
                "deleted": {"tenants": 1},
                "residual": {"tenants": 1},
            }

    with pytest.raises(RuntimeError, match="incomplete"):
        asyncio.run(hpa_driver._hpa_probe_cleanup(FakeConnection(), nonce))


def test_receipt_decoder_emits_only_the_fixed_contract_fields() -> None:
    nonce = "a" * 32
    prepare = {
        "schema_version": 1,
        "status": "pass",
        "phase": "prepare",
        "run_nonce": nonce,
        "tenant_id": "hpa-" + nonce,
        "seeded_rows": hpa_driver.HPA_PROBE_ROWS,
        "diagnostic": "discard-me",
    }
    decoded_prepare = hpa_driver._decode_hpa_receipt(prepare, phase="prepare", nonce=nonce)
    assert decoded_prepare == {
        "schema_version": 1,
        "status": "pass",
        "phase": "prepare",
        "run_nonce": nonce,
        "tenant_id": "hpa-" + nonce,
        "seeded_rows": hpa_driver.HPA_PROBE_ROWS,
    }

    clear = _clear_receipt(nonce)
    clear["diagnostic"] = "discard-me"
    decoded_clear = hpa_driver._decode_hpa_receipt(clear, phase="clear", nonce=nonce)
    assert set(decoded_clear) == {
        "schema_version",
        "status",
        "phase",
        "run_nonce",
        "tenant_id",
        "already_absent",
        "deleted",
        "residual",
    }
    assert "diagnostic" not in decoded_clear


@pytest.mark.parametrize(
    ("value", "valid"),
    [("a", True), ("a" * 63, True), ("a" * 64, False), ("a.b", False)],
)
def test_namespace_and_service_account_subject_use_dns_label_limit(value: str, valid: bool) -> None:
    assert (hpa_driver.NAMESPACE_RE.fullmatch(value) is not None) is valid
    subject = f"system:serviceaccount:{value}:driver"
    assert (hpa_driver.SERVICE_ACCOUNT_SUBJECT_RE.fullmatch(subject) is not None) is valid


def test_job_namespace_is_separate_from_hpa_target_namespace(monkeypatch) -> None:
    for name, value in {
        "TRPC_K8S_HPA_NAMESPACE": "trpc-runtime-gate-a1b2c3d4e5",
        hpa_driver.HPA_JOB_NAMESPACE_ENV: "trpc-runtime-driver",
        "TRPC_K8S_HPA_RUN_NONCE": "a" * 32,
        "TRPC_K8S_HPA_CLUSTER_FINGERPRINT": "b" * 64,
        "TRPC_K8S_HPA_PHASE": "load",
        "TRPC_K8S_HPA_DRIVER_SUBJECT": "system:serviceaccount:trpc-runtime-driver:hpa-driver",
        "TRPC_K8S_HPA_DRIVER_JOB_IMAGE": "ghcr.io/acme/backlog@sha256:" + "c" * 64,
        "TRPC_K8S_HPA_DRIVER_JOB_COMMAND": '["python","--backlog-probe"]',
    }.items():
        monkeypatch.setenv(name, value)

    config = hpa_driver._configuration()
    manifest = hpa_driver._job_manifest(config)

    assert config["namespace"] == "trpc-runtime-gate-a1b2c3d4e5"
    assert config["job_namespace"] == "trpc-runtime-driver"
    assert manifest["metadata"]["namespace"] == "trpc-runtime-driver"
    env = {
        item["name"]: item for item in manifest["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert env["TRPC_HPA_TARGET_NAMESPACE"] == {
        "name": "TRPC_HPA_TARGET_NAMESPACE",
        "value": "trpc-runtime-gate-a1b2c3d4e5",
    }


def test_load_accepts_active_probe_job(monkeypatch) -> None:
    config = {
        "namespace": "runtime-gate",
        "nonce": "a" * 32,
        "fingerprint": "b" * 64,
        "phase": "load",
        "subject": "system:serviceaccount:driver:driver",
        "image": "registry.example/redis@sha256:" + "c" * 64,
        "command": ["python", "scripts/kubernetes_hpa_load_driver.py", "--backlog-probe"],
    }
    job_payload = {
        "metadata": {
            "name": hpa_driver._job_name(config["nonce"]),
            "namespace": config["namespace"],
            "uid": "job-uid",
            "labels": hpa_driver._labels(config),
        },
        "status": {"active": 1},
    }
    monkeypatch.setattr(hpa_driver, "_whoami", lambda *_args: None)
    monkeypatch.setattr(hpa_driver, "_cluster_fingerprint", lambda _timeout: "b" * 64)
    monkeypatch.setattr(hpa_driver, "_get_job", lambda _config, _timeout: job_payload)

    result = hpa_driver._load(config, 5)

    assert result["status"] == "pass"
    assert result["job_active"] == 1
    assert result["job_succeeded"] == 0


def test_configuration_projects_and_validates_load_driver_placement(monkeypatch) -> None:
    for name, value in {
        "TRPC_K8S_HPA_NAMESPACE": "runtime-gate",
        "TRPC_K8S_HPA_RUN_NONCE": "a" * 32,
        "TRPC_K8S_HPA_CLUSTER_FINGERPRINT": "b" * 64,
        "TRPC_K8S_HPA_PHASE": "load",
        "TRPC_K8S_HPA_DRIVER_SUBJECT": "system:serviceaccount:runtime-gate:driver",
        "TRPC_K8S_HPA_DRIVER_JOB_IMAGE": "ghcr.io/acme/backlog@sha256:" + "c" * 64,
        "TRPC_K8S_HPA_DRIVER_JOB_COMMAND": '["python","-m","backlog"]',
        hpa_driver.HPA_NODE_NAME_ENV: "cn-shenzhen.10.134.38.156",
        hpa_driver.HPA_NODE_LABEL_ENV: "trpc-role=load-driver",
        hpa_driver.HPA_TAINT_KEY_ENV: "trpc-role",
        hpa_driver.HPA_TAINT_VALUE_ENV: "load-driver",
        hpa_driver.HPA_TAINT_EFFECT_ENV: "NoSchedule",
    }.items():
        monkeypatch.setenv(name, value)

    config = hpa_driver._configuration()

    assert config["node_name"] == "cn-shenzhen.10.134.38.156"
    assert config["node_label"] == "trpc-role=load-driver"
    assert config["taint_effect"] == "NoSchedule"


def test_configuration_rejects_subject_outside_job_namespace(monkeypatch) -> None:
    for name, value in {
        "TRPC_K8S_HPA_NAMESPACE": "runtime-gate",
        hpa_driver.HPA_JOB_NAMESPACE_ENV: "trpc-runtime-driver",
        "TRPC_K8S_HPA_RUN_NONCE": "a" * 32,
        "TRPC_K8S_HPA_CLUSTER_FINGERPRINT": "b" * 64,
        "TRPC_K8S_HPA_PHASE": "load",
        "TRPC_K8S_HPA_DRIVER_SUBJECT": "system:serviceaccount:other:driver",
        "TRPC_K8S_HPA_DRIVER_JOB_IMAGE": "ghcr.io/acme/backlog@sha256:" + "c" * 64,
        "TRPC_K8S_HPA_DRIVER_JOB_COMMAND": '["python","-m","backlog"]',
    }.items():
        monkeypatch.setenv(name, value)

    with pytest.raises(ValueError, match="subject namespace must match"):
        hpa_driver._configuration()


def test_configuration_rejects_invalid_image_pull_secret(monkeypatch) -> None:
    for name, value in {
        "TRPC_K8S_HPA_NAMESPACE": "runtime-gate",
        "TRPC_K8S_HPA_RUN_NONCE": "a" * 32,
        "TRPC_K8S_HPA_CLUSTER_FINGERPRINT": "b" * 64,
        "TRPC_K8S_HPA_PHASE": "load",
        "TRPC_K8S_HPA_DRIVER_SUBJECT": "system:serviceaccount:runtime-gate:driver",
        "TRPC_K8S_HPA_DRIVER_JOB_IMAGE": "ghcr.io/acme/backlog@sha256:" + "c" * 64,
        "TRPC_K8S_HPA_DRIVER_JOB_COMMAND": '["python","-m","backlog"]',
        "TRPC_K8S_HPA_DRIVER_IMAGE_PULL_SECRET": "registry/secret",
    }.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match="image pull Secret name is invalid"):
        hpa_driver._configuration()


def _clear_config() -> dict[str, str | list[str]]:
    return {
        "namespace": "runtime-gate-a1b2c3d4e5",
        "job_namespace": "trpc-runtime-driver",
        "nonce": "a" * 32,
        "fingerprint": "b" * 64,
        "phase": "clear",
        "subject": "system:serviceaccount:trpc-runtime-driver:hpa-driver",
        "image": "registry.example/redis@sha256:" + "c" * 64,
        "command": ["/bin/sh", "-c", "sleep 1"],
    }


def _clear_receipt(nonce: str, *, residual: dict[str, int] | None = None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "pass",
        "phase": "clear",
        "run_nonce": nonce,
        "tenant_id": "hpa-" + nonce,
        "already_absent": False,
        "deleted": {table: 0 for table in hpa_driver._HPA_PROBE_CLEANUP_TABLES},
        "residual": residual
        if residual is not None
        else {table: 0 for table in hpa_driver._HPA_PROBE_CLEANUP_TABLES},
    }


def test_cleanup_receipt_rejects_wrong_tenant_and_partial_deleted_map() -> None:
    nonce = "a" * 32
    wrong_tenant = _clear_receipt(nonce)
    wrong_tenant["tenant_id"] = "hpa-" + "b" * 32
    with pytest.raises(RuntimeError, match="nonce-bound"):
        hpa_driver._decode_hpa_receipt(wrong_tenant, phase="clear", nonce=nonce)

    partial_deleted = _clear_receipt(nonce)
    partial_deleted["deleted"] = {"tenants": 0}
    with pytest.raises(RuntimeError, match="incomplete"):
        hpa_driver._decode_hpa_receipt(partial_deleted, phase="clear", nonce=nonce)


def test_cleanup_receipt_rejects_negative_or_boolean_deleted_count() -> None:
    nonce = "a" * 32
    for invalid in (-1, True):
        receipt = _clear_receipt(nonce)
        deleted = dict(receipt["deleted"])
        deleted["sessions"] = invalid
        receipt["deleted"] = deleted
        with pytest.raises(RuntimeError, match="invalid deleted row count"):
            hpa_driver._decode_hpa_receipt(receipt, phase="clear", nonce=nonce)


def _clear_job_payloads(
    config: dict[str, str | list[str]],
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    load_job = {
        "metadata": {
            "name": hpa_driver._job_name(config["nonce"]),
            "namespace": config["job_namespace"],
            "uid": "load-job-uid",
            "labels": hpa_driver._labels(config),
        },
        "status": {"active": 1},
    }
    cleanup_uid = "cleanup-job-uid"
    cleanup_job = {
        "metadata": {
            "name": hpa_driver._cleanup_job_name(config["nonce"]),
            "namespace": config["job_namespace"],
            "uid": cleanup_uid,
            "labels": hpa_driver._labels(config, phase="cleanup"),
        },
        "status": {"succeeded": 1},
    }
    cleanup_pod = {
        "metadata": {
            "name": "cleanup-pod",
            "namespace": config["job_namespace"],
            "labels": hpa_driver._labels(config, phase="cleanup"),
            "ownerReferences": [{"kind": "Job", "uid": cleanup_uid, "controller": True}],
        },
        "status": {"phase": "Succeeded"},
    }
    return load_job, cleanup_job, cleanup_pod


def test_clear_runs_cleanup_job_and_validates_receipt_before_deleting_jobs(monkeypatch) -> None:
    config = _clear_config()
    load_job, cleanup_job, cleanup_pod = _clear_job_payloads(config)
    deleted: list[str] = []
    created: list[dict[str, object]] = []
    log_calls: list[list[str]] = []
    cleanup_reads = 0

    def fake_get_named(_config, name, _timeout):
        nonlocal cleanup_reads
        if name == hpa_driver._cleanup_job_name(config["nonce"]):
            cleanup_reads += 1
            if cleanup_reads == 1:
                return None
            return cleanup_job if name not in deleted else None
        return load_job if name not in deleted else None

    def fake_kubectl(arguments, *, timeout, input_text=None):
        del timeout
        if arguments[:2] == ["create", "-f"]:
            assert input_text is not None
            manifest = json.loads(input_text)
            created.append(manifest)
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        if arguments[0] == "get" and arguments[1] == "pods":
            return type(
                "Completed",
                (),
                {"returncode": 0, "stdout": json.dumps({"items": [cleanup_pod]}), "stderr": ""},
            )()
        if arguments[0] == "logs":
            log_calls.append(arguments)
            return type(
                "Completed",
                (),
                {
                    "returncode": 0,
                    "stdout": json.dumps(_clear_receipt(config["nonce"])),
                    "stderr": "",
                },
            )()
        if arguments[0] == "delete":
            deleted.append(arguments[2])
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        raise AssertionError(f"unexpected kubectl call: {arguments}")

    monkeypatch.setattr(hpa_driver, "_whoami", lambda *_args: None)
    monkeypatch.setattr(hpa_driver, "_cluster_fingerprint", lambda _timeout: "b" * 64)
    monkeypatch.setattr(hpa_driver, "_get_job", lambda *_args: load_job)
    monkeypatch.setattr(hpa_driver, "_get_named_job", fake_get_named)
    monkeypatch.setattr(hpa_driver, "_kubectl", fake_kubectl)
    monkeypatch.setattr(hpa_driver.time, "sleep", lambda _seconds: None)

    result = hpa_driver._clear(config, 5)

    assert result["status"] == "pass"
    assert result["job_uid"] == "load-job-uid"
    assert result["cleanup_job_uid"] == "cleanup-job-uid"
    assert result["target_namespace"] == "runtime-gate-a1b2c3d4e5"
    assert result["job_namespace"] == "trpc-runtime-driver"
    assert result["residual"] == {table: 0 for table in hpa_driver._HPA_PROBE_CLEANUP_TABLES}
    assert [manifest["metadata"]["name"] for manifest in created] == [
        hpa_driver._cleanup_job_name(config["nonce"])
    ]
    cleanup_manifest = created[0]
    assert cleanup_manifest["metadata"]["namespace"] == config["job_namespace"]
    container = cleanup_manifest["spec"]["template"]["spec"]["containers"][0]
    assert container["command"] == [
        "python",
        "scripts/kubernetes_hpa_load_driver.py",
        hpa_driver.HPA_CLEANUP_ARGUMENT,
    ]
    assert [call[0:2] for call in log_calls] == [["logs", "cleanup-pod"]]
    assert deleted == [
        hpa_driver._cleanup_job_name(config["nonce"]),
        hpa_driver._job_name(config["nonce"]),
    ]


def test_cleanup_manifest_uses_hpa_secret_and_clear_phase() -> None:
    config = _clear_config()
    manifest = hpa_driver._cleanup_job_manifest(config)
    assert manifest["metadata"] == {
        "name": hpa_driver._cleanup_job_name(config["nonce"]),
        "namespace": config["job_namespace"],
        "labels": hpa_driver._labels(config, phase="cleanup"),
    }
    container = manifest["spec"]["template"]["spec"]["containers"][0]
    env = {item["name"]: item for item in container["env"]}
    assert env[hpa_driver.HPA_PHASE_ENV] == {
        "name": hpa_driver.HPA_PHASE_ENV,
        "value": "clear",
    }
    assert env[hpa_driver.HPA_DATABASE_DSN_ENV]["valueFrom"] == {
        "secretKeyRef": {
            "name": "trpc-hpa-secrets",
            "key": hpa_driver.HPA_DATABASE_DSN_ENV,
        }
    }
    assert container["command"][-1] == hpa_driver.HPA_CLEANUP_ARGUMENT


def test_clear_does_not_read_load_pod_stdout(monkeypatch) -> None:
    config = _clear_config()
    load_job, cleanup_job, cleanup_pod = _clear_job_payloads(config)
    deleted: set[str] = set()
    log_calls: list[list[str]] = []

    def fake_get_named(_config, name, _timeout):
        payload = cleanup_job if name == hpa_driver._cleanup_job_name(config["nonce"]) else load_job
        return None if name in deleted else payload

    def fake_kubectl(arguments, *, timeout, input_text=None):
        del timeout
        if arguments[:2] == ["create", "-f"]:
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        if arguments[0] == "get" and arguments[1] == "pods":
            return type(
                "Completed",
                (),
                {"returncode": 0, "stdout": json.dumps({"items": [cleanup_pod]}), "stderr": ""},
            )()
        if arguments[0] == "logs":
            log_calls.append(arguments)
            return type(
                "Completed",
                (),
                {
                    "returncode": 0,
                    "stdout": json.dumps(_clear_receipt(config["nonce"])),
                    "stderr": "",
                },
            )()
        if arguments[0] == "delete":
            deleted.add(arguments[2])
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        raise AssertionError(f"unexpected kubectl call: {arguments}")

    monkeypatch.setattr(hpa_driver, "_whoami", lambda *_args: None)
    monkeypatch.setattr(hpa_driver, "_cluster_fingerprint", lambda _timeout: "b" * 64)
    monkeypatch.setattr(hpa_driver, "_get_job", lambda *_args: load_job)
    monkeypatch.setattr(hpa_driver, "_get_named_job", fake_get_named)
    monkeypatch.setattr(hpa_driver, "_kubectl", fake_kubectl)
    monkeypatch.setattr(hpa_driver.time, "sleep", lambda _seconds: None)

    hpa_driver._clear(config, 5)
    assert len(log_calls) == 1
    assert log_calls[0][1] == "cleanup-pod"


def test_clear_fails_closed_for_nonzero_cleanup_residual(monkeypatch) -> None:
    config = _clear_config()
    load_job, cleanup_job, cleanup_pod = _clear_job_payloads(config)
    deleted: list[str] = []
    residual = {table: 0 for table in hpa_driver._HPA_PROBE_CLEANUP_TABLES}
    residual["session_mailboxes"] = 1

    def fake_get_named(_config, name, _timeout):
        return cleanup_job if name == hpa_driver._cleanup_job_name(config["nonce"]) else load_job

    def fake_kubectl(arguments, *, timeout, input_text=None):
        del timeout, input_text
        if arguments[:2] == ["create", "-f"]:
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        if arguments[0] == "get" and arguments[1] == "pods":
            return type(
                "Completed",
                (),
                {"returncode": 0, "stdout": json.dumps({"items": [cleanup_pod]}), "stderr": ""},
            )()
        if arguments[0] == "logs":
            return type(
                "Completed",
                (),
                {
                    "returncode": 0,
                    "stdout": json.dumps(_clear_receipt(config["nonce"], residual=residual)),
                    "stderr": "",
                },
            )()
        if arguments[0] == "delete":
            deleted.append(arguments[2])
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        raise AssertionError(f"unexpected kubectl call: {arguments}")

    monkeypatch.setattr(hpa_driver, "_whoami", lambda *_args: None)
    monkeypatch.setattr(hpa_driver, "_cluster_fingerprint", lambda _timeout: "b" * 64)
    monkeypatch.setattr(hpa_driver, "_get_job", lambda *_args: load_job)
    monkeypatch.setattr(hpa_driver, "_get_named_job", fake_get_named)
    monkeypatch.setattr(hpa_driver, "_kubectl", fake_kubectl)
    monkeypatch.setattr(hpa_driver.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="residual"):
        hpa_driver._clear(config, 5)
    assert deleted == []


def test_cleanup_receipt_wait_retries_pod_propagation(monkeypatch) -> None:
    config = _clear_config()
    _load_job, cleanup_job, cleanup_pod = _clear_job_payloads(config)
    pod_reads = 0

    monkeypatch.setattr(hpa_driver, "_get_named_job", lambda *_args: cleanup_job)

    def fake_kubectl(arguments, *, timeout, input_text=None):
        nonlocal pod_reads
        del timeout, input_text
        if arguments[0] == "get" and arguments[1] == "pods":
            pod_reads += 1
            items = [] if pod_reads == 1 else [cleanup_pod]
            return type(
                "Completed",
                (),
                {"returncode": 0, "stdout": json.dumps({"items": items}), "stderr": ""},
            )()
        if arguments[0] == "logs":
            return type(
                "Completed",
                (),
                {
                    "returncode": 0,
                    "stdout": json.dumps(_clear_receipt(config["nonce"])),
                    "stderr": "",
                },
            )()
        raise AssertionError(f"unexpected kubectl call: {arguments}")

    monkeypatch.setattr(hpa_driver, "_kubectl", fake_kubectl)
    monkeypatch.setattr(hpa_driver.time, "sleep", lambda _seconds: None)
    _uid, receipt = hpa_driver._wait_for_cleanup_receipt(config, 5)
    assert pod_reads == 2
    assert receipt["residual"] == {table: 0 for table in hpa_driver._HPA_PROBE_CLEANUP_TABLES}


def test_clear_rejects_non_transient_cleanup_delete_error(monkeypatch) -> None:
    config = _clear_config()
    load_job, cleanup_job, cleanup_pod = _clear_job_payloads(config)

    def fake_get_named(_config, name, _timeout):
        return cleanup_job if name == hpa_driver._cleanup_job_name(config["nonce"]) else load_job

    def fake_kubectl(arguments, *, timeout, input_text=None):
        del timeout, input_text
        if arguments[:2] == ["create", "-f"]:
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        if arguments[0] == "get" and arguments[1] == "pods":
            return type(
                "Completed",
                (),
                {"returncode": 0, "stdout": json.dumps({"items": [cleanup_pod]}), "stderr": ""},
            )()
        if arguments[0] == "logs":
            return type(
                "Completed",
                (),
                {
                    "returncode": 0,
                    "stdout": json.dumps(_clear_receipt(config["nonce"])),
                    "stderr": "",
                },
            )()
        if arguments[0] == "delete":
            return type("Completed", (), {"returncode": 1, "stdout": "", "stderr": "Forbidden"})()
        raise AssertionError(f"unexpected kubectl call: {arguments}")

    monkeypatch.setattr(hpa_driver, "_whoami", lambda *_args: None)
    monkeypatch.setattr(hpa_driver, "_cluster_fingerprint", lambda _timeout: "b" * 64)
    monkeypatch.setattr(hpa_driver, "_get_job", lambda *_args: load_job)
    monkeypatch.setattr(hpa_driver, "_get_named_job", fake_get_named)
    monkeypatch.setattr(hpa_driver, "_kubectl", fake_kubectl)
    monkeypatch.setattr(hpa_driver.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="could not be deleted"):
        hpa_driver._clear(config, 5)
