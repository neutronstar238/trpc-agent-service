from __future__ import annotations

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


def test_clear_uses_async_delete_and_polls_exact_job_until_absent(monkeypatch) -> None:
    config = {
        "namespace": "runtime-gate",
        "nonce": "a" * 32,
        "fingerprint": "b" * 64,
        "phase": "clear",
        "subject": "system:serviceaccount:driver:driver",
        "image": "registry.example/redis@sha256:" + "c" * 64,
        "command": ["/bin/sh", "-c", "sleep 1"],
    }
    job_payload = {
        "metadata": {
            "name": hpa_driver._job_name(config["nonce"]),
            "namespace": config["namespace"],
            "uid": "job-uid",
            "labels": hpa_driver._labels(config),
        },
        "status": {"succeeded": 1},
    }
    observed_jobs = iter((job_payload, job_payload, None))
    polls = 0

    def fake_get_job(_config, _timeout):
        nonlocal polls
        polls += 1
        return next(observed_jobs)

    calls: list[list[str]] = []

    def fake_kubectl(arguments, *, timeout, input_text=None):
        del timeout, input_text
        calls.append(arguments)
        return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(hpa_driver, "_whoami", lambda *_args: None)
    monkeypatch.setattr(hpa_driver, "_cluster_fingerprint", lambda _timeout: "b" * 64)
    monkeypatch.setattr(hpa_driver, "_get_job", fake_get_job)
    monkeypatch.setattr(hpa_driver, "_kubectl", fake_kubectl)
    monkeypatch.setattr(hpa_driver.time, "sleep", lambda _seconds: None)

    result = hpa_driver._clear(config, 5)

    assert result["status"] == "pass"
    assert result["job_uid"] == "job-uid"
    assert result["job_deleted"] is True
    assert polls == 3
    assert calls == [
        [
            "delete",
            "job",
            hpa_driver._job_name(config["nonce"]),
            "--namespace",
            "runtime-gate",
            "--ignore-not-found",
            "--wait=false",
        ]
    ]


def test_clear_fails_closed_when_exact_job_never_becomes_absent(monkeypatch) -> None:
    config = {
        "namespace": "runtime-gate",
        "nonce": "a" * 32,
        "fingerprint": "b" * 64,
        "phase": "clear",
        "subject": "system:serviceaccount:driver:driver",
        "image": "registry.example/redis@sha256:" + "c" * 64,
        "command": ["/bin/sh", "-c", "sleep 1"],
    }
    job_payload = {
        "metadata": {
            "name": hpa_driver._job_name(config["nonce"]),
            "namespace": config["namespace"],
            "uid": "job-uid",
            "labels": hpa_driver._labels(config),
        },
        "status": {"succeeded": 1},
    }
    calls = 0

    def fake_monotonic() -> float:
        nonlocal calls
        calls += 1
        return 0.0 if calls <= 3 else 2.0

    monkeypatch.setattr(hpa_driver, "_whoami", lambda *_args: None)
    monkeypatch.setattr(hpa_driver, "_cluster_fingerprint", lambda _timeout: "b" * 64)
    monkeypatch.setattr(hpa_driver, "_get_job", lambda _config, _timeout: job_payload)
    monkeypatch.setattr(
        hpa_driver,
        "_kubectl",
        lambda _arguments, *, timeout, input_text=None: type(
            "Completed", (), {"returncode": 0, "stdout": "", "stderr": ""}
        )(),
    )
    monkeypatch.setattr(hpa_driver.time, "monotonic", fake_monotonic)

    with pytest.raises(RuntimeError, match="deletion was not observed"):
        hpa_driver._clear(config, 1)
