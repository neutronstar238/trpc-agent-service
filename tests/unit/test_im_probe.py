from __future__ import annotations

import base64
import json
import threading
from http.client import RemoteDisconnected
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.im_probe import server as im_probe
from scripts.im_online_gate import REQUIRED_CASES, _verify_probe_signature

IMAGE_DIGEST = "sha256:" + "1" * 64
IDENTITY_SHA256 = "2" * 64
NONCE = "probe_nonce_123456"


@pytest.fixture
def probe_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    secrets = {
        "feishu": {
            "FEISHU_APP_SECRET": "feishu-app-secret",
            "FEISHU_VERIFICATION_TOKEN": "feishu-verification-token",
            "FEISHU_ENCRYPT_KEY": "feishu-encrypt-key",
        },
        "wecom": {"WECOM_BOT_SECRET": "wecom-bot-secret"},
    }
    credential_paths: dict[str, dict[str, Path]] = {"feishu": {}, "wecom": {}}
    for channel, values in secrets.items():
        for name, value in values.items():
            path = tmp_path / f"{channel.lower()}-{name.lower()}"
            path.write_text(value, encoding="utf-8")
            credential_paths[channel][name] = path

    private_key = Ed25519PrivateKey.generate()
    signing_key_path = tmp_path / "im-probe-ed25519-seed"
    signing_key_path.write_text(
        base64.b64encode(
            private_key.private_bytes_raw(),
        ).decode("ascii"),
        encoding="ascii",
    )
    config = im_probe.ProbeConfig(
        bind_host="127.0.0.1",
        port=8750,
        runner=None,
        runner_timeout_seconds=1,
        driver_timeout_seconds=1,
        signing_key_path=signing_key_path,
        key_id="offline-probe-key",
        image_digest=IMAGE_DIGEST,
        identity_sha256=IDENTITY_SHA256,
        account_ids={"feishu": "cli_offline_feishu", "wecom": "offline_wecom_bot"},
        credential_paths=credential_paths,
        runner_secret_paths={"feishu": {}, "wecom": {}},
        driver_paths={},
    )
    service = im_probe.ProbeService(config)
    monkeypatch.setenv("FEISHU_APP_ID", config.account_ids["feishu"])
    monkeypatch.setenv("WECOM_BOT_ID", config.account_ids["wecom"])
    return config, service, private_key, secrets


def _request(config: im_probe.ProbeConfig, channel: str, nonce: str = NONCE) -> dict[str, object]:
    credential_fingerprints = im_probe._credential_fingerprints(config, channel)
    return {
        "run_id": f"offline-{channel}-run",
        "channel": channel,
        "nonce": nonce,
        "cases": list(REQUIRED_CASES),
        "expected_image_digest": config.image_digest,
        "credential_fingerprints": credential_fingerprints,
        "probe_identity_sha256": config.identity_sha256,
        "account_fingerprint": im_probe._fingerprint(
            config.account_ids[channel],
            label=im_probe.CHANNEL_ACCOUNT_VARIABLE[channel],
        ),
    }


def test_signed_response_uses_gate_canonical_json(
    probe_fixture,
) -> None:
    config, _service, private_key, _secrets = probe_fixture
    payload = {
        "schema_version": 1,
        "runtime": {"status": "pass", "image_digest": config.image_digest},
        "cases": {case: {"status": "not_run"} for case in REQUIRED_CASES},
    }

    signed = im_probe._signed_response(config, payload)
    attestation = signed["signature_attestation"]
    assert attestation["algorithm"] == "ed25519"
    assert attestation["key_id"] == config.key_id
    public_key = private_key.public_key()
    _verify_probe_signature(
        signed,
        {
            "key_id": config.key_id,
            "public_key": public_key.public_bytes_raw(),
        },
    )
    signed_payload = dict(signed)
    signed_payload.pop("signature_attestation")
    public_key.verify(
        base64.b64decode(attestation["signature"]),
        im_probe._canonical_json(signed_payload),
    )


def test_missing_runner_is_signed_not_run_and_has_no_secret_leak(probe_fixture) -> None:
    config, service, private_key, secrets = probe_fixture
    response = service.handle(_request(config, "feishu"))

    assert response["error_code"] == "provider_runner_unconfigured"
    assert response["runtime"]["status"] == "pass"
    assert all(case["status"] == "not_run" for case in response["cases"].values())
    serialized = json.dumps(response, ensure_ascii=True)
    for values in secrets.values():
        for secret in values.values():
            assert secret not in serialized
    attestation = response["signature_attestation"]
    signed_payload = dict(response)
    signed_payload.pop("signature_attestation")
    private_key.public_key().verify(
        base64.b64decode(attestation["signature"]),
        im_probe._canonical_json(signed_payload),
    )


def test_request_is_bound_to_candidate_credentials_identity_and_nonce(probe_fixture) -> None:
    config, service, _private_key, _secrets = probe_fixture
    invalid = _request(config, "wecom")
    invalid["expected_image_digest"] = "sha256:" + "3" * 64
    with pytest.raises(im_probe.ProbeRequestError):
        service.handle(invalid)

    valid = _request(config, "wecom")
    service.handle(valid)
    with pytest.raises(im_probe.ProbeRequestError, match="nonce was already consumed"):
        service.handle(valid)


def test_invalid_provider_runner_evidence_stays_not_run(probe_fixture, monkeypatch) -> None:
    config, service, _private_key, _secrets = probe_fixture
    monkeypatch.setattr(
        im_probe,
        "_run_provider_runner",
        lambda _config, _request: {"provider_evidence": {"status": "pass"}},
    )

    response = service.handle(_request(config, "wecom"))

    assert response["error_code"] == "provider_evidence_invalid"
    assert "provider_evidence" not in response
    assert all(case["status"] == "not_run" for case in response["cases"].values())


def test_runner_gets_secret_paths_but_not_secret_values(probe_fixture, monkeypatch) -> None:
    config, _service, _private_key, secrets = probe_fixture
    runner = Path(config.signing_key_path.parent / "provider-runner")
    runner.write_text("placeholder", encoding="utf-8")
    driver = Path(config.signing_key_path.parent / "feishu-driver")
    driver.write_text("placeholder", encoding="utf-8")
    config = im_probe.ProbeConfig(
        **{**config.__dict__, "runner": runner, "driver_paths": {"feishu": driver}},
    )
    request = _request(config, "feishu")
    observed: dict[str, object] = {}

    class FakeProcess:
        returncode = 0

        def __init__(self, *args, **kwargs) -> None:
            observed["args"] = args
            observed["kwargs"] = kwargs

        def communicate(self, *, input, timeout) -> None:
            observed["input"] = input
            observed["kwargs"]["stdout"].write(b"{}")

    def fake_popen(*args, **kwargs):
        observed["args"] = args
        observed["kwargs"] = kwargs
        return FakeProcess(*args, **kwargs)

    monkeypatch.setattr(im_probe.subprocess, "Popen", fake_popen)
    assert im_probe._run_provider_runner(config, request) == {}
    environment = observed["kwargs"]["env"]
    runner_input = observed["input"].decode("utf-8")
    assert all(
        str(path) in environment.values() for path in config.credential_paths["feishu"].values()
    )
    assert "TRPC_IM_PROBE_FEISHU_APP_SECRET_FILE" in environment
    assert "TRPC_IM_PROBE_FEISHU_ENCRYPT_KEY_FILE" in environment
    assert "TRPC_IM_PROBE_WECOM_BOT_ID" not in environment
    assert "TRPC_IM_PROBE_WECOM_BOT_SECRET_FILE" not in environment
    assert "PYTHONPATH" not in environment
    for values in secrets.values():
        for secret in values.values():
            assert secret not in runner_input
            assert secret not in environment.values()


def test_probe_service_does_not_mutate_process_account_environment(
    probe_fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _service, _private_key, _secrets = probe_fixture
    monkeypatch.delenv("FEISHU_APP_ID", raising=False)
    monkeypatch.delenv("WECOM_BOT_ID", raising=False)

    im_probe.ProbeService(config)

    assert "FEISHU_APP_ID" not in im_probe.os.environ
    assert "WECOM_BOT_ID" not in im_probe.os.environ


def test_runner_output_is_bounded_before_json_is_loaded(monkeypatch: pytest.MonkeyPatch) -> None:
    class OversizedProcess:
        returncode = 0

        def __init__(self, *args, **kwargs) -> None:
            self.output = kwargs["stdout"]

        def communicate(self, *, input, timeout) -> None:
            self.output.write(b"x" * (im_probe.MAX_RUNNER_OUTPUT_BYTES + 1))

    monkeypatch.setattr(im_probe.subprocess, "Popen", OversizedProcess)

    assert (
        im_probe._run_bounded_json_process(
            ["provider-runner"],
            input_bytes=b"{}",
            timeout=1,
            environment={},
        )
        is None
    )


def test_nonce_cache_is_bounded_and_rejects_recent_replay(probe_fixture) -> None:
    _config, service, _private_key, _secrets = probe_fixture
    for index in range(im_probe.NONCE_CACHE_CAPACITY + 1):
        service._consume_nonce(("feishu", f"nonce-{index}"))

    assert len(service._seen) == im_probe.NONCE_CACHE_CAPACITY
    with pytest.raises(im_probe.ProbeRequestError, match="nonce was already consumed"):
        service._consume_nonce(("feishu", f"nonce-{im_probe.NONCE_CACHE_CAPACITY}"))


def test_ready_checks_both_external_drivers(probe_fixture, monkeypatch: pytest.MonkeyPatch) -> None:
    config, _service, _private_key, _secrets = probe_fixture
    runner = config.signing_key_path.parent / "provider-runner"
    feishu_driver = config.signing_key_path.parent / "feishu-driver"
    wecom_driver = config.signing_key_path.parent / "wecom-driver"
    for path in (runner, feishu_driver, wecom_driver):
        path.write_text("executable", encoding="utf-8")
    config = im_probe.ProbeConfig(
        **{
            **config.__dict__,
            "runner": runner,
            "driver_paths": {"feishu": feishu_driver, "wecom": wecom_driver},
        }
    )
    observed: list[tuple[list[str], dict[str, str]]] = []

    def fake_process(command, *, input_bytes, timeout, environment):
        observed.append((list(command), dict(environment)))
        return {"status": "ready"}

    monkeypatch.setattr(im_probe, "_run_bounded_json_process", fake_process)

    assert im_probe.ProbeService(config).ready()
    assert [command[-1] for command, _environment in observed] == ["feishu", "wecom"]
    assert "TRPC_IM_PROBE_WECOM_DRIVER" not in observed[0][1]
    assert "TRPC_IM_PROBE_FEISHU_DRIVER" not in observed[1][1]
    assert im_probe._ProbeHTTPServer.daemon_threads is True


def test_http_health_and_invalid_request_are_local_and_fail_closed(probe_fixture) -> None:
    _config, service, _private_key, _secrets = probe_fixture
    http_server = im_probe._ProbeHTTPServer(("127.0.0.1", 0), service)
    thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{http_server.server_port}"
    try:
        with urlopen(base_url + "/health/live", timeout=3) as response:  # noqa: S310
            assert response.status == 200
            assert json.loads(response.read()) == {"status": "pass"}

        with pytest.raises(HTTPError) as ready_error:
            urlopen(base_url + "/health/ready", timeout=3)  # noqa: S310
        assert ready_error.value.code == 503
        assert json.loads(ready_error.value.read()) == {"status": "not_ready"}

        request = Request(  # noqa: S310
            base_url + "/probe",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as probe_error:
            urlopen(request, timeout=3)  # noqa: S310
        assert probe_error.value.code == 400
        assert json.loads(probe_error.value.read()) == {
            "reason": "request_invalid",
            "status": "not_run",
        }
    except RemoteDisconnected as error:
        pytest.fail(f"probe HTTP server disconnected unexpectedly: {error}")
    finally:
        http_server.shutdown()
        http_server.server_close()
        thread.join(timeout=3)
    assert not thread.is_alive()
