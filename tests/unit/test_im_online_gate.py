from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.im_online_gate import (
    CHANNEL_CREDENTIALS,
    MAX_OUTAGE_SECONDS,
    MAX_RETRY_AFTER_SECONDS,
    REQUIRED_CASES,
    _run,
    _validate_probe_runtime,
    _validate_provider_evidence,
)
from trpc_service.agent.wecom_manager import _binding_signature
from trpc_service.channels.wecom import parse_wecom_frame
from trpc_service.channels.wecom_download import _http_status_error
from trpc_service.config.secrets import SecretRef
from trpc_service.tenant.models import Channel, ChannelBinding, ConversationKind


def test_documented_direct_invocation_resolves_scripts_package() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/im_online_gate.py", "--help"],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "usage: im_online_gate.py" in result.stdout


def _install_probe_trust(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    probe_url: str = "https://probe.example.test",
) -> Ed25519PrivateKey:
    import scripts.im_online_gate as online_gate

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    deploy_root = tmp_path / "deploy"
    deploy_root.mkdir()
    trust_path = deploy_root / "im-probe-trust.json"
    trust_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "probe_url": probe_url,
                "key_id": "offline-test-key",
                "ed25519_public_key": base64.b64encode(public_key).decode("ascii"),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(online_gate, "ROOT", tmp_path)
    monkeypatch.setattr(online_gate, "PROBE_TRUST_PATH", trust_path)
    return private_key


def _sign_probe_response(
    response: dict[str, Any], private_key: Ed25519PrivateKey
) -> dict[str, Any]:
    signed = dict(response)
    message = json.dumps(
        signed,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    signed["signature_attestation"] = {
        "algorithm": "ed25519",
        "key_id": "offline-test-key",
        "signature": base64.b64encode(private_key.sign(message)).decode("ascii"),
    }
    return signed


def _credentials(monkeypatch: pytest.MonkeyPatch) -> dict[str, dict[str, str]]:
    monkeypatch.setenv("FEISHU_APP_ID", "offline-feishu-account")
    monkeypatch.setenv("WECOM_BOT_ID", "offline-wecom-account")
    result: dict[str, dict[str, str]] = {}
    for channel, names in CHANNEL_CREDENTIALS.items():
        values: dict[str, str] = {}
        for name in names:
            value = (
                f"offline-{name.lower()}-value"
                if name not in {"FEISHU_APP_ID", "WECOM_BOT_ID"}
                else os.environ[name]
            )
            monkeypatch.setenv(name, value)
            from scripts.im_online_gate import _fingerprint

            values[name] = _fingerprint(value, label=name)
        result[channel] = values
    return result


def _observations(channel: str, nonce: str) -> dict[str, dict[str, object]]:
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    common = {"status": "pass", "run_nonce": nonce, "observed_at": timestamp}
    return {
        "round_trip": {
            **common,
            "provider_event_id": f"{channel}-round-trip",
            "callback_event_id": f"{channel}-callback",
            "outbound_request_id": f"{channel}-request",
            "provider_code": 0,
        },
        "idempotency": {
            **common,
            "provider_event_id": f"{channel}-first-event",
            "duplicate_event_id": f"{channel}-duplicate-event",
            "unique_inbound_id": f"{channel}-inbound",
            "duplicate_count": 1,
        },
        "media": {
            **common,
            "provider_event_id": f"{channel}-media-event",
            "media_id_hash": "a" * 64,
            "sha256": "b" * 64,
            "bytes": 16,
        },
        "reconnect": {
            **common,
            "provider_event_id": f"{channel}-reconnect-event",
            "disconnect_event_id": f"{channel}-disconnect",
            "reconnect_event_id": f"{channel}-reconnect",
            "received_after_reconnect_event_id": f"{channel}-after-reconnect",
            "lock_takeover_event_id": f"{channel}-lock-takeover",
            "old_lock_owner_released": True,
            "new_lock_owner_acquired": True,
            "lock_epoch": 2,
        },
        "rate_limit_retry_after": {
            **common,
            "provider_event_id": f"{channel}-rate-event",
            "provider_error_code": 429,
            "retry_after_seconds": 1.0,
            "retry_request_id": f"{channel}-retry",
            "retry_attempts": 2,
            "retry_elapsed_seconds": 1.0,
        },
        "credential_rotation": {
            **common,
            "provider_event_id": f"{channel}-rotation-event",
            "old_credential_event_id": f"{channel}-old",
            "new_credential_event_id": f"{channel}-new",
            "post_rotation_event_id": f"{channel}-post-rotation",
            "old_credential_rejected": True,
        },
        "prolonged_outage": {
            **common,
            "provider_event_id": f"{channel}-outage-event",
            "outage_event_id": f"{channel}-outage",
            "recovery_event_id": f"{channel}-recovery",
            "outage_seconds": 60.0,
        },
        "ambiguous": {
            **common,
            "provider_event_id": f"{channel}-ambiguous-event",
            "ambiguous_event_id": f"{channel}-ambiguous",
            "manual_review_id": f"{channel}-manual-review",
            "drop_response_observed": True,
            "auto_replay_count": 0,
        },
    }


def test_online_gate_default_is_fail_closed_and_expanded() -> None:
    assert REQUIRED_CASES == (
        "round_trip",
        "idempotency",
        "media",
        "reconnect",
        "rate_limit_retry_after",
        "credential_rotation",
        "prolonged_outage",
        "ambiguous",
    )


def test_provider_evidence_missing_independent_source_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprints = _credentials(monkeypatch)["feishu"]
    evidence, errors = _validate_provider_evidence(
        "feishu",
        {"cases": {case: {"status": "pass"} for case in REQUIRED_CASES}},
        run_nonce="nonce",
        credential_fingerprints=fingerprints,
    )
    assert evidence is None
    assert "provider_evidence is missing" in errors


def test_provider_evidence_requires_nonce_and_platform_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprints = _credentials(monkeypatch)["wecom"]
    response = {
        "credential_attestation": {
            "status": "pass",
            "run_nonce": "wrong",
            "fingerprints": fingerprints,
        },
        "provider_evidence": {
            "source": "wecom_ws_and_send_ack",
            "independent_paths": ["provider_ws_event", "provider_send_ack"],
            "run_nonce": "wrong",
            "account_fingerprint": "0" * 64,
            "observations": {},
        },
    }
    evidence, errors = _validate_provider_evidence(
        "wecom",
        response,
        run_nonce="nonce",
        credential_fingerprints=fingerprints,
    )
    assert evidence is None
    assert any("run_nonce" in error for error in errors)
    assert any("observations.round_trip" in error for error in errors)


def test_provider_evidence_is_sanitized_and_keeps_required_case_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprints = _credentials(monkeypatch)["feishu"]
    from scripts.im_online_gate import (
        CHANNEL_ACCOUNT_VARIABLE,
        PROVIDER_EVIDENCE_SOURCE,
        _fingerprint,
    )

    account_name = CHANNEL_ACCOUNT_VARIABLE["feishu"]
    account_hash = _fingerprint("offline-feishu-account", label=account_name)
    response = {
        "credential_attestation": {
            "status": "pass",
            "run_nonce": "nonce",
            "fingerprints": fingerprints,
        },
        "provider_evidence": {
            "source": PROVIDER_EVIDENCE_SOURCE["feishu"],
            "independent_paths": ["provider_callback", "provider_send_ack"],
            "run_nonce": "nonce",
            "account_fingerprint": account_hash,
            "observations": _observations("feishu", "nonce"),
            "message_body": "must never be copied",
        },
    }
    evidence, errors = _validate_provider_evidence(
        "feishu",
        response,
        run_nonce="nonce",
        credential_fingerprints=fingerprints,
    )
    assert not errors
    assert evidence is not None
    assert set(evidence["observations"]) == set(REQUIRED_CASES)
    assert evidence["independent_paths"] == ["provider_callback", "provider_send_ack"]
    assert evidence["run_nonce"] == "nonce"
    assert "observed_at" in evidence["observations"]["round_trip"]
    assert evidence["observations"]["round_trip"]["run_nonce"] == "nonce"
    assert "run_started_at" not in evidence
    assert "fingerprints" not in json.dumps(evidence)
    rendered = json.dumps(evidence)
    assert all(os.environ[name] not in rendered for name in CHANNEL_CREDENTIALS["feishu"])
    assert "message_body" not in json.dumps(evidence)
    assert evidence["observations"]["ambiguous"]["auto_replay_count"] == 0
    assert evidence["observations"]["ambiguous"]["drop_response_observed"] is True
    assert evidence["observations"]["reconnect"]["lock_epoch"] == 2
    assert evidence["observations"]["rate_limit_retry_after"]["retry_attempts"] == 2


def test_provider_evidence_rejects_events_outside_run_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprints = _credentials(monkeypatch)["feishu"]
    from scripts.im_online_gate import (
        CHANNEL_ACCOUNT_VARIABLE,
        PROVIDER_EVIDENCE_SOURCE,
        _fingerprint,
    )

    run_started_at = datetime.now(UTC)
    observations = _observations("feishu", "nonce")
    observations["round_trip"]["observed_at"] = (run_started_at - timedelta(seconds=10)).isoformat()
    response = {
        "credential_attestation": {
            "status": "pass",
            "run_nonce": "nonce",
            "fingerprints": fingerprints,
        },
        "provider_evidence": {
            "source": PROVIDER_EVIDENCE_SOURCE["feishu"],
            "independent_paths": ["provider_callback", "provider_send_ack"],
            "run_nonce": "nonce",
            "account_fingerprint": _fingerprint(
                "offline-feishu-account",
                label=CHANNEL_ACCOUNT_VARIABLE["feishu"],
            ),
            "observations": observations,
        },
    }
    evidence, errors = _validate_provider_evidence(
        "feishu",
        response,
        run_nonce="nonce",
        credential_fingerprints=fingerprints,
        run_started_at=run_started_at,
        now=run_started_at,
    )
    assert evidence is None
    assert any("predates this run" in error for error in errors)


@pytest.mark.parametrize(
    ("channel", "provider_code"),
    [("feishu", 230027), ("wecom", 40001)],
)
def test_provider_evidence_rejects_non_rate_limit_platform_codes(
    monkeypatch: pytest.MonkeyPatch,
    channel: str,
    provider_code: int,
) -> None:
    fingerprints = _credentials(monkeypatch)[channel]
    from scripts.im_online_gate import (
        CHANNEL_ACCOUNT_VARIABLE,
        PROVIDER_EVIDENCE_SOURCE,
        _fingerprint,
    )

    observations = _observations(channel, "nonce")
    observations["rate_limit_retry_after"]["provider_error_code"] = provider_code
    response = {
        "credential_attestation": {
            "status": "pass",
            "run_nonce": "nonce",
            "fingerprints": fingerprints,
        },
        "provider_evidence": {
            "source": PROVIDER_EVIDENCE_SOURCE[channel],
            "independent_paths": [
                "provider_callback",
                "provider_send_ack",
            ] if channel == "feishu" else ["provider_ws_event", "provider_send_ack"],
            "run_nonce": "nonce",
            "account_fingerprint": _fingerprint(
                os.environ[CHANNEL_ACCOUNT_VARIABLE[channel]],
                label=CHANNEL_ACCOUNT_VARIABLE[channel],
            ),
            "observations": observations,
        },
    }
    evidence, errors = _validate_provider_evidence(
        channel,
        response,
        run_nonce="nonce",
        credential_fingerprints=fingerprints,
    )
    assert evidence is None
    assert any("rate-limit code" in error for error in errors)


def test_provider_evidence_rejects_short_retry_timing_and_outage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprints = _credentials(monkeypatch)["feishu"]
    from scripts.im_online_gate import (
        CHANNEL_ACCOUNT_VARIABLE,
        MIN_PROLONGED_OUTAGE_SECONDS,
        PROVIDER_EVIDENCE_SOURCE,
        _fingerprint,
    )

    observations = _observations("feishu", "nonce")
    observations["rate_limit_retry_after"]["retry_elapsed_seconds"] = 0.5
    observations["prolonged_outage"]["outage_seconds"] = MIN_PROLONGED_OUTAGE_SECONDS - 1
    response = {
        "credential_attestation": {
            "status": "pass",
            "run_nonce": "nonce",
            "fingerprints": fingerprints,
        },
        "provider_evidence": {
            "source": PROVIDER_EVIDENCE_SOURCE["feishu"],
            "independent_paths": ["provider_callback", "provider_send_ack"],
            "run_nonce": "nonce",
            "account_fingerprint": _fingerprint(
                os.environ[CHANNEL_ACCOUNT_VARIABLE["feishu"]],
                label=CHANNEL_ACCOUNT_VARIABLE["feishu"],
            ),
            "observations": observations,
        },
    }
    evidence, errors = _validate_provider_evidence(
        "feishu",
        response,
        run_nonce="nonce",
        credential_fingerprints=fingerprints,
    )
    assert evidence is None
    assert any("did not honor Retry-After" in error for error in errors)
    assert any("outage_seconds" in error for error in errors)


def test_provider_evidence_requires_real_drop_response_for_ambiguous_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprints = _credentials(monkeypatch)["feishu"]
    from scripts.im_online_gate import (
        CHANNEL_ACCOUNT_VARIABLE,
        PROVIDER_EVIDENCE_SOURCE,
        _fingerprint,
    )

    observations = _observations("feishu", "nonce")
    observations["ambiguous"].pop("drop_response_observed")
    response = {
        "credential_attestation": {
            "status": "pass",
            "run_nonce": "nonce",
            "fingerprints": fingerprints,
        },
        "provider_evidence": {
            "source": PROVIDER_EVIDENCE_SOURCE["feishu"],
            "independent_paths": ["provider_callback", "provider_send_ack"],
            "run_nonce": "nonce",
            "account_fingerprint": _fingerprint(
                "offline-feishu-account",
                label=CHANNEL_ACCOUNT_VARIABLE["feishu"],
            ),
            "observations": observations,
        },
    }

    evidence, errors = _validate_provider_evidence(
        "feishu",
        response,
        run_nonce="nonce",
        credential_fingerprints=fingerprints,
    )

    assert evidence is None
    assert any("drop_response_observed" in error for error in errors)


@pytest.mark.parametrize(
    ("case", "field", "value"),
    [
        ("rate_limit_retry_after", "retry_after_seconds", float("nan")),
        ("rate_limit_retry_after", "retry_after_seconds", float("inf")),
        ("rate_limit_retry_after", "retry_after_seconds", MAX_RETRY_AFTER_SECONDS + 1),
        ("prolonged_outage", "outage_seconds", float("nan")),
        ("prolonged_outage", "outage_seconds", float("inf")),
        ("prolonged_outage", "outage_seconds", MAX_OUTAGE_SECONDS + 1),
    ],
)
def test_provider_evidence_rejects_non_finite_or_unbounded_durations(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    field: str,
    value: float,
) -> None:
    fingerprints = _credentials(monkeypatch)["feishu"]
    from scripts.im_online_gate import (
        CHANNEL_ACCOUNT_VARIABLE,
        PROVIDER_EVIDENCE_SOURCE,
        _fingerprint,
    )

    observations = _observations("feishu", "nonce")
    observations[case][field] = value
    response = {
        "credential_attestation": {
            "status": "pass",
            "run_nonce": "nonce",
            "fingerprints": fingerprints,
        },
        "provider_evidence": {
            "source": PROVIDER_EVIDENCE_SOURCE["feishu"],
            "independent_paths": ["provider_callback", "provider_send_ack"],
            "run_nonce": "nonce",
            "account_fingerprint": _fingerprint(
                "offline-feishu-account",
                label=CHANNEL_ACCOUNT_VARIABLE["feishu"],
            ),
            "observations": observations,
        },
    }
    evidence, errors = _validate_provider_evidence(
        "feishu",
        response,
        run_nonce="nonce",
        credential_fingerprints=fingerprints,
    )
    assert evidence is None
    assert any(field in error for error in errors)


def test_probe_runtime_requires_nonce_image_and_fixed_identity() -> None:
    assert (
        _validate_probe_runtime(
            {
                "status": "pass",
                "run_nonce": "nonce",
                "image_digest": "sha256:" + "a" * 64,
                "identity_fingerprint": "b" * 64,
            },
            run_nonce="nonce",
            image_digest="sha256:" + "a" * 64,
            configured_identity=None,
            identity_hash="c" * 64,
        )[0]
        is False
    )


def test_probe_runtime_accepts_report_safe_identity_hash() -> None:
    assert (
        _validate_probe_runtime(
            {
                "status": "pass",
                "run_nonce": "nonce",
                "image_digest": "sha256:" + "a" * 64,
                "identity_fingerprint": "b" * 64,
            },
            run_nonce="nonce",
            image_digest="sha256:" + "a" * 64,
            configured_identity=None,
            identity_hash="b" * 64,
        )[0]
        is True
    )


def test_wecom_group_mention_is_removed_only_when_bot_is_explicitly_mentioned() -> None:
    mentioned = parse_wecom_frame(
        {
            "body": {
                "msgid": "message-group-mention",
                "aibotid": "bot-id",
                "atuserlist": ["bot-id"],
                "chattype": "group",
                "chatid": "chat-id",
                "from": {"userid": "user-id"},
                "msgtype": "text",
                "text": {"content": "@机器人 你好"},
            }
        },
        account_id="bot-id",
    )
    assert mentioned.conversation_kind == ConversationKind.GROUP
    assert mentioned.text == "你好"

    mentioned_object = parse_wecom_frame(
        {
            "body": {
                "msgid": "message-group-mention-object",
                "aibotid": "bot-id",
                "atuserlist": [{"userid": "bot-id"}],
                "chattype": "group",
                "chatid": "chat-id",
                "from": {"userid": "user-id"},
                "msgtype": "text",
                "text": {"content": "@机器人 再见"},
            }
        },
        account_id="bot-id",
    )
    assert mentioned_object.text == "再见"

    ordinary = parse_wecom_frame(
        {
            "body": {
                "msgid": "message-group-ordinary",
                "chattype": "group",
                "chatid": "chat-id",
                "from": {"userid": "user-id"},
                "msgtype": "text",
                "text": {"content": "@all 你好"},
            }
        },
        account_id="bot-id",
    )
    assert ordinary.text == "@all 你好"


def test_wecom_media_retry_after_is_bounded_and_retryable() -> None:
    error = _http_status_error(429, "3")
    assert error.provider_code == "rate_limited"
    assert error.retryable
    assert error.retry_after_seconds == 3.0


def test_wecom_binding_signature_changes_on_secret_rotation_without_resolving_secret() -> None:
    original = ChannelBinding(
        binding_id="binding",
        tenant_id="tenant",
        app_id="app",
        channel=Channel.WECOM_AI_BOT,
        account_id="bot",
        secret_refs={"bot_secret": SecretRef(uri="env://WECOM_SECRET_V1")},
    )
    rotated = original.model_copy(
        update={
            "control_version": 2,
            "secret_refs": {"bot_secret": SecretRef(uri="env://WECOM_SECRET_V2")},
        }
    )
    assert _binding_signature(original) != _binding_signature(rotated)


def test_online_probe_pass_without_provider_originated_evidence_stays_not_run(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _credentials(monkeypatch)
    monkeypatch.setenv("TRPC_IM_ONLINE_TESTS_ENABLED", "true")
    monkeypatch.setenv("TRPC_IM_ONLINE_PROBE_URL", "https://probe.example.test")
    monkeypatch.setenv("TRPC_IM_ONLINE_PROBE_URL_ALLOWLIST", "https://probe.example.test")
    monkeypatch.setenv("TRPC_IM_ONLINE_PROBE_IDENTITY", "offline-probe-1")
    monkeypatch.setenv("TRPC_IM_ONLINE_IMAGE_DIGEST", "sha256:" + "a" * 64)
    monkeypatch.setenv("TRPC_RELEASE_ID", "release-offline-test")
    monkeypatch.setenv("TRPC_RELEASE_NONCE", "r" * 32)
    private_key = _install_probe_trust(tmp_path, monkeypatch)

    def fake_probe(_url: str, payload: dict[str, object], _timeout: float) -> dict[str, object]:
        from scripts.im_online_gate import _fingerprint

        return _sign_probe_response(
            {
                "runtime": {
                    "status": "pass",
                    "run_nonce": payload["nonce"],
                    "image_digest": "sha256:" + "a" * 64,
                    "identity_fingerprint": _fingerprint(
                        "offline-probe-1",
                        label="TRPC_IM_ONLINE_PROBE_IDENTITY",
                    ),
                },
                "cases": {case: {"status": "pass"} for case in REQUIRED_CASES},
            },
            private_key,
        )

    import scripts.im_online_gate as online_gate

    monkeypatch.setattr(online_gate, "_safe_post", fake_probe)
    output = tmp_path / "im-online.json"
    assert _run(output, timeout=1.0, require_production=True) == 1
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["gate"] == "not_run"
    assert report["production_gate"] == "not_run"
    assert any("provider_evidence" in reason for reason in report["rejection_reasons"])


def test_online_probe_requires_current_release_binding(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _credentials(monkeypatch)
    monkeypatch.setenv("TRPC_IM_ONLINE_TESTS_ENABLED", "true")
    monkeypatch.setenv("TRPC_IM_ONLINE_PROBE_URL", "https://probe.example.test")
    monkeypatch.setenv("TRPC_IM_ONLINE_PROBE_URL_ALLOWLIST", "https://probe.example.test")
    monkeypatch.setenv("TRPC_IM_ONLINE_PROBE_IDENTITY", "offline-probe-1")
    monkeypatch.setenv("TRPC_IM_ONLINE_IMAGE_DIGEST", "sha256:" + "a" * 64)
    monkeypatch.delenv("TRPC_RELEASE_ID", raising=False)
    monkeypatch.delenv("TRPC_RELEASE_NONCE", raising=False)
    _install_probe_trust(tmp_path, monkeypatch)

    output = tmp_path / "im-online.json"
    assert _run(output, timeout=1.0, require_production=True) == 1
    report = json.loads(output.read_text(encoding="utf-8"))

    assert report["gate"] == "not_run"
    assert report["production_gate"] == "not_run"
    reasons = " ".join(report["rejection_reasons"])
    assert "TRPC_RELEASE_ID" in reasons
    assert "TRPC_RELEASE_NONCE" in reasons


def test_online_report_rejects_release_binding_changed_during_probe(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _credentials(monkeypatch)
    monkeypatch.setenv("TRPC_IM_ONLINE_TESTS_ENABLED", "true")
    monkeypatch.setenv("TRPC_IM_ONLINE_PROBE_URL", "https://probe.example.test")
    monkeypatch.setenv("TRPC_IM_ONLINE_PROBE_URL_ALLOWLIST", "https://probe.example.test")
    monkeypatch.setenv("TRPC_IM_ONLINE_PROBE_IDENTITY", "offline-probe-1")
    monkeypatch.setenv("TRPC_IM_ONLINE_IMAGE_DIGEST", "sha256:" + "a" * 64)
    monkeypatch.setenv("TRPC_RELEASE_ID", "release-online-test")
    monkeypatch.setenv("TRPC_RELEASE_NONCE", "r" * 32)
    private_key = _install_probe_trust(tmp_path, monkeypatch)

    import scripts.im_online_gate as online_gate

    def fake_probe(_url: str, payload: dict[str, object], _timeout: float) -> dict[str, object]:
        monkeypatch.delenv("TRPC_RELEASE_NONCE", raising=False)
        return _sign_probe_response(
            {
                "runtime": {
                    "status": "pass",
                    "run_nonce": payload["nonce"],
                    "image_digest": "sha256:" + "a" * 64,
                    "identity_fingerprint": online_gate._fingerprint(
                        "offline-probe-1",
                        label="TRPC_IM_ONLINE_PROBE_IDENTITY",
                    ),
                },
                "cases": {case: {"status": "pass"} for case in REQUIRED_CASES},
            },
            private_key,
        )

    monkeypatch.setattr(online_gate, "_safe_post", fake_probe)
    output = tmp_path / "im-online.json"
    assert _run(output, timeout=1.0, require_production=True) == 1
    report = json.loads(output.read_text(encoding="utf-8"))

    assert report["gate"] == "not_run"
    assert any(
        "production evidence release_binding is missing" in reason
        for reason in report["rejection_reasons"]
    )


def test_online_run_without_opt_in_writes_not_run(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("TRPC_IM_ONLINE_TESTS_ENABLED", raising=False)
    output = tmp_path / "im-online.json"
    assert _run(output, timeout=1.0, require_production=False) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["gate"] == "not_run"
    assert report["production_gate"] == "not_run"
    assert all(
        case in report["candidate"]["channels"]["feishu"]["cases"] for case in REQUIRED_CASES
    )


def test_probe_trust_verifies_signed_response_and_rejects_tampering(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.im_online_gate as online_gate

    private_key = _install_probe_trust(tmp_path, monkeypatch)
    trust, reason = online_gate._load_probe_trust()
    assert reason is None
    assert trust is not None
    response = _sign_probe_response(
        {"runtime": {"status": "pass"}, "cases": {"round_trip": {"status": "pass"}}},
        private_key,
    )
    online_gate._verify_probe_signature(response, trust)
    response["runtime"] = {"status": "not_run"}
    with pytest.raises(RuntimeError, match="signature verification"):
        online_gate._verify_probe_signature(response, trust)


def test_probe_trust_rejects_duplicate_keys(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    import scripts.im_online_gate as online_gate

    deploy_root = tmp_path / "deploy"
    deploy_root.mkdir()
    trust_path = deploy_root / "im-probe-trust.json"
    trust_path.write_text(
        '{"schema_version":1,"schema_version":1,"probe_url":"https://probe.example.test",'
        '"key_id":"test","ed25519_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}',
        encoding="utf-8",
    )
    monkeypatch.setattr(online_gate, "ROOT", tmp_path)
    monkeypatch.setattr(online_gate, "PROBE_TRUST_PATH", trust_path)
    trust, reason = online_gate._load_probe_trust()
    assert trust is None
    assert reason == "probe trust file is not strict JSON"


def test_probe_trust_rejects_boolean_schema_version(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.im_online_gate as online_gate

    _install_probe_trust(tmp_path, monkeypatch)
    online_gate.PROBE_TRUST_PATH.write_text(
        json.dumps(
            {
                "schema_version": True,
                "probe_url": "https://probe.example.test",
                "key_id": "offline-test-key",
                "ed25519_public_key": base64.b64encode(bytes(range(1, 33))).decode("ascii"),
            }
        ),
        encoding="utf-8",
    )

    trust, reason = online_gate._load_probe_trust()

    assert trust is None
    assert reason == "probe trust file has an invalid schema or URL"


def test_probe_trust_rotation_changes_bound_hashes_and_missing_is_not_run(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.im_online_gate as online_gate

    first_private = _install_probe_trust(tmp_path, monkeypatch)
    first, reason = online_gate._load_probe_trust()
    assert first is not None
    assert reason is None
    second_private = Ed25519PrivateKey.generate()
    second_public = second_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    del first_private
    online_gate.PROBE_TRUST_PATH.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "probe_url": "https://probe.example.test",
                "key_id": "offline-rotated-key",
                "ed25519_public_key": base64.b64encode(second_public).decode("ascii"),
            }
        ),
        encoding="utf-8",
    )
    rotated, reason = online_gate._load_probe_trust()
    assert rotated is not None
    assert reason is None
    assert rotated["key_sha256"] != first["key_sha256"]
    assert rotated["config_sha256"] != first["config_sha256"]
    assert rotated["file_sha256"] != first["file_sha256"]

    online_gate.PROBE_TRUST_PATH.unlink()
    missing, reason = online_gate._load_probe_trust()
    assert missing is None
    assert reason == "deploy/im-probe-trust.json is missing or outside deploy"


def test_normalized_signed_response_digest_excludes_signature_and_body(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.im_online_gate as online_gate

    private_key = _install_probe_trust(tmp_path, monkeypatch)
    trust, reason = online_gate._load_probe_trust()
    assert trust is not None
    assert reason is None
    response = _sign_probe_response(
        {
            "runtime": {
                "status": "pass",
                "run_nonce": "nonce-for-digest",
                "image_digest": "sha256:" + "a" * 64,
                "identity_fingerprint": "b" * 64,
            },
            "cases": {case: {"status": "pass"} for case in REQUIRED_CASES},
            "message_body": "must not enter release evidence",
        },
        private_key,
    )
    online_gate._verify_probe_signature(response, trust)
    provider_evidence = {
        "run_nonce": "nonce-for-digest",
        "observations": {"round_trip": {"provider_event_id_hash": "c" * 64}},
    }
    first = online_gate._normalized_probe_response_sha256("feishu", response, provider_evidence)
    response["message_body"] = "different secret body"
    response["signature_attestation"]["signature"] = "not part of the digest"
    second = online_gate._normalized_probe_response_sha256("feishu", response, provider_evidence)

    assert first == second
    assert len(first) == 64
