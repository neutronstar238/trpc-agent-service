from __future__ import annotations

import json

from scripts.kind_im_gateway_probe import _evaluate, _signed_callback
from trpc_service.channels.base import WebhookRequest
from trpc_service.channels.feishu import FeishuAdapter
from trpc_service.config.secrets import LocalSecretProvider, SecretRef
from trpc_service.tenant.models import Channel, ChannelBinding


def test_signed_callback_is_accepted_by_production_adapter(monkeypatch) -> None:
    monkeypatch.setattr("scripts.kind_im_gateway_probe.time.time", lambda: 1_800_000_000)
    body, headers = _signed_callback(
        account_id="cli_kind_account",
        message_id="kind-message",
        verification_token="kind-token",
        encrypt_key="kind-encrypt-key",
    )
    binding = ChannelBinding(
        binding_id="kind-binding",
        tenant_id="kind-tenant",
        app_id="support",
        channel=Channel.FEISHU,
        account_id="cli_kind_account",
        secret_refs={
            "app_secret": SecretRef(uri="literal://kind-app-secret"),
            "verification_token": SecretRef(uri="literal://kind-token"),
            "encrypt_key": SecretRef(uri="literal://kind-encrypt-key"),
        },
        capabilities=frozenset({"text"}),
    )
    adapter = FeishuAdapter(
        LocalSecretProvider(allow_literal=True), wall_clock=lambda: 1_800_000_000
    )

    callback = adapter.verify_and_parse(
        WebhookRequest(method="POST", headers=headers, body=body), binding
    )

    assert callback.envelope is not None
    assert callback.envelope.external_message_id == "kind-message"
    assert callback.envelope.text == "kind idempotency probe"


def test_evaluate_requires_exactly_once_and_tenant_isolation() -> None:
    first = {
        "inbound": 1,
        "accepted_audit": 1,
        "mailboxes": 1,
        "mailbox_items": 1,
        "ready_events": 1,
        "session_digest": "a" * 64,
    }
    second = {**first, "session_digest": "b" * 64}

    passed, reasons = _evaluate(
        duplicate_statuses=[200] * 100,
        second_tenant_status=200,
        invalid_signature_status=403,
        first=first,
        second=second,
    )

    assert passed is True
    assert reasons == []


def test_evaluate_reports_each_failed_fence_without_sensitive_values() -> None:
    counts = {
        "inbound": 2,
        "accepted_audit": 0,
        "mailboxes": 0,
        "mailbox_items": 0,
        "ready_events": 0,
        "session_digest": "same",
    }

    passed, reasons = _evaluate(
        duplicate_statuses=[503],
        second_tenant_status=409,
        invalid_signature_status=200,
        first=counts,
        second=counts,
    )

    assert passed is False
    assert "cross_tenant_session_isolation_failed" in reasons
    assert "not_all_duplicate_callbacks_were_acknowledged" in reasons
    assert "invalid_signature_did_not_fail_closed" in reasons
    assert "secret" not in json.dumps(reasons).lower()
