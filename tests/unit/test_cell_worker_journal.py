from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from trpc_agent_sdk.events import Event
from trpc_agent_sdk.types import Content, Part

from trpc_service.cell.capsule import AgentCapsule
from trpc_service.cell.events import CausalEvent, CellAddress, EventDraft, InMemoryEventStore
from trpc_service.cell.worker_journal import CellRuntimeJournal
from trpc_service.channels.envelopes import InboundEnvelope, OutboundEnvelope, PayloadKind
from trpc_service.storage.models import Acceptance, CommitResult, SessionLease, SessionSnapshot
from trpc_service.tenant.models import (
    Channel,
    ConversationKind,
    ModelPolicy,
    StorageSelection,
    TenantConfig,
    TenantContext,
    ToolRisk,
)
from trpc_service.tool.governance import Decision


class MemoryProjectionStore:
    def __init__(self) -> None:
        self.events = InMemoryEventStore()
        self.capsules: dict[str, AgentCapsule] = {}
        self.append_fences: list[tuple[str | None, int | None, datetime | None]] = []

    async def ensure_capsule(
        self,
        capsule: AgentCapsule,
        *,
        trust_class: str = "deployment",
    ) -> str:
        assert trust_class == "runtime_projection"
        assert capsule.verify_digest()
        capsule.spec.validate_asset_refs()
        assert capsule.digest is not None
        self.capsules[capsule.digest] = capsule
        return capsule.digest

    async def ensure_cell(
        self,
        address: CellAddress,
        *,
        status: str = "idle",
        session_lease_owner: str | None = None,
        session_fencing_token: int | None = None,
    ) -> object:
        assert status in {"idle", "running"}
        assert (session_lease_owner is None) == (session_fencing_token is None)
        return self.events.get_branch(address)

    async def append(
        self,
        draft: EventDraft,
        *,
        lease_owner: str | None = None,
        lease_epoch: int | None = None,
        lease_expires_at: datetime | None = None,
        session_lease_owner: str | None = None,
        session_fencing_token: int | None = None,
    ) -> CausalEvent:
        assert (lease_owner is None) == (lease_epoch is None)
        assert (lease_owner is None) == (lease_expires_at is None)
        assert (session_lease_owner is None) == (session_fencing_token is None)
        assert lease_owner == session_lease_owner
        assert lease_epoch == session_fencing_token
        self.append_fences.append((lease_owner, lease_epoch, lease_expires_at))
        return await self.events.append_async(draft)


def _fixture(
    *,
    inbound_id: str = "inbound-1",
    turn_id: str = "turn-1",
    fencing_token: int = 4,
    worker_id: str = "worker-private-name",
    app_id: str = "app-a",
    session_id: str = "session-hmac-id",
) -> tuple[Acceptance, TenantConfig, SessionLease]:
    context = TenantContext(
        tenant_id="tenant-a",
        app_id=app_id,
        config_version=7,
        channel_binding_id="binding-secret-name",
        principal_id="principal-private",
        session_id=session_id,
        request_id=f"request-{turn_id}",
        trace_id="a" * 32,
    )
    acceptance = Acceptance(
        inbound_id=inbound_id,
        context=context,
        envelope=InboundEnvelope(
            channel=Channel.WECOM_AI_BOT,
            account_id="account-a",
            external_message_id=f"external-{inbound_id}",
            external_user_id="external-private-user",
            conversation_kind=ConversationKind.DIRECT,
            payload_kind=PayloadKind.TEXT,
            text="sensitive customer message",
        ),
    )
    config = TenantConfig(
        tenant_id=context.tenant_id,
        app_id=context.app_id,
        version=context.config_version,
        model=ModelPolicy(provider="offline", model="deterministic"),
        storage=StorageSelection(profile_id="profile-a"),
        instructions="private system prompt",
        policy_version=3,
    )
    lease = SessionLease(
        tenant_id=context.tenant_id,
        session_id=context.session_id,
        turn_id=turn_id,
        inbound_id=inbound_id,
        worker_id=worker_id,
        fencing_token=fencing_token,
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
        snapshot=SessionSnapshot(
            tenant_id=context.tenant_id,
            app_id=context.app_id,
            session_id=context.session_id,
            principal_id=context.principal_id,
        ),
    )
    return acceptance, config, lease


def _journal(store: MemoryProjectionStore) -> CellRuntimeJournal:
    return CellRuntimeJournal(
        store,
        capsule_signing_key=b"c" * 32,
        privacy_hash_key=b"p" * 32,
    )


@pytest.mark.asyncio
async def test_real_runner_and_tool_boundaries_form_one_private_causal_chain() -> None:
    store = MemoryProjectionStore()
    journal = _journal(store)
    acceptance, config, lease = _fixture()
    turn = await journal.begin_turn(acceptance, config, lease)

    await journal.record_agent_event(
        turn,
        Event(
            id="sdk-event-1",
            author="agent-a",
            content=Content(parts=[Part(text="private model answer")]),
        ),
    )
    token = await journal.intent_created(
        acceptance.context,
        turn_id=lease.turn_id,
        invocation_id="invocation-1",
        tool_name="refund.create",
        arguments_hash="f" * 64,
        effect_key="d" * 64,
        risk=ToolRisk.NON_IDEMPOTENT,
    )
    with pytest.raises(ValueError, match="not issued"):
        await journal.policy_decided(
            replace(token),
            decision=Decision.ALLOW,
            reason="forged-token",
        )
    await journal.policy_decided(
        token,
        decision=Decision.ALLOW,
        reason="tenant_policy_allow",
    )
    await journal.effect_completed(
        token,
        status="succeeded",
        result_hash="e" * 64,
        error_type=None,
    )
    outbound = OutboundEnvelope(
        outbound_id="outbound-private-id",
        tenant_id=acceptance.context.tenant_id,
        binding_id=acceptance.context.channel_binding_id,
        channel=acceptance.envelope.channel,
        target_id="provider-private-user",
        session_id=acceptance.context.session_id,
        text="private reply",
    )
    await journal.prepare_reply(turn, outbound)
    await journal.commit_turn(
        turn,
        CommitResult(
            turn_id=lease.turn_id,
            first_sequence=1,
            last_sequence=2,
            outbound_id=outbound.outbound_id,
        ),
    )

    events = store.events.read(turn.address)
    assert [event.event_type for event in events] == [
        "message.accepted",
        "cell.activated",
        "context.projected",
        "agent.event.observed",
        "tool.intent.created",
        "policy.decided",
        "tool.effect.committed",
        "reply.prepared",
        "turn.committed",
    ]
    store.events.verify_chain(turn.address)
    assert {event.trace_id for event in events} == {acceptance.context.trace_id}
    assert {event.request_id for event in events} == {acceptance.context.request_id}
    assert {event.correlation_id for event in events} == {lease.turn_id}
    effect_event = next(event for event in events if event.event_type == "tool.effect.committed")
    assert effect_event.payload["status"] == "succeeded"
    assert all(
        owner == lease.worker_id and epoch == lease.fencing_token and expires_at == lease.expires_at
        for owner, epoch, expires_at in store.append_fences[:-1]
    )
    assert store.append_fences[-1] == (None, None, None)
    intent_payload = next(
        event.payload for event in events if event.event_type == "tool.intent.created"
    )
    assert intent_payload["effect_key"] == "d" * 64
    assert intent_payload["intent_id"]
    rendered = json.dumps([event.to_dict() for event in events], ensure_ascii=False)
    for secret in (
        "sensitive customer message",
        "private system prompt",
        "private model answer",
        "private reply",
        "external-private-user",
        "provider-private-user",
        "binding-secret-name",
        "worker-private-name",
    ):
        assert secret not in rendered


@pytest.mark.asyncio
async def test_tool_observer_fails_closed_without_an_active_turn() -> None:
    store = MemoryProjectionStore()
    journal = _journal(store)
    acceptance, _config, lease = _fixture()

    with pytest.raises(LookupError):
        await journal.intent_created(
            acceptance.context,
            turn_id=lease.turn_id,
            invocation_id="invocation-1",
            tool_name="refund.create",
            arguments_hash="f" * 64,
            effect_key="d" * 64,
            risk=ToolRisk.IDEMPOTENT,
        )


@pytest.mark.asyncio
async def test_runtime_journal_simulated_effect_emits_simulated_event() -> None:
    store = MemoryProjectionStore()
    journal = _journal(store)
    acceptance, config, lease = _fixture()
    await journal.begin_turn(acceptance, config, lease)
    token = await journal.intent_created(
        acceptance.context,
        turn_id=lease.turn_id,
        invocation_id="invocation-simulated",
        tool_name="refund.create",
        arguments_hash="f" * 64,
        effect_key="d" * 64,
        risk=ToolRisk.NON_IDEMPOTENT,
    )

    await journal.effect_completed(
        token,
        status="simulated",
        result_hash="e" * 64,
        error_type=None,
    )

    event = store.events.read(token.address)[-1]
    assert event.event_type == "tool.effect.simulated"
    assert event.payload["status"] == "simulated"


@pytest.mark.asyncio
async def test_each_fenced_turn_records_one_traceable_cell_activation() -> None:
    store = MemoryProjectionStore()
    journal = _journal(store)
    first = _fixture(inbound_id="inbound-1", turn_id="turn-1")
    second = _fixture(inbound_id="inbound-2", turn_id="turn-2")

    first_turn = await journal.begin_turn(*first)
    await journal.fail_turn(first_turn, error_type="ModelTimeout")
    second_turn = await journal.begin_turn(*second)
    await journal.fail_turn(second_turn, error_type="ModelTimeout")

    assert first_turn.address == second_turn.address
    events = store.events.read(first_turn.address)
    assert sum(event.event_type == "cell.activated" for event in events) == 2
    assert sum(event.event_type == "message.accepted" for event in events) == 2
    assert sum(event.event_type == "turn.failed" for event in events) == 2


@pytest.mark.asyncio
async def test_event_ids_include_the_complete_cell_namespace() -> None:
    store = MemoryProjectionStore()
    journal = _journal(store)
    first = _fixture(inbound_id="same-inbound", turn_id="same-turn")
    second = _fixture(
        inbound_id="same-inbound",
        turn_id="same-turn",
        app_id="app-b",
        session_id="session-b",
    )

    first_turn = await journal.begin_turn(*first)
    await journal.fail_turn(first_turn, error_type="ModelTimeout")
    second_turn = await journal.begin_turn(*second)
    await journal.fail_turn(second_turn, error_type="ModelTimeout")

    first_ids = {event.event_id for event in store.events.read(first_turn.address)}
    second_ids = {event.event_id for event in store.events.read(second_turn.address)}
    assert first_ids.isdisjoint(second_ids)


@pytest.mark.asyncio
async def test_same_turn_recovery_uses_attempt_scoped_immutable_events() -> None:
    store = MemoryProjectionStore()
    journal = _journal(store)
    first = _fixture(turn_id="turn-recovered", fencing_token=4, worker_id="worker-a")
    retry = _fixture(turn_id="turn-recovered", fencing_token=5, worker_id="worker-b")

    first_turn = await journal.begin_turn(*first)
    await journal.fail_turn(first_turn, error_type="WorkerLost")
    retry_turn = await journal.begin_turn(*retry)
    await journal.fail_turn(retry_turn, error_type="WorkerLost")

    events = store.events.read(first_turn.address)
    assert sum(event.event_type == "message.accepted" for event in events) == 1
    assert sum(event.event_type == "context.projected" for event in events) == 2
    assert sum(event.event_type == "turn.failed" for event in events) == 2


@pytest.mark.asyncio
async def test_begin_turn_rejects_cross_namespace_config_or_lease() -> None:
    store = MemoryProjectionStore()
    journal = _journal(store)
    acceptance, config, lease = _fixture()

    with pytest.raises(ValueError, match="pinned config"):
        await journal.begin_turn(
            acceptance,
            config.model_copy(update={"tenant_id": "tenant-b"}),
            lease,
        )
    with pytest.raises(ValueError, match="session lease"):
        await journal.begin_turn(
            acceptance,
            config,
            lease.model_copy(update={"session_id": "other-session"}),
        )
