"""Meaningful edge coverage for Cell boundary state machines.

These tests exercise failure and recovery paths that are easy to miss in the
happy-path competition demo: immutable intent validation, effect fencing,
placement reservation checks, and the runtime journal's fail-closed namespace
rules.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from trpc_service.cell.effects import (
    ApprovalCredential,
    CellApprovalAuthority,
    EffectClaim,
    EffectKeyConflict,
    EffectLeaseConflict,
    EffectReceipt,
    EffectStatus,
    ExactlyOnceEffectExecutor,
    InMemoryEffectLedger,
    _approval_b64,
    _approval_json,
)
from trpc_service.cell.events import CellAddress, EventDraft
from trpc_service.cell.intents import (
    ConfirmationScope,
    IntentIntegrityError,
    IntentRisk,
    PolicyDecision,
    ToolIntent,
    _freeze_value,
    _is_frozen_value,
    stable_effect_key,
)
from trpc_service.cell.scheduler import (
    CellPlacementRequest,
    CellScheduler,
    NodeSnapshot,
    PlacementDecision,
    PlacementReservation,
)
from trpc_service.cell.worker_journal import (
    CellRuntimeJournal,
    PostgresCellCommitReconciler,
    _require_tool_token,
    _require_turn,
    _validate_turn_namespace,
)
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


def _intent(**overrides: object) -> ToolIntent:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "app_id": "app-a",
        "cell_id": "cell-a",
        "session_id": "session-a",
        "intent_id": "intent-a",
        "tool_name": "ticket.create",
        "arguments": {"subject": "hello", "labels": ["support"]},
        "policy_decision": PolicyDecision.ALLOW,
        "risk": IntentRisk.LOW,
        "principal_id": "principal-a",
        "request_id": "request-a",
        "trace_id": "trace-a",
    }
    values.update(overrides)
    return ToolIntent(**values)  # type: ignore[arg-type]


def _signed_approval(payload: dict[str, object], key: bytes) -> ApprovalCredential:
    encoded = _approval_b64(_approval_json(payload))
    signature = _approval_b64(hmac.new(key, encoded.encode("ascii"), hashlib.sha256).digest())
    return ApprovalCredential(f"{encoded}.{signature}")


def test_intent_normalization_rejects_unsupported_values_and_detects_all_drift() -> None:
    with pytest.raises(ValueError, match="unsupported policy decision"):
        PolicyDecision.parse(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unsupported intent risk"):
        IntentRisk.parse(object())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="keys must be strings"):
        _freeze_value({1: "not a JSON object"})
    assert _freeze_value((1, {"x"})) == (1, frozenset({"x"}))
    assert _is_frozen_value(frozenset({"x"}))
    assert not _is_frozen_value(object())

    for field_name, message in (
        ("metadata_hash", "metadata hash"),
        ("policy_hash", "policy hash"),
        ("effect_key", "effect key"),
    ):
        tampered = _intent(intent_id=f"tampered-{field_name}")
        object.__setattr__(tampered, field_name, "0" * 64)
        with pytest.raises(IntentIntegrityError, match=message):
            tampered.validate_integrity()

    missing_policy = _intent(intent_id="missing-policy")
    object.__setattr__(missing_policy, "policy_decision", None)
    with pytest.raises(IntentIntegrityError, match="policy decision is missing"):
        missing_policy.validate_integrity()


def test_stable_effect_key_expanded_form_validates_namespace_and_supports_hmac() -> None:
    common: dict[str, object] = {
        "tenant_id": "tenant-a",
        "cell_id": "cell-a",
        "session_id": "session-a",
        "intent_id": "intent-a",
        "tool_name": "ticket.create",
        "arguments": {"id": 1},
    }
    with pytest.raises(ValueError, match="app_id"):
        stable_effect_key(**common, app_id="")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="branch_id"):
        stable_effect_key(**common, branch_id="")  # type: ignore[arg-type]
    plain = stable_effect_key(**common)
    private = stable_effect_key(**common, key=b"k" * 32)
    assert plain != private
    assert private.startswith("trpc-agent-effect/v1:")


def test_confirmation_scope_expiry_and_malformed_intent_are_fail_closed() -> None:
    intent = _intent(intent_id="scope", risk=IntentRisk.HIGH)
    scope = intent.confirmation_scope(approved_by="operator", approval_id="approval")
    assert scope.matches(intent)
    assert scope.is_expired(now=datetime.now(UTC) - timedelta(seconds=1)) is False
    malformed = replace(scope, expires_at=object())  # type: ignore[arg-type]
    assert malformed.matches(intent) is False
    assert malformed.is_expired() is True

    tampered = _intent(intent_id="scope-tampered")
    object.__setattr__(tampered, "arguments", {"changed": True})
    assert scope.matches(tampered) is False


class _ReservationSink:
    def __init__(self) -> None:
        self.calls: list[
            tuple[CellPlacementRequest, PlacementDecision, str, float, str | None]
        ] = []

    async def reserve(
        self,
        request: CellPlacementRequest,
        decision: PlacementDecision,
        *,
        owner_id: str,
        lease_seconds: float = 30.0,
        reservation_id: str | None = None,
    ) -> PlacementReservation:
        self.calls.append((request, decision, owner_id, lease_seconds, reservation_id))
        return PlacementReservation(
            reservation_id=reservation_id or "reservation-a",
            tenant_id=request.tenant_id,
            cell_id=request.cell_id,
            node_id=decision.node_id,
            owner_id=owner_id,
            lease_epoch=1,
            expires_at=datetime.now(UTC) + timedelta(seconds=lease_seconds),
            cpu_millis=request.cpu_millis,
            memory_mb=request.memory_mb,
            decision=decision,
            app_id=request.app_id,
            session_id=request.session_id,
            capsule_digest=request.capsule_digest,
            branch_id=request.branch_id,
        )


def _placement_request() -> CellPlacementRequest:
    return CellPlacementRequest(
        cell_id="cell-a",
        tenant_id="tenant-a",
        app_id="app-a",
        session_id="session-a",
        capsule_digest="sha256:" + "a" * 64,
        cpu_millis=100,
        memory_mb=128,
    )


def _placement_node() -> NodeSnapshot:
    return NodeSnapshot(
        node_id="node-a",
        region="cn-east-1",
        capacity_cpu_millis=1000,
        observed_generation=1,
        capacity_memory_mb=1024,
        max_cells=10,
    )


def test_reservation_value_object_rejects_bad_identity_epoch_resources_and_expiry() -> None:
    request = _placement_request()
    decision = CellScheduler().place(request, [_placement_node()])
    valid = dict(
        reservation_id="reservation-a",
        tenant_id=request.tenant_id,
        cell_id=request.cell_id,
        node_id=decision.node_id,
        owner_id="worker-a",
        lease_epoch=1,
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
        cpu_millis=100,
        memory_mb=128,
        decision=decision,
        app_id=request.app_id,
        session_id=request.session_id,
        capsule_digest=request.capsule_digest,
        branch_id=request.branch_id,
    )
    assert PlacementReservation(**valid).lease_epoch == 1
    with pytest.raises(ValueError, match="reservation_id"):
        PlacementReservation(**{**valid, "reservation_id": " "})
    with pytest.raises(ValueError, match="lease_epoch"):
        PlacementReservation(**{**valid, "lease_epoch": 0})
    with pytest.raises(ValueError, match="reservation resources"):
        PlacementReservation(**{**valid, "cpu_millis": 0})
    with pytest.raises(ValueError, match="timezone-aware"):
        PlacementReservation(**{**valid, "expires_at": datetime.now()})


@pytest.mark.asyncio
async def test_place_and_reserve_validates_owner_and_lease_before_authoritative_claim() -> None:
    request = _placement_request()
    sink = _ReservationSink()
    scheduler = CellScheduler()
    with pytest.raises(ValueError, match="owner_id"):
        await scheduler.place_and_reserve(request, [_placement_node()], sink, owner_id=" ")
    with pytest.raises(ValueError, match="owner_id"):
        await scheduler.place_and_reserve(request, [_placement_node()], sink, owner_id=object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="lease_seconds"):
        await scheduler.place_and_reserve(
            request, [_placement_node()], sink, owner_id="worker", lease_seconds=0
        )
    with pytest.raises(ValueError, match="lease_seconds"):
        await scheduler.place_and_reserve(
            request,
            [_placement_node()],
            sink,
            owner_id="worker",
            lease_seconds=float("nan"),
        )
    reservation = await scheduler.place_and_reserve(
        request,
        [_placement_node()],
        sink,
        owner_id="worker",
        lease_seconds=5,
        reservation_id="reservation-requested",
    )
    assert reservation.reservation_id == "reservation-requested"
    assert sink.calls[-1][2:] == ("worker", 5, "reservation-requested")


class _PolicyOnlyLedger:
    async def get(self, _effect_key: str) -> EffectReceipt | None:
        return None

    async def record_policy(
        self,
        intent: ToolIntent,
        *,
        status: EffectStatus,
        error_type: str | None = None,
        worker_id: str | None = None,
    ) -> EffectReceipt:
        return EffectReceipt(
            intent.effect_key,
            status,
            intent_id=intent.intent_id,
            error_type=error_type,
            worker_id=worker_id,
        )


class _CompletionConflictLedger:
    def __init__(self, intent: ToolIntent) -> None:
        self.running = EffectReceipt(
            intent.effect_key,
            EffectStatus.RUNNING,
            intent_id=intent.intent_id,
            attempt=1,
        )
        self.ambiguous = replace(
            self.running,
            status=EffectStatus.AMBIGUOUS,
            error_type="lease-lost",
        )

    async def get(self, _effect_key: str) -> EffectReceipt | None:
        return self.ambiguous

    async def claim(self, *_args: object, **_kwargs: object) -> EffectClaim:
        return EffectClaim(self.running, True)

    async def complete(self, *_args: object, **_kwargs: object) -> EffectReceipt:
        raise EffectLeaseConflict("fenced completion")


@pytest.mark.asyncio
async def test_approval_parser_and_executor_fail_closed_on_malformed_scope_or_service() -> None:
    key = b"a" * 32
    authority = CellApprovalAuthority(key)
    intent = _intent(intent_id="approval-edges", risk=IntentRisk.HIGH)

    assert await authority.verify_and_consume("***.signature", intent) is False
    assert await authority.verify_and_consume(object(), intent) is False  # type: ignore[arg-type]
    assert await authority.verify_and_consume(_signed_approval({"v": 2}, key), intent) is False
    assert (
        await authority.verify_and_consume(
            _signed_approval({"v": 1, "nonce": 1, "exp": "bad", "scope": []}, key), intent
        )
        is False
    )

    credential = await authority.issue(intent, approved_by="operator", approval_id="approval")
    wrong_identity = replace(
        intent.confirmation_scope(approved_by="operator"), principal_id="other"
    )
    assert (
        await authority.verify_and_consume(credential, intent, expected_scope=wrong_identity)
        is False
    )
    wrong_approver = intent.confirmation_scope(approved_by="different")
    assert (
        await authority.verify_and_consume(credential, intent, expected_scope=wrong_approver)
        is False
    )

    class BrokenVerifier:
        async def verify_and_consume(self, *_args: object, **_kwargs: object) -> bool:
            raise RuntimeError("approval service unavailable")

    executor = ExactlyOnceEffectExecutor(
        policy_judge=lambda _intent: PolicyDecision.ALLOW,
        approval_verifier=BrokenVerifier(),  # type: ignore[arg-type]
    )
    pending = await executor.execute(intent, lambda: "must-not-run")
    assert pending.status is EffectStatus.REQUIRE_CONFIRMATION


@pytest.mark.asyncio
async def test_effect_ledger_fences_conflicts_and_bounded_waits() -> None:
    ledger = InMemoryEffectLedger()
    intent = _intent(intent_id="ledger-edges")
    claim = await ledger.claim(intent, worker_id="worker-a")
    with pytest.raises(ValueError, match="wait timeout"):
        await ledger.wait(intent.effect_key, timeout=-1)
    with pytest.raises(EffectKeyConflict):
        foreign = _intent(intent_id="foreign")
        object.__setattr__(foreign, "effect_key", intent.effect_key)
        await ledger.claim(foreign)
    await ledger.complete(
        intent,
        attempt=claim.receipt.attempt,
        status=EffectStatus.SUCCEEDED,
        result="done",
        worker_id="worker-a",
    )


@pytest.mark.asyncio
async def test_executor_constructor_aliases_simulation_and_completion_recovery() -> None:
    with pytest.raises(ValueError, match="effect lease"):
        ExactlyOnceEffectExecutor(lease_seconds=0)
    with pytest.raises(ValueError, match="worker_id"):
        ExactlyOnceEffectExecutor(worker_id="")
    with pytest.raises(ValueError, match="wait timeout"):
        ExactlyOnceEffectExecutor(wait_timeout_seconds=0)
    with pytest.raises(TypeError, match="approval_verifier"):
        ExactlyOnceEffectExecutor(approval_verifier=object(), approval_authority=object())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="policy_judge"):
        ExactlyOnceEffectExecutor(
            policy_judge=lambda _intent: PolicyDecision.ALLOW, policy_authority=object()
        )  # type: ignore[arg-type]

    intent = _intent(intent_id="executor-edges")
    executor = ExactlyOnceEffectExecutor(
        ledger=_PolicyOnlyLedger(),  # type: ignore[arg-type]
        policy_judge=lambda _intent: PolicyDecision.SIMULATE_ONLY,
    )
    simulated = await executor.execute(intent, simulate=lambda: {"would": "create"})
    assert simulated.status is EffectStatus.SIMULATED
    with pytest.raises(TypeError, match="effect or call"):
        await executor.execute(intent, lambda: None, call=lambda: None)
    with pytest.raises(TypeError, match="confirmation_scope"):
        await executor.execute(
            intent,
            confirmation_scope=ConfirmationScope("t", "c", "s", "p", "tool", "a", "e"),
            confirmation=ConfirmationScope("t", "c", "s", "p", "tool", "a", "e"),
        )
    with pytest.raises(TypeError, match="approval_credential"):
        await executor.execute(intent, approval_credential="a", approval_token="b")

    allowed = ExactlyOnceEffectExecutor(policy_judge=lambda _intent: PolicyDecision.ALLOW)
    done = await allowed.execute_or_raise(_intent(intent_id="execute-or-raise"), lambda: "ok")
    assert done.status is EffectStatus.SUCCEEDED

    conflict_intent = _intent(intent_id="completion-conflict")
    conflict_executor = ExactlyOnceEffectExecutor(
        ledger=_CompletionConflictLedger(conflict_intent),  # type: ignore[arg-type]
        policy_judge=lambda _intent: PolicyDecision.ALLOW,
    )
    recovered = await conflict_executor.execute(conflict_intent, lambda: "provider-result")
    assert recovered.status is EffectStatus.AMBIGUOUS


class _ProjectionStore:
    def __init__(self) -> None:
        self.drafts: list[EventDraft] = []

    async def ensure_capsule(self, capsule: object, *, trust_class: str = "deployment") -> str:
        assert trust_class == "runtime_projection"
        return capsule.digest or capsule.compute_digest()  # type: ignore[attr-defined]

    async def ensure_cell(self, *_args: object, **_kwargs: object) -> object:
        return None

    async def append(self, draft: EventDraft, **_kwargs: object) -> object:
        self.drafts.append(draft)
        return None


def _runtime_fixture() -> tuple[Acceptance, TenantConfig, SessionLease]:
    context = TenantContext(
        tenant_id="tenant-a",
        app_id="app-a",
        config_version=3,
        channel_binding_id="binding-a",
        principal_id="principal-a",
        session_id="session-a",
        request_id="request-a",
        trace_id="t" * 32,
    )
    acceptance = Acceptance(
        inbound_id="inbound-a",
        context=context,
        envelope=InboundEnvelope(
            channel=Channel.WECOM_AI_BOT,
            account_id="account-a",
            external_message_id="external-a",
            external_user_id="user-a",
            conversation_kind=ConversationKind.DIRECT,
            payload_kind=PayloadKind.TEXT,
            text="hello",
        ),
    )
    config = TenantConfig(
        tenant_id="tenant-a",
        app_id="app-a",
        version=3,
        model=ModelPolicy(provider="offline", model="deterministic"),
        storage=StorageSelection(profile_id="profile-a"),
        instructions="private",
        policy_version=2,
    )
    lease = SessionLease(
        tenant_id="tenant-a",
        session_id="session-a",
        turn_id="turn-a",
        inbound_id="inbound-a",
        worker_id="worker-a",
        fencing_token=1,
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
        snapshot=SessionSnapshot(
            tenant_id="tenant-a",
            app_id="app-a",
            session_id="session-a",
            principal_id="principal-a",
        ),
    )
    return acceptance, config, lease


def _runtime_journal(store: _ProjectionStore) -> CellRuntimeJournal:
    return CellRuntimeJournal(store, capsule_signing_key=b"c" * 32, privacy_hash_key=b"p" * 32)


@pytest.mark.asyncio
async def test_runtime_journal_rejects_invalid_credentials_namespace_and_stale_tool_tokens() -> (
    None
):
    store = _ProjectionStore()
    with pytest.raises(ValueError, match="privacy hash"):
        CellRuntimeJournal(store, capsule_signing_key=b"c" * 32, privacy_hash_key=b"short")
    with pytest.raises(ValueError, match="exactly 32"):
        CellRuntimeJournal(store, capsule_signing_key=b"short", privacy_hash_key=b"p" * 32)
    with pytest.raises(ValueError, match="capsule_key_id"):
        CellRuntimeJournal(
            store, capsule_signing_key=b"c" * 32, privacy_hash_key=b"p" * 32, capsule_key_id=""
        )
    with pytest.raises(ValueError, match="runtime_artifact_digest"):
        CellRuntimeJournal(
            store,
            capsule_signing_key=b"c" * 32,
            privacy_hash_key=b"p" * 32,
            runtime_artifact_digest="bad",
        )
    with pytest.raises(TypeError, match="turn token"):
        _require_turn(object())
    with pytest.raises(TypeError, match="tool token"):
        _require_tool_token(object())

    journal = _runtime_journal(store)
    acceptance, config, lease = _runtime_fixture()
    turn = await journal.begin_turn(acceptance, config, lease)
    outbound = OutboundEnvelope(
        outbound_id="outbound-a",
        tenant_id="tenant-b",
        binding_id="binding-a",
        channel=acceptance.envelope.channel,
        target_id="user-a",
        session_id="session-a",
        text="reply",
    )
    with pytest.raises(ValueError, match="active Cell namespace"):
        await journal.prepare_reply(turn, outbound)
    with pytest.raises(ValueError, match="arguments_hash"):
        await journal.intent_created(
            acceptance.context,
            turn_id=lease.turn_id,
            invocation_id="invocation-a",
            tool_name="ticket.create",
            arguments_hash="bad",
            effect_key="d" * 64,
            risk=ToolRisk.IDEMPOTENT,
        )
    with pytest.raises(ValueError, match="effect_key"):
        await journal.intent_created(
            acceptance.context,
            turn_id=lease.turn_id,
            invocation_id="invocation-a",
            tool_name="ticket.create",
            arguments_hash="d" * 64,
            effect_key="bad",
            risk=ToolRisk.IDEMPOTENT,
        )
    foreign_context = acceptance.context.model_copy(update={"principal_id": "principal-b"})
    with pytest.raises(LookupError, match="active Cell turn"):
        await journal.intent_created(
            foreign_context,
            turn_id=lease.turn_id,
            invocation_id="invocation-a",
            tool_name="ticket.create",
            arguments_hash="d" * 64,
            effect_key="e" * 64,
            risk=ToolRisk.IDEMPOTENT,
        )
    token = await journal.intent_created(
        acceptance.context,
        turn_id=lease.turn_id,
        invocation_id="invocation-b",
        tool_name="ticket.create",
        arguments_hash="d" * 64,
        effect_key="e" * 64,
        risk=ToolRisk.IDEMPOTENT,
    )
    journal._turns.clear()
    with pytest.raises(ValueError, match="active Cell turn"):
        await journal.policy_decided(token, decision=Decision.DENY, reason="stale")


def test_turn_namespace_checks_session_snapshot_identity() -> None:
    acceptance, config, lease = _runtime_fixture()
    with pytest.raises(ValueError, match="app or principal"):
        _validate_turn_namespace(
            acceptance.context,
            config,
            lease.model_copy(
                update={"snapshot": lease.snapshot.model_copy(update={"app_id": "other-app"})}
            ),
        )


class _ReconcileStore:
    def __init__(self, prepared: object | None, effects: list[dict[str, object]]) -> None:
        self.prepared = prepared
        self.effects = effects
        self.drafts: list[EventDraft] = []
        self.latest_calls: list[tuple[str, str, str]] = []
        self.effect_calls: list[tuple[str, str]] = []

    async def find_latest_by_correlation(
        self,
        tenant_id: str,
        correlation_id: str,
        *,
        event_type: str,
    ) -> object | None:
        self.latest_calls.append((tenant_id, correlation_id, event_type))
        return self.prepared

    async def find_unprojected_terminal_effects(
        self,
        tenant_id: str,
        correlation_id: str,
    ) -> list[dict[str, object]]:
        self.effect_calls.append((tenant_id, correlation_id))
        return self.effects

    async def append(self, draft: EventDraft) -> None:
        self.drafts.append(draft)


def _prepared_event() -> SimpleNamespace:
    address = CellAddress(
        tenant_id="tenant-a",
        app_id="app-a",
        cell_id="cell-a",
        session_id="session-a",
        capsule_digest="sha256:" + "a" * 64,
        branch_id="main",
    )
    return SimpleNamespace(
        tenant_id=address.tenant_id,
        app_id=address.app_id,
        cell_id=address.cell_id,
        session_id=address.session_id,
        capsule_digest=address.capsule_digest,
        branch_id=address.branch_id,
        address=address,
        causation_id="accepted-event",
        trace_id="trace-a",
        request_id="request-a",
    )


@pytest.mark.asyncio
async def test_commit_reconciler_handles_missing_and_replays_terminal_effects() -> None:
    empty = object.__new__(PostgresCellCommitReconciler)
    empty._store = _ReconcileStore(None, [])
    with pytest.raises(ValueError, match="up_to_sequence"):
        await empty.reconcile_committed_turn("tenant-a", "turn-a", up_to_sequence=-1)
    assert await empty.reconcile_committed_turn("tenant-a", "turn-a", up_to_sequence=0) is False

    prepared = _prepared_event()
    effects = [
        {
            "tenant_id": "tenant-a",
            "app_id": "app-a",
            "cell_id": "cell-a",
            "session_id": "session-a",
            "capsule_digest": "sha256:" + "a" * 64,
            "branch_id": "main",
            "intent_event_id": "intent-success",
            "effect_key": "e" * 64,
            "status": "succeeded",
            "tool_name": "ticket.create",
            "trace_id": "trace-effect",
            "request_id": None,
        },
        {
            "tenant_id": "tenant-a",
            "app_id": "app-a",
            "cell_id": "cell-a",
            "session_id": "session-a",
            "capsule_digest": "sha256:" + "a" * 64,
            "branch_id": "main",
            "intent_event_id": "intent-failed",
            "effect_key": "f" * 64,
            "status": "failed",
            "tool_name": "ticket.create",
            "trace_id": None,
            "request_id": "request-effect",
        },
        {
            "tenant_id": "tenant-a",
            "app_id": "app-a",
            "cell_id": "cell-a",
            "session_id": "session-a",
            "capsule_digest": "sha256:" + "a" * 64,
            "branch_id": "main",
            "intent_event_id": "intent-simulated",
            "effect_key": "s" * 64,
            "status": "simulated",
            "tool_name": "ticket.create",
            "trace_id": "trace-simulated",
            "request_id": "request-simulated",
        },
    ]
    store = _ReconcileStore(prepared, effects)
    reconciler = object.__new__(PostgresCellCommitReconciler)
    reconciler._store = store
    assert await reconciler.reconcile_committed_turn("tenant-a", "turn-a", up_to_sequence=9) is True
    assert store.latest_calls == [("tenant-a", "turn-a", "reply.prepared")]
    assert store.effect_calls == [("tenant-a", "turn-a")]
    assert [draft.event_type for draft in store.drafts] == [
        "tool.effect.committed",
        "tool.effect.failed",
        "tool.effect.simulated",
        "turn.committed",
    ]
    assert store.drafts[0].trace_id == "trace-effect"
    assert store.drafts[0].payload["status"] == "succeeded"
    assert store.drafts[1].request_id == "request-effect"
    assert store.drafts[2].payload["status"] == "simulated"
    assert store.drafts[-1].payload["last_sequence"] == 9


@pytest.mark.asyncio
async def test_runtime_journal_denied_effect_and_reply_keep_trace_metadata() -> None:
    store = _ProjectionStore()
    journal = _runtime_journal(store)
    acceptance, config, lease = _runtime_fixture()
    turn = await journal.begin_turn(acceptance, config, lease)
    token = await journal.intent_created(
        acceptance.context,
        turn_id=lease.turn_id,
        invocation_id="invocation-trace",
        tool_name="ticket.create",
        arguments_hash="d" * 64,
        effect_key="e" * 64,
        risk=ToolRisk.IDEMPOTENT,
    )
    await journal.policy_decided(token, decision=Decision.DENY, reason="policy")
    await journal.effect_completed(token, status="denied", result_hash=None, error_type="Denied")
    outbound = OutboundEnvelope(
        outbound_id="outbound-a",
        tenant_id="tenant-a",
        binding_id="binding-a",
        channel=acceptance.envelope.channel,
        target_id="user-a",
        session_id="session-a",
        text="reply",
    )
    await journal.prepare_reply(turn, outbound)
    await journal.commit_turn(
        turn,
        CommitResult(
            turn_id=lease.turn_id, first_sequence=1, last_sequence=4, outbound_id="outbound-a"
        ),
    )
    assert all(draft.trace_id == acceptance.context.trace_id for draft in store.drafts)
    assert all(draft.request_id == acceptance.context.request_id for draft in store.drafts)
    assert any(draft.event_type == "tool.effect.denied" for draft in store.drafts)
