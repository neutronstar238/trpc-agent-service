"""Behavioral tests for the durable Cell effect, placement, and approval adapters.

These tests deliberately use an asyncpg-shaped double instead of a real server.
The assertions model the business invariants at the SQL boundary: a tool effect
must have a matching causal intent and policy fact, leases are fenced by owner
and attempt, receipts are immutable, and placement/approval calls are scoped.
"""

from __future__ import annotations

import asyncio
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import asyncpg
import pytest

from trpc_service.cell.effects import (
    EffectKeyConflict,
    EffectLeaseConflict,
    EffectStatus,
)
from trpc_service.cell.events import NamespaceViolation
from trpc_service.cell.intents import IntentRisk, PolicyDecision, ToolIntent
from trpc_service.cell.postgres import (
    PostgresApprovalLedger,
    PostgresCellRepository,
    PostgresEffectLedger,
    PostgresPlacementReservationStore,
    _decision_from_json,
    _decision_json,
)
from trpc_service.cell.scheduler import (
    CellPlacementRequest,
    NodeSnapshot,
    PlacementCandidate,
    PlacementDecision,
    PlacementReservation,
    ReservationConflict,
)


class _AsyncContext:
    def __init__(self, value: object) -> None:
        self.value = value

    async def __aenter__(self) -> object:
        return self.value

    async def __aexit__(self, *args: object) -> None:
        del args


class ScriptedConnection:
    """Small deterministic asyncpg double with per-call response scripts."""

    def __init__(
        self,
        *,
        rows: Sequence[object] = (),
        values: Sequence[object] = (),
        execute_results: Sequence[object] = (),
    ) -> None:
        self.rows = list(rows)
        self.values = list(values)
        self.execute_results = list(execute_results)
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def transaction(self) -> _AsyncContext:
        return _AsyncContext(self)

    @staticmethod
    def _next(values: list[object]) -> object:
        value = values.pop(0) if values else None
        if isinstance(value, BaseException):
            raise value
        if callable(value):
            return value()
        return value

    async def execute(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        return self._next(self.execute_results) if self.execute_results else "OK"

    async def fetchval(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        return self._next(self.values)

    async def fetchrow(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        return self._next(self.rows)


class ReceiptAwareConnection(ScriptedConnection):
    """Scripted connection that models the receipt attempt predicate."""

    async def fetchrow(self, query: str, *args: object) -> object:
        row = await super().fetchrow(query, *args)
        if (
            "FROM cell_effect_receipts" in query
            and "AND attempt=$3" in query
            and isinstance(row, Mapping)
            and len(args) >= 3
            and row.get("attempt") != args[2]
        ):
            return None
        return row


class _CommitTrackingTransaction(_AsyncContext):
    def __init__(self, value: object) -> None:
        super().__init__(value)
        self.exit_args: tuple[object, ...] | None = None

    async def __aexit__(self, *args: object) -> None:
        self.exit_args = args


class CommitTrackingConnection(ReceiptAwareConnection):
    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.transaction_context: _CommitTrackingTransaction | None = None

    def transaction(self) -> _CommitTrackingTransaction:
        self.transaction_context = _CommitTrackingTransaction(self)
        return self.transaction_context


class RecordingPool:
    def __init__(self, connection: ScriptedConnection) -> None:
        self.connection = connection

    def acquire(self) -> _AsyncContext:
        return _AsyncContext(self.connection)


def make_intent(
    *,
    tenant_id: str = "tenant-a",
    app_id: str = "app-a",
    cell_id: str = "cell-a",
    session_id: str = "session-a",
    branch_id: str = "main",
    intent_id: str = "intent-a",
    policy_decision: PolicyDecision = PolicyDecision.ALLOW,
    risk: IntentRisk = IntentRisk.LOW,
) -> ToolIntent:
    return ToolIntent(
        tenant_id=tenant_id,
        app_id=app_id,
        cell_id=cell_id,
        session_id=session_id,
        capsule_digest="sha256:" + "a" * 64,
        branch_id=branch_id,
        intent_id=intent_id,
        tool_name="ticket.create",
        arguments={"subject": "safe"},
        policy_decision=policy_decision,
        risk=risk,
        trace_id="trace-a",
        request_id="request-a",
    )


def causal_event(
    intent: ToolIntent,
    *,
    payload: Mapping[str, object] | str | object | None = None,
    **overrides: object,
) -> dict[str, object]:
    event_payload: object = payload
    if event_payload is None:
        event_payload = {
            "intent_id": intent.intent_id,
            "tool_name": intent.tool_name,
            "arguments_hash": intent.arguments_hash,
            "effect_key": intent.effect_key,
            "risk": str(intent.risk),
        }
    return {
        "tenant_id": intent.tenant_id,
        "app_id": intent.app_id,
        "cell_id": intent.cell_id,
        "session_id": intent.session_id,
        "capsule_digest": intent.capsule_digest,
        "branch_id": intent.branch_id,
        "sequence": 4,
        "event_id": "intent-event-a",
        "payload": event_payload,
        **overrides,
    }


def persisted_intent(intent: ToolIntent, **overrides: object) -> dict[str, object]:
    return {
        "tenant_id": intent.tenant_id,
        "intent_id": intent.intent_id,
        "app_id": intent.app_id,
        "cell_id": intent.cell_id,
        "session_id": intent.session_id,
        "capsule_digest": intent.capsule_digest,
        "branch_id": intent.branch_id,
        "sequence": 4,
        "tool_name": intent.tool_name,
        "arguments_hash": intent.arguments_hash,
        "effect_key": intent.effect_key,
        "risk": str(intent.risk),
        "decision": str(intent.policy_decision),
        **overrides,
    }


def ledger_row(
    intent: ToolIntent,
    *,
    status: EffectStatus = EffectStatus.RUNNING,
    attempt: int = 1,
    worker_id: str | None = "worker-a",
    expires_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> dict[str, object]:
    now = updated_at or datetime.now(UTC)
    return {
        "effect_key": intent.effect_key,
        "intent_id": intent.intent_id,
        "status": status.value,
        "attempt": attempt,
        "lease_owner": worker_id,
        "lease_epoch": attempt,
        "lease_expires_at": expires_at,
        "updated_at": now,
        "tenant_id": intent.tenant_id,
        "app_id": intent.app_id,
        "cell_id": intent.cell_id,
        "session_id": intent.session_id,
        "capsule_digest": intent.capsule_digest,
        "branch_id": intent.branch_id,
    }


def pending_ledger_row(intent: ToolIntent) -> dict[str, object]:
    """The durable placeholder created before a first claim is locked."""

    return ledger_row(
        intent,
        status=EffectStatus.PENDING,
        attempt=0,
        worker_id=None,
        expires_at=None,
    )


def receipt_row(
    intent: ToolIntent,
    *,
    status: EffectStatus,
    attempt: int,
    worker_id: str | None = "worker-a",
    error_type: str | None = None,
    completed_at: datetime | None = None,
) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "effect_key": intent.effect_key,
        "intent_id": intent.intent_id,
        "status": status.value,
        "attempt": attempt,
        "worker_id": worker_id,
        "error_type": error_type,
        "attempted_at": now,
        "updated_at": now,
        "completed_at": completed_at,
        "trace_id": intent.trace_id,
    }


def ensure_rows(
    intent: ToolIntent,
    *,
    existing: Mapping[str, object] | None = None,
    persisted: Mapping[str, object] | None = None,
    event: Mapping[str, object] | None = None,
) -> list[object]:
    """Rows consumed by ``_ensure_intent`` for an existing/new intent."""
    rows: list[object] = [dict(event or causal_event(intent))]
    rows.append(dict(existing) if existing is not None else None)
    if existing is None:
        rows.append(dict(persisted or persisted_intent(intent)))
    return rows


def placement_request() -> CellPlacementRequest:
    return CellPlacementRequest(
        cell_id="cell-a",
        tenant_id="tenant-a",
        capsule_digest="sha256:" + "a" * 64,
        app_id="app-a",
        session_id="session-a",
        branch_id="main",
        cpu_millis=100,
        memory_mb=128,
    )


def placement_decision(cell_id: str = "cell-a") -> PlacementDecision:
    winner = PlacementCandidate(
        node_id="node-a",
        score=0.9,
        component_scores=(("load", 0.8), ("locality", 1.0)),
        reasons=("healthy",),
    )
    return PlacementDecision(
        cell_id=cell_id,
        node_id="node-a",
        score=0.9,
        candidates=(winner,),
        rejected=(("node-b", "draining"),),
    )


def reservation_row(
    request: CellPlacementRequest,
    decision: PlacementDecision,
    *,
    reservation_id: str = "11111111-1111-1111-1111-111111111111",
    lease_epoch: int = 1,
) -> dict[str, object]:
    return {
        "reservation_id": UUID(reservation_id),
        "lease_epoch": lease_epoch,
        "expires_at": datetime.now(UTC) + timedelta(seconds=30),
        "decision": json.dumps(_decision_json(decision)),
        "tenant_id": request.tenant_id,
        "app_id": request.app_id,
        "cell_id": request.cell_id,
        "session_id": request.session_id,
        "capsule_digest": request.capsule_digest,
        "branch_id": request.branch_id,
        "node_id": decision.node_id,
        "owner_id": "scheduler-a",
        "cpu_millis": request.cpu_millis,
        "memory_mb": request.memory_mb,
    }


@pytest.mark.asyncio
async def test_effect_ledger_scope_and_integrity_guards() -> None:
    with pytest.raises(ValueError, match="tenant_id"):
        PostgresEffectLedger(RecordingPool(ScriptedConnection()), tenant_id=" ")

    intent = make_intent()
    ledger = PostgresEffectLedger(RecordingPool(ScriptedConnection()), tenant_id="tenant-a")
    with pytest.raises(NamespaceViolation, match="tenant"):
        ledger._assert_tenant("tenant-b")

    object.__setattr__(intent, "arguments_hash", "tampered")
    connection = ScriptedConnection()
    with pytest.raises(EffectKeyConflict, match="integrity"):
        await ledger._ensure_intent(connection, intent)  # type: ignore[arg-type]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("event", "values", "message"),
    [
        (None, (), "must be journaled"),
        ("namespace", (), "namespace"),
        ("bad-json", (1,), "valid JSON"),
        ("scalar", (1,), "object"),
        ("payload-mismatch", (1,), "causal event payload"),
        ("no-policy", (0,), "policy decision"),
    ],
)
async def test_ensure_intent_rejects_missing_or_tampered_causal_facts(
    event: str | None,
    values: Sequence[object],
    message: str,
) -> None:
    intent = make_intent()
    if event is None:
        rows: list[object] = [None]
    elif event == "namespace":
        rows = [causal_event(intent, app_id="another-app")]
    elif event == "bad-json":
        rows = [causal_event(intent, payload="{not-json")]
    elif event == "scalar":
        rows = [causal_event(intent, payload=["not", "an", "object"])]
    elif event == "payload-mismatch":
        rows = [
            causal_event(intent, payload={"intent_id": intent.intent_id, "effect_key": "other"})
        ]
    else:
        rows = [causal_event(intent)]
    ledger = PostgresEffectLedger(
        RecordingPool(ScriptedConnection(rows=rows, values=values)),
        tenant_id=intent.tenant_id,
    )
    with pytest.raises((EffectKeyConflict, NamespaceViolation), match=message):
        await ledger._ensure_intent(ledger.pool.connection, intent)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_ensure_intent_persists_once_and_detects_existing_content_conflict() -> None:
    intent = make_intent()
    connection = ScriptedConnection(
        rows=ensure_rows(intent),
        values=[1],
    )
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)
    stored = await ledger._ensure_intent(connection, intent)  # type: ignore[arg-type]
    assert stored["intent_id"] == intent.intent_id
    assert any("INSERT INTO cell_tool_intents" in query for query, _ in connection.calls)

    conflict = persisted_intent(intent, tool_name="ticket.delete")
    conflict_connection = ScriptedConnection(
        rows=ensure_rows(intent, existing=conflict),
        values=[1],
    )
    conflict_ledger = PostgresEffectLedger(
        RecordingPool(conflict_connection), tenant_id=intent.tenant_id
    )
    with pytest.raises(EffectKeyConflict, match="different immutable"):
        await conflict_ledger._ensure_intent(conflict_connection, intent)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_ensure_intent_fails_if_insert_is_not_visible_after_commit() -> None:
    intent = make_intent()
    connection = ScriptedConnection(
        rows=[*ensure_rows(intent)[:2], None],
        values=[1],
    )
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)
    with pytest.raises(EffectKeyConflict, match="could not be persisted"):
        await ledger._ensure_intent(connection, intent)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_effect_get_distinguishes_missing_and_content_free_receipt() -> None:
    intent = make_intent()
    missing_connection = ScriptedConnection(rows=[None])
    missing = PostgresEffectLedger(RecordingPool(missing_connection), tenant_id=intent.tenant_id)
    assert await missing.get(intent.effect_key) is None

    now = datetime.now(UTC)
    row = ledger_row(intent, status=EffectStatus.SUCCEEDED, attempt=2, worker_id=None)
    row["updated_at"] = now
    content_free = receipt_row(
        intent, status=EffectStatus.SUCCEEDED, attempt=2, worker_id="provider-42"
    )
    found_connection = ScriptedConnection(rows=[row, content_free])
    found = PostgresEffectLedger(RecordingPool(found_connection), tenant_id=intent.tenant_id)
    result = await found.get(intent.effect_key)
    assert result is not None
    assert result.status is EffectStatus.SUCCEEDED
    assert result.replayed is True
    assert result.result is None
    assert result.worker_id == "provider-42"


@pytest.mark.asyncio
async def test_claim_new_effect_creates_fenced_lease_and_returns_acquired() -> None:
    intent = make_intent()
    now = datetime.now(UTC)
    running = ledger_row(intent, expires_at=now + timedelta(seconds=60), updated_at=now)
    connection = ScriptedConnection(
        rows=[*ensure_rows(intent), pending_ledger_row(intent), None, running, None],
        values=[1, now],
    )
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)
    claim = await ledger.claim(intent, worker_id="worker-a", lease_seconds=15)
    assert claim.acquired is True
    assert claim.receipt.status is EffectStatus.RUNNING
    assert claim.receipt.worker_id == "worker-a"
    insert = next(
        query for query, _ in connection.calls if "INSERT INTO cell_effect_ledger" in query
    )
    assert "clock_timestamp()" in insert
    assert "DO NOTHING" in insert
    assert "DO UPDATE" not in insert
    lock_index = next(
        index
        for index, (query, _) in enumerate(connection.calls)
        if "cell_effect_ledger" in query and "FOR UPDATE" in query
    )
    update_index = next(
        index
        for index, (query, _) in enumerate(connection.calls)
        if "UPDATE cell_effect_ledger" in query
    )
    insert_index = next(
        index
        for index, (query, _) in enumerate(connection.calls)
        if "INSERT INTO cell_effect_ledger" in query
    )
    assert insert_index < lock_index < update_index


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "confirmation_valid", "manual_replay"),
    [
        (EffectStatus.SUCCEEDED, False, False),
        (EffectStatus.SIMULATED, False, False),
        (EffectStatus.DENIED, False, False),
        (EffectStatus.REQUIRE_CONFIRMATION, False, False),
        (EffectStatus.AMBIGUOUS, False, False),
        (EffectStatus.UNKNOWN, False, True),
        (EffectStatus.RUNNING, False, False),
    ],
)
async def test_claim_returns_existing_non_acquired_states(
    status: EffectStatus,
    confirmation_valid: bool,
    manual_replay: bool,
) -> None:
    intent = make_intent()
    now = datetime.now(UTC)
    expires = now + timedelta(seconds=30) if status is EffectStatus.RUNNING else None
    row = ledger_row(intent, status=status, expires_at=expires, updated_at=now)
    latest = receipt_row(intent, status=status, attempt=1)
    connection = ScriptedConnection(
        rows=[*ensure_rows(intent, existing=persisted_intent(intent)), row, latest],
        values=[1, now],
    )
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)
    claim = await ledger.claim(
        intent,
        worker_id="worker-a",
        confirmation_valid=confirmation_valid,
        manual_replay=manual_replay,
    )
    assert claim.acquired is False
    assert claim.receipt.status is status


@pytest.mark.asyncio
async def test_claim_requires_confirmation_and_manual_replay_before_new_attempt() -> None:
    intent = make_intent()
    now = datetime.now(UTC)
    current = ledger_row(
        intent,
        status=EffectStatus.REQUIRE_CONFIRMATION,
        attempt=2,
        expires_at=None,
        updated_at=now,
    )
    latest = receipt_row(intent, status=EffectStatus.REQUIRE_CONFIRMATION, attempt=2)
    running = ledger_row(
        intent,
        status=EffectStatus.RUNNING,
        attempt=3,
        worker_id="cell-effect-worker",
        expires_at=now + timedelta(20),
    )
    rows = [
        *ensure_rows(intent, existing=persisted_intent(intent)),
        current,
        latest,
        running,
        None,
    ]
    # First call is denied without exact confirmation.  The second call has a
    # fresh connection script in a separate ledger so both paths are explicit.
    connection = ScriptedConnection(
        rows=[*ensure_rows(intent, existing=persisted_intent(intent)), current, latest],
        values=[1, now],
    )
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)
    denied = await ledger.claim(intent, confirmation_valid=False)
    assert denied.acquired is False

    approved_connection = ScriptedConnection(rows=rows, values=[1, now])
    approved_ledger = PostgresEffectLedger(
        RecordingPool(approved_connection), tenant_id=intent.tenant_id
    )
    approved = await approved_ledger.claim(intent, confirmation_valid=True)
    assert approved.acquired is True
    assert approved.receipt.attempt == 3

    ambiguous = ledger_row(intent, status=EffectStatus.AMBIGUOUS, attempt=1, updated_at=now)
    ambiguous_receipt = receipt_row(intent, status=EffectStatus.AMBIGUOUS, attempt=1)
    manual_connection = ScriptedConnection(
        rows=[
            *ensure_rows(intent, existing=persisted_intent(intent)),
            ambiguous,
            ambiguous_receipt,
        ],
        values=[1, now],
    )
    manual_ledger = PostgresEffectLedger(
        RecordingPool(manual_connection), tenant_id=intent.tenant_id
    )
    replay_blocked = await manual_ledger.claim(intent, manual_replay=True, confirmation_valid=False)
    assert replay_blocked.acquired is False

    replay_running = ledger_row(
        intent,
        status=EffectStatus.RUNNING,
        attempt=2,
        worker_id="worker-replay",
        expires_at=now + timedelta(seconds=30),
        updated_at=now,
    )
    replay_connection = ScriptedConnection(
        rows=[
            *ensure_rows(intent, existing=persisted_intent(intent)),
            ambiguous,
            ambiguous_receipt,
            replay_running,
            None,
        ],
        values=[1, now],
    )
    replay_ledger = PostgresEffectLedger(
        RecordingPool(replay_connection), tenant_id=intent.tenant_id
    )
    replayed = await replay_ledger.claim(
        intent,
        manual_replay=True,
        confirmation_valid=True,
        worker_id="worker-replay",
    )
    assert replayed.acquired is True
    assert replayed.receipt.attempt == 2


@pytest.mark.asyncio
async def test_claim_marks_expired_running_lease_ambiguous() -> None:
    intent = make_intent()
    now = datetime.now(UTC)
    expired = ledger_row(intent, expires_at=now - timedelta(seconds=1), updated_at=now)
    old_receipt = receipt_row(intent, status=EffectStatus.RUNNING, attempt=1)
    ambiguous = ledger_row(
        intent, status=EffectStatus.AMBIGUOUS, attempt=1, worker_id=None, updated_at=now
    )
    new_receipt = receipt_row(
        intent,
        status=EffectStatus.AMBIGUOUS,
        attempt=1,
        worker_id="worker-a",
        error_type="effect_lease_expired",
    )
    connection = ScriptedConnection(
        rows=[
            *ensure_rows(intent, existing=persisted_intent(intent)),
            expired,
            old_receipt,
            persisted_intent(intent),
            ambiguous,
            new_receipt,
        ],
        values=[1, now],
    )
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)
    claim = await ledger.claim(intent, worker_id="worker-a")
    assert claim.acquired is False
    assert claim.receipt.status is EffectStatus.AMBIGUOUS
    assert claim.receipt.error_type == "effect_lease_expired"


@pytest.mark.asyncio
async def test_claim_validates_lease_and_detects_missing_ledger_row() -> None:
    intent = make_intent()
    ledger = PostgresEffectLedger(RecordingPool(ScriptedConnection()), tenant_id=intent.tenant_id)
    with pytest.raises(ValueError, match="lease"):
        await ledger.claim(intent, lease_seconds=0)

    now = datetime.now(UTC)
    connection = ScriptedConnection(
        rows=[*ensure_rows(intent), None, None],
        values=[1, now],
    )
    missing_ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)
    with pytest.raises(EffectKeyConflict, match="not created"):
        await missing_ledger.claim(intent)


@pytest.mark.asyncio
async def test_claim_fails_closed_for_non_executable_policy_decisions() -> None:
    connection = ScriptedConnection()
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id="tenant-a")

    for decision in (PolicyDecision.DENY, PolicyDecision.SIMULATE_ONLY):
        with pytest.raises(EffectLeaseConflict, match="does not authorize"):
            await ledger.claim(make_intent(policy_decision=decision))
    with pytest.raises(EffectLeaseConflict, match="validated confirmation"):
        await ledger.claim(make_intent(policy_decision=PolicyDecision.REQUIRE_CONFIRMATION))
    assert connection.calls == []


@pytest.mark.asyncio
async def test_claim_fails_closed_when_database_clock_is_missing() -> None:
    intent = make_intent()
    connection = ScriptedConnection(
        rows=[
            *ensure_rows(intent, existing=persisted_intent(intent)),
            pending_ledger_row(intent),
            None,
        ],
        values=[1, None],
    )
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)
    with pytest.raises(EffectLeaseConflict, match="lease clock"):
        await ledger.claim(intent)

    with pytest.raises(ValueError, match="lease"):
        await ledger.claim(intent, lease_seconds=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="lease"):
        await ledger.claim(intent, lease_seconds="15")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_record_policy_writes_denial_receipt_and_returns_existing_state() -> None:
    intent = make_intent(policy_decision=PolicyDecision.DENY)
    denied_row = ledger_row(intent, status=EffectStatus.DENIED, attempt=0, worker_id=None)
    denied_receipt = receipt_row(
        intent, status=EffectStatus.DENIED, attempt=0, worker_id="policy-worker"
    )
    connection = ScriptedConnection(
        rows=[
            *ensure_rows(intent),
            pending_ledger_row(intent),
            persisted_intent(intent),
            denied_row,
            denied_receipt,
        ],
        values=[1],
    )
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)
    receipt = await ledger.record_policy(
        intent,
        status=EffectStatus.DENIED,
        error_type="tool_not_allowed",
        worker_id="policy-worker",
    )
    assert receipt.status is EffectStatus.DENIED
    assert receipt.attempt == 0
    assert any("INSERT INTO cell_effect_receipts" in query for query, _ in connection.calls)

    existing_intent = make_intent(policy_decision=PolicyDecision.SIMULATE_ONLY)
    existing = ledger_row(existing_intent, status=EffectStatus.SIMULATED, attempt=0, worker_id=None)
    existing_receipt = receipt_row(existing_intent, status=EffectStatus.SIMULATED, attempt=0)
    existing_connection = ScriptedConnection(
        rows=[
            *ensure_rows(existing_intent, existing=persisted_intent(existing_intent)),
            existing,
            existing_receipt,
        ],
        values=[1],
    )
    existing_ledger = PostgresEffectLedger(
        RecordingPool(existing_connection), tenant_id=intent.tenant_id
    )
    found = await existing_ledger.record_policy(
        existing_intent,
        status=EffectStatus.SIMULATED,
        worker_id="policy-worker",
    )
    assert found.status is EffectStatus.SIMULATED


@pytest.mark.asyncio
async def test_record_policy_rejects_wrong_status_worker_and_missing_insert() -> None:
    intent = make_intent()
    ledger = PostgresEffectLedger(RecordingPool(ScriptedConnection()), tenant_id=intent.tenant_id)
    with pytest.raises(ValueError, match="worker_id"):
        await ledger.record_policy(intent, status=EffectStatus.DENIED)
    with pytest.raises(ValueError, match="policy records"):
        await ledger.record_policy(intent, status=EffectStatus.SUCCEEDED, worker_id="policy-worker")

    missing_intent = make_intent(policy_decision=PolicyDecision.DENY)
    connection = ScriptedConnection(
        rows=[*ensure_rows(missing_intent), None, persisted_intent(missing_intent), None],
        values=[1],
    )
    missing = PostgresEffectLedger(RecordingPool(connection), tenant_id=missing_intent.tenant_id)
    with pytest.raises(EffectKeyConflict, match="policy ledger row"):
        await missing.record_policy(
            missing_intent,
            status=EffectStatus.DENIED,
            worker_id="policy-worker",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("decision", "status"),
    [
        (PolicyDecision.ALLOW, EffectStatus.DENIED),
        (PolicyDecision.DENY, EffectStatus.SIMULATED),
    ],
)
async def test_record_policy_requires_status_to_match_intent_decision(
    decision: PolicyDecision,
    status: EffectStatus,
) -> None:
    intent = make_intent(policy_decision=decision)
    connection = ScriptedConnection()
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)

    with pytest.raises(ValueError, match="does not match"):
        await ledger.record_policy(intent, status=status, worker_id="policy-worker")

    assert connection.calls == []


def complete_script(
    intent: ToolIntent,
    *,
    current_status: EffectStatus = EffectStatus.RUNNING,
    current_attempt: int = 1,
    current_worker: str | None = "worker-a",
    current_expiry: datetime | None = None,
    completed: object = "effect-key",
    expired: object = None,
    final_row: Mapping[str, object] | object | None = "default",
    final_receipt: Mapping[str, object] | None = None,
) -> tuple[list[object], list[object]]:
    now = datetime.now(UTC)
    current = ledger_row(
        intent,
        status=current_status,
        attempt=current_attempt,
        worker_id=current_worker,
        expires_at=current_expiry or (now + timedelta(seconds=30)),
        updated_at=now,
    )
    current_receipt = receipt_row(
        intent,
        status=current_status,
        attempt=current_attempt,
        worker_id=current_worker,
    )
    rows: list[object] = [
        *ensure_rows(intent, existing=persisted_intent(intent)),
        current,
        current_receipt,
    ]
    values: list[object] = [1, completed]
    if completed is None and expired is not None:
        values.append(expired)
        rows.append(persisted_intent(intent))
    if completed is not None:
        if final_row == "default":
            final_row = ledger_row(
                intent,
                status=EffectStatus.SUCCEEDED,
                attempt=current_attempt,
                worker_id=None,
                expires_at=None,
                updated_at=now,
            )
        # Completion writes a receipt using the persisted intent namespace
        # before re-reading the final ledger row.
        rows.append(persisted_intent(intent))
        rows.append(final_row)
        if final_row is not None:
            rows.append(
                final_receipt
                or receipt_row(intent, status=EffectStatus.SUCCEEDED, attempt=current_attempt)
            )
    return rows, values


@pytest.mark.asyncio
async def test_complete_success_is_owner_attempt_and_clock_fenced() -> None:
    intent = make_intent()
    rows, values = complete_script(
        intent, final_receipt=receipt_row(intent, status=EffectStatus.SUCCEEDED, attempt=1)
    )
    connection = ScriptedConnection(rows=rows, values=values)
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)
    result = await ledger.complete(
        intent,
        attempt=1,
        status=EffectStatus.SUCCEEDED,
        result={"ticket_id": "T-42"},
        worker_id="worker-a",
    )
    assert result.status is EffectStatus.SUCCEEDED
    assert result.result is None
    assert result.worker_id == "worker-a"
    completion = next(
        query for query, _ in connection.calls if "UPDATE cell_effect_ledger" in query
    )
    assert "attempt=$4" in completion
    assert "lease_owner=$5" in completion
    assert "clock_timestamp()" in completion


@pytest.mark.asyncio
async def test_complete_retry_uses_current_attempt_owner_without_a_new_receipt() -> None:
    intent = make_intent()
    now = datetime.now(UTC)
    current = ledger_row(
        intent,
        status=EffectStatus.RUNNING,
        attempt=2,
        worker_id="worker-b",
        expires_at=now + timedelta(seconds=30),
        updated_at=now,
    )
    previous_receipt = receipt_row(
        intent,
        status=EffectStatus.FAILED,
        attempt=1,
        worker_id="worker-a",
    )
    rows = [
        *ensure_rows(intent, existing=persisted_intent(intent)),
        current,
        previous_receipt,
        persisted_intent(intent),
        ledger_row(
            intent,
            status=EffectStatus.SUCCEEDED,
            attempt=2,
            worker_id=None,
            expires_at=None,
            updated_at=now,
        ),
        receipt_row(intent, status=EffectStatus.SUCCEEDED, attempt=2, worker_id="worker-b"),
    ]
    connection = ReceiptAwareConnection(rows=rows, values=[1, "effect-key"])
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)

    result = await ledger.complete(
        intent,
        attempt=2,
        status=EffectStatus.SUCCEEDED,
        worker_id="worker-b",
    )

    assert result.status is EffectStatus.SUCCEEDED
    assert result.attempt == 2
    assert result.worker_id == "worker-b"
    receipt_query = next(
        query for query, _ in connection.calls if "FROM cell_effect_receipts" in query
    )
    assert "AND attempt=$3" in receipt_query


@pytest.mark.asyncio
async def test_expired_retry_uses_current_attempt_owner_before_marking_ambiguous() -> None:
    intent = make_intent()
    now = datetime.now(UTC)
    current = ledger_row(
        intent,
        status=EffectStatus.RUNNING,
        attempt=2,
        worker_id="worker-b",
        expires_at=now - timedelta(seconds=1),
        updated_at=now,
    )
    previous_receipt = receipt_row(
        intent,
        status=EffectStatus.FAILED,
        attempt=1,
        worker_id="worker-a",
    )
    rows = [
        *ensure_rows(intent, existing=persisted_intent(intent)),
        current,
        previous_receipt,
        persisted_intent(intent),
    ]
    connection = CommitTrackingConnection(rows=rows, values=[1, None, "effect-key"])
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)

    with pytest.raises(EffectLeaseConflict, match="expired"):
        await ledger.complete(
            intent,
            attempt=2,
            status=EffectStatus.SUCCEEDED,
            worker_id="worker-b",
        )

    expiration_update = next(
        query for query, _ in connection.calls if "SET status='ambiguous'" in query
    )
    assert "AND attempt=$3" in expiration_update
    assert connection.transaction_context is not None
    assert connection.transaction_context.exit_args is not None
    assert connection.transaction_context.exit_args[0] is None


@pytest.mark.asyncio
async def test_complete_is_idempotent_for_same_terminal_attempt() -> None:
    intent = make_intent()
    terminal = ledger_row(intent, status=EffectStatus.SUCCEEDED, attempt=1, worker_id=None)
    terminal_receipt = receipt_row(
        intent, status=EffectStatus.SUCCEEDED, attempt=1, worker_id="worker-a"
    )
    connection = ScriptedConnection(
        rows=[*ensure_rows(intent, existing=persisted_intent(intent)), terminal, terminal_receipt],
        values=[1],
    )
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)
    result = await ledger.complete(
        intent,
        attempt=1,
        status=EffectStatus.SUCCEEDED,
        worker_id="worker-a",
    )
    assert result.status is EffectStatus.SUCCEEDED
    assert not any("UPDATE cell_effect_ledger" in query for query, _ in connection.calls)


@pytest.mark.asyncio
async def test_complete_rejects_missing_or_fenced_claims() -> None:
    intent = make_intent()
    ledger = PostgresEffectLedger(RecordingPool(ScriptedConnection()), tenant_id=intent.tenant_id)
    with pytest.raises(ValueError, match="worker_id"):
        await ledger.complete(intent, attempt=1, status=EffectStatus.SUCCEEDED)
    with pytest.raises(ValueError, match="completion"):
        await ledger.complete(
            intent,
            attempt=1,
            status=EffectStatus.SIMULATED,
            worker_id="worker-a",
        )

    missing_connection = ScriptedConnection(
        rows=[*ensure_rows(intent, existing=persisted_intent(intent)), None],
        values=[1],
    )
    missing = PostgresEffectLedger(RecordingPool(missing_connection), tenant_id=intent.tenant_id)
    with pytest.raises(EffectLeaseConflict, match="not claimed"):
        await missing.complete(
            intent,
            attempt=1,
            status=EffectStatus.FAILED,
            worker_id="worker-a",
        )

    now = datetime.now(UTC)
    stale_attempt = ledger_row(
        intent, status=EffectStatus.RUNNING, attempt=2, expires_at=now + timedelta(30)
    )
    stale_receipt = receipt_row(intent, status=EffectStatus.RUNNING, attempt=2)
    stale_connection = ScriptedConnection(
        rows=[
            *ensure_rows(intent, existing=persisted_intent(intent)),
            stale_attempt,
            stale_receipt,
        ],
        values=[1],
    )
    stale = PostgresEffectLedger(RecordingPool(stale_connection), tenant_id=intent.tenant_id)
    with pytest.raises(EffectLeaseConflict, match="attempt"):
        await stale.complete(
            intent,
            attempt=1,
            status=EffectStatus.FAILED,
            worker_id="worker-a",
        )

    wrong_owner = ledger_row(intent, status=EffectStatus.RUNNING, attempt=1, worker_id="worker-b")
    wrong_owner_receipt = receipt_row(
        intent, status=EffectStatus.RUNNING, attempt=1, worker_id="worker-b"
    )
    owner_connection = ScriptedConnection(
        rows=[
            *ensure_rows(intent, existing=persisted_intent(intent)),
            wrong_owner,
            wrong_owner_receipt,
        ],
        values=[1],
    )
    owner = PostgresEffectLedger(RecordingPool(owner_connection), tenant_id=intent.tenant_id)
    with pytest.raises(EffectLeaseConflict, match="worker"):
        await owner.complete(
            intent,
            attempt=1,
            status=EffectStatus.FAILED,
            worker_id="worker-a",
        )

    pending = ledger_row(intent, status=EffectStatus.PENDING, attempt=1, worker_id="worker-a")
    pending_receipt = receipt_row(intent, status=EffectStatus.PENDING, attempt=1)
    pending_connection = ScriptedConnection(
        rows=[*ensure_rows(intent, existing=persisted_intent(intent)), pending, pending_receipt],
        values=[1],
    )
    pending_ledger = PostgresEffectLedger(
        RecordingPool(pending_connection), tenant_id=intent.tenant_id
    )
    with pytest.raises(EffectLeaseConflict, match="no longer active"):
        await pending_ledger.complete(
            intent,
            attempt=1,
            status=EffectStatus.FAILED,
            worker_id="worker-a",
        )


@pytest.mark.asyncio
async def test_complete_turns_expired_lease_ambiguous_and_fences_race() -> None:
    intent = make_intent()
    rows, values = complete_script(
        intent,
        current_expiry=datetime.now(UTC) - timedelta(seconds=1),
        completed=None,
        expired="effect-key",
    )
    connection = CommitTrackingConnection(rows=rows, values=values)
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)
    with pytest.raises(EffectLeaseConflict, match="expired"):
        await ledger.complete(
            intent,
            attempt=1,
            status=EffectStatus.SUCCEEDED,
            worker_id="worker-a",
        )
    assert any("status='ambiguous'" in query for query, _ in connection.calls)
    assert connection.transaction_context is not None
    # The conflict is raised after the transaction exits, so the ambiguity
    # fence and receipt are committed instead of being rolled back.
    assert connection.transaction_context.exit_args is not None
    assert connection.transaction_context.exit_args[0] is None

    raced_rows, raced_values = complete_script(intent, completed=None, expired=None)
    raced_connection = ScriptedConnection(rows=raced_rows, values=raced_values)
    raced = PostgresEffectLedger(RecordingPool(raced_connection), tenant_id=intent.tenant_id)
    with pytest.raises(EffectLeaseConflict, match="changed"):
        await raced.complete(
            intent,
            attempt=1,
            status=EffectStatus.FAILED,
            worker_id="worker-a",
        )


@pytest.mark.asyncio
async def test_complete_rejects_disappearing_final_ledger_row() -> None:
    intent = make_intent()
    rows, values = complete_script(intent, final_row=None)
    connection = ScriptedConnection(rows=rows, values=values)
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)
    with pytest.raises(EffectLeaseConflict, match="disappeared"):
        await ledger.complete(
            intent,
            attempt=1,
            status=EffectStatus.SUCCEEDED,
            worker_id="worker-a",
        )


@pytest.mark.asyncio
async def test_write_receipt_rejects_unknown_intent_namespace() -> None:
    intent = make_intent()
    connection = ScriptedConnection(rows=[None])
    ledger = PostgresEffectLedger(RecordingPool(connection), tenant_id=intent.tenant_id)
    with pytest.raises(EffectKeyConflict, match="unknown intent"):
        await ledger._write_receipt(  # type: ignore[arg-type]
            connection,
            intent,
            status=EffectStatus.FAILED,
            attempt=1,
            worker_id="worker-a",
        )


@pytest.mark.asyncio
async def test_wait_returns_missing_terminal_and_eventually_completed_receipts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    intent = make_intent()
    unbound = PostgresEffectLedger(RecordingPool(ScriptedConnection()))
    with pytest.raises(ValueError, match="tenant_id is required"):
        await unbound.wait(intent.effect_key, timeout=0)

    missing = PostgresEffectLedger(
        RecordingPool(ScriptedConnection(rows=[None])), tenant_id=intent.tenant_id
    )
    assert await missing.wait(intent.effect_key, timeout=None) is None
    with pytest.raises(ValueError, match="non-negative"):
        await missing.wait(intent.effect_key, timeout=-1)

    now = datetime.now(UTC)
    terminal_row = ledger_row(intent, status=EffectStatus.FAILED, worker_id=None, expires_at=None)
    terminal = PostgresEffectLedger(
        RecordingPool(ScriptedConnection(rows=[terminal_row, None])), tenant_id=intent.tenant_id
    )
    result = await terminal.wait(intent.effect_key, timeout=1)
    assert result is not None and result.status is EffectStatus.FAILED

    running_row = ledger_row(intent, status=EffectStatus.RUNNING, expires_at=now + timedelta(30))
    done_row = ledger_row(intent, status=EffectStatus.SUCCEEDED, worker_id=None, expires_at=None)
    active_connection = ScriptedConnection(rows=[running_row, None, done_row, None])
    active = PostgresEffectLedger(RecordingPool(active_connection), tenant_id=intent.tenant_id)

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    result = await active.wait(intent.effect_key, timeout=1)
    assert result is not None and result.status is EffectStatus.SUCCEEDED


def test_decision_json_round_trip_and_strict_rejection_of_invalid_shapes() -> None:
    decision = placement_decision()
    encoded = _decision_json(decision)
    assert _decision_from_json(json.dumps(encoded)).node_id == "node-a"
    assert _decision_from_json(encoded).rejected == (("node-b", "draining"),)

    invalid_values: list[object] = [
        42,
        {"cell_id": "cell-a", "node_id": "node-a", "score": 1, "candidates": "bad"},
        {"cell_id": "cell-a", "node_id": "node-a", "score": 1, "candidates": ["bad"]},
        {
            "cell_id": "cell-a",
            "node_id": "node-a",
            "score": 1,
            "candidates": [{"node_id": "node-a", "score": 1, "component_scores": [["x"]]}],
        },
        {
            "cell_id": "cell-a",
            "node_id": "node-a",
            "score": 1,
            "candidates": [
                {"node_id": "node-a", "score": 1, "component_scores": [["x", math.nan]]}
            ],
        },
        {
            "cell_id": "cell-a",
            "node_id": "node-a",
            "score": math.nan,
            "candidates": [{"node_id": "node-a", "score": 1}],
        },
        {
            "cell_id": "cell-a",
            "node_id": "node-a",
            "score": 1,
            "candidates": [{"node_id": "node-a", "score": math.inf}],
        },
        {
            "cell_id": "cell-a",
            "node_id": "node-a",
            "score": 1,
            "candidates": [{"node_id": "node-a", "score": 1}],
            "rejected": [["node-a"]],
        },
        {
            "cell_id": "cell-a",
            "node_id": "node-a",
            "score": 1,
            "candidates": [],
        },
    ]
    for value in invalid_values:
        with pytest.raises(ReservationConflict):
            _decision_from_json(value)


@pytest.mark.asyncio
async def test_placement_update_reserve_and_read_are_namespace_complete() -> None:
    request = placement_request()
    decision = placement_decision()
    row = reservation_row(request, decision)
    connection = ScriptedConnection(rows=[row, row], values=[7])
    store = PostgresPlacementReservationStore(RecordingPool(connection))

    generation = await store.update_node(
        NodeSnapshot(
            node_id="node-a",
            region="cn-shanghai",
            capacity_cpu_millis=1000,
            observed_generation=1,
            capacity_memory_mb=2048,
            max_cells=10,
        )
    )
    assert generation == 7
    reserved = await store.reserve(
        request,
        decision,
        owner_id="scheduler-a",
        lease_seconds=15,
        reservation_id=str(row["reservation_id"]),
    )
    assert reserved.tenant_id == request.tenant_id
    assert reserved.app_id == request.app_id
    assert reserved.lease_epoch == 1

    found = await store.get(str(row["reservation_id"]), tenant_id=request.tenant_id)
    assert found is not None and found.node_id == "node-a"
    update_args = next(
        args for query, args in connection.calls if "update_cell_node_snapshot" in query
    )
    assert update_args[-2:] == (True, False)


@pytest.mark.asyncio
async def test_placement_reserve_rejects_invalid_decisions_leases_and_db_conflicts() -> None:
    request = placement_request()
    decision = placement_decision()
    store = PostgresPlacementReservationStore(RecordingPool(ScriptedConnection()))
    with pytest.raises(ReservationConflict, match="another Cell"):
        await store.reserve(request, placement_decision("other-cell"), owner_id="scheduler-a")

    outsider = PlacementDecision(
        cell_id=request.cell_id,
        node_id="node-z",
        score=0.1,
        candidates=decision.candidates,
    )
    with pytest.raises(ReservationConflict, match="candidate"):
        await store.reserve(request, outsider, owner_id="scheduler-a")
    with pytest.raises(ValueError, match="owner_id"):
        await store.reserve(request, decision, owner_id=" ")
    with pytest.raises(ValueError, match="lease_seconds"):
        await store.reserve(request, decision, owner_id="scheduler-a", lease_seconds=math.nan)
    with pytest.raises(ValueError, match="lease_seconds"):
        await store.reserve(request, decision, owner_id="scheduler-a", lease_seconds=0)
    with pytest.raises(ValueError):
        await store.reserve(
            request,
            decision,
            owner_id="scheduler-a",
            reservation_id="not-a-uuid",
        )

    rejected = ScriptedConnection(rows=[asyncpg.PostgresError("capacity")])
    conflict_store = PostgresPlacementReservationStore(RecordingPool(rejected))
    with pytest.raises(ReservationConflict, match="rejected"):
        await conflict_store.reserve(request, decision, owner_id="scheduler-a")

    empty = PostgresPlacementReservationStore(RecordingPool(ScriptedConnection(rows=[None])))
    with pytest.raises(ReservationConflict, match="no row"):
        await empty.reserve(request, decision, owner_id="scheduler-a")


@pytest.mark.asyncio
async def test_placement_reserve_rejects_authoritative_winner_change() -> None:
    request = placement_request()
    decision = placement_decision()
    changed = placement_decision("other-cell")
    row = reservation_row(request, decision)
    row["decision"] = json.dumps(_decision_json(changed))
    connection = ScriptedConnection(rows=[row])
    store = PostgresPlacementReservationStore(RecordingPool(connection))
    with pytest.raises(ReservationConflict, match="changed its Cell or winner"):
        await store.reserve(request, decision, owner_id="scheduler-a")


def make_reservation(
    request: CellPlacementRequest, decision: PlacementDecision
) -> PlacementReservation:
    return PlacementReservation(
        reservation_id="11111111-1111-1111-1111-111111111111",
        tenant_id=request.tenant_id,
        app_id=request.app_id,
        cell_id=request.cell_id,
        session_id=request.session_id,
        capsule_digest=request.capsule_digest,
        branch_id=request.branch_id,
        node_id=decision.node_id,
        owner_id="scheduler-a",
        lease_epoch=1,
        expires_at=datetime.now(UTC) + timedelta(seconds=30),
        cpu_millis=request.cpu_millis,
        memory_mb=request.memory_mb,
        decision=decision,
    )


@pytest.mark.asyncio
async def test_placement_renew_release_are_epoch_fenced_and_get_handles_absence() -> None:
    request = placement_request()
    decision = placement_decision()
    reservation = make_reservation(request, decision)
    renewed_row = reservation_row(request, decision, lease_epoch=2)
    connection = ScriptedConnection(rows=[renewed_row, renewed_row], values=[])
    store = PostgresPlacementReservationStore(RecordingPool(connection))
    renewed = await store.renew(reservation, lease_seconds=20)
    assert renewed.lease_epoch == 2
    renew_args = next(args for query, args in connection.calls if "renew_cell_placement" in query)
    assert renew_args[2] == reservation.lease_epoch

    await store.release(reservation, owner_id="scheduler-b")
    release_args = next(
        args for query, args in connection.calls if "release_cell_placement" in query
    )
    assert release_args[2] == reservation.lease_epoch

    with pytest.raises(ValueError, match="lease_seconds"):
        await store.renew(reservation, lease_seconds=math.inf)

    renew_error = ScriptedConnection(rows=[asyncpg.PostgresError("stale epoch")])
    renew_error_store = PostgresPlacementReservationStore(RecordingPool(renew_error))
    with pytest.raises(ReservationConflict, match="renew was fenced"):
        await renew_error_store.renew(reservation)

    renew_empty = PostgresPlacementReservationStore(RecordingPool(ScriptedConnection(rows=[None])))
    with pytest.raises(ReservationConflict, match="no row"):
        await renew_empty.renew(reservation)

    for bad_owner in (" ", 42):
        with pytest.raises(ValueError, match="owner_id"):
            await store.renew(reservation, owner_id=bad_owner)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="lease_seconds"):
        await store.renew(reservation, lease_seconds=True)  # type: ignore[arg-type]

    changed = placement_decision("other-cell")
    changed_row = reservation_row(request, changed, lease_epoch=2)
    changed_connection = ScriptedConnection(rows=[changed_row, changed_row])
    changed_store = PostgresPlacementReservationStore(RecordingPool(changed_connection))
    with pytest.raises(ReservationConflict, match="changed its Cell or winner"):
        await changed_store.renew(reservation)


@pytest.mark.asyncio
async def test_placement_renew_rehydrates_all_metadata_from_locked_database_row() -> None:
    request = placement_request()
    decision = placement_decision()
    reservation = make_reservation(request, decision)
    forged = replace(
        reservation,
        app_id="forged-app",
        cell_id="forged-cell",
        session_id="forged-session",
        capsule_digest="sha256:" + "f" * 64,
        branch_id="forged-branch",
        node_id="forged-node",
        cpu_millis=9999,
        memory_mb=9999,
    )
    authoritative = reservation_row(request, decision, lease_epoch=2)
    connection = ScriptedConnection(rows=[authoritative, authoritative])
    store = PostgresPlacementReservationStore(RecordingPool(connection))

    renewed = await store.renew(forged, owner_id="scheduler-a")

    assert renewed.tenant_id == authoritative["tenant_id"]
    assert renewed.app_id == authoritative["app_id"]
    assert renewed.cell_id == authoritative["cell_id"]
    assert renewed.session_id == authoritative["session_id"]
    assert renewed.capsule_digest == authoritative["capsule_digest"]
    assert renewed.branch_id == authoritative["branch_id"]
    assert renewed.node_id == authoritative["node_id"]
    assert renewed.owner_id == authoritative["owner_id"]
    assert renewed.cpu_millis == authoritative["cpu_millis"]
    assert renewed.memory_mb == authoritative["memory_mb"]
    assert renewed.decision == decision
    rehydrate_query = connection.calls[2][0]
    assert "FROM cell_placement_reservations" in rehydrate_query
    assert "tenant_id=$2" in rehydrate_query
    assert "FOR SHARE" in rehydrate_query

    release_error = ScriptedConnection(execute_results=[asyncpg.PostgresError("stale epoch")])
    release_error_store = PostgresPlacementReservationStore(RecordingPool(release_error))
    with pytest.raises(ReservationConflict, match="release was fenced"):
        await release_error_store.release(reservation)

    for bad_owner in (" ", 42):
        with pytest.raises(ValueError, match="owner_id"):
            await store.release(reservation, owner_id=bad_owner)  # type: ignore[arg-type]

    missing = PostgresPlacementReservationStore(RecordingPool(ScriptedConnection(rows=[None])))
    assert await missing.get(reservation.reservation_id, tenant_id=request.tenant_id) is None


@pytest.mark.asyncio
async def test_placement_get_rejects_cross_tenant_and_changed_decision() -> None:
    request = placement_request()
    decision = placement_decision()
    row = reservation_row(request, decision)
    row["tenant_id"] = "tenant-b"
    cross_tenant = PostgresPlacementReservationStore(RecordingPool(ScriptedConnection(rows=[row])))
    with pytest.raises(NamespaceViolation, match="tenant namespace"):
        await cross_tenant.get(str(row["reservation_id"]), tenant_id="tenant-a")

    mismatched = reservation_row(request, decision)
    mismatched["cell_id"] = "another-cell"
    changed = PostgresPlacementReservationStore(
        RecordingPool(ScriptedConnection(rows=[mismatched]))
    )
    with pytest.raises(ReservationConflict, match="does not match"):
        await changed.get(str(mismatched["reservation_id"]), tenant_id="tenant-a")


@pytest.mark.asyncio
async def test_approval_ledger_hashes_nonce_and_consumes_once_with_strict_scope() -> None:
    scope = "b" * 64
    expiry = datetime.now(UTC).timestamp() + 60
    connection = ScriptedConnection(values=[True, False])
    ledger = PostgresApprovalLedger(RecordingPool(connection), tenant_id="tenant-a")
    await ledger.issue("nonce-a", expiry, scope)
    assert await ledger.consume("nonce-a", expiry, scope) is True
    assert await ledger.consume("nonce-a", expiry, scope) is False
    issue_args = next(
        args for query, args in connection.calls if "issue_cell_approval_nonce" in query
    )
    consume_args = next(
        args for query, args in connection.calls if "consume_cell_approval_nonce" in query
    )
    assert issue_args[1] != "nonce-a"
    assert consume_args[1] == issue_args[1]
    assert len(issue_args[1]) == 64

    duplicate = ScriptedConnection(
        execute_results=["OK", asyncpg.UniqueViolationError("duplicate")]
    )
    duplicate_ledger = PostgresApprovalLedger(RecordingPool(duplicate), tenant_id="tenant-a")
    with pytest.raises(ValueError, match="already exists"):
        await duplicate_ledger.issue("nonce-b", expiry, scope)


@pytest.mark.asyncio
async def test_approval_ledger_rejects_bad_expiry_scope_and_tenant() -> None:
    scope = "b" * 64
    expiry = datetime.now(UTC).timestamp() + 60
    connection = ScriptedConnection(values=[True])
    ledger = PostgresApprovalLedger(RecordingPool(connection), tenant_id="tenant-a")
    with pytest.raises(ValueError, match="tenant_id"):
        PostgresApprovalLedger(RecordingPool(connection), tenant_id=" ")
    with pytest.raises(ValueError, match="approval expiry"):
        await ledger.issue("nonce", 0, scope)
    with pytest.raises(ValueError, match="approval expiry"):
        await ledger.issue("nonce", math.nan, scope)
    with pytest.raises(ValueError, match="scope_digest"):
        await ledger.issue("nonce", expiry, "bad")
    with pytest.raises(ValueError, match="expiry is invalid"):
        await ledger.issue("nonce", 1e308, scope)
    with pytest.raises(ValueError, match="nonce"):
        await ledger.issue("", expiry, scope)

    assert await ledger.consume("nonce", 0, scope) is False
    assert await ledger.consume("nonce", expiry, "bad") is False
    assert await ledger.consume("nonce", math.inf, scope) is False
    assert await ledger.consume("", expiry, scope) is False
    assert await ledger.consume("nonce", 1e308, scope) is False


def test_repository_bundle_and_tenant_factory_keep_scopes_explicit() -> None:
    connection = ScriptedConnection()
    pool = RecordingPool(connection)
    repository = PostgresCellRepository(pool, tenant_id="tenant-a")  # type: ignore[arg-type]
    assert isinstance(repository.effects, PostgresEffectLedger)
    assert repository.effects.tenant_id == "tenant-a"
    approval = PostgresApprovalLedger.for_tenant(pool, "tenant-a")  # type: ignore[arg-type]
    assert approval.tenant_id == "tenant-a"
