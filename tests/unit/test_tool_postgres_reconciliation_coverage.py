"""Deterministic branch coverage for the PostgreSQL execution ledger."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from tests.unit.test_tool_execution_reconciliation import _FakeConnection, _FakePool
from trpc_service.tenant.models import ToolRisk
from trpc_service.tool.execution import ExecutionStatus
from trpc_service.tool.postgres import (
    PostgresExecutionLedger,
    ToolExecutionConflict,
    _claim_from_row,
    _evidence_from_row,
    _execution_status,
    _lease_is_valid,
    _probe_intent_from_row,
    _row_int,
    _row_value,
)
from trpc_service.tool.reconciliation import (
    ExecutionProbeIntent,
    ReconciliationConflict,
    ReconciliationEvidence,
    ReconciliationOutcome,
)

TURN_ID = "00000000-0000-0000-0000-000000000001"
OBSERVED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _active_rows(*, owner: str = "worker-a", epoch: int = 1) -> list[dict[str, object]]:
    return [
        {"session_id": "session-a"},
        {"session_id": "session-a", "lease_owner": owner, "lease_epoch": epoch},
        {"session_id": "session-a", "status": "processing", "fencing_token": epoch},
        {"lease_owner": owner, "lease_epoch": epoch, "lease_valid": True},
    ]


def _existing(
    status: str | ExecutionStatus,
    *,
    owner: str = "worker-a",
    epoch: int = 1,
    attempt: int = 1,
) -> dict[str, object]:
    return {
        "turn_id": TURN_ID,
        "status": str(status),
        "lease_owner": owner,
        "lease_epoch": epoch,
        "attempt": attempt,
    }


def _intent(
    *, tenant_id: str = "tenant-a", execution_key: str = "execution-a"
) -> ExecutionProbeIntent:
    return ExecutionProbeIntent(
        tenant_id=tenant_id,
        execution_key=execution_key,
        turn_id="turn-a",
        tool_name="ticket.create",
        arguments_hash="a" * 64,
        app_id="app-a",
        session_id="session-a",
        trace_id="trace-a",
        attempt=1,
    )


def _evidence(
    outcome: ReconciliationOutcome,
    *,
    tenant_id: str = "tenant-a",
    execution_key: str = "execution-a",
    attempt: int = 1,
    summary: str = "provider_status_applied",
    trace_id: str | None = "trace-a",
    reconciler_id: str = "reconciler-a",
) -> ReconciliationEvidence:
    return ReconciliationEvidence(
        execution_key,
        attempt,
        outcome,
        evidence_summary=summary,
        trace_id=trace_id,
        observed_at=OBSERVED_AT,
        reconciler_id=reconciler_id,
        tenant_id=tenant_id,
    )


async def _begin(
    ledger: PostgresExecutionLedger,
    *,
    execution_key: str = "execution-a",
    tenant_id: str = "tenant-a",
    turn_id: str = TURN_ID,
    risk: ToolRisk = ToolRisk.IDEMPOTENT,
    owner_id: str = "worker-a",
    fencing_token: int = 1,
) -> Any:
    return await ledger.begin(
        execution_key,
        tenant_id=tenant_id,
        turn_id=turn_id,
        tool_name="ticket.create",
        risk=risk,
        arguments_hash="a" * 64,
        owner_id=owner_id,
        fencing_token=fencing_token,
    )


@pytest.mark.asyncio
async def test_begin_existing_terminal_success_non_idempotent_is_authoritative() -> None:
    connection = _FakeConnection(rows=[_existing(ExecutionStatus.SUCCEEDED, attempt=4)])

    record = await _begin(
        PostgresExecutionLedger(_FakePool(connection)),
        risk=ToolRisk.NON_IDEMPOTENT,
    )

    assert record.status is ExecutionStatus.SUCCEEDED
    assert record.attempt == 4
    assert not record.fresh
    assert not record.replay_terminal
    assert len(connection.calls) == 2


@pytest.mark.asyncio
async def test_begin_existing_same_fence_returns_existing_nonterminal() -> None:
    connection = _FakeConnection(
        rows=[_existing(ExecutionStatus.FAILED), *_active_rows()],
    )

    record = await _begin(PostgresExecutionLedger(_FakePool(connection)))

    assert record.status is ExecutionStatus.FAILED
    assert record.attempt == 1
    assert not record.fresh


@pytest.mark.asyncio
async def test_begin_existing_idempotent_takeover_cas_failure_is_fenced() -> None:
    connection = _FakeConnection(
        rows=[_existing(ExecutionStatus.AMBIGUOUS, owner="worker-old"), *_active_rows()],
        values=[None],
    )

    with pytest.raises(ToolExecutionConflict, match="changed while taking its fence") as exc_info:
        await _begin(PostgresExecutionLedger(_FakePool(connection)))

    assert exc_info.value.requires_confirmation


@pytest.mark.asyncio
async def test_begin_new_execution_checks_active_turn_before_insert() -> None:
    connection = _FakeConnection(rows=[None, *_active_rows()], values=["execution-a"])

    record = await _begin(PostgresExecutionLedger(_FakePool(connection)))

    assert record.fresh and record.status is ExecutionStatus.STARTED
    assert record.attempt == 1
    assert "INSERT INTO tool_executions" in connection.calls[-1][0]


@pytest.mark.asyncio
async def test_begin_concurrent_insert_disappears() -> None:
    connection = _FakeConnection(rows=[None, *_active_rows(), None], values=[None])

    with pytest.raises(RuntimeError, match="disappeared during conflict resolution"):
        await _begin(PostgresExecutionLedger(_FakePool(connection)))


@pytest.mark.asyncio
async def test_begin_concurrent_insert_terminal_success_replays_idempotently() -> None:
    connection = _FakeConnection(
        rows=[
            None,
            *_active_rows(),
            _existing(ExecutionStatus.SUCCEEDED, attempt=2),
            *_active_rows(),
        ],
        values=[None],
    )

    record = await _begin(PostgresExecutionLedger(_FakePool(connection)))

    assert record.status is ExecutionStatus.SUCCEEDED
    assert record.replay_terminal
    assert record.attempt == 2


@pytest.mark.asyncio
async def test_begin_concurrent_insert_terminal_success_is_returned_for_non_idempotent() -> None:
    connection = _FakeConnection(
        rows=[None, *_active_rows(), _existing(ExecutionStatus.SUCCEEDED, attempt=3)],
        values=[None],
    )

    record = await _begin(
        PostgresExecutionLedger(_FakePool(connection)),
        risk=ToolRisk.NON_IDEMPOTENT,
    )

    assert record.status is ExecutionStatus.SUCCEEDED
    assert not record.replay_terminal
    assert record.attempt == 3


@pytest.mark.asyncio
async def test_begin_concurrent_insert_same_fence_returns_existing() -> None:
    connection = _FakeConnection(
        rows=[None, *_active_rows(), _existing(ExecutionStatus.UNKNOWN), *_active_rows()],
        values=[None],
    )

    record = await _begin(PostgresExecutionLedger(_FakePool(connection)))

    assert record.status is ExecutionStatus.UNKNOWN
    assert record.attempt == 1
    assert not record.fresh


@pytest.mark.asyncio
async def test_begin_concurrent_insert_non_idempotent_fence_conflict() -> None:
    connection = _FakeConnection(
        rows=[
            None,
            *_active_rows(),
            _existing(ExecutionStatus.STARTED, owner="worker-old", epoch=2),
            *_active_rows(),
        ],
        values=[None],
    )

    with pytest.raises(
        ToolExecutionConflict, match="fencing token is no longer current"
    ) as exc_info:
        await _begin(
            PostgresExecutionLedger(_FakePool(connection)),
            risk=ToolRisk.NON_IDEMPOTENT,
        )

    assert exc_info.value.requires_confirmation


@pytest.mark.asyncio
@pytest.mark.parametrize("claimed", ["execution-a", None])
async def test_begin_concurrent_insert_idempotent_takeover_result(claimed: str | None) -> None:
    connection = _FakeConnection(
        rows=[
            None,
            *_active_rows(),
            _existing(ExecutionStatus.FAILED, owner="worker-old", epoch=2, attempt=5),
            *_active_rows(),
        ],
        values=[None, claimed],
    )

    if claimed is None:
        with pytest.raises(ToolExecutionConflict, match="changed while taking its fence"):
            await _begin(PostgresExecutionLedger(_FakePool(connection)))
        return

    record = await _begin(PostgresExecutionLedger(_FakePool(connection)))
    assert record.fresh
    assert record.status is ExecutionStatus.STARTED
    assert record.attempt == 6


@pytest.mark.asyncio
async def test_finish_validates_terminal_status_before_database_access() -> None:
    connection = _FakeConnection()

    with pytest.raises(ValueError, match="requires a terminal status"):
        await PostgresExecutionLedger(_FakePool(connection)).finish(
            "execution-a",
            tenant_id="tenant-a",
            status=ExecutionStatus.STARTED,
            owner_id="worker-a",
            fencing_token=1,
        )

    assert connection.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("row", "error"),
    [
        (None, "does not exist or is no longer owned"),
        (_existing(ExecutionStatus.FAILED), "does not exist or is no longer owned"),
    ],
)
async def test_finish_rejects_missing_or_terminal_row(
    row: dict[str, object] | None, error: str
) -> None:
    with pytest.raises(RuntimeError, match=error):
        await PostgresExecutionLedger(_FakePool(_FakeConnection(rows=[row]))).finish(
            "execution-a",
            tenant_id="tenant-a",
            status=ExecutionStatus.FAILED,
            owner_id="worker-a",
            fencing_token=1,
        )


@pytest.mark.asyncio
async def test_finish_rejects_changed_execution_fence() -> None:
    connection = _FakeConnection(rows=[_existing(ExecutionStatus.STARTED, owner="worker-old")])

    with pytest.raises(ToolExecutionConflict, match="finish crossed a session fence") as exc_info:
        await PostgresExecutionLedger(_FakePool(connection)).finish(
            "execution-a",
            tenant_id="tenant-a",
            status=ExecutionStatus.SUCCEEDED,
            owner_id="worker-a",
            fencing_token=1,
        )

    assert exc_info.value.requires_confirmation


@pytest.mark.asyncio
async def test_finish_rejects_cas_update_that_lost_the_fence() -> None:
    connection = _FakeConnection(
        rows=[_existing(ExecutionStatus.STARTED), *_active_rows()],
        values=[None],
    )

    with pytest.raises(RuntimeError, match="does not exist or is no longer owned"):
        await PostgresExecutionLedger(_FakePool(connection)).finish(
            "execution-a",
            tenant_id="tenant-a",
            status=ExecutionStatus.FAILED,
            owner_id="worker-a",
            fencing_token=1,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("row", [None, {"status": "failed", "attempt": "7"}])
async def test_get_record_handles_empty_and_mapping_rows(row: dict[str, object] | None) -> None:
    record = await PostgresExecutionLedger(
        _FakePool(_FakeConnection(rows=[row])),
    ).get_record("execution-a", tenant_id="tenant-a")

    if row is None:
        assert record is None
    else:
        assert record is not None
        assert record.status is ExecutionStatus.FAILED
        assert record.attempt == 7


@pytest.mark.asyncio
async def test_list_ambiguous_maps_all_identity_fields_and_is_tenant_scoped() -> None:
    connection = _FakeConnection(
        fetch_rows=[
            [
                {
                    "tenant_id": "tenant-a",
                    "execution_key": "execution-a",
                    "turn_id": "turn-a",
                    "tool_name": "ticket.create",
                    "arguments_hash": "a" * 64,
                    "status": "ambiguous",
                    "attempt": "2",
                    "session_id": "session-a",
                    "app_id": "app-a",
                    "trace_id": "trace-a",
                },
                {
                    "tenant_id": "tenant-a",
                    "execution_key": "execution-b",
                    "turn_id": "turn-b",
                    "tool_name": "ticket.update",
                    "arguments_hash": "b" * 64,
                    "status": "unknown",
                    "attempt": True,
                    "session_id": "session-b",
                    "app_id": "app-b",
                },
            ]
        ],
    )

    intents = await PostgresExecutionLedger(_FakePool(connection)).list_ambiguous(
        tenant_id="tenant-a",
        limit=2,
    )

    assert [intent.execution_key for intent in intents] == ["execution-a", "execution-b"]
    assert intents[0].attempt == 2 and intents[0].trace_id == "trace-a"
    assert intents[1].attempt == 1 and intents[1].trace_id is None
    assert "execution.tenant_id=$1" in connection.calls[1][0]


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [0, 1001, True, "1"])
async def test_list_ambiguous_rejects_invalid_limits(limit: object) -> None:
    with pytest.raises(ValueError, match="between 1 and 1000"):
        await PostgresExecutionLedger(_FakePool(_FakeConnection())).list_ambiguous(
            tenant_id="tenant-a",
            limit=limit,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_claim_ambiguous_returns_empty_without_rows() -> None:
    connection = _FakeConnection(fetch_rows=[[]])

    claims = await PostgresExecutionLedger(_FakePool(connection)).claim_ambiguous(
        tenant_id="tenant-a",
        owner_id="reconciler-a",
        limit=3,
        lease_seconds=12.5,
    )

    assert claims == []
    query, args = connection.calls[1]
    assert "FOR UPDATE OF execution SKIP LOCKED" in query
    assert args == ("tenant-a", 3, "reconciler-a", 12.5)


@pytest.mark.asyncio
@pytest.mark.parametrize("owner_id", ["", "   ", None, 7])
async def test_claim_ambiguous_rejects_invalid_owner(owner_id: object) -> None:
    with pytest.raises(ValueError, match="owner_id is required"):
        await PostgresExecutionLedger(_FakePool(_FakeConnection())).claim_ambiguous(
            tenant_id="tenant-a",
            owner_id=owner_id,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("lease_seconds", [0, -1, 3601, True, "30"])
async def test_claim_ambiguous_rejects_invalid_lease(lease_seconds: object) -> None:
    with pytest.raises(ValueError, match="reconciliation lease"):
        await PostgresExecutionLedger(_FakePool(_FakeConnection())).claim_ambiguous(
            tenant_id="tenant-a",
            owner_id="reconciler-a",
            lease_seconds=lease_seconds,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_claim_ambiguous_maps_owner_epoch_and_expiry() -> None:
    expires = datetime.now(UTC) + timedelta(minutes=1)
    connection = _FakeConnection(
        fetch_rows=[
            [
                {
                    "tenant_id": "tenant-a",
                    "execution_key": "execution-a",
                    "turn_id": "turn-a",
                    "tool_name": "ticket.create",
                    "arguments_hash": "a" * 64,
                    "status": "unknown",
                    "attempt": "4",
                    "reconciliation_owner": "reconciler-a",
                    "reconciliation_epoch": "9",
                    "reconciliation_lease_expires_at": expires,
                    "session_id": "session-a",
                    "app_id": "app-a",
                    "trace_id": "trace-a",
                }
            ]
        ],
    )

    claims = await PostgresExecutionLedger(_FakePool(connection)).claim_ambiguous(
        tenant_id="tenant-a",
        owner_id="reconciler-a",
    )

    assert len(claims) == 1
    assert claims[0].owner_id == "reconciler-a"
    assert claims[0].claim_epoch == 9
    assert claims[0].attempt == 4
    assert claims[0].lease_expires_at == expires


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "row", "error"),
    [
        (
            "lease",
            {"reconciliation_lease_expires_at": None, "reconciliation_owner": "r"},
            "no lease expiry",
        ),
        (
            "owner",
            {"reconciliation_lease_expires_at": OBSERVED_AT, "reconciliation_owner": ""},
            "no owner",
        ),
    ],
)
async def test_claim_ambiguous_rejects_malformed_return_rows(
    field: str,
    row: dict[str, object],
    error: str,
) -> None:
    del field
    with pytest.raises(RuntimeError, match=error):
        await PostgresExecutionLedger(
            _FakePool(_FakeConnection(fetch_rows=[[row]]))
        ).claim_ambiguous(
            tenant_id="tenant-a",
            owner_id="reconciler-a",
        )


@pytest.mark.asyncio
async def test_list_evidence_maps_optional_trace_and_outcomes() -> None:
    applied = _evidence(ReconciliationOutcome.APPLIED)
    not_applied = _evidence(
        ReconciliationOutcome.NOT_APPLIED,
        summary="provider_status_not_applied",
        trace_id=None,
        reconciler_id="reconciler-b",
    )
    unknown = _evidence(
        ReconciliationOutcome.UNKNOWN,
        summary="provider_status_unknown",
    )
    rows = [
        {
            "execution_key": item.execution_key,
            "attempt": item.attempt,
            "outcome": item.outcome.value,
            "evidence_summary": item.evidence_summary,
            "evidence_digest": item.evidence_digest,
            "trace_id": item.trace_id,
            "reconciler_id": item.reconciler_id,
            "observed_at": item.observed_at,
            "tenant_id": item.tenant_id,
        }
        for item in (applied, not_applied, unknown)
    ]
    connection = _FakeConnection(fetch_rows=[rows])

    evidence = await PostgresExecutionLedger(_FakePool(connection)).list_reconciliation_evidence(
        tenant_id="tenant-a",
        execution_key="execution-a",
        attempt=1,
    )

    assert [item.outcome for item in evidence] == [
        ReconciliationOutcome.APPLIED,
        ReconciliationOutcome.NOT_APPLIED,
        ReconciliationOutcome.UNKNOWN,
    ]
    assert evidence[0].trace_id == "trace-a"
    assert evidence[1].trace_id is None
    assert connection.calls[1][1] == ("tenant-a", "execution-a", 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("attempt", [0, -1, True, "1"])
async def test_list_evidence_rejects_invalid_attempt(attempt: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        await PostgresExecutionLedger(_FakePool(_FakeConnection())).list_reconciliation_evidence(
            tenant_id="tenant-a",
            execution_key="execution-a",
            attempt=attempt,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("row", "error"),
    [
        ({"observed_at": None}, "no observed_at"),
        (
            {"observed_at": OBSERVED_AT, "outcome": "unsupported"},
            "unsupported reconciliation outcome",
        ),
        (
            {
                "observed_at": OBSERVED_AT,
                "outcome": "applied",
                "execution_key": "execution-a",
                "attempt": 1,
                "evidence_summary": "provider_status_applied",
                "evidence_digest": "0" * 64,
                "trace_id": None,
                "reconciler_id": "reconciler-a",
                "tenant_id": "tenant-a",
            },
            "evidence_digest does not match canonical evidence",
        ),
    ],
)
async def test_list_evidence_rejects_malformed_rows(row: dict[str, object], error: str) -> None:
    with pytest.raises((RuntimeError, ValueError), match=error):
        await PostgresExecutionLedger(
            _FakePool(_FakeConnection(fetch_rows=[[row]]))
        ).list_reconciliation_evidence(
            tenant_id="tenant-a",
            execution_key="execution-a",
        )


@pytest.mark.asyncio
async def test_reconcile_unknown_without_claim_converges_to_unknown() -> None:
    evidence = _evidence(ReconciliationOutcome.UNKNOWN)
    connection = _FakeConnection(
        rows=[
            {
                "status": "unknown",
                "attempt": 1,
                "reconciliation_owner": None,
                "reconciliation_epoch": 0,
                "reconciliation_lease_expires_at": None,
            },
            None,
            {"execution_key": "execution-a", "status": "unknown", "attempt": 1},
        ],
        values=["reconciliation-id"],
    )

    result = await PostgresExecutionLedger(_FakePool(connection)).reconcile(
        "execution-a",
        tenant_id="tenant-a",
        expected_attempt=1,
        evidence=evidence,
    )

    assert result.status is ExecutionStatus.UNKNOWN
    assert result.attempt == 1
    assert any(
        "INSERT INTO tool_execution_reconciliations" in query for query, _ in connection.calls
    )


@pytest.mark.asyncio
async def test_reconcile_duplicate_same_digest_returns_current_record() -> None:
    evidence = _evidence(ReconciliationOutcome.APPLIED)
    connection = _FakeConnection(
        rows=[
            {
                "status": "ambiguous",
                "attempt": 1,
                "reconciliation_owner": None,
                "reconciliation_epoch": 0,
                "reconciliation_lease_expires_at": None,
            },
            None,
            {"outcome": "applied"},
        ],
        values=[None],
    )

    result = await PostgresExecutionLedger(_FakePool(connection)).reconcile(
        "execution-a",
        tenant_id="tenant-a",
        expected_attempt=1,
        evidence=evidence,
    )

    assert result.status is ExecutionStatus.AMBIGUOUS
    assert result.attempt == 1


@pytest.mark.asyncio
async def test_reconcile_duplicate_missing_row_is_concurrent_conflict() -> None:
    connection = _FakeConnection(
        rows=[
            {"status": "ambiguous", "attempt": 1},
            None,
            None,
        ],
        values=[None],
    )

    with pytest.raises(ReconciliationConflict, match="changed concurrently"):
        await PostgresExecutionLedger(_FakePool(connection)).reconcile(
            "execution-a",
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=_evidence(ReconciliationOutcome.APPLIED),
        )


@pytest.mark.asyncio
async def test_reconcile_duplicate_digest_with_different_outcome_conflicts() -> None:
    connection = _FakeConnection(
        rows=[
            {"status": "ambiguous", "attempt": 1},
            None,
            {"outcome": "not_applied"},
        ],
        values=[None],
    )

    with pytest.raises(ReconciliationConflict, match="evidence conflicts"):
        await PostgresExecutionLedger(_FakePool(connection)).reconcile(
            "execution-a",
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=_evidence(ReconciliationOutcome.APPLIED),
        )


@pytest.mark.asyncio
async def test_reconcile_prior_evidence_conflict_is_rejected_before_insert() -> None:
    connection = _FakeConnection(
        rows=[
            {"status": "ambiguous", "attempt": 1},
            {"outcome": "not_applied"},
        ],
    )

    with pytest.raises(ReconciliationConflict, match="evidence conflicts"):
        await PostgresExecutionLedger(_FakePool(connection)).reconcile(
            "execution-a",
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=_evidence(ReconciliationOutcome.APPLIED),
        )


@pytest.mark.asyncio
async def test_reconcile_prior_matching_evidence_continues_to_append_and_update() -> None:
    connection = _FakeConnection(
        rows=[
            {"status": "ambiguous", "attempt": 1},
            {"outcome": "applied"},
            {"execution_key": "execution-a", "status": "succeeded", "attempt": 1},
        ],
        values=["reconciliation-id"],
    )

    result = await PostgresExecutionLedger(_FakePool(connection)).reconcile(
        "execution-a",
        tenant_id="tenant-a",
        expected_attempt=1,
        evidence=_evidence(ReconciliationOutcome.APPLIED),
    )

    assert result.status is ExecutionStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_reconcile_terminal_state_conflict_is_rejected() -> None:
    connection = _FakeConnection(
        rows=[
            {"status": "succeeded", "attempt": 1},
            None,
        ],
    )

    with pytest.raises(ReconciliationConflict, match="final execution state"):
        await PostgresExecutionLedger(_FakePool(connection)).reconcile(
            "execution-a",
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=_evidence(ReconciliationOutcome.NOT_APPLIED),
        )


@pytest.mark.asyncio
async def test_reconcile_terminal_matching_state_continues_to_cas() -> None:
    connection = _FakeConnection(
        rows=[
            {"status": "succeeded", "attempt": 1},
            None,
            None,
            {"status": "succeeded", "attempt": 1},
        ],
        values=["reconciliation-id"],
    )

    result = await PostgresExecutionLedger(_FakePool(connection)).reconcile(
        "execution-a",
        tenant_id="tenant-a",
        expected_attempt=1,
        evidence=_evidence(ReconciliationOutcome.APPLIED),
    )

    assert result.status is ExecutionStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_reconcile_started_state_is_not_reconcilable() -> None:
    connection = _FakeConnection(rows=[{"status": "started", "attempt": 1}])

    with pytest.raises(ReconciliationConflict, match="only ambiguous or unknown"):
        await PostgresExecutionLedger(_FakePool(connection)).reconcile(
            "execution-a",
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=_evidence(ReconciliationOutcome.UNKNOWN),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("rows", "error"),
    [
        ([None], "was not claimed"),
        ([{"status": "ambiguous", "attempt": 2}], "attempt is stale"),
    ],
)
async def test_reconcile_missing_or_stale_execution(rows: list[object], error: str) -> None:
    with pytest.raises(ReconciliationConflict, match=error):
        await PostgresExecutionLedger(_FakePool(_FakeConnection(rows=rows))).reconcile(
            "execution-a",
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=_evidence(ReconciliationOutcome.UNKNOWN),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("claim_owner", "claim_epoch", "error"),
    [
        (None, 1, "owner_id is required"),
        ("reconciler-a", 0, "claim epoch is invalid"),
        ("reconciler-a", True, "claim epoch is invalid"),
    ],
)
async def test_reconcile_validates_claim_owner_and_epoch(
    claim_owner: str | None,
    claim_epoch: int | None,
    error: str,
) -> None:
    with pytest.raises((ValueError, ReconciliationConflict), match=error):
        await PostgresExecutionLedger(_FakePool(_FakeConnection())).reconcile(
            "execution-a",
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=_evidence(ReconciliationOutcome.UNKNOWN),
            claim_owner=claim_owner,
            claim_epoch=claim_epoch,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "current",
    [
        {
            "status": "ambiguous",
            "attempt": 1,
            "reconciliation_owner": "reconciler-b",
            "reconciliation_epoch": 1,
            "reconciliation_lease_expires_at": datetime.now(UTC) + timedelta(minutes=1),
        },
        {
            "status": "ambiguous",
            "attempt": 1,
            "reconciliation_owner": "reconciler-a",
            "reconciliation_epoch": 2,
            "reconciliation_lease_expires_at": datetime.now(UTC) + timedelta(minutes=1),
        },
        {
            "status": "ambiguous",
            "attempt": 1,
            "reconciliation_owner": "reconciler-a",
            "reconciliation_epoch": 1,
            "reconciliation_lease_expires_at": datetime.now(UTC) - timedelta(minutes=1),
        },
    ],
)
async def test_reconcile_rejects_stale_claim(current: dict[str, object]) -> None:
    with pytest.raises(ReconciliationConflict, match="claim is stale"):
        await PostgresExecutionLedger(_FakePool(_FakeConnection(rows=[current]))).reconcile(
            "execution-a",
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=_evidence(ReconciliationOutcome.UNKNOWN),
            claim_owner="reconciler-a",
            claim_epoch=1,
        )


@pytest.mark.asyncio
async def test_reconcile_cas_loss_accepts_matching_terminal_completion() -> None:
    connection = _FakeConnection(
        rows=[
            {
                "status": "ambiguous",
                "attempt": 1,
                "reconciliation_owner": None,
                "reconciliation_epoch": 0,
                "reconciliation_lease_expires_at": None,
            },
            None,
            None,
            {"status": "succeeded", "attempt": 1},
        ],
        values=["reconciliation-id"],
    )

    result = await PostgresExecutionLedger(_FakePool(connection)).reconcile(
        "execution-a",
        tenant_id="tenant-a",
        expected_attempt=1,
        evidence=_evidence(ReconciliationOutcome.APPLIED),
    )

    assert result.status is ExecutionStatus.SUCCEEDED
    assert result.attempt == 1


@pytest.mark.asyncio
async def test_reconcile_cas_loss_with_missing_latest_row_conflicts() -> None:
    connection = _FakeConnection(
        rows=[
            {"status": "ambiguous", "attempt": 1},
            None,
            None,
        ],
        values=["reconciliation-id"],
    )

    with pytest.raises(ReconciliationConflict, match="CAS fence was lost"):
        await PostgresExecutionLedger(_FakePool(connection)).reconcile(
            "execution-a",
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=_evidence(ReconciliationOutcome.APPLIED),
        )


@pytest.mark.asyncio
async def test_reconcile_cas_loss_with_different_latest_status_conflicts() -> None:
    connection = _FakeConnection(
        rows=[
            {"status": "ambiguous", "attempt": 1},
            None,
            None,
            {"status": "failed", "attempt": 1},
        ],
        values=["reconciliation-id"],
    )

    with pytest.raises(ReconciliationConflict, match="CAS fence was lost"):
        await PostgresExecutionLedger(_FakePool(connection)).reconcile(
            "execution-a",
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=_evidence(ReconciliationOutcome.APPLIED),
        )


@pytest.mark.asyncio
async def test_reconcile_rejects_cross_tenant_evidence_before_database_access() -> None:
    evidence = _evidence(ReconciliationOutcome.UNKNOWN, tenant_id="tenant-b")
    connection = _FakeConnection()

    with pytest.raises(ReconciliationConflict, match="tenant is out of scope"):
        await PostgresExecutionLedger(_FakePool(connection)).reconcile(
            "execution-a",
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=evidence,
        )

    assert connection.calls == []


@pytest.mark.asyncio
async def test_reconcile_rejects_stale_attempt_and_execution_key_evidence() -> None:
    with pytest.raises(ReconciliationConflict, match="attempt is stale"):
        await PostgresExecutionLedger(_FakePool(_FakeConnection())).reconcile(
            "execution-a",
            tenant_id="tenant-a",
            expected_attempt=2,
            evidence=_evidence(ReconciliationOutcome.UNKNOWN, attempt=1),
        )

    with pytest.raises(ReconciliationConflict, match="execution key does not match"):
        await PostgresExecutionLedger(_FakePool(_FakeConnection())).reconcile(
            "execution-a",
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=_evidence(ReconciliationOutcome.UNKNOWN, execution_key="other-key"),
        )


def test_row_helpers_cover_mapping_sequence_and_conversion_failures() -> None:
    class KeyErrorRow:
        def __getitem__(self, key: object) -> object:
            del key
            raise KeyError("missing")

    assert _row_value(None, "missing", "fallback") == "fallback"
    assert _row_value({"field": "value"}, "field") == "value"
    assert _row_value(KeyErrorRow(), "field", "fallback") == "fallback"
    assert _row_int({"field": True}, "field", 7) == 7
    assert _row_int({"field": "not-an-int"}, "field", 7) == 7
    assert _row_int({"field": b"8"}, "field", 7) == 8
    assert _row_int({"field": object()}, "field", 7) == 7


def test_row_conversion_helpers_validate_status_lease_and_shape() -> None:
    with pytest.raises(RuntimeError, match="invalid status"):
        _execution_status("corrupt")

    assert _lease_is_valid(
        {"reconciliation_lease_expires_at": datetime.now(UTC) + timedelta(seconds=1)}
    )
    assert not _lease_is_valid(
        {"reconciliation_lease_expires_at": datetime.now(UTC) - timedelta(seconds=1)}
    )
    assert not _lease_is_valid({"reconciliation_lease_expires_at": "tomorrow"})

    intent = _probe_intent_from_row(
        {
            "tenant_id": "tenant-a",
            "execution_key": "execution-a",
            "turn_id": "turn-a",
            "tool_name": "read",
            "arguments_hash": "h",
            "app_id": "app-a",
            "session_id": "session-a",
            "trace_id": None,
            "attempt": "3",
        }
    )
    assert intent.attempt == 3 and intent.trace_id is None


def test_evidence_and_claim_helpers_reject_invalid_shapes() -> None:
    with pytest.raises(RuntimeError, match="no lease expiry"):
        _claim_from_row({"reconciliation_lease_expires_at": None})
    with pytest.raises(RuntimeError, match="no owner"):
        _claim_from_row(
            {
                "reconciliation_lease_expires_at": OBSERVED_AT,
                "reconciliation_owner": "",
            }
        )
    with pytest.raises(RuntimeError, match="no observed_at"):
        _evidence_from_row({"observed_at": None})
