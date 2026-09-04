"""Tests for the baseline-tool-ledger reconciliation boundary."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trpc_service.tenant.models import ToolRisk
from trpc_service.tool.execution import (
    ExecutionIdentityConflict,
    ExecutionStatus,
    InMemoryExecutionLedger,
)
from trpc_service.tool.postgres import PostgresExecutionLedger
from trpc_service.tool.reconciliation import (
    ExecutionProbeIntent,
    ProviderReconciler,
    ReconciliationConflict,
    ReconciliationEvidence,
    ReconciliationOutcome,
    ToolExecutionReconciliationCoordinator,
)


class _AsyncContext:
    def __init__(self, value: object) -> None:
        self.value = value

    async def __aenter__(self) -> object:
        return self.value

    async def __aexit__(self, *args: object) -> None:
        del args


class _FakeConnection:
    def __init__(
        self,
        *,
        rows: Sequence[object] = (),
        values: Sequence[object] = (),
        fetch_rows: Sequence[Sequence[object]] = (),
    ) -> None:
        self.rows = list(rows)
        self.values = list(values)
        self.fetch_rows = [list(items) for items in fetch_rows]
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def transaction(self) -> _AsyncContext:
        return _AsyncContext(self)

    async def execute(self, query: str, *args: object) -> str:
        self.calls.append((query, args))
        return "OK"

    async def fetchrow(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        return self.rows.pop(0) if self.rows else None

    async def fetchval(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        return self.values.pop(0) if self.values else None

    async def fetch(self, query: str, *args: object) -> list[object]:
        self.calls.append((query, args))
        return self.fetch_rows.pop(0) if self.fetch_rows else []


class _FakePool:
    def __init__(self, connection: _FakeConnection) -> None:
        self.connection = connection

    def acquire(self) -> _AsyncContext:
        return _AsyncContext(self.connection)


def _intent(
    *,
    tenant_id: str = "tenant-a",
    execution_key: str = "execution-a",
    attempt: int = 1,
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
        attempt=attempt,
    )


async def _ambiguous(
    *,
    tenant_id: str = "tenant-a",
    execution_key: str = "execution-a",
) -> tuple[InMemoryExecutionLedger, ExecutionProbeIntent]:
    ledger = InMemoryExecutionLedger()
    intent = _intent(tenant_id=tenant_id, execution_key=execution_key)
    started = await ledger.begin(
        intent.execution_key,
        tenant_id=tenant_id,
        turn_id=intent.turn_id,
        tool_name=intent.tool_name,
        risk=ToolRisk.NON_IDEMPOTENT,
        arguments_hash=intent.arguments_hash,
    )
    assert started.fresh
    await ledger.finish(
        intent.execution_key,
        tenant_id=tenant_id,
        status=ExecutionStatus.AMBIGUOUS,
    )
    return ledger, intent


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "status"),
    [
        (ReconciliationOutcome.APPLIED, ExecutionStatus.SUCCEEDED),
        (ReconciliationOutcome.NOT_APPLIED, ExecutionStatus.FAILED),
        (ReconciliationOutcome.UNKNOWN, ExecutionStatus.UNKNOWN),
    ],
)
async def test_probe_outcomes_converge_one_baseline_execution_row(
    outcome: ReconciliationOutcome,
    status: ExecutionStatus,
) -> None:
    ledger, intent = await _ambiguous()
    calls = 0

    async def read_only_probe(
        queried: ExecutionProbeIntent,
        _receipt: object,
    ) -> ReconciliationOutcome:
        nonlocal calls
        calls += 1
        assert queried.tenant_id == intent.tenant_id
        assert queried.execution_key == intent.execution_key
        return outcome

    coordinator = ToolExecutionReconciliationCoordinator(
        ledger,
        ProviderReconciler(read_only_probe, reconciler_id="fake-provider"),
    )
    results = await coordinator.reconcile_pending(
        tenant_id=intent.tenant_id,
        owner_id="reconciler-a",
    )

    assert [result.status for result in results] == [status]
    assert calls == 1
    assert ledger.records[intent.execution_key].status is status


@pytest.mark.asyncio
async def test_unknown_keeps_automatic_retry_locked_and_never_reexecutes_provider() -> None:
    ledger, intent = await _ambiguous()
    provider_calls = 0

    async def unavailable(_intent: ExecutionProbeIntent, _receipt: object) -> None:
        nonlocal provider_calls
        provider_calls += 1
        raise TimeoutError("provider response omitted")

    coordinator = ToolExecutionReconciliationCoordinator(
        ledger,
        ProviderReconciler(unavailable),
    )
    first = await coordinator.reconcile_pending(
        tenant_id=intent.tenant_id,
        owner_id="reconciler-a",
    )
    assert first[0].status is ExecutionStatus.UNKNOWN
    assert provider_calls == 1
    # No second claim can be taken until a later lease expires; even a direct
    # begin for a non-idempotent tool remains held by the unknown outcome.
    blocked = await ledger.begin(
        intent.execution_key,
        tenant_id=intent.tenant_id,
        turn_id=intent.turn_id,
        tool_name=intent.tool_name,
        risk=ToolRisk.NON_IDEMPOTENT,
        arguments_hash=intent.arguments_hash,
    )
    assert blocked.status is ExecutionStatus.UNKNOWN
    assert not blocked.fresh


@pytest.mark.asyncio
async def test_duplicate_evidence_is_idempotent_but_conflicting_evidence_is_rejected() -> None:
    ledger, intent = await _ambiguous()
    observed = datetime(2026, 1, 1, tzinfo=UTC)
    evidence = ReconciliationEvidence(
        intent.execution_key,
        1,
        ReconciliationOutcome.APPLIED,
        evidence_summary="provider_status_applied",
        observed_at=observed,
        tenant_id=intent.tenant_id,
    )
    first = await ledger.reconcile(
        intent.execution_key,
        tenant_id=intent.tenant_id,
        expected_attempt=1,
        evidence=evidence,
    )
    duplicate = await ledger.reconcile(
        intent.execution_key,
        tenant_id=intent.tenant_id,
        expected_attempt=1,
        evidence=evidence,
    )
    assert first == duplicate

    conflict = ReconciliationEvidence(
        intent.execution_key,
        1,
        ReconciliationOutcome.NOT_APPLIED,
        evidence_summary="provider_status_not_applied",
        observed_at=observed,
        tenant_id=intent.tenant_id,
    )
    with pytest.raises(ReconciliationConflict, match="conflicts"):
        await ledger.reconcile(
            intent.execution_key,
            tenant_id=intent.tenant_id,
            expected_attempt=1,
            evidence=conflict,
        )


@pytest.mark.asyncio
async def test_stale_claim_and_cross_tenant_evidence_fail_closed() -> None:
    ledger, intent = await _ambiguous()
    claims = await ledger.claim_ambiguous(
        tenant_id=intent.tenant_id,
        owner_id="reconciler-a",
    )
    assert len(claims) == 1
    claim = claims[0]
    evidence = ReconciliationEvidence(
        intent.execution_key,
        1,
        ReconciliationOutcome.APPLIED,
        tenant_id="tenant-b",
    )
    with pytest.raises(ReconciliationConflict, match="out of scope"):
        await ledger.reconcile(
            intent.execution_key,
            tenant_id=intent.tenant_id,
            expected_attempt=1,
            evidence=evidence,
            claim_owner=claim.owner_id,
            claim_epoch=claim.claim_epoch,
        )

    good = ReconciliationEvidence(
        intent.execution_key,
        1,
        ReconciliationOutcome.APPLIED,
        tenant_id=intent.tenant_id,
    )
    with pytest.raises(ReconciliationConflict, match="stale"):
        await ledger.reconcile(
            intent.execution_key,
            tenant_id=intent.tenant_id,
            expected_attempt=2,
            evidence=good,
            claim_owner=claim.owner_id,
            claim_epoch=claim.claim_epoch,
        )

    assert (
        await ledger.claim_ambiguous(
            tenant_id=intent.tenant_id,
            owner_id="reconciler-b",
        )
        == []
    )


@pytest.mark.asyncio
async def test_two_reconcilers_cannot_share_an_unexpired_claim() -> None:
    ledger, intent = await _ambiguous()
    first, second = await asyncio.gather(
        ledger.claim_ambiguous(
            tenant_id=intent.tenant_id,
            owner_id="reconciler-a",
        ),
        ledger.claim_ambiguous(
            tenant_id=intent.tenant_id,
            owner_id="reconciler-b",
        ),
    )
    assert sorted(len(items) for items in (first, second)) == [0, 1]


def test_evidence_is_immutable_and_migration_extends_baseline_table() -> None:
    observed = datetime(2026, 1, 1, tzinfo=UTC)
    evidence = ReconciliationEvidence(
        "execution-a",
        1,
        ReconciliationOutcome.UNKNOWN,
        observed_at=observed,
        tenant_id="tenant-a",
    )
    with pytest.raises((AttributeError, TypeError)):
        evidence.outcome = ReconciliationOutcome.APPLIED  # type: ignore[misc]
    source = (
        Path(__file__).parents[2]
        / "migrations"
        / "versions"
        / "0027_tool_execution_reconciliation.py"
    ).read_text(encoding="utf-8")
    assert "ALTER TABLE tool_executions" in source
    assert "tool_execution_reconciliations" in source
    assert "FOREIGN KEY (tenant_id, execution_key)" in source
    assert "ON DELETE CASCADE" in source
    assert "ENABLE ROW LEVEL SECURITY" in source
    assert "FORCE ROW LEVEL SECURITY" in source
    assert "reconciliation_epoch" in source
    assert "trpc_tool_reconciler" in source
    assert "evidence_summary ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$'" in source
    assert "UNIQUE (tenant_id, execution_key, attempt, evidence_digest)" in source


@pytest.mark.asyncio
async def test_postgres_reconcile_uses_same_execution_row_and_fenced_cas() -> None:
    observed = datetime(2026, 1, 1, tzinfo=UTC)
    intent = _intent()
    evidence = ReconciliationEvidence(
        intent.execution_key,
        1,
        ReconciliationOutcome.APPLIED,
        evidence_summary="provider_status_applied",
        observed_at=observed,
        tenant_id=intent.tenant_id,
    )
    connection = _FakeConnection(
        rows=[
            {
                "status": "ambiguous",
                "attempt": 1,
                "reconciliation_owner": "reconciler-a",
                "reconciliation_epoch": 3,
                "reconciliation_lease_expires_at": datetime.now(UTC) + timedelta(minutes=1),
            },
            None,
            None,
            {
                "execution_key": intent.execution_key,
                "status": "succeeded",
                "attempt": 1,
            },
        ],
        values=["reconciliation-id"],
    )
    result = await PostgresExecutionLedger(_FakePool(connection)).reconcile(
        intent.execution_key,
        tenant_id=intent.tenant_id,
        expected_attempt=1,
        evidence=evidence,
        claim_owner="reconciler-a",
        claim_epoch=3,
    )
    assert result.status is ExecutionStatus.SUCCEEDED
    assert result.attempt == 1
    sql = [query for query, _ in connection.calls]
    assert any("tool_execution_reconciliations" in query for query in sql)
    assert any(
        "ON CONFLICT (tenant_id,execution_key,attempt,evidence_digest)" in query for query in sql
    )
    cas = [query for query in sql if "UPDATE tool_executions" in query]
    assert cas and "status IN ('ambiguous','unknown')" in cas[0]
    assert "reconciliation_owner=$8" in cas[0]


@pytest.mark.asyncio
async def test_postgres_claim_query_is_tenant_scoped_and_skip_locked() -> None:
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
                    "attempt": 1,
                    "reconciliation_owner": "reconciler-a",
                    "reconciliation_epoch": 1,
                    "reconciliation_lease_expires_at": datetime.now(UTC) + timedelta(minutes=1),
                    "session_id": "session-a",
                    "app_id": "app-a",
                }
            ]
        ]
    )
    claims = await PostgresExecutionLedger(_FakePool(connection)).claim_ambiguous(
        tenant_id="tenant-a",
        owner_id="reconciler-a",
    )
    assert len(claims) == 1
    assert claims[0].intent.tenant_id == "tenant-a"
    query = connection.calls[1][0]
    assert "FOR UPDATE OF execution SKIP LOCKED" in query
    assert "execution.tenant_id=$1" in query
    assert "reconciliation_epoch=execution.reconciliation_epoch+1" in query


@pytest.mark.asyncio
async def test_memory_ledger_rejects_same_key_across_tenants() -> None:
    ledger = InMemoryExecutionLedger()
    await ledger.begin(
        "same-key",
        tenant_id="tenant-a",
        turn_id="turn-a",
        tool_name="write",
        risk=ToolRisk.NON_IDEMPOTENT,
        arguments_hash="a" * 64,
    )
    with pytest.raises(ExecutionIdentityConflict, match="another tenant"):
        await ledger.begin(
            "same-key",
            tenant_id="tenant-b",
            turn_id="turn-b",
            tool_name="write",
            risk=ToolRisk.NON_IDEMPOTENT,
            arguments_hash="a" * 64,
        )
