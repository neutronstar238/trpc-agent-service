"""Regression tests for attempt isolation and monotonic reconciliation leases."""

from __future__ import annotations

import pytest

from tests.unit.test_tool_execution_reconciliation import _ambiguous
from trpc_service.tenant.models import ToolRisk
from trpc_service.tool.execution import ExecutionStatus
from trpc_service.tool.reconciliation import (
    ReconciliationConflict,
    ReconciliationEvidence,
    ReconciliationOutcome,
)


@pytest.mark.asyncio
async def test_prior_attempt_evidence_cannot_reject_a_later_attempt() -> None:
    ledger, intent = await _ambiguous()
    await ledger.reconcile(
        intent.execution_key,
        tenant_id=intent.tenant_id,
        expected_attempt=1,
        evidence=ReconciliationEvidence(
            intent.execution_key, 1, "not_applied", tenant_id=intent.tenant_id
        ),
    )
    restarted = await ledger.begin(
        intent.execution_key,
        tenant_id=intent.tenant_id,
        turn_id=intent.turn_id,
        tool_name=intent.tool_name,
        risk=ToolRisk.IDEMPOTENT,
        arguments_hash=intent.arguments_hash,
    )
    assert restarted.fresh and restarted.attempt == 2
    await ledger.finish(
        intent.execution_key, tenant_id=intent.tenant_id, status=ExecutionStatus.AMBIGUOUS
    )
    result = await ledger.reconcile(
        intent.execution_key,
        tenant_id=intent.tenant_id,
        expected_attempt=2,
        evidence=ReconciliationEvidence(
            intent.execution_key, 2, "applied", tenant_id=intent.tenant_id
        ),
    )
    assert result.status is ExecutionStatus.SUCCEEDED
    assert result.attempt == 2
    assert len(ledger._reconciliation_evidence[intent.execution_key]) == 2


@pytest.mark.asyncio
async def test_unknown_reprobe_never_reuses_a_consumed_lease_epoch() -> None:
    ledger, intent = await _ambiguous()
    first = (await ledger.claim_ambiguous(tenant_id=intent.tenant_id, owner_id="same-owner"))[0]
    await ledger.reconcile(
        intent.execution_key,
        tenant_id=intent.tenant_id,
        expected_attempt=1,
        claim_owner=first.owner_id,
        claim_epoch=first.claim_epoch,
        evidence=ReconciliationEvidence(
            intent.execution_key, 1, "unknown", tenant_id=intent.tenant_id
        ),
    )
    second = (await ledger.claim_ambiguous(tenant_id=intent.tenant_id, owner_id="same-owner"))[0]
    assert second.claim_epoch > first.claim_epoch
    applied = ReconciliationEvidence(
        intent.execution_key, 1, ReconciliationOutcome.APPLIED, tenant_id=intent.tenant_id
    )
    with pytest.raises(ReconciliationConflict, match="stale"):
        await ledger.reconcile(
            intent.execution_key,
            tenant_id=intent.tenant_id,
            expected_attempt=1,
            claim_owner=first.owner_id,
            claim_epoch=first.claim_epoch,
            evidence=applied,
        )
    result = await ledger.reconcile(
        intent.execution_key,
        tenant_id=intent.tenant_id,
        expected_attempt=1,
        claim_owner=second.owner_id,
        claim_epoch=second.claim_epoch,
        evidence=applied,
    )
    assert result.status is ExecutionStatus.SUCCEEDED


@pytest.mark.asyncio
@pytest.mark.parametrize("lease", [float("nan"), float("inf")])
async def test_reconciliation_lease_rejects_nonfinite_duration(lease: float) -> None:
    ledger, intent = await _ambiguous()
    with pytest.raises(ValueError, match="lease"):
        await ledger.claim_ambiguous(
            tenant_id=intent.tenant_id, owner_id="owner", lease_seconds=lease
        )
