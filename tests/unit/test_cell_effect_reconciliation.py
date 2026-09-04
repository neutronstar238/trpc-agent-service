"""Unit coverage for the read-only effect reconciliation boundary."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from trpc_service.cell.effects import (
    EffectReceipt,
    EffectStatus,
    InMemoryEffectLedger,
    ReconciliationConflict,
    ReconciliationEvidence,
    ReconciliationOutcome,
)
from trpc_service.cell.intents import IntentRisk, PolicyDecision, ToolIntent
from trpc_service.cell.postgres import PostgresEffectLedger
from trpc_service.cell.reconciliation import (
    EffectReconciliationCoordinator,
    ProviderReconciler,
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
        rows: Sequence[object],
        values: Sequence[object],
    ) -> None:
        self.rows = list(rows)
        self.values = list(values)
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


class _FakePool:
    def __init__(self, connection: _FakeConnection) -> None:
        self.connection = connection

    def acquire(self) -> _AsyncContext:
        return _AsyncContext(self.connection)


def _intent(*, tenant_id: str = "tenant-a", intent_id: str = "intent-a") -> ToolIntent:
    return ToolIntent(
        tenant_id=tenant_id,
        app_id="app-a",
        cell_id="cell-a",
        session_id="session-a",
        capsule_digest="sha256:" + "a" * 64,
        branch_id="main",
        intent_id=intent_id,
        tool_name="ticket.create",
        arguments={"subject": "safe"},
        policy_decision=PolicyDecision.ALLOW,
        risk=IntentRisk.LOW,
        trace_id="trace-a",
    )


async def _ambiguous(
    intent: ToolIntent,
) -> tuple[InMemoryEffectLedger, int]:
    ledger = InMemoryEffectLedger()
    claim = await ledger.claim(intent, worker_id="worker-a")
    assert claim.acquired
    receipt = await ledger.complete(
        intent,
        attempt=claim.receipt.attempt,
        status=EffectStatus.AMBIGUOUS,
        worker_id="worker-a",
    )
    return ledger, receipt.attempt


@pytest.mark.parametrize(
    ("outcome", "status", "retryable"),
    [
        (ReconciliationOutcome.APPLIED, EffectStatus.SUCCEEDED, False),
        (ReconciliationOutcome.NOT_APPLIED, EffectStatus.FAILED, True),
        (ReconciliationOutcome.UNKNOWN, EffectStatus.UNKNOWN, False),
    ],
)
async def test_coordinator_maps_probe_outcome_without_reexecuting(
    outcome: ReconciliationOutcome,
    status: EffectStatus,
    retryable: bool,
) -> None:
    intent = _intent()
    ledger, attempt = await _ambiguous(intent)
    calls = 0

    async def read_only_probe(
        queried_intent: ToolIntent,
        queried_receipt: EffectReceipt,
    ) -> ReconciliationOutcome:
        nonlocal calls
        calls += 1
        assert queried_intent is intent
        assert queried_receipt.attempt == attempt
        return outcome

    coordinator = EffectReconciliationCoordinator(
        ledger,
        ProviderReconciler(read_only_probe, reconciler_id="fake-provider"),
    )
    receipt = await coordinator.reconcile(intent)

    assert receipt.status is status
    assert receipt.safe_to_retry_automatically is retryable
    assert calls == 1
    assert ledger.reconciliations[(intent.effect_key, attempt)].outcome is outcome


async def test_concurrent_duplicate_evidence_is_idempotent_and_conflicts_are_rejected() -> None:
    intent = _intent()
    ledger, attempt = await _ambiguous(intent)
    observed = datetime(2026, 1, 1, tzinfo=UTC)
    evidence = ReconciliationEvidence(
        intent.effect_key,
        attempt,
        result="applied",
        evidence_summary="provider_status_applied",
        trace_id="trace-a",
        reconciler_id="fake-provider",
        observed_at=observed,
        tenant_id=intent.tenant_id,
    )
    receipts = await asyncio.gather(
        ledger.reconcile(intent, attempt, evidence),
        ledger.reconcile(intent, attempt, evidence),
    )
    assert receipts[0] == receipts[1]
    assert len(ledger.reconciliation_history[(intent.effect_key, attempt)]) == 1

    conflict = ReconciliationEvidence(
        intent.effect_key,
        attempt,
        outcome=ReconciliationOutcome.NOT_APPLIED,
        evidence_summary="provider_status_conflict",
        trace_id="trace-a",
        reconciler_id="fake-provider",
        observed_at=observed,
        tenant_id=intent.tenant_id,
    )
    with pytest.raises(ReconciliationConflict):
        await ledger.reconcile(intent, attempt, conflict)


async def test_unknown_evidence_can_be_refined_once_more_without_replacing_history() -> None:
    intent = _intent()
    ledger, attempt = await _ambiguous(intent)
    unknown = ReconciliationEvidence(
        intent.effect_key,
        attempt,
        ReconciliationOutcome.UNKNOWN,
        evidence_summary="provider_status_pending",
        tenant_id=intent.tenant_id,
    )
    first = await ledger.reconcile(intent, attempt, unknown)
    assert first.status is EffectStatus.UNKNOWN

    applied = ReconciliationEvidence(
        intent.effect_key,
        attempt,
        ReconciliationOutcome.APPLIED,
        evidence_summary="provider_status_applied",
        tenant_id=intent.tenant_id,
    )
    second = await ledger.reconcile(intent, attempt, applied)
    assert second.status is EffectStatus.SUCCEEDED
    outcomes = [
        item.outcome for item in ledger.reconciliation_history[(intent.effect_key, attempt)]
    ]
    assert outcomes == [ReconciliationOutcome.UNKNOWN, ReconciliationOutcome.APPLIED]

    contradictory = ReconciliationEvidence(
        intent.effect_key,
        attempt,
        ReconciliationOutcome.NOT_APPLIED,
        evidence_summary="provider_status_not_applied",
        tenant_id=intent.tenant_id,
    )
    with pytest.raises(ReconciliationConflict):
        await ledger.reconcile(intent, attempt, contradictory)


async def test_provider_adapter_discards_arbitrary_provider_payloads() -> None:
    intent = _intent()
    ledger, _ = await _ambiguous(intent)
    receipt = await ledger.get(intent.effect_key)
    assert receipt is not None

    async def probe(
        queried_intent: ToolIntent,
        queried_receipt: EffectReceipt,
    ) -> dict[str, object]:
        del queried_intent, queried_receipt
        return {
            "result": "applied",
            "evidence_summary": "SECRET provider response with raw fields",
        }

    evidence = await ProviderReconciler(probe).probe(intent, receipt)
    assert evidence.outcome is ReconciliationOutcome.APPLIED
    assert evidence.evidence_summary == "provider_status_probe"
    assert "SECRET" not in evidence.evidence_summary


def test_evidence_requires_canonical_digest_and_safe_summary() -> None:
    observed = datetime(2026, 1, 1, tzinfo=UTC)
    valid = ReconciliationEvidence(
        "effect-key",
        1,
        ReconciliationOutcome.UNKNOWN,
        evidence_summary="provider_status_pending",
        observed_at=observed,
    )
    assert valid.evidence_digest == valid.canonical_digest
    with pytest.raises(ValueError):
        ReconciliationEvidence(
            "effect-key",
            1,
            ReconciliationOutcome.UNKNOWN,
            evidence_summary="provider_status_pending",
            observed_at=observed,
            evidence_digest="0" * 64,
        )
    with pytest.raises(ValueError):
        ReconciliationEvidence(
            "effect-key",
            1,
            ReconciliationOutcome.UNKNOWN,
            evidence_summary="Raw provider response",
            observed_at=observed,
        )


async def test_stale_attempt_and_cross_tenant_evidence_fail_closed() -> None:
    intent = _intent()
    ledger, attempt = await _ambiguous(intent)
    evidence = ReconciliationEvidence(
        intent.effect_key,
        attempt,
        outcome=ReconciliationOutcome.APPLIED,
        tenant_id="tenant-b",
    )
    with pytest.raises(ReconciliationConflict):
        await ledger.reconcile(intent, attempt, evidence)

    missing_tenant = ReconciliationEvidence(
        intent.effect_key,
        attempt,
        outcome=ReconciliationOutcome.APPLIED,
    )
    with pytest.raises(ReconciliationConflict):
        await ledger.reconcile(intent, attempt, missing_tenant)

    stale = ReconciliationEvidence(
        intent.effect_key,
        attempt + 1,
        outcome=ReconciliationOutcome.APPLIED,
        tenant_id=intent.tenant_id,
    )
    with pytest.raises(ReconciliationConflict):
        await ledger.reconcile(intent, attempt, stale)


async def test_unknown_probe_failure_remains_unknown_and_replay_is_blocked() -> None:
    intent = _intent()
    ledger, _ = await _ambiguous(intent)

    async def unavailable(
        queried_intent: ToolIntent,
        queried_receipt: EffectReceipt,
    ) -> ReconciliationOutcome:
        del queried_intent, queried_receipt
        raise RuntimeError("provider timeout with sensitive response omitted")

    receipt = await EffectReconciliationCoordinator(
        ledger,
        ProviderReconciler(unavailable),
    ).reconcile(intent)
    assert receipt.status is EffectStatus.UNKNOWN
    retry = await ledger.claim(intent)
    assert retry.acquired is False
    assert retry.receipt.status is EffectStatus.UNKNOWN


async def test_postgres_reconcile_is_tenant_scoped_and_uses_ambiguous_cas() -> None:
    intent = _intent()
    observed = datetime(2026, 1, 1, tzinfo=UTC)
    evidence = ReconciliationEvidence(
        intent.effect_key,
        1,
        ReconciliationOutcome.APPLIED,
        evidence_summary="status_endpoint_applied",
        trace_id=intent.trace_id,
        reconciler_id="fake-provider",
        observed_at=observed,
        tenant_id=intent.tenant_id,
    )
    event = {
        "tenant_id": intent.tenant_id,
        "app_id": intent.app_id,
        "cell_id": intent.cell_id,
        "session_id": intent.session_id,
        "capsule_digest": intent.capsule_digest,
        "branch_id": intent.branch_id,
        "sequence": 3,
        "event_id": "event-a",
        "payload": {
            "intent_id": intent.intent_id,
            "tool_name": intent.tool_name,
            "arguments_hash": intent.arguments_hash,
            "effect_key": intent.effect_key,
            "risk": str(intent.risk),
        },
    }
    intent_row = {
        "tenant_id": intent.tenant_id,
        "intent_id": intent.intent_id,
        "app_id": intent.app_id,
        "cell_id": intent.cell_id,
        "session_id": intent.session_id,
        "capsule_digest": intent.capsule_digest,
        "branch_id": intent.branch_id,
        "sequence": 3,
        "tool_name": intent.tool_name,
        "arguments_hash": intent.arguments_hash,
        "effect_key": intent.effect_key,
        "risk": str(intent.risk),
        "decision": str(intent.policy_decision),
    }
    ledger_row = {
        "effect_key": intent.effect_key,
        "intent_id": intent.intent_id,
        "status": "ambiguous",
        "attempt": 1,
        "lease_owner": "worker-a",
        "lease_epoch": 1,
        "lease_expires_at": None,
        "updated_at": observed,
        "tenant_id": intent.tenant_id,
        "app_id": intent.app_id,
        "cell_id": intent.cell_id,
        "session_id": intent.session_id,
        "capsule_digest": intent.capsule_digest,
        "branch_id": intent.branch_id,
    }
    receipt_row = {
        "attempt": 1,
        "result_hash": None,
        "error_type": "provider_timeout",
        "attempted_at": observed,
        "trace_id": intent.trace_id,
        "provider_reference": "worker-a",
    }
    connection = _FakeConnection(
        rows=[
            event,
            intent_row,
            ledger_row,
            receipt_row,
            None,
            {**ledger_row, "status": "succeeded"},
            {**receipt_row, "error_type": None, "provider_reference": "fake-provider"},
        ],
        values=[True, True],
    )
    receipt = await PostgresEffectLedger(
        _FakePool(connection), tenant_id=intent.tenant_id
    ).reconcile(intent, 1, evidence)

    assert receipt.status is EffectStatus.SUCCEEDED
    reconciliation_queries = [
        query for query, _ in connection.calls if "cell_effect_reconciliations" in query
    ]
    assert any(
        "INSERT INTO cell_effect_reconciliations" in query for query in reconciliation_queries
    )
    assert any(
        "ON CONFLICT (tenant_id, effect_key, attempt, evidence_digest)" in query
        for query in reconciliation_queries
    )
    cas_queries = [query for query, _ in connection.calls if "UPDATE cell_effect_ledger" in query]
    assert any("status IN ('ambiguous', 'unknown')" in query for query in cas_queries)
    assert any(
        "UPDATE cell_effect_receipts" in query and "status IN ('ambiguous', 'unknown')" in query
        for query, _ in connection.calls
    )
    assert all("raw provider" not in query.lower() for query in reconciliation_queries)


def test_evidence_is_immutable_and_migration_is_tenant_scoped() -> None:
    evidence = ReconciliationEvidence("effect-key", 1, ReconciliationOutcome.UNKNOWN)
    with pytest.raises((AttributeError, TypeError)):
        evidence.outcome = ReconciliationOutcome.APPLIED  # type: ignore[misc]
    migration = (
        Path(__file__).parents[2]
        / "migrations"
        / "versions"
        / ("0024_cell_effect_reconciliation.py")
    )
    source = migration.read_text(encoding="utf-8")
    assert "cell_effect_reconciliations" in source
    assert "ENABLE ROW LEVEL SECURITY" in source
    assert "FORCE ROW LEVEL SECURITY" in source
    assert "trpc_cell_reconciler" in source
    assert "evidence_summary" in source
    assert "provider response" in source
    assert "evidence_summary ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$'" in source
    assert "UNIQUE (tenant_id, effect_key, attempt, evidence_digest)" in source
    assert "GRANT SELECT, UPDATE ON cell_effect_receipts" in source
    assert "ON DELETE CASCADE" in source
    assert "NOCREATEDB NOCREATEROLE" in source


def test_reconciler_rejects_invalid_configuration() -> None:
    with pytest.raises(TypeError, match="probe must be callable"):
        ProviderReconciler(cast(Any, object()))
    with pytest.raises(ValueError, match="reconciler_id must be non-empty"):
        ProviderReconciler(reconciler_id=" ")


async def test_reconciler_without_probe_requires_a_read_only_adapter() -> None:
    intent = _intent()
    ledger, attempt = await _ambiguous(intent)
    del ledger

    with pytest.raises(NotImplementedError, match="read-only provider probe"):
        await ProviderReconciler().probe(
            intent,
            EffectReceipt(
                effect_key=intent.effect_key,
                status=EffectStatus.AMBIGUOUS,
                attempt=attempt,
            ),
        )


async def test_reconciler_preserves_already_redacted_evidence() -> None:
    intent = _intent()
    ledger, attempt = await _ambiguous(intent)
    evidence = ReconciliationEvidence(
        intent.effect_key,
        attempt,
        ReconciliationOutcome.APPLIED,
        evidence_summary="status_endpoint_applied",
        tenant_id=intent.tenant_id,
    )

    observed = await ProviderReconciler(lambda _intent, _receipt: evidence).probe(
        intent,
        EffectReceipt(
            effect_key=intent.effect_key,
            status=EffectStatus.AMBIGUOUS,
            attempt=attempt,
        ),
    )

    assert observed is evidence
    del ledger


async def test_reconciler_invalid_probe_outcome_is_safe_unknown() -> None:
    intent = _intent()
    ledger, attempt = await _ambiguous(intent)

    observed = await ProviderReconciler(
        lambda _intent, _receipt: {
            "outcome": "provider-secret-payload",
            "evidence_summary": "status_endpoint_applied",
        }
    ).probe(
        intent,
        EffectReceipt(
            effect_key=intent.effect_key,
            status=EffectStatus.AMBIGUOUS,
            attempt=attempt,
        ),
    )

    assert observed.outcome is ReconciliationOutcome.UNKNOWN
    assert observed.evidence_summary == "provider_status_unknown"
    del ledger


async def test_coordinator_validates_ledger_and_reconciler_dependencies() -> None:
    intent = _intent()
    ledger, receipt = await _ambiguous(intent)
    provider = ProviderReconciler(lambda _intent, _receipt: ReconciliationOutcome.UNKNOWN)

    with pytest.raises(TypeError, match="pass only one"):
        EffectReconciliationCoordinator(
            ledger,
            provider,
            provider_reconciler=provider,
        )
    with pytest.raises(TypeError, match="ledger must expose reconcile"):
        EffectReconciliationCoordinator(cast(Any, object()), provider)
    with pytest.raises(TypeError, match="reconciler must expose probe"):
        EffectReconciliationCoordinator(ledger)
    del receipt


async def test_coordinator_rejects_bool_receipt_and_accepts_attempt_shorthand() -> None:
    intent = _intent()
    ledger, attempt = await _ambiguous(intent)
    provider = ProviderReconciler(lambda _intent, _receipt: ReconciliationOutcome.APPLIED)
    coordinator = EffectReconciliationCoordinator(ledger, provider)

    with pytest.raises(TypeError, match="receipt must be"):
        await coordinator.reconcile(intent, True)

    evidence = ReconciliationEvidence(
        intent.effect_key,
        attempt,
        ReconciliationOutcome.APPLIED,
        evidence_summary="status_endpoint_applied",
        tenant_id=intent.tenant_id,
    )
    converged = await coordinator.reconcile(intent, attempt, evidence)

    assert converged.status is EffectStatus.SUCCEEDED


async def test_coordinator_rejects_missing_and_mismatched_receipts() -> None:
    intent = _intent()
    ledger = InMemoryEffectLedger()
    provider = ProviderReconciler(lambda _intent, _receipt: ReconciliationOutcome.UNKNOWN)
    coordinator = EffectReconciliationCoordinator(ledger, provider)

    with pytest.raises(ReconciliationConflict, match="not claimed"):
        await coordinator.reconcile(intent)

    wrong_receipt = EffectReceipt(
        effect_key="other-effect",
        status=EffectStatus.AMBIGUOUS,
        attempt=1,
    )
    with pytest.raises(ReconciliationConflict, match="does not match"):
        await coordinator.reconcile(intent, wrong_receipt)


def test_reconciliation_evidence_rejects_invalid_shapes() -> None:
    with pytest.raises(ValueError, match="unsupported reconciliation outcome"):
        ReconciliationOutcome.parse(1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="outcome and result disagree"):
        ReconciliationEvidence(
            "effect-key",
            1,
            ReconciliationOutcome.APPLIED,
            result=ReconciliationOutcome.NOT_APPLIED,
        )
    with pytest.raises(ValueError, match="outcome is required"):
        ReconciliationEvidence("effect-key", 1)
    with pytest.raises(ValueError, match="effect_key must"):
        ReconciliationEvidence("", 1, ReconciliationOutcome.UNKNOWN)
