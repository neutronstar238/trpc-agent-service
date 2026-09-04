"""High-value deterministic coverage for the tool reconciliation boundary."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from trpc_service.faults import FaultStage, FaultStageEvent
from trpc_service.tenant.models import TenantContext, ToolRisk
from trpc_service.tool.confirmation import arguments_hash as canonical_arguments_hash
from trpc_service.tool.execution import (
    ExecutionIdentityConflict,
    ExecutionReconciliationConflict,
    ExecutionRecord,
    ExecutionStatus,
    HumanReviewRequired,
    InMemoryExecutionLedger,
    ToolExecutor,
)
from trpc_service.tool.reconciliation import (
    ExecutionProbeIntent,
    ExecutionReconciliationClaim,
    ProviderReconciler,
    ReconciliationConflict,
    ReconciliationEvidence,
    ReconciliationOutcome,
    ToolExecutionReconciliationCoordinator,
    reconciliation_status,
    validate_reconciliation_evidence,
)

OBSERVED_AT = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _intent(
    *,
    tenant_id: str = "tenant-a",
    execution_key: str = "execution-a",
    attempt: int = 1,
    trace_id: str | None = "trace-a",
) -> ExecutionProbeIntent:
    return ExecutionProbeIntent(
        tenant_id=tenant_id,
        execution_key=execution_key,
        turn_id="turn-a",
        tool_name="ticket.create",
        arguments_hash="a" * 64,
        app_id="app-a",
        session_id="session-a",
        trace_id=trace_id,
        attempt=attempt,
    )


def _evidence(
    intent: ExecutionProbeIntent,
    outcome: ReconciliationOutcome | str = ReconciliationOutcome.APPLIED,
    *,
    attempt: int | None = None,
    tenant_id: str | None = None,
    evidence_summary: str = "provider_status_applied",
    trace_id: str | None = None,
) -> ReconciliationEvidence:
    return ReconciliationEvidence(
        intent.execution_key,
        intent.attempt if attempt is None else attempt,
        outcome,
        evidence_summary=evidence_summary,
        trace_id=intent.trace_id if trace_id is None else trace_id,
        observed_at=OBSERVED_AT,
        tenant_id=intent.tenant_id if tenant_id is None else tenant_id,
    )


def _context(
    *,
    tenant_id: str = "tenant-a",
    app_id: str = "app-a",
    session_id: str = "session-a",
) -> TenantContext:
    return TenantContext(
        tenant_id=tenant_id,
        app_id=app_id,
        config_version=1,
        channel_binding_id="channel-a",
        principal_id="principal-a",
        session_id=session_id,
        request_id="request-a",
        trace_id="trace-a",
    )


async def _ambiguous(
    *,
    tenant_id: str = "tenant-a",
    execution_key: str = "execution-a",
    status: ExecutionStatus = ExecutionStatus.AMBIGUOUS,
) -> tuple[InMemoryExecutionLedger, ExecutionProbeIntent]:
    ledger = InMemoryExecutionLedger()
    intent = _intent(tenant_id=tenant_id, execution_key=execution_key)
    started = await ledger.begin(
        intent.execution_key,
        tenant_id=intent.tenant_id,
        turn_id=intent.turn_id,
        tool_name=intent.tool_name,
        risk=ToolRisk.NON_IDEMPOTENT,
        arguments_hash=intent.arguments_hash,
    )
    assert started.fresh
    await ledger.finish(intent.execution_key, tenant_id=tenant_id, status=status)
    return ledger, intent


@pytest.mark.parametrize(
    ("raw", "parsed"),
    [
        (ReconciliationOutcome.APPLIED, ReconciliationOutcome.APPLIED),
        (" APPLIED ", ReconciliationOutcome.APPLIED),
        ("not-applied", ReconciliationOutcome.NOT_APPLIED),
        ("unknown", ReconciliationOutcome.UNKNOWN),
    ],
)
def test_outcome_parser_aliases_and_status_mapping(
    raw: ReconciliationOutcome | str,
    parsed: ReconciliationOutcome,
) -> None:
    assert ReconciliationOutcome.parse(raw) is parsed
    assert (
        reconciliation_status(raw)
        is {
            ReconciliationOutcome.APPLIED: ExecutionStatus.SUCCEEDED,
            ReconciliationOutcome.NOT_APPLIED: ExecutionStatus.FAILED,
            ReconciliationOutcome.UNKNOWN: ExecutionStatus.UNKNOWN,
        }[parsed]
    )


@pytest.mark.parametrize("raw", [None, 1, object(), "", "pending", " APPLIED! "])
def test_outcome_parser_rejects_non_protocol_values(raw: object) -> None:
    with pytest.raises(ValueError, match="unsupported reconciliation outcome"):
        ReconciliationOutcome.parse(raw)  # type: ignore[arg-type]


def test_evidence_alias_normalization_digest_and_immutable_properties() -> None:
    evidence = ReconciliationEvidence(
        "execution-a",
        1,
        result="applied",
        evidence_summary="provider_status_applied",
        observed_at=datetime(2026, 1, 1, 12, 0),
        tenant_id="tenant-a",
    )
    assert evidence.outcome is ReconciliationOutcome.APPLIED
    assert evidence.result is evidence.outcome
    assert evidence.summary == evidence.evidence_summary
    assert evidence.digest == evidence.evidence_digest == evidence.canonical_digest
    assert evidence.observed_at.tzinfo is UTC
    assert evidence.as_dict()["outcome"] == "applied"
    with pytest.raises((AttributeError, TypeError)):
        evidence.outcome = ReconciliationOutcome.UNKNOWN  # type: ignore[misc]


@pytest.mark.parametrize(
    ("kwargs", "error", "message"),
    [
        ({"outcome": None, "result": None}, ValueError, "outcome is required"),
        ({"outcome": "applied", "result": "not_applied"}, ValueError, "disagree"),
        ({"execution_key": "  "}, ValueError, "execution_key"),
        ({"attempt": True}, ValueError, "positive integer"),
        ({"attempt": 0}, ValueError, "positive integer"),
        ({"evidence_summary": "UPPER"}, ValueError, "evidence_summary"),
        ({"evidence_summary": ""}, ValueError, "evidence_summary"),
        ({"trace_id": 7}, TypeError, "trace_id"),
        ({"reconciler_id": " "}, ValueError, "reconciler_id"),
        ({"tenant_id": " "}, ValueError, "tenant_id"),
        ({"evidence_digest": "0" * 64}, ValueError, "evidence_digest"),
        ({"evidence_digest": "x" * 64}, ValueError, "evidence_digest"),
    ],
)
def test_evidence_constructor_validates_protocol_boundaries(
    kwargs: dict[str, object], error: type[Exception], message: str
) -> None:
    base: dict[str, object] = {
        "execution_key": "execution-a",
        "attempt": 1,
        "outcome": ReconciliationOutcome.APPLIED,
        "evidence_summary": "provider_status_applied",
        "observed_at": OBSERVED_AT,
        "tenant_id": "tenant-a",
    }
    base.update(kwargs)
    with pytest.raises(error, match=message):
        ReconciliationEvidence(**base)  # type: ignore[arg-type]


def test_validate_evidence_rejects_type_attempt_namespace_and_tampered_digest() -> None:
    intent = _intent()
    evidence = _evidence(intent)
    with pytest.raises(TypeError, match="ReconciliationEvidence"):
        validate_reconciliation_evidence(
            object(),  # type: ignore[arg-type]
            execution_key=intent.execution_key,
            tenant_id=intent.tenant_id,
            expected_attempt=1,
        )
    with pytest.raises(ValueError, match="expected_attempt"):
        validate_reconciliation_evidence(
            evidence,
            execution_key=intent.execution_key,
            tenant_id=intent.tenant_id,
            expected_attempt=True,  # type: ignore[arg-type]
        )
    with pytest.raises(ReconciliationConflict, match="stale"):
        validate_reconciliation_evidence(
            evidence,
            execution_key=intent.execution_key,
            tenant_id=intent.tenant_id,
            expected_attempt=0,
        )
    for kwargs, message in [
        ({"expected_attempt": 2}, "stale"),
        ({"execution_key": "other"}, "does not match"),
        ({"tenant_id": "tenant-b"}, "out of scope"),
    ]:
        with pytest.raises(ReconciliationConflict, match=message):
            validate_reconciliation_evidence(
                evidence,
                execution_key=kwargs.get("execution_key", intent.execution_key),
                tenant_id=kwargs.get("tenant_id", intent.tenant_id),
                expected_attempt=kwargs.get("expected_attempt", 1),  # type: ignore[arg-type]
            )
    object.__setattr__(evidence, "evidence_digest", "0" * 64)
    with pytest.raises(ReconciliationConflict, match="digest"):
        validate_reconciliation_evidence(
            evidence,
            execution_key=intent.execution_key,
            tenant_id=intent.tenant_id,
            expected_attempt=1,
        )


def test_provider_reconciler_constructor_and_missing_probe_validation() -> None:
    with pytest.raises(TypeError, match="callable"):
        ProviderReconciler(7)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="reconciler_id"):
        ProviderReconciler(reconciler_id=" ")

    async def run() -> None:
        with pytest.raises(NotImplementedError, match="read-only provider probe"):
            await ProviderReconciler().probe(
                _intent(), ExecutionRecord("execution-a", ExecutionStatus.AMBIGUOUS)
            )

    asyncio.run(run())


@pytest.mark.asyncio
async def test_provider_reconciler_sync_async_mapping_and_typed_results() -> None:
    intent = _intent()
    receipt = ExecutionRecord(intent.execution_key, ExecutionStatus.AMBIGUOUS, attempt=3)
    seen: list[object] = []

    def sync_probe(queried: ExecutionProbeIntent, observed: object) -> str:
        seen.extend((queried, observed))
        return "applied"

    sync_evidence = await ProviderReconciler(sync_probe, reconciler_id="sync").probe(
        intent, receipt
    )
    assert sync_evidence.outcome is ReconciliationOutcome.APPLIED
    assert sync_evidence.attempt == 3
    assert sync_evidence.reconciler_id == "sync"
    assert seen == [intent, receipt]

    async def async_probe(_intent: ExecutionProbeIntent, _receipt: object) -> dict[str, object]:
        return {"result": "not-applied", "summary": "provider_status_not_applied"}

    mapped = await ProviderReconciler(async_probe).probe(intent, receipt)
    assert mapped.outcome is ReconciliationOutcome.NOT_APPLIED
    assert mapped.evidence_summary == "provider_status_not_applied"

    typed = _evidence(intent, ReconciliationOutcome.UNKNOWN)

    def typed_probe(_intent: ExecutionProbeIntent, _receipt: object) -> ReconciliationEvidence:
        return typed

    assert await ProviderReconciler(typed_probe).probe(intent, receipt) is typed


@pytest.mark.asyncio
async def test_provider_reconciler_invalid_mapping_summary_outcome_and_receipt_fallbacks() -> None:
    intent = _intent(trace_id="trace-intent")
    invalid_summary = await ProviderReconciler(
        lambda _intent, _receipt: {
            "outcome": "unknown",
            "evidence_summary": "Not-A-Code",
        }
    ).probe(intent, ExecutionRecord(intent.execution_key, ExecutionStatus.UNKNOWN, attempt=True))  # type: ignore[arg-type]
    assert invalid_summary.outcome is ReconciliationOutcome.UNKNOWN
    assert invalid_summary.evidence_summary == "provider_status_probe"
    assert invalid_summary.attempt == intent.attempt
    assert invalid_summary.trace_id == intent.trace_id

    invalid_outcome = await ProviderReconciler(
        lambda _intent, _receipt: {"outcome": "not-a-status", "summary": "provider_status_bad"}
    ).probe(intent, ExecutionRecord(intent.execution_key, ExecutionStatus.UNKNOWN, attempt=2))
    assert invalid_outcome.outcome is ReconciliationOutcome.UNKNOWN
    assert invalid_outcome.evidence_summary == "provider_status_unknown"
    assert invalid_outcome.attempt == 2

    none_outcome = await ProviderReconciler(lambda _intent, _receipt: None).probe(
        _intent(trace_id=None), ExecutionRecord("execution-a", ExecutionStatus.UNKNOWN, attempt=1)
    )
    assert none_outcome.outcome is ReconciliationOutcome.UNKNOWN
    assert none_outcome.trace_id is None


@pytest.mark.asyncio
async def test_coordinator_constructor_claim_empty_and_claim_metadata() -> None:
    ledger, intent = await _ambiguous()
    provider = ProviderReconciler(lambda _intent, _receipt: "applied", reconciler_id="provider")
    coordinator = ToolExecutionReconciliationCoordinator(ledger, provider)
    assert await coordinator.reconcile_pending(tenant_id="tenant-empty", owner_id="worker") == []

    claims = await ledger.claim_ambiguous(tenant_id=intent.tenant_id, owner_id="worker")
    assert len(claims) == 1
    claim = claims[0]
    assert claim.tenant_id == intent.tenant_id
    result = await coordinator.reconcile(claim)
    assert result.status is ExecutionStatus.SUCCEEDED
    assert ledger._reconciliation_claims == {}
    assert coordinator.reconciler_id == "provider"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "status"),
    [
        (ReconciliationOutcome.APPLIED, ExecutionStatus.SUCCEEDED),
        (ReconciliationOutcome.NOT_APPLIED, ExecutionStatus.FAILED),
        (ReconciliationOutcome.UNKNOWN, ExecutionStatus.UNKNOWN),
    ],
)
async def test_coordinator_direct_reconcile_each_outcome_and_receipt_paths(
    outcome: ReconciliationOutcome,
    status: ExecutionStatus,
) -> None:
    ledger, intent = await _ambiguous()
    coordinator = ToolExecutionReconciliationCoordinator(
        ledger, ProviderReconciler(lambda _intent, _receipt: outcome)
    )
    first = await coordinator.reconcile(intent, evidence=_evidence(intent, outcome))
    assert first.status is status

    # A second ambiguous row exercises the supplied receipt branch and the
    # coordinator's explicit expected-attempt fence.
    second_ledger, second_intent = await _ambiguous(execution_key="execution-b")
    second_coordinator = ToolExecutionReconciliationCoordinator(
        second_ledger, ProviderReconciler(lambda _intent, _receipt: outcome)
    )
    current = await second_ledger.get_record(
        second_intent.execution_key, tenant_id=second_intent.tenant_id
    )
    assert current is not None
    second = await second_coordinator.reconcile(
        second_intent,
        receipt=current,
        expected_attempt=1,
    )
    assert second.status is status


@pytest.mark.asyncio
async def test_coordinator_probe_exception_unknown_and_fence_errors() -> None:
    ledger, intent = await _ambiguous()

    async def unavailable(_intent: ExecutionProbeIntent, _receipt: object) -> object:
        raise TimeoutError("provider unavailable")

    coordinator = ToolExecutionReconciliationCoordinator(ledger, ProviderReconciler(unavailable))
    result = await coordinator.reconcile(intent)
    assert result.status is ExecutionStatus.UNKNOWN
    assert ledger._reconciliation_evidence[intent.execution_key][0].evidence_summary == (
        "provider_status_probe_unavailable"
    )

    missing_ledger = InMemoryExecutionLedger()
    with pytest.raises(ReconciliationConflict, match="not claimed"):
        await ToolExecutionReconciliationCoordinator(
            missing_ledger, ProviderReconciler(lambda _intent, _receipt: "applied")
        ).reconcile(intent)

    stale_ledger, stale_intent = await _ambiguous(execution_key="execution-stale")
    stale_current = await stale_ledger.get_record(
        stale_intent.execution_key, tenant_id=stale_intent.tenant_id
    )
    assert stale_current is not None
    with pytest.raises(ReconciliationConflict, match="stale"):
        await ToolExecutionReconciliationCoordinator(
            stale_ledger, ProviderReconciler(lambda _intent, _receipt: "applied")
        ).reconcile(stale_intent, receipt=stale_current, expected_attempt=2)


def test_coordinator_rejects_invalid_dependencies() -> None:
    with pytest.raises(TypeError, match="ledger"):
        ToolExecutionReconciliationCoordinator(object(), ProviderReconciler(lambda *_: "unknown"))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="reconciler"):
        ToolExecutionReconciliationCoordinator(InMemoryExecutionLedger(), object())  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_memory_begin_duplicate_terminal_and_idempotent_retry_paths() -> None:
    ledger = InMemoryExecutionLedger()
    common = {
        "tenant_id": "tenant-a",
        "turn_id": "turn-a",
        "tool_name": "write",
        "arguments_hash": "a" * 64,
    }
    fresh = await ledger.begin("key-success", risk=ToolRisk.IDEMPOTENT, **common)
    assert fresh.fresh and fresh.attempt == 1
    await ledger.finish(
        "key-success", tenant_id="tenant-a", status=ExecutionStatus.SUCCEEDED, result="done"
    )
    replay = await ledger.begin("key-success", risk=ToolRisk.IDEMPOTENT, **common)
    assert replay.result == "done" and not replay.fresh

    no_result = await ledger.begin("key-no-result", risk=ToolRisk.IDEMPOTENT, **common)
    assert no_result.fresh
    await ledger.finish("key-no-result", tenant_id="tenant-a", status=ExecutionStatus.SUCCEEDED)
    terminal_replay = await ledger.begin("key-no-result", risk=ToolRisk.IDEMPOTENT, **common)
    assert terminal_replay.replay_terminal
    with pytest.raises(ExecutionReconciliationConflict, match="no longer active"):
        await ledger.finish("key-no-result", status=ExecutionStatus.FAILED, tenant_id="tenant-a")

    ambiguous = await ledger.begin("key-ambiguous", risk=ToolRisk.NON_IDEMPOTENT, **common)
    assert ambiguous.fresh
    await ledger.finish("key-ambiguous", tenant_id="tenant-a", status=ExecutionStatus.AMBIGUOUS)
    blocked = await ledger.begin("key-ambiguous", risk=ToolRisk.NON_IDEMPOTENT, **common)
    assert blocked.status is ExecutionStatus.AMBIGUOUS and not blocked.fresh
    restarted = await ledger.begin("key-ambiguous", risk=ToolRisk.IDEMPOTENT, **common)
    assert restarted.fresh and restarted.attempt == 2

    await ledger.begin("key-unknown", risk=ToolRisk.NON_IDEMPOTENT, **common)
    await ledger.finish("key-unknown", tenant_id="tenant-a", status=ExecutionStatus.UNKNOWN)
    assert not (await ledger.begin("key-unknown", risk=ToolRisk.NON_IDEMPOTENT, **common)).fresh


@pytest.mark.asyncio
async def test_memory_begin_identity_and_started_duplicate_conflicts() -> None:
    ledger = InMemoryExecutionLedger()
    common = {
        "tenant_id": "tenant-a",
        "turn_id": "turn-a",
        "tool_name": "write",
        "risk": ToolRisk.NON_IDEMPOTENT,
        "arguments_hash": "a" * 64,
    }
    first = await ledger.begin("same", **common)
    duplicate = await ledger.begin("same", **common)
    assert duplicate == ledger.records["same"] and not duplicate.fresh
    with pytest.raises(ExecutionIdentityConflict, match="another tenant"):
        await ledger.begin("same", **{**common, "tenant_id": "tenant-b"})
    with pytest.raises(ExecutionIdentityConflict, match="another tenant"):
        await ledger.begin("same", **{**common, "turn_id": "turn-b"})
    assert first.fresh


@pytest.mark.asyncio
async def test_memory_finish_missing_tenant_duplicate_and_get_record_scope() -> None:
    ledger = InMemoryExecutionLedger()
    with pytest.raises(RuntimeError, match="does not exist"):
        await ledger.finish("missing", tenant_id="tenant-a", status=ExecutionStatus.FAILED)
    await ledger.begin(
        "finish-key",
        tenant_id="tenant-a",
        turn_id="turn-a",
        tool_name="write",
        risk=ToolRisk.IDEMPOTENT,
        arguments_hash="a" * 64,
    )
    with pytest.raises(ExecutionIdentityConflict, match="out of scope"):
        await ledger.finish("finish-key", tenant_id="tenant-b", status=ExecutionStatus.FAILED)
    await ledger.finish("finish-key", tenant_id="tenant-a", status=ExecutionStatus.FAILED)
    await ledger.finish("finish-key", tenant_id="tenant-a", status=ExecutionStatus.FAILED)
    with pytest.raises(ExecutionReconciliationConflict, match="no longer active"):
        await ledger.finish("finish-key", tenant_id="tenant-a", status=ExecutionStatus.SUCCEEDED)
    assert await ledger.get_record("missing", tenant_id="tenant-a") is None
    with pytest.raises(ExecutionIdentityConflict, match="out of scope"):
        await ledger.get_record("finish-key", tenant_id="tenant-b")


@pytest.mark.asyncio
async def test_memory_list_and_claim_validation_filtering_and_lease_epochs() -> None:
    ledger = InMemoryExecutionLedger()
    with pytest.raises(ValueError, match="between 1 and 1000"):
        await ledger.list_ambiguous(tenant_id="tenant-a", limit=0)
    with pytest.raises(ValueError, match="between 1 and 1000"):
        await ledger.list_ambiguous(tenant_id="tenant-a", limit=True)  # type: ignore[arg-type]
    for owner in ("", " "):
        with pytest.raises(ValueError, match="owner_id"):
            await ledger.claim_ambiguous(tenant_id="tenant-a", owner_id=owner)
    for lease in (True, "30", 0, 3601):
        with pytest.raises(ValueError, match="lease"):
            await ledger.claim_ambiguous(
                tenant_id="tenant-a",
                owner_id="worker",
                lease_seconds=lease,  # type: ignore[arg-type]
            )

    ledger, terminal_intent = await _ambiguous(execution_key="terminal")
    await ledger.begin(
        "succeeded",
        tenant_id="tenant-a",
        turn_id="turn-s",
        tool_name="read",
        risk=ToolRisk.IDEMPOTENT,
        arguments_hash=canonical_arguments_hash({"id": 1}),
    )
    await ledger.finish("succeeded", tenant_id="tenant-a", status=ExecutionStatus.SUCCEEDED)
    intents = await ledger.list_ambiguous(tenant_id="tenant-a", limit=1)
    assert len(intents) == 1 and intents[0].execution_key == terminal_intent.execution_key
    claims = await ledger.claim_ambiguous(tenant_id="tenant-a", owner_id="worker", lease_seconds=1)
    assert len(claims) == 1
    assert await ledger.claim_ambiguous(tenant_id="tenant-a", owner_id="other") == []
    claimed = claims[0]
    assert isinstance(claimed, ExecutionReconciliationClaim)
    ledger._reconciliation_claims[claimed.execution_key] = (
        claimed.owner_id,
        claimed.claim_epoch,
        datetime.now(UTC) - timedelta(seconds=1),
    )
    takeover = await ledger.claim_ambiguous(tenant_id="tenant-a", owner_id="other")
    assert len(takeover) == 1 and takeover[0].claim_epoch == claimed.claim_epoch + 1


@pytest.mark.asyncio
async def test_memory_reconcile_validates_type_scope_claim_epoch_and_status() -> None:
    ledger, intent = await _ambiguous()
    evidence = _evidence(intent)
    with pytest.raises(TypeError, match="ReconciliationEvidence"):
        await ledger.reconcile(
            intent.execution_key,
            tenant_id=intent.tenant_id,
            expected_attempt=1,
            evidence=object(),
        )
    missing_intent = _intent(execution_key="missing")
    with pytest.raises(ReconciliationConflict, match="not claimed"):
        await ledger.reconcile(
            "missing",
            tenant_id=intent.tenant_id,
            expected_attempt=1,
            evidence=_evidence(missing_intent),
        )
    with pytest.raises(ExecutionIdentityConflict, match="out of scope"):
        await ledger.reconcile(
            intent.execution_key,
            tenant_id="tenant-b",
            expected_attempt=1,
            evidence=_evidence(intent, tenant_id="tenant-b"),
        )
    with pytest.raises(ReconciliationConflict, match="stale"):
        await ledger.reconcile(
            intent.execution_key,
            tenant_id=intent.tenant_id,
            expected_attempt=2,
            evidence=_evidence(intent, attempt=2),
        )

    claim = (await ledger.claim_ambiguous(tenant_id=intent.tenant_id, owner_id="owner"))[0]
    with pytest.raises(ReconciliationConflict, match="invalid"):
        await ledger.reconcile(
            intent.execution_key,
            tenant_id=intent.tenant_id,
            expected_attempt=1,
            evidence=evidence,
            claim_owner=7,  # type: ignore[arg-type]
            claim_epoch=claim.claim_epoch,
        )
    with pytest.raises(ReconciliationConflict, match="stale"):
        await ledger.reconcile(
            intent.execution_key,
            tenant_id=intent.tenant_id,
            expected_attempt=1,
            evidence=evidence,
            claim_owner="other",
            claim_epoch=claim.claim_epoch,
        )
    with pytest.raises(ReconciliationConflict, match="stale"):
        await ledger.reconcile(
            intent.execution_key,
            tenant_id=intent.tenant_id,
            expected_attempt=1,
            evidence=evidence,
            claim_owner=claim.owner_id,
            claim_epoch=claim.claim_epoch + 1,
        )
    ledger._reconciliation_claims[intent.execution_key] = (
        claim.owner_id,
        claim.claim_epoch,
        datetime.now(UTC) - timedelta(seconds=1),
    )
    with pytest.raises(ReconciliationConflict, match="stale"):
        await ledger.reconcile(
            intent.execution_key,
            tenant_id=intent.tenant_id,
            expected_attempt=1,
            evidence=evidence,
            claim_owner=claim.owner_id,
            claim_epoch=claim.claim_epoch,
        )

    started_ledger = InMemoryExecutionLedger()
    started = await started_ledger.begin(
        "started",
        tenant_id="tenant-a",
        turn_id="turn-a",
        tool_name="write",
        risk=ToolRisk.IDEMPOTENT,
        arguments_hash="a" * 64,
    )
    assert started.fresh
    started_intent = _intent(execution_key="started")
    with pytest.raises(ReconciliationConflict, match="only ambiguous"):
        await started_ledger.reconcile(
            "started",
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=_evidence(started_intent),
        )


@pytest.mark.asyncio
async def test_memory_reconcile_final_state_history_and_unknown_idempotency() -> None:
    ledger, intent = await _ambiguous()
    applied = _evidence(intent, ReconciliationOutcome.APPLIED)
    assert (
        await ledger.reconcile(
            intent.execution_key,
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=applied,
        )
    ).status is ExecutionStatus.SUCCEEDED
    assert (
        await ledger.reconcile(
            intent.execution_key, tenant_id="tenant-a", expected_attempt=1, evidence=applied
        )
    ).status is ExecutionStatus.SUCCEEDED
    same_status_different_evidence = ReconciliationEvidence(
        intent.execution_key,
        1,
        ReconciliationOutcome.APPLIED,
        evidence_summary="provider_status_applied",
        observed_at=OBSERVED_AT + timedelta(seconds=1),
        tenant_id="tenant-a",
    )
    assert (
        await ledger.reconcile(
            intent.execution_key,
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=same_status_different_evidence,
        )
    ).status is ExecutionStatus.SUCCEEDED
    with pytest.raises(ReconciliationConflict, match="final execution state"):
        await ledger.reconcile(
            intent.execution_key,
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=_evidence(intent, ReconciliationOutcome.NOT_APPLIED),
        )

    unknown_ledger, unknown_intent = await _ambiguous(execution_key="unknown")
    unknown = _evidence(
        unknown_intent,
        ReconciliationOutcome.UNKNOWN,
        evidence_summary="provider_status_unknown",
    )
    first = await unknown_ledger.reconcile(
        "unknown", tenant_id="tenant-a", expected_attempt=1, evidence=unknown
    )
    assert first.status is ExecutionStatus.UNKNOWN
    assert (
        await unknown_ledger.reconcile(
            "unknown", tenant_id="tenant-a", expected_attempt=1, evidence=unknown
        )
    ).status is ExecutionStatus.UNKNOWN

    conflict_ledger, conflict_intent = await _ambiguous(execution_key="history")
    not_applied = _evidence(
        conflict_intent,
        ReconciliationOutcome.NOT_APPLIED,
        evidence_summary="provider_status_not_applied",
    )
    await conflict_ledger.reconcile(
        "history", tenant_id="tenant-a", expected_attempt=1, evidence=not_applied
    )
    # Reopen the in-memory test row to exercise the historical contradiction
    # guard without introducing a second provider execution.
    conflict_ledger.records["history"] = ExecutionRecord(
        "history", ExecutionStatus.UNKNOWN, attempt=1
    )
    with pytest.raises(ReconciliationConflict, match="conflicts"):
        await conflict_ledger.reconcile(
            "history",
            tenant_id="tenant-a",
            expected_attempt=1,
            evidence=_evidence(conflict_intent, ReconciliationOutcome.APPLIED),
        )


class _FaultRecorder:
    def __init__(self) -> None:
        self.events: list[FaultStageEvent] = []

    async def checkpoint(self, event: FaultStageEvent) -> bool:
        self.events.append(event)
        return True


@pytest.mark.asyncio
async def test_tool_executor_key_and_success_fault_checkpoint() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        ToolExecutor(b"short", InMemoryExecutionLedger())
    with pytest.raises(ValueError, match="between 0 and 5"):
        ToolExecutor(b"k" * 32, InMemoryExecutionLedger(), fault_stage_delay_seconds=6)
    context = _context()
    ledger = InMemoryExecutionLedger()
    recorder = _FaultRecorder()
    executor = ToolExecutor(
        b"k" * 32,
        ledger,
        fault_stages=recorder,
        worker_id="worker-a",
        fault_stage_delay_seconds=0.001,
    )
    key_a = executor.key_for(context, turn_id="turn-a", tool_name="read", arguments={"id": 1})
    key_b = executor.key_for(context, turn_id="turn-b", tool_name="read", arguments={"id": 1})
    assert key_a != key_b
    result = await executor.execute(
        context,
        turn_id="turn-a",
        tool_name="read",
        arguments={"id": 1},
        risk=ToolRisk.IDEMPOTENT,
        call=lambda: _return_value("ok"),
        owner_id="owner-a",
        fencing_token=3,
    )
    assert result == "ok"
    assert ledger.records[key_a].status is ExecutionStatus.SUCCEEDED
    no_delay_executor = ToolExecutor(b"k" * 32, ledger, fault_stages=recorder)
    no_delay_key = no_delay_executor.key_for(
        context, turn_id="turn-no-delay", tool_name="read", arguments={"id": 2}
    )
    assert (
        await no_delay_executor.execute(
            context,
            turn_id="turn-no-delay",
            tool_name="read",
            arguments={"id": 2},
            risk=ToolRisk.IDEMPOTENT,
            call=lambda: _return_value("no-delay"),
        )
        == "no-delay"
    )
    assert ledger.records[no_delay_key].status is ExecutionStatus.SUCCEEDED
    assert len(recorder.events) == 2
    event = recorder.events[0]
    assert event.stage is FaultStage.TOOL
    assert event.tenant_id == context.tenant_id and event.worker_id == "worker-a"


async def _return_value(value: Any) -> Any:
    return value


@pytest.mark.asyncio
async def test_tool_executor_failure_retry_review_and_terminal_replay_paths() -> None:
    context = _context()
    ledger = InMemoryExecutionLedger()
    executor = ToolExecutor(b"k" * 32, ledger)
    calls = 0

    async def fail() -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await executor.execute(
            context,
            turn_id="turn-idempotent",
            tool_name="write",
            arguments={"id": 1},
            risk=ToolRisk.IDEMPOTENT,
            call=fail,
        )
    failed_key = executor.key_for(
        context, turn_id="turn-idempotent", tool_name="write", arguments={"id": 1}
    )
    assert ledger.records[failed_key].status is ExecutionStatus.FAILED
    assert calls == 1
    assert (
        await executor.execute(
            context,
            turn_id="turn-idempotent",
            tool_name="write",
            arguments={"id": 1},
            risk=ToolRisk.IDEMPOTENT,
            call=lambda: _return_value("retried"),
        )
        == "retried"
    )
    assert ledger.records[failed_key].attempt == 2

    async def non_idempotent_fail() -> None:
        raise RuntimeError("provider write failed")

    with pytest.raises(HumanReviewRequired, match="unknown"):
        await executor.execute(
            context,
            turn_id="turn-non-idempotent-failure",
            tool_name="write",
            arguments={"id": 9},
            risk=ToolRisk.NON_IDEMPOTENT,
            call=non_idempotent_fail,
        )
    non_idempotent_failure_key = executor.key_for(
        context,
        turn_id="turn-non-idempotent-failure",
        tool_name="write",
        arguments={"id": 9},
    )
    assert ledger.records[non_idempotent_failure_key].status is ExecutionStatus.AMBIGUOUS

    non_idempotent_key = executor.key_for(
        context, turn_id="turn-non-idempotent", tool_name="write", arguments={"id": 2}
    )
    await ledger.begin(
        non_idempotent_key,
        tenant_id=context.tenant_id,
        turn_id="turn-non-idempotent",
        tool_name="write",
        risk=ToolRisk.NON_IDEMPOTENT,
        arguments_hash=canonical_arguments_hash({"id": 2}),
    )
    await ledger.finish(
        non_idempotent_key, tenant_id=context.tenant_id, status=ExecutionStatus.AMBIGUOUS
    )
    with pytest.raises(HumanReviewRequired, match="unknown"):
        await executor.execute(
            context,
            turn_id="turn-non-idempotent",
            tool_name="write",
            arguments={"id": 2},
            risk=ToolRisk.NON_IDEMPOTENT,
            call=lambda: _return_value("must-not-run"),
        )

    success_key = executor.key_for(
        context, turn_id="turn-success", tool_name="write", arguments={"id": 3}
    )
    await ledger.begin(
        success_key,
        tenant_id=context.tenant_id,
        turn_id="turn-success",
        tool_name="write",
        risk=ToolRisk.IDEMPOTENT,
        arguments_hash=canonical_arguments_hash({"id": 3}),
    )
    await ledger.finish(
        success_key, tenant_id=context.tenant_id, status=ExecutionStatus.SUCCEEDED, result="cached"
    )
    assert (
        await executor.execute(
            context,
            turn_id="turn-success",
            tool_name="write",
            arguments={"id": 3},
            risk=ToolRisk.IDEMPOTENT,
            call=lambda: _return_value("must-not-run"),
        )
        == "cached"
    )

    missing_result_key = executor.key_for(
        context, turn_id="turn-missing-result", tool_name="write", arguments={"id": 4}
    )
    await ledger.begin(
        missing_result_key,
        tenant_id=context.tenant_id,
        turn_id="turn-missing-result",
        tool_name="write",
        risk=ToolRisk.NON_IDEMPOTENT,
        arguments_hash=canonical_arguments_hash({"id": 4}),
    )
    await ledger.finish(
        missing_result_key,
        tenant_id=context.tenant_id,
        status=ExecutionStatus.SUCCEEDED,
    )
    with pytest.raises(HumanReviewRequired, match="result"):
        await executor.execute(
            context,
            turn_id="turn-missing-result",
            tool_name="write",
            arguments={"id": 4},
            risk=ToolRisk.NON_IDEMPOTENT,
            call=lambda: _return_value("must-not-run"),
        )

    replay_key = executor.key_for(
        context, turn_id="turn-replay", tool_name="write", arguments={"id": 5}
    )
    await ledger.begin(
        replay_key,
        tenant_id=context.tenant_id,
        turn_id="turn-replay",
        tool_name="write",
        risk=ToolRisk.IDEMPOTENT,
        arguments_hash=canonical_arguments_hash({"id": 5}),
    )
    await ledger.finish(replay_key, tenant_id=context.tenant_id, status=ExecutionStatus.SUCCEEDED)

    async def replay_failure() -> None:
        raise LookupError("result reconstruction failed")

    with pytest.raises(LookupError, match="reconstruction"):
        await executor.execute(
            context,
            turn_id="turn-replay",
            tool_name="write",
            arguments={"id": 5},
            risk=ToolRisk.IDEMPOTENT,
            call=replay_failure,
        )
    assert ledger.records[replay_key].status is ExecutionStatus.SUCCEEDED
    assert (
        await executor.execute(
            context,
            turn_id="turn-replay",
            tool_name="write",
            arguments={"id": 5},
            risk=ToolRisk.IDEMPOTENT,
            call=lambda: _return_value("reconstructed"),
        )
        == "reconstructed"
    )


@pytest.mark.asyncio
async def test_tool_executor_blocks_non_idempotent_existing_started_and_unknown() -> None:
    context = _context()
    executor = ToolExecutor(b"k" * 32, ledger := InMemoryExecutionLedger())
    key = executor.key_for(context, turn_id="turn-started", tool_name="write", arguments={"x": 1})
    await ledger.begin(
        key,
        tenant_id=context.tenant_id,
        turn_id="turn-started",
        tool_name="write",
        risk=ToolRisk.NON_IDEMPOTENT,
        arguments_hash=canonical_arguments_hash({"x": 1}),
    )
    called = False

    async def should_not_run() -> str:
        nonlocal called
        called = True
        return "bad"

    with pytest.raises(HumanReviewRequired, match="unknown"):
        await executor.execute(
            context,
            turn_id="turn-started",
            tool_name="write",
            arguments={"x": 1},
            risk=ToolRisk.NON_IDEMPOTENT,
            call=should_not_run,
        )
    assert not called
