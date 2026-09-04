"""Safe provider-outcome probes for the Cell effect ledger.

Reconciliation is intentionally separate from effect execution.  A
``ProviderReconciler`` may read provider state, but it has no execution API;
the coordinator only passes the resulting, redacted evidence to the ledger's
fenced CAS transition.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping

from trpc_service.cell.effects import (
    EffectLedger,
    EffectReceipt,
    EffectStatus,
    ReconciliationConflict,
    ReconciliationEvidence,
    ReconciliationOutcome,
    _is_reconciliation_summary,
)
from trpc_service.cell.intents import ToolIntent

ProbeResult = ReconciliationEvidence | ReconciliationOutcome | str | Mapping[str, object] | None
ProbeCallable = Callable[
    [ToolIntent, EffectReceipt],
    ProbeResult | Awaitable[ProbeResult],
]


class ProviderReconciler:
    """Adapter for a provider's read-only status endpoint.

    The callback is expected to perform a status/query operation only.  It
    may return a fully formed :class:`ReconciliationEvidence`, an outcome
    enum/string, or a small mapping containing ``outcome``/``result`` and an
    optional redacted ``evidence_summary``.  No callback result is persisted
    verbatim unless it is explicitly supplied as that summary.

    Subclasses may override :meth:`probe` when a provider has a richer
    adapter; the base class remains useful for tests and local integrations.
    """

    def __init__(
        self,
        probe: ProbeCallable | None = None,
        *,
        reconciler_id: str = "provider-reconciler",
    ) -> None:
        if probe is not None and not callable(probe):
            raise TypeError("probe must be callable")
        if not isinstance(reconciler_id, str) or not reconciler_id.strip():
            raise ValueError("reconciler_id must be non-empty")
        self._probe = probe
        self.reconciler_id = reconciler_id

    async def probe(self, intent: ToolIntent, receipt: EffectReceipt) -> ReconciliationEvidence:
        """Query provider state and normalize the redacted result."""

        if self._probe is None:
            raise NotImplementedError("a read-only provider probe is required")
        raw = self._probe(intent, receipt)
        if inspect.isawaitable(raw):
            raw = await raw
        return self._coerce(raw, intent, receipt)

    def _coerce(
        self,
        raw: ProbeResult,
        intent: ToolIntent,
        receipt: EffectReceipt,
    ) -> ReconciliationEvidence:
        if isinstance(raw, ReconciliationEvidence):
            return raw
        summary = "provider_status_probe"
        outcome: ReconciliationOutcome | str | None = None
        if isinstance(raw, Mapping):
            candidate = raw.get("outcome", raw.get("result"))
            if isinstance(candidate, (ReconciliationOutcome, str)):
                outcome = candidate
            supplied_summary = raw.get("evidence_summary", raw.get("summary"))
            if _is_reconciliation_summary(supplied_summary):
                summary = str(supplied_summary)
        elif isinstance(raw, (ReconciliationOutcome, str)):
            outcome = raw
        try:
            parsed_outcome = ReconciliationOutcome.parse(outcome) if outcome is not None else None
        except ValueError:
            parsed_outcome = None
        if parsed_outcome is None:
            outcome = ReconciliationOutcome.UNKNOWN
            summary = "provider_status_unknown"
        else:
            outcome = parsed_outcome
        return ReconciliationEvidence(
            effect_key=intent.effect_key,
            attempt=receipt.attempt,
            outcome=outcome,
            evidence_summary=summary,
            trace_id=receipt.trace_id or intent.trace_id,
            reconciler_id=self.reconciler_id,
            tenant_id=intent.tenant_id,
        )


class EffectReconciliationCoordinator:
    """Run one read-only probe and converge a fenced ledger attempt."""

    def __init__(
        self,
        ledger: EffectLedger,
        reconciler: ProviderReconciler | None = None,
        *,
        provider_reconciler: ProviderReconciler | None = None,
        reconciler_id: str | None = None,
    ) -> None:
        if reconciler is not None and provider_reconciler is not None:
            raise TypeError("pass only one provider reconciler")
        reconciler = reconciler or provider_reconciler
        if ledger is None or not callable(getattr(ledger, "reconcile", None)):
            raise TypeError("ledger must expose reconcile()")
        if reconciler is None or not callable(getattr(reconciler, "probe", None)):
            raise TypeError("reconciler must expose probe()")
        self.ledger = ledger
        self.reconciler = reconciler
        self.reconciler_id = reconciler_id

    async def reconcile(
        self,
        intent: ToolIntent,
        receipt: EffectReceipt | int | None = None,
        evidence: ReconciliationEvidence | None = None,
        *,
        expected_attempt: int | None = None,
    ) -> EffectReceipt:
        """Probe an ambiguous attempt and atomically converge its status.

        ``receipt`` may be omitted, in which case the coordinator reads the
        current ledger row.  An integer second positional argument is
        accepted as a compatibility shorthand for ``expected_attempt``.
        """

        supplied_attempt: int | None = None
        if isinstance(receipt, bool):
            raise TypeError("receipt must be an EffectReceipt or attempt integer")
        if isinstance(receipt, int):
            supplied_attempt = receipt
            receipt = None
        intent.validate_integrity()
        current = receipt or await self.ledger.get(intent.effect_key)
        if current is None:
            raise ReconciliationConflict("effect was not claimed")
        if current.effect_key != intent.effect_key:
            raise ReconciliationConflict("receipt effect key does not match intent")
        attempt = expected_attempt if expected_attempt is not None else supplied_attempt
        if attempt is None:
            attempt = current.attempt
        if attempt != current.attempt:
            raise ReconciliationConflict("reconciliation attempt is fenced")
        if (
            current.status not in {EffectStatus.AMBIGUOUS, EffectStatus.UNKNOWN}
            and evidence is None
        ):
            return current
        if evidence is None:
            try:
                probe_result: object = self.reconciler.probe(intent, current)
                if inspect.isawaitable(probe_result):
                    probe_result = await probe_result
                if not isinstance(probe_result, ReconciliationEvidence):
                    raise TypeError("provider probe must return ReconciliationEvidence")
                evidence = probe_result
            except Exception:
                # A failed status query cannot prove non-application.  Record
                # a redacted unknown result so automatic retry remains locked.
                evidence = ReconciliationEvidence(
                    effect_key=intent.effect_key,
                    attempt=attempt,
                    outcome=ReconciliationOutcome.UNKNOWN,
                    evidence_summary="provider_status_probe_unavailable",
                    trace_id=current.trace_id or intent.trace_id,
                    reconciler_id=self.reconciler_id or "effect-reconciler",
                    tenant_id=intent.tenant_id,
                )
        if not isinstance(evidence, ReconciliationEvidence):
            raise TypeError("provider probe must return ReconciliationEvidence")
        return await self.ledger.reconcile(intent, attempt, evidence)

    reconcile_effect = reconcile


__all__ = [
    "EffectReconciliationCoordinator",
    "ProbeCallable",
    "ProviderReconciler",
    "ReconciliationConflict",
    "ReconciliationEvidence",
    "ReconciliationOutcome",
]
