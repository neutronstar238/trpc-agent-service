"""Durable reconciliation for the baseline ``tool_executions`` ledger.

The ordinary tool executor owns the only provider execution path.  This module
adds a deliberately narrower control-plane path for an outcome that became
ambiguous after the request was submitted: it may query a provider status
endpoint and CAS the result into the *same* execution ledger.  It never
replays a tool call and never creates a second effect ledger.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol, cast

from trpc_service.tool.execution import (
    ExecutionReconciliationConflict,
    ExecutionRecord,
    ExecutionStatus,
)

_SUMMARY_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")


class ReconciliationOutcome(StrEnum):
    """The only facts a read-only provider probe may establish."""

    APPLIED = "applied"
    NOT_APPLIED = "not_applied"
    UNKNOWN = "unknown"

    # Lowercase aliases make enum use ergonomic for storage-facing callers.
    applied = "applied"
    not_applied = "not_applied"
    unknown = "unknown"

    @classmethod
    def parse(cls, value: ReconciliationOutcome | str) -> ReconciliationOutcome:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            raise ValueError(f"unsupported reconciliation outcome: {value!r}")
        normalized = value.strip().lower().replace("-", "_")
        try:
            return cls(normalized)
        except ValueError as exc:
            raise ValueError(f"unsupported reconciliation outcome: {value!r}") from exc


@dataclass(frozen=True, slots=True, init=False)
class ReconciliationEvidence:
    """Immutable, content-free evidence returned by a provider status query.

    The constructor accepts ``result`` as a compatibility alias for
    ``outcome``.  The canonical digest includes every persisted field, so a
    caller cannot replace a prior probe with a different interpretation under
    the same digest.
    """

    execution_key: str
    attempt: int
    outcome: ReconciliationOutcome
    evidence_summary: str
    trace_id: str | None
    observed_at: datetime
    reconciler_id: str
    evidence_digest: str
    tenant_id: str | None

    def __init__(
        self,
        execution_key: str,
        attempt: int,
        outcome: ReconciliationOutcome | str | None = None,
        *,
        result: ReconciliationOutcome | str | None = None,
        evidence_summary: str = "provider_status_unknown",
        trace_id: str | None = None,
        observed_at: datetime | None = None,
        reconciler_id: str = "provider-reconciler",
        evidence_digest: str | None = None,
        tenant_id: str | None = None,
    ) -> None:
        if outcome is None:
            outcome = result
        elif result is not None and ReconciliationOutcome.parse(
            outcome
        ) != ReconciliationOutcome.parse(result):
            raise ValueError("outcome and result disagree")
        if outcome is None:
            raise ValueError("reconciliation outcome is required")
        if not isinstance(execution_key, str) or not execution_key.strip():
            raise ValueError("execution_key must be non-empty")
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
            raise ValueError("reconciliation attempt must be a positive integer")
        parsed = ReconciliationOutcome.parse(outcome)
        if not isinstance(evidence_summary, str) or _SUMMARY_RE.fullmatch(evidence_summary) is None:
            raise ValueError("evidence_summary must be a short lowercase machine-readable code")
        if trace_id is not None and not isinstance(trace_id, str):
            raise TypeError("trace_id must be a string or None")
        if not isinstance(reconciler_id, str) or not reconciler_id.strip():
            raise ValueError("reconciler_id must be non-empty")
        if tenant_id is not None and (not isinstance(tenant_id, str) or not tenant_id.strip()):
            raise ValueError("tenant_id must be non-empty when provided")
        current = observed_at or datetime.now(UTC)
        if current.tzinfo is None or current.utcoffset() is None:
            current = current.replace(tzinfo=UTC)
        else:
            current = current.astimezone(UTC)
        material = _canonical_json(
            {
                "attempt": attempt,
                "evidence_summary": evidence_summary,
                "execution_key": execution_key,
                "outcome": parsed.value,
                "reconciler_id": reconciler_id,
                "tenant_id": tenant_id or "",
                "trace_id": trace_id or "",
                "observed_at": current.isoformat(),
            }
        )
        canonical_digest = hashlib.sha256(material).hexdigest()
        if evidence_digest is None:
            evidence_digest = canonical_digest
        if evidence_digest != canonical_digest or not _is_sha256(evidence_digest):
            raise ValueError("evidence_digest does not match canonical evidence")
        object.__setattr__(self, "execution_key", execution_key)
        object.__setattr__(self, "attempt", attempt)
        object.__setattr__(self, "outcome", parsed)
        object.__setattr__(self, "evidence_summary", evidence_summary)
        object.__setattr__(self, "trace_id", trace_id)
        object.__setattr__(self, "observed_at", current)
        object.__setattr__(self, "reconciler_id", reconciler_id)
        object.__setattr__(self, "evidence_digest", evidence_digest)
        object.__setattr__(self, "tenant_id", tenant_id)

    @property
    def result(self) -> ReconciliationOutcome:
        return self.outcome

    @property
    def summary(self) -> str:
        return self.evidence_summary

    @property
    def canonical_digest(self) -> str:
        return hashlib.sha256(
            _canonical_json(
                {
                    "attempt": self.attempt,
                    "evidence_summary": self.evidence_summary,
                    "execution_key": self.execution_key,
                    "outcome": self.outcome.value,
                    "reconciler_id": self.reconciler_id,
                    "tenant_id": self.tenant_id or "",
                    "trace_id": self.trace_id or "",
                    "observed_at": self.observed_at.isoformat(),
                }
            )
        ).hexdigest()

    @property
    def digest(self) -> str:
        return self.evidence_digest

    def as_dict(self) -> dict[str, Any]:
        return {
            "execution_key": self.execution_key,
            "attempt": self.attempt,
            "outcome": self.outcome.value,
            "evidence_summary": self.evidence_summary,
            "trace_id": self.trace_id,
            "observed_at": self.observed_at.isoformat(),
            "reconciler_id": self.reconciler_id,
            "evidence_digest": self.evidence_digest,
            "tenant_id": self.tenant_id,
        }


@dataclass(frozen=True, slots=True)
class ExecutionProbeIntent:
    """Minimal non-sensitive identity passed to a status provider."""

    tenant_id: str
    execution_key: str
    turn_id: str
    tool_name: str
    arguments_hash: str
    app_id: str = ""
    session_id: str = ""
    trace_id: str | None = None
    attempt: int = 1


@dataclass(frozen=True, slots=True)
class ExecutionReconciliationClaim:
    """A durable, leased scan claim for one ambiguous execution."""

    intent: ExecutionProbeIntent
    status: ExecutionStatus
    attempt: int
    owner_id: str
    claim_epoch: int
    lease_expires_at: datetime

    @property
    def execution_key(self) -> str:
        return self.intent.execution_key

    @property
    def tenant_id(self) -> str:
        return self.intent.tenant_id


class ReconciliationConflict(ExecutionReconciliationConflict):
    """Public conflict type for stale, cross-tenant, or contradictory facts."""


def reconciliation_status(outcome: ReconciliationOutcome) -> ExecutionStatus:
    parsed = ReconciliationOutcome.parse(outcome)
    return {
        ReconciliationOutcome.APPLIED: ExecutionStatus.SUCCEEDED,
        ReconciliationOutcome.NOT_APPLIED: ExecutionStatus.FAILED,
        ReconciliationOutcome.UNKNOWN: ExecutionStatus.UNKNOWN,
    }[parsed]


def validate_reconciliation_evidence(
    evidence: ReconciliationEvidence,
    *,
    execution_key: str,
    tenant_id: str,
    expected_attempt: int,
) -> None:
    if not isinstance(evidence, ReconciliationEvidence):
        raise TypeError("evidence must be ReconciliationEvidence")
    if isinstance(expected_attempt, bool) or not isinstance(expected_attempt, int):
        raise ValueError("expected_attempt must be a positive integer")
    if expected_attempt < 1 or evidence.attempt != expected_attempt:
        raise ReconciliationConflict("reconciliation attempt is stale")
    if evidence.execution_key != execution_key:
        raise ReconciliationConflict("reconciliation execution key does not match")
    # Missing tenant scope is rejected, not interpreted as a wildcard.
    if evidence.tenant_id != tenant_id:
        raise ReconciliationConflict("reconciliation evidence tenant is out of scope")
    if evidence.canonical_digest != evidence.evidence_digest:
        raise ReconciliationConflict("reconciliation evidence digest is invalid")


ProbeResult = ReconciliationEvidence | ReconciliationOutcome | str | Mapping[str, object] | None
ProbeCallable = Callable[
    [ExecutionProbeIntent, ExecutionRecord | ExecutionReconciliationClaim],
    ProbeResult | Awaitable[ProbeResult],
]


class ProviderReconciler:
    """Provider adapter exposing only a read-only status probe.

    The callback is injected by a provider-specific integration.  It receives
    no tool callable and the coordinator never supplies one, so a scan cannot
    accidentally re-run a side effect.
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

    async def probe(
        self,
        intent: ExecutionProbeIntent,
        receipt: ExecutionRecord | ExecutionReconciliationClaim,
    ) -> ReconciliationEvidence:
        if self._probe is None:
            raise NotImplementedError("a read-only provider probe is required")
        raw = self._probe(intent, receipt)
        if inspect.isawaitable(raw):
            raw = await raw
        return self._coerce(raw, intent, receipt)

    def _coerce(
        self,
        raw: ProbeResult,
        intent: ExecutionProbeIntent,
        receipt: ExecutionRecord | ExecutionReconciliationClaim,
    ) -> ReconciliationEvidence:
        if isinstance(raw, ReconciliationEvidence):
            return raw
        summary = "provider_status_probe"
        candidate: object = raw
        if isinstance(raw, Mapping):
            candidate = raw.get("outcome", raw.get("result"))
            supplied_summary = raw.get("evidence_summary", raw.get("summary"))
            if isinstance(supplied_summary, str) and _SUMMARY_RE.fullmatch(supplied_summary):
                summary = supplied_summary
        try:
            outcome = ReconciliationOutcome.parse(cast(Any, candidate))
        except (TypeError, ValueError):
            outcome = ReconciliationOutcome.UNKNOWN
            summary = "provider_status_unknown"
        attempt = _receipt_attempt(receipt, intent.attempt)
        trace_id = _receipt_trace(receipt, intent.trace_id)
        return ReconciliationEvidence(
            intent.execution_key,
            attempt,
            outcome,
            evidence_summary=summary,
            trace_id=trace_id,
            reconciler_id=self.reconciler_id,
            tenant_id=intent.tenant_id,
        )


class ReconciliationLedger(Protocol):
    async def get_record(self, execution_key: str, *, tenant_id: str) -> ExecutionRecord | None: ...

    async def claim_ambiguous(
        self,
        *,
        tenant_id: str,
        owner_id: str,
        limit: int = 100,
        lease_seconds: float = 30.0,
    ) -> Sequence[ExecutionReconciliationClaim]: ...

    async def reconcile(
        self,
        execution_key: str,
        *,
        tenant_id: str,
        expected_attempt: int,
        evidence: ReconciliationEvidence,
        claim_owner: str | None = None,
        claim_epoch: int | None = None,
    ) -> ExecutionRecord: ...


class ToolExecutionReconciliationCoordinator:
    """Run query-only probes and converge one baseline execution row."""

    def __init__(
        self,
        ledger: ReconciliationLedger,
        reconciler: ProviderReconciler,
        *,
        reconciler_id: str | None = None,
    ) -> None:
        if ledger is None or not callable(getattr(ledger, "reconcile", None)):
            raise TypeError("ledger must expose reconcile()")
        if reconciler is None or not callable(getattr(reconciler, "probe", None)):
            raise TypeError("reconciler must expose probe()")
        self.ledger = ledger
        self.reconciler = reconciler
        self.reconciler_id = reconciler_id or reconciler.reconciler_id

    async def reconcile(
        self,
        intent: ExecutionProbeIntent | ExecutionReconciliationClaim,
        receipt: ExecutionRecord | ExecutionReconciliationClaim | None = None,
        evidence: ReconciliationEvidence | None = None,
        *,
        expected_attempt: int | None = None,
    ) -> ExecutionRecord:
        claim: ExecutionReconciliationClaim | None
        if isinstance(intent, ExecutionReconciliationClaim):
            claim = intent
            probe_intent = intent.intent
        else:
            claim = None
            probe_intent = intent
        current: ExecutionRecord | ExecutionReconciliationClaim | None = receipt or claim
        if current is None:
            current = await self.ledger.get_record(
                probe_intent.execution_key,
                tenant_id=probe_intent.tenant_id,
            )
        if current is None:
            raise ReconciliationConflict("tool execution was not claimed")
        attempt = expected_attempt or _receipt_attempt(current, probe_intent.attempt)
        if attempt != _receipt_attempt(current, attempt):
            raise ReconciliationConflict("reconciliation attempt is stale")
        if evidence is None:
            try:
                evidence = await self.reconciler.probe(probe_intent, current)
            except Exception:
                # Probe failure is not evidence of non-application.  Preserve
                # the ambiguity and keep automatic retry disabled.
                evidence = ReconciliationEvidence(
                    probe_intent.execution_key,
                    attempt,
                    ReconciliationOutcome.UNKNOWN,
                    evidence_summary="provider_status_probe_unavailable",
                    trace_id=_receipt_trace(current, probe_intent.trace_id),
                    reconciler_id=self.reconciler_id,
                    tenant_id=probe_intent.tenant_id,
                )
        validate_reconciliation_evidence(
            evidence,
            execution_key=probe_intent.execution_key,
            tenant_id=probe_intent.tenant_id,
            expected_attempt=attempt,
        )
        return await self.ledger.reconcile(
            probe_intent.execution_key,
            tenant_id=probe_intent.tenant_id,
            expected_attempt=attempt,
            evidence=evidence,
            claim_owner=claim.owner_id if claim is not None else None,
            claim_epoch=claim.claim_epoch if claim is not None else None,
        )

    async def reconcile_pending(
        self,
        *,
        tenant_id: str,
        owner_id: str,
        limit: int = 100,
        lease_seconds: float = 30.0,
    ) -> list[ExecutionRecord]:
        claims = await self.ledger.claim_ambiguous(
            tenant_id=tenant_id,
            owner_id=owner_id,
            limit=limit,
            lease_seconds=lease_seconds,
        )
        results: list[ExecutionRecord] = []
        for claim in claims:
            results.append(await self.reconcile(claim))
        return results


# Short aliases for integrations that use the Cell terminology while still
# pointing at the baseline tool ledger.
EffectReconciliationCoordinator = ToolExecutionReconciliationCoordinator
ExecutionReconciler = ToolExecutionReconciliationCoordinator


def _receipt_attempt(
    receipt: ExecutionRecord | ExecutionReconciliationClaim,
    fallback: int,
) -> int:
    attempt = getattr(receipt, "attempt", fallback)
    return attempt if isinstance(attempt, int) and not isinstance(attempt, bool) else fallback


def _receipt_trace(
    receipt: ExecutionRecord | ExecutionReconciliationClaim,
    fallback: str | None,
) -> str | None:
    trace_id = getattr(receipt, "trace_id", None)
    return trace_id if isinstance(trace_id, str) else fallback


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


__all__ = [
    "EffectReconciliationCoordinator",
    "ExecutionProbeIntent",
    "ExecutionReconciler",
    "ExecutionReconciliationClaim",
    "ProbeCallable",
    "ProviderReconciler",
    "ReconciliationConflict",
    "ReconciliationEvidence",
    "ReconciliationOutcome",
    "ToolExecutionReconciliationCoordinator",
    "reconciliation_status",
    "validate_reconciliation_evidence",
]
