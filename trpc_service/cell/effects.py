"""Exactly-once-by-intent execution for Agent Cell side effects.

The executor deliberately makes a conservative distinction between a known
failure and an unknown provider outcome.  A normal exception from an effect
call means the process cannot prove whether the provider applied the request,
so the receipt becomes ``ambiguous`` and a later automatic retry is refused.
Only :class:`KnownEffectFailure` is eligible for an automatic retry.  A human
can explicitly replay an ambiguous intent with a one-time signed approval
credential scoped to the exact intent.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import inspect
import json
import re
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from trpc_service.cell.intents import (
    ConfirmationScope,
    IntentIntegrityError,
    PolicyDecision,
    ToolIntent,
)

DEFAULT_WAIT_TIMEOUT_SECONDS = 30.0
MAX_POLICY_AUTHORIZATIONS = 4096
_RECONCILIATION_SUMMARY_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")


class EffectStatus(StrEnum):
    """Durable lifecycle states of an intent's effect ledger row."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"
    SIMULATED = "simulated"
    DENIED = "denied"
    REQUIRE_CONFIRMATION = "require_confirmation"

    # Friendly aliases used by callers that prefer execution terminology.
    IN_PROGRESS = "running"
    NEEDS_CONFIRMATION = "require_confirmation"
    allow = "succeeded"
    denied = "denied"
    ambiguous = "ambiguous"
    unknown = "unknown"

    @property
    def terminal(self) -> bool:
        return self not in {EffectStatus.PENDING, EffectStatus.RUNNING}


class ReconciliationOutcome(StrEnum):
    """The only outcomes a provider status probe may report.

    A probe is deliberately weaker than the provider's execution API.  It
    can establish that an effect was applied, establish that it was not
    applied, or leave the outcome unknown.  In particular, ``unknown`` is a
    terminal *ledger decision* that keeps automatic retries disabled.
    """

    APPLIED = "applied"
    NOT_APPLIED = "not_applied"
    UNKNOWN = "unknown"

    # The lowercase spellings are convenient for callers that use the enum
    # alongside the persisted status values.
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
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unsupported reconciliation outcome: {value!r}") from exc


@dataclass(frozen=True, slots=True, init=False)
class ReconciliationEvidence:
    """Content-free, immutable evidence from a provider status probe.

    ``evidence_summary`` is an operator-facing redacted summary, never the
    provider response or the original intent arguments.  ``result`` is
    accepted as a constructor alias for integrations that use the database
    column's terminology; both attributes expose the same enum value.
    """

    effect_key: str
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
        effect_key: str,
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
        if not isinstance(effect_key, str) or not effect_key:
            raise ValueError("effect_key must be a non-empty string")
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 0:
            raise ValueError("reconciliation attempt must be a non-negative integer")
        parsed_outcome = ReconciliationOutcome.parse(outcome)
        if not isinstance(evidence_summary, str):
            raise TypeError("evidence_summary must be a string")
        if not _RECONCILIATION_SUMMARY_RE.fullmatch(evidence_summary):
            raise ValueError("evidence_summary must be a short lowercase machine-readable code")
        if trace_id is not None and not isinstance(trace_id, str):
            raise TypeError("trace_id must be a string or None")
        if not isinstance(reconciler_id, str) or not reconciler_id.strip():
            raise ValueError("reconciler_id must be a non-empty string")
        if tenant_id is not None and (not isinstance(tenant_id, str) or not tenant_id.strip()):
            raise ValueError("tenant_id must be non-empty when provided")
        current_time = observed_at or datetime.now(UTC)
        if current_time.tzinfo is None or current_time.utcoffset() is None:
            current_time = current_time.replace(tzinfo=UTC)
        else:
            current_time = current_time.astimezone(UTC)
        digest_material = {
            "attempt": attempt,
            "effect_key": effect_key,
            "evidence_summary": evidence_summary,
            "outcome": parsed_outcome.value,
            "reconciler_id": reconciler_id,
            "tenant_id": tenant_id or "",
            "trace_id": trace_id or "",
            "observed_at": current_time.isoformat(),
        }
        canonical_digest = hashlib.sha256(_approval_json(digest_material)).hexdigest()
        if evidence_digest is None:
            evidence_digest = canonical_digest
        elif evidence_digest != canonical_digest:
            raise ValueError("evidence_digest does not match canonical evidence")
        if (
            not isinstance(evidence_digest, str)
            or len(evidence_digest) != 64
            or any(character not in "0123456789abcdef" for character in evidence_digest)
        ):
            raise ValueError("evidence_digest must be a lowercase SHA-256 hex digest")
        object.__setattr__(self, "effect_key", effect_key)
        object.__setattr__(self, "attempt", attempt)
        object.__setattr__(self, "outcome", parsed_outcome)
        object.__setattr__(self, "evidence_summary", evidence_summary)
        object.__setattr__(self, "trace_id", trace_id)
        object.__setattr__(self, "observed_at", current_time)
        object.__setattr__(self, "reconciler_id", reconciler_id)
        object.__setattr__(self, "evidence_digest", evidence_digest)
        object.__setattr__(self, "tenant_id", tenant_id)

    @property
    def result(self) -> ReconciliationOutcome:
        """Alias for the persisted ``outcome`` column."""

        return self.outcome

    @property
    def summary(self) -> str:
        """Short alias used by provider adapters."""

        return self.evidence_summary

    @property
    def canonical_digest(self) -> str:
        """Digest of all immutable evidence fields.

        This is independent of a caller-supplied ``evidence_digest`` and is
        used for duplicate/conflict checks at the ledger boundary.
        """

        material = {
            "attempt": self.attempt,
            "effect_key": self.effect_key,
            "evidence_summary": self.evidence_summary,
            "outcome": self.outcome.value,
            "reconciler_id": self.reconciler_id,
            "tenant_id": self.tenant_id or "",
            "trace_id": self.trace_id or "",
            "observed_at": self.observed_at.isoformat(),
        }
        return hashlib.sha256(_approval_json(material)).hexdigest()

    @property
    def digest(self) -> str:
        return self.evidence_digest

    def as_dict(self) -> dict[str, Any]:
        return {
            "effect_key": self.effect_key,
            "attempt": self.attempt,
            "outcome": self.outcome.value,
            "evidence_summary": self.evidence_summary,
            "trace_id": self.trace_id,
            "observed_at": self.observed_at.isoformat(),
            "reconciler_id": self.reconciler_id,
            "evidence_digest": self.evidence_digest,
            "tenant_id": self.tenant_id,
        }


def _is_reconciliation_summary(value: object) -> bool:
    return isinstance(value, str) and _RECONCILIATION_SUMMARY_RE.fullmatch(value) is not None


# This alias makes the public API self-documenting for storage code that uses
# ``ExecutionStatus`` terminology elsewhere in the service.
ExecutionStatus = EffectStatus


@dataclass(frozen=True, slots=True)
class EffectReceipt:
    """The durable result associated with one stable effect key."""

    effect_key: str
    status: EffectStatus
    intent_id: str = ""
    result: Any = None
    error_type: str | None = None
    attempt: int = 0
    replayed: bool = False
    worker_id: str | None = None
    trace_id: str | None = None
    intent_fingerprint: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    lease_expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.effect_key:
            raise ValueError("effect_key must be a non-empty string")
        if self.attempt < 0:
            raise ValueError("effect attempt must be non-negative")
        object.__setattr__(self, "status", EffectStatus(self.status))

    @property
    def is_terminal(self) -> bool:
        return self.status.terminal

    @property
    def is_unknown(self) -> bool:
        return self.status in {EffectStatus.UNKNOWN, EffectStatus.AMBIGUOUS}

    @property
    def manual_replay_required(self) -> bool:
        return self.is_unknown

    @property
    def safe_to_retry_automatically(self) -> bool:
        """Whether a fresh call may be made without human approval."""

        return self.status == EffectStatus.FAILED

    @property
    def succeeded(self) -> bool:
        return self.status in {EffectStatus.SUCCEEDED, EffectStatus.SIMULATED}

    def as_dict(self) -> dict[str, Any]:
        """Return a log-safe metadata view (the result is intentionally kept)."""

        return {
            "effect_key": self.effect_key,
            "intent_id": self.intent_id,
            "status": self.status.value,
            "attempt": self.attempt,
            "replayed": self.replayed,
            "worker_id": self.worker_id,
            "trace_id": self.trace_id,
            "error_type": self.error_type,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


@dataclass(frozen=True, slots=True)
class EffectClaim:
    """The atomic result of claiming an effect ledger row."""

    receipt: EffectReceipt
    acquired: bool

    @property
    def owned(self) -> bool:
        return self.acquired


class EffectExecutionError(RuntimeError):
    """Base class for errors that affect effect execution semantics."""


class KnownEffectFailure(EffectExecutionError):
    """The caller knows the provider did not apply the external effect.

    Raising this exception from an effect function records ``failed`` and
    permits a subsequent automatic retry.  A generic exception must not use
    this class unless the provider contract proves the operation was not
    applied.
    """


class UnknownEffectOutcome(EffectExecutionError):
    """The provider outcome cannot be established safely."""


class AmbiguousEffectOutcome(UnknownEffectOutcome):
    """Explicit spelling for a provider response lost after submission."""


class ConfirmationRequired(EffectExecutionError):
    """Raised by :meth:`execute_or_raise` when policy approval is missing."""

    def __init__(self, receipt: EffectReceipt) -> None:
        super().__init__("effect requires an exact approval credential")
        self.receipt = receipt


class EffectKeyConflict(EffectExecutionError):
    """A caller attempted to reuse a key for a different logical intent."""


class EffectLeaseConflict(EffectExecutionError):
    """A stale worker attempted to finish a newer effect attempt."""


class ReconciliationError(EffectExecutionError):
    """Base class for provider-outcome reconciliation failures."""


class ReconciliationConflict(ReconciliationError):
    """A stale, cross-tenant, or conflicting reconciliation was rejected."""


class ApprovalError(EffectExecutionError):
    """Base class for malformed, expired, or already consumed approvals."""


class InvalidApproval(ApprovalError):
    """An approval credential failed cryptographic or scope validation."""


@dataclass(frozen=True, slots=True, repr=False)
class ApprovalCredential:
    """Opaque, one-time credential issued by a trusted approval authority.

    The token is intentionally not included in ``repr`` so accidental object
    logging does not publish a credential that can authorize a side effect.
    A caller may pass either this object or its string token to the executor.
    """

    token: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.token, str) or not self.token:
            raise ValueError("approval token must be a non-empty string")


class ApprovalVerifier(Protocol):
    """Injection point for a platform approval service.

    Implementations must atomically verify scope and consume a credential.
    Returning ``False`` is intentionally indistinguishable from an invalid or
    already-used token at the effect boundary.
    """

    async def verify_and_consume(
        self,
        credential: ApprovalCredential | str,
        intent: ToolIntent,
        *,
        expected_scope: ConfirmationScope | None = None,
    ) -> bool: ...


class PolicyAuthority(Protocol):
    """Trusted policy decision provider used before an effect is claimed."""

    def decide(
        self, intent: ToolIntent
    ) -> PolicyDecision | str | Awaitable[PolicyDecision | str]: ...


PolicyJudge = Callable[[ToolIntent], PolicyDecision | str | Awaitable[PolicyDecision | str]]


class ApprovalLedger(Protocol):
    """Atomic one-time nonce store for :class:`CellApprovalAuthority`."""

    async def issue(self, nonce: str, expires_at: float, scope_digest: str) -> None: ...

    async def consume(self, nonce: str, expires_at: float, scope_digest: str) -> bool: ...


class InMemoryApprovalLedger:
    """Process-local nonce store for tests and development.

    Production deployments should provide a shared implementation backed by a
    conditional SQL update or Redis ``SETNX``/Lua transaction.
    """

    def __init__(self) -> None:
        self._records: dict[str, tuple[float, str, bool]] = {}
        self._lock = asyncio.Lock()

    async def issue(self, nonce: str, expires_at: float, scope_digest: str) -> None:
        async with self._lock:
            if nonce in self._records:
                raise ValueError("approval nonce already exists")
            self._records[nonce] = (expires_at, scope_digest, False)

    async def consume(self, nonce: str, expires_at: float, scope_digest: str) -> bool:
        async with self._lock:
            record = self._records.get(nonce)
            if record is None:
                return False
            stored_expiry, stored_digest, consumed = record
            now = time.time()
            if (
                consumed
                or stored_expiry <= now
                or expires_at != stored_expiry
                or not hmac.compare_digest(stored_digest, scope_digest)
            ):
                return False
            self._records[nonce] = (stored_expiry, stored_digest, True)
            return True


def _approval_b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _approval_unb64(value: str) -> bytes:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if not value or any(character not in alphabet for character in value):
        raise InvalidApproval("approval token encoding is invalid")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise InvalidApproval("approval token encoding is invalid") from exc


def _approval_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _approval_scope(
    intent: ToolIntent,
    approved_by: str,
    approval_id: str,
) -> dict[str, str]:
    return {
        "tenant_id": intent.tenant_id,
        "app_id": intent.app_id,
        "cell_id": intent.cell_id,
        "session_id": intent.session_id,
        "principal_id": intent.principal_id or "",
        "tool_name": intent.tool_name,
        "arguments_hash": intent.arguments_hash,
        "effect_key": intent.effect_key,
        "branch_id": intent.branch_id,
        "approved_by": approved_by,
        "approval_id": approval_id,
    }


def _approval_scope_digest(scope: Mapping[str, Any]) -> str:
    return hashlib.sha256(_approval_json(scope)).hexdigest()


class CellApprovalAuthority:
    """Mint and atomically consume signed, exact-scope Cell approvals.

    ``ConfirmationScope.for_intent`` remains a useful *description* for UI
    and compatibility, but it is not a credential.  Only a token minted by
    this authority (or an injected compatible ``ApprovalVerifier``) can cross
    the executor's high-risk boundary.
    """

    def __init__(
        self,
        signing_key: bytes,
        ledger: ApprovalLedger | None = None,
        *,
        ttl_seconds: int = 300,
    ) -> None:
        if not isinstance(signing_key, bytes) or len(signing_key) < 32:
            raise ValueError("approval signing key must contain at least 32 bytes")
        if ttl_seconds <= 0:
            raise ValueError("approval TTL must be positive")
        self._signing_key = signing_key
        self.ledger = ledger or InMemoryApprovalLedger()
        self.ttl_seconds = ttl_seconds

    async def issue(
        self,
        intent: ToolIntent,
        *,
        approved_by: str,
        approval_id: str,
        ttl_seconds: int | None = None,
    ) -> ApprovalCredential:
        intent.validate_integrity()
        if not approved_by or not approval_id:
            raise ValueError("approved_by and approval_id are required")
        ttl = self.ttl_seconds if ttl_seconds is None else ttl_seconds
        if ttl <= 0:
            raise ValueError("approval TTL must be positive")
        expires_at = time.time() + ttl
        nonce = secrets.token_urlsafe(18)
        scope = _approval_scope(intent, approved_by, approval_id)
        payload = {
            "v": 1,
            "nonce": nonce,
            "exp": expires_at,
            "scope": scope,
        }
        encoded = _approval_b64(_approval_json(payload))
        signature = _approval_b64(
            hmac.new(self._signing_key, encoded.encode("ascii"), hashlib.sha256).digest()
        )
        await self.ledger.issue(nonce, expires_at, _approval_scope_digest(scope))
        return ApprovalCredential(f"{encoded}.{signature}")

    # Explicit aliases make the trust boundary discoverable without changing
    # the compact primary API.
    issue_approval = issue
    mint = issue

    async def verify_and_consume(
        self,
        credential: ApprovalCredential | str,
        intent: ToolIntent,
        *,
        expected_scope: ConfirmationScope | None = None,
    ) -> bool:
        try:
            intent.validate_integrity()
            token = credential.token if isinstance(credential, ApprovalCredential) else credential
            if not isinstance(token, str):
                return False
            parts = token.split(".")
            if len(parts) != 2:
                return False
            encoded, supplied_signature = parts
            expected_signature = _approval_b64(
                hmac.new(
                    self._signing_key,
                    encoded.encode("ascii"),
                    hashlib.sha256,
                ).digest()
            )
            if not hmac.compare_digest(expected_signature, supplied_signature):
                return False
            payload = json.loads(_approval_unb64(encoded))
            if not isinstance(payload, dict) or payload.get("v") != 1:
                return False
            nonce = payload.get("nonce")
            expires_at = payload.get("exp")
            scope = payload.get("scope")
            if (
                not isinstance(nonce, str)
                or not isinstance(expires_at, (int, float))
                or not isinstance(scope, dict)
                or expires_at <= time.time()
            ):
                return False
            expected = _approval_scope(
                intent,
                str(scope.get("approved_by", "")),
                str(scope.get("approval_id", "")),
            )
            if scope != expected:
                return False
            if expected_scope is not None:
                if not expected_scope.matches(intent):
                    return False
                if (
                    expected_scope.approved_by
                    and expected_scope.approved_by != scope["approved_by"]
                ):
                    return False
                if (
                    expected_scope.approval_id
                    and expected_scope.approval_id != scope["approval_id"]
                ):
                    return False
            return await self.ledger.consume(
                nonce,
                float(expires_at),
                _approval_scope_digest(scope),
            )
        except (
            InvalidApproval,
            TypeError,
            ValueError,
            KeyError,
            UnicodeError,
            json.JSONDecodeError,
        ):
            return False


EffectCallable = Callable[[], Awaitable[Any] | Any]


class EffectLedger(Protocol):
    """Persistence contract for a durable effect ledger.

    ``claim`` must be atomic across all workers sharing a backend.  The
    in-memory implementation below is intended for local development and
    tests; production deployments should implement the same operations with a
    unique ``effect_key`` constraint and a fenced attempt/lease column.
    """

    async def get(self, effect_key: str) -> EffectReceipt | None: ...

    async def claim(
        self,
        intent: ToolIntent,
        *,
        manual_replay: bool = False,
        confirmation_valid: bool = False,
        lease_seconds: float = 60.0,
        worker_id: str | None = None,
    ) -> EffectClaim: ...

    async def record_policy(
        self,
        intent: ToolIntent,
        *,
        status: EffectStatus,
        error_type: str | None = None,
        worker_id: str | None = None,
    ) -> EffectReceipt: ...

    async def complete(
        self,
        intent: ToolIntent,
        *,
        attempt: int,
        status: EffectStatus,
        result: Any = None,
        error_type: str | None = None,
        worker_id: str | None = None,
    ) -> EffectReceipt: ...

    async def reconcile(
        self,
        intent: ToolIntent,
        expected_attempt: int,
        evidence: ReconciliationEvidence,
    ) -> EffectReceipt: ...

    async def wait(
        self,
        effect_key: str,
        *,
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> EffectReceipt | None: ...


def _intent_fingerprint(intent: ToolIntent) -> str:
    # The stable effect key already covers the identity relevant to external
    # side effects.  Keeping a separate fingerprint lets a ledger detect a
    # malicious or accidental caller that manually reuses a key.
    return ":".join(
        (
            intent.tenant_id,
            intent.app_id,
            intent.cell_id,
            intent.session_id,
            intent.intent_id,
            intent.tool_name,
            intent.arguments_hash,
            intent.branch_id,
            intent.principal_id or "",
            intent.capsule_digest or "",
        )
    )


def _reconciliation_status(outcome: ReconciliationOutcome) -> EffectStatus:
    return {
        ReconciliationOutcome.APPLIED: EffectStatus.SUCCEEDED,
        ReconciliationOutcome.NOT_APPLIED: EffectStatus.FAILED,
        ReconciliationOutcome.UNKNOWN: EffectStatus.UNKNOWN,
    }[outcome]


def _validate_reconciliation(
    intent: ToolIntent,
    expected_attempt: int,
    evidence: ReconciliationEvidence,
) -> None:
    if isinstance(expected_attempt, bool) or not isinstance(expected_attempt, int):
        raise ValueError("expected_attempt must be a non-negative integer")
    if expected_attempt < 0:
        raise ValueError("expected_attempt must be a non-negative integer")
    if not isinstance(evidence, ReconciliationEvidence):
        raise TypeError("evidence must be ReconciliationEvidence")
    try:
        intent.validate_integrity()
    except IntentIntegrityError as exc:
        raise EffectKeyConflict("intent integrity validation failed") from exc
    if evidence.effect_key != intent.effect_key:
        raise ReconciliationConflict("reconciliation effect key does not match intent")
    if evidence.attempt != expected_attempt:
        raise ReconciliationConflict("reconciliation evidence attempt is stale")
    if evidence.tenant_id != intent.tenant_id:
        raise ReconciliationConflict("reconciliation evidence tenant is out of scope")


class InMemoryEffectLedger:
    """Concurrency-safe effect ledger for tests and a single process.

    The lock covers claim/complete transitions, not user code.  Therefore a
    slow effect never blocks unrelated intent keys.  A second executor for
    the same key waits for the first terminal receipt and never invokes the
    effect function itself.
    """

    def __init__(self) -> None:
        self.records: dict[str, EffectReceipt] = {}
        self.history: dict[str, list[EffectReceipt]] = {}
        self.reconciliations: dict[tuple[str, int], ReconciliationEvidence] = {}
        self.reconciliation_history: dict[tuple[str, int], list[ReconciliationEvidence]] = {}
        self._lock = asyncio.Lock()
        self._done: dict[str, asyncio.Event] = {}

    @property
    def receipts(self) -> dict[str, EffectReceipt]:
        """Compatibility view of the durable rows."""

        return self.records

    def _event_for(self, effect_key: str) -> asyncio.Event:
        return self._done.setdefault(effect_key, asyncio.Event())

    def _append(self, receipt: EffectReceipt) -> None:
        self.records[receipt.effect_key] = receipt
        self.history.setdefault(receipt.effect_key, []).append(receipt)
        if receipt.is_terminal:
            self._event_for(receipt.effect_key).set()

    def _expire_if_needed_locked(
        self,
        effect_key: str,
        *,
        now: datetime | None = None,
    ) -> EffectReceipt | None:
        current = self.records.get(effect_key)
        if (
            current is None
            or current.status != EffectStatus.RUNNING
            or current.lease_expires_at is None
            or current.lease_expires_at > (now or datetime.now(UTC))
        ):
            return current
        ambiguous = replace(
            current,
            status=EffectStatus.AMBIGUOUS,
            error_type="effect_lease_expired",
            completed_at=now or datetime.now(UTC),
            lease_expires_at=None,
        )
        self._append(ambiguous)
        return ambiguous

    @staticmethod
    def _ensure_identity(current: EffectReceipt | None, intent: ToolIntent) -> None:
        if current is not None and current.intent_fingerprint not in {
            "",
            _intent_fingerprint(intent),
        }:
            raise EffectKeyConflict("effect key is already bound to another intent")

    async def get(self, effect_key: str) -> EffectReceipt | None:
        async with self._lock:
            return self.records.get(effect_key)

    @staticmethod
    def _validate_intent(intent: ToolIntent) -> None:
        try:
            intent.validate_integrity()
        except IntentIntegrityError as exc:
            # Keep the ledger's historical key-conflict vocabulary for direct
            # storage callers, while the executor exposes the more precise
            # integrity error before it reaches this layer.
            raise EffectKeyConflict("intent integrity validation failed") from exc

    async def claim(
        self,
        intent: ToolIntent,
        *,
        manual_replay: bool = False,
        confirmation_valid: bool = False,
        lease_seconds: float = 60.0,
        worker_id: str | None = None,
    ) -> EffectClaim:
        if lease_seconds <= 0:
            raise ValueError("effect lease must be positive")
        self._validate_intent(intent)
        async with self._lock:
            current = self.records.get(intent.effect_key)
            self._ensure_identity(current, intent)
            now = datetime.now(UTC)
            if current is not None:
                if current.status == EffectStatus.RUNNING:
                    expires_at = current.lease_expires_at
                    if expires_at is not None and expires_at <= now:
                        # A killed worker may have submitted the external
                        # request immediately before dying.  Its result is
                        # therefore unknown, never safe to auto-replay.
                        ambiguous = replace(
                            current,
                            status=EffectStatus.AMBIGUOUS,
                            error_type="effect_lease_expired",
                            completed_at=now,
                            lease_expires_at=None,
                        )
                        self._append(ambiguous)
                        return EffectClaim(ambiguous, False)
                    return EffectClaim(current, False)
                if current.status in {
                    EffectStatus.SUCCEEDED,
                    EffectStatus.SIMULATED,
                    EffectStatus.DENIED,
                }:
                    return EffectClaim(current, False)
                if current.status == EffectStatus.REQUIRE_CONFIRMATION and not confirmation_valid:
                    return EffectClaim(current, False)
                if current.status in {EffectStatus.AMBIGUOUS, EffectStatus.UNKNOWN}:
                    if not manual_replay or not confirmation_valid:
                        return EffectClaim(current, False)
                # ``FAILED`` is explicitly known not to have been applied and
                # is the only state eligible for an automatic retry.
                attempt = current.attempt + 1
                replayed = current.status in {EffectStatus.AMBIGUOUS, EffectStatus.UNKNOWN}
            else:
                attempt = 1
                replayed = False
            running = EffectReceipt(
                effect_key=intent.effect_key,
                intent_id=intent.intent_id,
                status=EffectStatus.RUNNING,
                attempt=attempt,
                replayed=replayed,
                worker_id=worker_id,
                trace_id=intent.trace_id,
                intent_fingerprint=_intent_fingerprint(intent),
                started_at=now,
                lease_expires_at=now + timedelta(seconds=lease_seconds),
            )
            event = self._event_for(intent.effect_key)
            event.clear()
            self._append(running)
            return EffectClaim(running, True)

    async def record_policy(
        self,
        intent: ToolIntent,
        *,
        status: EffectStatus,
        error_type: str | None = None,
        worker_id: str | None = None,
    ) -> EffectReceipt:
        if status not in {
            EffectStatus.DENIED,
            EffectStatus.SIMULATED,
            EffectStatus.REQUIRE_CONFIRMATION,
        }:
            raise ValueError("policy records must be denied, simulated, or confirmation-required")
        self._validate_intent(intent)
        async with self._lock:
            current = self.records.get(intent.effect_key)
            self._ensure_identity(current, intent)
            if current is not None:
                return current
            receipt = EffectReceipt(
                effect_key=intent.effect_key,
                intent_id=intent.intent_id,
                status=status,
                attempt=0,
                error_type=error_type,
                worker_id=worker_id,
                trace_id=intent.trace_id,
                intent_fingerprint=_intent_fingerprint(intent),
                completed_at=datetime.now(UTC),
            )
            self._append(receipt)
            return receipt

    async def complete(
        self,
        intent: ToolIntent,
        *,
        attempt: int,
        status: EffectStatus,
        result: Any = None,
        error_type: str | None = None,
        worker_id: str | None = None,
    ) -> EffectReceipt:
        if status not in {
            EffectStatus.SUCCEEDED,
            EffectStatus.FAILED,
            EffectStatus.AMBIGUOUS,
            EffectStatus.UNKNOWN,
        }:
            raise ValueError("effect completion must be succeeded, failed, or unknown")
        self._validate_intent(intent)
        async with self._lock:
            current = self.records.get(intent.effect_key)
            self._ensure_identity(current, intent)
            if current is None:
                raise EffectLeaseConflict("effect was not claimed")
            if current.status != EffectStatus.RUNNING:
                if current.attempt == attempt and current.status.terminal:
                    # A duplicate completion from the same worker is
                    # idempotent and must not overwrite the terminal receipt.
                    return current
                raise EffectLeaseConflict("effect claim is no longer active")
            if current.attempt != attempt:
                raise EffectLeaseConflict("effect attempt is fenced")
            if worker_id is not None and current.worker_id not in {None, worker_id}:
                raise EffectLeaseConflict("effect worker is fenced")
            lease_expires_at = current.lease_expires_at
            now = datetime.now(UTC)
            if lease_expires_at is not None and lease_expires_at <= now:
                # Never accept a result after the worker's fence expired.  The
                # provider may have applied the operation, so the only safe
                # durable outcome is ambiguous and manual review is required.
                ambiguous = replace(
                    current,
                    status=EffectStatus.AMBIGUOUS,
                    result=None,
                    error_type="effect_lease_expired",
                    completed_at=now,
                    lease_expires_at=None,
                )
                self._append(ambiguous)
                raise EffectLeaseConflict("effect lease expired before completion")
            receipt = replace(
                current,
                status=status,
                result=result if status == EffectStatus.SUCCEEDED else None,
                error_type=error_type,
                worker_id=worker_id or current.worker_id,
                completed_at=now,
                lease_expires_at=None,
            )
            self._append(receipt)
            return receipt

    async def reconcile(
        self,
        intent: ToolIntent,
        expected_attempt: int,
        evidence: ReconciliationEvidence,
    ) -> EffectReceipt:
        """CAS a provider probe into one ambiguous ledger attempt.

        Reconciliation never claims a new attempt and never invokes provider
        code.  The lock makes a duplicate probe idempotent while preserving a
        hard rejection for contradictory evidence.
        """

        _validate_reconciliation(intent, expected_attempt, evidence)
        async with self._lock:
            current = self.records.get(intent.effect_key)
            self._ensure_identity(current, intent)
            if current is None:
                raise EffectLeaseConflict("effect was not claimed")
            if current.attempt != expected_attempt:
                raise ReconciliationConflict("reconciliation attempt is fenced")
            key = (intent.effect_key, expected_attempt)
            history = self.reconciliation_history.get(key, [])
            if any(previous.canonical_digest == evidence.canonical_digest for previous in history):
                if current.status == _reconciliation_status(evidence.outcome):
                    return current
                raise ReconciliationConflict("reconciliation evidence has no matching ledger state")
            if current.status in {EffectStatus.SUCCEEDED, EffectStatus.FAILED}:
                if current.status != _reconciliation_status(evidence.outcome):
                    raise ReconciliationConflict("effect has already reached a final state")
                # A subsequent probe that confirms the same final outcome is
                # retained as immutable evidence without rewriting the effect
                # receipt.  Only contradictory evidence is rejected.
                self.reconciliations[key] = evidence
                self.reconciliation_history.setdefault(key, []).append(evidence)
                return current
            if current.status not in {EffectStatus.AMBIGUOUS, EffectStatus.UNKNOWN}:
                raise ReconciliationConflict(
                    "only ambiguous or unknown effect attempts may be reconciled"
                )
            self.reconciliations[key] = evidence
            self.reconciliation_history.setdefault(key, []).append(evidence)
            status = _reconciliation_status(evidence.outcome)
            error_type = {
                ReconciliationOutcome.APPLIED: None,
                ReconciliationOutcome.NOT_APPLIED: "provider_not_applied",
                ReconciliationOutcome.UNKNOWN: "provider_outcome_unknown",
            }[evidence.outcome]
            receipt = replace(
                current,
                status=status,
                result=None,
                error_type=error_type,
                trace_id=evidence.trace_id or current.trace_id,
                completed_at=evidence.observed_at,
                lease_expires_at=None,
            )
            self._append(receipt)
            return receipt

    async def wait(
        self,
        effect_key: str,
        *,
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> EffectReceipt | None:
        if timeout is None:
            timeout = DEFAULT_WAIT_TIMEOUT_SECONDS
        elif timeout < 0:
            raise ValueError("wait timeout must be non-negative")
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            async with self._lock:
                current = self._expire_if_needed_locked(effect_key)
                if current is None or current.is_terminal:
                    return current
                event = self._event_for(effect_key)
            try:
                remaining = max(0.0, deadline - asyncio.get_running_loop().time())
                await asyncio.wait_for(event.wait(), timeout=remaining)
            except TimeoutError:
                async with self._lock:
                    return self._expire_if_needed_locked(effect_key)


class ExactlyOnceEffectExecutor:
    """Execute a ToolIntent at most once unless a human approves replay.

    This class provides the policy and execution semantics.  Atomicity across
    processes is delegated to the supplied ``EffectLedger``; the built-in
    ledger is process-local and should not be used for multi-node production.
    """

    def __init__(
        self,
        ledger: EffectLedger | None = None,
        *,
        lease_seconds: float = 60.0,
        worker_id: str = "cell-effect-worker",
        wait_timeout_seconds: float = DEFAULT_WAIT_TIMEOUT_SECONDS,
        approval_verifier: ApprovalVerifier | None = None,
        approval_authority: ApprovalVerifier | None = None,
        policy_judge: PolicyJudge | None = None,
        policy_authority: PolicyAuthority | None = None,
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("effect lease must be positive")
        if not worker_id:
            raise ValueError("worker_id must be non-empty")
        if wait_timeout_seconds <= 0:
            raise ValueError("wait timeout must be positive")
        if approval_verifier is not None and approval_authority is not None:
            raise TypeError("provide approval_verifier or approval_authority, not both")
        if policy_judge is not None and policy_authority is not None:
            raise TypeError("provide policy_judge or policy_authority, not both")
        self.ledger = ledger or InMemoryEffectLedger()
        self.lease_seconds = lease_seconds
        self.worker_id = worker_id
        self.wait_timeout_seconds = wait_timeout_seconds
        self.approval_verifier = approval_verifier or approval_authority
        self.policy_judge = policy_judge
        self.policy_authority = policy_authority
        self._policy_authorizations: dict[str, tuple[ToolIntent, str | None]] = {}

    @staticmethod
    def effect_key_for(intent: ToolIntent) -> str:
        return intent.effect_key

    async def authorize(
        self,
        intent: ToolIntent,
    ) -> tuple[ToolIntent, str | None]:
        """Resolve policy once and return an executor-bound decision.

        The returned intent is not a bearer token by itself.  ``execute``
        accepts it only when this same executor previously produced and cached
        the exact value, so a caller cannot manufacture an ALLOW replacement
        and bypass the policy authority.  The cache also lets a runtime record
        the decision before invoking the effect without evaluating policy a
        second time.
        """

        intent.validate_integrity()
        effective_intent, policy_error = await self._resolve_policy(intent)
        if len(self._policy_authorizations) >= MAX_POLICY_AUTHORIZATIONS:
            self._policy_authorizations.pop(next(iter(self._policy_authorizations)))
        self._policy_authorizations[intent.effect_key] = (
            effective_intent,
            policy_error,
        )
        return effective_intent, policy_error

    async def execute(
        self,
        intent: ToolIntent,
        effect: EffectCallable | None = None,
        *,
        call: EffectCallable | None = None,
        simulate: EffectCallable | None = None,
        confirmation_scope: ConfirmationScope | None = None,
        confirmation: ConfirmationScope | None = None,
        approval_credential: ApprovalCredential | str | None = None,
        approval_token: ApprovalCredential | str | None = None,
        authorized_intent: ToolIntent | None = None,
        manual_replay: bool = False,
        wait: bool = True,
        wait_timeout: float | None = None,
        worker_id: str | None = None,
    ) -> EffectReceipt:
        """Evaluate policy and execute one intent.

        ``effect`` and ``call`` are aliases.  ``simulate`` is used only for a
        ``simulate_only`` policy and never enters the external effect path.
        Generic exceptions from ``effect`` are recorded as ``ambiguous`` and
        returned as a receipt; callers can inspect ``manual_replay_required``
        before deciding whether to ask for human approval.
        """

        intent.validate_integrity()
        if effect is not None and call is not None:
            raise TypeError("provide effect or call, not both")
        if confirmation_scope is not None and confirmation is not None:
            raise TypeError("provide confirmation_scope or confirmation, not both")
        if approval_credential is not None and approval_token is not None:
            raise TypeError("provide approval_credential or approval_token, not both")
        effect_fn = effect or call
        scope = confirmation_scope or confirmation
        credential = approval_credential or approval_token
        owner = worker_id or self.worker_id
        existing = await self.ledger.get(intent.effect_key)

        # A durable terminal result is authoritative.  In particular, do not
        # ask for a new confirmation or invoke a function again after success.
        if existing is not None and existing.status in {
            EffectStatus.SUCCEEDED,
            EffectStatus.SIMULATED,
            EffectStatus.DENIED,
        }:
            if authorized_intent is not None:
                self._policy_authorizations.pop(intent.effect_key, None)
            return existing

        if authorized_intent is None:
            effective_intent, policy_error = await self._resolve_policy(intent)
        else:
            try:
                authorized_intent.validate_integrity()
                cached = self._policy_authorizations.pop(intent.effect_key, None)
                if (
                    cached is None
                    or cached[0] != authorized_intent
                    or authorized_intent.effect_key != intent.effect_key
                ):
                    raise ValueError("authorization is not bound to this executor and intent")
                effective_intent, policy_error = cached
            except (IntentIntegrityError, ValueError):
                effective_intent = replace_intent_decision(intent, PolicyDecision.DENY)
                policy_error = "policy_authorization_invalid"

        if effective_intent.policy_decision == PolicyDecision.DENY:
            return await self.ledger.record_policy(
                effective_intent,
                status=EffectStatus.DENIED,
                error_type=policy_error or "policy_denied",
                worker_id=owner,
            )

        if effective_intent.policy_decision == PolicyDecision.SIMULATE_ONLY:
            if existing is not None and existing.status == EffectStatus.REQUIRE_CONFIRMATION:
                # A previous policy decision cannot be bypassed by changing
                # only the caller's function; the intent is immutable.
                return existing
            simulation_result: Any = None
            if simulate is not None:
                simulation_result = await _call_effect(simulate)
            return (
                await self.ledger.record_policy(
                    replace_intent_decision(effective_intent, PolicyDecision.SIMULATE_ONLY),
                    status=EffectStatus.SIMULATED,
                    worker_id=owner,
                )
                if simulate is None
                else await self._record_simulation_result(
                    effective_intent,
                    simulation_result,
                    owner,
                )
            )

        if effect_fn is None:
            raise ValueError("an effect callable is required for an allow decision")

        needs_approval = effective_intent.requires_confirmation or (
            manual_replay
            and existing is not None
            and existing.status in {EffectStatus.AMBIGUOUS, EffectStatus.UNKNOWN}
        )
        confirmation_valid = False
        if needs_approval:
            confirmation_valid = await self._verify_approval(
                credential,
                effective_intent,
                expected_scope=scope,
            )
        if needs_approval and not confirmation_valid:
            if existing is not None and existing.status in {
                EffectStatus.AMBIGUOUS,
                EffectStatus.UNKNOWN,
                EffectStatus.REQUIRE_CONFIRMATION,
            }:
                return existing
            return await self.ledger.record_policy(
                effective_intent,
                status=EffectStatus.REQUIRE_CONFIRMATION,
                error_type="approval_required",
                worker_id=owner,
            )

        claim = await self.ledger.claim(
            effective_intent,
            manual_replay=manual_replay,
            confirmation_valid=confirmation_valid,
            lease_seconds=self.lease_seconds,
            worker_id=owner,
        )
        if not claim.acquired:
            if claim.receipt.status == EffectStatus.RUNNING and wait:
                effective_wait_timeout = (
                    self.wait_timeout_seconds if wait_timeout is None else wait_timeout
                )
                if effective_wait_timeout < 0:
                    raise ValueError("wait timeout must be non-negative")
                waited = await self.ledger.wait(
                    effective_intent.effect_key,
                    timeout=effective_wait_timeout,
                )
                return waited or claim.receipt
            return claim.receipt

        attempt = claim.receipt.attempt
        try:
            result = await _call_effect(effect_fn)
        except KnownEffectFailure as exc:
            return await self._complete_safely(
                effective_intent,
                attempt=attempt,
                status=EffectStatus.FAILED,
                error_type=type(exc).__name__,
                worker_id=owner,
            )
        except asyncio.CancelledError:
            # Cancellation can happen after the provider accepted the request;
            # persist ambiguity before propagating cancellation to the worker.
            try:
                await self._complete_safely(
                    effective_intent,
                    attempt=attempt,
                    status=EffectStatus.AMBIGUOUS,
                    error_type="CancelledError",
                    worker_id=owner,
                )
            except EffectLeaseConflict:
                # Cancellation must retain its cancellation semantics even if
                # the worker lost its lease while trying to fence the result.
                pass
            raise
        except Exception as exc:
            # The safe default is ambiguous, including ordinary network
            # errors.  A provider-specific adapter may raise
            # ``KnownEffectFailure`` only when it has a definitive negative
            # acknowledgement.
            error_type = type(exc).__name__
            return await self._complete_safely(
                effective_intent,
                attempt=attempt,
                status=EffectStatus.AMBIGUOUS,
                error_type=error_type,
                worker_id=owner,
            )
        return await self._complete_safely(
            effective_intent,
            attempt=attempt,
            status=EffectStatus.SUCCEEDED,
            result=result,
            worker_id=owner,
        )

    async def _resolve_policy(self, intent: ToolIntent) -> tuple[ToolIntent, str | None]:
        """Resolve caller-provided policy through a trusted authority.

        A caller-supplied ALLOW is only a proposal.  Without an injected
        authority it is converted to DENY, and an authority failure is also a
        deny decision.  Explicit DENY and SIMULATE_ONLY decisions are already
        fail-safe and do not need an authority call.
        """

        if intent.policy_decision != PolicyDecision.ALLOW:
            return intent, None
        evaluator: PolicyJudge | None = self.policy_judge
        if self.policy_authority is not None:
            evaluator = self.policy_authority.decide
        if evaluator is None:
            return replace_intent_decision(intent, PolicyDecision.DENY), "policy_unverified"
        try:
            decision = await _call_policy(evaluator, intent)
            normalized = PolicyDecision.parse(decision)
        except Exception:
            return replace_intent_decision(intent, PolicyDecision.DENY), "policy_judge_error"
        return replace_intent_decision(intent, normalized), None

    async def _verify_approval(
        self,
        credential: ApprovalCredential | str | None,
        intent: ToolIntent,
        *,
        expected_scope: ConfirmationScope | None,
    ) -> bool:
        """Verify and consume a one-time approval at the effect boundary."""

        if credential is None or self.approval_verifier is None:
            # A plain ConfirmationScope is deliberately not sufficient: it is
            # an easily forgeable value object, not proof of human approval.
            return False
        if expected_scope is not None and not expected_scope.matches(intent):
            return False
        try:
            return bool(
                await self.approval_verifier.verify_and_consume(
                    credential,
                    intent,
                    expected_scope=expected_scope,
                )
            )
        except Exception:
            # An unavailable or malformed approval service must fail closed.
            return False

    async def _complete_safely(
        self,
        intent: ToolIntent,
        *,
        attempt: int,
        status: EffectStatus,
        result: Any = None,
        error_type: str | None = None,
        worker_id: str | None = None,
    ) -> EffectReceipt:
        """Fence late completions without losing the durable ambiguity row."""

        try:
            return await self.ledger.complete(
                intent,
                attempt=attempt,
                status=status,
                result=result,
                error_type=error_type,
                worker_id=worker_id,
            )
        except EffectLeaseConflict:
            current = await self.ledger.get(intent.effect_key)
            if (
                current is not None
                and current.attempt == attempt
                and current.status in {EffectStatus.AMBIGUOUS, EffectStatus.UNKNOWN}
            ):
                return current
            raise

    async def _record_simulation_result(
        self,
        intent: ToolIntent,
        result: Any,
        worker_id: str,
    ) -> EffectReceipt:
        # The public ledger protocol deliberately has no separate result
        # argument for policy rows, so an in-memory ledger can persist the
        # simulation result while other backends may choose to omit it.
        receipt = await self.ledger.record_policy(
            intent,
            status=EffectStatus.SIMULATED,
            worker_id=worker_id,
        )
        if isinstance(self.ledger, InMemoryEffectLedger):
            async with self.ledger._lock:
                current = self.ledger.records.get(intent.effect_key)
                if current is not None and current.status == EffectStatus.SIMULATED:
                    updated = replace(current, result=result)
                    self.ledger._append(updated)
                    return updated
        return receipt

    async def execute_or_raise(
        self, intent: ToolIntent, effect: EffectCallable, **kwargs: Any
    ) -> EffectReceipt:
        """Variant that raises for a missing confirmation scope."""

        receipt = await self.execute(intent, effect, **kwargs)
        if receipt.status == EffectStatus.REQUIRE_CONFIRMATION:
            raise ConfirmationRequired(receipt)
        return receipt

    async def replay(
        self,
        intent: ToolIntent,
        effect: EffectCallable,
        *,
        confirmation_scope: ConfirmationScope | None = None,
        approval_credential: ApprovalCredential | str | None = None,
        approval_token: ApprovalCredential | str | None = None,
        **kwargs: Any,
    ) -> EffectReceipt:
        """Explicitly replay an ambiguous intent after verified approval.

        ``confirmation_scope`` is retained as a compatibility hint and is
        never accepted as authorization by itself.  Pass a credential issued
        by :class:`CellApprovalAuthority` (or another injected verifier).
        """

        return await self.execute(
            intent,
            effect,
            confirmation_scope=confirmation_scope,
            approval_credential=approval_credential,
            approval_token=approval_token,
            manual_replay=True,
            **kwargs,
        )


# Concise aliases make the concept easy to discover from either vocabulary.
EffectExecutor = ExactlyOnceEffectExecutor
ToolEffectExecutor = ExactlyOnceEffectExecutor


async def _call_effect(effect: EffectCallable) -> Any:
    value = effect()
    if inspect.isawaitable(value):
        return await value
    return value


async def _call_policy(
    policy: PolicyJudge,
    intent: ToolIntent,
) -> PolicyDecision | str:
    value = policy(intent)
    if inspect.isawaitable(value):
        return await value
    return value


def replace_intent_decision(intent: ToolIntent, decision: PolicyDecision) -> ToolIntent:
    """Return an equivalent intent with a different immutable policy decision.

    This helper is kept local to the effect plane so simulation results are
    represented without mutating the caller's intent.  The effect key does
    not include the policy decision, preserving one ledger row per logical
    side effect.
    """

    return ToolIntent(
        tenant_id=intent.tenant_id,
        app_id=intent.app_id,
        cell_id=intent.cell_id,
        session_id=intent.session_id,
        tool_name=intent.tool_name,
        arguments=intent.arguments,
        intent_id=intent.intent_id,
        branch_id=intent.branch_id,
        policy_decision=decision,
        risk=intent.risk,
        principal_id=intent.principal_id,
        request_id=intent.request_id,
        trace_id=intent.trace_id,
        capsule_digest=intent.capsule_digest,
        metadata=intent.metadata,
        created_at=intent.created_at,
    )


__all__ = [
    "AmbiguousEffectOutcome",
    "ApprovalCredential",
    "ApprovalError",
    "ApprovalLedger",
    "ApprovalVerifier",
    "CellApprovalAuthority",
    "ConfirmationRequired",
    "EffectCallable",
    "EffectClaim",
    "EffectExecutionError",
    "EffectExecutor",
    "EffectKeyConflict",
    "EffectLeaseConflict",
    "EffectLedger",
    "EffectReceipt",
    "EffectStatus",
    "ExactlyOnceEffectExecutor",
    "ExecutionStatus",
    "InMemoryApprovalLedger",
    "InMemoryEffectLedger",
    "InvalidApproval",
    "KnownEffectFailure",
    "PolicyAuthority",
    "PolicyJudge",
    "ReconciliationConflict",
    "ReconciliationError",
    "ReconciliationEvidence",
    "ReconciliationOutcome",
    "ToolEffectExecutor",
    "UnknownEffectOutcome",
]
