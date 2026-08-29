"""Exactly-once-by-intent execution for Agent Cell side effects.

The executor deliberately makes a conservative distinction between a known
failure and an unknown provider outcome.  A normal exception from an effect
call means the process cannot prove whether the provider applied the request,
so the receipt becomes ``ambiguous`` and a later automatic retry is refused.
Only :class:`KnownEffectFailure` is eligible for an automatic retry.  A human
can explicitly replay an ambiguous intent with an exact
:class:`~trpc_service.cell.intents.ConfirmationScope`.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from trpc_service.cell.intents import (
    ConfirmationScope,
    PolicyDecision,
    ToolIntent,
)


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
        super().__init__("effect requires an exact confirmation scope")
        self.receipt = receipt


class EffectKeyConflict(EffectExecutionError):
    """A caller attempted to reuse a key for a different logical intent."""


class EffectLeaseConflict(EffectExecutionError):
    """A stale worker attempted to finish a newer effect attempt."""


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
            receipt = replace(
                current,
                status=status,
                result=result if status == EffectStatus.SUCCEEDED else None,
                error_type=error_type,
                worker_id=worker_id or current.worker_id,
                completed_at=datetime.now(UTC),
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
        while True:
            async with self._lock:
                current = self.records.get(effect_key)
                if current is None or current.is_terminal:
                    return current
                event = self._event_for(effect_key)
            try:
                if timeout is None:
                    await event.wait()
                else:
                    await asyncio.wait_for(event.wait(), timeout=timeout)
            except TimeoutError:
                return await self.get(effect_key)


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
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("effect lease must be positive")
        if not worker_id:
            raise ValueError("worker_id must be non-empty")
        self.ledger = ledger or InMemoryEffectLedger()
        self.lease_seconds = lease_seconds
        self.worker_id = worker_id

    @staticmethod
    def effect_key_for(intent: ToolIntent) -> str:
        return intent.effect_key

    async def execute(
        self,
        intent: ToolIntent,
        effect: EffectCallable | None = None,
        *,
        call: EffectCallable | None = None,
        simulate: EffectCallable | None = None,
        confirmation_scope: ConfirmationScope | None = None,
        confirmation: ConfirmationScope | None = None,
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

        if effect is not None and call is not None:
            raise TypeError("provide effect or call, not both")
        effect_fn = effect or call
        scope = confirmation_scope or confirmation
        owner = worker_id or self.worker_id
        existing = await self.ledger.get(intent.effect_key)

        # A durable terminal result is authoritative.  In particular, do not
        # ask for a new confirmation or invoke a function again after success.
        if existing is not None and existing.status in {
            EffectStatus.SUCCEEDED,
            EffectStatus.SIMULATED,
            EffectStatus.DENIED,
        }:
            return existing

        if intent.policy_decision == PolicyDecision.DENY:
            return await self.ledger.record_policy(
                intent,
                status=EffectStatus.DENIED,
                error_type="policy_denied",
                worker_id=owner,
            )

        if intent.policy_decision == PolicyDecision.SIMULATE_ONLY:
            if existing is not None and existing.status == EffectStatus.REQUIRE_CONFIRMATION:
                # A previous policy decision cannot be bypassed by changing
                # only the caller's function; the intent is immutable.
                return existing
            simulation_result: Any = None
            if simulate is not None:
                simulation_result = await _call_effect(simulate)
            return (
                await self.ledger.record_policy(
                    replace_intent_decision(intent, PolicyDecision.SIMULATE_ONLY),
                    status=EffectStatus.SIMULATED,
                    worker_id=owner,
                )
                if simulate is None
                else await self._record_simulation_result(
                    intent,
                    simulation_result,
                    owner,
                )
            )

        confirmation_valid = scope is not None and scope.matches(intent)
        if intent.requires_confirmation and not confirmation_valid:
            if existing is not None and existing.status in {
                EffectStatus.AMBIGUOUS,
                EffectStatus.UNKNOWN,
                EffectStatus.REQUIRE_CONFIRMATION,
            }:
                return existing
            return await self.ledger.record_policy(
                intent,
                status=EffectStatus.REQUIRE_CONFIRMATION,
                error_type="confirmation_required",
                worker_id=owner,
            )

        if effect_fn is None:
            raise ValueError("an effect callable is required for an allow decision")

        claim = await self.ledger.claim(
            intent,
            manual_replay=manual_replay,
            confirmation_valid=confirmation_valid,
            lease_seconds=self.lease_seconds,
            worker_id=owner,
        )
        if not claim.acquired:
            if claim.receipt.status == EffectStatus.RUNNING and wait:
                waited = await self.ledger.wait(intent.effect_key, timeout=wait_timeout)
                return waited or claim.receipt
            return claim.receipt

        attempt = claim.receipt.attempt
        try:
            result = await _call_effect(effect_fn)
        except KnownEffectFailure as exc:
            return await self.ledger.complete(
                intent,
                attempt=attempt,
                status=EffectStatus.FAILED,
                error_type=type(exc).__name__,
                worker_id=owner,
            )
        except asyncio.CancelledError:
            # Cancellation can happen after the provider accepted the request;
            # persist ambiguity before propagating cancellation to the worker.
            await self.ledger.complete(
                intent,
                attempt=attempt,
                status=EffectStatus.AMBIGUOUS,
                error_type="CancelledError",
                worker_id=owner,
            )
            raise
        except Exception as exc:
            # The safe default is ambiguous, including ordinary network
            # errors.  A provider-specific adapter may raise
            # ``KnownEffectFailure`` only when it has a definitive negative
            # acknowledgement.
            error_type = type(exc).__name__
            return await self.ledger.complete(
                intent,
                attempt=attempt,
                status=EffectStatus.AMBIGUOUS,
                error_type=error_type,
                worker_id=owner,
            )
        return await self.ledger.complete(
            intent,
            attempt=attempt,
            status=EffectStatus.SUCCEEDED,
            result=result,
            worker_id=owner,
        )

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
        confirmation_scope: ConfirmationScope,
        **kwargs: Any,
    ) -> EffectReceipt:
        """Explicitly replay an ambiguous intent after exact approval."""

        return await self.execute(
            intent,
            effect,
            confirmation_scope=confirmation_scope,
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


def replace_intent_decision(intent: ToolIntent, decision: PolicyDecision) -> ToolIntent:
    """Return an equivalent intent with a different immutable policy decision.

    This helper is kept local to the effect plane so simulation results are
    represented without mutating the caller's intent.  The effect key does
    not include the policy decision, preserving one ledger row per logical
    side effect.
    """

    return ToolIntent(
        tenant_id=intent.tenant_id,
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
    "InMemoryEffectLedger",
    "KnownEffectFailure",
    "ToolEffectExecutor",
    "UnknownEffectOutcome",
]
