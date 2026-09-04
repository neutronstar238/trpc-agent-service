"""Stable execution keys and non-idempotent ambiguity handling."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol, cast

from trpc_service.faults import FaultStage, FaultStageController, FaultStageEvent
from trpc_service.tenant.models import TenantContext, ToolRisk
from trpc_service.tool.confirmation import arguments_hash


class ExecutionStatus(StrEnum):
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    execution_key: str
    status: ExecutionStatus
    result: Any = None
    fresh: bool = False
    # A terminal success without a persisted result may be re-run only when
    # the storage ledger has validated the current turn fence.  The ledger
    # remains terminal and must not be finished/overwritten by the retry.
    replay_terminal: bool = False
    # Durable reconciliation uses the attempt as its execution fence.  This
    # field is appended with a default to preserve positional SDK callers.
    attempt: int = 0


class ExecutionIdentityConflict(RuntimeError):
    """A stable execution key was reused for another tenant or turn."""


class ExecutionReconciliationConflict(RuntimeError):
    """A reconciliation operation crossed an execution or claim fence."""


class ExecutionLedger(Protocol):
    async def begin(
        self,
        execution_key: str,
        *,
        tenant_id: str,
        turn_id: str,
        tool_name: str,
        risk: ToolRisk,
        arguments_hash: str,
        owner_id: str | None = None,
        fencing_token: int | None = None,
    ) -> ExecutionRecord: ...

    async def finish(
        self,
        execution_key: str,
        *,
        tenant_id: str,
        status: ExecutionStatus,
        result: Any = None,
        owner_id: str | None = None,
        fencing_token: int | None = None,
    ) -> None: ...


class InMemoryExecutionLedger:
    def __init__(self) -> None:
        self.records: dict[str, ExecutionRecord] = {}
        # Keep the legacy public ``records[key]`` view while retaining the
        # tenant/turn identity needed to reject a malicious key collision.
        self._identities: dict[str, tuple[str, str, str, str]] = {}
        self._attempts: dict[str, int] = {}
        self._reconciliation_claims: dict[str, tuple[str, int, datetime]] = {}
        self._reconciliation_evidence: dict[str, list[object]] = {}
        self._lock = asyncio.Lock()

    async def begin(
        self,
        execution_key: str,
        *,
        tenant_id: str,
        turn_id: str,
        tool_name: str,
        risk: ToolRisk,
        arguments_hash: str,
        owner_id: str | None = None,
        fencing_token: int | None = None,
    ) -> ExecutionRecord:
        identity = (tenant_id, turn_id, tool_name, arguments_hash)
        async with self._lock:
            existing = self.records.get(execution_key)
            previous_identity = self._identities.get(execution_key)
            if previous_identity is not None and previous_identity != identity:
                raise ExecutionIdentityConflict(
                    "execution key is already bound to another tenant or turn"
                )
            if existing:
                if (
                    existing.status == ExecutionStatus.SUCCEEDED
                    and existing.result is None
                    and risk == ToolRisk.IDEMPOTENT
                ):
                    return ExecutionRecord(
                        execution_key,
                        existing.status,
                        replay_terminal=True,
                        attempt=self._attempts.get(execution_key, existing.attempt),
                    )
                if (
                    existing.status
                    in {
                        ExecutionStatus.AMBIGUOUS,
                        ExecutionStatus.UNKNOWN,
                    }
                    and risk != ToolRisk.IDEMPOTENT
                ):
                    # An unknown non-idempotent outcome cannot be replayed.
                    return existing
                if (
                    existing.status
                    in {
                        ExecutionStatus.FAILED,
                        ExecutionStatus.AMBIGUOUS,
                        ExecutionStatus.UNKNOWN,
                    }
                    and risk == ToolRisk.IDEMPOTENT
                ):
                    attempt = self._attempts.get(execution_key, existing.attempt or 1) + 1
                    self._attempts[execution_key] = attempt
                    restarted = ExecutionRecord(
                        execution_key,
                        ExecutionStatus.STARTED,
                        attempt=attempt,
                        fresh=True,
                    )
                    self.records[execution_key] = restarted
                    self._reconciliation_claims.pop(execution_key, None)
                    return restarted
                return existing
            attempt = 1
            record = ExecutionRecord(
                execution_key,
                ExecutionStatus.STARTED,
                fresh=True,
                attempt=attempt,
            )
            self._identities[execution_key] = identity
            self._attempts[execution_key] = attempt
            self.records[execution_key] = ExecutionRecord(
                execution_key,
                ExecutionStatus.STARTED,
                attempt=attempt,
            )
            return record

    async def finish(
        self,
        execution_key: str,
        *,
        tenant_id: str,
        status: ExecutionStatus,
        result: Any = None,
        owner_id: str | None = None,
        fencing_token: int | None = None,
    ) -> None:
        async with self._lock:
            current = self.records.get(execution_key)
            if current is None:
                raise RuntimeError("tool execution does not exist")
            identity = self._identities.get(execution_key)
            if identity is not None and identity[0] != tenant_id:
                raise ExecutionIdentityConflict("execution tenant is out of scope")
            if current.status != ExecutionStatus.STARTED:
                # Duplicate terminal completion is idempotent; a conflicting
                # completion must never reopen or overwrite the fact.
                if current.status == status:
                    return
                raise ExecutionReconciliationConflict("execution is no longer active")
            attempt = self._attempts.get(execution_key, current.attempt)
            self.records[execution_key] = ExecutionRecord(
                execution_key,
                status,
                result,
                attempt=attempt,
            )

    async def get_record(
        self,
        execution_key: str,
        *,
        tenant_id: str,
    ) -> ExecutionRecord | None:
        async with self._lock:
            current = self.records.get(execution_key)
            identity = self._identities.get(execution_key)
            if identity is not None and identity[0] != tenant_id:
                raise ExecutionIdentityConflict("execution tenant is out of scope")
            return current

    async def list_ambiguous(
        self,
        *,
        tenant_id: str,
        limit: int = 100,
    ) -> list[object]:
        from trpc_service.tool.reconciliation import ExecutionProbeIntent

        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValueError("reconciliation limit must be between 1 and 1000")
        async with self._lock:
            result: list[object] = []
            for execution_key, record in self.records.items():
                identity = self._identities.get(execution_key)
                if identity is None or identity[0] != tenant_id:
                    continue
                if record.status not in {
                    ExecutionStatus.AMBIGUOUS,
                    ExecutionStatus.UNKNOWN,
                }:
                    continue
                result.append(
                    ExecutionProbeIntent(
                        tenant_id=identity[0],
                        execution_key=execution_key,
                        turn_id=identity[1],
                        tool_name=identity[2],
                        arguments_hash=identity[3],
                        attempt=self._attempts.get(execution_key, record.attempt),
                    )
                )
                if len(result) >= limit:
                    break
            return result

    async def claim_ambiguous(
        self,
        *,
        tenant_id: str,
        owner_id: str,
        limit: int = 100,
        lease_seconds: float = 30.0,
    ) -> list[object]:
        from trpc_service.tool.reconciliation import ExecutionReconciliationClaim

        if not isinstance(owner_id, str) or not owner_id.strip():
            raise ValueError("reconciliation owner_id is required")
        if not isinstance(lease_seconds, (int, float)) or isinstance(lease_seconds, bool):
            raise ValueError("reconciliation lease must be positive")
        if lease_seconds <= 0 or lease_seconds > 3600:
            raise ValueError("reconciliation lease must be between 0 and 3600 seconds")
        candidates = await self.list_ambiguous(tenant_id=tenant_id, limit=limit)
        now = datetime.now(UTC)
        claims: list[object] = []
        async with self._lock:
            for candidate in candidates:
                candidate = cast(Any, candidate)
                execution_key = candidate.execution_key
                previous = self._reconciliation_claims.get(execution_key)
                if previous is not None and previous[2] > now:
                    continue
                epoch = (previous[1] if previous is not None else 0) + 1
                expires = now + timedelta(seconds=float(lease_seconds))
                self._reconciliation_claims[execution_key] = (owner_id, epoch, expires)
                record = self.records[execution_key]
                claims.append(
                    ExecutionReconciliationClaim(
                        intent=candidate,
                        status=record.status,
                        attempt=self._attempts.get(execution_key, record.attempt),
                        owner_id=owner_id,
                        claim_epoch=epoch,
                        lease_expires_at=expires,
                    )
                )
            return claims

    async def reconcile(
        self,
        execution_key: str,
        *,
        tenant_id: str,
        expected_attempt: int,
        evidence: object,
        claim_owner: str | None = None,
        claim_epoch: int | None = None,
    ) -> ExecutionRecord:
        from trpc_service.tool.reconciliation import (
            ReconciliationConflict,
            ReconciliationEvidence,
            ReconciliationOutcome,
            reconciliation_status,
            validate_reconciliation_evidence,
        )

        if not isinstance(evidence, ReconciliationEvidence):
            raise TypeError("evidence must be ReconciliationEvidence")
        validate_reconciliation_evidence(
            evidence,
            execution_key=execution_key,
            tenant_id=tenant_id,
            expected_attempt=expected_attempt,
        )
        async with self._lock:
            current = self.records.get(execution_key)
            identity = self._identities.get(execution_key)
            if current is None or identity is None:
                raise ReconciliationConflict("tool execution was not claimed")
            if identity[0] != tenant_id:
                raise ExecutionIdentityConflict("execution tenant is out of scope")
            attempt = self._attempts.get(execution_key, current.attempt)
            if attempt != expected_attempt:
                raise ReconciliationConflict("reconciliation attempt is stale")
            if claim_owner is not None or claim_epoch is not None:
                if not isinstance(claim_owner, str) or not isinstance(claim_epoch, int):
                    raise ReconciliationConflict("reconciliation claim is invalid")
                claim = self._reconciliation_claims.get(execution_key)
                if (
                    claim is None
                    or claim[0] != claim_owner
                    or claim[1] != claim_epoch
                    or claim[2] <= datetime.now(UTC)
                ):
                    raise ReconciliationConflict("reconciliation claim is stale")
            if current.status not in {
                ExecutionStatus.AMBIGUOUS,
                ExecutionStatus.UNKNOWN,
                ExecutionStatus.SUCCEEDED,
                ExecutionStatus.FAILED,
            }:
                raise ReconciliationConflict(
                    "only ambiguous or unknown executions may be reconciled"
                )
            history = self._reconciliation_evidence.setdefault(execution_key, [])
            typed_history = [cast(Any, item) for item in history]
            previous_same = next(
                (
                    item
                    for item in typed_history
                    if item.canonical_digest == evidence.canonical_digest
                ),
                None,
            )
            target_status = reconciliation_status(evidence.outcome)
            if previous_same is not None:
                return current
            if current.status in {ExecutionStatus.SUCCEEDED, ExecutionStatus.FAILED}:
                if current.status != target_status:
                    raise ReconciliationConflict(
                        "reconciliation evidence conflicts with final execution state"
                    )
            elif any(
                reconciliation_status(item.outcome)
                in {
                    ExecutionStatus.SUCCEEDED,
                    ExecutionStatus.FAILED,
                }
                and reconciliation_status(item.outcome) != target_status
                for item in typed_history
            ):
                raise ReconciliationConflict("reconciliation evidence conflicts")
            history.append(evidence)
            status = (
                ExecutionStatus.UNKNOWN
                if evidence.outcome is ReconciliationOutcome.UNKNOWN
                else target_status
            )
            self.records[execution_key] = ExecutionRecord(
                execution_key,
                status,
                attempt=attempt,
            )
            self._reconciliation_claims.pop(execution_key, None)
            return self.records[execution_key]


class HumanReviewRequired(RuntimeError):
    pass


class ToolExecutor:
    def __init__(
        self,
        key: bytes,
        ledger: ExecutionLedger,
        *,
        fault_stages: FaultStageController | None = None,
        worker_id: str | None = None,
        fault_stage_delay_seconds: float = 0.0,
    ) -> None:
        if len(key) < 32:
            raise ValueError("tool execution key must contain at least 32 bytes")
        if not 0 <= fault_stage_delay_seconds <= 5:
            raise ValueError("fault-stage delay must be between 0 and 5 seconds")
        self._key = key
        self._ledger = ledger
        # Fault-stage observation is opt-in so existing SDK/worker callers keep
        # the same hot path and do not open an additional marker connection.
        self._fault_stages = fault_stages
        self._worker_id = worker_id or "tool-executor"
        self._fault_stage_delay_seconds = fault_stage_delay_seconds

    def key_for(
        self,
        context: TenantContext,
        *,
        turn_id: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> str:
        canonical = json.dumps(
            [
                context.tenant_id,
                context.app_id,
                context.session_id,
                turn_id,
                tool_name,
                arguments_hash(arguments),
            ],
            separators=(",", ":"),
        )
        return hmac.new(self._key, canonical.encode(), hashlib.sha256).hexdigest()

    async def execute(
        self,
        context: TenantContext,
        *,
        turn_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        risk: ToolRisk,
        call: Callable[[], Awaitable[Any]],
        owner_id: str | None = None,
        fencing_token: int | None = None,
    ) -> Any:
        key = self.key_for(
            context,
            turn_id=turn_id,
            tool_name=tool_name,
            arguments=arguments,
        )
        record = await self._ledger.begin(
            key,
            tenant_id=context.tenant_id,
            turn_id=turn_id,
            tool_name=tool_name,
            risk=risk,
            arguments_hash=arguments_hash(arguments),
            owner_id=owner_id,
            fencing_token=fencing_token,
        )
        replay_terminal = record.status == ExecutionStatus.SUCCEEDED and record.replay_terminal
        if record.status == ExecutionStatus.SUCCEEDED:
            if record.result is not None:
                return record.result
            if risk != ToolRisk.IDEMPOTENT:
                raise HumanReviewRequired("tool succeeded previously; result is unavailable")
        if (
            not record.fresh
            and record.status
            in {ExecutionStatus.STARTED, ExecutionStatus.AMBIGUOUS, ExecutionStatus.UNKNOWN}
            and risk != ToolRisk.IDEMPOTENT
        ):
            raise HumanReviewRequired("non-idempotent tool outcome is unknown")
        if self._fault_stages is not None:
            if self._fault_stage_delay_seconds:
                # Only the explicit TEST fault runtime supplies this delay.
                # It creates a deterministic window after the durable
                # started ledger row and before the marker checkpoint;
                # ordinary tool execution remains unchanged.
                await asyncio.sleep(self._fault_stage_delay_seconds)
            event = FaultStageEvent(
                stage=FaultStage.TOOL,
                tenant_id=context.tenant_id,
                turn_id=turn_id,
                execution_key=key,
                worker_id=self._worker_id,
            )
            await self._fault_stages.checkpoint(event)
        try:
            result = await call()
        except BaseException:
            if replay_terminal:
                # The terminal success is authoritative.  A best-effort
                # result reconstruction failure must not downgrade it to
                # failed/ambiguous or reopen a side-effect attempt.
                raise
            status = (
                ExecutionStatus.FAILED if risk == ToolRisk.IDEMPOTENT else ExecutionStatus.AMBIGUOUS
            )
            await self._ledger.finish(
                key,
                tenant_id=context.tenant_id,
                status=status,
                owner_id=owner_id,
                fencing_token=fencing_token,
            )
            if status == ExecutionStatus.AMBIGUOUS:
                raise HumanReviewRequired("non-idempotent tool outcome is unknown") from None
            raise
        if not replay_terminal:
            await self._ledger.finish(
                key,
                tenant_id=context.tenant_id,
                status=ExecutionStatus.SUCCEEDED,
                result=result,
                owner_id=owner_id,
                fencing_token=fencing_token,
            )
        return result


__all__ = [
    "ExecutionIdentityConflict",
    "ExecutionLedger",
    "ExecutionReconciliationConflict",
    "ExecutionRecord",
    "ExecutionStatus",
    "HumanReviewRequired",
    "InMemoryExecutionLedger",
    "ToolExecutor",
]
