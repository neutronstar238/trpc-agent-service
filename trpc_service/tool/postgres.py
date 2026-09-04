"""PostgreSQL ledgers for budgets, confirmation tokens, and tool execution."""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import asyncpg

from trpc_service.tenant.models import TenantConfig, TenantContext, ToolRisk
from trpc_service.tool.confirmation import ConfirmationScope
from trpc_service.tool.execution import (
    ExecutionReconciliationConflict,
    ExecutionRecord,
    ExecutionStatus,
)
from trpc_service.tool.governance import Decision
from trpc_service.tool.reconciliation import (
    ExecutionProbeIntent,
    ExecutionReconciliationClaim,
    ReconciliationConflict,
    ReconciliationEvidence,
    ReconciliationOutcome,
    reconciliation_status,
    validate_reconciliation_evidence,
)


class _TenantStore:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    @asynccontextmanager
    async def _transaction(self, tenant_id: str) -> AsyncIterator[asyncpg.Connection]:
        async with self._pool.acquire() as connection, connection.transaction():
            await connection.execute("SELECT set_config('app.tenant_id', $1, true)", tenant_id)
            yield connection


class PostgresBudgetLedger(_TenantStore):
    """Atomically reserve monthly tenant usage across all worker processes."""

    async def reserve(
        self,
        tenant_id: str,
        *,
        token_units: int,
        cost_units: int,
        monthly_limit: int,
    ) -> bool:
        if token_units < 0 or cost_units < 0:
            raise ValueError("budget reservation cannot be negative")
        async with self._transaction(tenant_id) as connection:
            reserved = await connection.fetchval(
                """
                INSERT INTO tenant_budget_usage (
                    tenant_id,usage_month,token_units,cost_units
                )
                SELECT $1,date_trunc('month',now())::date,$2::bigint,$3::bigint
                 WHERE $3::bigint <= $4::bigint
                ON CONFLICT (tenant_id,usage_month)
                DO UPDATE SET token_units=tenant_budget_usage.token_units+excluded.token_units,
                              cost_units=tenant_budget_usage.cost_units+excluded.cost_units,
                              updated_at=now()
                 WHERE tenant_budget_usage.cost_units+excluded.cost_units <= $4::bigint
                RETURNING true
                """,
                tenant_id,
                token_units,
                cost_units,
                monthly_limit,
            )
        return bool(reserved)


class PostgresConfirmationLedger(_TenantStore):
    """Store only a hash of the one-time token identifier."""

    async def issue(
        self,
        token_id: str,
        expires_at: int,
        scope: ConfirmationScope,
    ) -> None:
        token_hash = _token_hash(token_id)
        expires = datetime.fromtimestamp(expires_at, tz=UTC)
        async with self._transaction(scope.tenant_id) as connection:
            await connection.execute(
                """
                INSERT INTO confirmation_challenges (
                    tenant_id,principal_id,session_id,tool_name,arguments_hash,
                    token_hash,expires_at
                ) VALUES ($1,$2,$3,$4,$5,$6,$7)
                """,
                scope.tenant_id,
                scope.principal_id,
                scope.session_id,
                scope.tool_name,
                scope.arguments_hash,
                token_hash,
                expires,
            )

    async def consume(self, token_id: str, scope: ConfirmationScope) -> bool:
        async with self._transaction(scope.tenant_id) as connection:
            challenge_id = await connection.fetchval(
                """
                UPDATE confirmation_challenges
                   SET consumed_at=now()
                 WHERE tenant_id=$1 AND token_hash=$2
                   AND principal_id=$3 AND session_id=$4 AND tool_name=$5
                   AND arguments_hash=$6 AND consumed_at IS NULL AND expires_at>=now()
                RETURNING challenge_id
                """,
                scope.tenant_id,
                _token_hash(token_id),
                scope.principal_id,
                scope.session_id,
                scope.tool_name,
                scope.arguments_hash,
            )
        return challenge_id is not None


class PostgresExecutionLedger(_TenantStore):
    """Persist tool outcome state without storing arguments or result content."""

    async def _assert_active_turn(
        self,
        connection: asyncpg.Connection,
        *,
        tenant_id: str,
        turn_id: UUID,
        owner_id: str,
        fencing_token: int,
    ) -> None:
        """Lock and validate the authoritative session lease for a tool turn.

        ``tool_executions.lease_*`` is only a copy of the worker fence.  The
        session and turn rows are authoritative, so every operation that can
        create or finish a side effect checks them in the same transaction.
        Locking both rows also makes a lease hand-off serialize with this
        check; the final UPDATE below repeats the predicates as a last CAS.
        """

        # Do not lock a joined pair here.  The session mailbox commit path
        # locks ``sessions`` before ``session_turns``; explicitly acquire the
        # same order to avoid a planner-dependent turn/session deadlock.
        turn_ref = await connection.fetchrow(
            """
            SELECT session_id
              FROM session_turns
             WHERE tenant_id=$1 AND turn_id=$2::uuid
            """,
            tenant_id,
            turn_id,
        )
        if turn_ref is None:
            raise ToolExecutionConflict(
                "tool execution session lease is no longer current",
                requires_confirmation=True,
            )
        session = await connection.fetchrow(
            """
            SELECT session_id,lease_owner,lease_epoch,lease_expires_at
              FROM sessions
             WHERE tenant_id=$1 AND session_id=$2
             FOR UPDATE
            """,
            tenant_id,
            turn_ref["session_id"],
        )
        turn = await connection.fetchrow(
            """
            SELECT session_id,status,fencing_token
              FROM session_turns
             WHERE tenant_id=$1 AND turn_id=$2::uuid
             FOR UPDATE
            """,
            tenant_id,
            turn_id,
        )
        current = await connection.fetchrow(
            """
            SELECT lease_owner,lease_epoch,lease_expires_at,
                   lease_expires_at > clock_timestamp() AS lease_valid
              FROM sessions
             WHERE tenant_id=$1 AND session_id=$2
            """,
            tenant_id,
            turn_ref["session_id"],
        )
        if (
            session is None
            or turn is None
            or current is None
            or turn["session_id"] != turn_ref["session_id"]
            or turn["status"] != "processing"
            or int(turn["fencing_token"]) != fencing_token
            or current["lease_owner"] != owner_id
            or int(current["lease_epoch"]) != fencing_token
            or not bool(current["lease_valid"])
        ):
            raise ToolExecutionConflict(
                "tool execution session lease is no longer current",
                requires_confirmation=True,
            )

    @staticmethod
    def _require_fencing(owner_id: str | None, fencing_token: int | None) -> None:
        """Reject a tool ledger operation that cannot be fenced.

        The database predicates intentionally retain the nullable SQL form
        for compatibility with old rows, but production callers must never
        use that bypass.  The worker's session lease owner and epoch are the
        values that must be supplied for both begin and finish.
        """

        if not isinstance(owner_id, str) or not owner_id.strip():
            raise ValueError("tool execution owner_id is required for fencing")
        if (
            not isinstance(fencing_token, int)
            or isinstance(fencing_token, bool)
            or fencing_token < 1
        ):
            raise ValueError("tool execution fencing_token must be a positive integer")

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
        self._require_fencing(owner_id, fencing_token)
        turn_uuid = UUID(turn_id)
        assert owner_id is not None
        assert fencing_token is not None
        async with self._transaction(tenant_id) as connection:
            existing = await connection.fetchrow(
                """
                SELECT turn_id,tool_name,classification,arguments_hash,status,
                       lease_owner,lease_epoch,attempt
                  FROM tool_executions
                 WHERE tenant_id=$1 AND execution_key=$2
                 FOR UPDATE
                """,
                tenant_id,
                execution_key,
            )
            if existing is None:
                await self._assert_active_turn(
                    connection,
                    tenant_id=tenant_id,
                    turn_id=turn_uuid,
                    owner_id=owner_id,
                    fencing_token=fencing_token,
                )
            else:
                status = _execution_status(existing["status"])
                # A terminal success is authoritative and must never require
                # a live lease merely to answer a duplicate non-idempotent
                # request.  An idempotent success without a stored result is
                # recoverable only while the current processing fence is
                # still valid; the caller may rebuild the result, but must
                # not rewrite the terminal ledger row.
                if status == ExecutionStatus.SUCCEEDED:
                    if risk == ToolRisk.IDEMPOTENT:
                        await self._assert_active_turn(
                            connection,
                            tenant_id=tenant_id,
                            turn_id=UUID(str(existing["turn_id"])),
                            owner_id=owner_id,
                            fencing_token=fencing_token,
                        )
                        return ExecutionRecord(
                            execution_key,
                            status,
                            replay_terminal=True,
                            attempt=_row_int(existing, "attempt", 1),
                        )
                    return ExecutionRecord(
                        execution_key,
                        status,
                        attempt=_row_int(existing, "attempt", 1),
                    )
                existing_turn_id = UUID(str(existing["turn_id"]))
                await self._assert_active_turn(
                    connection,
                    tenant_id=tenant_id,
                    turn_id=existing_turn_id,
                    owner_id=owner_id,
                    fencing_token=fencing_token,
                )
                same_fence = (
                    existing["lease_owner"] == owner_id
                    and int(existing["lease_epoch"]) == fencing_token
                )
                if not same_fence:
                    if risk != ToolRisk.IDEMPOTENT:
                        raise ToolExecutionConflict(
                            "non-idempotent tool execution crossed a session fence",
                            requires_confirmation=True,
                        )
                    claimed = await connection.fetchval(
                        """
                        UPDATE tool_executions
                           SET lease_owner=$3,lease_epoch=$4,
                               status='started',completed_at=NULL,
                               attempt=attempt+1,
                               reconciliation_owner=NULL,
                               reconciliation_lease_expires_at=NULL,
                               reconciliation_outcome=NULL,
                               reconciliation_evidence_digest=NULL,
                               reconciled_at=NULL
                         WHERE tenant_id=$1 AND execution_key=$2
                            AND status IN ('started','failed','ambiguous','unknown')
                           AND (
                               lease_owner IS DISTINCT FROM $3
                               OR lease_epoch IS DISTINCT FROM $4
                           )
                        RETURNING execution_key
                        """,
                        tenant_id,
                        execution_key,
                        owner_id,
                        fencing_token,
                    )
                    if claimed is None:
                        raise ToolExecutionConflict(
                            "tool execution was changed while taking its fence",
                            requires_confirmation=True,
                        )
                    return ExecutionRecord(
                        execution_key,
                        ExecutionStatus.STARTED,
                        fresh=True,
                        attempt=_row_int(existing, "attempt", 1) + 1,
                    )
                return ExecutionRecord(
                    execution_key,
                    status,
                    attempt=_row_int(existing, "attempt", 1),
                )

            inserted = await connection.fetchval(
                """
                INSERT INTO tool_executions (
                    tenant_id,execution_key,turn_id,tool_name,classification,
                    arguments_hash,status,lease_owner,lease_epoch,attempt
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,1)
                ON CONFLICT (tenant_id,execution_key) DO NOTHING
                RETURNING execution_key
                """,
                tenant_id,
                execution_key,
                turn_uuid,
                tool_name,
                risk.value,
                arguments_hash,
                ExecutionStatus.STARTED.value,
                owner_id,
                fencing_token,
            )
            if inserted is not None:
                return ExecutionRecord(
                    execution_key,
                    ExecutionStatus.STARTED,
                    fresh=True,
                    attempt=1,
                )
            # A concurrent insert can win after the initial SELECT.  Re-read
            # its locked row and apply exactly the same fence rules.
            existing = await connection.fetchrow(
                """
                SELECT turn_id,status,lease_owner,lease_epoch,attempt
                  FROM tool_executions
                 WHERE tenant_id=$1 AND execution_key=$2
                 FOR UPDATE
                """,
                tenant_id,
                execution_key,
            )
            if existing is None:
                raise RuntimeError("tool execution disappeared during conflict resolution")
            status = _execution_status(existing["status"])
            if status == ExecutionStatus.SUCCEEDED:
                if risk == ToolRisk.IDEMPOTENT:
                    await self._assert_active_turn(
                        connection,
                        tenant_id=tenant_id,
                        turn_id=UUID(str(existing["turn_id"])),
                        owner_id=owner_id,
                        fencing_token=fencing_token,
                    )
                    return ExecutionRecord(
                        execution_key,
                        status,
                        replay_terminal=True,
                        attempt=_row_int(existing, "attempt", 1),
                    )
                return ExecutionRecord(
                    execution_key,
                    status,
                    attempt=_row_int(existing, "attempt", 1),
                )
            await self._assert_active_turn(
                connection,
                tenant_id=tenant_id,
                turn_id=UUID(str(existing["turn_id"])),
                owner_id=owner_id,
                fencing_token=fencing_token,
            )
            if existing["lease_owner"] != owner_id or int(existing["lease_epoch"]) != fencing_token:
                if risk != ToolRisk.IDEMPOTENT:
                    raise ToolExecutionConflict(
                        "tool execution fencing token is no longer current",
                        requires_confirmation=True,
                    )
                claimed = await connection.fetchval(
                    """
                    UPDATE tool_executions
                       SET lease_owner=$3,lease_epoch=$4,
                           status='started',completed_at=NULL,
                           attempt=attempt+1,
                           reconciliation_owner=NULL,
                           reconciliation_lease_expires_at=NULL,
                           reconciliation_outcome=NULL,
                           reconciliation_evidence_digest=NULL,
                           reconciled_at=NULL
                     WHERE tenant_id=$1 AND execution_key=$2
                       AND status IN ('started','failed','ambiguous','unknown')
                    RETURNING execution_key
                    """,
                    tenant_id,
                    execution_key,
                    owner_id,
                    fencing_token,
                )
                if claimed is None:
                    raise ToolExecutionConflict(
                        "tool execution was changed while taking its fence",
                        requires_confirmation=True,
                    )
                return ExecutionRecord(
                    execution_key,
                    ExecutionStatus.STARTED,
                    fresh=True,
                    attempt=_row_int(existing, "attempt", 1) + 1,
                )
            return ExecutionRecord(
                execution_key,
                status,
                attempt=_row_int(existing, "attempt", 1),
            )

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
        if status == ExecutionStatus.STARTED:
            raise ValueError("tool execution finish requires a terminal status")
        self._require_fencing(owner_id, fencing_token)
        assert owner_id is not None
        assert fencing_token is not None
        async with self._transaction(tenant_id) as connection:
            existing = await connection.fetchrow(
                """
                SELECT turn_id,status,lease_owner,lease_epoch,attempt
                  FROM tool_executions
                 WHERE tenant_id=$1 AND execution_key=$2
                 FOR UPDATE
                """,
                tenant_id,
                execution_key,
            )
            if existing is None:
                raise RuntimeError("tool execution does not exist or is no longer owned")
            if _execution_status(existing["status"]) != ExecutionStatus.STARTED:
                raise RuntimeError("tool execution does not exist or is no longer owned")
            if existing["lease_owner"] != owner_id or int(existing["lease_epoch"]) != fencing_token:
                raise ToolExecutionConflict(
                    "tool execution finish crossed a session fence",
                    requires_confirmation=True,
                )
            await self._assert_active_turn(
                connection,
                tenant_id=tenant_id,
                turn_id=UUID(str(existing["turn_id"])),
                owner_id=owner_id,
                fencing_token=fencing_token,
            )
            updated = await connection.fetchval(
                """
                UPDATE tool_executions AS execution
                   SET status=$3,
                       completed_at=clock_timestamp(),
                       reconciliation_owner=NULL,
                       reconciliation_lease_expires_at=NULL
                 WHERE tenant_id=$1 AND execution_key=$2
                   AND status='started'
                   AND lease_owner=$4 AND lease_epoch=$5
                   AND EXISTS (
                       SELECT 1
                         FROM session_turns AS turn
                         JOIN sessions AS session
                           ON session.tenant_id=turn.tenant_id
                          AND session.session_id=turn.session_id
                        WHERE turn.tenant_id=execution.tenant_id
                          AND turn.turn_id=execution.turn_id
                          AND turn.status='processing'
                          AND turn.fencing_token=$5
                          AND session.lease_owner=$4
                          AND session.lease_epoch=$5
                          AND session.lease_expires_at > clock_timestamp()
                   )
                RETURNING execution_key
                """,
                tenant_id,
                execution_key,
                status.value,
                owner_id,
                fencing_token,
            )
        if updated is None:
            raise RuntimeError("tool execution does not exist or is no longer owned")

    async def get_record(
        self,
        execution_key: str,
        *,
        tenant_id: str,
    ) -> ExecutionRecord | None:
        """Read one execution row under the caller's tenant RLS context."""

        async with self._transaction(tenant_id) as connection:
            row = await connection.fetchrow(
                """
                SELECT execution_key,status,attempt
                  FROM tool_executions
                 WHERE tenant_id=$1 AND execution_key=$2
                """,
                tenant_id,
                execution_key,
            )
        if row is None:
            return None
        return ExecutionRecord(
            execution_key,
            _execution_status(_row_value(row, "status")),
            attempt=_row_int(row, "attempt", 1),
        )

    async def list_ambiguous(
        self,
        *,
        tenant_id: str,
        limit: int = 100,
    ) -> list[ExecutionProbeIntent]:
        """List only ambiguous/unknown rows; this method never invokes tools."""

        _validate_reconciliation_limit(limit)
        async with self._transaction(tenant_id) as connection:
            rows = await connection.fetch(
                """
                SELECT execution.tenant_id,execution.execution_key,
                       execution.turn_id,execution.tool_name,
                       execution.arguments_hash,execution.status,
                       execution.attempt,turn.session_id,session.app_id
                  FROM tool_executions AS execution
                  JOIN session_turns AS turn
                    ON turn.tenant_id=execution.tenant_id
                   AND turn.turn_id=execution.turn_id
                  JOIN sessions AS session
                    ON session.tenant_id=turn.tenant_id
                   AND session.session_id=turn.session_id
                 WHERE execution.tenant_id=$1
                   AND execution.status IN ('ambiguous','unknown')
                 ORDER BY execution.started_at,execution.execution_key
                 LIMIT $2
                """,
                tenant_id,
                limit,
            )
        return [_probe_intent_from_row(row) for row in rows]

    async def claim_ambiguous(
        self,
        *,
        tenant_id: str,
        owner_id: str,
        limit: int = 100,
        lease_seconds: float = 30.0,
    ) -> list[ExecutionReconciliationClaim]:
        """Atomically lease ambiguous rows for a reconciler worker.

        ``FOR UPDATE SKIP LOCKED`` plus the epoch increment makes two
        reconciler Pods safe to run concurrently.  The lease is independent
        from the tool worker lease, so a recovered worker cannot finish a
        stale probe after a reconciler hand-off.
        """

        _validate_reconciliation_limit(limit)
        _validate_reconciliation_owner(owner_id)
        _validate_reconciliation_lease(lease_seconds)
        async with self._transaction(tenant_id) as connection:
            rows = await connection.fetch(
                """
                WITH candidates AS (
                    SELECT execution.tenant_id,execution.execution_key,
                           execution.turn_id
                      FROM tool_executions AS execution
                      JOIN session_turns AS turn
                        ON turn.tenant_id=execution.tenant_id
                       AND turn.turn_id=execution.turn_id
                      JOIN sessions AS session
                        ON session.tenant_id=turn.tenant_id
                       AND session.session_id=turn.session_id
                     WHERE execution.tenant_id=$1
                       AND execution.status IN ('ambiguous','unknown')
                       AND (
                           execution.reconciliation_lease_expires_at IS NULL
                           OR execution.reconciliation_lease_expires_at <= clock_timestamp()
                       )
                     ORDER BY execution.started_at,execution.execution_key
                     FOR UPDATE OF execution SKIP LOCKED
                     LIMIT $2
                ), claimed AS (
                    UPDATE tool_executions AS execution
                       SET reconciliation_owner=$3,
                           reconciliation_epoch=execution.reconciliation_epoch+1,
                           reconciliation_lease_expires_at=(
                               clock_timestamp() + ($4::double precision * interval '1 second')
                           )
                      FROM candidates
                     WHERE execution.tenant_id=candidates.tenant_id
                       AND execution.execution_key=candidates.execution_key
                     RETURNING execution.tenant_id,execution.execution_key,
                               execution.turn_id,execution.tool_name,
                               execution.arguments_hash,execution.status,
                               execution.attempt,execution.reconciliation_owner,
                               execution.reconciliation_epoch,
                               execution.reconciliation_lease_expires_at,
                               execution.started_at,execution.lease_owner,
                               execution.lease_epoch,execution.error_type,
                               execution.completed_at
                )
                SELECT claimed.tenant_id,claimed.execution_key,
                       claimed.turn_id,claimed.tool_name,
                       claimed.arguments_hash,claimed.status,
                       claimed.attempt,claimed.reconciliation_owner,
                       claimed.reconciliation_epoch,
                       claimed.reconciliation_lease_expires_at,
                       claimed.started_at,claimed.lease_owner,
                       claimed.lease_epoch,claimed.error_type,
                       claimed.completed_at,turn.session_id,session.app_id
                  FROM claimed
                  JOIN session_turns AS turn
                    ON turn.tenant_id=claimed.tenant_id
                   AND turn.turn_id=claimed.turn_id
                  JOIN sessions AS session
                    ON session.tenant_id=turn.tenant_id
                   AND session.session_id=turn.session_id
                """,
                tenant_id,
                limit,
                owner_id,
                float(lease_seconds),
            )
        return [_claim_from_row(row) for row in rows]

    async def list_reconciliation_evidence(
        self,
        *,
        tenant_id: str,
        execution_key: str,
        attempt: int | None = None,
    ) -> list[ReconciliationEvidence]:
        """Read immutable probe evidence for audit and recovery tooling."""

        if attempt is not None and (
            isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1
        ):
            raise ValueError("reconciliation attempt must be a positive integer")
        async with self._transaction(tenant_id) as connection:
            rows = await connection.fetch(
                """
                SELECT execution_key,attempt,outcome,evidence_summary,
                       evidence_digest,trace_id,reconciler_id,observed_at,tenant_id
                  FROM tool_execution_reconciliations
                 WHERE tenant_id=$1 AND execution_key=$2
                   AND ($3::integer IS NULL OR attempt=$3)
                 ORDER BY attempt,observed_at,reconciliation_id
                """,
                tenant_id,
                execution_key,
                attempt,
            )
        return [_evidence_from_row(row) for row in rows]

    async def reconcile(
        self,
        execution_key: str,
        *,
        tenant_id: str,
        expected_attempt: int,
        evidence: ReconciliationEvidence,
        claim_owner: str | None = None,
        claim_epoch: int | None = None,
    ) -> ExecutionRecord:
        """Append probe evidence and CAS its outcome into ``tool_executions``."""

        validate_reconciliation_evidence(
            evidence,
            execution_key=execution_key,
            tenant_id=tenant_id,
            expected_attempt=expected_attempt,
        )
        if claim_owner is not None or claim_epoch is not None:
            _validate_reconciliation_owner(claim_owner)
            if isinstance(claim_epoch, bool) or not isinstance(claim_epoch, int) or claim_epoch < 1:
                raise ReconciliationConflict("reconciliation claim epoch is invalid")
        async with self._transaction(tenant_id) as connection:
            current = await connection.fetchrow(
                """
                SELECT execution_key,status,attempt,reconciliation_owner,
                       reconciliation_epoch,reconciliation_lease_expires_at
                  FROM tool_executions
                 WHERE tenant_id=$1 AND execution_key=$2
                 FOR UPDATE
                """,
                tenant_id,
                execution_key,
            )
            if current is None:
                raise ReconciliationConflict("tool execution was not claimed")
            current_attempt = _row_int(current, "attempt", 1)
            if current_attempt != expected_attempt:
                raise ReconciliationConflict("reconciliation attempt is stale")
            status = _execution_status(_row_value(current, "status"))
            if status not in {
                ExecutionStatus.AMBIGUOUS,
                ExecutionStatus.UNKNOWN,
                ExecutionStatus.SUCCEEDED,
                ExecutionStatus.FAILED,
            }:
                raise ReconciliationConflict(
                    "only ambiguous or unknown executions may be reconciled"
                )
            if claim_owner is not None or claim_epoch is not None:
                if (
                    _row_value(current, "reconciliation_owner") != claim_owner
                    or _row_int(current, "reconciliation_epoch", 0) != claim_epoch
                    or not _lease_is_valid(current)
                ):
                    raise ReconciliationConflict("reconciliation claim is stale")

            target_status = reconciliation_status(evidence.outcome)
            previous = await connection.fetchrow(
                """
                SELECT outcome
                  FROM tool_execution_reconciliations
                 WHERE tenant_id=$1 AND execution_key=$2 AND attempt=$3
                   AND outcome IN ('applied','not_applied')
                 ORDER BY observed_at DESC,reconciliation_id DESC
                 LIMIT 1
                """,
                tenant_id,
                execution_key,
                expected_attempt,
            )
            previous_outcome = _row_value(previous, "outcome") if previous else None
            if previous_outcome is not None:
                previous_status = reconciliation_status(
                    ReconciliationOutcome.parse(str(previous_outcome))
                )
                if previous_status != target_status:
                    raise ReconciliationConflict("reconciliation evidence conflicts")
            if status in {ExecutionStatus.SUCCEEDED, ExecutionStatus.FAILED}:
                if status != target_status:
                    raise ReconciliationConflict(
                        "reconciliation evidence conflicts with final execution state"
                    )

            inserted = await connection.fetchval(
                """
                INSERT INTO tool_execution_reconciliations (
                    tenant_id,execution_key,attempt,outcome,evidence_digest,
                    evidence_summary,trace_id,reconciler_id,observed_at
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                ON CONFLICT (tenant_id,execution_key,attempt,evidence_digest)
                DO NOTHING
                RETURNING reconciliation_id
                """,
                tenant_id,
                execution_key,
                expected_attempt,
                evidence.outcome.value,
                evidence.evidence_digest,
                evidence.evidence_summary,
                evidence.trace_id,
                evidence.reconciler_id,
                evidence.observed_at,
            )
            if inserted is None:
                duplicate = await connection.fetchrow(
                    """
                    SELECT outcome
                      FROM tool_execution_reconciliations
                     WHERE tenant_id=$1 AND execution_key=$2
                       AND attempt=$3 AND evidence_digest=$4
                    """,
                    tenant_id,
                    execution_key,
                    expected_attempt,
                    evidence.evidence_digest,
                )
                if duplicate is None:
                    raise ReconciliationConflict("reconciliation evidence was changed concurrently")
                if str(_row_value(duplicate, "outcome")) != evidence.outcome.value:
                    raise ReconciliationConflict("reconciliation evidence conflicts")
                return ExecutionRecord(
                    execution_key,
                    status,
                    attempt=current_attempt,
                )

            updated = await connection.fetchrow(
                """
                UPDATE tool_executions
                   SET status=$4,
                       reconciliation_outcome=$5,
                       reconciliation_evidence_digest=$6,
                       reconciled_at=$7,
                       reconciliation_owner=NULL,
                       reconciliation_lease_expires_at=NULL,
                       completed_at=CASE
                           WHEN $4 IN ('succeeded','failed') THEN $7
                           ELSE completed_at
                       END
                 WHERE tenant_id=$1 AND execution_key=$2
                   AND attempt=$3
                   AND status IN ('ambiguous','unknown')
                   AND (
                       $8::text IS NULL
                       OR (
                           reconciliation_owner=$8
                           AND reconciliation_epoch=$9
                           AND reconciliation_lease_expires_at > clock_timestamp()
                       )
                   )
                 RETURNING execution_key,status,attempt
                """,
                tenant_id,
                execution_key,
                expected_attempt,
                target_status.value,
                evidence.outcome.value,
                evidence.evidence_digest,
                evidence.observed_at,
                claim_owner,
                claim_epoch,
            )
            if updated is None:
                # A terminal row may have been finalized by a concurrent
                # completion only when it agrees with this evidence.
                latest = await connection.fetchrow(
                    """
                    SELECT status,attempt
                      FROM tool_executions
                     WHERE tenant_id=$1 AND execution_key=$2
                    """,
                    tenant_id,
                    execution_key,
                )
                latest_status = _execution_status(_row_value(latest, "status")) if latest else None
                if latest_status == target_status:
                    return ExecutionRecord(
                        execution_key,
                        latest_status,
                        attempt=_row_int(latest, "attempt", expected_attempt),
                    )
                raise ReconciliationConflict("execution CAS fence was lost")
            return ExecutionRecord(
                execution_key,
                target_status,
                attempt=_row_int(updated, "attempt", expected_attempt),
            )


class ToolExecutionConflict(ExecutionReconciliationConflict):
    """A tool operation crossed the authoritative session fence."""

    def __init__(self, message: str, *, requires_confirmation: bool = False) -> None:
        super().__init__(message)
        self.requires_confirmation = requires_confirmation


def _execution_status(value: object) -> ExecutionStatus:
    try:
        return ExecutionStatus(str(value))
    except ValueError as exc:
        raise RuntimeError("tool execution has an invalid status") from exc


def _row_value(row: object, key: str, default: object = None) -> object:
    """Read a field from asyncpg.Record or the dict rows used by tests."""

    if row is None:
        return default
    if isinstance(row, Mapping):
        return row.get(key, default)
    try:
        return row[key]  # type: ignore[index]
    except (IndexError, KeyError, TypeError):
        return default


def _row_int(row: object, key: str, default: int) -> int:
    value = _row_value(row, key, default)
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, str, bytes)):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
    return default


def _lease_is_valid(row: object) -> bool:
    value = _row_value(row, "reconciliation_lease_expires_at")
    return isinstance(value, datetime) and value > datetime.now(UTC)


def _probe_intent_from_row(row: object) -> ExecutionProbeIntent:
    return ExecutionProbeIntent(
        tenant_id=str(_row_value(row, "tenant_id", "")),
        execution_key=str(_row_value(row, "execution_key", "")),
        turn_id=str(_row_value(row, "turn_id", "")),
        tool_name=str(_row_value(row, "tool_name", "")),
        arguments_hash=str(_row_value(row, "arguments_hash", "")),
        app_id=str(_row_value(row, "app_id", "")),
        session_id=str(_row_value(row, "session_id", "")),
        trace_id=(
            str(_row_value(row, "trace_id")) if _row_value(row, "trace_id") is not None else None
        ),
        attempt=_row_int(row, "attempt", 1),
    )


def _claim_from_row(row: object) -> ExecutionReconciliationClaim:
    expires = _row_value(row, "reconciliation_lease_expires_at")
    if not isinstance(expires, datetime):
        raise RuntimeError("reconciliation claim has no lease expiry")
    owner = _row_value(row, "reconciliation_owner")
    if not isinstance(owner, str) or not owner:
        raise RuntimeError("reconciliation claim has no owner")
    return ExecutionReconciliationClaim(
        intent=_probe_intent_from_row(row),
        status=_execution_status(_row_value(row, "status")),
        attempt=_row_int(row, "attempt", 1),
        owner_id=owner,
        claim_epoch=_row_int(row, "reconciliation_epoch", 0),
        lease_expires_at=expires,
    )


def _evidence_from_row(row: object) -> ReconciliationEvidence:
    observed = _row_value(row, "observed_at")
    if not isinstance(observed, datetime):
        raise RuntimeError("reconciliation evidence has no observed_at")
    outcome = ReconciliationOutcome.parse(str(_row_value(row, "outcome")))
    return ReconciliationEvidence(
        str(_row_value(row, "execution_key")),
        _row_int(row, "attempt", 1),
        outcome,
        evidence_summary=str(_row_value(row, "evidence_summary")),
        trace_id=(
            str(_row_value(row, "trace_id")) if _row_value(row, "trace_id") is not None else None
        ),
        observed_at=observed,
        reconciler_id=str(_row_value(row, "reconciler_id")),
        evidence_digest=str(_row_value(row, "evidence_digest")),
        tenant_id=str(_row_value(row, "tenant_id")),
    )


def _validate_reconciliation_limit(limit: int) -> None:
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
        raise ValueError("reconciliation limit must be between 1 and 1000")


def _validate_reconciliation_owner(owner_id: str | None) -> None:
    if not isinstance(owner_id, str) or not owner_id.strip():
        raise ValueError("reconciliation owner_id is required")


def _validate_reconciliation_lease(lease_seconds: float) -> None:
    if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, (int, float)):
        raise ValueError("reconciliation lease must be positive")
    if lease_seconds <= 0 or lease_seconds > 3600:
        raise ValueError("reconciliation lease must be between 0 and 3600 seconds")


class PostgresGovernanceAuditSink(_TenantStore):
    """Persist policy decisions without arguments, results, or message content."""

    async def record(
        self,
        *,
        context: TenantContext,
        config: TenantConfig,
        tool_name: str,
        decision: Decision,
        reason: str,
    ) -> None:
        async with self._transaction(context.tenant_id) as connection:
            await connection.execute(
                """
                INSERT INTO audit_logs (
                    tenant_id,user_id,session_id,tool_name,decision,trace_id,
                    config_version,policy_version,redaction_applied,metadata_json
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true,$9::jsonb)
                """,
                context.tenant_id,
                context.principal_id,
                context.session_id,
                tool_name,
                decision.value,
                context.trace_id,
                config.version,
                config.policy_version,
                json.dumps({"reason": reason}, separators=(",", ":")),
            )


def _token_hash(token_id: str) -> str:
    return hashlib.sha256(token_id.encode()).hexdigest()


__all__ = [
    "PostgresBudgetLedger",
    "PostgresConfirmationLedger",
    "PostgresExecutionLedger",
    "PostgresGovernanceAuditSink",
    "ToolExecutionConflict",
]
