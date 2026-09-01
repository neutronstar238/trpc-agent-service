"""Persistent tenant control-plane operations."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol
from uuid import UUID

import asyncpg

from trpc_service.tenant.models import ChannelBinding, TenantConfig

_WECOM_STATE_FIELDS = (
    "owner_hash",
    "epoch",
    "phase",
    "acquired_at",
    "authenticated_at",
    "disconnected_at",
    "released_at",
    "last_provider_event_hash",
    "last_provider_event_at",
    "updated_at",
)
_WECOM_EVENT_FIELDS = (
    "event_id",
    "connection_epoch",
    "event_type",
    "owner_hash",
    "provider_event_hash",
    "occurred_at",
)
_SAFE_PROVIDER_CODES = frozenset(
    {"0", "200", "429", "45009", "45011", "99991400", "99991401", "99991402", "99991672"}
)


class IdempotencyConflict(RuntimeError):
    pass


class ControlVersionConflict(RuntimeError):
    pass


class ControlPlaneRepository(Protocol):
    async def create_tenant(
        self,
        *,
        tenant_id: str,
        display_name: str,
        actor: str,
        idempotency_key: str,
        request_hash: str,
    ) -> dict[str, Any]: ...

    async def get_tenant(self, tenant_id: str) -> dict[str, Any] | None: ...

    async def put_binding(
        self,
        *,
        tenant_id: str,
        binding_id: str,
        binding: ChannelBinding,
        actor: str,
        expected_version: int,
        idempotency_key: str,
        request_hash: str,
    ) -> dict[str, Any]: ...

    async def create_config_revision(
        self,
        *,
        tenant_id: str,
        app_id: str,
        config: dict[str, Any],
        actor: str,
        expected_version: int,
        idempotency_key: str,
        request_hash: str,
    ) -> dict[str, Any]: ...

    async def activate_config(
        self,
        *,
        tenant_id: str,
        app_id: str,
        version: int,
        percentage: float,
        actor: str,
        expected_version: int,
        idempotency_key: str,
        request_hash: str,
        operation: Literal["activate_config", "rollback_config"] = "activate_config",
    ) -> dict[str, Any]: ...

    async def audit_page(
        self, tenant_id: str, *, cursor: str | None, limit: int
    ) -> dict[str, Any]: ...

    async def wecom_acceptance_snapshot(
        self, tenant_id: str, binding_id: str, *, limit: int
    ) -> dict[str, Any] | None: ...

    async def im_acceptance_outbound_evidence(
        self,
        tenant_id: str,
        binding_id: str,
        *,
        run_id: str,
        outbound_id: UUID,
    ) -> dict[str, Any] | None: ...


class PostgresControlPlaneRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    @asynccontextmanager
    async def _transaction(self, tenant_id: str) -> AsyncIterator[asyncpg.Connection]:
        async with self._pool.acquire() as connection, connection.transaction():
            await connection.execute("SELECT set_config('app.tenant_id', $1, true)", tenant_id)
            yield connection

    async def create_tenant(
        self,
        *,
        tenant_id: str,
        display_name: str,
        actor: str,
        idempotency_key: str,
        request_hash: str,
    ) -> dict[str, Any]:
        async with self._transaction(tenant_id) as connection:
            cached = await self._cached(connection, tenant_id, idempotency_key, request_hash)
            if cached:
                return cached
            inserted = await connection.fetchrow(
                """
                INSERT INTO tenants (tenant_id,display_name)
                VALUES ($1,$2)
                ON CONFLICT (tenant_id) DO NOTHING
                RETURNING tenant_id,display_name,status,control_version,created_at
                """,
                tenant_id,
                display_name,
            )
            if inserted is None:
                raise ControlVersionConflict("tenant already exists")
            response = _record_json(inserted)
            await self._store_idempotency(
                connection,
                tenant_id,
                idempotency_key,
                "create_tenant",
                request_hash,
                response,
                201,
            )
            await self._audit(connection, tenant_id, actor, "tenant_created", idempotency_key)
            return response

    async def get_tenant(self, tenant_id: str) -> dict[str, Any] | None:
        async with self._transaction(tenant_id) as connection:
            row = await connection.fetchrow(
                """
                SELECT tenant_id,display_name,status,control_version,created_at,updated_at
                  FROM tenants WHERE tenant_id=$1
                """,
                tenant_id,
            )
        return _record_json(row) if row else None

    async def put_binding(
        self,
        *,
        tenant_id: str,
        binding_id: str,
        binding: ChannelBinding,
        actor: str,
        expected_version: int,
        idempotency_key: str,
        request_hash: str,
    ) -> dict[str, Any]:
        if binding.tenant_id != tenant_id or binding.binding_id != binding_id:
            raise ValueError("binding identity does not match the request path")
        async with self._transaction(tenant_id) as connection:
            cached = await self._cached(connection, tenant_id, idempotency_key, request_hash)
            if cached:
                return cached
            current = await self._lock_version(connection, tenant_id, expected_version)
            row = await connection.fetchrow(
                """
                INSERT INTO channel_bindings (
                    tenant_id,binding_id,app_id,channel,account_id,secret_refs,capabilities,enabled
                ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8)
                ON CONFLICT (tenant_id,binding_id) DO UPDATE
                   SET app_id=excluded.app_id,channel=excluded.channel,
                       account_id=excluded.account_id,
                       secret_refs=excluded.secret_refs,capabilities=excluded.capabilities,
                       enabled=excluded.enabled,
                       control_version=channel_bindings.control_version+1,updated_at=now()
                RETURNING binding_id,app_id,channel,account_id,enabled,control_version
                """,
                tenant_id,
                binding_id,
                binding.app_id,
                binding.channel.value,
                binding.account_id,
                json.dumps(
                    {
                        key: value.model_dump(mode="json")
                        for key, value in binding.secret_refs.items()
                    }
                ),
                json.dumps(sorted(binding.capabilities)),
                binding.enabled,
            )
            new_version = await self._bump_version(connection, tenant_id, current)
            response = {**_record_json(row), "tenant_control_version": new_version}
            await self._store_idempotency(
                connection,
                tenant_id,
                idempotency_key,
                "put_binding",
                request_hash,
                response,
                200,
            )
            await self._audit(connection, tenant_id, actor, "binding_updated", idempotency_key)
            return response

    async def create_config_revision(
        self,
        *,
        tenant_id: str,
        app_id: str,
        config: dict[str, Any],
        actor: str,
        expected_version: int,
        idempotency_key: str,
        request_hash: str,
    ) -> dict[str, Any]:
        async with self._transaction(tenant_id) as connection:
            cached = await self._cached(connection, tenant_id, idempotency_key, request_hash)
            if cached:
                return cached
            current = await self._lock_version(connection, tenant_id, expected_version)
            app_exists = await connection.fetchval(
                "SELECT 1 FROM agent_apps WHERE tenant_id=$1 AND app_id=$2",
                tenant_id,
                app_id,
            )
            if not app_exists:
                await connection.execute(
                    """
                    INSERT INTO agent_apps (tenant_id,app_id,display_name,active_config_version)
                    VALUES ($1,$2,$2,1)
                    """,
                    tenant_id,
                    app_id,
                )
            version = await connection.fetchval(
                """
                SELECT coalesce(max(version),0)+1 FROM config_revisions
                 WHERE tenant_id=$1 AND app_id=$2
                """,
                tenant_id,
                app_id,
            )
            payload = {**config, "tenant_id": tenant_id, "app_id": app_id, "version": version}
            validated = TenantConfig.model_validate(payload)
            canonical = validated.model_dump_json()
            checksum = hashlib.sha256(canonical.encode()).hexdigest()
            await connection.execute(
                """
                INSERT INTO config_revisions (
                    tenant_id,app_id,version,config_json,checksum,created_by
                ) VALUES ($1,$2,$3,$4::jsonb,$5,$6)
                """,
                tenant_id,
                app_id,
                version,
                canonical,
                checksum,
                actor,
            )
            await connection.execute(
                """
                UPDATE agent_apps
                   SET control_version=control_version+1,updated_at=now()
                 WHERE tenant_id=$1 AND app_id=$2
                """,
                tenant_id,
                app_id,
            )
            new_version = await self._bump_version(connection, tenant_id, current)
            response = {
                "tenant_id": tenant_id,
                "app_id": app_id,
                "version": version,
                "checksum": checksum,
                "tenant_control_version": new_version,
            }
            await self._store_idempotency(
                connection,
                tenant_id,
                idempotency_key,
                "create_config_revision",
                request_hash,
                response,
                201,
            )
            await self._audit(connection, tenant_id, actor, "config_created", idempotency_key)
            return response

    async def activate_config(
        self,
        *,
        tenant_id: str,
        app_id: str,
        version: int,
        percentage: float,
        actor: str,
        expected_version: int,
        idempotency_key: str,
        request_hash: str,
        operation: Literal["activate_config", "rollback_config"] = "activate_config",
    ) -> dict[str, Any]:
        if not 0 <= percentage <= 100:
            raise ValueError("rollout percentage must be between 0 and 100")
        async with self._transaction(tenant_id) as connection:
            cached = await self._cached(connection, tenant_id, idempotency_key, request_hash)
            if cached:
                return cached
            current = await self._lock_version(connection, tenant_id, expected_version)
            exists = await connection.fetchval(
                """
                SELECT 1 FROM config_revisions
                 WHERE tenant_id=$1 AND app_id=$2 AND version=$3
                """,
                tenant_id,
                app_id,
                version,
            )
            if not exists:
                raise LookupError("configuration revision does not exist")
            if percentage == 100:
                await connection.execute(
                    """
                    UPDATE agent_apps
                       SET active_config_version=$3,candidate_config_version=NULL,
                           candidate_percent=0,control_version=control_version+1,
                           updated_at=now()
                     WHERE tenant_id=$1 AND app_id=$2
                    """,
                    tenant_id,
                    app_id,
                    version,
                )
            elif percentage == 0:
                await connection.execute(
                    """
                    UPDATE agent_apps SET candidate_config_version=NULL,
                           candidate_percent=0,control_version=control_version+1,
                           updated_at=now()
                     WHERE tenant_id=$1 AND app_id=$2
                    """,
                    tenant_id,
                    app_id,
                )
            else:
                await connection.execute(
                    """
                    UPDATE agent_apps
                       SET candidate_config_version=$3,candidate_percent=$4,
                           control_version=control_version+1,updated_at=now()
                     WHERE tenant_id=$1 AND app_id=$2
                    """,
                    tenant_id,
                    app_id,
                    version,
                    percentage,
                )
            new_version = await self._bump_version(connection, tenant_id, current)
            response = {
                "tenant_id": tenant_id,
                "app_id": app_id,
                "version": version,
                "percentage": percentage,
                "tenant_control_version": new_version,
            }
            await self._store_idempotency(
                connection,
                tenant_id,
                idempotency_key,
                operation,
                request_hash,
                response,
                200,
            )
            await self._audit(connection, tenant_id, actor, operation, idempotency_key)
            return response

    async def audit_page(self, tenant_id: str, *, cursor: str | None, limit: int) -> dict[str, Any]:
        limit = max(1, min(limit, 200))
        boundary: tuple[datetime, UUID] | None = _decode_cursor(cursor) if cursor else None
        async with self._transaction(tenant_id) as connection:
            if boundary:
                rows = await connection.fetch(
                    """
                    SELECT * FROM audit_logs
                     WHERE tenant_id=$1 AND (occurred_at,audit_id) < ($2,$3)
                     ORDER BY occurred_at DESC,audit_id DESC LIMIT $4
                    """,
                    tenant_id,
                    boundary[0],
                    boundary[1],
                    limit + 1,
                )
            else:
                rows = await connection.fetch(
                    """
                    SELECT * FROM audit_logs WHERE tenant_id=$1
                     ORDER BY occurred_at DESC,audit_id DESC LIMIT $2
                    """,
                    tenant_id,
                    limit + 1,
                )
        has_more = len(rows) > limit
        page = rows[:limit]
        next_cursor = (
            _encode_cursor(page[-1]["occurred_at"], page[-1]["audit_id"]) if has_more else None
        )
        return {"items": [_record_json(row) for row in page], "next_cursor": next_cursor}

    async def dead_letters(self, tenant_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        async with self._transaction(tenant_id) as connection:
            rows = await connection.fetch(
                """
                SELECT dead_letter_id,source_type,source_id,reason,status,created_at
                  FROM dead_letters WHERE tenant_id=$1 AND status='open'
                 ORDER BY created_at DESC LIMIT $2
                """,
                tenant_id,
                max(1, min(limit, 200)),
            )
        return [_record_json(row) for row in rows]

    async def wecom_acceptance_snapshot(
        self, tenant_id: str, binding_id: str, *, limit: int
    ) -> dict[str, Any] | None:
        bounded_limit = max(1, min(limit, 200))
        async with self._transaction(tenant_id) as connection:
            exists = await connection.fetchval(
                """
                SELECT 1
                  FROM channel_bindings
                 WHERE tenant_id=$1 AND binding_id=$2
                   AND channel='wecom_ai_bot'
                """,
                tenant_id,
                binding_id,
            )
            if not exists:
                return None
            state = await connection.fetchrow(
                """
                SELECT owner_hash,epoch,phase,acquired_at,authenticated_at,
                       disconnected_at,released_at,last_provider_event_hash,
                       last_provider_event_at,updated_at
                  FROM wecom_connection_state
                 WHERE tenant_id=$1 AND binding_id=$2
                """,
                tenant_id,
                binding_id,
            )
            events = await connection.fetch(
                """
                SELECT event_id,connection_epoch,event_type,owner_hash,
                       provider_event_hash,occurred_at
                  FROM im_acceptance_evidence_events
                 WHERE tenant_id=$1 AND binding_id=$2
                 ORDER BY occurred_at DESC,event_id DESC
                 LIMIT $3
                """,
                tenant_id,
                binding_id,
                bounded_limit,
            )
        return {
            "state": _project_record(state, _WECOM_STATE_FIELDS) if state else None,
            "events": [_project_record(row, _WECOM_EVENT_FIELDS) for row in events],
        }

    async def im_acceptance_outbound_evidence(
        self,
        tenant_id: str,
        binding_id: str,
        *,
        run_id: str,
        outbound_id: UUID,
    ) -> dict[str, Any] | None:
        """Return bounded, content-free delivery evidence for one outbound.

        The current schema does not persist an IM acceptance run ID on an
        outbound or artifact row.  The response therefore hashes the caller's
        run ID for request binding but explicitly marks run and artifact
        correlation unavailable instead of inferring either from timestamps,
        sessions, or payload content.
        """

        async with self._transaction(tenant_id) as connection:
            exists = await connection.fetchval(
                """
                SELECT 1
                  FROM channel_bindings
                 WHERE tenant_id=$1 AND binding_id=$2
                """,
                tenant_id,
                binding_id,
            )
            if not exists:
                return None
            outbound = await connection.fetchrow(
                """
                SELECT message.status,message.provider_message_id,
                       message.created_at,message.updated_at,
                       (
                           SELECT count(*)
                             FROM outbox_events AS pending
                            WHERE pending.tenant_id=message.tenant_id
                              AND pending.aggregate_type='outbound'
                              AND pending.aggregate_id=message.outbound_id::text
                              AND pending.published_at IS NULL
                       ) AS pending_count,
                       (
                           SELECT count(*)
                             FROM dead_letters AS dead
                            WHERE dead.tenant_id=message.tenant_id
                              AND dead.source_id=message.outbound_id::text
                              AND dead.status='open'
                       ) AS dlq_count
                  FROM outbound_messages AS message
                 WHERE message.tenant_id=$1 AND message.binding_id=$2
                   AND message.outbound_id=$3
                """,
                tenant_id,
                binding_id,
                outbound_id,
            )
            attempts = (
                await connection.fetch(
                    """
                    SELECT attempt_number,status,provider_code,started_at,completed_at,
                           total_count
                      FROM (
                          SELECT attempt_number,status,provider_code,started_at,completed_at,
                                 count(*) OVER () AS total_count
                            FROM delivery_attempts
                           WHERE tenant_id=$1 AND outbound_id=$2
                           ORDER BY attempt_number DESC
                           LIMIT 100
                      ) AS recent_attempts
                     ORDER BY attempt_number
                    """,
                    tenant_id,
                    outbound_id,
                )
                if outbound is not None
                else []
            )

        response: dict[str, Any] = {
            "schema_version": 1,
            "tenant_id": tenant_id,
            "binding_id": binding_id,
            "requested_run_id_sha256": _acceptance_identifier_hash(
                "run", tenant_id, binding_id, run_id
            ),
            "run_correlation": {
                "availability": "unavailable",
                "reason": "run_id_not_persisted_on_outbound_records",
            },
            "artifact": {
                "availability": "unavailable",
                "reason": "artifact_not_correlated_to_run_or_binding",
            },
        }
        if outbound is None:
            response["outbound"] = {"availability": "not_found"}
            return response

        provider_message_id = outbound["provider_message_id"]
        attempt_count = int(attempts[0]["total_count"]) if attempts else 0
        response["outbound"] = {
            "availability": "available",
            "outbound_id_sha256": _acceptance_identifier_hash(
                "outbound", tenant_id, binding_id, str(outbound_id)
            ),
            "delivery_status": str(outbound["status"]),
            "provider_message_id_sha256": (
                _acceptance_identifier_hash(
                    "provider-message",
                    tenant_id,
                    binding_id,
                    str(provider_message_id),
                )
                if provider_message_id is not None
                else None
            ),
            "attempt_count": attempt_count,
            "attempts_truncated": attempt_count > len(attempts),
            "attempts": [
                {
                    "attempt_number": int(attempt["attempt_number"]),
                    "status": str(attempt["status"]),
                    "provider_code": _safe_provider_code(attempt["provider_code"]),
                    "started_at": _timestamp_json(attempt["started_at"]),
                    "completed_at": _timestamp_json(attempt["completed_at"]),
                }
                for attempt in attempts
            ],
            "pending_count": int(outbound["pending_count"]),
            "dlq_count": int(outbound["dlq_count"]),
            "created_at": _timestamp_json(outbound["created_at"]),
            "updated_at": _timestamp_json(outbound["updated_at"]),
        }
        return response

    async def replay_outbound(
        self,
        *,
        tenant_id: str,
        outbound_id: str,
        confirm_ambiguous: bool,
        actor: str,
        expected_version: int,
        idempotency_key: str,
        request_hash: str,
    ) -> dict[str, Any]:
        async with self._transaction(tenant_id) as connection:
            cached = await self._cached(connection, tenant_id, idempotency_key, request_hash)
            if cached:
                return cached
            current = await self._lock_version(connection, tenant_id, expected_version)
            row = await connection.fetchrow(
                """
                SELECT * FROM outbound_messages
                 WHERE tenant_id=$1 AND outbound_id=$2 FOR UPDATE
                """,
                tenant_id,
                UUID(outbound_id),
            )
            if row is None:
                raise LookupError("outbound message does not exist")
            status = str(row["status"])
            if status == "ambiguous":
                if not confirm_ambiguous:
                    raise ValueError("ambiguous delivery requires explicit confirmation")
            elif status != "failed":
                raise ValueError(
                    "only failed or explicitly confirmed ambiguous deliveries can be replayed"
                )
            await connection.execute(
                """
                UPDATE outbound_messages
                   SET status='pending',manual_replay_approved=$3,updated_at=now()
                 WHERE tenant_id=$1 AND outbound_id=$2
                """,
                tenant_id,
                UUID(outbound_id),
                status == "ambiguous" and confirm_ambiguous,
            )
            await connection.execute(
                """
                INSERT INTO outbox_events (
                    tenant_id,aggregate_type,aggregate_id,event_type,payload_json,trace_headers
                ) VALUES ($1,'outbound',$2,$5,$3,$4)
                ON CONFLICT DO NOTHING
                """,
                tenant_id,
                outbound_id,
                row["payload_json"],
                row["trace_headers"],
                f"outbound.{row['channel']}.ready",
            )
            await connection.execute(
                """
                UPDATE dead_letters
                   SET status='replayed',resolved_at=now()
                 WHERE tenant_id=$1 AND source_id=$2 AND status='open'
                """,
                tenant_id,
                outbound_id,
            )
            new_version = await self._bump_version(connection, tenant_id, current)
            response = {
                "outbound_id": outbound_id,
                "status": "pending",
                "tenant_control_version": new_version,
            }
            await self._store_idempotency(
                connection,
                tenant_id,
                idempotency_key,
                "replay_outbound",
                request_hash,
                response,
                202,
            )
            await self._audit(connection, tenant_id, actor, "outbound_replayed", idempotency_key)
            return response

    @staticmethod
    async def _cached(
        connection: asyncpg.Connection,
        tenant_id: str,
        key: str,
        request_hash: str,
    ) -> dict[str, Any] | None:
        row = await connection.fetchrow(
            """
            SELECT request_hash,response_json FROM admin_idempotency
             WHERE tenant_id=$1 AND idempotency_key=$2 AND expires_at>now()
            """,
            tenant_id,
            key,
        )
        if row is None:
            return None
        if row["request_hash"] != request_hash:
            raise IdempotencyConflict("idempotency key was used for another request")
        value = row["response_json"]
        if isinstance(value, str):
            value = json.loads(value)
        if not isinstance(value, Mapping):
            raise RuntimeError("invalid idempotency response")
        return dict(value)

    @staticmethod
    async def _store_idempotency(
        connection: asyncpg.Connection,
        tenant_id: str,
        key: str,
        operation: str,
        request_hash: str,
        response: dict[str, Any],
        status: int,
    ) -> None:
        await connection.execute(
            """
            INSERT INTO admin_idempotency (
                tenant_id,idempotency_key,operation,request_hash,response_status,
                response_json,expires_at
            ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)
            """,
            tenant_id,
            key,
            operation,
            request_hash,
            status,
            json.dumps(response, default=str, separators=(",", ":")),
            datetime.now(UTC) + timedelta(hours=24),
        )

    @staticmethod
    async def _lock_version(connection: asyncpg.Connection, tenant_id: str, expected: int) -> int:
        current = await connection.fetchval(
            "SELECT control_version FROM tenants WHERE tenant_id=$1 FOR UPDATE", tenant_id
        )
        if current is None:
            raise LookupError("tenant does not exist")
        if int(current) != expected:
            raise ControlVersionConflict("tenant control version changed")
        return int(current)

    @staticmethod
    async def _bump_version(connection: asyncpg.Connection, tenant_id: str, current: int) -> int:
        return int(
            await connection.fetchval(
                """
                UPDATE tenants SET control_version=control_version+1,updated_at=now()
                 WHERE tenant_id=$1 AND control_version=$2 RETURNING control_version
                """,
                tenant_id,
                current,
            )
        )

    @staticmethod
    async def _audit(
        connection: asyncpg.Connection,
        tenant_id: str,
        actor: str,
        decision: str,
        idempotency_key: str,
    ) -> None:
        await connection.execute(
            """
            INSERT INTO audit_logs (
                tenant_id,user_id,decision,trace_id,idempotency_key,redaction_applied
            ) VALUES ($1,$2,$3,$4,$5,true)
            """,
            tenant_id,
            actor,
            decision,
            f"admin:{idempotency_key}",
            idempotency_key,
        )


def _record_json(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value.isoformat()
        if isinstance(value, datetime)
        else str(value)
        if isinstance(value, UUID)
        else value
        for key, value in row.items()
    }


def _project_record(row: Mapping[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return _record_json({field: row[field] for field in fields})


def _acceptance_identifier_hash(domain: str, *parts: str) -> str:
    material = "\x00".join(("trpc-im-acceptance-evidence-v1", domain, *parts))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _safe_provider_code(value: object) -> str | None:
    if value is None:
        return None
    rendered = str(value)
    return rendered if rendered in _SAFE_PROVIDER_CODES else None


def _timestamp_json(value: object) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else None


def _encode_cursor(timestamp: datetime, audit_id: UUID) -> str:
    value = json.dumps([timestamp.isoformat(), str(audit_id)], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode_cursor(cursor: str) -> tuple[datetime, UUID]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        timestamp, audit_id = json.loads(base64.urlsafe_b64decode(padded))
        return datetime.fromisoformat(timestamp), UUID(audit_id)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid audit cursor") from exc


__all__ = [
    "ControlPlaneRepository",
    "ControlVersionConflict",
    "IdempotencyConflict",
    "PostgresControlPlaneRepository",
]
