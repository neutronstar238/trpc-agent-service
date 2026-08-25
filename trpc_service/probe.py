"""Lightweight authenticated dependency probe for non-HTTP runtime roles."""

from __future__ import annotations

import argparse
import asyncio
import math
import os
import re
import tempfile
from collections.abc import Awaitable
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

from trpc_service.config.secrets import (
    LocalSecretProvider,
    SecretRef,
    SecretResolutionError,
)

_SECRET_REFERENCE_SCHEMES = frozenset({"env", "file", "literal"})

_REDIS_ROLES = {
    "gateway",
    "worker",
    "outbox-dispatcher",
    "post-turn-projector",
    "wecom-connector",
}


def _runtime_state_dir() -> Path:
    configured = os.getenv("TRPC_SERVICE_RUNTIME_STATE_DIR", "").strip()
    if configured:
        return Path(configured)
    return Path(tempfile.gettempdir()) / "trpc-agent-service"


def _liveness_max_age_seconds() -> float | None:
    raw = os.getenv("TRPC_SERVICE_LIVENESS_MAX_AGE_SECONDS", "30")
    try:
        value = float(raw)
    except ValueError:
        return None
    if not math.isfinite(value) or not 5 <= value <= 300:
        return None
    return value


def _production_environment() -> bool:
    return os.getenv("TRPC_SERVICE_ENVIRONMENT", "development").strip().lower() == "production"


def _secret_provider() -> LocalSecretProvider:
    """Build the same bounded local provider used by runtime settings."""

    production = _production_environment()
    raw_root = os.getenv("TRPC_SERVICE_TENANT_SECRET_ROOT", "").strip()
    secret_root: Path | None = None
    if raw_root:
        secret_root = Path(raw_root)
        if not secret_root.is_absolute():
            raise SecretResolutionError("tenant secret root must be absolute")
    elif production:
        raise SecretResolutionError("tenant secret root is required in production")
    return LocalSecretProvider(
        allow_literal=not production,
        secret_root=secret_root,
    )


def _normalize_file_reference(raw: str) -> str:
    """Normalize the native Windows file spelling before URI parsing."""

    if os.name != "nt" or not raw.startswith("file://"):
        return raw
    native = raw.removeprefix("file://")
    if not re.match(r"^[A-Za-z]:[\\/]", native):
        return raw
    try:
        return Path(native).as_uri()
    except ValueError:
        return raw


def _resolve_reference(name: str) -> str | None:
    """Resolve a service setting reference with production-safe boundaries.

    Plain values remain valid for non-reference settings such as database and
    Redis URLs. Variables named ``*_REF`` must contain a supported
    ``SecretRef`` URI so a healthcheck cannot silently treat an unreviewed
    password literal as a resolved secret.
    """

    raw = os.getenv(name)
    if not raw:
        return None
    raw = _normalize_file_reference(raw)
    parsed = urlsplit(raw)
    if parsed.scheme not in _SECRET_REFERENCE_SCHEMES:
        return None if name.endswith("_REF") else raw
    try:
        return _secret_provider().resolve(SecretRef(uri=raw))
    except (OSError, SecretResolutionError, ValueError):
        return None


def _valid_role(role: str) -> bool:
    return isinstance(role, str) and role.strip().lower() in _SUPPORTED_ROLES


_WORKER_DATABASE_ROLES = {
    "worker",
    "outbox-dispatcher",
    "channel-dispatcher",
    "post-turn-projector",
    "wecom-connector",
    "session-recovery",
}
_SUPPORTED_ROLES = frozenset(_REDIS_ROLES | _WORKER_DATABASE_ROLES | {"admin"})
_DATABASE_FUNCTIONS = {
    "gateway": ("public.resolve_channel_binding(text)",),
    "worker": (
        "public.resolve_channel_binding(text)",
        "public.list_channel_bindings(text)",
        "public.claim_outbox_events(text,text,integer,integer)",
        "public.sweep_expired_session_leases(integer)",
        "public.schedule_session_mailbox_retries(integer)",
        "public.reconcile_session_mailboxes(integer)",
        "public.reconcile_session_mailboxes_v2(integer,integer)",
    ),
    "outbox-dispatcher": ("public.claim_outbox_events(text,text,integer,integer)",),
    "channel-dispatcher": (
        "public.claim_outbox_events(text,text,integer,integer)",
        "public.resolve_channel_binding(text)",
    ),
    "post-turn-projector": ("public.claim_outbox_events(text,text,integer,integer)",),
    "wecom-connector": (
        "public.list_channel_bindings(text)",
        "public.resolve_channel_binding(text)",
    ),
    "session-recovery": (
        "public.sweep_expired_session_leases(integer)",
        "public.schedule_session_mailbox_retries(integer)",
        "public.reconcile_session_mailboxes(integer)",
        "public.reconcile_session_mailboxes_v2(integer,integer)",
    ),
}
_WORKER_TABLES = (
    "tenants",
    "agent_apps",
    "config_revisions",
    "storage_profiles",
    "tenant_policies",
    "admin_idempotency",
    "channel_bindings",
    "channel_identities",
    "inbound_messages",
    "outbound_messages",
    "delivery_attempts",
    "sessions",
    "session_turns",
    "turn_intents",
    "session_events",
    "session_summaries",
    "memories",
    "artifacts",
    "knowledge_items",
    "knowledge_embeddings",
    "outbox_events",
    "dead_letters",
    "tool_executions",
    "confirmation_challenges",
    "audit_logs",
    "tenant_budget_usage",
    "fault_stage_controls",
    "session_mailboxes",
    "session_mailbox_items",
)


def _url_password(url: str, password: str | None) -> str:
    if not password:
        return url
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    user = quote(parts.username or "", safe="")
    credentials = f"{user}:{quote(password, safe='')}@" if user else f":{quote(password, safe='')}@"
    return urlunsplit(
        (parts.scheme, credentials + host + port, parts.path, parts.query, parts.fragment)
    )


async def check(role: str) -> bool:
    if not _valid_role(role):
        return False
    role = role.strip().lower()
    import asyncpg
    import redis.asyncio as redis_async

    from trpc_service.lifecycle import is_process_ready

    if not is_process_ready(role, _runtime_state_dir()):
        return False
    worker_reference_configured = bool(
        os.getenv("TRPC_SERVICE_WORKER_DATABASE_DSN_REF", "").strip()
    )
    worker_reference = _resolve_reference("TRPC_SERVICE_WORKER_DATABASE_DSN_REF")
    if role in _WORKER_DATABASE_ROLES:
        database_url = worker_reference
        password_configured = bool(
            os.getenv("TRPC_SERVICE_WORKER_DATABASE_PASSWORD_REF", "").strip()
        )
        password_reference = _resolve_reference("TRPC_SERVICE_WORKER_DATABASE_PASSWORD_REF")
        expected_role = "trpc_worker"
    else:
        if worker_reference_configured:
            return False
        database_url = _resolve_reference("TRPC_SERVICE_DATABASE_DSN")
        if database_url is None:
            database_url = _resolve_reference("TRPC_SERVICE_DATABASE_DSN_REF")
        password_configured = bool(
            os.getenv("TRPC_SERVICE_DATABASE_PASSWORD_REF", "").strip()
        )
        password_reference = _resolve_reference("TRPC_SERVICE_DATABASE_PASSWORD_REF")
        expected_role = "trpc_runtime"
    if password_configured and password_reference is None:
        return False
    redis_url = _resolve_reference("TRPC_SERVICE_REDIS_URL")
    if not database_url or (role in _REDIS_ROLES and not redis_url):
        return False
    database_url = _url_password(
        database_url.replace("postgresql+asyncpg://", "postgresql://"),
        password_reference,
    )
    connection: asyncpg.Connection | None = None
    redis = None
    try:
        connection = await asyncpg.connect(database_url, timeout=3, command_timeout=3)
        if await connection.fetchval("SELECT 1") != 1:
            return False
        fetchrow = getattr(connection, "fetchrow", None)
        if not callable(fetchrow):
            return False
        identity = await fetchrow(
            """
                SELECT current_user::text AS current_user,
                       session_user::text AS session_user,
                       rolsuper AS is_superuser,
                       rolbypassrls AS bypasses_rls,
                       rolcanlogin,
                       has_schema_privilege(current_user, 'public', 'USAGE')
                           AS schema_usage,
                       (SELECT count(*)
                          FROM pg_class AS c
                          JOIN pg_namespace AS n ON n.oid = c.relnamespace
                         WHERE n.nspname = 'public' AND c.relrowsecurity
                           AND pg_get_userbyid(c.relowner) = current_user)
                           AS owned_rls_table_count
                  FROM pg_roles
                 WHERE rolname = current_user
            """
        )
        expected_bypass = role in _WORKER_DATABASE_ROLES
        if (
            identity is None
            or identity["current_user"] != expected_role
            or identity["session_user"] != expected_role
            or identity["is_superuser"]
            or not identity["rolcanlogin"]
            or not identity["schema_usage"]
            or identity["owned_rls_table_count"] != 0
            or bool(identity["bypasses_rls"]) != expected_bypass
        ):
            return False
        for signature in _DATABASE_FUNCTIONS.get(role, ()):
            if not await connection.fetchval(
                "SELECT has_function_privilege(current_user, $1::regprocedure, 'EXECUTE')",
                signature,
            ):
                return False
        if expected_bypass and not await connection.fetchval(
            """
                SELECT bool_and(
                    has_table_privilege(
                        current_user,
                        format('public.%I', table_name),
                        'SELECT,INSERT,UPDATE,DELETE'
                    )
                )
                  FROM unnest($1::text[]) AS table_name
            """,
            list(_WORKER_TABLES),
        ):
            return False
        if role in _REDIS_ROLES:
            assert redis_url is not None
            redis_password_configured = bool(
                os.getenv("TRPC_SERVICE_REDIS_PASSWORD_REF", "").strip()
            )
            redis_password = _resolve_reference("TRPC_SERVICE_REDIS_PASSWORD_REF")
            if redis_password_configured and redis_password is None:
                return False
            redis = redis_async.from_url(
                _url_password(
                    redis_url,
                    redis_password,
                ),
                socket_connect_timeout=3,
                socket_timeout=3,
            )
            ping_result = redis.ping()
            if isinstance(ping_result, Awaitable):
                ping_result = await ping_result
            if not ping_result:
                return False
        return True
    except Exception:
        return False
    finally:
        if redis is not None:
            await redis.aclose()
        if connection is not None:
            await connection.close()


def check_liveness(role: str) -> bool:
    if not _valid_role(role):
        return False
    role = role.strip().lower()
    from trpc_service.lifecycle import is_process_live

    max_age_seconds = _liveness_max_age_seconds()
    return max_age_seconds is not None and is_process_live(
        role,
        _runtime_state_dir(),
        max_age_seconds=max_age_seconds,
    )


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--role", required=True)
    parser.add_argument("--liveness", action="store_true")
    args = parser.parse_args()
    if not _valid_role(args.role):
        return 1
    role = args.role.strip().lower()
    if args.liveness:
        return 0 if check_liveness(role) else 1
    return 0 if asyncio.run(check(role)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
