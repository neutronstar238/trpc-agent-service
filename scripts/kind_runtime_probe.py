#!/usr/bin/env python3
"""Run the candidate image's PostgreSQL/IM runtime probe.

This probe is intentionally different from :mod:`scripts.kind_ack_gate`:
the gate checks disposable HTTP fixtures, while this module calls the
production repositories against PostgreSQL.  The provider endpoint is used
only as an external side-effect/status oracle.  CAS, attempts, leases and
immutable evidence are all exercised through ``PostgresExecutionLedger``.

The command has no dependency on an ACK or Kubernetes client and is suitable
for ``kubectl exec`` inside a candidate Pod::

    python scripts/kind_runtime_probe.py all --json --report /tmp/probe.json

Required values are supplied through environment variables so a DSN is never
part of a command line or JSON report.  See ``RuntimeProbeConfig.from_env``
for the exact names.  A missing value is reported as ``not_run`` and exits
non-zero; it is never treated as a successful check.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

import asyncpg

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.evidence_lineage import source_fingerprint
from scripts.report_io import atomic_write_json
from trpc_service.channels.envelopes import InboundEnvelope, PayloadKind
from trpc_service.config.settings import SchedulerVersion
from trpc_service.runtime import TenantRuntime
from trpc_service.storage.postgres import PostgresRuntimeRepository
from trpc_service.tenant.models import (
    Channel,
    ConversationKind,
    ModelPolicy,
    StorageSelection,
    TenantConfig,
    ToolRisk,
)
from trpc_service.tool.execution import ExecutionStatus
from trpc_service.tool.postgres import PostgresExecutionLedger
from trpc_service.tool.reconciliation import (
    ExecutionProbeIntent,
    ProviderReconciler,
    ReconciliationConflict,
    ReconciliationEvidence,
    ReconciliationOutcome,
    ToolExecutionReconciliationCoordinator,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = ROOT / "runs" / "multitenant" / "kind-runtime-probe.json"
DEFAULT_PROVIDER_URL = "http://kind-fake-provider:8080"
PROBE_SCHEMA_VERSION = 1
PROBE_SCENARIO = "kind_runtime_postgres_reconciliation"
PROBE_ASSERTION = (
    "candidate repositories prove duplicate IM and effect reconciliation against PostgreSQL"
)
OWNER_ID = "kind-runtime-probe-worker"
RECONCILER_ID = "kind-runtime-probe-reconciler"
ROUTING_KEY = b"kind-runtime-probe-routing-key-v1" * 2


class _JsonRequester(Protocol):
    def __call__(
        self,
        url: str,
        *,
        method: str = "GET",
        body: Mapping[str, object] | None = None,
        timeout: float,
    ) -> tuple[int, Mapping[str, object]]: ...


def _safe_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_exception(exc: BaseException) -> str:
    """Return a non-sensitive, stable error class for a report."""

    return type(exc).__name__


def _normalize_dsn(value: str) -> str:
    """Make SQLAlchemy-style DSNs usable by asyncpg without logging them."""

    raw = value.strip()
    if raw.startswith("postgresql+asyncpg://"):
        return "postgresql://" + raw.removeprefix("postgresql+asyncpg://")
    if raw.startswith("postgres://"):
        return "postgresql://" + raw.removeprefix("postgres://")
    return raw


def _valid_url(value: str | None) -> bool:
    if not isinstance(value, str) or not value or len(value) > 2048:
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return (
        parsed.scheme.lower() in {"http", "https"}
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
        and not any(char.isspace() for char in value)
    )


@dataclass(frozen=True, slots=True)
class RuntimeProbeConfig:
    """Explicit, non-secret inputs for a live candidate-Pod probe."""

    fixture_dsn: str = ""
    runtime_dsn: str = ""
    reconciler_dsn: str = ""
    cleanup_dsn: str = ""
    provider_execute_url: str = ""
    provider_status_url: str = ""
    provider_metrics_url: str = ""
    timeout_seconds: float = 10.0
    duplicate_count: int = 100
    keep_fixtures: bool = False

    @classmethod
    def from_env(cls) -> RuntimeProbeConfig:
        runtime_base = os.getenv("TRPC_SERVICE_DATABASE_DSN", "").strip()
        worker = os.getenv("TRPC_SERVICE_WORKER_DATABASE_DSN", "").strip()
        fixture = os.getenv("TRPC_KIND_PROBE_FIXTURE_DSN", "").strip()
        runtime = os.getenv("TRPC_KIND_PROBE_RUNTIME_DSN", "").strip()
        reconciler = os.getenv("TRPC_KIND_TOOL_RECONCILER_DSN", "").strip()
        reconciler = reconciler or os.getenv("TRPC_KIND_PROBE_RECONCILER_DSN", "").strip()
        cleanup = os.getenv("TRPC_KIND_PROBE_CLEANUP_DSN", "").strip()
        cleanup = cleanup or os.getenv("TRPC_KIND_PROBE_MIGRATION_DSN", "").strip()
        provider_base = (
            os.getenv("TRPC_KIND_PROVIDER_URL", "").strip().rstrip("/") or DEFAULT_PROVIDER_URL
        )
        provider_execute = os.getenv("TRPC_KIND_PROVIDER_EXECUTE_URL", "").strip()
        provider_status = os.getenv("TRPC_KIND_PROVIDER_STATUS_URL", "").strip()
        provider_metrics = os.getenv("TRPC_KIND_PROVIDER_METRICS_URL", "").strip()
        if provider_base:
            provider_execute = provider_execute or f"{provider_base}/v1/effects"
            provider_status = provider_status or f"{provider_base}/v1/effects/{{execution_key}}"
            provider_metrics = provider_metrics or f"{provider_base}/v1/metrics"
        timeout_raw = os.getenv("TRPC_KIND_PROBE_TIMEOUT_SECONDS", "10").strip()
        count_raw = os.getenv("TRPC_KIND_PROBE_DUPLICATE_COUNT", "100").strip()
        try:
            timeout = float(timeout_raw)
        except ValueError:
            timeout = -1
        try:
            count = int(count_raw)
        except ValueError:
            count = -1
        return cls(
            fixture_dsn=fixture or runtime_base or worker,
            runtime_dsn=runtime or runtime_base or worker,
            reconciler_dsn=reconciler or worker or runtime_base,
            cleanup_dsn=cleanup,
            provider_execute_url=provider_execute,
            provider_status_url=provider_status,
            provider_metrics_url=provider_metrics,
            timeout_seconds=timeout,
            duplicate_count=count,
            keep_fixtures=os.getenv("TRPC_KIND_PROBE_KEEP_FIXTURES", "").strip().lower()
            in {"1", "true", "yes"},
        )

    def missing_for(self, command: str) -> tuple[str, ...]:
        missing: list[str] = []
        if not self.fixture_dsn:
            missing.append(
                "TRPC_KIND_PROBE_FIXTURE_DSN/TRPC_SERVICE_DATABASE_DSN/TRPC_SERVICE_WORKER_DATABASE_DSN"
            )
        if command in {"all", "im"} and not self.runtime_dsn:
            missing.append("TRPC_KIND_PROBE_RUNTIME_DSN/TRPC_SERVICE_DATABASE_DSN")
        if command in {"all", "reconcile"}:
            if not self.reconciler_dsn:
                missing.append("TRPC_KIND_TOOL_RECONCILER_DSN/TRPC_KIND_PROBE_RECONCILER_DSN")
            for name, value in (
                ("TRPC_KIND_PROVIDER_EXECUTE_URL", self.provider_execute_url),
                ("TRPC_KIND_PROVIDER_STATUS_URL", self.provider_status_url),
                ("TRPC_KIND_PROVIDER_METRICS_URL", self.provider_metrics_url),
            ):
                if not _valid_url(value):
                    missing.append(name)
        if not 0.1 <= self.timeout_seconds <= 120:
            missing.append("TRPC_KIND_PROBE_TIMEOUT_SECONDS(0.1..120)")
        if not 1 <= self.duplicate_count <= 1000:
            missing.append("TRPC_KIND_PROBE_DUPLICATE_COUNT(1..1000)")
        return tuple(missing)


@dataclass(frozen=True, slots=True)
class ExecutionFixture:
    tenant_id: str
    execution_key: str
    turn_id: str
    session_id: str
    inbound_id: uuid.UUID
    tool_name: str = "probe_external_effect"
    arguments_hash: str = "probe-arguments-hash"
    trace_id: str = "probe-trace"

    def intent(self) -> ExecutionProbeIntent:
        return ExecutionProbeIntent(
            tenant_id=self.tenant_id,
            execution_key=self.execution_key,
            turn_id=self.turn_id,
            tool_name=self.tool_name,
            arguments_hash=self.arguments_hash,
            app_id="kind-probe-app",
            session_id=self.session_id,
            trace_id=self.trace_id,
            attempt=1,
        )


class ProbeFixtures:
    """Create isolated tenant rows; never reuse a customer's identifiers."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        suffix = uuid.uuid4().hex
        self.primary_tenant = f"kind-probe-a-{suffix}"
        self.secondary_tenant = f"kind-probe-b-{suffix}"
        self.primary_binding = f"kind-probe-binding-a-{suffix}"
        self.secondary_binding = f"kind-probe-binding-b-{suffix}"
        self.pool = pool
        self.execution_fixtures: list[ExecutionFixture] = []

    @property
    def tenants(self) -> tuple[str, str]:
        return self.primary_tenant, self.secondary_tenant

    async def seed(self) -> None:
        config = TenantConfig(
            tenant_id=self.primary_tenant,
            app_id="kind-probe-app",
            version=1,
            model=ModelPolicy(provider="offline", model="deterministic"),
            storage=StorageSelection(profile_id="kind-probe"),
        )
        for tenant_id, binding_id in (
            (self.primary_tenant, self.primary_binding),
            (self.secondary_tenant, self.secondary_binding),
        ):
            tenant_config = config.model_copy(update={"tenant_id": tenant_id})
            rendered = json.dumps(
                tenant_config.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            async with self.pool.acquire() as connection, connection.transaction():
                await connection.execute("SELECT set_config('app.tenant_id', $1, true)", tenant_id)
                await connection.execute(
                    "INSERT INTO tenants (tenant_id,display_name) VALUES ($1,$2)",
                    tenant_id,
                    f"Kind runtime probe {tenant_id[-8:]}",
                )
                await connection.execute(
                    """
                    INSERT INTO agent_apps (tenant_id,app_id,display_name,active_config_version)
                    VALUES ($1,'kind-probe-app','Kind runtime probe',1)
                    """,
                    tenant_id,
                )
                await connection.execute(
                    """
                    INSERT INTO config_revisions (
                        tenant_id,app_id,version,config_json,checksum,created_by
                    ) VALUES ($1,'kind-probe-app',1,$2::jsonb,$3,'kind-runtime-probe')
                    """,
                    tenant_id,
                    rendered,
                    _safe_hash(rendered),
                )
                await connection.execute(
                    """
                    INSERT INTO storage_profiles (
                        tenant_id,profile_id,profile_json,embedding_dimension
                    ) VALUES ($1,'kind-probe','{}'::jsonb,1536)
                    """,
                    tenant_id,
                )
                await connection.execute(
                    """
                    INSERT INTO channel_bindings (
                        tenant_id,binding_id,app_id,channel,account_id,
                        secret_refs,capabilities
                    ) VALUES ($1,$2,'kind-probe-app','wecom_ai_bot',$3,'{}'::jsonb,'[]'::jsonb)
                    """,
                    tenant_id,
                    binding_id,
                    "kind-probe-wecom-account",
                )

    async def add_execution(self, label: str) -> ExecutionFixture:
        fixture = ExecutionFixture(
            tenant_id=self.primary_tenant,
            execution_key=f"kind-probe-effect-{label}-{uuid.uuid4().hex}",
            turn_id=str(uuid.uuid4()),
            session_id=f"kind-probe-session-{uuid.uuid4().hex}",
            inbound_id=uuid.uuid4(),
            trace_id=f"kind-probe-trace-{uuid.uuid4().hex}",
        )
        async with self.pool.acquire() as connection, connection.transaction():
            await connection.execute(
                "SELECT set_config('app.tenant_id', $1, true)", fixture.tenant_id
            )
            await connection.execute(
                """
                INSERT INTO inbound_messages (
                    tenant_id,inbound_id,binding_id,app_id,config_version,
                    channel,account_id,external_message_id,principal_id,session_id,
                    request_id,trace_id,envelope_json,status
                ) VALUES (
                    $1,$2,$3,'kind-probe-app',1,'wecom_ai_bot',$4,$5,$6,$7,$8,$9,
                    '{}'::jsonb,'processing'
                )
                """,
                fixture.tenant_id,
                fixture.inbound_id,
                self.primary_binding,
                "kind-probe-wecom-account",
                f"kind-probe-inbound-{uuid.uuid4().hex}",
                f"kind-probe-principal-{uuid.uuid4().hex}",
                fixture.session_id,
                f"kind-probe-request-{uuid.uuid4().hex}",
                fixture.trace_id,
            )
            await connection.execute(
                """
                INSERT INTO sessions (
                    tenant_id,session_id,app_id,principal_id,
                    lease_owner,lease_epoch,lease_expires_at
                ) VALUES (
                    $1,$2,'kind-probe-app',$3,$4,1,
                    clock_timestamp()+interval '10 minutes'
                )
                """,
                fixture.tenant_id,
                fixture.session_id,
                f"kind-probe-principal-{uuid.uuid4().hex}",
                OWNER_ID,
            )
            # The principal is not part of the execution fence; the session
            # row only needs a stable value for the production ledger checks.
            await connection.execute(
                """
                INSERT INTO session_turns (
                    tenant_id,turn_id,session_id,inbound_id,config_version,
                    status,fencing_token
                ) VALUES ($1,$2,$3,$4,1,'processing',1)
                """,
                fixture.tenant_id,
                fixture.turn_id,
                fixture.session_id,
                fixture.inbound_id,
            )
        self.execution_fixtures.append(fixture)
        return fixture

    async def cleanup(self, cleanup_dsn: str) -> None:
        """Remove only this probe's rows using the migration authority.

        The evidence trigger deliberately rejects deletes by worker/runtime
        roles.  Consequently a live run needs the migration DSN for cleanup;
        this is a safety feature, not a reason to weaken append-only evidence.
        """

        pool = await _create_pool(cleanup_dsn, application_name="kind-runtime-probe-cleanup")
        try:
            async with pool.acquire() as connection, connection.transaction():
                tenants = list(self.tenants)
                await connection.execute(
                    "DELETE FROM tool_execution_reconciliations WHERE tenant_id = ANY($1::text[])",
                    tenants,
                )
                await connection.execute(
                    "DELETE FROM tool_executions WHERE tenant_id = ANY($1::text[])", tenants
                )
                await connection.execute(
                    "DELETE FROM turn_intents WHERE tenant_id = ANY($1::text[])", tenants
                )
                await connection.execute(
                    "DELETE FROM session_events WHERE tenant_id = ANY($1::text[])", tenants
                )
                await connection.execute(
                    "DELETE FROM session_summaries WHERE tenant_id = ANY($1::text[])", tenants
                )
                await connection.execute(
                    "DELETE FROM session_mailbox_items WHERE tenant_id = ANY($1::text[])",
                    tenants,
                )
                await connection.execute(
                    "DELETE FROM session_mailboxes WHERE tenant_id = ANY($1::text[])", tenants
                )
                await connection.execute(
                    "DELETE FROM session_turns WHERE tenant_id = ANY($1::text[])", tenants
                )
                await connection.execute(
                    "DELETE FROM outbox_events WHERE tenant_id = ANY($1::text[])", tenants
                )
                await connection.execute(
                    "DELETE FROM audit_logs WHERE tenant_id = ANY($1::text[])", tenants
                )
                await connection.execute(
                    "DELETE FROM channel_identities WHERE tenant_id = ANY($1::text[])", tenants
                )
                await connection.execute(
                    "DELETE FROM inbound_messages WHERE tenant_id = ANY($1::text[])", tenants
                )
                await connection.execute(
                    "DELETE FROM sessions WHERE tenant_id = ANY($1::text[])", tenants
                )
                await connection.execute(
                    "DELETE FROM channel_bindings WHERE tenant_id = ANY($1::text[])", tenants
                )
                await connection.execute(
                    "DELETE FROM config_revisions WHERE tenant_id = ANY($1::text[])", tenants
                )
                await connection.execute(
                    "DELETE FROM storage_profiles WHERE tenant_id = ANY($1::text[])", tenants
                )
                await connection.execute(
                    "DELETE FROM agent_apps WHERE tenant_id = ANY($1::text[])", tenants
                )
                await connection.execute(
                    "DELETE FROM tenants WHERE tenant_id = ANY($1::text[])", tenants
                )
        finally:
            await pool.close()


async def _create_pool(dsn: str, *, application_name: str) -> asyncpg.Pool:
    return await asyncpg.create_pool(
        _normalize_dsn(dsn),
        min_size=1,
        max_size=16,
        command_timeout=30,
        server_settings={"application_name": application_name},
    )


def _request_json_sync(
    url: str,
    *,
    method: str = "GET",
    body: Mapping[str, object] | None = None,
    timeout: float,
) -> tuple[int, Mapping[str, object]]:
    """Bounded, keyless HTTP exchange used by the provider/IM adapters."""

    if not _valid_url(url):
        raise ValueError("provider endpoint URL is invalid")
    data = (
        json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if body is not None
        else None
    )
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
        # Older disposable kind images recognized the timeout fault as a
        # header; newer ones read the same marker from JSON.  Keep both forms
        # for the known local fixture without sending a test-only header to a
        # non-kind provider endpoint.
        if (
            body is not None
            and body.get("simulate_timeout") is True
            and urlsplit(url).hostname == "kind-fake-provider"
        ):
            headers["X-Simulate-Timeout"] = "true"
    request = Request(url, data=data, headers=headers, method=method)  # noqa: S310
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL is operator supplied
        raw = response.read(128 * 1024)
        parsed = json.loads(raw.decode("utf-8"))
        if not isinstance(parsed, Mapping):
            raise ValueError("provider response must be a JSON object")
        return int(response.status), parsed


class ProviderHTTPClient:
    """One-shot provider execution plus a read-only status/metrics client."""

    def __init__(
        self, config: RuntimeProbeConfig, *, request: _JsonRequester | None = None
    ) -> None:
        self.config = config
        self.request = request or _request_json_sync
        self.execute_calls = 0
        self.status_queries = 0

    def _status_url(self, intent: ExecutionProbeIntent) -> str:
        template = self.config.provider_status_url
        encoded = quote(intent.execution_key, safe="")
        if "{execution_key}" in template:
            return template.replace("{execution_key}", encoded)
        parsed = urlsplit(template)
        # The kind gate passes the provider's collection endpoint directly
        # (``/v1/effects``).  Preserve compatibility with provider adapters
        # that expose a query endpoint by using query parameters everywhere
        # else, while addressing the collection endpoint as a keyed GET.
        if parsed.path.rstrip("/").endswith("/v1/effects"):
            return urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path.rstrip("/") + "/" + encoded,
                    parsed.query,
                    parsed.fragment,
                )
            )
        query = dict(_query_pairs(parsed.query))
        query.update(
            {
                "tenant_id": intent.tenant_id,
                "execution_key": intent.execution_key,
                "attempt": str(intent.attempt),
            }
        )
        return urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment)
        )

    async def execute_once(self, intent: ExecutionProbeIntent) -> int | None:
        self.execute_calls += 1
        body = {
            "tenant_id": intent.tenant_id,
            "execution_key": intent.execution_key,
            # The kind provider and production adapters both key the external
            # request by the same durable execution identity.  Keeping the
            # explicit ``effect_key`` field makes the one POST interoperable
            # with providers that do not know the internal field name.
            "effect_key": intent.execution_key,
            "attempt": intent.attempt,
            # The acceptance provider commits the effect and then deliberately
            # drops this response.  A real provider adapter may implement the
            # same fault with a transport timeout; this flag is only for the
            # disposable kind endpoint and is never retried by this client.
            "simulate_timeout": True,
        }
        try:
            status, _payload = await asyncio.to_thread(
                self.request,
                self.config.provider_execute_url,
                method="POST",
                body=body,
                timeout=self.config.timeout_seconds,
            )
            return status
        except (HTTPError, URLError, TimeoutError, OSError):
            # The POST is intentionally not retried.  The ledger is marked
            # ambiguous and only the GET probe can establish a new fact.
            return None

    async def probe(
        self,
        intent: ExecutionProbeIntent,
        _receipt: object,
    ) -> Mapping[str, object]:
        self.status_queries += 1
        try:
            _status, payload = await asyncio.to_thread(
                self.request,
                self._status_url(intent),
                method="GET",
                timeout=self.config.timeout_seconds,
            )
        except HTTPError as exc:
            if exc.code == 404:
                return {
                    "outcome": ReconciliationOutcome.UNKNOWN.value,
                    "evidence_summary": "provider_status_absent",
                }
            return {
                "outcome": ReconciliationOutcome.UNKNOWN.value,
                "evidence_summary": "provider_status_unavailable",
            }
        except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
            return {
                "outcome": ReconciliationOutcome.UNKNOWN.value,
                "evidence_summary": "provider_status_unavailable",
            }
        raw_status = payload.get("status")
        status = raw_status.strip().lower() if isinstance(raw_status, str) else ""
        if status in {"applied", "accepted", "succeeded", "complete", "completed"}:
            outcome = ReconciliationOutcome.APPLIED
            summary = "provider_status_applied"
        elif status in {"not_applied", "not-applied", "failed", "rejected"}:
            outcome = ReconciliationOutcome.NOT_APPLIED
            summary = "provider_status_not_applied"
        else:
            outcome = ReconciliationOutcome.UNKNOWN
            summary = "provider_status_unknown"
        return {"outcome": outcome.value, "evidence_summary": summary}

    async def metrics(self) -> Mapping[str, object]:
        _status, payload = await asyncio.to_thread(
            self.request,
            self.config.provider_metrics_url,
            method="GET",
            timeout=self.config.timeout_seconds,
        )
        return payload


def _query_pairs(query: str) -> list[tuple[str, str]]:
    if not query:
        return []
    pairs: list[tuple[str, str]] = []
    for part in query.split("&"):
        item = part.split("=", 1)
        if len(item) == 2:
            pairs.append((item[0], item[1]))
    return pairs


def _provider_call_count(payload: Mapping[str, object]) -> int | None:
    for key in ("provider_calls", "calls", "execution_count"):
        value = payload.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


async def _prepare_ambiguous(
    ledger: PostgresExecutionLedger,
    fixture: ExecutionFixture,
) -> ExecutionProbeIntent:
    intent = fixture.intent()
    record = await ledger.begin(
        intent.execution_key,
        tenant_id=intent.tenant_id,
        turn_id=intent.turn_id,
        tool_name=intent.tool_name,
        risk=ToolRisk.NON_IDEMPOTENT,
        arguments_hash=intent.arguments_hash,
        owner_id=OWNER_ID,
        fencing_token=1,
    )
    if not record.fresh or record.status != ExecutionStatus.STARTED:
        raise RuntimeError("probe execution was not newly claimed")
    await ledger.finish(
        intent.execution_key,
        tenant_id=intent.tenant_id,
        status=ExecutionStatus.AMBIGUOUS,
        owner_id=OWNER_ID,
        fencing_token=1,
    )
    return intent


async def _run_reconciliation(
    fixtures: ProbeFixtures,
    fixture_pool: asyncpg.Pool,
    reconciler_pool: asyncpg.Pool,
    config: RuntimeProbeConfig,
) -> dict[str, object]:
    # Worker authority creates/finishes the ambiguous execution.  The
    # dedicated reconciler authority only claims and CASes it; using one pool
    # for both would hide a real ACK role/privilege wiring error.
    worker_ledger = PostgresExecutionLedger(fixture_pool)
    ledger = PostgresExecutionLedger(reconciler_pool)
    provider = ProviderHTTPClient(config)
    reconciler = ProviderReconciler(provider.probe, reconciler_id=RECONCILER_ID)
    coordinator = ToolExecutionReconciliationCoordinator(ledger, reconciler)
    checks: dict[str, object] = {}
    reasons: list[str] = []

    applied_fixture = await fixtures.add_execution("applied")
    applied_intent = await _prepare_ambiguous(worker_ledger, applied_fixture)
    before_metrics = await provider.metrics()
    before_calls = _provider_call_count(before_metrics)
    execute_status = await provider.execute_once(applied_intent)
    if execute_status is not None and execute_status < 400:
        raise RuntimeError("provider response-loss fault was not activated")
    # Model a lost response: the external request was made once, but the
    # worker cannot infer its result and must persist ambiguity.
    claims = await coordinator.reconcile_pending(
        tenant_id=fixtures.primary_tenant,
        owner_id=RECONCILER_ID,
        limit=20,
        lease_seconds=30,
    )
    applied_record = next(
        (record for record in claims if record.execution_key == applied_intent.execution_key),
        None,
    )
    if applied_record is None or applied_record.status != ExecutionStatus.SUCCEEDED:
        raise RuntimeError("applied provider status did not converge to succeeded")
    applied_evidence = await ledger.list_reconciliation_evidence(
        tenant_id=fixtures.primary_tenant,
        execution_key=applied_intent.execution_key,
        attempt=1,
    )
    if len(applied_evidence) != 1 or applied_evidence[0].outcome != ReconciliationOutcome.APPLIED:
        raise RuntimeError("applied reconciliation evidence was not persisted exactly once")
    after_metrics = await provider.metrics()
    after_calls = _provider_call_count(after_metrics)
    provider_delta = (
        after_calls - before_calls if before_calls is not None and after_calls is not None else None
    )
    checks["applied_query_only"] = {
        "status": "pass",
        "execution_status": applied_record.status.value,
        "evidence_rows": len(applied_evidence),
        "provider_execution_delta": provider_delta,
        "provider_response_status": execute_status,
        "provider_execute_calls": provider.execute_calls,
        "status_queries": provider.status_queries,
    }
    if provider.execute_calls != 1 or provider_delta != 1 or provider.status_queries < 1:
        reasons.append(
            "provider execution was not exactly one call with a query-only reconciliation"
        )

    unknown_fixture = await fixtures.add_execution("unknown")
    unknown_intent = await _prepare_ambiguous(worker_ledger, unknown_fixture)
    unknown_records = await coordinator.reconcile_pending(
        tenant_id=fixtures.primary_tenant,
        owner_id=RECONCILER_ID,
        limit=20,
        lease_seconds=30,
    )
    unknown_record = next(
        (
            record
            for record in unknown_records
            if record.execution_key == unknown_intent.execution_key
        ),
        None,
    )
    unknown_evidence = await ledger.list_reconciliation_evidence(
        tenant_id=fixtures.primary_tenant,
        execution_key=unknown_intent.execution_key,
        attempt=1,
    )
    if unknown_record is None or unknown_record.status != ExecutionStatus.UNKNOWN:
        raise RuntimeError("unknown provider status did not remain unknown")
    if len(unknown_evidence) != 1 or unknown_evidence[0].outcome != ReconciliationOutcome.UNKNOWN:
        raise RuntimeError("unknown reconciliation evidence was not persisted")
    duplicate = await ledger.reconcile(
        unknown_intent.execution_key,
        tenant_id=unknown_intent.tenant_id,
        expected_attempt=1,
        evidence=unknown_evidence[0],
    )
    if (
        duplicate.status != ExecutionStatus.UNKNOWN
        or len(
            await ledger.list_reconciliation_evidence(
                tenant_id=unknown_intent.tenant_id,
                execution_key=unknown_intent.execution_key,
                attempt=1,
            )
        )
        != 1
    ):
        raise RuntimeError("duplicate unknown evidence was not idempotent")
    no_replay = await worker_ledger.begin(
        unknown_intent.execution_key,
        tenant_id=unknown_intent.tenant_id,
        turn_id=unknown_intent.turn_id,
        tool_name=unknown_intent.tool_name,
        risk=ToolRisk.NON_IDEMPOTENT,
        arguments_hash=unknown_intent.arguments_hash,
        owner_id=OWNER_ID,
        fencing_token=1,
    )
    checks["unknown_blocks_replay"] = {
        "status": "pass"
        if not no_replay.fresh and no_replay.status == ExecutionStatus.UNKNOWN
        else "fail",
        "execution_status": no_replay.status.value,
        "automatic_replay": no_replay.fresh,
        "evidence_rows": len(unknown_evidence),
    }
    if no_replay.fresh or no_replay.status != ExecutionStatus.UNKNOWN:
        reasons.append("unknown provider outcome allowed an automatic replay")

    stale_evidence = ReconciliationEvidence(
        unknown_intent.execution_key,
        2,
        ReconciliationOutcome.UNKNOWN,
        evidence_summary="provider_status_unknown",
        trace_id=unknown_intent.trace_id,
        reconciler_id=RECONCILER_ID,
        tenant_id=unknown_intent.tenant_id,
    )
    stale_rejected = False
    try:
        await ledger.reconcile(
            unknown_intent.execution_key,
            tenant_id=unknown_intent.tenant_id,
            expected_attempt=2,
            evidence=stale_evidence,
        )
    except ReconciliationConflict:
        stale_rejected = True
    checks["stale_attempt_rejected"] = {"status": "pass" if stale_rejected else "fail"}
    if not stale_rejected:
        reasons.append("stale reconciliation attempt was accepted")

    cross_tenant_evidence = ReconciliationEvidence(
        applied_intent.execution_key,
        1,
        ReconciliationOutcome.APPLIED,
        evidence_summary="provider_status_applied",
        trace_id=applied_intent.trace_id,
        reconciler_id=RECONCILER_ID,
        tenant_id=fixtures.secondary_tenant,
    )
    cross_tenant_rejected = False
    try:
        await ledger.reconcile(
            applied_intent.execution_key,
            tenant_id=fixtures.primary_tenant,
            expected_attempt=1,
            evidence=cross_tenant_evidence,
        )
    except ReconciliationConflict:
        cross_tenant_rejected = True
    checks["cross_tenant_evidence_rejected"] = {
        "status": "pass" if cross_tenant_rejected else "fail"
    }
    if not cross_tenant_rejected:
        reasons.append("cross-tenant reconciliation evidence was accepted")

    cas_fixture = await fixtures.add_execution("cas")
    cas_intent = await _prepare_ambiguous(worker_ledger, cas_fixture)
    cas_claims = await ledger.claim_ambiguous(
        tenant_id=cas_intent.tenant_id,
        owner_id=RECONCILER_ID,
        limit=20,
        lease_seconds=30,
    )
    cas_claim = next(
        (claim for claim in cas_claims if claim.execution_key == cas_intent.execution_key), None
    )
    cas_rejected = False
    if cas_claim is not None:
        cas_evidence = ReconciliationEvidence(
            cas_intent.execution_key,
            cas_claim.attempt,
            ReconciliationOutcome.UNKNOWN,
            evidence_summary="provider_status_unknown",
            trace_id=cas_intent.trace_id,
            reconciler_id=RECONCILER_ID,
            tenant_id=cas_intent.tenant_id,
        )
        try:
            await ledger.reconcile(
                cas_intent.execution_key,
                tenant_id=cas_intent.tenant_id,
                expected_attempt=cas_claim.attempt,
                evidence=cas_evidence,
                claim_owner=cas_claim.owner_id,
                claim_epoch=cas_claim.claim_epoch + 1,
            )
        except ReconciliationConflict:
            cas_rejected = True
    checks["claim_cas_rejected"] = {"status": "pass" if cas_rejected else "fail"}
    if not cas_rejected:
        reasons.append("stale claim epoch was accepted")

    for check in checks.values():
        if isinstance(check, Mapping) and check.get("status") == "fail":
            reasons.append(str(check.get("reason", "reconciliation assertion failed")))
    return {
        "status": "pass"
        if not reasons
        and all(
            isinstance(item, Mapping) and item.get("status") == "pass" for item in checks.values()
        )
        else "fail",
        "checks": checks,
        "rejection_reasons": reasons,
        "tenant_sha256": _safe_hash(fixtures.primary_tenant),
        "provider_execute_calls": provider.execute_calls,
        "provider_status_queries": provider.status_queries,
    }


async def _count_im_rows(
    pool: asyncpg.Pool,
    tenant_id: str,
    external_message_id: str,
    session_id: str,
) -> dict[str, int]:
    async with pool.acquire() as connection, connection.transaction():
        await connection.execute("SELECT set_config('app.tenant_id', $1, true)", tenant_id)
        rows = {
            "inbound": await connection.fetchval(
                """
                SELECT count(*) FROM inbound_messages
                 WHERE tenant_id=$1 AND channel='wecom_ai_bot' AND account_id=$2
                   AND external_message_id=$3
                """,
                tenant_id,
                "kind-probe-wecom-account",
                external_message_id,
            ),
            "audit": await connection.fetchval(
                """
                SELECT count(*) FROM audit_logs
                 WHERE tenant_id=$1 AND idempotency_key=$2 AND decision='inbound_accepted'
                """,
                tenant_id,
                external_message_id,
            ),
            "outbox": await connection.fetchval(
                """
                SELECT count(*) FROM outbox_events
                 WHERE tenant_id=$1 AND event_type='session.ready.v2'
                   AND payload_json->>'inbound_id' IS NULL
                   AND aggregate_id=$2
                """,
                tenant_id,
                session_id,
            ),
            "mailbox": await connection.fetchval(
                """
                SELECT count(*) FROM session_mailboxes
                 WHERE tenant_id=$1 AND session_id=$2
                """,
                tenant_id,
                session_id,
            ),
        }
    return {key: int(value or 0) for key, value in rows.items()}


async def _run_im_idempotency(
    fixtures: ProbeFixtures,
    runtime_pool: asyncpg.Pool,
    config: RuntimeProbeConfig,
) -> dict[str, object]:
    repository = PostgresRuntimeRepository(runtime_pool)
    runtime = TenantRuntime(
        repository,
        routing_key=ROUTING_KEY,
        scheduler_version=SchedulerVersion.V2,
    )
    message_id = f"kind-probe-im-{uuid.uuid4().hex}"
    envelope = InboundEnvelope(
        channel=Channel.WECOM_AI_BOT,
        account_id="kind-probe-wecom-account",
        external_message_id=message_id,
        external_user_id="kind-probe-user",
        conversation_kind=ConversationKind.DIRECT,
        payload_kind=PayloadKind.TEXT,
        text="kind runtime probe",
    )
    primary_results = await asyncio.gather(
        *(
            runtime.accept(fixtures.primary_binding, envelope)
            for _ in range(config.duplicate_count)
        ),
        return_exceptions=True,
    )
    errors = [item for item in primary_results if isinstance(item, BaseException)]
    accepted = [
        item
        for item in primary_results
        if not isinstance(item, BaseException) and not item.duplicate
    ]
    duplicates = [
        item for item in primary_results if not isinstance(item, BaseException) and item.duplicate
    ]
    if errors or len(accepted) != 1 or len(duplicates) != config.duplicate_count - 1:
        raise RuntimeError("concurrent duplicate IM callbacks did not collapse to one acceptance")
    primary_acceptance = cast(Any, accepted[0])
    inbound_ids = {
        item.inbound_id for item in primary_results if not isinstance(item, BaseException)
    }
    session_ids = {
        item.context.session_id for item in primary_results if not isinstance(item, BaseException)
    }
    primary_rows = await _count_im_rows(
        fixtures.pool,
        fixtures.primary_tenant,
        message_id,
        primary_acceptance.context.session_id,
    )
    secondary = await runtime.accept(fixtures.secondary_binding, envelope)
    secondary_rows = await _count_im_rows(
        fixtures.pool,
        fixtures.secondary_tenant,
        message_id,
        secondary.context.session_id,
    )
    expected_rows = {"inbound": 1, "audit": 1, "outbox": 1, "mailbox": 1}
    passed = (
        len(inbound_ids) == 1
        and len(session_ids) == 1
        and all(primary_rows[key] == value for key, value in expected_rows.items())
        and not secondary.duplicate
        and all(secondary_rows[key] == value for key, value in expected_rows.items())
        and primary_acceptance.context.session_id != secondary.context.session_id
    )
    return {
        "status": "pass" if passed else "fail",
        "channel": Channel.WECOM_AI_BOT.value,
        "duplicate_callbacks": config.duplicate_count,
        "first_acceptances": len(accepted),
        "duplicate_results": len(duplicates),
        "primary_inbound_ids": len(inbound_ids),
        "primary_session_ids": len(session_ids),
        "primary_rows": primary_rows,
        "secondary_same_message_accepted": not secondary.duplicate,
        "secondary_rows": secondary_rows,
        "tenant_sha256": _safe_hash(fixtures.primary_tenant),
        "secondary_tenant_sha256": _safe_hash(fixtures.secondary_tenant),
        "rejection_reasons": [] if passed else ["PostgreSQL IM idempotency assertions failed"],
    }


def _git_sha() -> str | None:
    executable = shutil.which("git")
    if executable is None:
        return None
    try:
        result = subprocess.run(  # noqa: S603 - executable is resolved from PATH
            [executable, "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and len(value) == 40 else None


def _source_fingerprint() -> dict[str, object]:
    try:
        lineage = source_fingerprint(ROOT)
        return {key: lineage[key] for key in ("algorithm", "status", "value") if key in lineage}
    except Exception as error:  # pragma: no cover - defensive report boundary
        return {
            "algorithm": "sha256",
            "status": "unavailable",
            "reason": type(error).__name__,
        }


def _not_run_report(command: str, missing: Sequence[str]) -> dict[str, object]:
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": PROBE_SCHEMA_VERSION,
        "probe": "kind_runtime_probe",
        "scenario": PROBE_SCENARIO,
        "assertion": PROBE_ASSERTION,
        "command": command,
        "status": "not_run",
        "production_gate": "not_run",
        "started_at": now,
        "ended_at": now,
        "git_sha": _git_sha(),
        "source_fingerprint": _source_fingerprint(),
        "checks": {},
        "missing_configuration": list(missing),
        "rejection_reasons": ["required live probe configuration is missing"],
    }


async def run_probe(
    config: RuntimeProbeConfig,
    *,
    command: str = "all",
) -> dict[str, object]:
    """Run one or both production repository checks and return keyless JSON."""

    missing = config.missing_for(command)
    if missing:
        return _not_run_report(command, missing)
    started = datetime.now(UTC)
    fixture_pool: asyncpg.Pool | None = None
    runtime_pool: asyncpg.Pool | None = None
    reconciler_pool: asyncpg.Pool | None = None
    fixtures: ProbeFixtures | None = None
    checks: dict[str, object] = {}
    errors: list[str] = []
    cleanup_status: dict[str, object]
    try:
        fixture_pool = await _create_pool(
            config.fixture_dsn, application_name="kind-runtime-probe-fixture"
        )
        fixtures = ProbeFixtures(fixture_pool)
        await fixtures.seed()
        if command in {"all", "reconcile"}:
            reconciler_pool = await _create_pool(
                config.reconciler_dsn,
                application_name="kind-runtime-probe-reconciler",
            )
            try:
                checks["tool_reconciliation"] = await _run_reconciliation(
                    fixtures, fixture_pool, reconciler_pool, config
                )
            except Exception as exc:  # keep report keyless and actionable
                checks["tool_reconciliation"] = {
                    "status": "fail",
                    "rejection_reasons": [_safe_exception(exc)],
                }
                errors.append("tool_reconciliation")
        if command in {"all", "im"}:
            runtime_pool = await _create_pool(
                config.runtime_dsn,
                application_name="kind-runtime-probe-runtime",
            )
            try:
                checks["im_idempotency"] = await _run_im_idempotency(fixtures, runtime_pool, config)
            except Exception as exc:
                checks["im_idempotency"] = {
                    "status": "fail",
                    "rejection_reasons": [_safe_exception(exc)],
                }
                errors.append("im_idempotency")
    except Exception as exc:
        errors.append(_safe_exception(exc))
        checks["postgres_connection"] = {
            "status": "fail",
            "rejection_reasons": [_safe_exception(exc)],
        }
    finally:
        if fixtures is not None:
            if config.keep_fixtures:
                cleanup_status = {"status": "not_run", "reason": "TRPC_KIND_PROBE_KEEP_FIXTURES"}
            elif config.cleanup_dsn:
                try:
                    await fixtures.cleanup(config.cleanup_dsn)
                    cleanup_status = {"status": "pass"}
                except Exception as exc:
                    cleanup_status = {
                        "status": "fail",
                        "rejection_reasons": [_safe_exception(exc)],
                    }
                    errors.append("cleanup")
            else:
                cleanup_status = {
                    "status": "not_run",
                    "reason": (
                        "TRPC_KIND_PROBE_CLEANUP_DSN is required for append-only evidence cleanup"
                    ),
                }
        else:
            cleanup_status = {"status": "not_run", "reason": "fixture seed did not complete"}
        for pool in (runtime_pool, reconciler_pool, fixture_pool):
            if pool is not None:
                await pool.close()
    ended = datetime.now(UTC)
    statuses = [value.get("status") for value in checks.values() if isinstance(value, Mapping)]
    functional_pass = bool(statuses) and not errors and all(value == "pass" for value in statuses)
    reconciliation = checks.get("tool_reconciliation")
    provider_execute_calls: object = None
    provider_status_queries: object = None
    if isinstance(reconciliation, Mapping):
        provider_execute_calls = reconciliation.get("provider_execute_calls")
        provider_status_queries = reconciliation.get("provider_status_queries")
    return {
        "schema_version": PROBE_SCHEMA_VERSION,
        "probe": "kind_runtime_probe",
        "scenario": PROBE_SCENARIO,
        "assertion": PROBE_ASSERTION,
        "command": command,
        "status": "pass" if functional_pass else "fail",
        "production_gate": "not_run",
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "ended_at": ended.isoformat().replace("+00:00", "Z"),
        "git_sha": _git_sha(),
        "source_fingerprint": _source_fingerprint(),
        "provider_execute_calls": provider_execute_calls,
        "provider_status_queries": provider_status_queries,
        "checks": checks,
        "cleanup": cleanup_status,
        "rejection_reasons": errors,
        "credentials": {
            "fixture_dsn": bool(config.fixture_dsn),
            "runtime_dsn": bool(config.runtime_dsn),
            "reconciler_dsn": bool(config.reconciler_dsn),
            "cleanup_dsn": bool(config.cleanup_dsn),
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=("all", "reconcile", "im"), default="all")
    parser.add_argument("--json", action="store_true", help="print JSON to stdout")
    parser.add_argument("--report", type=Path, default=None, help="write the keyless JSON report")
    parser.add_argument("--keep-fixtures", action="store_true", help="do not attempt cleanup")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config = RuntimeProbeConfig.from_env()
    if args.keep_fixtures:
        config = replace(config, keep_fixtures=True)
    report = asyncio.run(run_probe(config, command=args.command))
    if args.report is not None:
        atomic_write_json(args.report, report)
    # Keep stdout machine-readable for kubectl exec/driver wrappers.  The
    # optional flag is retained for backwards-compatible command lines; a
    # report path never suppresses the single JSON line.
    del args.json
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report.get("status") == "pass" else 2 if report.get("status") == "not_run" else 1


if __name__ == "__main__":
    raise SystemExit(main())
