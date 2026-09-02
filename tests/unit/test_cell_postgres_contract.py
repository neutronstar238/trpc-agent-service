"""Static and boundary contracts for the optional PostgreSQL Cell adapters."""

from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trpc_service.cell.capsule import (
    AgentCapsule,
    CapsuleMetadata,
    CapsuleSignatureError,
    CapsuleSpec,
)
from trpc_service.cell.effects import EffectKeyConflict
from trpc_service.cell.events import NamespaceViolation
from trpc_service.cell.intents import IntentRisk, PolicyDecision, ToolIntent
from trpc_service.cell.postgres import (
    PostgresApprovalLedger,
    PostgresEffectLedger,
    PostgresEventStore,
)
from trpc_service.database_contract import (
    WORKER_CELL_FUNCTIONS,
    WORKER_FORBIDDEN_CELL_PRIVILEGES,
    WORKER_TABLE_PRIVILEGES,
)


class PoolDouble:
    def acquire(self) -> None:
        raise AssertionError("the boundary tests must not open a database connection")


class AsyncContextDouble:
    def __init__(self, value: object) -> None:
        self.value = value

    async def __aenter__(self) -> object:
        return self.value

    async def __aexit__(self, *args: object) -> None:
        del args


class ConnectionDouble:
    def __init__(
        self,
        *,
        fetchval: object = None,
        fetchrows: list[object] | None = None,
    ) -> None:
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.fetchval_result = fetchval
        self.fetchrows = list(fetchrows or [])

    def transaction(self) -> AsyncContextDouble:
        return AsyncContextDouble(self)

    async def execute(self, query: str, *args: object) -> str:
        self.calls.append((query, args))
        return "OK"

    async def fetchval(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        return self.fetchval_result

    async def fetchrow(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        return self.fetchrows.pop(0) if self.fetchrows else None


class RecordingPool:
    def __init__(self, connection: ConnectionDouble) -> None:
        self.connection = connection

    def acquire(self) -> AsyncContextDouble:
        return AsyncContextDouble(self.connection)


def migration_source() -> str:
    return (
        Path(__file__).parents[2]
        / "migrations"
        / "versions"
        / "0018_cell_namespace_and_reservations.py"
    ).read_text(encoding="utf-8")


def branch_head_lock_migration_source() -> str:
    return (
        Path(__file__).parents[2] / "migrations" / "versions" / "0019_cell_branch_head_lock.py"
    ).read_text(encoding="utf-8")


def performance_cell_cleanup_migration_source() -> str:
    return (
        Path(__file__).parents[2] / "migrations" / "versions" / "0020_performance_cell_cleanup.py"
    ).read_text(encoding="utf-8")


def performance_reservation_cleanup_migration_source() -> str:
    return (
        Path(__file__).parents[2]
        / "migrations"
        / "versions"
        / "0021_performance_reservation_cleanup.py"
    ).read_text(encoding="utf-8")


def node_generation_migration_source() -> str:
    return (
        Path(__file__).parents[2]
        / "migrations"
        / "versions"
        / "0022_cell_node_snapshot_generation.py"
    ).read_text(encoding="utf-8")


def native_intent() -> ToolIntent:
    return ToolIntent(
        tenant_id="tenant-a",
        app_id="app-a",
        cell_id="cell-a",
        session_id="session-a",
        capsule_digest="sha256:" + "a" * 64,
        branch_id="main",
        intent_id="intent-a",
        tool_name="ticket.create",
        arguments={"subject": "safe"},
        policy_decision=PolicyDecision.ALLOW,
        risk=IntentRisk.LOW,
    )


@pytest.mark.asyncio
async def test_effect_reads_cannot_run_without_a_tenant_scope() -> None:
    unbound = PostgresEffectLedger(PoolDouble())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="tenant_id is required"):
        await unbound.get("effect-key")

    bound = PostgresEffectLedger(PoolDouble(), tenant_id="tenant-a")  # type: ignore[arg-type]
    assert bound._assert_tenant("tenant-a") == "tenant-a"
    with pytest.raises(NamespaceViolation, match="tenant"):
        bound._assert_tenant("tenant-b")


@pytest.mark.asyncio
async def test_postgres_capsule_registration_rejects_unsigned_or_legacy_assets() -> None:
    store = PostgresEventStore(PoolDouble())  # type: ignore[arg-type]
    digest = "sha256:" + "a" * 64
    capsule = AgentCapsule(
        metadata=CapsuleMetadata(tenant_id="tenant-a", name="agent-a"),
        spec=CapsuleSpec(
            graph=digest,
            prompt=digest,
            modelPolicy=digest,
            toolManifest=digest,
            governancePolicy=digest,
            storageProfile=digest,
        ),
    ).with_digest()
    with pytest.raises(ValueError, match="signature"):
        await store.ensure_capsule(capsule)

    legacy = capsule.model_copy(
        update={"spec": capsule.spec.model_copy(update={"prompt": "legacy-bare-ref"})}
    ).sign(b"c" * 32, key_id="test-key")
    with pytest.raises(ValueError, match="logical asset reference"):
        await store.ensure_capsule(legacy)

    signing_key = Ed25519PrivateKey.generate()
    signed = capsule.sign(signing_key, key_id="control-key")
    with pytest.raises(CapsuleSignatureError, match="trusted signing keys"):
        await store.ensure_capsule(signed)
    with pytest.raises(CapsuleSignatureError, match="not trusted"):
        await store.ensure_capsule(
            signed,
            trusted_keys={"another-key": signing_key.public_key()},
        )


@pytest.mark.asyncio
async def test_postgres_capsule_admission_verifies_deployment_and_separates_runtime() -> None:
    digest = "sha256:" + "a" * 64
    signing_key = Ed25519PrivateKey.generate()
    capsule = AgentCapsule(
        metadata=CapsuleMetadata(tenant_id="tenant-a", name="agent-a"),
        spec=CapsuleSpec(
            graph=digest,
            prompt=digest,
            modelPolicy=digest,
            toolManifest=digest,
            governancePolicy=digest,
            storageProfile=digest,
        ),
    ).sign(signing_key, key_id="control-key")
    connection = ConnectionDouble()
    store = PostgresEventStore(RecordingPool(connection))  # type: ignore[arg-type]

    stored_digest = await store.ensure_capsule(
        capsule,
        trusted_keys={"control-key": signing_key.public_key()},
    )
    assert stored_digest == capsule.digest
    assert "ensure_agent_capsule" in connection.calls[-1][0]

    await store.ensure_capsule(
        "tenant-a",
        capsule,
        trust_class="runtime_projection",
    )
    assert "ensure_runtime_projection_capsule" in connection.calls[-1][0]
    assert connection.calls[0][1] == ("tenant-a",)

    with pytest.raises(NamespaceViolation, match="tenant"):
        await store.ensure_capsule("tenant-b", capsule, trust_class="runtime_projection")
    with pytest.raises(ValueError, match="trust_class"):
        await store.ensure_capsule(capsule, trust_class="unknown")  # type: ignore[arg-type]


def test_pg_event_append_keeps_parent_causation_in_the_visible_lineage() -> None:
    source = inspect.getsource(PostgresEventStore.append)
    assert "visible_event_ids" in source
    assert "await self._read_lineage(connection, address)" in source
    assert "causation event" in source
    assert "session_lease_owner" in source
    assert "session_fencing_token" in source
    assert "lease_expires_at" in source
    assert "app.cell_branch_lease_expires_at" in source
    assert "self._lock_branch_head(" in source
    lock_source = inspect.getsource(PostgresEventStore._lock_branch_head)
    assert "public.lock_cell_branch_head($1, $2, $3, $4, $5, $6)" in lock_source
    fence_source = inspect.getsource(PostgresEventStore._assert_session_fence)
    assert "FROM public.sessions" in fence_source
    assert "session lease is stale" in fence_source
    assert "FOR UPDATE" in fence_source
    lineage_source = inspect.getsource(PostgresEventStore._read_lineage)
    assert "lineage contains a cycle" in lineage_source
    assert "maximum depth" in lineage_source

    reconcile_source = inspect.getsource(PostgresEventStore.find_unprojected_terminal_effects)
    for namespace_column in (
        "projected.app_id = intent.app_id",
        "projected.cell_id = intent.cell_id",
        "projected.session_id = intent.session_id",
        "projected.capsule_digest = intent.capsule_digest",
        "projected.branch_id = intent.branch_id",
    ):
        assert namespace_column in reconcile_source


def test_migration_closes_namespace_and_keeps_receipts_content_free() -> None:
    source = migration_source()
    assert "0018_cell_namespace_reservations" in source
    assert "cell_events_head_advance" in source
    assert "cell_effect_ledger_intent_fk" in source
    assert "cell_effect_receipts_ledger_fk" in source
    assert "ck_agent_cell_parent_not_self" in source
    assert "result_json" not in source
    assert "GRANT EXECUTE ON FUNCTION ensure_runtime_projection_capsule" in source
    assert ") TO trpc_worker" in source
    assert "REVOKE EXECUTE ON FUNCTION ensure_agent_capsule" in source
    assert ") FROM trpc_worker" in source
    assert ") FROM trpc_runtime" in source
    assert "runtime projection capsule cannot authorize placement" in source
    assert "capsule envelope does not match its registry identity" in source
    assert "capsule signature envelope is required and must match" in source
    assert "p_expected_lease_epoch bigint" in source
    assert "current_reservation.lease_epoch <> p_expected_lease_epoch" in source
    assert "DEFAULT 'runtime_projection'" in source
    assert "ALTER COLUMN trust_class DROP DEFAULT" in source
    assert "placement changed concurrently; retry reservation" in source
    assert "placement lease duration must be positive" in source
    assert "REVOKE ALL ON agent_capsules, agent_cells, cell_events" in source
    assert "GRANT SELECT, INSERT ON cell_events TO trpc_worker" in source
    assert "GRANT EXECUTE ON FUNCTION issue_cell_approval_nonce" in source
    assert "TO trpc_cell_executor" in source
    assert "NOT isfinite(p_expires_at)" in source
    assert "jsonb_typeof(p_decision->'cell_id')" in source
    assert "jsonb_typeof(p_decision->'node_id')" in source
    assert "winner := p_decision->'candidates'->0" in source
    assert "jsonb_array_elements(p_decision->'candidates')" in source
    assert "ALTER TABLE cell_placement_reservations ENABLE ROW LEVEL SECURITY" in source
    assert "ALTER TABLE cell_placement_reservations FORCE ROW LEVEL SECURITY" not in source
    assert "expired reservations from every tenant" in source
    assert "GRANT SELECT, INSERT, UPDATE ON cell_effect_ledger TO trpc_cell_executor" in source
    assert "GRANT SELECT, INSERT ON cell_effect_receipts TO trpc_cell_executor" in source
    assert "trpc_cell_executor must be LOGIN NOSUPERUSER NOINHERIT NOBYPASSRLS" in source
    assert "REVOKE ALL ON agent_capsules, agent_cells, cell_events," in source
    assert (
        "cell_approval_nonces, cell_node_capacity\n                    FROM trpc_cell_executor"
        in source
    )
    assert "FROM pg_auth_members AS membership" in source
    assert "rolinherit IS DISTINCT FROM FALSE" in source
    assert "rolcanlogin IS DISTINCT FROM TRUE" in source
    assert "must not inherit any role membership" in source
    assert source.count("SET search_path = pg_catalog, public, pg_temp") >= 10
    assert "SET search_path = pg_catalog, public\n" not in source

    upgrade = source[: source.index("def downgrade()")]
    assert "session_user = 'trpc_worker'" in upgrade
    assert "app.cell_session_lease_owner" in upgrade
    assert "app.cell_session_fencing_token" in upgrade
    assert "app.cell_branch_lease_owner" in upgrade
    assert "app.cell_branch_fencing_token" in upgrade
    assert "app.cell_branch_lease_expires_at" in upgrade
    assert "branch_lease_expires_at <= clock_timestamp()" in upgrade
    assert "head.lease_epoch > branch_fencing_token" in upgrade
    assert "head.lease_expires_at > clock_timestamp()" in upgrade
    assert "NULL/0/NULL head is the explicit branch" in upgrade
    assert "branch fence requires a live session fence" in upgrade
    assert "cell event committed-turn proof is invalid" in upgrade
    assert "FROM public.session_turns AS turn" in upgrade
    assert "evidence.event_type = 'reply.prepared'" in upgrade
    assert "GRANT SELECT, INSERT ON agent_cells TO trpc_worker" in upgrade
    assert "GRANT SELECT, INSERT ON cell_branch_heads TO trpc_worker" in upgrade
    assert "GRANT SELECT, INSERT, UPDATE ON agent_cells TO trpc_worker" not in upgrade
    assert "GRANT SELECT, INSERT, UPDATE ON cell_branch_heads TO trpc_worker" not in upgrade

    downgrade = source[source.index("def downgrade()") :]
    for index_name in (
        "ix_cell_events_full_stream",
        "ix_cell_tool_intents_stream",
        "ix_cell_effect_ledger_stream",
    ):
        assert f"DROP INDEX IF EXISTS {index_name}" in downgrade
    assert downgrade.index("DROP INDEX IF EXISTS ix_cell_events_full_stream") < downgrade.index(
        "DROP COLUMN IF EXISTS app_id"
    )
    assert "0018 downgrade refused: agent_cells namespace collision would lose data" in downgrade
    assert "0018 downgrade refused: cell_events namespace collision would lose data" in downgrade
    assert "0018 downgrade refused: deployment Capsule trust would be lost" in downgrade
    for constraint_name in (
        "cell_tool_intents_tenant_id_cell_id_branch_id_sequence_fkey",
        "cell_effect_ledger_tenant_id_intent_id_fkey",
        "cell_effect_receipts_tenant_id_intent_id_fkey",
        "cell_effect_receipts_tenant_id_effect_key_fkey",
    ):
        assert f"ADD CONSTRAINT {constraint_name}" in downgrade
    assert "$restore_legacy_grants$" in downgrade
    assert "FROM trpc_cell_executor" in downgrade


def test_worker_startup_contract_matches_cell_migration_minimum_privileges() -> None:
    assert "public.lock_cell_branch_head(text,text,text,text,text,text)" in WORKER_CELL_FUNCTIONS
    assert WORKER_TABLE_PRIVILEGES["agent_capsules"] == "SELECT"
    assert WORKER_TABLE_PRIVILEGES["agent_cells"] == "SELECT,INSERT"
    assert WORKER_TABLE_PRIVILEGES["cell_events"] == "SELECT,INSERT"
    assert WORKER_TABLE_PRIVILEGES["cell_branch_heads"] == "SELECT,INSERT"
    assert ("agent_cells", "UPDATE") in WORKER_FORBIDDEN_CELL_PRIVILEGES
    assert ("cell_branch_heads", "UPDATE") in WORKER_FORBIDDEN_CELL_PRIVILEGES
    assert "cell_tool_intents" not in WORKER_TABLE_PRIVILEGES
    assert "cell_effect_ledger" not in WORKER_TABLE_PRIVILEGES
    assert "cell_effect_receipts" not in WORKER_TABLE_PRIVILEGES
    assert "cell_placement_reservations" not in WORKER_TABLE_PRIVILEGES
    assert "cell_approval_nonces" not in WORKER_TABLE_PRIVILEGES
    assert ("cell_approval_nonces", "UPDATE") in WORKER_FORBIDDEN_CELL_PRIVILEGES


def test_branch_head_lock_migration_is_tenant_bound_and_keeps_table_grants_narrow() -> None:
    source = branch_head_lock_migration_source()

    assert 'revision = "0019_cell_branch_head_lock"' in source
    assert 'down_revision = "0018_cell_namespace_reservations"' in source
    assert "CREATE FUNCTION public.lock_cell_branch_head" in source
    assert "RETURNS TABLE" in source
    assert "SECURITY DEFINER" in source
    assert "SET search_path = pg_catalog, public, pg_temp" in source
    assert "current_setting('app.tenant_id', true)" in source
    assert "scoped_tenant IS DISTINCT FROM p_tenant_id" in source
    assert "FROM public.cell_branch_heads AS head" in source
    assert "FOR UPDATE" in source
    assert "REVOKE ALL ON FUNCTION public.lock_cell_branch_head" in source
    assert ") FROM PUBLIC" in source
    assert ") TO trpc_worker" in source
    assert "TO trpc_runtime" not in source
    assert "TO trpc_cell_executor" not in source
    assert "GRANT UPDATE ON cell_branch_heads" not in source
    assert "GRANT SELECT, INSERT, UPDATE ON cell_branch_heads" not in source


def test_performance_cell_cleanup_is_a_narrow_runtime_only_privilege_boundary() -> None:
    source = performance_cell_cleanup_migration_source()

    assert 'revision = "0020_performance_cell_cleanup"' in source
    assert 'down_revision = "0019_cell_branch_head_lock"' in source
    assert "CREATE FUNCTION public.cleanup_performance_cell_fixture" in source
    assert "SECURITY DEFINER" in source
    assert "SET search_path = pg_catalog, public, pg_temp" in source
    assert "SET row_security = on" in source
    assert "session_user <> 'trpc_runtime'" in source
    assert "current_user <> 'trpc_migration'" in source
    assert "p_tenant_id !~ '^perf-[0-9a-f]{32}$'" in source
    assert "tenant.display_name = 'Synthetic performance fixture'" in source
    assert "audit.user_id = 'performance-fixture'" in source
    assert "audit.decision = 'tenant_created'" in source
    assert "audit.idempotency_key = ownership_key" in source
    assert "audit.trace_id = 'admin:' || ownership_key" in source
    assert "performance fixture has placement reservations requiring release" in source
    assert "app.performance_fixture_cleanup_tenant" in source
    assert "REVOKE ALL ON FUNCTION public.cleanup_performance_cell_fixture" in source
    assert ") FROM PUBLIC" in source
    assert ") TO trpc_runtime" in source
    assert ") TO trpc_worker" not in source


def test_performance_reservation_cleanup_reconciles_capacity_before_deleting_fixture() -> None:
    source = performance_reservation_cleanup_migration_source()

    assert 'revision = "0021_performance_reservation_cleanup"' in source
    assert 'down_revision = "0020_performance_cell_cleanup"' in source
    assert "CREATE OR REPLACE FUNCTION public.cleanup_performance_cell_fixture" in source
    assert "SECURITY DEFINER" in source
    assert "SET search_path = pg_catalog, public, pg_temp" in source
    assert "SET row_security = on" in source
    assert "ORDER BY capacity.node_id" in source
    assert "FOR UPDATE" in source
    assert "status = 'active'" in source
    assert "expires_at > v_now_at" in source
    assert "performance fixture has placement reservations requiring release" in source
    assert "SET status = 'expired'" in source
    assert "status IN ('released', 'expired')" in source
    assert "cell_node_capacity" in source
    assert "used_cpu_millis = active_cpu" in source
    assert "used_memory_mb = active_memory" in source
    assert "active_cells = v_active_cells" in source
    assert "'cell_placement_reservations', deleted_placement_reservations" in source


def test_node_snapshot_generation_keeps_a_fail_closed_legacy_overload() -> None:
    source = node_generation_migration_source()

    assert 'revision = "0022_cell_node_snapshot_generation"' in source
    assert 'down_revision = "0021_performance_reservation_cleanup"' in source
    assert "rolsuper, rolbypassrls, rolinherit" in source
    assert "c.relrowsecurity" in source
    assert "c.relforcerowsecurity" in source
    assert "p.prosecdef" in source
    assert "p.proconfig" in source
    assert "pg_catalog.aclexplode" in source
    assert "pg_catalog.acldefault('f'::\"char\"" in source
    assert "acl.grantee = 0" in source
    assert "ck_cell_node_observed_generation_positive" in source
    assert "p_observed_generation < 1" in source
    assert "legacy 7-argument update_cell_node_snapshot is disabled" in source
    assert "USING ERRCODE = '0A000'" in source
    assert "new_function::pg_catalog.regprocedure" in source
    assert "old_function::pg_catalog.regprocedure" in source
    assert "GRANT EXECUTE ON FUNCTION public.update_cell_node_snapshot" in source
    assert "FROM PUBLIC" in source


def test_append_uses_the_tenant_bound_branch_head_lock_function() -> None:
    source = inspect.getsource(PostgresEventStore.append)

    assert "self._lock_branch_head(" in source
    assert "FROM cell_branch_heads" not in source
    assert "lease_expires_at > clock_timestamp() AS lease_valid" not in source


def test_fork_locks_the_head_before_reading_cell_metadata() -> None:
    source = inspect.getsource(PostgresEventStore.fork)

    assert "await self._lock_branch_head(connection, parent)" in source
    assert "parent_branch = await self._get_branch(connection, parent)" in source
    assert "_get_branch(connection, parent, for_update=True)" not in source


def test_approval_consume_is_a_single_scoped_conditional_update() -> None:
    source = inspect.getsource(PostgresApprovalLedger.consume)
    assert "consume_cell_approval_nonce" in source
    assert "UPDATE cell_approval_nonces" not in source


def test_native_effect_completion_is_owner_attempt_and_database_clock_fenced() -> None:
    ensure_source = inspect.getsource(PostgresEffectLedger._ensure_intent)
    complete_source = inspect.getsource(PostgresEffectLedger.complete)
    receipt_source = inspect.getsource(PostgresEffectLedger._write_receipt)

    assert 'namespace.get("payload")' in ensure_source
    assert '"effect_key": intent.effect_key' in ensure_source
    assert "event_type='policy.decided'" in ensure_source
    assert "payload->>'decision'=$9" in ensure_source
    assert "AND attempt=$4 AND lease_owner=$5" in complete_source
    assert "lease_expires_at > clock_timestamp()" in complete_source
    assert "RETURNING effect_key" in complete_source
    assert "ON CONFLICT (tenant_id, effect_key, attempt) DO NOTHING" in receipt_source


@pytest.mark.asyncio
async def test_native_effect_intent_matches_its_event_and_policy_facts() -> None:
    intent = native_intent()
    event = {
        "tenant_id": intent.tenant_id,
        "app_id": intent.app_id,
        "cell_id": intent.cell_id,
        "session_id": intent.session_id,
        "capsule_digest": intent.capsule_digest,
        "branch_id": intent.branch_id,
        "sequence": 4,
        "event_id": "intent-event-a",
        "payload": json.dumps(
            {
                "intent_id": intent.intent_id,
                "tool_name": intent.tool_name,
                "arguments_hash": intent.arguments_hash,
                "effect_key": intent.effect_key,
                "risk": str(intent.risk),
            }
        ),
    }
    persisted = {
        **event,
        "intent_id": intent.intent_id,
        "tool_name": intent.tool_name,
        "arguments_hash": intent.arguments_hash,
        "effect_key": intent.effect_key,
        "risk": str(intent.risk),
        "decision": str(intent.policy_decision),
    }
    connection = ConnectionDouble(fetchval=1, fetchrows=[event, persisted])
    ledger = PostgresEffectLedger(  # type: ignore[arg-type]
        RecordingPool(connection),
        tenant_id=intent.tenant_id,
    )

    stored = await ledger._ensure_intent(connection, intent)  # type: ignore[arg-type]

    assert stored["effect_key"] == intent.effect_key
    assert any("event_type='policy.decided'" in query for query, _ in connection.calls)


@pytest.mark.asyncio
async def test_native_effect_intent_rejects_mismatched_event_payload() -> None:
    intent = native_intent()
    event = {
        "tenant_id": intent.tenant_id,
        "app_id": intent.app_id,
        "cell_id": intent.cell_id,
        "session_id": intent.session_id,
        "capsule_digest": intent.capsule_digest,
        "branch_id": intent.branch_id,
        "sequence": 4,
        "event_id": "intent-event-a",
        "payload": {
            "intent_id": intent.intent_id,
            "tool_name": intent.tool_name,
            "arguments_hash": intent.arguments_hash,
            "effect_key": "trpc-agent-effect/v1:" + "0" * 64,
            "risk": str(intent.risk),
        },
    }
    connection = ConnectionDouble(fetchval=1, fetchrows=[event])
    ledger = PostgresEffectLedger(  # type: ignore[arg-type]
        RecordingPool(connection),
        tenant_id=intent.tenant_id,
    )

    with pytest.raises(EffectKeyConflict, match="causal event payload"):
        await ledger._ensure_intent(connection, intent)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_postgres_approval_ledger_issues_and_consumes_one_scoped_digest() -> None:
    connection = ConnectionDouble(fetchval=True)
    ledger = PostgresApprovalLedger(  # type: ignore[arg-type]
        RecordingPool(connection),
        tenant_id="tenant-a",
    )
    expires_at = datetime.now(UTC).timestamp() + 60
    scope_digest = "a" * 64

    await ledger.issue("nonce-a", expires_at, scope_digest)
    assert await ledger.consume("nonce-a", expires_at, scope_digest) is True
    assert sum("set_config" in query for query, _ in connection.calls) == 2
    assert any("issue_cell_approval_nonce" in query for query, _ in connection.calls)
    assert any("consume_cell_approval_nonce" in query for query, _ in connection.calls)

    assert await ledger.consume("", 0, scope_digest) is False
    assert await ledger.consume("nonce-a", expires_at, "bad") is False
    with pytest.raises(ValueError, match="tenant_id"):
        PostgresApprovalLedger(RecordingPool(connection), tenant_id="")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="approval expiry"):
        await ledger.issue("nonce-a", 0, scope_digest)
    with pytest.raises(ValueError, match="scope_digest"):
        await ledger.issue("nonce-a", expires_at, "bad")
    with pytest.raises(ValueError, match="nonce"):
        await ledger.issue("", expires_at, scope_digest)
