from __future__ import annotations

import importlib
from pathlib import Path

import scripts.kubernetes_hpa_load_driver as hpa_driver
import scripts.kubernetes_runtime_gate as runtime_gate
import scripts.release_gate as release_gate

hpa_migration = importlib.import_module("migrations.versions.0023_hpa_fixture_boundary")

ROOT = Path(__file__).parents[2]
MIGRATION = ROOT / "migrations" / "versions" / "0023_hpa_fixture_boundary.py"
DRIVER = ROOT / "scripts" / "kubernetes_hpa_load_driver.py"
POSTGRES_INIT = ROOT / "deploy" / "postgres" / "init.sh"


def test_hpa_fixture_migration_is_versioned_after_current_schema_head() -> None:
    source = MIGRATION.read_text(encoding="utf-8")

    assert 'revision = "0023_hpa_fixture_boundary"' in source
    assert 'down_revision = "0022_cell_node_snapshot_generation"' in source
    assert "CREATE FUNCTION public.prepare_hpa_fixture" in source
    assert "CREATE FUNCTION public.cleanup_hpa_fixture" in source
    assert "CREATE FUNCTION public.count_session_ready_backlog_for_tenant" in source


def test_hpa_fixture_migration_has_a_non_bypass_role_and_narrow_grants() -> None:
    source = MIGRATION.read_text(encoding="utf-8")

    assert "role must be provisioned before migration 0023" in source
    assert "ARRAY['trpc_hpa', 'trpc_metrics']" in source
    assert "pg_catalog.pg_auth_members" in source
    assert "reachable_roles(role_id)" in source
    assert "direct or transitive SET ROLE membership" in source
    assert "role_id <> role_oid" in source
    assert "rolbypassrls" in source
    assert "NOBYPASSRLS" in source
    assert "must be LOGIN NOSUPERUSER NOCREATEDB" in source
    assert "GRANT EXECUTE ON FUNCTION public.prepare_hpa_fixture(text, integer)" in source
    assert "GRANT EXECUTE ON FUNCTION public.cleanup_hpa_fixture(text)" in source
    assert "GRANT EXECUTE ON FUNCTION public.count_session_ready_backlog_for_tenant(text)" in source
    assert "FROM PUBLIC, trpc_runtime, trpc_worker, trpc_hpa" in source
    assert "trpc_hpa must not execute tenant backlog metric" in source


def test_hpa_fixture_cleanup_receipt_covers_every_tenant_table() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    expected_tables = {
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
        "migration_checkpoints",
        "tenant_budget_usage",
        "fault_stage_controls",
        "migration_scope_manifests",
        "migration_leases",
        "migration_write_barriers",
        "agent_capsules",
        "agent_cells",
        "cell_events",
        "cell_tool_intents",
        "cell_effect_ledger",
        "cell_effect_receipts",
        "cell_branch_heads",
        "cell_placement_reservations",
        "cell_approval_nonces",
    }
    for table in expected_tables:
        assert f'"{table}"' in source
    assert "residual := residual ||" in source
    assert "HPA fixture cleanup left residual rows" in source


def test_hpa_cleanup_table_contract_is_identical_across_all_gates() -> None:
    expected = set(hpa_migration._TENANT_TABLES)

    assert set(hpa_driver._HPA_PROBE_CLEANUP_TABLES) == expected
    assert set(runtime_gate._HPA_CLEANUP_TABLES) == expected
    assert set(release_gate.K8S_HPA_CLEANUP_TABLES) == expected


def test_hpa_driver_has_no_worker_secret_or_table_dml() -> None:
    source = DRIVER.read_text(encoding="utf-8")

    assert "trpc-worker-secrets" not in source
    assert "TRPC_SERVICE_WORKER_DATABASE_DSN" not in source
    assert "executemany(" not in source
    assert "INSERT INTO public." not in source
    assert "DELETE FROM public." not in source
    assert "SELECT count(*) FROM public." not in source
    assert "prepare_hpa_fixture($1, $2)" in source
    assert "cleanup_hpa_fixture($1)" in source


def test_hpa_driver_job_contract_separates_target_and_job_namespace() -> None:
    source = DRIVER.read_text(encoding="utf-8")

    assert 'HPA_JOB_NAMESPACE_ENV = "TRPC_K8S_HPA_JOB_NAMESPACE"' in source
    assert '"target_namespace": config["namespace"]' in source
    assert '"job_namespace": config.get("job_namespace", config["namespace"])' in source
    assert 'HPA_DATABASE_SECRET_NAME = "trpc-hpa-secrets"' in source


def test_hpa_metric_function_sets_transaction_tenant_and_checks_base_tables() -> None:
    source = MIGRATION.read_text(encoding="utf-8")

    assert "PERFORM pg_catalog.set_config('app.tenant_id', p_tenant_id, true);" in source
    assert "session_user <> 'trpc_metrics'" in source
    assert "table_info.table_type = 'BASE TABLE'" in source
    assert "present.table_type <> 'BASE TABLE'" in source
    assert "'row_security=on' = ANY(function_config)" in source
    assert "cell_node_capacity" in source


def test_hpa_init_provisions_an_independent_non_bypass_role_and_secret() -> None:
    source = POSTGRES_INIT.read_text(encoding="utf-8")

    assert "/run/secrets/hpa_database_password" in source
    assert (
        "CREATE ROLE trpc_hpa LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS"
    ) in source
    assert (
        "ALTER ROLE trpc_hpa LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS"
    ) in source
    assert "GRANT CONNECT ON DATABASE %I TO trpc_hpa" in source
    assert "ALTER ROLE trpc_hpa PASSWORD" in source
    assert "TRPC_SERVICE_WORKER_DATABASE_DSN" not in source
