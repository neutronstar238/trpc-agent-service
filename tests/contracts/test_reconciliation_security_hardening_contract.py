"""Contract checks for the forward-only reconciliation privilege migration."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[2]
MIGRATION = ROOT / "migrations" / "versions" / "0029_reconciliation_security_hardening.py"


def test_hardening_is_a_single_forward_revision() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    assert 'revision = "0029_reconciliation_security_hardening"' in source
    assert 'down_revision = "0028_evolution_least_privilege"' in source
    assert "ON DELETE RESTRICT" in source
    assert "ON DELETE CASCADE" not in source
    assert "fk_cell_promotion_target_capsule_retention" in source
    assert "fk_cell_promotion_use_target_retention" in source
    assert "fk_cell_promotion_receipt_target_retention" in source
    assert source.count("ON DELETE RESTRICT") >= 5


def test_reconciliation_requires_fenced_cas_and_no_direct_update_grant() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    assert "CREATE OR REPLACE FUNCTION public.reconcile_cell_effect_cas" in source
    assert "CREATE OR REPLACE FUNCTION public.reconcile_tool_execution_cas" in source
    assert "CREATE OR REPLACE FUNCTION public.claim_tool_execution_ambiguous" in source
    assert "CREATE OR REPLACE FUNCTION public.lock_cell_effect_reconciliation" in source
    assert "CREATE OR REPLACE FUNCTION public.lock_tool_execution_reconciliation" in source
    assert "SECURITY DEFINER" in source
    assert "p_claim_owner" in source
    assert "p_claim_epoch" in source
    assert "p_evidence_digest" in source
    assert "cell reconciliation evidence is missing" in source
    assert "tool reconciliation evidence is missing" in source
    assert "cell reconciliation receipt is missing" in source
    assert "FOR UPDATE OF execution SKIP LOCKED" in source
    assert "GRANT EXECUTE ON FUNCTION public.reconcile_cell_effect_cas" in source
    assert "GRANT EXECUTE ON FUNCTION public.reconcile_tool_execution_cas" in source
    assert "GRANT EXECUTE ON FUNCTION public.claim_tool_execution_ambiguous" in source
    assert "GRANT EXECUTE ON FUNCTION public.lock_cell_effect_reconciliation" in source
    assert "GRANT EXECUTE ON FUNCTION public.lock_tool_execution_reconciliation" in source
    assert "REVOKE UPDATE, DELETE ON public.cell_effect_receipts," in source
    assert "public.cell_effect_ledger" in source
    assert "REVOKE UPDATE, DELETE ON public.tool_executions" in source
    assert "REVOKE UPDATE (" in source
    assert "reconciliation_evidence_digest" in source
    assert "GRANT SELECT ON public.sessions, public.session_turns" in source
    assert (
        "GRANT UPDATE ("
        not in source.split("def downgrade", 1)[0].split(
            "REVOKE UPDATE ON public.cell_promotion_targets", 1
        )[0]
    )
    assert "REVOKE EXECUTE ON FUNCTION" in source.split("def downgrade", 1)[1]


def test_evidence_cannot_be_deleted_by_migration_session() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    assert "REVOKE DELETE ON public.cell_effect_reconciliations," in source
    assert "public.tool_execution_reconciliations" in source
    assert "session_user = 'trpc_migration'" not in source
    assert "evidence is immutable" in source


def test_migration_write_barrier_checks_durable_scope_and_session() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    assert "public.migration_write_barrier_guard" in source
    assert "public.migration_leases" in source
    assert "public.migration_scope_manifests" in source
    assert "SELECT b.*" in source
    assert "SELECT l.*" in source
    assert "SELECT m.*" in source
    assert "lease.expires_at <= pg_catalog.clock_timestamp()" in source
    assert "session_user NOT IN ('trpc_runtime', 'trpc_worker', 'trpc_migration')" in source
    assert "active migration barrier requires trpc_runtime" in source
    assert "app.migration_id" in source
    assert "app.migration_owner_instance" in source
    assert "app.migration_lease_epoch" in source
    barrier_start = source.index("migration_write_barrier_guard")
    assert source.index("IF NOT FOUND THEN", barrier_start) < source.index(
        "IF session_user NOT IN", barrier_start
    )


def test_candidate_head_reader_is_narrow_and_tenant_bound() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    assert "public.read_cell_branch_head_hash" in source
    assert "session_user <> 'trpc_evolution_authority'" in source
    assert "current_setting('app.tenant_id', true)" in source
    assert "REVOKE SELECT ON public.cell_branch_heads" in source
    assert "TO trpc_evolution_authority" in source


def test_downgrade_does_not_restore_unsafe_privileges() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    downgrade = source.split("def downgrade", 1)[1]
    assert "GRANT UPDATE ON" not in downgrade
    assert "ON DELETE CASCADE" not in downgrade
    assert "session_user = 'trpc_migration'" not in downgrade
