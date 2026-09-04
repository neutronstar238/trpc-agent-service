"""Static contracts for the production tool-ledger reconciliation boundary."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).parents[2]
MIGRATION = ROOT / "migrations" / "versions" / "0027_tool_execution_reconciliation.py"
EXECUTION = ROOT / "trpc_service" / "tool" / "execution.py"
RECONCILIATION = ROOT / "trpc_service" / "tool" / "reconciliation.py"
POSTGRES = ROOT / "trpc_service" / "tool" / "postgres.py"


def _sql() -> str:
    return re.sub(r"\s+", " ", MIGRATION.read_text(encoding="utf-8")).lower()


def test_migration_is_single_head_and_extends_tool_executions() -> None:
    spec = importlib.util.spec_from_file_location("tool_reconciliation", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == "0027_tool_execution_reconciliation"
    assert module.down_revision == "0026_evolution_online_control"
    sql = _sql()
    assert "alter table tool_executions" in sql
    assert "add column if not exists attempt" in sql
    assert "reconciliation_owner" in sql
    assert "reconciliation_epoch" in sql
    assert "reconciliation_lease_expires_at" in sql
    assert "reconciliation_outcome" in sql
    assert "reconciliation_evidence_digest" in sql


def test_evidence_is_append_only_redacted_and_tenant_scoped() -> None:
    sql = _sql()
    assert "create table tool_execution_reconciliations" in sql
    assert "foreign key (tenant_id, execution_key)" in sql
    assert "on delete cascade" in sql
    assert "unique (tenant_id, execution_key, attempt, evidence_digest)" in sql
    assert "evidence_summary" in sql
    assert "trace_id" in sql
    assert "reconciler_id" in sql
    assert "enable row level security" in sql
    assert "force row level security" in sql
    assert "tenant_isolation_tool_execution_reconciliations" in sql
    assert "reject_tool_execution_reconciliation_mutation" in sql
    assert "grant select, insert on tool_execution_reconciliations" in sql
    assert "from public, trpc_runtime, trpc_worker" in sql


def test_immutable_trigger_checks_authenticated_session_role() -> None:
    sql = _sql()
    assert "security definer" in sql
    assert "tg_op = 'delete' and session_user = 'trpc_migration'" in sql
    assert "tg_op = 'delete' and current_user = 'trpc_migration'" not in sql


def test_reconciler_claim_is_skip_locked_and_provider_path_has_no_tool_call() -> None:
    postgres = POSTGRES.read_text(encoding="utf-8")
    reconciliation = RECONCILIATION.read_text(encoding="utf-8")
    execution = EXECUTION.read_text(encoding="utf-8")
    assert "for update of execution skip locked" in postgres.lower()
    assert "reconciliation_epoch=execution.reconciliation_epoch+1" in postgres
    assert "status IN ('ambiguous','unknown')" in postgres
    assert "class ProviderReconciler" in reconciliation
    assert "class ToolExecutionReconciliationCoordinator" in reconciliation
    assert "self.reconciler.probe" in reconciliation
    assert "await call()" not in reconciliation
    assert 'UNKNOWN = "unknown"' in execution
    assert "ExecutionIdentityConflict" in execution
