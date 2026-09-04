"""Static contract checks for the multi-Pod evolution persistence boundary."""

from __future__ import annotations

import inspect
from pathlib import Path

from trpc_service.cell import PostgresPromotionStore, PromotionOutboxClaim
from trpc_service.cell.evolution_postgres import PromotionOutboxConflict

ROOT = Path(__file__).parents[2]


def test_public_adapter_has_the_online_fencing_contract() -> None:
    assert PostgresPromotionStore.__module__ == "trpc_service.cell.evolution_postgres"
    assert PromotionOutboxClaim.__module__ == "trpc_service.cell.evolution_postgres"
    assert issubclass(PromotionOutboxConflict, RuntimeError)
    for name in (
        "get",
        "compare_and_swap",
        "rollback",
        "pending_outbox",
        "claim_outbox",
        "acknowledge",
        "release",
        "reconcile",
    ):
        assert inspect.iscoroutinefunction(getattr(PostgresPromotionStore, name))

    assert "certificate_verifier" in inspect.signature(PostgresPromotionStore).parameters
    assert "approval_secret" in inspect.signature(PostgresPromotionStore).parameters
    assert "lease_epoch" in inspect.signature(PostgresPromotionStore.acknowledge).parameters


def test_adapter_source_keeps_tenant_scope_and_cas_fences() -> None:
    source = inspect.getsource(PostgresPromotionStore)
    assert "set_config('app.tenant_id', $1, true)" in source
    assert "async with self._tenant_transaction(tenant)" in source
    assert "FOR UPDATE" in source
    assert "SKIP LOCKED" in source
    assert "active_capsule_digest=$7" in source
    assert "control_version=$8" in source
    assert "lease_epoch=$5" in source
    assert "claimed_by=$3" in source
    assert "lease_expires_at > clock_timestamp()" in source
    assert "PromotionAlreadyUsed" in source
    assert "approval_id" in source


def test_append_only_use_fence_does_not_require_update_privilege() -> None:
    source = inspect.getsource(PostgresPromotionStore._assert_unused_certificate)
    assert "FROM cell_promotion_uses" in source
    assert "FOR UPDATE" not in source

    migration = (ROOT / "migrations" / "versions" / "0025_proof_carrying_evolution.py").read_text(
        encoding="utf-8"
    )
    assert "GRANT SELECT, INSERT ON cell_promotion_uses" in migration
    assert "GRANT SELECT, INSERT, UPDATE ON cell_promotion_uses" not in migration


def test_evolution_authority_updates_only_mutable_control_columns() -> None:
    targets = (ROOT / "migrations" / "versions" / "0025_proof_carrying_evolution.py").read_text(
        encoding="utf-8"
    )
    assert "GRANT SELECT, INSERT, UPDATE ON cell_promotion_targets" not in targets
    assert "UPDATE (active_capsule_digest, control_version, updated_at)" in targets

    outbox = (ROOT / "migrations" / "versions" / "0026_evolution_online_control.py").read_text(
        encoding="utf-8"
    )
    assert "GRANT SELECT, INSERT, UPDATE ON cell_promotion_outbox" not in outbox
    assert "status, claimed_by, lease_epoch, lease_expires_at" in outbox
    assert "attempts, available_at, published_at, last_error" in outbox

    forward_fix = (
        ROOT / "migrations" / "versions" / "0028_evolution_least_privilege.py"
    ).read_text(encoding="utf-8")
    assert "REVOKE UPDATE ON cell_promotion_targets" in forward_fix
    assert "REVOKE UPDATE ON cell_promotion_outbox" in forward_fix
    assert "UPDATE (active_capsule_digest, control_version, updated_at)" in forward_fix
    assert "status, claimed_by, lease_epoch, lease_expires_at" in forward_fix


def test_online_control_migration_has_durable_rls_and_recovery_fields() -> None:
    source = (ROOT / "migrations" / "versions" / "0026_evolution_online_control.py").read_text(
        encoding="utf-8"
    )
    assert 'revision = "0026_evolution_online_control"' in source
    assert 'down_revision = "0025_proof_carrying_evolution"' in source
    for table in ("cell_promotion_receipts", "cell_promotion_outbox"):
        assert f"CREATE TABLE {table}" in source
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in source
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in source
        assert f"tenant_isolation_{table}" in source
    for field in (
        "certificate_id",
        "signature",
        "lease_epoch",
        "claimed_by",
        "lease_expires_at",
        "published_at",
    ):
        assert field in source
    uses = (ROOT / "migrations" / "versions" / "0025_proof_carrying_evolution.py").read_text(
        encoding="utf-8"
    )
    assert "approval_id" in uses
    assert "ON DELETE CASCADE" in source
    assert "trpc_evolution_authority" in source


def test_receipt_path_does_not_contain_provider_or_secret_persistence() -> None:
    source = inspect.getsource(PostgresPromotionStore)
    assert "provider(" not in source.lower()
    assert "provider_call" not in source.lower()
    assert "prompt" not in source.lower()
    assert "secret" in source.lower()  # only constructor/approval verification wording
    assert "cell_promotion_receipts" in source
    assert "cell_promotion_outbox" in source
