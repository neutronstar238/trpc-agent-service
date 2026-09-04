"""Restrict evolution authority updates to mutable control-plane columns.

Earlier revisions granted table-wide UPDATE so existing databases need an
explicit forward migration.  The authority may advance a Capsule pointer and
lease/publish outbox rows, but immutable tenant, Cell and receipt identity
columns remain database-enforced.
"""

from __future__ import annotations

from alembic import op

revision = "0028_evolution_least_privilege"
down_revision = "0027_tool_execution_reconciliation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        REVOKE UPDATE ON cell_promotion_targets
            FROM trpc_evolution_authority;
        GRANT UPDATE (active_capsule_digest, control_version, updated_at)
            ON cell_promotion_targets
            TO trpc_evolution_authority;

        REVOKE UPDATE ON cell_promotion_outbox
            FROM trpc_evolution_authority;
        GRANT UPDATE (
            status, claimed_by, lease_epoch, lease_expires_at,
            attempts, available_at, published_at, last_error
        ) ON cell_promotion_outbox
            TO trpc_evolution_authority;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        GRANT UPDATE ON cell_promotion_targets, cell_promotion_outbox
            TO trpc_evolution_authority;
        """
    )
