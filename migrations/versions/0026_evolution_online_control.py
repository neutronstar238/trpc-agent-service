"""Add the durable online boundary for Proof-Carrying Evolution.

Revision 0025 stores the exact-Cell pointer and the certificate/approval
idempotency fence.  This revision adds the facts needed by more than one Pod:
signed promotion receipts and an at-least-once outbox with an epoch-fenced
claim lease.  All rows are tenant scoped and the dedicated evolution authority
is the only runtime role allowed to mutate them.
"""

from __future__ import annotations

from alembic import op

revision = "0026_evolution_online_control"
down_revision = "0025_proof_carrying_evolution"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE cell_promotion_receipts (
            tenant_id text NOT NULL,
            receipt_id uuid NOT NULL,
            certificate_id text NOT NULL,
            app_id text NOT NULL,
            cell_id text NOT NULL,
            session_id text NOT NULL,
            previous_active_capsule text NOT NULL,
            active_capsule text NOT NULL,
            previous_control_version bigint NOT NULL,
            control_version bigint NOT NULL,
            issued_at timestamptz NOT NULL,
            signing_key_id text NOT NULL,
            signature text NOT NULL,
            operation text NOT NULL DEFAULT 'promote',
            rollback_of uuid,
            PRIMARY KEY (tenant_id, receipt_id),
            FOREIGN KEY (tenant_id, app_id, cell_id, session_id)
                REFERENCES cell_promotion_targets
                    (tenant_id, app_id, cell_id, session_id)
                ON DELETE CASCADE,
            CONSTRAINT uq_cell_promotion_receipt_rollback
                UNIQUE (tenant_id, rollback_of),
            CONSTRAINT ck_cell_promotion_receipt_scope CHECK (
                tenant_id <> '' AND app_id <> '' AND cell_id <> ''
                AND session_id <> '' AND tenant_id NOT LIKE '%*%'
                AND app_id NOT LIKE '%*%' AND cell_id NOT LIKE '%*%'
                AND session_id NOT LIKE '%*%'
            ),
            CONSTRAINT ck_cell_promotion_receipt_capsules CHECK (
                previous_active_capsule ~ '^sha256:[0-9a-f]{64}$'
                AND active_capsule ~ '^sha256:[0-9a-f]{64}$'
            ),
            CONSTRAINT ck_cell_promotion_receipt_versions CHECK (
                previous_control_version >= 0
                AND control_version > previous_control_version
            ),
            CONSTRAINT ck_cell_promotion_receipt_operation CHECK (
                operation IN ('promote', 'rollback')
                AND (operation = 'promote' OR rollback_of IS NOT NULL)
            ),
            CONSTRAINT ck_cell_promotion_receipt_ids CHECK (
                certificate_id <> '' AND signing_key_id <> '' AND signature <> ''
            ),
            FOREIGN KEY (tenant_id, previous_active_capsule)
                REFERENCES agent_capsules (tenant_id, capsule_digest),
            FOREIGN KEY (tenant_id, active_capsule)
                REFERENCES agent_capsules (tenant_id, capsule_digest)
        );

        CREATE TABLE cell_promotion_outbox (
            tenant_id text NOT NULL,
            receipt_id uuid NOT NULL,
            status text NOT NULL DEFAULT 'pending',
            claimed_by text,
            lease_epoch bigint NOT NULL DEFAULT 0,
            lease_expires_at timestamptz,
            attempts integer NOT NULL DEFAULT 0,
            available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            published_at timestamptz,
            last_error text,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (tenant_id, receipt_id),
            FOREIGN KEY (tenant_id, receipt_id)
                REFERENCES cell_promotion_receipts (tenant_id, receipt_id)
                ON DELETE CASCADE,
            CONSTRAINT ck_cell_promotion_outbox_status CHECK (
                status IN ('pending', 'claimed', 'published')
            ),
            CONSTRAINT ck_cell_promotion_outbox_epoch CHECK (lease_epoch >= 0),
            CONSTRAINT ck_cell_promotion_outbox_attempts CHECK (attempts >= 0),
            CONSTRAINT ck_cell_promotion_outbox_claim CHECK (
                (status = 'claimed' AND claimed_by IS NOT NULL
                    AND lease_expires_at IS NOT NULL)
                OR status <> 'claimed'
            )
        );

        CREATE INDEX ix_cell_promotion_outbox_ready
            ON cell_promotion_outbox (tenant_id, status, available_at, created_at);
        CREATE INDEX ix_cell_promotion_outbox_lease
            ON cell_promotion_outbox (tenant_id, lease_expires_at)
            WHERE status = 'claimed';
        CREATE INDEX ix_cell_promotion_receipts_target
            ON cell_promotion_receipts (tenant_id, app_id, cell_id, session_id, issued_at);

        ALTER TABLE cell_promotion_receipts ENABLE ROW LEVEL SECURITY;
        ALTER TABLE cell_promotion_receipts FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation_cell_promotion_receipts
            ON cell_promotion_receipts
            USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
            WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''));

        ALTER TABLE cell_promotion_outbox ENABLE ROW LEVEL SECURITY;
        ALTER TABLE cell_promotion_outbox FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation_cell_promotion_outbox
            ON cell_promotion_outbox
            USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
            WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''));

        REVOKE ALL ON cell_promotion_receipts, cell_promotion_outbox FROM PUBLIC;
        REVOKE ALL ON cell_promotion_receipts, cell_promotion_outbox
            FROM trpc_runtime, trpc_worker, trpc_cell_executor;
        GRANT SELECT, INSERT ON cell_promotion_receipts
            TO trpc_evolution_authority;
        GRANT SELECT, INSERT ON cell_promotion_outbox
            TO trpc_evolution_authority;
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
        REVOKE ALL ON cell_promotion_receipts, cell_promotion_outbox
            FROM PUBLIC, trpc_runtime, trpc_worker,
                 trpc_cell_executor, trpc_evolution_authority;
        DROP TABLE IF EXISTS cell_promotion_outbox;
        DROP TABLE IF EXISTS cell_promotion_receipts;
        """
    )
