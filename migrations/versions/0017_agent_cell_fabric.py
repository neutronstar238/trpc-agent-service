"""Add the causal Agent Cell Fabric persistence model.

The existing inbox/mailbox tables remain the delivery authority.  These tables
add a content-addressed deployment unit, a movable logical cell, an append-only
causal log, and an intent/effect ledger without weakening the existing tenant
RLS boundary.
"""

from __future__ import annotations

from alembic import op

revision = "0017_agent_cell_fabric"
down_revision = "0016_session_ready_backlog_metric"
branch_labels = None
depends_on = None


_TENANT_TABLES = (
    "agent_capsules",
    "agent_cells",
    "cell_events",
    "cell_tool_intents",
    "cell_effect_ledger",
    "cell_effect_receipts",
)


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE agent_capsules (
            tenant_id text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
            capsule_digest text NOT NULL,
            capsule_name text NOT NULL,
            manifest jsonb NOT NULL,
            signature text,
            signer_key_id text,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (tenant_id, capsule_digest),
            CONSTRAINT ck_agent_capsule_digest
                CHECK (capsule_digest ~ '^sha256:[0-9a-f]{64}$')
        );

        CREATE TABLE agent_cells (
            tenant_id text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
            cell_id text NOT NULL,
            app_id text NOT NULL,
            session_id text NOT NULL,
            capsule_digest text NOT NULL,
            branch_id text NOT NULL DEFAULT 'main',
            parent_branch_id text,
            parent_capsule_digest text,
            fork_sequence bigint,
            status text NOT NULL DEFAULT 'idle',
            assigned_node_id text,
            lease_owner text,
            lease_epoch bigint NOT NULL DEFAULT 0,
            lease_expires_at timestamptz,
            last_sequence bigint NOT NULL DEFAULT 0,
            state_hash text,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (tenant_id, cell_id, branch_id),
            FOREIGN KEY (tenant_id, capsule_digest)
                REFERENCES agent_capsules(tenant_id, capsule_digest),
            CONSTRAINT ck_agent_cell_status CHECK (
                status IN ('idle', 'queued', 'running', 'suspended', 'failed', 'completed')
            ),
            CONSTRAINT ck_agent_cell_fork CHECK (
                (parent_branch_id IS NULL AND parent_capsule_digest IS NULL
                    AND fork_sequence IS NULL)
                OR (parent_branch_id IS NOT NULL AND parent_capsule_digest IS NOT NULL
                    AND fork_sequence IS NOT NULL
                    AND fork_sequence >= 0)
            )
        );
        CREATE INDEX ix_agent_cells_session
            ON agent_cells(tenant_id, session_id, branch_id);
        CREATE INDEX ix_agent_cells_placement
            ON agent_cells(status, assigned_node_id, updated_at);

        CREATE TABLE cell_events (
            tenant_id text NOT NULL,
            cell_id text NOT NULL,
            branch_id text NOT NULL,
            sequence bigint NOT NULL,
            event_id text NOT NULL,
            event_type text NOT NULL,
            capsule_digest text NOT NULL,
            causation_id text,
            correlation_id text NOT NULL,
            trace_id text NOT NULL,
            request_id text NOT NULL,
            prev_hash text NOT NULL,
            payload_hash text NOT NULL,
            event_hash text NOT NULL,
            payload jsonb NOT NULL,
            occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (tenant_id, cell_id, branch_id, sequence),
            UNIQUE (tenant_id, event_id),
            FOREIGN KEY (tenant_id, cell_id, branch_id)
                REFERENCES agent_cells(tenant_id, cell_id, branch_id) ON DELETE CASCADE,
            CONSTRAINT ck_cell_event_sequence CHECK (sequence > 0),
            CONSTRAINT ck_cell_event_hashes CHECK (
                prev_hash ~ '^[0-9a-f]{64}$'
                AND payload_hash ~ '^[0-9a-f]{64}$'
                AND event_hash ~ '^[0-9a-f]{64}$'
            )
        );
        CREATE INDEX ix_cell_events_correlation
            ON cell_events(tenant_id, correlation_id, occurred_at);
        CREATE INDEX ix_cell_events_trace
            ON cell_events(tenant_id, trace_id, occurred_at);

        CREATE TABLE cell_tool_intents (
            tenant_id text NOT NULL,
            intent_id text NOT NULL,
            cell_id text NOT NULL,
            branch_id text NOT NULL,
            sequence bigint NOT NULL,
            tool_name text NOT NULL,
            arguments_hash text NOT NULL,
            effect_key text NOT NULL,
            risk text NOT NULL,
            decision text NOT NULL,
            confirmation_scope_hash text,
            expires_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (tenant_id, intent_id),
            UNIQUE (tenant_id, effect_key),
            FOREIGN KEY (tenant_id, cell_id, branch_id, sequence)
                REFERENCES cell_events(tenant_id, cell_id, branch_id, sequence),
            CONSTRAINT ck_cell_intent_decision CHECK (
                decision IN ('pending', 'allow', 'deny', 'require_confirmation', 'simulate_only')
            ),
            CONSTRAINT ck_cell_intent_hashes CHECK (
                arguments_hash ~ '^[0-9a-f]{64}$'
                AND effect_key ~ '^trpc-agent-effect/v1:[0-9a-f]{64}$'
            )
        );

        CREATE TABLE cell_effect_ledger (
            tenant_id text NOT NULL,
            effect_key text NOT NULL,
            intent_id text NOT NULL,
            status text NOT NULL,
            attempt integer NOT NULL DEFAULT 0,
            lease_owner text,
            lease_epoch bigint NOT NULL DEFAULT 0,
            lease_expires_at timestamptz,
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (tenant_id, effect_key),
            FOREIGN KEY (tenant_id, intent_id)
                REFERENCES cell_tool_intents(tenant_id, intent_id),
            CONSTRAINT ck_cell_effect_ledger_status CHECK (
                status IN (
                    'pending', 'running', 'succeeded', 'failed', 'ambiguous', 'unknown',
                    'simulated', 'denied', 'require_confirmation'
                )
            ),
            CONSTRAINT ck_cell_effect_ledger_attempt CHECK (attempt >= 0),
            CONSTRAINT ck_cell_effect_ledger_key CHECK (
                effect_key ~ '^trpc-agent-effect/v1:[0-9a-f]{64}$'
            )
        );

        CREATE TABLE cell_effect_receipts (
            tenant_id text NOT NULL,
            receipt_id uuid NOT NULL DEFAULT gen_random_uuid(),
            intent_id text NOT NULL,
            effect_key text NOT NULL,
            attempt integer NOT NULL,
            status text NOT NULL,
            result_hash text,
            provider_reference text,
            error_type text,
            attempted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (tenant_id, receipt_id),
            UNIQUE (tenant_id, effect_key, attempt),
            FOREIGN KEY (tenant_id, intent_id)
                REFERENCES cell_tool_intents(tenant_id, intent_id),
            FOREIGN KEY (tenant_id, effect_key)
                REFERENCES cell_effect_ledger(tenant_id, effect_key),
            CONSTRAINT ck_cell_effect_status CHECK (
                status IN (
                    'succeeded', 'failed', 'ambiguous', 'unknown', 'simulated', 'denied',
                    'require_confirmation'
                )
            ),
            CONSTRAINT ck_cell_effect_receipt_attempt CHECK (attempt >= 0)
        );
        """
    )

    for table in _TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation_{table} ON {table}
            USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
            WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
            """
        )

    op.execute(
        """
        REVOKE ALL ON agent_capsules, agent_cells, cell_events,
            cell_tool_intents, cell_effect_ledger, cell_effect_receipts FROM PUBLIC;
        GRANT SELECT, INSERT ON agent_capsules TO trpc_runtime, trpc_worker;
        GRANT SELECT, INSERT, UPDATE ON agent_cells TO trpc_runtime, trpc_worker;
        GRANT SELECT, INSERT, UPDATE ON cell_effect_ledger TO trpc_runtime, trpc_worker;
        GRANT SELECT, INSERT ON cell_events, cell_tool_intents, cell_effect_receipts
            TO trpc_runtime, trpc_worker;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS cell_effect_receipts;
        DROP TABLE IF EXISTS cell_effect_ledger;
        DROP TABLE IF EXISTS cell_tool_intents;
        DROP TABLE IF EXISTS cell_events;
        DROP TABLE IF EXISTS agent_cells;
        DROP TABLE IF EXISTS agent_capsules;
        """
    )
