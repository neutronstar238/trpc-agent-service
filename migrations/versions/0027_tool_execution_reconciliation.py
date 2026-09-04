"""Unify provider-outcome reconciliation with the baseline tool ledger.

The Cell-specific effect ledger is intentionally not used on the production
tool path.  This revision extends ``tool_executions`` with a fenced attempt
and reconciler lease, then stores append-only, redacted probe evidence keyed
back to that same row.  Consequently IM/message idempotency, session fencing,
tool execution idempotency, and provider reconciliation share one source of
truth.
"""

from __future__ import annotations

from alembic import op

revision = "0027_tool_execution_reconciliation"
down_revision = "0026_evolution_online_control"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE tool_executions
            ADD COLUMN IF NOT EXISTS attempt integer NOT NULL DEFAULT 1,
            ADD COLUMN IF NOT EXISTS reconciliation_owner text,
            ADD COLUMN IF NOT EXISTS reconciliation_epoch bigint NOT NULL DEFAULT 0,
            ADD COLUMN IF NOT EXISTS reconciliation_lease_expires_at timestamptz,
            ADD COLUMN IF NOT EXISTS reconciliation_outcome text,
            ADD COLUMN IF NOT EXISTS reconciliation_evidence_digest text,
            ADD COLUMN IF NOT EXISTS reconciled_at timestamptz;

        UPDATE tool_executions
           SET attempt=1
         WHERE attempt IS NULL OR attempt < 1;

        DO $constraints$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                 WHERE conname='tool_executions_attempt_positive'
            ) THEN
                ALTER TABLE tool_executions
                    ADD CONSTRAINT tool_executions_attempt_positive
                    CHECK (attempt > 0);
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                 WHERE conname='tool_executions_reconciliation_epoch_nonnegative'
            ) THEN
                ALTER TABLE tool_executions
                    ADD CONSTRAINT tool_executions_reconciliation_epoch_nonnegative
                    CHECK (reconciliation_epoch >= 0);
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                 WHERE conname='tool_executions_reconciliation_outcome_valid'
            ) THEN
                ALTER TABLE tool_executions
                    ADD CONSTRAINT tool_executions_reconciliation_outcome_valid
                    CHECK (
                        reconciliation_outcome IS NULL
                        OR reconciliation_outcome IN ('applied','not_applied','unknown')
                    );
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                 WHERE conname='tool_executions_reconciliation_digest_valid'
            ) THEN
                ALTER TABLE tool_executions
                    ADD CONSTRAINT tool_executions_reconciliation_digest_valid
                    CHECK (
                        reconciliation_evidence_digest IS NULL
                        OR reconciliation_evidence_digest ~ '^[0-9a-f]{64}$'
                    );
            END IF;
        END
        $constraints$;

        CREATE INDEX IF NOT EXISTS ix_tool_executions_reconciliation_queue
            ON tool_executions (
                tenant_id, status, reconciliation_lease_expires_at, started_at
            )
            WHERE status IN ('ambiguous','unknown');

        CREATE TABLE tool_execution_reconciliations (
            tenant_id text NOT NULL,
            reconciliation_id uuid NOT NULL DEFAULT gen_random_uuid(),
            execution_key text NOT NULL,
            attempt integer NOT NULL,
            outcome text NOT NULL,
            evidence_digest text NOT NULL,
            evidence_summary text NOT NULL,
            trace_id text,
            reconciler_id text NOT NULL,
            observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (tenant_id, reconciliation_id),
            UNIQUE (tenant_id, execution_key, attempt, evidence_digest),
            FOREIGN KEY (tenant_id, execution_key)
                REFERENCES tool_executions (tenant_id, execution_key)
                ON DELETE CASCADE,
            CONSTRAINT ck_tool_execution_reconciliation_attempt CHECK (attempt > 0),
            CONSTRAINT ck_tool_execution_reconciliation_outcome CHECK (
                outcome IN ('applied','not_applied','unknown')
            ),
            CONSTRAINT ck_tool_execution_reconciliation_digest CHECK (
                evidence_digest ~ '^[0-9a-f]{64}$'
            ),
            CONSTRAINT ck_tool_execution_reconciliation_summary CHECK (
                evidence_summary ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$'
            ),
            CONSTRAINT ck_tool_execution_reconciliation_reconciler CHECK (
                reconciler_id <> ''
            )
        );

        ALTER TABLE tool_execution_reconciliations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE tool_execution_reconciliations FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation_tool_execution_reconciliations
            ON tool_execution_reconciliations
            USING (
                tenant_id = nullif(current_setting('app.tenant_id', true), '')
            )
            WITH CHECK (
                tenant_id = nullif(current_setting('app.tenant_id', true), '')
            );

        -- Evidence is append-only for runtime roles.  The migration owner is
        -- allowed to remove rows through the existing tenant fixture cleanup;
        -- the foreign-key cascade keeps that cleanup complete without giving
        -- an application role DELETE access to evidence.
        CREATE FUNCTION public.reject_tool_execution_reconciliation_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        BEGIN
            -- SECURITY DEFINER changes current_user to the function owner.
            -- Use the authenticated session role for this narrow cleanup
            -- exception; otherwise any invoker would appear to be the owner.
            IF TG_OP = 'DELETE' AND session_user = 'trpc_migration' THEN
                RETURN OLD;
            END IF;
            RAISE EXCEPTION 'tool execution reconciliation evidence is immutable'
                USING ERRCODE = '25006';
        END
        $function$;
        CREATE TRIGGER tool_execution_reconciliations_immutable
            BEFORE UPDATE OR DELETE ON tool_execution_reconciliations
            FOR EACH ROW
            EXECUTE FUNCTION public.reject_tool_execution_reconciliation_mutation();
        """
    )

    op.execute(
        """
        DO $role$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname='trpc_tool_reconciler'
            ) THEN
                CREATE ROLE trpc_tool_reconciler
                    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                    NOINHERIT NOBYPASSRLS;
            END IF;
            IF EXISTS (
                SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname='trpc_tool_reconciler'
                   AND (
                       rolsuper
                       OR rolcreatedb
                       OR rolcreaterole
                       OR rolbypassrls
                       OR rolinherit IS DISTINCT FROM FALSE
                       OR rolcanlogin IS DISTINCT FROM TRUE
                   )
            ) THEN
                RAISE EXCEPTION
                    'trpc_tool_reconciler must be LOGIN NOSUPERUSER '
                    'NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS'
                    USING ERRCODE='42501';
            END IF;
            IF EXISTS (
                WITH RECURSIVE reachable_roles(role_id) AS (
                    SELECT oid FROM pg_catalog.pg_roles
                     WHERE rolname='trpc_tool_reconciler'
                    UNION
                    SELECT membership.roleid
                      FROM pg_catalog.pg_auth_members AS membership
                      JOIN reachable_roles AS reachable
                        ON reachable.role_id=membership.member
                )
                SELECT 1 FROM reachable_roles
                 WHERE role_id <> (
                     SELECT oid FROM pg_catalog.pg_roles
                      WHERE rolname='trpc_tool_reconciler'
                 )
            ) THEN
                RAISE EXCEPTION
                    'trpc_tool_reconciler must not have SET ROLE membership'
                    USING ERRCODE='42501';
            END IF;
        END
        $role$;

        REVOKE ALL ON tool_execution_reconciliations
            FROM PUBLIC, trpc_runtime, trpc_worker;
        GRANT USAGE ON SCHEMA public TO trpc_tool_reconciler;
        GRANT SELECT, INSERT ON tool_execution_reconciliations
            TO trpc_tool_reconciler;
        GRANT SELECT ON tool_executions TO trpc_tool_reconciler;
        GRANT SELECT ON sessions, session_turns TO trpc_tool_reconciler;
        GRANT UPDATE (
            status, completed_at, reconciliation_owner,
            reconciliation_epoch, reconciliation_lease_expires_at,
            reconciliation_outcome, reconciliation_evidence_digest,
            reconciled_at
        ) ON tool_executions TO trpc_tool_reconciler;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        REVOKE ALL ON tool_execution_reconciliations
            FROM PUBLIC, trpc_runtime, trpc_worker, trpc_tool_reconciler;
        REVOKE UPDATE (
            status, completed_at, reconciliation_owner,
            reconciliation_epoch, reconciliation_lease_expires_at,
            reconciliation_outcome, reconciliation_evidence_digest,
            reconciled_at
        ) ON tool_executions FROM trpc_tool_reconciler;
        REVOKE SELECT ON tool_executions FROM trpc_tool_reconciler;
        REVOKE SELECT ON sessions, session_turns FROM trpc_tool_reconciler;
        DROP TRIGGER IF EXISTS tool_execution_reconciliations_immutable
            ON tool_execution_reconciliations;
        DROP FUNCTION IF EXISTS public.reject_tool_execution_reconciliation_mutation();
        DROP TABLE IF EXISTS tool_execution_reconciliations;
        DROP INDEX IF EXISTS ix_tool_executions_reconciliation_queue;
        ALTER TABLE tool_executions
            DROP CONSTRAINT IF EXISTS tool_executions_reconciliation_digest_valid,
            DROP CONSTRAINT IF EXISTS tool_executions_reconciliation_outcome_valid,
            DROP CONSTRAINT IF EXISTS tool_executions_reconciliation_epoch_nonnegative,
            DROP CONSTRAINT IF EXISTS tool_executions_attempt_positive,
            DROP COLUMN IF EXISTS reconciled_at,
            DROP COLUMN IF EXISTS reconciliation_evidence_digest,
            DROP COLUMN IF EXISTS reconciliation_outcome,
            DROP COLUMN IF EXISTS reconciliation_lease_expires_at,
            DROP COLUMN IF EXISTS reconciliation_epoch,
            DROP COLUMN IF EXISTS reconciliation_owner,
            DROP COLUMN IF EXISTS attempt;
        """
    )
