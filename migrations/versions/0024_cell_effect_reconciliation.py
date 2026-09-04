"""Add immutable provider-outcome reconciliation evidence.

The effect ledger already fences execution attempts.  This revision adds a
separate append-only fact for a read-only provider probe and grants its write
path only to a dedicated reconciliation authority.  No provider response,
intent argument, or credential is stored in the table.
"""

from __future__ import annotations

from alembic import op

revision = "0024_cell_effect_reconciliation"
down_revision = "0023_hpa_fixture_boundary"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE cell_effect_reconciliations (
            tenant_id text NOT NULL,
            reconciliation_id uuid NOT NULL DEFAULT gen_random_uuid(),
            effect_key text NOT NULL,
            attempt integer NOT NULL,
            app_id text NOT NULL,
            cell_id text NOT NULL,
            session_id text NOT NULL,
            capsule_digest text NOT NULL,
            branch_id text NOT NULL,
            outcome text NOT NULL,
            evidence_digest text NOT NULL,
            evidence_summary text NOT NULL,
            trace_id text,
            reconciler_id text NOT NULL,
            observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (tenant_id, reconciliation_id),
            UNIQUE (tenant_id, effect_key, attempt, evidence_digest),
            FOREIGN KEY (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, effect_key
            ) REFERENCES cell_effect_ledger (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, effect_key
            ) ON DELETE CASCADE,
            CONSTRAINT ck_cell_effect_reconciliation_attempt CHECK (attempt >= 0),
            CONSTRAINT ck_cell_effect_reconciliation_outcome CHECK (
                outcome IN ('applied', 'not_applied', 'unknown')
            ),
            CONSTRAINT ck_cell_effect_reconciliation_effect_key CHECK (
                effect_key ~ '^trpc-agent-effect/v1:[0-9a-f]{64}$'
            ),
            CONSTRAINT ck_cell_effect_reconciliation_digest CHECK (
                evidence_digest ~ '^[0-9a-f]{64}$'
            ),
            CONSTRAINT ck_cell_effect_reconciliation_summary CHECK (
                evidence_summary ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$'
            )
        );

        ALTER TABLE cell_effect_reconciliations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE cell_effect_reconciliations FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation_cell_effect_reconciliations
            ON cell_effect_reconciliations
            USING (
                tenant_id = nullif(current_setting('app.tenant_id', true), '')
            )
            WITH CHECK (
                tenant_id = nullif(current_setting('app.tenant_id', true), '')
            );

        CREATE FUNCTION public.reject_cell_effect_reconciliation_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        BEGIN
            IF TG_OP = 'DELETE'
               AND current_user = 'trpc_migration'
               AND session_user = 'trpc_runtime'
               AND nullif(
                    pg_catalog.current_setting(
                        'app.performance_fixture_cleanup_tenant', true
                    ), ''
               ) IS NOT DISTINCT FROM OLD.tenant_id THEN
                RETURN OLD;
            END IF;
            RAISE EXCEPTION 'cell effect reconciliation evidence is immutable'
                USING ERRCODE = '25006';
        END
        $function$;
        CREATE TRIGGER cell_effect_reconciliations_immutable
            BEFORE UPDATE OR DELETE ON cell_effect_reconciliations
            FOR EACH ROW
            EXECUTE FUNCTION public.reject_cell_effect_reconciliation_mutation();
        """
    )

    op.execute(
        """
        DO $role$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname = 'trpc_cell_reconciler'
            ) THEN
                CREATE ROLE trpc_cell_reconciler
                    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                    NOINHERIT NOBYPASSRLS;
            END IF;
            IF EXISTS (
                SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname = 'trpc_cell_reconciler'
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
                    'trpc_cell_reconciler must be LOGIN NOSUPERUSER NOINHERIT NOBYPASSRLS'
                    USING ERRCODE = '42501';
            END IF;
            IF EXISTS (
                WITH RECURSIVE reachable_roles(role_id) AS (
                    SELECT oid FROM pg_catalog.pg_roles
                     WHERE rolname = 'trpc_cell_reconciler'
                    UNION
                    SELECT membership.roleid
                      FROM pg_catalog.pg_auth_members AS membership
                      JOIN reachable_roles AS reachable
                        ON reachable.role_id = membership.member
                )
                SELECT 1 FROM reachable_roles
                 WHERE role_id <> (
                     SELECT oid FROM pg_catalog.pg_roles
                      WHERE rolname = 'trpc_cell_reconciler'
                 )
            ) THEN
                RAISE EXCEPTION
                    'trpc_cell_reconciler must not have SET ROLE membership'
                    USING ERRCODE = '42501';
            END IF;
        END
        $role$;

        REVOKE ALL ON cell_effect_reconciliations FROM PUBLIC;
        REVOKE ALL ON cell_effect_reconciliations
            FROM trpc_runtime, trpc_worker, trpc_cell_executor;
        REVOKE UPDATE, DELETE ON cell_effect_reconciliations
            FROM trpc_cell_reconciler;
        GRANT SELECT, INSERT ON cell_effect_reconciliations
            TO trpc_cell_reconciler;

        -- Reconciliation may only touch an already journaled, tenant-scoped
        -- attempt.  It does not receive intent creation or receipt deletion.
        GRANT SELECT ON cell_events, cell_tool_intents
            TO trpc_cell_reconciler;
        GRANT SELECT, UPDATE ON cell_effect_receipts TO trpc_cell_reconciler;
        GRANT SELECT, UPDATE ON cell_effect_ledger TO trpc_cell_reconciler;
        REVOKE UPDATE, DELETE ON cell_effect_reconciliations
            FROM PUBLIC, trpc_runtime, trpc_worker, trpc_cell_executor;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        REVOKE ALL ON cell_events, cell_tool_intents,
            cell_effect_ledger, cell_effect_receipts
            FROM trpc_cell_reconciler;
        REVOKE ALL ON cell_effect_reconciliations
            FROM PUBLIC, trpc_runtime, trpc_worker,
                 trpc_cell_executor, trpc_cell_reconciler;
        DROP TRIGGER IF EXISTS cell_effect_reconciliations_immutable
            ON cell_effect_reconciliations;
        DROP FUNCTION IF EXISTS public.reject_cell_effect_reconciliation_mutation();
        DROP TABLE IF EXISTS cell_effect_reconciliations;
        """
    )
