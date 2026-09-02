"""Add a tenant-bound cleanup boundary for synthetic performance Cells.

Cell events remain append-only for ordinary runtime and Worker sessions.  A
performance fixture, however, must be removable after a bounded acceptance
run.  This revision grants the runtime role one narrow SECURITY DEFINER
operation which accepts only the fixture identity already proven by the
control-plane audit record.
"""

from __future__ import annotations

from alembic import op

revision = "0020_performance_cell_cleanup"
down_revision = "0019_cell_branch_head_lock"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $preflight$
        DECLARE
            migration_is_superuser boolean;
            migration_bypasses_rls boolean;
            migration_inherits boolean;
            events_owner text;
            events_has_rls boolean;
            events_forces_rls boolean;
        BEGIN
            IF current_user <> 'trpc_migration' THEN
                RAISE EXCEPTION
                    'migration 0020 must run as the trpc_migration schema owner';
            END IF;
            SELECT rolsuper, rolbypassrls, rolinherit
              INTO migration_is_superuser, migration_bypasses_rls, migration_inherits
              FROM pg_catalog.pg_roles
             WHERE rolname = current_user;
            IF migration_is_superuser IS DISTINCT FROM FALSE
               OR migration_bypasses_rls IS DISTINCT FROM FALSE
               OR migration_inherits IS DISTINCT FROM FALSE THEN
                RAISE EXCEPTION
                    'trpc_migration must be NOSUPERUSER NOBYPASSRLS NOINHERIT';
            END IF;
            SELECT pg_catalog.pg_get_userbyid(c.relowner),
                   c.relrowsecurity,
                   c.relforcerowsecurity
              INTO events_owner, events_has_rls, events_forces_rls
              FROM pg_catalog.pg_class AS c
             WHERE c.oid = 'public.cell_events'::pg_catalog.regclass;
            IF events_owner IS DISTINCT FROM current_user
               OR events_has_rls IS DISTINCT FROM TRUE
               OR events_forces_rls IS DISTINCT FROM TRUE THEN
                RAISE EXCEPTION
                    'cell_events must be owned by trpc_migration with FORCE RLS';
            END IF;
        END
        $preflight$;

        CREATE OR REPLACE FUNCTION public.reject_cell_event_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
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
            RAISE EXCEPTION 'cell_events is append-only';
        END
        $function$;

        CREATE FUNCTION public.cleanup_performance_cell_fixture(
            p_tenant_id text,
            p_run_id text,
            p_manifest_checksum text
        )
        RETURNS jsonb
        LANGUAGE plpgsql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        DECLARE
            ownership_key text;
            deleted_effect_receipts integer;
            deleted_effect_ledger integer;
            deleted_tool_intents integer;
            deleted_approval_nonces integer;
            deleted_branch_heads integer;
            deleted_events integer;
            deleted_cells integer;
            deleted_capsules integer;
        BEGIN
            IF session_user <> 'trpc_runtime' THEN
                RAISE EXCEPTION
                    'performance Cell cleanup requires the trpc_runtime session identity'
                    USING ERRCODE = '42501';
            END IF;
            IF current_user <> 'trpc_migration' THEN
                RAISE EXCEPTION
                    'performance Cell cleanup owner contract is unsafe'
                    USING ERRCODE = '42501';
            END IF;
            IF p_tenant_id IS NULL
               OR p_tenant_id !~ '^perf-[0-9a-f]{32}$'
               OR p_run_id IS DISTINCT FROM
                    'perf-fixture-' || pg_catalog.substr(p_tenant_id, 6)
               OR p_manifest_checksum IS NULL
               OR p_manifest_checksum !~ '^[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'performance fixture identity is invalid'
                    USING ERRCODE = '22023';
            END IF;

            PERFORM pg_catalog.set_config('app.tenant_id', p_tenant_id, true);
            ownership_key := p_run_id || ':tenant:' || p_manifest_checksum;
            IF NOT EXISTS (
                SELECT 1
                  FROM public.tenants AS tenant
                  JOIN public.audit_logs AS audit
                    ON audit.tenant_id = tenant.tenant_id
                 WHERE tenant.tenant_id = p_tenant_id
                   AND tenant.display_name = 'Synthetic performance fixture'
                   AND audit.user_id = 'performance-fixture'
                   AND audit.decision = 'tenant_created'
                   AND audit.idempotency_key = ownership_key
                   AND audit.trace_id = 'admin:' || ownership_key
            ) THEN
                RAISE EXCEPTION 'performance fixture ownership proof is missing'
                    USING ERRCODE = '42501';
            END IF;
            IF EXISTS (
                SELECT 1
                  FROM public.cell_placement_reservations
                 WHERE tenant_id = p_tenant_id
            ) THEN
                RAISE EXCEPTION
                    'performance fixture has placement reservations requiring release'
                    USING ERRCODE = '55000';
            END IF;

            PERFORM pg_catalog.set_config(
                'app.performance_fixture_cleanup_tenant', p_tenant_id, true
            );
            DELETE FROM public.cell_effect_receipts WHERE tenant_id = p_tenant_id;
            GET DIAGNOSTICS deleted_effect_receipts = ROW_COUNT;
            DELETE FROM public.cell_effect_ledger WHERE tenant_id = p_tenant_id;
            GET DIAGNOSTICS deleted_effect_ledger = ROW_COUNT;
            DELETE FROM public.cell_tool_intents WHERE tenant_id = p_tenant_id;
            GET DIAGNOSTICS deleted_tool_intents = ROW_COUNT;
            DELETE FROM public.cell_approval_nonces WHERE tenant_id = p_tenant_id;
            GET DIAGNOSTICS deleted_approval_nonces = ROW_COUNT;
            DELETE FROM public.cell_branch_heads WHERE tenant_id = p_tenant_id;
            GET DIAGNOSTICS deleted_branch_heads = ROW_COUNT;
            DELETE FROM public.cell_events WHERE tenant_id = p_tenant_id;
            GET DIAGNOSTICS deleted_events = ROW_COUNT;
            DELETE FROM public.agent_cells WHERE tenant_id = p_tenant_id;
            GET DIAGNOSTICS deleted_cells = ROW_COUNT;
            DELETE FROM public.agent_capsules WHERE tenant_id = p_tenant_id;
            GET DIAGNOSTICS deleted_capsules = ROW_COUNT;

            RETURN pg_catalog.jsonb_build_object(
                'cell_effect_receipts', deleted_effect_receipts,
                'cell_effect_ledger', deleted_effect_ledger,
                'cell_tool_intents', deleted_tool_intents,
                'cell_approval_nonces', deleted_approval_nonces,
                'cell_branch_heads', deleted_branch_heads,
                'cell_events', deleted_events,
                'agent_cells', deleted_cells,
                'agent_capsules', deleted_capsules
            );
        END
        $function$;

        DO $contract$
        DECLARE
            function_owner oid;
            events_owner oid;
            owner_is_superuser boolean;
            owner_bypasses_rls boolean;
            owner_inherits boolean;
            is_security_definer boolean;
            function_config text[];
        BEGIN
            SELECT p.proowner,
                   c.relowner,
                   r.rolsuper,
                   r.rolbypassrls,
                   r.rolinherit,
                   p.prosecdef,
                   p.proconfig
              INTO function_owner,
                   events_owner,
                   owner_is_superuser,
                   owner_bypasses_rls,
                   owner_inherits,
                   is_security_definer,
                   function_config
              FROM pg_catalog.pg_proc AS p
              JOIN pg_catalog.pg_roles AS r ON r.oid = p.proowner
              JOIN pg_catalog.pg_class AS c
                ON c.oid = 'public.cell_events'::pg_catalog.regclass
             WHERE p.oid =
                'public.cleanup_performance_cell_fixture(text,text,text)'
                    ::pg_catalog.regprocedure;
            IF NOT FOUND
               OR function_owner IS DISTINCT FROM events_owner
               OR pg_catalog.pg_get_userbyid(function_owner)
                    IS DISTINCT FROM 'trpc_migration'
               OR owner_is_superuser IS DISTINCT FROM FALSE
               OR owner_bypasses_rls IS DISTINCT FROM FALSE
               OR owner_inherits IS DISTINCT FROM FALSE
               OR is_security_definer IS DISTINCT FROM TRUE
               OR NOT COALESCE('row_security=on' = ANY(function_config), FALSE)
               OR NOT COALESCE(
                    'search_path=pg_catalog, public, pg_temp' = ANY(function_config), FALSE
               ) THEN
                RAISE EXCEPTION 'unsafe performance Cell cleanup function contract';
            END IF;
        END
        $contract$;

        REVOKE ALL ON FUNCTION public.cleanup_performance_cell_fixture(
            text, text, text
        ) FROM PUBLIC;
        DO $grant$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_worker') THEN
                REVOKE ALL ON FUNCTION public.cleanup_performance_cell_fixture(
                    text, text, text
                ) FROM trpc_worker;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_cell_executor') THEN
                REVOKE ALL ON FUNCTION public.cleanup_performance_cell_fixture(
                    text, text, text
                ) FROM trpc_cell_executor;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_scheduler') THEN
                REVOKE ALL ON FUNCTION public.cleanup_performance_cell_fixture(
                    text, text, text
                ) FROM trpc_scheduler;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_metrics') THEN
                REVOKE ALL ON FUNCTION public.cleanup_performance_cell_fixture(
                    text, text, text
                ) FROM trpc_metrics;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_runtime') THEN
                GRANT EXECUTE ON FUNCTION public.cleanup_performance_cell_fixture(
                    text, text, text
                ) TO trpc_runtime;
            END IF;
        END
        $grant$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        REVOKE ALL ON FUNCTION public.cleanup_performance_cell_fixture(
            text, text, text
        ) FROM PUBLIC;
        DO $revoke$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_runtime') THEN
                REVOKE ALL ON FUNCTION public.cleanup_performance_cell_fixture(
                    text, text, text
                ) FROM trpc_runtime;
            END IF;
        END
        $revoke$;
        DROP FUNCTION IF EXISTS public.cleanup_performance_cell_fixture(
            text, text, text
        );

        CREATE OR REPLACE FUNCTION public.reject_cell_event_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $function$
        BEGIN
            RAISE EXCEPTION 'cell_events is append-only';
        END
        $function$;
        """
    )
