"""Lock a Cell branch head without widening the Worker table grant.

``trpc_worker`` may insert a new branch head, but it must not receive direct
``UPDATE`` privilege on the authoritative CAS row.  This revision exposes the
small row-lock operation needed by the append adapter through a tenant-bound
``SECURITY DEFINER`` function instead.  The transaction-local tenant proof is
checked inside the function to catch accidental namespace mismatches.  The
global Worker is already a cross-tenant identity, so this proof is deliberately
not described as a boundary against a compromised Worker process.
"""

from __future__ import annotations

from alembic import op

revision = "0019_cell_branch_head_lock"
down_revision = "0018_cell_namespace_reservations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $preflight$
        DECLARE
            migration_is_superuser boolean;
            migration_bypasses_rls boolean;
            head_owner text;
            head_has_rls boolean;
            head_forces_rls boolean;
        BEGIN
            IF current_user <> 'trpc_migration' THEN
                RAISE EXCEPTION
                    'migration 0019 must run as the trpc_migration schema owner';
            END IF;
            SELECT rolsuper, rolbypassrls
              INTO migration_is_superuser, migration_bypasses_rls
              FROM pg_catalog.pg_roles
             WHERE rolname = current_user;
            IF migration_is_superuser IS DISTINCT FROM FALSE
               OR migration_bypasses_rls IS DISTINCT FROM FALSE THEN
                RAISE EXCEPTION
                    'trpc_migration must be NOSUPERUSER NOBYPASSRLS before migration 0019';
            END IF;
            SELECT pg_catalog.pg_get_userbyid(c.relowner),
                   c.relrowsecurity,
                   c.relforcerowsecurity
              INTO head_owner, head_has_rls, head_forces_rls
              FROM pg_catalog.pg_class AS c
             WHERE c.oid = 'public.cell_branch_heads'::pg_catalog.regclass;
            IF head_owner IS DISTINCT FROM current_user
               OR head_has_rls IS DISTINCT FROM TRUE
               OR head_forces_rls IS DISTINCT FROM TRUE THEN
                RAISE EXCEPTION
                    'cell_branch_heads must be owned by trpc_migration with RLS and FORCE RLS';
            END IF;
        END
        $preflight$;

        CREATE FUNCTION public.lock_cell_branch_head(
            p_tenant_id text,
            p_app_id text,
            p_cell_id text,
            p_session_id text,
            p_capsule_digest text,
            p_branch_id text
        )
        RETURNS TABLE (
            last_sequence bigint,
            last_event_hash text,
            lease_owner text,
            lease_epoch bigint,
            lease_expires_at timestamptz,
            lease_valid boolean
        )
        LANGUAGE plpgsql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        DECLARE
            scoped_tenant text;
        BEGIN
            IF session_user <> 'trpc_worker' THEN
                RAISE EXCEPTION
                    'branch head lock requires the trpc_worker session identity'
                    USING ERRCODE = '42501';
            END IF;
            IF current_user <> 'trpc_migration' THEN
                RAISE EXCEPTION
                    'branch head lock owner contract is unsafe'
                    USING ERRCODE = '42501';
            END IF;
            scoped_tenant := nullif(
                pg_catalog.current_setting('app.tenant_id', true), ''
            );
            IF p_tenant_id IS NULL
               OR pg_catalog.btrim(p_tenant_id) = ''
               OR scoped_tenant IS DISTINCT FROM p_tenant_id THEN
                RAISE EXCEPTION
                    'tenant scope does not match branch head lock request'
                    USING ERRCODE = '42501';
            END IF;

            RETURN QUERY
            SELECT head.last_sequence,
                   head.last_event_hash,
                   head.lease_owner,
                   head.lease_epoch,
                   head.lease_expires_at,
                   head.lease_expires_at > pg_catalog.clock_timestamp() AS lease_valid
              FROM public.cell_branch_heads AS head
             WHERE head.tenant_id = p_tenant_id
               AND head.app_id = p_app_id
               AND head.cell_id = p_cell_id
               AND head.session_id = p_session_id
               AND head.capsule_digest = p_capsule_digest
               AND head.branch_id = p_branch_id
             FOR UPDATE OF head;
        END
        $function$;

        DO $contract$
        DECLARE
            function_owner oid;
            table_owner oid;
            owner_is_superuser boolean;
            owner_bypasses_rls boolean;
            owner_inherits boolean;
            table_has_rls boolean;
            table_forces_rls boolean;
            is_security_definer boolean;
            function_config text[];
        BEGIN
            SELECT p.proowner,
                   c.relowner,
                   r.rolsuper,
                   r.rolbypassrls,
                   r.rolinherit,
                   c.relrowsecurity,
                   c.relforcerowsecurity,
                   p.prosecdef,
                   p.proconfig
              INTO function_owner,
                   table_owner,
                   owner_is_superuser,
                   owner_bypasses_rls,
                   owner_inherits,
                   table_has_rls,
                   table_forces_rls,
                   is_security_definer,
                   function_config
              FROM pg_catalog.pg_proc AS p
              JOIN pg_catalog.pg_roles AS r ON r.oid = p.proowner
              JOIN pg_catalog.pg_class AS c
                ON c.oid = 'public.cell_branch_heads'::pg_catalog.regclass
             WHERE p.oid = 'public.lock_cell_branch_head(text,text,text,text,text,text)'
                    ::pg_catalog.regprocedure;
            IF NOT FOUND
               OR function_owner IS DISTINCT FROM table_owner
               OR pg_catalog.pg_get_userbyid(function_owner)
                    IS DISTINCT FROM 'trpc_migration'
               OR owner_is_superuser IS DISTINCT FROM FALSE
               OR owner_bypasses_rls IS DISTINCT FROM FALSE
               OR owner_inherits IS DISTINCT FROM FALSE
               OR table_has_rls IS DISTINCT FROM TRUE
               OR table_forces_rls IS DISTINCT FROM TRUE
               OR is_security_definer IS DISTINCT FROM TRUE
               OR NOT COALESCE(
                    'row_security=on' = ANY(function_config), FALSE
               )
               OR NOT COALESCE(
                    'search_path=pg_catalog, public, pg_temp' = ANY(function_config), FALSE
               ) THEN
                RAISE EXCEPTION 'unsafe branch head lock function contract';
            END IF;
        END
        $contract$;

        -- A SECURITY DEFINER function is an explicit privilege boundary.  Do
        -- not leave the default PUBLIC EXECUTE grant in place, and do not
        -- grant the lock capability to the ordinary runtime or executor
        -- identities.  The worker role is provisioned by 0014/0015.
        REVOKE ALL ON FUNCTION public.lock_cell_branch_head(
            text, text, text, text, text, text
        ) FROM PUBLIC;
        DO $grant$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_runtime') THEN
                REVOKE ALL ON FUNCTION public.lock_cell_branch_head(
                    text, text, text, text, text, text
                ) FROM trpc_runtime;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_cell_executor') THEN
                REVOKE ALL ON FUNCTION public.lock_cell_branch_head(
                    text, text, text, text, text, text
                ) FROM trpc_cell_executor;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_scheduler') THEN
                REVOKE ALL ON FUNCTION public.lock_cell_branch_head(
                    text, text, text, text, text, text
                ) FROM trpc_scheduler;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_metrics') THEN
                REVOKE ALL ON FUNCTION public.lock_cell_branch_head(
                    text, text, text, text, text, text
                ) FROM trpc_metrics;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_worker') THEN
                GRANT EXECUTE ON FUNCTION public.lock_cell_branch_head(
                    text, text, text, text, text, text
                ) TO trpc_worker;
            END IF;
        END
        $grant$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        REVOKE ALL ON FUNCTION public.lock_cell_branch_head(
            text, text, text, text, text, text
        ) FROM PUBLIC;
        DO $revoke$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_worker') THEN
                REVOKE ALL ON FUNCTION public.lock_cell_branch_head(
                    text, text, text, text, text, text
                ) FROM trpc_worker;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_runtime') THEN
                REVOKE ALL ON FUNCTION public.lock_cell_branch_head(
                    text, text, text, text, text, text
                ) FROM trpc_runtime;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_cell_executor') THEN
                REVOKE ALL ON FUNCTION public.lock_cell_branch_head(
                    text, text, text, text, text, text
                ) FROM trpc_cell_executor;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_scheduler') THEN
                REVOKE ALL ON FUNCTION public.lock_cell_branch_head(
                    text, text, text, text, text, text
                ) FROM trpc_scheduler;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_metrics') THEN
                REVOKE ALL ON FUNCTION public.lock_cell_branch_head(
                    text, text, text, text, text, text
                ) FROM trpc_metrics;
            END IF;
        END
        $revoke$;
        DROP FUNCTION IF EXISTS public.lock_cell_branch_head(
            text, text, text, text, text, text
        );
        """
    )
