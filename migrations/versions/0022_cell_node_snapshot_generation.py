"""Fence node snapshots by a producer-owned positive source revision.

``generation`` remains the database-local fence returned to callers.  The
separate ``observed_generation`` is supplied by the node snapshot producer;
the database accepts only a strictly newer value, so delayed heartbeats
cannot overwrite a newer capacity/health view.
"""

from __future__ import annotations

from alembic import op

revision = "0022_cell_node_snapshot_generation"
down_revision = "0021_performance_reservation_cleanup"
branch_labels = None
depends_on = None


_PREFLIGHT = """
DO $preflight$
DECLARE
    migration_is_superuser boolean;
    migration_bypasses_rls boolean;
    migration_inherits boolean;
    node_owner text;
    node_has_rls boolean;
    node_forces_rls boolean;
BEGIN
    IF current_user <> 'trpc_migration' THEN
        RAISE EXCEPTION
            'migration 0022 must run as the trpc_migration schema owner'
            USING ERRCODE = '42501';
    END IF;
    SELECT rolsuper, rolbypassrls, rolinherit
      INTO migration_is_superuser, migration_bypasses_rls, migration_inherits
      FROM pg_catalog.pg_roles
     WHERE rolname = current_user;
    IF migration_is_superuser IS DISTINCT FROM FALSE
       OR migration_bypasses_rls IS DISTINCT FROM FALSE
       OR migration_inherits IS DISTINCT FROM FALSE THEN
        RAISE EXCEPTION
            'trpc_migration must be NOSUPERUSER NOBYPASSRLS NOINHERIT before migration 0022'
            USING ERRCODE = '42501';
    END IF;
    SELECT pg_catalog.pg_get_userbyid(c.relowner),
           c.relrowsecurity,
           c.relforcerowsecurity
      INTO node_owner, node_has_rls, node_forces_rls
      FROM pg_catalog.pg_class AS c
     WHERE c.oid = 'public.cell_node_capacity'::pg_catalog.regclass;
    IF node_owner IS DISTINCT FROM current_user
       OR node_has_rls IS DISTINCT FROM FALSE
       OR node_forces_rls IS DISTINCT FROM FALSE THEN
        RAISE EXCEPTION
            'cell_node_capacity must be migration-owned and have RLS disabled'
            USING ERRCODE = '42501';
    END IF;
END
$preflight$;
"""


_DROP_OLD_FUNCTIONS = """
DROP FUNCTION IF EXISTS public.update_cell_node_snapshot(
    text, text, bigint, bigint, bigint, boolean, boolean
);
DROP FUNCTION IF EXISTS public.update_cell_node_snapshot(
    bigint, text, text, bigint, bigint, bigint, boolean, boolean
);
"""


_NEW_FUNCTION = """
CREATE FUNCTION public.update_cell_node_snapshot(
    p_observed_generation bigint,
    p_node_id text,
    p_region text,
    p_capacity_cpu_millis bigint,
    p_capacity_memory_mb bigint,
    p_max_cells bigint,
    p_healthy boolean,
    p_draining boolean
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    next_generation bigint;
BEGIN
    IF p_observed_generation IS NULL OR p_observed_generation < 1 THEN
        RAISE EXCEPTION 'observed_generation must be a positive integer'
            USING ERRCODE = '22023';
    END IF;

    INSERT INTO public.cell_node_capacity (
        node_id, region, capacity_cpu_millis,
        capacity_memory_mb, max_cells, healthy, draining,
        observed_generation
    ) VALUES (
        p_node_id, p_region, p_capacity_cpu_millis,
        p_capacity_memory_mb, p_max_cells, p_healthy, p_draining,
        p_observed_generation
    )
    ON CONFLICT (node_id) DO UPDATE SET
        region = EXCLUDED.region,
        capacity_cpu_millis = EXCLUDED.capacity_cpu_millis,
        capacity_memory_mb = EXCLUDED.capacity_memory_mb,
        max_cells = EXCLUDED.max_cells,
        healthy = EXCLUDED.healthy,
        draining = EXCLUDED.draining,
        observed_generation = EXCLUDED.observed_generation,
        generation = cell_node_capacity.generation + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE EXCLUDED.observed_generation > cell_node_capacity.observed_generation
    RETURNING generation INTO next_generation;

    IF NOT FOUND THEN
        -- Duplicate or stale observations are successful no-ops.  Returning
        -- the current local fence lets audit records identify the durable
        -- row even when a delayed heartbeat was rejected.
        SELECT generation
          INTO next_generation
          FROM public.cell_node_capacity
         WHERE node_id = p_node_id;
    END IF;
    RETURN next_generation;
END
$function$;
"""


_LEGACY_SHIM = """
CREATE FUNCTION public.update_cell_node_snapshot(
    p_node_id text,
    p_region text,
    p_capacity_cpu_millis bigint,
    p_capacity_memory_mb bigint,
    p_max_cells bigint,
    p_healthy boolean,
    p_draining boolean
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
BEGIN
    RAISE EXCEPTION
        'legacy 7-argument update_cell_node_snapshot is disabled; '
        'call the 8-argument overload with a positive observed_generation'
        USING ERRCODE = '0A000';
END
$function$;
"""


_GRANTS = """
REVOKE ALL ON FUNCTION public.update_cell_node_snapshot(
    bigint, text, text, bigint, bigint, bigint, boolean, boolean
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.update_cell_node_snapshot(
    text, text, bigint, bigint, bigint, boolean, boolean
) FROM PUBLIC;
DO $scheduler_grant$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'trpc_scheduler') THEN
        GRANT EXECUTE ON FUNCTION public.update_cell_node_snapshot(
            bigint, text, text, bigint, bigint, bigint, boolean, boolean
        ) TO trpc_scheduler;
        -- Keep the old symbol resolvable for rolling deployments, but make it
        -- an explicit fail-closed shim with no write capability.
        GRANT EXECUTE ON FUNCTION public.update_cell_node_snapshot(
            text, text, bigint, bigint, bigint, boolean, boolean
        ) TO trpc_scheduler;
    END IF;
END
$scheduler_grant$;
"""


_CONTRACT = """
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
    new_function constant text :=
        'public.update_cell_node_snapshot(bigint,text,text,bigint,bigint,bigint,boolean,boolean)';
    old_function constant text :=
        'public.update_cell_node_snapshot(text,text,bigint,bigint,bigint,boolean,boolean)';
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
        ON c.oid = 'public.cell_node_capacity'::pg_catalog.regclass
     WHERE p.oid = new_function::pg_catalog.regprocedure;
    IF NOT FOUND
       OR function_owner IS DISTINCT FROM table_owner
       OR pg_catalog.pg_get_userbyid(function_owner)
            IS DISTINCT FROM 'trpc_migration'
       OR owner_is_superuser IS DISTINCT FROM FALSE
       OR owner_bypasses_rls IS DISTINCT FROM FALSE
       OR owner_inherits IS DISTINCT FROM FALSE
       OR table_has_rls IS DISTINCT FROM FALSE
       OR table_forces_rls IS DISTINCT FROM FALSE
       OR is_security_definer IS DISTINCT FROM TRUE
       OR NOT COALESCE(
            'search_path=pg_catalog, public, pg_temp' = ANY(function_config), FALSE
       ) THEN
        RAISE EXCEPTION 'unsafe producer-fenced node snapshot function contract'
            USING ERRCODE = '42501';
    END IF;

    SELECT p.proowner,
           p.prosecdef,
           p.proconfig
      INTO function_owner, is_security_definer, function_config
      FROM pg_catalog.pg_proc AS p
     WHERE p.oid = old_function::pg_catalog.regprocedure;
    IF NOT FOUND
       OR pg_catalog.pg_get_userbyid(function_owner)
            IS DISTINCT FROM 'trpc_migration'
       OR is_security_definer IS DISTINCT FROM TRUE
       OR NOT COALESCE(
            'search_path=pg_catalog, public, pg_temp' = ANY(function_config), FALSE
       ) THEN
        RAISE EXCEPTION 'unsafe legacy node snapshot compatibility shim contract'
            USING ERRCODE = '42501';
    END IF;

    IF EXISTS (
           SELECT 1
             FROM pg_catalog.pg_proc AS acl_proc
             CROSS JOIN LATERAL pg_catalog.aclexplode(
                 COALESCE(
                     acl_proc.proacl,
                     pg_catalog.acldefault('f'::"char", acl_proc.proowner)
                 )
             ) AS acl
            WHERE acl_proc.oid = new_function::pg_catalog.regprocedure
              AND acl.grantee = 0
              AND acl.privilege_type = 'EXECUTE'
       )
       OR EXISTS (
           SELECT 1
             FROM pg_catalog.pg_proc AS acl_proc
             CROSS JOIN LATERAL pg_catalog.aclexplode(
                 COALESCE(
                     acl_proc.proacl,
                     pg_catalog.acldefault('f'::"char", acl_proc.proowner)
                 )
             ) AS acl
            WHERE acl_proc.oid = old_function::pg_catalog.regprocedure
              AND acl.grantee = 0
              AND acl.privilege_type = 'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'node snapshot functions must not be PUBLIC executable'
            USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'trpc_scheduler')
       AND (
           NOT pg_catalog.has_function_privilege('trpc_scheduler', new_function, 'EXECUTE')
           OR NOT pg_catalog.has_function_privilege('trpc_scheduler', old_function, 'EXECUTE')
       ) THEN
        RAISE EXCEPTION 'trpc_scheduler must have both node snapshot function grants'
            USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'trpc_runtime')
       AND (
           pg_catalog.has_function_privilege('trpc_runtime', new_function, 'EXECUTE')
           OR pg_catalog.has_function_privilege('trpc_runtime', old_function, 'EXECUTE')
       ) THEN
        RAISE EXCEPTION 'trpc_runtime must not execute node snapshot functions'
            USING ERRCODE = '42501';
    END IF;
END
$contract$;
"""


_LEGACY_FUNCTION = """
CREATE FUNCTION public.update_cell_node_snapshot(
    p_node_id text,
    p_region text,
    p_capacity_cpu_millis bigint,
    p_capacity_memory_mb bigint,
    p_max_cells bigint,
    p_healthy boolean,
    p_draining boolean
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    next_generation bigint;
BEGIN
    INSERT INTO public.cell_node_capacity (
        node_id, region, capacity_cpu_millis,
        capacity_memory_mb, max_cells, healthy, draining
    ) VALUES (
        p_node_id, p_region, p_capacity_cpu_millis,
        p_capacity_memory_mb, p_max_cells, p_healthy, p_draining
    )
    ON CONFLICT (node_id) DO UPDATE SET
        region = EXCLUDED.region,
        capacity_cpu_millis = EXCLUDED.capacity_cpu_millis,
        capacity_memory_mb = EXCLUDED.capacity_memory_mb,
        max_cells = EXCLUDED.max_cells,
        healthy = EXCLUDED.healthy,
        draining = EXCLUDED.draining,
        generation = cell_node_capacity.generation + 1,
        updated_at = pg_catalog.clock_timestamp()
    RETURNING generation INTO next_generation;
    RETURN next_generation;
END
$function$;
"""


def upgrade() -> None:
    op.execute(_PREFLIGHT)
    op.execute(
        """
        ALTER TABLE public.cell_node_capacity
            ADD COLUMN observed_generation bigint;
        UPDATE public.cell_node_capacity
           SET observed_generation = GREATEST(generation, 1::bigint);
        ALTER TABLE public.cell_node_capacity
            ALTER COLUMN observed_generation SET NOT NULL,
            ADD CONSTRAINT ck_cell_node_observed_generation_positive
                CHECK (observed_generation > 0);
        """
    )
    op.execute(_DROP_OLD_FUNCTIONS)
    op.execute(_NEW_FUNCTION)
    op.execute(_LEGACY_SHIM)
    op.execute(_GRANTS)
    op.execute(_CONTRACT)


def downgrade() -> None:
    op.execute(
        """
        -- DROP removes the function ACL with the function itself.  Keeping
        -- the drops unconditional makes downgrade safe against the earlier
        -- 0022 implementation, which had no legacy seven-argument overload.
        DROP FUNCTION IF EXISTS public.update_cell_node_snapshot(
            bigint, text, text, bigint, bigint, bigint, boolean, boolean
        );
        DROP FUNCTION IF EXISTS public.update_cell_node_snapshot(
            text, text, bigint, bigint, bigint, boolean, boolean
        );
        ALTER TABLE public.cell_node_capacity
            DROP CONSTRAINT IF EXISTS ck_cell_node_observed_generation_positive,
            DROP COLUMN IF EXISTS observed_generation;
        """
    )
    op.execute(_LEGACY_FUNCTION)
    op.execute(
        """
        REVOKE ALL ON FUNCTION public.update_cell_node_snapshot(
            text, text, bigint, bigint, bigint, boolean, boolean
        ) FROM PUBLIC;
        DO $scheduler_grant$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'trpc_scheduler') THEN
                GRANT EXECUTE ON FUNCTION public.update_cell_node_snapshot(
                    text, text, bigint, bigint, bigint, boolean, boolean
                ) TO trpc_scheduler;
            END IF;
        END
        $scheduler_grant$;
        """
    )
