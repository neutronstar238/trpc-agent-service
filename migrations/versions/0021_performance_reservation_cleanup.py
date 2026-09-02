"""Make synthetic Cell fixture cleanup reservation- and capacity-safe.

Revision 0020 correctly refused to remove a fixture while any placement
reservation existed.  That left a bounded performance run unable to clean up
after an expired lease, and it also left the cleanup path unable to repair a
capacity counter after a process died between reservation transitions.

This revision keeps the same narrow runtime-only SECURITY DEFINER boundary,
but serializes cleanup with placement operations, rejects unexpired active
reservations, expires stale active rows, removes released/expired rows, and
reconciles every node counter from the remaining active reservations.
"""

from __future__ import annotations

from alembic import op

revision = "0021_performance_reservation_cleanup"
down_revision = "0020_performance_cell_cleanup"
branch_labels = None
depends_on = None


_PREFLIGHT = """
DO $preflight$
DECLARE
    migration_is_superuser boolean;
    migration_bypasses_rls boolean;
    migration_inherits boolean;
    reservation_owner text;
    reservation_has_rls boolean;
    reservation_forces_rls boolean;
BEGIN
    IF current_user <> 'trpc_migration' THEN
        RAISE EXCEPTION
            'migration 0021 must run as the trpc_migration schema owner'
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
            'trpc_migration must be NOSUPERUSER NOBYPASSRLS NOINHERIT before migration 0021'
            USING ERRCODE = '42501';
    END IF;
    SELECT pg_catalog.pg_get_userbyid(c.relowner),
           c.relrowsecurity,
           c.relforcerowsecurity
      INTO reservation_owner, reservation_has_rls, reservation_forces_rls
      FROM pg_catalog.pg_class AS c
     WHERE c.oid = 'public.cell_placement_reservations'::pg_catalog.regclass;
    IF reservation_owner IS DISTINCT FROM current_user
       OR reservation_has_rls IS DISTINCT FROM TRUE
       OR reservation_forces_rls IS DISTINCT FROM FALSE THEN
        RAISE EXCEPTION
            'cell_placement_reservations must be migration-owned with RLS and without FORCE RLS'
            USING ERRCODE = '42501';
    END IF;
END
$preflight$;
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
    function_name constant text :=
        'public.cleanup_performance_cell_fixture(text,text,text)';
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
        ON c.oid = 'public.cell_placement_reservations'::pg_catalog.regclass
     WHERE p.oid = function_name::pg_catalog.regprocedure;
    IF NOT FOUND
       OR function_owner IS DISTINCT FROM table_owner
       OR pg_catalog.pg_get_userbyid(function_owner)
            IS DISTINCT FROM 'trpc_migration'
       OR owner_is_superuser IS DISTINCT FROM FALSE
       OR owner_bypasses_rls IS DISTINCT FROM FALSE
       OR owner_inherits IS DISTINCT FROM FALSE
       OR table_has_rls IS DISTINCT FROM TRUE
       OR table_forces_rls IS DISTINCT FROM FALSE
       OR is_security_definer IS DISTINCT FROM TRUE
       OR NOT COALESCE(
            'row_security=on' = ANY(function_config), FALSE
       )
       OR NOT COALESCE(
            'search_path=pg_catalog, public, pg_temp' = ANY(function_config), FALSE
       ) THEN
        RAISE EXCEPTION 'unsafe performance reservation cleanup function contract'
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
            WHERE acl_proc.oid = function_name::pg_catalog.regprocedure
              AND acl.grantee = 0
              AND acl.privilege_type = 'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'performance reservation cleanup must not be PUBLIC executable'
            USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'trpc_runtime')
       AND NOT pg_catalog.has_function_privilege(
           'trpc_runtime', function_name, 'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'trpc_runtime must execute performance reservation cleanup'
            USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'trpc_worker')
       AND pg_catalog.has_function_privilege(
           'trpc_worker', function_name, 'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'trpc_worker must not execute performance reservation cleanup'
            USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'trpc_cell_executor')
       AND pg_catalog.has_function_privilege(
           'trpc_cell_executor', function_name, 'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'trpc_cell_executor must not execute performance reservation cleanup'
            USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'trpc_scheduler')
       AND pg_catalog.has_function_privilege(
           'trpc_scheduler', function_name, 'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'trpc_scheduler must not execute performance reservation cleanup'
            USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'trpc_metrics')
       AND pg_catalog.has_function_privilege(
           'trpc_metrics', function_name, 'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'trpc_metrics must not execute performance reservation cleanup'
            USING ERRCODE = '42501';
    END IF;
END
$contract$;
"""


_FIXED_CLEANUP_FUNCTION = """
CREATE OR REPLACE FUNCTION public.cleanup_performance_cell_fixture(
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
    v_now_at timestamptz;
    v_node_id text;
    deleted_effect_receipts integer;
    deleted_effect_ledger integer;
    deleted_tool_intents integer;
    deleted_approval_nonces integer;
    deleted_placement_reservations integer;
    deleted_branch_heads integer;
    deleted_events integer;
    deleted_cells integer;
    deleted_capsules integer;
    active_cpu bigint;
    active_memory bigint;
    v_active_cells bigint;
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

    -- Every reserve/release transition locks its node before touching a
    -- reservation row.  Locking all nodes in node_id order gives cleanup the
    -- same global order and prevents a new reservation from racing the
    -- expiry, delete, or counter-reconciliation steps below.
    PERFORM 1
      FROM public.cell_node_capacity AS capacity
     ORDER BY capacity.node_id
     FOR UPDATE;
    PERFORM 1
      FROM public.cell_placement_reservations AS reservation
     WHERE reservation.tenant_id = p_tenant_id
     ORDER BY reservation.reservation_id
     FOR UPDATE;

    v_now_at := clock_timestamp();
    IF EXISTS (
        SELECT 1
          FROM public.cell_placement_reservations AS reservation
         WHERE reservation.tenant_id = p_tenant_id
           AND reservation.status = 'active'
           AND reservation.expires_at > v_now_at
    ) THEN
        RAISE EXCEPTION
            'performance fixture has placement reservations requiring release: active lease is unexpired'
            USING ERRCODE = '55000';
    END IF;

    -- An active row whose lease has elapsed still owns capacity until this
    -- transition.  Mark it expired before deletion so its resources are no
    -- longer considered active by the reconciliation query.
    UPDATE public.cell_placement_reservations
       SET status = 'expired', updated_at = v_now_at
     WHERE tenant_id = p_tenant_id
       AND status = 'active'
       AND expires_at <= v_now_at;

    DELETE FROM public.cell_placement_reservations
     WHERE tenant_id = p_tenant_id
       AND status IN ('released', 'expired');
    GET DIAGNOSTICS deleted_placement_reservations = ROW_COUNT;

    -- Rebuild counters from the authoritative surviving active rows while
    -- every capacity row remains locked.  This repairs counters left behind
    -- by a crashed release/expiry transition and preserves other tenants'
    -- active reservations on the same node.
    FOR v_node_id IN
        SELECT capacity.node_id
          FROM public.cell_node_capacity AS capacity
         ORDER BY capacity.node_id
    LOOP
        SELECT COALESCE(pg_catalog.sum(reservation.cpu_millis), 0)::bigint,
               COALESCE(pg_catalog.sum(reservation.memory_mb), 0)::bigint,
               pg_catalog.count(*)::bigint
          INTO active_cpu, active_memory, v_active_cells
          FROM public.cell_placement_reservations AS reservation
         WHERE reservation.node_id = v_node_id
           AND reservation.status = 'active';

        UPDATE public.cell_node_capacity AS capacity
           SET used_cpu_millis = active_cpu,
               used_memory_mb = active_memory,
               active_cells = v_active_cells,
               updated_at = pg_catalog.clock_timestamp()
         WHERE capacity.node_id = v_node_id;
    END LOOP;

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
        'cell_placement_reservations', deleted_placement_reservations,
        'cell_branch_heads', deleted_branch_heads,
        'cell_events', deleted_events,
        'agent_cells', deleted_cells,
        'agent_capsules', deleted_capsules
    );
END
$function$;
"""


_LEGACY_CLEANUP_FUNCTION = """
CREATE OR REPLACE FUNCTION public.cleanup_performance_cell_fixture(
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
    deleted_placement_reservations integer := 0;
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
        'cell_placement_reservations', deleted_placement_reservations,
        'cell_branch_heads', deleted_branch_heads,
        'cell_events', deleted_events,
        'agent_cells', deleted_cells,
        'agent_capsules', deleted_capsules
    );
END
$function$;
"""


def upgrade() -> None:
    op.execute(_PREFLIGHT)
    op.execute(_FIXED_CLEANUP_FUNCTION)
    op.execute(_CONTRACT)


def downgrade() -> None:
    op.execute(_LEGACY_CLEANUP_FUNCTION)
