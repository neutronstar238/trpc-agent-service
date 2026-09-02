"""Add the least-privilege HPA fixture and cleanup database boundary.

The bounded HPA probe is deliberately not a worker.  It receives only the
``trpc_hpa`` login and can execute these two tenant/nonce-scoped functions;
all table DML stays in this migration-owned ``SECURITY DEFINER`` boundary.
The cleanup function returns a receipt containing every tenant-bearing table
in the current schema, so a caller cannot mistake a partial cleanup for a
successful acceptance run.
"""

from __future__ import annotations

from alembic import op

# The SQL text is assembled only from the module-level closed table tuple;
# Ruff's generic string-SQL heuristic cannot see that allowlist proof.
# ruff: noqa: S608

revision = "0023_hpa_fixture_boundary"
down_revision = "0022_cell_node_snapshot_generation"
branch_labels = None
depends_on = None


# This list is intentionally duplicated in the probe's receipt validator.
# Keep child tables before parents; the SQL function is the authority.
_TENANT_TABLES = (
    "cell_effect_receipts",
    "cell_effect_ledger",
    "cell_tool_intents",
    "cell_branch_heads",
    "cell_placement_reservations",
    "cell_approval_nonces",
    "cell_events",
    "agent_cells",
    "agent_capsules",
    "session_mailbox_items",
    "delivery_attempts",
    "outbox_events",
    "turn_intents",
    "session_events",
    "session_summaries",
    "tool_executions",
    "session_turns",
    "inbound_messages",
    "outbound_messages",
    "knowledge_embeddings",
    "knowledge_items",
    "artifacts",
    "memories",
    "dead_letters",
    "confirmation_challenges",
    "audit_logs",
    "tenant_budget_usage",
    "fault_stage_controls",
    "migration_write_barriers",
    "migration_leases",
    "migration_checkpoints",
    "admin_idempotency",
    "channel_identities",
    "channel_bindings",
    "config_revisions",
    "tenant_policies",
    "storage_profiles",
    "session_mailboxes",
    "sessions",
    "agent_apps",
    "migration_scope_manifests",
    "tenants",
)

_TABLE_ARRAY = (
    "ARRAY[\n            "
    + ",\n            ".join(repr(table) for table in _TENANT_TABLES)
    + "\n        ]::text[]"
)


def _role_preflight() -> str:
    return """
        DO $roles$
        DECLARE
            role_name text;
            role_oid oid;
            can_login boolean;
            is_superuser boolean;
            can_create_database boolean;
            can_create_role boolean;
            inherits boolean;
            bypasses_rls boolean;
        BEGIN
            FOREACH role_name IN ARRAY ARRAY['trpc_hpa', 'trpc_metrics'] LOOP
                SELECT oid, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole,
                       rolinherit, rolbypassrls
                  INTO role_oid, can_login, is_superuser, can_create_database,
                       can_create_role, inherits, bypasses_rls
                  FROM pg_catalog.pg_roles
                 WHERE rolname = role_name;
                IF NOT FOUND THEN
                    RAISE EXCEPTION
                        '% role must be provisioned before migration 0023',
                        role_name
                        USING ERRCODE = '42501';
                END IF;
                IF can_login IS DISTINCT FROM TRUE
                   OR is_superuser IS DISTINCT FROM FALSE
                   OR can_create_database IS DISTINCT FROM FALSE
                   OR can_create_role IS DISTINCT FROM FALSE
                   OR inherits IS DISTINCT FROM FALSE
                   OR bypasses_rls IS DISTINCT FROM FALSE THEN
                    RAISE EXCEPTION
                        '% must be LOGIN NOSUPERUSER NOCREATEDB '
                        'NOCREATEROLE NOINHERIT NOBYPASSRLS',
                        role_name
                        USING ERRCODE = '42501';
                END IF;
                -- A direct or transitive membership gives the role a possible
                -- SET ROLE path.  Reject all such paths even when NOINHERIT is
                -- set; NOINHERIT does not make an explicitly requested role
                -- switch safe for this database boundary.
                IF EXISTS (
                    WITH RECURSIVE reachable_roles(role_id) AS (
                        SELECT role_oid
                        UNION
                        SELECT membership.roleid
                          FROM pg_catalog.pg_auth_members AS membership
                          JOIN reachable_roles AS reachable
                            ON reachable.role_id = membership.member
                    )
                    SELECT 1
                      FROM reachable_roles
                     WHERE role_id <> role_oid
                ) THEN
                    RAISE EXCEPTION
                        '% must not have a direct or transitive SET ROLE membership',
                        role_name
                        USING ERRCODE = '42501';
                END IF;
            END LOOP;
        END
        $roles$;
    """


def _cleanup_function() -> str:
    tables = _TABLE_ARRAY
    return f"""
        CREATE FUNCTION public.cleanup_hpa_fixture(p_nonce text)
        RETURNS jsonb
        LANGUAGE plpgsql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        DECLARE
            v_tenant_id text;
            table_name text;
            deleted_count bigint;
            residual_count bigint;
            deleted jsonb := '{{}}'::jsonb;
            residual jsonb := '{{}}'::jsonb;
            tenant_exists boolean := false;
        BEGIN
            IF session_user <> 'trpc_hpa' THEN
                RAISE EXCEPTION
                    'HPA fixture cleanup requires the trpc_hpa session identity'
                    USING ERRCODE = '42501';
            END IF;
            IF current_user <> 'trpc_migration' THEN
                RAISE EXCEPTION
                    'HPA fixture cleanup owner contract is unsafe'
                    USING ERRCODE = '42501';
            END IF;
            IF p_nonce IS NULL OR p_nonce !~ '^[0-9a-f]{{32}}$' THEN
                RAISE EXCEPTION 'HPA fixture nonce is invalid'
                    USING ERRCODE = '22023';
            END IF;

            v_tenant_id := 'hpa-' || p_nonce;
            PERFORM pg_catalog.set_config('app.tenant_id', v_tenant_id, true);
            SELECT EXISTS (
                SELECT 1
                  FROM public.tenants
                 WHERE tenants.tenant_id = v_tenant_id
            ) INTO tenant_exists;

            IF tenant_exists AND NOT EXISTS (
                SELECT 1
                  FROM public.tenants AS tenant
                  JOIN public.agent_apps AS app
                    ON app.tenant_id = tenant.tenant_id
                 WHERE tenant.tenant_id = v_tenant_id
                   AND tenant.display_name = 'Bounded HPA backlog probe'
                   AND app.app_id = 'hpa-probe'
            ) THEN
                RAISE EXCEPTION 'HPA fixture ownership proof is missing'
                    USING ERRCODE = '42501';
            END IF;
            IF tenant_exists AND NOT EXISTS (
                SELECT 1
                  FROM public.config_revisions AS config
                 WHERE config.tenant_id = v_tenant_id
                   AND config.app_id = 'hpa-probe'
                   AND config.version = 1
                   AND config.config_json->>'nonce' = p_nonce
            ) THEN
                RAISE EXCEPTION 'HPA fixture configuration proof is missing'
                    USING ERRCODE = '42501';
            END IF;

            -- These rows are not produced by the probe.  Refuse to guess how
            -- to repair global placement counters or append-only event
            -- history if another component wrote under this nonce.
            IF EXISTS (
                SELECT 1 FROM public.cell_placement_reservations
                 WHERE cell_placement_reservations.tenant_id = v_tenant_id
            ) THEN
                RAISE EXCEPTION 'HPA fixture has unexpected placement reservations'
                    USING ERRCODE = '55000';
            END IF;
            IF EXISTS (
                SELECT 1 FROM public.cell_events
                 WHERE cell_events.tenant_id = v_tenant_id
            ) THEN
                RAISE EXCEPTION 'HPA fixture has unexpected append-only cell events'
                    USING ERRCODE = '55000';
            END IF;
            IF EXISTS (
                SELECT 1 FROM public.migration_write_barriers
                 WHERE migration_write_barriers.tenant_id = v_tenant_id
            ) THEN
                RAISE EXCEPTION 'HPA fixture has an active migration barrier'
                    USING ERRCODE = '55000';
            END IF;

            FOREACH table_name IN ARRAY {tables} LOOP
                EXECUTE pg_catalog.format(
                    'DELETE FROM public.%I WHERE tenant_id = $1', table_name
                ) USING v_tenant_id;
                GET DIAGNOSTICS deleted_count = ROW_COUNT;
                deleted := deleted || pg_catalog.jsonb_build_object(
                    table_name, deleted_count
                );
            END LOOP;

            FOREACH table_name IN ARRAY {tables} LOOP
                EXECUTE pg_catalog.format(
                    'SELECT count(*) FROM public.%I WHERE tenant_id = $1', table_name
                ) INTO residual_count USING v_tenant_id;
                IF residual_count < 0 THEN
                    RAISE EXCEPTION 'HPA fixture residual count is invalid'
                        USING ERRCODE = '55000';
                END IF;
                residual := residual || pg_catalog.jsonb_build_object(
                    table_name, residual_count
                );
                IF residual_count <> 0 THEN
                    RAISE EXCEPTION
                        'HPA fixture cleanup left residual rows in %', table_name
                        USING ERRCODE = '55000';
                END IF;
            END LOOP;

            RETURN pg_catalog.jsonb_build_object(
                'schema_version', 1,
                'status', 'pass',
                'phase', 'clear',
                'run_nonce', p_nonce,
                'tenant_id', v_tenant_id,
                'already_absent', NOT tenant_exists,
                'deleted', deleted,
                'residual', residual
            );
        END
        $function$;
    """


def _prepare_function() -> str:
    return """
        CREATE FUNCTION public.prepare_hpa_fixture(
            p_nonce text,
            p_rows integer
        )
        RETURNS jsonb
        LANGUAGE plpgsql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        DECLARE
            v_tenant_id text;
            binding_id text;
            account_id text;
            session_id text;
            principal_id text;
            inbound_id uuid;
            trace_id text;
            external_message_id text;
            request_id text;
            config_checksum text;
            index_value integer;
        BEGIN
            IF session_user <> 'trpc_hpa' THEN
                RAISE EXCEPTION
                    'HPA fixture preparation requires the trpc_hpa session identity'
                    USING ERRCODE = '42501';
            END IF;
            IF current_user <> 'trpc_migration' THEN
                RAISE EXCEPTION
                    'HPA fixture preparation owner contract is unsafe'
                    USING ERRCODE = '42501';
            END IF;
            IF p_nonce IS NULL OR p_nonce !~ '^[0-9a-f]{32}$' THEN
                RAISE EXCEPTION 'HPA fixture nonce is invalid'
                    USING ERRCODE = '22023';
            END IF;
            IF p_rows IS NULL OR p_rows < 1 OR p_rows > 256 THEN
                RAISE EXCEPTION 'HPA fixture row count is outside the safe bound'
                    USING ERRCODE = '22023';
            END IF;

            v_tenant_id := 'hpa-' || p_nonce;
            binding_id := 'hpa-binding-' || p_nonce;
            account_id := 'hpa-account-' || p_nonce;
            config_checksum := encode(
                digest(('hpa-probe:' || p_nonce)::text, 'sha256'), 'hex'
            );
            PERFORM pg_catalog.set_config('app.tenant_id', v_tenant_id, true);

            -- A repeated nonce is recoverable only through the same audited
            -- ownership boundary.  The cleanup function is atomic with the
            -- following inserts because both run in the caller's transaction.
            IF EXISTS (
                SELECT 1 FROM public.tenants
                 WHERE tenants.tenant_id = v_tenant_id
            ) THEN
                PERFORM public.cleanup_hpa_fixture(p_nonce);
            END IF;

            INSERT INTO public.tenants (tenant_id, display_name)
            VALUES (v_tenant_id, 'Bounded HPA backlog probe');
            INSERT INTO public.agent_apps (
                tenant_id, app_id, display_name, active_config_version
            ) VALUES (
                v_tenant_id, 'hpa-probe', 'Bounded HPA probe app', 1
            );
            INSERT INTO public.config_revisions (
                tenant_id, app_id, version, config_json, checksum, created_by
            ) VALUES (
                v_tenant_id,
                'hpa-probe',
                1,
                pg_catalog.jsonb_build_object(
                    'kind', 'hpa-backlog-probe',
                    'synthetic', true,
                    'nonce', p_nonce,
                    'model', pg_catalog.jsonb_build_object('provider', 'none')
                ),
                config_checksum,
                'hpa-backlog-probe'
            );
            INSERT INTO public.channel_bindings (
                tenant_id, binding_id, app_id, channel, account_id,
                secret_refs, capabilities
            ) VALUES (
                v_tenant_id, binding_id, 'hpa-probe', 'wecom_ai_bot', account_id,
                '{}'::jsonb, '[]'::jsonb
            );

            FOR index_value IN 0..p_rows - 1 LOOP
                session_id := 'hpa-' || pg_catalog.substr(p_nonce, 1, 16)
                    || '-' || pg_catalog.lpad(index_value::text, 3, '0');
                principal_id := 'hpa-probe-principal-'
                    || pg_catalog.lpad(index_value::text, 3, '0');
                inbound_id := gen_random_uuid();
                trace_id := 'hpa-probe-trace-' || p_nonce || '-'
                    || pg_catalog.lpad(index_value::text, 3, '0');
                external_message_id := 'hpa-probe-message-' || p_nonce || '-'
                    || pg_catalog.lpad(index_value::text, 3, '0');
                request_id := 'hpa-probe-request-' || p_nonce || '-'
                    || pg_catalog.lpad(index_value::text, 3, '0');

                INSERT INTO public.sessions (
                    tenant_id, session_id, app_id, principal_id, state_json
                ) VALUES (v_tenant_id, session_id, 'hpa-probe', principal_id, '{}'::jsonb);
                INSERT INTO public.inbound_messages (
                    tenant_id, inbound_id, binding_id, app_id, config_version,
                    channel, account_id, external_message_id, principal_id,
                    session_id, request_id, trace_id, envelope_json
                ) VALUES (
                    v_tenant_id, inbound_id, binding_id, 'hpa-probe', 1,
                    'wecom_ai_bot', account_id, external_message_id,
                    principal_id, session_id, request_id, trace_id,
                    pg_catalog.jsonb_build_object(
                        'text', 'bounded hpa backlog',
                        'synthetic', true,
                        'nonce', p_nonce,
                        'index', index_value
                    )
                );
                INSERT INTO public.session_mailboxes (
                    tenant_id, session_id, status, accepted_sequence,
                    resolved_sequence, queue_generation, priority
                ) VALUES (v_tenant_id, session_id, 'QUEUED', 1, 0, 1, 1);
                INSERT INTO public.session_mailbox_items (
                    tenant_id, session_id, sequence, inbound_id, trace_id, priority
                ) VALUES (v_tenant_id, session_id, 1, inbound_id, trace_id, 1);
                INSERT INTO public.outbox_events (
                    tenant_id, aggregate_type, aggregate_id, event_type,
                    payload_json, trace_headers, available_at
                ) VALUES (
                    v_tenant_id, 'session', session_id, 'session.ready.v2',
                    pg_catalog.jsonb_build_object(
                        'generation', 1,
                        'priority', 1,
                        'trace_id', trace_id,
                        'created_at', pg_catalog.clock_timestamp()::text
                    ),
                    pg_catalog.jsonb_build_object('trace_id', trace_id),
                    pg_catalog.clock_timestamp() + interval '1 day'
                );
            END LOOP;

            RETURN pg_catalog.jsonb_build_object(
                'schema_version', 1,
                'status', 'pass',
                'phase', 'prepare',
                'run_nonce', p_nonce,
                'tenant_id', v_tenant_id,
                'seeded_rows', p_rows
            );
        END
        $function$;
    """


def _tenant_backlog_function() -> str:
    return """
        CREATE FUNCTION public.count_session_ready_backlog_for_tenant(
            p_tenant_id text
        )
        RETURNS bigint
        LANGUAGE plpgsql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        BEGIN
            IF session_user <> 'trpc_metrics' THEN
                RAISE EXCEPTION
                    'tenant backlog metric requires the trpc_metrics session identity'
                    USING ERRCODE = '42501';
            END IF;
            IF p_tenant_id IS NULL OR p_tenant_id !~ '^hpa-[0-9a-f]{32}$' THEN
                RAISE EXCEPTION 'HPA metric tenant is invalid'
                    USING ERRCODE = '22023';
            END IF;
            PERFORM pg_catalog.set_config('app.tenant_id', p_tenant_id, true);
            RETURN (
                SELECT count(*)::bigint
                  FROM public.session_mailboxes
                 WHERE session_mailboxes.tenant_id = p_tenant_id
                   AND status = 'QUEUED'
                   AND accepted_sequence > resolved_sequence
                   AND (
                       retry_at IS NULL
                       OR retry_at <= pg_catalog.clock_timestamp()
                   )
            );
        END
        $function$;
    """


def _contracts() -> str:
    tables = _TABLE_ARRAY
    return f"""
        REVOKE ALL ON FUNCTION public.prepare_hpa_fixture(text, integer) FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.prepare_hpa_fixture(text, integer)
            FROM trpc_runtime, trpc_worker, trpc_metrics;
        REVOKE ALL ON FUNCTION public.cleanup_hpa_fixture(text) FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.cleanup_hpa_fixture(text)
            FROM trpc_runtime, trpc_worker, trpc_metrics;
        REVOKE ALL ON FUNCTION public.count_session_ready_backlog_for_tenant(text)
            FROM PUBLIC, trpc_runtime, trpc_worker, trpc_hpa;
        GRANT USAGE ON SCHEMA public TO trpc_hpa, trpc_metrics;
        GRANT EXECUTE ON FUNCTION public.prepare_hpa_fixture(text, integer)
            TO trpc_hpa;
        GRANT EXECUTE ON FUNCTION public.cleanup_hpa_fixture(text)
            TO trpc_hpa;
        GRANT EXECUTE ON FUNCTION public.count_session_ready_backlog_for_tenant(text)
            TO trpc_metrics;

        DO $contract$
        DECLARE
            owner_name text;
            is_security_definer boolean;
            function_config text[];
            function_name text;
        BEGIN
            -- Make schema drift fail closed.  Every public table carrying a
            -- tenant_id must be represented by the receipt allowlist; the
            -- node-capacity ledger is intentionally global and has no such
            -- column.
            IF EXISTS (
                SELECT 1
                  FROM information_schema.columns AS column_info
                  JOIN information_schema.tables AS table_info
                    ON table_info.table_schema = column_info.table_schema
                   AND table_info.table_name = column_info.table_name
                 WHERE column_info.table_schema = 'public'
                   AND column_info.column_name = 'tenant_id'
                   AND table_info.table_type = 'BASE TABLE'
                   AND column_info.table_name <> 'cell_node_capacity'
                   AND column_info.table_name <> ALL({tables})
            ) THEN
                RAISE EXCEPTION
                    'HPA cleanup allowlist omits a tenant-bearing public table'
                    USING ERRCODE = '42501';
            END IF;
            IF EXISTS (
                SELECT 1
                  FROM pg_catalog.unnest({tables}) AS expected(table_name)
                  LEFT JOIN information_schema.tables AS present
                    ON present.table_schema = 'public'
                   AND present.table_name = expected.table_name
                 WHERE present.table_name IS NULL
                    OR present.table_type <> 'BASE TABLE'
            ) THEN
                RAISE EXCEPTION
                    'HPA cleanup allowlist names a missing public table'
                    USING ERRCODE = '42501';
            END IF;
            FOREACH function_name IN ARRAY ARRAY[
                'public.prepare_hpa_fixture(text,integer)',
                'public.cleanup_hpa_fixture(text)',
                'public.count_session_ready_backlog_for_tenant(text)'
            ] LOOP
                SELECT pg_catalog.pg_get_userbyid(proc.proowner),
                       proc.prosecdef, proc.proconfig
                  INTO owner_name, is_security_definer, function_config
                  FROM pg_catalog.pg_proc AS proc
                 WHERE proc.oid = function_name::pg_catalog.regprocedure;
                IF NOT FOUND
                   OR owner_name IS DISTINCT FROM 'trpc_migration'
                   OR is_security_definer IS DISTINCT FROM TRUE
                   OR NOT COALESCE(
                        'search_path=pg_catalog, public, pg_temp' = ANY(function_config),
                        FALSE
                   )
                   OR NOT COALESCE(
                        'row_security=on' = ANY(function_config),
                        FALSE
                   ) THEN
                    RAISE EXCEPTION 'unsafe HPA database function contract: %', function_name
                        USING ERRCODE = '42501';
                END IF;
            END LOOP;
            IF pg_catalog.has_function_privilege(
                'trpc_hpa',
                'public.count_session_ready_backlog_for_tenant(text)',
                'EXECUTE'
            ) THEN
                RAISE EXCEPTION 'trpc_hpa must not execute tenant backlog metric'
                    USING ERRCODE = '42501';
            END IF;
            IF pg_catalog.has_function_privilege(
                'trpc_metrics',
                'public.cleanup_hpa_fixture(text)',
                'EXECUTE'
            ) THEN
                RAISE EXCEPTION 'trpc_metrics must not execute HPA cleanup'
                    USING ERRCODE = '42501';
            END IF;
        END
        $contract$;
    """


def upgrade() -> None:
    op.execute(_role_preflight())
    op.execute(_cleanup_function())
    op.execute(_prepare_function())
    op.execute(_tenant_backlog_function())
    op.execute(_contracts())


def downgrade() -> None:
    op.execute(
        """
        REVOKE ALL ON FUNCTION public.prepare_hpa_fixture(text, integer) FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.cleanup_hpa_fixture(text) FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.count_session_ready_backlog_for_tenant(text)
            FROM PUBLIC;
        DROP FUNCTION IF EXISTS public.prepare_hpa_fixture(text, integer);
        DROP FUNCTION IF EXISTS public.cleanup_hpa_fixture(text);
        DROP FUNCTION IF EXISTS public.count_session_ready_backlog_for_tenant(text);
        """
    )
