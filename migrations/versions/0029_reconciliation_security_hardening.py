"""Harden already-published reconciliation and evolution privileges.

0024 and 0027 are published migrations and may already have been applied to
long-lived databases.  This forward-only revision moves the security fix into
an additive migration: evidence is retained when an owning execution is
removed, tool reconciliation status changes cross a tenant/lease/attempt CAS
boundary, Cell reconciliation uses a tenant/attempt/status CAS function, and
the evolution authority reads candidate heads through one narrow function.

The downgrade intentionally removes only the helper functions.  It never
restores table-wide UPDATE or the old evidence-delete escape hatch.
"""

from __future__ import annotations

from alembic import op

revision = "0029_reconciliation_security_hardening"
down_revision = "0028_evolution_least_privilege"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Replace the 0024/0027 cascading evidence FKs without relying on
    # PostgreSQL's generated (and truncated) constraint names.
    op.execute(
        """
        ALTER TABLE public.cell_effect_reconciliations
            DROP CONSTRAINT IF EXISTS fk_cell_effect_reconciliation_ledger;
        DO $drop_cell_fk$
        DECLARE
            fk_name text;
        BEGIN
            FOR fk_name IN
                SELECT c.conname
                  FROM pg_catalog.pg_constraint AS c
                 WHERE c.conrelid = 'public.cell_effect_reconciliations'::regclass
                   AND c.confrelid = 'public.cell_effect_ledger'::regclass
                   AND c.contype = 'f'
            LOOP
                EXECUTE format(
                    'ALTER TABLE public.cell_effect_reconciliations DROP CONSTRAINT %I',
                    fk_name
                );
            END LOOP;
        END
        $drop_cell_fk$;
        ALTER TABLE public.cell_effect_reconciliations
            ADD CONSTRAINT fk_cell_effect_reconciliation_ledger
            FOREIGN KEY (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, effect_key
            ) REFERENCES public.cell_effect_ledger (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, effect_key
            ) ON DELETE RESTRICT;

        ALTER TABLE public.tool_execution_reconciliations
            DROP CONSTRAINT IF EXISTS fk_tool_execution_reconciliation_execution;
        DO $drop_tool_fk$
        DECLARE
            fk_name text;
        BEGIN
            FOR fk_name IN
                SELECT c.conname
                  FROM pg_catalog.pg_constraint AS c
                 WHERE c.conrelid = 'public.tool_execution_reconciliations'::regclass
                   AND c.confrelid = 'public.tool_executions'::regclass
                   AND c.contype = 'f'
            LOOP
                EXECUTE format(
                    'ALTER TABLE public.tool_execution_reconciliations DROP CONSTRAINT %I',
                    fk_name
                );
            END LOOP;
        END
        $drop_tool_fk$;
        ALTER TABLE public.tool_execution_reconciliations
            ADD CONSTRAINT fk_tool_execution_reconciliation_execution
            FOREIGN KEY (tenant_id, execution_key)
            REFERENCES public.tool_executions (tenant_id, execution_key)
            ON DELETE RESTRICT;
        """
    )

    # Promotion pointers and their one-time evidence are retention roots.  The
    # published 0025/0026 revisions used generated FK names and CASCADE, so
    # locate those historical constraints by catalog identity and replace them
    # without mutating the already-published revisions.
    op.execute(
        """
        ALTER TABLE public.cell_promotion_targets
            DROP CONSTRAINT IF EXISTS fk_cell_promotion_target_capsule_retention;
        DO $drop_promotion_target_capsule_fk$
        DECLARE
            fk_name text;
        BEGIN
            FOR fk_name IN
                SELECT c.conname
                  FROM pg_catalog.pg_constraint AS c
                 WHERE c.conrelid = 'public.cell_promotion_targets'::regclass
                   AND c.confrelid = 'public.agent_capsules'::regclass
                   AND c.contype = 'f'
            LOOP
                EXECUTE format(
                    'ALTER TABLE public.cell_promotion_targets DROP CONSTRAINT %I',
                    fk_name
                );
            END LOOP;
        END
        $drop_promotion_target_capsule_fk$;
        ALTER TABLE public.cell_promotion_targets
            ADD CONSTRAINT fk_cell_promotion_target_capsule_retention
            FOREIGN KEY (tenant_id, active_capsule_digest)
            REFERENCES public.agent_capsules (tenant_id, capsule_digest)
            ON DELETE RESTRICT;

        ALTER TABLE public.cell_promotion_uses
            DROP CONSTRAINT IF EXISTS fk_cell_promotion_use_target_retention;
        DO $drop_promotion_use_target_fk$
        DECLARE
            fk_name text;
        BEGIN
            FOR fk_name IN
                SELECT c.conname
                  FROM pg_catalog.pg_constraint AS c
                 WHERE c.conrelid = 'public.cell_promotion_uses'::regclass
                   AND c.confrelid = 'public.cell_promotion_targets'::regclass
                   AND c.contype = 'f'
            LOOP
                EXECUTE format(
                    'ALTER TABLE public.cell_promotion_uses DROP CONSTRAINT %I',
                    fk_name
                );
            END LOOP;
        END
        $drop_promotion_use_target_fk$;
        ALTER TABLE public.cell_promotion_uses
            ADD CONSTRAINT fk_cell_promotion_use_target_retention
            FOREIGN KEY (tenant_id, app_id, cell_id, session_id)
            REFERENCES public.cell_promotion_targets (
                tenant_id, app_id, cell_id, session_id
            ) ON DELETE RESTRICT;

        ALTER TABLE public.cell_promotion_receipts
            DROP CONSTRAINT IF EXISTS fk_cell_promotion_receipt_target_retention;
        DO $drop_promotion_receipt_target_fk$
        DECLARE
            fk_name text;
        BEGIN
            FOR fk_name IN
                SELECT c.conname
                  FROM pg_catalog.pg_constraint AS c
                 WHERE c.conrelid = 'public.cell_promotion_receipts'::regclass
                   AND c.confrelid = 'public.cell_promotion_targets'::regclass
                   AND c.contype = 'f'
            LOOP
                EXECUTE format(
                    'ALTER TABLE public.cell_promotion_receipts DROP CONSTRAINT %I',
                    fk_name
                );
            END LOOP;
        END
        $drop_promotion_receipt_target_fk$;
        ALTER TABLE public.cell_promotion_receipts
            ADD CONSTRAINT fk_cell_promotion_receipt_target_retention
            FOREIGN KEY (tenant_id, app_id, cell_id, session_id)
            REFERENCES public.cell_promotion_targets (
                tenant_id, app_id, cell_id, session_id
            ) ON DELETE RESTRICT;
        """
    )

    # Existing trigger names remain stable; replacing the function removes the
    # old migration-session deletion exception even on already-upgraded DBs.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.reject_cell_effect_reconciliation_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        BEGIN
            RAISE EXCEPTION 'cell effect reconciliation evidence is immutable'
                USING ERRCODE = '25006';
        END
        $function$;

        CREATE OR REPLACE FUNCTION public.reject_tool_execution_reconciliation_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        BEGIN
            RAISE EXCEPTION 'tool execution reconciliation evidence is immutable'
                USING ERRCODE = '25006';
        END
        $function$;
        """
    )

    # 0013's trigger trusted three transaction-local GUCs as the whole fence.
    # Rebind it to the durable manifest + lease + barrier rows and only permit
    # the dedicated runtime session to write while a live barrier is active.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.migration_write_barrier_guard()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        DECLARE
            effective_tenant text;
            barrier public.migration_write_barriers%ROWTYPE;
            lease public.migration_leases%ROWTYPE;
            manifest public.migration_scope_manifests%ROWTYPE;
            lease_found boolean;
            manifest_found boolean;
            active_tenant text;
            active_migration text;
            active_owner_instance text;
            active_epoch text;
        BEGIN
            effective_tenant := COALESCE(NEW.tenant_id, OLD.tenant_id);

            SELECT b.*
              INTO barrier
              FROM public.migration_write_barriers AS b
             WHERE b.tenant_id = effective_tenant
               AND b.mode = 'active'
             FOR SHARE;
            IF NOT FOUND THEN
                -- The trigger is a no-op for ordinary writes.  It is a fence
                -- only while the durable barrier row is active.
                RETURN COALESCE(NEW, OLD);
            END IF;

            SELECT l.*
              INTO lease
              FROM public.migration_leases AS l
             WHERE l.tenant_id = barrier.tenant_id
               AND l.migration_id = barrier.migration_id
             FOR SHARE;
            lease_found := FOUND;
            SELECT m.*
              INTO manifest
              FROM public.migration_scope_manifests AS m
             WHERE m.tenant_id = barrier.tenant_id
               AND m.migration_id = barrier.migration_id
             FOR SHARE;
            manifest_found := FOUND;

            IF session_user NOT IN ('trpc_runtime', 'trpc_worker', 'trpc_migration') THEN
                RAISE EXCEPTION 'migration barrier requires a dedicated database session'
                    USING ERRCODE = '42501';
            END IF;
            IF session_user <> 'trpc_runtime' THEN
                RAISE EXCEPTION 'active migration barrier requires trpc_runtime'
                    USING ERRCODE = '42501';
            END IF;
            active_tenant := nullif(
                pg_catalog.current_setting('app.tenant_id', true), ''
            );
            IF effective_tenant IS NULL
               OR active_tenant IS DISTINCT FROM effective_tenant THEN
                RAISE EXCEPTION 'migration barrier tenant scope is invalid'
                    USING ERRCODE = '42501';
            END IF;
            active_migration := nullif(
                pg_catalog.current_setting('app.migration_id', true), ''
            );
            active_owner_instance := nullif(
                pg_catalog.current_setting('app.migration_owner_instance', true), ''
            );
            active_epoch := nullif(
                pg_catalog.current_setting('app.migration_lease_epoch', true), ''
            );
            IF active_migration IS DISTINCT FROM barrier.migration_id
               OR active_owner_instance IS DISTINCT FROM barrier.owner_instance
               OR active_epoch IS DISTINCT FROM barrier.lease_epoch::text
               OR NOT lease_found
               OR NOT manifest_found
               OR barrier.tenant_id IS DISTINCT FROM lease.tenant_id
               OR barrier.migration_id IS DISTINCT FROM lease.migration_id
               OR barrier.owner_instance IS DISTINCT FROM lease.owner_instance
               OR barrier.lease_epoch IS DISTINCT FROM lease.lease_epoch
               OR lease.expires_at <= pg_catalog.clock_timestamp()
               OR manifest.tenant_id IS DISTINCT FROM effective_tenant
               OR manifest.migration_id IS DISTINCT FROM barrier.migration_id THEN
                RAISE EXCEPTION
                    'tenant % is protected by a stale or mismatched migration write barrier',
                    effective_tenant
                    USING ERRCODE = '55000';
            END IF;
            RETURN COALESCE(NEW, OLD);
        END;
        $function$;
        ALTER FUNCTION public.migration_write_barrier_guard() OWNER TO trpc_migration;
        REVOKE ALL ON FUNCTION public.migration_write_barrier_guard() FROM PUBLIC;
        """
    )

    # Reconciliation transitions and claims are SECURITY DEFINER CAS
    # operations.  The invoker only receives narrow evidence access and
    # EXECUTE on the exact function; it cannot update a ledger table directly.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.reconcile_cell_effect_cas(
            p_tenant_id text,
            p_effect_key text,
            p_expected_attempt integer,
            p_status text,
            p_error_type text,
            p_provider_reference text,
            p_outcome text,
            p_evidence_digest text
        ) RETURNS TABLE (
            effect_key text,
            status text,
            attempt integer
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        DECLARE
            updated_ledger public.cell_effect_ledger%ROWTYPE;
            updated_receipt uuid;
        BEGIN
            IF session_user <> 'trpc_cell_reconciler'
               OR current_user <> 'trpc_migration' THEN
                RAISE EXCEPTION 'cell reconciliation function caller is invalid'
                    USING ERRCODE = '42501';
            END IF;
            IF p_tenant_id IS DISTINCT FROM
               nullif(pg_catalog.current_setting('app.tenant_id', true), '') THEN
                RAISE EXCEPTION 'cell reconciliation tenant proof is invalid'
                    USING ERRCODE = '42501';
            END IF;
            IF p_effect_key IS NULL OR p_effect_key = ''
               OR p_expected_attempt IS NULL OR p_expected_attempt < 0 THEN
                RAISE EXCEPTION 'cell reconciliation fence is invalid'
                    USING ERRCODE = '22023';
            END IF;
            IF p_status NOT IN ('succeeded', 'failed', 'unknown') THEN
                RAISE EXCEPTION 'cell reconciliation status is invalid'
                    USING ERRCODE = '22023';
            END IF;
            IF p_outcome NOT IN ('applied', 'not_applied', 'unknown')
               OR (p_outcome = 'applied' AND p_status <> 'succeeded')
               OR (p_outcome = 'not_applied' AND p_status <> 'failed')
               OR (p_outcome = 'unknown' AND p_status <> 'unknown')
               OR p_evidence_digest IS NULL
               OR p_evidence_digest !~ '^[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'cell reconciliation outcome is invalid'
                    USING ERRCODE = '22023';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                  FROM public.cell_effect_reconciliations AS evidence
                 WHERE evidence.tenant_id = p_tenant_id
                   AND evidence.effect_key = p_effect_key
                   AND evidence.attempt = p_expected_attempt
                   AND evidence.outcome = p_outcome
                   AND evidence.evidence_digest = p_evidence_digest
            ) THEN
                RAISE EXCEPTION 'cell reconciliation evidence is missing'
                    USING ERRCODE = '42501';
            END IF;
            UPDATE public.cell_effect_ledger AS ledger
               SET status = p_status,
                   lease_owner = NULL,
                   lease_expires_at = NULL,
                   updated_at = pg_catalog.clock_timestamp()
             WHERE ledger.tenant_id = p_tenant_id
               AND ledger.effect_key = p_effect_key
               AND ledger.attempt = p_expected_attempt
               AND ledger.status IN ('ambiguous', 'unknown')
              RETURNING ledger.* INTO updated_ledger;
            IF NOT FOUND THEN
                RETURN;
            END IF;
            UPDATE public.cell_effect_receipts AS receipt
               SET status = p_status,
                   error_type = p_error_type,
                   provider_reference = p_provider_reference,
                   attempted_at = pg_catalog.clock_timestamp()
             WHERE receipt.tenant_id = p_tenant_id
               AND receipt.effect_key = p_effect_key
               AND receipt.attempt = p_expected_attempt
               AND receipt.status IN ('ambiguous', 'unknown')
              RETURNING receipt_id INTO updated_receipt;
            IF NOT FOUND OR updated_receipt IS NULL THEN
                RAISE EXCEPTION 'cell reconciliation receipt is missing'
                    USING ERRCODE = '40001';
            END IF;
            effect_key := updated_ledger.effect_key;
            status := updated_ledger.status;
            attempt := updated_ledger.attempt;
            RETURN NEXT;
        END
        $function$;
        ALTER FUNCTION public.reconcile_cell_effect_cas(
            text, text, integer, text, text, text, text, text
        ) OWNER TO trpc_migration;
        REVOKE ALL ON FUNCTION public.reconcile_cell_effect_cas(
            text, text, integer, text, text, text, text, text
        ) FROM PUBLIC;

        CREATE OR REPLACE FUNCTION public.reconcile_tool_execution_cas(
            p_tenant_id text,
            p_execution_key text,
            p_expected_attempt integer,
            p_claim_owner text,
            p_claim_epoch bigint,
            p_status text,
            p_outcome text,
            p_evidence_digest text,
            p_reconciled_at timestamptz
        ) RETURNS TABLE (
            execution_key text,
            status text,
            attempt integer
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        DECLARE
            updated_key text;
            updated_status text;
            updated_attempt integer;
        BEGIN
            IF session_user <> 'trpc_tool_reconciler'
               OR current_user <> 'trpc_migration' THEN
                RAISE EXCEPTION 'tool reconciliation function caller is invalid'
                    USING ERRCODE = '42501';
            END IF;
            IF p_tenant_id IS DISTINCT FROM
               nullif(pg_catalog.current_setting('app.tenant_id', true), '') THEN
                RAISE EXCEPTION 'tool reconciliation tenant proof is invalid'
                    USING ERRCODE = '42501';
            END IF;
            IF p_execution_key IS NULL OR p_execution_key = ''
               OR p_expected_attempt IS NULL OR p_expected_attempt < 1
               OR p_claim_owner IS NULL OR pg_catalog.btrim(p_claim_owner) = ''
               OR p_claim_epoch IS NULL OR p_claim_epoch < 1 THEN
                RAISE EXCEPTION 'tool reconciliation claim is invalid'
                    USING ERRCODE = '22023';
            END IF;
            IF p_status NOT IN ('succeeded', 'failed', 'unknown')
               OR p_outcome NOT IN ('applied', 'not_applied', 'unknown')
               OR (p_outcome = 'applied' AND p_status <> 'succeeded')
               OR (p_outcome = 'not_applied' AND p_status <> 'failed')
               OR (p_outcome = 'unknown' AND p_status <> 'unknown')
               OR p_evidence_digest IS NULL
               OR p_evidence_digest !~ '^[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'tool reconciliation outcome is invalid'
                    USING ERRCODE = '22023';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                  FROM public.tool_execution_reconciliations AS evidence
                 WHERE evidence.tenant_id = p_tenant_id
                   AND evidence.execution_key = p_execution_key
                   AND evidence.attempt = p_expected_attempt
                   AND evidence.outcome = p_outcome
                   AND evidence.evidence_digest = p_evidence_digest
            ) THEN
                RAISE EXCEPTION 'tool reconciliation evidence is missing'
                    USING ERRCODE = '42501';
            END IF;
            UPDATE public.tool_executions AS execution
               SET status = p_status,
                   reconciliation_outcome = p_outcome,
                   reconciliation_evidence_digest = p_evidence_digest,
                   reconciled_at = COALESCE(
                       p_reconciled_at, pg_catalog.clock_timestamp()
                   ),
                   reconciliation_owner = NULL,
                   reconciliation_lease_expires_at = NULL,
                   completed_at = CASE
                       WHEN p_status IN ('succeeded', 'failed')
                       THEN COALESCE(p_reconciled_at, pg_catalog.clock_timestamp())
                       ELSE execution.completed_at
                   END
             WHERE execution.tenant_id = p_tenant_id
               AND execution.execution_key = p_execution_key
               AND execution.attempt = p_expected_attempt
               AND execution.status IN ('ambiguous', 'unknown')
               AND execution.reconciliation_owner = p_claim_owner
               AND execution.reconciliation_epoch = p_claim_epoch
               AND execution.reconciliation_lease_expires_at > pg_catalog.clock_timestamp()
             RETURNING execution.execution_key, execution.status, execution.attempt
                  INTO updated_key, updated_status, updated_attempt;
            IF NOT FOUND THEN
                RETURN;
            END IF;
            execution_key := updated_key;
            status := updated_status;
            attempt := updated_attempt;
            RETURN NEXT;
        END
        $function$;
        ALTER FUNCTION public.reconcile_tool_execution_cas(
            text, text, integer, text, bigint, text, text, text, timestamptz
        ) OWNER TO trpc_migration;
        REVOKE ALL ON FUNCTION public.reconcile_tool_execution_cas(
            text, text, integer, text, bigint, text, text, text, timestamptz
        ) FROM PUBLIC;
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.lock_cell_effect_reconciliation(
            p_tenant_id text,
            p_effect_key text
        ) RETURNS TABLE (
            effect_key text,
            intent_id text,
            status text,
            attempt integer,
            lease_owner text,
            lease_epoch bigint,
            lease_expires_at timestamptz,
            updated_at timestamptz,
            tenant_id text,
            app_id text,
            cell_id text,
            session_id text,
            capsule_digest text,
            branch_id text
        )
        LANGUAGE plpgsql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        BEGIN
            IF session_user <> 'trpc_cell_reconciler'
               OR current_user <> 'trpc_migration' THEN
                RAISE EXCEPTION 'cell reconciliation lock caller is invalid'
                    USING ERRCODE = '42501';
            END IF;
            IF p_tenant_id IS NULL
               OR pg_catalog.btrim(p_tenant_id) = ''
               OR p_tenant_id IS DISTINCT FROM
                    nullif(pg_catalog.current_setting('app.tenant_id', true), '') THEN
                RAISE EXCEPTION 'cell reconciliation lock tenant proof is invalid'
                    USING ERRCODE = '42501';
            END IF;
            IF p_effect_key IS NULL OR p_effect_key = '' THEN
                RAISE EXCEPTION 'cell reconciliation lock key is invalid'
                    USING ERRCODE = '22023';
            END IF;
            RETURN QUERY
            SELECT ledger.effect_key,
                   ledger.intent_id,
                   ledger.status,
                   ledger.attempt,
                   ledger.lease_owner,
                   ledger.lease_epoch,
                   ledger.lease_expires_at,
                   ledger.updated_at,
                   ledger.tenant_id,
                   ledger.app_id,
                   ledger.cell_id,
                   ledger.session_id,
                   ledger.capsule_digest,
                   ledger.branch_id
              FROM public.cell_effect_ledger AS ledger
             WHERE ledger.tenant_id = p_tenant_id
               AND ledger.effect_key = p_effect_key
             FOR UPDATE OF ledger;
        END
        $function$;
        ALTER FUNCTION public.lock_cell_effect_reconciliation(text, text)
            OWNER TO trpc_migration;
        REVOKE ALL ON FUNCTION public.lock_cell_effect_reconciliation(text, text)
            FROM PUBLIC;

        CREATE OR REPLACE FUNCTION public.lock_tool_execution_reconciliation(
            p_tenant_id text,
            p_execution_key text
        ) RETURNS TABLE (
            execution_key text,
            status text,
            attempt integer,
            reconciliation_owner text,
            reconciliation_epoch bigint,
            reconciliation_lease_expires_at timestamptz
        )
        LANGUAGE plpgsql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        BEGIN
            IF session_user <> 'trpc_tool_reconciler'
               OR current_user <> 'trpc_migration' THEN
                RAISE EXCEPTION 'tool reconciliation lock caller is invalid'
                    USING ERRCODE = '42501';
            END IF;
            IF p_tenant_id IS NULL
               OR pg_catalog.btrim(p_tenant_id) = ''
               OR p_tenant_id IS DISTINCT FROM
                    nullif(pg_catalog.current_setting('app.tenant_id', true), '') THEN
                RAISE EXCEPTION 'tool reconciliation lock tenant proof is invalid'
                    USING ERRCODE = '42501';
            END IF;
            IF p_execution_key IS NULL OR p_execution_key = '' THEN
                RAISE EXCEPTION 'tool reconciliation lock key is invalid'
                    USING ERRCODE = '22023';
            END IF;
            RETURN QUERY
            SELECT execution.execution_key,
                   execution.status,
                   execution.attempt,
                   execution.reconciliation_owner,
                   execution.reconciliation_epoch,
                   execution.reconciliation_lease_expires_at
              FROM public.tool_executions AS execution
             WHERE execution.tenant_id = p_tenant_id
               AND execution.execution_key = p_execution_key
             FOR UPDATE OF execution;
        END
        $function$;
        ALTER FUNCTION public.lock_tool_execution_reconciliation(text, text)
            OWNER TO trpc_migration;
        REVOKE ALL ON FUNCTION public.lock_tool_execution_reconciliation(text, text)
            FROM PUBLIC;
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.claim_tool_execution_ambiguous(
            p_tenant_id text,
            p_limit integer,
            p_owner_id text,
            p_lease_seconds double precision
        ) RETURNS TABLE (
            tenant_id text,
            execution_key text,
            turn_id uuid,
            tool_name text,
            arguments_hash text,
            status text,
            attempt integer,
            reconciliation_owner text,
            reconciliation_epoch bigint,
            reconciliation_lease_expires_at timestamptz,
            started_at timestamptz,
            lease_owner text,
            lease_epoch bigint,
            error_type text,
            completed_at timestamptz,
            session_id text,
            app_id text
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        BEGIN
            IF session_user <> 'trpc_tool_reconciler'
               OR current_user <> 'trpc_migration' THEN
                RAISE EXCEPTION 'tool claim function caller is invalid'
                    USING ERRCODE = '42501';
            END IF;
            IF p_tenant_id IS NULL
               OR pg_catalog.btrim(p_tenant_id) = ''
               OR pg_catalog.length(p_tenant_id) > 256
               OR p_tenant_id IS DISTINCT FROM
                    nullif(pg_catalog.current_setting('app.tenant_id', true), '') THEN
                RAISE EXCEPTION 'tool claim tenant proof is invalid'
                    USING ERRCODE = '42501';
            END IF;
            IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
                RAISE EXCEPTION 'tool claim limit is invalid'
                    USING ERRCODE = '22023';
            END IF;
            IF p_owner_id IS NULL
               OR pg_catalog.btrim(p_owner_id) = ''
               OR pg_catalog.length(p_owner_id) > 256 THEN
                RAISE EXCEPTION 'tool claim owner is invalid'
                    USING ERRCODE = '22023';
            END IF;
            IF p_lease_seconds IS NULL
               OR p_lease_seconds <> p_lease_seconds
               OR p_lease_seconds <= 0
               OR p_lease_seconds > 3600 THEN
                RAISE EXCEPTION 'tool claim lease is invalid'
                    USING ERRCODE = '22023';
            END IF;
            RETURN QUERY
            WITH candidates AS (
                SELECT execution.tenant_id, execution.execution_key
                  FROM public.tool_executions AS execution
                  JOIN public.session_turns AS turn
                    ON turn.tenant_id = execution.tenant_id
                   AND turn.turn_id = execution.turn_id
                  JOIN public.sessions AS session
                    ON session.tenant_id = turn.tenant_id
                   AND session.session_id = turn.session_id
                 WHERE execution.tenant_id = p_tenant_id
                   AND execution.status IN ('ambiguous', 'unknown')
                   AND (
                       execution.reconciliation_lease_expires_at IS NULL
                       OR execution.reconciliation_lease_expires_at
                            <= pg_catalog.clock_timestamp()
                   )
                 ORDER BY execution.started_at, execution.execution_key
                 FOR UPDATE OF execution SKIP LOCKED
                 LIMIT p_limit
            ), claimed AS (
                UPDATE public.tool_executions AS execution
                   SET reconciliation_owner = p_owner_id,
                       reconciliation_epoch = execution.reconciliation_epoch + 1,
                       reconciliation_lease_expires_at = (
                           pg_catalog.clock_timestamp()
                           + (p_lease_seconds * interval '1 second')
                       )
                  FROM candidates
                 WHERE execution.tenant_id = candidates.tenant_id
                   AND execution.execution_key = candidates.execution_key
                 RETURNING execution.tenant_id, execution.execution_key,
                           execution.turn_id, execution.tool_name,
                           execution.arguments_hash, execution.status,
                           execution.attempt, execution.reconciliation_owner,
                           execution.reconciliation_epoch,
                           execution.reconciliation_lease_expires_at,
                           execution.started_at, execution.lease_owner,
                           execution.lease_epoch, execution.error_type,
                           execution.completed_at
            )
            SELECT claimed.tenant_id, claimed.execution_key,
                   claimed.turn_id, claimed.tool_name,
                   claimed.arguments_hash, claimed.status,
                   claimed.attempt, claimed.reconciliation_owner,
                   claimed.reconciliation_epoch,
                   claimed.reconciliation_lease_expires_at,
                   claimed.started_at, claimed.lease_owner,
                   claimed.lease_epoch, claimed.error_type,
                   claimed.completed_at, turn.session_id, session.app_id
              FROM claimed
              JOIN public.session_turns AS turn
                ON turn.tenant_id = claimed.tenant_id
               AND turn.turn_id = claimed.turn_id
              JOIN public.sessions AS session
                ON session.tenant_id = turn.tenant_id
               AND session.session_id = turn.session_id;
        END
        $function$;
        ALTER FUNCTION public.claim_tool_execution_ambiguous(
            text, integer, text, double precision
        ) OWNER TO trpc_migration;
        REVOKE ALL ON FUNCTION public.claim_tool_execution_ambiguous(
            text, integer, text, double precision
        ) FROM PUBLIC;
        """
    )

    # Candidate verification needs no table-wide read grant.  The function
    # enforces tenant setting and login identity before reading one head row.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.read_cell_branch_head_hash(
            p_tenant_id text,
            p_app_id text,
            p_cell_id text,
            p_session_id text,
            p_capsule_digest text,
            p_branch_id text
        ) RETURNS text
        LANGUAGE plpgsql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET row_security = on
        AS $function$
        DECLARE
            observed_hash text;
        BEGIN
            IF session_user <> 'trpc_evolution_authority' THEN
                RAISE EXCEPTION 'candidate head reader caller is invalid'
                    USING ERRCODE = '42501';
            END IF;
            IF p_tenant_id IS NULL OR p_tenant_id = ''
               OR p_app_id IS NULL OR p_app_id = ''
               OR p_cell_id IS NULL OR p_cell_id = ''
               OR p_session_id IS NULL OR p_session_id = ''
               OR p_capsule_digest IS NULL OR p_capsule_digest = ''
               OR p_branch_id IS NULL OR p_branch_id = '' THEN
                RAISE EXCEPTION 'candidate head reader address is invalid'
                    USING ERRCODE = '22023';
            END IF;
            IF p_tenant_id IS DISTINCT FROM
               nullif(pg_catalog.current_setting('app.tenant_id', true), '') THEN
                RAISE EXCEPTION 'candidate head reader tenant proof is invalid'
                    USING ERRCODE = '42501';
            END IF;
            SELECT head.last_event_hash
              INTO observed_hash
              FROM public.cell_branch_heads AS head
             WHERE head.tenant_id = p_tenant_id
               AND head.app_id = p_app_id
               AND head.cell_id = p_cell_id
               AND head.session_id = p_session_id
               AND head.capsule_digest = p_capsule_digest
               AND head.branch_id = p_branch_id
             FOR SHARE;
            RETURN observed_hash;
        END
        $function$;
        ALTER FUNCTION public.read_cell_branch_head_hash(
            text, text, text, text, text, text
        ) OWNER TO trpc_migration;
        REVOKE ALL ON FUNCTION public.read_cell_branch_head_hash(
            text, text, text, text, text, text
        ) FROM PUBLIC;
        """
    )

    # Reassert every affected privilege so this migration repairs databases
    # that already ran 0024/0027/0028, not only new installs.
    op.execute(
        """
        GRANT USAGE ON SCHEMA public
            TO trpc_cell_reconciler, trpc_tool_reconciler,
               trpc_evolution_authority;

        REVOKE UPDATE, DELETE ON public.cell_effect_receipts,
            public.cell_effect_ledger
            FROM trpc_cell_reconciler;
        GRANT SELECT ON public.cell_effect_receipts,
            public.cell_effect_ledger
            TO trpc_cell_reconciler;
        GRANT EXECUTE ON FUNCTION public.reconcile_cell_effect_cas(
            text, text, integer, text, text, text, text, text
        ) TO trpc_cell_reconciler;
        GRANT EXECUTE ON FUNCTION public.lock_cell_effect_reconciliation(
            text, text
        ) TO trpc_cell_reconciler;

        -- 0027 granted these columns explicitly.  A table-level REVOKE does
        -- not remove historical column ACL entries, so revoke that grant by
        -- column before leaving the reconciler with SELECT plus function
        -- execution only.
        REVOKE UPDATE (
            status, completed_at, reconciliation_owner,
            reconciliation_epoch, reconciliation_lease_expires_at,
            reconciliation_outcome, reconciliation_evidence_digest,
            reconciled_at
        ) ON public.tool_executions FROM trpc_tool_reconciler;
        REVOKE UPDATE, DELETE ON public.tool_executions
            FROM trpc_tool_reconciler;
        GRANT SELECT ON public.tool_executions
            TO trpc_tool_reconciler;
        -- list_ambiguous remains a read-only compatibility path; the claim
        -- mutation itself is performed only by the SECURITY DEFINER function.
        GRANT SELECT ON public.sessions, public.session_turns
            TO trpc_tool_reconciler;
        GRANT EXECUTE ON FUNCTION public.reconcile_tool_execution_cas(
            text, text, integer, text, bigint, text, text, text, timestamptz
        ) TO trpc_tool_reconciler;
        GRANT EXECUTE ON FUNCTION public.lock_tool_execution_reconciliation(
            text, text
        ) TO trpc_tool_reconciler;
        GRANT EXECUTE ON FUNCTION public.claim_tool_execution_ambiguous(
            text, integer, text, double precision
        ) TO trpc_tool_reconciler;

        REVOKE DELETE ON public.cell_effect_reconciliations,
            public.tool_execution_reconciliations
            FROM trpc_migration, trpc_cell_reconciler, trpc_tool_reconciler;
        REVOKE SELECT ON public.cell_branch_heads
            FROM trpc_evolution_authority;
        GRANT EXECUTE ON FUNCTION public.read_cell_branch_head_hash(
            text, text, text, text, text, text
        ) TO trpc_evolution_authority;

        REVOKE UPDATE ON public.cell_promotion_targets,
            public.cell_promotion_outbox
            FROM trpc_evolution_authority;
        GRANT UPDATE (active_capsule_digest, control_version, updated_at)
            ON public.cell_promotion_targets
            TO trpc_evolution_authority;
        GRANT UPDATE (
            status, claimed_by, lease_epoch, lease_expires_at,
            attempts, available_at, published_at, last_error
        ) ON public.cell_promotion_outbox
            TO trpc_evolution_authority;
        """
    )


def downgrade() -> None:
    # Do not restore direct UPDATE or migration-session evidence deletion.  A
    # forward migration is required for any future privilege change.
    op.execute(
        """
        REVOKE EXECUTE ON FUNCTION public.read_cell_branch_head_hash(
            text, text, text, text, text, text
        ) FROM PUBLIC, trpc_evolution_authority;
        DROP FUNCTION IF EXISTS public.read_cell_branch_head_hash(
            text, text, text, text, text, text
        );
        REVOKE EXECUTE ON FUNCTION public.reconcile_cell_effect_cas(
            text, text, integer, text, text, text, text, text
        ) FROM PUBLIC, trpc_cell_reconciler;
        DROP FUNCTION IF EXISTS public.reconcile_cell_effect_cas(
            text, text, integer, text, text, text, text, text
        );
        REVOKE EXECUTE ON FUNCTION public.lock_cell_effect_reconciliation(
            text, text
        ) FROM PUBLIC, trpc_cell_reconciler;
        DROP FUNCTION IF EXISTS public.lock_cell_effect_reconciliation(text, text);
        REVOKE EXECUTE ON FUNCTION public.reconcile_tool_execution_cas(
            text, text, integer, text, bigint, text, text, text, timestamptz
        ) FROM PUBLIC, trpc_tool_reconciler;
        DROP FUNCTION IF EXISTS public.reconcile_tool_execution_cas(
            text, text, integer, text, bigint, text, text, text, timestamptz
        );
        REVOKE EXECUTE ON FUNCTION public.lock_tool_execution_reconciliation(
            text, text
        ) FROM PUBLIC, trpc_tool_reconciler;
        DROP FUNCTION IF EXISTS public.lock_tool_execution_reconciliation(text, text);
        REVOKE EXECUTE ON FUNCTION public.claim_tool_execution_ambiguous(
            text, integer, text, double precision
        ) FROM PUBLIC, trpc_tool_reconciler;
        DROP FUNCTION IF EXISTS public.claim_tool_execution_ambiguous(
            text, integer, text, double precision
        );
        """
    )
