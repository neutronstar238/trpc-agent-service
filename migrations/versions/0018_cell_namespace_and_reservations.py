"""Close the Cell namespace and add durable fencing/reservations.

Revision 0017 introduced the first Cell tables, but its foreign keys keyed a
Cell only by ``(tenant_id, cell_id, branch_id)`` even though the row already
contained ``app_id``, ``session_id`` and ``capsule_digest``.  This migration
expands every causal relation to the complete Cell address.  It also adds a
branch-head CAS row and an authoritative node-capacity ledger; the latter is
what prevents two gateways from both accepting the same stale snapshot.

The migration is deliberately additive in history: 0017 remains immutable and
all backfills happen before the new NOT NULL/composite constraints are added.
"""

# The only interpolated SQL below receives fixed private call-site constants.
# Keep the migration's safety lint explicit instead of weakening project-wide
# checks for normal application queries.
# ruff: noqa: S608

from __future__ import annotations

from alembic import op

revision = "0018_cell_namespace_reservations"
down_revision = "0017_agent_cell_fabric"
branch_labels = None
depends_on = None


_TENANT_TABLES = (
    "cell_branch_heads",
    "cell_events",
    "cell_tool_intents",
    "cell_effect_ledger",
    "cell_effect_receipts",
    "cell_placement_reservations",
)


def _assert_backfill_complete(table: str, columns: str) -> None:
    op.execute(
        f"""
        DO $check$
        BEGIN
            IF EXISTS (SELECT 1 FROM {table} WHERE {columns}) THEN
                RAISE EXCEPTION '0018 namespace backfill incomplete for {table}';
            END IF;
        END
        $check$;
        """
    )


def upgrade() -> None:
    # The old event FK prevents replacing the old Cell primary key.  Drop only
    # the 0017-generated constraints; no pre-existing application constraint
    # is changed here.
    op.execute(
        """
        CREATE EXTENSION IF NOT EXISTS pgcrypto;

        ALTER TABLE cell_events
            DROP CONSTRAINT IF EXISTS cell_events_tenant_id_cell_id_branch_id_fkey;
        ALTER TABLE cell_tool_intents
            DROP CONSTRAINT IF EXISTS cell_tool_intents_tenant_id_cell_id_branch_id_sequence_fkey;
        ALTER TABLE cell_effect_ledger
            DROP CONSTRAINT IF EXISTS cell_effect_ledger_tenant_id_intent_id_fkey;
        ALTER TABLE cell_effect_receipts
            DROP CONSTRAINT IF EXISTS cell_effect_receipts_tenant_id_intent_id_fkey,
            DROP CONSTRAINT IF EXISTS cell_effect_receipts_tenant_id_effect_key_fkey;

        ALTER TABLE cell_events
            ADD COLUMN IF NOT EXISTS app_id text,
            ADD COLUMN IF NOT EXISTS session_id text;
        UPDATE cell_events AS e
           SET app_id = c.app_id,
               session_id = c.session_id
          FROM agent_cells AS c
         WHERE c.tenant_id = e.tenant_id
           AND c.cell_id = e.cell_id
           AND c.branch_id = e.branch_id;

        ALTER TABLE cell_tool_intents
            ADD COLUMN IF NOT EXISTS app_id text,
            ADD COLUMN IF NOT EXISTS session_id text,
            ADD COLUMN IF NOT EXISTS capsule_digest text;
        UPDATE cell_tool_intents AS i
           SET app_id = e.app_id,
               session_id = e.session_id,
               capsule_digest = e.capsule_digest
          FROM cell_events AS e
         WHERE e.tenant_id = i.tenant_id
           AND e.cell_id = i.cell_id
           AND e.branch_id = i.branch_id
           AND e.sequence = i.sequence;

        ALTER TABLE cell_effect_ledger
            ADD COLUMN IF NOT EXISTS app_id text,
            ADD COLUMN IF NOT EXISTS cell_id text,
            ADD COLUMN IF NOT EXISTS session_id text,
            ADD COLUMN IF NOT EXISTS capsule_digest text,
            ADD COLUMN IF NOT EXISTS branch_id text;
        UPDATE cell_effect_ledger AS l
           SET app_id = i.app_id,
               cell_id = i.cell_id,
               session_id = i.session_id,
               capsule_digest = i.capsule_digest,
               branch_id = i.branch_id
          FROM cell_tool_intents AS i
         WHERE i.tenant_id = l.tenant_id
           AND i.intent_id = l.intent_id;

        ALTER TABLE cell_effect_receipts
            ADD COLUMN IF NOT EXISTS app_id text,
            ADD COLUMN IF NOT EXISTS cell_id text,
            ADD COLUMN IF NOT EXISTS session_id text,
            ADD COLUMN IF NOT EXISTS capsule_digest text,
            ADD COLUMN IF NOT EXISTS branch_id text,
            ADD COLUMN IF NOT EXISTS trace_id text;
        UPDATE cell_effect_receipts AS r
           SET app_id = l.app_id,
               cell_id = l.cell_id,
               session_id = l.session_id,
               capsule_digest = l.capsule_digest,
               branch_id = l.branch_id
          FROM cell_effect_ledger AS l
         WHERE l.tenant_id = r.tenant_id
           AND l.effect_key = r.effect_key;
        """
    )

    _assert_backfill_complete(
        "cell_events",
        "app_id IS NULL OR session_id IS NULL",
    )
    _assert_backfill_complete(
        "cell_tool_intents",
        "app_id IS NULL OR session_id IS NULL OR capsule_digest IS NULL",
    )
    _assert_backfill_complete(
        "cell_effect_ledger",
        "app_id IS NULL OR cell_id IS NULL OR session_id IS NULL "
        "OR capsule_digest IS NULL OR branch_id IS NULL",
    )
    _assert_backfill_complete(
        "cell_effect_receipts",
        "app_id IS NULL OR cell_id IS NULL OR session_id IS NULL "
        "OR capsule_digest IS NULL OR branch_id IS NULL",
    )

    op.execute(
        """
        -- The complete address is the identity used by every event/branch FK.
        ALTER TABLE agent_cells DROP CONSTRAINT IF EXISTS agent_cells_pkey;
        ALTER TABLE agent_cells
            ADD CONSTRAINT agent_cells_pkey
            PRIMARY KEY (tenant_id, app_id, cell_id, session_id, capsule_digest, branch_id);
        ALTER TABLE agent_cells
            ADD CONSTRAINT agent_cells_parent_fk
            FOREIGN KEY (
                tenant_id, app_id, cell_id, session_id,
                parent_capsule_digest, parent_branch_id
            ) REFERENCES agent_cells (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id
            );
        ALTER TABLE agent_cells
            ADD CONSTRAINT ck_agent_cell_parent_not_self CHECK (
                parent_branch_id IS NULL
                OR parent_branch_id <> branch_id
                OR parent_capsule_digest <> capsule_digest
            );

        ALTER TABLE cell_events DROP CONSTRAINT IF EXISTS cell_events_pkey;
        ALTER TABLE cell_events
            ALTER COLUMN app_id SET NOT NULL,
            ALTER COLUMN session_id SET NOT NULL;
        ALTER TABLE cell_events
            ADD CONSTRAINT cell_events_pkey
            PRIMARY KEY (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, sequence
            );
        ALTER TABLE cell_events
            ADD CONSTRAINT cell_events_cell_fk
            FOREIGN KEY (
                tenant_id, app_id, cell_id, session_id, capsule_digest, branch_id
            ) REFERENCES agent_cells (
                tenant_id, app_id, cell_id, session_id, capsule_digest, branch_id
            ) ON DELETE CASCADE;
        ALTER TABLE cell_events
            DROP CONSTRAINT IF EXISTS cell_events_tenant_id_event_id_key;
        ALTER TABLE cell_events
            ADD CONSTRAINT cell_events_tenant_event_id_key
            UNIQUE (tenant_id, event_id);
        CREATE INDEX IF NOT EXISTS ix_cell_events_full_stream
            ON cell_events (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, sequence
            );

        ALTER TABLE cell_tool_intents
            ALTER COLUMN app_id SET NOT NULL,
            ALTER COLUMN session_id SET NOT NULL,
            ALTER COLUMN capsule_digest SET NOT NULL;
        ALTER TABLE cell_tool_intents
            ADD CONSTRAINT cell_tool_intents_event_fk
            FOREIGN KEY (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, sequence
            ) REFERENCES cell_events (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, sequence
            );
        CREATE INDEX IF NOT EXISTS ix_cell_tool_intents_stream
            ON cell_tool_intents (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, sequence
            );

        ALTER TABLE cell_effect_ledger
            ALTER COLUMN app_id SET NOT NULL,
            ALTER COLUMN cell_id SET NOT NULL,
            ALTER COLUMN session_id SET NOT NULL,
            ALTER COLUMN capsule_digest SET NOT NULL,
            ALTER COLUMN branch_id SET NOT NULL;
        ALTER TABLE cell_tool_intents
            ADD CONSTRAINT cell_tool_intents_namespace_intent_key
            UNIQUE (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, intent_id
            );
        ALTER TABLE cell_effect_ledger
            ADD CONSTRAINT cell_effect_ledger_intent_fk
            FOREIGN KEY (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, intent_id
            ) REFERENCES cell_tool_intents (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, intent_id
            );
        ALTER TABLE cell_effect_ledger
            ADD CONSTRAINT cell_effect_ledger_namespace_effect_key
            UNIQUE (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, effect_key
            );
        CREATE INDEX IF NOT EXISTS ix_cell_effect_ledger_stream
            ON cell_effect_ledger (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, updated_at
            );

        ALTER TABLE cell_effect_receipts
            ALTER COLUMN app_id SET NOT NULL,
            ALTER COLUMN cell_id SET NOT NULL,
            ALTER COLUMN session_id SET NOT NULL,
            ALTER COLUMN capsule_digest SET NOT NULL,
            ALTER COLUMN branch_id SET NOT NULL;
        ALTER TABLE cell_effect_receipts
            ADD CONSTRAINT cell_effect_receipts_intent_fk
            FOREIGN KEY (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, intent_id
            ) REFERENCES cell_tool_intents (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, intent_id
            );
        ALTER TABLE cell_effect_receipts
            ADD CONSTRAINT cell_effect_receipts_ledger_fk
            FOREIGN KEY (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, effect_key
            ) REFERENCES cell_effect_ledger (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id, effect_key
            );

        -- Branch heads are the single CAS/fencing point for append and lease
        -- ownership.  Child branches start at their parent fork sequence.
        CREATE TABLE cell_branch_heads (
            tenant_id text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
            app_id text NOT NULL,
            cell_id text NOT NULL,
            session_id text NOT NULL,
            capsule_digest text NOT NULL,
            branch_id text NOT NULL,
            last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
            last_event_hash text NOT NULL DEFAULT repeat('0', 64),
            lease_owner text,
            lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
            lease_expires_at timestamptz,
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id
            ),
            FOREIGN KEY (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id
            ) REFERENCES agent_cells (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id
            ) ON DELETE CASCADE,
            CONSTRAINT ck_cell_branch_head_hash
                CHECK (last_event_hash ~ '^[0-9a-f]{64}$')
        );
        INSERT INTO cell_branch_heads (
            tenant_id, app_id, cell_id, session_id,
            capsule_digest, branch_id, last_sequence, last_event_hash,
            lease_owner, lease_epoch, lease_expires_at, updated_at
        )
        SELECT tenant_id, app_id, cell_id, session_id,
               capsule_digest, branch_id, last_sequence,
               COALESCE((
                   SELECT e.event_hash
                     FROM cell_events AS e
                    WHERE e.tenant_id = c.tenant_id
                      AND e.app_id = c.app_id
                      AND e.cell_id = c.cell_id
                      AND e.session_id = c.session_id
                      AND e.capsule_digest = c.capsule_digest
                      AND e.branch_id = c.branch_id
                    ORDER BY e.sequence DESC
                    LIMIT 1
               ), repeat('0', 64)),
               lease_owner, lease_epoch, lease_expires_at, updated_at
          FROM agent_cells AS c
        ON CONFLICT DO NOTHING;
        ALTER TABLE cell_branch_heads ENABLE ROW LEVEL SECURITY;
        ALTER TABLE cell_branch_heads FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation_cell_branch_heads
            ON cell_branch_heads
            USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
            WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''));

        -- Reject mutation of an event once its append transaction committed.
        CREATE OR REPLACE FUNCTION reject_cell_event_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $function$
        BEGIN
            RAISE EXCEPTION 'cell_events is append-only';
        END
        $function$;
        DROP TRIGGER IF EXISTS cell_events_append_only ON cell_events;
        CREATE TRIGGER cell_events_append_only
            BEFORE UPDATE OR DELETE ON cell_events
            FOR EACH ROW EXECUTE FUNCTION reject_cell_event_mutation();

        CREATE OR REPLACE FUNCTION guard_cell_event_append()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $function$
        DECLARE
            head cell_branch_heads%ROWTYPE;
            expected_hash text;
            session_lease_owner text;
            session_fencing_token_text text;
            session_fencing_token bigint;
            session_lease_expires_at timestamptz;
            branch_lease_owner text;
            branch_fencing_token_text text;
            branch_fencing_token bigint;
            branch_lease_expires_at_text text;
            branch_lease_expires_at timestamptz;
        BEGIN
            -- trpc_worker is deliberately BYPASSRLS for global queue work, so
            -- RLS cannot be its event-write authority.  Every online append
            -- must instead prove the current Session owner/epoch using
            -- transaction-local values set by PostgresEventStore.  The only
            -- no-lease exception is a derived projection whose committed turn
            -- and reply.prepared evidence are already durable.
            IF session_user = 'trpc_worker' THEN
                session_lease_owner := nullif(
                    current_setting('app.cell_session_lease_owner', true), ''
                );
                session_fencing_token_text := nullif(
                    current_setting('app.cell_session_fencing_token', true), ''
                );
                branch_lease_owner := nullif(
                    current_setting('app.cell_branch_lease_owner', true), ''
                );
                branch_fencing_token_text := nullif(
                    current_setting('app.cell_branch_fencing_token', true), ''
                );
                branch_lease_expires_at_text := nullif(
                    current_setting('app.cell_branch_lease_expires_at', true), ''
                );
                IF session_lease_owner IS NOT NULL
                   AND session_fencing_token_text IS NOT NULL THEN
                    IF session_fencing_token_text !~ '^[1-9][0-9]*$' THEN
                        RAISE EXCEPTION 'cell event session fencing token is invalid';
                    END IF;
                    session_fencing_token := session_fencing_token_text::bigint;
                    IF branch_lease_owner IS NULL
                       OR branch_fencing_token_text IS NULL
                       OR branch_lease_expires_at_text IS NULL THEN
                        RAISE EXCEPTION 'cell event branch fence is incomplete';
                    END IF;
                    IF branch_fencing_token_text !~ '^[1-9][0-9]*$' THEN
                        RAISE EXCEPTION 'cell event branch fencing token is invalid';
                    END IF;
                    branch_fencing_token := branch_fencing_token_text::bigint;
                    branch_lease_expires_at := branch_lease_expires_at_text::timestamptz;
                    SELECT session_row.lease_expires_at
                      INTO session_lease_expires_at
                      FROM public.sessions AS session_row
                     WHERE session_row.tenant_id = NEW.tenant_id
                       AND session_row.session_id = NEW.session_id
                       AND session_row.app_id = NEW.app_id
                       AND session_row.lease_owner = session_lease_owner
                       AND session_row.lease_epoch = session_fencing_token
                       AND session_row.lease_expires_at > clock_timestamp()
                     FOR UPDATE;
                    IF NOT FOUND THEN
                        RAISE EXCEPTION 'cell event session lease is stale';
                    END IF;
                    IF branch_lease_owner IS DISTINCT FROM session_lease_owner
                       OR branch_fencing_token IS DISTINCT FROM session_fencing_token
                       OR branch_lease_expires_at IS DISTINCT FROM session_lease_expires_at
                       OR branch_lease_expires_at <= clock_timestamp() THEN
                        RAISE EXCEPTION 'cell event branch fence does not match session lease';
                    END IF;
                ELSIF session_lease_owner IS NOT NULL
                      OR session_fencing_token_text IS NOT NULL THEN
                    RAISE EXCEPTION 'cell event session fence is incomplete';
                ELSE
                    IF branch_lease_owner IS NOT NULL
                       OR branch_fencing_token_text IS NOT NULL
                       OR branch_lease_expires_at_text IS NOT NULL THEN
                        RAISE EXCEPTION
                            'cell event branch fence requires a live session fence';
                    END IF;
                    IF NEW.event_type NOT IN (
                        'turn.committed',
                        'turn.reconcile_required',
                        'tool.effect.committed',
                        'tool.effect.failed',
                        'tool.effect.ambiguous',
                        'tool.effect.unknown',
                        'tool.effect.simulated',
                        'tool.effect.denied',
                        'tool.effect.require_confirmation'
                    ) OR NEW.correlation_id !~
                        '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN
                        RAISE EXCEPTION
                            'cell event requires a live session fence or committed-turn proof';
                    END IF;
                    PERFORM 1
                      FROM public.session_turns AS turn
                      JOIN public.sessions AS session_row
                        ON session_row.tenant_id = turn.tenant_id
                       AND session_row.session_id = turn.session_id
                     WHERE turn.tenant_id = NEW.tenant_id
                       AND turn.session_id = NEW.session_id
                       AND turn.turn_id::text = lower(NEW.correlation_id)
                       AND turn.status = 'committed'
                       AND session_row.app_id = NEW.app_id
                       AND EXISTS (
                            SELECT 1
                              FROM public.cell_events AS evidence
                             WHERE evidence.tenant_id = NEW.tenant_id
                               AND evidence.app_id = NEW.app_id
                               AND evidence.cell_id = NEW.cell_id
                               AND evidence.session_id = NEW.session_id
                               AND evidence.capsule_digest = NEW.capsule_digest
                               AND evidence.branch_id = NEW.branch_id
                               AND evidence.correlation_id = NEW.correlation_id
                               AND evidence.event_type = 'reply.prepared'
                               AND evidence.sequence < NEW.sequence
                       );
                    IF NOT FOUND THEN
                        RAISE EXCEPTION 'cell event committed-turn proof is invalid';
                    END IF;
                END IF;
            END IF;

            SELECT * INTO head
              FROM public.cell_branch_heads
             WHERE tenant_id = NEW.tenant_id
               AND app_id = NEW.app_id
               AND cell_id = NEW.cell_id
               AND session_id = NEW.session_id
               AND capsule_digest = NEW.capsule_digest
               AND branch_id = NEW.branch_id
             FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'cell branch head is missing';
            END IF;
            IF session_lease_owner IS NOT NULL THEN
                -- The complete Session fence is authoritative for the live
                -- Worker.  A NULL/0/NULL head is the explicit branch
                -- initialization state (also used by forked heads); after
                -- the session row is locked above, rebinding the mirror
                -- cannot resurrect a stale Worker.  Every online append
                -- still supplies owner, epoch and expiry through GUCs, and
                -- the comparisons above use the database clock.
                IF head.lease_epoch > branch_fencing_token THEN
                    RAISE EXCEPTION 'cell branch lease epoch is stale';
                END IF;
                IF head.lease_epoch = branch_fencing_token
                   AND head.lease_owner IS NOT NULL
                   AND head.lease_owner IS DISTINCT FROM branch_lease_owner
                   AND head.lease_expires_at > clock_timestamp() THEN
                    RAISE EXCEPTION 'cell branch lease owner is stale';
                END IF;
                UPDATE public.cell_branch_heads
                   SET lease_owner = branch_lease_owner,
                       lease_epoch = branch_fencing_token,
                       lease_expires_at = branch_lease_expires_at,
                       updated_at = clock_timestamp()
                 WHERE tenant_id = NEW.tenant_id
                   AND app_id = NEW.app_id
                   AND cell_id = NEW.cell_id
                   AND session_id = NEW.session_id
                   AND capsule_digest = NEW.capsule_digest
                   AND branch_id = NEW.branch_id;
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'cell branch lease update failed';
                END IF;
            END IF;
            expected_hash := CASE
                WHEN head.last_sequence = 0 THEN repeat('0', 64)
                ELSE head.last_event_hash
            END;
            IF NEW.sequence <> head.last_sequence + 1
               OR NEW.prev_hash <> expected_hash THEN
                RAISE EXCEPTION 'cell event append failed branch-head CAS';
            END IF;
            RETURN NEW;
        END
        $function$;
        DROP TRIGGER IF EXISTS cell_events_branch_head_guard ON cell_events;
        CREATE TRIGGER cell_events_branch_head_guard
            BEFORE INSERT ON cell_events
            FOR EACH ROW EXECUTE FUNCTION guard_cell_event_append();

        CREATE OR REPLACE FUNCTION advance_cell_event_head()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $function$
        BEGIN
            UPDATE public.cell_branch_heads
               SET last_sequence = NEW.sequence,
                   last_event_hash = NEW.event_hash,
                   updated_at = clock_timestamp()
             WHERE tenant_id = NEW.tenant_id
               AND app_id = NEW.app_id
               AND cell_id = NEW.cell_id
               AND session_id = NEW.session_id
               AND capsule_digest = NEW.capsule_digest
               AND branch_id = NEW.branch_id
               AND last_sequence = NEW.sequence - 1
               AND last_event_hash = NEW.prev_hash;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'cell event append did not advance branch head';
            END IF;
            UPDATE public.agent_cells
               SET last_sequence = GREATEST(last_sequence, NEW.sequence),
                   updated_at = clock_timestamp()
             WHERE tenant_id = NEW.tenant_id
               AND app_id = NEW.app_id
               AND cell_id = NEW.cell_id
               AND session_id = NEW.session_id
               AND capsule_digest = NEW.capsule_digest
               AND branch_id = NEW.branch_id;
            RETURN NEW;
        END
        $function$;
        DROP TRIGGER IF EXISTS cell_events_head_advance ON cell_events;
        CREATE CONSTRAINT TRIGGER cell_events_head_advance
            AFTER INSERT ON cell_events
            DEFERRABLE INITIALLY IMMEDIATE
            FOR EACH ROW EXECUTE FUNCTION advance_cell_event_head();

        -- A runtime projection is evidence about an execution, never a
        -- deployment authorization.  Keeping the trust class in the schema
        -- prevents a compromised cross-tenant worker from turning its local
        -- projection signer into a scheduler-admitted Capsule signer.
        ALTER TABLE agent_capsules
            -- Rows created by 0017 predate trusted-key admission.  They must
            -- never acquire deployment authority merely by being upgraded.
            ADD COLUMN trust_class text NOT NULL DEFAULT 'runtime_projection'
            CHECK (trust_class IN ('deployment', 'runtime_projection'));
        ALTER TABLE agent_capsules ALTER COLUMN trust_class DROP DEFAULT;

        CREATE OR REPLACE FUNCTION persist_agent_capsule(
            p_tenant_id text,
            p_capsule_digest text,
            p_capsule_name text,
            p_manifest jsonb,
            p_signature text,
            p_signer_key_id text,
            p_trust_class text
        ) RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $function$
        BEGIN
            IF p_tenant_id IS DISTINCT FROM
               nullif(current_setting('app.tenant_id', true), '') THEN
                RAISE EXCEPTION 'capsule tenant does not match app.tenant_id';
            END IF;
            IF p_capsule_digest !~ '^sha256:[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'capsule digest is not a content digest';
            END IF;
            IF p_trust_class NOT IN ('deployment', 'runtime_projection') THEN
                RAISE EXCEPTION 'capsule trust class is invalid';
            END IF;
            IF p_manifest->>'digest' IS DISTINCT FROM p_capsule_digest
               OR p_manifest#>>'{metadata,tenant_id}' IS DISTINCT FROM p_tenant_id
               OR p_manifest#>>'{metadata,name}' IS DISTINCT FROM p_capsule_name THEN
                RAISE EXCEPTION 'capsule envelope does not match its registry identity';
            END IF;
            IF p_signature IS NULL OR p_signature = ''
               OR p_signer_key_id IS NULL OR p_signer_key_id = ''
               OR p_manifest#>>'{signature,value}' IS DISTINCT FROM p_signature
               OR p_manifest#>>'{signature,key_id}' IS DISTINCT FROM p_signer_key_id THEN
                RAISE EXCEPTION 'capsule signature envelope is required and must match';
            END IF;
            INSERT INTO agent_capsules (
                tenant_id, capsule_digest, capsule_name, manifest,
                signature, signer_key_id, trust_class
            ) VALUES (
                p_tenant_id, p_capsule_digest, p_capsule_name, p_manifest,
                p_signature, p_signer_key_id, p_trust_class
            )
            ON CONFLICT (tenant_id, capsule_digest) DO NOTHING;
            IF EXISTS (
                SELECT 1
                  FROM agent_capsules
                 WHERE tenant_id = p_tenant_id
                   AND capsule_digest = p_capsule_digest
                   AND (
                        capsule_name IS DISTINCT FROM p_capsule_name
                        OR trust_class IS DISTINCT FROM p_trust_class
                        OR (manifest - 'digest' - 'signature') IS DISTINCT FROM
                          (p_manifest - 'digest' - 'signature')
                   )
            ) THEN
                RAISE EXCEPTION
                    'capsule digest is immutable and conflicts with existing manifest';
            END IF;
            -- The unsigned content is immutable, while the signature envelope
            -- is deliberately rotatable during key rollover.
            UPDATE agent_capsules
               SET manifest = p_manifest,
                   signature = p_signature,
                   signer_key_id = p_signer_key_id
             WHERE tenant_id = p_tenant_id
               AND capsule_digest = p_capsule_digest;
        END
        $function$;
        REVOKE ALL ON FUNCTION persist_agent_capsule(
            text, text, text, jsonb, text, text, text
        ) FROM PUBLIC;

        CREATE OR REPLACE FUNCTION ensure_agent_capsule(
            p_tenant_id text, p_capsule_digest text, p_capsule_name text,
            p_manifest jsonb, p_signature text, p_signer_key_id text
        ) RETURNS void
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp
        AS $function$
            SELECT public.persist_agent_capsule(
                p_tenant_id, p_capsule_digest, p_capsule_name, p_manifest,
                p_signature, p_signer_key_id, 'deployment'
            );
        $function$;
        CREATE OR REPLACE FUNCTION ensure_runtime_projection_capsule(
            p_tenant_id text, p_capsule_digest text, p_capsule_name text,
            p_manifest jsonb, p_signature text, p_signer_key_id text
        ) RETURNS void
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp
        AS $function$
            SELECT public.persist_agent_capsule(
                p_tenant_id, p_capsule_digest, p_capsule_name, p_manifest,
                p_signature, p_signer_key_id, 'runtime_projection'
            );
        $function$;
        REVOKE ALL ON FUNCTION ensure_agent_capsule(
            text, text, text, jsonb, text, text
        ) FROM PUBLIC;
        REVOKE ALL ON FUNCTION ensure_runtime_projection_capsule(
            text, text, text, jsonb, text, text
        ) FROM PUBLIC;
        DO $capsule_grant$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_runtime') THEN
                -- Deployment registration is a control-plane/KMS operation.
                -- The ordinary runtime role must not mint scheduler-authorising
                -- Capsules; a dedicated control-plane credential may receive
                -- this grant explicitly during production provisioning.
                REVOKE INSERT ON agent_capsules FROM trpc_runtime;
                REVOKE EXECUTE ON FUNCTION ensure_agent_capsule(
                    text, text, text, jsonb, text, text
                ) FROM trpc_runtime;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_worker') THEN
                REVOKE INSERT ON agent_capsules FROM trpc_worker;
                REVOKE EXECUTE ON FUNCTION ensure_agent_capsule(
                    text, text, text, jsonb, text, text
                ) FROM trpc_worker;
                -- Worker journals can create non-authorizing evidence only.
                GRANT EXECUTE ON FUNCTION ensure_runtime_projection_capsule(
                    text, text, text, jsonb, text, text
                ) TO trpc_worker;
            END IF;
        END
        $capsule_grant$;
        """
    )

    op.execute(
        """
        -- Node capacity is global placement state; reservations remain tenant
        -- scoped.  ``used_*`` is updated while the node row is FOR UPDATE.
        CREATE TABLE cell_node_capacity (
            node_id text PRIMARY KEY,
            region text NOT NULL,
            capacity_cpu_millis bigint NOT NULL CHECK (capacity_cpu_millis > 0),
            used_cpu_millis bigint NOT NULL DEFAULT 0 CHECK (used_cpu_millis >= 0),
            capacity_memory_mb bigint NOT NULL CHECK (capacity_memory_mb > 0),
            used_memory_mb bigint NOT NULL DEFAULT 0 CHECK (used_memory_mb >= 0),
            max_cells bigint NOT NULL CHECK (max_cells > 0),
            active_cells bigint NOT NULL DEFAULT 0 CHECK (active_cells >= 0),
            healthy boolean NOT NULL DEFAULT true,
            draining boolean NOT NULL DEFAULT false,
            generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            CONSTRAINT ck_cell_node_cpu_bound
                CHECK (used_cpu_millis <= capacity_cpu_millis),
            CONSTRAINT ck_cell_node_memory_bound
                CHECK (used_memory_mb <= capacity_memory_mb),
            CONSTRAINT ck_cell_node_cells_bound
                CHECK (active_cells <= max_cells)
        );

        CREATE TABLE cell_placement_reservations (
            reservation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
            cell_id text NOT NULL,
            app_id text NOT NULL,
            session_id text NOT NULL,
            capsule_digest text NOT NULL,
            branch_id text NOT NULL,
            node_id text NOT NULL REFERENCES cell_node_capacity(node_id),
            owner_id text NOT NULL,
            lease_epoch bigint NOT NULL CHECK (lease_epoch >= 1),
            status text NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'released', 'expired')),
            cpu_millis bigint NOT NULL CHECK (cpu_millis > 0),
            memory_mb bigint NOT NULL CHECK (memory_mb > 0),
            decision jsonb NOT NULL,
            expires_at timestamptz NOT NULL,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            FOREIGN KEY (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id
            ) REFERENCES agent_cells (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id
            ) ON DELETE CASCADE
        );
        CREATE UNIQUE INDEX ux_cell_active_reservation
            ON cell_placement_reservations (
                tenant_id, app_id, cell_id, session_id,
                capsule_digest, branch_id
            )
            WHERE status = 'active';
        CREATE INDEX ix_cell_reservation_node
            ON cell_placement_reservations (node_id, status, expires_at);

        CREATE TABLE cell_approval_nonces (
            tenant_id text NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
            nonce_digest text NOT NULL,
            scope_digest text NOT NULL,
            expires_at timestamptz NOT NULL,
            consumed_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (tenant_id, nonce_digest),
            CONSTRAINT ck_cell_approval_nonce_digest
                CHECK (nonce_digest ~ '^[0-9a-f]{64}$'),
            CONSTRAINT ck_cell_approval_scope_digest
                CHECK (scope_digest ~ '^[0-9a-f]{64}$')
        );
        CREATE INDEX ix_cell_approval_nonce_expiry
            ON cell_approval_nonces (tenant_id, nonce_digest, expires_at)
            WHERE consumed_at IS NULL;
        ALTER TABLE cell_approval_nonces ENABLE ROW LEVEL SECURITY;
        ALTER TABLE cell_approval_nonces FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation_cell_approval_nonces
            ON cell_approval_nonces
            USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
            WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''));
        -- Placement cleanup is performed by SECURITY DEFINER functions that
        -- maintain global node counters.  Keep ordinary runtime access tenant
        -- isolated, but do not FORCE RLS here: the table/function owner must
        -- see expired reservations from every tenant while reclaiming capacity.
        ALTER TABLE cell_placement_reservations ENABLE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation_cell_placement_reservations
            ON cell_placement_reservations
            USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
            WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''));

        -- Approval nonces are immutable except for the single NULL -> now()
        -- transition below.  Callers never receive table DML, so a process
        -- cannot reset consumed_at and replay an already used credential.
        CREATE OR REPLACE FUNCTION issue_cell_approval_nonce(
            p_tenant_id text,
            p_nonce_digest text,
            p_scope_digest text,
            p_expires_at timestamptz
        ) RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $function$
        BEGIN
            IF p_tenant_id IS DISTINCT FROM
               nullif(current_setting('app.tenant_id', true), '') THEN
                RAISE EXCEPTION 'approval tenant does not match app.tenant_id';
            END IF;
            IF p_nonce_digest !~ '^[0-9a-f]{64}$'
               OR p_scope_digest !~ '^[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'approval digests must be SHA-256 hex';
            END IF;
            IF p_expires_at IS NULL
               OR NOT isfinite(p_expires_at)
               OR p_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'approval expiry must be finite and in the future';
            END IF;
            INSERT INTO public.cell_approval_nonces (
                tenant_id, nonce_digest, scope_digest, expires_at
            ) VALUES (
                p_tenant_id, p_nonce_digest, p_scope_digest, p_expires_at
            );
        END
        $function$;

        CREATE OR REPLACE FUNCTION consume_cell_approval_nonce(
            p_tenant_id text,
            p_nonce_digest text,
            p_scope_digest text,
            p_expires_at timestamptz
        ) RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $function$
        DECLARE
            consumed boolean := false;
        BEGIN
            IF p_tenant_id IS DISTINCT FROM
               nullif(current_setting('app.tenant_id', true), '') THEN
                RETURN false;
            END IF;
            IF p_expires_at IS NULL OR NOT isfinite(p_expires_at) THEN
                RETURN false;
            END IF;
            UPDATE public.cell_approval_nonces
               SET consumed_at = clock_timestamp()
             WHERE tenant_id = p_tenant_id
               AND nonce_digest = p_nonce_digest
               AND scope_digest = p_scope_digest
                AND consumed_at IS NULL
                AND expires_at = p_expires_at
                AND isfinite(expires_at)
                AND expires_at > clock_timestamp()
             RETURNING true INTO consumed;
            RETURN COALESCE(consumed, false);
        END
        $function$;
        REVOKE ALL ON FUNCTION issue_cell_approval_nonce(
            text, text, text, timestamptz
        ) FROM PUBLIC;
        REVOKE ALL ON FUNCTION consume_cell_approval_nonce(
            text, text, text, timestamptz
        ) FROM PUBLIC;

        CREATE OR REPLACE FUNCTION update_cell_node_snapshot(
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
            INSERT INTO cell_node_capacity (
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
                updated_at = clock_timestamp()
            RETURNING generation INTO next_generation;
            RETURN next_generation;
        END
        $function$;

        CREATE OR REPLACE FUNCTION reserve_cell_placement(
            p_reservation_id uuid,
            p_tenant_id text,
            p_cell_id text,
            p_app_id text,
            p_session_id text,
            p_capsule_digest text,
            p_branch_id text,
            p_node_id text,
            p_owner_id text,
            p_cpu_millis bigint,
            p_memory_mb bigint,
            p_decision jsonb,
            p_lease_seconds double precision
        ) RETURNS TABLE (
            reservation_id uuid,
            lease_epoch bigint,
            expires_at timestamptz,
            decision jsonb
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $function$
        DECLARE
            node cell_node_capacity%ROWTYPE;
            existing cell_placement_reservations%ROWTYPE;
            expired cell_placement_reservations%ROWTYPE;
            winner jsonb;
            existing_node_id text;
            now_at timestamptz := clock_timestamp();
            used_cpu bigint;
            used_memory bigint;
            used_cells bigint;
        BEGIN
            IF p_tenant_id IS DISTINCT FROM
               nullif(current_setting('app.tenant_id', true), '') THEN
                RAISE EXCEPTION 'reservation tenant does not match app.tenant_id';
            END IF;
            IF p_lease_seconds IS NULL
               OR NOT (
                   p_lease_seconds > 0
                   AND p_lease_seconds < 'Infinity'::double precision
               )
               OR p_cpu_millis <= 0 OR p_memory_mb <= 0 THEN
                RAISE EXCEPTION 'reservation values must be positive';
            END IF;
            IF jsonb_typeof(p_decision) IS DISTINCT FROM 'object'
               OR jsonb_typeof(p_decision->'cell_id') IS DISTINCT FROM 'string'
               OR p_decision->>'cell_id' IS DISTINCT FROM p_cell_id
               OR jsonb_typeof(p_decision->'node_id') IS DISTINCT FROM 'string'
               OR p_decision->>'node_id' IS DISTINCT FROM p_node_id
               OR jsonb_typeof(p_decision->'score') IS DISTINCT FROM 'number'
               OR jsonb_typeof(p_decision->'candidates') IS DISTINCT FROM 'array' THEN
                RAISE EXCEPTION 'placement decision does not match reservation identity';
            END IF;
            IF jsonb_array_length(p_decision->'candidates') < 1 THEN
                RAISE EXCEPTION 'placement decision must include its winner';
            END IF;
            winner := p_decision->'candidates'->0;
            IF jsonb_typeof(winner) IS DISTINCT FROM 'object'
               OR jsonb_typeof(winner->'node_id') IS DISTINCT FROM 'string'
               OR winner->>'node_id' IS DISTINCT FROM p_node_id
               OR jsonb_typeof(winner->'score') IS DISTINCT FROM 'number'
               OR (winner->'score') IS DISTINCT FROM (p_decision->'score') THEN
                RAISE EXCEPTION 'placement decision winner does not match reservation node';
            END IF;
            IF EXISTS (
                SELECT 1
                  FROM jsonb_array_elements(p_decision->'candidates') AS candidate
                 WHERE jsonb_typeof(candidate) IS DISTINCT FROM 'object'
                    OR jsonb_typeof(candidate->'node_id') IS DISTINCT FROM 'string'
                    OR jsonb_typeof(candidate->'score') IS DISTINCT FROM 'number'
            ) THEN
                RAISE EXCEPTION 'placement decision candidates are invalid';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                  FROM agent_cells AS c
                  JOIN agent_capsules AS a
                    ON a.tenant_id = c.tenant_id
                   AND a.capsule_digest = c.capsule_digest
                 WHERE c.tenant_id = p_tenant_id
                   AND c.app_id = p_app_id
                   AND c.cell_id = p_cell_id
                   AND c.session_id = p_session_id
                   AND c.capsule_digest = p_capsule_digest
                   AND c.branch_id = p_branch_id
                   AND a.trust_class = 'deployment'
            ) THEN
                RAISE EXCEPTION 'runtime projection capsule cannot authorize placement';
            END IF;
            -- Discover a previous placement first, then lock every involved
            -- node in stable order.  This permits an expired Cell to move to a
            -- different node without leaking the old capacity counters or
            -- deadlocking two concurrent cross-node moves.
            SELECT node_id INTO existing_node_id
              FROM cell_placement_reservations
             WHERE tenant_id = p_tenant_id
               AND cell_id = p_cell_id
               AND app_id = p_app_id
               AND session_id = p_session_id
               AND capsule_digest = p_capsule_digest
               AND branch_id = p_branch_id
               AND status = 'active';
            PERFORM 1 FROM cell_node_capacity
             WHERE node_id = p_node_id OR node_id = existing_node_id
             ORDER BY node_id
             FOR UPDATE;
            SELECT * INTO node FROM cell_node_capacity
             WHERE node_id = p_node_id;
            IF NOT FOUND OR NOT node.healthy OR node.draining THEN
                RAISE EXCEPTION 'node is unavailable for placement';
            END IF;

            FOR expired IN
                SELECT * FROM cell_placement_reservations
                 WHERE node_id = p_node_id
                   AND status = 'active'
                   AND expires_at <= now_at
                 FOR UPDATE
            LOOP
                UPDATE cell_placement_reservations
                   SET status = 'expired', updated_at = now_at
                 WHERE reservation_id = expired.reservation_id;
                UPDATE cell_node_capacity
                   SET used_cpu_millis = used_cpu_millis - expired.cpu_millis,
                       used_memory_mb = used_memory_mb - expired.memory_mb,
                       active_cells = active_cells - 1,
                       updated_at = now_at
                 WHERE node_id = p_node_id;
            END LOOP;

            SELECT * INTO existing
              FROM cell_placement_reservations
             WHERE tenant_id = p_tenant_id
               AND cell_id = p_cell_id
               AND app_id = p_app_id
               AND session_id = p_session_id
               AND capsule_digest = p_capsule_digest
               AND branch_id = p_branch_id
               AND status = 'active'
              FOR UPDATE;
            IF FOUND AND existing.expires_at <= now_at THEN
                IF existing.node_id <> p_node_id
                   AND existing.node_id IS DISTINCT FROM existing_node_id THEN
                    RAISE EXCEPTION 'placement changed concurrently; retry reservation';
                END IF;
                UPDATE cell_placement_reservations
                   SET status = 'expired', updated_at = now_at
                 WHERE reservation_id = existing.reservation_id;
                UPDATE cell_node_capacity
                   SET used_cpu_millis = used_cpu_millis - existing.cpu_millis,
                       used_memory_mb = used_memory_mb - existing.memory_mb,
                       active_cells = active_cells - 1,
                       updated_at = now_at
                 WHERE node_id = existing.node_id;
            END IF;

            SELECT * INTO existing
              FROM cell_placement_reservations
             WHERE tenant_id = p_tenant_id
               AND cell_id = p_cell_id
               AND app_id = p_app_id
               AND session_id = p_session_id
               AND capsule_digest = p_capsule_digest
               AND branch_id = p_branch_id
               AND status = 'active'
             FOR UPDATE;
            IF FOUND THEN
                IF existing.owner_id = p_owner_id
                   AND existing.node_id = p_node_id
                   AND existing.cpu_millis = p_cpu_millis
                   AND existing.memory_mb = p_memory_mb THEN
                    RETURN QUERY SELECT existing.reservation_id,
                        existing.lease_epoch, existing.expires_at, existing.decision;
                    RETURN;
                END IF;
                RAISE EXCEPTION 'Cell already has an active placement reservation';
            END IF;

            SELECT used_cpu_millis, used_memory_mb, active_cells
              INTO used_cpu, used_memory, used_cells
              FROM cell_node_capacity
             WHERE node_id = p_node_id;
            IF used_cpu + p_cpu_millis > node.capacity_cpu_millis
               OR used_memory + p_memory_mb > node.capacity_memory_mb
               OR used_cells + 1 > node.max_cells THEN
                RAISE EXCEPTION 'node capacity reservation conflict';
            END IF;
            UPDATE cell_node_capacity
               SET used_cpu_millis = used_cpu_millis + p_cpu_millis,
                   used_memory_mb = used_memory_mb + p_memory_mb,
                   active_cells = active_cells + 1,
                   updated_at = now_at
             WHERE node_id = p_node_id;
            INSERT INTO cell_placement_reservations (
                reservation_id, tenant_id, cell_id, app_id, session_id,
                capsule_digest, branch_id, node_id, owner_id,
                lease_epoch, cpu_millis, memory_mb, decision, expires_at
            ) VALUES (
                p_reservation_id, p_tenant_id, p_cell_id, p_app_id, p_session_id,
                p_capsule_digest, p_branch_id, p_node_id, p_owner_id,
                1, p_cpu_millis, p_memory_mb, p_decision,
                now_at + make_interval(secs => p_lease_seconds)
            ) RETURNING cell_placement_reservations.reservation_id,
                        cell_placement_reservations.lease_epoch,
                        cell_placement_reservations.expires_at,
                        cell_placement_reservations.decision
                 INTO reservation_id, lease_epoch, expires_at, decision;
            RETURN NEXT;
        END
        $function$;

        CREATE OR REPLACE FUNCTION renew_cell_placement(
            p_reservation_id uuid,
            p_owner_id text,
            p_expected_lease_epoch bigint,
            p_lease_seconds double precision
        ) RETURNS TABLE (
            reservation_id uuid,
            lease_epoch bigint,
            expires_at timestamptz,
            decision jsonb
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $function$
        DECLARE
            current_reservation cell_placement_reservations%ROWTYPE;
            now_at timestamptz := clock_timestamp();
        BEGIN
            IF p_lease_seconds IS NULL OR NOT (
                p_lease_seconds > 0
                AND p_lease_seconds < 'Infinity'::double precision
            ) THEN
                RAISE EXCEPTION 'placement lease duration must be positive';
            END IF;
            SELECT * INTO current_reservation
              FROM cell_placement_reservations
             WHERE reservation_id = p_reservation_id
               AND tenant_id = nullif(current_setting('app.tenant_id', true), '')
             FOR UPDATE;
            IF NOT FOUND OR current_reservation.status <> 'active'
               OR current_reservation.owner_id <> p_owner_id
               OR current_reservation.lease_epoch <> p_expected_lease_epoch
               OR current_reservation.expires_at <= now_at THEN
                RAISE EXCEPTION 'placement reservation is fenced or expired';
            END IF;
            UPDATE cell_placement_reservations
               SET lease_epoch = current_reservation.lease_epoch + 1,
                   expires_at = now_at + make_interval(secs => p_lease_seconds),
                   updated_at = now_at
             WHERE reservation_id = p_reservation_id
            RETURNING cell_placement_reservations.reservation_id,
                      cell_placement_reservations.lease_epoch,
                      cell_placement_reservations.expires_at,
                      cell_placement_reservations.decision
                 INTO reservation_id, lease_epoch, expires_at, decision;
            RETURN NEXT;
        END
        $function$;

        CREATE OR REPLACE FUNCTION release_cell_placement(
            p_reservation_id uuid,
            p_owner_id text,
            p_expected_lease_epoch bigint
        ) RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $function$
        DECLARE
            current_reservation cell_placement_reservations%ROWTYPE;
        BEGIN
            -- Reserve locks node capacity before reservation rows.  Acquire a
            -- non-locking copy first and then take the same node lock here so
            -- release cannot deadlock with expiry cleanup in reserve.
            SELECT * INTO current_reservation
              FROM cell_placement_reservations
             WHERE reservation_id = p_reservation_id
               AND tenant_id = nullif(current_setting('app.tenant_id', true), '');
            IF NOT FOUND OR current_reservation.status <> 'active' THEN
                RETURN;
            END IF;
            PERFORM 1 FROM cell_node_capacity
             WHERE node_id = current_reservation.node_id
             FOR UPDATE;
            SELECT * INTO current_reservation
              FROM cell_placement_reservations
             WHERE reservation_id = p_reservation_id
               AND tenant_id = nullif(current_setting('app.tenant_id', true), '')
             FOR UPDATE;
            IF NOT FOUND OR current_reservation.status <> 'active' THEN
                RETURN;
            END IF;
            IF current_reservation.owner_id <> p_owner_id THEN
                RAISE EXCEPTION 'placement reservation owner is fenced';
            END IF;
            IF current_reservation.lease_epoch <> p_expected_lease_epoch THEN
                RAISE EXCEPTION 'placement reservation lease epoch is fenced';
            END IF;
            UPDATE cell_placement_reservations
               SET status = 'released', updated_at = clock_timestamp()
             WHERE reservation_id = p_reservation_id;
            UPDATE cell_node_capacity
               SET used_cpu_millis = used_cpu_millis - current_reservation.cpu_millis,
                   used_memory_mb = used_memory_mb - current_reservation.memory_mb,
                   active_cells = active_cells - 1,
                   updated_at = clock_timestamp()
             WHERE node_id = current_reservation.node_id;
        END
        $function$;

        REVOKE ALL ON FUNCTION update_cell_node_snapshot(
            text, text, bigint, bigint, bigint, boolean, boolean
        ) FROM PUBLIC;
        REVOKE ALL ON FUNCTION reserve_cell_placement(
            uuid, text, text, text, text, text, text, text, text,
            bigint, bigint, jsonb, double precision
        ) FROM PUBLIC;
        REVOKE ALL ON FUNCTION renew_cell_placement(
            uuid, text, bigint, double precision
        ) FROM PUBLIC;
        REVOKE ALL ON FUNCTION release_cell_placement(uuid, text, bigint) FROM PUBLIC;
        DO $scheduler_grant$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_scheduler') THEN
                GRANT EXECUTE ON FUNCTION update_cell_node_snapshot(
                    text, text, bigint, bigint, bigint, boolean, boolean
                ) TO trpc_scheduler;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_runtime') THEN
                GRANT EXECUTE ON FUNCTION reserve_cell_placement(
                    uuid, text, text, text, text, text, text, text, text,
                    bigint, bigint, jsonb, double precision
                ) TO trpc_runtime;
                GRANT EXECUTE ON FUNCTION renew_cell_placement(
                    uuid, text, bigint, double precision
                ) TO trpc_runtime;
                GRANT EXECUTE ON FUNCTION release_cell_placement(
                    uuid, text, bigint
                ) TO trpc_runtime;
            END IF;
        END
        $scheduler_grant$;

        -- The bootstrap grant exists for the legacy schema.  Starting with
        -- this revision, every new table must opt in explicitly.
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
            REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM trpc_runtime;

        DO $grant$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_runtime') THEN
                REVOKE ALL ON agent_capsules, agent_cells, cell_events,
                    cell_tool_intents, cell_effect_ledger, cell_effect_receipts,
                    cell_branch_heads, cell_placement_reservations,
                    cell_approval_nonces, cell_node_capacity FROM trpc_runtime;
                -- Tenant runtime can observe placement state.  Every Cell
                -- mutation remains either Worker-only or a controlled
                -- SECURITY DEFINER transition.
                GRANT SELECT ON agent_capsules, agent_cells, cell_branch_heads,
                    cell_placement_reservations TO trpc_runtime;
                REVOKE ALL ON cell_node_capacity FROM trpc_runtime;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_worker') THEN
                REVOKE ALL ON agent_capsules, agent_cells, cell_events,
                    cell_tool_intents, cell_effect_ledger, cell_effect_receipts,
                    cell_branch_heads, cell_placement_reservations,
                    cell_approval_nonces, cell_node_capacity FROM trpc_worker;
                GRANT SELECT ON agent_capsules TO trpc_worker;
                GRANT SELECT, INSERT ON agent_cells TO trpc_worker;
                GRANT SELECT, INSERT ON cell_events TO trpc_worker;
                GRANT SELECT, INSERT ON cell_branch_heads TO trpc_worker;
                -- Native Intent/Effect and approval adapters are not on the
                -- default Worker hot path.  They require a separately
                -- provisioned executor role instead of expanding this
                -- cross-tenant coordination root.
                REVOKE ALL ON cell_tool_intents, cell_effect_ledger,
                    cell_effect_receipts, cell_approval_nonces,
                    cell_placement_reservations FROM trpc_worker;
                REVOKE ALL ON cell_node_capacity FROM trpc_worker;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_cell_executor') THEN
                -- A separately provisioned executor must not inherit a wider
                -- schema grant.  Revoke direct Cell-table privileges first,
                -- then fail closed if the role itself is privileged or is a
                -- member of another role (NOINHERIT alone does not prevent
                -- SET ROLE into a granted membership).
                REVOKE ALL ON agent_capsules, agent_cells, cell_events,
                    cell_tool_intents, cell_effect_ledger, cell_effect_receipts,
                    cell_branch_heads, cell_placement_reservations,
                    cell_approval_nonces, cell_node_capacity
                    FROM trpc_cell_executor;
                IF EXISTS (
                    SELECT 1
                      FROM pg_roles
                     WHERE rolname = 'trpc_cell_executor'
                       AND (
                           rolsuper
                           OR rolbypassrls
                           OR rolinherit IS DISTINCT FROM FALSE
                           OR rolcanlogin IS DISTINCT FROM TRUE
                       )
                ) THEN
                    RAISE EXCEPTION
                        'trpc_cell_executor must be LOGIN NOSUPERUSER NOINHERIT NOBYPASSRLS';
                END IF;
                IF EXISTS (
                    SELECT 1
                      FROM pg_auth_members AS membership
                      JOIN pg_roles AS member ON member.oid = membership.member
                     WHERE member.rolname = 'trpc_cell_executor'
                ) THEN
                    RAISE EXCEPTION
                        'trpc_cell_executor must not inherit any role membership';
                END IF;
                GRANT SELECT ON cell_events TO trpc_cell_executor;
                GRANT SELECT, INSERT ON cell_tool_intents TO trpc_cell_executor;
                GRANT SELECT, INSERT, UPDATE ON cell_effect_ledger TO trpc_cell_executor;
                GRANT SELECT, INSERT ON cell_effect_receipts TO trpc_cell_executor;
                GRANT EXECUTE ON FUNCTION issue_cell_approval_nonce(
                    text, text, text, timestamptz
                ) TO trpc_cell_executor;
                GRANT EXECUTE ON FUNCTION consume_cell_approval_nonce(
                    text, text, text, timestamptz
                ) TO trpc_cell_executor;
            END IF;
        END
        $grant$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DO $downgrade_guard$
        BEGIN
            IF EXISTS (
                SELECT 1
                  FROM agent_capsules
                 WHERE trust_class = 'deployment'
            ) THEN
                RAISE EXCEPTION
                    '0018 downgrade refused: deployment Capsule trust would be lost';
            END IF;
            IF EXISTS (
                SELECT 1
                  FROM agent_cells
                 GROUP BY tenant_id, cell_id, branch_id
                HAVING count(*) > 1
            ) THEN
                RAISE EXCEPTION
                    '0018 downgrade refused: agent_cells namespace collision would lose data';
            END IF;
            IF EXISTS (
                SELECT 1
                  FROM cell_events
                 GROUP BY tenant_id, cell_id, branch_id, sequence
                HAVING count(*) > 1
            ) THEN
                RAISE EXCEPTION
                    '0018 downgrade refused: cell_events namespace collision would lose data';
            END IF;
        END
        $downgrade_guard$;

        DROP INDEX IF EXISTS ix_cell_events_full_stream;
        DROP INDEX IF EXISTS ix_cell_tool_intents_stream;
        DROP INDEX IF EXISTS ix_cell_effect_ledger_stream;
        DROP TRIGGER IF EXISTS cell_events_append_only ON cell_events;
        DROP TRIGGER IF EXISTS cell_events_branch_head_guard ON cell_events;
        DROP TRIGGER IF EXISTS cell_events_head_advance ON cell_events;
        DROP FUNCTION IF EXISTS reject_cell_event_mutation();
        DROP FUNCTION IF EXISTS ensure_agent_capsule(text, text, text, jsonb, text, text);
        DROP FUNCTION IF EXISTS ensure_runtime_projection_capsule(
            text, text, text, jsonb, text, text
        );
        DROP FUNCTION IF EXISTS issue_cell_approval_nonce(
            text, text, text, timestamptz
        );
        DROP FUNCTION IF EXISTS consume_cell_approval_nonce(
            text, text, text, timestamptz
        );
        DROP FUNCTION IF EXISTS persist_agent_capsule(
            text, text, text, jsonb, text, text, text
        );
        DROP FUNCTION IF EXISTS guard_cell_event_append();
        DROP FUNCTION IF EXISTS advance_cell_event_head();
        DROP FUNCTION IF EXISTS update_cell_node_snapshot(
            text, text, bigint, bigint, bigint, boolean, boolean
        );
        DROP FUNCTION IF EXISTS reserve_cell_placement(
            uuid, text, text, text, text, text, text, text, text,
            bigint, bigint, jsonb, double precision
        );
        DROP FUNCTION IF EXISTS renew_cell_placement(uuid, text, bigint, double precision);
        DROP FUNCTION IF EXISTS release_cell_placement(uuid, text, bigint);
        DROP TABLE IF EXISTS cell_placement_reservations;
        DROP TABLE IF EXISTS cell_approval_nonces;
        DROP TABLE IF EXISTS cell_node_capacity;
        DROP TABLE IF EXISTS cell_branch_heads;
        ALTER TABLE agent_capsules DROP COLUMN IF EXISTS trust_class;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
            GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO trpc_runtime;

        ALTER TABLE cell_effect_receipts
            DROP CONSTRAINT IF EXISTS cell_effect_receipts_ledger_fk,
            DROP CONSTRAINT IF EXISTS cell_effect_receipts_intent_fk;
        ALTER TABLE cell_effect_ledger
            DROP CONSTRAINT IF EXISTS cell_effect_ledger_namespace_effect_key;
        ALTER TABLE cell_tool_intents
            DROP CONSTRAINT IF EXISTS cell_tool_intents_namespace_intent_key;
        ALTER TABLE cell_effect_ledger
            DROP CONSTRAINT IF EXISTS cell_effect_ledger_intent_fk;
        ALTER TABLE cell_tool_intents
            DROP CONSTRAINT IF EXISTS cell_tool_intents_event_fk;
        ALTER TABLE cell_events DROP CONSTRAINT IF EXISTS cell_events_cell_fk;
        ALTER TABLE agent_cells DROP CONSTRAINT IF EXISTS agent_cells_parent_fk;
        ALTER TABLE agent_cells DROP CONSTRAINT IF EXISTS ck_agent_cell_parent_not_self;

        ALTER TABLE cell_events DROP CONSTRAINT IF EXISTS cell_events_pkey;
        ALTER TABLE cell_events
            ADD CONSTRAINT cell_events_pkey
            PRIMARY KEY (tenant_id, cell_id, branch_id, sequence);
        ALTER TABLE agent_cells DROP CONSTRAINT IF EXISTS agent_cells_pkey;
        ALTER TABLE agent_cells
            ADD CONSTRAINT agent_cells_pkey PRIMARY KEY (tenant_id, cell_id, branch_id);
        ALTER TABLE cell_events
            ADD CONSTRAINT cell_events_tenant_id_cell_id_branch_id_fkey
            FOREIGN KEY (tenant_id, cell_id, branch_id)
            REFERENCES agent_cells (tenant_id, cell_id, branch_id) ON DELETE CASCADE;
        ALTER TABLE cell_tool_intents
            ADD CONSTRAINT cell_tool_intents_tenant_id_cell_id_branch_id_sequence_fkey
            FOREIGN KEY (tenant_id, cell_id, branch_id, sequence)
            REFERENCES cell_events (tenant_id, cell_id, branch_id, sequence);
        ALTER TABLE cell_effect_ledger
            ADD CONSTRAINT cell_effect_ledger_tenant_id_intent_id_fkey
            FOREIGN KEY (tenant_id, intent_id)
            REFERENCES cell_tool_intents (tenant_id, intent_id);
        ALTER TABLE cell_effect_receipts
            ADD CONSTRAINT cell_effect_receipts_tenant_id_intent_id_fkey
            FOREIGN KEY (tenant_id, intent_id)
            REFERENCES cell_tool_intents (tenant_id, intent_id);
        ALTER TABLE cell_effect_receipts
            ADD CONSTRAINT cell_effect_receipts_tenant_id_effect_key_fkey
            FOREIGN KEY (tenant_id, effect_key)
            REFERENCES cell_effect_ledger (tenant_id, effect_key);

        ALTER TABLE cell_events DROP CONSTRAINT IF EXISTS cell_events_tenant_event_id_key;
        ALTER TABLE cell_events
            ADD CONSTRAINT cell_events_tenant_id_event_id_key UNIQUE (tenant_id, event_id);
        ALTER TABLE cell_events DROP COLUMN IF EXISTS app_id, DROP COLUMN IF EXISTS session_id;
        ALTER TABLE cell_tool_intents
            DROP COLUMN IF EXISTS app_id,
            DROP COLUMN IF EXISTS session_id,
            DROP COLUMN IF EXISTS capsule_digest;
        ALTER TABLE cell_effect_ledger
            DROP COLUMN IF EXISTS app_id,
            DROP COLUMN IF EXISTS cell_id,
            DROP COLUMN IF EXISTS session_id,
            DROP COLUMN IF EXISTS capsule_digest,
            DROP COLUMN IF EXISTS branch_id;
        ALTER TABLE cell_effect_receipts
            DROP COLUMN IF EXISTS app_id,
            DROP COLUMN IF EXISTS cell_id,
            DROP COLUMN IF EXISTS session_id,
            DROP COLUMN IF EXISTS capsule_digest,
            DROP COLUMN IF EXISTS branch_id,
            DROP COLUMN IF EXISTS trace_id;

        REVOKE ALL ON agent_capsules, agent_cells, cell_events,
            cell_tool_intents, cell_effect_ledger, cell_effect_receipts FROM PUBLIC;
        DO $restore_legacy_grants$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_runtime') THEN
                REVOKE ALL ON agent_capsules, agent_cells, cell_events,
                    cell_tool_intents, cell_effect_ledger, cell_effect_receipts
                    FROM trpc_runtime;
                GRANT SELECT, INSERT ON agent_capsules TO trpc_runtime;
                GRANT SELECT, INSERT, UPDATE ON agent_cells TO trpc_runtime;
                GRANT SELECT, INSERT, UPDATE ON cell_effect_ledger TO trpc_runtime;
                GRANT SELECT, INSERT ON cell_events, cell_tool_intents,
                    cell_effect_receipts TO trpc_runtime;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_worker') THEN
                REVOKE ALL ON agent_capsules, agent_cells, cell_events,
                    cell_tool_intents, cell_effect_ledger, cell_effect_receipts
                    FROM trpc_worker;
                GRANT SELECT, INSERT ON agent_capsules TO trpc_worker;
                GRANT SELECT, INSERT, UPDATE ON agent_cells TO trpc_worker;
                GRANT SELECT, INSERT, UPDATE ON cell_effect_ledger TO trpc_worker;
                GRANT SELECT, INSERT ON cell_events, cell_tool_intents,
                    cell_effect_receipts TO trpc_worker;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_cell_executor') THEN
                REVOKE ALL ON agent_capsules, agent_cells, cell_events,
                    cell_tool_intents, cell_effect_ledger, cell_effect_receipts
                    FROM trpc_cell_executor;
            END IF;
        END
        $restore_legacy_grants$;
        """
    )
