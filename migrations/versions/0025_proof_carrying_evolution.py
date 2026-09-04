"""Persist exact-Cell promotion pointers and one-time certificate uses.

The evolution proof itself is content addressed and can be retained by an
offline evidence service.  These two tables are the narrow online boundary:
``cell_promotion_targets`` is the optimistic-concurrency pointer and
``cell_promotion_uses`` is the idempotency fence for a certificate/manual
approval.  Neither table contains prompts, tool arguments, secrets or
provider responses.
"""

from __future__ import annotations

from alembic import op

revision = "0025_proof_carrying_evolution"
down_revision = "0024_cell_effect_reconciliation"
branch_labels = None
depends_on = None


_CREATE = """
CREATE TABLE cell_promotion_targets (
    tenant_id text NOT NULL,
    app_id text NOT NULL,
    cell_id text NOT NULL,
    session_id text NOT NULL,
    active_capsule_digest text NOT NULL,
    control_version bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, app_id, cell_id, session_id),
    CONSTRAINT ck_cell_promotion_target_scope CHECK (
        tenant_id <> '' AND app_id <> '' AND cell_id <> '' AND session_id <> ''
        AND tenant_id NOT LIKE '%*%' AND app_id NOT LIKE '%*%'
        AND cell_id NOT LIKE '%*%' AND session_id NOT LIKE '%*%'
    ),
    CONSTRAINT ck_cell_promotion_target_capsule CHECK (
        active_capsule_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_cell_promotion_target_version CHECK (control_version >= 0),
    CONSTRAINT fk_cell_promotion_target_capsule
        FOREIGN KEY (tenant_id, active_capsule_digest)
        REFERENCES agent_capsules (tenant_id, capsule_digest)
        ON DELETE CASCADE
);

CREATE TABLE cell_promotion_uses (
    tenant_id text NOT NULL,
    certificate_id text NOT NULL,
    certificate_digest text NOT NULL,
    approval_id text NOT NULL,
    app_id text NOT NULL,
    cell_id text NOT NULL,
    session_id text NOT NULL,
    receipt_id uuid NOT NULL DEFAULT gen_random_uuid(),
    consumed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, certificate_id),
    UNIQUE (tenant_id, approval_id),
    UNIQUE (tenant_id, receipt_id),
    FOREIGN KEY (tenant_id, app_id, cell_id, session_id)
        REFERENCES cell_promotion_targets (tenant_id, app_id, cell_id, session_id)
        ON DELETE CASCADE,
    CONSTRAINT ck_cell_promotion_use_ids CHECK (
        certificate_id <> '' AND approval_id <> ''
        AND certificate_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_cell_promotion_use_scope CHECK (
        tenant_id <> '' AND app_id <> '' AND cell_id <> '' AND session_id <> ''
        AND tenant_id NOT LIKE '%*%' AND app_id NOT LIKE '%*%'
        AND cell_id NOT LIKE '%*%' AND session_id NOT LIKE '%*%'
    )
);

CREATE INDEX ix_cell_promotion_targets_capsule
    ON cell_promotion_targets (tenant_id, active_capsule_digest);
CREATE INDEX ix_cell_promotion_uses_target
    ON cell_promotion_uses (tenant_id, app_id, cell_id, session_id, consumed_at);

ALTER TABLE cell_promotion_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE cell_promotion_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_cell_promotion_targets
    ON cell_promotion_targets
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''));

ALTER TABLE cell_promotion_uses ENABLE ROW LEVEL SECURITY;
ALTER TABLE cell_promotion_uses FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_cell_promotion_uses
    ON cell_promotion_uses
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''));

REVOKE ALL ON cell_promotion_targets, cell_promotion_uses FROM PUBLIC;
REVOKE ALL ON cell_promotion_targets, cell_promotion_uses
    FROM trpc_runtime, trpc_worker, trpc_cell_executor;

DO $grant_evolution_authority$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trpc_evolution_authority') THEN
        CREATE ROLE trpc_evolution_authority
            LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOINHERIT NOBYPASSRLS;
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_roles
         WHERE rolname = 'trpc_evolution_authority'
           AND (
               rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls
               OR rolinherit IS DISTINCT FROM FALSE
               OR rolcanlogin IS DISTINCT FROM TRUE
           )
    ) THEN
        RAISE EXCEPTION
            'trpc_evolution_authority must be LOGIN NOSUPERUSER NOINHERIT NOBYPASSRLS'
            USING ERRCODE = '42501';
    END IF;
    IF EXISTS (
        WITH RECURSIVE reachable_roles(role_id) AS (
            SELECT oid FROM pg_catalog.pg_roles
             WHERE rolname = 'trpc_evolution_authority'
            UNION
            SELECT membership.roleid
              FROM pg_catalog.pg_auth_members AS membership
              JOIN reachable_roles AS reachable
                ON reachable.role_id = membership.member
        )
        SELECT 1 FROM reachable_roles
         WHERE role_id <> (
             SELECT oid FROM pg_catalog.pg_roles
              WHERE rolname = 'trpc_evolution_authority'
         )
    ) THEN
        RAISE EXCEPTION
            'trpc_evolution_authority must not have SET ROLE membership'
            USING ERRCODE = '42501';
    END IF;
    GRANT SELECT, INSERT ON cell_promotion_targets
        TO trpc_evolution_authority;
    GRANT UPDATE (active_capsule_digest, control_version, updated_at)
        ON cell_promotion_targets
        TO trpc_evolution_authority;
    GRANT SELECT, INSERT ON cell_promotion_uses
        TO trpc_evolution_authority;
END
$grant_evolution_authority$;
"""


def upgrade() -> None:
    op.execute(_CREATE)


def downgrade() -> None:
    op.execute(
        """
        REVOKE ALL ON cell_promotion_targets, cell_promotion_uses
            FROM PUBLIC, trpc_runtime, trpc_worker,
                 trpc_cell_executor, trpc_evolution_authority;
        DROP TABLE IF EXISTS cell_promotion_uses;
        DROP TABLE IF EXISTS cell_promotion_targets;
        """
    )
