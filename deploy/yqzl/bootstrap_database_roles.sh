#!/usr/bin/env bash
set -euo pipefail

readonly SITE_ROOT=/www/wwwroot/tx.nstarzx.cn
readonly APP_ROOT="$SITE_ROOT/app"
readonly SERVICE_GROUP=trpcagent
readonly PG_BIN=/www/server/pgsql/bin
readonly DATABASE_NAME=trpc_agent_service
readonly LOCK_FILE=/run/lock/trpc-yqzl-database-roles.lock
readonly RUNTIME_SECRET="$SITE_ROOT/secrets/runtime_database_password"
readonly MIGRATION_SECRET="$SITE_ROOT/secrets/migration_database_password"
readonly WORKER_SECRET="$SITE_ROOT/secrets/worker_database_password"
readonly METRICS_SECRET="$SITE_ROOT/secrets/metrics_database_password"

declare -a temporary_paths=()

cleanup() {
  local path
  unset runtime_password migration_password worker_password metrics_password \
    TRPC_YQZL_RUNTIME_PASSWORD TRPC_YQZL_MIGRATION_PASSWORD \
    TRPC_YQZL_WORKER_PASSWORD TRPC_YQZL_METRICS_PASSWORD
  for path in "${temporary_paths[@]}"; do
    case "$path" in
      "$SITE_ROOT"/secrets/.database-secret.*|"$SITE_ROOT"/config/.worker-role-env.*)
        rm -f -- "$path"
        ;;
    esac
  done
}
trap cleanup EXIT

if [[ ${EUID} -ne 0 ]]; then
  echo "bootstrap_database_roles.sh must run as root" >&2
  exit 1
fi
if ! command -v flock >/dev/null 2>&1; then
  echo "flock is required for database role bootstrap" >&2
  exit 1
fi
if [[ ! -x "$PG_BIN/psql" ]]; then
  echo "the expected BaoTa PostgreSQL installation was not found" >&2
  exit 1
fi
if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
  echo "service group $SERVICE_GROUP does not exist" >&2
  exit 1
fi
if [[ ! -f "$APP_ROOT/deploy/postgres/bootstrap.sql" ]]; then
  echo "deploy/postgres/bootstrap.sql is missing from the active release" >&2
  exit 1
fi

exec 9>"$LOCK_FILE"
if ! flock --exclusive --nonblock 9; then
  echo "another database role bootstrap is already running" >&2
  exit 1
fi

install -d -m 0750 -o root -g "$SERVICE_GROUP" \
  "$SITE_ROOT/config" "$SITE_ROOT/secrets"

runtime_environment="$SITE_ROOT/config/runtime.env"
if [[ ! -f "$runtime_environment" ]]; then
  echo "base runtime.env must be installed before database role bootstrap" >&2
  exit 1
fi
if grep -Eq '^TRPC_SERVICE_WORKER_DATABASE_(DSN|DSN_REF|PASSWORD|PASSWORD_REF)=' \
  "$runtime_environment"; then
  echo "base runtime.env must not expose worker database settings" >&2
  exit 1
fi

validate_existing_secret() {
  local path=$1
  local owner=$2
  local group=$3
  local mode=$4

  if [[ -L "$path" || ! -f "$path" || ! -s "$path" ]]; then
    echo "required existing database secret is missing or invalid: $path" >&2
    exit 1
  fi
  chown "$owner:$group" "$path"
  chmod "$mode" "$path"
}

ensure_generated_secret() {
  local path=$1
  local owner=$2
  local group=$3
  local mode=$4
  local temporary

  if [[ -L "$path" ]]; then
    echo "refusing symlink database secret: $path" >&2
    exit 1
  fi
  if [[ -e "$path" && ! -f "$path" ]]; then
    echo "database secret is not a regular file: $path" >&2
    exit 1
  fi
  if [[ ! -s "$path" ]]; then
    temporary=$(mktemp "$SITE_ROOT/secrets/.database-secret.XXXXXX")
    temporary_paths+=("$temporary")
    chmod 0600 "$temporary"
    openssl rand -base64 36 | tr -d '\r\n' >"$temporary"
    chown "$owner:$group" "$temporary"
    chmod "$mode" "$temporary"
    mv -T "$temporary" "$path"
  fi
  chown "$owner:$group" "$path"
  chmod "$mode" "$path"
}

# Runtime and migration are pre-existing production identities. Their absence
# is a deployment error; this repair path must never create or rotate them.
validate_existing_secret "$RUNTIME_SECRET" root "$SERVICE_GROUP" 0640
validate_existing_secret "$MIGRATION_SECRET" root root 0600
# Worker and metrics are the only identities introduced by this bootstrap.
# Existing values are preserved, so repeated runs never rotate them either.
ensure_generated_secret "$WORKER_SECRET" root "$SERVICE_GROUP" 0640
ensure_generated_secret "$METRICS_SECRET" root root 0600

runtime_password=$(<"$RUNTIME_SECRET")
migration_password=$(<"$MIGRATION_SECRET")
worker_password=$(<"$WORKER_SECRET")
metrics_password=$(<"$METRICS_SECRET")
export TRPC_YQZL_RUNTIME_PASSWORD="$runtime_password"
export TRPC_YQZL_MIGRATION_PASSWORD="$migration_password"
export TRPC_YQZL_WORKER_PASSWORD="$worker_password"
export TRPC_YQZL_METRICS_PASSWORD="$metrics_password"

# This is a repair/bootstrap for the existing yqzl database. It deliberately
# does not create a database or install extensions.
if ! runuser -u postgres -- "$PG_BIN/psql" -At --dbname=postgres \
  --set=ON_ERROR_STOP=1 \
  --command="SELECT 1 FROM pg_database WHERE datname = '$DATABASE_NAME'" |
  grep -qx 1; then
  echo "existing database $DATABASE_NAME is required" >&2
  exit 1
fi

{
  printf '%s\n' \
    '\getenv runtime_password TRPC_YQZL_RUNTIME_PASSWORD' \
    '\getenv migration_password TRPC_YQZL_MIGRATION_PASSWORD' \
    '\getenv worker_password TRPC_YQZL_WORKER_PASSWORD' \
    '\getenv metrics_password TRPC_YQZL_METRICS_PASSWORD'
  cat "$APP_ROOT/deploy/postgres/bootstrap.sql"
} | runuser --preserve-environment -u postgres -- "$PG_BIN/psql" \
  --set=ON_ERROR_STOP=1 --dbname="$DATABASE_NAME"

unset runtime_password migration_password worker_password metrics_password \
  TRPC_YQZL_RUNTIME_PASSWORD TRPC_YQZL_MIGRATION_PASSWORD \
  TRPC_YQZL_WORKER_PASSWORD TRPC_YQZL_METRICS_PASSWORD

# Ownership and membership are trust boundaries, not repairable drift. Abort
# instead of silently adopting a database or privilege graph owned elsewhere.
runuser -u postgres -- "$PG_BIN/psql" --set=ON_ERROR_STOP=1 \
  --dbname="$DATABASE_NAME" <<'SQL'
DO $contract$
DECLARE
    migration_oid oid := 'trpc_migration'::regrole::oid;
    runtime_oid oid := 'trpc_runtime'::regrole::oid;
    worker_oid oid := 'trpc_worker'::regrole::oid;
    metrics_oid oid := 'trpc_metrics'::regrole::oid;
    database_owner_oid oid := 'pg_database_owner'::regrole::oid;
BEGIN
    IF EXISTS (
        SELECT 1
          FROM pg_auth_members
         WHERE member IN (migration_oid, runtime_oid, worker_oid, metrics_oid)
            OR roleid IN (migration_oid, runtime_oid, worker_oid, metrics_oid)
    ) THEN
        RAISE EXCEPTION 'database service roles must not have role memberships';
    END IF;
    IF (SELECT datdba FROM pg_database WHERE datname = current_database()) <> migration_oid THEN
        RAISE EXCEPTION 'trpc_migration must own the application database';
    END IF;
    IF (SELECT nspowner FROM pg_namespace WHERE nspname = 'public') <> migration_oid
       AND (
           (SELECT nspowner FROM pg_namespace WHERE nspname = 'public') <> database_owner_oid
           OR NOT pg_has_role(migration_oid, database_owner_oid, 'USAGE')
       ) THEN
        RAISE EXCEPTION 'trpc_migration must own the public schema';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM pg_class AS object
          JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace
         WHERE namespace.nspname = 'public'
           AND object.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
           AND object.relowner <> migration_oid
           AND NOT EXISTS (
               SELECT 1
                 FROM pg_depend AS dependency
                WHERE dependency.classid = 'pg_class'::regclass
                  AND dependency.objid = object.oid
                  AND dependency.deptype = 'e'
           )
    ) OR EXISTS (
        SELECT 1
          FROM pg_proc AS object
          JOIN pg_namespace AS namespace ON namespace.oid = object.pronamespace
         WHERE namespace.nspname = 'public'
           AND object.proowner <> migration_oid
           AND NOT EXISTS (
               SELECT 1
                 FROM pg_depend AS dependency
                WHERE dependency.classid = 'pg_proc'::regclass
                  AND dependency.objid = object.oid
                  AND dependency.deptype = 'e'
           )
    ) THEN
        RAISE EXCEPTION 'trpc_migration must own existing application objects';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM pg_class AS object
          JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace
         WHERE namespace.nspname = 'public'
           AND object.relrowsecurity
           AND object.relowner IN (runtime_oid, worker_oid)
    ) THEN
        RAISE EXCEPTION 'runtime and worker roles must not own RLS tables';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM pg_class AS object
          JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace
         WHERE namespace.nspname = 'public'
           AND object.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
           AND has_table_privilege(
               metrics_oid,
               object.oid,
               'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
           )
    ) THEN
        RAISE EXCEPTION 'trpc_metrics must not have table privileges';
    END IF;
END
$contract$;
SQL

write_worker_role_environment() {
  local role=$1
  local destination="$SITE_ROOT/config/$role.env"
  local temporary

  temporary=$(mktemp "$SITE_ROOT/config/.worker-role-env.XXXXXX")
  temporary_paths+=("$temporary")
  cat >"$temporary" <<'EOF'
TRPC_SERVICE_WORKER_DATABASE_DSN_REF=env://TRPC_SERVICE_WORKER_DATABASE_DSN
TRPC_SERVICE_WORKER_DATABASE_DSN=postgresql://trpc_worker@127.0.0.1:5432/trpc_agent_service
TRPC_SERVICE_WORKER_DATABASE_PASSWORD_REF=file:///www/wwwroot/tx.nstarzx.cn/secrets/worker_database_password
EOF
  chown root:"$SERVICE_GROUP" "$temporary"
  chmod 0640 "$temporary"
  mv -T "$temporary" "$destination"
}

for role in \
  worker \
  outbox-dispatcher \
  channel-dispatcher \
  post-turn-projector \
  wecom-connector \
  session-recovery \
  artifact-gc; do
  write_worker_role_environment "$role"
done

echo "database roles and role-specific environments are ready"
