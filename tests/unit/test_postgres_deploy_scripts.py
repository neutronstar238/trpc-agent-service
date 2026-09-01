import re
from pathlib import Path

ROOT = Path(__file__).parents[2]
INIT_SCRIPT = ROOT / "deploy" / "postgres" / "init.sh"
BOOTSTRAP_SQL = ROOT / "deploy" / "postgres" / "bootstrap.sql"
PROVISION_SCRIPT = ROOT / "deploy" / "yqzl" / "provision.sh"
ROLE_BOOTSTRAP_SCRIPT = ROOT / "deploy" / "yqzl" / "bootstrap_database_roles.sh"


def test_postgres_init_imports_both_passwords_without_secret_argv() -> None:
    script = INIT_SCRIPT.read_text(encoding="utf-8")

    assert "</run/secrets/runtime_database_password" in script
    assert "</run/secrets/migration_database_password" in script
    assert 'export TRPC_INIT_RUNTIME_PASSWORD="$runtime_password"' in script
    assert 'export TRPC_INIT_MIGRATION_PASSWORD="$migration_password"' in script
    assert r"\getenv runtime_password TRPC_INIT_RUNTIME_PASSWORD" in script
    assert r"\getenv migration_password TRPC_INIT_MIGRATION_PASSWORD" in script
    assert "trap cleanup_passwords EXIT" in script
    assert "unset runtime_password migration_password" in script
    assert "CREATE EXTENSION IF NOT EXISTS pgcrypto" in script
    assert "CREATE EXTENSION IF NOT EXISTS vector" in script
    assert not re.search(r"--(?:set|variable)=[^\\n]*password=", script)


def test_postgres_init_separates_runtime_and_global_worker_roles() -> None:
    script = INIT_SCRIPT.read_text(encoding="utf-8")

    assert "CREATE ROLE trpc_runtime LOGIN NOSUPERUSER" in script
    assert "NOINHERIT NOBYPASSRLS" in script
    assert "CREATE ROLE trpc_worker LOGIN NOSUPERUSER" in script
    assert "NOINHERIT BYPASSRLS" in script
    assert "GRANT CONNECT ON DATABASE %I TO trpc_worker" in script
    assert "/run/secrets/worker_database_password" in script


def test_postgres_init_provisions_a_non_bypass_metrics_role_from_secret() -> None:
    script = INIT_SCRIPT.read_text(encoding="utf-8")

    assert "/run/secrets/metrics_database_password" in script
    assert 'export TRPC_INIT_METRICS_PASSWORD="$metrics_password"' in script
    assert r"\getenv metrics_password TRPC_INIT_METRICS_PASSWORD" in script
    assert "CREATE ROLE trpc_metrics LOGIN NOSUPERUSER" in script
    assert "NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS" in script
    assert "GRANT CONNECT ON DATABASE %I TO trpc_metrics" in script
    assert "ALTER ROLE trpc_metrics PASSWORD %L" in script


def test_yqzl_provision_keeps_database_passwords_out_of_psql_argv() -> None:
    script = PROVISION_SCRIPT.read_text(encoding="utf-8")

    assert 'bash "$APP_ROOT/deploy/yqzl/bootstrap_database_roles.sh"' in script
    assert "CREATE ROLE trpc_runtime" not in script
    assert "CREATE ROLE trpc_worker" not in script
    assert 'cat "$APP_ROOT/deploy/postgres/bootstrap.sql"' not in script
    assert not re.search(r"--(?:set|variable)=[^\\n]*password=", script)
    assert not re.search(r"--(?:set|variable)\\s+[^\\n]*password=", script)
    assert "trap cleanup_sensitive_values EXIT" in script


def test_yqzl_role_bootstrap_uses_stdin_getenv_and_preserves_secrets() -> None:
    script = ROLE_BOOTSTRAP_SCRIPT.read_text(encoding="utf-8")

    assert "bootstrap_database_roles.sh must run as root" in script
    assert "flock --exclusive --nonblock 9" in script
    for name in ("RUNTIME", "MIGRATION", "WORKER", "METRICS"):
        assert f"TRPC_YQZL_{name}_PASSWORD" in script
        assert rf"\getenv {name.lower()}_password TRPC_YQZL_{name}_PASSWORD" in script
    assert 'if [[ ! -s "$path" ]]' in script
    assert "must never create or rotate them" in script
    assert not re.search(r"--(?:set|variable)=[^\\n]*password=", script)
    assert not re.search(r"--(?:set|variable)\\s+[^\\n]*password=", script)
    assert "apt-get" not in script
    assert "docker" not in script


def test_yqzl_role_bootstrap_hardens_roles_and_fails_closed_on_trust_drift() -> None:
    script = ROLE_BOOTSTRAP_SCRIPT.read_text(encoding="utf-8")
    sql = BOOTSTRAP_SQL.read_text(encoding="utf-8")

    assert "existing database $DATABASE_NAME is required" in script
    assert "CREATE ROLE trpc_worker LOGIN NOSUPERUSER" in sql
    assert "CREATE ROLE trpc_metrics LOGIN NOSUPERUSER" in sql
    assert "NOINHERIT NOREPLICATION BYPASSRLS" in sql
    assert "NOINHERIT NOREPLICATION NOBYPASSRLS" in script + sql
    assert "FROM pg_auth_members" in script
    assert "trpc_migration must own the application database" in script
    assert "trpc_migration must own the public schema" in script
    assert "trpc_migration must own existing application objects" in script
    assert "runtime and worker roles must not own RLS tables" in script
    assert "trpc_metrics must not have table privileges" in script
    assert "ALTER DATABASE" not in script
    assert "createdb" not in script
    assert "CREATE EXTENSION" not in script


def test_yqzl_role_bootstrap_generates_exact_worker_role_environments() -> None:
    script = ROLE_BOOTSTRAP_SCRIPT.read_text(encoding="utf-8")

    expected_roles = {
        "worker",
        "outbox-dispatcher",
        "channel-dispatcher",
        "post-turn-projector",
        "wecom-connector",
        "session-recovery",
        "artifact-gc",
    }
    role_loop = re.search(r"for role in \\\n(?P<roles>.*?)do\n", script, re.DOTALL)
    assert role_loop is not None
    actual_roles = {
        line.strip().removesuffix("\\").removesuffix(";").strip()
        for line in role_loop["roles"].splitlines()
        if line.strip()
    }
    assert actual_roles == expected_roles

    environment = re.search(
        r"cat >\"\$temporary\" <<'EOF'\n(?P<body>.*?)\nEOF",
        script,
        re.DOTALL,
    )
    assert environment is not None
    assert environment["body"].splitlines() == [
        "TRPC_SERVICE_WORKER_DATABASE_DSN_REF=env://TRPC_SERVICE_WORKER_DATABASE_DSN",
        "TRPC_SERVICE_WORKER_DATABASE_DSN=postgresql://trpc_worker@127.0.0.1:5432/trpc_agent_service",
        "TRPC_SERVICE_WORKER_DATABASE_PASSWORD_REF=file:///www/wwwroot/tx.nstarzx.cn/secrets/worker_database_password",
    ]
    assert "base runtime.env must not expose worker database settings" in script
    assert 'chown root:"$SERVICE_GROUP" "$temporary"' in script
    assert 'chmod 0640 "$temporary"' in script


def test_yqzl_role_bootstrap_enforces_secret_ownership_contract() -> None:
    script = ROLE_BOOTSTRAP_SCRIPT.read_text(encoding="utf-8")

    assert 'validate_existing_secret "$RUNTIME_SECRET" root "$SERVICE_GROUP" 0640' in script
    assert 'validate_existing_secret "$MIGRATION_SECRET" root root 0600' in script
    assert 'ensure_generated_secret "$WORKER_SECRET" root "$SERVICE_GROUP" 0640' in script
    assert 'ensure_generated_secret "$METRICS_SECRET" root root 0600' in script
    assert "required existing database secret is missing or invalid" in script
    assert "refusing symlink database secret" in script
    assert "database secret is not a regular file" in script


def test_postgres_bootstrap_declares_metrics_and_complete_role_attributes() -> None:
    script = BOOTSTRAP_SQL.read_text(encoding="utf-8")

    for role in ("trpc_migration", "trpc_runtime", "trpc_metrics"):
        assert f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE" in script
    assert "CREATE ROLE trpc_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE" in script
    assert script.count("NOINHERIT NOREPLICATION NOBYPASSRLS") >= 6
    assert script.count("NOINHERIT NOREPLICATION BYPASSRLS") >= 2
    assert "ALTER ROLE trpc_metrics PASSWORD %L" in script
    assert "GRANT CONNECT ON DATABASE %I TO trpc_metrics" in script


def test_yqzl_provision_publishes_dedicated_metrics_secret() -> None:
    script = PROVISION_SCRIPT.read_text(encoding="utf-8")

    assert "readonly METRICS_ROLE=trpc_metrics" in script
    assert "readonly METRICS_SECRET_NAME=trpc-metrics-secrets" in script
    assert "readonly METRICS_SECRET_KEY=TRPC_SERVICE_METRICS_DATABASE_DSN" in script
    assert "kubectl" in script
    assert '--from-file="$METRICS_SECRET_KEY=$temporary"' in script
    assert '_url_encode_uri_component "$metrics_password"' in script
    assert "postgresql://${METRICS_ROLE}:${metrics_password_uri}" in script
    assert "${DATABASE_NAME}" in script
    assert 'metrics_password=$(<"$SITE_ROOT/secrets/metrics_database_password")' in script


def test_yqzl_provision_protects_and_cleans_secret_temp_files() -> None:
    script = PROVISION_SCRIPT.read_text(encoding="utf-8")

    assert "declare -a secret_temp_paths=()" in script
    assert 'secret_temp_paths+=("$temporary")' in script
    assert script.count('chmod 0600 "$temporary"') >= 2
    assert 'rm -f -- "$path"' in script
    assert '"$SITE_ROOT"/secrets/.secret.*' in script
    assert '"$SITE_ROOT"/secrets/.minio-env.*' in script
    assert '"$SITE_ROOT"/secrets/.metrics-dsn.*' in script
    assert "unset redis_password metrics_password metrics_password_uri" in script
