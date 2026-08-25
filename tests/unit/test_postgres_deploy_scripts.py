import re
from pathlib import Path

ROOT = Path(__file__).parents[2]
INIT_SCRIPT = ROOT / "deploy" / "postgres" / "init.sh"
PROVISION_SCRIPT = ROOT / "deploy" / "yqzl" / "provision.sh"


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


def test_yqzl_provision_keeps_database_passwords_out_of_psql_argv() -> None:
    script = PROVISION_SCRIPT.read_text(encoding="utf-8")

    assert 'export TRPC_PROVISION_RUNTIME_PASSWORD="$runtime_password"' in script
    assert 'export TRPC_PROVISION_MIGRATION_PASSWORD="$migration_password"' in script
    assert r"\getenv runtime_password TRPC_PROVISION_RUNTIME_PASSWORD" in script
    assert r"\getenv migration_password TRPC_PROVISION_MIGRATION_PASSWORD" in script
    assert script.count("runuser --preserve-environment -u postgres") >= 2
    assert not re.search(r"--(?:set|variable)=[^\\n]*password=", script)
    assert not re.search(r"--(?:set|variable)\\s+[^\\n]*password=", script)
    assert 'cat "$APP_ROOT/deploy/postgres/bootstrap.sql"' in script
    assert "trap cleanup_sensitive_values EXIT" in script


def test_yqzl_provision_creates_a_dedicated_worker_login() -> None:
    script = PROVISION_SCRIPT.read_text(encoding="utf-8")

    assert "readonly WORKER_ROLE=trpc_worker" in script
    assert 'make_secret "$SITE_ROOT/secrets/worker_database_password" password' in script
    assert "TRPC_PROVISION_WORKER_PASSWORD" in script
    assert "CREATE ROLE trpc_worker LOGIN NOSUPERUSER" in script
    assert "NOINHERIT BYPASSRLS" in script


def test_yqzl_provision_protects_and_cleans_secret_temp_files() -> None:
    script = PROVISION_SCRIPT.read_text(encoding="utf-8")

    assert "declare -a secret_temp_paths=()" in script
    assert 'secret_temp_paths+=("$temporary")' in script
    assert script.count('chmod 0600 "$temporary"') >= 2
    assert 'rm -f -- "$path"' in script
    assert '"$SITE_ROOT"/secrets/.secret.*' in script
    assert '"$SITE_ROOT"/secrets/.minio-env.*' in script
    assert "unset runtime_password migration_password redis_password" in script
