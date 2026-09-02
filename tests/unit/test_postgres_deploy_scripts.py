import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]
INIT_SCRIPT = ROOT / "deploy" / "postgres" / "init.sh"
PROVISION_SCRIPT = ROOT / "deploy" / "yqzl" / "provision.sh"
ACK_SUPPORT = ROOT / "runs" / "multitenant" / "ack-runtime-support.yaml"


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

    role_contract = "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS"
    assert f"CREATE ROLE trpc_migration {role_contract}" in script
    assert f"ALTER ROLE trpc_migration {role_contract}" in script
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


def test_ack_support_bootstrap_provisions_hpa_without_password_argv() -> None:
    manifest = ACK_SUPPORT.read_text(encoding="utf-8")

    assert "key: hpa-password" in manifest
    assert r"\getenv hpa_password TRPC_INIT_HPA_PASSWORD" in manifest
    assert "CREATE ROLE trpc_hpa LOGIN NOSUPERUSER" in manifest
    assert (
        "ALTER ROLE trpc_hpa NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS" in manifest
    )
    assert "GRANT CONNECT ON DATABASE trpc_service TO" in manifest
    assert "trpc_metrics, trpc_hpa" in manifest
    assert '--set=hpa_password="$HPA_PASSWORD"' not in manifest


def test_ack_support_database_pods_disable_tokens_and_privilege_escalation() -> None:
    documents = [
        value
        for value in yaml.safe_load_all(ACK_SUPPORT.read_text(encoding="utf-8"))
        if isinstance(value, dict)
    ]
    workloads = {
        (value["kind"], value["metadata"]["name"]): value
        for value in documents
        if (value.get("kind"), value.get("metadata", {}).get("name"))
        in {
            ("Deployment", "postgres"),
            ("Deployment", "redis"),
            ("Job", "postgres-bootstrap"),
        }
    }

    assert set(workloads) == {
        ("Deployment", "postgres"),
        ("Deployment", "redis"),
        ("Job", "postgres-bootstrap"),
    }
    for workload in workloads.values():
        pod = workload["spec"]["template"]["spec"]
        assert pod["automountServiceAccountToken"] is False
        assert pod["enableServiceLinks"] is False
        assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
        assert pod["containers"][0]["securityContext"]["allowPrivilegeEscalation"] is False


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


def test_migration_role_is_explicitly_least_privilege_in_all_bootstraps() -> None:
    bootstrap = (ROOT / "deploy" / "postgres" / "bootstrap.sql").read_text(encoding="utf-8")
    yqzl = PROVISION_SCRIPT.read_text(encoding="utf-8")
    role_contract = "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS"

    for source in (bootstrap, yqzl):
        assert f"CREATE ROLE trpc_migration {role_contract}" in source
        assert f"ALTER ROLE trpc_migration {role_contract}" in source


def test_yqzl_provision_creates_a_dedicated_metrics_login_and_secret() -> None:
    script = PROVISION_SCRIPT.read_text(encoding="utf-8")

    assert "readonly METRICS_ROLE=trpc_metrics" in script
    assert 'make_secret "$SITE_ROOT/secrets/metrics_database_password" password' in script
    assert "TRPC_PROVISION_METRICS_PASSWORD" in script
    assert "CREATE ROLE trpc_metrics LOGIN NOSUPERUSER" in script
    assert "NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS" in script
    assert "readonly METRICS_SECRET_NAME=trpc-metrics-secrets" in script
    assert "readonly METRICS_SECRET_KEY=TRPC_SERVICE_METRICS_DATABASE_DSN" in script
    assert "kubectl" in script
    assert '--from-file="$METRICS_SECRET_KEY=$temporary"' in script
    assert '_url_encode_uri_component "$metrics_password"' in script
    assert "postgresql://${METRICS_ROLE}:${metrics_password_uri}" in script
    assert "${DATABASE_NAME}" in script
    assert "GRANT CONNECT ON DATABASE %I TO %I', current_database(), 'trpc_metrics" in script


def test_yqzl_provision_protects_and_cleans_secret_temp_files() -> None:
    script = PROVISION_SCRIPT.read_text(encoding="utf-8")

    assert "declare -a secret_temp_paths=()" in script
    assert 'secret_temp_paths+=("$temporary")' in script
    assert script.count('chmod 0600 "$temporary"') >= 2
    assert 'rm -f -- "$path"' in script
    assert '"$SITE_ROOT"/secrets/.secret.*' in script
    assert '"$SITE_ROOT"/secrets/.minio-env.*' in script
    assert '"$SITE_ROOT"/secrets/.metrics-dsn.*' in script
    assert "unset runtime_password migration_password redis_password" in script
