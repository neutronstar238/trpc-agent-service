from __future__ import annotations

import pytest

from scripts import migration_acceptance_bootstrap as bootstrap


def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "TRPC_MIGRATION_SOURCE_REDIS_URL": "redis://source.example:6379/0",
        "TRPC_MIGRATION_TARGET_DATABASE_DSN": "postgresql://trpc_runtime@target.example:5432/db",
        "TRPC_MIGRATION_TENANT_ID": "migration-acceptance-tenant-1",
        "TRPC_MIGRATION_ID": "migration-acceptance-run-1",
        "TRPC_MIGRATION_EXPECTED_RECORDS": "200",
        "TRPC_MIGRATION_APP_ID": "migration-acceptance-app-1",
        "TRPC_MIGRATION_APP_REVISION": "1",
        "TRPC_MIGRATION_CONFIG_VERSION": "1",
        "TRPC_MIGRATION_BINDING_ID": "migration-acceptance-binding-1",
        "TRPC_MIGRATION_BINDING_REVISION": "1",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_bootstrap_derives_distinct_phase_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    base, phase = bootstrap._scope_from_env()
    assert base.tenant_id != phase.tenant_id
    assert base.migration_id != phase.migration_id
    assert base.app_id != phase.app_id
    assert phase.binding_id is None


def test_bootstrap_rejects_reused_scope_identifiers(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch)
    monkeypatch.setenv("TRPC_MIGRATION_PHASE_APP_ID", "migration-acceptance-app-1")
    with pytest.raises(ValueError, match="unique"):
        bootstrap._scope_from_env()


@pytest.mark.asyncio
async def test_bootstrap_is_opt_in_before_opening_connections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TRPC_RUN_REAL_MIGRATION", raising=False)
    monkeypatch.delenv("TRPC_MIGRATION_FULL_ACCEPTANCE", raising=False)
    monkeypatch.delenv("TRPC_MIGRATION_BOOTSTRAP", raising=False)
    result = await bootstrap.bootstrap()
    assert result == {"status": "not_run", "reason": "both live migration opt-ins are required"}
