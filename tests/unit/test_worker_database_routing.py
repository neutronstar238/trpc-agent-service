from __future__ import annotations

import pytest

import trpc_service._cli as cli
from trpc_service.config import LocalSecretProvider, Role, SecretRef, ServiceSettings
from trpc_service.database_contract import (
    RUNTIME_FORBIDDEN_CELL_PRIVILEGES,
    WORKER_FORBIDDEN_CELL_PRIVILEGES,
)


def _settings(*, worker_ref: bool = True, worker_user: str = "trpc_worker") -> ServiceSettings:
    updates = {
        "_env_file": None,
        "database_dsn_ref": SecretRef(uri="literal://postgresql://trpc_runtime@db/service"),
    }
    if worker_ref:
        updates["worker_database_dsn_ref"] = SecretRef(
            uri=f"literal://postgresql://{worker_user}@db/service"
        )
    return ServiceSettings(**updates)


def test_worker_reference_requires_a_worker_dsn() -> None:
    with pytest.raises(ValueError, match="worker database password reference"):
        ServiceSettings(
            _env_file=None,
            worker_database_password_ref=SecretRef(uri="literal://password"),
        )


def test_runtime_role_rejects_worker_secret_and_worker_requires_one() -> None:
    settings = _settings()
    secrets = LocalSecretProvider(allow_literal=True)
    with pytest.raises(ValueError, match="forbidden for tenant runtime roles"):
        cli._database_dsn_for_role(Role.GATEWAY, settings, secrets)

    with pytest.raises(ValueError, match="required for cross-tenant"):
        cli._database_dsn_for_role(Role.WORKER, _settings(worker_ref=False), secrets)


def test_worker_dsn_username_is_pinned() -> None:
    with pytest.raises(ValueError, match="database DSN username must be trpc_worker"):
        cli._database_dsn_for_role(
            Role.SESSION_RECOVERY,
            _settings(worker_user="trpc_runtime"),
            LocalSecretProvider(allow_literal=True),
        )


def test_production_rejects_literal_worker_database_references() -> None:
    with pytest.raises(ValueError, match="literal secret"):
        ServiceSettings(
            _env_file=None,
            environment="production",
            allow_development_token=False,
            oidc_issuer="https://issuer.example",
            oidc_audience="service",
            worker_database_dsn_ref=SecretRef(
                uri="literal://postgresql://trpc_worker:password@db/service"
            ),
        )


class _Connection:
    def __init__(
        self,
        *,
        bypasses_rls: bool,
        function_grants: bool = True,
        forbidden_table_grants: bool = False,
        can_login: bool = True,
        owned_rls_tables: int = 0,
    ) -> None:
        self.identity = {
            "current_user": "trpc_worker" if bypasses_rls else "trpc_runtime",
            "session_user": "trpc_worker" if bypasses_rls else "trpc_runtime",
            "is_superuser": False,
            "bypasses_rls": bypasses_rls,
            "rolcanlogin": can_login,
            "owned_rls_table_count": owned_rls_tables,
            "schema_usage": True,
        }
        self.function_grants = function_grants
        self.forbidden_table_grants = forbidden_table_grants
        self.privilege_checks: list[tuple[str, str]] = []

    async def fetchrow(self, _query: str):
        return self.identity

    async def fetchval(self, query: str, *args):
        if "has_table_privilege" in query:
            table, privilege = str(args[0]), str(args[1])
            self.privilege_checks.append((table, privilege))
            forbidden = (
                WORKER_FORBIDDEN_CELL_PRIVILEGES
                if self.identity["bypasses_rls"]
                else RUNTIME_FORBIDDEN_CELL_PRIVILEGES
            )
            if (table.removeprefix("public."), privilege) in forbidden:
                return self.forbidden_table_grants
        return self.function_grants


class _Acquire:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, *_args) -> None:
        return None


class _Pool:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    def acquire(self):
        return _Acquire(self.connection)


class _Repository:
    def __init__(self, connection: _Connection) -> None:
        self.pool = _Pool(connection)


@pytest.mark.asyncio
async def test_identity_requires_worker_bypassrls_and_explicit_grants() -> None:
    worker = _Connection(bypasses_rls=True)
    await cli._validate_database_identity(_Repository(worker), Role.WORKER)
    assert ("public.agent_capsules", "SELECT") in worker.privilege_checks
    assert ("public.cell_events", "SELECT,INSERT") in worker.privilege_checks
    assert ("public.cell_effect_ledger", "UPDATE") in worker.privilege_checks
    assert ("public.cell_placement_reservations", "SELECT") in worker.privilege_checks
    await cli._validate_database_identity(_Repository(_Connection(bypasses_rls=False)), Role.ADMIN)
    wrong_bypass = _Connection(bypasses_rls=False)
    wrong_bypass.identity.update(current_user="trpc_worker", session_user="trpc_worker")
    with pytest.raises(RuntimeError, match="must bypass"):
        await cli._validate_database_identity(_Repository(wrong_bypass), Role.WORKER)
    with pytest.raises(RuntimeError, match="lacks EXECUTE"):
        await cli._validate_database_identity(
            _Repository(_Connection(bypasses_rls=True, function_grants=False)),
            Role.WORKER,
        )
    with pytest.raises(RuntimeError, match="forbidden"):
        await cli._validate_database_identity(
            _Repository(
                _Connection(
                    bypasses_rls=True,
                    forbidden_table_grants=True,
                )
            ),
            Role.WORKER,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("can_login", "owned_rls_tables", "message"),
    (
        (False, 0, "login-enabled"),
        (True, 1, "must not own RLS tables"),
    ),
)
async def test_identity_rejects_non_login_or_rls_owner_worker_roles(
    can_login: bool, owned_rls_tables: int, message: str
) -> None:
    with pytest.raises(RuntimeError, match=message):
        await cli._validate_database_identity(
            _Repository(
                _Connection(
                    bypasses_rls=True,
                    can_login=can_login,
                    owned_rls_tables=owned_rls_tables,
                )
            ),
            Role.WORKER,
        )
