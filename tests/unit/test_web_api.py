from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from trpc_service.runtime import BindingMismatch, UnknownBinding
from trpc_service.tenant.auth import Principal, Role
from trpc_service.tenant.control import ControlVersionConflict, IdempotencyConflict
from trpc_service.web.admin import BindingRequest, create_admin_router
from trpc_service.web.app import create_base_app
from trpc_service.web.health import create_health_router


class Authorizer:
    def __init__(self, principal=None) -> None:
        self.principal = principal or Principal(
            subject="admin",
            roles=frozenset(Role),
            tenant_ids=frozenset({"tenant-1"}),
        )

    async def authenticate(self, token):
        return self.principal


class AdminRepository:
    def __init__(self) -> None:
        self.calls = []
        self.tenant = {"tenant_id": "tenant-1", "control_version": 1}
        self.error = None

    async def _result(self, operation, kwargs, result):
        self.calls.append((operation, kwargs))
        if self.error:
            raise self.error
        return result

    async def create_tenant(self, **kwargs):
        return await self._result("create", kwargs, self.tenant)

    async def get_tenant(self, tenant_id):
        return await self._result("get", {"tenant_id": tenant_id}, self.tenant)

    async def put_binding(self, **kwargs):
        return await self._result("binding", kwargs, {"tenant_control_version": 2})

    async def create_config_revision(self, **kwargs):
        return await self._result("config", kwargs, {"tenant_control_version": 3})

    async def activate_config(self, **kwargs):
        return await self._result("activate", kwargs, {"tenant_control_version": 4})

    async def audit_page(self, tenant_id, **kwargs):
        return await self._result("audit", kwargs, {"entries": [], "next_cursor": None})

    async def dead_letters(self, tenant_id, **kwargs):
        return await self._result("dead", kwargs, [])

    async def replay_outbound(self, **kwargs):
        return await self._result("replay", kwargs, {"tenant_control_version": 5})


def admin_client(repo=None, authorizer=None) -> TestClient:
    app = create_base_app(title="admin")
    app.include_router(create_admin_router(repo or AdminRepository(), authorizer or Authorizer()))
    return TestClient(app, raise_server_exceptions=False)


def headers(etag='"1"'):
    return {
        "Authorization": "Bearer token",
        "Idempotency-Key": "idempotency-123",
        "If-Match": etag,
    }


def test_binding_request_normalisation_and_validation_branches() -> None:
    with pytest.raises(ValidationError):
        BindingRequest.model_validate(object())

    wecom = BindingRequest.model_validate(
        {"app_id": "app", "channel": "wecom_ai_bot", "account_id": "bot"}
    )
    assert wecom.account_id == "bot"
    with pytest.raises(ValidationError, match="account_id is required"):
        BindingRequest.model_validate({"app_id": "app", "channel": "wecom_ai_bot"})

    feishu = BindingRequest.model_validate(
        {
            "app_id": "app",
            "channel": "feishu",
            "account_id": "cli_app",
            "secret_refs": {
                "app_secret": "env://FEISHU_APP_SECRET",
                "verification_token": "env://FEISHU_VERIFICATION_TOKEN",
                "encrypt_key": "env://FEISHU_ENCRYPT_KEY",
            },
        }
    )
    assert feishu.account_id == "cli_app"
    with pytest.raises(ValidationError, match="Feishu secret references"):
        BindingRequest.model_validate(
            {"app_id": "app", "channel": "feishu", "account_id": "cli_app"}
        )


def test_admin_routes_etags_idempotency_and_rbac() -> None:
    repo = AdminRepository()
    client = admin_client(repo)
    response = client.post(
        "/v1/tenants",
        json={"tenant_id": "tenant-1", "display_name": "Tenant"},
        headers=headers(),
    )
    assert response.status_code == 201 and response.headers["etag"] == '"1"'
    assert client.get("/v1/tenants/tenant-1", headers=headers()).status_code == 200

    response = client.put(
        "/v1/tenants/tenant-1/channel-bindings/binding-1",
        json={
            "app_id": "app",
            "channel": "wecom_ai_bot",
            "account_id": "bot-account",
            "secret_refs": {"bot_secret": {"uri": "env://WECOM_BOT_SECRET"}},
        },
        headers=headers(),
    )
    assert response.status_code == 200 and response.headers["etag"] == '"2"'
    assert repo.calls[-1][1]["expected_version"] == 1

    assert (
        client.post(
            "/v1/tenants/tenant-1/config-revisions",
            json={"app_id": "app", "config": {"model": "fake"}},
            headers=headers('W/"2"'),
        ).status_code
        == 201
    )
    assert (
        client.post(
            "/v1/tenants/tenant-1/config-revisions/2:activate",
            json={"app_id": "app", "percentage": 25},
            headers=headers(),
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/v1/tenants/tenant-1/config-revisions/1:rollback",
            json={"app_id": "app"},
            headers=headers(),
        ).status_code
        == 200
    )
    assert repo.calls[-1][1]["percentage"] == 100
    assert client.get("/v1/tenants/tenant-1/audit", headers=headers()).status_code == 200
    assert client.get("/v1/tenants/tenant-1/dead-letters", headers=headers()).status_code == 200
    assert (
        client.post(
            "/v1/tenants/tenant-1/outbound/outbound-1:replay",
            json={"confirm_ambiguous": True},
            headers=headers(),
        ).status_code
        == 202
    )

    assert client.get("/v1/tenants/tenant-1").status_code == 401
    forbidden = Authorizer(
        Principal(subject="other", roles=frozenset({Role.TENANT_ADMIN}), tenant_ids=frozenset())
    )
    assert (
        admin_client(authorizer=forbidden)
        .get("/v1/tenants/tenant-1", headers=headers())
        .status_code
        == 403
    )
    assert (
        client.put(
            "/v1/tenants/tenant-1/channel-bindings/b",
            json={
                "app_id": "app",
                "channel": "wecom_ai_bot",
                "account_id": "a",
            },
            headers=headers("invalid"),
        ).status_code
        == 400
    )
    assert (
        client.put(
            "/v1/tenants/tenant-1/channel-bindings/b",
            json={
                "app_id": "app",
                "channel": "wecom_ai_bot",
                "account_id": "a",
            },
            headers=headers("0"),
        ).status_code
        == 400
    )


def test_admin_not_found_and_safe_repository_errors() -> None:
    repo = AdminRepository()
    repo.tenant = None
    assert admin_client(repo).get("/v1/tenants/tenant-1", headers=headers()).status_code == 404
    repo.tenant = {"tenant_id": "tenant-1", "control_version": 1}
    repo.error = IdempotencyConflict()
    assert admin_client(repo).post(
        "/v1/tenants",
        json={"tenant_id": "tenant-1", "display_name": "Tenant"},
        headers=headers(),
    ).json() == {"error": "idempotency_conflict"}
    repo.error = ControlVersionConflict()
    assert admin_client(repo).get("/v1/tenants/tenant-1", headers=headers()).status_code == 412


def test_health_metrics_and_all_safe_error_shapes() -> None:
    app = create_base_app(title="base")

    async def unhealthy():
        return False

    app.include_router(create_health_router(unhealthy), prefix="/checked")

    @app.get("/unknown")
    async def unknown():
        raise UnknownBinding()

    @app.get("/mismatch")
    async def mismatch():
        raise BindingMismatch()

    client = TestClient(app, raise_server_exceptions=False)
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").status_code == 200
    assert client.get("/checked/health/ready").status_code == 503
    assert "text/plain" in client.get("/metrics").headers["content-type"]
    assert client.get("/unknown").json() == {"error": "not_found"}
    assert client.get("/mismatch").json() == {"error": "invalid_callback"}
