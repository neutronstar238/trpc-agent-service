from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from tests.conftest import binding, tenant_config
from tests.unit.test_postgres_repository import Connection, Pool
from trpc_service.tenant.control import (
    ControlVersionConflict,
    IdempotencyConflict,
    PostgresControlPlaneRepository,
    _decode_cursor,
    _encode_cursor,
    _record_json,
)


def control(connection: Connection) -> PostgresControlPlaneRepository:
    return PostgresControlPlaneRepository(Pool(connection))


def tenant_row(version=1):
    return {
        "tenant_id": "tenant-a",
        "display_name": "Tenant",
        "status": "active",
        "control_version": version,
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "updated_at": datetime(2026, 1, 2, tzinfo=UTC),
    }


def kwargs():
    return {
        "tenant_id": "tenant-a",
        "actor": "admin",
        "idempotency_key": "idem-key",
        "request_hash": "request-hash",
    }


@pytest.mark.asyncio
async def test_create_and_get_tenant_cached_conflict_and_success() -> None:
    cached = Connection(
        fetchrows=[{"request_hash": "request-hash", "response_json": '{"cached":true}'}]
    )
    assert await control(cached).create_tenant(display_name="Tenant", **kwargs()) == {
        "cached": True
    }

    created = await control(Connection(fetchrows=[None, tenant_row()])).create_tenant(
        display_name="Tenant", **kwargs()
    )
    assert created["created_at"].startswith("2026-")
    with pytest.raises(ControlVersionConflict, match="exists"):
        await control(Connection(fetchrows=[None, None])).create_tenant(
            display_name="Tenant", **kwargs()
        )
    assert await control(Connection(fetchrows=[None])).get_tenant("tenant-a") is None
    assert (await control(Connection(fetchrows=[tenant_row()])).get_tenant("tenant-a"))[
        "tenant_id"
    ] == "tenant-a"


@pytest.mark.asyncio
async def test_binding_idempotency_and_version_paths() -> None:
    route_binding = binding()
    with pytest.raises(ValueError, match="identity"):
        await control(Connection()).put_binding(
            binding_id="wrong",
            binding=route_binding,
            expected_version=1,
            **kwargs(),
        )
    cached = Connection(
        fetchrows=[{"request_hash": "request-hash", "response_json": {"cached": True}}]
    )
    assert (
        await control(cached).put_binding(
            binding_id=route_binding.binding_id,
            binding=route_binding,
            expected_version=1,
            **kwargs(),
        )
    )["cached"]

    row = {
        "binding_id": route_binding.binding_id,
        "app_id": route_binding.app_id,
        "channel": route_binding.channel.value,
        "account_id": route_binding.account_id,
        "enabled": True,
        "control_version": 1,
    }
    connection = Connection(fetchrows=[None, row], fetchvals=[1, 2])
    result = await control(connection).put_binding(
        binding_id=route_binding.binding_id,
        binding=route_binding,
        expected_version=1,
        **kwargs(),
    )
    assert result["tenant_control_version"] == 2

    with pytest.raises(LookupError, match="tenant"):
        await control(Connection(fetchrows=[None], fetchvals=[None])).put_binding(
            binding_id=route_binding.binding_id,
            binding=route_binding,
            expected_version=1,
            **kwargs(),
        )
    with pytest.raises(ControlVersionConflict, match="changed"):
        await control(Connection(fetchrows=[None], fetchvals=[2])).put_binding(
            binding_id=route_binding.binding_id,
            binding=route_binding,
            expected_version=1,
            **kwargs(),
        )


@pytest.mark.asyncio
async def test_create_config_for_new_and_existing_app() -> None:
    payload = tenant_config().model_dump(
        mode="json", exclude={"tenant_id", "app_id", "version", "created_at"}
    )
    connection = Connection(fetchrows=[None], fetchvals=[1, None, 1, 2])
    result = await control(connection).create_config_revision(
        app_id="support", config=payload, expected_version=1, **kwargs()
    )
    assert result["version"] == 1 and len(result["checksum"]) == 64
    assert any("INSERT INTO agent_apps" in call[1][0] for call in connection.calls)

    existing = Connection(fetchrows=[None], fetchvals=[2, 1, 2, 3])
    result = await control(existing).create_config_revision(
        app_id="support", config=payload, expected_version=2, **kwargs()
    )
    assert result["tenant_control_version"] == 3
    assert not any("INSERT INTO agent_apps" in call[1][0] for call in existing.calls)

    cached = Connection(
        fetchrows=[{"request_hash": "request-hash", "response_json": '{"version":9}'}]
    )
    assert (
        await control(cached).create_config_revision(
            app_id="support", config=payload, expected_version=1, **kwargs()
        )
    )["version"] == 9


async def activate(percentage, *, exists=1, operation="activate_config"):
    connection = Connection(fetchrows=[None], fetchvals=[1, exists, 2])
    result = await control(connection).activate_config(
        app_id="support",
        version=1,
        percentage=percentage,
        expected_version=1,
        operation=operation,
        **kwargs(),
    )
    return result, connection


@pytest.mark.asyncio
async def test_activate_gray_cancel_full_and_rollback_labels() -> None:
    with pytest.raises(ValueError, match="percentage"):
        await control(Connection()).activate_config(
            app_id="support", version=1, percentage=101, expected_version=1, **kwargs()
        )
    with pytest.raises(LookupError, match="revision"):
        await activate(50, exists=None)
    for percentage in (0, 25, 100):
        result, connection = await activate(percentage)
        assert result["percentage"] == percentage
        updates = [call for call in connection.calls if call[0] == "execute"]
        assert updates
    _, rollback = await activate(100, operation="rollback_config")
    assert any("rollback_config" in str(call[1]) for call in rollback.calls if call[0] == "execute")

    cached = Connection(
        fetchrows=[{"request_hash": "request-hash", "response_json": {"percentage": 10}}]
    )
    assert (
        await control(cached).activate_config(
            app_id="support", version=1, percentage=10, expected_version=1, **kwargs()
        )
    )["percentage"] == 10


@pytest.mark.asyncio
async def test_audit_cursor_dead_letters_and_helpers() -> None:
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    ids = [uuid4(), uuid4()]
    rows = [
        {"occurred_at": timestamp, "audit_id": ids[0], "decision": "one"},
        {"occurred_at": timestamp, "audit_id": ids[1], "decision": "two"},
    ]
    first = await control(Connection(fetches=[rows])).audit_page("tenant-a", cursor=None, limit=1)
    assert len(first["items"]) == 1 and first["next_cursor"]
    cursor = _encode_cursor(timestamp, ids[0])
    assert _decode_cursor(cursor) == (timestamp, ids[0])
    second = await control(Connection(fetches=[rows[:1]])).audit_page(
        "tenant-a", cursor=cursor, limit=999
    )
    assert second["next_cursor"] is None
    with pytest.raises(ValueError, match="cursor"):
        _decode_cursor("not-a-cursor")

    dead = await control(Connection(fetches=[[{"dead_letter_id": ids[0]}]])).dead_letters(
        "tenant-a", limit=0
    )
    assert dead[0]["dead_letter_id"] == str(ids[0])
    converted = _record_json({"when": timestamp, "id": ids[0], "value": 1})
    assert converted["when"].endswith("+00:00") and converted["id"] == str(ids[0])


@pytest.mark.asyncio
async def test_replay_outbound_guards_and_success() -> None:
    outbound_id = str(uuid4())
    base = [None]
    with pytest.raises(LookupError, match="outbound"):
        await control(Connection(fetchrows=[*base, None], fetchvals=[1])).replay_outbound(
            outbound_id=outbound_id,
            confirm_ambiguous=False,
            expected_version=1,
            **kwargs(),
        )
    ambiguous_row = {
        "status": "ambiguous",
        "payload_json": "{}",
        "trace_headers": "{}",
        "channel": "feishu",
    }
    with pytest.raises(ValueError, match="confirmation"):
        await control(Connection(fetchrows=[*base, ambiguous_row], fetchvals=[1])).replay_outbound(
            outbound_id=outbound_id,
            confirm_ambiguous=False,
            expected_version=1,
            **kwargs(),
        )
    success = Connection(fetchrows=[*base, ambiguous_row], fetchvals=[1, 2])
    result = await control(success).replay_outbound(
        outbound_id=outbound_id,
        confirm_ambiguous=True,
        expected_version=1,
        **kwargs(),
    )
    assert result["status"] == "pending" and result["tenant_control_version"] == 2

    cached = Connection(
        fetchrows=[{"request_hash": "request-hash", "response_json": '{"status":"cached"}'}]
    )
    assert (
        await control(cached).replay_outbound(
            outbound_id=outbound_id,
            confirm_ambiguous=False,
            expected_version=1,
            **kwargs(),
        )
    )["status"] == "cached"


@pytest.mark.asyncio
async def test_cached_idempotency_rejects_reuse_and_invalid_storage() -> None:
    mismatch = Connection(fetchrows=[{"request_hash": "other", "response_json": "{}"}])
    with pytest.raises(IdempotencyConflict, match="another"):
        await PostgresControlPlaneRepository._cached(mismatch, "tenant", "key", "request-hash")
    invalid = Connection(fetchrows=[{"request_hash": "request-hash", "response_json": 1}])
    with pytest.raises(RuntimeError, match="invalid"):
        await PostgresControlPlaneRepository._cached(invalid, "tenant", "key", "request-hash")
