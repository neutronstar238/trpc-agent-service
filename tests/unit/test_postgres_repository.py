from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from tests.conftest import envelope, repository, tenant_config
from trpc_service.channels.envelopes import (
    DeliveryReceipt,
    DeliveryStatus,
    OutboundEnvelope,
)
from trpc_service.runtime import TenantRuntime
from trpc_service.storage.models import SessionLease, SessionSnapshot, StoredEvent, TurnCommit
from trpc_service.storage.postgres import PostgresBindingLease, PostgresRuntimeRepository
from trpc_service.storage.protocols import FencingConflict
from trpc_service.tenant.models import Channel


class Connection:
    def __init__(
        self,
        *,
        fetchrows=(),
        fetches=(),
        fetchvals=(),
        executes=(),
    ) -> None:
        self.fetchrows = list(fetchrows)
        self.fetches = list(fetches)
        self.fetchvals = list(fetchvals)
        self.executes = list(executes)
        self.calls = []

    def transaction(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def fetchrow(self, *args):
        self.calls.append(("fetchrow", args))
        return self.fetchrows.pop(0) if self.fetchrows else None

    async def fetch(self, *args):
        self.calls.append(("fetch", args))
        return self.fetches.pop(0) if self.fetches else []

    async def fetchval(self, *args):
        self.calls.append(("fetchval", args))
        value = self.fetchvals.pop(0) if self.fetchvals else None
        if isinstance(value, BaseException):
            raise value
        return value

    async def execute(self, *args):
        self.calls.append(("execute", args))
        return self.executes.pop(0) if self.executes else "UPDATE 1"


class Acquire:
    def __init__(self, connection):
        self.connection = connection

    def __await__(self):
        async def value():
            return self.connection

        return value().__await__()

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, *args):
        return None


class Pool:
    def __init__(self, connection):
        self.connection = connection
        self.closed = False
        self.released = []

    def acquire(self):
        return Acquire(self.connection)

    async def release(self, connection):
        self.released.append(connection)

    async def close(self):
        self.closed = True


async def acceptance():
    memory = repository()
    accepted = await TenantRuntime(memory, routing_key=b"p" * 32).accept(
        "binding-unpredictable-a", envelope()
    )
    return accepted.model_copy(update={"inbound_id": str(uuid4())})


@pytest.mark.asyncio
async def test_repository_readiness_checks_database_without_tenant_context() -> None:
    healthy = PostgresRuntimeRepository(Pool(Connection(fetchvals=[1])))
    unavailable = PostgresRuntimeRepository(Pool(Connection(fetchvals=[OSError("down")])))
    assert await healthy.ready()
    assert not await unavailable.ready()


def route_row():
    return {
        "binding_id": "binding",
        "tenant_id": "tenant-a",
        "app_id": "support",
        "channel": "feishu",
        "account_id": "account",
        "secret_refs": "{}",
        "enabled": True,
        "control_version": 1,
        "capabilities": '["media"]',
        "tenant_active": True,
        "active_config_version": 1,
        "candidate_config_version": None,
        "candidate_percent": 0,
    }


def inbound_row(accepted, *, status="accepted"):
    return {
        "inbound_id": accepted.inbound_id,
        "tenant_id": accepted.context.tenant_id,
        "app_id": accepted.context.app_id,
        "config_version": accepted.context.config_version,
        "binding_id": accepted.context.channel_binding_id,
        "principal_id": accepted.context.principal_id,
        "session_id": accepted.context.session_id,
        "request_id": accepted.context.request_id,
        "trace_id": accepted.context.trace_id,
        "envelope_json": accepted.envelope.model_dump_json(),
        "status": status,
        "accepted_at": datetime.now(UTC),
    }


def session_row(accepted, *, owner=None, expires=None, epoch=0):
    return {
        "app_id": accepted.context.app_id,
        "principal_id": accepted.context.principal_id,
        "version": 0,
        "next_sequence": 1,
        "state_json": "{}",
        "lease_owner": owner,
        "lease_expires_at": expires,
        "lease_epoch": epoch,
    }


def event_row():
    return {
        "sequence": 1,
        "event_id": "event",
        "author": "agent",
        "event_timestamp": 1.0,
        "event_json": '{"id":"event","author":"agent"}',
        "state_delta": '{"x":1}',
    }


@pytest.mark.asyncio
async def test_repository_construction_binding_config_and_reads(monkeypatch) -> None:
    created_pool = Pool(Connection())

    async def create_pool(*args, **kwargs):
        assert kwargs["server_settings"]["application_name"] == "trpc-agent-service"
        return created_pool

    monkeypatch.setattr("trpc_service.storage.postgres.asyncpg.create_pool", create_pool)
    created = await PostgresRuntimeRepository.create("postgresql://dsn", min_size=1, max_size=3)
    assert created.pool is created_pool
    await created.close()
    assert created_pool.closed

    connection = Connection(fetchrows=[None, route_row()], fetches=[[route_row()]])
    repo = PostgresRuntimeRepository(Pool(connection))
    assert await repo.resolve_binding("missing") is None
    route = await repo.resolve_binding("binding")
    assert route is not None and "media" in route.binding.capabilities
    assert len(await repo.list_bindings(Channel.FEISHU)) == 1

    connection.fetchvals.extend([None, tenant_config().model_dump_json()])
    with pytest.raises(LookupError, match="configuration"):
        await repo.get_config("tenant-a", "support", 1)
    assert (await repo.get_config("tenant-a", "support", 1)).version == 1

    accepted = await acceptance()
    connection.fetchrows.extend([None, inbound_row(accepted), None, session_row(accepted)])
    connection.fetches.append([event_row()])
    assert await repo.get_acceptance("tenant-a", str(uuid4())) is None
    persisted = await repo.get_acceptance("tenant-a", accepted.inbound_id)
    assert persisted is not None and persisted.context == accepted.context
    assert not persisted.duplicate
    assert await repo.get_session_snapshot("tenant-a", "missing") is None
    snapshot = await repo.get_session_snapshot("tenant-a", accepted.context.session_id)
    assert snapshot is not None and snapshot.events[0].state_delta == {"x": 1}


@pytest.mark.asyncio
async def test_accept_inbound_new_and_duplicate() -> None:
    accepted = await acceptance()
    row = inbound_row(accepted)
    connection = Connection(fetchrows=[row])
    repo = PostgresRuntimeRepository(Pool(connection))
    value = await repo.accept_inbound(
        context=accepted.context,
        envelope=accepted.envelope,
        trace_headers={"traceparent": "trace"},
    )
    assert value.context == accepted.context
    assert len([call for call in connection.calls if call[0] == "execute"]) == 4

    duplicate_connection = Connection(fetchrows=[None, row])
    duplicate = await PostgresRuntimeRepository(Pool(duplicate_connection)).accept_inbound(
        context=accepted.context,
        envelope=accepted.envelope,
        trace_headers={},
    )
    assert duplicate.duplicate


@pytest.mark.asyncio
async def test_get_acceptance_marks_committed_redelivery_duplicate() -> None:
    accepted = await acceptance()
    row = inbound_row(accepted, status="committed")
    duplicate = await PostgresRuntimeRepository(Pool(Connection(fetchrows=[row]))).get_acceptance(
        "tenant-a", accepted.inbound_id
    )
    assert duplicate is not None and duplicate.duplicate


@pytest.mark.asyncio
async def test_acquire_all_contention_and_retry_branches() -> None:
    accepted = await acceptance()
    now = datetime.now(UTC)
    committed = Connection(
        fetchrows=[session_row(accepted), {"status": "committed"}],
        fetchvals=[now],
    )
    assert (
        await PostgresRuntimeRepository(Pool(committed)).acquire(
            acceptance=accepted, worker_id="worker", lease_for=timedelta(seconds=30)
        )
        is None
    )

    busy = Connection(
        fetchrows=[
            session_row(accepted, owner="other", expires=now + timedelta(minutes=1)),
            None,
        ],
        fetchvals=[now],
    )
    assert (
        await PostgresRuntimeRepository(Pool(busy)).acquire(
            acceptance=accepted, worker_id="worker", lease_for=timedelta(seconds=30)
        )
        is None
    )

    same_owner = Connection(
        fetchrows=[
            session_row(accepted, owner="worker", expires=now + timedelta(minutes=1)),
            None,
        ],
        fetchvals=[now],
    )
    assert (
        await PostgresRuntimeRepository(Pool(same_owner)).acquire(
            acceptance=accepted, worker_id="worker", lease_for=timedelta(seconds=30)
        )
        is None
    )

    earlier = Connection(
        fetchrows=[session_row(accepted), None, {"accepted_at": now}],
        fetchvals=[now, 1],
    )
    assert (
        await PostgresRuntimeRepository(Pool(earlier)).acquire(
            acceptance=accepted, worker_id="worker", lease_for=timedelta(seconds=30)
        )
        is None
    )

    fresh = Connection(
        fetchrows=[session_row(accepted), None, {"accepted_at": now}],
        fetchvals=[now, None],
        fetches=[[event_row()]],
    )
    lease = await PostgresRuntimeRepository(Pool(fresh)).acquire(
        acceptance=accepted, worker_id="worker", lease_for=timedelta(seconds=30)
    )
    assert lease is not None and lease.attempt == 1 and lease.snapshot.events

    turn_id = uuid4()
    retry = Connection(
        fetchrows=[
            session_row(accepted, owner="worker", expires=now - timedelta(seconds=1), epoch=1),
            {"status": "failed", "turn_id": turn_id, "attempt": 2},
            {"accepted_at": now},
        ],
        fetchvals=[now, None],
        fetches=[[]],
    )
    retried = await PostgresRuntimeRepository(Pool(retry)).acquire(
        acceptance=accepted, worker_id="worker", lease_for=timedelta(seconds=30)
    )
    assert retried is not None and retried.attempt == 3 and retried.turn_id == str(turn_id)


@pytest.mark.asyncio
async def test_renew_commit_fail_and_delivery() -> None:
    accepted = await acceptance()
    now = datetime.now(UTC)
    acquire_connection = Connection(
        fetchrows=[session_row(accepted), None, {"accepted_at": now}],
        fetchvals=[now, None],
        fetches=[[]],
    )
    repo = PostgresRuntimeRepository(Pool(acquire_connection))
    lease = await repo.acquire(
        acceptance=accepted, worker_id="worker", lease_for=timedelta(seconds=30)
    )
    assert lease is not None

    failed_renew = PostgresRuntimeRepository(Pool(Connection(fetchvals=[None])))
    with pytest.raises(FencingConflict, match="lease"):
        await failed_renew.renew(lease, lease_for=timedelta(seconds=30))
    renewed_at = now + timedelta(minutes=1)
    renew_connection = Connection(fetchvals=[renewed_at])
    renewed = await PostgresRuntimeRepository(Pool(renew_connection)).renew(
        lease, lease_for=timedelta(seconds=30)
    )
    assert renewed.expires_at == renewed_at
    renew_query = next(call for call in renew_connection.calls if call[0] == "fetchval")
    assert "GREATEST" in renew_query[1][0]
    assert "clock_timestamp()" in renew_query[1][0]
    assert "now()" not in renew_query[1][0]
    assert renew_query[1][-1] == timedelta(seconds=30)

    with pytest.raises(FencingConflict, match="stale"):
        await PostgresRuntimeRepository(Pool(Connection(fetchrows=[None, None]))).commit(
            TurnCommit(context=accepted.context, lease=lease, state={}, events=())
        )

    valid_session = session_row(
        accepted,
        owner="worker",
        expires=now + timedelta(minutes=1),
        epoch=lease.fencing_token,
    )
    turn = {"fencing_token": lease.fencing_token, "status": "processing"}
    outbound = OutboundEnvelope(
        outbound_id=str(uuid4()),
        tenant_id="tenant-a",
        binding_id=accepted.context.channel_binding_id,
        channel=Channel.FEISHU,
        target_id="user",
        session_id=accepted.context.session_id,
        text="reply",
    )
    commit_connection = Connection(fetchrows=[valid_session, turn], fetchvals=[now])
    result = await PostgresRuntimeRepository(Pool(commit_connection)).commit(
        TurnCommit(
            context=accepted.context,
            lease=lease,
            state={"done": True},
            events=(
                StoredEvent(event_id="event", author="agent", timestamp=1, event={"id": "event"}),
            ),
            outbound=outbound,
        )
    )
    assert result.first_sequence == 1 and result.outbound_id == outbound.outbound_id

    empty_commit = await PostgresRuntimeRepository(
        Pool(Connection(fetchrows=[valid_session, turn], fetchvals=[now]))
    ).commit(TurnCommit(context=accepted.context, lease=lease, state={}, events=()))
    assert empty_commit.first_sequence is None and empty_commit.last_sequence is None

    failed = Connection()
    await PostgresRuntimeRepository(Pool(failed)).fail(lease, error_type="model_timeout")
    assert len([call for call in failed.calls if call[0] == "execute"]) == 4

    receipt = DeliveryReceipt(
        outbound_id=str(uuid4()),
        status=DeliveryStatus.FAILED,
        provider_code="rate",
        retryable=True,
    )
    delivery = Connection(fetchvals=[2])
    await PostgresRuntimeRepository(Pool(delivery)).record_delivery(
        "tenant-a", receipt, retrying=True
    )
    assert len([call for call in delivery.calls if call[0] == "execute"]) == 4
    audit_sql = [call[1][0] for call in delivery.calls if call[0] == "execute"][-1]
    assert "$4::text" in audit_sql


@pytest.mark.asyncio
async def test_acquire_uses_database_clock_when_application_clock_is_behind() -> None:
    accepted = await acceptance()
    application_now = datetime.now(UTC)
    database_now = application_now + timedelta(minutes=2)
    connection = Connection(
        fetchrows=[
            session_row(
                accepted,
                owner="old-worker",
                expires=application_now + timedelta(minutes=1),
            ),
            None,
            {"accepted_at": application_now},
        ],
        fetchvals=[database_now, None],
        fetches=[[]],
    )

    lease = await PostgresRuntimeRepository(Pool(connection)).acquire(
        acceptance=accepted,
        worker_id="new-worker",
        lease_for=timedelta(seconds=30),
    )

    assert lease is not None
    assert lease.expires_at == database_now + timedelta(seconds=30)
    update_sql = next(
        args[0]
        for kind, args in connection.calls
        if kind == "execute" and "UPDATE sessions" in args[0]
    )
    assert "clock_timestamp()" in update_sql
    update_args = next(
        args
        for kind, args in connection.calls
        if kind == "execute" and "UPDATE sessions" in args[0]
    )
    assert update_args[-1] == timedelta(seconds=30)


@pytest.mark.asyncio
async def test_commit_rejects_expired_lease_at_database_clock() -> None:
    accepted = await acceptance()
    database_now = datetime.now(UTC)
    lease = SessionLease(
        tenant_id=accepted.context.tenant_id,
        session_id=accepted.context.session_id,
        turn_id=str(uuid4()),
        inbound_id=accepted.inbound_id,
        worker_id="worker",
        fencing_token=3,
        expires_at=database_now - timedelta(seconds=1),
        snapshot=SessionSnapshot(
            tenant_id=accepted.context.tenant_id,
            app_id=accepted.context.app_id,
            session_id=accepted.context.session_id,
            principal_id=accepted.context.principal_id,
        ),
    )
    connection = Connection(
        fetchrows=[
            session_row(
                accepted,
                owner=lease.worker_id,
                expires=lease.expires_at,
                epoch=lease.fencing_token,
            ),
            {"fencing_token": lease.fencing_token, "status": "processing"},
        ],
        fetchvals=[database_now],
    )

    with pytest.raises(FencingConflict, match="stale"):
        await PostgresRuntimeRepository(Pool(connection)).commit(
            TurnCommit(context=accepted.context, lease=lease, state={}, events=())
        )

    assert not any(
        kind == "execute" and "UPDATE sessions" in args[0] for kind, args in connection.calls
    )
    clock_query = next(args[0] for kind, args in connection.calls if kind == "fetchval")
    assert clock_query == "SELECT clock_timestamp()"


@pytest.mark.asyncio
async def test_outbox_claim_mark_release() -> None:
    outbox_id = uuid4()
    row = {
        "outbox_id": outbox_id,
        "tenant_id": "tenant-a",
        "event_type": "inbound.accepted",
        "aggregate_id": "aggregate",
        "payload_json": '{"x":1}',
        "trace_headers": "{}",
        "attempts": 2,
    }
    connection = Connection(fetches=[[row]])
    repo = PostgresRuntimeRepository(Pool(connection))
    claimed = await repo.claim_outbox(
        event_type="inbound.accepted",
        owner_id="owner",
        limit=10,
        lease_for=timedelta(seconds=30),
    )
    assert claimed[0].payload == {"x": 1}

    await PostgresRuntimeRepository(Pool(Connection(executes=["UPDATE 1"]))).mark_outbox_published(
        "tenant-a", str(outbox_id), owner_id="owner"
    )
    with pytest.raises(FencingConflict, match="claim"):
        await PostgresRuntimeRepository(
            Pool(Connection(executes=["SELECT 1", "UPDATE 0"]))
        ).mark_outbox_published("tenant-a", str(outbox_id), owner_id="owner")
    release = Connection()
    await PostgresRuntimeRepository(Pool(release)).release_outbox(
        "tenant-a",
        str(outbox_id),
        owner_id="owner",
        delay=timedelta(seconds=1),
        error_type="redis",
    )
    assert any(call[0] == "execute" for call in release.calls)

    dead_letter = Connection()
    await PostgresRuntimeRepository(Pool(dead_letter)).dead_letter_outbox(
        claimed[0], owner_id="owner", reason="delivery_exhausted"
    )
    statements = [call[1][0] for call in dead_letter.calls if call[0] == "execute"]
    assert any("INSERT INTO dead_letters" in statement for statement in statements)
    assert any("UPDATE outbox_events" in statement for statement in statements)


@pytest.mark.asyncio
async def test_postgres_binding_lease_ownership_and_release() -> None:
    connection = Connection(fetchvals=[True])
    pool = Pool(connection)
    lease = PostgresBindingLease(pool)
    assert await lease.acquire_binding("binding", "owner")
    assert await lease.acquire_binding("binding", "owner")
    assert not await lease.acquire_binding("binding", "other")
    await lease.release_binding("binding", "other")
    await lease.release_binding("binding", "owner")
    assert pool.released == [connection]

    unavailable_pool = Pool(Connection(fetchvals=[False]))
    assert not await PostgresBindingLease(unavailable_pool).acquire_binding("b", "o")
    assert unavailable_pool.released

    broken_pool = Pool(Connection(fetchvals=[RuntimeError("db")]))
    with pytest.raises(RuntimeError, match="db"):
        await PostgresBindingLease(broken_pool).acquire_binding("b", "o")
    assert broken_pool.released
