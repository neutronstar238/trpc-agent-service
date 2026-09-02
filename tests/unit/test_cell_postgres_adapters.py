"""Behavioral tests for the PostgreSQL Cell event-store adapter.

The project keeps the PostgreSQL adapter optional at runtime, so these tests
use a tiny stateful asyncpg double.  It models the rows and constraints that
the adapter relies on (rather than merely returning a queue of SQL results),
which makes the tests useful for append idempotency, fencing and lineage
semantics without requiring a live database.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trpc_service.cell.capsule import AgentCapsule, CapsuleMetadata, CapsuleSpec
from trpc_service.cell.events import (
    GENESIS_HASH,
    AppendOnlyViolation,
    BranchNotFound,
    CausalEvent,
    CellAddress,
    ChainIntegrityError,
    EventBranch,
    EventDraft,
    EventStoreError,
    InMemoryEventStore,
    InvalidBranch,
    NamespaceViolation,
)
from trpc_service.cell.postgres import (
    CompareAndSwapConflict,
    FencedLeaseError,
    PostgresEventStore,
)

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


class AsyncContext:
    def __init__(self, value: object) -> None:
        self.value = value

    async def __aenter__(self) -> object:
        return self.value

    async def __aexit__(self, *args: object) -> bool:
        del args
        return False


class CellConnection:
    """Small row-level fake for the SQL used by ``PostgresEventStore``."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.cells: dict[tuple[str, str, str, str, str, str], dict[str, object]] = {}
        self.heads: dict[tuple[str, str, str, str, str, str], dict[str, object]] = {}
        self.events: dict[tuple[str, str], dict[str, object]] = {}
        self.capsules: set[tuple[str, str]] = set()
        self.session_fence_result: object = 1
        self.return_missing_cell = False
        self.return_missing_inserted_event = False
        self.skip_event_preflight_once = False
        self.lineage_override: list[dict[str, object]] | None = None

    @staticmethod
    def _key(args: tuple[object, ...]) -> tuple[str, str, str, str, str, str]:
        return cast(tuple[str, str, str, str, str, str], tuple(str(item) for item in args[:6]))

    @staticmethod
    def _address(row: dict[str, object]) -> tuple[str, str, str, str, str, str]:
        return (
            cast(str, row["tenant_id"]),
            cast(str, row["app_id"]),
            cast(str, row["cell_id"]),
            cast(str, row["session_id"]),
            cast(str, row["capsule_digest"]),
            cast(str, row["branch_id"]),
        )

    def transaction(self) -> AsyncContext:
        return AsyncContext(self)

    def _cell_row(self, key: tuple[str, str, str, str, str, str]) -> dict[str, object] | None:
        return self.cells.get(key)

    def _event_rows_for(self, key: tuple[str, str, str, str, str, str]) -> list[dict[str, object]]:
        rows = [row for row in self.events.values() if self._address(row) == key]
        rows.sort(key=lambda row: int(cast(int, row["sequence"])))
        return rows

    async def execute(self, query: str, *args: object) -> str:
        self.calls.append((query, args))
        compact = " ".join(query.split())
        if "INSERT INTO cell_branch_heads" in compact:
            key = self._key(args)
            self.heads.setdefault(
                key,
                {
                    "last_sequence": int(cast(int, args[6])),
                    "last_event_hash": str(args[7]),
                    "lease_owner": None,
                    "lease_epoch": 0,
                    "lease_expires_at": None,
                    "lease_valid": True,
                },
            )
        elif "INSERT INTO agent_cells" in compact:
            key = self._key(args)
            assert (key[0], key[4]) in self.capsules, "agent_cells capsule foreign key"
            # ensure_cell() supplies 13 values while fork() supplies 10.
            # Model INSERT .. DO NOTHING so a second ensure cannot rewrite
            # immutable parent metadata.
            self.cells.setdefault(
                key,
                {
                    "tenant_id": key[0],
                    "app_id": key[1],
                    "cell_id": key[2],
                    "session_id": key[3],
                    "capsule_digest": key[4],
                    "branch_id": key[5],
                    "parent_branch_id": args[6],
                    "parent_capsule_digest": args[7],
                    "fork_sequence": args[8],
                    "state_hash": str(args[12] if len(args) == 13 else args[9]),
                    "created_at": NOW,
                },
            )
        return "OK"

    async def fetchval(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        compact = " ".join(query.split())
        if "FROM public.sessions" in compact or "FROM sessions" in compact:
            return self.session_fence_result
        if "FROM agent_capsules" in compact:
            return 1 if (str(args[0]), str(args[1])) in self.capsules else None
        if "SELECT 1 FROM cell_events" in compact:
            return 1 if (str(args[0]), str(args[1])) in self.events else None
        if "SELECT 1 FROM agent_cells" in compact:
            key = self._key(args)
            return 1 if key in self.cells else None
        return None

    async def fetchrow(self, query: str, *args: object) -> dict[str, object] | None:
        self.calls.append((query, args))
        compact = " ".join(query.split())

        if "FROM public.sessions" in compact or "FROM sessions" in compact:
            if self.session_fence_result is None:
                return None
            return {"lease_expires_at": NOW + timedelta(minutes=1)}

        if "INSERT INTO agent_cells" in compact:
            key = self._key(args)
            assert (key[0], key[4]) in self.capsules, "agent_cells capsule foreign key"
            if self.return_missing_cell:
                return None
            existing = self.cells.get(key)
            if existing is None:
                existing = {
                    "tenant_id": key[0],
                    "app_id": key[1],
                    "cell_id": key[2],
                    "session_id": key[3],
                    "capsule_digest": key[4],
                    "branch_id": key[5],
                    "parent_branch_id": args[6],
                    "parent_capsule_digest": args[7],
                    "fork_sequence": args[8],
                    "state_hash": args[12],
                    "created_at": NOW,
                }
                self.cells[key] = existing
            return {
                "parent_branch_id": existing.get("parent_branch_id"),
                "parent_capsule_digest": existing.get("parent_capsule_digest"),
                "fork_sequence": existing.get("fork_sequence"),
            }

        if "INSERT INTO cell_events" in compact:
            event_id = str(args[7])
            event_key = (str(args[0]), event_id)
            if self.return_missing_inserted_event:
                return None
            if event_key in self.events:
                return None
            payload_raw = args[9]
            payload = json.loads(payload_raw) if isinstance(payload_raw, str) else payload_raw
            row: dict[str, object] = {
                "tenant_id": args[0],
                "app_id": args[1],
                "cell_id": args[2],
                "session_id": args[3],
                "capsule_digest": args[4],
                "branch_id": args[5],
                "sequence": args[6],
                "event_id": args[7],
                "event_type": args[8],
                "payload": payload,
                "causation_id": args[10],
                "correlation_id": args[11],
                "trace_id": args[12],
                "request_id": args[13],
                "occurred_at": args[14],
                "prev_hash": args[15],
                "payload_hash": args[16],
                "event_hash": args[17],
            }
            self.events[event_key] = row
            key = self._address(row)
            head = self.heads[key]
            head["last_sequence"] = args[6]
            head["last_event_hash"] = args[17]
            return row

        if "FROM cell_events" in compact and "correlation_id=$2" in compact:
            return next(
                (
                    row
                    for row in self.events.values()
                    if row.get("tenant_id") == args[0]
                    and row.get("correlation_id") == args[1]
                    and row.get("event_type") == args[2]
                ),
                None,
            )

        if "FROM cell_events" in compact and "event_id=$2" in compact:
            if self.skip_event_preflight_once:
                self.skip_event_preflight_once = False
                return None
            return self.events.get((str(args[0]), str(args[1])))

        if "lock_cell_branch_head" in compact or "FROM cell_branch_heads" in compact:
            return self.heads.get(self._key(args))

        if "FROM agent_cells" in compact:
            if self.return_missing_cell:
                return None
            return self.cells.get(self._key(args))

        return None

    async def fetch(self, query: str, *args: object) -> list[dict[str, object]]:
        self.calls.append((query, args))
        compact = " ".join(query.split())
        if "FROM cell_events" in compact:
            if "JOIN tool_executions" in compact:
                return []
            key = self._key(args)
            lower = int(cast(int, args[6]))
            upper = int(cast(int, args[7])) if len(args) > 7 else None
            source = self.lineage_override
            if source is None:
                source = self._event_rows_for(key)
            rows = [row for row in source if int(cast(int, row["sequence"])) > lower]
            if upper is not None:
                rows = [row for row in rows if int(cast(int, row["sequence"])) <= upper]
            return rows
        if "FROM agent_cells" in compact:
            tenant, app, cell, session, digest = (str(item) for item in args)
            return [
                row
                for row in sorted(self.cells.values(), key=lambda value: str(value["branch_id"]))
                if (
                    row["tenant_id"],
                    row["app_id"],
                    row["cell_id"],
                    row["session_id"],
                    row["capsule_digest"],
                )
                == (tenant, app, cell, session, digest)
            ]
        return []


class CellPool:
    def __init__(self, connection: CellConnection) -> None:
        self.connection = connection

    def acquire(self) -> AsyncContext:
        return AsyncContext(self.connection)


def address(
    *,
    tenant: str = "tenant-a",
    app: str = "app-a",
    cell: str = "cell-a",
    session: str = "session-a",
    digest: str = DIGEST,
    branch: str = "main",
) -> CellAddress:
    return CellAddress(
        tenant_id=tenant,
        app_id=app,
        cell_id=cell,
        session_id=session,
        capsule_digest=digest,
        branch_id=branch,
    )


def signed_capsule(*, tenant: str = "tenant-a", name: str = "agent-a") -> AgentCapsule:
    capsule = AgentCapsule(
        metadata=CapsuleMetadata(tenant_id=tenant, name=name),
        spec=CapsuleSpec(
            graph=DIGEST,
            prompt=DIGEST,
            model_policy=DIGEST,
            tool_manifest=DIGEST,
            governance_policy=DIGEST,
            storage_profile=DIGEST,
        ),
    )
    return capsule.sign(Ed25519PrivateKey.generate(), key_id="control-key")


def malformed_capsule(*, tenant: str, name: str) -> AgentCapsule:
    """Create a model-shaped payload with invalid identity for final guards."""

    valid = signed_capsule()
    metadata = CapsuleMetadata.model_construct(
        tenant_id=tenant,
        name=name,
        version=1,
        labels={},
        annotations={},
    )
    model = AgentCapsule.model_construct(
        api_version=valid.api_version,
        kind="AgentCapsule",
        metadata=metadata,
        spec=valid.spec,
        digest=None,
        signature=valid.signature,
    )
    return model.model_copy(update={"digest": model.compute_digest()})


def draft(
    target: CellAddress,
    *,
    event_id: str | None = None,
    payload: dict[str, object] | None = None,
    event_type: str = "message.accepted",
    causation_id: str | None = None,
    correlation_id: str = "corr-a",
    trace_id: str = "trace-a",
    request_id: str = "request-a",
) -> EventDraft:
    return EventDraft(
        tenant_id=target.tenant_id,
        app_id=target.app_id,
        cell_id=target.cell_id,
        session_id=target.session_id,
        capsule_digest=target.capsule_digest,
        branch_id=target.branch_id,
        event_type=event_type,
        payload=payload or {"text": "hello"},
        event_id=event_id,
        causation_id=causation_id,
        correlation_id=correlation_id,
        trace_id=trace_id,
        request_id=request_id,
        occurred_at=NOW,
    )


def make_store() -> tuple[PostgresEventStore, CellConnection]:
    connection = CellConnection()
    # ``agent_cells`` has a tenant/capsule foreign key in the real schema.
    # Seed the deployment registry precondition so event-store tests cannot
    # accidentally pass with a Cell that PostgreSQL would reject.
    connection.capsules.add(("tenant-a", DIGEST))
    return PostgresEventStore(CellPool(connection)), connection


def seed_row_event(
    connection: CellConnection,
    target: CellAddress,
    *,
    sequence: int,
    event_id: str,
    prev_hash: str = GENESIS_HASH,
    payload: dict[str, object] | None = None,
) -> CausalEvent:
    normalised = draft(target, event_id=event_id, payload=payload).normalised()
    event = InMemoryEventStore._build_event(
        normalised,
        sequence=sequence,
        prev_hash=prev_hash,
    )
    row = event.to_dict()
    row["app_id"] = target.app_id
    connection.events[(target.tenant_id, event.event_id)] = row
    return event


async def ensure_root(store: PostgresEventStore, target: CellAddress) -> EventBranch:
    return await store.ensure_cell(target)


def test_repository_rejects_a_pool_without_asyncpg_acquire() -> None:
    with pytest.raises(TypeError, match="acquire"):
        PostgresEventStore(cast(Any, object()))


def test_result_hash_falls_back_to_repr_for_non_json_values() -> None:
    from trpc_service.cell.postgres import _result_hash

    value = object()
    assert _result_hash(value) == hashlib.sha256(repr(value).encode("utf-8")).hexdigest()
    assert _result_hash(None) is None


@pytest.mark.asyncio
async def test_capsule_registration_rejects_conflicting_arguments_and_bad_models() -> None:
    store, connection = make_store()
    capsule = signed_capsule()

    with pytest.raises(TypeError, match="omitted"):
        await store.ensure_capsule(capsule, capsule)
    with pytest.raises(TypeError, match="manifest"):
        await store.ensure_capsule("tenant-a")
    with pytest.raises(ValueError, match="digest"):
        await store.ensure_capsule(capsule.model_copy(update={"digest": OTHER_DIGEST}))

    # These model-shaped cases represent corrupted control-plane payloads at
    # the adapter boundary.  They verify that invalid identity fields cannot
    # reach the privileged SQL function even if upstream validation regresses.
    for malformed, message in (
        (malformed_capsule(tenant="", name="agent-a"), "tenant_id"),
        (malformed_capsule(tenant="tenant-a", name=""), "capsule_name"),
    ):
        with pytest.raises(ValueError, match=message):
            await store.ensure_capsule(malformed, trust_class="runtime_projection")
    assert not any("ensure_" in query for query, _ in connection.calls)


@pytest.mark.asyncio
async def test_ensure_cell_is_idempotent_and_preserves_branch_metadata() -> None:
    store, connection = make_store()
    target = address()

    first = await ensure_root(store, target)
    second = await ensure_root(store, target)

    assert first.address == second.address
    assert first.parent_branch_id is None and second.parent_branch_id is None
    assert first.fork_sequence == second.fork_sequence == 0
    assert first.base_hash == second.base_hash == GENESIS_HASH
    assert connection.heads[target.stream_key]["last_sequence"] == 0
    assert sum("INSERT INTO agent_cells" in query for query, _ in connection.calls) == 2

    child = target.with_branch("review")
    child_branch = EventBranch(
        tenant_id=child.tenant_id,
        app_id=child.app_id,
        cell_id=child.cell_id,
        session_id=child.session_id,
        capsule_digest=child.capsule_digest,
        branch_id=child.branch_id,
        parent_branch_id="main",
        parent_capsule_digest=target.capsule_digest,
        fork_sequence=0,
        base_hash=GENESIS_HASH,
    )
    returned = await store.ensure_cell(child, branch=child_branch, assigned_node_id="node-1")
    assert returned == child_branch
    assert connection.cells[child.stream_key]["parent_branch_id"] == "main"


@pytest.mark.asyncio
async def test_ensure_cell_rejects_invalid_fence_and_namespace_inputs() -> None:
    store, connection = make_store()
    target = address()
    mismatched = address(cell="cell-other")
    metadata = EventBranch(
        tenant_id=mismatched.tenant_id,
        app_id=mismatched.app_id,
        cell_id=mismatched.cell_id,
        session_id=mismatched.session_id,
        capsule_digest=mismatched.capsule_digest,
        branch_id=mismatched.branch_id,
        parent_branch_id=None,
        fork_sequence=0,
        base_hash=GENESIS_HASH,
    )
    with pytest.raises(NamespaceViolation, match="metadata"):
        await store.ensure_cell(target, branch=metadata)
    with pytest.raises(ValueError, match="supplied together"):
        await store.ensure_cell(target, session_lease_owner="gateway-a")
    with pytest.raises(ValueError, match="positive integer"):
        await store.ensure_cell(target, session_fencing_token=0, session_lease_owner="gateway-a")
    with pytest.raises(ValueError, match="positive integer"):
        await store.ensure_cell(target, session_fencing_token=True, session_lease_owner="gateway-a")

    connection.session_fence_result = None
    with pytest.raises(FencedLeaseError, match="session lease"):
        await store.ensure_cell(target, session_lease_owner="gateway-a", session_fencing_token=3)

    connection.return_missing_cell = True
    with pytest.raises(EventStoreError, match="not returned"):
        await store.ensure_cell(target)


@pytest.mark.asyncio
async def test_ensure_cell_detects_immutable_parent_metadata() -> None:
    store, _ = make_store()
    target = address()
    await ensure_root(store, target)
    conflicting = EventBranch(
        tenant_id=target.tenant_id,
        app_id=target.app_id,
        cell_id=target.cell_id,
        session_id=target.session_id,
        capsule_digest=target.capsule_digest,
        branch_id=target.branch_id,
        parent_branch_id="parent",
        parent_capsule_digest=target.capsule_digest,
        fork_sequence=1,
        base_hash="f" * 64,
    )
    with pytest.raises(NamespaceViolation, match="immutable"):
        await store.ensure_cell(target, branch=conflicting)


@pytest.mark.asyncio
async def test_append_uses_head_cas_and_returns_the_materialized_event() -> None:
    store, connection = make_store()
    target = address()
    await ensure_root(store, target)

    first = await store.append(
        draft(target, event_id="event-1"),
        expected_sequence=0,
        expected_prev_hash=GENESIS_HASH,
    )
    second = await store.append(
        draft(
            target,
            event_id="event-2",
            causation_id=first.event_id,
            payload={"text": "follow-up"},
        ),
        expected_sequence=1,
        expected_prev_hash=first.event_hash,
    )

    assert (first.sequence, second.sequence) == (1, 2)
    assert second.prev_hash == first.event_hash
    assert connection.heads[target.stream_key]["last_sequence"] == 2
    assert len(await store.read(target)) == 2
    head_lock_calls = [
        (query, args) for query, args in connection.calls if "lock_cell_branch_head" in query
    ]
    assert head_lock_calls
    assert head_lock_calls[0][1] == (
        target.tenant_id,
        target.app_id,
        target.cell_id,
        target.session_id,
        target.capsule_digest,
        target.branch_id,
    )

    with pytest.raises(CompareAndSwapConflict, match="expected sequence"):
        await store.append(draft(target, event_id="stale-sequence"), expected_sequence=0)
    with pytest.raises(CompareAndSwapConflict, match="previous hash"):
        await store.append(draft(target, event_id="stale-hash"), expected_prev_hash="0" * 64)


@pytest.mark.asyncio
async def test_append_supports_keyword_drafts_and_validates_branch_lease_arguments() -> None:
    store, _ = make_store()
    target = address()
    await ensure_root(store, target)

    with pytest.raises(TypeError, match="either a draft"):
        await store.append(draft(target), event_type="message.accepted")
    with pytest.raises(ValueError, match="supplied together"):
        await store.append(draft(target, event_id="owner-without-epoch"), lease_owner="worker-a")
    with pytest.raises(ValueError, match="supplied together"):
        await store.append(draft(target, event_id="epoch-without-owner"), lease_epoch=1)
    with pytest.raises(ValueError, match="positive integer"):
        await store.append(
            draft(target, event_id="zero-epoch"), lease_owner="worker-a", lease_epoch=0
        )
    with pytest.raises(ValueError, match="positive integer"):
        await store.append(
            draft(target, event_id="bool-epoch"), lease_owner="worker-a", lease_epoch=True
        )

    keyword_event = await store.append(
        tenant_id=target.tenant_id,
        app_id=target.app_id,
        cell_id=target.cell_id,
        session_id=target.session_id,
        capsule_digest=target.capsule_digest,
        branch_id=target.branch_id,
        event_type="message.accepted",
        payload={"text": "keyword"},
        event_id="keyword-event",
        correlation_id="corr-keyword",
        trace_id="trace-keyword",
        request_id="request-keyword",
        occurred_at=NOW,
    )
    assert keyword_event.event_id == "keyword-event"


@pytest.mark.asyncio
async def test_append_rejects_missing_branch_head_and_allows_generated_event_id() -> None:
    store, _ = make_store()
    target = address()
    with pytest.raises(BranchNotFound, match="no branch head"):
        await store.append(draft(target, event_id="without-head"))

    await ensure_root(store, target)
    generated = await store.append(draft(target))
    assert generated.event_id
    assert generated.sequence == 1


@pytest.mark.asyncio
async def test_append_checks_branch_and_session_leases_before_mutation() -> None:
    store, connection = make_store()
    target = address()
    await ensure_root(store, target)

    head = connection.heads[target.stream_key]
    head.update(
        {
            "lease_owner": "worker-a",
            "lease_epoch": 4,
            "lease_expires_at": NOW + timedelta(minutes=1),
        }
    )
    with pytest.raises(FencedLeaseError, match="epoch"):
        await store.append(
            draft(target, event_id="bad-epoch"), lease_epoch=3, lease_owner="worker-a"
        )
    with pytest.raises(FencedLeaseError, match="owner"):
        await store.append(
            draft(target, event_id="bad-owner"), lease_epoch=4, lease_owner="worker-b"
        )

    head["lease_expires_at"] = NOW - timedelta(seconds=1)
    head["lease_valid"] = False
    with pytest.raises(FencedLeaseError, match="expired"):
        await store.append(draft(target, event_id="expired"), lease_epoch=4, lease_owner="worker-a")

    connection.session_fence_result = None
    with pytest.raises(FencedLeaseError, match="session lease"):
        await store.append(
            draft(target, event_id="bad-session-fence"),
            session_lease_owner="gateway-a",
            session_fencing_token=2,
        )
    with pytest.raises(ValueError, match="supplied together"):
        await store.append(draft(target, event_id="bad-pair"), session_lease_owner="gateway-a")
    with pytest.raises(ValueError, match="positive integer"):
        await store.append(
            draft(target, event_id="bad-token"),
            session_lease_owner="gateway-a",
            session_fencing_token=True,
        )

    connection.session_fence_result = 1
    appended = await store.append(
        draft(target, event_id="valid-session-fence"),
        session_lease_owner="gateway-a",
        session_fencing_token=2,
    )
    assert appended.event_id == "valid-session-fence"
    assert any(
        "app.cell_session_lease_owner" in query and args == ("gateway-a", "2")
        for query, args in connection.calls
    )


@pytest.mark.asyncio
async def test_append_branch_fence_allows_initialization_and_only_monotonic_takeover() -> None:
    store, connection = make_store()
    target = address()
    await ensure_root(store, target)
    expiry = NOW + timedelta(minutes=1)

    # A new/forked head is the explicit NULL/0/NULL initialization state.
    first = await store.append(
        draft(target, event_id="initialised"),
        lease_owner="worker-a",
        lease_epoch=4,
        lease_expires_at=expiry,
    )
    assert first.event_id == "initialised"

    head = connection.heads[target.stream_key]
    head.update(
        {
            "lease_owner": "worker-a",
            "lease_epoch": 4,
            "lease_expires_at": expiry,
            "lease_valid": True,
        }
    )
    # A newer epoch may take over after the database session fence has moved.
    second = await store.append(
        draft(target, event_id="takeover"),
        lease_owner="worker-b",
        lease_epoch=5,
        lease_expires_at=expiry,
    )
    assert second.event_id == "takeover"

    head.update({"lease_owner": "worker-b", "lease_epoch": 5, "lease_valid": True})
    with pytest.raises(FencedLeaseError, match="epoch"):
        await store.append(
            draft(target, event_id="downgrade"),
            lease_owner="worker-a",
            lease_epoch=4,
            lease_expires_at=expiry,
        )
    with pytest.raises(FencedLeaseError, match="owner"):
        await store.append(
            draft(target, event_id="same-epoch-other-owner"),
            lease_owner="worker-c",
            lease_epoch=5,
            lease_expires_at=expiry,
        )


@pytest.mark.asyncio
async def test_append_event_id_is_namespace_scoped_and_immutable() -> None:
    store, connection = make_store()
    target = address()
    await ensure_root(store, target)
    original = await store.append(draft(target, event_id="same-id"))

    assert await store.append(draft(target, event_id="same-id")) == original
    with pytest.raises(AppendOnlyViolation, match="immutable"):
        await store.append(draft(target, event_id="same-id", payload={"text": "tampered"}))

    other = address(session="session-other")
    await ensure_root(store, other)
    with pytest.raises(NamespaceViolation, match="another Cell"):
        await store.append(draft(other, event_id="same-id"))

    # The INSERT conflict path is distinct from the preflight idempotency
    # lookup and must return the same immutable event when the race winner
    # wrote equivalent content.
    raced = draft(target, event_id="raced", payload={"text": "race"}).normalised()
    race_event = InMemoryEventStore._build_event(
        raced,
        sequence=2,
        prev_hash=original.event_hash,
    )
    race_row = race_event.to_dict()
    race_row["app_id"] = target.app_id
    connection.events[(target.tenant_id, race_event.event_id)] = race_row
    connection.return_missing_inserted_event = True
    assert await store.append(raced, expected_sequence=1) == race_event


@pytest.mark.asyncio
async def test_append_race_rechecks_namespace_and_immutable_payload() -> None:
    store, connection = make_store()
    target = address()
    await ensure_root(store, target)

    foreign = seed_row_event(
        connection,
        address(session="race-foreign"),
        sequence=1,
        event_id="race-foreign-id",
    )
    connection.skip_event_preflight_once = True
    connection.return_missing_inserted_event = True
    with pytest.raises(NamespaceViolation, match="another Cell"):
        await store.append(draft(target, event_id=foreign.event_id))

    immutable = seed_row_event(
        connection,
        target,
        sequence=1,
        event_id="race-immutable-id",
        payload={"text": "persisted"},
    )
    connection.skip_event_preflight_once = True
    with pytest.raises(AppendOnlyViolation, match="immutable"):
        await store.append(
            draft(target, event_id=immutable.event_id, payload={"text": "different"})
        )


@pytest.mark.asyncio
async def test_append_handles_concurrent_conflict_and_known_cross_branch_causation() -> None:
    store, connection = make_store()
    target = address()
    await ensure_root(store, target)
    connection.return_missing_inserted_event = True
    with pytest.raises(CompareAndSwapConflict, match="concurrently"):
        await store.append(draft(target, event_id="no-race-row"))

    # A known same-tenant cause outside the target lineage is rejected, while
    # an unknown forward reference remains compatible with the event contract.
    foreign = address(session="foreign-session")
    await ensure_root(store, foreign)
    foreign_event = seed_row_event(connection, foreign, sequence=1, event_id="foreign-cause")
    connection.return_missing_inserted_event = False
    with pytest.raises(NamespaceViolation, match="crosses"):
        await store.append(draft(target, event_id="crossed", causation_id=foreign_event.event_id))
    accepted = await store.append(draft(target, event_id="forward", causation_id="future-event"))
    assert accepted.causation_id == "future-event"


@pytest.mark.asyncio
async def test_lineage_read_supports_forks_and_sequence_windows() -> None:
    store, connection = make_store()
    root = address()
    await ensure_root(store, root)
    first = await store.append(draft(root, event_id="root-1"))
    second = await store.append(draft(root, event_id="root-2", payload={"text": "two"}))
    connection.capsules.add((root.tenant_id, root.capsule_digest))

    fork = await store.fork(root, 1, new_branch_id="review")
    child = root.with_branch("review")
    child_event = await store.append(draft(child, event_id="child-1", payload={"text": "branch"}))

    assert fork.parent_branch_id == "main"
    assert [event.event_id for event in await store.read(child)] == [
        first.event_id,
        child_event.event_id,
    ]
    assert [event.event_id for event in await store.read(root, from_sequence=2)] == [
        second.event_id
    ]
    assert [event.event_id for event in await store.read(child, to_sequence=1)] == [first.event_id]
    assert await store.head(child) == child_event
    stored_branch = await store.get_branch(child)
    assert stored_branch.address == fork.address
    assert stored_branch.parent_address == fork.parent_address
    assert stored_branch.fork_sequence == fork.fork_sequence
    assert stored_branch.base_hash == fork.base_hash
    assert {item.branch_id for item in await store.branches(root)} == {"main", "review"}
    assert any("lock_cell_branch_head" in query for query, _ in connection.calls)
    assert not any(
        "FROM agent_cells" in query and "FOR UPDATE" in query for query, _ in connection.calls
    )

    with pytest.raises(ValueError, match="from_sequence"):
        await store.read(root, from_sequence=0)
    with pytest.raises(ValueError, match="to_sequence"):
        await store.read(root, from_sequence=2, to_sequence=1)


@pytest.mark.asyncio
async def test_causal_append_decodes_asyncpg_jsonb_text_rows() -> None:
    store, connection = make_store()
    target = address()
    await ensure_root(store, target)
    first = await store.append(draft(target, event_id="jsonb-first", payload={"step": 1}))

    # asyncpg's default json/jsonb codec returns text.  Preserve that real
    # driver boundary in the fake before the next append reads its cause.
    stored = connection.events[(target.tenant_id, first.event_id)]
    stored["payload"] = json.dumps(stored["payload"], sort_keys=True)

    second = await store.append(
        draft(
            target,
            event_id="jsonb-second",
            payload={"step": 2},
            causation_id=first.event_id,
        )
    )

    assert second.causation_id == first.event_id
    assert [event.payload for event in await store.read(target)] == [
        {"step": 1},
        {"step": 2},
    ]


@pytest.mark.asyncio
async def test_fork_rejects_invalid_parent_target_and_duplicate_requests() -> None:
    store, connection = make_store()
    root = address()
    await ensure_root(store, root)
    await store.append(draft(root, event_id="root-1"))

    with pytest.raises(InvalidBranch, match="non-empty"):
        await store.fork(root, 0, new_branch_id=" ")
    with pytest.raises(InvalidBranch, match="negative"):
        await store.fork(root, -1, new_branch_id="bad")
    with pytest.raises(InvalidBranch, match="target_capsule"):
        await store.fork(root, 0, new_branch_id="bad", target_capsule_digest=" ")
    with pytest.raises(InvalidBranch, match="beyond"):
        await store.fork(root, 2, new_branch_id="too-far")

    connection.capsules.add((root.tenant_id, root.capsule_digest))
    await store.fork(root, 0, new_branch_id="already")
    with pytest.raises(InvalidBranch, match="already exists"):
        await store.fork(root, 0, new_branch_id="already")
    with pytest.raises(InvalidBranch, match="registered"):
        await store.fork(
            root, 0, new_branch_id="missing-capsule", target_capsule_digest=OTHER_DIGEST
        )
    with pytest.raises(BranchNotFound):
        await store.fork(root.with_branch("missing"), 0, new_branch_id="child")


@pytest.mark.asyncio
async def test_verify_chain_accepts_valid_root_and_child_lineage() -> None:
    store, connection = make_store()
    root = address()
    await ensure_root(store, root)
    first = await store.append(draft(root, event_id="verify-1"))
    await store.append(draft(root, event_id="verify-2", causation_id=first.event_id))
    await store.verify_chain(root)

    connection.capsules.add((root.tenant_id, root.capsule_digest))
    child = await store.fork(root, 1, new_branch_id="verify-child")
    child_address = root.with_branch("verify-child")
    await store.append(draft(child_address, event_id="verify-child-1"))
    await store.verify_chain(child_address)
    assert child.base_hash == first.event_hash


@pytest.mark.asyncio
async def test_verify_chain_reports_namespace_sequence_and_hash_corruption() -> None:
    store, connection = make_store()
    target = address()
    await ensure_root(store, target)
    await store.append(draft(target, event_id="corrupt-1"))
    await store.append(draft(target, event_id="corrupt-2"))

    wrong_namespace = seed_row_event(
        connection,
        address(cell="other-cell"),
        sequence=1,
        event_id="wrong-namespace",
    )
    wrong_row = connection.events[(target.tenant_id, wrong_namespace.event_id)]
    connection.lineage_override = [wrong_row]
    with pytest.raises(NamespaceViolation, match="Cell/session"):
        await store.verify_chain(target)
    connection.lineage_override = None

    wrong_app = seed_row_event(
        connection,
        address(app="other-app"),
        sequence=1,
        event_id="wrong-app",
    )
    connection.lineage_override = [connection.events[(target.tenant_id, wrong_app.event_id)]]
    with pytest.raises(NamespaceViolation, match="tenant/app"):
        await store.verify_chain(target)
    connection.lineage_override = None

    sequence_one = seed_row_event(connection, target, sequence=1, event_id="sequence-one")
    sequence_three = seed_row_event(
        connection,
        target,
        sequence=3,
        event_id="sequence-three",
        prev_hash=sequence_one.event_hash,
    )
    connection.lineage_override = [
        connection.events[(target.tenant_id, sequence_one.event_id)],
        connection.events[(target.tenant_id, sequence_three.event_id)],
    ]
    with pytest.raises(ChainIntegrityError, match="contiguous"):
        await store.verify_chain(target)
    sequence_two_bad = seed_row_event(
        connection,
        target,
        sequence=2,
        event_id="sequence-two-bad",
        prev_hash="f" * 64,
    )
    connection.lineage_override = [
        connection.events[(target.tenant_id, sequence_one.event_id)],
        connection.events[(target.tenant_id, sequence_two_bad.event_id)],
    ]
    with pytest.raises(ChainIntegrityError, match="link"):
        await store.verify_chain(target)
    connection.lineage_override = None

    # Root metadata must retain the genesis anchor.
    connection.lineage_override = [
        connection.events[(target.tenant_id, "corrupt-1")],
        connection.events[(target.tenant_id, "corrupt-2")],
    ]
    connection.cells[target.stream_key]["state_hash"] = "f" * 64
    with pytest.raises(ChainIntegrityError, match="genesis"):
        await store.verify_chain(target)


@pytest.mark.asyncio
async def test_verify_chain_rejects_invalid_child_fork_anchor() -> None:
    store, connection = make_store()
    root = address()
    await ensure_root(store, root)
    await store.append(draft(root, event_id="anchor-source"))
    child = root.with_branch("corrupt-child")
    connection.cells[child.stream_key] = {
        "tenant_id": child.tenant_id,
        "app_id": child.app_id,
        "cell_id": child.cell_id,
        "session_id": child.session_id,
        "capsule_digest": child.capsule_digest,
        "branch_id": child.branch_id,
        "parent_branch_id": root.branch_id,
        "parent_capsule_digest": root.capsule_digest,
        "fork_sequence": 2,
        "state_hash": GENESIS_HASH,
        "created_at": NOW,
    }
    with pytest.raises(ChainIntegrityError, match="outside"):
        await store.verify_chain(child)

    connection.cells[child.stream_key]["fork_sequence"] = 1
    connection.cells[child.stream_key]["state_hash"] = "f" * 64
    with pytest.raises(ChainIntegrityError, match="base hash"):
        await store.verify_chain(child)


@pytest.mark.asyncio
async def test_verify_chain_handles_corrupt_parent_metadata() -> None:
    from unittest.mock import AsyncMock

    store, connection = make_store()
    target = address()
    await ensure_root(store, target)

    class BrokenBranch:
        parent_branch_id = "parent"
        fork_sequence = 0
        base_hash = GENESIS_HASH
        parent_address = None

    store._get_branch = AsyncMock(return_value=BrokenBranch())  # type: ignore[method-assign]
    with pytest.raises(ChainIntegrityError, match="incomplete"):
        await store.verify_chain(target)
    assert connection.calls


@pytest.mark.asyncio
async def test_lineage_cycle_and_depth_guards_fail_closed() -> None:
    store, connection = make_store()
    target = address()
    await ensure_root(store, target)
    root_row = connection.cells[target.stream_key]
    root_row.update(
        {
            "parent_branch_id": "main",
            "parent_capsule_digest": target.capsule_digest,
            "fork_sequence": 1,
        }
    )
    with pytest.raises(NamespaceViolation, match="cycle"):
        await store.read(target)

    # Build a deliberately deep but acyclic parent chain.  The adapter caps
    # recursion so malformed database metadata cannot exhaust the worker.
    connection.cells.clear()
    connection.heads.clear()
    previous = "branch-0"
    for index in range(129):
        branch_id = f"branch-{index}"
        target_branch = target.with_branch(branch_id)
        connection.cells[target_branch.stream_key] = {
            "tenant_id": target.tenant_id,
            "app_id": target.app_id,
            "cell_id": target.cell_id,
            "session_id": target.session_id,
            "capsule_digest": target.capsule_digest,
            "branch_id": branch_id,
            "parent_branch_id": None if index == 0 else previous,
            "parent_capsule_digest": target.capsule_digest,
            "fork_sequence": 0 if index == 0 else 1,
            "state_hash": GENESIS_HASH,
            "created_at": NOW,
        }
        previous = branch_id
    deep = target.with_branch("branch-128")
    with pytest.raises(EventStoreError, match="maximum depth"):
        await store.read(deep)


@pytest.mark.asyncio
async def test_event_store_lookup_helpers_are_tenant_scoped() -> None:
    store, connection = make_store()
    target = address()
    await ensure_root(store, target)
    event = await store.append(
        draft(target, event_id="correlation-event", correlation_id="correlation-a")
    )
    found = await store.find_latest_by_correlation(
        target.tenant_id,
        "correlation-a",
        event_type="message.accepted",
    )
    assert found == event
    assert (
        await store.find_latest_by_correlation("tenant-b", "correlation-a", event_type="x") is None
    )
    assert await store.find_unprojected_terminal_effects(target.tenant_id, "none") == ()
    with pytest.raises(ValueError, match="tenant"):
        await store.find_latest_by_correlation("", "correlation-a", event_type="x")
    with pytest.raises(ValueError, match="tenant"):
        await store.find_unprojected_terminal_effects("", "correlation-a")
    assert any("ORDER BY occurred_at" in query for query, _ in connection.calls)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (DIGEST, True),
        ("sha256:" + "A" * 64, False),
        ("sha256:" + "a" * 63, False),
        ("md5:" + "a" * 64, False),
    ],
)
def test_digest_shape_is_enforced_before_database_work(value: str, expected: bool) -> None:
    from trpc_service.cell.postgres import _is_digest

    assert _is_digest(value) is expected


def test_event_row_hydration_normalises_naive_timestamps() -> None:
    from trpc_service.cell.postgres import _event_from_row

    target = address()
    normalised = draft(target, event_id="naive-row").normalised()
    event = InMemoryEventStore._build_event(
        normalised,
        sequence=1,
        prev_hash=GENESIS_HASH,
    )
    row = event.to_dict()
    row["occurred_at"] = event.occurred_at.replace(tzinfo=None)
    assert _event_from_row(row).occurred_at.tzinfo == UTC
