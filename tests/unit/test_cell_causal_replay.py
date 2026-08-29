from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import cast

import pytest

from trpc_service.cell import events as event_module
from trpc_service.cell.events import (
    GENESIS_HASH,
    AppendOnlyViolation,
    BranchNotFound,
    BranchView,
    CausalEvent,
    CellAddress,
    ChainIntegrityError,
    EventDraft,
    EventType,
    InMemoryEventStore,
    InvalidBranch,
    NamespaceViolation,
)
from trpc_service.cell.replay import (
    DeterminismViolation,
    ProjectionReplayer,
    replay_projection,
    state_fingerprint,
)


def address(tenant_id: str = "tenant-a", *, branch_id: str = "main") -> CellAddress:
    return CellAddress(
        tenant_id=tenant_id,
        cell_id="cell-customer-service",
        session_id="session-001",
        capsule_digest="sha256:capsule-v1",
        branch_id=branch_id,
    )


def append_message(
    store: InMemoryEventStore,
    stream: CellAddress,
    sequence_hint: int,
    *,
    value: int | None = None,
) -> CausalEvent:
    return store.append(
        EventDraft(
            tenant_id=stream.tenant_id,
            cell_id=stream.cell_id,
            session_id=stream.session_id,
            capsule_digest=stream.capsule_digest,
            branch_id=stream.branch_id,
            event_type=EventType.MESSAGE_ACCEPTED,
            payload={"delta": value if value is not None else sequence_hint},
            event_id=f"event-{stream.branch_id}-{sequence_hint}",
            causation_id=f"cause-{sequence_hint}",
            correlation_id="corr-001",
            trace_id="trace-001",
            request_id=f"request-{sequence_hint}",
            occurred_at=datetime(2026, 1, 1, 0, 0, sequence_hint, tzinfo=UTC),
        )
    )


def test_append_assigns_ordered_typed_metadata_and_hash_chain() -> None:
    store = InMemoryEventStore()
    stream = address()
    first = store.append(
        tenant_id=stream.tenant_id,
        cell_id=stream.cell_id,
        session_id=stream.session_id,
        capsule_digest=stream.capsule_digest,
        branch_id=stream.branch_id,
        event_type="message.accepted",
        payload={"message": "hello", "attributes": {"lang": "zh"}},
        correlation_id="corr-001",
        trace_id="trace-001",
        request_id="request-001",
    )
    second = store.append(
        EventDraft(
            tenant_id=stream.tenant_id,
            cell_id=stream.cell_id,
            session_id=stream.session_id,
            capsule_digest=stream.capsule_digest,
            event_type="memory.fact.appended",
            payload={"fact": "customer prefers Chinese"},
            causation_id=first.event_id,
            correlation_id=first.correlation_id,
            trace_id=first.trace_id,
            request_id=first.request_id,
        )
    )

    assert first.sequence == 1
    assert first.prev_hash == GENESIS_HASH
    assert first.payload_hash == first.recompute_payload_hash()
    assert first.event_hash == first.recompute_event_hash()
    assert second.sequence == 2
    assert second.prev_hash == first.event_hash
    assert second.causation_id == first.event_id
    assert second.address == stream
    store.verify_chain(stream)

    # Canonical JSON makes insertion order irrelevant to the payload digest.
    equivalent = store.append(
        tenant_id=stream.tenant_id,
        cell_id=stream.cell_id,
        session_id=stream.session_id,
        capsule_digest=stream.capsule_digest,
        event_type="message.accepted",
        payload={"x": 1, "y": {"a": True, "b": 2}},
        event_id="canonical-event",
        correlation_id="corr-canonical",
        trace_id="trace-canonical",
        request_id="request-canonical",
    )
    equivalent_reordered = store.append(
        tenant_id=stream.tenant_id,
        cell_id=stream.cell_id,
        session_id=stream.session_id,
        capsule_digest=stream.capsule_digest,
        event_type="message.accepted",
        payload={"y": {"b": 2, "a": True}, "x": 1},
        event_id="canonical-event-2",
        correlation_id="corr-canonical",
        trace_id="trace-canonical",
        request_id="request-canonical",
    )
    assert equivalent.payload_hash == equivalent_reordered.payload_hash


def test_event_id_is_idempotent_but_cannot_replace_immutable_content() -> None:
    store = InMemoryEventStore()
    stream = address()
    draft = EventDraft(
        tenant_id=stream.tenant_id,
        cell_id=stream.cell_id,
        session_id=stream.session_id,
        capsule_digest=stream.capsule_digest,
        event_type="reply.prepared",
        payload={"text": "done"},
        event_id="idempotency-key-1",
        correlation_id="corr-1",
        trace_id="trace-1",
        request_id="request-1",
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    first = store.append(draft)
    assert store.append(draft) == first
    with pytest.raises(AppendOnlyViolation):
        store.append(
            EventDraft(
                tenant_id=stream.tenant_id,
                cell_id=stream.cell_id,
                session_id=stream.session_id,
                capsule_digest=stream.capsule_digest,
                event_type="reply.prepared",
                payload={"text": "changed"},
                event_id=draft.event_id,
                correlation_id="corr-1",
                trace_id="trace-1",
                request_id="request-1",
                occurred_at=draft.occurred_at,
            )
        )


def test_hash_chain_detects_payload_tampering() -> None:
    store = InMemoryEventStore()
    stream = address()
    event = store.append(
        tenant_id=stream.tenant_id,
        cell_id=stream.cell_id,
        session_id=stream.session_id,
        capsule_digest=stream.capsule_digest,
        event_type="message.accepted",
        payload={"text": "original"},
    )
    # The record is frozen, but a nested dict supplied by an in-memory test
    # can still be mutated.  Verification must catch that representation.
    event.payload["text"] = "tampered"
    with pytest.raises(ChainIntegrityError, match="payload hash mismatch"):
        store.verify_chain(stream)


def test_branch_is_a_hash_anchored_lineage_and_replays_parent_prefix() -> None:
    store = InMemoryEventStore()
    main = address()
    append_message(store, main, 1, value=1)
    append_message(store, main, 2, value=2)
    append_message(store, main, 3, value=3)

    branch = store.fork(main, 2, new_branch_id="shadow")
    shadow = main.with_branch("shadow")
    assert branch.parent_branch_id == "main"
    assert branch.fork_sequence == 2
    assert branch.base_hash == store.read(main)[1].event_hash

    child = append_message(store, shadow, 3, value=100)
    assert child.sequence == 3
    visible = store.read(shadow)
    assert [event.sequence for event in visible] == [1, 2, 3]
    assert [event.branch_id for event in visible] == ["main", "main", "shadow"]
    assert visible[-1].prev_hash == visible[1].event_hash
    store.verify_chain(shadow)

    def reducer(state: dict[str, int], event) -> dict[str, int]:
        updated = dict(state)
        updated["total"] += int(event.payload["delta"])
        updated["events"] += 1
        return updated

    result = replay_projection(store, shadow, reducer, initial_state={"total": 0, "events": 0})
    assert result.state == {"total": 103, "events": 3}
    assert result.last_sequence == 3
    assert result.last_event_hash == visible[-1].event_hash


def test_branch_can_switch_capsule_without_crossing_tenant_or_cell_scope() -> None:
    store = InMemoryEventStore()
    source = address()
    append_message(store, source, 1, value=11)
    append_message(store, source, 2, value=12)

    candidate = store.fork(
        source,
        2,
        new_branch_id="candidate-capsule",
        target_capsule_digest="sha256:capsule-v2",
    )
    target = CellAddress(
        tenant_id=source.tenant_id,
        cell_id=source.cell_id,
        session_id=source.session_id,
        capsule_digest="sha256:capsule-v2",
        branch_id="candidate-capsule",
    )
    assert candidate.capsule_digest == "sha256:capsule-v2"
    assert candidate.parent_capsule_digest == source.capsule_digest
    child = append_message(store, target, 3, value=99)
    assert child.capsule_digest == "sha256:capsule-v2"
    assert [event.payload["delta"] for event in store.read(target)] == [11, 12, 99]
    store.verify_chain(target)

    def reducer(state: list[int], event) -> list[int]:
        return [*state, int(event.payload["delta"])]

    result = ProjectionReplayer(store).replay(target, reducer, initial_state=[])
    assert result.state == [11, 12, 99]

    with pytest.raises(NamespaceViolation):
        store.append(
            tenant_id="tenant-b",
            cell_id=source.cell_id,
            session_id=source.session_id,
            capsule_digest="sha256:capsule-v2",
            branch_id="candidate-capsule",
            event_type="message.accepted",
            payload={"delta": 1000},
            event_id=child.event_id,
        )


def test_branch_from_genesis_and_nested_branch_are_supported() -> None:
    store = InMemoryEventStore()
    main = address()
    append_message(store, main, 1, value=10)
    genesis = store.fork(main, 0, new_branch_id="experiment")
    experiment = main.with_branch("experiment")
    event = append_message(store, experiment, 1, value=7)
    assert genesis.base_hash == GENESIS_HASH
    assert event.sequence == 1
    assert store.read(experiment)[0].branch_id == "experiment"

    store.fork(experiment, 1, new_branch_id="experiment-2")
    nested_address = main.with_branch("experiment-2")
    append_message(store, nested_address, 2, value=8)
    assert [event.payload["delta"] for event in store.read(nested_address)] == [7, 8]
    store.verify_chain(nested_address)

    with pytest.raises(InvalidBranch):
        store.fork(main, 99, new_branch_id="invalid")


def test_streams_are_isolated_by_tenant_and_cell_scope() -> None:
    store = InMemoryEventStore()
    tenant_a = address("tenant-a")
    tenant_b = address("tenant-b")
    store.append(
        tenant_id=tenant_a.tenant_id,
        cell_id=tenant_a.cell_id,
        session_id=tenant_a.session_id,
        capsule_digest=tenant_a.capsule_digest,
        event_type="message.accepted",
        payload={"tenant": "a"},
        event_id="shared-event-id",
    )
    assert store.read(tenant_b) == ()
    with pytest.raises(NamespaceViolation):
        store.append(
            tenant_id=tenant_b.tenant_id,
            cell_id=tenant_b.cell_id,
            session_id=tenant_b.session_id,
            capsule_digest=tenant_b.capsule_digest,
            event_type="message.accepted",
            payload={"tenant": "b"},
            event_id="shared-event-id",
        )

    other_cell = CellAddress(
        tenant_id="tenant-a",
        cell_id="another-cell",
        session_id=tenant_a.session_id,
        capsule_digest=tenant_a.capsule_digest,
    )
    assert store.read(other_cell) == ()


def test_projection_replay_is_deterministic_and_supports_checkpointed_ranges() -> None:
    store = InMemoryEventStore()
    stream = address()
    for index in range(1, 4):
        append_message(store, stream, index, value=index)

    def reducer(state: list[int], event) -> list[int]:
        return [*state, int(event.payload["delta"])]

    replayer = ProjectionReplayer(store)
    result = replayer.assert_deterministic(stream, reducer, initial_state=[])
    assert result.state == [1, 2, 3]
    assert result.state_hash == state_fingerprint([1, 2, 3])

    checkpoint = replayer.replay_at(stream, 1, reducer, initial_state=[])
    tail = replayer.replay(
        stream,
        reducer,
        initial_state=checkpoint.state,
        from_sequence=2,
    )
    assert tail.state == [1, 2, 3]
    assert tail.first_sequence == 2

    def nondeterministic(state: list[int], event) -> list[int]:
        return [*state, id(event)]

    with pytest.raises(DeterminismViolation):
        replayer.assert_deterministic(stream, nondeterministic, initial_state=[])


@pytest.mark.asyncio
async def test_async_adapters_are_usable_by_service_code() -> None:
    store = InMemoryEventStore()
    stream = address()
    event = await store.append_async(
        tenant_id=stream.tenant_id,
        cell_id=stream.cell_id,
        session_id=stream.session_id,
        capsule_digest=stream.capsule_digest,
        event_type="message.accepted",
        payload={"text": "async"},
    )
    assert (await store.read_async(stream))[0] == event
    await store.verify_chain_async(stream)
    branch = await store.fork_async(stream, 1, new_branch_id="async-shadow")
    assert branch.parent_branch_id == "main"


@dataclass
class CounterProjection:
    def initial_state(self) -> dict[str, int]:
        return {"count": 0}

    def apply(self, state: dict[str, int], event) -> dict[str, int]:
        state["count"] += int(event.payload.get("delta", 1))
        return state


def test_projection_object_can_supply_initial_state() -> None:
    store = InMemoryEventStore()
    stream = address()
    append_message(store, stream, 1, value=5)
    result = ProjectionReplayer(store).replay(stream, CounterProjection())
    assert result.state == {"count": 5}


def test_identifier_json_and_timestamp_validation() -> None:
    with pytest.raises(ValueError, match="tenant_id"):
        CellAddress("", "cell", "session", "capsule")
    with pytest.raises(ValueError, match="branch_id"):
        CellAddress("tenant", "cell", "session", "capsule", "")

    stream = address()
    draft_fields = {
        "tenant_id": stream.tenant_id,
        "cell_id": stream.cell_id,
        "session_id": stream.session_id,
        "capsule_digest": stream.capsule_digest,
        "event_type": "message.accepted",
    }
    with pytest.raises(ValueError, match="event_type"):
        EventDraft(**{**draft_fields, "event_type": ""}).normalised()
    with pytest.raises(ValueError, match="event_id"):
        EventDraft(**{**draft_fields, "event_id": ""}).normalised()
    with pytest.raises(ValueError, match="causation_id"):
        EventDraft(**{**draft_fields, "causation_id": ""}).normalised()
    with pytest.raises(ValueError, match="correlation_id"):
        EventDraft(**{**draft_fields, "correlation_id": ""}).normalised()
    with pytest.raises(ValueError, match="trace_id"):
        EventDraft(**{**draft_fields, "trace_id": ""}).normalised()
    with pytest.raises(ValueError, match="request_id"):
        EventDraft(**{**draft_fields, "request_id": ""}).normalised()
    with pytest.raises(ValueError, match="timezone-aware"):
        EventDraft(**{**draft_fields, "occurred_at": datetime(2026, 1, 1)}).normalised()

    store = InMemoryEventStore()
    common = {**draft_fields, "payload": {"valid": True}}
    with pytest.raises(TypeError, match="non-finite"):
        store.append(EventDraft(**{**common, "payload": {"n": float("inf")}}))
    with pytest.raises(TypeError, match="keys must be strings"):
        store.append(EventDraft(**{**common, "payload": cast(object, {1: "bad"})}))
    with pytest.raises(TypeError, match="unsupported"):
        store.append(EventDraft(**{**common, "payload": {"object": object()}}))
    with pytest.raises(TypeError, match="JSON object"):
        store.append(EventDraft(**{**common, "payload": cast(object, ["not", "object"])}))
    event = store.append(EventDraft(**{**common, "payload": {"items": (1, 2, 3)}}))
    assert event.payload == {"items": [1, 2, 3]}


def test_event_serialisation_and_integrity_failure_modes() -> None:
    store = InMemoryEventStore()
    stream = address()
    event = store.append(
        tenant_id=stream.tenant_id,
        cell_id=stream.cell_id,
        session_id=stream.session_id,
        capsule_digest=stream.capsule_digest,
        event_type="message.accepted",
        payload={"text": "round-trip"},
        event_id="serialised-event",
        correlation_id="corr",
        trace_id="trace",
        request_id="request",
        occurred_at=datetime(2026, 2, 3, 4, 5, 6, 123456, tzinfo=UTC),
    )
    assert event.hash == event.event_hash
    row = event.to_dict()
    assert event_module.CausalEvent.from_dict(row) == event

    with pytest.raises(TypeError, match="ISO timestamp"):
        event_module.CausalEvent.from_dict({**row, "occurred_at": None})
    with pytest.raises(TypeError, match="JSON object"):
        event_module.CausalEvent.from_dict({**row, "payload": ["bad"]})
    with pytest.raises(ValueError, match="Invalid isoformat"):
        event_module.CausalEvent.from_dict({**row, "occurred_at": "not-a-time"})

    with pytest.raises(ChainIntegrityError, match="sequence"):
        replace(event, sequence=0).verify_integrity()
    with pytest.raises(ChainIntegrityError, match="SHA-256"):
        replace(event, prev_hash="short").verify_integrity()
    with pytest.raises(ChainIntegrityError, match="payload hash"):
        replace(event, payload_hash="f" * 64).verify_integrity()
    with pytest.raises(ChainIntegrityError, match="event hash"):
        replace(event, event_hash="f" * 64).verify_integrity()

    with pytest.raises(TypeError, match="either a draft"):
        store.append(
            EventDraft(
                tenant_id=stream.tenant_id,
                cell_id=stream.cell_id,
                session_id=stream.session_id,
                capsule_digest=stream.capsule_digest,
                event_type="message.accepted",
                payload={},
            ),
            event_type="other",
        )
    with pytest.raises(TypeError, match="do not form"):
        store.append(not_an_event=True)
    with pytest.raises(TypeError, match="JSON object"):
        event_module.InMemoryEventStore._build_event(
            EventDraft(
                tenant_id=stream.tenant_id,
                cell_id=stream.cell_id,
                session_id=stream.session_id,
                capsule_digest=stream.capsule_digest,
                event_type="bad",
                payload=cast(object, ["bad"]),
            ),
            sequence=1,
            prev_hash=GENESIS_HASH,
        )


def test_branch_views_heads_and_invalid_ranges() -> None:
    store = InMemoryEventStore()
    stream = address()
    assert store.head(stream) is None
    root = store.get_branch(stream)
    assert root.address == stream
    assert root.parent_address is None
    assert store.branches(stream) == (root,)
    with pytest.raises(BranchNotFound):
        store.read(stream.with_branch("missing"))
    with pytest.raises(BranchNotFound):
        store.get_branch(stream.with_branch("missing"))
    with pytest.raises(ValueError, match="from_sequence"):
        store.read(stream, from_sequence=0)
    with pytest.raises(ValueError, match="to_sequence"):
        store.read(stream, from_sequence=2, to_sequence=1)

    event = append_message(store, stream, 1)
    assert store.head(stream) == event
    view = BranchView(root, (event,))
    assert tuple(view) == (event,)
    with pytest.raises(NamespaceViolation):
        store._validate_namespace(event, address("other-tenant"))

    with pytest.raises(InvalidBranch, match="negative"):
        store.fork(stream, -1, new_branch_id="bad")
    with pytest.raises(ValueError, match="new_branch_id"):
        store.fork(stream, 1, new_branch_id="")
    store.create_branch(stream, branch_id="alias", fork_sequence=1)
    with pytest.raises(InvalidBranch, match="already exists"):
        store.fork(stream, 1, new_branch_id="alias")


def test_chain_rejects_namespace_sequence_link_and_branch_metadata_tampering() -> None:
    # Each case uses an independent store because the tamper is intentionally
    # destructive and models a corrupt persistence adapter.
    store = InMemoryEventStore()
    stream = address()
    event = append_message(store, stream, 1)
    object.__setattr__(event, "tenant_id", "tenant-tampered")
    object.__setattr__(event, "event_hash", event.recompute_event_hash())
    with pytest.raises(NamespaceViolation, match="tenant"):
        store.verify_chain(stream)

    store = InMemoryEventStore()
    stream = address()
    event = append_message(store, stream, 1)
    object.__setattr__(event, "branch_id", "rogue")
    object.__setattr__(event, "event_hash", event.recompute_event_hash())
    with pytest.raises(NamespaceViolation, match="branch lineage"):
        store.verify_chain(stream)

    store = InMemoryEventStore()
    stream = address()
    event = append_message(store, stream, 1)
    object.__setattr__(event, "sequence", 2)
    object.__setattr__(event, "event_hash", event.recompute_event_hash())
    with pytest.raises(ChainIntegrityError, match="sequence gap"):
        store.verify_chain(stream)

    store = InMemoryEventStore()
    stream = address()
    event = append_message(store, stream, 1)
    object.__setattr__(event, "prev_hash", "f" * 64)
    object.__setattr__(event, "event_hash", event.recompute_event_hash())
    with pytest.raises(ChainIntegrityError, match="prev_hash"):
        store.verify_chain(stream)

    store = InMemoryEventStore()
    stream = address()
    append_message(store, stream, 1)
    branch = store.fork(stream, 1, new_branch_id="shadow")
    object.__setattr__(branch, "base_hash", "f" * 64)
    with pytest.raises(ChainIntegrityError, match="base hash"):
        store.verify_chain(stream.with_branch("shadow"))

    store = InMemoryEventStore()
    stream = address()
    append_message(store, stream, 1)
    branch = store.fork(stream, 1, new_branch_id="shadow")
    object.__setattr__(branch, "base_hash", GENESIS_HASH)
    object.__setattr__(branch, "fork_sequence", 100)
    with pytest.raises(ChainIntegrityError, match="outside"):
        store.verify_chain(stream.with_branch("shadow"))

    store = InMemoryEventStore()
    stream = address()
    append_message(store, stream, 1)
    root = store.get_branch(stream)
    object.__setattr__(root, "base_hash", "f" * 64)
    with pytest.raises(ChainIntegrityError, match="genesis"):
        store.verify_chain(stream)


def test_replay_errors_empty_prefix_and_state_fingerprint_shapes() -> None:
    store = InMemoryEventStore()
    stream = address()
    append_message(store, stream, 1, value=4)
    replayer = ProjectionReplayer(store)

    def reducer(state: list[int], event) -> list[int]:
        return [*state, int(event.payload["delta"])]

    with pytest.raises(ValueError, match="from_sequence"):
        replayer.replay(stream, reducer, initial_state=[], from_sequence=0)
    with pytest.raises(ValueError, match="to_sequence"):
        replayer.replay(stream, reducer, initial_state=[], from_sequence=2, to_sequence=1)
    with pytest.raises(ValueError, match="negative"):
        replayer.replay_at(stream, -1, reducer, initial_state=[])
    empty = replayer.replay_at(stream, 0, reducer, initial_state=[])
    assert empty.events == ()
    assert empty.event_count == 0
    assert empty.sequence == 0
    assert empty.head_hash == ""

    with pytest.raises(TypeError, match="initial_state"):
        replayer.replay(stream, reducer)

    class ApplyOnly:
        def apply(self, state: list[int], event) -> list[int]:
            return reducer(state, event)

    with pytest.raises(TypeError, match="initial_state"):
        replayer.replay(stream, ApplyOnly())

    class AwaitableResult:
        def __await__(self):
            async def done():
                return []

            return done().__await__()

    def async_result(state: list[int], event):
        return AwaitableResult()

    with pytest.raises(TypeError, match="async reducers"):
        replayer.replay(stream, async_result, initial_state=[])

    class Dumpable:
        def model_dump(self, mode: str = "json"):
            return {"mode": mode, "set": {3, 1}}

    class HasDict:
        def __init__(self):
            self.value = {"b": 2, "a": 1}

    assert state_fingerprint(Dumpable()) == state_fingerprint(Dumpable())
    assert state_fingerprint(HasDict()) == state_fingerprint(HasDict())
    assert state_fingerprint(object())


def test_replay_detects_malformed_inputs_before_reducer() -> None:
    store = InMemoryEventStore()
    stream = address()
    first = append_message(store, stream, 1)
    replayer = ProjectionReplayer(store)

    wrong_scope = replace(first, tenant_id="tenant-other")
    with pytest.raises(NamespaceViolation, match="another tenant"):
        replayer._check_events(stream, (wrong_scope,))
    no_branch = replace(first, branch_id="")
    with pytest.raises(NamespaceViolation, match="branch id"):
        replayer._check_events(stream, (no_branch,))
    second = append_message(store, stream, 2)
    with pytest.raises(ChainIntegrityError, match="sequence gap"):
        replayer._check_events(stream, (first, replace(second, sequence=3)))


@pytest.mark.asyncio
async def test_async_replay_supports_async_reducers_and_sync_store_fallback() -> None:
    store = InMemoryEventStore()
    stream = address()
    append_message(store, stream, 1, value=2)
    append_message(store, stream, 2, value=3)

    async def async_reducer(state: int, event) -> int:
        return state + int(event.payload["delta"])

    replayer = ProjectionReplayer(store)
    result = await replayer.replay_async(stream, async_reducer, initial_state=0)
    assert result.state == 5
    assert result.verified is True

    class SyncOnlyStore:
        def verify_chain(self, address: CellAddress) -> None:
            store.verify_chain(address)

        def read(self, address: CellAddress, *, from_sequence=1, to_sequence=None):
            return store.read(address, from_sequence=from_sequence, to_sequence=to_sequence)

    fallback = ProjectionReplayer(SyncOnlyStore())

    def sync_reducer(state: list[int], event) -> list[int]:
        return [*state, int(event.payload["delta"])]

    result = await fallback.replay_async(stream, sync_reducer, initial_state=[])
    assert result.state == [2, 3]
    unchecked = await replayer.replay_async(
        stream,
        sync_reducer,
        initial_state=[],
        verify=False,
    )
    assert unchecked.verified is False

    with pytest.raises(ValueError, match="from_sequence"):
        await replayer.replay_async(stream, sync_reducer, initial_state=[], from_sequence=0)
    with pytest.raises(ValueError, match="to_sequence"):
        await replayer.replay_async(
            stream,
            sync_reducer,
            initial_state=[],
            from_sequence=2,
            to_sequence=1,
        )
