"""Deterministic projection replay and branch utilities.

The event log is the source of truth; Session, Memory, Summary, cost and
audit views can all be rebuilt by supplying a small pure reducer.  Replay
never merges streams implicitly: the complete ``CellAddress`` is checked for
every event before the reducer sees it.
"""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
from collections.abc import Mapping
from dataclasses import dataclass
from itertools import pairwise
from typing import Generic, Protocol, TypeVar, cast

from trpc_service.cell.events import (
    CausalEvent,
    CellAddress,
    ChainIntegrityError,
    EventStore,
    NamespaceViolation,
)

StateT = TypeVar("StateT")
_UNSET = object()


class ProjectionReducer(Protocol[StateT]):
    """A pure state transition function for one event."""

    def __call__(self, state: StateT, event: CausalEvent) -> StateT: ...


class Projection(Protocol[StateT]):
    """Optional object form of a projection with a state factory."""

    def initial_state(self) -> StateT: ...

    def apply(self, state: StateT, event: CausalEvent) -> StateT: ...


class DeterminismViolation(RuntimeError):
    """Raised when replaying the same event prefix produces different state."""


@dataclass(frozen=True, slots=True)
class ProjectionResult(Generic[StateT]):
    """Result of replaying one exact branch prefix."""

    address: CellAddress
    state: StateT
    events: tuple[CausalEvent, ...]
    first_sequence: int | None
    last_sequence: int
    last_event_hash: str
    state_hash: str
    verified: bool = True

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def sequence(self) -> int:
        return self.last_sequence

    @property
    def head_hash(self) -> str:
        return self.last_event_hash


ReplayResult = ProjectionResult


def _jsonable(value: object) -> object:
    """Produce a stable representation for state fingerprints."""

    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _jsonable(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_jsonable(item) for item in value), key=repr)
    if hasattr(value, "model_dump"):
        return _jsonable(cast(object, value.model_dump(mode="json")))
    if hasattr(value, "__dict__"):
        return _jsonable(vars(value))
    return repr(value)


def state_fingerprint(state: object) -> str:
    """Hash a projection state for deterministic replay comparisons."""

    encoded = json.dumps(
        _jsonable(state), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class ProjectionReplayer(Generic[StateT]):
    """Apply a projection to a verified event lineage."""

    def __init__(self, store: EventStore) -> None:
        self.store = store

    @staticmethod
    def _scope(address: CellAddress) -> tuple[str, str, str, str]:
        return (
            address.tenant_id,
            address.app_id,
            address.cell_id,
            address.session_id,
        )

    @classmethod
    def _check_events(cls, address: CellAddress, events: tuple[CausalEvent, ...]) -> None:
        for event in events:
            if event.branch_id == "":
                raise NamespaceViolation("projection received an event without a branch id")
            if cls._scope(event.address) != cls._scope(address):
                raise NamespaceViolation(
                    "projection received an event from another tenant, app, cell or session"
                )
        for previous, current in pairwise(events):
            if current.sequence != previous.sequence + 1:
                raise ChainIntegrityError("projection input contains a sequence gap")

    @staticmethod
    def _resolve_reducer(
        projection: Projection[StateT] | ProjectionReducer[StateT],
        initial_state: object,
    ) -> tuple[ProjectionReducer[StateT], StateT]:
        if hasattr(projection, "apply") and callable(projection.apply):
            reducer = cast(ProjectionReducer[StateT], projection.apply)
            if initial_state is _UNSET:
                factory = getattr(projection, "initial_state", None)
                if not callable(factory):
                    raise TypeError("projection object must provide initial_state()")
                return reducer, cast(StateT, factory())
            return reducer, cast(StateT, initial_state)
        if initial_state is _UNSET:
            raise TypeError("initial_state is required when projection is a callable")
        return cast(ProjectionReducer[StateT], projection), cast(StateT, initial_state)

    def _apply(
        self,
        address: CellAddress,
        events: tuple[CausalEvent, ...],
        projection: Projection[StateT] | ProjectionReducer[StateT],
        *,
        initial_state: object,
        verified: bool,
    ) -> ProjectionResult[StateT]:
        self._check_events(address, events)
        reducer, state = self._resolve_reducer(projection, initial_state)
        for event in events:
            # A reducer is application code.  Give it an isolated copy so a
            # bug in a projection cannot mutate the immutable log in memory.
            result = reducer(copy.deepcopy(state), copy.deepcopy(event))
            if inspect.isawaitable(result):
                raise TypeError("async reducers must be used with replay_async()")
            state = result
        last_event = events[-1] if events else None
        return ProjectionResult(
            address=address,
            state=state,
            events=events,
            first_sequence=events[0].sequence if events else None,
            last_sequence=last_event.sequence if last_event is not None else 0,
            last_event_hash=last_event.event_hash if last_event is not None else "",
            state_hash=state_fingerprint(state),
            verified=verified,
        )

    def replay(
        self,
        address: CellAddress,
        projection: Projection[StateT] | ProjectionReducer[StateT],
        *,
        initial_state: StateT | object = _UNSET,
        from_sequence: int = 1,
        to_sequence: int | None = None,
        verify: bool = True,
    ) -> ProjectionResult[StateT]:
        """Replay a branch, optionally stopping at a sequence.

        When ``from_sequence`` is greater than one, ``initial_state`` must be
        the state immediately before that sequence.  This is useful for
        checkpoint restoration and makes branch replay inexpensive.
        """

        if from_sequence < 1:
            raise ValueError("from_sequence must be positive")
        if to_sequence is not None and to_sequence < from_sequence:
            raise ValueError("to_sequence must be >= from_sequence")
        if verify:
            self.store.verify_chain(address)
        events = self.store.read(address, from_sequence=from_sequence, to_sequence=to_sequence)
        return self._apply(
            address,
            events,
            projection,
            initial_state=initial_state,
            verified=verify,
        )

    def replay_at(
        self,
        address: CellAddress,
        sequence: int,
        projection: Projection[StateT] | ProjectionReducer[StateT],
        *,
        initial_state: StateT | object = _UNSET,
        verify: bool = True,
    ) -> ProjectionResult[StateT]:
        """Replay the visible lineage at an exact sequence."""

        if sequence < 0:
            raise ValueError("sequence cannot be negative")
        if sequence == 0:
            events: tuple[CausalEvent, ...] = ()
            if verify:
                self.store.verify_chain(address)
            return self._apply(
                address,
                events,
                projection,
                initial_state=initial_state,
                verified=verify,
            )
        return self.replay(
            address,
            projection,
            initial_state=initial_state,
            to_sequence=sequence,
            verify=verify,
        )

    def assert_deterministic(
        self,
        address: CellAddress,
        projection: Projection[StateT] | ProjectionReducer[StateT],
        *,
        initial_state: StateT | object = _UNSET,
        from_sequence: int = 1,
        to_sequence: int | None = None,
    ) -> ProjectionResult[StateT]:
        """Replay twice and fail if the state fingerprint changes."""

        first = self.replay(
            address,
            projection,
            initial_state=(_UNSET if initial_state is _UNSET else copy.deepcopy(initial_state)),
            from_sequence=from_sequence,
            to_sequence=to_sequence,
        )
        second = self.replay(
            address,
            projection,
            initial_state=(_UNSET if initial_state is _UNSET else copy.deepcopy(initial_state)),
            from_sequence=from_sequence,
            to_sequence=to_sequence,
        )
        if first.state_hash != second.state_hash:
            raise DeterminismViolation(
                f"projection changed for {address.stream_key} at sequence {first.last_sequence}"
            )
        return first

    async def replay_async(
        self,
        address: CellAddress,
        projection: Projection[StateT] | ProjectionReducer[StateT],
        *,
        initial_state: StateT | object = _UNSET,
        from_sequence: int = 1,
        to_sequence: int | None = None,
        verify: bool = True,
    ) -> ProjectionResult[StateT]:
        """Async-store adapter for the surrounding FastAPI runtime."""

        if from_sequence < 1:
            raise ValueError("from_sequence must be positive")
        if to_sequence is not None and to_sequence < from_sequence:
            raise ValueError("to_sequence must be >= from_sequence")
        if verify:
            verify_async = getattr(self.store, "verify_chain_async", None)
            if callable(verify_async):
                await verify_async(address)
            else:
                self.store.verify_chain(address)
        read_async = getattr(self.store, "read_async", None)
        if callable(read_async):
            events = await read_async(address, from_sequence=from_sequence, to_sequence=to_sequence)
        else:
            events = self.store.read(address, from_sequence=from_sequence, to_sequence=to_sequence)
        self._check_events(address, events)
        reducer, state = self._resolve_reducer(projection, initial_state)
        for event in events:
            result = reducer(copy.deepcopy(state), copy.deepcopy(event))
            if inspect.isawaitable(result):
                state = await result
            else:
                state = result
        last_event = events[-1] if events else None
        return ProjectionResult(
            address=address,
            state=state,
            events=events,
            first_sequence=events[0].sequence if events else None,
            last_sequence=last_event.sequence if last_event is not None else 0,
            last_event_hash=last_event.event_hash if last_event is not None else "",
            state_hash=state_fingerprint(state),
            verified=verify,
        )


def replay_projection(
    store: EventStore,
    address: CellAddress,
    projection: Projection[StateT] | ProjectionReducer[StateT],
    *,
    initial_state: StateT | object = _UNSET,
    from_sequence: int = 1,
    to_sequence: int | None = None,
    verify: bool = True,
) -> ProjectionResult[StateT]:
    """Functional convenience wrapper around :class:`ProjectionReplayer`."""

    return ProjectionReplayer[StateT](store).replay(
        address,
        projection,
        initial_state=initial_state,
        from_sequence=from_sequence,
        to_sequence=to_sequence,
        verify=verify,
    )


__all__ = [
    "DeterminismViolation",
    "Projection",
    "ProjectionReducer",
    "ProjectionReplayer",
    "ProjectionResult",
    "ReplayResult",
    "replay_projection",
    "state_fingerprint",
]
