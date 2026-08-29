"""Causal, append-only events for an Agent Cell.

The cell event log is deliberately small and persistence neutral.  It is the
contract that a PostgreSQL implementation can later back without changing
replay or branch semantics.  A stream is identified by the complete cell
scope (tenant, cell, session, capsule and branch); no method in this module
accepts a partially qualified stream.

The in-memory implementation is synchronous because appending an event is a
local, atomic operation.  ``*_async`` methods are provided as thin adapters
for the surrounding async service and make it straightforward to replace the
store with an async PostgreSQL implementation later.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import threading
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Protocol, TypeAlias, cast

GENESIS_HASH: Final[str] = "0" * 64
"""The previous hash used by the first event in a root branch."""


JsonPrimitive: TypeAlias = bool | int | float | str | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]


class EventType(StrEnum):
    """Well-known event names used by the reference Agent Cell runtime.

    The store accepts arbitrary non-empty event names so applications can add
    domain events without changing this package.
    """

    MESSAGE_ACCEPTED = "message.accepted"
    CELL_ACTIVATED = "cell.activated"
    CONTEXT_PROJECTED = "context.projected"
    MODEL_REQUESTED = "model.requested"
    MODEL_RESPONDED = "model.responded"
    TOOL_INTENT_CREATED = "tool.intent.created"
    POLICY_DECIDED = "policy.decided"
    CONFIRMATION_RECEIVED = "confirmation.received"
    TOOL_EFFECT_COMMITTED = "tool.effect.committed"
    MEMORY_FACT_APPENDED = "memory.fact.appended"
    REPLY_PREPARED = "reply.prepared"
    REPLY_DELIVERED = "reply.delivered"


class EventStoreError(RuntimeError):
    """Base class for event store failures."""


class NamespaceViolation(EventStoreError):
    """Raised when an operation crosses a tenant, cell or capsule boundary."""


class ChainIntegrityError(EventStoreError):
    """Raised when an event payload or hash chain has been tampered with."""


class AppendOnlyViolation(EventStoreError):
    """Raised when an event id is reused for different immutable content."""


class BranchNotFound(EventStoreError):
    """Raised when a requested branch does not exist in the requested cell."""


class InvalidBranch(EventStoreError):
    """Raised when a branch fork point or branch id is invalid."""


def _require_identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _normalise_json(value: object, *, path: str = "payload") -> JsonValue:
    """Copy and validate JSON data before it enters the hash chain."""

    if value is None or isinstance(value, (str, bool, int)):
        return cast(JsonPrimitive, value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError(f"{path} contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        result: JsonObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} keys must be strings")
            result[key] = _normalise_json(item, path=f"{path}.{key}")
        return result
    if isinstance(value, (list, tuple)):
        return [_normalise_json(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    raise TypeError(f"{path} contains unsupported value {type(value).__name__}")


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("occurred_at must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


@dataclass(frozen=True, slots=True)
class CellAddress:
    """Complete namespace of an Agent Cell event stream."""

    tenant_id: str
    cell_id: str
    session_id: str
    capsule_digest: str
    branch_id: str = "main"

    def __post_init__(self) -> None:
        for name in ("tenant_id", "cell_id", "session_id", "capsule_digest", "branch_id"):
            _require_identifier(name, getattr(self, name))

    @property
    def stream_key(self) -> tuple[str, str, str, str, str]:
        return (
            self.tenant_id,
            self.cell_id,
            self.session_id,
            self.capsule_digest,
            self.branch_id,
        )

    def with_branch(self, branch_id: str) -> CellAddress:
        return CellAddress(
            tenant_id=self.tenant_id,
            cell_id=self.cell_id,
            session_id=self.session_id,
            capsule_digest=self.capsule_digest,
            branch_id=branch_id,
        )


# Friendly aliases used in design documents and by integrations.
AgentCellAddress = CellAddress
CellKey = CellAddress


@dataclass(frozen=True, slots=True)
class EventDraft:
    """Typed input to :meth:`InMemoryEventStore.append`.

    ``correlation_id``, ``trace_id`` and ``request_id`` are generated when a
    caller does not supply them.  Production ingress should always supply the
    IDs from the IM callback so the complete chain remains traceable.
    """

    tenant_id: str
    cell_id: str
    session_id: str
    capsule_digest: str
    event_type: str | EventType
    branch_id: str = "main"
    payload: Mapping[str, object] = field(default_factory=dict)
    event_id: str | None = None
    causation_id: str | None = None
    correlation_id: str | None = None
    trace_id: str | None = None
    request_id: str | None = None
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def address(self) -> CellAddress:
        return CellAddress(
            tenant_id=self.tenant_id,
            cell_id=self.cell_id,
            session_id=self.session_id,
            capsule_digest=self.capsule_digest,
            branch_id=self.branch_id,
        )

    def normalised(self) -> EventDraft:
        """Return a validated, immutable-copy-friendly draft."""

        _require_identifier("event_type", str(self.event_type))
        if self.event_id is not None:
            _require_identifier("event_id", self.event_id)
        if self.causation_id is not None:
            _require_identifier("causation_id", self.causation_id)
        for name, value in (
            ("correlation_id", self.correlation_id),
            ("trace_id", self.trace_id),
            ("request_id", self.request_id),
        ):
            if value is not None:
                _require_identifier(name, value)
        _timestamp(self.occurred_at)
        payload_value = _normalise_json(self.payload)
        if not isinstance(payload_value, dict):
            raise TypeError("event payload must be a JSON object")
        payload = cast(Mapping[str, object], payload_value)
        return EventDraft(
            tenant_id=self.tenant_id,
            cell_id=self.cell_id,
            session_id=self.session_id,
            capsule_digest=self.capsule_digest,
            event_type=str(self.event_type),
            branch_id=self.branch_id,
            payload=payload,
            event_id=self.event_id,
            causation_id=self.causation_id,
            correlation_id=self.correlation_id or str(uuid.uuid4()),
            trace_id=self.trace_id or str(uuid.uuid4()),
            request_id=self.request_id or str(uuid.uuid4()),
            occurred_at=self.occurred_at,
        )


# Alternate spelling retained for callers that use the full name.
CausalEventDraft = EventDraft


@dataclass(frozen=True, slots=True)
class CausalEvent:
    """One immutable event in a cell's causal hash chain."""

    tenant_id: str
    cell_id: str
    session_id: str
    capsule_digest: str
    branch_id: str
    sequence: int
    event_id: str
    event_type: str
    payload: JsonObject
    causation_id: str | None
    correlation_id: str
    trace_id: str
    request_id: str
    occurred_at: datetime
    prev_hash: str
    payload_hash: str
    event_hash: str

    @property
    def address(self) -> CellAddress:
        return CellAddress(
            tenant_id=self.tenant_id,
            cell_id=self.cell_id,
            session_id=self.session_id,
            capsule_digest=self.capsule_digest,
            branch_id=self.branch_id,
        )

    @property
    def hash(self) -> str:
        """Short alias used by projection and lineage code."""

        return self.event_hash

    def _body(self) -> JsonObject:
        return {
            "version": 1,
            "tenant_id": self.tenant_id,
            "cell_id": self.cell_id,
            "session_id": self.session_id,
            "capsule_digest": self.capsule_digest,
            "branch_id": self.branch_id,
            "sequence": self.sequence,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "causation_id": self.causation_id,
            "correlation_id": self.correlation_id,
            "trace_id": self.trace_id,
            "request_id": self.request_id,
            "occurred_at": _timestamp(self.occurred_at),
            "prev_hash": self.prev_hash,
            "payload_hash": self.payload_hash,
        }

    def recompute_payload_hash(self) -> str:
        return _sha256(_canonical_json(self.payload))

    def recompute_event_hash(self) -> str:
        return _sha256(_canonical_json(self._body()))

    def verify_integrity(self) -> None:
        """Validate this event's payload hash and self-hash."""

        if self.sequence < 1:
            raise ChainIntegrityError("event sequence must be positive")
        if len(self.prev_hash) != 64 or len(self.payload_hash) != 64 or len(self.event_hash) != 64:
            raise ChainIntegrityError("event hashes must be SHA-256 hex strings")
        if self.recompute_payload_hash() != self.payload_hash:
            raise ChainIntegrityError(f"payload hash mismatch for event {self.event_id}")
        if self.recompute_event_hash() != self.event_hash:
            raise ChainIntegrityError(f"event hash mismatch for event {self.event_id}")

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable record suitable for a PG adapter."""

        return {
            "tenant_id": self.tenant_id,
            "cell_id": self.cell_id,
            "session_id": self.session_id,
            "capsule_digest": self.capsule_digest,
            "branch_id": self.branch_id,
            "sequence": self.sequence,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "payload": copy.deepcopy(self.payload),
            "causation_id": self.causation_id,
            "correlation_id": self.correlation_id,
            "trace_id": self.trace_id,
            "request_id": self.request_id,
            "occurred_at": _timestamp(self.occurred_at),
            "prev_hash": self.prev_hash,
            "payload_hash": self.payload_hash,
            "event_hash": self.event_hash,
        }

    @classmethod
    def from_dict(cls, row: Mapping[str, object]) -> CausalEvent:
        """Hydrate an event and immediately validate its self-integrity."""

        occurred_at_raw = row.get("occurred_at")
        if not isinstance(occurred_at_raw, str):
            raise TypeError("occurred_at must be an ISO timestamp")
        occurred_at = datetime.fromisoformat(occurred_at_raw)
        payload_raw = row.get("payload")
        payload = _normalise_json(payload_raw)
        if not isinstance(payload, dict):
            raise TypeError("event payload must be a JSON object")
        event = cls(
            tenant_id=_require_identifier("tenant_id", cast(str, row.get("tenant_id"))),
            cell_id=_require_identifier("cell_id", cast(str, row.get("cell_id"))),
            session_id=_require_identifier("session_id", cast(str, row.get("session_id"))),
            capsule_digest=_require_identifier(
                "capsule_digest", cast(str, row.get("capsule_digest"))
            ),
            branch_id=_require_identifier("branch_id", cast(str, row.get("branch_id"))),
            sequence=cast(int, row.get("sequence")),
            event_id=_require_identifier("event_id", cast(str, row.get("event_id"))),
            event_type=_require_identifier("event_type", cast(str, row.get("event_type"))),
            payload=payload,
            causation_id=cast(str | None, row.get("causation_id")),
            correlation_id=_require_identifier(
                "correlation_id", cast(str, row.get("correlation_id"))
            ),
            trace_id=_require_identifier("trace_id", cast(str, row.get("trace_id"))),
            request_id=_require_identifier("request_id", cast(str, row.get("request_id"))),
            occurred_at=occurred_at,
            prev_hash=_require_identifier("prev_hash", cast(str, row.get("prev_hash"))),
            payload_hash=_require_identifier("payload_hash", cast(str, row.get("payload_hash"))),
            event_hash=_require_identifier("event_hash", cast(str, row.get("event_hash"))),
        )
        event.verify_integrity()
        return event


@dataclass(frozen=True, slots=True)
class EventBranch:
    """Immutable branch metadata and its parent hash anchor."""

    tenant_id: str
    cell_id: str
    session_id: str
    capsule_digest: str
    branch_id: str
    parent_branch_id: str | None
    fork_sequence: int
    base_hash: str
    parent_capsule_digest: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def address(self) -> CellAddress:
        return CellAddress(
            tenant_id=self.tenant_id,
            cell_id=self.cell_id,
            session_id=self.session_id,
            capsule_digest=self.capsule_digest,
            branch_id=self.branch_id,
        )

    @property
    def parent_address(self) -> CellAddress | None:
        if self.parent_branch_id is None:
            return None
        return CellAddress(
            tenant_id=self.tenant_id,
            cell_id=self.cell_id,
            session_id=self.session_id,
            capsule_digest=self.parent_capsule_digest or self.capsule_digest,
            branch_id=self.parent_branch_id,
        )


@dataclass(frozen=True, slots=True)
class BranchView:
    """A branch plus the events visible through its parent lineage."""

    branch: EventBranch
    events: tuple[CausalEvent, ...]

    def __iter__(self) -> Iterator[CausalEvent]:
        return iter(self.events)


StreamKey: TypeAlias = tuple[str, str, str, str]


class EventStore(Protocol):
    """Persistence-neutral protocol for a causal cell event log.

    The protocol is intentionally independent of SQLAlchemy.  A PostgreSQL
    adapter can implement the same methods using ``SELECT ... FOR UPDATE`` on
    the branch head and a unique ``(tenant_id, cell_id, session_id,
    capsule_digest, branch_id, sequence)`` constraint.
    """

    def append(self, draft: EventDraft | None = None, **kwargs: object) -> CausalEvent:
        raise NotImplementedError

    def read(
        self,
        address: CellAddress,
        *,
        from_sequence: int = 1,
        to_sequence: int | None = None,
    ) -> tuple[CausalEvent, ...]:
        raise NotImplementedError

    def head(self, address: CellAddress) -> CausalEvent | None:
        raise NotImplementedError

    def verify_chain(self, address: CellAddress) -> None:
        raise NotImplementedError

    def fork(
        self,
        address: CellAddress,
        from_sequence: int,
        *,
        new_branch_id: str,
        parent_branch_id: str | None = None,
        target_capsule_digest: str | None = None,
    ) -> EventBranch:
        raise NotImplementedError


@dataclass(slots=True)
class _BranchState:
    metadata: EventBranch
    events: list[CausalEvent] = field(default_factory=list)


class InMemoryEventStore:
    """Thread-safe reference event store with explicit tenant isolation.

    Events are stored as branch-local lists, while ``read`` exposes the
    parent's prefix followed by the branch's own events.  That makes a branch
    cheap to create and gives replay the same history a real PG implementation
    would return from a lineage query.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._branches: dict[StreamKey, dict[str, _BranchState]] = {}
        self._event_ids: dict[str, CausalEvent] = {}

    def _stream_key(self, address: CellAddress) -> StreamKey:
        return (
            address.tenant_id,
            address.cell_id,
            address.session_id,
            address.capsule_digest,
        )

    def _ensure_root(self, address: CellAddress) -> _BranchState:
        key = self._stream_key(address)
        branches = self._branches.setdefault(key, {})
        root = branches.get("main")
        if root is None:
            root = _BranchState(
                metadata=EventBranch(
                    tenant_id=address.tenant_id,
                    cell_id=address.cell_id,
                    session_id=address.session_id,
                    capsule_digest=address.capsule_digest,
                    branch_id="main",
                    parent_branch_id=None,
                    fork_sequence=0,
                    base_hash=GENESIS_HASH,
                )
            )
            branches["main"] = root
        return root

    def _branch(self, address: CellAddress) -> _BranchState:
        self._ensure_root(address)
        branch = self._branches[self._stream_key(address)].get(address.branch_id)
        if branch is None:
            raise BranchNotFound(
                f"branch {address.branch_id!r} does not exist in tenant={address.tenant_id!r} "
                f"cell={address.cell_id!r}"
            )
        return branch

    def _lineage(self, address: CellAddress) -> tuple[CausalEvent, ...]:
        branch = self._branch(address)
        metadata = branch.metadata
        if metadata.parent_branch_id is None:
            return tuple(branch.events)
        parent_address = metadata.parent_address
        if parent_address is None:  # pragma: no cover - guarded by parent_branch_id
            raise ChainIntegrityError("branch parent metadata is incomplete")
        parent_events = self._lineage(parent_address)
        prefix = tuple(event for event in parent_events if event.sequence <= metadata.fork_sequence)
        return prefix + tuple(branch.events)

    def branches(self, address: CellAddress) -> tuple[EventBranch, ...]:
        """List branches in one exact tenant/cell/session/capsule stream."""

        with self._lock:
            self._ensure_root(address)
            return tuple(
                state.metadata for state in self._branches[self._stream_key(address)].values()
            )

    def get_branch(self, address: CellAddress) -> EventBranch:
        with self._lock:
            return self._branch(address).metadata

    def append(self, draft: EventDraft | None = None, **kwargs: object) -> CausalEvent:
        """Atomically append one event and return the immutable record.

        Callers may pass an :class:`EventDraft` or keyword fields accepted by
        that dataclass.  Supplying an existing ``event_id`` is idempotent only
        when every immutable field matches; reusing it for another namespace
        or payload raises an error.
        """

        with self._lock:
            if draft is not None and kwargs:
                raise TypeError("append accepts either a draft or keyword fields, not both")
            if draft is None:
                try:
                    draft_factory = cast(Any, EventDraft)
                    draft = draft_factory(**kwargs)
                except TypeError as exc:
                    raise TypeError("append keyword fields do not form an EventDraft") from exc
            supplied_draft = draft
            draft = draft.normalised()
            address = draft.address

            # Check the globally unique event id before materialising a
            # possibly forged namespace.  A retry from another tenant is a
            # namespace violation, not a harmless "unknown branch" lookup.
            if draft.event_id is not None:
                existing = self._event_ids.get(draft.event_id)
                if existing is not None and existing.address != address:
                    raise NamespaceViolation(
                        f"event {draft.event_id} already belongs to another cell namespace"
                    )
            branch = self._branch(address)

            if draft.event_id is not None:
                existing = self._event_ids.get(draft.event_id)
                if existing is not None:
                    if not self._same_draft(existing, draft, supplied=supplied_draft):
                        raise AppendOnlyViolation(
                            f"event {draft.event_id} is immutable and cannot be replaced"
                        )
                    return existing

            visible = self._lineage(address)
            sequence = (visible[-1].sequence + 1) if visible else 1
            prev_hash = visible[-1].event_hash if visible else branch.metadata.base_hash
            event = self._build_event(draft, sequence=sequence, prev_hash=prev_hash)
            self._validate_namespace(event, address)
            event.verify_integrity()
            branch.events.append(event)
            self._event_ids[event.event_id] = event
            return event

    @staticmethod
    def _same_draft(
        event: CausalEvent, draft: EventDraft, *, supplied: EventDraft | None = None
    ) -> bool:
        if (
            event.address != draft.address
            or event.event_type != str(draft.event_type)
            or event.payload != _normalise_json(draft.payload)
        ):
            return False
        # An explicit event_id is the ingress idempotency key.  Correlation
        # IDs are compared only when the caller supplied them; omitted IDs are
        # generated on each attempt and must not turn a retry into a conflict.
        requested = supplied or draft
        for field_name in ("causation_id", "correlation_id", "trace_id", "request_id"):
            requested_value = getattr(requested, field_name)
            if requested_value is not None and getattr(event, field_name) != requested_value:
                return False
        return True

    @staticmethod
    def _build_event(draft: EventDraft, *, sequence: int, prev_hash: str) -> CausalEvent:
        payload = _normalise_json(draft.payload)
        if not isinstance(payload, dict):
            raise TypeError("event payload must be a JSON object")
        event_id = draft.event_id or str(uuid.uuid4())
        event_type = str(draft.event_type)
        payload_hash = _sha256(_canonical_json(payload))
        event = CausalEvent(
            tenant_id=draft.tenant_id,
            cell_id=draft.cell_id,
            session_id=draft.session_id,
            capsule_digest=draft.capsule_digest,
            branch_id=draft.branch_id,
            sequence=sequence,
            event_id=event_id,
            event_type=event_type,
            payload=payload,
            causation_id=draft.causation_id,
            correlation_id=cast(str, draft.correlation_id),
            trace_id=cast(str, draft.trace_id),
            request_id=cast(str, draft.request_id),
            occurred_at=draft.occurred_at,
            prev_hash=prev_hash,
            payload_hash=payload_hash,
            event_hash="",
        )
        return CausalEvent(
            tenant_id=event.tenant_id,
            cell_id=event.cell_id,
            session_id=event.session_id,
            capsule_digest=event.capsule_digest,
            branch_id=event.branch_id,
            sequence=event.sequence,
            event_id=event.event_id,
            event_type=event.event_type,
            payload=event.payload,
            causation_id=event.causation_id,
            correlation_id=event.correlation_id,
            trace_id=event.trace_id,
            request_id=event.request_id,
            occurred_at=event.occurred_at,
            prev_hash=event.prev_hash,
            payload_hash=event.payload_hash,
            event_hash=_sha256(_canonical_json(event._body())),
        )

    @staticmethod
    def _validate_namespace(event: CausalEvent, address: CellAddress) -> None:
        if event.address != address:
            raise NamespaceViolation("event namespace does not match the target stream")

    def read(
        self,
        address: CellAddress,
        *,
        from_sequence: int = 1,
        to_sequence: int | None = None,
    ) -> tuple[CausalEvent, ...]:
        if from_sequence < 1:
            raise ValueError("from_sequence must be positive")
        if to_sequence is not None and to_sequence < from_sequence:
            raise ValueError("to_sequence must be >= from_sequence")
        with self._lock:
            events = self._lineage(address)
            return tuple(
                event
                for event in events
                if event.sequence >= from_sequence
                and (to_sequence is None or event.sequence <= to_sequence)
            )

    def head(self, address: CellAddress) -> CausalEvent | None:
        with self._lock:
            events = self._lineage(address)
            return events[-1] if events else None

    def verify_chain(self, address: CellAddress) -> None:
        """Verify namespace, contiguous sequence, payload and hash links."""

        with self._lock:
            branch = self._branch(address)
            events = self._lineage(address)
            lineage_branches = self._lineage_branches(address)
            expected_prev = GENESIS_HASH
            expected_sequence = 1
            for event in events:
                if (
                    event.tenant_id != address.tenant_id
                    or event.cell_id != address.cell_id
                    or event.session_id != address.session_id
                ):
                    raise NamespaceViolation(
                        "event crosses tenant, cell or session boundary in a branch lineage"
                    )
                matching_branch = next(
                    (
                        candidate
                        for candidate in lineage_branches
                        if candidate.metadata.branch_id == event.branch_id
                        and candidate.metadata.capsule_digest == event.capsule_digest
                    ),
                    None,
                )
                if matching_branch is None:
                    raise NamespaceViolation("event does not belong to this branch lineage")
                event.verify_integrity()
                if event.sequence != expected_sequence:
                    raise ChainIntegrityError(
                        f"sequence gap in {address.stream_key}: expected {expected_sequence}, "
                        f"got {event.sequence}"
                    )
                if event.prev_hash != expected_prev:
                    raise ChainIntegrityError(
                        f"prev_hash mismatch at sequence {event.sequence} in {address.stream_key}"
                    )
                expected_prev = event.event_hash
                expected_sequence += 1

            if branch.metadata.parent_branch_id is not None:
                parent_address = branch.metadata.parent_address
                if parent_address is None:  # pragma: no cover - guarded above
                    raise ChainIntegrityError("branch parent metadata is incomplete")
                parent_events = self._lineage(parent_address)
                anchor = next(
                    (
                        event
                        for event in parent_events
                        if event.sequence == branch.metadata.fork_sequence
                    ),
                    None,
                )
                anchor_hash = anchor.event_hash if anchor is not None else GENESIS_HASH
                if anchor_hash != branch.metadata.base_hash:
                    raise ChainIntegrityError("branch base hash no longer matches its fork anchor")
                if branch.metadata.fork_sequence > len(parent_events):
                    raise ChainIntegrityError("branch fork sequence is outside the parent history")
            elif branch.metadata.base_hash != GENESIS_HASH or branch.metadata.fork_sequence != 0:
                raise ChainIntegrityError("root branch has an invalid genesis anchor")

            if branch.events:
                expected_branch_prev = branch.metadata.base_hash
                for event in branch.events:
                    if event.prev_hash != expected_branch_prev:
                        raise ChainIntegrityError("branch-local hash link is invalid")
                    expected_branch_prev = event.event_hash

    def _lineage_branches(self, address: CellAddress) -> tuple[_BranchState, ...]:
        branch = self._branch(address)
        parent_address = branch.metadata.parent_address
        if parent_address is None:
            return (branch,)
        return (*self._lineage_branches(parent_address), branch)

    def fork(
        self,
        address: CellAddress,
        from_sequence: int,
        *,
        new_branch_id: str,
        parent_branch_id: str | None = None,
        target_capsule_digest: str | None = None,
    ) -> EventBranch:
        """Create a child branch anchored at an exact parent sequence.

        The fork copies no events.  Its first append uses ``from_sequence + 1``
        and the parent's event hash as ``prev_hash``; replay walks the parent
        prefix and then the child events.
        """

        _require_identifier("new_branch_id", new_branch_id)
        if from_sequence < 0:
            raise InvalidBranch("from_sequence cannot be negative")
        with self._lock:
            parent = address.with_branch(parent_branch_id or address.branch_id)
            parent_events = self._lineage(parent)
            if from_sequence > len(parent_events):
                raise InvalidBranch("fork sequence is beyond the parent head")
            target_capsule = target_capsule_digest or address.capsule_digest
            _require_identifier("target_capsule_digest", target_capsule)
            target = CellAddress(
                tenant_id=address.tenant_id,
                cell_id=address.cell_id,
                session_id=address.session_id,
                capsule_digest=target_capsule,
                branch_id=new_branch_id,
            )
            branches = self._branches.setdefault(self._stream_key(target), {})
            self._ensure_root(parent)
            self._ensure_root(target)
            if new_branch_id in branches:
                raise InvalidBranch(f"branch {new_branch_id!r} already exists")
            anchor_hash = (
                parent_events[from_sequence - 1].event_hash if from_sequence else GENESIS_HASH
            )
            metadata = EventBranch(
                tenant_id=address.tenant_id,
                cell_id=address.cell_id,
                session_id=address.session_id,
                capsule_digest=target_capsule,
                branch_id=new_branch_id,
                parent_branch_id=parent.branch_id,
                fork_sequence=from_sequence,
                base_hash=anchor_hash,
                parent_capsule_digest=parent.capsule_digest,
            )
            branches[new_branch_id] = _BranchState(metadata=metadata)
            return metadata

    def create_branch(
        self,
        address: CellAddress,
        *,
        branch_id: str,
        fork_sequence: int,
        parent_branch_id: str | None = None,
        target_capsule_digest: str | None = None,
    ) -> EventBranch:
        """Named alias for :meth:`fork` used by control-plane callers."""

        return self.fork(
            address,
            fork_sequence,
            new_branch_id=branch_id,
            parent_branch_id=parent_branch_id,
            target_capsule_digest=target_capsule_digest,
        )

    # Async adapters -----------------------------------------------------

    async def append_async(self, draft: EventDraft | None = None, **kwargs: object) -> CausalEvent:
        return self.append(draft, **kwargs)

    async def read_async(
        self,
        address: CellAddress,
        *,
        from_sequence: int = 1,
        to_sequence: int | None = None,
    ) -> tuple[CausalEvent, ...]:
        return self.read(address, from_sequence=from_sequence, to_sequence=to_sequence)

    async def head_async(self, address: CellAddress) -> CausalEvent | None:
        return self.head(address)

    async def verify_chain_async(self, address: CellAddress) -> None:
        self.verify_chain(address)

    async def fork_async(
        self,
        address: CellAddress,
        from_sequence: int,
        *,
        new_branch_id: str,
        parent_branch_id: str | None = None,
        target_capsule_digest: str | None = None,
    ) -> EventBranch:
        return self.fork(
            address,
            from_sequence,
            new_branch_id=new_branch_id,
            parent_branch_id=parent_branch_id,
            target_capsule_digest=target_capsule_digest,
        )


__all__ = [
    "GENESIS_HASH",
    "AgentCellAddress",
    "AppendOnlyViolation",
    "BranchNotFound",
    "BranchView",
    "CausalEvent",
    "CausalEventDraft",
    "CellAddress",
    "CellKey",
    "ChainIntegrityError",
    "EventBranch",
    "EventDraft",
    "EventStore",
    "EventStoreError",
    "EventType",
    "InMemoryEventStore",
    "InvalidBranch",
    "JsonObject",
    "JsonValue",
    "NamespaceViolation",
]
