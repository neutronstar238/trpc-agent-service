"""PostgreSQL adapters for the causal Cell kernel.

The adapters deliberately use small, parameterised asyncpg statements rather
than leaking SQLAlchemy models into the Cell contracts.  Every mutating
operation runs in one transaction with ``app.tenant_id`` set locally.  Event
append and placement reservation lock their authoritative head/capacity row,
so a stale gateway snapshot cannot create a second sequence or oversell a node.

The module is optional at import time for the in-memory SDK: ``asyncpg`` is a
normal project dependency, but no connection is opened until an adapter method
is called.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import uuid
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import asyncpg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from trpc_service.cell.capsule import AgentCapsule
from trpc_service.cell.effects import (
    EffectClaim,
    EffectKeyConflict,
    EffectLeaseConflict,
    EffectReceipt,
    EffectStatus,
    _intent_fingerprint,
)
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
from trpc_service.cell.intents import PolicyDecision, ToolIntent
from trpc_service.cell.scheduler import (
    CellPlacementRequest,
    NodeSnapshot,
    PlacementCandidate,
    PlacementDecision,
    PlacementReservation,
    PlacementReservationStore,
    ReservationConflict,
)


class CompareAndSwapConflict(EventStoreError):
    """A caller supplied a stale sequence/hash/lease fence."""


class FencedLeaseError(EventStoreError):
    """A worker attempted a write after its branch lease was superseded."""


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _json_param(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _result_hash(value: object) -> str | None:
    if value is None:
        return None
    try:
        encoded = _json_param(value).encode("utf-8")
    except (TypeError, ValueError):
        encoded = repr(value).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class _TenantRepository:
    """Shared pool/transaction helpers used by all Cell repositories."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        if not callable(getattr(pool, "acquire", None)):
            raise TypeError("pool must expose asyncpg-compatible acquire()")
        self.pool = pool

    @asynccontextmanager
    async def _tenant_transaction(self, tenant_id: str) -> AsyncIterator[asyncpg.Connection]:
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute(
                    "SELECT set_config('app.tenant_id', $1, true)",
                    tenant_id,
                )
                yield connection


_EVENT_COLUMNS = """
    tenant_id, app_id, cell_id, session_id, capsule_digest, branch_id,
    sequence, event_id, event_type, payload, causation_id, correlation_id,
    trace_id, request_id, occurred_at, prev_hash, payload_hash, event_hash
"""


def _event_from_row(row: Mapping[str, object]) -> CausalEvent:
    data = dict(row)
    payload = data.get("payload")
    if isinstance(payload, str):
        try:
            data["payload"] = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ChainIntegrityError("stored event payload is not valid JSON") from exc
    occurred_at = data.get("occurred_at")
    if isinstance(occurred_at, datetime):
        data["occurred_at"] = _aware(occurred_at).isoformat()  # type: ignore[union-attr]
    return CausalEvent.from_dict(cast(Mapping[str, object], data))


def _branch_from_row(row: Mapping[str, object]) -> EventBranch:
    parent_branch_id = cast(str | None, row.get("parent_branch_id"))
    fork_sequence = cast(int | None, row.get("fork_sequence"))
    return EventBranch(
        tenant_id=cast(str, row["tenant_id"]),
        app_id=cast(str, row["app_id"]),
        cell_id=cast(str, row["cell_id"]),
        session_id=cast(str, row["session_id"]),
        capsule_digest=cast(str, row["capsule_digest"]),
        branch_id=cast(str, row["branch_id"]),
        parent_branch_id=parent_branch_id,
        fork_sequence=int(fork_sequence or 0),
        base_hash=cast(str, row.get("state_hash") or row.get("base_hash") or GENESIS_HASH),
        parent_capsule_digest=cast(str | None, row.get("parent_capsule_digest")),
        created_at=_aware(cast(datetime | None, row.get("created_at"))) or datetime.now(UTC),
    )


def _validate_capsule_registration(
    capsule: AgentCapsule,
    *,
    trusted_keys: Mapping[str, Ed25519PublicKey | bytes] | None = None,
    require_trusted_signature: bool = False,
) -> None:
    """Reject malformed direct registrations before the privileged SQL call.

    Runtime projections enforce structural integrity but are deliberately not
    scheduler-authorising.  Deployment registrations additionally require an
    explicit trust map and verify the Ed25519 signature here, before the
    privileged SQL boundary.
    """

    if not capsule.verify_digest():
        raise ValueError("capsule digest does not match its canonical manifest")
    capsule.spec.validate_asset_refs()
    if capsule.signature is None:
        raise ValueError("capsule signature is required for PostgreSQL registration")
    if require_trusted_signature:
        capsule.verify(trusted_keys)


class PostgresEventStore(_TenantRepository):
    """Atomic PostgreSQL implementation of the Cell ``EventStore`` contract.

    Construct with ``PostgresEventStore(pool)`` where ``pool`` is an
    ``asyncpg.Pool``.  The normal bridge sequence is:

    ``await store.ensure_capsule(...); await store.ensure_cell(address);``
    followed by ``await store.append(draft)``.  ``ensure_cell`` is idempotent;
    ``append`` is idempotent for the same tenant/event id and fenced by the
    branch head for all other writes.
    """

    @staticmethod
    async def _assert_session_fence(
        connection: asyncpg.Connection,
        address: CellAddress,
        *,
        owner: str,
        fencing_token: int,
    ) -> datetime:
        current = await connection.fetchrow(
            """
            SELECT lease_expires_at
              FROM public.sessions
             WHERE tenant_id=$1 AND session_id=$2 AND app_id=$5
               AND lease_owner=$3 AND lease_epoch=$4
               AND lease_expires_at > clock_timestamp()
             FOR UPDATE
            """,
            address.tenant_id,
            address.session_id,
            owner,
            fencing_token,
            address.app_id,
        )
        if current is None:
            raise FencedLeaseError("session lease is stale for Cell event append")
        expires_at = _aware(cast(datetime | None, current["lease_expires_at"]))
        if expires_at is None:
            raise FencedLeaseError("session lease expiry is missing for Cell event append")
        return expires_at

    async def ensure_capsule(
        self,
        tenant_id: str | AgentCapsule,
        capsule: AgentCapsule | None = None,
        *,
        trust_class: str = "deployment",
        trusted_keys: Mapping[str, Ed25519PublicKey | bytes] | None = None,
    ) -> str:
        """Persist a structurally valid Capsule through the 0018 functions.

        ``deployment`` admission is fail-closed: callers must provide the
        control-plane trust map so this process verifies the Ed25519 envelope.
        ``runtime_projection`` is non-authorising evidence and therefore only
        requires structural integrity.  Raw mappings are intentionally not
        accepted because they would bypass canonical digest verification.
        """

        if trust_class not in {"deployment", "runtime_projection"}:
            raise ValueError("capsule trust_class is invalid")
        digest: str | None = None
        if isinstance(tenant_id, AgentCapsule):
            if capsule is not None:
                raise TypeError("capsule must be omitted when tenant_id is an AgentCapsule")
            model = tenant_id
            _validate_capsule_registration(
                model,
                trusted_keys=trusted_keys,
                require_trusted_signature=trust_class == "deployment",
            )
            tenant = model.metadata.tenant_id
            manifest = model.model_dump(mode="json", by_alias=True)
            digest = model.digest or model.compute_digest()
            name = model.metadata.name
            envelope = model.signature
            signature = envelope.value if envelope is not None else None
            signer_key_id = envelope.key_id if envelope is not None else None
        else:
            tenant = tenant_id
            if capsule is None:
                raise TypeError("capsule manifest is required")
            if capsule.metadata.tenant_id != tenant:
                raise NamespaceViolation("capsule tenant does not match ensure_capsule tenant")
            _validate_capsule_registration(
                capsule,
                trusted_keys=trusted_keys,
                require_trusted_signature=trust_class == "deployment",
            )
            manifest = capsule.model_dump(mode="json", by_alias=True)
            digest = capsule.digest or capsule.compute_digest()
            name = capsule.metadata.name
            envelope = capsule.signature
            signature = envelope.value if envelope is not None else None
            signer_key_id = envelope.key_id if envelope is not None else None
        if not isinstance(tenant, str) or not tenant.strip():
            raise ValueError("tenant_id must be non-empty")
        if not isinstance(digest, str) or not _is_digest(digest):
            raise ValueError("capsule_digest must be sha256:<64 lowercase hex>")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("capsule_name must be non-empty")
        async with self._tenant_transaction(tenant) as connection:
            function_name = (
                "ensure_agent_capsule"
                if trust_class == "deployment"
                else "ensure_runtime_projection_capsule"
            )
            await connection.execute(
                f"SELECT public.{function_name}($1, $2, $3, $4::jsonb, $5, $6)",
                tenant,
                digest,
                name,
                _json_param(manifest),
                signature,
                signer_key_id,
            )
        return digest

    async def ensure_cell(
        self,
        address: CellAddress,
        *,
        status: str = "idle",
        branch: EventBranch | None = None,
        assigned_node_id: str | None = None,
        session_lease_owner: str | None = None,
        session_fencing_token: int | None = None,
    ) -> EventBranch:
        """Ensure a full Cell row and its branch head exist atomically."""

        if branch is not None and branch.address != address:
            raise NamespaceViolation("branch metadata does not match CellAddress")
        parent = branch.parent_address if branch is not None else None
        # 0017's root-row CHECK requires NULL fork_sequence; branch heads use
        # zero for the corresponding root cursor.
        fork_sequence = branch.fork_sequence if branch is not None else None
        base_hash = branch.base_hash if branch is not None else GENESIS_HASH
        parent_branch_id = parent.branch_id if parent is not None else None
        parent_capsule_digest = parent.capsule_digest if parent is not None else None
        if (session_lease_owner is None) != (session_fencing_token is None):
            raise ValueError("session lease owner and fencing token must be supplied together")
        if session_fencing_token is not None and (
            isinstance(session_fencing_token, bool) or session_fencing_token < 1
        ):
            raise ValueError("session fencing token must be a positive integer")
        async with self._tenant_transaction(address.tenant_id) as connection:
            if session_lease_owner is not None and session_fencing_token is not None:
                await self._assert_session_fence(
                    connection,
                    address,
                    owner=session_lease_owner,
                    fencing_token=session_fencing_token,
                )
            await connection.execute(
                """
                INSERT INTO agent_cells (
                    tenant_id, app_id, cell_id, session_id, capsule_digest, branch_id,
                    parent_branch_id, parent_capsule_digest, fork_sequence, status,
                    assigned_node_id, last_sequence, state_hash
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
                ON CONFLICT (
                    tenant_id, app_id, cell_id, session_id, capsule_digest, branch_id
                ) DO NOTHING
                """,
                address.tenant_id,
                address.app_id,
                address.cell_id,
                address.session_id,
                address.capsule_digest,
                address.branch_id,
                parent_branch_id,
                parent_capsule_digest,
                fork_sequence,
                status,
                assigned_node_id,
                fork_sequence or 0,
                base_hash,
            )
            stored = await connection.fetchrow(
                """
                SELECT parent_branch_id, parent_capsule_digest, fork_sequence
                  FROM agent_cells
                 WHERE tenant_id=$1 AND app_id=$2 AND cell_id=$3
                   AND session_id=$4 AND capsule_digest=$5 AND branch_id=$6
                """,
                address.tenant_id,
                address.app_id,
                address.cell_id,
                address.session_id,
                address.capsule_digest,
                address.branch_id,
            )
            if stored is None:
                raise EventStoreError("Cell row was not returned by ensure_cell")
            stored_map = cast(Mapping[str, object], dict(stored))
            stored_parent_branch = cast(str | None, stored_map.get("parent_branch_id"))
            stored_parent_capsule = cast(str | None, stored_map.get("parent_capsule_digest"))
            stored_fork = cast(int | None, stored_map.get("fork_sequence"))
            if (
                stored_parent_branch != parent_branch_id
                or stored_parent_capsule != parent_capsule_digest
                or stored_fork != fork_sequence
            ):
                raise NamespaceViolation("Cell branch metadata is immutable")
            await connection.execute(
                """
                INSERT INTO cell_branch_heads (
                    tenant_id, app_id, cell_id, session_id,
                    capsule_digest, branch_id, last_sequence, last_event_hash
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                ON CONFLICT (
                    tenant_id, app_id, cell_id, session_id, capsule_digest, branch_id
                ) DO NOTHING
                """,
                address.tenant_id,
                address.app_id,
                address.cell_id,
                address.session_id,
                address.capsule_digest,
                address.branch_id,
                fork_sequence or 0,
                base_hash,
            )
        if branch is not None:
            return branch
        return EventBranch(
            tenant_id=address.tenant_id,
            app_id=address.app_id,
            cell_id=address.cell_id,
            session_id=address.session_id,
            capsule_digest=address.capsule_digest,
            branch_id=address.branch_id,
            parent_branch_id=None,
            fork_sequence=0,
            base_hash=GENESIS_HASH,
        )

    async def _get_branch(
        self,
        connection: asyncpg.Connection,
        address: CellAddress,
    ) -> EventBranch:
        branch_query = """
            SELECT tenant_id, app_id, cell_id, session_id, capsule_digest,
                   branch_id, parent_branch_id, parent_capsule_digest,
                   fork_sequence, state_hash, created_at
              FROM agent_cells
             WHERE tenant_id=$1 AND app_id=$2 AND cell_id=$3
               AND session_id=$4 AND capsule_digest=$5 AND branch_id=$6
        """
        row = await connection.fetchrow(
            branch_query,
            address.tenant_id,
            address.app_id,
            address.cell_id,
            address.session_id,
            address.capsule_digest,
            address.branch_id,
        )
        if row is None:
            raise BranchNotFound(
                f"branch {address.branch_id!r} does not exist in tenant={address.tenant_id!r}"
            )
        data = dict(row)
        data["base_hash"] = data.get("state_hash") or GENESIS_HASH
        return _branch_from_row(cast(Mapping[str, object], data))

    @staticmethod
    async def _lock_branch_head(
        connection: asyncpg.Connection,
        address: CellAddress,
    ) -> Mapping[str, object]:
        """Lock and return a branch head through the tenant-bound SQL boundary.

        The Worker role intentionally has no ``UPDATE`` privilege on either
        the branch-head or Cell tables.  ``SELECT ... FOR UPDATE`` is therefore
        owned by the migration-provisioned ``SECURITY DEFINER`` function; the
        returned mapping is the only head snapshot the adapter consumes.
        """

        row = await connection.fetchrow(
            """
            SELECT last_sequence, last_event_hash,
                   lease_owner, lease_epoch, lease_expires_at, lease_valid
              FROM public.lock_cell_branch_head($1, $2, $3, $4, $5, $6)
            """,
            address.tenant_id,
            address.app_id,
            address.cell_id,
            address.session_id,
            address.capsule_digest,
            address.branch_id,
        )
        if row is None:
            raise BranchNotFound(f"branch {address.branch_id!r} has no branch head")
        return cast(Mapping[str, object], dict(row))

    async def append(
        self,
        draft: EventDraft | None = None,
        *,
        expected_sequence: int | None = None,
        expected_prev_hash: str | None = None,
        lease_epoch: int | None = None,
        lease_owner: str | None = None,
        lease_expires_at: datetime | None = None,
        session_lease_owner: str | None = None,
        session_fencing_token: int | None = None,
        **kwargs: object,
    ) -> CausalEvent:
        """Append with branch-head CAS and tenant-scoped idempotency."""

        if draft is not None and kwargs:
            raise TypeError("append accepts either a draft or keyword fields, not both")
        if draft is None:
            draft = EventDraft(**cast(dict[str, Any], kwargs))
        supplied = draft
        normalized = draft.normalised()
        address = normalized.address
        if (lease_owner is None) != (lease_epoch is None):
            raise ValueError("branch lease owner and epoch must be supplied together")
        if lease_epoch is not None and (isinstance(lease_epoch, bool) or lease_epoch < 1):
            raise ValueError("branch lease epoch must be a positive integer")
        if lease_expires_at is not None and not isinstance(lease_expires_at, datetime):
            raise ValueError("branch lease expiry must be a datetime")
        if lease_expires_at is not None and lease_owner is None:
            raise ValueError("branch lease expiry requires an owner and epoch")
        normalized_lease_expires_at = _aware(lease_expires_at)
        if (session_lease_owner is None) != (session_fencing_token is None):
            raise ValueError("session lease owner and fencing token must be supplied together")
        if session_fencing_token is not None and (
            isinstance(session_fencing_token, bool) or session_fencing_token < 1
        ):
            raise ValueError("session fencing token must be a positive integer")
        async with self._tenant_transaction(address.tenant_id) as connection:
            session_lease_expires_at: datetime | None = None
            if session_lease_owner is not None and session_fencing_token is not None:
                session_lease_expires_at = await self._assert_session_fence(
                    connection,
                    address,
                    owner=session_lease_owner,
                    fencing_token=session_fencing_token,
                )
                # The database trigger independently re-validates this
                # transaction-local proof before accepting a Worker event.
                # A bare INSERT with no proof therefore fails closed even if
                # application code accidentally bypasses this adapter.
                await connection.execute(
                    """
                    SELECT set_config('app.cell_session_lease_owner', $1, true),
                           set_config('app.cell_session_fencing_token', $2, true)
                    """,
                    session_lease_owner,
                    str(session_fencing_token),
                )
            if lease_owner is not None and lease_epoch is not None:
                # The branch proof is transaction-local and is independently
                # checked by guard_cell_event_append with clock_timestamp().
                # Empty expiry is retained only for legacy non-Worker calls;
                # a live Worker append is rejected by the trigger unless all
                # three branch values are present and match sessions.
                effective_lease_expires_at = session_lease_expires_at or normalized_lease_expires_at
                await connection.execute(
                    """
                    SELECT set_config('app.cell_branch_lease_owner', $1, true),
                           set_config('app.cell_branch_fencing_token', $2, true),
                           set_config('app.cell_branch_lease_expires_at', $3, true)
                    """,
                    lease_owner,
                    str(lease_epoch),
                    (
                        effective_lease_expires_at.isoformat()
                        if effective_lease_expires_at is not None
                        else ""
                    ),
                )
            if normalized.event_id is not None:
                existing_row = await connection.fetchrow(
                    f"SELECT {_EVENT_COLUMNS} FROM cell_events "  # noqa: S608
                    "WHERE tenant_id=$1 AND event_id=$2",
                    address.tenant_id,
                    normalized.event_id,
                )
                if existing_row is not None:
                    existing = _event_from_row(cast(Mapping[str, object], dict(existing_row)))
                    if existing.address != address:
                        raise NamespaceViolation(
                            f"event {normalized.event_id} belongs to another Cell namespace"
                        )
                    if not InMemoryEventStore._same_draft(existing, normalized, supplied=supplied):
                        raise AppendOnlyViolation(
                            f"event {normalized.event_id} is immutable and cannot be replaced"
                        )
                    return existing

            # ``trpc_worker`` deliberately has no UPDATE privilege on
            # ``cell_branch_heads``.  The tenant-bound SECURITY DEFINER
            # function owns the row lock and returns the CAS/fencing snapshot.
            head = await self._lock_branch_head(connection, address)
            last_sequence = int(cast(int, head["last_sequence"]))
            previous_hash = str(head["last_event_hash"])
            if expected_sequence is not None and expected_sequence != last_sequence:
                raise CompareAndSwapConflict(
                    f"expected sequence {expected_sequence}, current {last_sequence}"
                )
            if expected_prev_hash is not None and expected_prev_hash != previous_hash:
                raise CompareAndSwapConflict("expected previous hash does not match branch head")
            if lease_epoch is not None:
                head_epoch = int(cast(int, head["lease_epoch"]))
                head_owner = cast(str | None, head["lease_owner"])
                head_is_unleased = (
                    head_owner is None and head_epoch == 0 and head["lease_expires_at"] is None
                )
                if lease_owner is None or head_epoch > lease_epoch:
                    raise FencedLeaseError("branch lease epoch is stale")
                if (
                    not head_is_unleased
                    and head_epoch == lease_epoch
                    and head_owner is not None
                    and head_owner != lease_owner
                    and head["lease_valid"] is True
                ):
                    raise FencedLeaseError("branch lease owner is stale")
                if (
                    session_lease_owner is None
                    and not head_is_unleased
                    and head_epoch == lease_epoch
                    and head_owner == lease_owner
                    and head["lease_valid"] is not True
                ):
                    raise FencedLeaseError("branch lease has expired")

            # A causation id is tenant-scoped, but a child branch may validly
            # point at an event in its visible parent prefix (including a
            # parent using a different capsule digest).  Reject only a known
            # same-tenant id that is outside this branch's lineage; unknown
            # ids remain forward-reference compatible with the in-memory
            # contract.
            if normalized.causation_id is not None:
                cause_exists = await connection.fetchval(
                    """
                    SELECT 1 FROM cell_events
                     WHERE tenant_id=$1 AND event_id=$2
                    """,
                    address.tenant_id,
                    normalized.causation_id,
                )
                if cause_exists:
                    visible_event_ids = {
                        event.event_id for event in await self._read_lineage(connection, address)
                    }
                    if normalized.causation_id not in visible_event_ids:
                        raise NamespaceViolation(
                            f"causation event {normalized.causation_id} crosses the Cell namespace"
                        )

            event = InMemoryEventStore._build_event(
                normalized,
                sequence=last_sequence + 1,
                prev_hash=previous_hash,
            )
            inserted = await connection.fetchrow(
                f"""
                INSERT INTO cell_events ({_EVENT_COLUMNS})
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,
                        $15,$16,$17,$18)
                ON CONFLICT (tenant_id, event_id) DO NOTHING
                RETURNING {_EVENT_COLUMNS}
                """,  # noqa: S608 - _EVENT_COLUMNS is a private fixed SQL projection
                event.tenant_id,
                event.app_id,
                event.cell_id,
                event.session_id,
                event.capsule_digest,
                event.branch_id,
                event.sequence,
                event.event_id,
                event.event_type,
                _json_param(event.payload),
                event.causation_id,
                event.correlation_id,
                event.trace_id,
                event.request_id,
                event.occurred_at,
                event.prev_hash,
                event.payload_hash,
                event.event_hash,
            )
            if inserted is None:
                existing_row = await connection.fetchrow(
                    f"SELECT {_EVENT_COLUMNS} FROM cell_events "  # noqa: S608
                    "WHERE tenant_id=$1 AND event_id=$2",
                    address.tenant_id,
                    event.event_id,
                )
                if existing_row is None:
                    raise CompareAndSwapConflict("event sequence was concurrently claimed")
                existing = _event_from_row(cast(Mapping[str, object], dict(existing_row)))
                if existing.address != address:
                    raise NamespaceViolation("event id belongs to another Cell namespace")
                if not InMemoryEventStore._same_draft(existing, normalized, supplied=supplied):
                    raise AppendOnlyViolation("event id is immutable and cannot be replaced")
                return existing
            # 0018's AFTER INSERT trigger advances both cell_branch_heads and
            # agent_cells in the same transaction.  Keeping that write in the
            # database authority also closes the bare-INSERT/stale-head gap.
            return event

    async def _read_lineage(
        self,
        connection: asyncpg.Connection,
        address: CellAddress,
        *,
        limit_sequence: int | None = None,
        _visited: frozenset[tuple[str, str, str, str, str, str]] | None = None,
    ) -> tuple[CausalEvent, ...]:
        if _visited is None:
            _visited = frozenset()
        if address.stream_key in _visited:
            raise NamespaceViolation("Cell branch lineage contains a cycle")
        if len(_visited) >= 128:
            raise EventStoreError("Cell branch lineage exceeds the maximum depth")
        visited = _visited | {address.stream_key}
        branch = await self._get_branch(connection, address)
        parent = branch.parent_address
        events: list[CausalEvent] = []
        if parent is not None:
            parent_limit = branch.fork_sequence
            if limit_sequence is not None:
                parent_limit = min(parent_limit, limit_sequence)
            if parent_limit > 0:
                events.extend(
                    await self._read_lineage(
                        connection,
                        parent,
                        limit_sequence=parent_limit,
                        _visited=visited,
                    )
                )
        local_limit = limit_sequence
        query = f"SELECT {_EVENT_COLUMNS} FROM cell_events WHERE "  # noqa: S608
        query += (
            "tenant_id=$1 AND app_id=$2 AND cell_id=$3 AND session_id=$4 "
            "AND capsule_digest=$5 AND branch_id=$6 AND sequence > $7"
        )
        args: list[object] = [
            address.tenant_id,
            address.app_id,
            address.cell_id,
            address.session_id,
            address.capsule_digest,
            address.branch_id,
            branch.fork_sequence,
        ]
        if local_limit is not None:
            query += " AND sequence <= $8"
            args.append(local_limit)
        query += " ORDER BY sequence"
        rows = await connection.fetch(query, *args)
        events.extend(_event_from_row(cast(Mapping[str, object], dict(row))) for row in rows)
        return tuple(events)

    async def read(
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
        async with self._tenant_transaction(address.tenant_id) as connection:
            events = await self._read_lineage(connection, address, limit_sequence=to_sequence)
        return tuple(event for event in events if event.sequence >= from_sequence)

    async def find_latest_by_correlation(
        self,
        tenant_id: str,
        correlation_id: str,
        *,
        event_type: str,
    ) -> CausalEvent | None:
        """Find a tenant-scoped projection anchor for durable reconciliation."""

        if not tenant_id or not correlation_id or not event_type:
            raise ValueError("tenant, correlation_id, and event_type must be non-empty")
        async with self._tenant_transaction(tenant_id) as connection:
            row = await connection.fetchrow(
                f"SELECT {_EVENT_COLUMNS} FROM cell_events "  # noqa: S608
                "WHERE tenant_id=$1 AND correlation_id=$2 AND event_type=$3 "
                "ORDER BY occurred_at DESC, sequence DESC LIMIT 1",
                tenant_id,
                correlation_id,
                event_type,
            )
        return _event_from_row(cast(Mapping[str, object], dict(row))) if row is not None else None

    async def find_unprojected_terminal_effects(
        self,
        tenant_id: str,
        correlation_id: str,
    ) -> tuple[Mapping[str, object], ...]:
        """Return content-free legacy effect facts missing from the Cell log."""

        if not tenant_id or not correlation_id:
            raise ValueError("tenant and correlation_id must be non-empty")
        async with self._tenant_transaction(tenant_id) as connection:
            rows = await connection.fetch(
                """
                SELECT intent.tenant_id, intent.app_id, intent.cell_id,
                       intent.session_id, intent.capsule_digest, intent.branch_id,
                       intent.event_id AS intent_event_id,
                       intent.trace_id, intent.request_id, intent.correlation_id,
                       execution.execution_key AS effect_key,
                       execution.tool_name, execution.status, execution.error_type
                  FROM cell_events AS intent
                  JOIN tool_executions AS execution
                    ON execution.tenant_id = intent.tenant_id
                   AND execution.execution_key = intent.payload->>'effect_key'
                 WHERE intent.tenant_id=$1
                   AND intent.correlation_id=$2
                   AND intent.event_type='tool.intent.created'
                   AND execution.status IN ('succeeded','failed','ambiguous')
                   AND NOT EXISTS (
                       SELECT 1
                         FROM cell_events AS projected
                         WHERE projected.tenant_id = intent.tenant_id
                           AND projected.app_id = intent.app_id
                           AND projected.cell_id = intent.cell_id
                           AND projected.session_id = intent.session_id
                           AND projected.capsule_digest = intent.capsule_digest
                           AND projected.branch_id = intent.branch_id
                           AND projected.correlation_id = intent.correlation_id
                          AND projected.event_type LIKE 'tool.effect.%'
                          AND projected.payload->>'effect_key' = execution.execution_key
                   )
                 ORDER BY intent.sequence
                """,
                tenant_id,
                correlation_id,
            )
        return tuple(cast(Mapping[str, object], dict(row)) for row in rows)

    async def head(self, address: CellAddress) -> CausalEvent | None:
        events = await self.read(address)
        return events[-1] if events else None

    async def verify_chain(self, address: CellAddress) -> None:
        async with self._tenant_transaction(address.tenant_id) as connection:
            branch = await self._get_branch(connection, address)
            events = await self._read_lineage(connection, address)
            expected_sequence = 1
            expected_prev = GENESIS_HASH
            for event in events:
                if (
                    event.address.tenant_id != address.tenant_id
                    or event.address.app_id != address.app_id
                ):
                    raise NamespaceViolation("event crosses tenant/app namespace")
                if (
                    event.address.cell_id != address.cell_id
                    or event.address.session_id != address.session_id
                ):
                    raise NamespaceViolation("event crosses Cell/session namespace")
                event.verify_integrity()
                if event.sequence != expected_sequence:
                    raise ChainIntegrityError("event sequence is not contiguous")
                if event.prev_hash != expected_prev:
                    raise ChainIntegrityError("event hash chain link is invalid")
                expected_sequence += 1
                expected_prev = event.event_hash
            if branch.parent_branch_id is None:
                if branch.fork_sequence != 0 or branch.base_hash != GENESIS_HASH:
                    raise ChainIntegrityError("root branch has an invalid genesis anchor")
            else:
                parent = branch.parent_address
                if parent is None:
                    raise ChainIntegrityError("branch parent metadata is incomplete")
                parent_events = await self._read_lineage(connection, parent)
                if branch.fork_sequence > len(parent_events):
                    raise ChainIntegrityError("branch fork sequence is outside the parent history")
                anchor = (
                    parent_events[branch.fork_sequence - 1].event_hash
                    if branch.fork_sequence
                    else GENESIS_HASH
                )
                if anchor != branch.base_hash:
                    raise ChainIntegrityError("branch base hash no longer matches fork anchor")

    async def fork(
        self,
        address: CellAddress,
        from_sequence: int,
        *,
        new_branch_id: str,
        parent_branch_id: str | None = None,
        target_capsule_digest: str | None = None,
    ) -> EventBranch:
        if not isinstance(new_branch_id, str) or not new_branch_id.strip():
            raise InvalidBranch("new_branch_id must be non-empty")
        if from_sequence < 0:
            raise InvalidBranch("from_sequence cannot be negative")
        parent = address.with_branch(parent_branch_id or address.branch_id)
        target_capsule = target_capsule_digest or address.capsule_digest
        if not isinstance(target_capsule, str) or not target_capsule.strip():
            raise InvalidBranch("target_capsule_digest must be non-empty")
        target = CellAddress(
            tenant_id=address.tenant_id,
            app_id=address.app_id,
            cell_id=address.cell_id,
            session_id=address.session_id,
            capsule_digest=target_capsule,
            branch_id=new_branch_id,
        )
        async with self._tenant_transaction(address.tenant_id) as connection:
            # Serialize the fork point on the authoritative head row.  The
            # Worker role cannot lock ``agent_cells`` directly because it has
            # no UPDATE privilege there; branch metadata is read after the
            # head lock through the ordinary tenant-scoped SELECT path.
            await self._lock_branch_head(connection, parent)
            parent_branch = await self._get_branch(connection, parent)
            parent_events = await self._read_lineage(connection, parent)
            if from_sequence > len(parent_events):
                raise InvalidBranch("fork sequence is beyond the parent head")
            if await connection.fetchval(
                """
                SELECT 1 FROM agent_cells
                 WHERE tenant_id=$1 AND app_id=$2 AND cell_id=$3
                   AND session_id=$4 AND capsule_digest=$5 AND branch_id=$6
                """,
                target.tenant_id,
                target.app_id,
                target.cell_id,
                target.session_id,
                target.capsule_digest,
                target.branch_id,
            ):
                raise InvalidBranch(f"branch {new_branch_id!r} already exists")
            if not await connection.fetchval(
                "SELECT 1 FROM agent_capsules WHERE tenant_id=$1 AND capsule_digest=$2",
                target.tenant_id,
                target.capsule_digest,
            ):
                raise InvalidBranch("target capsule is not registered for this tenant")
            anchor_hash = (
                parent_events[from_sequence - 1].event_hash if from_sequence else GENESIS_HASH
            )
            await connection.execute(
                """
                INSERT INTO agent_cells (
                    tenant_id, app_id, cell_id, session_id, capsule_digest, branch_id,
                    parent_branch_id, parent_capsule_digest, fork_sequence,
                    status, last_sequence, state_hash
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'idle',$9,$10)
                """,
                target.tenant_id,
                target.app_id,
                target.cell_id,
                target.session_id,
                target.capsule_digest,
                target.branch_id,
                parent_branch.branch_id,
                parent_branch.capsule_digest,
                from_sequence,
                anchor_hash,
            )
            await connection.execute(
                """
                INSERT INTO cell_branch_heads (
                    tenant_id, app_id, cell_id, session_id,
                    capsule_digest, branch_id, last_sequence, last_event_hash
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                """,
                target.tenant_id,
                target.app_id,
                target.cell_id,
                target.session_id,
                target.capsule_digest,
                target.branch_id,
                from_sequence,
                anchor_hash,
            )
        return EventBranch(
            tenant_id=target.tenant_id,
            app_id=target.app_id,
            cell_id=target.cell_id,
            session_id=target.session_id,
            capsule_digest=target.capsule_digest,
            branch_id=target.branch_id,
            parent_branch_id=parent_branch.branch_id,
            fork_sequence=from_sequence,
            base_hash=anchor_hash,
            parent_capsule_digest=parent_branch.capsule_digest,
        )

    async def get_branch(self, address: CellAddress) -> EventBranch:
        async with self._tenant_transaction(address.tenant_id) as connection:
            return await self._get_branch(connection, address)

    async def branches(self, address: CellAddress) -> tuple[EventBranch, ...]:
        async with self._tenant_transaction(address.tenant_id) as connection:
            rows = await connection.fetch(
                """
                SELECT tenant_id, app_id, cell_id, session_id, capsule_digest,
                       branch_id, parent_branch_id, parent_capsule_digest,
                       fork_sequence, state_hash, created_at
                  FROM agent_cells
                 WHERE tenant_id=$1 AND app_id=$2 AND cell_id=$3
                   AND session_id=$4 AND capsule_digest=$5
                 ORDER BY branch_id
                """,
                address.tenant_id,
                address.app_id,
                address.cell_id,
                address.session_id,
                address.capsule_digest,
            )
        return tuple(_branch_from_row(cast(Mapping[str, object], dict(row))) for row in rows)

    # InMemory-compatible async method names used by existing bridge code.
    append_async = append
    read_async = read
    head_async = head
    verify_chain_async = verify_chain
    fork_async = fork


def _is_digest(value: str) -> bool:
    return (
        len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


_LEDGER_COLUMNS = """
    effect_key, intent_id, status, attempt, lease_owner, lease_epoch,
    lease_expires_at, updated_at, tenant_id, app_id, cell_id, session_id,
    capsule_digest, branch_id
"""


def _receipt_from_row(
    row: Mapping[str, object],
    *,
    intent: ToolIntent | None = None,
) -> EffectReceipt:
    status = EffectStatus(cast(str, row["status"]))
    completed_at = _aware(cast(datetime | None, row.get("completed_at")))
    updated_at = _aware(cast(datetime | None, row.get("updated_at"))) or datetime.now(UTC)
    attempted_at = _aware(cast(datetime | None, row.get("attempted_at")))
    attempt = cast(int | None, row.get("attempt")) or 0
    return EffectReceipt(
        effect_key=cast(str, row["effect_key"]),
        intent_id=cast(str, row.get("intent_id") or ""),
        status=status,
        attempt=attempt,
        replayed=attempt > 1,
        # Cell receipts are content-free.  Callers may keep the immediate
        # result in memory, but a later read can recover only its hash.
        result=None,
        error_type=cast(str | None, row.get("error_type")),
        worker_id=cast(str | None, row.get("lease_owner") or row.get("worker_id")),
        trace_id=intent.trace_id if intent is not None else cast(str | None, row.get("trace_id")),
        intent_fingerprint=_intent_fingerprint(intent) if intent is not None else "",
        started_at=updated_at,
        completed_at=completed_at or (attempted_at if status.terminal else None),
        lease_expires_at=_aware(cast(datetime | None, row.get("lease_expires_at"))),
    )


class PostgresEffectLedger(_TenantRepository):
    """Fenced, tenant-scoped implementation of ``EffectLedger``.

    The first ``tool.intent.created`` event for an intent supplies the event
    FK/complete Cell namespace.  This intentionally rejects an effect that
    was not journaled first; it prevents a worker from creating an orphan
    side-effect row outside the causal log.
    """

    def __init__(self, pool: asyncpg.Pool, *, tenant_id: str | None = None) -> None:
        super().__init__(pool)
        if tenant_id is not None and (not isinstance(tenant_id, str) or not tenant_id.strip()):
            raise ValueError("tenant_id must be non-empty when provided")
        self.tenant_id = tenant_id

    def _assert_tenant(self, tenant_id: str) -> str:
        if self.tenant_id is not None and tenant_id != self.tenant_id:
            raise NamespaceViolation("effect ledger tenant does not match its adapter scope")
        return self.tenant_id or tenant_id

    async def _ensure_intent(
        self,
        connection: asyncpg.Connection,
        intent: ToolIntent,
    ) -> Mapping[str, object]:
        self._assert_tenant(intent.tenant_id)
        try:
            intent.validate_integrity()
        except ValueError as exc:
            raise EffectKeyConflict("intent integrity validation failed") from exc
        event = await connection.fetchrow(
            """
            SELECT tenant_id, app_id, cell_id, session_id,
                   capsule_digest, branch_id, sequence, event_id, payload
              FROM cell_events
             WHERE tenant_id=$1
               AND event_type='tool.intent.created'
               AND payload->>'intent_id'=$2
             ORDER BY sequence DESC
             LIMIT 1
            """,
            intent.tenant_id,
            intent.intent_id,
        )
        if event is None:
            raise EffectKeyConflict("tool intent must be journaled before effect claim")
        namespace = cast(Mapping[str, object], dict(event))
        if (
            namespace["app_id"] != intent.app_id
            or namespace["cell_id"] != intent.cell_id
            or namespace["session_id"] != intent.session_id
            or namespace["branch_id"] != intent.branch_id
            or (
                intent.capsule_digest is not None
                and namespace["capsule_digest"] != intent.capsule_digest
            )
        ):
            raise NamespaceViolation("effect intent does not match its causal event namespace")
        raw_payload = namespace.get("payload")
        if isinstance(raw_payload, str):
            try:
                raw_payload = json.loads(raw_payload)
            except json.JSONDecodeError as exc:
                raise EffectKeyConflict("causal intent payload is not valid JSON") from exc
        if not isinstance(raw_payload, Mapping):
            raise EffectKeyConflict("causal intent payload is not an object")
        payload = cast(Mapping[str, object], raw_payload)
        expected_event_payload = {
            "intent_id": intent.intent_id,
            "tool_name": intent.tool_name,
            "arguments_hash": intent.arguments_hash,
            "effect_key": intent.effect_key,
            "risk": str(intent.risk),
        }
        if any(payload.get(key) != value for key, value in expected_event_payload.items()):
            raise EffectKeyConflict("tool intent does not match its causal event payload")
        policy_recorded = await connection.fetchval(
            """
            SELECT 1
              FROM cell_events
             WHERE tenant_id=$1 AND app_id=$2 AND cell_id=$3
               AND session_id=$4 AND capsule_digest=$5 AND branch_id=$6
               AND event_type='policy.decided' AND causation_id=$7
               AND payload->>'intent_id'=$8
               AND payload->>'decision'=$9
             LIMIT 1
            """,
            intent.tenant_id,
            intent.app_id,
            intent.cell_id,
            intent.session_id,
            namespace["capsule_digest"],
            intent.branch_id,
            namespace["event_id"],
            intent.intent_id,
            str(intent.policy_decision),
        )
        if not policy_recorded:
            raise EffectKeyConflict("tool intent has no matching causal policy decision")
        existing = await connection.fetchrow(
            """
            SELECT tenant_id, app_id, cell_id, session_id,
                   capsule_digest, branch_id, sequence, intent_id,
                   tool_name, arguments_hash, effect_key, risk, decision
              FROM cell_tool_intents
             WHERE tenant_id=$1 AND intent_id=$2
            """,
            intent.tenant_id,
            intent.intent_id,
        )
        if existing is None:
            await connection.execute(
                """
                INSERT INTO cell_tool_intents (
                    tenant_id, intent_id, app_id, cell_id, session_id,
                    capsule_digest, branch_id, sequence, tool_name,
                    arguments_hash, effect_key, risk, decision
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
                ON CONFLICT (tenant_id, intent_id) DO NOTHING
                """,
                intent.tenant_id,
                intent.intent_id,
                namespace["app_id"],
                intent.cell_id,
                intent.session_id,
                namespace["capsule_digest"],
                intent.branch_id,
                namespace["sequence"],
                intent.tool_name,
                intent.arguments_hash,
                intent.effect_key,
                str(intent.risk),
                str(intent.policy_decision),
            )
            existing = await connection.fetchrow(
                """
                SELECT tenant_id, app_id, cell_id, session_id,
                       capsule_digest, branch_id, sequence, intent_id,
                       tool_name, arguments_hash, effect_key, risk, decision
                  FROM cell_tool_intents
                 WHERE tenant_id=$1 AND intent_id=$2
                """,
                intent.tenant_id,
                intent.intent_id,
            )
        if existing is None:
            raise EffectKeyConflict("effect intent could not be persisted")
        existing_map = cast(Mapping[str, object], dict(existing))
        expected = {
            "app_id": namespace["app_id"],
            "cell_id": intent.cell_id,
            "session_id": intent.session_id,
            "capsule_digest": namespace["capsule_digest"],
            "branch_id": intent.branch_id,
            "tool_name": intent.tool_name,
            "arguments_hash": intent.arguments_hash,
            "effect_key": intent.effect_key,
            "risk": str(intent.risk),
            "decision": str(intent.policy_decision),
        }
        if any(existing_map.get(key) != value for key, value in expected.items()):
            raise EffectKeyConflict("intent id is already bound to different immutable content")
        return existing_map

    async def _get_ledger(
        self,
        connection: asyncpg.Connection,
        effect_key: str,
        *,
        for_update: bool = False,
    ) -> Mapping[str, object] | None:
        row = await connection.fetchrow(
            f"SELECT {_LEDGER_COLUMNS} FROM cell_effect_ledger "  # noqa: S608
            "WHERE tenant_id = current_setting('app.tenant_id', true) "
            "AND effect_key=$1" + (" FOR UPDATE" if for_update else ""),
            effect_key,
        )
        return cast(Mapping[str, object] | None, dict(row) if row is not None else None)

    async def _ensure_ledger_placeholder(
        self,
        connection: asyncpg.Connection,
        intent: ToolIntent,
    ) -> None:
        """Create the immutable-key row before attempting to claim it.

        The insert is intentionally ``DO NOTHING``.  A claim must first make
        the row visible and then lock that row with ``FOR UPDATE``; using an
        upsert that also writes the running state would let a racing worker
        overwrite a policy or terminal decision after the unique-key wait.
        """

        await connection.execute(
            """
            INSERT INTO cell_effect_ledger (
                tenant_id, effect_key, intent_id, app_id, cell_id,
                session_id, capsule_digest, branch_id, status, attempt,
                lease_owner, lease_epoch, lease_expires_at, updated_at
            )
            SELECT tenant_id, effect_key, intent_id, app_id, cell_id,
                   session_id, capsule_digest, branch_id, 'pending', 0,
                   NULL, 0, NULL, clock_timestamp()
              FROM cell_tool_intents
             WHERE tenant_id=$1 AND effect_key=$2
            ON CONFLICT (tenant_id, effect_key) DO NOTHING
            """,
            intent.tenant_id,
            intent.effect_key,
        )

    async def _with_latest_receipt(
        self,
        connection: asyncpg.Connection,
        row: Mapping[str, object],
        *,
        intent: ToolIntent | None = None,
    ) -> EffectReceipt:
        receipt = await connection.fetchrow(
            """
             SELECT result_hash, error_type, attempted_at, trace_id,
                    provider_reference AS worker_id
               FROM cell_effect_receipts
              WHERE tenant_id=$1 AND effect_key=$2 AND attempt=$3
              ORDER BY attempt DESC, attempted_at DESC
             LIMIT 1
             """,
            row["tenant_id"],
            row["effect_key"],
            int(cast(int | None, row.get("attempt")) or 0),
        )
        merged = dict(row)
        if receipt is not None:
            merged.update(dict(receipt))
        return _receipt_from_row(cast(Mapping[str, object], merged), intent=intent)

    async def get(self, effect_key: str) -> EffectReceipt | None:
        if self.tenant_id is None:
            raise ValueError("tenant_id is required for tenant-scoped effect get")
        async with self._tenant_transaction(self.tenant_id) as connection:
            row = await connection.fetchrow(
                f"SELECT {_LEDGER_COLUMNS} FROM cell_effect_ledger "  # noqa: S608
                "WHERE tenant_id=$1 AND effect_key=$2",
                self.tenant_id,
                effect_key,
            )
            if row is None:
                return None
            return await self._with_latest_receipt(connection, dict(row))

    async def claim(
        self,
        intent: ToolIntent,
        *,
        manual_replay: bool = False,
        confirmation_valid: bool = False,
        lease_seconds: float = 60.0,
        worker_id: str | None = None,
    ) -> EffectClaim:
        tenant_id = self._assert_tenant(intent.tenant_id)
        if intent.policy_decision in {PolicyDecision.DENY, PolicyDecision.SIMULATE_ONLY}:
            raise EffectLeaseConflict("effect policy does not authorize execution")
        if intent.policy_decision == PolicyDecision.REQUIRE_CONFIRMATION and not confirmation_valid:
            raise EffectLeaseConflict("effect claim requires validated confirmation")
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, (int, float))
            or not math.isfinite(lease_seconds)
            or lease_seconds <= 0
        ):
            raise ValueError("effect lease must be positive")
        owner = worker_id or "cell-effect-worker"
        async with self._tenant_transaction(tenant_id) as connection:
            await self._ensure_intent(connection, intent)
            # Establish the unique row first.  The subsequent row lock is the
            # serialization point for a first claim racing with another
            # worker (or with policy recording).
            await self._ensure_ledger_placeholder(connection, intent)
            row = await self._get_ledger(connection, intent.effect_key, for_update=True)
            if row is None:
                raise EffectKeyConflict("effect ledger row was not created")
            previous_attempt = int(cast(int | None, row.get("attempt")) or 0)
            database_now = await connection.fetchval("SELECT clock_timestamp()")
            now = _aware(cast(datetime | None, database_now))
            if now is None:
                raise EffectLeaseConflict("database did not return an effect lease clock")
            current = await self._with_latest_receipt(connection, row, intent=intent)
            if current.status == EffectStatus.RUNNING:
                if current.lease_expires_at is not None and current.lease_expires_at <= now:
                    await self._write_receipt(
                        connection,
                        intent,
                        status=EffectStatus.AMBIGUOUS,
                        attempt=current.attempt,
                        worker_id=owner,
                        error_type="effect_lease_expired",
                    )
                    await connection.execute(
                        """
                        UPDATE cell_effect_ledger
                           SET status='ambiguous', lease_owner=NULL,
                               lease_expires_at=NULL, updated_at=clock_timestamp()
                         WHERE tenant_id=$1 AND effect_key=$2
                        """,
                        intent.tenant_id,
                        intent.effect_key,
                    )
                    ambiguous = await self._get_ledger(connection, intent.effect_key)
                    assert ambiguous is not None
                    return EffectClaim(
                        await self._with_latest_receipt(connection, ambiguous, intent=intent),
                        False,
                    )
                return EffectClaim(current, False)
            if current.status in {
                EffectStatus.SUCCEEDED,
                EffectStatus.SIMULATED,
                EffectStatus.DENIED,
            }:
                return EffectClaim(current, False)
            if current.status == EffectStatus.REQUIRE_CONFIRMATION and not confirmation_valid:
                return EffectClaim(current, False)
            if current.status in {EffectStatus.AMBIGUOUS, EffectStatus.UNKNOWN} and (
                not manual_replay or not confirmation_valid
            ):
                return EffectClaim(current, False)
            attempt = current.attempt + 1
            expires_at = now + timedelta(seconds=lease_seconds)
            await connection.execute(
                """
                UPDATE cell_effect_ledger
                   SET status='running', attempt=$3,
                       lease_owner=$4, lease_epoch=lease_epoch + 1,
                       lease_expires_at=$5, updated_at=clock_timestamp()
                 WHERE tenant_id=$1 AND effect_key=$2
                   AND attempt=$6 AND status IN (
                       'pending', 'failed', 'require_confirmation',
                       'ambiguous', 'unknown'
                   )
                """,
                intent.tenant_id,
                intent.effect_key,
                attempt,
                owner,
                expires_at,
                previous_attempt,
            )
            running_row = await self._get_ledger(connection, intent.effect_key)
            if (
                running_row is None
                or running_row.get("status") != EffectStatus.RUNNING.value
                or running_row.get("attempt") != attempt
                or running_row.get("lease_owner") != owner
            ):
                raise EffectLeaseConflict("effect claim changed before acquisition")
            running = await self._with_latest_receipt(connection, running_row, intent=intent)
            return EffectClaim(running, True)

    async def _write_receipt(
        self,
        connection: asyncpg.Connection,
        intent: ToolIntent,
        *,
        status: EffectStatus,
        attempt: int,
        worker_id: str | None = None,
        result: object = None,
        error_type: str | None = None,
        lease_expires_at: datetime | None = None,
    ) -> None:
        namespace = await connection.fetchrow(
            """
            SELECT app_id, cell_id, session_id, capsule_digest, branch_id
              FROM cell_tool_intents
             WHERE tenant_id=$1 AND intent_id=$2
            """,
            intent.tenant_id,
            intent.intent_id,
        )
        if namespace is None:
            raise EffectKeyConflict("cannot write receipt for an unknown intent")
        await connection.execute(
            """
            INSERT INTO cell_effect_receipts (
                tenant_id, intent_id, effect_key, app_id, cell_id,
                session_id, capsule_digest, branch_id, attempt, status,
                result_hash, error_type, trace_id, provider_reference
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14
            )
            ON CONFLICT (tenant_id, effect_key, attempt) DO NOTHING
            """,
            intent.tenant_id,
            intent.intent_id,
            intent.effect_key,
            namespace["app_id"],
            namespace["cell_id"],
            namespace["session_id"],
            namespace["capsule_digest"],
            namespace["branch_id"],
            attempt,
            status.value,
            _result_hash(result),
            error_type,
            intent.trace_id,
            worker_id,
        )

    async def record_policy(
        self,
        intent: ToolIntent,
        *,
        status: EffectStatus,
        error_type: str | None = None,
        worker_id: str | None = None,
    ) -> EffectReceipt:
        tenant_id = self._assert_tenant(intent.tenant_id)
        if not worker_id:
            raise ValueError("worker_id is required for PostgreSQL policy recording")
        if status not in {
            EffectStatus.DENIED,
            EffectStatus.SIMULATED,
            EffectStatus.REQUIRE_CONFIRMATION,
        }:
            raise ValueError("policy records must be denied, simulated, or confirmation-required")
        decision = intent.policy_decision
        if decision is None:
            raise ValueError("policy status does not match intent policy decision")
        expected_status = {
            PolicyDecision.DENY: EffectStatus.DENIED,
            PolicyDecision.SIMULATE_ONLY: EffectStatus.SIMULATED,
            PolicyDecision.REQUIRE_CONFIRMATION: EffectStatus.REQUIRE_CONFIRMATION,
        }.get(PolicyDecision.parse(decision))
        if expected_status is None or status is not expected_status:
            raise ValueError("policy status does not match intent policy decision")
        async with self._tenant_transaction(tenant_id) as connection:
            await self._ensure_intent(connection, intent)
            # Share the placeholder/lock protocol with claim so a policy
            # decision cannot race a first worker into a unique-key error.
            await self._ensure_ledger_placeholder(connection, intent)
            current = await self._get_ledger(connection, intent.effect_key, for_update=True)
            if current is None:
                raise EffectKeyConflict("policy ledger row was not created")
            if current.get("status") == EffectStatus.PENDING.value and current.get("attempt") == 0:
                await connection.execute(
                    """
                    UPDATE cell_effect_ledger
                       SET status=$3, lease_owner=NULL, lease_epoch=0,
                           lease_expires_at=NULL, updated_at=clock_timestamp()
                     WHERE tenant_id=$1 AND effect_key=$2
                       AND status='pending' AND attempt=0
                    """,
                    intent.tenant_id,
                    intent.effect_key,
                    status.value,
                )
                await self._write_receipt(
                    connection,
                    intent,
                    status=status,
                    attempt=0,
                    worker_id=worker_id,
                    error_type=error_type,
                )
                current = await self._get_ledger(connection, intent.effect_key)
                if current is None:
                    raise EffectKeyConflict("policy ledger row disappeared")
            return await self._with_latest_receipt(connection, current, intent=intent)

    async def complete(
        self,
        intent: ToolIntent,
        *,
        attempt: int,
        status: EffectStatus,
        result: Any = None,
        error_type: str | None = None,
        worker_id: str | None = None,
    ) -> EffectReceipt:
        tenant_id = self._assert_tenant(intent.tenant_id)
        if not worker_id:
            raise ValueError("worker_id is required for PostgreSQL effect completion")
        if status not in {
            EffectStatus.SUCCEEDED,
            EffectStatus.FAILED,
            EffectStatus.AMBIGUOUS,
            EffectStatus.UNKNOWN,
        }:
            raise ValueError("effect completion must be succeeded, failed, or unknown")
        lease_expired = False
        async with self._tenant_transaction(tenant_id) as connection:
            await self._ensure_intent(connection, intent)
            row = await self._get_ledger(connection, intent.effect_key, for_update=True)
            if row is None:
                raise EffectLeaseConflict("effect was not claimed")
            current = await self._with_latest_receipt(connection, row, intent=intent)
            if current.status != EffectStatus.RUNNING:
                if current.attempt == attempt and current.status.terminal:
                    return current
                raise EffectLeaseConflict("effect claim is no longer active")
            if current.attempt != attempt:
                raise EffectLeaseConflict("effect attempt is fenced")
            if current.worker_id != worker_id:
                raise EffectLeaseConflict("effect worker is fenced")
            completed = await connection.fetchval(
                """
                UPDATE cell_effect_ledger
                   SET status=$3, lease_owner=NULL, lease_expires_at=NULL,
                       updated_at=clock_timestamp()
                 WHERE tenant_id=$1 AND effect_key=$2 AND status='running'
                   AND attempt=$4 AND lease_owner=$5
                   AND lease_expires_at > clock_timestamp()
                 RETURNING effect_key
                """,
                intent.tenant_id,
                intent.effect_key,
                status.value,
                attempt,
                worker_id,
            )
            if completed is None:
                expired = await connection.fetchval(
                    """
                    UPDATE cell_effect_ledger
                       SET status='ambiguous', lease_owner=NULL,
                           lease_expires_at=NULL, updated_at=clock_timestamp()
                     WHERE tenant_id=$1 AND effect_key=$2 AND status='running'
                       AND attempt=$3 AND lease_owner=$4
                       AND lease_expires_at <= clock_timestamp()
                     RETURNING effect_key
                    """,
                    intent.tenant_id,
                    intent.effect_key,
                    attempt,
                    worker_id,
                )
                if expired is None:
                    raise EffectLeaseConflict("effect claim changed before completion")
                await self._write_receipt(
                    connection,
                    intent,
                    status=EffectStatus.AMBIGUOUS,
                    attempt=attempt,
                    worker_id=worker_id,
                    error_type="effect_lease_expired",
                )
                # Let the transaction scope exit normally so the ambiguous
                # fence and receipt commit before surfacing the conflict.
                lease_expired = True
            else:
                await self._write_receipt(
                    connection,
                    intent,
                    status=status,
                    attempt=attempt,
                    worker_id=worker_id,
                    result=result if status == EffectStatus.SUCCEEDED else None,
                    error_type=error_type,
                )
                final_row = await self._get_ledger(connection, intent.effect_key)
                if final_row is None:
                    raise EffectLeaseConflict("effect completion disappeared")
                return await self._with_latest_receipt(connection, final_row, intent=intent)
        if lease_expired:
            raise EffectLeaseConflict("effect lease expired before completion")
        raise EffectLeaseConflict("effect completion did not produce a receipt")

    async def wait(
        self,
        effect_key: str,
        *,
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> EffectReceipt | None:
        if timeout is None:
            timeout = 30.0
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError("wait timeout must be non-negative")
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            current = await self.get(effect_key)
            if current is None or current.is_terminal:
                return current
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return current
            await asyncio.sleep(min(0.25, remaining))


def _decision_json(decision: PlacementDecision) -> dict[str, object]:
    return {
        "cell_id": decision.cell_id,
        "node_id": decision.node_id,
        "score": decision.score,
        "candidates": [
            {
                "node_id": candidate.node_id,
                "score": candidate.score,
                "component_scores": [list(pair) for pair in candidate.component_scores],
                "reasons": list(candidate.reasons),
            }
            for candidate in decision.candidates
        ],
        "rejected": [list(pair) for pair in decision.rejected],
    }


def _decision_from_json(value: object) -> PlacementDecision:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ReservationConflict("stored placement decision is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise ReservationConflict("stored placement decision is not JSON")
    candidates_raw = value.get("candidates", ())
    candidates: list[PlacementCandidate] = []
    candidate_items = (
        candidates_raw
        if isinstance(candidates_raw, Sequence) and not isinstance(candidates_raw, (str, bytes))
        else ()
    )
    for candidate in candidate_items:
        if not isinstance(candidate, Mapping):
            raise ReservationConflict("stored placement candidate is invalid")
        scores_raw = candidate.get("component_scores", ())
        scores: list[tuple[str, float]] = []
        score_items = (
            scores_raw
            if isinstance(scores_raw, Sequence) and not isinstance(scores_raw, (str, bytes))
            else ()
        )
        for pair in score_items:
            if not isinstance(pair, Sequence) or isinstance(pair, (str, bytes)) or len(pair) != 2:
                raise ReservationConflict("stored placement component score is invalid")
            score = float(pair[1])
            if not math.isfinite(score):
                raise ReservationConflict("stored placement component score is not finite")
            scores.append((str(pair[0]), score))
        candidate_score = float(candidate["score"])
        if not math.isfinite(candidate_score):
            raise ReservationConflict("stored placement candidate score is not finite")
        reasons_raw = candidate.get("reasons", ())
        reasons = (
            tuple(str(reason) for reason in reasons_raw)
            if isinstance(reasons_raw, Sequence) and not isinstance(reasons_raw, (str, bytes))
            else ()
        )
        candidates.append(
            PlacementCandidate(
                node_id=str(candidate["node_id"]),
                score=candidate_score,
                component_scores=tuple(scores),
                reasons=reasons,
            )
        )
    rejected_raw = value.get("rejected", ())
    rejected: list[tuple[str, str]] = []
    rejected_items = (
        rejected_raw
        if isinstance(rejected_raw, Sequence) and not isinstance(rejected_raw, (str, bytes))
        else ()
    )
    for pair in rejected_items:
        if not isinstance(pair, Sequence) or isinstance(pair, (str, bytes)) or len(pair) != 2:
            raise ReservationConflict("stored placement rejection is invalid")
        rejected.append((str(pair[0]), str(pair[1])))
    if not candidates:
        raise ReservationConflict("stored placement decision has no candidates")
    decision_score = float(value["score"])
    if not math.isfinite(decision_score):
        raise ReservationConflict("stored placement decision score is not finite")
    return PlacementDecision(
        cell_id=str(value["cell_id"]),
        node_id=str(value["node_id"]),
        score=decision_score,
        candidates=tuple(candidates),
        rejected=tuple(rejected),
    )


class PostgresPlacementReservationStore(_TenantRepository, PlacementReservationStore):
    """Authoritative placement reservation repository.

    ``update_node`` should be called by the independent scheduler/control-plane
    role granted ``update_cell_node_snapshot``.  Runtime gateways only call
    the controlled reserve/renew/release functions, which lock the global
    capacity row while applying a full CellAddress reservation.
    """

    async def update_node(self, snapshot: NodeSnapshot) -> int:
        """Publish a newer node snapshot and return its durable fence.

        ``observed_generation`` belongs to the node snapshot producer.  The
        database function compares it under the node-row lock, making delayed
        or duplicate heartbeats no-ops instead of allowing them to roll back
        newer capacity/health state.
        """

        async with self.pool.acquire() as connection:
            generation = await connection.fetchval(
                """
                SELECT public.update_cell_node_snapshot(
                    $1,$2,$3,$4,$5,$6,$7,$8
                )
                """,
                snapshot.observed_generation,
                snapshot.node_id,
                snapshot.region,
                snapshot.capacity_cpu_millis,
                snapshot.capacity_memory_mb,
                snapshot.max_cells,
                snapshot.healthy,
                snapshot.draining,
            )
        return int(generation)

    upsert_node = update_node

    async def reserve(
        self,
        request: CellPlacementRequest,
        decision: PlacementDecision,
        *,
        owner_id: str,
        lease_seconds: float = 30.0,
        reservation_id: str | None = None,
    ) -> PlacementReservation:
        if decision.cell_id != request.cell_id:
            raise ReservationConflict("placement decision targets another Cell")
        if decision.node_id not in {candidate.node_id for candidate in decision.candidates}:
            raise ReservationConflict("placement winner is not in its candidate list")
        if not isinstance(owner_id, str) or not owner_id.strip():
            raise ValueError("owner_id cannot be empty")
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, (int, float))
            or not math.isfinite(lease_seconds)
            or lease_seconds <= 0
        ):
            raise ValueError("lease_seconds must be positive")
        # A scheduler decision is an external control-plane input.  Validate
        # its numeric fields before serialising it into the privileged SQL
        # function so NaN/Infinity cannot poison durable audit evidence.
        _decision_from_json(_decision_json(decision))
        reservation_uuid = uuid.UUID(reservation_id) if reservation_id else uuid.uuid4()
        try:
            async with self._tenant_transaction(request.tenant_id) as connection:
                row = await connection.fetchrow(
                    """
                    SELECT * FROM public.reserve_cell_placement(
                        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13
                    )
                    """,
                    reservation_uuid,
                    request.tenant_id,
                    request.cell_id,
                    request.app_id,
                    request.session_id,
                    request.capsule_digest,
                    request.branch_id,
                    decision.node_id,
                    owner_id,
                    request.cpu_millis,
                    request.memory_mb,
                    _json_param(_decision_json(decision)),
                    lease_seconds,
                )
        except asyncpg.PostgresError as exc:
            raise ReservationConflict("durable placement reservation rejected") from exc
        if row is None:
            raise ReservationConflict("durable placement reservation returned no row")
        data = dict(row)
        stored_id = str(data["reservation_id"])
        stored_decision = _decision_from_json(data["decision"])
        if (
            stored_decision.cell_id != request.cell_id
            or stored_decision.node_id != decision.node_id
        ):
            raise ReservationConflict("stored placement decision changed its Cell or winner")
        return PlacementReservation(
            reservation_id=stored_id,
            tenant_id=request.tenant_id,
            app_id=request.app_id,
            cell_id=request.cell_id,
            session_id=request.session_id,
            capsule_digest=request.capsule_digest,
            branch_id=request.branch_id,
            node_id=decision.node_id,
            owner_id=owner_id,
            lease_epoch=int(data["lease_epoch"]),
            expires_at=_aware(cast(datetime, data["expires_at"])) or datetime.now(UTC),
            cpu_millis=request.cpu_millis,
            memory_mb=request.memory_mb,
            decision=stored_decision,
        )

    async def renew(
        self,
        reservation: PlacementReservation,
        *,
        owner_id: str | None = None,
        lease_seconds: float = 30.0,
    ) -> PlacementReservation:
        if owner_id is not None and (not isinstance(owner_id, str) or not owner_id.strip()):
            raise ValueError("owner_id cannot be empty")
        owner = owner_id or reservation.owner_id
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, (int, float))
            or not math.isfinite(lease_seconds)
            or lease_seconds <= 0
        ):
            raise ValueError("lease_seconds must be positive")
        row: asyncpg.Record | None = None
        data_row: asyncpg.Record | None = None
        try:
            async with self._tenant_transaction(reservation.tenant_id) as connection:
                row = await connection.fetchrow(
                    """
                    SELECT * FROM public.renew_cell_placement($1::uuid,$2,$3,$4)
                    """,
                    uuid.UUID(reservation.reservation_id),
                    owner,
                    reservation.lease_epoch,
                    lease_seconds,
                )
                if row is not None:
                    # The renew function intentionally returns only its
                    # transition receipt.  Re-read the locked row before
                    # constructing the public object: a caller-supplied
                    # handle is an untrusted snapshot and must never be able
                    # to rewrite tenant, node, Cell, or resource metadata in
                    # the value returned to the scheduler.
                    data_row = await connection.fetchrow(
                        """
                        SELECT reservation_id, tenant_id, app_id, cell_id, session_id,
                               capsule_digest, branch_id, node_id, owner_id, lease_epoch,
                               cpu_millis, memory_mb, decision, expires_at
                          FROM cell_placement_reservations
                         WHERE reservation_id=$1::uuid AND tenant_id=$2
                         FOR SHARE
                        """,
                        uuid.UUID(reservation.reservation_id),
                        reservation.tenant_id,
                    )
        except asyncpg.PostgresError as exc:
            raise ReservationConflict("placement reservation renew was fenced") from exc
        if row is None:
            raise ReservationConflict("placement reservation renew returned no row")
        if data_row is None:
            raise ReservationConflict("renewed placement reservation disappeared")
        data = dict(data_row)
        if str(data["tenant_id"]) != reservation.tenant_id:
            raise NamespaceViolation("renewed placement reservation crossed its tenant namespace")
        stored_decision = _decision_from_json(data["decision"])
        if stored_decision.cell_id != str(data["cell_id"]) or stored_decision.node_id != str(
            data["node_id"]
        ):
            raise ReservationConflict("renewed placement decision changed its Cell or winner")
        return PlacementReservation(
            reservation_id=str(data["reservation_id"]),
            tenant_id=str(data["tenant_id"]),
            app_id=str(data["app_id"]),
            cell_id=str(data["cell_id"]),
            session_id=str(data["session_id"]),
            capsule_digest=str(data["capsule_digest"]),
            branch_id=str(data["branch_id"]),
            node_id=str(data["node_id"]),
            owner_id=str(data["owner_id"]),
            lease_epoch=int(data["lease_epoch"]),
            expires_at=_aware(cast(datetime, data["expires_at"])) or datetime.now(UTC),
            cpu_millis=int(data["cpu_millis"]),
            memory_mb=int(data["memory_mb"]),
            decision=stored_decision,
        )

    async def release(
        self,
        reservation: PlacementReservation,
        *,
        owner_id: str | None = None,
    ) -> None:
        if owner_id is not None and (not isinstance(owner_id, str) or not owner_id.strip()):
            raise ValueError("owner_id cannot be empty")
        try:
            async with self._tenant_transaction(reservation.tenant_id) as connection:
                await connection.execute(
                    "SELECT public.release_cell_placement($1::uuid,$2,$3)",
                    uuid.UUID(reservation.reservation_id),
                    owner_id or reservation.owner_id,
                    reservation.lease_epoch,
                )
        except asyncpg.PostgresError as exc:
            raise ReservationConflict("placement reservation release was fenced") from exc

    async def get(self, reservation_id: str, *, tenant_id: str) -> PlacementReservation | None:
        async with self._tenant_transaction(tenant_id) as connection:
            row = await connection.fetchrow(
                """
                SELECT reservation_id, tenant_id, app_id, cell_id, session_id,
                       capsule_digest, branch_id, node_id, owner_id, lease_epoch,
                       cpu_millis, memory_mb, decision, expires_at
                  FROM cell_placement_reservations
                 WHERE reservation_id=$1::uuid
                """,
                uuid.UUID(reservation_id),
            )
        if row is None:
            return None
        data = dict(row)
        if str(data["tenant_id"]) != tenant_id:
            raise NamespaceViolation("placement reservation crossed its tenant namespace")
        decision = _decision_from_json(data["decision"])
        if decision.cell_id != str(data["cell_id"]) or decision.node_id != str(data["node_id"]):
            raise ReservationConflict("stored placement decision does not match its reservation")
        return PlacementReservation(
            reservation_id=str(data["reservation_id"]),
            tenant_id=str(data["tenant_id"]),
            app_id=str(data["app_id"]),
            cell_id=str(data["cell_id"]),
            session_id=str(data["session_id"]),
            capsule_digest=str(data["capsule_digest"]),
            branch_id=str(data["branch_id"]),
            node_id=str(data["node_id"]),
            owner_id=str(data["owner_id"]),
            lease_epoch=int(data["lease_epoch"]),
            expires_at=_aware(cast(datetime, data["expires_at"])) or datetime.now(UTC),
            cpu_millis=int(data["cpu_millis"]),
            memory_mb=int(data["memory_mb"]),
            decision=decision,
        )


class PostgresApprovalLedger(_TenantRepository):
    """Tenant-scoped one-time approval nonce store.

    Construct one ledger per tenant (``PostgresApprovalLedger(pool,
    tenant_id="tenant-a")``) and pass it to ``CellApprovalAuthority``.  Only
    SHA-256 digests of the nonce and signed approval scope are stored; the
    bearer token itself never reaches PostgreSQL.  ``consume`` is one
    conditional UPDATE, so concurrent consumers cannot both succeed.
    """

    def __init__(self, pool: asyncpg.Pool, *, tenant_id: str) -> None:
        super().__init__(pool)
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("tenant_id must be non-empty")
        self.tenant_id = tenant_id

    @classmethod
    def for_tenant(cls, pool: asyncpg.Pool, tenant_id: str) -> PostgresApprovalLedger:
        return cls(pool, tenant_id=tenant_id)

    @staticmethod
    def _nonce_digest(nonce: str) -> str:
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("nonce must be non-empty")
        return hashlib.sha256(nonce.encode("utf-8")).hexdigest()

    async def issue(self, nonce: str, expires_at: float, scope_digest: str) -> None:
        if (
            not isinstance(expires_at, (int, float))
            or not math.isfinite(expires_at)
            or expires_at <= 0
        ):
            raise ValueError("approval expiry must be positive")
        if (
            not isinstance(scope_digest, str)
            or len(scope_digest) != 64
            or any(character not in "0123456789abcdef" for character in scope_digest)
        ):
            raise ValueError("scope_digest must be a SHA-256 hex digest")
        try:
            expiry = datetime.fromtimestamp(expires_at, tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError("approval expiry is invalid") from exc
        async with self._tenant_transaction(self.tenant_id) as connection:
            try:
                await connection.execute(
                    """
                    SELECT public.issue_cell_approval_nonce($1,$2,$3,$4)
                    """,
                    self.tenant_id,
                    self._nonce_digest(nonce),
                    scope_digest,
                    expiry,
                )
            except asyncpg.UniqueViolationError as exc:
                raise ValueError("approval nonce already exists") from exc

    async def consume(self, nonce: str, expires_at: float, scope_digest: str) -> bool:
        if not isinstance(nonce, str) or not nonce:
            return False
        if (
            not isinstance(expires_at, (int, float))
            or not math.isfinite(expires_at)
            or expires_at <= 0
        ):
            return False
        if (
            not isinstance(scope_digest, str)
            or len(scope_digest) != 64
            or any(character not in "0123456789abcdef" for character in scope_digest)
        ):
            return False
        try:
            expiry = datetime.fromtimestamp(expires_at, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return False
        async with self._tenant_transaction(self.tenant_id) as connection:
            consumed = await connection.fetchval(
                """
                SELECT public.consume_cell_approval_nonce($1,$2,$3,$4)
                """,
                self.tenant_id,
                self._nonce_digest(nonce),
                scope_digest,
                expiry,
            )
        return consumed is True


class PostgresCellRepository:
    """Convenience bundle for bridge wiring in a multi-node worker."""

    def __init__(self, pool: asyncpg.Pool, *, tenant_id: str | None = None) -> None:
        self.events = PostgresEventStore(pool)
        self.effects = PostgresEffectLedger(pool, tenant_id=tenant_id)
        self.placements = PostgresPlacementReservationStore(pool)


__all__ = [
    "CompareAndSwapConflict",
    "FencedLeaseError",
    "PostgresApprovalLedger",
    "PostgresCellRepository",
    "PostgresEffectLedger",
    "PostgresEventStore",
    "PostgresPlacementReservationStore",
]
