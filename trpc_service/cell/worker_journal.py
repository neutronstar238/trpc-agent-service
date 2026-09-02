"""Production bridge from the real Worker/Tool path into the Cell journal.

The Cell kernel is useful only when it observes the same execution that owns
the authoritative Session/Outbox transaction.  This module implements both
``CellTurnJournal`` and ``GovernedToolObserver`` without importing those
Protocols at runtime.  It projects privacy-safe hashes and causal metadata;
message text, prompts, tool arguments, tool results, and resolved secrets are
never copied into the Cell event log.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from trpc_agent_sdk.events import Event

from trpc_service.cell.capsule import AgentCapsule, CapsuleMetadata, CapsuleSpec
from trpc_service.cell.events import CausalEvent, CellAddress, EventDraft, EventType
from trpc_service.channels.envelopes import OutboundEnvelope
from trpc_service.storage.models import Acceptance, CommitResult, SessionLease
from trpc_service.tenant.models import TenantConfig, TenantContext, ToolRisk
from trpc_service.tool.governance import Decision


class CellProjectionStore(Protocol):
    """Small async storage surface required by the runtime projection."""

    async def ensure_capsule(
        self,
        capsule: AgentCapsule,
        *,
        trust_class: str = "deployment",
    ) -> str: ...

    async def ensure_cell(
        self,
        address: CellAddress,
        *,
        status: str = "idle",
        session_lease_owner: str | None = None,
        session_fencing_token: int | None = None,
    ) -> object: ...

    async def append(
        self,
        draft: EventDraft,
        *,
        lease_owner: str | None = None,
        lease_epoch: int | None = None,
        lease_expires_at: datetime | None = None,
        session_lease_owner: str | None = None,
        session_fencing_token: int | None = None,
    ) -> CausalEvent: ...


@dataclass(slots=True)
class CellTurn:
    """Ephemeral handle for one fenced turn; durable state stays in the store."""

    address: CellAddress
    turn_id: str
    trace_id: str
    request_id: str
    correlation_id: str
    accepted_event_id: str
    config_version: int
    principal_id: str
    channel_binding_id: str
    lease_owner: str
    fencing_token: int
    lease_expires_at: datetime


@dataclass(frozen=True, slots=True)
class CellToolToken:
    """Join key returned before governance and consumed after the effect."""

    address: CellAddress
    turn_id: str
    trace_id: str
    request_id: str
    correlation_id: str
    intent_event_id: str
    invocation_id: str
    tool_name: str
    effect_key: str
    lease_owner: str
    fencing_token: int
    lease_expires_at: datetime


class CellRuntimeJournal:
    """Project real Runner and governed Tool facts into an append-only Cell.

    ``begin_turn`` is deliberately turn-critical.  If the causal ingress fact
    cannot be persisted, the model is not invoked.  After the authoritative
    Session/Outbox commit, Cell projection failures are reconciled by the
    Worker and never cause the already committed turn to be replayed.
    """

    def __init__(
        self,
        store: CellProjectionStore,
        *,
        capsule_signing_key: bytes | Ed25519PrivateKey,
        privacy_hash_key: bytes,
        capsule_key_id: str = "runtime-projection-non-authorizing-v1",
        runtime_artifact_digest: str | None = None,
    ) -> None:
        if not isinstance(privacy_hash_key, bytes) or len(privacy_hash_key) < 32:
            raise ValueError("privacy hash key must contain at least 32 bytes")
        if isinstance(capsule_signing_key, bytes):
            if len(capsule_signing_key) != 32:
                raise ValueError("capsule signing key must be exactly 32 bytes")
            capsule_signing_key = Ed25519PrivateKey.from_private_bytes(capsule_signing_key)
        if not capsule_key_id:
            raise ValueError("capsule_key_id must be non-empty")
        if runtime_artifact_digest is not None and not _is_digest(runtime_artifact_digest):
            raise ValueError("runtime_artifact_digest must be sha256:<64 lowercase hex>")
        self._store = store
        self._signing_key = capsule_signing_key
        self._privacy_hash_key = privacy_hash_key
        self._capsule_key_id = capsule_key_id
        self._runtime_artifact_digest = runtime_artifact_digest
        self._turns: dict[tuple[str, str, str], CellTurn] = {}
        self._tool_tokens: dict[str, CellToolToken] = {}

    async def begin_turn(
        self,
        acceptance: Acceptance,
        config: TenantConfig,
        lease: SessionLease,
    ) -> CellTurn:
        context = acceptance.context
        _validate_turn_namespace(context, config, lease)
        capsule = self._capsule_for_config(config)
        digest = await self._store.ensure_capsule(capsule, trust_class="runtime_projection")
        address = CellAddress(
            tenant_id=context.tenant_id,
            app_id=context.app_id,
            cell_id=self._cell_id(context),
            session_id=context.session_id,
            capsule_digest=digest,
            branch_id="main",
        )
        await self._store.ensure_cell(
            address,
            status="running",
            session_lease_owner=lease.worker_id,
            session_fencing_token=lease.fencing_token,
        )
        correlation_id = lease.turn_id
        accepted_event_id = self._scoped_event_id(
            address,
            context.channel_binding_id,
            acceptance.inbound_id,
            "message.accepted",
        )
        await self._append(
            address,
            event_type=EventType.MESSAGE_ACCEPTED,
            event_id=accepted_event_id,
            payload={
                "channel": acceptance.envelope.channel.value,
                "binding_hash": self._private_hash(context.channel_binding_id),
                "external_message_hash": self._private_hash(
                    acceptance.envelope.external_message_id
                ),
                "payload_kind": acceptance.envelope.payload_kind.value,
                "content_hash": self._private_hash(
                    {
                        "text": acceptance.envelope.text,
                        "media": [
                            item.model_dump(mode="json") for item in acceptance.envelope.media
                        ],
                        "event_type": acceptance.envelope.event_type,
                    }
                ),
                "duplicate": acceptance.duplicate,
            },
            trace_id=context.trace_id,
            request_id=context.request_id,
            correlation_id=correlation_id,
            lease_owner=lease.worker_id,
            fencing_token=lease.fencing_token,
            lease_expires_at=lease.expires_at,
        )
        activated_event_id = self._scoped_event_id(
            address,
            lease.turn_id,
            lease.fencing_token,
            "cell.activated",
        )
        await self._append(
            address,
            event_type=EventType.CELL_ACTIVATED,
            event_id=activated_event_id,
            payload={
                "capsule_digest": digest,
                "config_version": config.version,
                "runtime_artifact_attested": self._runtime_artifact_digest is not None,
            },
            causation_id=accepted_event_id,
            trace_id=context.trace_id,
            request_id=context.request_id,
            correlation_id=correlation_id,
            lease_owner=lease.worker_id,
            fencing_token=lease.fencing_token,
            lease_expires_at=lease.expires_at,
        )
        await self._append(
            address,
            event_type=EventType.CONTEXT_PROJECTED,
            event_id=self._scoped_event_id(
                address,
                lease.turn_id,
                lease.fencing_token,
                "context.projected",
            ),
            payload={
                "turn_id_hash": self._private_hash(lease.turn_id),
                "config_version": config.version,
                "policy_version": config.policy_version,
                "principal_hash": self._private_hash(context.principal_id),
                "lease_owner_hash": self._private_hash(lease.worker_id),
                "fencing_token": lease.fencing_token,
            },
            causation_id=activated_event_id,
            trace_id=context.trace_id,
            request_id=context.request_id,
            correlation_id=correlation_id,
            lease_owner=lease.worker_id,
            fencing_token=lease.fencing_token,
            lease_expires_at=lease.expires_at,
        )
        turn = CellTurn(
            address=address,
            turn_id=lease.turn_id,
            trace_id=context.trace_id,
            request_id=context.request_id,
            correlation_id=correlation_id,
            accepted_event_id=accepted_event_id,
            config_version=config.version,
            principal_id=context.principal_id,
            channel_binding_id=context.channel_binding_id,
            lease_owner=lease.worker_id,
            fencing_token=lease.fencing_token,
            lease_expires_at=lease.expires_at,
        )
        self._turns[(context.tenant_id, context.app_id, lease.turn_id)] = turn
        return turn

    async def record_agent_event(self, turn: object, event: Event) -> None:
        current = _require_turn(turn)
        dumped = event.model_dump(mode="json", by_alias=True)
        event_identity = event.id or self._private_hash(dumped)
        await self._append(
            current.address,
            event_type="agent.event.observed",
            event_id=self._scoped_event_id(
                current.address,
                current.turn_id,
                current.fencing_token,
                "agent.event",
                event_identity,
            ),
            payload={
                "sdk_event_hash": self._private_hash(dumped),
                "author_hash": self._private_hash(str(event.author or "")),
                "partial": bool(event.partial),
                "visible": bool(event.visible),
                "final_response": bool(event.is_final_response()),
                "has_text": bool(event.get_text()),
            },
            causation_id=current.accepted_event_id,
            trace_id=current.trace_id,
            request_id=current.request_id,
            correlation_id=current.correlation_id,
            lease_owner=current.lease_owner,
            fencing_token=current.fencing_token,
            lease_expires_at=current.lease_expires_at,
        )

    async def prepare_reply(self, turn: object, outbound: OutboundEnvelope) -> None:
        current = _require_turn(turn)
        if (
            outbound.tenant_id != current.address.tenant_id
            or outbound.session_id != current.address.session_id
        ):
            raise ValueError("outbound crosses the active Cell namespace")
        await self._append(
            current.address,
            event_type=EventType.REPLY_PREPARED,
            event_id=self._scoped_event_id(
                current.address,
                current.turn_id,
                current.fencing_token,
                "reply.prepared",
            ),
            payload={
                "outbound_id_hash": self._private_hash(outbound.outbound_id),
                "payload_kind": outbound.payload_kind.value,
                "reply_hash": self._private_hash(
                    {
                        "text": outbound.text,
                        "media": [item.model_dump(mode="json") for item in outbound.media],
                    }
                ),
            },
            causation_id=current.accepted_event_id,
            trace_id=current.trace_id,
            request_id=current.request_id,
            correlation_id=current.correlation_id,
            lease_owner=current.lease_owner,
            fencing_token=current.fencing_token,
            lease_expires_at=current.lease_expires_at,
        )

    async def commit_turn(self, turn: object, result: CommitResult) -> None:
        current = _require_turn(turn)
        try:
            await self._append(
                current.address,
                event_type="turn.committed",
                event_id=_public_event_id(
                    "turn.committed",
                    *current.address.stream_key,
                    current.turn_id,
                ),
                payload={
                    "last_sequence": result.last_sequence,
                },
                causation_id=current.accepted_event_id,
                trace_id=current.trace_id,
                request_id=current.request_id,
                correlation_id=current.correlation_id,
            )
        finally:
            self._forget(current)

    async def fail_turn(self, turn: object, *, error_type: str) -> None:
        current = _require_turn(turn)
        try:
            await self._append(
                current.address,
                event_type="turn.failed",
                event_id=self._scoped_event_id(
                    current.address,
                    current.turn_id,
                    current.fencing_token,
                    "turn.failed",
                ),
                payload={"error_type_hash": self._private_hash(error_type)},
                causation_id=current.accepted_event_id,
                trace_id=current.trace_id,
                request_id=current.request_id,
                correlation_id=current.correlation_id,
                lease_owner=current.lease_owner,
                fencing_token=current.fencing_token,
                lease_expires_at=current.lease_expires_at,
            )
        finally:
            self._forget(current)

    async def mark_reconcile_required(
        self,
        turn: object,
        *,
        error_type: str,
    ) -> None:
        current = _require_turn(turn)
        await self._append(
            current.address,
            event_type="turn.reconcile_required",
            event_id=self._scoped_event_id(
                current.address,
                current.turn_id,
                current.fencing_token,
                "turn.reconcile_required",
            ),
            payload={"error_type_hash": self._private_hash(error_type)},
            causation_id=current.accepted_event_id,
            trace_id=current.trace_id,
            request_id=current.request_id,
            correlation_id=current.correlation_id,
        )

    async def intent_created(
        self,
        context: TenantContext,
        *,
        turn_id: str,
        invocation_id: str,
        tool_name: str,
        arguments_hash: str,
        effect_key: str,
        risk: ToolRisk,
    ) -> CellToolToken:
        if not _is_sha256_hex(arguments_hash):
            raise ValueError("arguments_hash must be a SHA-256 hex digest")
        if not _is_sha256_hex(effect_key):
            raise ValueError("effect_key must be a 64-character lowercase hex key")
        turn = self._turns.get((context.tenant_id, context.app_id, turn_id))
        if (
            turn is None
            or turn.address.session_id != context.session_id
            or turn.config_version != context.config_version
            or turn.principal_id != context.principal_id
            or turn.channel_binding_id != context.channel_binding_id
            or turn.trace_id != context.trace_id
            or turn.request_id != context.request_id
        ):
            # This callback runs before governance and the effect.  Missing
            # causal context therefore fails closed instead of producing an
            # unjournaled external side effect.
            raise LookupError("governed tool invocation has no active Cell turn")
        intent_event_id = self._scoped_event_id(
            turn.address,
            turn_id,
            turn.fencing_token,
            invocation_id,
            tool_name,
            "tool.intent",
        )
        await self._append(
            turn.address,
            event_type=EventType.TOOL_INTENT_CREATED,
            event_id=intent_event_id,
            payload={
                "intent_id": intent_event_id,
                "effect_key": effect_key,
                "invocation_id_hash": self._private_hash(invocation_id),
                "tool_name": tool_name,
                "arguments_hash": self._private_hash(
                    {"source_digest": arguments_hash, "tool_name": tool_name}
                ),
                "risk": risk.value,
                "config_version": context.config_version,
            },
            causation_id=turn.accepted_event_id,
            trace_id=context.trace_id,
            request_id=context.request_id,
            correlation_id=turn.correlation_id,
            lease_owner=turn.lease_owner,
            fencing_token=turn.fencing_token,
            lease_expires_at=turn.lease_expires_at,
        )
        token = CellToolToken(
            address=turn.address,
            turn_id=turn_id,
            trace_id=context.trace_id,
            request_id=context.request_id,
            correlation_id=turn.correlation_id,
            intent_event_id=intent_event_id,
            invocation_id=invocation_id,
            tool_name=tool_name,
            effect_key=effect_key,
            lease_owner=turn.lease_owner,
            fencing_token=turn.fencing_token,
            lease_expires_at=turn.lease_expires_at,
        )
        self._tool_tokens[intent_event_id] = token
        return token

    async def policy_decided(
        self,
        token: object,
        *,
        decision: Decision,
        reason: str,
    ) -> None:
        current = self._active_tool_token(token)
        await self._append(
            current.address,
            event_type=EventType.POLICY_DECIDED,
            event_id=self._scoped_event_id(
                current.address,
                current.intent_event_id,
                "policy",
                decision.value,
            ),
            payload={
                "tool_name": current.tool_name,
                "decision": decision.value,
                "reason_hash": self._private_hash(reason),
            },
            causation_id=current.intent_event_id,
            trace_id=current.trace_id,
            request_id=current.request_id,
            correlation_id=current.correlation_id,
            lease_owner=current.lease_owner,
            fencing_token=current.fencing_token,
            lease_expires_at=current.lease_expires_at,
        )

    async def effect_completed(
        self,
        token: object,
        *,
        status: str,
        result_hash: str | None,
        error_type: str | None,
    ) -> None:
        current = self._active_tool_token(token)
        event_type = _effect_event_type(status)
        await self._append(
            current.address,
            event_type=event_type,
            event_id=_public_event_id(
                "tool.effect",
                *current.address.stream_key,
                current.intent_event_id,
                current.effect_key,
                status,
            ),
            payload={
                "tool_name": current.tool_name,
                "status": status,
                "effect_key": current.effect_key,
                "result_hash": (
                    self._private_hash({"source_digest": result_hash})
                    if result_hash is not None
                    else None
                ),
                "error_type_hash": (self._private_hash(error_type) if error_type else None),
            },
            causation_id=current.intent_event_id,
            trace_id=current.trace_id,
            request_id=current.request_id,
            correlation_id=current.correlation_id,
            lease_owner=current.lease_owner,
            fencing_token=current.fencing_token,
            lease_expires_at=current.lease_expires_at,
        )
        self._tool_tokens.pop(current.intent_event_id, None)

    async def _append(
        self,
        address: CellAddress,
        *,
        event_type: str | EventType,
        event_id: str,
        payload: dict[str, object],
        trace_id: str | None,
        request_id: str | None,
        correlation_id: str | None,
        causation_id: str | None = None,
        lease_owner: str | None = None,
        fencing_token: int | None = None,
        lease_expires_at: datetime | None = None,
    ) -> CausalEvent:
        return await self._store.append(
            EventDraft(
                tenant_id=address.tenant_id,
                app_id=address.app_id,
                cell_id=address.cell_id,
                session_id=address.session_id,
                capsule_digest=address.capsule_digest,
                branch_id=address.branch_id,
                event_type=event_type,
                event_id=event_id,
                payload=payload,
                causation_id=causation_id,
                correlation_id=correlation_id,
                trace_id=trace_id,
                request_id=request_id,
            ),
            lease_owner=lease_owner,
            lease_epoch=fencing_token,
            lease_expires_at=lease_expires_at,
            session_lease_owner=lease_owner,
            session_fencing_token=fencing_token,
        )

    def _capsule_for_config(self, config: TenantConfig) -> AgentCapsule:
        runtime_graph = self._runtime_artifact_digest or _digest_ref(
            {"runtime": "trpc-agent-python", "bridge": "cell-runtime-journal-v1"}
        )
        capsule = AgentCapsule(
            metadata=CapsuleMetadata(
                tenant_id=config.tenant_id,
                name=config.app_id,
                version=config.version,
                labels={
                    "source": "tenant-config",
                    "app": config.app_id,
                    "trust.class": "runtime_projection",
                },
                annotations={
                    "configVersion": str(config.version),
                    "policyVersion": str(config.policy_version),
                },
            ),
            spec=CapsuleSpec(
                graph=runtime_graph,
                prompt=self._private_digest_ref({"instructions": config.instructions}),
                model_policy=self._private_digest_ref(config.model.model_dump(mode="json")),
                tool_manifest=self._private_digest_ref(config.tools.model_dump(mode="json")),
                governance_policy=self._private_digest_ref(
                    {
                        "budget": config.budget.model_dump(mode="json"),
                        "audit": config.audit.model_dump(mode="json"),
                        "policy_version": config.policy_version,
                    }
                ),
                knowledge_snapshot=self._private_digest_ref(
                    {
                        "profile_id": config.storage.profile_id,
                        "backend": config.storage.knowledge_backend,
                    }
                ),
                storage_profile=self._private_digest_ref(config.storage.model_dump(mode="json")),
            ),
        )
        capsule.spec.validate_asset_refs()
        return capsule.sign(self._signing_key, key_id=self._capsule_key_id)

    def _private_hash(self, value: object) -> str:
        encoded = _canonical_bytes(value)
        return hmac.new(self._privacy_hash_key, encoded, hashlib.sha256).hexdigest()

    def _private_digest_ref(self, value: object) -> str:
        """Return a cross-node-stable keyed reference for private config data."""

        return "sha256:" + self._private_hash(value)

    def _event_id(self, *parts: object) -> str:
        return "cell-event-" + self._private_hash(parts)

    def _scoped_event_id(self, address: CellAddress, *parts: object) -> str:
        return self._event_id(*address.stream_key, *parts)

    def _cell_id(self, context: TenantContext) -> str:
        return (
            "cell-"
            + self._private_hash(
                "\x1f".join((context.tenant_id, context.app_id, context.session_id))
            )[:32]
        )

    def _active_tool_token(self, value: object) -> CellToolToken:
        token = _require_tool_token(value)
        issued = self._tool_tokens.get(token.intent_event_id)
        if issued is not token:
            raise ValueError("tool token was not issued by this active Cell journal")
        turn = self._turns.get((token.address.tenant_id, token.address.app_id, token.turn_id))
        if turn is None or turn.address != token.address:
            raise ValueError("tool token no longer belongs to an active Cell turn")
        return token

    def _forget(self, turn: CellTurn) -> None:
        self._turns.pop(
            (turn.address.tenant_id, turn.address.app_id, turn.turn_id),
            None,
        )
        stale_intents = [
            intent_id
            for intent_id, token in self._tool_tokens.items()
            if token.turn_id == turn.turn_id and token.address == turn.address
        ]
        for intent_id in stale_intents:
            self._tool_tokens.pop(intent_id, None)


class PostgresCellRuntimeJournal(CellRuntimeJournal):
    """Cell runtime journal backed by the production asyncpg pool."""

    def __init__(
        self,
        pool: object,
        *,
        capsule_signing_key: bytes | Ed25519PrivateKey,
        privacy_hash_key: bytes,
        capsule_key_id: str = "runtime-projection-non-authorizing-v1",
        runtime_artifact_digest: str | None = None,
    ) -> None:
        from trpc_service.cell.postgres import PostgresEventStore

        super().__init__(
            PostgresEventStore(pool),  # type: ignore[arg-type]
            capsule_signing_key=capsule_signing_key,
            privacy_hash_key=privacy_hash_key,
            capsule_key_id=capsule_key_id,
            runtime_artifact_digest=runtime_artifact_digest,
        )


class PostgresCellCommitReconciler:
    """Repair the post-Session-commit crash window from durable outbox facts.

    ``reply.prepared`` is written before the authoritative Session/Outbox
    transaction.  The existing ``post_turn.ready`` outbox row is written in
    that transaction, so their intersection is a durable proof that a missing
    ``turn.committed`` projection may be appended without replaying the Agent.
    """

    def __init__(self, pool: object) -> None:
        from trpc_service.cell.postgres import PostgresEventStore

        self._store = PostgresEventStore(pool)

    async def reconcile_committed_turn(
        self,
        tenant_id: str,
        turn_id: str,
        *,
        up_to_sequence: int,
    ) -> bool:
        if up_to_sequence < 0:
            raise ValueError("up_to_sequence must be non-negative")
        prepared = await self._store.find_latest_by_correlation(
            tenant_id,
            turn_id,
            event_type=str(EventType.REPLY_PREPARED),
        )
        if prepared is None:
            # Turns created before Cell projection was enabled are valid and
            # must not poison the existing post-turn projection queue.
            return False
        missing_effects = await self._store.find_unprojected_terminal_effects(
            tenant_id,
            turn_id,
        )
        for effect in missing_effects:
            status = str(effect["status"])
            effect_key = str(effect["effect_key"])
            event_type = _effect_event_type(status)
            stream_key = (
                str(effect["tenant_id"]),
                str(effect["app_id"]),
                str(effect["cell_id"]),
                str(effect["session_id"]),
                str(effect["capsule_digest"]),
                str(effect["branch_id"]),
            )
            await self._store.append(
                EventDraft(
                    tenant_id=str(effect["tenant_id"]),
                    app_id=str(effect["app_id"]),
                    cell_id=str(effect["cell_id"]),
                    session_id=str(effect["session_id"]),
                    capsule_digest=str(effect["capsule_digest"]),
                    branch_id=str(effect["branch_id"]),
                    event_type=event_type,
                    event_id=_public_event_id(
                        "tool.effect",
                        *stream_key,
                        effect["intent_event_id"],
                        effect_key,
                        status,
                    ),
                    payload={
                        "tool_name": str(effect["tool_name"]),
                        "status": status,
                        "effect_key": effect_key,
                        "result_hash": None,
                        "error_type_hash": None,
                        "reconciled": True,
                    },
                    causation_id=str(effect["intent_event_id"]),
                    correlation_id=turn_id,
                    trace_id=(str(effect["trace_id"]) if effect["trace_id"] else None),
                    request_id=(str(effect["request_id"]) if effect["request_id"] else None),
                )
            )
        await self._store.append(
            EventDraft(
                tenant_id=prepared.tenant_id,
                app_id=prepared.app_id,
                cell_id=prepared.cell_id,
                session_id=prepared.session_id,
                capsule_digest=prepared.capsule_digest,
                branch_id=prepared.branch_id,
                event_type="turn.committed",
                event_id=_public_event_id(
                    "turn.committed",
                    *prepared.address.stream_key,
                    turn_id,
                ),
                payload={"last_sequence": up_to_sequence},
                causation_id=prepared.causation_id,
                correlation_id=turn_id,
                trace_id=prepared.trace_id,
                request_id=prepared.request_id,
            )
        )
        return True


def _effect_event_type(status: str) -> str:
    if status == "succeeded":
        return EventType.TOOL_EFFECT_COMMITTED
    if status == "simulated":
        return "tool.effect.simulated"
    return f"tool.effect.{status}"


def _validate_turn_namespace(
    context: TenantContext,
    config: TenantConfig,
    lease: SessionLease,
) -> None:
    if (
        config.tenant_id != context.tenant_id
        or config.app_id != context.app_id
        or config.version != context.config_version
    ):
        raise ValueError("pinned config crosses the accepted tenant/app revision")
    if lease.tenant_id != context.tenant_id or lease.session_id != context.session_id:
        raise ValueError("session lease crosses the accepted Cell namespace")
    snapshot = lease.snapshot
    if (
        snapshot.tenant_id != context.tenant_id
        or snapshot.session_id != context.session_id
        or snapshot.app_id != context.app_id
        or snapshot.principal_id != context.principal_id
    ):
        raise ValueError("session lease snapshot crosses the accepted app or principal")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=str,
    ).encode("utf-8")


def _value_hash(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _digest_ref(value: object) -> str:
    return "sha256:" + _value_hash(value)


def _public_event_id(kind: str, *parts: object) -> str:
    """Stable ID for reconciliation facts derived from high-entropy turn keys."""

    material = _canonical_bytes(["cell-projection/v1", kind, *parts])
    return f"cell-{kind}-{hashlib.sha256(material).hexdigest()}"


def _is_digest(value: str) -> bool:
    return (
        len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _is_sha256_hex(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_turn(value: object) -> CellTurn:
    if not isinstance(value, CellTurn):
        raise TypeError("turn token was not issued by CellRuntimeJournal")
    return value


def _require_tool_token(value: object) -> CellToolToken:
    if not isinstance(value, CellToolToken):
        raise TypeError("tool token was not issued by CellRuntimeJournal")
    return value


__all__ = [
    "CellProjectionStore",
    "CellRuntimeJournal",
    "CellToolToken",
    "CellTurn",
    "PostgresCellCommitReconciler",
    "PostgresCellRuntimeJournal",
]
