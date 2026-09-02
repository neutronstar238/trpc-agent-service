"""Reference coordinator that composes the Agent Cell Fabric primitives."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from trpc_service.cell.capsule import AgentCapsule
from trpc_service.cell.effects import (
    ApprovalCredential,
    ApprovalVerifier,
    EffectCallable,
    EffectReceipt,
    EffectStatus,
    ExactlyOnceEffectExecutor,
    PolicyAuthority,
    PolicyJudge,
)
from trpc_service.cell.events import (
    CausalEvent,
    CellAddress,
    EventDraft,
    EventStore,
    EventType,
    InMemoryEventStore,
)
from trpc_service.cell.intents import ConfirmationScope, PolicyDecision, ToolIntent
from trpc_service.cell.replay import ProjectionReplayer, ProjectionResult, state_fingerprint
from trpc_service.cell.scheduler import (
    CellPlacementRequest,
    CellScheduler,
    NodeSnapshot,
    PlacementDecision,
)


class CapsuleNotRegistered(LookupError):
    """Raised when a Cell references an unknown capsule digest."""


class CellNamespaceMismatch(ValueError):
    """Raised before data can cross a tenant, Cell, Session or capsule boundary."""


class BranchEffectDenied(PermissionError):
    """Raised when a counterfactual branch attempts a real-world side effect."""


class CellNotActive(LookupError):
    """Raised when an effect targets a Cell that was never activated or forked."""


@dataclass(frozen=True, slots=True)
class CellActivation:
    """Auditable result of accepting and placing one logical Cell."""

    address: CellAddress
    placement: PlacementDecision
    accepted_event: CausalEvent
    activated_event: CausalEvent


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _stable_event_id(tenant_id: str, kind: str, *parts: str) -> str:
    material = "\x1f".join(("trpc-agent-cell/v1", tenant_id, kind, *parts))
    return f"cell-{kind}-{hashlib.sha256(material.encode('utf-8')).hexdigest()}"


def default_cell_reducer(state: dict[str, Any], event: CausalEvent) -> dict[str, Any]:
    """Build a small content-free operational projection for demos and audits."""

    state["event_count"] = int(state.get("event_count", 0)) + 1
    state["last_sequence"] = event.sequence
    state["last_event_type"] = event.event_type
    state["capsule_digest"] = event.capsule_digest
    if event.event_type == EventType.CELL_ACTIVATED:
        state["status"] = "running"
        state["node_id"] = event.payload.get("node_id")
    elif event.event_type == EventType.TOOL_EFFECT_COMMITTED:
        state["last_effect_key"] = event.payload.get("effect_key")
        state["last_effect_status"] = event.payload.get("status")
    elif event.event_type == EventType.REPLY_DELIVERED:
        state["status"] = "idle"
        state["last_reply_hash"] = event.payload.get("reply_hash")
    return state


class AgentCellFabric:
    """In-process reference implementation of the innovation architecture.

    Production deployments replace the in-memory registries with PostgreSQL
    implementations created by migration ``0017_agent_cell_fabric``.  The
    orchestration semantics remain the same.
    """

    def __init__(
        self,
        *,
        trusted_capsule_keys: Mapping[str, Mapping[str, Ed25519PublicKey | bytes]] | None = None,
        require_signed_capsules: bool = True,
        event_store: EventStore | None = None,
        scheduler: CellScheduler | None = None,
        effect_executor: ExactlyOnceEffectExecutor | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        policy_authority: PolicyAuthority | None = None,
        policy_judge: PolicyJudge | None = None,
    ) -> None:
        self._trusted_capsule_keys = {
            tenant_id: dict(keys) for tenant_id, keys in (trusted_capsule_keys or {}).items()
        }
        self._require_signed_capsules = require_signed_capsules
        self.events = event_store or InMemoryEventStore()
        self.scheduler = scheduler or CellScheduler()
        if effect_executor is not None and any(
            value is not None for value in (approval_verifier, policy_authority, policy_judge)
        ):
            raise TypeError(
                "inject policy/approval authorities into the executor or the fabric, not both"
            )
        self.effects = effect_executor or ExactlyOnceEffectExecutor(
            approval_verifier=approval_verifier,
            policy_authority=policy_authority,
            policy_judge=policy_judge,
        )
        self._capsules: dict[tuple[str, str], AgentCapsule] = {}
        self._active_cells: set[CellAddress] = set()

    def register_capsule(self, capsule: AgentCapsule) -> str:
        """Verify and register one immutable capsule, returning its digest."""

        tenant_keys = self._trusted_capsule_keys.get(capsule.metadata.tenant_id, {})
        capsule.spec.validate_asset_refs()
        capsule.verify(
            tenant_keys,
            require_signature=self._require_signed_capsules,
        )
        if capsule.digest is None:
            raise ValueError("verified capsule did not declare a digest")
        key = (capsule.metadata.tenant_id, capsule.digest)
        existing = self._capsules.get(key)
        if existing is not None and existing.canonical_bytes() != capsule.canonical_bytes():
            raise ValueError("capsule digest collision with different canonical content")
        self._capsules[key] = capsule
        return capsule.digest

    def get_capsule(self, tenant_id: str, capsule_digest: str) -> AgentCapsule:
        try:
            return self._capsules[(tenant_id, capsule_digest)]
        except KeyError as exc:
            raise CapsuleNotRegistered(
                f"capsule {capsule_digest!r} is not registered for tenant {tenant_id!r}"
            ) from exc

    def activate_cell(
        self,
        *,
        tenant_id: str,
        app_id: str = "default",
        cell_id: str,
        session_id: str,
        capsule_digest: str,
        message: str,
        channel: str,
        external_message_id: str,
        channel_binding_id: str = "default",
        nodes: tuple[NodeSnapshot, ...] | list[NodeSnapshot],
        correlation_id: str,
        trace_id: str,
        request_id: str,
        branch_id: str = "main",
        compliance_regions: frozenset[str] = frozenset(),
        data_localities: frozenset[str] = frozenset(),
    ) -> CellActivation:
        """Accept a content-redacted message and place its logical Cell."""

        capsule = self.get_capsule(tenant_id, capsule_digest)
        request = CellPlacementRequest(
            cell_id=cell_id,
            tenant_id=tenant_id,
            app_id=app_id,
            capsule_digest=capsule_digest,
            slo=capsule.spec.slo,
            required_capabilities=frozenset(capsule.spec.channel_capabilities),
            compliance_regions=compliance_regions,
            data_localities=data_localities,
        )
        placement = self.scheduler.place(request, nodes)
        address = CellAddress(
            tenant_id=tenant_id,
            app_id=app_id,
            cell_id=cell_id,
            session_id=session_id,
            capsule_digest=capsule_digest,
            branch_id=branch_id,
        )
        accepted = self.events.append(
            EventDraft(
                tenant_id=tenant_id,
                app_id=app_id,
                cell_id=cell_id,
                session_id=session_id,
                capsule_digest=capsule_digest,
                branch_id=branch_id,
                event_type=EventType.MESSAGE_ACCEPTED,
                event_id=_stable_event_id(
                    tenant_id,
                    "message-accepted",
                    app_id,
                    channel,
                    channel_binding_id,
                    external_message_id,
                ),
                payload={
                    "message_hash": _sha256_text(message),
                    "channel": channel,
                    "external_message_id_hash": _sha256_text(external_message_id),
                    "channel_binding_id_hash": _sha256_text(channel_binding_id),
                },
                correlation_id=correlation_id,
                trace_id=trace_id,
                request_id=request_id,
            )
        )
        activated = self.events.append(
            EventDraft(
                tenant_id=tenant_id,
                app_id=app_id,
                cell_id=cell_id,
                session_id=session_id,
                capsule_digest=capsule_digest,
                branch_id=branch_id,
                event_type=EventType.CELL_ACTIVATED,
                event_id=_stable_event_id(
                    tenant_id,
                    "cell-activated",
                    app_id,
                    cell_id,
                    session_id,
                    capsule_digest,
                    branch_id,
                    accepted.event_id,
                ),
                payload={
                    "node_id": placement.node_id,
                    "score": placement.score,
                    "score_components": dict(placement.winner.component_scores),
                },
                causation_id=accepted.event_id,
                correlation_id=correlation_id,
                trace_id=trace_id,
                request_id=request_id,
            )
        )
        self._active_cells.add(address)
        return CellActivation(address, placement, accepted, activated)

    async def execute_intent(
        self,
        address: CellAddress,
        intent: ToolIntent,
        effect: EffectCallable | None,
        *,
        confirmation_scope: ConfirmationScope | None = None,
        approval_credential: ApprovalCredential | str | None = None,
        simulate: EffectCallable | None = None,
        manual_replay: bool = False,
    ) -> EffectReceipt:
        """Persist intent/policy/effect metadata around one guarded side effect."""

        self._validate_intent_namespace(address, intent)
        if address not in self._active_cells:
            raise CellNotActive("tool intent targets a Cell that is not active")
        if address.branch_id != "main" and intent.policy_decision != PolicyDecision.SIMULATE_ONLY:
            raise BranchEffectDenied(
                "counterfactual branches may only execute simulate_only tool intents"
            )
        created = self._append_from_intent(
            address,
            intent,
            EventType.TOOL_INTENT_CREATED,
            {
                "intent_id": intent.intent_id,
                "tool_name": intent.tool_name,
                "arguments_hash": intent.arguments_hash,
                "effect_key": intent.effect_key,
                "risk": str(intent.risk),
            },
        )
        effective_intent, policy_error = await self.effects.authorize(intent)
        decided = self._append_from_intent(
            address,
            intent,
            EventType.POLICY_DECIDED,
            {
                "intent_id": intent.intent_id,
                "decision": str(effective_intent.policy_decision),
                "reason": policy_error,
            },
            causation_id=created.event_id,
        )
        receipt = await self.effects.execute(
            intent,
            effect,
            simulate=simulate,
            confirmation_scope=confirmation_scope,
            approval_credential=approval_credential,
            authorized_intent=effective_intent,
            manual_replay=manual_replay,
        )
        event_type = (
            EventType.TOOL_EFFECT_COMMITTED
            if receipt.status in {EffectStatus.SUCCEEDED, EffectStatus.SIMULATED}
            else f"tool.effect.{receipt.status.value}"
        )
        self._append_from_intent(
            address,
            intent,
            event_type,
            {
                "intent_id": intent.intent_id,
                "effect_key": intent.effect_key,
                "status": receipt.status.value,
                "attempt": receipt.attempt,
                "result_hash": (
                    state_fingerprint(receipt.result) if receipt.result is not None else None
                ),
                "error_type": receipt.error_type,
            },
            causation_id=decided.event_id,
        )
        return receipt

    def deliver_reply(
        self,
        address: CellAddress,
        *,
        reply: str,
        provider_message_id: str,
        correlation_id: str,
        trace_id: str,
        request_id: str,
    ) -> CausalEvent:
        """Record a content-redacted terminal delivery event."""

        if address not in self._active_cells:
            raise CellNotActive("reply targets a Cell that is not active")
        head = self.events.head(address)
        return self.events.append(
            EventDraft(
                tenant_id=address.tenant_id,
                app_id=address.app_id,
                cell_id=address.cell_id,
                session_id=address.session_id,
                capsule_digest=address.capsule_digest,
                branch_id=address.branch_id,
                event_type=EventType.REPLY_DELIVERED,
                event_id=_stable_event_id(
                    address.tenant_id,
                    "reply-delivered",
                    address.app_id,
                    address.cell_id,
                    address.session_id,
                    address.capsule_digest,
                    address.branch_id,
                    provider_message_id,
                ),
                payload={
                    "reply_hash": _sha256_text(reply),
                    "provider_message_id_hash": _sha256_text(provider_message_id),
                },
                causation_id=head.event_id if head is not None else None,
                correlation_id=correlation_id,
                trace_id=trace_id,
                request_id=request_id,
            )
        )

    def fork(
        self,
        address: CellAddress,
        *,
        from_sequence: int,
        new_branch_id: str,
        target_capsule_digest: str | None = None,
    ) -> CellAddress:
        """Create a cheap branch, optionally rebased onto a candidate Capsule."""

        target = target_capsule_digest or address.capsule_digest
        self.get_capsule(address.tenant_id, target)
        branch = self.events.fork(
            address,
            from_sequence,
            new_branch_id=new_branch_id,
            target_capsule_digest=target,
        )
        self._active_cells.add(branch.address)
        return branch.address

    def replay(self, address: CellAddress) -> ProjectionResult[dict[str, Any]]:
        """Verify the chain and deterministically rebuild the default projection."""

        return ProjectionReplayer[dict[str, Any]](self.events).assert_deterministic(
            address,
            default_cell_reducer,
            initial_state={},
        )

    @staticmethod
    def _validate_intent_namespace(address: CellAddress, intent: ToolIntent) -> None:
        if (
            intent.tenant_id != address.tenant_id
            or intent.app_id != address.app_id
            or intent.cell_id != address.cell_id
            or intent.session_id != address.session_id
            or intent.capsule_digest != address.capsule_digest
            or intent.branch_id != address.branch_id
        ):
            raise CellNamespaceMismatch("tool intent does not belong to the target Cell")

    def _append_from_intent(
        self,
        address: CellAddress,
        intent: ToolIntent,
        event_type: str | EventType,
        payload: Mapping[str, object],
        *,
        causation_id: str | None = None,
    ) -> CausalEvent:
        return self.events.append(
            EventDraft(
                tenant_id=address.tenant_id,
                app_id=address.app_id,
                cell_id=address.cell_id,
                session_id=address.session_id,
                capsule_digest=address.capsule_digest,
                branch_id=address.branch_id,
                event_type=event_type,
                event_id=_stable_event_id(
                    address.tenant_id,
                    "intent-event",
                    address.app_id,
                    address.cell_id,
                    address.session_id,
                    address.capsule_digest,
                    address.branch_id,
                    intent.intent_id,
                    str(event_type),
                ),
                payload=payload,
                causation_id=causation_id,
                correlation_id=intent.request_id or intent.intent_id,
                trace_id=intent.trace_id or intent.intent_id,
                request_id=intent.request_id or intent.intent_id,
            )
        )


__all__ = [
    "AgentCellFabric",
    "BranchEffectDenied",
    "CapsuleNotRegistered",
    "CellActivation",
    "CellNamespaceMismatch",
    "CellNotActive",
    "default_cell_reducer",
]
