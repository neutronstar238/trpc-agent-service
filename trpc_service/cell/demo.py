"""Offline, credential-free demonstration of the complete Agent Cell chain."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trpc_service.agent.fake import DeterministicAgent
from trpc_service.agent.registry import RevisionRegistry
from trpc_service.agent.runner import TenantRunner
from trpc_service.cell.capsule import AgentCapsule, CapsuleMetadata, CapsuleSpec
from trpc_service.cell.effects import (
    CellApprovalAuthority,
    ExactlyOnceEffectExecutor,
    ReconciliationOutcome,
)
from trpc_service.cell.events import EventDraft
from trpc_service.cell.intents import IntentRisk, PolicyDecision, ToolIntent
from trpc_service.cell.reconciliation import (
    EffectReconciliationCoordinator,
    ProviderReconciler,
)
from trpc_service.cell.replay import state_fingerprint
from trpc_service.cell.runtime import AgentCellFabric, BranchEffectDenied
from trpc_service.cell.scheduler import NodeSnapshot
from trpc_service.channels.envelopes import InboundEnvelope, PayloadKind
from trpc_service.storage.models import SessionLease, SessionSnapshot
from trpc_service.tenant.models import (
    Channel,
    ConversationKind,
    ModelPolicy,
    StorageSelection,
    TenantConfig,
    TenantContext,
)


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class _DemoAgentLoader:
    async def __call__(self, config: TenantConfig) -> DeterministicAgent:
        del config
        return DeterministicAgent(
            name="cell-demo-runner",
            response="已收到退款申请, 正在进行受控校验。",
        )


async def run_demo() -> dict[str, Any]:
    """Execute Capsule → placement → intent/effect → replay/branch offline."""

    signing_key = Ed25519PrivateKey.generate()
    capsule = AgentCapsule(
        metadata=CapsuleMetadata(
            tenant_id="award-tenant",
            name="wecom-customer-service",
            labels={"track": "causal-agent-cell"},
        ),
        spec=CapsuleSpec(
            graph=_digest("customer-service-graph-v1"),
            prompt=_digest("redacted-prompt-v3"),
            model_policy="policy://model/cost-aware-v2",
            tool_manifest=_digest("refund-tools-v4"),
            governance_policy="policy://governance/refund-v8",
            knowledge_snapshot=_digest("knowledge-20260829"),
            storage_profile="storage://profiles/enterprise-cn",
            channel_capabilities=("tool-sandbox", "wecom"),
        ),
    ).sign(signing_key, key_id="ephemeral-demo-key")
    candidate_capsule = AgentCapsule(
        metadata=CapsuleMetadata(
            tenant_id="award-tenant",
            name="wecom-customer-service",
            version=2,
            labels={"track": "causal-agent-cell", "mode": "shadow"},
        ),
        spec=CapsuleSpec(
            graph=_digest("customer-service-graph-v1"),
            prompt=_digest("redacted-prompt-v4-candidate"),
            model_policy="policy://model/quality-candidate-v3",
            tool_manifest=_digest("refund-tools-v4"),
            governance_policy="policy://governance/refund-v8",
            knowledge_snapshot=_digest("knowledge-20260829"),
            storage_profile="storage://profiles/enterprise-cn",
            channel_capabilities=("tool-sandbox", "wecom"),
        ),
    ).sign(signing_key, key_id="ephemeral-demo-key")
    approval_authority = CellApprovalAuthority(b"a" * 32)
    effect_executor = ExactlyOnceEffectExecutor(
        approval_verifier=approval_authority,
        policy_judge=lambda proposed: (
            PolicyDecision.ALLOW
            if proposed.tool_name.startswith("refund.")
            else PolicyDecision.DENY
        ),
    )
    fabric = AgentCellFabric(
        trusted_capsule_keys={"award-tenant": {"ephemeral-demo-key": signing_key.public_key()}},
        effect_executor=effect_executor,
    )
    digest = fabric.register_capsule(capsule)
    candidate_digest = fabric.register_capsule(candidate_capsule)

    activation = fabric.activate_cell(
        tenant_id="award-tenant",
        app_id="wecom-customer-service",
        cell_id="cell-refund-demo",
        session_id="session-wecom-demo",
        capsule_digest=digest,
        message="申请订单退款",
        channel="wecom",
        external_message_id="wecom-demo-001",
        nodes=[
            NodeSnapshot(
                node_id="node-general",
                region="cn-beijing",
                capacity_cpu_millis=4_000,
                observed_generation=1,
                capacity_memory_mb=8_192,
                max_cells=100,
                capabilities=frozenset({"wecom"}),
            ),
            NodeSnapshot(
                node_id="node-compliant-cn",
                region="cn-shanghai",
                capacity_cpu_millis=4_000,
                observed_generation=1,
                capacity_memory_mb=8_192,
                max_cells=100,
                capabilities=frozenset({"wecom", "tool-sandbox"}),
                data_localities=frozenset({"enterprise-cn"}),
                estimated_latency_ms=80,
            ),
        ],
        compliance_regions=frozenset({"cn-shanghai"}),
        data_localities=frozenset({"enterprise-cn"}),
        correlation_id="goal-refund-demo",
        trace_id="trace-refund-demo",
        request_id="request-refund-demo",
    )

    # Run the public tRPC-Agent Runner path and project its real SDK Event into
    # the same Cell stream.  The event body remains private; only a digest and
    # operational flags enter the causal log.
    runner_config = TenantConfig(
        tenant_id="award-tenant",
        app_id="wecom-customer-service",
        version=1,
        model=ModelPolicy(provider="offline", model="deterministic"),
        storage=StorageSelection(profile_id="enterprise-cn"),
        instructions="Answer the verified enterprise user request.",
    )
    runner_context = TenantContext(
        tenant_id="award-tenant",
        app_id="wecom-customer-service",
        config_version=1,
        channel_binding_id="binding-wecom-demo",
        principal_id="principal-demo",
        session_id=activation.address.session_id,
        request_id="request-refund-demo",
        trace_id="trace-refund-demo",
    )
    runner_lease = SessionLease(
        tenant_id=runner_context.tenant_id,
        session_id=runner_context.session_id,
        turn_id="turn-refund-demo",
        inbound_id="wecom-demo-001",
        worker_id="offline-demo-worker",
        fencing_token=1,
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
        snapshot=SessionSnapshot(
            tenant_id=runner_context.tenant_id,
            app_id=runner_context.app_id,
            session_id=runner_context.session_id,
            principal_id=runner_context.principal_id,
        ),
    )

    runner = TenantRunner(
        config=runner_config,
        lease=runner_lease,
        registry=RevisionRegistry(),
        agent_loader=_DemoAgentLoader(),
    )
    sdk_events = []
    runner_input = InboundEnvelope(
        channel=Channel.WECOM_AI_BOT,
        account_id="wecom-demo-account",
        external_message_id="wecom-demo-001",
        external_user_id="principal-demo",
        conversation_kind=ConversationKind.DIRECT,
        payload_kind=PayloadKind.TEXT,
        text="申请订单退款",
    )
    async for sdk_event in runner.run(runner_context, runner_input):
        sdk_events.append(sdk_event)
        fabric.events.append(
            EventDraft(
                tenant_id=activation.address.tenant_id,
                app_id=activation.address.app_id,
                cell_id=activation.address.cell_id,
                session_id=activation.address.session_id,
                capsule_digest=activation.address.capsule_digest,
                branch_id=activation.address.branch_id,
                event_type="agent.event.observed",
                event_id="sdk-event-"
                + (
                    sdk_event.id
                    or state_fingerprint(sdk_event.model_dump(mode="json", by_alias=True))
                ),
                payload={
                    "sdk_event_hash": state_fingerprint(
                        sdk_event.model_dump(mode="json", by_alias=True)
                    ),
                    "final_response": sdk_event.is_final_response(),
                    "visible": sdk_event.visible,
                },
                causation_id=activation.accepted_event.event_id,
                correlation_id="goal-refund-demo",
                trace_id="trace-refund-demo",
                request_id="request-refund-demo",
            )
        )

    intent = ToolIntent(
        tenant_id="award-tenant",
        app_id=activation.address.app_id,
        cell_id=activation.address.cell_id,
        session_id=activation.address.session_id,
        tool_name="refund.create",
        arguments={"order_id": "ORDER-DEMO", "amount": 100},
        intent_id="intent-refund-demo",
        policy_decision=PolicyDecision.REQUIRE_CONFIRMATION,
        risk=IntentRisk.NON_IDEMPOTENT,
        principal_id="principal-demo",
        request_id="request-refund-demo",
        trace_id="trace-refund-demo",
        capsule_digest=digest,
    )
    effect_calls = 0

    async def external_refund() -> dict[str, str]:
        nonlocal effect_calls
        effect_calls += 1
        return {"provider_reference": "refund-demo-accepted"}

    pending = await fabric.execute_intent(activation.address, intent, external_refund)
    approval = intent.confirmation_scope(
        approved_by="human-reviewer",
        approval_id="approval-demo-001",
    )
    approval_credential = await approval_authority.issue(
        intent,
        approved_by="human-reviewer",
        approval_id="approval-demo-001",
    )
    committed = await fabric.execute_intent(
        activation.address,
        intent,
        external_refund,
        confirmation_scope=approval,
        approval_credential=approval_credential,
    )
    duplicate = await fabric.execute_intent(
        activation.address,
        intent,
        external_refund,
    )

    # Model the hard production case: the provider applied a request but its
    # response was lost.  Reconciliation calls only the provider's read-only
    # status endpoint and converges the fenced attempt without replaying it.
    ambiguous_intent = ToolIntent(
        tenant_id="award-tenant",
        app_id=activation.address.app_id,
        cell_id=activation.address.cell_id,
        session_id=activation.address.session_id,
        tool_name="refund.notify",
        arguments={"order_id": "ORDER-DEMO"},
        intent_id="intent-refund-ambiguous-demo",
        policy_decision=PolicyDecision.ALLOW,
        risk=IntentRisk.NON_IDEMPOTENT,
        principal_id="principal-demo",
        request_id="request-refund-demo",
        trace_id="trace-refund-demo",
        capsule_digest=digest,
    )
    ambiguous_provider_calls = 0
    status_probe_calls = 0

    async def provider_applies_then_times_out() -> None:
        nonlocal ambiguous_provider_calls
        ambiguous_provider_calls += 1
        raise TimeoutError("provider response unavailable")

    ambiguous_scope = ambiguous_intent.confirmation_scope(
        approved_by="human-reviewer",
        approval_id="approval-demo-ambiguous-001",
    )
    ambiguous_credential = await approval_authority.issue(
        ambiguous_intent,
        approved_by="human-reviewer",
        approval_id="approval-demo-ambiguous-001",
    )
    ambiguous = await fabric.execute_intent(
        activation.address,
        ambiguous_intent,
        provider_applies_then_times_out,
        confirmation_scope=ambiguous_scope,
        approval_credential=ambiguous_credential,
    )

    async def read_only_status_probe(*_args: object) -> dict[str, str]:
        nonlocal status_probe_calls
        status_probe_calls += 1
        return {"outcome": ReconciliationOutcome.APPLIED.value, "summary": "provider_applied"}

    reconciled = await EffectReconciliationCoordinator(
        effect_executor.ledger,
        ProviderReconciler(read_only_status_probe, reconciler_id="demo-status-query"),
    ).reconcile(ambiguous_intent, ambiguous)
    after_reconciliation = await fabric.execute_intent(
        activation.address,
        ambiguous_intent,
        provider_applies_then_times_out,
    )
    fabric.deliver_reply(
        activation.address,
        reply="退款申请已提交",
        provider_message_id="wecom-reply-demo-001",
        correlation_id="goal-refund-demo",
        trace_id="trace-refund-demo",
        request_id="request-refund-demo",
    )

    main = fabric.replay(activation.address)
    candidate_address = fabric.fork(
        activation.address,
        from_sequence=activation.activated_event.sequence,
        new_branch_id="candidate-model-b",
        target_capsule_digest=candidate_digest,
    )
    candidate_real_effect_calls = 0
    candidate_simulation_calls = 0
    candidate_intent = ToolIntent(
        tenant_id=candidate_address.tenant_id,
        app_id=candidate_address.app_id,
        cell_id=candidate_address.cell_id,
        session_id=candidate_address.session_id,
        branch_id=candidate_address.branch_id,
        tool_name="refund.create",
        arguments={"order_id": "ORDER-DEMO", "amount": 100},
        intent_id="intent-refund-candidate",
        policy_decision=PolicyDecision.ALLOW,
        risk=IntentRisk.LOW,
        principal_id="principal-demo",
        request_id="request-refund-shadow",
        trace_id="trace-refund-shadow",
        capsule_digest=candidate_digest,
    )

    async def candidate_real_effect() -> dict[str, bool]:
        nonlocal candidate_real_effect_calls
        candidate_real_effect_calls += 1
        return {"committed": True}

    candidate_effect_blocked = False
    try:
        await fabric.execute_intent(
            candidate_address,
            candidate_intent,
            candidate_real_effect,
        )
    except BranchEffectDenied:
        candidate_effect_blocked = True

    simulation_intent = ToolIntent(
        tenant_id=candidate_address.tenant_id,
        app_id=candidate_address.app_id,
        cell_id=candidate_address.cell_id,
        session_id=candidate_address.session_id,
        branch_id=candidate_address.branch_id,
        tool_name="refund.create",
        arguments={"order_id": "ORDER-DEMO", "amount": 100},
        intent_id="intent-refund-candidate-simulation",
        policy_decision=PolicyDecision.SIMULATE_ONLY,
        risk=IntentRisk.HIGH,
        principal_id="principal-demo",
        request_id="request-refund-shadow",
        trace_id="trace-refund-shadow",
        capsule_digest=candidate_digest,
    )

    async def candidate_simulation() -> dict[str, int]:
        nonlocal candidate_simulation_calls
        candidate_simulation_calls += 1
        return {"affected_orders": 1}

    simulated = await fabric.execute_intent(
        candidate_address,
        simulation_intent,
        candidate_real_effect,
        simulate=candidate_simulation,
    )
    fabric.deliver_reply(
        candidate_address,
        reply="候选模型影子回复",
        provider_message_id="shadow-not-delivered",
        correlation_id="goal-refund-shadow",
        trace_id="trace-refund-shadow",
        request_id="request-refund-shadow",
    )
    candidate = fabric.replay(candidate_address)

    return {
        "capsule": {
            "digest": digest,
            "candidate_digest": candidate_digest,
            "signature_verified": True,
        },
        "placement": {
            "selected_node": activation.placement.node_id,
            "score": activation.placement.score,
            "rejected": list(activation.placement.rejected),
        },
        "runner": {
            "sdk": "tRPC-Agent-Python public Runner",
            "sdk_event_count": len(sdk_events),
            "final_response_observed": any(event.is_final_response() for event in sdk_events),
            "cell_projected": True,
        },
        "intent_effect": {
            "initial_status": pending.status.value,
            "committed_status": committed.status.value,
            "duplicate_status": duplicate.status.value,
            "external_effect_calls": effect_calls,
            "effect_key": intent.effect_key,
        },
        "reconciliation": {
            "initial_status": ambiguous.status.value,
            "reconciled_status": reconciled.status.value,
            "duplicate_status": after_reconciliation.status.value,
            "provider_effect_calls": ambiguous_provider_calls,
            "status_probe_calls": status_probe_calls,
            "automatic_retry_blocked": ambiguous_provider_calls == 1,
        },
        "replay": {
            "main_event_count": main.event_count,
            "main_state_hash": main.state_hash,
            "candidate_event_count": candidate.event_count,
            "candidate_state_hash": candidate.state_hash,
            "candidate_branch": candidate_address.branch_id,
            "candidate_real_effect_blocked": candidate_effect_blocked,
            "candidate_real_effect_calls": candidate_real_effect_calls,
            "candidate_simulation_calls": candidate_simulation_calls,
            "candidate_simulation_status": simulated.status.value,
            "main_unchanged_after_fork": fabric.replay(activation.address).state_hash
            == main.state_hash,
        },
        "trace_id": "trace-refund-demo",
        "gate": "pass"
        if len(sdk_events) >= 1
        and any(event.is_final_response() for event in sdk_events)
        and effect_calls == 1
        and ambiguous.status.value == "ambiguous"
        and reconciled.status.value == "succeeded"
        and after_reconciliation.status.value == "succeeded"
        and ambiguous_provider_calls == 1
        and status_probe_calls == 1
        and candidate_effect_blocked
        and candidate_real_effect_calls == 0
        and candidate_simulation_calls == 1
        and simulated.status.value == "simulated"
        and pending.status.value == "require_confirmation"
        and committed.status.value == "succeeded"
        else "fail",
    }


__all__ = ["run_demo"]
