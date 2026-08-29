"""Offline, credential-free demonstration of the complete Agent Cell chain."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trpc_service.cell.capsule import AgentCapsule, CapsuleMetadata, CapsuleSpec
from trpc_service.cell.intents import IntentRisk, PolicyDecision, ToolIntent
from trpc_service.cell.runtime import AgentCellFabric, BranchEffectDenied
from trpc_service.cell.scheduler import NodeSnapshot


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
            graph="sha256:customer-service-graph-v1",
            prompt="sha256:redacted-prompt-v3",
            model_policy="policy://model/cost-aware-v2",
            tool_manifest="sha256:refund-tools-v4",
            governance_policy="policy://governance/refund-v8",
            knowledge_snapshot="sha256:knowledge-20260829",
            storage_profile="enterprise-cn",
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
            graph="sha256:customer-service-graph-v1",
            prompt="sha256:redacted-prompt-v4-candidate",
            model_policy="policy://model/quality-candidate-v3",
            tool_manifest="sha256:refund-tools-v4",
            governance_policy="policy://governance/refund-v8",
            knowledge_snapshot="sha256:knowledge-20260829",
            storage_profile="enterprise-cn",
            channel_capabilities=("tool-sandbox", "wecom"),
        ),
    ).sign(signing_key, key_id="ephemeral-demo-key")
    fabric = AgentCellFabric(
        trusted_capsule_keys={"ephemeral-demo-key": signing_key.public_key()},
    )
    digest = fabric.register_capsule(capsule)
    candidate_digest = fabric.register_capsule(candidate_capsule)

    activation = fabric.activate_cell(
        tenant_id="award-tenant",
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
                capacity_memory_mb=8_192,
                max_cells=100,
                capabilities=frozenset({"wecom"}),
            ),
            NodeSnapshot(
                node_id="node-compliant-cn",
                region="cn-shanghai",
                capacity_cpu_millis=4_000,
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

    intent = ToolIntent(
        tenant_id="award-tenant",
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
    committed = await fabric.execute_intent(
        activation.address,
        intent,
        external_refund,
        confirmation_scope=approval,
    )
    duplicate = await fabric.execute_intent(
        activation.address,
        intent,
        external_refund,
        confirmation_scope=approval,
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
        "intent_effect": {
            "initial_status": pending.status.value,
            "committed_status": committed.status.value,
            "duplicate_status": duplicate.status.value,
            "external_effect_calls": effect_calls,
            "effect_key": intent.effect_key,
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
        if effect_calls == 1
        and candidate_effect_blocked
        and candidate_real_effect_calls == 0
        and candidate_simulation_calls == 1
        and simulated.status.value == "simulated"
        and pending.status.value == "require_confirmation"
        and committed.status.value == "succeeded"
        else "fail",
    }


__all__ = ["run_demo"]
