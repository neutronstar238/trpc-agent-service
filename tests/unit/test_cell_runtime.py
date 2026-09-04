import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trpc_service.cell.capsule import AgentCapsule, CapsuleMetadata, CapsuleSpec
from trpc_service.cell.demo import run_demo
from trpc_service.cell.effects import EffectStatus
from trpc_service.cell.intents import IntentRisk, PolicyDecision, ToolIntent
from trpc_service.cell.runtime import (
    AgentCellFabric,
    BranchEffectDenied,
    CellActivation,
    CellNamespaceMismatch,
)
from trpc_service.cell.scheduler import NodeSnapshot


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _signed_capsule() -> tuple[AgentCapsule, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    capsule = AgentCapsule(
        metadata=CapsuleMetadata(tenant_id="tenant-a", name="customer-service"),
        spec=CapsuleSpec(
            graph=_digest("graph"),
            prompt=_digest("prompt"),
            model_policy="policy://model/v1",
            tool_manifest=_digest("tools"),
            governance_policy="policy://governance/v1",
            knowledge_snapshot=_digest("knowledge"),
            storage_profile="storage://profiles/enterprise-cn",
            channel_capabilities=("wecom", "tool-sandbox"),
        ),
    ).sign(private_key, key_id="award-demo")
    return capsule, private_key


def _fabric_and_activation() -> tuple[AgentCellFabric, CellActivation, str]:
    capsule, private_key = _signed_capsule()
    fabric = AgentCellFabric(
        trusted_capsule_keys={"tenant-a": {"award-demo": private_key.public_key()}},
        policy_judge=lambda _intent: PolicyDecision.ALLOW,
    )
    digest = fabric.register_capsule(capsule)
    activation = fabric.activate_cell(
        tenant_id="tenant-a",
        cell_id="cell-customer-1",
        session_id="session-1",
        capsule_digest=digest,
        message="please refund order 42",
        channel="wecom",
        external_message_id="wecom-42",
        nodes=[
            NodeSnapshot(
                node_id="node-us",
                region="us-west",
                capacity_cpu_millis=4_000,
                observed_generation=1,
                capacity_memory_mb=8_192,
                max_cells=100,
                capabilities=frozenset({"wecom", "tool-sandbox"}),
            ),
            NodeSnapshot(
                node_id="node-cn",
                region="cn-shanghai",
                capacity_cpu_millis=4_000,
                observed_generation=1,
                capacity_memory_mb=8_192,
                max_cells=100,
                capabilities=frozenset({"wecom", "tool-sandbox"}),
                data_localities=frozenset({"enterprise-cn"}),
            ),
        ],
        compliance_regions=frozenset({"cn-shanghai"}),
        data_localities=frozenset({"enterprise-cn"}),
        correlation_id="goal-42",
        trace_id="trace-42",
        request_id="request-42",
    )
    return fabric, activation, digest


@pytest.mark.asyncio
async def test_fabric_places_executes_once_and_replays() -> None:
    fabric, activation_object, digest = _fabric_and_activation()
    activation = activation_object
    address = activation.address
    assert activation.placement.node_id == "node-cn"

    intent = ToolIntent(
        tenant_id="tenant-a",
        cell_id="cell-customer-1",
        session_id="session-1",
        tool_name="refund.propose",
        arguments={"order_id": "42"},
        intent_id="intent-refund-42",
        policy_decision=PolicyDecision.ALLOW,
        risk=IntentRisk.LOW,
        principal_id="principal-1",
        request_id="request-42",
        trace_id="trace-42",
        capsule_digest=digest,
    )
    calls = 0

    async def effect() -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {"proposal_id": "refund-proposal-42"}

    first = await fabric.execute_intent(address, intent, effect)
    second = await fabric.execute_intent(address, intent, effect)
    assert first.status == second.status == EffectStatus.SUCCEEDED
    assert calls == 1

    fabric.deliver_reply(
        address,
        reply="refund proposal created",
        provider_message_id="wecom-reply-42",
        correlation_id="goal-42",
        trace_id="trace-42",
        request_id="request-42",
    )
    projection = fabric.replay(address)
    assert projection.verified is True
    assert projection.state["status"] == "idle"
    assert projection.state["node_id"] == "node-cn"
    assert projection.state["last_effect_status"] == "succeeded"
    # The duplicate intent reuses the same immutable event ids, so the
    # causal stream grows only for the first externally visible execution.
    assert projection.event_count == 6


@pytest.mark.asyncio
async def test_intent_cannot_cross_cell_namespace() -> None:
    fabric, activation_object, digest = _fabric_and_activation()
    address = activation_object.address
    foreign = ToolIntent(
        tenant_id="tenant-b",
        cell_id=address.cell_id,
        session_id=address.session_id,
        tool_name="refund.propose",
        arguments={},
        capsule_digest=digest,
        risk=IntentRisk.LOW,
    )

    with pytest.raises(CellNamespaceMismatch):
        await fabric.execute_intent(address, foreign, lambda: None)


def test_counterfactual_branch_does_not_mutate_main() -> None:
    fabric, activation_object, _digest = _fabric_and_activation()
    address = activation_object.address
    candidate = fabric.fork(address, from_sequence=2, new_branch_id="candidate-model-b")
    fabric.deliver_reply(
        candidate,
        reply="candidate answer",
        provider_message_id="shadow-only",
        correlation_id="goal-42-shadow",
        trace_id="trace-42-shadow",
        request_id="request-42-shadow",
    )

    assert fabric.replay(address).event_count == 2
    assert fabric.replay(candidate).event_count == 3


@pytest.mark.asyncio
async def test_counterfactual_branch_cannot_commit_real_effect() -> None:
    fabric, activation, digest = _fabric_and_activation()
    candidate = fabric.fork(
        activation.address,
        from_sequence=2,
        new_branch_id="candidate-model-b",
    )
    intent = ToolIntent(
        tenant_id=candidate.tenant_id,
        cell_id=candidate.cell_id,
        session_id=candidate.session_id,
        branch_id=candidate.branch_id,
        tool_name="refund.commit",
        arguments={"order_id": "42"},
        capsule_digest=digest,
        risk=IntentRisk.LOW,
    )

    with pytest.raises(BranchEffectDenied):
        await fabric.execute_intent(candidate, intent, lambda: {"committed": True})


@pytest.mark.asyncio
async def test_counterfactual_branch_can_only_simulate_effect() -> None:
    fabric, activation, digest = _fabric_and_activation()
    candidate = fabric.fork(
        activation.address,
        from_sequence=2,
        new_branch_id="candidate-model-b",
    )
    intent = ToolIntent(
        tenant_id=candidate.tenant_id,
        cell_id=candidate.cell_id,
        session_id=candidate.session_id,
        branch_id=candidate.branch_id,
        tool_name="refund.commit",
        arguments={"order_id": "42"},
        capsule_digest=digest,
        policy_decision=PolicyDecision.SIMULATE_ONLY,
        risk=IntentRisk.HIGH,
    )
    external_calls = 0
    simulation_calls = 0

    async def external_effect() -> dict[str, bool]:
        nonlocal external_calls
        external_calls += 1
        return {"committed": True}

    async def simulate() -> dict[str, int]:
        nonlocal simulation_calls
        simulation_calls += 1
        return {"affected_orders": 1}

    receipt = await fabric.execute_intent(
        candidate,
        intent,
        external_effect,
        simulate=simulate,
    )

    assert receipt.status == EffectStatus.SIMULATED
    assert external_calls == 0
    assert simulation_calls == 1


@pytest.mark.asyncio
async def test_competition_demo_passes_all_innovation_gates() -> None:
    result = await run_demo()

    assert result["gate"] == "pass"
    assert result["capsule"]["signature_verified"] is True
    assert result["placement"]["selected_node"] == "node-compliant-cn"
    assert result["intent_effect"]["external_effect_calls"] == 1
    assert result["reconciliation"] == {
        "initial_status": "ambiguous",
        "reconciled_status": "succeeded",
        "duplicate_status": "succeeded",
        "provider_effect_calls": 1,
        "status_probe_calls": 1,
        "automatic_retry_blocked": True,
    }
    assert result["replay"]["candidate_real_effect_blocked"] is True
    assert result["replay"]["candidate_real_effect_calls"] == 0
    assert result["replay"]["candidate_simulation_calls"] == 1
    assert result["replay"]["main_unchanged_after_fork"] is True
