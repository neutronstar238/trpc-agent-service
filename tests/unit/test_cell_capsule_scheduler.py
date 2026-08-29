"""Unit contracts for Agent Capsules and deterministic Cell placement."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from trpc_service.cell.capsule import (
    AgentCapsule,
    CapsuleDigestMismatch,
    CapsuleMetadata,
    CapsuleSignature,
    CapsuleSignatureError,
    CapsuleSpec,
    SLOProfile,
)
from trpc_service.cell.scheduler import (
    CellPlacementRequest,
    CellScheduler,
    NodeSnapshot,
    NoFeasibleNodeError,
    SchedulerWeights,
)


def make_capsule(*, capabilities: tuple[str, ...] = ("wecom.markdown",)) -> AgentCapsule:
    return AgentCapsule(
        metadata=CapsuleMetadata(tenant_id="tenant-a", name="support", version=3),
        spec=CapsuleSpec(
            graph="sha256:" + "1" * 64,
            prompt="sha256:" + "2" * 64,
            modelPolicy="sha256:" + "3" * 64,
            toolManifest="sha256:" + "4" * 64,
            governancePolicy="sha256:" + "5" * 64,
            knowledgeSnapshot="sha256:" + "6" * 64,
            storageProfile="profile-enterprise",
            channelCapabilities=capabilities,
            slo={"latency_budget_ms": 1_500, "priority": 80},
        ),
    )


def make_node(node_id: str, **overrides: object) -> NodeSnapshot:
    values: dict[str, object] = {
        "node_id": node_id,
        "region": "cn-east-1",
        "capacity_cpu_millis": 4_000,
        "used_cpu_millis": 500,
        "capacity_memory_mb": 8_192,
        "used_memory_mb": 1_024,
        "max_cells": 100,
        "active_cells": 10,
        "capabilities": frozenset({"wecom.markdown", "gpu.a10"}),
        "data_localities": frozenset({"tenant-a", "kb:support"}),
        "estimated_latency_ms": 100,
        "cost_per_hour": 1.0,
    }
    values.update(overrides)
    return NodeSnapshot(**values)  # type: ignore[arg-type]


def make_request(**overrides: object) -> CellPlacementRequest:
    values: dict[str, object] = {
        "cell_id": "cell-001",
        "tenant_id": "tenant-a",
        "capsule_digest": "sha256:" + "a" * 64,
        "slo": SLOProfile(latency_budget_ms=1_000),
        "required_capabilities": frozenset({"wecom.markdown"}),
        "data_localities": frozenset({"tenant-a", "kb:support"}),
        "compliance_regions": frozenset({"cn-east-1"}),
        "cpu_millis": 250,
        "memory_mb": 256,
    }
    values.update(overrides)
    return CellPlacementRequest(**values)  # type: ignore[arg-type]


def test_capsule_digest_is_canonical_and_excludes_signature_envelope() -> None:
    first = make_capsule(capabilities=("wecom.markdown", "feishu.card"))
    second = make_capsule(capabilities=("feishu.card", "wecom.markdown"))

    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.compute_digest() == second.compute_digest()
    assert first.with_digest().verify_digest()

    signed = first.sign(Ed25519PrivateKey.generate(), key_id="platform-key-1")
    assert signed.digest == first.compute_digest()
    assert signed.compute_digest() == first.compute_digest()
    assert signed.content_digest == first.compute_digest()


def test_capsule_public_manifest_excludes_signature_and_keeps_digest() -> None:
    signed = make_capsule().sign(Ed25519PrivateKey.generate(), key_id="platform-key-1")

    public = signed.public_manifest()

    assert public["apiVersion"] == "agent.trpc.io/v1"
    assert public["digest"] == signed.digest
    assert "signature" not in public
    assert public["spec"]["channelCapabilities"] == ["wecom.markdown"]


def test_capsule_digest_and_identity_validation_errors_are_explicit() -> None:
    with pytest.raises(ValidationError, match="digest must use"):
        AgentCapsule.model_validate(make_capsule().model_dump() | {"digest": "sha256:not-a-digest"})
    with pytest.raises(ValidationError, match="value cannot be empty"):
        AgentCapsule(
            apiVersion=" ",
            metadata={"tenant_id": "tenant-a", "name": "support"},
            spec={
                "graph": "g",
                "prompt": "p",
                "modelPolicy": "m",
                "toolManifest": "t",
                "governancePolicy": "g",
                "storageProfile": "s",
            },
        )
    with pytest.raises(ValidationError, match="capability values cannot be empty"):
        CapsuleSpec(
            graph="g",
            prompt="p",
            modelPolicy="m",
            toolManifest="t",
            governancePolicy="g",
            storageProfile="s",
            channelCapabilities=(" ",),
        )


def test_capsule_optional_knowledge_and_explicit_digest_are_supported() -> None:
    capsule = make_capsule().model_copy(update={"digest": "sha256:" + "0" * 64})
    no_knowledge = CapsuleSpec(
        graph="g",
        prompt="p",
        modelPolicy="m",
        toolManifest="t",
        governancePolicy="g",
        storageProfile="s",
        knowledgeSnapshot=None,
    )

    assert no_knowledge.knowledge_snapshot is None
    assert capsule.digest == "sha256:" + "0" * 64


def test_capsule_signature_verifies_with_raw_public_key_and_digest_is_required() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = make_capsule().sign(private_key, key_id="platform-key-1")

    signed.verify({"platform-key-1": private_key.public_key().public_bytes_raw()})
    with pytest.raises(CapsuleSignatureError, match="not trusted"):
        signed.verify({"other-key": private_key.public_key()})

    unsigned = make_capsule().with_digest()
    with pytest.raises(CapsuleSignatureError, match="signature is required"):
        unsigned.verify({})
    with pytest.raises(CapsuleSignatureError, match="trusted signing keys are required"):
        signed.verify()


def test_capsule_signature_validation_and_invalid_key_types_are_rejected() -> None:
    with pytest.raises(ValidationError, match="base64url encoded"):
        CapsuleSignature(key_id="key", value="bad*")
    with pytest.raises(ValidationError, match="base64url encoded"):
        CapsuleSignature(key_id="key", value="a")
    with pytest.raises(ValidationError, match="64 bytes"):
        CapsuleSignature(key_id="key", value="aa")
    with pytest.raises(ValidationError, match="value cannot be empty"):
        CapsuleSignature(key_id=" ", value="aa")

    capsule = make_capsule()
    with pytest.raises(CapsuleSignatureError, match="32 raw bytes"):
        capsule.sign(b"short", key_id="key")
    with pytest.raises(CapsuleSignatureError, match="unsupported"):
        capsule.sign(object(), key_id="key")  # type: ignore[arg-type]


def test_capsule_invalid_signature_and_public_key_inputs_are_rejected() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = make_capsule().sign(private_key, key_id="platform-key-1")
    with pytest.raises(CapsuleSignatureError, match="invalid"):
        signed.verify({"platform-key-1": Ed25519PrivateKey.generate().public_key()})
    with pytest.raises(CapsuleSignatureError, match="32 raw bytes"):
        signed.verify({"platform-key-1": b"short"})
    with pytest.raises(CapsuleSignatureError, match="unsupported"):
        signed.verify({"platform-key-1": object()})  # type: ignore[dict-item]
    signed.verify(
        require_signature=False,
        trusted_keys={"platform-key-1": private_key.public_key()},
    )


def test_capsule_tampering_fails_before_signature_check() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = make_capsule().sign(private_key, key_id="platform-key-1")
    tampered = signed.model_copy(
        update={"metadata": signed.metadata.model_copy(update={"name": "billing"})}
    )

    with pytest.raises(CapsuleDigestMismatch):
        tampered.verify({"platform-key-1": private_key.public_key()})


def test_capsule_is_frozen_and_rejects_unknown_manifest_fields() -> None:
    capsule = make_capsule()
    with pytest.raises((TypeError, ValidationError)):
        capsule.metadata.name = "changed"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        CapsuleSpec(
            graph="g",
            prompt="p",
            modelPolicy="m",
            toolManifest="t",
            governancePolicy="g",
            storageProfile="s",
            unexpected="value",
        )


def test_capsule_accepts_raw_private_key_bytes_and_rejects_invalid_reference_values() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = make_capsule().sign(private_key.private_bytes_raw(), key_id="platform-key-1")
    assert signed.verify_digest()
    for field in (
        "graph",
        "prompt",
        "modelPolicy",
        "toolManifest",
        "governancePolicy",
        "storageProfile",
    ):
        with pytest.raises(ValidationError, match="value cannot be empty"):
            CapsuleSpec(
                graph="g" if field != "graph" else " ",
                prompt="p" if field != "prompt" else " ",
                modelPolicy="m" if field != "modelPolicy" else " ",
                toolManifest="t" if field != "toolManifest" else " ",
                governancePolicy="g" if field != "governancePolicy" else " ",
                storageProfile="s" if field != "storageProfile" else " ",
            )


def test_scheduler_applies_hard_constraints_and_returns_explainable_ranking() -> None:
    scheduler = CellScheduler()
    request = make_request()
    good = make_node("node-good")
    wrong_region = make_node("node-wrong-region", region="us-west-1")
    missing_capability = make_node("node-missing", capabilities=frozenset())

    decision = scheduler.place(request, [missing_capability, wrong_region, good])

    assert decision.node_id == "node-good"
    assert decision.winner.reasons[0].startswith("slo=")
    assert dict(decision.rejected) == {
        "node-missing": "missing required capabilities: wecom.markdown",
        "node-wrong-region": "node region violates compliance constraint",
    }


def test_scheduler_is_order_independent_and_ties_break_by_node_id() -> None:
    scheduler = CellScheduler()
    request = make_request(compliance_regions=frozenset())
    first = make_node("node-b")
    second = make_node("node-a")

    left = scheduler.place(request, [first, second])
    right = scheduler.place(request, [second, first])

    assert left.node_id == right.node_id == "node-a"
    assert left.candidates == right.candidates
    assert scheduler.select_node(request, [first, second]) == "node-a"
    assert scheduler.schedule(request, [first, second]).node_id == "node-a"


def test_scheduler_scores_slo_locality_capability_cost_and_load() -> None:
    request = make_request(
        compliance_regions=frozenset(),
        preferred_regions=frozenset({"cn-east-1"}),
        preferred_capabilities=frozenset({"gpu.a10"}),
        max_cost_per_hour=5.0,
    )
    local = make_node("node-local", data_localities=frozenset({"tenant-a", "kb:support"}))
    remote = make_node(
        "node-remote",
        region="us-west-1",
        data_localities=frozenset(),
        capabilities=frozenset({"wecom.markdown"}),
        estimated_latency_ms=900,
        cost_per_hour=4.0,
        used_cpu_millis=3_500,
        used_memory_mb=7_000,
        active_cells=90,
    )

    decision = CellScheduler().place(request, [remote, local])

    assert decision.node_id == "node-local"
    assert set(name for name, _ in decision.winner.component_scores) == {
        "slo",
        "locality",
        "capability",
        "compliance",
        "cost",
        "load",
    }
    assert decision.winner.component("locality") == 1.0
    assert decision.winner.component("capability") == 1.0


def test_scheduler_rejects_budget_and_resource_overcommit() -> None:
    request = make_request(max_cost_per_hour=0.5, cpu_millis=250)
    expensive = make_node("node-expensive", cost_per_hour=1.0, used_cpu_millis=100)
    overloaded = make_node("node-overloaded", used_cpu_millis=3_900, cost_per_hour=0.1)

    with pytest.raises(NoFeasibleNodeError) as error:
        CellScheduler().place(request, [overloaded, expensive])

    assert error.value.cell_id == "cell-001"
    assert "insufficient CPU capacity" in str(error.value)
    assert "node cost exceeds Cell budget" in str(error.value)


def test_scheduler_rejects_unhealthy_draining_and_duplicate_nodes() -> None:
    request = make_request()
    scheduler = CellScheduler()
    with pytest.raises(NoFeasibleNodeError, match="unhealthy"):
        scheduler.place(request, [make_node("node-1", healthy=False)])
    with pytest.raises(NoFeasibleNodeError, match="draining"):
        scheduler.place(request, [make_node("node-1", draining=True)])
    with pytest.raises(ValueError, match="duplicate node_id"):
        scheduler.place(request, [make_node("node-1"), make_node("node-1")])


def test_scheduler_rejects_tenant_memory_concurrency_and_empty_identity_constraints() -> None:
    scheduler = CellScheduler()
    request = make_request()
    with pytest.raises(NoFeasibleNodeError, match="tenant is not allowed"):
        scheduler.place(
            request,
            [make_node("node-tenant", tenant_allowlist=frozenset({"tenant-b"}))],
        )
    with pytest.raises(NoFeasibleNodeError, match="insufficient memory"):
        scheduler.place(request, [make_node("node-memory", used_memory_mb=8_000)])
    with pytest.raises(NoFeasibleNodeError, match="concurrency"):
        scheduler.place(request, [make_node("node-cells", active_cells=100)])
    with pytest.raises(ValueError, match="cell_id cannot be empty"):
        make_request(cell_id=" ")
    with pytest.raises(ValueError, match="tenant_id cannot be empty"):
        make_request(tenant_id=" ")
    with pytest.raises(ValueError, match="capsule_digest cannot be empty"):
        make_request(capsule_digest=" ")
    with pytest.raises(ValueError, match="node_id cannot be empty"):
        make_node(" ")
    with pytest.raises(ValueError, match="region cannot be empty"):
        make_node("node-region", region=" ")


def test_scheduler_validates_empty_sets_limits_and_zero_cost_ratio() -> None:
    with pytest.raises(ValueError, match="set values cannot be empty"):
        make_request(required_capabilities={" "})
    with pytest.raises(ValueError, match="max_cost_per_hour"):
        make_request(max_cost_per_hour=-1)
    with pytest.raises(ValueError, match="max_cost_per_hour"):
        make_request(max_cost_per_hour=float("nan"))
    with pytest.raises(ValueError, match="capacities must be positive"):
        make_node("bad-capacity", capacity_memory_mb=0)
    with pytest.raises(ValueError, match="usage cannot be negative"):
        make_node("bad-usage", used_cpu_millis=-1)
    with pytest.raises(ValueError, match="cost_per_hour"):
        make_node("bad-cost", cost_per_hour=-1)

    zero_cost = make_node("node-zero-cost", cost_per_hour=0)
    request = make_request(compliance_regions=frozenset(), max_cost_per_hour=0)
    assert CellScheduler().place(request, [zero_cost]).winner.component("cost") == 0.0


def test_scheduler_validates_weights_and_node_inputs() -> None:
    with pytest.raises(ValueError):
        SchedulerWeights(slo=-1)
    with pytest.raises(ValueError):
        SchedulerWeights(slo=0, locality=0, capability=0, compliance=0, cost=0, load=0)
    with pytest.raises(ValueError):
        make_node("bad", estimated_latency_ms=0)
    with pytest.raises(ValueError):
        make_request(cpu_millis=0)
