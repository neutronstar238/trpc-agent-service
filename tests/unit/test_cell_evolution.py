from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trpc_service.cell.capsule import AgentCapsule, CapsuleMetadata, CapsuleSpec
from trpc_service.cell.events import GENESIS_HASH, CellAddress, EventDraft, InMemoryEventStore
from trpc_service.cell.evolution import (
    CertificateVerifier,
    EvaluationObservation,
    EvidenceBundle,
    EvidenceSealingError,
    EvolutionCertificate,
    EvolutionCoordinator,
    EvolutionJudge,
    EvolutionState,
    EvolutionValidationError,
    JudgePolicy,
    PromotionAlreadyUsed,
    PromotionApprovalAuthority,
    PromotionCASConflict,
    PromotionReceiptError,
    PromotionStore,
    PromotionTarget,
    ReplayVerificationError,
    merkle_root,
    run_evolution_demo,
)


def _capsule(tenant: str, prompt: str) -> AgentCapsule:
    return AgentCapsule(
        metadata=CapsuleMetadata(tenant_id=tenant, name="evolution-test"),
        spec=CapsuleSpec(
            graph="graph://test",
            prompt=f"prompt://{prompt}",
            model_policy="policy://model/test",
            tool_manifest="tools://test",
            governance_policy="policy://governance/test",
            storage_profile="storage://test",
        ),
    ).with_digest()


def _setup() -> tuple[InMemoryEventStore, EvolutionCoordinator, CellAddress, AgentCapsule]:
    source = _capsule("tenant-a", "source")
    candidate = _capsule("tenant-a", "candidate")
    address = CellAddress(
        tenant_id="tenant-a",
        app_id="app-a",
        cell_id="cell-a",
        session_id="session-a",
        capsule_digest=source.digest or source.content_digest,
    )
    store = InMemoryEventStore()
    store.append(
        EventDraft(
            tenant_id=address.tenant_id,
            app_id=address.app_id,
            cell_id=address.cell_id,
            session_id=address.session_id,
            capsule_digest=address.capsule_digest,
            event_type="message.accepted",
            payload={"delta": 1},
            event_id="e-1",
            occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )
    coordinator = EvolutionCoordinator(store)
    run = coordinator.create_run(
        address,
        source_capsule=source,
        candidate_capsule=candidate,
        fork_sequence=1,
        fork_hash=store.head(address).event_hash,  # type: ignore[union-attr]
        dataset_id="dataset://test",
        runner_id="runner://test",
        model_id="model://test",
        policy_digest="policy://judge/test",
        tool_manifest_digest="tools://test",
        reducer_id="reducer://sum-v1",
    )
    assert run.state is EvolutionState.PLANNED
    return store, coordinator, address, candidate


def _observation(
    *, quality: int = 1010, cost: int = 90, latency: int = 90
) -> EvaluationObservation:
    return EvaluationObservation(
        sample_id="sample-1",
        quality_bps=quality,
        cost_units=cost,
        latency_ms=latency,
        baseline_quality_bps=1000,
        baseline_cost_units=100,
        baseline_latency_ms=100,
        baseline_output_hash="sha256:" + "a" * 64,
        candidate_output_hash="sha256:" + "b" * 64,
        summary="provider_secret=do-not-store",
    )


def test_merkle_root_is_stable_and_summary_is_redacted() -> None:
    first = _observation()
    second = replace(first, sample_id="sample-2")
    assert merkle_root((first, second)) == merkle_root((second, first))
    assert "provider_secret" not in first.summary
    assert first.summary.startswith("sha256:")
    assert EvaluationObservation.from_dict(first.to_dict()) == first


def test_offline_demo_and_promotion_schema_are_fail_closed() -> None:
    result = run_evolution_demo()

    assert result["gate"] == "pass"
    assert result["offline_gate"] == "pass"
    assert result["real_provider_calls"] == 0
    assert all(case["status"] == "pass" for case in result["cases"])
    assert {case["name"] for case in result["cases"]} >= {
        "tampered_evidence_rejected",
        "cross_tenant_rejected",
        "expired_certificate_rejected",
        "stale_cas_rejected",
    }

    migration = (
        Path(__file__).parents[2] / "migrations" / "versions" / ("0025_proof_carrying_evolution.py")
    )
    source = migration.read_text(encoding="utf-8")
    assert 'down_revision = "0024_cell_effect_reconciliation"' in source
    assert "CREATE ROLE trpc_evolution_authority" in source
    assert "ENABLE ROW LEVEL SECURITY" in source
    assert "FORCE ROW LEVEL SECURITY" in source
    assert "ON DELETE CASCADE" in source
    assert "NOCREATEDB NOCREATEROLE" in source


def test_judge_enforces_complete_safe_pareto_bundle() -> None:
    _store, coordinator, address, _candidate = _setup()
    run = coordinator.fork(coordinator.get_run(next(iter(coordinator._runs))))
    coordinator.verify_replay(
        run, lambda state, event: state + event.payload["delta"], initial_state=0
    )
    bundle = EvidenceBundle(
        target=address,
        candidate=coordinator.get_run(run.run_id).candidate_address,  # type: ignore[arg-type]
        dataset_id="dataset://test",
        runner_id="runner://test",
        model_id="model://test",
        policy_digest="policy://judge/test",
        tool_manifest_digest="tools://test",
        reducer_id="reducer://sum-v1",
        observations=(_observation(),),
        expected_sample_ids=("sample-1",),
    )
    assert EvolutionJudge().evaluate(bundle, JudgePolicy()).accepted
    assert bundle.sample_merkle_root == merkle_root(bundle.observations)
    assert bundle.evidence_digest != replace(bundle, expected_sample_ids=("other",)).evidence_digest
    incomplete = replace(bundle, expected_sample_ids=("sample-1", "sample-2"))
    assert "samples_incomplete" in EvolutionJudge().evaluate(incomplete).reasons
    missing_manifest = replace(bundle, expected_sample_ids=())
    assert "samples_incomplete" in EvolutionJudge().evaluate(missing_manifest).reasons
    unsafe = replace(bundle, real_provider_calls=1)
    assert "candidate_real_side_effects" in EvolutionJudge().evaluate(unsafe).reasons
    unsafe_mode = replace(bundle, simulate_only=False)
    assert "candidate_real_side_effects" in EvolutionJudge().evaluate(unsafe_mode).reasons
    unsafe_finding = replace(
        bundle, observations=(replace(_observation(), safety_findings=("critical",)),)
    )
    assert "high_risk_safety_finding" in EvolutionJudge().evaluate(unsafe_finding).reasons
    regression = replace(
        bundle,
        observations=(_observation(quality=800, cost=200, latency=200),),
    )
    assert "policy_regression_exceeded" in EvolutionJudge().evaluate(regression).reasons
    no_improvement = replace(
        bundle,
        observations=(_observation(quality=1000, cost=100, latency=100),),
    )
    assert "no_strict_improvement" in EvolutionJudge().evaluate(no_improvement).reasons
    missing_baseline = replace(
        bundle,
        observations=(
            EvaluationObservation(
                sample_id="sample-1",
                quality_bps=1_010,
                cost_units=90,
                latency_ms=90,
                baseline_output_hash="sha256:" + "a" * 64,
                candidate_output_hash="sha256:" + "b" * 64,
            ),
        ),
    )
    assert "baseline_metrics_incomplete" in EvolutionJudge().evaluate(missing_baseline).reasons
    with pytest.raises(EvolutionValidationError):
        replace(_observation(), candidate_output_hash="")


def test_seal_shadow_binds_every_evaluation_manifest_field() -> None:
    _store, coordinator, address, _candidate = _setup()
    run = coordinator.fork(next(iter(coordinator._runs)))
    run = coordinator.verify_replay(
        run, lambda state, event: state + event.payload["delta"], initial_state=0
    )
    candidate_address = coordinator.get_run(run.run_id).candidate_address
    assert candidate_address is not None
    valid = EvidenceBundle(
        target=address,
        candidate=candidate_address,
        dataset_id=run.dataset_id,
        runner_id=run.runner_id,
        model_id=run.model_id,
        policy_digest=run.policy_digest,
        tool_manifest_digest=run.tool_manifest_digest,
        reducer_id=run.reducer_id,
        observations=(_observation(),),
    )
    for field_name in (
        "dataset_id",
        "runner_id",
        "model_id",
        "policy_digest",
        "tool_manifest_digest",
        "reducer_id",
    ):
        # Each rejection is independent; sealing the first malformed bundle
        # correctly rejects the run and closes its state machine.
        _store, isolated_coordinator, _address, _candidate = _setup()
        isolated_run = isolated_coordinator.fork(next(iter(isolated_coordinator._runs)))
        isolated_run = isolated_coordinator.verify_replay(
            isolated_run,
            lambda state, event: state + event.payload["delta"],
            initial_state=0,
        )
        changed = replace(
            valid,
            target=isolated_run.source_address,
            candidate=isolated_run.candidate_address,
            **{field_name: "changed"},
        )
        with pytest.raises(EvidenceSealingError):
            isolated_coordinator.seal_shadow(isolated_run, changed)


def test_full_certificate_promotion_and_signed_rollback_are_one_time() -> None:
    _store, coordinator, address, _candidate = _setup()
    run = coordinator.fork(next(iter(coordinator._runs)))
    run = coordinator.verify_replay(
        run, lambda state, event: state + event.payload["delta"], initial_state=0
    )
    run = coordinator.seal_shadow(
        run,
        observations=(_observation(),),
        expected_sample_ids=("sample-1",),
    )
    key = Ed25519PrivateKey.generate()
    certificate = coordinator.issue_certificate(
        run,
        JudgePolicy(),
        key,
        signing_key_id="judge-key",
        certificate_id="cert-1",
    )
    target = PromotionTarget(address=address, active_capsule_digest=address.capsule_digest)
    assert CertificateVerifier({"judge-key": key.public_key()}).verify(certificate, target).valid
    authority = PromotionApprovalAuthority(b"a" * 32)
    approval = authority.issue(certificate, target, approved_by="reviewer")
    pointer_store = PromotionStore(receipt_signing_key=Ed25519PrivateKey.generate())
    receipt = coordinator.promote(
        run,
        pointer_store,
        authority,
        approval,
        verifier=CertificateVerifier({"judge-key": key.public_key()}),
    )
    assert coordinator.get_run(run.run_id).state is EvolutionState.PROMOTED
    assert pointer_store.get(target).active_capsule_digest == certificate.candidate_capsule_digest
    rollback = coordinator.rollback(run, pointer_store, receipt)
    assert rollback.operation == "rollback"
    assert pointer_store.get(target).active_capsule_digest == address.capsule_digest
    assert pointer_store.get(target).control_version == 2
    assert (
        not CertificateVerifier({"judge-key": key.public_key()})
        .verify(
            certificate,
            pointer_store.get(target),  # type: ignore[arg-type]
        )
        .valid
    )
    with pytest.raises(PromotionAlreadyUsed):
        authority.verify_and_consume(approval, certificate, target)
    with pytest.raises(PromotionCASConflict):
        pointer_store.rollback(receipt)
    with pytest.raises(PromotionReceiptError):
        pointer_store.rollback(rollback)

    pending_ids = {item.receipt_id for item in pointer_store.pending_outbox()}

    def unavailable_publisher(_item: object) -> None:
        raise RuntimeError("offline")

    with pytest.raises(RuntimeError):
        pointer_store.reconcile(unavailable_publisher)
    assert {item.receipt_id for item in pointer_store.pending_outbox()} == pending_ids
    delivered: list[str] = []
    assert (
        set(pointer_store.reconcile(lambda item: delivered.append(item.receipt_id))) == pending_ids
    )
    assert set(delivered) == pending_ids
    assert pointer_store.pending_outbox() == ()


def test_replay_and_promotion_reject_effects_tampering_and_stale_cas() -> None:
    _store, coordinator, address, _candidate = _setup()
    run = coordinator.fork(next(iter(coordinator._runs)))
    with pytest.raises(ReplayVerificationError):
        coordinator.verify_replay(run, lambda state, event: state, real_provider_calls=1)
    assert coordinator.get_run(run.run_id).state is EvolutionState.REJECTED

    target = PromotionTarget(address=address, active_capsule_digest=address.capsule_digest)
    pointer_store = PromotionStore()
    pointer_store.compare_and_swap(target, new_active_capsule="sha256:" + "c" * 64)
    with pytest.raises(PromotionCASConflict):
        pointer_store.compare_and_swap(
            target,
            expected_active_capsule=address.capsule_digest,
            new_active_capsule="sha256:" + "d" * 64,
        )


def test_certificate_tamper_expiry_and_cross_tenant_are_rejected() -> None:
    source = _capsule("tenant-a", "source")
    candidate = _capsule("tenant-a", "candidate")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    certificate = EvolutionCertificate(
        certificate_id="cert",
        source_address=CellAddress(
            "tenant-a", "cell", "session", source.digest or source.content_digest
        ),
        candidate_address=CellAddress(
            "tenant-a", "cell", "session", candidate.digest or candidate.content_digest, "candidate"
        ),
        source_capsule_digest=source.digest or source.content_digest,
        candidate_capsule_digest=candidate.digest or candidate.content_digest,
        fork_sequence=0,
        fork_hash=GENESIS_HASH,
        source_head_hash=GENESIS_HASH,
        candidate_head_hash=GENESIS_HASH,
        dataset_id="dataset",
        runner_id="runner",
        model_id="model",
        policy_digest="policy",
        tool_manifest_digest="tools",
        reducer_id="reducer",
        evidence_digest="sha256:" + "e" * 64,
        judge_policy=JudgePolicy().to_dict(),
        expected_active_capsule=source.digest or source.content_digest,
        control_version=0,
        signing_key_id="key",
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )
    key = Ed25519PrivateKey.generate()
    certificate = certificate.with_signature(key)
    verifier = CertificateVerifier({"key": key.public_key()}, clock=lambda: now)
    target = PromotionTarget(certificate.source_address, certificate.source_capsule_digest)
    assert verifier.verify(certificate, target).valid
    assert not verifier.verify(
        replace(certificate, evidence_digest="sha256:" + "f" * 64), target
    ).valid
    assert not verifier.verify(
        certificate,
        PromotionTarget(
            CellAddress("tenant-b", "cell", "session", certificate.source_capsule_digest),
            certificate.source_capsule_digest,
        ),
    ).valid
    expired = replace(certificate, expires_at=now)
    assert not verifier.verify(expired, target).valid
