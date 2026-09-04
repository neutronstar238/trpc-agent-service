from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import trpc_service.cell.evolution as evolution_module
from trpc_service.cell.capsule import AgentCapsule, CapsuleMetadata, CapsuleSpec
from trpc_service.cell.events import CellAddress, EventDraft, InMemoryEventStore
from trpc_service.cell.evolution import (
    ApprovalError,
    CertificateError,
    CertificateVerifier,
    EvaluationObservation,
    EvidenceBundle,
    EvidenceSealingError,
    EvolutionCertificate,
    EvolutionCoordinator,
    EvolutionJudge,
    EvolutionState,
    EvolutionTransitionError,
    EvolutionValidationError,
    JudgeDecision,
    JudgePolicy,
    MetricSnapshot,
    NamespaceViolation,
    PromotionAlreadyUsed,
    PromotionApprovalAuthority,
    PromotionCASConflict,
    PromotionError,
    PromotionPointer,
    PromotionReceipt,
    PromotionReceiptError,
    PromotionStore,
    PromotionTarget,
    ReplayVerificationError,
    _address_dict,
    _address_from,
    _decode_b64,
    _parse_timestamp,
    _private_key,
    _public_key,
    _reject_wildcard,
    _require_sha256,
    _timestamp,
    capsule_digest,
    merkle_root,
)

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
HASH_C = "sha256:" + "c" * 64
HASH_D = "sha256:" + "d" * 64


def _capsule(tenant: str, prompt: str) -> AgentCapsule:
    return AgentCapsule(
        metadata=CapsuleMetadata(tenant_id=tenant, name="coverage-evolution"),
        spec=CapsuleSpec(
            graph="graph://coverage",
            prompt=f"prompt://{prompt}",
            model_policy="policy://model/coverage",
            tool_manifest="tools://coverage",
            governance_policy="policy://governance/coverage",
            storage_profile="storage://coverage",
        ),
    ).with_digest()


def _fixture(
    *, clock: Any | None = None
) -> tuple[InMemoryEventStore, EvolutionCoordinator, CellAddress, AgentCapsule, AgentCapsule]:
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
            event_id="coverage-event",
            occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )
    coordinator = EvolutionCoordinator(store, clock=clock)
    run = coordinator.create_run(
        address,
        source_capsule=source,
        candidate_capsule=candidate,
        fork_sequence=1,
        fork_hash=cast(Any, store.head(address)).event_hash,
        dataset_id="dataset://coverage",
        runner_id="runner://coverage",
        model_id="model://coverage",
        policy_digest="policy://judge/coverage",
        tool_manifest_digest="tools://coverage",
        reducer_id="reducer://sum-coverage",
    )
    assert run.state is EvolutionState.PLANNED
    return store, coordinator, address, source, candidate


def _observation(
    sample_id: str = "sample-1",
    *,
    quality: int = 1_010,
    cost: int = 90,
    latency: int = 90,
    findings: tuple[str, ...] = (),
    baseline: tuple[int | None, int | None, int | None] = (1_000, 100, 100),
) -> EvaluationObservation:
    return EvaluationObservation(
        sample_id=sample_id,
        quality_bps=quality,
        cost_units=cost,
        latency_ms=latency,
        safety_findings=findings,
        baseline_quality_bps=baseline[0],
        baseline_cost_units=baseline[1],
        baseline_latency_ms=baseline[2],
        baseline_output_hash=HASH_A,
        candidate_output_hash=HASH_B,
        summary="sensitive provider response is redacted",
    )


def _forked() -> tuple[
    InMemoryEventStore, EvolutionCoordinator, CellAddress, AgentCapsule, AgentCapsule, Any
]:
    store, coordinator, address, source, candidate = _fixture()
    run = coordinator.fork(next(iter(coordinator._runs)))
    return store, coordinator, address, source, candidate, run


def _sealed() -> tuple[
    InMemoryEventStore, EvolutionCoordinator, CellAddress, AgentCapsule, AgentCapsule, Any
]:
    store, coordinator, address, source, candidate, run = _forked()
    run = coordinator.verify_replay(
        run, lambda state, event: state + event.payload["delta"], initial_state=0
    )
    run = coordinator.seal_shadow(
        run,
        observations=(_observation(),),
        expected_sample_ids=("sample-1",),
    )
    return store, coordinator, address, source, candidate, run


def _certified() -> tuple[
    InMemoryEventStore,
    EvolutionCoordinator,
    CellAddress,
    AgentCapsule,
    AgentCapsule,
    Any,
    Ed25519PrivateKey,
    EvolutionCertificate,
    PromotionTarget,
]:
    store, coordinator, address, source, candidate, run = _sealed()
    key = Ed25519PrivateKey.generate()
    cert = coordinator.issue_certificate(
        run,
        JudgePolicy(),
        key,
        signing_key_id="coverage-judge",
        certificate_id="coverage-cert",
    )
    target = PromotionTarget(address, source.digest or source.content_digest)
    return store, coordinator, address, source, candidate, run, key, cert, target


def _bundle() -> EvidenceBundle:
    _store, _coordinator, address, _source, _candidate, run = _forked()
    candidate_address = run.candidate_address
    assert candidate_address is not None
    return EvidenceBundle(
        target=address,
        candidate=candidate_address,
        dataset_id=run.dataset_id,
        runner_id=run.runner_id,
        model_id=run.model_id,
        policy_digest=run.policy_digest,
        tool_manifest_digest=run.tool_manifest_digest,
        reducer_id=run.reducer_id,
        observations=(_observation(),),
        expected_sample_ids=("sample-1",),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("quality_bps", -1),
        ("cost_units", True),
        ("latency_ms", 1.5),
    ],
)
def test_metric_snapshot_rejects_non_nonnegative_integers(field: str, value: object) -> None:
    values: dict[str, object] = {"quality_bps": 0, "cost_units": 0, "latency_ms": 0}
    values[field] = value
    with pytest.raises(EvolutionValidationError):
        MetricSnapshot(**cast(Any, values))


def test_observation_validation_redacts_and_rejects_malformed_values() -> None:
    assert _observation().redacted_summary.startswith("sha256:")
    assert _observation().metrics == MetricSnapshot(1_010, 90, 90)
    assert _observation().candidate_quality_bps == 1_010
    assert _observation().candidate_cost_units == 90
    assert _observation().candidate_latency_ms == 90
    assert _observation().baseline_metrics() == MetricSnapshot(1_000, 100, 100)
    assert _observation(baseline=(None, None, None)).baseline_metrics(MetricSnapshot(1, 2, 3)) == (
        MetricSnapshot(1, 2, 3)
    )
    with pytest.raises(EvolutionValidationError):
        _observation(baseline=(1, None, 1)).baseline_metrics()
    with pytest.raises(EvolutionValidationError):
        replace(_observation(), sample_id=" ")
    with pytest.raises(EvolutionValidationError):
        replace(_observation(), safety_findings=("critical", "critical"))
    with pytest.raises(EvolutionValidationError):
        replace(_observation(), safety_findings=(" ",))
    with pytest.raises(EvolutionValidationError):
        replace(_observation(), baseline_quality_bps=True)
    with pytest.raises(EvolutionValidationError):
        replace(_observation(), baseline_output_hash="")
    with pytest.raises(EvolutionValidationError):
        replace(_observation(), candidate_output_hash="not-a-digest")
    with pytest.raises((KeyError, EvolutionValidationError)):
        EvaluationObservation.from_dict({"sample_id": "only"})
    assert EvaluationObservation.from_dict(_observation().to_dict()) == _observation()


def test_digest_and_merkle_helpers_cover_empty_odd_duplicate_and_invalid_inputs() -> None:
    assert merkle_root(()) == merkle_root(())
    odd = (_observation("a"), _observation("b"), _observation("c"))
    assert merkle_root(odd) == merkle_root(tuple(reversed(odd)))
    with pytest.raises(EvidenceSealingError):
        merkle_root((_observation("a"), _observation("a")))
    with pytest.raises(EvolutionValidationError):
        _address_from({"tenant_id": "tenant-a"})
    with pytest.raises(EvolutionValidationError):
        _address_from("not-an-address")
    with pytest.raises(EvolutionValidationError):
        _reject_wildcard(
            CellAddress(
                tenant_id="tenant-a",
                app_id="app*",
                cell_id="cell",
                session_id="session",
                capsule_digest=HASH_A,
            )
        )
    with pytest.raises(EvolutionValidationError):
        capsule_digest(cast(Any, object()))


@pytest.mark.parametrize(
    "mutator",
    [
        lambda bundle: replace(
            bundle,
            target=CellAddress(
                tenant_id="tenant-b",
                app_id="app-a",
                cell_id="cell-a",
                session_id="session-a",
                capsule_digest=HASH_A,
            ),
        ),
        lambda bundle: replace(
            bundle,
            candidate=CellAddress(
                tenant_id="tenant-a",
                app_id="other",
                cell_id="cell-a",
                session_id="session-a",
                capsule_digest=HASH_B,
                branch_id="fork",
            ),
        ),
        lambda bundle: replace(
            bundle,
            candidate=CellAddress(
                tenant_id="tenant-a",
                app_id="app-a",
                cell_id="cell-a",
                session_id="session-a",
                capsule_digest=HASH_B,
                branch_id="main",
            ),
        ),
        lambda bundle: replace(bundle, candidate=replace(bundle.candidate, branch_id="main")),
        lambda bundle: replace(bundle, dataset_id=" "),
        lambda bundle: replace(bundle, real_provider_calls=True),
        lambda bundle: replace(bundle, real_provider_calls=-1),
        lambda bundle: replace(bundle, simulate_only=1),
        lambda bundle: replace(bundle, observations=(cast(Any, object()),)),
        lambda bundle: replace(bundle, observations=(_observation("same"), _observation("same"))),
        lambda bundle: replace(bundle, expected_sample_ids=("sample-1", "sample-1")),
        lambda bundle: replace(bundle, baseline_metrics={"sample-1": cast(Any, object())}),
        lambda bundle: replace(bundle, baseline_metrics={"": MetricSnapshot(1, 1, 1)}),
        lambda bundle: replace(bundle, sealed_at=datetime(2026, 1, 1)),
    ],
)
def test_evidence_bundle_rejects_scope_manifest_and_storage_violations(mutator: Any) -> None:
    with pytest.raises((EvolutionValidationError, EvidenceSealingError, NamespaceViolation)):
        mutator(_bundle())


def test_evidence_bundle_accepts_mapping_baselines_and_binds_context() -> None:
    bundle = replace(
        _bundle(),
        baseline_metrics={"sample-1": {"quality_bps": 1_000, "cost_units": 100, "latency_ms": 100}},
    )
    assert bundle.baseline_metrics["sample-1"] == MetricSnapshot(1_000, 100, 100)
    assert bundle.provider_calls == 0
    assert bundle.sample_count == 1
    assert bundle.canonical_bytes()
    assert bundle.evidence_digest != replace(bundle, runner_id="runner://other").evidence_digest


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("quality_regression_bps", -1),
        ("cost_regression_units", True),
        ("latency_regression_ms", 1.2),
    ],
)
def test_judge_policy_rejects_invalid_bounds_and_duplicate_expected_ids(
    field: str, value: object
) -> None:
    values: dict[str, object] = {
        "max_quality_regression_bps": 0,
        "max_cost_regression_units": 0,
        "max_latency_regression_ms": 0,
    }
    values[field] = value
    with pytest.raises(EvolutionValidationError):
        JudgePolicy(**cast(Any, values))
    with pytest.raises(EvolutionValidationError):
        JudgePolicy(expected_sample_ids=("one", "one"))
    with pytest.raises(EvolutionValidationError):
        JudgePolicy(high_risk_findings=("",))


def test_judge_covers_each_hard_gate_and_pareto_fallback() -> None:
    bundle = _bundle()
    judge = EvolutionJudge()
    accepted = judge.evaluate(bundle, JudgePolicy())
    assert accepted.accepted and accepted.passed and accepted.ok
    assert accepted.checks["samples_complete"]
    assert judge.evaluate(replace(bundle, expected_sample_ids=()), JudgePolicy()).reasons
    assert (
        "samples_incomplete"
        in judge.evaluate(replace(bundle, expected_sample_ids=("missing",)), JudgePolicy()).reasons
    )
    assert (
        "high_risk_safety_finding"
        in judge.evaluate(
            replace(
                bundle, observations=(replace(_observation(), safety_findings=("critical-ish",)),)
            )
        ).reasons
    )
    assert (
        "candidate_real_side_effects"
        in judge.evaluate(replace(bundle, real_provider_calls=1)).reasons
    )
    assert (
        "candidate_real_side_effects"
        in judge.evaluate(replace(bundle, simulate_only=False)).reasons
    )
    assert (
        "policy_regression_exceeded"
        in judge.evaluate(
            replace(bundle, observations=(_observation(quality=800, cost=200, latency=200),))
        ).reasons
    )
    equal = replace(bundle, observations=(_observation(quality=1_000, cost=100, latency=100),))
    assert "no_strict_improvement" in judge.evaluate(equal).reasons
    assert judge.evaluate(equal, JudgePolicy(require_strict_improvement=False)).accepted
    no_baseline = replace(
        bundle,
        observations=(_observation(baseline=(None, None, None)),),
        baseline_metrics={},
    )
    decision = judge.evaluate(no_baseline)
    assert "baseline_metrics_incomplete" in decision.reasons
    assert "no_strict_improvement" in decision.reasons
    fallback = replace(
        no_baseline,
        baseline_metrics={"sample-1": MetricSnapshot(1_000, 100, 100)},
    )
    assert judge.evaluate(fallback).accepted
    with pytest.raises(EvolutionValidationError):
        judge.evaluate(cast(Any, object()))
    assert JudgeDecision(accepted=True).to_dict()["accepted"] is True


def test_certificate_constructor_and_serialization_reject_all_structural_tampering() -> None:
    _store, _coordinator, address, _source, _candidate, _run, key, cert, target = _certified()
    assert cert.tenant_id == address.tenant_id
    assert cert.source_capsule == cert.source_capsule_digest
    assert cert.candidate_capsule == cert.candidate_capsule_digest
    assert cert.digest == cert.certificate_digest
    assert not cert.expired
    assert cert.is_expired(now=cert.issued_at - timedelta(seconds=1)) is False
    assert cert.canonical_json() == cert.canonical_json()
    assert cert.signing_bytes()
    assert "signature" not in cert.to_dict(include_signature=False)
    assert EvolutionCertificate.from_dict(cert.to_dict()) == cert
    assert CertificateVerifier({"coverage-judge": key.public_key()}).verify(cert, target).valid

    invalids = [
        lambda: replace(
            cert,
            candidate_address=CellAddress(
                tenant_id="tenant-b",
                app_id=address.app_id,
                cell_id=address.cell_id,
                session_id=address.session_id,
                capsule_digest=HASH_B,
                branch_id="fork",
            ),
        ),
        lambda: replace(
            cert,
            candidate_address=CellAddress(
                tenant_id=address.tenant_id,
                app_id="other-app",
                cell_id=address.cell_id,
                session_id=address.session_id,
                capsule_digest=HASH_B,
                branch_id="fork",
            ),
        ),
        lambda: replace(cert, source_address=replace(cert.source_address, branch_id="fork")),
        lambda: replace(cert, candidate_address=replace(cert.candidate_address, branch_id="main")),
        lambda: replace(cert, source_capsule_digest=HASH_C),
        lambda: replace(cert, candidate_capsule_digest=HASH_C),
        lambda: replace(cert, fork_sequence=True),
        lambda: replace(cert, control_version=True),
        lambda: replace(cert, signature_algorithm="rsa"),
        lambda: replace(cert, schema_version=2),
        lambda: replace(cert, issued_at=datetime(2026, 1, 1)),
        lambda: replace(cert, expires_at=datetime(2026, 1, 1)),
    ]
    for invalid_factory in invalids:
        with pytest.raises((CertificateError, EvolutionValidationError, NamespaceViolation)):
            invalid_factory()

    with pytest.raises(CertificateError):
        cert.verify_signature({})
    with pytest.raises(CertificateError):
        replace(cert, signature="").verify_signature({"coverage-judge": key.public_key()})
    with pytest.raises(CertificateError):
        cert.verify_signature({"coverage-judge": b"bad"})
    with pytest.raises(CertificateError):
        replace(cert, signature=cert.signature[:-1] + "!").verify_signature(
            {"coverage-judge": key.public_key()}
        )
    with pytest.raises(CertificateError):
        cert.with_signature(cast(Any, object()))
    with pytest.raises(CertificateError):
        cert.with_signature(b"short")
    malformed = cert.to_dict()
    malformed.pop("certificate_id")
    with pytest.raises(CertificateError):
        EvolutionCertificate.from_dict(malformed)
    malformed = cert.to_dict()
    malformed["issued_at"] = "not-a-timestamp"
    with pytest.raises(CertificateError):
        EvolutionCertificate.from_dict(malformed)
    malformed = cert.to_dict()
    malformed["source_address"] = "not-an-address"
    with pytest.raises((CertificateError, EvolutionValidationError)):
        EvolutionCertificate.from_dict(malformed)


def test_certificate_verifier_covers_target_forms_and_rejection_reasons() -> None:
    _store, _coordinator, address, _source, _candidate, _run, key, cert, target = _certified()
    verifier = CertificateVerifier(
        {"coverage-judge": key.public_key()}, clock=lambda: cert.issued_at
    )
    assert verifier.verify(cert, address).valid
    assert verifier.verify(cert, target.to_dict()).valid
    assert verifier.verify(
        cert,
        {**target.to_dict(), "expected_active_capsule": target.active_capsule_digest},
    ).valid
    assert verifier.verify(cert, {"address": _address_dict(address)}).valid
    assert not verifier.verify(cast(Any, object()), target).valid
    assert not verifier.verify(cert, cast(Any, object())).valid
    assert not verifier.verify(
        cert, replace(target, address=replace(address, cell_id="other"))
    ).valid
    assert not verifier.verify(cert, replace(target, active_capsule_digest=HASH_C)).valid
    assert not verifier.verify(cert, replace(target, control_version=1)).valid
    expired = replace(
        cert, expires_at=cert.issued_at - timedelta(seconds=1), signature=""
    ).with_signature(key)
    expired_result = verifier.verify(expired, target)
    assert not expired_result.valid and "expired" in expired_result.reason
    bad_key = CertificateVerifier({"other": key.public_key()})
    assert not bad_key.verify(cert, target).valid
    bad_signature = replace(cert, evidence_digest=HASH_C)
    assert not verifier.verify(bad_signature, target).valid
    with pytest.raises(CertificateError):
        CertificateVerifier._target(cast(Any, object()), cert)


def test_low_level_encoding_and_timestamp_errors_are_explicit() -> None:
    with pytest.raises(CertificateError):
        _decode_b64("!")
    with pytest.raises(CertificateError):
        _decode_b64("AA")
    with pytest.raises(CertificateError):
        _decode_b64("A" * 88)
    with pytest.raises(CertificateError):
        _private_key(cast(Any, object()))
    with pytest.raises(CertificateError):
        _private_key(b"short")
    with pytest.raises(CertificateError):
        _public_key(cast(Any, object()))
    with pytest.raises(CertificateError):
        _public_key(b"short")
    with pytest.raises(EvolutionValidationError):
        _timestamp(datetime(2026, 1, 1))
    with pytest.raises(CertificateError):
        _parse_timestamp("not-a-time")
    with pytest.raises(CertificateError):
        _parse_timestamp("2026-01-01T00:00:00")


def test_approval_issue_coerce_and_consume_rejects_invalid_scope_and_reuse() -> None:
    _store, _coordinator, address, _source, _candidate, _run, _key, cert, target = _certified()
    authority = PromotionApprovalAuthority(b"coverage-approval-secret")
    assert authority.issue(cert, approved_by="default").credential
    with pytest.raises(ApprovalError):
        authority.issue(cert, target, approved_by=" ")
    with pytest.raises(ApprovalError):
        authority.issue(cert, target, approved_by="reviewer", ttl_seconds=0)
    with pytest.raises(ApprovalError):
        authority.issue(None, None, approved_by="reviewer")
    detached = authority.issue(
        None,
        {
            "address": _address_dict(address),
            "active_capsule_digest": address.capsule_digest,
            "control_version": 0,
        },
        approved_by="reviewer",
        certificate_id="detached",
        certificate_digest=HASH_D,
        tenant_id="tenant-a",
    )
    assert detached.token == detached.mac
    with pytest.raises(NamespaceViolation):
        authority.issue(
            None,
            target,
            approved_by="reviewer",
            certificate_id="detached",
            certificate_digest=HASH_D,
            tenant_id="tenant-b",
        )
    with pytest.raises(ApprovalError):
        authority.issue(
            None,
            cast(Any, object()),
            approved_by="reviewer",
            certificate_id="detached",
            certificate_digest=HASH_D,
        )
    with pytest.raises(ApprovalError):
        authority.issue(
            None,
            {"address": _address_dict(address)},
            approved_by="reviewer",
            certificate_id="detached",
            certificate_digest=HASH_D,
        )
    with pytest.raises(ApprovalError):
        authority.issue(
            None,
            {
                "address": _address_dict(address),
                "active_capsule_digest": address.capsule_digest,
                "control_version": "bad",
            },
            approved_by="reviewer",
            certificate_id="detached",
            certificate_digest=HASH_D,
        )
    approval = authority.issue(cert, target, approved_by="reviewer")
    assert authority.consume(approval, cert, target)
    with pytest.raises(PromotionAlreadyUsed):
        authority.verify_and_consume(approval, cert, target)
    with pytest.raises(ApprovalError):
        authority.verify_and_consume(cast(Any, object()), cert, target)
    with pytest.raises(ApprovalError):
        authority.verify_and_consume(approval, cast(Any, object()), target)


def test_approval_expiry_mac_and_namespace_are_fail_closed() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    clock_value = [now]
    _store, _coordinator, _address, _source, _candidate, _run, key, cert, target = _certified()
    authority = PromotionApprovalAuthority(b"coverage-expiry-secret", clock=lambda: clock_value[0])
    approval = authority.issue(cert, target, approved_by="reviewer", ttl_seconds=1)
    clock_value[0] = now + timedelta(seconds=2)
    with pytest.raises(ApprovalError):
        authority.verify_and_consume(approval, cert, target)
    clock_value[0] = now
    fresh = authority.issue(cert, target, approved_by="reviewer")
    invalid_mac = ("A" if fresh.mac[0] != "A" else "B") + fresh.mac[1:]
    with pytest.raises(ApprovalError):
        authority.verify_and_consume(replace(fresh, mac=invalid_mac), cert, target)
    scoped = authority.issue(cert, target, approved_by="reviewer")
    with pytest.raises(NamespaceViolation):
        authority.verify_and_consume(
            scoped,
            cert,
            replace(target, address=replace(target.address, cell_id="other")),
        )
    other_tenant = replace(
        target,
        address=CellAddress(
            tenant_id="tenant-b",
            app_id=target.app_id,
            cell_id=target.cell_id,
            session_id=target.session_id,
            capsule_digest=HASH_A,
        ),
    )
    with pytest.raises(NamespaceViolation):
        authority.issue(cert, other_tenant, approved_by="reviewer", tenant_id="tenant-a")
    assert key.public_key()


@pytest.mark.parametrize(
    "value",
    [
        CellAddress(
            tenant_id="tenant-a",
            app_id="app-a",
            cell_id="cell-a",
            session_id="session-a",
            capsule_digest=HASH_A,
            branch_id="fork",
        ),
        CellAddress(
            tenant_id="tenant-a",
            app_id="app*",
            cell_id="cell-a",
            session_id="session-a",
            capsule_digest=HASH_A,
        ),
    ],
)
def test_promotion_target_rejects_non_main_or_wildcard(value: CellAddress) -> None:
    with pytest.raises(PromotionError if value.branch_id != "main" else EvolutionValidationError):
        PromotionTarget(value, HASH_A)


def test_promotion_store_initial_mapping_get_and_manual_cas_guards() -> None:
    _store, _coordinator, address, source, candidate, _run, _key, _cert, _target = _certified()
    target = PromotionTarget(address, source.digest or source.content_digest)
    mapped = PromotionStore(initial={"cell": target})
    assert mapped.get(address) == target
    assert mapped.current(target) == target
    missing = PromotionTarget(
        CellAddress(
            tenant_id="tenant-a",
            app_id="app-a",
            cell_id="missing",
            session_id="session-a",
            capsule_digest=HASH_A,
        ),
        HASH_A,
    )
    assert mapped.get(missing) is None
    with pytest.raises(PromotionCASConflict):
        PromotionStore().compare_and_swap(address, new_active_capsule=HASH_B)
    with pytest.raises(PromotionError):
        mapped.compare_and_swap(target, new_active_capsule=None)
    with pytest.raises(EvolutionValidationError):
        mapped.compare_and_swap(target, new_active_capsule="bad")
    with pytest.raises(PromotionCASConflict):
        mapped.compare_and_swap(target, new_active_capsule=HASH_B, control_version=0)
    receipt = mapped.compare_and_swap(target, new_active_capsule=candidate.digest)
    assert receipt.previous_active_capsule == source.digest
    assert mapped.get(target).active_capsule_digest == candidate.digest  # type: ignore[union-attr]
    with pytest.raises(PromotionCASConflict):
        mapped.compare_and_swap(
            target,
            expected_active_capsule=source.digest,
            expected_control_version=0,
            new_active_capsule=HASH_C,
        )
    assert mapped.pending_outbox()
    mapped.acknowledge("unknown-receipt")
    delivered: list[str] = []
    assert mapped.reconcile(lambda item: delivered.append(item.receipt_id))
    assert mapped.pending_outbox() == ()


def test_promotion_store_certificate_guards_and_receipt_verification() -> None:
    _store, _coordinator, _address, source, candidate, _run, _key, cert, target = _certified()
    store = PromotionStore(initial=(target,))
    with pytest.raises(PromotionError):
        store.compare_and_swap(target, new_active_capsule=candidate.digest, certificate=cert)
    with pytest.raises(PromotionError):
        store.compare_and_swap(
            target,
            new_active_capsule=HASH_C,
            certificate=cert,
            approval_consumed=True,
        )
    with pytest.raises(PromotionCASConflict):
        store.compare_and_swap(
            replace(target, active_capsule_digest=HASH_C),
            new_active_capsule=candidate.digest,
            certificate=cert,
            approval_consumed=True,
        )
    wrong_source = replace(
        cert,
        source_address=CellAddress(
            tenant_id="tenant-a",
            app_id="app-a",
            cell_id="other",
            session_id="session-a",
            capsule_digest=cert.source_capsule_digest,
        ),
        candidate_address=CellAddress(
            tenant_id="tenant-a",
            app_id="app-a",
            cell_id="other",
            session_id="session-a",
            capsule_digest=cert.candidate_capsule_digest,
            branch_id="fork",
        ),
    )
    with pytest.raises(NamespaceViolation):
        store.compare_and_swap(
            target,
            new_active_capsule=candidate.digest,
            certificate=wrong_source,
            approval_consumed=True,
        )
    authority = PromotionApprovalAuthority(b"store-approval")
    approval = authority.issue(cert, target, approved_by="reviewer")
    assert authority.verify_and_consume(approval, cert, target)
    receipt = store.compare_and_swap(
        target,
        new_active_capsule=candidate.digest,
        certificate=cert,
        approval_consumed=True,
    )
    assert receipt.signature
    store._pointers[store._key(target.address)] = PromotionPointer(
        target=target, updated_at=datetime.now(UTC)
    )
    with pytest.raises(PromotionAlreadyUsed):
        store.compare_and_swap(
            target,
            expected_active_capsule=source.digest,
            expected_control_version=0,
            new_active_capsule=candidate.digest,
            certificate=cert,
            approval_consumed=True,
        )
    with pytest.raises(PromotionReceiptError):
        store.rollback(replace(receipt, signature=""))
    with pytest.raises(PromotionReceiptError):
        store.rollback(replace(receipt, signing_key_id="other"))
    invalid_signature = ("A" if receipt.signature[0] != "A" else "B") + receipt.signature[1:]
    with pytest.raises(PromotionReceiptError):
        store.rollback(replace(receipt, signature=invalid_signature))


def test_promotion_store_rollback_checks_pointer_receipt_and_caller_cas() -> None:
    _store, _coordinator, _address, source, candidate, _run, _key, _cert, target = _certified()
    store = PromotionStore(initial=(target,))
    receipt = store.compare_and_swap(target, new_active_capsule=candidate.digest)
    with pytest.raises(PromotionReceiptError):
        store.rollback(cast(Any, object()))
    with pytest.raises(PromotionReceiptError):
        store.rollback(replace(receipt, operation="rollback"))
    with pytest.raises(PromotionCASConflict):
        store.rollback(receipt, expected_active_capsule=source.digest)
    with pytest.raises(PromotionCASConflict):
        store.rollback(receipt, expected_control_version=0)
    store2 = PromotionStore(initial=(target,))
    receipt2 = store2.compare_and_swap(target, new_active_capsule=candidate.digest)
    store2.compare_and_swap(
        store2.get(target),  # type: ignore[arg-type]
        new_active_capsule=HASH_C,
    )
    with pytest.raises(PromotionCASConflict):
        store2.rollback(receipt2)
    store3 = PromotionStore()
    with pytest.raises(PromotionReceiptError):
        store3.rollback(receipt)
    rollback = store.rollback(receipt)
    assert rollback.operation == "rollback"
    assert rollback.control_version == receipt.control_version + 1
    assert store.get(target).control_version == receipt.control_version + 1  # type: ignore[union-attr]
    assert store.get(target).active_capsule_digest == source.digest  # type: ignore[union-attr]


def test_receipt_constructor_rejects_invalid_versions_operation_and_time() -> None:
    _store, _coordinator, _address, _source, _candidate, _run, _key, cert, target = _certified()
    base = PromotionReceipt(
        receipt_id="r",
        certificate_id=cert.certificate_id,
        target=target,
        previous_active_capsule=HASH_A,
        active_capsule=HASH_B,
        previous_control_version=0,
        control_version=1,
        issued_at=datetime(2026, 1, 1, tzinfo=UTC),
        signing_key_id="store",
    )
    assert base.digest.startswith("sha256:")
    for change in (
        {"previous_control_version": -1},
        {"control_version": 0},
        {"operation": "other"},
        {"issued_at": datetime(2026, 1, 1)},
        {"signing_key_id": " "},
    ):
        with pytest.raises((PromotionReceiptError, EvolutionValidationError)):
            replace(base, **change)


def test_coordinator_create_fork_and_lookup_reject_invalid_inputs() -> None:
    store, coordinator, address, source, candidate = _fixture()
    with pytest.raises(EvolutionValidationError):
        coordinator.get_run("missing")
    with pytest.raises(EvolutionValidationError):
        coordinator.create_run(address, candidate_capsule=None)
    with pytest.raises(EvolutionValidationError):
        coordinator.create_run(replace(address, branch_id="fork"), candidate_capsule=candidate)
    with pytest.raises(EvolutionValidationError):
        coordinator.create_run(address, candidate_capsule=candidate, fork_sequence=-1)
    foreign = _capsule("tenant-b", "foreign")
    with pytest.raises(NamespaceViolation):
        coordinator.create_run(address, candidate_capsule=foreign)
    same = _capsule("tenant-a", "source")
    with pytest.raises(EvolutionValidationError):
        coordinator.create_run(address, source_capsule=source, candidate_capsule=same)
    duplicate = _capsule("tenant-a", "candidate")
    bad_digest = duplicate.model_copy(update={"digest": HASH_C})
    with pytest.raises(EvolutionValidationError):
        coordinator.create_run(address, candidate_capsule=bad_digest)
    with pytest.raises(NamespaceViolation):
        coordinator.create_run(
            address,
            source_capsule=_capsule("tenant-a", "other-source"),
            candidate_capsule=candidate,
        )
    with pytest.raises(EvolutionValidationError):
        coordinator.create_run(address, candidate_capsule=candidate, ttl_seconds=0)
    with pytest.raises(EvolutionValidationError):
        coordinator.create_run(
            address,
            candidate_capsule=candidate,
            expires_at=datetime(2020, 1, 1, tzinfo=UTC),
        )
    run = coordinator.create_run(
        address,
        candidate_capsule=candidate,
        run_id="fixed-run",
        fork_sequence=1,
        fork_hash=cast(Any, store.head(address)).event_hash,
        dataset_id="dataset",
        runner_id="runner",
        model_id="model",
        policy_digest="policy",
        tool_manifest_digest="tools",
        reducer_id="reducer",
    )
    with pytest.raises(EvolutionValidationError):
        coordinator.create_run(
            address,
            candidate_capsule=duplicate,
            run_id=run.run_id,
            dataset_id="dataset",
            runner_id="runner",
            model_id="model",
            policy_digest="policy",
            tool_manifest_digest="tools",
            reducer_id="reducer",
        )
    with pytest.raises(EvolutionValidationError):
        coordinator.fork(run, fork_sequence=2)
    with pytest.raises(EvolutionValidationError):
        coordinator.fork(run, fork_hash=HASH_C)
    assert coordinator.get_run(run.run_id).state is EvolutionState.REJECTED
    assert store.head(address) is not None


def test_coordinator_replay_shadow_and_certificate_state_failures() -> None:
    _store, coordinator, _address, _source, _candidate, run = _forked()
    with pytest.raises(ReplayVerificationError):
        coordinator.verify_replay(run, lambda state, event: state, simulate_only=False)
    assert coordinator.get_run(run.run_id).state is EvolutionState.REJECTED

    _store, coordinator, _address, _source, _candidate, run = _forked()
    with pytest.raises(ReplayVerificationError):
        coordinator.verify_replay(run, lambda state, event: state, provider_call_count=1)
    _store, coordinator, _address, _source, _candidate, run = _forked()
    count = [0]

    def nondeterministic(state: int, event: Any) -> int:
        count[0] += 1
        return state + count[0]

    with pytest.raises(ReplayVerificationError):
        coordinator.verify_replay(run, nondeterministic, initial_state=0)
    assert coordinator.get_run(run.run_id).state is EvolutionState.REJECTED
    _store, coordinator, _address, _source, _candidate, run = _forked()
    with pytest.raises(ZeroDivisionError):
        coordinator.verify_replay(run, lambda state, event: 1 / 0, initial_state=0)
    _store, coordinator, _address, _source, _candidate, run = _forked()
    coordinator._runs[run.run_id] = replace(run, candidate_address=None)
    with pytest.raises(ReplayVerificationError):
        coordinator.verify_replay(run, lambda state, event: state)

    _store, coordinator, address, _source, _candidate, run = _sealed()
    assert coordinator.get_run(run.run_id).state is EvolutionState.EVIDENCE_SEALED
    with pytest.raises(EvolutionTransitionError):
        coordinator.fork(run)
    key = Ed25519PrivateKey.generate()
    certificate = coordinator.issue_certificate(
        run, JudgePolicy(), key, signing_key_id="coverage-state"
    )
    assert certificate.certificate_id
    with pytest.raises(EvolutionTransitionError):
        coordinator.issue_certificate(
            run, JudgePolicy(), Ed25519PrivateKey.generate(), signing_key_id="x"
        )
    assert address.tenant_id == "tenant-a"


def test_coordinator_shadow_rejects_unsafe_and_mismatched_bundles() -> None:
    _store, coordinator, address, _source, _candidate, run = _forked()
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
        expected_sample_ids=("sample-1",),
    )
    with pytest.raises(NamespaceViolation):
        coordinator.seal_shadow(
            run,
            replace(valid, target=replace(address, tenant_id="tenant-b")),
        )
    _store, coordinator, _address, _source, _candidate, run = _forked()
    run = coordinator.verify_replay(
        run, lambda state, event: state + event.payload["delta"], initial_state=0
    )
    candidate_address = coordinator.get_run(run.run_id).candidate_address
    assert candidate_address is not None
    with pytest.raises(EvidenceSealingError):
        coordinator.seal_shadow(
            run,
            observations=(_observation(),),
            expected_sample_ids=("sample-1",),
            dataset_id="dataset://other",
        )
    assert coordinator.get_run(run.run_id).state is EvolutionState.REJECTED

    _store, coordinator, _address, _source, _candidate, run = _forked()
    run = coordinator.verify_replay(
        run, lambda state, event: state + event.payload["delta"], initial_state=0
    )
    with pytest.raises(EvidenceSealingError):
        coordinator.seal_shadow(
            run,
            observations=(_observation(),),
            expected_sample_ids=("sample-1",),
            real_provider_calls=1,
        )
    assert coordinator.get_run(run.run_id).state is EvolutionState.REJECTED


def test_issue_certificate_rejects_judge_and_invalid_expiry_then_promotes() -> None:
    _store, coordinator, _address, _source, _candidate, run = _sealed()
    with pytest.raises(CertificateError):
        coordinator.issue_certificate(
            run,
            JudgePolicy(expected_sample_ids=("missing",)),
            Ed25519PrivateKey.generate(),
            signing_key_id="judge",
        )
    assert coordinator.get_run(run.run_id).state is EvolutionState.REJECTED

    _store, coordinator, address, source, candidate, run = _sealed()
    key = Ed25519PrivateKey.generate()
    with pytest.raises(CertificateError):
        coordinator.issue_certificate(
            run, JudgePolicy(), key, signing_key_id="judge", valid_for_seconds=0
        )
    assert coordinator.get_run(run.run_id).state is EvolutionState.EVIDENCE_SEALED
    cert = coordinator.issue_certificate(run, JudgePolicy(), key, signing_key_id="judge")
    target = PromotionTarget(address, source.digest or source.content_digest)
    authority = PromotionApprovalAuthority(b"coordinator-promotion")
    approval = authority.issue(cert, target, approved_by="reviewer")
    with pytest.raises(PromotionError):
        coordinator.promote(
            run,
            PromotionStore(initial=(replace(target, active_capsule_digest=HASH_C),)),
            authority,
            approval,
            verifier=CertificateVerifier({"judge": key.public_key()}),
        )
    # A failed pointer CAS consumes the manual credential, so issue a fresh one.
    authority = PromotionApprovalAuthority(b"coordinator-promotion-2")
    approval = authority.issue(cert, target, approved_by="reviewer")
    store = PromotionStore(initial=(target,))
    receipt = coordinator.promote(
        run,
        store,
        authority,
        approval,
        verifier=CertificateVerifier({"judge": key.public_key()}),
    )
    assert receipt.active_capsule == candidate.digest
    assert coordinator.get_run(run.run_id).state is EvolutionState.PROMOTED
    rollback = coordinator.rollback(run, store, receipt)
    assert rollback.control_version == 2
    assert coordinator.get_run(run.run_id).state is EvolutionState.ROLLED_BACK
    with pytest.raises(EvolutionTransitionError):
        coordinator.rollback(run, store, receipt)


def test_coordinator_abort_expire_terminal_and_clock_paths() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    clock_value = [now]
    _store, coordinator, _address, _source, _candidate = _fixture(clock=lambda: clock_value[0])
    run = coordinator.get_run(next(iter(coordinator._runs)))
    aborted = coordinator.abort(run, reason="operator stopped")
    assert aborted.state is EvolutionState.ABORTED
    with pytest.raises(EvolutionTransitionError):
        coordinator.abort(aborted)

    _store, coordinator, _address, _source, _candidate = _fixture(clock=lambda: clock_value[0])
    run = coordinator.get_run(next(iter(coordinator._runs)))
    with pytest.raises(EvolutionTransitionError):
        coordinator.expire(run)
    expired = coordinator._save(replace(run, expires_at=now - timedelta(seconds=1)))
    expired = coordinator.expire(expired)
    assert expired.state is EvolutionState.EXPIRED
    with pytest.raises(EvolutionTransitionError):
        coordinator.expire(expired)

    _store, coordinator, _address, _source, _candidate = _fixture(clock=lambda: clock_value[0])
    run = coordinator.get_run(next(iter(coordinator._runs)))
    old_expiry = run.expires_at
    clock_value[0] = old_expiry + timedelta(seconds=1)
    with pytest.raises(EvolutionTransitionError):
        coordinator.fork(run)
    assert coordinator.get_run(run.run_id).state is EvolutionState.EXPIRED


def test_remaining_constructor_and_target_branches_are_fail_closed(monkeypatch: Any) -> None:
    assert _require_sha256("optional", "", allow_empty=True) == ""
    _store, _coordinator, address, _source, _candidate, _run, key, cert, target = _certified()
    assert _address_from(address) is address

    bundle = _bundle()
    main_target = replace(bundle.target, branch_id="fork")
    main_candidate = replace(bundle.candidate, branch_id="main")
    with pytest.raises(EvidenceSealingError):
        replace(bundle, target=main_target, candidate=main_candidate)

    malformed = cert.to_dict()
    malformed["signature"] = "!"
    with pytest.raises(CertificateError):
        EvolutionCertificate.from_dict(malformed)

    class CertificateValueError(CertificateError, ValueError):
        pass

    def raise_certificate_value_error(_value: Any) -> Any:
        raise CertificateValueError("already a certificate error")

    monkeypatch.setattr(evolution_module, "_address_from", raise_certificate_value_error)
    with pytest.raises(CertificateValueError):
        EvolutionCertificate.from_dict(cert.to_dict())
    monkeypatch.undo()

    with pytest.raises(PromotionError):
        PromotionTarget(target.address, HASH_A, control_version=True)
    flat_target = _address_dict(target.address)
    flat_target.update(
        {
            "active_capsule_digest": target.active_capsule_digest,
            "control_version": target.control_version,
        }
    )
    assert CertificateVerifier({"coverage-judge": key.public_key()}).verify(cert, flat_target).valid

    class EmptyDigest:
        def digest(self) -> bytes:
            return b""

    monkeypatch.setattr(evolution_module.hashlib, "sha256", lambda *_args: EmptyDigest())
    with pytest.raises(ApprovalError):
        PromotionApprovalAuthority()
    monkeypatch.undo()

    authority = PromotionApprovalAuthority(b"remaining-branches")
    by_address = authority.issue(cert, target.address, approved_by="reviewer")
    by_mapping = authority.issue(
        cert,
        {"address": _address_dict(target.address)},
        approved_by="reviewer",
    )
    assert by_address.target == by_mapping.target
    with pytest.raises(PromotionError):
        PromotionStore().get(target.address.with_branch("fork"))


def test_remaining_cas_and_rollback_pointer_branches_are_exercised() -> None:
    _store, _coordinator, address, source, candidate, _run, _key, cert, target = _certified()
    store = PromotionStore(initial=(target,))
    inferred = store.compare_and_swap(
        target,
        new_active_capsule=None,
        certificate=cert,
        approval_consumed=True,
    )
    assert inferred.active_capsule == candidate.digest

    _store, _coordinator, _address, _source, _candidate, _run, _key, cert, target = _certified()
    version_store = PromotionStore(initial=(target,))
    with pytest.raises(PromotionCASConflict):
        version_store.compare_and_swap(
            target,
            expected_control_version=1,
            new_active_capsule=cert.candidate_capsule_digest,
            certificate=cert,
            approval_consumed=True,
        )

    missing_store = PromotionStore(initial=(target,))
    receipt = missing_store.compare_and_swap(target, new_active_capsule=candidate.digest)
    del missing_store._pointers[missing_store._key(target.address)]
    with pytest.raises(PromotionReceiptError):
        missing_store.rollback(receipt)

    stale_store = PromotionStore(initial=(target,))
    stale_receipt = stale_store.compare_and_swap(target, new_active_capsule=candidate.digest)
    current = stale_store.get(target)
    assert current is not None
    stale_store._pointers[stale_store._key(target.address)] = PromotionPointer(
        target=replace(current, control_version=stale_receipt.control_version + 1),
        updated_at=datetime.now(UTC),
    )
    with pytest.raises(PromotionCASConflict):
        stale_store.rollback(stale_receipt)
    assert address.tenant_id == source.metadata.tenant_id
