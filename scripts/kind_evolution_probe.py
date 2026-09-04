#!/usr/bin/env python3
"""Run the Evolution online-control acceptance probe against real PostgreSQL.

This is an opt-in, destructive-in-the-sense-of-writing probe for a disposable
kind database.  It creates uniquely named promotion pointers and leaves the
resulting receipts/outbox rows in place for inspection.  By default, the
worker DSN creates runtime-only source/candidate capsules through the existing
security-definer API; ``--skip-fixture`` requires pre-provisioned digests.

The probe is intentionally separate from the deployment manifests.  A gate
runner can inject the dedicated authority DSN as
``TRPC_KIND_EVOLUTION_DATABASE_DSN`` into a candidate Pod and execute::

    python scripts/kind_evolution_probe.py --execute

Only typed status, counts, epochs and exception class names are emitted.  DSNs,
identifiers, signatures and exception messages never enter the report.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import inspect
import json
import os
import re
import secrets
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import asyncpg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.evidence_lineage import source_fingerprint
from scripts.report_io import atomic_write_json
from trpc_service.cell.capsule import AgentCapsule, CapsuleMetadata, CapsuleSpec
from trpc_service.cell.events import CellAddress, NamespaceViolation
from trpc_service.cell.evolution import (
    CertificateVerifier,
    EvolutionCertificate,
    PromotionAlreadyUsed,
    PromotionApprovalAuthority,
    PromotionCASConflict,
    PromotionReceipt,
    PromotionReceiptError,
    PromotionTarget,
)
from trpc_service.cell.evolution_postgres import PostgresPromotionStore
from trpc_service.cell.postgres import PostgresEventStore

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SAFE_CASE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_DSN_ENV = "TRPC_KIND_EVOLUTION_DATABASE_DSN"
_DEFAULT_FIXTURE_DSN_ENV = "TRPC_SERVICE_WORKER_DATABASE_DSN"
_DEFAULT_OUTPUT = Path("runs/multitenant/kind-evolution-probe.json")
_SOURCE_ENV = "TRPC_EVOLUTION_PROBE_SOURCE_CAPSULE_DIGEST"
_CANDIDATE_ENV = "TRPC_EVOLUTION_PROBE_CANDIDATE_CAPSULE_DIGEST"
_FIXTURE_FUNCTION = "public.ensure_runtime_projection_capsule(text,text,text,jsonb,text,text)"
PROBE_SCENARIO = "kind_evolution_postgres_control"
PROBE_ASSERTION = "candidate evolution control proves certificate, CAS and rollback invariants"


class ProbeConfigurationError(ValueError):
    """The opt-in probe did not receive safe, complete configuration."""


class ProbeAssertionError(RuntimeError):
    """A live PostgreSQL invariant did not hold."""

    def __init__(self, case: str, details: Mapping[str, object] | None = None) -> None:
        super().__init__(case)
        self.case = case
        self.details = dict(details or {})


class FixtureProvisionError(RuntimeError):
    """A worker-role fixture could not be created, with safe report metadata."""

    def __init__(self, *, role: str = "not_run", capsule_count: int = 0) -> None:
        super().__init__("evolution fixture provisioning failed")
        self.role = role
        self.capsule_count = capsule_count


@dataclass(frozen=True, slots=True)
class ProbeConfig:
    """Validated non-secret identifiers and the secret DSN kept out of reports."""

    database_dsn: str
    tenant_id: str
    app_id: str
    cell_id: str
    session_id: str
    source_capsule_digest: str
    candidate_capsule_digest: str
    run_token: str
    lease_seconds: float = 0.25
    timeout_seconds: float = 45.0

    def __post_init__(self) -> None:
        if not isinstance(self.database_dsn, str) or not self.database_dsn.strip():
            raise ProbeConfigurationError("database DSN is required")
        for field_name in ("tenant_id", "app_id", "cell_id", "session_id", "run_token"):
            _validate_identifier(field_name, getattr(self, field_name))
        _validate_digest("source_capsule_digest", self.source_capsule_digest)
        _validate_digest("candidate_capsule_digest", self.candidate_capsule_digest)
        if self.source_capsule_digest == self.candidate_capsule_digest:
            raise ProbeConfigurationError("source and candidate capsule digests must differ")
        if (
            isinstance(self.lease_seconds, bool)
            or not isinstance(self.lease_seconds, (int, float))
            or self.lease_seconds <= 0
        ):
            raise ProbeConfigurationError("lease_seconds must be positive")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or self.timeout_seconds <= 0
        ):
            raise ProbeConfigurationError("timeout_seconds must be positive")

    def address(self, suffix: str) -> CellAddress:
        _validate_identifier("target suffix", suffix)
        return CellAddress(
            tenant_id=self.tenant_id,
            app_id=self.app_id,
            cell_id=f"{self.cell_id}-evo-{self.run_token}-{suffix}",
            session_id=f"{self.session_id}-evo-{self.run_token}-{suffix}",
            capsule_digest=self.source_capsule_digest,
            branch_id="main",
        )

    def scope(self) -> dict[str, str]:
        return {
            "tenant_sha256": _fingerprint(self.tenant_id),
            "app_sha256": _fingerprint(self.app_id),
            "cell_sha256": _fingerprint(self.cell_id),
            "session_sha256": _fingerprint(self.session_id),
            "source_capsule_sha256": _fingerprint(self.source_capsule_digest),
            "candidate_capsule_sha256": _fingerprint(self.candidate_capsule_digest),
        }


def _validate_identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise ProbeConfigurationError(f"{name} has unsafe syntax")


def _validate_digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ProbeConfigurationError(f"{name} must be a lowercase sha256 digest")


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_error_type(error: BaseException) -> str:
    """Return only a stable class name; messages may contain credentials."""

    return type(error).__name__


def _normalise_dsn(value: str) -> str:
    # SQLAlchemy-style DSNs are occasionally supplied by the runtime secret.
    # Keep this transformation local and never include the resulting value in
    # a status object.
    return value.replace("postgresql+asyncpg://", "postgresql://", 1)


def _row_value(row: object, key: str) -> object:
    if isinstance(row, Mapping):
        return row.get(key)
    try:
        return cast(Any, row)[key]
    except (KeyError, TypeError, IndexError):
        return None


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _sha256_digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode('utf-8')).hexdigest()}"


def _redacted_case(name: str, *, passed: bool, **details: object) -> dict[str, object]:
    result: dict[str, object] = {"name": name, "passed": passed}
    result.update(details)
    return result


def _base_report(config: ProbeConfig | None, *, gate: str) -> dict[str, object]:
    try:
        raw_lineage = source_fingerprint(ROOT)
        lineage: dict[str, object] = {
            key: raw_lineage[key] for key in ("algorithm", "status", "value") if key in raw_lineage
        }
    except Exception as error:  # pragma: no cover - defensive report boundary
        lineage = {
            "algorithm": "sha256",
            "status": "unavailable",
            "reason": type(error).__name__,
        }
    value: dict[str, object] = {
        "schema_version": 1,
        "probe": "kind_evolution_postgres",
        "scenario": PROBE_SCENARIO,
        "assertion": PROBE_ASSERTION,
        "source_fingerprint": lineage,
        "environment": "kind",
        "generated_at": _utc_now().isoformat(timespec="seconds"),
        "gate": gate,
        "status": gate,
        "local_k8s_gate": gate,
        # This probe is scoped to a disposable local kind cluster.  It never
        # constitutes independent production evidence.
        "production_gate": "not_run",
        "provider_calls": 0,
        "checks": {},
        "rejection_reasons": [],
        "fixture": {"status": "not_run", "role": "not_run", "capsule_count": 0},
        "database": {"connected": False, "role_verified": False, "required_tables": False},
        "cases": [],
    }
    if config is not None:
        value["run_token_sha256"] = _fingerprint(config.run_token)
        value["scope"] = config.scope()
    return value


def _append_case(report: dict[str, object], case: dict[str, object]) -> None:
    cases = cast(list[dict[str, object]], report["cases"])
    cases.append(case)
    checks = cast(dict[str, dict[str, object]], report["checks"])
    name = case.get("name")
    if isinstance(name, str):
        checks[name] = {"status": "pass" if case.get("passed") is True else "fail"}


def _record_assertion_failure(report: dict[str, object], error: ProbeAssertionError) -> None:
    """Record only stable, non-sensitive metadata for a failed live case."""

    case_name = (
        error.case
        if isinstance(error.case, str) and _SAFE_CASE_NAME_RE.fullmatch(error.case)
        else "probe_assertion"
    )
    rejection_reason = f"probe assertion failed: {case_name}"
    report["rejection_reasons"] = [rejection_reason]
    _append_case(
        report,
        _redacted_case(
            case_name,
            passed=False,
            error_type=_safe_error_type(error),
            rejection_reason=rejection_reason,
        ),
    )


def _make_address(config: ProbeConfig, suffix: str, *, branch: str, digest: str) -> CellAddress:
    base = config.address(suffix)
    _validate_identifier("candidate branch", branch)
    return replace(base, capsule_digest=digest, branch_id=branch)


def _make_certificate(
    config: ProbeConfig,
    target: PromotionTarget,
    *,
    certificate_id: str,
    candidate_suffix: str,
    signing_key: Ed25519PrivateKey,
    issued_at: datetime,
) -> EvolutionCertificate:
    candidate_branch = f"candidate-{config.run_token}-{candidate_suffix}"
    candidate_address = _make_address(
        config,
        target.address.cell_id.removeprefix(f"{config.cell_id}-evo-{config.run_token}-"),
        branch=candidate_branch,
        digest=config.candidate_capsule_digest,
    )
    certificate = EvolutionCertificate(
        certificate_id=certificate_id,
        source_address=target.address,
        candidate_address=candidate_address,
        source_capsule_digest=config.source_capsule_digest,
        candidate_capsule_digest=config.candidate_capsule_digest,
        fork_sequence=0,
        fork_hash=_sha256_digest(f"fork:{certificate_id}"),
        source_head_hash=_sha256_digest(f"source-head:{certificate_id}"),
        candidate_head_hash=_sha256_digest(f"candidate-head:{certificate_id}"),
        dataset_id="dataset://kind-evolution-probe",
        runner_id="runner://kind-evolution-probe",
        model_id="model://kind-evolution-probe",
        policy_digest=_sha256_digest("policy:kind-evolution-probe"),
        tool_manifest_digest=_sha256_digest("tools:kind-evolution-probe"),
        reducer_id="reducer://kind-evolution-probe",
        evidence_digest=_sha256_digest(f"evidence:{certificate_id}"),
        judge_policy={"mode": "probe"},
        expected_active_capsule=target.active_capsule_digest,
        control_version=target.control_version,
        signing_key_id="kind-evolution-certificate",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=5),
    )
    return certificate.with_signature(signing_key)


async def _database_preflight(pool: Any) -> dict[str, bool]:
    async with pool.acquire() as connection:
        row = await connection.fetchrow(
            """
            SELECT current_user::text AS role,
                   to_regclass('public.cell_promotion_targets')::text AS targets,
                   to_regclass('public.cell_promotion_uses')::text AS uses,
                   to_regclass('public.cell_promotion_receipts')::text AS receipts,
                   to_regclass('public.cell_promotion_outbox')::text AS outbox
            """
        )
    role_verified = _row_value(row, "role") == "trpc_evolution_authority"
    required_tables = all(
        _row_value(row, table) is not None for table in ("targets", "uses", "receipts", "outbox")
    )
    return {
        "connected": True,
        "role_verified": role_verified,
        "required_tables": required_tables,
    }


def _synthetic_capsule(
    config: ProbeConfig,
    label: str,
    signing_key: Ed25519PrivateKey,
) -> AgentCapsule:
    """Build a signed, content-addressed runtime-only fixture capsule."""

    base = f"probe://kind-evolution/{config.run_token}/{label}"
    return AgentCapsule(
        metadata=CapsuleMetadata(
            tenant_id=config.tenant_id,
            name=f"kind-evolution-{config.run_token}-{label}",
        ),
        spec=CapsuleSpec(
            graph=f"{base}/graph",
            prompt=f"{base}/prompt",
            model_policy=f"{base}/model-policy",
            tool_manifest=f"{base}/tool-manifest",
            governance_policy=f"{base}/governance-policy",
            storage_profile=f"{base}/storage",
        ),
    ).sign(signing_key, key_id="kind-evolution-fixture")


async def _provision_fixture(
    config: ProbeConfig, fixture_dsn: str
) -> tuple[ProbeConfig, dict[str, object]]:
    """Seed two runtime-only capsules through the worker's security boundary."""

    fixture_pool: Any = None
    try:
        fixture_pool = await asyncpg.create_pool(
            dsn=_normalise_dsn(fixture_dsn),
            min_size=1,
            max_size=1,
            command_timeout=config.timeout_seconds,
        )
        async with fixture_pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                SELECT current_user::text AS role,
                       to_regprocedure($1)::text AS capsule_function
                """,
                _FIXTURE_FUNCTION,
            )
        worker_role = _row_value(row, "role") == "trpc_worker"
        function_available = _row_value(row, "capsule_function") is not None
        if not worker_role:
            raise FixtureProvisionError(role="unexpected")
        if not function_available:
            raise FixtureProvisionError(role="trpc_worker")

        async with fixture_pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute(
                    "SELECT set_config('app.tenant_id', $1, true)", config.tenant_id
                )
                await connection.execute(
                    """
                    INSERT INTO public.tenants (tenant_id, display_name)
                    VALUES ($1, $2)
                    ON CONFLICT (tenant_id) DO NOTHING
                    """,
                    config.tenant_id,
                    "Kind Evolution Acceptance Fixture",
                )

        fixture_signing_key = Ed25519PrivateKey.generate()
        source = _synthetic_capsule(config, "source", fixture_signing_key)
        candidate = _synthetic_capsule(config, "candidate", fixture_signing_key)
        event_store = PostgresEventStore(fixture_pool)
        source_digest = await event_store.ensure_capsule(
            config.tenant_id, source, trust_class="runtime_projection"
        )
        candidate_digest = await event_store.ensure_capsule(
            config.tenant_id, candidate, trust_class="runtime_projection"
        )
        async with fixture_pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute(
                    "SELECT set_config('app.tenant_id', $1, true)", config.tenant_id
                )
                capsule_count = await connection.fetchval(
                    """
                    SELECT count(*)
                      FROM public.agent_capsules
                     WHERE tenant_id=$1
                       AND capsule_digest = ANY($2::text[])
                       AND trust_class='runtime_projection'
                    """,
                    config.tenant_id,
                    [source_digest, candidate_digest],
                )
        count = int(capsule_count or 0)
        if count != 2:
            raise FixtureProvisionError(role="trpc_worker", capsule_count=count)
        return (
            replace(
                config,
                source_capsule_digest=source_digest,
                candidate_capsule_digest=candidate_digest,
            ),
            {"status": "pass", "role": "trpc_worker", "capsule_count": count},
        )
    finally:
        if fixture_pool is not None:
            await _close_pool(fixture_pool)


async def _ensure_target(pool: Any, target: PromotionTarget) -> None:
    """Create only the probe pointer; capsules remain a caller-owned fixture."""

    async with pool.acquire() as connection:
        async with connection.transaction():
            await connection.execute(
                "SELECT set_config('app.tenant_id', $1, true)", target.tenant_id
            )
            row = await connection.fetchrow(
                """
                SELECT active_capsule_digest, control_version
                  FROM cell_promotion_targets
                 WHERE tenant_id=$1 AND app_id=$2 AND cell_id=$3 AND session_id=$4
                """,
                target.tenant_id,
                target.address.app_id,
                target.address.cell_id,
                target.address.session_id,
            )
            if row is None:
                await connection.execute(
                    """
                    INSERT INTO cell_promotion_targets
                        (tenant_id, app_id, cell_id, session_id,
                         active_capsule_digest, control_version)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    """,
                    target.tenant_id,
                    target.address.app_id,
                    target.address.cell_id,
                    target.address.session_id,
                    target.active_capsule_digest,
                    target.control_version,
                )
                return
            if (
                _row_value(row, "active_capsule_digest") != target.active_capsule_digest
                or int(cast(Any, _row_value(row, "control_version"))) != target.control_version
            ):
                raise ProbeConfigurationError("probe pointer already has a different state")


async def _use_counts(
    pool: Any, target: PromotionTarget, certificate_id: str, approval_id: str
) -> tuple[int, int]:
    async with pool.acquire() as connection:
        async with connection.transaction():
            await connection.execute(
                "SELECT set_config('app.tenant_id', $1, true)", target.tenant_id
            )
            certificate_count = await connection.fetchval(
                """
                SELECT count(*) FROM cell_promotion_uses
                 WHERE tenant_id=$1 AND certificate_id=$2
                """,
                target.tenant_id,
                certificate_id,
            )
            approval_count = await connection.fetchval(
                """
                SELECT count(*) FROM cell_promotion_uses
                 WHERE tenant_id=$1 AND approval_id=$2
                """,
                target.tenant_id,
                approval_id,
            )
    return int(certificate_count or 0), int(approval_count or 0)


def _store(
    pool: Any,
    config: ProbeConfig,
    *,
    certificate_verifier: CertificateVerifier,
    approval_secret: bytes,
    receipt_signing_key: Ed25519PrivateKey,
) -> PostgresPromotionStore:
    return PostgresPromotionStore(
        pool,
        tenant_id=config.tenant_id,
        receipt_signing_key=receipt_signing_key,
        receipt_key_id="kind-evolution-receipt",
        certificate_verifier=certificate_verifier,
        approval_secret=approval_secret,
        clock=_utc_now,
    )


def _assert(condition: bool, case: str, **details: object) -> None:
    if not condition:
        raise ProbeAssertionError(case, details)


async def _run_live(config: ProbeConfig, pool: Any) -> dict[str, object]:
    report = _base_report(config, gate="fail")
    preflight = await _database_preflight(pool)
    report["database"] = preflight
    _assert(
        preflight["role_verified"] and preflight["required_tables"],
        "database_identity_and_schema",
        role_verified=preflight["role_verified"],
        required_tables=preflight["required_tables"],
    )
    _append_case(report, _redacted_case("database_identity_and_schema", passed=True))

    certificate_key = Ed25519PrivateKey.generate()
    receipt_key = Ed25519PrivateKey.generate()
    approval_secret = secrets.token_bytes(32)
    verifier = CertificateVerifier(
        {"kind-evolution-certificate": certificate_key.public_key()}, clock=_utc_now
    )
    approval_authority = PromotionApprovalAuthority(approval_secret, clock=_utc_now)
    store = _store(
        pool,
        config,
        certificate_verifier=verifier,
        approval_secret=approval_secret,
        receipt_signing_key=receipt_key,
    )

    target_cas = PromotionTarget(
        config.address("cas"), config.source_capsule_digest, control_version=0
    )
    target_certificate = PromotionTarget(
        config.address("certificate"), config.source_capsule_digest, control_version=0
    )
    target_approval = PromotionTarget(
        config.address("approval"), config.source_capsule_digest, control_version=0
    )
    for target in (target_cas, target_certificate, target_approval):
        await _ensure_target(pool, target)

    issued_at = _utc_now()
    primary_certificate = _make_certificate(
        config,
        target_cas,
        certificate_id=f"{config.run_token}-certificate-primary",
        candidate_suffix="cas",
        signing_key=certificate_key,
        issued_at=issued_at,
    )
    primary_approval = approval_authority.issue(
        primary_certificate,
        target_cas,
        approved_by="kind-probe",
        ttl_seconds=300,
        approval_id=f"{config.run_token}-approval-primary",
    )

    async def promote_once() -> tuple[str, PromotionReceipt | None, str | None]:
        try:
            receipt = await store.compare_and_swap(
                target_cas, certificate=primary_certificate, approval=primary_approval
            )
            return "winner", receipt, None
        except PromotionCASConflict as error:
            return "conflict", None, _safe_error_type(error)
        except Exception as error:
            return "error", None, _safe_error_type(error)

    attempts = await asyncio.gather(promote_once(), promote_once())
    winners = [item for item in attempts if item[0] == "winner"]
    conflicts = [item for item in attempts if item[0] == "conflict"]
    errors = [item for item in attempts if item[0] == "error"]
    _assert(
        len(winners) == 1 and len(conflicts) == 1 and not errors,
        "concurrent_cas",
        winner_count=len(winners),
        conflict_count=len(conflicts),
        error_count=len(errors),
        error_types=sorted(item[2] for item in errors if item[2]),
    )
    winner_receipt = cast(PromotionReceipt, winners[0][1])
    cert_count, approval_count = await _use_counts(
        pool, target_cas, primary_certificate.certificate_id, primary_approval.approval_id
    )
    _assert(
        cert_count == 1 and approval_count == 1,
        "concurrent_cas_use_fence",
        certificate_count=cert_count,
        approval_count=approval_count,
    )
    _append_case(
        report,
        _redacted_case(
            "concurrent_cas",
            passed=True,
            winner_count=1,
            conflict_count=1,
            durable_certificate_uses=cert_count,
            durable_approval_uses=approval_count,
        ),
    )

    duplicate_certificate = _make_certificate(
        config,
        target_certificate,
        certificate_id=primary_certificate.certificate_id,
        candidate_suffix="certificate-duplicate",
        signing_key=certificate_key,
        issued_at=issued_at,
    )
    duplicate_certificate_approval = approval_authority.issue(
        duplicate_certificate,
        target_certificate,
        approved_by="kind-probe",
        ttl_seconds=300,
        approval_id=f"{config.run_token}-approval-duplicate-certificate",
    )
    duplicate_certificate_error: str | None = None
    try:
        await store.compare_and_swap(
            target_certificate,
            certificate=duplicate_certificate,
            approval=duplicate_certificate_approval,
        )
    except PromotionAlreadyUsed as error:
        duplicate_certificate_error = _safe_error_type(error)

    duplicate_approval_certificate = _make_certificate(
        config,
        target_approval,
        certificate_id=f"{config.run_token}-certificate-duplicate-approval",
        candidate_suffix="approval-duplicate",
        signing_key=certificate_key,
        issued_at=issued_at,
    )
    duplicate_approval = approval_authority.issue(
        duplicate_approval_certificate,
        target_approval,
        approved_by="kind-probe",
        ttl_seconds=300,
        approval_id=primary_approval.approval_id,
    )
    duplicate_approval_error: str | None = None
    try:
        await store.compare_and_swap(
            target_approval,
            certificate=duplicate_approval_certificate,
            approval=duplicate_approval,
        )
    except PromotionAlreadyUsed as error:
        duplicate_approval_error = _safe_error_type(error)

    authority_first = approval_authority.verify_and_consume(
        primary_approval, primary_certificate, target_cas
    )
    authority_duplicate_error: str | None = None
    try:
        approval_authority.verify_and_consume(primary_approval, primary_certificate, target_cas)
    except PromotionAlreadyUsed as error:
        authority_duplicate_error = _safe_error_type(error)
    cert_target_state = await store.get(target_certificate)
    approval_target_state = await store.get(target_approval)
    _assert(
        duplicate_certificate_error == "PromotionAlreadyUsed"
        and duplicate_approval_error == "PromotionAlreadyUsed"
        and authority_first
        and authority_duplicate_error == "PromotionAlreadyUsed"
        and cert_target_state == target_certificate
        and approval_target_state == target_approval,
        "certificate_approval_one_time",
        duplicate_certificate_rejected=duplicate_certificate_error == "PromotionAlreadyUsed",
        duplicate_approval_rejected=duplicate_approval_error == "PromotionAlreadyUsed",
        authority_duplicate_rejected=authority_duplicate_error == "PromotionAlreadyUsed",
    )
    _append_case(
        report,
        _redacted_case(
            "certificate_approval_one_time",
            passed=True,
            duplicate_certificate_rejected=True,
            duplicate_approval_rejected=True,
            authority_duplicate_rejected=True,
        ),
    )

    claim_a_values = await store.claim_outbox(
        owner_id=f"{config.run_token}-worker-a",
        lease_seconds=config.lease_seconds,
        limit=1,
    )
    _assert(
        len(claim_a_values) == 1,
        "outbox_lease_takeover",
        first_claim_count=len(claim_a_values),
    )
    claim_a = claim_a_values[0]
    stale_ack_before_expiry = await store.acknowledge(
        claim_a.receipt_id,
        owner_id=f"{config.run_token}-wrong-owner",
        lease_epoch=claim_a.lease_epoch,
    )
    await asyncio.sleep(config.lease_seconds + 0.05)
    claim_b_values = await store.claim_outbox(
        owner_id=f"{config.run_token}-worker-b",
        lease_seconds=config.lease_seconds,
        limit=1,
    )
    _assert(
        len(claim_b_values) == 1,
        "outbox_lease_takeover",
        takeover_claim_count=len(claim_b_values),
    )
    claim_b = claim_b_values[0]
    stale_ack_after_takeover = await store.acknowledge(
        claim_b.receipt_id,
        owner_id=claim_a.owner_id,
        lease_epoch=claim_a.lease_epoch,
    )
    released = await store.release(
        claim_b.receipt_id,
        owner_id=claim_b.owner_id,
        lease_epoch=claim_b.lease_epoch,
        error="simulated_publish_failure",
        delay_seconds=0,
    )
    claim_c_values = await store.claim_outbox(
        owner_id=f"{config.run_token}-worker-c",
        lease_seconds=config.lease_seconds,
        limit=1,
    )
    _assert(
        len(claim_c_values) == 1,
        "outbox_lease_takeover",
        recovery_claim_count=len(claim_c_values),
    )
    claim_c = claim_c_values[0]
    acknowledged = await store.acknowledge(
        claim_c.receipt_id,
        owner_id=claim_c.owner_id,
        lease_epoch=claim_c.lease_epoch,
    )
    duplicate_ack = await store.acknowledge(
        claim_c.receipt_id,
        owner_id=claim_c.owner_id,
        lease_epoch=claim_c.lease_epoch,
    )
    _assert(
        not stale_ack_before_expiry
        and not stale_ack_after_takeover
        and released
        and acknowledged
        and not duplicate_ack
        and claim_b.lease_epoch > claim_a.lease_epoch
        and claim_c.lease_epoch > claim_b.lease_epoch,
        "outbox_lease_takeover",
        stale_ack_before_expiry=stale_ack_before_expiry,
        stale_ack_after_takeover=stale_ack_after_takeover,
        released=released,
        acknowledged=acknowledged,
        duplicate_ack=duplicate_ack,
        first_lease_epoch=claim_a.lease_epoch,
        takeover_lease_epoch=claim_b.lease_epoch,
        recovery_lease_epoch=claim_c.lease_epoch,
    )
    _append_case(
        report,
        _redacted_case(
            "outbox_lease_takeover",
            passed=True,
            stale_ack_before_expiry=False,
            stale_ack_after_takeover=False,
            acknowledged=True,
            duplicate_ack=False,
            lease_epochs=[claim_a.lease_epoch, claim_b.lease_epoch, claim_c.lease_epoch],
        ),
    )

    rollback_receipt = await store.rollback(winner_receipt)
    current_after_rollback = await store.get(target_cas)
    duplicate_rollback_error: str | None = None
    try:
        await store.rollback(winner_receipt)
    except PromotionAlreadyUsed as error:
        duplicate_rollback_error = _safe_error_type(error)
    tampered_signature = base64.urlsafe_b64encode(b"x" * 64).decode("ascii").rstrip("=")
    tampered_receipt_error: str | None = None
    try:
        await store.rollback(replace(winner_receipt, signature=tampered_signature))
    except PromotionReceiptError as error:
        tampered_receipt_error = _safe_error_type(error)
    _assert(
        rollback_receipt.operation == "rollback"
        and rollback_receipt.rollback_of == winner_receipt.receipt_id
        and current_after_rollback is not None
        and current_after_rollback.active_capsule_digest == config.source_capsule_digest
        and current_after_rollback.control_version == 2
        and duplicate_rollback_error == "PromotionAlreadyUsed"
        and tampered_receipt_error == "PromotionReceiptError",
        "receipt_rollback",
        rollback_version=getattr(rollback_receipt, "control_version", None),
        duplicate_rollback_rejected=duplicate_rollback_error == "PromotionAlreadyUsed",
        tampered_receipt_rejected=tampered_receipt_error == "PromotionReceiptError",
    )
    _append_case(
        report,
        _redacted_case(
            "receipt_rollback",
            passed=True,
            rollback_version=rollback_receipt.control_version,
            duplicate_rollback_rejected=True,
            tampered_receipt_rejected=True,
        ),
    )

    stale_cas_error: str | None = None
    try:
        await store.compare_and_swap(
            target_cas,
            expected_active_capsule=config.source_capsule_digest,
            expected_control_version=0,
            new_active_capsule=config.candidate_capsule_digest,
        )
    except PromotionCASConflict as error:
        stale_cas_error = _safe_error_type(error)
    stale_verification = verifier.verify(
        primary_certificate,
        PromotionTarget(target_cas.address, config.source_capsule_digest, control_version=2),
    )
    _assert(
        stale_cas_error == "PromotionCASConflict" and not stale_verification.valid,
        "stale_aba_rejection",
        stale_cas_rejected=stale_cas_error == "PromotionCASConflict",
        stale_certificate_rejected=not stale_verification.valid,
    )
    _append_case(
        report,
        _redacted_case(
            "stale_aba_rejection",
            passed=True,
            stale_cas_rejected=True,
            stale_certificate_rejected=True,
            final_control_version=2,
        ),
    )

    foreign_address = CellAddress(
        tenant_id=f"foreign-{config.run_token}",
        app_id=target_cas.address.app_id,
        cell_id=target_cas.address.cell_id,
        session_id=target_cas.address.session_id,
        capsule_digest=config.source_capsule_digest,
        branch_id="main",
    )
    foreign_target = PromotionTarget(
        foreign_address, config.source_capsule_digest, control_version=0
    )
    foreign_store_error: str | None = None
    try:
        await store.get(foreign_target)
    except NamespaceViolation as error:
        foreign_store_error = _safe_error_type(error)
    foreign_verification = verifier.verify(primary_certificate, foreign_target)
    _assert(
        foreign_store_error == "NamespaceViolation" and not foreign_verification.valid,
        "cross_tenant_rejection",
        store_scope_rejected=foreign_store_error == "NamespaceViolation",
        certificate_scope_rejected=not foreign_verification.valid,
    )
    _append_case(
        report,
        _redacted_case(
            "cross_tenant_rejection",
            passed=True,
            store_scope_rejected=True,
            certificate_scope_rejected=True,
        ),
    )
    report["gate"] = "pass"
    report["status"] = "pass"
    report["local_k8s_gate"] = "pass"
    return report


async def _close_pool(pool: Any) -> None:
    close = getattr(pool, "close", None)
    if callable(close):
        result = close()
        if inspect.isawaitable(result):
            await result


def _config_from_environment(
    *,
    database_dsn: str | None,
    database_dsn_env: str,
    tenant_id: str | None,
    app_id: str | None,
    cell_id: str | None,
    session_id: str | None,
    source_capsule_digest: str | None,
    candidate_capsule_digest: str | None,
    run_token: str | None,
    lease_seconds: float,
    timeout_seconds: float,
) -> ProbeConfig:
    if not _ENV_NAME_RE.fullmatch(database_dsn_env):
        raise ProbeConfigurationError("database DSN environment name is unsafe")

    def value_or_env(value: str | None, env_name: str) -> str | None:
        return value if value is not None else os.environ.get(env_name)

    resolved_dsn = database_dsn if database_dsn is not None else os.environ.get(database_dsn_env)
    resolved_token = value_or_env(run_token, "TRPC_EVOLUTION_PROBE_RUN_TOKEN")
    if resolved_token is None:
        resolved_token = secrets.token_hex(8)
    resolved_tenant = value_or_env(tenant_id, "TRPC_EVOLUTION_PROBE_TENANT_ID")
    resolved_app = value_or_env(app_id, "TRPC_EVOLUTION_PROBE_APP_ID")
    resolved_cell = value_or_env(cell_id, "TRPC_EVOLUTION_PROBE_CELL_ID")
    resolved_session = value_or_env(session_id, "TRPC_EVOLUTION_PROBE_SESSION_ID")
    resolved_source = value_or_env(source_capsule_digest, _SOURCE_ENV)
    resolved_candidate = value_or_env(candidate_capsule_digest, _CANDIDATE_ENV)
    source_explicit = source_capsule_digest is not None or _SOURCE_ENV in os.environ
    candidate_explicit = candidate_capsule_digest is not None or _CANDIDATE_ENV in os.environ
    if source_explicit != candidate_explicit:
        raise ProbeConfigurationError("source and candidate digests must be supplied together")

    # A kind gate normally injects only the dedicated authority DSN.  Missing
    # namespace values therefore get unique synthetic defaults, while an
    # explicitly supplied empty value still fails closed through validation.
    if resolved_tenant is None:
        resolved_tenant = f"kind-evolution-{resolved_token}"
    if resolved_app is None:
        resolved_app = "evolution-probe"
    if resolved_cell is None:
        resolved_cell = "probe-cell"
    if resolved_session is None:
        resolved_session = "probe-session"
    if resolved_source is None:
        resolved_source = _sha256_digest(f"source-capsule:{resolved_token}")
    if resolved_candidate is None:
        resolved_candidate = _sha256_digest(f"candidate-capsule:{resolved_token}")
    missing = [
        name
        for name, item in (
            ("database_dsn", resolved_dsn),
            ("tenant_id", resolved_tenant),
            ("app_id", resolved_app),
            ("cell_id", resolved_cell),
            ("session_id", resolved_session),
            ("source_capsule_digest", resolved_source),
            ("candidate_capsule_digest", resolved_candidate),
        )
        if not item
    ]
    if missing:
        raise ProbeConfigurationError("required configuration is missing")
    assert resolved_dsn is not None
    return ProbeConfig(
        database_dsn=resolved_dsn,
        tenant_id=resolved_tenant,
        app_id=resolved_app,
        cell_id=resolved_cell,
        session_id=resolved_session,
        source_capsule_digest=resolved_source,
        candidate_capsule_digest=resolved_candidate,
        run_token=resolved_token,
        lease_seconds=lease_seconds,
        timeout_seconds=timeout_seconds,
    )


async def run_probe(
    *,
    execute: bool = False,
    database_dsn: str | None = None,
    database_dsn_env: str = _DEFAULT_DSN_ENV,
    fixture_dsn: str | None = None,
    fixture_dsn_env: str = _DEFAULT_FIXTURE_DSN_ENV,
    skip_fixture: bool = False,
    tenant_id: str | None = None,
    app_id: str | None = None,
    cell_id: str | None = None,
    session_id: str | None = None,
    source_capsule_digest: str | None = None,
    candidate_capsule_digest: str | None = None,
    run_token: str | None = None,
    lease_seconds: float = 0.25,
    timeout_seconds: float = 45.0,
    pool_factory: Callable[..., Awaitable[Any]] | None = None,
) -> dict[str, object]:
    """Run the probe; no network connection is attempted without ``execute``."""

    if not execute:
        return _base_report(None, gate="not_run")
    try:
        config = _config_from_environment(
            database_dsn=database_dsn,
            database_dsn_env=database_dsn_env,
            tenant_id=tenant_id,
            app_id=app_id,
            cell_id=cell_id,
            session_id=session_id,
            source_capsule_digest=source_capsule_digest,
            candidate_capsule_digest=candidate_capsule_digest,
            run_token=run_token,
            lease_seconds=lease_seconds,
            timeout_seconds=timeout_seconds,
        )
    except Exception as error:
        report = _base_report(None, gate="fail")
        _append_case(
            report,
            _redacted_case(
                "required_configuration", passed=False, error_type=_safe_error_type(error)
            ),
        )
        return report

    source_explicit = source_capsule_digest is not None or _SOURCE_ENV in os.environ
    candidate_explicit = candidate_capsule_digest is not None or _CANDIDATE_ENV in os.environ
    fixture_report: dict[str, object]
    if skip_fixture:
        if not source_explicit or not candidate_explicit:
            report = _base_report(config, gate="fail")
            report["fixture"] = {"status": "fail", "role": "not_run", "capsule_count": 0}
            _append_case(
                report,
                _redacted_case(
                    "fixture_configuration",
                    passed=False,
                    error_type="ProbeConfigurationError",
                ),
            )
            return report
        fixture_report = {"status": "skipped", "role": "not_run", "capsule_count": 0}
    else:
        if not _ENV_NAME_RE.fullmatch(fixture_dsn_env):
            report = _base_report(config, gate="fail")
            report["fixture"] = {"status": "fail", "role": "not_run", "capsule_count": 0}
            _append_case(
                report,
                _redacted_case(
                    "fixture_configuration",
                    passed=False,
                    error_type="ProbeConfigurationError",
                ),
            )
            return report
        resolved_fixture_dsn = (
            fixture_dsn if fixture_dsn is not None else os.environ.get(fixture_dsn_env)
        )
        if not resolved_fixture_dsn:
            report = _base_report(config, gate="fail")
            report["fixture"] = {"status": "fail", "role": "not_run", "capsule_count": 0}
            _append_case(
                report,
                _redacted_case(
                    "fixture_configuration",
                    passed=False,
                    error_type="ProbeConfigurationError",
                ),
            )
            return report
        try:
            config, fixture_report = await _provision_fixture(config, resolved_fixture_dsn)
        except Exception as error:
            report = _base_report(config, gate="fail")
            if isinstance(error, FixtureProvisionError):
                report["fixture"] = {
                    "status": "fail",
                    "role": error.role,
                    "capsule_count": error.capsule_count,
                }
            else:
                report["fixture"] = {
                    "status": "fail",
                    "role": "not_run",
                    "capsule_count": 0,
                }
            _append_case(
                report,
                _redacted_case("fixture_setup", passed=False, error_type=_safe_error_type(error)),
            )
            return report

    factory = pool_factory or asyncpg.create_pool
    pool: Any = None
    try:
        pool = await factory(
            dsn=_normalise_dsn(config.database_dsn),
            min_size=1,
            max_size=4,
            command_timeout=config.timeout_seconds,
        )
        report = await asyncio.wait_for(_run_live(config, pool), timeout=config.timeout_seconds)
        report["fixture"] = fixture_report
    except ProbeAssertionError as error:
        report = _base_report(config, gate="fail")
        report["fixture"] = fixture_report
        _record_assertion_failure(report, error)
    except Exception as error:
        report = _base_report(config, gate="fail")
        report["fixture"] = fixture_report
        _append_case(
            report,
            _redacted_case("live_probe", passed=False, error_type=_safe_error_type(error)),
        )
    finally:
        if pool is not None:
            try:
                await _close_pool(pool)
            except Exception as error:
                if report.get("gate") == "pass":
                    report["gate"] = "fail"
                    report["status"] = "fail"
                    report["local_k8s_gate"] = "fail"
                    _append_case(
                        report,
                        _redacted_case(
                            "database_close", passed=False, error_type=_safe_error_type(error)
                        ),
                    )
    return report


def _exit_code(report: Mapping[str, object]) -> int:
    gate = report.get("gate")
    return {"pass": 0, "fail": 1, "not_run": 2}.get(cast(str, gate), 1)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="opt in to the real PostgreSQL probe (or set TRPC_RUN_REAL_EVOLUTION=1)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="with a DSN present, run the live probe and emit JSON only",
    )
    parser.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT)
    parser.add_argument("--database-dsn-env", default=_DEFAULT_DSN_ENV)
    parser.add_argument("--fixture-dsn-env", default=_DEFAULT_FIXTURE_DSN_ENV)
    parser.add_argument(
        "--skip-fixture",
        action="store_true",
        help="use explicitly supplied pre-provisioned capsule digests",
    )
    parser.add_argument("--tenant-id")
    parser.add_argument("--app-id")
    parser.add_argument("--cell-id")
    parser.add_argument("--session-id")
    parser.add_argument("--source-capsule-digest", default=None)
    parser.add_argument("--candidate-capsule-digest", default=None)
    parser.add_argument("--run-token", default=None)
    parser.add_argument("--lease-seconds", type=float, default=0.25)
    parser.add_argument("--timeout-seconds", type=float, default=45.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    # The kind ACK runner invokes candidate probes with ``--json`` and injects
    # only the dedicated DSN.  A present DSN plus that explicit machine-output
    # flag is therefore also an opt-in; a bare invocation remains not_run.
    execute = bool(
        args.execute
        or os.environ.get("TRPC_RUN_REAL_EVOLUTION") == "1"
        or (args.json and os.environ.get(args.database_dsn_env))
    )
    report = asyncio.run(
        run_probe(
            execute=execute,
            database_dsn_env=args.database_dsn_env,
            fixture_dsn_env=args.fixture_dsn_env,
            skip_fixture=args.skip_fixture,
            tenant_id=args.tenant_id,
            app_id=args.app_id,
            cell_id=args.cell_id,
            session_id=args.session_id,
            source_capsule_digest=args.source_capsule_digest,
            candidate_capsule_digest=args.candidate_capsule_digest,
            run_token=args.run_token,
            lease_seconds=args.lease_seconds,
            timeout_seconds=args.timeout_seconds,
        )
    )
    if not args.json:
        try:
            atomic_write_json(args.output, report)
        except Exception as error:
            report = dict(report)
            report["gate"] = "fail"
            report["status"] = "fail"
            report["local_k8s_gate"] = "fail"
            _append_case(
                report,
                _redacted_case("report_write", passed=False, error_type=_safe_error_type(error)),
            )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return _exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
