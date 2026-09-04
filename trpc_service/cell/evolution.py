"""Offline Proof-Carrying Evolution contracts.

This module contains the control-plane part of candidate Cell evolution.  It
is deliberately independent from the worker and effect executor: candidate
evaluation is always ``simulate_only`` and a certificate never carries a
credential that can invoke a provider.  The reference implementation keeps
promotion pointers in memory so the complete protocol can be exercised on a
developer machine; :mod:`migrations.versions.0025_proof_carrying_evolution`
defines the PostgreSQL tables for a future adapter.

The public objects are intentionally small immutable records.  Their
canonical JSON representations are used for digests, Merkle leaves,
certificates and promotion receipts, which makes tampering and replay
failures observable without retaining prompts, arguments or provider
responses.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import hmac
import json
import threading
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from trpc_service.cell.capsule import AgentCapsule
from trpc_service.cell.events import (
    GENESIS_HASH,
    CellAddress,
    EventStore,
    InMemoryEventStore,
    NamespaceViolation,
)
from trpc_service.cell.replay import (
    DeterminismViolation,
    Projection,
    ProjectionReducer,
    ProjectionReplayer,
    ProjectionResult,
)

EvolutionProjection = Projection[Any] | ProjectionReducer[Any]
_UNSET: Final[object] = object()
_SHA256_RE = "0123456789abcdef"


class EvolutionError(RuntimeError):
    """Base error for the evolution control plane."""


class EvolutionTransitionError(EvolutionError):
    """Raised when a run does not permit the requested transition."""


class EvolutionValidationError(EvolutionError, ValueError):
    """Raised when a run, evidence bundle or certificate is invalid."""


class ReplayVerificationError(EvolutionError):
    """Raised when candidate replay is not deterministic or not shadow-only."""


class EvidenceSealingError(EvolutionError):
    """Raised when shadow evidence cannot be safely sealed."""


class CertificateError(EvolutionError):
    """Raised for malformed or untrusted evolution certificates."""


class PromotionError(EvolutionError):
    """Base error for pointer promotion and rollback."""


class PromotionCASConflict(PromotionError):
    """The active pointer changed since the caller read it."""


class PromotionAlreadyUsed(PromotionError):
    """A certificate or manual approval was already consumed."""


class PromotionReceiptError(PromotionError):
    """A receipt is invalid, stale or does not describe the active pointer."""


class ApprovalError(PromotionError):
    """A manual, one-time promotion approval is invalid or expired."""


class EvolutionState(StrEnum):
    """Terminal and in-flight states of an evolution run."""

    PLANNED = "PLANNED"
    FORKED = "FORKED"
    REPLAY_VERIFIED = "REPLAY_VERIFIED"
    EVIDENCE_SEALED = "EVIDENCE_SEALED"
    CERTIFIED = "CERTIFIED"
    PROMOTED = "PROMOTED"
    ROLLED_BACK = "ROLLED_BACK"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    ABORTED = "ABORTED"


# Several callers use "status" terminology; keeping aliases costs no state
# and makes the contract easier to discover without a compatibility shim.
EvolutionRunState = EvolutionState
EvolutionStatus = EvolutionState
RunState = EvolutionState


def _require_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvolutionValidationError(f"{name} must be a non-empty string")
    return value.strip()


def _require_sha256(name: str, value: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return value
    value = _require_text(name, value)
    if value.startswith("sha256:"):
        digest = value[7:]
    else:
        digest = value
    if len(digest) != 64 or any(char not in _SHA256_RE for char in digest):
        raise EvolutionValidationError(f"{name} must be a SHA-256 digest")
    return value


def _canonical(value: object) -> str:
    """Serialize JSON-compatible values in the one canonical form."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest_json(value: object) -> str:
    return _digest_bytes(_canonical(value).encode("utf-8"))


def _encode_b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_b64(value: str) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or any(
            char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-="
            for char in value
        )
    ):
        raise CertificateError("signature is not base64url encoded")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise CertificateError("signature is not base64url encoded") from exc
    if len(decoded) != 64:
        raise CertificateError("Ed25519 signature must decode to 64 bytes")
    return decoded


def _private_key(value: Ed25519PrivateKey | bytes) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    if isinstance(value, bytes):
        try:
            return Ed25519PrivateKey.from_private_bytes(value)
        except ValueError as exc:
            raise CertificateError("Ed25519 private key must be 32 raw bytes") from exc
    raise CertificateError("unsupported Ed25519 private key type")


def _public_key(value: Ed25519PublicKey | bytes) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value
    if isinstance(value, bytes):
        try:
            return Ed25519PublicKey.from_public_bytes(value)
        except ValueError as exc:
            raise CertificateError("Ed25519 public key must be 32 raw bytes") from exc
    raise CertificateError("unsupported Ed25519 public key type")


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EvolutionValidationError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise CertificateError("timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CertificateError("timestamp must be timezone-aware")
    return parsed.astimezone(UTC)


def _address_dict(address: CellAddress) -> dict[str, str]:
    return {
        "tenant_id": address.tenant_id,
        "app_id": address.app_id,
        "cell_id": address.cell_id,
        "session_id": address.session_id,
        "capsule_digest": address.capsule_digest,
        "branch_id": address.branch_id,
    }


def _address_from(value: CellAddress | Mapping[str, object]) -> CellAddress:
    if isinstance(value, CellAddress):
        return value
    if not isinstance(value, Mapping):
        raise EvolutionValidationError("address must be a CellAddress or object")
    try:
        return CellAddress(
            tenant_id=cast(str, value["tenant_id"]),
            app_id=cast(str, value.get("app_id", "default")),
            cell_id=cast(str, value["cell_id"]),
            session_id=cast(str, value["session_id"]),
            capsule_digest=cast(str, value["capsule_digest"]),
            branch_id=cast(str, value.get("branch_id", "main")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise EvolutionValidationError("address fields are invalid") from exc


def _reject_wildcard(address: CellAddress) -> None:
    if any("*" in value or "?" in value for value in address.stream_key):
        raise EvolutionValidationError("v1 promotion scope must be one exact Cell")


def capsule_digest(capsule: AgentCapsule) -> str:
    """Return the declared digest, or the content address when unsigned."""

    if not isinstance(capsule, AgentCapsule):
        raise EvolutionValidationError("capsule must be an AgentCapsule")
    return capsule.digest or capsule.content_digest


@dataclass(frozen=True, slots=True)
class MetricSnapshot:
    """Integer metrics used by the Judge, never raw model/provider output."""

    quality_bps: int
    cost_units: int
    latency_ms: int

    def __post_init__(self) -> None:
        for name in ("quality_bps", "cost_units", "latency_ms"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise EvolutionValidationError(f"{name} must be a non-negative integer")

    def to_dict(self) -> dict[str, int]:
        return {
            "quality_bps": self.quality_bps,
            "cost_units": self.cost_units,
            "latency_ms": self.latency_ms,
        }


@dataclass(frozen=True, slots=True)
class EvaluationObservation:
    """One redacted shadow-evaluation sample.

    ``summary`` is immediately reduced to a digest.  This is intentional:
    callers can provide a human-readable local description, but the evidence
    ledger never stores it and therefore cannot accidentally retain prompts,
    arguments, credentials or provider response bodies.
    """

    sample_id: str
    quality_bps: int
    cost_units: int
    latency_ms: int
    safety_findings: tuple[str, ...] = ()
    baseline_output_hash: str = ""
    candidate_output_hash: str = ""
    summary: str = ""
    baseline_quality_bps: int | None = None
    baseline_cost_units: int | None = None
    baseline_latency_ms: int | None = None

    def __post_init__(self) -> None:
        _require_text("sample_id", self.sample_id)
        MetricSnapshot(self.quality_bps, self.cost_units, self.latency_ms)
        for name in (
            "baseline_quality_bps",
            "baseline_cost_units",
            "baseline_latency_ms",
        ):
            value = getattr(self, name)
            if value is not None:
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise EvolutionValidationError(f"{name} must be a non-negative integer")
        normalized_findings: list[str] = []
        for finding in self.safety_findings:
            normalized_findings.append(_require_text("safety finding", finding))
        if len(set(normalized_findings)) != len(normalized_findings):
            raise EvolutionValidationError("safety findings must be unique")
        object.__setattr__(self, "safety_findings", tuple(sorted(normalized_findings)))
        for name in ("baseline_output_hash", "candidate_output_hash"):
            value = getattr(self, name)
            if not value:
                raise EvolutionValidationError(f"{name} is required")
            _require_sha256(name, value)
        # Preserve no free-form observation text.  A digest is still useful
        # for correlating a local redaction without leaking the text itself.
        # ``from_dict`` may already be loading that digest; retaining it makes
        # serialization round-trips stable.
        summary = self.summary
        if not (
            isinstance(summary, str)
            and summary.startswith("sha256:")
            and len(summary) == 71
            and all(character in _SHA256_RE for character in summary[7:])
        ):
            summary = _digest_json({"summary": summary})
        object.__setattr__(self, "summary", summary)

    @property
    def redacted_summary(self) -> str:
        return self.summary

    @property
    def metrics(self) -> MetricSnapshot:
        return MetricSnapshot(self.quality_bps, self.cost_units, self.latency_ms)

    @property
    def candidate_quality_bps(self) -> int:
        return self.quality_bps

    @property
    def candidate_cost_units(self) -> int:
        return self.cost_units

    @property
    def candidate_latency_ms(self) -> int:
        return self.latency_ms

    def baseline_metrics(self, fallback: MetricSnapshot | None = None) -> MetricSnapshot | None:
        values = (
            self.baseline_quality_bps,
            self.baseline_cost_units,
            self.baseline_latency_ms,
        )
        if all(value is None for value in values):
            return fallback
        if any(value is None for value in values):
            raise EvolutionValidationError(
                f"baseline metrics for sample {self.sample_id!r} are incomplete"
            )
        return MetricSnapshot(cast(int, values[0]), cast(int, values[1]), cast(int, values[2]))

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "sample_id": self.sample_id,
            "quality_bps": self.quality_bps,
            "cost_units": self.cost_units,
            "latency_ms": self.latency_ms,
            "safety_findings": list(self.safety_findings),
            "baseline_output_hash": self.baseline_output_hash,
            "candidate_output_hash": self.candidate_output_hash,
            "summary": self.summary,
        }
        if self.baseline_quality_bps is not None:
            result.update(
                {
                    "baseline_quality_bps": self.baseline_quality_bps,
                    "baseline_cost_units": self.baseline_cost_units,
                    "baseline_latency_ms": self.baseline_latency_ms,
                }
            )
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> EvaluationObservation:
        return cls(
            sample_id=cast(str, value["sample_id"]),
            quality_bps=cast(int, value["quality_bps"]),
            cost_units=cast(int, value["cost_units"]),
            latency_ms=cast(int, value["latency_ms"]),
            safety_findings=tuple(cast(Sequence[str], value.get("safety_findings", ()))),
            baseline_output_hash=cast(str, value.get("baseline_output_hash", "")),
            candidate_output_hash=cast(str, value.get("candidate_output_hash", "")),
            summary=cast(str, value.get("summary", "")),
            baseline_quality_bps=cast(int | None, value.get("baseline_quality_bps")),
            baseline_cost_units=cast(int | None, value.get("baseline_cost_units")),
            baseline_latency_ms=cast(int | None, value.get("baseline_latency_ms")),
        )


# Names used by early design notes and external demo code.
EvidenceObservation = EvaluationObservation
ShadowObservation = EvaluationObservation
EvaluationSample = EvaluationObservation


def merkle_root(observations: Iterable[EvaluationObservation]) -> str:
    """Build a stable SHA-256 Merkle root from observations sorted by sample id."""

    ordered = sorted(tuple(observations), key=lambda item: item.sample_id)
    if len({item.sample_id for item in ordered}) != len(ordered):
        raise EvidenceSealingError("sample ids must be unique before Merkle sealing")
    leaves = [
        hashlib.sha256(b"leaf:v1:" + _canonical(item.to_dict()).encode("utf-8")).digest()
        for item in ordered
    ]
    if not leaves:
        return _digest_bytes(b"merkle:v1:empty")
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves.append(leaves[-1])
        leaves = [
            hashlib.sha256(b"node:v1:" + left + right).digest()
            for left, right in zip(leaves[::2], leaves[1::2], strict=True)
        ]
    return "sha256:" + leaves[0].hex()


evidence_merkle_root = merkle_root
compute_merkle_root = merkle_root


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    """Complete, redacted candidate evidence and its immutable identity."""

    target: CellAddress
    candidate: CellAddress
    dataset_id: str
    runner_id: str
    model_id: str
    policy_digest: str
    tool_manifest_digest: str
    reducer_id: str
    observations: tuple[EvaluationObservation, ...]
    expected_sample_ids: tuple[str, ...] = ()
    baseline_metrics: Mapping[str, MetricSnapshot] = field(default_factory=dict)
    real_provider_calls: int = 0
    simulate_only: bool = True
    sealed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _reject_wildcard(self.target)
        _reject_wildcard(self.candidate)
        if self.target.tenant_id != self.candidate.tenant_id:
            raise NamespaceViolation("evidence target and candidate cross tenants")
        if (
            self.target.app_id,
            self.target.cell_id,
            self.target.session_id,
        ) != (
            self.candidate.app_id,
            self.candidate.cell_id,
            self.candidate.session_id,
        ):
            raise NamespaceViolation("evidence target and candidate are different Cells")
        if self.target.branch_id == self.candidate.branch_id:
            raise EvidenceSealingError("candidate must use a distinct branch")
        if self.candidate.branch_id == "main":
            raise EvidenceSealingError("candidate must not use the main branch")
        for name in (
            "dataset_id",
            "runner_id",
            "model_id",
            "policy_digest",
            "tool_manifest_digest",
            "reducer_id",
        ):
            _require_text(name, getattr(self, name))
        if (
            isinstance(self.real_provider_calls, bool)
            or not isinstance(self.real_provider_calls, int)
            or self.real_provider_calls < 0
        ):
            raise EvidenceSealingError("real_provider_calls must be a non-negative integer")
        if not isinstance(self.simulate_only, bool):
            raise EvidenceSealingError("simulate_only must be boolean")
        observations = tuple(self.observations)
        if any(not isinstance(item, EvaluationObservation) for item in observations):
            raise EvidenceSealingError("observations must be EvaluationObservation values")
        sample_ids = tuple(item.sample_id for item in observations)
        if len(set(sample_ids)) != len(sample_ids):
            raise EvidenceSealingError("sample ids must be unique")
        expected = tuple(self.expected_sample_ids)
        if len(set(expected)) != len(expected):
            raise EvidenceSealingError("expected sample ids must be unique")
        object.__setattr__(self, "observations", observations)
        object.__setattr__(self, "expected_sample_ids", tuple(sorted(expected)))
        normalized_baseline: dict[str, MetricSnapshot] = {}
        for sample_id, metric in self.baseline_metrics.items():
            _require_text("baseline sample id", sample_id)
            if not isinstance(metric, MetricSnapshot):
                if isinstance(metric, Mapping):
                    metric = MetricSnapshot(
                        quality_bps=cast(int, metric["quality_bps"]),
                        cost_units=cast(int, metric["cost_units"]),
                        latency_ms=cast(int, metric["latency_ms"]),
                    )
                else:
                    raise EvidenceSealingError("baseline metrics must be MetricSnapshot values")
            normalized_baseline[sample_id] = metric
        object.__setattr__(self, "baseline_metrics", MappingProxy(normalized_baseline))
        if self.sealed_at.tzinfo is None or self.sealed_at.utcoffset() is None:
            raise EvidenceSealingError("sealed_at must be timezone-aware")

    @property
    def evidence_digest(self) -> str:
        # The sample Merkle root is stable independently of input order.  The
        # outer digest additionally binds the evaluation manifest so an
        # attacker cannot reuse the same sample leaves under another dataset,
        # reducer, target Cell or expected-sample set.
        return _digest_json(
            {
                "version": 1,
                "sample_merkle_root": self.sample_merkle_root,
                "expected_sample_ids": list(self.expected_sample_ids),
                "baseline_metrics": {
                    key: value.to_dict() for key, value in sorted(self.baseline_metrics.items())
                },
                "target": _address_dict(self.target),
                "candidate": _address_dict(self.candidate),
                "dataset_id": self.dataset_id,
                "runner_id": self.runner_id,
                "model_id": self.model_id,
                "policy_digest": self.policy_digest,
                "tool_manifest_digest": self.tool_manifest_digest,
                "reducer_id": self.reducer_id,
                "real_provider_calls": self.real_provider_calls,
                "simulate_only": self.simulate_only,
            }
        )

    @property
    def sample_merkle_root(self) -> str:
        """Stable Merkle root of the redacted samples alone."""

        return merkle_root(self.observations)

    @property
    def sample_count(self) -> int:
        return len(self.observations)

    @property
    def provider_calls(self) -> int:
        return self.real_provider_calls

    def to_dict(self) -> dict[str, object]:
        return {
            "target": _address_dict(self.target),
            "candidate": _address_dict(self.candidate),
            "dataset_id": self.dataset_id,
            "runner_id": self.runner_id,
            "model_id": self.model_id,
            "policy_digest": self.policy_digest,
            "tool_manifest_digest": self.tool_manifest_digest,
            "reducer_id": self.reducer_id,
            "observations": [
                item.to_dict() for item in sorted(self.observations, key=lambda x: x.sample_id)
            ],
            "expected_sample_ids": list(self.expected_sample_ids),
            "baseline_metrics": {
                key: value.to_dict() for key, value in sorted(self.baseline_metrics.items())
            },
            "real_provider_calls": self.real_provider_calls,
            "simulate_only": self.simulate_only,
            "sealed_at": _timestamp(self.sealed_at),
            "evidence_digest": self.evidence_digest,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical(self.to_dict()).encode("utf-8")


class MappingProxy(Mapping[str, MetricSnapshot]):
    """Tiny immutable Mapping wrapper without importing a mutable proxy type."""

    def __init__(self, values: Mapping[str, MetricSnapshot]) -> None:
        self._values = dict(values)

    def __getitem__(self, key: str) -> MetricSnapshot:
        return self._values[key]

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


@dataclass(frozen=True, slots=True, init=False)
class JudgePolicy:
    """Hard safety gates and allowed baseline regressions."""

    max_quality_regression_bps: int
    max_cost_regression_units: int
    max_latency_regression_ms: int
    require_strict_improvement: bool
    high_risk_findings: frozenset[str]
    expected_sample_ids: tuple[str, ...]

    def __init__(
        self,
        max_quality_regression_bps: int = 0,
        max_cost_regression_units: int = 0,
        max_latency_regression_ms: int = 0,
        require_strict_improvement: bool = True,
        high_risk_findings: Iterable[str] = (
            "critical",
            "high",
            "high_risk",
            "critical_security",
        ),
        expected_sample_ids: Iterable[str] = (),
        *,
        quality_regression_bps: int | None = None,
        cost_regression_units: int | None = None,
        latency_regression_ms: int | None = None,
    ) -> None:
        values = (
            quality_regression_bps
            if quality_regression_bps is not None
            else max_quality_regression_bps,
            cost_regression_units
            if cost_regression_units is not None
            else max_cost_regression_units,
            latency_regression_ms
            if latency_regression_ms is not None
            else max_latency_regression_ms,
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values
        ):
            raise EvolutionValidationError("Judge regression bounds must be non-negative integers")
        findings = frozenset(
            _require_text("high-risk finding", value).lower() for value in high_risk_findings
        )
        expected = tuple(
            _require_text("expected sample id", value) for value in expected_sample_ids
        )
        if len(set(expected)) != len(expected):
            raise EvolutionValidationError("Judge expected sample ids must be unique")
        object.__setattr__(self, "max_quality_regression_bps", values[0])
        object.__setattr__(self, "max_cost_regression_units", values[1])
        object.__setattr__(self, "max_latency_regression_ms", values[2])
        object.__setattr__(self, "require_strict_improvement", bool(require_strict_improvement))
        object.__setattr__(self, "high_risk_findings", findings)
        object.__setattr__(self, "expected_sample_ids", tuple(sorted(expected)))

    @property
    def quality_regression_bps(self) -> int:
        return self.max_quality_regression_bps

    @property
    def cost_regression_units(self) -> int:
        return self.max_cost_regression_units

    @property
    def latency_regression_ms(self) -> int:
        return self.max_latency_regression_ms

    def to_dict(self) -> dict[str, object]:
        return {
            "max_quality_regression_bps": self.max_quality_regression_bps,
            "max_cost_regression_units": self.max_cost_regression_units,
            "max_latency_regression_ms": self.max_latency_regression_ms,
            "require_strict_improvement": self.require_strict_improvement,
            "high_risk_findings": sorted(self.high_risk_findings),
            "expected_sample_ids": list(self.expected_sample_ids),
        }


EvolutionPolicy = JudgePolicy


@dataclass(frozen=True, slots=True)
class JudgeDecision:
    """Explainable outcome of all Judge hard gates and Pareto checks."""

    accepted: bool
    reasons: tuple[str, ...] = ()
    strict_improvements: tuple[str, ...] = ()
    checks: Mapping[str, bool] = field(default_factory=dict)
    evidence_digest: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "reasons", tuple(self.reasons))
        object.__setattr__(self, "strict_improvements", tuple(self.strict_improvements))
        object.__setattr__(self, "checks", MappingProxyBool(self.checks))
        if self.evidence_digest:
            _require_sha256("evidence_digest", self.evidence_digest)

    @property
    def passed(self) -> bool:
        return self.accepted

    @property
    def ok(self) -> bool:
        return self.accepted

    def to_dict(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "reasons": list(self.reasons),
            "strict_improvements": list(self.strict_improvements),
            "checks": {key: self.checks[key] for key in sorted(self.checks)},
            "evidence_digest": self.evidence_digest,
        }


class MappingProxyBool(Mapping[str, bool]):
    def __init__(self, values: Mapping[str, bool]) -> None:
        self._values = {str(key): bool(value) for key, value in values.items()}

    def __getitem__(self, key: str) -> bool:
        return self._values[key]

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


class EvolutionJudge:
    """Evaluate evidence using hard gates followed by Pareto improvement."""

    def evaluate(
        self,
        bundle: EvidenceBundle,
        policy: JudgePolicy | None = None,
    ) -> JudgeDecision:
        if not isinstance(bundle, EvidenceBundle):
            raise EvolutionValidationError("Judge bundle must be an EvidenceBundle")
        policy = policy or JudgePolicy()
        reasons: list[str] = []
        checks: dict[str, bool] = {}
        observed_ids = {item.sample_id for item in bundle.observations}
        expected_ids = set(policy.expected_sample_ids or bundle.expected_sample_ids)
        complete = bool(expected_ids) and observed_ids == expected_ids
        checks["samples_complete"] = complete
        if not complete:
            reasons.append("samples_incomplete")

        high_risk: list[str] = []
        for item in bundle.observations:
            for finding in item.safety_findings:
                normalized = finding.lower()
                if normalized in policy.high_risk_findings or normalized.startswith("critical"):
                    high_risk.append(finding)
        checks["no_high_risk_safety_findings"] = not high_risk
        if high_risk:
            reasons.append("high_risk_safety_finding")

        no_real_effects = bundle.simulate_only and bundle.real_provider_calls == 0
        checks["no_real_side_effects"] = no_real_effects
        if not no_real_effects:
            reasons.append("candidate_real_side_effects")

        strict_improvements: set[str] = set()
        regressions_ok = True
        compared = False
        baselines_complete = True
        for item in bundle.observations:
            fallback = bundle.baseline_metrics.get(item.sample_id)
            baseline = item.baseline_metrics(fallback)
            if baseline is None:
                baselines_complete = False
                continue
            compared = True
            quality_delta = item.quality_bps - baseline.quality_bps
            cost_delta = item.cost_units - baseline.cost_units
            latency_delta = item.latency_ms - baseline.latency_ms
            if quality_delta < -policy.max_quality_regression_bps:
                regressions_ok = False
            if cost_delta > policy.max_cost_regression_units:
                regressions_ok = False
            if latency_delta > policy.max_latency_regression_ms:
                regressions_ok = False
            if quality_delta > 0:
                strict_improvements.add("quality")
            if cost_delta < 0:
                strict_improvements.add("cost")
            if latency_delta < 0:
                strict_improvements.add("latency")
        checks["baseline_metrics_complete"] = baselines_complete
        if not baselines_complete:
            reasons.append("baseline_metrics_incomplete")
        checks["regressions_within_policy"] = regressions_ok
        if not regressions_ok:
            reasons.append("policy_regression_exceeded")
        strict_ok = bool(strict_improvements) if policy.require_strict_improvement else True
        # If a bundle has no explicit baseline, the sample itself is still a
        # valid shadow record but cannot claim Pareto improvement.
        if policy.require_strict_improvement and not compared:
            strict_ok = False
        checks["strict_improvement"] = strict_ok
        if not strict_ok:
            reasons.append("no_strict_improvement")

        accepted = (
            not reasons
            and complete
            and not high_risk
            and no_real_effects
            and baselines_complete
            and regressions_ok
            and strict_ok
        )
        return JudgeDecision(
            accepted=accepted,
            reasons=tuple(reasons),
            strict_improvements=tuple(sorted(strict_improvements)),
            checks=checks,
            evidence_digest=bundle.evidence_digest,
        )


@dataclass(frozen=True, slots=True)
class EvolutionCertificate:
    """Signed canonical proof that a candidate passed offline evaluation."""

    certificate_id: str
    source_address: CellAddress
    candidate_address: CellAddress
    source_capsule_digest: str
    candidate_capsule_digest: str
    fork_sequence: int
    fork_hash: str
    source_head_hash: str
    candidate_head_hash: str
    dataset_id: str
    runner_id: str
    model_id: str
    policy_digest: str
    tool_manifest_digest: str
    reducer_id: str
    evidence_digest: str
    judge_policy: Mapping[str, object]
    expected_active_capsule: str
    control_version: int
    signing_key_id: str
    issued_at: datetime
    expires_at: datetime
    signature: str = ""
    signature_algorithm: str = "ed25519"
    schema_version: int = 1

    def __post_init__(self) -> None:
        _require_text("certificate_id", self.certificate_id)
        _reject_wildcard(self.source_address)
        _reject_wildcard(self.candidate_address)
        if self.source_address.tenant_id != self.candidate_address.tenant_id:
            raise NamespaceViolation("certificate source and candidate cross tenants")
        if (
            self.source_address.app_id,
            self.source_address.cell_id,
            self.source_address.session_id,
        ) != (
            self.candidate_address.app_id,
            self.candidate_address.cell_id,
            self.candidate_address.session_id,
        ):
            raise NamespaceViolation("certificate source and candidate are different Cells")
        if self.source_address.branch_id != "main":
            raise CertificateError("v1 certificate source must be the main branch")
        if self.candidate_address.branch_id == "main":
            raise CertificateError("v1 certificate candidate must be a fork branch")
        if self.source_capsule_digest != self.source_address.capsule_digest:
            raise CertificateError("source capsule digest does not match source address")
        if self.candidate_capsule_digest != self.candidate_address.capsule_digest:
            raise CertificateError("candidate capsule digest does not match candidate address")
        for name in (
            "source_capsule_digest",
            "candidate_capsule_digest",
            "fork_hash",
            "source_head_hash",
            "candidate_head_hash",
            "evidence_digest",
            "expected_active_capsule",
        ):
            _require_sha256(name, getattr(self, name))
        if (
            isinstance(self.fork_sequence, bool)
            or not isinstance(self.fork_sequence, int)
            or self.fork_sequence < 0
        ):
            raise CertificateError("fork_sequence must be a non-negative integer")
        if (
            isinstance(self.control_version, bool)
            or not isinstance(self.control_version, int)
            or self.control_version < 0
        ):
            raise CertificateError("control_version must be a non-negative integer")
        for name in (
            "dataset_id",
            "runner_id",
            "model_id",
            "policy_digest",
            "tool_manifest_digest",
            "reducer_id",
            "signing_key_id",
        ):
            _require_text(name, getattr(self, name))
        if self.signature_algorithm != "ed25519":
            raise CertificateError("only Ed25519 certificate signatures are supported")
        if self.schema_version != 1:
            raise CertificateError("unsupported certificate schema version")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise CertificateError("certificate timestamps must be timezone-aware")
        # A verifier must be able to inspect an already-expired certificate
        # and return a structured rejection.  Issuance itself always creates
        # a future expiry; retaining malformed/expired records is useful for
        # audit and tamper tests.
        if self.signature:
            _decode_b64(self.signature)
        object.__setattr__(self, "judge_policy", MappingProxyObject(self.judge_policy))

    @property
    def tenant_id(self) -> str:
        return self.source_address.tenant_id

    @property
    def source_capsule(self) -> str:
        return self.source_capsule_digest

    @property
    def candidate_capsule(self) -> str:
        return self.candidate_capsule_digest

    @property
    def digest(self) -> str:
        return _digest_bytes(self.signing_bytes())

    @property
    def certificate_digest(self) -> str:
        return self.digest

    @property
    def expired(self) -> bool:
        return self.is_expired()

    def is_expired(self, *, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        return self.expires_at.astimezone(UTC) <= current.astimezone(UTC)

    def unsigned_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "certificate_id": self.certificate_id,
            "source_address": _address_dict(self.source_address),
            "candidate_address": _address_dict(self.candidate_address),
            "source_capsule_digest": self.source_capsule_digest,
            "candidate_capsule_digest": self.candidate_capsule_digest,
            "fork_sequence": self.fork_sequence,
            "fork_hash": self.fork_hash,
            "source_head_hash": self.source_head_hash,
            "candidate_head_hash": self.candidate_head_hash,
            "dataset_id": self.dataset_id,
            "runner_id": self.runner_id,
            "model_id": self.model_id,
            "policy_digest": self.policy_digest,
            "tool_manifest_digest": self.tool_manifest_digest,
            "reducer_id": self.reducer_id,
            "evidence_digest": self.evidence_digest,
            "judge_policy": dict(self.judge_policy),
            "expected_active_capsule": self.expected_active_capsule,
            "control_version": self.control_version,
            "signing_key_id": self.signing_key_id,
            "issued_at": _timestamp(self.issued_at),
            "expires_at": _timestamp(self.expires_at),
            "signature_algorithm": self.signature_algorithm,
        }

    def to_dict(self, *, include_signature: bool = True) -> dict[str, object]:
        value = self.unsigned_dict()
        if include_signature:
            value["signature"] = self.signature
        return value

    def canonical_json(self) -> str:
        return _canonical(self.unsigned_dict())

    def signing_bytes(self) -> bytes:
        return self.canonical_json().encode("utf-8")

    def verify_signature(self, trusted_keys: Mapping[str, Ed25519PublicKey | bytes]) -> None:
        if not self.signature:
            raise CertificateError("certificate signature is required")
        if self.signing_key_id not in trusted_keys:
            raise CertificateError("certificate signing key is not trusted")
        try:
            _public_key(trusted_keys[self.signing_key_id]).verify(
                _decode_b64(self.signature), self.signing_bytes()
            )
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise CertificateError("certificate signature is invalid") from exc

    def with_signature(self, private_key: Ed25519PrivateKey | bytes) -> EvolutionCertificate:
        signature = _encode_b64(_private_key(private_key).sign(self.signing_bytes()))
        return replace(self, signature=signature)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> EvolutionCertificate:
        try:
            return cls(
                certificate_id=cast(str, value["certificate_id"]),
                source_address=_address_from(cast(Mapping[str, object], value["source_address"])),
                candidate_address=_address_from(
                    cast(Mapping[str, object], value["candidate_address"])
                ),
                source_capsule_digest=cast(str, value["source_capsule_digest"]),
                candidate_capsule_digest=cast(str, value["candidate_capsule_digest"]),
                fork_sequence=cast(int, value["fork_sequence"]),
                fork_hash=cast(str, value["fork_hash"]),
                source_head_hash=cast(str, value["source_head_hash"]),
                candidate_head_hash=cast(str, value["candidate_head_hash"]),
                dataset_id=cast(str, value["dataset_id"]),
                runner_id=cast(str, value["runner_id"]),
                model_id=cast(str, value["model_id"]),
                policy_digest=cast(str, value["policy_digest"]),
                tool_manifest_digest=cast(str, value["tool_manifest_digest"]),
                reducer_id=cast(str, value["reducer_id"]),
                evidence_digest=cast(str, value["evidence_digest"]),
                judge_policy=cast(Mapping[str, object], value["judge_policy"]),
                expected_active_capsule=cast(str, value["expected_active_capsule"]),
                control_version=cast(int, value["control_version"]),
                signing_key_id=cast(str, value["signing_key_id"]),
                issued_at=_parse_timestamp(cast(str, value["issued_at"])),
                expires_at=_parse_timestamp(cast(str, value["expires_at"])),
                signature=cast(str, value.get("signature", "")),
                signature_algorithm=cast(str, value.get("signature_algorithm", "ed25519")),
                schema_version=cast(int, value.get("schema_version", 1)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, CertificateError):
                raise
            raise CertificateError("certificate fields are invalid") from exc


class MappingProxyObject(Mapping[str, object]):
    def __init__(self, values: Mapping[str, object]) -> None:
        self._values = copy.deepcopy(dict(values))

    def __getitem__(self, key: str) -> object:
        return self._values[key]

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


@dataclass(frozen=True, slots=True)
class PromotionTarget:
    """Exact Cell pointer and optimistic-concurrency version."""

    address: CellAddress
    active_capsule_digest: str
    control_version: int = 0

    def __post_init__(self) -> None:
        _reject_wildcard(self.address)
        if self.address.branch_id != "main":
            raise PromotionError("promotion target must identify the main branch")
        _require_sha256("active_capsule_digest", self.active_capsule_digest)
        if (
            isinstance(self.control_version, bool)
            or not isinstance(self.control_version, int)
            or self.control_version < 0
        ):
            raise PromotionError("control_version must be a non-negative integer")

    @property
    def tenant_id(self) -> str:
        return self.address.tenant_id

    @property
    def app_id(self) -> str:
        return self.address.app_id

    @property
    def cell_id(self) -> str:
        return self.address.cell_id

    @property
    def session_id(self) -> str:
        return self.address.session_id

    @property
    def expected_active_capsule(self) -> str:
        return self.active_capsule_digest

    def to_dict(self) -> dict[str, object]:
        return {
            "address": _address_dict(self.address),
            "active_capsule_digest": self.active_capsule_digest,
            "control_version": self.control_version,
        }


@dataclass(frozen=True, slots=True)
class VerificationResult:
    valid: bool
    reason: str = ""
    certificate_id: str = ""
    checks: Mapping[str, bool] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.valid

    @property
    def accepted(self) -> bool:
        return self.valid

    def __bool__(self) -> bool:
        return self.valid


class CertificateVerifier:
    """Verify signatures, scope, expiry and expected pointer preconditions."""

    def __init__(
        self,
        trusted_keys: Mapping[str, Ed25519PublicKey | bytes] | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.trusted_keys = dict(trusted_keys or {})
        self.clock = clock or (lambda: datetime.now(UTC))

    def verify(
        self,
        certificate: EvolutionCertificate,
        target: PromotionTarget | CellAddress | Mapping[str, object],
    ) -> VerificationResult:
        checks: dict[str, bool] = {}
        try:
            if not isinstance(certificate, EvolutionCertificate):
                raise CertificateError("certificate type is invalid")
            target_obj = self._target(target, certificate)
            checks["signature"] = False
            certificate.verify_signature(self.trusted_keys)
            checks["signature"] = True
            now = self.clock()
            if certificate.is_expired(now=now):
                raise CertificateError("certificate is expired")
            checks["not_expired"] = True
            if certificate.source_address != target_obj.address:
                raise NamespaceViolation("certificate source does not match promotion target")
            checks["exact_cell_scope"] = True
            if certificate.expected_active_capsule != target_obj.active_capsule_digest:
                raise CertificateError("certificate expected active Capsule is stale")
            checks["expected_active_capsule"] = True
            if certificate.control_version != target_obj.control_version:
                raise CertificateError("certificate control version is stale")
            checks["control_version"] = True
            return VerificationResult(
                valid=True,
                certificate_id=certificate.certificate_id,
                checks=checks,
            )
        except (CertificateError, EvolutionError, NamespaceViolation, TypeError, ValueError) as exc:
            return VerificationResult(
                valid=False,
                reason=str(exc),
                certificate_id=getattr(certificate, "certificate_id", ""),
                checks=checks,
            )

    @staticmethod
    def _target(
        target: PromotionTarget | CellAddress | Mapping[str, object],
        certificate: EvolutionCertificate,
    ) -> PromotionTarget:
        if isinstance(target, PromotionTarget):
            return target
        if isinstance(target, CellAddress):
            return PromotionTarget(
                address=target,
                active_capsule_digest=certificate.expected_active_capsule,
                control_version=certificate.control_version,
            )
        if isinstance(target, Mapping):
            if "address" in target:
                address = _address_from(cast(Mapping[str, object], target["address"]))
            else:
                address = _address_from(target)
            active = cast(
                str,
                target.get(
                    "active_capsule_digest",
                    target.get("expected_active_capsule", certificate.expected_active_capsule),
                ),
            )
            version = cast(int, target.get("control_version", certificate.control_version))
            return PromotionTarget(
                address=address, active_capsule_digest=active, control_version=version
            )
        raise CertificateError("promotion target is invalid")


@dataclass(frozen=True, slots=True)
class PromotionApproval:
    """One-time HMAC-bound manual approval credential."""

    approval_id: str
    certificate_id: str
    certificate_digest: str
    target: PromotionTarget
    approved_by: str
    issued_at: datetime
    expires_at: datetime
    mac: str

    @property
    def token(self) -> str:
        return self.mac

    @property
    def credential(self) -> str:
        return self.mac

    def unsigned_dict(self) -> dict[str, object]:
        return {
            "approval_id": self.approval_id,
            "certificate_id": self.certificate_id,
            "certificate_digest": self.certificate_digest,
            "target": self.target.to_dict(),
            "approved_by": self.approved_by,
            "issued_at": _timestamp(self.issued_at),
            "expires_at": _timestamp(self.expires_at),
        }


class PromotionApprovalAuthority:
    """Issue and atomically consume one manual approval per certificate."""

    def __init__(
        self, secret: bytes | None = None, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        self._secret = secret or hashlib.sha256(uuid.uuid4().bytes).digest()
        if not self._secret:
            raise ApprovalError("approval secret cannot be empty")
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self._consumed: set[str] = set()

    def issue(
        self,
        certificate: EvolutionCertificate | None = None,
        target: PromotionTarget | CellAddress | Mapping[str, object] | None = None,
        *,
        approved_by: str,
        ttl_seconds: int = 300,
        approval_id: str | None = None,
        tenant_id: str | None = None,
        certificate_id: str | None = None,
        certificate_digest: str | None = None,
    ) -> PromotionApproval:
        if not approved_by.strip():
            raise ApprovalError("approved_by is required")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise ApprovalError("approval TTL must be positive")
        if certificate is None:
            if target is None or certificate_id is None or certificate_digest is None:
                raise ApprovalError("certificate and target are required for an approval")
            target_obj = self._coerce_target(target, certificate_digest=certificate_digest)
            cert_id = certificate_id
            cert_digest = certificate_digest
            if tenant_id is not None and target_obj.tenant_id != tenant_id:
                raise NamespaceViolation("approval tenant does not match target")
        else:
            if target is None:
                target_obj = PromotionTarget(
                    address=certificate.source_address,
                    active_capsule_digest=certificate.expected_active_capsule,
                    control_version=certificate.control_version,
                )
            else:
                target_obj = self._coerce_target(target, certificate=certificate)
            cert_id = certificate.certificate_id
            cert_digest = certificate.digest
            if tenant_id is not None and target_obj.tenant_id != tenant_id:
                raise NamespaceViolation("approval tenant does not match target")
        now = self._clock().astimezone(UTC)
        expires = now + timedelta(seconds=ttl_seconds)
        approval = PromotionApproval(
            approval_id=approval_id or str(uuid.uuid4()),
            certificate_id=cert_id,
            certificate_digest=cert_digest,
            target=target_obj,
            approved_by=approved_by.strip(),
            issued_at=now,
            expires_at=expires,
            mac="",
        )
        mac = _encode_b64(
            hmac.new(
                self._secret, _canonical(approval.unsigned_dict()).encode("utf-8"), hashlib.sha256
            ).digest()
        )
        return replace(approval, mac=mac)

    def verify_and_consume(
        self,
        approval: PromotionApproval,
        certificate: EvolutionCertificate,
        target: PromotionTarget | CellAddress | Mapping[str, object],
    ) -> bool:
        if not isinstance(approval, PromotionApproval):
            raise ApprovalError("approval credential is invalid")
        if not isinstance(certificate, EvolutionCertificate):
            raise ApprovalError("certificate is invalid")
        target_obj = CertificateVerifier._target(target, certificate)
        with self._lock:
            if approval.approval_id in self._consumed:
                raise PromotionAlreadyUsed("manual approval was already consumed")
            if approval.expires_at <= self._clock().astimezone(UTC):
                raise ApprovalError("manual approval is expired")
            expected_mac = _encode_b64(
                hmac.new(
                    self._secret,
                    _canonical(approval.unsigned_dict()).encode("utf-8"),
                    hashlib.sha256,
                ).digest()
            )
            if not hmac.compare_digest(expected_mac, approval.mac):
                raise ApprovalError("manual approval signature is invalid")
            if (
                approval.certificate_id != certificate.certificate_id
                or approval.certificate_digest != certificate.digest
                or approval.target != target_obj
            ):
                raise NamespaceViolation("manual approval is not scoped to this certificate")
            self._consumed.add(approval.approval_id)
            return True

    consume = verify_and_consume

    @staticmethod
    def _coerce_target(
        target: PromotionTarget | CellAddress | Mapping[str, object],
        *,
        certificate: EvolutionCertificate | None = None,
        certificate_digest: str | None = None,
    ) -> PromotionTarget:
        if isinstance(target, PromotionTarget):
            return target
        if isinstance(target, CellAddress):
            return PromotionTarget(
                address=target,
                active_capsule_digest=(
                    certificate.expected_active_capsule
                    if certificate is not None
                    else cast(str, certificate_digest)
                ),
                control_version=certificate.control_version if certificate is not None else 0,
            )
        if not isinstance(target, Mapping):
            raise ApprovalError("approval target is invalid")
        address_value = target.get("address", target)
        address = _address_from(cast(Mapping[str, object], address_value))
        active = target.get("active_capsule_digest", target.get("expected_active_capsule"))
        version = target.get("control_version", 0)
        if active is None and certificate is not None:
            active = certificate.expected_active_capsule
        if active is None:
            raise ApprovalError("approval target active Capsule is required")
        if not isinstance(version, int):
            raise ApprovalError("approval target control version is invalid")
        return PromotionTarget(
            address=address, active_capsule_digest=cast(str, active), control_version=version
        )


@dataclass(frozen=True, slots=True)
class PromotionReceipt:
    """Signed proof of one pointer transition."""

    receipt_id: str
    certificate_id: str
    target: PromotionTarget
    previous_active_capsule: str
    active_capsule: str
    previous_control_version: int
    control_version: int
    issued_at: datetime
    signing_key_id: str
    signature: str = ""
    operation: str = "promote"
    rollback_of: str | None = None

    def __post_init__(self) -> None:
        _require_text("receipt_id", self.receipt_id)
        _require_text("certificate_id", self.certificate_id)
        _require_sha256("previous_active_capsule", self.previous_active_capsule)
        _require_sha256("active_capsule", self.active_capsule)
        if self.previous_control_version < 0 or self.control_version < 0:
            raise PromotionReceiptError("receipt control versions must be non-negative")
        if self.control_version <= self.previous_control_version:
            raise PromotionReceiptError("receipt control version must advance monotonically")
        if self.operation not in {"promote", "rollback"}:
            raise PromotionReceiptError("unsupported receipt operation")
        _require_text("signing_key_id", self.signing_key_id)
        if self.issued_at.tzinfo is None or self.issued_at.utcoffset() is None:
            raise PromotionReceiptError("receipt timestamp must be timezone-aware")
        if self.signature:
            _decode_b64(self.signature)

    def unsigned_dict(self) -> dict[str, object]:
        return {
            "receipt_id": self.receipt_id,
            "certificate_id": self.certificate_id,
            "target": self.target.to_dict(),
            "previous_active_capsule": self.previous_active_capsule,
            "active_capsule": self.active_capsule,
            "previous_control_version": self.previous_control_version,
            "control_version": self.control_version,
            "issued_at": _timestamp(self.issued_at),
            "signing_key_id": self.signing_key_id,
            "operation": self.operation,
            "rollback_of": self.rollback_of,
        }

    def canonical_json(self) -> str:
        return _canonical(self.unsigned_dict())

    def signing_bytes(self) -> bytes:
        return self.canonical_json().encode("utf-8")

    @property
    def digest(self) -> str:
        return _digest_bytes(self.signing_bytes())


@dataclass(frozen=True, slots=True)
class PromotionPointer:
    target: PromotionTarget
    updated_at: datetime
    last_certificate_id: str = ""


class PromotionStore:
    """Thread-safe in-memory pointer/CAS/outbox reference implementation."""

    def __init__(
        self,
        initial: Iterable[PromotionTarget] | Mapping[object, PromotionTarget] | None = None,
        *,
        receipt_signing_key: Ed25519PrivateKey | bytes | None = None,
        receipt_key_id: str = "promotion-store",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._receipt_key = (
            _private_key(receipt_signing_key)
            if receipt_signing_key is not None
            else Ed25519PrivateKey.generate()
        )
        self.receipt_key_id = _require_text("receipt_key_id", receipt_key_id)
        self._pointers: dict[tuple[str, str, str, str], PromotionPointer] = {}
        self._used_certificates: set[str] = set()
        self._outbox: dict[str, PromotionReceipt] = {}
        if initial is not None:
            values = initial.values() if isinstance(initial, Mapping) else initial
            for target in values:
                self._pointers[self._key(target.address)] = PromotionPointer(
                    target=target,
                    updated_at=self._clock().astimezone(UTC),
                )

    @property
    def receipt_public_key(self) -> Ed25519PublicKey:
        return self._receipt_key.public_key()

    @staticmethod
    def _key(address: CellAddress) -> tuple[str, str, str, str]:
        _reject_wildcard(address)
        if address.branch_id != "main":
            raise PromotionError("pointer key must identify an exact main Cell")
        return address.tenant_id, address.app_id, address.cell_id, address.session_id

    def get(self, target: PromotionTarget | CellAddress) -> PromotionTarget | None:
        address = target.address if isinstance(target, PromotionTarget) else target
        with self._lock:
            pointer = self._pointers.get(self._key(address))
            return pointer.target if pointer is not None else None

    current = get

    def compare_and_swap(
        self,
        target: PromotionTarget | CellAddress,
        expected_active_capsule: str | None = None,
        new_active_capsule: str | None = None,
        *,
        expected_control_version: int | None = None,
        control_version: int | None = None,
        certificate: EvolutionCertificate | None = None,
        approval_consumed: bool = False,
    ) -> PromotionReceipt:
        target_obj = target if isinstance(target, PromotionTarget) else None
        address = target_obj.address if target_obj is not None else cast(CellAddress, target)
        key = self._key(address)
        with self._lock:
            pointer = self._pointers.get(key)
            if pointer is None:
                if target_obj is None:
                    raise PromotionCASConflict("pointer is not initialized")
                # Treat a caller-supplied target as the expected initial
                # value, but do not persist it until every certificate and
                # CAS guard has passed.  A rejected attempt must be entirely
                # non-mutating.
                pointer = None
            current = pointer.target if pointer is not None else cast(PromotionTarget, target_obj)
            expected_digest = expected_active_capsule or (
                target_obj.active_capsule_digest
                if target_obj is not None
                else current.active_capsule_digest
            )
            expected_version = (
                expected_control_version
                if expected_control_version is not None
                else (
                    target_obj.control_version
                    if target_obj is not None
                    else current.control_version
                )
            )
            next_digest = new_active_capsule
            if certificate is not None:
                if next_digest is None:
                    next_digest = certificate.candidate_capsule_digest
                if certificate.source_address != current.address:
                    raise NamespaceViolation("certificate source does not match pointer Cell")
                if certificate.candidate_capsule_digest != next_digest:
                    raise PromotionError("certificate candidate does not match new pointer")
                if certificate.expected_active_capsule != expected_digest:
                    raise PromotionCASConflict("certificate expected active Capsule is stale")
                if certificate.control_version != expected_version:
                    raise PromotionCASConflict("certificate control version is stale")
                if certificate.certificate_id in self._used_certificates:
                    raise PromotionAlreadyUsed("certificate was already consumed")
                if not approval_consumed:
                    raise ApprovalError("promotion requires a consumed manual approval")
            if next_digest is None:
                raise PromotionError("new active Capsule is required")
            _require_sha256("new_active_capsule", next_digest)
            if (
                current.active_capsule_digest != expected_digest
                or current.control_version != expected_version
            ):
                raise PromotionCASConflict("active pointer changed before CAS")
            next_version = control_version if control_version is not None else expected_version + 1
            if next_version <= expected_version:
                raise PromotionCASConflict("new control version must advance")
            next_target = PromotionTarget(
                address=current.address,
                active_capsule_digest=next_digest,
                control_version=next_version,
            )
            now = self._clock().astimezone(UTC)
            receipt = PromotionReceipt(
                receipt_id=str(uuid.uuid4()),
                certificate_id=certificate.certificate_id
                if certificate is not None
                else "manual-cas",
                target=current,
                previous_active_capsule=current.active_capsule_digest,
                active_capsule=next_digest,
                previous_control_version=expected_version,
                control_version=next_version,
                issued_at=now,
                signing_key_id=self.receipt_key_id,
            )
            receipt = replace(
                receipt, signature=_encode_b64(self._receipt_key.sign(receipt.signing_bytes()))
            )
            self._pointers[key] = PromotionPointer(
                target=next_target,
                updated_at=now,
                last_certificate_id=receipt.certificate_id,
            )
            if certificate is not None:
                self._used_certificates.add(certificate.certificate_id)
            self._outbox[receipt.receipt_id] = receipt
            return receipt

    def rollback(
        self,
        receipt: PromotionReceipt,
        *,
        expected_active_capsule: str | None = None,
        expected_control_version: int | None = None,
    ) -> PromotionReceipt:
        if not isinstance(receipt, PromotionReceipt):
            raise PromotionReceiptError("promotion receipt is invalid")
        if receipt.operation != "promote" or receipt.rollback_of is not None:
            raise PromotionReceiptError("only a promotion receipt can authorize rollback")
        with self._lock:
            self._verify_receipt(receipt)
            key = self._key(receipt.target.address)
            pointer = self._pointers.get(key)
            if pointer is None:
                raise PromotionReceiptError("promotion pointer does not exist")
            current = pointer.target
            if current.active_capsule_digest != receipt.active_capsule:
                raise PromotionCASConflict("active Capsule no longer matches promotion receipt")
            if current.control_version != receipt.control_version:
                raise PromotionCASConflict("control version no longer matches promotion receipt")
            if (
                expected_active_capsule is not None
                and current.active_capsule_digest != expected_active_capsule
            ):
                raise PromotionCASConflict("caller supplied a stale active Capsule")
            if (
                expected_control_version is not None
                and current.control_version != expected_control_version
            ):
                raise PromotionCASConflict("caller supplied a stale control version")
            now = self._clock().astimezone(UTC)
            rollback_target = PromotionTarget(
                address=current.address,
                active_capsule_digest=receipt.previous_active_capsule,
                # Rollback is a fresh pointer mutation.  Keeping the version
                # monotonic prevents ABA: an old certificate must not become
                # valid again merely because its Capsule was restored.
                control_version=current.control_version + 1,
            )
            rollback_receipt = PromotionReceipt(
                receipt_id=str(uuid.uuid4()),
                certificate_id=receipt.certificate_id,
                target=current,
                previous_active_capsule=current.active_capsule_digest,
                active_capsule=receipt.previous_active_capsule,
                previous_control_version=current.control_version,
                control_version=current.control_version + 1,
                issued_at=now,
                signing_key_id=self.receipt_key_id,
                operation="rollback",
                rollback_of=receipt.receipt_id,
            )
            rollback_receipt = replace(
                rollback_receipt,
                signature=_encode_b64(self._receipt_key.sign(rollback_receipt.signing_bytes())),
            )
            self._pointers[key] = PromotionPointer(
                target=rollback_target,
                updated_at=now,
                last_certificate_id=receipt.certificate_id,
            )
            self._outbox[rollback_receipt.receipt_id] = rollback_receipt
            return rollback_receipt

    def pending_outbox(self) -> tuple[PromotionReceipt, ...]:
        with self._lock:
            return tuple(self._outbox.values())

    def acknowledge(self, receipt_id: str) -> None:
        with self._lock:
            self._outbox.pop(receipt_id, None)

    def reconcile(self, publisher: Callable[[PromotionReceipt], object]) -> tuple[str, ...]:
        """Publish pending receipts and remove acknowledged outbox entries.

        A crash between publisher success and ``acknowledge`` can cause a
        retry, so the publisher must deduplicate by ``receipt_id``.
        """

        published: list[str] = []
        for receipt in self.pending_outbox():
            publisher(receipt)
            self.acknowledge(receipt.receipt_id)
            published.append(receipt.receipt_id)
        return tuple(published)

    def _verify_receipt(self, receipt: PromotionReceipt) -> None:
        if receipt.signing_key_id != self.receipt_key_id or not receipt.signature:
            raise PromotionReceiptError("promotion receipt signing identity is invalid")
        try:
            self.receipt_public_key.verify(_decode_b64(receipt.signature), receipt.signing_bytes())
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise PromotionReceiptError("promotion receipt signature is invalid") from exc


@dataclass(frozen=True, slots=True)
class EvolutionRun:
    run_id: str
    source_address: CellAddress
    source_capsule_digest: str
    candidate_capsule_digest: str
    fork_sequence: int
    fork_hash: str | None
    dataset_id: str
    runner_id: str
    model_id: str
    policy_digest: str
    tool_manifest_digest: str
    reducer_id: str
    expected_active_capsule: str
    control_version: int
    created_at: datetime
    expires_at: datetime
    state: EvolutionState = EvolutionState.PLANNED
    candidate_address: CellAddress | None = None
    source_head_hash: str = ""
    candidate_head_hash: str = ""
    candidate_state_hash: str = ""
    evidence: EvidenceBundle | None = None
    decision: JudgeDecision | None = None
    certificate: EvolutionCertificate | None = None
    promotion_receipt: PromotionReceipt | None = None
    rejection_reason: str = ""

    @property
    def status(self) -> EvolutionState:
        return self.state

    @property
    def tenant_id(self) -> str:
        return self.source_address.tenant_id

    @property
    def source_capsule(self) -> str:
        return self.source_capsule_digest

    @property
    def candidate_capsule(self) -> str:
        return self.candidate_capsule_digest


class EvolutionCoordinator:
    """Drive the fork → replay → evidence → certificate protocol."""

    def __init__(
        self,
        event_store: EventStore,
        *,
        judge: EvolutionJudge | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = event_store
        self.judge = judge or EvolutionJudge()
        self.clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self._runs: dict[str, EvolutionRun] = {}

    def create_run(
        self,
        source_address: CellAddress,
        *,
        source_capsule: AgentCapsule | None = None,
        candidate_capsule: AgentCapsule | None = None,
        fork_sequence: int = 0,
        fork_hash: str | None = None,
        dataset_id: str = "",
        runner_id: str = "",
        model_id: str = "",
        policy_digest: str = "",
        tool_manifest_digest: str = "",
        reducer_id: str = "",
        expected_active_capsule: str | None = None,
        control_version: int = 0,
        run_id: str | None = None,
        ttl_seconds: int = 3600,
        expires_at: datetime | None = None,
    ) -> EvolutionRun:
        _reject_wildcard(source_address)
        if source_address.branch_id != "main":
            raise EvolutionValidationError("evolution source must be the main branch")
        if fork_sequence < 0:
            raise EvolutionValidationError("fork_sequence cannot be negative")
        if candidate_capsule is None:
            raise EvolutionValidationError("candidate_capsule is required")
        if (
            source_capsule is not None
            and source_capsule.metadata.tenant_id != source_address.tenant_id
        ):
            raise NamespaceViolation("source capsule tenant does not match source address")
        if candidate_capsule.metadata.tenant_id != source_address.tenant_id:
            raise NamespaceViolation("candidate capsule tenant does not match source address")
        if (
            source_capsule is not None
            and source_capsule.digest is not None
            and not source_capsule.verify_digest()
        ):
            raise EvolutionValidationError("source capsule digest is invalid")
        if candidate_capsule.digest is not None and not candidate_capsule.verify_digest():
            raise EvolutionValidationError("candidate capsule digest is invalid")
        source_digest = (
            source_capsule.digest
            if source_capsule is not None and source_capsule.digest
            else source_address.capsule_digest
        )
        candidate_digest = capsule_digest(candidate_capsule)
        if source_capsule is not None and source_digest != source_address.capsule_digest:
            raise NamespaceViolation("source capsule digest does not match source address")
        if candidate_digest == source_address.capsule_digest:
            raise EvolutionValidationError("candidate Capsule must differ from source Capsule")
        if expected_active_capsule is None:
            expected_active_capsule = source_address.capsule_digest
        _require_sha256("expected_active_capsule", expected_active_capsule)
        for name, value in (
            ("dataset_id", dataset_id),
            ("runner_id", runner_id),
            ("model_id", model_id),
            ("policy_digest", policy_digest),
            ("tool_manifest_digest", tool_manifest_digest),
            ("reducer_id", reducer_id),
        ):
            _require_text(name, value)
        if fork_hash is not None:
            if fork_sequence == 0:
                if fork_hash != GENESIS_HASH and not fork_hash.startswith("sha256:"):
                    raise EvolutionValidationError("fork_hash is invalid")
            else:
                _require_sha256("fork_hash", fork_hash)
        if (
            isinstance(control_version, bool)
            or not isinstance(control_version, int)
            or control_version < 0
        ):
            raise EvolutionValidationError("control_version must be non-negative")
        now = self.clock().astimezone(UTC)
        if expires_at is None:
            if (
                isinstance(ttl_seconds, bool)
                or not isinstance(ttl_seconds, int)
                or ttl_seconds <= 0
            ):
                raise EvolutionValidationError("ttl_seconds must be positive")
            expires_at = now + timedelta(seconds=ttl_seconds)
        elif expires_at <= now:
            raise EvolutionValidationError("expires_at must be in the future")
        run = EvolutionRun(
            run_id=run_id or str(uuid.uuid4()),
            source_address=source_address,
            source_capsule_digest=source_digest,
            candidate_capsule_digest=candidate_digest,
            fork_sequence=fork_sequence,
            fork_hash=fork_hash,
            dataset_id=dataset_id,
            runner_id=runner_id,
            model_id=model_id,
            policy_digest=policy_digest,
            tool_manifest_digest=tool_manifest_digest,
            reducer_id=reducer_id,
            expected_active_capsule=expected_active_capsule,
            control_version=control_version,
            created_at=now,
            expires_at=expires_at,
        )
        with self._lock:
            if run.run_id in self._runs:
                raise EvolutionValidationError("run_id already exists")
            self._runs[run.run_id] = run
        return run

    def get_run(self, run_id: str) -> EvolutionRun:
        with self._lock:
            try:
                return self._runs[run_id]
            except KeyError as exc:
                raise EvolutionValidationError("evolution run does not exist") from exc

    def fork(
        self,
        run: EvolutionRun | str,
        *,
        candidate_branch_id: str | None = None,
        fork_sequence: int | None = None,
        fork_hash: str | None = None,
    ) -> EvolutionRun:
        current = self._resolve(run)
        self._require_live(current, EvolutionState.PLANNED)
        sequence = current.fork_sequence if fork_sequence is None else fork_sequence
        anchor = fork_hash if fork_hash is not None else current.fork_hash
        if sequence < 0:
            raise EvolutionValidationError("fork_sequence cannot be negative")
        source_events = self.store.read(current.source_address, to_sequence=sequence)
        if len(source_events) != sequence:
            raise EvolutionValidationError("fork sequence is beyond the source head")
        actual_anchor = source_events[-1].event_hash if source_events else GENESIS_HASH
        if anchor is not None and anchor != actual_anchor:
            self._reject(current, "fork hash does not match source event")
            raise EvolutionValidationError("fork hash does not match source event")
        branch_id = candidate_branch_id or f"candidate-{current.run_id[:12]}"
        branch = self.store.fork(
            current.source_address,
            sequence,
            new_branch_id=branch_id,
            target_capsule_digest=current.candidate_capsule_digest,
        )
        candidate_address = (
            branch.address
            if hasattr(branch, "address")
            else current.source_address.with_branch(branch_id)
        )
        source_head = self.store.head(current.source_address)
        candidate_head = self.store.head(candidate_address)
        updated = replace(
            current,
            state=EvolutionState.FORKED,
            fork_sequence=sequence,
            fork_hash=actual_anchor,
            candidate_address=candidate_address,
            source_head_hash=source_head.event_hash if source_head is not None else GENESIS_HASH,
            candidate_head_hash=candidate_head.event_hash
            if candidate_head is not None
            else actual_anchor,
        )
        return self._save(updated)

    def verify_replay(
        self,
        run: EvolutionRun | str,
        projection: EvolutionProjection,
        *,
        initial_state: object = _UNSET,
        real_provider_calls: int = 0,
        provider_call_count: int | None = None,
        simulate_only: bool = True,
    ) -> EvolutionRun:
        current = self._resolve(run)
        self._require_live(current, EvolutionState.FORKED)
        if current.candidate_address is None:
            raise ReplayVerificationError("candidate branch does not exist")
        calls = provider_call_count if provider_call_count is not None else real_provider_calls
        if not simulate_only or calls != 0:
            self._reject(current, "candidate replay attempted a real provider effect")
            raise ReplayVerificationError("candidate replay must be simulate_only with zero calls")
        try:
            replay: ProjectionResult[Any] = ProjectionReplayer(self.store).assert_deterministic(
                current.candidate_address,
                projection,
                initial_state=initial_state,
            )
        except DeterminismViolation as exc:
            self._reject(current, "deterministic replay mismatch")
            raise ReplayVerificationError("candidate replay is not deterministic") from exc
        except Exception as exc:
            self._reject(current, f"replay failed: {exc}")
            raise
        candidate_head = self.store.head(current.candidate_address)
        updated = replace(
            current,
            state=EvolutionState.REPLAY_VERIFIED,
            candidate_state_hash=replay.state_hash,
            candidate_head_hash=candidate_head.event_hash
            if candidate_head is not None
            else current.fork_hash or GENESIS_HASH,
        )
        return self._save(updated)

    def seal_shadow(
        self,
        run: EvolutionRun | str,
        bundle: EvidenceBundle | None = None,
        *,
        observations: Iterable[EvaluationObservation] | None = None,
        expected_sample_ids: Iterable[str] = (),
        baseline_metrics: Mapping[str, MetricSnapshot] | None = None,
        real_provider_calls: int = 0,
        simulate_only: bool = True,
        dataset_id: str | None = None,
        runner_id: str | None = None,
        model_id: str | None = None,
        policy_digest: str | None = None,
        tool_manifest_digest: str | None = None,
        reducer_id: str | None = None,
    ) -> EvolutionRun:
        current = self._resolve(run)
        self._require_live(current, EvolutionState.REPLAY_VERIFIED)
        if current.candidate_address is None:
            raise EvidenceSealingError("candidate branch does not exist")
        if bundle is None:
            bundle = EvidenceBundle(
                target=current.source_address,
                candidate=current.candidate_address,
                dataset_id=dataset_id or current.dataset_id,
                runner_id=runner_id or current.runner_id,
                model_id=model_id or current.model_id,
                policy_digest=policy_digest or current.policy_digest,
                tool_manifest_digest=tool_manifest_digest or current.tool_manifest_digest,
                reducer_id=reducer_id or current.reducer_id,
                observations=tuple(observations or ()),
                expected_sample_ids=tuple(expected_sample_ids),
                baseline_metrics=baseline_metrics or {},
                real_provider_calls=real_provider_calls,
                simulate_only=simulate_only,
            )
        if bundle.target != current.source_address or bundle.candidate != current.candidate_address:
            raise NamespaceViolation("evidence bundle does not match exact evolution Cell")
        for field_name in (
            "dataset_id",
            "runner_id",
            "model_id",
            "policy_digest",
            "tool_manifest_digest",
            "reducer_id",
        ):
            if getattr(bundle, field_name) != getattr(current, field_name):
                self._reject(current, f"evidence {field_name} does not match run")
                raise EvidenceSealingError(f"evidence {field_name} does not match run")
        if bundle.real_provider_calls != 0 or not bundle.simulate_only:
            self._reject(current, "shadow evidence recorded a real provider call")
            raise EvidenceSealingError("shadow evidence must be simulate_only with zero calls")
        updated = replace(current, state=EvolutionState.EVIDENCE_SEALED, evidence=bundle)
        return self._save(updated)

    def issue_certificate(
        self,
        run: EvolutionRun | str,
        policy: JudgePolicy,
        signing_key: Ed25519PrivateKey | bytes,
        *,
        signing_key_id: str,
        valid_for_seconds: int = 3600,
        certificate_id: str | None = None,
    ) -> EvolutionCertificate:
        current = self._resolve(run)
        self._require_live(current, EvolutionState.EVIDENCE_SEALED)
        if current.evidence is None or current.candidate_address is None:
            raise CertificateError("sealed evidence is missing")
        decision = self.judge.evaluate(current.evidence, policy)
        if not decision.accepted:
            updated = replace(
                current,
                decision=decision,
                state=EvolutionState.REJECTED,
                rejection_reason=";".join(decision.reasons),
            )
            self._save(updated)
            raise CertificateError("Judge rejected candidate: " + ",".join(decision.reasons))
        if (
            isinstance(valid_for_seconds, bool)
            or not isinstance(valid_for_seconds, int)
            or valid_for_seconds <= 0
        ):
            raise CertificateError("certificate validity must be positive")
        now = self.clock().astimezone(UTC)
        certificate = EvolutionCertificate(
            certificate_id=certificate_id or str(uuid.uuid4()),
            source_address=current.source_address,
            candidate_address=current.candidate_address,
            source_capsule_digest=current.source_address.capsule_digest,
            candidate_capsule_digest=current.candidate_address.capsule_digest,
            fork_sequence=current.fork_sequence,
            fork_hash=current.fork_hash or GENESIS_HASH,
            source_head_hash=current.source_head_hash or GENESIS_HASH,
            candidate_head_hash=current.candidate_head_hash or GENESIS_HASH,
            dataset_id=current.evidence.dataset_id,
            runner_id=current.evidence.runner_id,
            model_id=current.evidence.model_id,
            policy_digest=current.evidence.policy_digest,
            tool_manifest_digest=current.evidence.tool_manifest_digest,
            reducer_id=current.evidence.reducer_id,
            evidence_digest=current.evidence.evidence_digest,
            judge_policy=policy.to_dict(),
            expected_active_capsule=current.expected_active_capsule,
            control_version=current.control_version,
            signing_key_id=signing_key_id,
            issued_at=now,
            expires_at=now + timedelta(seconds=valid_for_seconds),
        ).with_signature(signing_key)
        self._save(
            replace(
                current, state=EvolutionState.CERTIFIED, decision=decision, certificate=certificate
            )
        )
        return certificate

    def promote(
        self,
        run: EvolutionRun | str,
        store: PromotionStore,
        approval_authority: PromotionApprovalAuthority,
        approval: PromotionApproval,
        *,
        verifier: CertificateVerifier,
    ) -> PromotionReceipt:
        current = self._resolve(run)
        self._require_live(current, EvolutionState.CERTIFIED)
        if current.certificate is None:
            raise PromotionError("certified run has no certificate")
        target = PromotionTarget(
            address=current.source_address,
            active_capsule_digest=current.expected_active_capsule,
            control_version=current.control_version,
        )
        result = verifier.verify(current.certificate, target)
        if not result.valid:
            raise PromotionError("certificate verification failed: " + result.reason)
        approval_authority.verify_and_consume(approval, current.certificate, target)
        receipt = store.compare_and_swap(
            target,
            expected_active_capsule=target.active_capsule_digest,
            new_active_capsule=current.candidate_address.capsule_digest
            if current.candidate_address
            else None,
            expected_control_version=target.control_version,
            certificate=current.certificate,
            approval_consumed=True,
        )
        self._save(replace(current, state=EvolutionState.PROMOTED, promotion_receipt=receipt))
        return receipt

    def rollback(
        self, run: EvolutionRun | str, store: PromotionStore, receipt: PromotionReceipt
    ) -> PromotionReceipt:
        current = self._resolve(run)
        self._require_live(current, EvolutionState.PROMOTED)
        rollback_receipt = store.rollback(receipt)
        self._save(
            replace(current, state=EvolutionState.ROLLED_BACK, promotion_receipt=rollback_receipt)
        )
        return rollback_receipt

    def abort(self, run: EvolutionRun | str, *, reason: str = "") -> EvolutionRun:
        current = self._resolve(run)
        self._require_live(
            current,
            *tuple(
                state
                for state in EvolutionState
                if state
                not in {
                    EvolutionState.PROMOTED,
                    EvolutionState.ROLLED_BACK,
                    EvolutionState.REJECTED,
                    EvolutionState.EXPIRED,
                    EvolutionState.ABORTED,
                }
            ),
        )
        return self._save(replace(current, state=EvolutionState.ABORTED, rejection_reason=reason))

    def expire(self, run: EvolutionRun | str) -> EvolutionRun:
        current = self._resolve(run)
        if current.state in {
            EvolutionState.PROMOTED,
            EvolutionState.ROLLED_BACK,
            EvolutionState.REJECTED,
            EvolutionState.EXPIRED,
            EvolutionState.ABORTED,
        }:
            raise EvolutionTransitionError("run is already terminal")
        if self.clock().astimezone(UTC) < current.expires_at:
            raise EvolutionTransitionError("run has not expired")
        return self._save(
            replace(current, state=EvolutionState.EXPIRED, rejection_reason="expired")
        )

    def _resolve(self, run: EvolutionRun | str) -> EvolutionRun:
        # Callers commonly keep the value returned by ``fork`` while later
        # steps return only a certificate/receipt.  Resolve object handles
        # through the coordinator's authoritative record so state transitions
        # cannot accidentally operate on a stale immutable snapshot.
        return self.get_run(run.run_id) if isinstance(run, EvolutionRun) else self.get_run(run)

    def _save(self, run: EvolutionRun) -> EvolutionRun:
        with self._lock:
            self._runs[run.run_id] = run
        return run

    def _reject(self, run: EvolutionRun, reason: str) -> None:
        self._save(replace(run, state=EvolutionState.REJECTED, rejection_reason=reason))

    def _require_live(self, run: EvolutionRun, *allowed: EvolutionState) -> None:
        if run.state not in allowed:
            raise EvolutionTransitionError(
                f"run {run.run_id} is {run.state}; expected one of "
                f"{', '.join(value.value for value in allowed)}"
            )
        if self.clock().astimezone(UTC) >= run.expires_at:
            self._save(replace(run, state=EvolutionState.EXPIRED, rejection_reason="expired"))
            raise EvolutionTransitionError("evolution run has expired")


def run_evolution_demo() -> dict[str, object]:
    """Run the complete credential-free Proof-Carrying Evolution demo.

    The helper is intentionally synchronous and deterministic apart from
    generated identifiers/keys.  It is suitable for a local acceptance gate:
    no worker, model, network, provider or effect executor is constructed.
    """

    def demo_capsule(prompt: str) -> AgentCapsule:
        return AgentCapsule(
            metadata={"tenant_id": "evolution-demo", "name": "demo"},
            spec={
                "graph": "graph://evolution-demo",
                "prompt": f"prompt://{prompt}",
                "modelPolicy": "policy://model/offline",
                "toolManifest": "tools://offline",
                "governancePolicy": "policy://governance/demo",
                "storageProfile": "storage://offline",
            },
        ).with_digest()

    source_capsule = demo_capsule("source")
    candidate_capsule = demo_capsule("candidate")
    source_digest = source_capsule.content_digest
    source_address = CellAddress(
        tenant_id="evolution-demo",
        app_id="demo-app",
        cell_id="demo-cell",
        session_id="demo-session",
        capsule_digest=source_digest,
    )
    event_store = InMemoryEventStore()
    event_store.append(
        tenant_id=source_address.tenant_id,
        app_id=source_address.app_id,
        cell_id=source_address.cell_id,
        session_id=source_address.session_id,
        capsule_digest=source_address.capsule_digest,
        event_type="message.accepted",
        payload={"delta": 1},
        event_id="evolution-demo-event",
    )
    coordinator = EvolutionCoordinator(event_store)
    source_head = event_store.head(source_address)
    if source_head is None:  # pragma: no cover - guarded by the append above
        raise EvolutionError("demo source event was not appended")
    run = coordinator.create_run(
        source_address,
        source_capsule=source_capsule,
        candidate_capsule=candidate_capsule,
        fork_sequence=source_head.sequence,
        fork_hash=source_head.event_hash,
        dataset_id="dataset://evolution-demo/v1",
        runner_id="runner://offline",
        model_id="model://deterministic",
        policy_digest="policy://judge/demo-v1",
        tool_manifest_digest="tools://offline",
        reducer_id="reducer://sum-v1",
    )
    run = coordinator.fork(run, candidate_branch_id="candidate-demo")
    run = coordinator.verify_replay(
        run,
        lambda state, event: state + cast(int, event.payload["delta"]),
        initial_state=0,
    )
    observation = EvaluationObservation(
        sample_id="sample-001",
        quality_bps=1_010,
        cost_units=90,
        latency_ms=90,
        baseline_quality_bps=1_000,
        baseline_cost_units=100,
        baseline_latency_ms=100,
        baseline_output_hash="sha256:" + "a" * 64,
        candidate_output_hash="sha256:" + "b" * 64,
        summary="redacted demo observation",
    )
    run = coordinator.seal_shadow(
        run,
        observations=(observation,),
        expected_sample_ids=("sample-001",),
    )
    judge_key = Ed25519PrivateKey.generate()
    certificate = coordinator.issue_certificate(
        run,
        JudgePolicy(),
        judge_key,
        signing_key_id="demo-judge",
        certificate_id="evolution-demo-certificate",
    )
    target = PromotionTarget(source_address, source_digest)
    verifier = CertificateVerifier({"demo-judge": judge_key.public_key()})
    approval_authority = PromotionApprovalAuthority(b"evolution-demo-approval-secret")
    approval = approval_authority.issue(certificate, target, approved_by="demo-reviewer")
    promotion_store = PromotionStore()
    receipt = coordinator.promote(
        run,
        promotion_store,
        approval_authority,
        approval,
        verifier=verifier,
    )
    rollback_receipt = coordinator.rollback(run, promotion_store, receipt)

    tampered_result = verifier.verify(
        replace(certificate, evidence_digest="sha256:" + "f" * 64), target
    )
    tampered = not tampered_result.valid
    cross_tenant_result = verifier.verify(
        certificate,
        PromotionTarget(
            CellAddress(
                "other-tenant",
                source_address.cell_id,
                source_address.session_id,
                source_digest,
                branch_id="main",
                app_id=source_address.app_id,
            ),
            source_digest,
        ),
    )
    cross_tenant = not cross_tenant_result.valid
    expired_certificate = replace(
        certificate,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
        signature="",
    ).with_signature(judge_key)
    expired_result = verifier.verify(expired_certificate, target)
    expired = not expired_result.valid
    stale_store = PromotionStore(initial=(target,))
    stale_store.compare_and_swap(target, new_active_capsule=candidate_capsule.content_digest)
    stale_cas_reason = ""
    try:
        stale_store.compare_and_swap(
            target,
            expected_active_capsule=source_digest,
            new_active_capsule=source_digest,
        )
    except PromotionCASConflict:
        stale_cas = True
        stale_cas_reason = "active pointer changed before CAS"
    else:  # pragma: no cover - the CAS guard is tested above
        stale_cas = False
    assertions = {
        "forked": True,
        "replay_verified": True,
        "shadow_only": True,
        "certificate_certified": True,
        "promotion_published": True,
        "rollback_verified": True,
        "tampered_evidence_rejected": tampered,
        "cross_tenant_rejected": cross_tenant,
        "expired_certificate_rejected": expired,
        "stale_cas_rejected": stale_cas,
    }
    cases = [
        {"name": "fork", "status": "pass"},
        {"name": "deterministic_replay", "status": "pass"},
        {"name": "shadow_zero_provider_calls", "status": "pass"},
        {"name": "certificate_and_promotion", "status": "pass"},
        {"name": "signed_rollback", "status": "pass"},
        {
            "name": "tampered_evidence_rejected",
            "status": "pass" if tampered else "fail",
            "reason": tampered_result.reason,
        },
        {
            "name": "cross_tenant_rejected",
            "status": "pass" if cross_tenant else "fail",
            "reason": cross_tenant_result.reason,
        },
        {
            "name": "expired_certificate_rejected",
            "status": "pass" if expired else "fail",
            "reason": expired_result.reason,
        },
        {
            "name": "stale_cas_rejected",
            "status": "pass" if stale_cas else "fail",
            "reason": stale_cas_reason,
        },
    ]
    return {
        "gate": "pass" if all(assertions.values()) else "fail",
        "offline_gate": "pass" if all(assertions.values()) else "fail",
        "state": coordinator.get_run(run.run_id).state.value,
        "run_id": run.run_id,
        "certificate_digest": certificate.digest,
        "evidence_digest": certificate.evidence_digest,
        "candidate_real_provider_calls": 0,
        "provider_call_count": 0,
        "real_provider_calls": 0,
        "promotion_receipt": receipt.receipt_id,
        "rollback_receipt": rollback_receipt.receipt_id,
        "assertions": assertions,
        "cases": cases,
        "case_results": cases,
    }


# The local gate accepts either spelling; retain the concise historical hook.
run_demo = run_evolution_demo


__all__ = [
    "ApprovalError",
    "CertificateError",
    "CertificateVerifier",
    "EvaluationObservation",
    "EvaluationSample",
    "EvidenceBundle",
    "EvidenceObservation",
    "EvidenceSealingError",
    "EvolutionCertificate",
    "EvolutionCoordinator",
    "EvolutionError",
    "EvolutionJudge",
    "EvolutionPolicy",
    "EvolutionRun",
    "EvolutionRunState",
    "EvolutionState",
    "EvolutionStatus",
    "EvolutionTransitionError",
    "EvolutionValidationError",
    "JudgeDecision",
    "JudgePolicy",
    "MetricSnapshot",
    "PromotionAlreadyUsed",
    "PromotionApproval",
    "PromotionApprovalAuthority",
    "PromotionCASConflict",
    "PromotionError",
    "PromotionPointer",
    "PromotionReceipt",
    "PromotionReceiptError",
    "PromotionStore",
    "PromotionTarget",
    "ReplayVerificationError",
    "RunState",
    "ShadowObservation",
    "VerificationResult",
    "capsule_digest",
    "compute_merkle_root",
    "evidence_merkle_root",
    "merkle_root",
    "run_demo",
    "run_evolution_demo",
]
