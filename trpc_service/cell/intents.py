"""Immutable tool intents and scoped approvals for Agent Cells.

An :class:`ToolIntent` is the durable, side-effect-free proposal produced by
an Agent Cell.  The effect executor consumes an intent only after its policy
decision has been checked.  Keeping the intent separate from execution is
important: a model retry can reproduce the proposal, while a provider retry
must never silently repeat an external side effect.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any


class PolicyDecision(StrEnum):
    """The decision made before an intent can cross the effect boundary."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_CONFIRMATION = "require_confirmation"
    SIMULATE_ONLY = "simulate_only"

    # Compatibility aliases make the value pleasant to use alongside the
    # existing governance pipeline, whose historical name is
    # ``NEEDS_CONFIRMATION``.
    NEEDS_CONFIRMATION = "require_confirmation"
    allow = "allow"
    deny = "deny"
    require_confirmation = "require_confirmation"
    simulate_only = "simulate_only"

    @classmethod
    def parse(cls, value: PolicyDecision | str) -> PolicyDecision:
        if isinstance(value, cls):
            return value
        normalized = value.strip().lower().replace("-", "_")
        if normalized == "needs_confirmation":
            normalized = "require_confirmation"
        try:
            return cls(normalized)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unsupported policy decision: {value!r}") from exc


class IntentRisk(StrEnum):
    """Risk labels used by the effect plane.

    ``NON_IDEMPOTENT`` and ``UNKNOWN`` are retained as values because they
    are the labels used by the existing tRPC-Agent service.  Both are treated
    as high risk by :attr:`ToolIntent.requires_confirmation`.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    IDEMPOTENT = "idempotent"
    NON_IDEMPOTENT = "non_idempotent"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: IntentRisk | str) -> IntentRisk:
        if isinstance(value, cls):
            return value
        normalized = value.strip().lower().replace("-", "_")
        try:
            return cls(normalized)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unsupported intent risk: {value!r}") from exc


# A readable alias for callers that think in terms of a generic risk level.
RiskLevel = IntentRisk


_HIGH_RISK = frozenset(
    {
        IntentRisk.HIGH,
        IntentRisk.CRITICAL,
        IntentRisk.NON_IDEMPOTENT,
        IntentRisk.UNKNOWN,
    }
)


def _canonical_value(value: Any) -> Any:
    """Return a JSON-safe, deterministic representation of ``value``.

    Tool arguments normally contain JSON values.  The small amount of
    normalization here also makes hashes stable for tuples, sets and nested
    mappings used by Python callers, while refusing values that cannot be
    represented safely instead of silently stringifying them.
    """

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [_canonical_value(item) for item in value]
        return sorted(normalized, key=lambda item: _canonical_json(item))
    raise TypeError(f"tool arguments contain unsupported value: {type(value).__name__}")


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _canonical_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def arguments_hash(arguments: Mapping[str, Any]) -> str:
    """Hash arguments without depending on dictionary insertion order."""

    return hashlib.sha256(_canonical_json(arguments).encode("utf-8")).hexdigest()


def stable_effect_key(
    tenant_id: str | ToolIntent,
    cell_id: str | None = None,
    session_id: str | None = None,
    intent_id: str | None = None,
    tool_name: str | None = None,
    arguments: Mapping[str, Any] | None = None,
    *,
    branch_id: str | None = "main",
    principal_id: str | None = None,
    capsule_digest: str | None = None,
    key: bytes | None = None,
    namespace: str = "trpc-agent-effect/v1",
) -> str:
    """Build a stable, tenant-scoped key for one logical side effect.

    The preferred form is ``stable_effect_key(intent)``.  The expanded form
    is useful for storage adapters that do not materialize a ``ToolIntent``.
    The key intentionally excludes transient worker, attempt, trace and
    lease identifiers.  Retries and failover therefore address the same
    ledger row.  A deployment may supply a tenant-specific HMAC key when the
    digest must not be guessable; the default remains deterministic and
    portable across nodes.
    """

    if isinstance(tenant_id, ToolIntent):
        intent = tenant_id
        material: dict[str, Any] = {
            "tenant_id": intent.tenant_id,
            "cell_id": intent.cell_id,
            "session_id": intent.session_id,
            "intent_id": intent.intent_id,
            "tool_name": intent.tool_name,
            "arguments_hash": intent.arguments_hash,
            "branch_id": intent.branch_id,
            "principal_id": intent.principal_id or "",
            "capsule_digest": intent.capsule_digest or "",
        }
    else:
        values = {
            "tenant_id": tenant_id,
            "cell_id": cell_id,
            "session_id": session_id,
            "intent_id": intent_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "branch_id": branch_id,
            "principal_id": principal_id,
            "capsule_digest": capsule_digest,
        }
        missing = [
            name
            for name in (
                "tenant_id",
                "cell_id",
                "session_id",
                "intent_id",
                "tool_name",
                "arguments",
                "branch_id",
            )
            if values[name] is None
        ]
        if missing:
            raise ValueError(f"effect key fields are missing: {', '.join(missing)}")
        if not isinstance(branch_id, str) or not branch_id:
            raise ValueError("branch_id must be a non-empty string")
        material = {
            "tenant_id": tenant_id,
            "cell_id": cell_id,
            "session_id": session_id,
            "intent_id": intent_id,
            "tool_name": tool_name,
            "arguments_hash": arguments_hash(arguments or {}),
            "branch_id": branch_id,
            "principal_id": principal_id or "",
            "capsule_digest": capsule_digest or "",
        }
    encoded = _canonical_json(material).encode("utf-8")
    digest = (
        hmac.new(key, encoded, hashlib.sha256).hexdigest()
        if key is not None
        else hashlib.sha256(encoded).hexdigest()
    )
    return f"{namespace}:{digest}"


@dataclass(frozen=True, slots=True)
class ConfirmationScope:
    """A narrowly scoped approval for one exact tool invocation.

    Every identity and argument component is checked by ``matches``.  In
    particular, an approval cannot be transferred to another tenant, Cell,
    Session, principal, tool, or changed argument set.  ``effect_key`` is
    included so a manual replay cannot accidentally approve a different
    logical intent that happens to use the same tool.
    """

    tenant_id: str
    cell_id: str
    session_id: str
    principal_id: str
    tool_name: str
    arguments_hash: str
    effect_key: str
    branch_id: str = "main"
    approved_by: str = ""
    approval_id: str = ""
    expires_at: datetime | None = None

    @classmethod
    def for_intent(
        cls,
        intent: ToolIntent,
        *,
        approved_by: str = "",
        approval_id: str = "",
        ttl_seconds: int = 300,
    ) -> ConfirmationScope:
        if ttl_seconds <= 0:
            raise ValueError("confirmation TTL must be positive")
        return cls(
            tenant_id=intent.tenant_id,
            cell_id=intent.cell_id,
            session_id=intent.session_id,
            principal_id=intent.principal_id or "",
            tool_name=intent.tool_name,
            arguments_hash=intent.arguments_hash,
            effect_key=intent.effect_key,
            branch_id=intent.branch_id,
            approved_by=approved_by,
            approval_id=approval_id,
            expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
        )

    # ``from_intent`` reads naturally for callers that use constructor-style
    # factories; retaining both names costs nothing and avoids loose dicts.
    from_intent = for_intent

    def matches(self, intent: ToolIntent, *, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        expires_at = self.expires_at
        if expires_at is not None:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            if expires_at <= current:
                return False
        return (
            hmac.compare_digest(self.tenant_id, intent.tenant_id)
            and hmac.compare_digest(self.cell_id, intent.cell_id)
            and hmac.compare_digest(self.session_id, intent.session_id)
            and hmac.compare_digest(self.principal_id, intent.principal_id or "")
            and hmac.compare_digest(self.tool_name, intent.tool_name)
            and hmac.compare_digest(self.arguments_hash, intent.arguments_hash)
            and hmac.compare_digest(self.effect_key, intent.effect_key)
            and hmac.compare_digest(self.branch_id, intent.branch_id)
        )

    def is_expired(self, *, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return expires_at <= (now or datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class ToolIntent:
    """Immutable proposal for one external tool effect.

    ``intent_id`` should be supplied by the Cell event (for example, the
    causal event id).  When omitted it is deterministically derived from the
    tenant/Cell/Session/tool/arguments, which is safe but deliberately
    conservative: two identical calls without a caller-owned id are treated
    as the same logical intent.
    """

    tenant_id: str
    cell_id: str
    session_id: str
    tool_name: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    intent_id: str = ""
    branch_id: str = "main"
    policy_decision: PolicyDecision | str = PolicyDecision.ALLOW
    risk: IntentRisk | str = IntentRisk.UNKNOWN
    principal_id: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    capsule_digest: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    decision: PolicyDecision | str | None = field(default=None, repr=False, compare=False)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC), compare=False)
    arguments_hash: str = field(init=False)
    effect_key: str = field(init=False)

    def __post_init__(self) -> None:
        for field_name in ("tenant_id", "cell_id", "session_id", "tool_name", "branch_id"):
            if not isinstance(getattr(self, field_name), str) or not getattr(self, field_name):
                raise ValueError(f"{field_name} must be a non-empty string")
        if not isinstance(self.arguments, Mapping):
            raise TypeError("arguments must be a mapping")
        normalized_arguments = dict(self.arguments)
        normalized_metadata = dict(self.metadata)
        argument_digest = arguments_hash(normalized_arguments)
        selected_decision = self.policy_decision if self.decision is None else self.decision
        normalized_decision = PolicyDecision.parse(selected_decision)
        normalized_risk = IntentRisk.parse(self.risk)
        supplied_intent_id = self.intent_id
        if not supplied_intent_id:
            seed = _canonical_json(
                {
                    "tenant_id": self.tenant_id,
                    "cell_id": self.cell_id,
                    "session_id": self.session_id,
                    "tool_name": self.tool_name,
                    "branch_id": self.branch_id,
                    "arguments_hash": argument_digest,
                    "principal_id": self.principal_id or "",
                    "capsule_digest": self.capsule_digest or "",
                    "request_id": self.request_id or "",
                }
            )
            supplied_intent_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]
        if not isinstance(supplied_intent_id, str) or not supplied_intent_id:
            raise ValueError("intent_id must be a non-empty string")
        object.__setattr__(self, "arguments", normalized_arguments)
        object.__setattr__(self, "metadata", normalized_metadata)
        object.__setattr__(self, "policy_decision", normalized_decision)
        object.__setattr__(self, "risk", normalized_risk)
        object.__setattr__(self, "intent_id", supplied_intent_id)
        object.__setattr__(self, "decision", normalized_decision)
        object.__setattr__(self, "arguments_hash", argument_digest)
        object.__setattr__(self, "effect_key", stable_effect_key(self))

    @property
    def args_hash(self) -> str:
        """Short alias used by storage adapters."""

        return self.arguments_hash

    @property
    def requires_confirmation(self) -> bool:
        return self.policy_decision == PolicyDecision.REQUIRE_CONFIRMATION or (
            self.risk in _HIGH_RISK
        )

    @property
    def high_risk(self) -> bool:
        return self.risk in _HIGH_RISK

    def confirmation_scope(
        self,
        *,
        approved_by: str = "",
        approval_id: str = "",
        ttl_seconds: int = 300,
    ) -> ConfirmationScope:
        return ConfirmationScope.for_intent(
            self,
            approved_by=approved_by,
            approval_id=approval_id,
            ttl_seconds=ttl_seconds,
        )


__all__ = [
    "ConfirmationScope",
    "IntentRisk",
    "PolicyDecision",
    "RiskLevel",
    "ToolIntent",
    "arguments_hash",
    "stable_effect_key",
]
