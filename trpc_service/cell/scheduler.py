"""Deterministic, explainable Cell placement.

The scheduler treats placement as a constrained decision, not just a least
loaded-node lookup.  Compliance and resource requirements are hard filters;
SLO fit, data locality, optional capabilities, cost and current load are
weighted soft signals.  Every score is derived only from the request and a
node snapshot, so the same inputs produce the same decision on every gateway.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from math import isfinite
from typing import Protocol

from trpc_service.cell.capsule import SLOProfile


class NoFeasibleNodeError(RuntimeError):
    """No node satisfied the Cell's hard placement constraints."""

    def __init__(self, cell_id: str, reasons: tuple[str, ...]) -> None:
        self.cell_id = cell_id
        self.reasons = reasons
        detail = "; ".join(reasons) if reasons else "no node is available"
        super().__init__(f"no feasible node for cell {cell_id!r}: {detail}")


def _non_empty(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} cannot be empty")
    return value.strip()


def _normalise_set(values: frozenset[str] | set[str] | tuple[str, ...]) -> frozenset[str]:
    result = frozenset(item.strip() for item in values)
    if any(not item for item in result):
        raise ValueError("set values cannot be empty")
    return result


def _ratio(numerator: int | float, denominator: int | float) -> float:
    if denominator <= 0:
        return 1.0
    return numerator / denominator


def _clamp(value: float, lower: float = 0.0, upper: float = 1.0) -> float:
    return max(lower, min(upper, value))


@dataclass(frozen=True, slots=True)
class SchedulerWeights:
    """Weights for the placement objective.

    Values are normalized automatically.  Keeping weights in a value object
    makes policy revisions explicit and allows a tenant-specific scheduler to
    use the same deterministic algorithm with a different objective.
    """

    slo: float = 0.28
    locality: float = 0.20
    capability: float = 0.15
    compliance: float = 0.12
    cost: float = 0.12
    load: float = 0.13

    def __post_init__(self) -> None:
        values = (self.slo, self.locality, self.capability, self.compliance, self.cost, self.load)
        if any(not isfinite(value) or value < 0 for value in values):
            raise ValueError("scheduler weights must be finite and non-negative")
        if sum(values) <= 0:
            raise ValueError("scheduler weights must have a positive total")

    @property
    def normalized(self) -> tuple[float, float, float, float, float, float]:
        total = self.slo + self.locality + self.capability + self.compliance + self.cost + self.load
        return (
            self.slo / total,
            self.locality / total,
            self.capability / total,
            self.compliance / total,
            self.cost / total,
            self.load / total,
        )


@dataclass(frozen=True, slots=True)
class CellPlacementRequest:
    """Immutable requirements used to place one Agent Cell."""

    cell_id: str
    tenant_id: str
    capsule_digest: str
    slo: SLOProfile = field(default_factory=SLOProfile)
    required_capabilities: frozenset[str] = frozenset()
    preferred_capabilities: frozenset[str] = frozenset()
    data_localities: frozenset[str] = frozenset()
    compliance_regions: frozenset[str] = frozenset()
    preferred_regions: frozenset[str] = frozenset()
    cpu_millis: int = 100
    memory_mb: int = 128
    max_cost_per_hour: float | None = None
    # Placement is a CellAddress concern too.  Defaults keep old scheduler
    # call sites valid while durable reservations can use the full identity.
    app_id: str = "default"
    session_id: str = "default"
    branch_id: str = "main"

    def __post_init__(self) -> None:
        object.__setattr__(self, "cell_id", _non_empty(self.cell_id, "cell_id"))
        object.__setattr__(self, "tenant_id", _non_empty(self.tenant_id, "tenant_id"))
        object.__setattr__(
            self,
            "capsule_digest",
            _non_empty(self.capsule_digest, "capsule_digest"),
        )
        object.__setattr__(self, "app_id", _non_empty(self.app_id, "app_id"))
        object.__setattr__(self, "session_id", _non_empty(self.session_id, "session_id"))
        object.__setattr__(self, "branch_id", _non_empty(self.branch_id, "branch_id"))
        for field_name in (
            "required_capabilities",
            "preferred_capabilities",
            "data_localities",
            "compliance_regions",
            "preferred_regions",
        ):
            object.__setattr__(self, field_name, _normalise_set(getattr(self, field_name)))
        if self.cpu_millis <= 0 or self.memory_mb <= 0:
            raise ValueError("Cell resource requests must be positive")
        if self.max_cost_per_hour is not None and (
            not isfinite(self.max_cost_per_hour) or self.max_cost_per_hour < 0
        ):
            raise ValueError("max_cost_per_hour must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class NodeSnapshot:
    """Point-in-time node capacity, capability and locality information."""

    node_id: str
    region: str
    capacity_cpu_millis: int
    # Producer-owned monotonic marker for the snapshot.  It is deliberately
    # required: a caller must persist and supply a source revision rather than
    # silently publishing an un-fenced ``0`` observation.
    observed_generation: int
    used_cpu_millis: int = 0
    capacity_memory_mb: int = 1
    used_memory_mb: int = 0
    max_cells: int = 1
    active_cells: int = 0
    capabilities: frozenset[str] = frozenset()
    data_localities: frozenset[str] = frozenset()
    estimated_latency_ms: float = 100
    cost_per_hour: float = 0
    healthy: bool = True
    draining: bool = False
    tenant_allowlist: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", _non_empty(self.node_id, "node_id"))
        object.__setattr__(self, "region", _non_empty(self.region, "region"))
        for field_name in ("capabilities", "data_localities", "tenant_allowlist"):
            object.__setattr__(self, field_name, _normalise_set(getattr(self, field_name)))
        if self.capacity_cpu_millis <= 0 or self.capacity_memory_mb <= 0 or self.max_cells <= 0:
            raise ValueError("node capacities must be positive")
        if self.used_cpu_millis < 0 or self.used_memory_mb < 0 or self.active_cells < 0:
            raise ValueError("node usage cannot be negative")
        if (
            isinstance(self.observed_generation, bool)
            or not isinstance(self.observed_generation, int)
            or self.observed_generation < 1
        ):
            raise ValueError("observed_generation must be a positive integer")
        if not isfinite(self.estimated_latency_ms) or self.estimated_latency_ms <= 0:
            raise ValueError("estimated_latency_ms must be finite and positive")
        if not isfinite(self.cost_per_hour) or self.cost_per_hour < 0:
            raise ValueError("cost_per_hour must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class PlacementCandidate:
    """A scored feasible node, including explainability data."""

    node_id: str
    score: float
    component_scores: tuple[tuple[str, float], ...]
    reasons: tuple[str, ...]

    def component(self, name: str) -> float:
        """Return one named component score."""

        return dict(self.component_scores)[name]


@dataclass(frozen=True, slots=True)
class PlacementDecision:
    """The winner and complete ranked alternatives for audit/debugging."""

    cell_id: str
    node_id: str
    score: float
    candidates: tuple[PlacementCandidate, ...]
    rejected: tuple[tuple[str, str], ...] = ()

    @property
    def winner(self) -> PlacementCandidate:
        return self.candidates[0]


class ReservationConflict(RuntimeError):
    """The authoritative placement store rejected a stale/over-capacity claim."""


@dataclass(frozen=True, slots=True)
class PlacementReservation:
    """A durable lease over the resources selected by the scheduler.

    The snapshot used by :meth:`CellScheduler.place` is advisory.  A
    persistent implementation must atomically re-check capacity and insert
    this lease under a row lock; callers must not treat a ``PlacementDecision``
    as a reservation until this object is returned.
    """

    reservation_id: str
    tenant_id: str
    cell_id: str
    node_id: str
    owner_id: str
    lease_epoch: int
    expires_at: datetime
    cpu_millis: int
    memory_mb: int
    decision: PlacementDecision
    app_id: str = "default"
    session_id: str = "default"
    capsule_digest: str = "default"
    branch_id: str = "main"

    def __post_init__(self) -> None:
        for name in (
            "reservation_id",
            "tenant_id",
            "cell_id",
            "node_id",
            "owner_id",
            "app_id",
            "session_id",
            "capsule_digest",
            "branch_id",
        ):
            _non_empty(getattr(self, name), name)
        if self.lease_epoch < 1:
            raise ValueError("lease_epoch must be positive")
        if self.cpu_millis <= 0 or self.memory_mb <= 0:
            raise ValueError("reservation resources must be positive")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("reservation expiry must be timezone-aware")


class PlacementReservationStore(Protocol):
    """Durable reservation contract used to close the snapshot oversell race."""

    async def reserve(
        self,
        request: CellPlacementRequest,
        decision: PlacementDecision,
        *,
        owner_id: str,
        lease_seconds: float = 30.0,
        reservation_id: str | None = None,
    ) -> PlacementReservation:
        """Atomically reserve the decision or raise ``ReservationConflict``."""

    async def renew(
        self,
        reservation: PlacementReservation,
        *,
        owner_id: str | None = None,
        lease_seconds: float = 30.0,
    ) -> PlacementReservation:
        """CAS-renew a lease owned by the current fencing epoch."""

    async def release(
        self,
        reservation: PlacementReservation,
        *,
        owner_id: str | None = None,
    ) -> None:
        """Release a lease idempotently, subject to owner/epoch fencing."""


class CellScheduler:
    """Place Cells using hard constraints followed by a deterministic score."""

    def __init__(self, *, weights: SchedulerWeights | None = None) -> None:
        self.weights = weights or SchedulerWeights()

    def place(
        self,
        request: CellPlacementRequest,
        nodes: tuple[NodeSnapshot, ...] | list[NodeSnapshot],
    ) -> PlacementDecision:
        """Return the best node and ranked alternatives for ``request``.

        Node order never affects the result.  Ties are resolved by the
        lexicographically smallest node id, which makes scheduler decisions
        reproducible in tests, replay and multi-gateway deployments.
        """

        snapshots = tuple(nodes)
        seen: set[str] = set()
        candidates: list[PlacementCandidate] = []
        rejected: list[tuple[str, str]] = []
        for node in snapshots:
            if node.node_id in seen:
                raise ValueError(f"duplicate node_id: {node.node_id}")
            seen.add(node.node_id)
            rejection = self._hard_rejection(request, node)
            if rejection is not None:
                rejected.append((node.node_id, rejection))
                continue
            candidates.append(self._score(request, node))

        if not candidates:
            reasons = tuple(f"{node_id}: {reason}" for node_id, reason in sorted(rejected))
            raise NoFeasibleNodeError(request.cell_id, reasons)

        ranked = tuple(sorted(candidates, key=lambda item: (-item.score, item.node_id)))
        winner = ranked[0]
        return PlacementDecision(
            cell_id=request.cell_id,
            node_id=winner.node_id,
            score=winner.score,
            candidates=ranked,
            rejected=tuple(sorted(rejected)),
        )

    def select_node(
        self,
        request: CellPlacementRequest,
        nodes: tuple[NodeSnapshot, ...] | list[NodeSnapshot],
    ) -> str:
        """Compatibility helper returning only the selected node id."""

        return self.place(request, nodes).node_id

    async def place_and_reserve(
        self,
        request: CellPlacementRequest,
        nodes: tuple[NodeSnapshot, ...] | list[NodeSnapshot],
        reservations: PlacementReservationStore,
        *,
        owner_id: str,
        lease_seconds: float = 30.0,
        reservation_id: str | None = None,
    ) -> PlacementReservation:
        """Score an advisory snapshot, then claim capacity durably.

        The repository is the source of truth: concurrent gateways may choose
        the same winner, but only one can consume the remaining capacity under
        its atomic ``reserve`` transaction.  A conflict is surfaced so the
        caller can refresh snapshots and retry instead of silently
        overselling a node.
        """

        if not isinstance(owner_id, str) or not owner_id.strip():
            raise ValueError("owner_id cannot be empty")
        if not isfinite(lease_seconds) or lease_seconds <= 0:
            raise ValueError("lease_seconds must be finite and positive")
        decision = self.place(request, nodes)
        return await reservations.reserve(
            request,
            decision,
            owner_id=owner_id,
            lease_seconds=lease_seconds,
            reservation_id=reservation_id,
        )

    # ``schedule`` reads naturally at call sites that treat placement as a
    # scheduling operation while ``place`` remains the primary API.
    schedule = place

    def _hard_rejection(self, request: CellPlacementRequest, node: NodeSnapshot) -> str | None:
        if not node.healthy:
            return "node is unhealthy"
        if node.draining:
            return "node is draining"
        if node.tenant_allowlist and request.tenant_id not in node.tenant_allowlist:
            return "tenant is not allowed on node"
        if request.compliance_regions and node.region not in request.compliance_regions:
            return "node region violates compliance constraint"
        if request.required_capabilities.difference(node.capabilities):
            missing = ",".join(sorted(request.required_capabilities.difference(node.capabilities)))
            return f"missing required capabilities: {missing}"
        if node.used_cpu_millis + request.cpu_millis > node.capacity_cpu_millis:
            return "insufficient CPU capacity"
        if node.used_memory_mb + request.memory_mb > node.capacity_memory_mb:
            return "insufficient memory capacity"
        if node.active_cells + 1 > node.max_cells:
            return "cell concurrency limit reached"
        if request.max_cost_per_hour is not None and node.cost_per_hour > request.max_cost_per_hour:
            return "node cost exceeds Cell budget"
        return None

    def _score(self, request: CellPlacementRequest, node: NodeSnapshot) -> PlacementCandidate:
        slo_score = _clamp(request.slo.latency_budget_ms / node.estimated_latency_ms)
        locality_score = (
            0.5
            if not request.data_localities
            else _clamp(
                _ratio(
                    len(request.data_localities.intersection(node.data_localities)),
                    len(request.data_localities),
                )
            )
        )
        capability_score = (
            0.5
            if not request.preferred_capabilities
            else _clamp(
                _ratio(
                    len(request.preferred_capabilities.intersection(node.capabilities)),
                    len(request.preferred_capabilities),
                )
            )
        )
        compliance_score = (
            1.0
            if request.compliance_regions
            else (1.0 if node.region in request.preferred_regions else 0.5)
        )
        if request.max_cost_per_hour is not None:
            cost_score = _clamp(1.0 - _ratio(node.cost_per_hour, request.max_cost_per_hour))
        else:
            # A bounded monotonically decreasing function keeps scores stable
            # when providers expose costs in different units.
            cost_score = 1.0 / (1.0 + node.cost_per_hour)
        cpu_load = _ratio(node.used_cpu_millis + request.cpu_millis, node.capacity_cpu_millis)
        memory_load = _ratio(node.used_memory_mb + request.memory_mb, node.capacity_memory_mb)
        cell_load = _ratio(node.active_cells + 1, node.max_cells)
        load_score = 1.0 - _clamp(max(cpu_load, memory_load, cell_load))

        weights = self.weights.normalized
        raw_score = sum(
            weight * component
            for weight, component in zip(
                weights,
                (
                    slo_score,
                    locality_score,
                    capability_score,
                    compliance_score,
                    cost_score,
                    load_score,
                ),
                strict=True,
            )
        )
        score = round(raw_score, 12)
        components = (
            ("slo", round(slo_score, 12)),
            ("locality", round(locality_score, 12)),
            ("capability", round(capability_score, 12)),
            ("compliance", round(compliance_score, 12)),
            ("cost", round(cost_score, 12)),
            ("load", round(load_score, 12)),
        )
        reasons = (
            f"slo={components[0][1]:.6f}",
            f"locality={components[1][1]:.6f}",
            f"capability={components[2][1]:.6f}",
            f"compliance={components[3][1]:.6f}",
            f"cost={components[4][1]:.6f}",
            f"load={components[5][1]:.6f}",
        )
        return PlacementCandidate(
            node_id=node.node_id,
            score=score,
            component_scores=components,
            reasons=reasons,
        )


__all__ = [
    "CellPlacementRequest",
    "CellScheduler",
    "NoFeasibleNodeError",
    "NodeSnapshot",
    "PlacementCandidate",
    "PlacementDecision",
    "PlacementReservation",
    "PlacementReservationStore",
    "ReservationConflict",
    "SchedulerWeights",
]
