"""Regression coverage for producer-fenced node snapshots."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from trpc_service.cell.postgres import PostgresPlacementReservationStore
from trpc_service.cell.scheduler import NodeSnapshot


class _AsyncContext:
    def __init__(self, value: object) -> None:
        self.value = value

    async def __aenter__(self) -> object:
        return self.value

    async def __aexit__(self, *args: object) -> None:
        del args


class _GenerationConnection:
    """Small asyncpg-shaped double for the node function contract."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.row: dict[str, Any] | None = None
        self.local_generation = -1

    async def fetchval(self, query: str, *args: object) -> int:
        self.calls.append((query, args))
        observed_generation = args[0]
        assert isinstance(observed_generation, int)
        if self.row is None:
            self.row = {
                "observed_generation": observed_generation,
                "healthy": args[6],
                "draining": args[7],
            }
            self.local_generation = 0
        elif observed_generation > self.row["observed_generation"]:
            self.row.update(
                observed_generation=observed_generation,
                healthy=args[6],
                draining=args[7],
            )
            self.local_generation += 1
        return self.local_generation


class _Pool:
    def __init__(self, connection: _GenerationConnection) -> None:
        self.connection = connection

    def acquire(self) -> _AsyncContext:
        return _AsyncContext(self.connection)


def _snapshot(observed_generation: int, *, healthy: bool, draining: bool) -> NodeSnapshot:
    return NodeSnapshot(
        node_id="node-a",
        region="cn-shanghai",
        capacity_cpu_millis=1_000,
        capacity_memory_mb=2_048,
        max_cells=10,
        healthy=healthy,
        draining=draining,
        observed_generation=observed_generation,
    )


@pytest.mark.asyncio
async def test_adapter_passes_observed_generation_and_stale_snapshot_is_noop() -> None:
    connection = _GenerationConnection()
    store = PostgresPlacementReservationStore(_Pool(connection))

    assert await store.update_node(_snapshot(10, healthy=True, draining=False)) == 0
    assert await store.update_node(_snapshot(12, healthy=False, draining=True)) == 1
    assert await store.update_node(_snapshot(11, healthy=True, draining=False)) == 1
    assert await store.update_node(_snapshot(12, healthy=True, draining=False)) == 1

    assert connection.row == {
        "observed_generation": 12,
        "healthy": False,
        "draining": True,
    }
    assert connection.calls[-1][1][0] == 12
    assert "$1,$2,$3,$4,$5,$6,$7,$8" in connection.calls[-1][0]


def test_node_snapshot_requires_a_positive_observed_generation() -> None:
    with pytest.raises(ValueError, match="positive integer"):
        _snapshot(0, healthy=True, draining=False)
    with pytest.raises(ValueError, match="observed_generation"):
        _snapshot(-1, healthy=True, draining=False)
    with pytest.raises(ValueError, match="observed_generation"):
        _snapshot(True, healthy=True, draining=False)  # type: ignore[arg-type]


def test_generation_migration_replaces_unsafe_function_and_restores_it_on_downgrade() -> None:
    migration = Path("migrations/versions/0022_cell_node_snapshot_generation.py").read_text(
        encoding="utf-8"
    )

    assert 'revision = "0022_cell_node_snapshot_generation"' in migration
    assert 'down_revision = "0021_performance_reservation_cleanup"' in migration
    assert "ADD COLUMN observed_generation bigint;" in migration
    assert "SET observed_generation = GREATEST(generation, 1::bigint)" in migration
    assert "ck_cell_node_observed_generation_positive" in migration
    assert (
        "WHERE EXCLUDED.observed_generation > cell_node_capacity.observed_generation" in migration
    )
    assert "DROP FUNCTION IF EXISTS public.update_cell_node_snapshot(" in migration
    assert "p_observed_generation bigint" in migration
    assert "p_observed_generation < 1" in migration
    assert "legacy 7-argument update_cell_node_snapshot is disabled" in migration
    assert "USING ERRCODE = '0A000'" in migration
    assert "pg_catalog.aclexplode" in migration
    assert "pg_catalog.acldefault('f'::\"char\"" in migration
    assert "acl.grantee = 0" in migration
    assert "DROP COLUMN IF EXISTS observed_generation" in migration
    downgrade = migration[migration.index("def downgrade()") :]
    assert "DROP FUNCTION IF EXISTS public.update_cell_node_snapshot(" in downgrade
    first_drop = downgrade.index("DROP FUNCTION IF EXISTS public.update_cell_node_snapshot(")
    assert "REVOKE ALL ON FUNCTION" not in downgrade[:first_drop]
