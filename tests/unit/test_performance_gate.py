from __future__ import annotations

import pytest

from scripts.performance_gate import _run, _validate_workload


def test_offline_performance_workload_is_hard_bounded() -> None:
    with pytest.raises(ValueError, match="workload exceeds limits"):
        _validate_workload(2_001, 50, 16, 60.0)
    with pytest.raises(ValueError, match="timeout"):
        _validate_workload(10, 5, 2, 121.0)


@pytest.mark.asyncio
async def test_small_offline_performance_run_cleans_up_and_reports_pass() -> None:
    report = await _run(4, 2, 2, 10.0)

    assert report["gate"] == "pass"
    assert report["production_gate"] == "not_run"
    candidate = report["candidate"]
    assert candidate["timed_out"] is False
    assert candidate["effective_turn_workers"] == 2
