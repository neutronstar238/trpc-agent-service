from __future__ import annotations

import pytest

from scripts.mock_production_gate import MAX_CONCURRENCY, _performance
from scripts.performance_gate import _run, _validate_workload


def test_offline_performance_workload_is_hard_bounded() -> None:
    with pytest.raises(ValueError, match="workload exceeds limits"):
        _validate_workload(2_001, 50, 16, 60.0)
    with pytest.raises(ValueError, match="timeout"):
        _validate_workload(10, 5, 2, 121.0)


def test_mock_gate_uses_performance_gate_concurrency_limit(tmp_path, monkeypatch) -> None:
    output = tmp_path / "performance.json"
    captured: list[str] = []

    def fake_run(command, **_kwargs):
        captured.extend(command)
        output.write_text('{"gate": "pass", "candidate": {}}', encoding="utf-8")
        return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr("scripts.mock_production_gate.subprocess.run", fake_run)
    _performance(output)

    concurrency_index = captured.index("--concurrency")
    assert captured[concurrency_index + 1] == str(MAX_CONCURRENCY)


@pytest.mark.asyncio
async def test_small_offline_performance_run_cleans_up_and_reports_pass() -> None:
    report = await _run(4, 2, 2, 10.0)

    assert report["gate"] == "pass"
    assert report["production_gate"] == "not_run"
    candidate = report["candidate"]
    assert candidate["timed_out"] is False
    assert candidate["effective_turn_workers"] == 2
