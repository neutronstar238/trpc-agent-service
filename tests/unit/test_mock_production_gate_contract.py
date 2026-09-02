from __future__ import annotations

import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from subprocess import CompletedProcess

import scripts.mock_production_gate as mock_production_gate
from scripts.mock_production_gate import SCENARIOS, _pytest


def test_mock_gate_preserves_existing_order_and_adds_cell_fabric() -> None:
    names = tuple(SCENARIOS)
    assert names[:5] == (
        "multinode_load",
        "fault_injection",
        "migration",
        "kubernetes_runtime",
        "im_protocol",
    )
    assert names[-1] == "cell_fabric"

    definition = SCENARIOS["cell_fabric"]
    assert definition["emulates"]
    assert definition["production_gap"]
    assert "tests/unit/test_cell_runtime.py" in definition["selectors"]
    assert "tests/unit/test_cell_postgres_adapters.py" in definition["selectors"]
    assert "tests/unit/test_cell_postgres_effects.py" in definition["selectors"]
    assert "real PostgreSQL locks/triggers/RLS" in definition["production_gap"]


def test_mock_gate_rejects_a_successful_pytest_process_with_no_passes(monkeypatch) -> None:
    monkeypatch.setattr(
        "scripts.mock_production_gate.subprocess.run",
        lambda *args, **kwargs: CompletedProcess(
            args=args, returncode=0, stdout="3 skipped", stderr=""
        ),
    )

    result = _pytest(("tests/unit/example.py",))

    assert result["status"] == "fail"
    assert result["passed_count"] == 0


def test_mock_gate_requires_at_least_one_reported_pass(monkeypatch) -> None:
    monkeypatch.setattr(
        "scripts.mock_production_gate.subprocess.run",
        lambda *args, **kwargs: CompletedProcess(
            args=args,
            returncode=0,
            stdout="2 passed, 1 skipped in 0.01s",
            stderr="",
        ),
    )

    result = _pytest(("tests/unit/example.py",))

    assert result["status"] == "pass"
    assert result["passed_count"] == 2


def _stub_mock_runs(monkeypatch) -> None:
    monkeypatch.setattr(
        mock_production_gate,
        "_performance",
        lambda _output: ({"status": "pass", "metrics": {}}, {}),
    )
    monkeypatch.setattr(
        mock_production_gate,
        "_pytest",
        lambda _selectors: {"status": "pass", "exit_code": 0, "passed_count": 1},
    )


def test_mock_gate_records_current_candidate_lineage(tmp_path: Path, monkeypatch) -> None:
    _stub_mock_runs(monkeypatch)
    output = tmp_path / "production-mock.json"
    performance_output = tmp_path / "performance-mock.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "mock_production_gate.py",
            "--output",
            str(output),
            "--performance-output",
            str(performance_output),
        ],
    )

    assert mock_production_gate.main() == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    generated_at = datetime.fromisoformat(payload["generated_at"].replace("Z", "+00:00"))

    assert generated_at.tzinfo == UTC
    assert payload["source_fingerprint"]["status"] == "available"
    assert re.fullmatch(r"[0-9a-f]{64}", payload["source_fingerprint"]["value"])
    assert ".github/workflows" in payload["source_fingerprint"]["included_roots"]
    assert "tests/simulation" in payload["source_fingerprint"]["included_roots"]
    assert payload["git_sha_status"] in {"available", "unavailable"}
    if payload["git_sha_status"] == "available":
        assert re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", payload["git_sha"])
    else:
        assert payload["git_sha"] is None
    assert payload["production_gate"] == "not_run"


def test_mock_gate_marks_unavailable_lineage_without_promoting_production(
    tmp_path: Path, monkeypatch
) -> None:
    _stub_mock_runs(monkeypatch)
    monkeypatch.setattr(mock_production_gate, "_git_sha", lambda _root: None)
    monkeypatch.setattr(
        mock_production_gate,
        "_source_fingerprint",
        lambda: {
            "algorithm": "sha256",
            "status": "unavailable",
            "reason": "test_fixture",
        },
    )
    output = tmp_path / "production-mock.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["mock_production_gate.py", "--output", str(output)],
    )

    assert mock_production_gate.main() == 0
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["git_sha"] is None
    assert payload["git_sha_status"] == "unavailable"
    assert payload["source_fingerprint"]["status"] == "unavailable"
    assert payload["production_gate"] == "not_run"
