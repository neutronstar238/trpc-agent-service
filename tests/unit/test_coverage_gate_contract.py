from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from scripts import check_coverage

ROOT = Path(__file__).parents[2]


def test_coverage_gate_entrypoints_use_import_safe_module_invocation() -> None:
    coverage_script = (ROOT / "coverage.sh").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "python -m scripts.check_coverage" in coverage_script
    assert "python -m uv" not in coverage_script
    assert "command -v uv" in coverage_script
    assert "python -m scripts.check_coverage" in workflow
    assert "python scripts/check_coverage.py" not in coverage_script
    assert "python scripts/check_coverage.py" not in workflow


def test_coverage_gate_runs_from_a_clean_python_path(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    output = tmp_path / "gate.json"
    report.write_text(
        json.dumps(
            {
                "totals": {
                    "percent_statements_covered": 95.0,
                    "percent_branches_covered": 91.0,
                }
            }
        ),
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)

    completed = subprocess.run(  # noqa: S603 - fixed interpreter and local module
        [
            sys.executable,
            "-m",
            "scripts.check_coverage",
            str(report),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["gate"] == "pass"
    assert payload["test_scope"] == "tests/unit"
    assert payload["source_fingerprint"]["status"] == "available"
    assert "tests/unit" in payload["source_fingerprint"]["included_roots"]
    assert re.fullmatch(r"[0-9a-f]{64}", payload["coverage_report_sha256"])
    assert len(payload["source_fingerprint"]["value"]) == 64
    if shutil.which("git") is None:
        assert payload["git_sha"] is None
    else:
        assert re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", payload["git_sha"])
    generated_at = datetime.fromisoformat(payload["generated_at"].replace("Z", "+00:00"))
    assert generated_at.tzinfo is not None
    assert generated_at.tzinfo == UTC


def test_coverage_gate_preserves_metadata_when_branch_gate_fails(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(
        json.dumps(
            {
                "totals": {
                    "percent_statements_covered": 95.0,
                    "percent_branches_covered": 89.9,
                }
            }
        ),
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and local module
        [
            sys.executable,
            "-m",
            "scripts.check_coverage",
            str(report),
            "--test-scope",
            "tests/unit",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    payload = json.loads(completed.stdout)
    assert payload["gate"] == "fail"
    assert payload["rejection_reasons"] == ["branch_coverage"]
    assert payload["test_scope"] == "tests/unit"
    assert payload["source_fingerprint"]["status"] == "available"
    assert payload["git_sha"]
    assert payload["generated_at"].endswith("Z")


def test_coverage_gate_fails_closed_when_source_fingerprint_is_unavailable(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(
        json.dumps(
            {
                "totals": {
                    "percent_statements_covered": 95.0,
                    "percent_branches_covered": 91.0,
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        check_coverage,
        "source_fingerprint",
        lambda *args, **kwargs: {
            "algorithm": "sha256",
            "status": "unavailable",
            "reason": "source_changed_during_fingerprint",
        },
    )
    monkeypatch.setattr(sys, "argv", ["check_coverage", str(report)])

    assert check_coverage.main() == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["gate"] == "fail"
    assert payload["rejection_reasons"] == ["source_fingerprint"]
