from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXTERNAL_VENV_PYTHON = ROOT.parent / "trpc-agent-service" / ".venv" / "Scripts" / "python.exe"


def _interpreter() -> str:
    """Prefer the separately-installed service interpreter when available."""

    return str(EXTERNAL_VENV_PYTHON if EXTERNAL_VENV_PYTHON.is_file() else Path(sys.executable))


@pytest.mark.parametrize(
    ("module", "script"),
    (
        ("scripts.mock_production_gate", "mock_production_gate.py"),
        ("scripts.release_gate", "release_gate.py"),
        ("scripts.check_coverage", "check_coverage.py"),
        ("scripts.supply_chain_gate", "supply_chain_gate.py"),
        ("scripts.candidate_lock", "candidate_lock.py"),
    ),
)
@pytest.mark.parametrize("module_mode", (False, True), ids=("file", "module"))
def test_evidence_entrypoints_ignore_a_shadow_scripts_namespace(
    tmp_path: Path,
    module: str,
    script: str,
    module_mode: bool,
) -> None:
    """A stale checkout on PYTHONPATH must not provide evidence helpers."""

    shadow_root = tmp_path / "shadow-checkout"
    shadow_scripts = shadow_root / "scripts"
    shadow_scripts.mkdir(parents=True)
    (shadow_scripts / "evidence_lineage.py").write_text(
        "raise RuntimeError('shadow scripts package was imported')\n",
        encoding="utf-8",
    )

    environment = os.environ.copy()
    # Put the poisoned namespace before the owning checkout.  This also
    # catches the subtle case where a bootstrap checks only membership and
    # leaves an existing, later root behind the shadow path.
    environment["PYTHONPATH"] = os.pathsep.join((str(shadow_root), str(ROOT)))
    command = (
        [_interpreter(), "-m", module, "--help"]
        if module_mode
        else [_interpreter(), str(ROOT / "scripts" / script), "--help"]
    )
    completed = subprocess.run(  # noqa: S603 - fixed local entrypoint and args
        command,
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, (
        f"{command!r} resolved a shadow helper or failed to start:\n"
        f"stdout={completed.stdout}\nstderr={completed.stderr}"
    )
