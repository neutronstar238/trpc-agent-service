#!/usr/bin/env python3
# ruff: noqa: E402
"""Run deterministic substitutes for production-only acceptance environments."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# A direct ``python scripts/mock_production_gate.py`` launch puts the
# ``scripts`` directory (rather than this checkout) at ``sys.path[0]``.  An
# operator may also have another checkout on ``PYTHONPATH``.  Pin the package
# lookup to the checkout that owns this file before importing any sibling
# helper; this keeps direct-file and ``python -m`` launches equivalent.
_REPO_IMPORT_ROOT = Path(__file__).resolve().parents[1]
_REPO_IMPORT_ROOT_STR = str(_REPO_IMPORT_ROOT)
while _REPO_IMPORT_ROOT_STR in sys.path:
    sys.path.remove(_REPO_IMPORT_ROOT_STR)
sys.path.insert(0, _REPO_IMPORT_ROOT_STR)

from scripts.evidence_lineage import SOURCE_FINGERPRINT_ROOTS, source_fingerprint
from scripts.performance_gate import MAX_CONCURRENCY
from scripts.report_io import atomic_write_json

ROOT = _REPO_IMPORT_ROOT
_GIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")

SCENARIOS = {
    "multinode_load": {
        "emulates": (
            "four tenants and eight independent worker nodes under duplicate/out-of-order load"
        ),
        "selectors": (
            "tests/simulation/test_multitenant_multinode.py::"
            "test_eight_nodes_isolate_four_tenants_under_duplicate_and_out_of_order_load",
        ),
        "production_gap": (
            "workers share one Python process and an in-memory authoritative repository"
        ),
    },
    "fault_injection": {
        "emulates": "node death, lease takeover, fencing, dependency failures and encrypted replay",
        "selectors": (
            "tests/unit/test_worker_consistency.py",
            "tests/unit/test_queue_dispatchers_and_projection.py",
            "tests/unit/test_agent_extended.py",
        ),
        "production_gap": (
            "faults are deterministic fakes rather than process kill and network corruption"
        ),
    },
    "migration": {
        "emulates": (
            "two-tenant backfill interruption, checkpoint resume, shadow read, cutover and rollback"
        ),
        "selectors": (
            "tests/unit/test_migration.py",
            "tests/simulation/test_multitenant_multinode.py::"
            "test_two_tenant_migration_resumes_independently_after_target_interruption",
        ),
        "production_gap": (
            "source and target are in-memory adapters rather than independently operated stores"
        ),
    },
    "kubernetes_runtime": {
        "emulates": "rolling update, HPA scale-up, PDB eviction and graceful termination",
        "selectors": ("tests/simulation/test_kubernetes_runtime_model.py",),
        "production_gap": (
            "controller behavior is modeled from manifests without a Kubernetes control plane"
        ),
    },
    "im_protocol": {
        "emulates": (
            "WeCom and Feishu signature, AES, callback, reconnect, media and delivery behavior"
        ),
        "selectors": (
            "tests/unit/test_feishu.py",
            "tests/unit/test_feishu_gateway.py",
            "tests/unit/test_wecom.py",
        ),
        "production_gap": (
            "recorded frames and fake clients replace provider accounts and rate limits"
        ),
    },
    "cell_fabric": {
        "emulates": (
            "signed Capsule admission, deterministic Cell placement, causal replay/fork, "
            "Intent/Effect confirmation and exactly-once-by-intent"
        ),
        "selectors": (
            "tests/unit/test_cell_capsule_scheduler.py",
            "tests/unit/test_cell_causal_replay.py",
            "tests/unit/test_cell_intent_effect.py",
            "tests/unit/test_cell_runtime.py",
            "tests/unit/test_cell_worker_journal.py",
            "tests/unit/test_cell_branch_completion.py",
            "tests/unit/test_cell_postgres_contract.py",
            "tests/unit/test_cell_postgres_adapters.py",
            "tests/unit/test_cell_postgres_effects.py",
            "tests/unit/test_cell_fabric_contract.py",
        ),
        "production_gap": (
            "real PostgreSQL locks/triggers/RLS, external KMS, multi-node projection and "
            "provider effect semantics are not exercised by deterministic fakes"
        ),
    },
}


def _git_sha(root: Path) -> str | None:
    """Return the checkout SHA when the environment exposes a valid one."""

    for variable in ("GITHUB_SHA", "CI_COMMIT_SHA"):
        value = os.environ.get(variable, "").strip()
        if _GIT_SHA_RE.fullmatch(value):
            return value.lower()
    git_executable = shutil.which("git")
    if git_executable is None:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - fixed git argv and local checkout
            [git_executable, "rev-parse", "--verify", "HEAD"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = completed.stdout.strip()
    if completed.returncode == 0 and _GIT_SHA_RE.fullmatch(value):
        return value.lower()
    return None


def _generated_at() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _source_fingerprint() -> dict[str, Any]:
    """Fingerprint the source and selectors represented by this mock report."""

    return source_fingerprint(ROOT, (*SOURCE_FINGERPRINT_ROOTS, "tests/unit"))


def _pytest(selectors: tuple[str, ...]) -> dict[str, Any]:
    started = time.perf_counter()
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and audited selectors
        [sys.executable, "-m", "pytest", "-q", *selectors],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    combined = f"{completed.stdout}\n{completed.stderr}"
    summaries = re.findall(r"\d+ passed(?:, \d+ skipped)?", combined)
    passed_matches = re.findall(r"(\d+) passed", combined)
    passed_count = int(passed_matches[-1]) if passed_matches else 0
    passed = completed.returncode == 0 and passed_count > 0
    if not passed:
        print(combined[-4000:], file=sys.stderr)
    return {
        "status": "pass" if passed else "fail",
        "exit_code": completed.returncode,
        "passed_count": passed_count,
        "duration_seconds": time.perf_counter() - started,
        "summary": summaries[-1] if summaries else "pytest did not report a pass summary",
    }


def _performance(output: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    completed = subprocess.run(  # noqa: S603 - fixed local script and interpreter
        [
            sys.executable,
            "-m",
            "scripts.performance_gate",
            "--callbacks",
            "500",
            "--turns",
            "200",
            "--concurrency",
            str(MAX_CONCURRENCY),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    try:
        report = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        report = {"gate": "fail", "rejection_reasons": [type(error).__name__]}
    result = {
        "status": "pass" if completed.returncode == 0 and report.get("gate") == "pass" else "fail",
        "exit_code": completed.returncode,
        "metrics": report.get("candidate", {}),
    }
    if result["status"] == "fail":
        print(f"{completed.stdout}\n{completed.stderr}"[-4000:], file=sys.stderr)
    return result, report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("runs/multitenant/production-mock.json"),
    )
    parser.add_argument(
        "--performance-output",
        type=Path,
        default=Path("runs/multitenant/performance-mock.json"),
    )
    args = parser.parse_args()

    performance, _ = _performance(args.performance_output)
    scenario_results: dict[str, dict[str, Any]] = {}
    for name, definition in SCENARIOS.items():
        result = _pytest(tuple(definition["selectors"]))
        result.update(
            {
                "emulates": definition["emulates"],
                "production_gap": definition["production_gap"],
                "selectors": list(definition["selectors"]),
            }
        )
        if name == "multinode_load":
            result["performance"] = performance
            if performance["status"] != "pass":
                result["status"] = "fail"
        scenario_results[name] = result

    failures = [name for name, result in scenario_results.items() if result["status"] != "pass"]
    simulation_gate = "fail" if failures else "pass"
    production_reasons = [
        "real multi-process load with PostgreSQL/Redis/MinIO/pgvector was not executed",
        "Toxiproxy network faults and operating-system process kills were not executed",
        "migration between independent live source and target backends was not executed",
        "Kubernetes rollout/HPA/eviction was not executed by a real control plane",
        "real WeCom and Feishu provider credentials and quotas were not exercised",
        "Cell trust roots, PostgreSQL CAS and external effect providers were not exercised",
    ]
    git_sha = _git_sha(ROOT)
    candidate_source = _source_fingerprint()
    result = {
        "generated_at": _generated_at(),
        "git_sha": git_sha,
        "git_sha_status": "available" if git_sha is not None else "unavailable",
        "source_fingerprint": candidate_source,
        "baseline": {
            "required_simulations": list(SCENARIOS),
            "all_simulations_must_pass": True,
            "mock_results_must_not_upgrade_production": True,
        },
        "candidate": {
            "mode": "deterministic_mock_without_external_credentials",
            "scenarios": scenario_results,
        },
        "case_deltas": {
            "total_simulations": len(scenario_results),
            "passed_simulations": len(scenario_results) - len(failures),
            "failed_simulations": failures,
        },
        "gate": simulation_gate,
        "simulation_gate": simulation_gate,
        "production_gate": "not_run",
        "rejection_reasons": [f"simulation failed: {name}" for name in failures],
        "production_rejection_reasons": production_reasons,
    }
    rendered = atomic_write_json(args.output, result).rstrip("\n")
    print(rendered)
    return 0 if simulation_gate == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
