#!/usr/bin/env python3
# ruff: noqa: E402
"""Enforce line and branch coverage independently."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Keep direct-file invocation isolated from another checkout that may be on
# ``PYTHONPATH``.  ``python -m scripts.check_coverage`` follows the same
# checkout because this path is already the module's owning repository.
_REPO_IMPORT_ROOT = Path(__file__).resolve().parents[1]

_REPO_IMPORT_ROOT_STR = str(_REPO_IMPORT_ROOT)
while _REPO_IMPORT_ROOT_STR in sys.path:
    sys.path.remove(_REPO_IMPORT_ROOT_STR)
sys.path.insert(0, _REPO_IMPORT_ROOT_STR)

from scripts.evidence_lineage import SOURCE_FINGERPRINT_ROOTS, source_fingerprint
from scripts.report_io import atomic_write_json

_GIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")


def _git_sha(root: Path) -> str | None:
    """Return a trusted checkout SHA, when the execution environment exposes one."""

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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--minimum", type=float, default=90.0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--test-scope", default="tests/unit")
    args = parser.parse_args()
    report_bytes = args.report.read_bytes()
    totals = json.loads(report_bytes)["totals"]
    line = float(totals["percent_statements_covered"])
    branch = float(totals["percent_branches_covered"])
    root = _REPO_IMPORT_ROOT
    fingerprint = source_fingerprint(
        root,
        (*SOURCE_FINGERPRINT_ROOTS, "tests/unit"),
    )
    rejection_reasons = [
        name
        for name, value in (("line_coverage", line), ("branch_coverage", branch))
        if value < args.minimum
    ]
    if fingerprint.get("status") != "available":
        rejection_reasons.append("source_fingerprint")
    result: dict[str, Any] = {
        "generated_at": _generated_at(),
        "test_scope": args.test_scope,
        "git_sha": _git_sha(root),
        "coverage_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "source_fingerprint": fingerprint,
        "baseline": {"line_percent": args.minimum, "branch_percent": args.minimum},
        "candidate": {"line_percent": line, "branch_percent": branch},
        "case_deltas": {
            "line_percent": line - args.minimum,
            "branch_percent": branch - args.minimum,
        },
        "gate": "pass" if not rejection_reasons else "fail",
        "rejection_reasons": rejection_reasons,
    }
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        rendered = atomic_write_json(args.output, result).rstrip("\n")
    print(rendered)
    return 0 if result["gate"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
