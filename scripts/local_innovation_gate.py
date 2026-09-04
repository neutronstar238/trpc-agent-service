#!/usr/bin/env python3
# ruff: noqa: E402
"""Run the credential-free local acceptance gate for Cell Fabric innovation.

The gate owns the evidence envelope, not the evolution implementation.  It
records checkout lineage and the offline/production boundary, then discovers
an optional evolution-demo hook at runtime.  Keeping the hook optional lets
the harness land before the Proof-Carrying Evolution domain is complete;
once a supported hook exists it is executed in simulate-only mode when its
signature exposes that option.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import inspect
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

# A direct ``python scripts/local_innovation_gate.py`` launch puts ``scripts``
# at ``sys.path[0]``.  Pin imports to the checkout owning this file so an
# older checkout on PYTHONPATH cannot provide the evidence helpers.
_REPO_IMPORT_ROOT = Path(__file__).resolve().parents[1]
_REPO_IMPORT_ROOT_STR = str(_REPO_IMPORT_ROOT)
while _REPO_IMPORT_ROOT_STR in sys.path:
    sys.path.remove(_REPO_IMPORT_ROOT_STR)
sys.path.insert(0, _REPO_IMPORT_ROOT_STR)

from scripts.evidence_lineage import SOURCE_FINGERPRINT_ROOTS, source_fingerprint
from scripts.report_io import atomic_write_json

ROOT = _REPO_IMPORT_ROOT
_GIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_VALID_STATUSES = frozenset({"pass", "fail", "not_run"})
_DEMO_TARGETS: tuple[tuple[str, str], ...] = (
    ("scripts.cell_evolve_demo", "run_demo"),
    ("trpc_service.cell.evolution", "run_demo"),
    ("trpc_service.cell.evolution", "run_evolution_demo"),
)
_PRODUCTION_REASONS = [
    "real PostgreSQL/RLS CAS and authority roles were not exercised",
    "real provider reconciliation and non-idempotent provider semantics were not exercised",
    "real IM, model, KMS, or supplier credentials were not used",
    "multi-process scheduling, rollout, and rollback were not exercised",
]

# Keep the optional hook opaque to the report builder without propagating an
# ``Any`` return through the gate's typed helpers.  Demo payloads are validated
# at the mapping boundary in ``_normalise_demo_result``.
DemoCallable = Callable[..., object]


def _git_sha(root: Path) -> str | None:
    """Return a valid checkout SHA from CI metadata or local git."""

    for variable in ("GITHUB_SHA", "CI_COMMIT_SHA"):
        value = os.environ.get(variable, "").strip()
        if _GIT_SHA_RE.fullmatch(value):
            return value.lower()
    git_executable = shutil.which("git")
    if git_executable is None:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - fixed local git argv
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


def _source_fingerprint() -> dict[str, Any]:
    """Fingerprint source and unit-test inputs represented by this gate."""

    return source_fingerprint(ROOT, (*SOURCE_FINGERPRINT_ROOTS, "tests/unit"))


def _generated_at() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_text(value: Any, *, limit: int = 512) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:limit]


def _safe_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    validated_value: int = value
    return validated_value


def _status(value: Any) -> str | None:
    return value if isinstance(value, str) and value in _VALID_STATUSES else None


def _safe_case_name(value: Any) -> str:
    if isinstance(value, str) and _SAFE_NAME_RE.fullmatch(value):
        return value
    return "unnamed_case"


def _safe_string_list(value: Any) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [item for item in (_safe_text(item, limit=256) for item in value) if item is not None]


def _normalise_demo_case(name: Any, value: Any) -> dict[str, Any]:
    """Keep only bounded, non-sensitive fields from an optional demo case."""

    case: dict[str, Any] = {"name": _safe_case_name(name)}
    if not isinstance(value, Mapping):
        case.update({"status": "fail", "reason": "demo case is not a mapping"})
        return case
    case_status = _status(value.get("status")) or _status(value.get("gate"))
    case["status"] = case_status or "fail"
    reason = _safe_text(value.get("reason")) or _safe_text(value.get("message"))
    if reason is not None:
        case["reason"] = reason
    assertions = _safe_string_list(value.get("assertions"))
    if assertions:
        case["assertions"] = assertions
    rejections = _safe_string_list(value.get("rejection_reasons"))
    if rejections:
        case["rejection_reasons"] = rejections
    for key in (
        "evidence_digest",
        "source_digest",
        "baseline_output_hash",
        "candidate_output_hash",
    ):
        text_value = _safe_text(value.get(key), limit=256)
        if text_value is not None:
            case[key] = text_value
    for key in (
        "provider_call_count",
        "real_provider_calls",
        "external_call_count",
        "side_effect_count",
    ):
        int_value = _safe_int(value.get(key))
        if int_value is not None:
            case[key] = int_value
    return case


def _normalise_demo_result(value: Any, *, module: str) -> dict[str, Any]:
    """Convert a demo result into the gate's safe, stable report shape."""

    if not isinstance(value, Mapping):
        return {
            "name": "core_evolution_demo",
            "status": "fail",
            "module": module,
            "reason": "core evolution demo did not return a mapping",
        }

    result: dict[str, Any] = {
        "name": "core_evolution_demo",
        "module": module,
    }
    result_status = _status(value.get("offline_gate")) or _status(value.get("gate"))
    cases_value = value.get("cases", value.get("case_results"))
    safe_cases: list[dict[str, Any]] = []
    if isinstance(cases_value, Mapping):
        safe_cases = [_normalise_demo_case(key, item) for key, item in cases_value.items()]
    elif isinstance(cases_value, Sequence) and not isinstance(cases_value, (str, bytes, bytearray)):
        for item in cases_value:
            if isinstance(item, Mapping):
                safe_cases.append(_normalise_demo_case(item.get("name"), item))
    if safe_cases:
        result["cases"] = safe_cases
        if any(item["status"] == "fail" for item in safe_cases):
            result_status = "fail"
        elif result_status is None and all(item["status"] == "pass" for item in safe_cases):
            result_status = "pass"

    reason = _safe_text(value.get("reason")) or _safe_text(value.get("message"))
    if reason is not None:
        result["reason"] = reason
    rejections = _safe_string_list(value.get("rejection_reasons"))
    if rejections:
        result["rejection_reasons"] = rejections

    provider_calls: list[int] = []
    for key in (
        "provider_call_count",
        "provider_calls",
        "real_provider_calls",
        "external_call_count",
        "side_effect_count",
    ):
        int_value = _safe_int(value.get(key))
        if int_value is not None:
            result[key] = int_value
            provider_calls.append(int_value)
    if provider_calls and any(item != 0 for item in provider_calls):
        result_status = "fail"
        result["reason"] = "core evolution demo reported a real external call"

    result["status"] = result_status or "fail"
    if result["status"] == "fail" and "reason" not in result:
        result["reason"] = "core evolution demo did not report offline success"
    return result


def _load_demo(module_name: str, callable_name: str) -> tuple[DemoCallable | None, str | None]:
    """Load an optional demo hook without importing it at module import time."""

    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as error:
        if error.name == module_name or (
            isinstance(error.name, str) and module_name.startswith(f"{error.name}.")
        ):
            return None, "optional core evolution demo is not available"
        return None, f"optional core evolution demo import failed: {type(error).__name__}"
    except Exception as error:
        return None, f"optional core evolution demo import failed: {type(error).__name__}"
    callback = getattr(module, callable_name, None)
    if not callable(callback):
        return None, f"optional hook {callable_name!r} is not defined"
    return callback, None


def _invoke_demo(callback: DemoCallable) -> object:
    """Invoke a demo while requesting its explicit simulate-only mode."""

    kwargs: dict[str, Any] = {}
    try:
        signature = inspect.signature(callback)
        parameters = signature.parameters
        accepts_kwargs = any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()
        )
        simulate_parameter = parameters.get("simulate_only")
        mode_parameter = parameters.get("mode")
        offline_parameter = parameters.get("offline")
        if (
            simulate_parameter is not None
            and simulate_parameter.kind is not inspect.Parameter.POSITIONAL_ONLY
        ) or accepts_kwargs:
            kwargs["simulate_only"] = True
        elif (
            mode_parameter is not None
            and mode_parameter.kind is not inspect.Parameter.POSITIONAL_ONLY
        ):
            kwargs["mode"] = "simulate_only"
        elif (
            offline_parameter is not None
            and offline_parameter.kind is not inspect.Parameter.POSITIONAL_ONLY
        ):
            kwargs["offline"] = True
    except (TypeError, ValueError):
        # Builtins and some extension callables do not expose a signature;
        # calling them without arguments is the least surprising fallback.
        pass
    result = callback(**kwargs)
    if inspect.isawaitable(result):
        return asyncio.run(_await_demo(cast(Awaitable[object], result)))
    return result


async def _await_demo(result: Awaitable[object]) -> object:
    return await result


def _run_core_demo(
    mode: str,
    *,
    module_name: str | None = None,
    callable_name: str = "run_demo",
) -> dict[str, Any]:
    if mode == "skip":
        return {
            "name": "core_evolution_demo",
            "status": "not_run",
            "reason": "core evolution demo was disabled by the operator",
        }
    targets = ((module_name, callable_name),) if module_name else _DEMO_TARGETS
    reasons: list[str] = []
    for target_module, target_callable in targets:
        callback, reason = _load_demo(target_module, target_callable)
        if callback is None:
            if reason is not None:
                reasons.append(f"{target_module}: {reason}")
            continue
        try:
            value = _invoke_demo(callback)
        except Exception as error:
            return {
                "name": "core_evolution_demo",
                "status": "fail",
                "module": target_module,
                "reason": f"core evolution demo raised {type(error).__name__}",
            }
        return _normalise_demo_result(value, module=target_module)
    return {
        "name": "core_evolution_demo",
        "status": "not_run",
        "reason": "; ".join(reasons)[:1024] or "optional core evolution demo is not available",
    }


def _lineage_case(git_sha: str | None, fingerprint: Mapping[str, Any]) -> dict[str, Any]:
    fingerprint_available = (
        fingerprint.get("algorithm") == "sha256"
        and fingerprint.get("status") == "available"
        and isinstance(fingerprint.get("value"), str)
    )
    case: dict[str, Any] = {
        "name": "candidate_lineage",
        "status": "pass" if fingerprint_available else "fail",
        "assertions": [
            "git SHA is recorded when local git or CI metadata provides it",
            "source fingerprint is content-addressed and bounded",
        ],
        "git_sha_status": "available" if git_sha is not None else "unavailable",
        "source_fingerprint_status": fingerprint.get("status", "unavailable"),
    }
    if not fingerprint_available:
        case["reason"] = "source fingerprint is unavailable"
    elif git_sha is None:
        case["reason"] = "git SHA is unavailable; source fingerprint remains authoritative"
    return case


def _scope_case() -> dict[str, Any]:
    return {
        "name": "offline_scope",
        "status": "pass",
        "assertions": [
            "the gate does not contact PostgreSQL, Kubernetes, IM, model, KMS, or providers",
            "the gate does not consume credentials or create external side effects",
            "production status remains not_run regardless of offline results",
        ],
        "external_calls": 0,
        "credentials_used": False,
    }


def _case_counts(cases: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    counts = {"total": len(cases), "pass": 0, "fail": 0, "not_run": 0}
    for case in cases:
        status = case.get("status")
        if status in _VALID_STATUSES:
            counts[status] += 1
    return counts


def build_report(
    *,
    demo_mode: str = "auto",
    require_core_demo: bool = False,
    demo_module: str | None = None,
    demo_callable: str = "run_demo",
) -> dict[str, Any]:
    """Build a local innovation report without performing production actions."""

    git_sha = _git_sha(ROOT)
    fingerprint = _source_fingerprint()
    cases: list[dict[str, Any]] = [
        _lineage_case(git_sha, fingerprint),
        _scope_case(),
        _run_core_demo(
            "required" if require_core_demo else demo_mode,
            module_name=demo_module,
            callable_name=demo_callable,
        ),
    ]
    failures = [
        str(case.get("name", "unnamed_case")) for case in cases if case.get("status") == "fail"
    ]
    demo_not_run = cases[-1].get("status") == "not_run"
    if require_core_demo and demo_not_run:
        cases[-1]["status"] = "fail"
        cases[-1]["reason"] = "core evolution demo is required but unavailable"
        failures.append("core_evolution_demo")
    offline_gate = "fail" if failures else "pass"
    return {
        "schema_version": 1,
        "kind": "local_innovation_gate",
        "generated_at": _generated_at(),
        "git_sha": git_sha,
        "git_sha_status": "available" if git_sha is not None else "unavailable",
        "source_fingerprint": dict(fingerprint),
        "scope": {
            "mode": "offline",
            "development": "pass" if offline_gate == "pass" else "fail",
            "credentials_used": False,
            "external_calls": 0,
            "production_actions": False,
        },
        "cases": cases,
        "case_counts": _case_counts(cases),
        "gate": offline_gate,
        "offline_gate": offline_gate,
        "development_gate": offline_gate,
        "production_gate": "not_run",
        "rejection_reasons": [f"offline case failed: {name}" for name in failures],
        "production_rejection_reasons": list(_PRODUCTION_REASONS),
        "core_demo": {
            "required": require_core_demo,
            "optional_when_mode_is_auto": True,
            "simulate_only_requested": True,
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("runs/multitenant/local-innovation-gate.json"),
        help="JSON report path",
    )
    parser.add_argument(
        "--core-demo",
        choices=("auto", "skip"),
        default="auto",
        help="discover and run the optional local evolution demo (default: auto)",
    )
    parser.add_argument(
        "--require-core-demo",
        action="store_true",
        help="fail when the optional evolution demo hook is not available",
    )
    parser.add_argument(
        "--demo-module",
        help="override the optional demo module for local API adaptation",
    )
    parser.add_argument(
        "--demo-callable",
        default="run_demo",
        help="callable exported by --demo-module (default: run_demo)",
    )
    args = parser.parse_args(argv)
    report = build_report(
        demo_mode=args.core_demo,
        require_core_demo=args.require_core_demo,
        demo_module=args.demo_module,
        demo_callable=args.demo_callable,
    )
    rendered = atomic_write_json(args.output, report).rstrip("\n")
    print(rendered)
    return 0 if report["offline_gate"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
