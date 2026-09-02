from __future__ import annotations

from pathlib import Path

from scripts.evidence_lineage import (
    SOURCE_FINGERPRINT_ROOTS,
    SOURCE_FINGERPRINT_STATIC_FILES,
    source_fingerprint,
)

ROOT = Path(__file__).resolve().parents[2]
DOCKERIGNORE = ROOT / ".dockerignore"

FINGERPRINT_FILES = frozenset(
    {
        "build.sh",
        "clean.sh",
        "coverage.sh",
        "format.sh",
        "lint.sh",
        "lint_flake8.sh",
        "start.sh",
        "stop.sh",
    }
)
FINGERPRINT_DIRECTORIES = frozenset({".github/workflows"})
STATIC_RUN_FILES = frozenset(SOURCE_FINGERPRINT_STATIC_FILES)


def _dockerignore_rules() -> list[str]:
    return [
        line.strip()
        for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_known_source_fingerprint_roots_have_explicit_reincludes() -> None:
    rules = set(_dockerignore_rules())
    roots = set(SOURCE_FINGERPRINT_ROOTS)

    assert FINGERPRINT_FILES | FINGERPRINT_DIRECTORIES <= roots
    assert {f"!{path}" for path in FINGERPRINT_FILES} <= rules
    assert "!.github/" in rules
    assert {f"!{path}/" for path in FINGERPRINT_DIRECTORIES} <= rules
    assert {f"!{path}/**" for path in FINGERPRINT_DIRECTORIES} <= rules
    assert STATIC_RUN_FILES <= roots
    assert {f"!{path}" for path in STATIC_RUN_FILES} <= rules


def test_reincludes_stay_narrow_around_non_fingerprint_trees() -> None:
    rules = _dockerignore_rules()
    rule_set = set(rules)

    assert {"tests", "tests/**", "docs", "data"} <= rule_set
    assert not any(
        rule in {"!tests/**", "!docs/", "!docs/**", "!data/", "!data/**"} for rule in rules
    )
    assert not any(rule in {"!.github/**", "!*.sh"} for rule in rules)

    tests_reincludes = {rule for rule in rules if rule.startswith("!tests/")}
    assert tests_reincludes == {
        "!tests/",
        "!tests/integration/",
        "!tests/integration/**",
        "!tests/simulation/",
        "!tests/simulation/**",
    }


def test_static_run_inputs_are_reincluded_without_reopening_runs_tree() -> None:
    rules = set(_dockerignore_rules())
    roots = set(SOURCE_FINGERPRINT_ROOTS)

    assert {"!runs/", "runs/*", "!runs/multitenant/", "runs/multitenant/*"} <= rules
    assert "runs" not in roots
    assert "runs/multitenant" not in roots
    assert "!runs/**" not in rules
    assert "!runs/multitenant/**" not in rules
    assert "!deploy/runtime-gate.yaml" not in rules


def test_deploy_reinclude_reexcludes_host_bound_inputs_and_caches() -> None:
    rules = _dockerignore_rules()
    required = {
        "deploy/runtime-gate.yaml",
        "deploy/yqzl/*.env",
        "deploy/**/__pycache__/",
        "deploy/**/*.pyc",
    }

    assert required <= set(rules)
    broad_reinclude = rules.index("!deploy/**")
    assert all(broad_reinclude < rules.index(rule) for rule in required)


def test_static_run_inputs_change_source_fingerprint(tmp_path) -> None:
    for relative_path in SOURCE_FINGERPRINT_STATIC_FILES:
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("initial\n", encoding="utf-8")

    baseline = source_fingerprint(tmp_path)
    assert baseline["status"] == "available"
    assert baseline["file_count"] == len(SOURCE_FINGERPRINT_STATIC_FILES)

    for relative_path in SOURCE_FINGERPRINT_STATIC_FILES:
        path = tmp_path / relative_path
        path.write_text("changed: " + relative_path + "\n", encoding="utf-8")
        changed = source_fingerprint(tmp_path)
        assert changed["status"] == "available"
        assert changed["value"] != baseline["value"]
        path.write_text("initial\n", encoding="utf-8")


def test_private_and_generated_run_inputs_remain_excluded(tmp_path) -> None:
    for relative_path in SOURCE_FINGERPRINT_STATIC_FILES:
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("static\n", encoding="utf-8")

    ignored_paths = (
        "runs/multitenant/coverage.json",
        "runs/multitenant/runtime-gate.yaml",
        "runs/multitenant/.ack-runtime-private/secret.yaml",
        "deploy/runtime-gate.yaml",
        "deploy/yqzl/admin.env",
        "deploy/yqzl/gateway.env",
        "deploy/yqzl/runtime.env",
    )
    for relative_path in ignored_paths:
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("initial\n", encoding="utf-8")

    baseline = source_fingerprint(tmp_path)
    for relative_path in ignored_paths:
        path = tmp_path / relative_path
        path.write_text("changed and still excluded\n", encoding="utf-8")
        changed = source_fingerprint(tmp_path)
        assert changed["status"] == "available"
        assert changed["value"] == baseline["value"]
        assert changed["file_count"] == baseline["file_count"]
