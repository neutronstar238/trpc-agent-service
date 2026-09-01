from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STAGE1 = ROOT / "runs/multitenant/run-final-ack-performance.ps1"
FORMAL_ENTRY = ROOT / "runs/multitenant/run-current-final-acceptance.ps1"

_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def _assignment(script: str, name: str) -> str:
    match = re.search(rf'^\${re.escape(name)}\s*=\s*"([^"]+)"$', script, re.MULTILINE)
    assert match is not None
    return match.group(1)


def _release_context_name(script: str) -> str:
    match = re.search(
        r'^\$privateReleaseContext\s*=.*"[^"]*/(release-context-[^"]+)"$',
        script,
        re.MULTILINE,
    )
    assert match is not None
    return match.group(1)


def test_stage1_reuses_verified_context_and_binds_canonical_index_digests() -> None:
    stage1 = STAGE1.read_text(encoding="utf-8")
    formal_entry = FORMAL_ENTRY.read_text(encoding="utf-8")

    initial_digest = _assignment(stage1, "imageDigest")
    upgrade_digest = _assignment(stage1, "upgradeDigest")
    context_initial = _assignment(stage1, "releaseContextInitialDigest")
    context_upgrade = _assignment(stage1, "releaseContextUpgradeDigest")
    context_name = _release_context_name(stage1)

    assert context_name.startswith("release-context-")
    assert context_name.endswith("-amd64.json")
    assert context_name in formal_entry
    assert "scripts/release_context.py verify" in stage1
    assert "scripts/release_context.py ensure" not in stage1

    assert _DIGEST_PATTERN.fullmatch(initial_digest)
    assert _DIGEST_PATTERN.fullmatch(upgrade_digest)
    assert initial_digest != upgrade_digest
    assert context_initial == initial_digest
    assert context_upgrade == upgrade_digest

    verify_block = stage1.split("scripts/release_context.py verify", 1)[1].split(
        "$releaseContext =", 1
    )[0]
    assert "--private-context $privateReleaseContext" in verify_block
    assert "--initial-digest $releaseContextInitialDigest" in verify_block
    assert "--upgrade-digest $releaseContextUpgradeDigest" in verify_block

    binding_block = stage1.split("bind_published_candidate.py", 1)[1].split("if ($LASTEXITCODE", 1)[
        0
    ]
    assert "--initial-digest $imageDigest" in binding_block
    assert "--upgrade-digest $upgradeDigest" in binding_block
    assert "--initial-digest $releaseContextInitialDigest" not in binding_block
    assert "--upgrade-digest $releaseContextUpgradeDigest" not in binding_block

    render_check = stage1.split("$renderedText", 1)[1].split("Invoke-Kubectl", 1)[0]
    assert "$imageDigest" in render_check


def test_stage1_failure_summary_tolerates_missing_optional_metrics() -> None:
    stage1 = STAGE1.read_text(encoding="utf-8")

    assert "function Get-OptionalPropertyValue" in stage1
    assert "$performanceReport.candidate.burst." not in stage1
    assert "$performanceReport.candidate.sustained." not in stage1
    assert "if ($gateExit -ne 0)" in stage1
    assert 'throw "formal ACK Performance gate failed; no automatic rerun was attempted"' in stage1
