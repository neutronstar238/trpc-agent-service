from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STAGE1 = ROOT / "runs/multitenant/run-final-ack-performance.ps1"
FORMAL_ENTRY = ROOT / "runs/multitenant/run-current-final-acceptance.ps1"

CANONICAL_INITIAL = "sha256:ef3bd5c94fe8fdf748019fa40fa21a1b21c9de0f1b8d534451c40ca5bb4dede9"
CANONICAL_UPGRADE = "sha256:87e5d418ed0fb4de1e61d35c343b2aac94ab79438ba566f4a2121a359286c335"
CONTEXT_INITIAL = CANONICAL_INITIAL
CONTEXT_UPGRADE = CANONICAL_UPGRADE
CONTEXT_NAME = "release-context-da1d5d43d852-amd64.json"


def test_stage1_reuses_verified_context_and_binds_canonical_index_digests() -> None:
    stage1 = STAGE1.read_text(encoding="utf-8")
    formal_entry = FORMAL_ENTRY.read_text(encoding="utf-8")

    assert CONTEXT_NAME in stage1
    assert CONTEXT_NAME in formal_entry
    assert "scripts/release_context.py verify" in stage1
    assert "scripts/release_context.py ensure" not in stage1

    assert f'$imageDigest = "{CANONICAL_INITIAL}"' in stage1
    assert f'$upgradeDigest = "{CANONICAL_UPGRADE}"' in stage1
    assert f'$releaseContextInitialDigest = "{CONTEXT_INITIAL}"' in stage1
    assert f'$releaseContextUpgradeDigest = "{CONTEXT_UPGRADE}"' in stage1

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
