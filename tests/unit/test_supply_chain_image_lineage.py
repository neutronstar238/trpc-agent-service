from __future__ import annotations

import json
from typing import Any

import pytest

import scripts.supply_chain_gate as gate


class _Completed:
    returncode = 0

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


def test_image_metadata_requires_source_fingerprint_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "sha256:" + "a" * 64
    monkeypatch.setattr(gate.shutil, "which", lambda _name: "docker")
    monkeypatch.setattr(
        gate.subprocess,
        "run",
        lambda *_args, **_kwargs: _Completed(digest + "|"),
    )

    observed_digest, fingerprint, reason = gate._image_metadata("candidate:local")

    assert observed_digest == digest
    assert fingerprint is None
    assert reason == "image source fingerprint label was not available"


def test_image_metadata_returns_only_digest_and_valid_source_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "sha256:" + "a" * 64
    fingerprint = "b" * 64
    command: list[Any] = []
    monkeypatch.setattr(gate.shutil, "which", lambda _name: "docker")

    def fake_run(arguments: list[str], **_kwargs: object) -> _Completed:
        command.extend(arguments)
        return _Completed(f"{digest}|{fingerprint}\n")

    monkeypatch.setattr(gate.subprocess, "run", fake_run)

    observed_digest, observed_fingerprint, reason = gate._image_metadata("candidate:local")

    assert observed_digest == digest
    assert observed_fingerprint == fingerprint
    assert reason is None
    assert gate._SOURCE_LABEL in command[-1]


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"dependencies": []}, "dependency audit evidence has no dependency list"),
        (
            {"dependencies": [{"name": "demo", "version": "1.0"}]},
            "dependency audit evidence contains an incomplete dependency",
        ),
        (
            {"dependencies": [{"name": "demo", "version": "1.0", "vulns": [{"id": "CVE"}]}]},
            "dependency audit evidence reports vulnerabilities",
        ),
    ],
)
def test_dependency_report_rejects_empty_malformed_or_vulnerable_evidence(
    tmp_path: Any,
    payload: dict[str, Any],
    expected: str,
) -> None:
    path = tmp_path / "dependency-audit.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert gate._dependency_report(path) == expected


def test_dependency_report_accepts_complete_pip_audit_evidence(tmp_path: Any) -> None:
    path = tmp_path / "dependency-audit.json"
    path.write_text(
        json.dumps(
            {
                "dependencies": [
                    {"name": "demo", "version": "1.0", "vulns": []},
                ]
            }
        ),
        encoding="utf-8",
    )

    assert gate._dependency_report(path) is None


def test_sarif_requires_trivy_image_digest_binding(tmp_path: Any) -> None:
    digest = "sha256:" + "a" * 64
    path = tmp_path / "trivy.sarif.json"
    path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "results": [],
                        "properties": {"imageID": digest},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    assert gate._sarif_findings(path, digest) == (0, 1)
    with pytest.raises(ValueError, match="different image digest"):
        gate._sarif_findings(path, "sha256:" + "b" * 64)


def test_sarif_rejects_missing_image_provenance(tmp_path: Any) -> None:
    path = tmp_path / "trivy.sarif.json"
    path.write_text(
        json.dumps({"version": "2.1.0", "runs": [{"results": []}]}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="without image provenance"):
        gate._sarif_findings(path, "sha256:" + "a" * 64)


def test_sbom_provenance_is_explicitly_unbound_when_spdx_has_no_image_digest() -> None:
    assert gate._sbom_provenance({"packages": [{"name": "demo"}]}, None) == (
        None,
        "unbound",
        None,
    )


def test_sbom_provenance_rejects_explicit_digest_mismatch() -> None:
    candidate = "sha256:" + "a" * 64
    other = "sha256:" + "b" * 64

    digest, status, reason = gate._sbom_provenance({"metadata": {"imageID": other}}, candidate)

    assert digest == other
    assert status == "mismatch"
    assert reason == "SBOM image digest does not match the candidate image"
