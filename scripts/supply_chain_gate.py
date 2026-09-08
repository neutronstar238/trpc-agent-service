#!/usr/bin/env python3
# ruff: noqa: E402
"""Aggregate complete SBOM, SARIF, dependency, and image lineage evidence."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

# Direct file execution otherwise places ``scripts/`` before the checkout
# root, allowing a different checkout supplied through ``PYTHONPATH`` to
# satisfy the namespace import below.
_REPO_IMPORT_ROOT = Path(__file__).resolve().parents[1]
_REPO_IMPORT_ROOT_STR = str(_REPO_IMPORT_ROOT)
while _REPO_IMPORT_ROOT_STR in sys.path:
    sys.path.remove(_REPO_IMPORT_ROOT_STR)
sys.path.insert(0, _REPO_IMPORT_ROOT_STR)

from scripts.evidence_lineage import source_fingerprint
from scripts.report_io import atomic_write_json

ROOT = _REPO_IMPORT_ROOT
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_LABEL = "io.trpc.agent-service.source-fingerprint"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _sarif_paths(value: Path) -> tuple[Path, ...]:
    if value.is_dir():
        return tuple(sorted(value.rglob("*.sarif.json")))
    return (value,)


def _sarif_findings(
    path: Path,
    expected_image_digest: str | None = None,
) -> tuple[int, int]:
    """Return (finding_count, run_count), rejecting incomplete/unbound SARIF.

    Trivy writes the Docker-reported image identity to ``runs[].properties.imageID``.
    Depending on the image store this can be a config or manifest digest; use
    ``docker inspect .Id`` rather than substituting a BuildKit config digest.
    This is deliberately checked for every run: a clean SARIF file from a
    different image must never be accepted as evidence for the candidate.
    ``expected_image_digest`` is optional for callers that only validate SARIF
    syntax; the production gate passes the digest read from ``docker inspect``.
    """

    document = _load(path)
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError(f"{path} has no SARIF runs")
    findings = 0
    for run in runs:
        if not isinstance(run, dict) or not isinstance(run.get("results"), list):
            raise ValueError(f"{path} contains a malformed SARIF run")
        properties = run.get("properties")
        if not isinstance(properties, dict):
            raise ValueError(f"{path} contains a SARIF run without image provenance")
        image_id = properties.get("imageID")
        if not isinstance(image_id, str) or _DIGEST_RE.fullmatch(image_id) is None:
            raise ValueError(f"{path} contains an invalid Trivy imageID")
        if expected_image_digest is not None and image_id != expected_image_digest:
            raise ValueError(f"{path} is bound to a different image digest")
        if any(not isinstance(result, dict) for result in run["results"]):
            raise ValueError(f"{path} contains a malformed SARIF result")
        findings += len(run["results"])
    return findings, len(runs)


def _image_metadata(image: str | None) -> tuple[str | None, str | None, str | None]:
    if not image:
        return None, None, "image reference was not supplied"
    executable = shutil.which("docker")
    if executable is None:
        return None, None, "docker is not installed; image lineage is unavailable"
    try:
        result = subprocess.run(  # noqa: S603 - executable and fixed arguments
            [
                executable,
                "image",
                "inspect",
                image,
                "--format",
                f'{{{{.Id}}}}|{{{{index .Config.Labels "{_SOURCE_LABEL}"}}}}',
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, None, "docker image inspection was unavailable"
    digest, separator, fingerprint = result.stdout.strip().partition("|")
    if result.returncode != 0 or not separator or _DIGEST_RE.fullmatch(digest) is None:
        return None, None, "image digest was not available"
    if _FINGERPRINT_RE.fullmatch(fingerprint) is None:
        return digest, None, "image source fingerprint label was not available"
    return digest, fingerprint, None


def _image_digest(image: str | None) -> tuple[str | None, str | None]:
    """Compatibility wrapper used by older callers and tests."""

    digest, _fingerprint, reason = _image_metadata(image)
    return digest, reason


def _dependency_report(path: Path) -> str | None:
    """Validate the dependency-audit envelope without echoing package data."""

    try:
        value = _load(path)
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as error:
        return f"dependency audit evidence is invalid: {type(error).__name__}"
    # pip-audit JSON currently uses ``dependencies``; ``results`` keeps this
    # gate compatible with older wrapper formats while still rejecting an
    # empty/malformed success artifact.
    dependencies = value.get("dependencies")
    if dependencies is None:
        dependencies = value.get("results")
    if not isinstance(dependencies, list) or not dependencies:
        return "dependency audit evidence has no dependency list"
    for item in dependencies:
        if not isinstance(item, dict):
            return "dependency audit evidence contains a malformed dependency"
        name = item.get("name")
        version = item.get("version")
        vulnerabilities = item.get("vulns")
        if (
            not isinstance(name, str)
            or not name.strip()
            or not isinstance(version, str)
            or not version.strip()
            or not isinstance(vulnerabilities, list)
        ):
            return "dependency audit evidence contains an incomplete dependency"
        if vulnerabilities:
            return "dependency audit evidence reports vulnerabilities"
    return None


def _sbom_provenance(
    value: dict[str, Any],
    expected_image_digest: str | None,
) -> tuple[str | None, str, str | None]:
    """Inspect optional SBOM image provenance without inventing a binding.

    SPDX JSON produced by Syft normally inventories packages but does not
    carry the Docker-reported image digest. In that case we report ``unbound``;
    Trivy remains the authoritative image-ID binding. If a producer does
    provide an image digest in one of the common provenance fields, it is
    validated and a mismatch fails closed.
    """

    candidates: list[Any] = []
    for container in (
        value,
        value.get("metadata"),
        value.get("properties"),
    ):
        if isinstance(container, dict):
            candidates.extend(
                container.get(key)
                for key in ("imageID", "imageId", "imageDigest", "image_digest")
                if key in container
            )
    annotations = value.get("annotations")
    if isinstance(annotations, list):
        for annotation in annotations:
            if not isinstance(annotation, dict):
                continue
            key = annotation.get("key", annotation.get("name"))
            if key in {"imageID", "imageId", "imageDigest", "image_digest"}:
                candidates.append(annotation.get("value"))
    if not candidates:
        return None, "unbound", None
    unique_candidates: list[Any] = []
    for candidate in candidates:
        if candidate not in unique_candidates:
            unique_candidates.append(candidate)
    if len(unique_candidates) != 1 or not isinstance(unique_candidates[0], str):
        return None, "invalid", "SBOM image provenance is malformed"
    digest = unique_candidates[0]
    if _DIGEST_RE.fullmatch(digest) is None:
        return None, "invalid", "SBOM image provenance is not a sha256 digest"
    if expected_image_digest is not None and digest != expected_image_digest:
        return digest, "mismatch", "SBOM image digest does not match the candidate image"
    return digest, "verified", None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sbom", type=Path, default=Path("runs/multitenant/sbom.spdx.json"))
    parser.add_argument(
        "--vulnerabilities",
        type=Path,
        default=Path("runs/multitenant/image-vulnerabilities.sarif.json"),
        help="SARIF file or directory; every *.sarif.json file/run is scanned",
    )
    parser.add_argument("--image", default=None, help="candidate image reference to inspect")
    parser.add_argument(
        "--dependency-audit-status",
        choices=("pass", "fail", "not_run"),
        default="not_run",
    )
    parser.add_argument(
        "--dependency-audit",
        type=Path,
        default=Path("runs/multitenant/dependency-audit.json"),
    )
    parser.add_argument(
        "--dependency-audit-reason",
        default="standalone dependency audit has no passing report",
    )
    parser.add_argument("--output", type=Path, default=Path("runs/multitenant/supply-chain.json"))
    parser.add_argument("--require-production", action="store_true")
    args = parser.parse_args()

    evidence_error: str | None
    package_count = 0
    finding_count = -1
    sarif_run_count = 0
    sbom_image_digest: str | None = None
    sbom_provenance_status = "unavailable"
    evidence_detail: str | None = None
    image_digest, image_source_fingerprint, image_reason = _image_metadata(args.image)
    report_paths = _sarif_paths(args.vulnerabilities)
    try:
        sbom = _load(args.sbom)
        packages = sbom.get("packages")
        if not isinstance(packages, list):
            raise ValueError("SBOM packages is not a list")
        package_count = len(packages)
        (
            sbom_image_digest,
            sbom_provenance_status,
            sbom_provenance_error,
        ) = _sbom_provenance(sbom, image_digest)
        if sbom_provenance_error:
            raise ValueError(sbom_provenance_error)
        if not report_paths:
            raise ValueError("no SARIF reports were found")
        finding_count = 0
        for report_path in report_paths:
            findings, runs = _sarif_findings(report_path, image_digest)
            finding_count += findings
            sarif_run_count += runs
    except (OSError, ValueError, json.JSONDecodeError, AttributeError, TypeError) as error:
        package_count = 0
        finding_count = -1
        evidence_error = type(error).__name__
        evidence_detail = str(error)
    else:
        evidence_error = None

    source = source_fingerprint(ROOT)
    lock = source_fingerprint(ROOT, ("pyproject.toml", "uv.lock"))
    dependency_reason = (
        _dependency_report(args.dependency_audit)
        if args.dependency_audit_status == "pass"
        else None
    )
    source_lineage_pass = source.get("status") == "available"
    image_source_matches = source_lineage_pass and image_source_fingerprint == source.get("value")
    image_lineage_pass = image_digest is not None and image_source_matches
    lock_lineage_pass = lock.get("status") == "available"
    image_passed = (
        evidence_error is None
        and package_count > 0
        and finding_count == 0
        and image_lineage_pass
        and source_lineage_pass
        and lock_lineage_pass
    )
    dependency_status = args.dependency_audit_status
    if dependency_reason:
        gate = "fail"
    elif not image_passed or dependency_status == "fail":
        gate = "fail"
    elif dependency_status == "pass":
        gate = "pass"
    else:
        gate = "not_run"

    reasons: list[str] = []
    if evidence_error:
        detail = f": {evidence_detail}" if evidence_detail else ""
        reasons.append(f"SBOM or SARIF evidence is invalid: {evidence_error}{detail}")
    elif package_count == 0:
        reasons.append("SBOM contains no packages")
    elif finding_count:
        reasons.append(f"image contains {finding_count} critical/high vulnerability findings")
    if image_reason:
        reasons.append(image_reason)
    elif not image_source_matches:
        reasons.append("image source fingerprint does not match the current checkout")
    if not lock_lineage_pass:
        reasons.append("pyproject.toml/uv.lock lineage is unavailable")
    if not source_lineage_pass:
        reasons.append("source checkout lineage is unavailable")
    if dependency_status != "pass":
        reasons.append(args.dependency_audit_reason)
    if dependency_reason:
        reasons.append(dependency_reason)

    result = {
        "baseline": {
            "sbom_required": True,
            "critical_high_vulnerabilities_max": 0,
            "dependency_audit_required": True,
            "image_digest_required": True,
            "image_source_fingerprint_required": True,
            "all_sarif_runs_scanned": True,
        },
        "candidate": {
            "sbom": str(args.sbom),
            "sbom_provenance": {
                "status": sbom_provenance_status,
                "image_digest": sbom_image_digest,
                "digest_binding": "trivy_sarif_imageID",
            },
            # Preserve the old singular consumer field while the plural field
            # records every SARIF input scanned by this gate.
            "vulnerability_report": str(report_paths[0]) if report_paths else None,
            "sbom_packages": package_count,
            "vulnerability_reports": [str(path) for path in report_paths],
            "sarif_runs": sarif_run_count,
            "critical_high_vulnerabilities": finding_count,
            "dependency_audit": dependency_status,
            "dependency_audit_report": str(args.dependency_audit),
            "image": {
                "configured": bool(args.image),
                "digest": image_digest,
                "source_fingerprint": image_source_fingerprint,
                "source_fingerprint_matches": image_source_matches,
            },
            "source_fingerprint": source,
            "lock_source_fingerprint": lock,
        },
        "case_deltas": {
            "critical_high_vulnerabilities": max(0, finding_count),
            "missing_package_inventory": int(package_count == 0),
            "missing_image_lineage": int(not image_lineage_pass),
        },
        "gate": gate,
        "production_gate": gate,
        "image_gate": "pass" if image_passed else "fail",
        "rejection_reasons": reasons,
        "production_rejection_reasons": reasons,
    }
    rendered = atomic_write_json(args.output, result).rstrip("\n")
    print(rendered)
    if gate == "fail" or (args.require_production and gate != "pass"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
