from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

from scripts.evidence_lineage import source_fingerprint


def _module() -> ModuleType:
    path = Path("runs/multitenant/bind_published_candidate.py").resolve()
    spec = importlib.util.spec_from_file_location("bind_published_candidate", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_binding_cli_logic_writes_matching_lock_without_raw_nonce(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    source = source_fingerprint(tmp_path)["value"]
    source_value = source
    initial_reference = "docker.io/example/service@sha256:" + "a" * 64
    upgrade_reference = "docker.io/example/service@sha256:" + "b" * 64
    pulls: list[tuple[str, ...]] = []
    labels: list[str] = []
    containers: list[str] = []

    def fake_docker(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        pulls.append(arguments)
        return subprocess.CompletedProcess(["docker", *arguments], 0, "", "")

    def fake_source_label(reference: str, *, source: str) -> None:
        assert source == source_value
        labels.append(reference)

    def fake_verify_container_source(reference: str, *, source: str) -> None:
        assert source == source_value
        containers.append(reference)

    monkeypatch.setattr(module, "_docker", fake_docker)
    monkeypatch.setattr(module, "_source_label", fake_source_label)
    monkeypatch.setattr(module, "_verify_container_source", fake_verify_container_source)
    monkeypatch.setenv("TRPC_RELEASE_ID", "release-test-one")
    monkeypatch.setenv("TRPC_RELEASE_NONCE", "n" * 32)
    output = tmp_path / "binding.json"
    lock = tmp_path / "lock.json"

    result = module.bind_published_candidate(
        expected_source=source,
        repository="docker.io/example/service",
        initial_tag="candidate-a",
        initial_digest="sha256:" + "a" * 64,
        upgrade_tag="candidate-b",
        upgrade_digest="sha256:" + "b" * 64,
        output=output,
        lock_output=lock,
        root=tmp_path,
    )

    rendered = output.read_text(encoding="utf-8") + lock.read_text(encoding="utf-8")
    assert result["source_fingerprint"]["value"] == source
    assert "n" * 32 not in rendered
    assert json.loads(lock.read_text(encoding="utf-8"))["images"] == result["images"]
    assert pulls == [
        ("pull", "--platform", "linux/amd64", initial_reference),
        ("pull", "--platform", "linux/amd64", upgrade_reference),
    ]
    assert labels == [initial_reference, upgrade_reference]
    assert containers == [initial_reference, upgrade_reference]


def test_binding_verification_failure_does_not_write_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    source = source_fingerprint(tmp_path)["value"]
    monkeypatch.setenv("TRPC_RELEASE_ID", "release-test-failure")
    monkeypatch.setenv("TRPC_RELEASE_NONCE", "f" * 32)

    def fail_verification(reference: str, *, source: str) -> None:
        del reference, source
        raise module.RegistryImageError(
            "candidate image source fingerprint does not match checkout"
        )

    monkeypatch.setattr(module, "_verify_published_image", fail_verification)
    output = tmp_path / "binding.json"
    lock = tmp_path / "lock.json"

    with pytest.raises(module.RegistryImageError, match="does not match"):
        module.bind_published_candidate(
            expected_source=source,
            repository="docker.io/example/service",
            initial_tag="candidate-a",
            initial_digest="sha256:" + "a" * 64,
            upgrade_tag="candidate-b",
            upgrade_digest="sha256:" + "b" * 64,
            output=output,
            lock_output=lock,
            root=tmp_path,
        )

    assert not output.exists()
    assert not lock.exists()


def test_binding_rejects_equal_digests(tmp_path: Path) -> None:
    module = _module()
    digest = "sha256:" + "a" * 64
    with pytest.raises(ValueError, match="digests must differ"):
        module.bind_published_candidate(
            expected_source=source_fingerprint(tmp_path)["value"],
            repository="docker.io/example/service",
            initial_tag="candidate-a",
            initial_digest=digest,
            upgrade_tag="candidate-b",
            upgrade_digest=digest,
            output=tmp_path / "binding.json",
            lock_output=tmp_path / "lock.json",
            root=tmp_path,
        )
