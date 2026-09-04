from __future__ import annotations

import json
from pathlib import Path

import pytest

import scripts.local_innovation_gate as local_gate


def test_build_report_records_offline_scope_and_optional_demo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprint = {
        "algorithm": "sha256",
        "status": "available",
        "value": "a" * 64,
        "file_count": 3,
        "total_bytes": 12,
    }
    monkeypatch.setattr(local_gate, "_git_sha", lambda _root: "b" * 40)
    monkeypatch.setattr(local_gate, "_source_fingerprint", lambda: fingerprint)
    monkeypatch.setattr(
        local_gate,
        "_run_core_demo",
        lambda *_args, **_kwargs: {
            "name": "core_evolution_demo",
            "status": "not_run",
            "reason": "optional core evolution demo is not available",
        },
    )

    report = local_gate.build_report()

    assert report["offline_gate"] == "pass"
    assert report["development_gate"] == "pass"
    assert report["production_gate"] == "not_run"
    assert report["git_sha"] == "b" * 40
    assert report["source_fingerprint"]["value"] == "a" * 64
    assert report["scope"]["external_calls"] == 0
    assert report["scope"]["credentials_used"] is False
    assert report["case_counts"] == {"total": 3, "pass": 2, "fail": 0, "not_run": 1}


def test_demo_result_rejects_reported_provider_calls() -> None:
    result = local_gate._normalise_demo_result(
        {
            "gate": "pass",
            "provider_call_count": 1,
            "cases": [{"name": "simulate_only", "status": "pass"}],
        },
        module="fixture.evolution",
    )

    assert result["status"] == "fail"
    assert "real external call" in result["reason"]
    assert result["cases"][0]["status"] == "pass"


def test_async_demo_is_invoked_with_simulate_only_flag() -> None:
    observed: list[bool] = []

    async def run_demo(*, simulate_only: bool) -> dict[str, object]:
        observed.append(simulate_only)
        return {"offline_gate": "pass", "provider_call_count": 0}

    result = local_gate._normalise_demo_result(
        local_gate._invoke_demo(run_demo),
        module="fixture.evolution",
    )

    assert observed == [True]
    assert result["status"] == "pass"


def test_required_demo_unavailable_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local_gate, "_git_sha", lambda _root: "c" * 40)
    monkeypatch.setattr(
        local_gate,
        "_source_fingerprint",
        lambda: {"algorithm": "sha256", "status": "available", "value": "d" * 64},
    )
    monkeypatch.setattr(
        local_gate,
        "_run_core_demo",
        lambda *_args, **_kwargs: {
            "name": "core_evolution_demo",
            "status": "not_run",
            "reason": "missing hook",
        },
    )

    report = local_gate.build_report(require_core_demo=True)

    assert report["offline_gate"] == "fail"
    assert report["production_gate"] == "not_run"
    assert report["cases"][-1]["status"] == "fail"
    assert "core_evolution_demo" in report["rejection_reasons"][0]


def test_main_writes_json_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(local_gate, "_git_sha", lambda _root: "e" * 40)
    monkeypatch.setattr(
        local_gate,
        "_source_fingerprint",
        lambda: {"algorithm": "sha256", "status": "available", "value": "f" * 64},
    )
    monkeypatch.setattr(
        local_gate,
        "_run_core_demo",
        lambda *_args, **_kwargs: {
            "name": "core_evolution_demo",
            "status": "not_run",
            "reason": "fixture",
        },
    )
    output = tmp_path / "gate.json"

    assert local_gate.main(["--output", str(output)]) == 0
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["kind"] == "local_innovation_gate"
    assert payload["offline_gate"] == "pass"
    assert payload["production_gate"] == "not_run"
    assert json.loads(capsys.readouterr().out)["git_sha"] == "e" * 40
