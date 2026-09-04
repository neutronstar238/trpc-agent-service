from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from scripts import kind_evolution_probe as probe


def test_probe_is_not_run_without_explicit_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    async def should_not_connect(*args: object, **kwargs: object) -> object:
        raise AssertionError("real PostgreSQL must not be contacted")

    monkeypatch.setattr(probe.asyncpg, "create_pool", should_not_connect)
    report = asyncio.run(
        probe.run_probe(
            execute=False,
            database_dsn="postgresql://user:password@host/db",
        )
    )
    rendered = json.dumps(report)
    assert report["gate"] == "not_run"
    assert report["status"] == "not_run"
    assert report["local_k8s_gate"] == "not_run"
    assert report["production_gate"] == "not_run"
    assert report["provider_calls"] == 0
    assert "password" not in rendered
    assert "postgresql://" not in rendered


def test_json_mode_emits_machine_readable_status_without_a_file(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("TRPC_KIND_EVOLUTION_DATABASE_DSN", raising=False)
    exit_code = probe.main(["--json"])
    line = capsys.readouterr().out.strip().splitlines()[-1]
    report = json.loads(line)
    assert exit_code == 2
    assert report["status"] == "not_run"
    assert report["production_gate"] == "not_run"


def test_opt_in_configuration_is_fail_closed_and_redacted() -> None:
    report = asyncio.run(
        probe.run_probe(
            execute=True,
            database_dsn="postgresql://user:password@host/db",
            tenant_id="tenant",
            app_id="app",
            cell_id="cell",
            session_id="session",
            source_capsule_digest="sha256:" + "0" * 64,
            candidate_capsule_digest="not-a-digest",
        )
    )
    rendered = json.dumps(report)
    assert report["gate"] == "fail"
    assert report["local_k8s_gate"] == "fail"
    assert report["production_gate"] == "not_run"
    assert report["provider_calls"] == 0
    assert report["cases"][0]["name"] == "required_configuration"
    assert report["cases"][0]["error_type"] == "ProbeConfigurationError"
    assert "password" not in rendered
    assert "postgresql://" not in rendered
    assert "not-a-digest" not in rendered


def test_safe_error_type_never_includes_message() -> None:
    error = RuntimeError("dsn=postgresql://user:password@db/secret")
    assert probe._safe_error_type(error) == "RuntimeError"


def test_probe_assertion_failure_keeps_safe_case_metadata_without_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakePool:
        async def close(self) -> None:
            return None

    async def fake_pool_factory(**_kwargs: object) -> FakePool:
        return FakePool()

    async def failing_live(_config: probe.ProbeConfig, _pool: object) -> dict[str, object]:
        raise probe.ProbeAssertionError(
            "receipt_rollback",
            {
                "dsn": "postgresql://user:super-secret@db/private",
                "secret": "do-not-report",
            },
        )

    monkeypatch.setattr(probe, "_run_live", failing_live)
    report = asyncio.run(
        probe.run_probe(
            execute=True,
            database_dsn="postgresql://authority:password@postgres/db",
            skip_fixture=True,
            source_capsule_digest="sha256:" + "0" * 64,
            candidate_capsule_digest="sha256:" + "1" * 64,
            pool_factory=fake_pool_factory,
        )
    )

    rendered = json.dumps(report)
    assert report["gate"] == "fail"
    assert report["rejection_reasons"] == ["probe assertion failed: receipt_rollback"]
    assert report["cases"] == [
        {
            "name": "receipt_rollback",
            "passed": False,
            "error_type": "ProbeAssertionError",
            "rejection_reason": "probe assertion failed: receipt_rollback",
        }
    ]
    assert "super-secret" not in rendered
    assert "do-not-report" not in rendered
    assert "postgresql://" not in rendered


def test_exit_code_mapping() -> None:
    assert probe._exit_code({"gate": "pass"}) == 0
    assert probe._exit_code({"gate": "fail"}) == 1
    assert probe._exit_code({"gate": "not_run"}) == 2
    assert probe._exit_code({"gate": "unexpected"}) == 1


def test_probe_config_rejects_unsafe_identifiers() -> None:
    with pytest.raises(probe.ProbeConfigurationError):
        probe.ProbeConfig(
            database_dsn="postgresql://host/db",
            tenant_id="tenant/*",
            app_id="app",
            cell_id="cell",
            session_id="session",
            source_capsule_digest="sha256:" + "0" * 64,
            candidate_capsule_digest="sha256:" + "1" * 64,
            run_token="run",
        )


def test_kind_defaults_fill_namespace_and_digest_fixture_labels() -> None:
    config = probe._config_from_environment(
        database_dsn="postgresql://authority@postgres/db",
        database_dsn_env=probe._DEFAULT_DSN_ENV,
        tenant_id=None,
        app_id=None,
        cell_id=None,
        session_id=None,
        source_capsule_digest=None,
        candidate_capsule_digest=None,
        run_token="run-token",
        lease_seconds=0.25,
        timeout_seconds=45,
    )
    assert config.tenant_id == "kind-evolution-run-token"
    assert config.app_id == "evolution-probe"
    assert config.cell_id == "probe-cell"
    assert config.session_id == "probe-session"
    assert config.source_capsule_digest.startswith("sha256:")
    assert config.candidate_capsule_digest.startswith("sha256:")
    assert config.source_capsule_digest != config.candidate_capsule_digest


def test_explicit_empty_namespace_value_does_not_use_kind_default() -> None:
    with pytest.raises(probe.ProbeConfigurationError):
        probe._config_from_environment(
            database_dsn="postgresql://authority@postgres/db",
            database_dsn_env=probe._DEFAULT_DSN_ENV,
            tenant_id="",
            app_id=None,
            cell_id=None,
            session_id=None,
            source_capsule_digest=None,
            candidate_capsule_digest=None,
            run_token="run-token",
            lease_seconds=0.25,
            timeout_seconds=45,
        )


def test_skip_fixture_requires_both_preprovisioned_digests() -> None:
    report = asyncio.run(
        probe.run_probe(
            execute=True,
            database_dsn="postgresql://authority@postgres/db",
            skip_fixture=True,
        )
    )
    assert report["gate"] == "fail"
    assert report["fixture"] == {
        "status": "fail",
        "role": "not_run",
        "capsule_count": 0,
    }
    assert report["production_gate"] == "not_run"


def test_explicit_digests_still_seed_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    async def fake_fixture(
        config: probe.ProbeConfig, fixture_dsn: str
    ) -> tuple[probe.ProbeConfig, dict[str, object]]:
        calls.append(fixture_dsn)
        return config, {"status": "pass", "role": "trpc_worker", "capsule_count": 2}

    class FakePool:
        async def close(self) -> None:
            return None

    async def fake_pool_factory(**kwargs: object) -> FakePool:
        assert kwargs["dsn"] == "postgresql://authority@postgres/db"
        return FakePool()

    async def fake_live(config: probe.ProbeConfig, pool: object) -> dict[str, object]:
        return probe._base_report(config, gate="pass")

    monkeypatch.setattr(probe, "_provision_fixture", fake_fixture)
    monkeypatch.setattr(probe, "_run_live", fake_live)
    report = asyncio.run(
        probe.run_probe(
            execute=True,
            database_dsn="postgresql://authority@postgres/db",
            fixture_dsn="postgresql://worker@postgres/db",
            source_capsule_digest="sha256:" + "0" * 64,
            candidate_capsule_digest="sha256:" + "1" * 64,
            pool_factory=fake_pool_factory,
        )
    )
    assert calls == ["postgresql://worker@postgres/db"]
    assert report["fixture"] == {
        "status": "pass",
        "role": "trpc_worker",
        "capsule_count": 2,
    }


def test_probe_source_contract() -> None:
    source = Path(probe.__file__).read_text(encoding="utf-8")
    for marker in (
        "PostgresPromotionStore",
        "CertificateVerifier",
        "PromotionApprovalAuthority",
        "cell_promotion_uses",
        "lease_epoch",
        "PromotionCASConflict",
        "PromotionAlreadyUsed",
        "PromotionReceiptError",
        "NamespaceViolation",
        "ensure_runtime_projection_capsule",
        "TRPC_SERVICE_WORKER_DATABASE_DSN",
        "provider_calls",
        "concurrent_cas",
        "certificate_approval_one_time",
        "outbox_lease_takeover",
        "receipt_rollback",
        "stale_aba_rejection",
        "cross_tenant_rejection",
    ):
        assert marker in source
