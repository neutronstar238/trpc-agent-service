from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast
from urllib.error import HTTPError

import pytest

import scripts.kind_runtime_probe as probe
from trpc_service.tool.reconciliation import ExecutionProbeIntent, ReconciliationOutcome


def _intent(key: str = "effect/key") -> ExecutionProbeIntent:
    return ExecutionProbeIntent(
        tenant_id="tenant-a",
        execution_key=key,
        turn_id="turn-a",
        tool_name="probe",
        arguments_hash="a" * 64,
        attempt=1,
    )


def _env_without_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "TRPC_SERVICE_DATABASE_DSN",
        "TRPC_SERVICE_WORKER_DATABASE_DSN",
        "TRPC_KIND_PROBE_FIXTURE_DSN",
        "TRPC_KIND_PROBE_RUNTIME_DSN",
        "TRPC_KIND_TOOL_RECONCILER_DSN",
        "TRPC_KIND_PROBE_RECONCILER_DSN",
        "TRPC_KIND_PROBE_CLEANUP_DSN",
        "TRPC_KIND_PROBE_MIGRATION_DSN",
        "TRPC_KIND_PROVIDER_URL",
        "TRPC_KIND_PROVIDER_EXECUTE_URL",
        "TRPC_KIND_PROVIDER_STATUS_URL",
        "TRPC_KIND_PROVIDER_METRICS_URL",
    ):
        monkeypatch.delenv(name, raising=False)


def test_config_reads_kind_aliases_without_printing_or_normalizing_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRPC_SERVICE_DATABASE_DSN", "postgresql://runtime:secret@postgres/db")
    monkeypatch.setenv(
        "TRPC_KIND_TOOL_RECONCILER_DSN", "postgresql://reconciler:secret@postgres/db"
    )
    monkeypatch.setenv("TRPC_KIND_PROVIDER_URL", "http://kind-fake-provider:8080/")

    config = probe.RuntimeProbeConfig.from_env()

    assert config.fixture_dsn.startswith("postgresql://runtime:")
    assert config.runtime_dsn == config.fixture_dsn
    assert config.reconciler_dsn.startswith("postgresql://reconciler:")
    assert config.provider_execute_url == "http://kind-fake-provider:8080/v1/effects"
    assert config.provider_status_url.endswith("/v1/effects/{execution_key}")
    assert config.provider_metrics_url == "http://kind-fake-provider:8080/v1/metrics"


def test_config_defaults_kind_provider_service_when_not_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env_without_probe(monkeypatch)
    monkeypatch.setenv("TRPC_SERVICE_DATABASE_DSN", "postgresql://runtime:secret@postgres/db")

    config = probe.RuntimeProbeConfig.from_env()

    assert config.provider_execute_url == f"{probe.DEFAULT_PROVIDER_URL}/v1/effects"
    assert (
        config.provider_status_url == f"{probe.DEFAULT_PROVIDER_URL}/v1/effects/{{execution_key}}"
    )
    assert config.provider_metrics_url == f"{probe.DEFAULT_PROVIDER_URL}/v1/metrics"


def test_missing_live_config_is_not_run_and_is_keyless(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env_without_probe(monkeypatch)
    secret_dsn = "postgresql://probe:do-not-print@postgres/trpc_service"
    config = probe.RuntimeProbeConfig(fixture_dsn=secret_dsn)

    report = asyncio.run(probe.run_probe(config, command="reconcile"))
    rendered = json.dumps(report, sort_keys=True)

    assert report["status"] == "not_run"
    assert report["production_gate"] == "not_run"
    assert secret_dsn not in rendered
    assert "do-not-print" not in rendered


@pytest.mark.asyncio
async def test_provider_probe_is_get_only_and_maps_applied_status() -> None:
    calls: list[tuple[str, str, Mapping[str, object] | None]] = []

    def request(
        url: str,
        *,
        method: str = "GET",
        body: Mapping[str, object] | None = None,
        timeout: float,
    ) -> tuple[int, Mapping[str, object]]:
        del timeout
        calls.append((url, method, body))
        return 200, {"status": "applied"}

    config = probe.RuntimeProbeConfig(
        provider_execute_url="http://provider/v1/effects",
        provider_status_url="http://provider/v1/effects/{execution_key}",
        provider_metrics_url="http://provider/v1/metrics",
    )
    client = probe.ProviderHTTPClient(config, request=request)
    evidence = await client.probe(_intent("effect/key"), object())

    assert evidence["outcome"] == ReconciliationOutcome.APPLIED.value
    assert calls == [("http://provider/v1/effects/effect%2Fkey", "GET", None)]
    assert client.execute_calls == 0
    assert client.status_queries == 1


@pytest.mark.asyncio
async def test_provider_execute_uses_durable_effect_key_once() -> None:
    requests: list[tuple[str, str, Mapping[str, object] | None]] = []

    def request(
        url: str,
        *,
        method: str = "GET",
        body: Mapping[str, object] | None = None,
        timeout: float,
    ) -> tuple[int, Mapping[str, object]]:
        del timeout
        requests.append((url, method, body))
        return 202, {"status": "accepted"}

    config = probe.RuntimeProbeConfig(provider_execute_url="http://provider/v1/effects")
    client = probe.ProviderHTTPClient(config, request=request)
    intent = _intent("effect/key")

    assert await client.execute_once(intent) == 202

    assert requests == [
        (
            "http://provider/v1/effects",
            "POST",
            {
                "tenant_id": "tenant-a",
                "execution_key": "effect/key",
                "effect_key": "effect/key",
                "attempt": 1,
                "simulate_timeout": True,
            },
        )
    ]
    assert client.execute_calls == 1


@pytest.mark.asyncio
async def test_provider_404_is_unknown_and_execute_timeout_is_not_retried() -> None:
    calls: list[tuple[str, str]] = []

    def request(
        url: str,
        *,
        method: str = "GET",
        body: Mapping[str, object] | None = None,
        timeout: float,
    ) -> tuple[int, Mapping[str, object]]:
        del body, timeout
        calls.append((url, method))
        raise HTTPError(
            url,
            504 if method == "POST" else 404,
            "unavailable",
            cast(Any, None),
            None,
        )

    config = probe.RuntimeProbeConfig(
        provider_execute_url="http://provider/v1/effects",
        provider_status_url="http://provider/v1/effects/{execution_key}",
        provider_metrics_url="http://provider/v1/metrics",
    )
    client = probe.ProviderHTTPClient(config, request=request)
    status = await client.execute_once(_intent())
    evidence = await client.probe(_intent(), object())

    assert status is None
    assert evidence["outcome"] == ReconciliationOutcome.UNKNOWN.value
    assert client.execute_calls == 1
    assert client.status_queries == 1
    assert calls[0][1] == "POST"
    assert calls[1][1] == "GET"


def test_query_status_url_preserves_operator_query_parameters() -> None:
    config = probe.RuntimeProbeConfig(
        provider_status_url="http://provider/status?region=kind",
    )
    client = probe.ProviderHTTPClient(config)

    url = client._status_url(_intent("effect/key"))

    assert url.startswith("http://provider/status?")
    assert "region=kind" in url
    assert "execution_key=effect%2Fkey" in url
    assert "tenant_id=tenant-a" in url


def test_status_url_accepts_kind_provider_collection_endpoint() -> None:
    config = probe.RuntimeProbeConfig(
        provider_status_url="http://kind-fake-provider:8080/v1/effects",
    )
    client = probe.ProviderHTTPClient(config)

    assert client._status_url(_intent("effect/key")) == (
        "http://kind-fake-provider:8080/v1/effects/effect%2Fkey"
    )


def test_source_contract_uses_real_repositories_and_has_no_http_cas() -> None:
    source = Path(probe.__file__).read_text(encoding="utf-8")

    for required in (
        "asyncpg.create_pool",
        "PostgresExecutionLedger",
        "ToolExecutionReconciliationCoordinator",
        "PostgresRuntimeRepository",
        "TenantRuntime",
        "claim_ambiguous",
        "reconcile_pending",
        "tool_executions",
        "tool_execution_reconciliations",
        "INSERT INTO storage_profiles",
        "DELETE FROM storage_profiles",
    ):
        assert required in source
    assert "/v1/promotions" not in source
    assert "compare_and_swap" not in source


def test_main_missing_configuration_returns_nonzero_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _env_without_probe(monkeypatch)

    result = probe.main(["im", "--json"])
    report = json.loads(capsys.readouterr().out)

    assert result == 2
    assert report["status"] == "not_run"
    assert report["command"] == "im"
