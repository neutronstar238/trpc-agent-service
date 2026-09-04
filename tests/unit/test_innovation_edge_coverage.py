from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from trpc_agent_sdk.context import new_agent_context
from trpc_agent_sdk.tools import FunctionTool
from typer.testing import CliRunner

import scripts.local_innovation_gate as local_gate
import trpc_service._cli as cli
import trpc_service.agent.worker as worker_module
from trpc_service.cell.events import CellAddress
from trpc_service.cell.intents import IntentRisk
from trpc_service.cell.shadow import CellEffectShadowValidator
from trpc_service.channels.envelopes import InboundEnvelope, PayloadKind
from trpc_service.storage.models import Acceptance, CommitResult, SessionLease, SessionSnapshot
from trpc_service.tenant.models import (
    Channel,
    ConversationKind,
    ModelPolicy,
    StorageSelection,
    TenantConfig,
    TenantContext,
    ToolEffectMode,
    ToolPolicy,
    ToolRisk,
)
from trpc_service.tool.confirmation import ConfirmationTokenService, InMemoryConfirmationLedger
from trpc_service.tool.execution import HumanReviewRequired, InMemoryExecutionLedger, ToolExecutor
from trpc_service.tool.governance import (
    Decision,
    GovernancePipeline,
    GovernanceResult,
    InMemoryBudgetLedger,
    SdkToolSafetyScanner,
)
from trpc_service.tool.integration import GovernedTool


def _context() -> TenantContext:
    return TenantContext(
        tenant_id="tenant-a",
        app_id="support",
        config_version=1,
        channel_binding_id="binding-a",
        principal_id="principal-a",
        session_id="session-a",
        request_id="request-a",
        trace_id="trace-a",
    )


def _address(**updates: str) -> CellAddress:
    values = {
        "tenant_id": "tenant-a",
        "app_id": "support",
        "cell_id": "cell-a",
        "session_id": "session-a",
        "capsule_digest": "sha256:" + "a" * 64,
        "branch_id": "main",
    }
    values.update(updates)
    return CellAddress(**values)


def _config(*, mode: ToolEffectMode = ToolEffectMode.OBSERVE) -> TenantConfig:
    return TenantConfig(
        tenant_id="tenant-a",
        app_id="support",
        version=1,
        model=ModelPolicy(provider="offline", model="deterministic"),
        storage=StorageSelection(profile_id="storage-a"),
        tools=ToolPolicy(
            allow=frozenset({"write_value"}),
            classifications={"write_value": ToolRisk.NON_IDEMPOTENT},
            effect_modes={"write_value": mode},
        ),
    )


def _metadata(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "tenant_id": "tenant-a",
        "app_id": "support",
        "config_version": 1,
        "binding_id": "binding-a",
        "principal_id": "principal-a",
        "session_id": "session-a",
        "request_id": "request-a",
        "trace_id": "trace-a",
        "turn_id": "turn-a",
        "cell_id": "cell-a",
        "capsule_digest": "sha256:" + "a" * 64,
        "branch_id": "main",
    }
    value.update(updates)
    return value


def _invocation(metadata: dict[str, object] | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        invocation_id="invocation-a",
        agent_context=new_agent_context(metadata=_metadata() if metadata is None else metadata),
        agent=SimpleNamespace(
            before_tool_callback=None,
            after_tool_callback=None,
            parallel_tool_calls=False,
        ),
    )


async def write_value(value: int) -> dict[str, int]:
    return {"value": value}


def _governed(
    *,
    config: TenantConfig | None = None,
    governance: object | None = None,
    executor: object | None = None,
    observer: object | None = None,
    shadow_validator: CellEffectShadowValidator | None = None,
    shadow_observer: object | None = None,
) -> GovernedTool:
    return GovernedTool(
        FunctionTool(write_value),
        config=config or _config(),
        governance=governance
        or GovernancePipeline(
            InMemoryBudgetLedger(),
            SdkToolSafetyScanner(),
            ConfirmationTokenService(b"c" * 32, InMemoryConfirmationLedger()),
        ),
        executor=executor or ToolExecutor(b"e" * 32, InMemoryExecutionLedger()),
        observer=observer,  # type: ignore[arg-type]
        shadow_validator=shadow_validator,
        shadow_observer=shadow_observer,  # type: ignore[arg-type]
    )


def test_gate_sanitizes_untrusted_demo_payloads() -> None:
    malformed = local_gate._normalise_demo_case("bad name/secret", "not-a-mapping")
    assert malformed == {
        "name": "unnamed_case",
        "status": "fail",
        "reason": "demo case is not a mapping",
    }

    case = local_gate._normalise_demo_case(
        "judge-1",
        {
            "gate": "pass",
            "message": " bounded reason ",
            "assertions": ("a", 4, "b"),
            "rejection_reasons": ["r"],
            "evidence_digest": "e" * 70,
            "provider_call_count": 0,
            "side_effect_count": True,
        },
    )
    assert case["status"] == "pass"
    assert case["reason"] == "bounded reason"
    assert case["assertions"] == ["a", "b"]
    assert case["rejection_reasons"] == ["r"]
    assert case["provider_call_count"] == 0
    assert "side_effect_count" not in case


def test_gate_demo_discovery_and_invocation_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(_module: str):
        error = ModuleNotFoundError("optional")
        error.name = "optional"
        raise error

    monkeypatch.setattr(local_gate.importlib, "import_module", missing)
    callback, reason = local_gate._load_demo("optional.module", "run_demo")
    assert callback is None and reason == "optional core evolution demo is not available"

    monkeypatch.setattr(
        local_gate.importlib,
        "import_module",
        lambda _module: SimpleNamespace(run_demo=object()),
    )
    callback, reason = local_gate._load_demo("fixture", "run_demo")
    assert callback is None and "not defined" in (reason or "")

    monkeypatch.setattr(
        local_gate,
        "_load_demo",
        lambda *_args: (None, "missing hook"),
    )
    assert local_gate._run_core_demo("skip")["status"] == "not_run"
    report = local_gate._run_core_demo("auto")
    assert report["status"] == "not_run" and "missing hook" in report["reason"]


def test_gate_handles_sync_async_and_bad_demo_results() -> None:
    seen: list[object] = []

    def sync(*, mode: str) -> dict[str, str]:
        seen.append(mode)
        return {"gate": "pass"}

    async def offline(*, offline: bool) -> dict[str, str]:
        seen.append(offline)
        return {"offline_gate": "pass"}

    assert local_gate._invoke_demo(sync) == {"gate": "pass"}
    assert local_gate._invoke_demo(offline) == {"offline_gate": "pass"}
    assert seen == ["simulate_only", True]
    assert local_gate._normalise_demo_result([], module="fixture")["status"] == "fail"
    assert (
        local_gate._normalise_demo_result({"cases": ["bad"]}, module="fixture")["status"] == "fail"
    )


def test_gate_main_reports_failures_without_external_actions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Exercise the real report writer and the non-zero return without using a
    # provider or credentials.
    monkeypatch.setattr(
        local_gate,
        "_source_fingerprint",
        lambda: {"algorithm": "sha256", "status": "unavailable"},
    )
    assert local_gate.main(["--core-demo", "skip", "--output", str(tmp_path / "fail.json")]) == 1
    payload = json.loads((tmp_path / "fail.json").read_text(encoding="utf-8"))
    assert payload["production_gate"] == "not_run"


@pytest.mark.parametrize(
    ("risk", "expected"),
    [
        (ToolRisk.IDEMPOTENT, IntentRisk.LOW),
        (ToolRisk.NON_IDEMPOTENT, IntentRisk.HIGH),
        (ToolRisk.UNKNOWN, IntentRisk.UNKNOWN),
    ],
)
def test_shadow_validator_maps_risk_without_authorizing_effect(
    risk: ToolRisk,
    expected: IntentRisk,
) -> None:
    evidence = CellEffectShadowValidator().derive(
        _context(),
        _address(),
        turn_id="turn-a",
        tool_name="write_value",
        arguments={"value": 1},
        risk=risk,
        legacy_effect_key="f" * 64,
    )
    assert evidence.intent.risk is expected
    assert evidence.intent.policy_decision.value == "deny"
    assert evidence.real_provider_call_count == 0


@pytest.mark.parametrize(
    "bad_address",
    [
        {"tenant_id": "tenant-b"},
        {"app_id": "other"},
        {"session_id": "other"},
        {"branch_id": "candidate"},
    ],
)
def test_shadow_validator_rejects_cross_namespace_and_empty_key(
    bad_address: dict[str, str],
) -> None:
    with pytest.raises(ValueError, match="active main Cell"):
        CellEffectShadowValidator().derive(
            _context(),
            _address(**bad_address),
            turn_id="turn-a",
            tool_name="write_value",
            arguments={},
            risk=ToolRisk.UNKNOWN,
            legacy_effect_key="f" * 64,
        )
    with pytest.raises(ValueError, match="legacy effect key"):
        CellEffectShadowValidator().derive(
            _context(),
            _address(),
            turn_id="turn-a",
            tool_name="write_value",
            arguments={},
            risk=ToolRisk.UNKNOWN,
            legacy_effect_key="",
        )


class _AllowGovernance:
    async def evaluate(self, **_kwargs: object) -> GovernanceResult:
        return GovernanceResult(Decision.ALLOW, "fixture_allow", {})


class _DenyGovernance:
    async def evaluate(self, **_kwargs: object) -> GovernanceResult:
        return GovernanceResult(Decision.DENY, "fixture_deny", {})


class _Observer:
    def __init__(self, *, fail_effect: bool = False) -> None:
        self.events: list[tuple[str, object]] = []
        self.fail_effect = fail_effect

    async def intent_created(self, _context: TenantContext, **kwargs: object) -> object:
        self.events.append(("intent", kwargs))
        return "token"

    async def shadow_intent_validated(self, _context: TenantContext, **kwargs: object) -> None:
        self.events.append(("shadow", kwargs))

    async def policy_decided(self, _token: object, **kwargs: object) -> None:
        self.events.append(("policy", kwargs))

    async def effect_completed(self, _token: object, **kwargs: object) -> None:
        self.events.append(("effect", kwargs))
        if self.fail_effect:
            raise RuntimeError("observer unavailable")


class _RaisingExecutor:
    def __init__(self, error: BaseException) -> None:
        self.error = error

    def key_for(self, *_args: object, **_kwargs: object) -> str:
        return "e" * 64

    async def execute(self, *_args: object, **_kwargs: object) -> object:
        raise self.error


def test_governed_tool_requires_shadow_components_and_metadata() -> None:
    with pytest.raises(ValueError, match="progress-streaming"):

        class ProgressTool(FunctionTool):
            @property
            def is_progress_streaming(self) -> bool:
                return True

        GovernedTool(
            ProgressTool(write_value),
            config=_config(),
            governance=_AllowGovernance(),  # type: ignore[arg-type]
            executor=_RaisingExecutor(RuntimeError()),  # type: ignore[arg-type]
        )

    governed = _governed(config=_config(mode=ToolEffectMode.SHADOW), governance=_AllowGovernance())
    with pytest.raises(ValueError, match="requires a validator"):
        asyncio.run(governed._run_async_impl(tool_context=_invocation(), args={"value": 1}))

    governed = _governed(
        config=_config(mode=ToolEffectMode.SHADOW),
        governance=_AllowGovernance(),
        shadow_validator=CellEffectShadowValidator(),
    )
    with pytest.raises(ValueError, match="requires a validator"):
        asyncio.run(governed._run_async_impl(tool_context=_invocation(), args={"value": 1}))

    governed = _governed(
        config=_config(mode=ToolEffectMode.SHADOW),
        governance=_AllowGovernance(),
        shadow_validator=CellEffectShadowValidator(),
        shadow_observer=_Observer(),
    )
    with pytest.raises(ValueError, match="missing tenant metadata"):
        asyncio.run(governed._run_async_impl(tool_context=_invocation({}), args={"value": 1}))
    with pytest.raises(ValueError, match="missing Cell metadata"):
        asyncio.run(
            governed._run_async_impl(
                tool_context=_invocation(_metadata(cell_id=None)),
                args={"value": 1},
            )
        )


@pytest.mark.asyncio
async def test_governed_tool_denial_is_observed_without_execution() -> None:
    observer = _Observer()
    governed = _governed(
        governance=_DenyGovernance(),
        observer=observer,
        executor=_RaisingExecutor(RuntimeError("must not execute")),
    )
    result = await governed._run_async_impl(tool_context=_invocation(), args={"value": 1})
    assert result == {"error": "fixture_deny", "status": "deny"}
    assert [event[0] for event in observer.events] == ["intent", "policy"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [HumanReviewRequired("unknown"), RuntimeError("provider failed"), asyncio.CancelledError()],
)
async def test_governed_tool_reconciles_all_execution_exception_classes(
    error: BaseException,
) -> None:
    observer = _Observer(fail_effect=True)
    governed = _governed(
        governance=_AllowGovernance(),
        executor=_RaisingExecutor(error),
        observer=observer,
    )
    with pytest.raises(type(error)):
        await governed._run_async_impl(tool_context=_invocation(), args={"value": 1})
    assert observer.events[1][0] == "policy"
    assert observer.events[2][0] == "effect"


def test_governed_tool_rejects_invalid_lease_identity_and_hashes_values() -> None:
    governed = _governed(governance=_AllowGovernance(), executor=_RaisingExecutor(RuntimeError()))
    with pytest.raises(ValueError, match="invalid lease identity"):
        asyncio.run(
            governed._run_async_impl(
                tool_context=_invocation(_metadata(lease_owner="worker", lease_epoch=0)),
                args={"value": 1},
            )
        )
    import trpc_service.tool.integration as integration

    assert integration._confirmation_token(_metadata(), "write_value") is None
    assert (
        integration._confirmation_token(
            _metadata(tool_confirmation_tokens={"write_value": "token"}), "write_value"
        )
        == "token"
    )
    assert integration._value_hash(object()) != integration._value_hash({})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [asyncio.CancelledError(), HumanReviewRequired("unknown"), RuntimeError("failed")],
)
async def test_governed_tool_rethrows_execution_errors_without_observer(
    error: BaseException,
) -> None:
    governed = _governed(
        governance=_AllowGovernance(),
        executor=_RaisingExecutor(error),
    )
    with pytest.raises(type(error)):
        await governed._run_async_impl(tool_context=_invocation(), args={"value": 1})


def test_worker_cell_address_accepts_legacy_and_real_journal_tokens() -> None:
    address = _address()
    assert worker_module._cell_address(None) is None
    assert worker_module._cell_address({"turn_id": "legacy"}) is None
    assert worker_module._cell_address({"address": address}) == address
    assert worker_module._cell_address(SimpleNamespace(address=address)) == address
    with pytest.raises(TypeError, match="valid CellAddress"):
        worker_module._cell_address({"address": "not-an-address"})


def _worker_acceptance_and_lease() -> tuple[Acceptance, SessionLease]:
    context = _context()
    acceptance = Acceptance(
        inbound_id="inbound-a",
        context=context,
        envelope=InboundEnvelope(
            channel=Channel.FEISHU,
            account_id="account-a",
            external_message_id="external-a",
            external_user_id="user-a",
            conversation_kind=ConversationKind.DIRECT,
            payload_kind=PayloadKind.TEXT,
            text="private user message",
        ),
    )
    snapshot = SessionSnapshot(
        tenant_id=context.tenant_id,
        app_id=context.app_id,
        session_id=context.session_id,
        principal_id=context.principal_id,
        next_sequence=4,
    )
    lease = SessionLease(
        tenant_id=context.tenant_id,
        session_id=context.session_id,
        turn_id="turn-a",
        inbound_id=acceptance.inbound_id,
        worker_id="worker-a",
        fencing_token=2,
        expires_at=datetime.now(UTC),
        snapshot=snapshot,
    )
    return acceptance, lease


@pytest.mark.asyncio
async def test_worker_post_commit_context_handles_optional_and_stale_projections() -> None:
    acceptance, lease = _worker_acceptance_and_lease()
    worker = worker_module.AgentWorker(
        SimpleNamespace(),
        worker_id="worker-a",
        agent_loader=lambda _config: None,
    )
    result_without_sequence = CommitResult(turn_id=lease.turn_id, last_sequence=None)

    await worker._post_commit_context(
        acceptance,
        lease,
        result_without_sequence,
        "answer",
        None,
    )

    class Memory:
        def __init__(self, *, fail: bool = False) -> None:
            self.calls: list[dict[str, object]] = []
            self.fail = fail

        async def put(self, *args: object, **kwargs: object) -> None:
            if self.fail:
                raise RuntimeError("memory unavailable")
            self.calls.append({"args": args, "kwargs": kwargs})

    class Summary:
        def __init__(
            self,
            previous: object = None,
            *,
            fail_get: bool = False,
            fail_put: bool = False,
        ) -> None:
            self.previous = previous
            self.fail_get = fail_get
            self.fail_put = fail_put
            self.calls: list[dict[str, object]] = []

        async def get(self, *_args: object) -> object:
            if self.fail_get:
                raise RuntimeError("summary read unavailable")
            return self.previous

        def put(self, *args: object, **kwargs: object) -> None:
            if self.fail_put:
                raise RuntimeError("summary write unavailable")
            self.calls.append({"args": args, "kwargs": kwargs})

    memory = Memory(fail=True)
    summary = Summary()
    services = SimpleNamespace(memory=memory, summary=summary)
    await worker._post_commit_context(
        acceptance,
        lease,
        CommitResult(turn_id=lease.turn_id, last_sequence=5),
        "answer",
        services,
    )
    assert summary.calls and summary.calls[0]["kwargs"]["expected_version"] is None

    memory = Memory()
    summary = Summary(SimpleNamespace(up_to_sequence=5, version=7))
    await worker._post_commit_context(
        acceptance,
        lease,
        CommitResult(turn_id=lease.turn_id, last_sequence=5),
        "answer",
        SimpleNamespace(memory=memory, summary=summary),
    )
    assert memory.calls
    assert summary.calls == []

    summary = Summary(fail_get=True, fail_put=True)
    await worker._post_commit_context(
        acceptance,
        lease,
        CommitResult(turn_id=lease.turn_id, last_sequence=5),
        "answer",
        SimpleNamespace(memory=Memory(), summary=summary),
    )


def test_cell_evolve_cli_writes_pass_and_fail_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import trpc_service.cell.evolution as evolution

    monkeypatch.setattr(evolution, "run_evolution_demo", lambda: {"gate": "pass", "cases": []})
    output = tmp_path / "evolve.json"
    result = CliRunner().invoke(cli.app, ["cell-evolve-demo", "--output", str(output)])
    assert result.exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["gate"] == "pass"

    monkeypatch.setattr(evolution, "run_evolution_demo", lambda: {"gate": "fail"})
    failed = CliRunner().invoke(cli.app, ["cell-evolve-demo"])
    assert failed.exit_code == 1
