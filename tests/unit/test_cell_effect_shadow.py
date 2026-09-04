from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from trpc_agent_sdk.context import new_agent_context
from trpc_agent_sdk.tools import FunctionTool

from trpc_service.cell.events import CellAddress
from trpc_service.cell.shadow import CellEffectShadowValidator
from trpc_service.tenant.models import (
    ModelPolicy,
    StorageSelection,
    TenantConfig,
    TenantContext,
    ToolEffectMode,
    ToolPolicy,
    ToolRisk,
)
from trpc_service.tool.confirmation import ConfirmationTokenService, InMemoryConfirmationLedger
from trpc_service.tool.execution import InMemoryExecutionLedger, ToolExecutor
from trpc_service.tool.governance import (
    GovernancePipeline,
    InMemoryBudgetLedger,
    SdkToolSafetyScanner,
)
from trpc_service.tool.integration import GovernedTool

KEY = b"s" * 32
DIGEST = "sha256:" + "a" * 64


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


def _address(*, branch_id: str = "main") -> CellAddress:
    return CellAddress(
        tenant_id="tenant-a",
        app_id="support",
        cell_id="cell-a",
        session_id="session-a",
        capsule_digest=DIGEST,
        branch_id=branch_id,
    )


def _config(mode: ToolEffectMode = ToolEffectMode.SHADOW) -> TenantConfig:
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


def test_shadow_validator_is_deterministic_and_never_authorizes_an_effect() -> None:
    validator = CellEffectShadowValidator()
    first = validator.derive(
        _context(),
        _address(),
        turn_id="turn-a",
        tool_name="write_value",
        arguments={"b": 2, "a": 1},
        risk=ToolRisk.NON_IDEMPOTENT,
        legacy_effect_key="f" * 64,
    )
    second = validator.derive(
        _context(),
        _address(),
        turn_id="turn-a",
        tool_name="write_value",
        arguments={"a": 1, "b": 2},
        risk=ToolRisk.NON_IDEMPOTENT,
        legacy_effect_key="f" * 64,
    )

    assert first.native_effect_key == second.native_effect_key
    assert first.arguments_hash == second.arguments_hash
    assert first.intent.policy_decision.value == "deny"
    assert first.intent.risk.value == "high"
    assert first.real_provider_call_count == 0

    with pytest.raises(ValueError, match="active main Cell"):
        validator.derive(
            _context(),
            _address(branch_id="candidate"),
            turn_id="turn-a",
            tool_name="write_value",
            arguments={},
            risk=ToolRisk.UNKNOWN,
            legacy_effect_key="f" * 64,
        )


@pytest.mark.asyncio
async def test_shadow_mode_records_native_evidence_without_a_second_provider_call() -> None:
    provider_calls: list[int] = []
    shadow_calls: list[dict[str, object]] = []

    async def write_value(value: int) -> dict[str, int]:
        provider_calls.append(value)
        return {"value": value}

    class ShadowObserver:
        async def shadow_intent_validated(self, _context: TenantContext, **kwargs: object) -> None:
            shadow_calls.append(kwargs)

    governed = GovernedTool(
        FunctionTool(write_value),
        config=_config(),
        governance=GovernancePipeline(
            InMemoryBudgetLedger(),
            SdkToolSafetyScanner(),
            ConfirmationTokenService(KEY, InMemoryConfirmationLedger()),
        ),
        executor=ToolExecutor(KEY, InMemoryExecutionLedger()),
        shadow_validator=CellEffectShadowValidator(),
        shadow_observer=ShadowObserver(),
    )
    metadata = {
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
        "capsule_digest": DIGEST,
        "branch_id": "main",
    }
    invocation = SimpleNamespace(
        invocation_id="invocation-a",
        agent_context=new_agent_context(metadata=metadata),
        agent=SimpleNamespace(
            before_tool_callback=None,
            after_tool_callback=None,
            parallel_tool_calls=False,
        ),
    )

    assert await governed._run_async_impl(tool_context=invocation, args={"value": 7}) == {
        "value": 7
    }
    assert await governed._run_async_impl(tool_context=invocation, args={"value": 7}) == {
        "value": 7
    }
    assert provider_calls == [7]
    assert len(shadow_calls) == 2
    assert shadow_calls[0]["native_effect_key"] == shadow_calls[1]["native_effect_key"]
    assert shadow_calls[0]["legacy_effect_key"] == shadow_calls[1]["legacy_effect_key"]


def test_effect_mode_defaults_to_observe_and_rejects_cutover() -> None:
    assert ToolPolicy().effect_mode_for("write_value") is ToolEffectMode.OBSERVE
    with pytest.raises(ValidationError):
        ToolPolicy.model_validate({"effect_modes": {"write_value": "cutover"}})
