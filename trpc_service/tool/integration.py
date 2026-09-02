"""SDK tool boundary enforcing tenant governance before side effects."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from typing import Any, Protocol

from trpc_agent_sdk.context import InvocationContext
from trpc_agent_sdk.tools import BaseTool
from trpc_agent_sdk.types import FunctionDeclaration
from typing_extensions import override

from trpc_service.tenant.models import TenantConfig, TenantContext, ToolRisk
from trpc_service.tool.confirmation import arguments_hash
from trpc_service.tool.execution import HumanReviewRequired, ToolExecutor
from trpc_service.tool.governance import Decision, GovernancePipeline

_LOGGER = logging.getLogger(__name__)


class GovernedToolObserver(Protocol):
    """Causal observer for the real governed SDK tool boundary.

    Raw arguments and results never cross this interface.  The observer gets
    only stable hashes and non-sensitive routing metadata, which is sufficient
    to join Policy/Effect facts to the Cell turn without leaking tool content.
    """

    async def intent_created(
        self,
        context: TenantContext,
        *,
        turn_id: str,
        invocation_id: str,
        tool_name: str,
        arguments_hash: str,
        effect_key: str,
        risk: ToolRisk,
    ) -> object: ...

    async def policy_decided(
        self,
        token: object,
        *,
        decision: Decision,
        reason: str,
    ) -> None: ...

    async def effect_completed(
        self,
        token: object,
        *,
        status: str,
        result_hash: str | None,
        error_type: str | None,
    ) -> None: ...


class GovernedTool(BaseTool):
    """Delegate to an SDK tool only after tenant policy and execution checks pass."""

    def __init__(
        self,
        tool: BaseTool,
        *,
        config: TenantConfig,
        governance: GovernancePipeline,
        executor: ToolExecutor,
        observer: GovernedToolObserver | None = None,
    ) -> None:
        if tool.is_progress_streaming:
            raise ValueError("progress-streaming tools need a governed streaming adapter")
        super().__init__(name=tool.name, description=tool.description)
        self._tool = tool
        self._config = config
        self._governance = governance
        self._executor = executor
        self._observer = observer

    @property
    def is_streaming(self) -> bool:
        return bool(self._tool.is_streaming)

    @property
    def api_variant(self) -> str:
        return str(self._tool.api_variant)

    @override
    def _get_declaration(self) -> FunctionDeclaration | None:
        return self._tool._get_declaration()

    @override
    async def _run_async_impl(
        self,
        *,
        tool_context: InvocationContext,
        args: dict[str, Any],
    ) -> Any:
        metadata = tool_context.agent_context.metadata
        context = _tenant_context(metadata)
        confirmation_token = _confirmation_token(metadata, self.name)
        risk = self._config.tools.classifications.get(self.name, ToolRisk.UNKNOWN)
        turn_id = str(metadata.get("turn_id") or context.request_id)
        effect_key = self._executor.key_for(
            context,
            turn_id=turn_id,
            tool_name=self.name,
            arguments=args,
        )
        observer_token: object | None = None
        if self._observer is not None:
            observer_token = await self._observer.intent_created(
                context,
                turn_id=turn_id,
                invocation_id=str(getattr(tool_context, "invocation_id", context.request_id)),
                tool_name=self.name,
                arguments_hash=arguments_hash(args),
                effect_key=effect_key,
                risk=risk,
            )
        result = await self._governance.evaluate(
            context=context,
            config=self._config,
            tool_name=self.name,
            arguments=args,
            estimated_cost=1,
            confirmation_token=confirmation_token,
        )
        if self._observer is not None and observer_token is not None:
            await self._observer.policy_decided(
                observer_token,
                decision=result.decision,
                reason=result.reason,
            )
        if result.decision != Decision.ALLOW:
            return {
                "error": result.reason,
                "status": result.decision.value,
            }

        lease_owner, lease_epoch = _lease_identity(metadata)
        try:
            effect_result = await self._executor.execute(
                context,
                turn_id=turn_id,
                tool_name=self.name,
                arguments=args,
                risk=risk,
                owner_id=lease_owner,
                fencing_token=lease_epoch,
                call=lambda: self._tool.run_async(tool_context=tool_context, args=args),
            )
        except asyncio.CancelledError as error:
            if self._observer is not None and observer_token is not None:
                await self._notify_effect(
                    observer_token,
                    status="failed",
                    result_hash=None,
                    error_type=type(error).__name__[:64],
                )
            raise
        except HumanReviewRequired as error:
            if self._observer is not None and observer_token is not None:
                await self._notify_effect(
                    observer_token,
                    status="ambiguous",
                    result_hash=None,
                    error_type=type(error).__name__[:64],
                )
            raise
        except Exception as error:
            if self._observer is not None and observer_token is not None:
                await self._notify_effect(
                    observer_token,
                    status="failed",
                    result_hash=None,
                    error_type=type(error).__name__[:64],
                )
            raise
        if self._observer is not None and observer_token is not None:
            await self._notify_effect(
                observer_token,
                status="succeeded",
                result_hash=_value_hash(effect_result),
                error_type=None,
            )
        return effect_result

    async def _notify_effect(
        self,
        token: object,
        *,
        status: str,
        result_hash: str | None,
        error_type: str | None,
    ) -> None:
        """Do not turn an already-ledgered external result into a replay."""

        assert self._observer is not None
        try:
            await self._observer.effect_completed(
                token,
                status=status,
                result_hash=result_hash,
                error_type=error_type,
            )
        except asyncio.CancelledError:
            raise
        except Exception as observer_error:
            _LOGGER.error(
                "cell tool projection requires reconciliation: %s",
                type(observer_error).__name__,
            )


def _tenant_context(metadata: dict[str, Any]) -> TenantContext:
    required = (
        "tenant_id",
        "app_id",
        "config_version",
        "binding_id",
        "principal_id",
        "session_id",
        "request_id",
        "trace_id",
    )
    missing = [name for name in required if metadata.get(name) in (None, "")]
    if missing:
        raise ValueError(f"tool context is missing tenant metadata: {', '.join(missing)}")
    return TenantContext(
        tenant_id=str(metadata["tenant_id"]),
        app_id=str(metadata["app_id"]),
        config_version=int(metadata["config_version"]),
        channel_binding_id=str(metadata["binding_id"]),
        principal_id=str(metadata["principal_id"]),
        session_id=str(metadata["session_id"]),
        request_id=str(metadata["request_id"]),
        trace_id=str(metadata["trace_id"]),
    )


def _confirmation_token(metadata: dict[str, Any], tool_name: str) -> str | None:
    tokens = metadata.get("tool_confirmation_tokens")
    if not isinstance(tokens, dict):
        return None
    token = tokens.get(tool_name)
    return token if isinstance(token, str) else None


def _lease_identity(metadata: dict[str, Any]) -> tuple[str | None, int | None]:
    owner = metadata.get("lease_owner")
    epoch = metadata.get("lease_epoch")
    if owner is None and epoch is None:
        return None, None
    if not isinstance(owner, str) or not owner or not isinstance(epoch, int) or epoch < 1:
        raise ValueError("tool context has an invalid lease identity")
    return owner, epoch


def _value_hash(value: object) -> str:
    try:
        canonical = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
    except (TypeError, ValueError):
        canonical = repr(type(value))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = ["GovernedTool", "GovernedToolObserver"]
