"""Tenant-aware wrapper around the public tRPC-Agent Runner API."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Protocol

from trpc_agent_sdk.agents import BaseAgent
from trpc_agent_sdk.context import new_agent_context
from trpc_agent_sdk.events import Event
from trpc_agent_sdk.runners import Runner
from trpc_agent_sdk.types import Blob, Content, Part

from trpc_service.agent.registry import RevisionRegistry
from trpc_service.agent.session import TurnBufferSessionService
from trpc_service.channels.envelopes import InboundEnvelope
from trpc_service.storage.models import SessionLease, StoredEvent
from trpc_service.storage.services import TenantDataServices
from trpc_service.tenant.models import TenantConfig, TenantContext
from trpc_service.workspace import TenantWorkspace


class AgentLoader(Protocol):
    async def __call__(self, config: TenantConfig) -> BaseAgent: ...


@dataclass(frozen=True, slots=True)
class PreparedMedia:
    """A durable attachment transformed into bounded model input."""

    filename: str | None
    content_type: str
    text: str | None = None
    inline_data: bytes | None = None


class TenantRunner:
    """Run one fenced turn with a configuration revision pinned at acceptance."""

    def __init__(
        self,
        *,
        config: TenantConfig,
        lease: SessionLease,
        registry: RevisionRegistry[BaseAgent],
        agent_loader: AgentLoader,
        services: TenantDataServices | None = None,
        workspace: TenantWorkspace | None = None,
    ) -> None:
        if not lease.snapshot_hydrated:
            raise ValueError("TenantRunner requires a hydrated session snapshot")
        self._config = config
        self._lease = lease
        self._registry = registry
        self._agent_loader = agent_loader
        self._workspace = workspace
        self._session_service = (
            services.session.open_turn(lease.snapshot)
            if services is not None
            else TurnBufferSessionService(lease.snapshot)
        )

    @property
    def buffered_events(self) -> tuple[StoredEvent, ...]:
        return self._session_service.buffered_events

    @property
    def state(self) -> dict[str, object]:
        return self._session_service.state

    async def run(
        self,
        context: TenantContext,
        envelope: InboundEnvelope,
        *,
        prepared_media: tuple[PreparedMedia, ...] = (),
    ) -> AsyncIterator[Event]:
        if context.config_version != self._config.version:
            raise ValueError("runner configuration does not match the pinned context")
        key = (context.tenant_id, context.app_id, context.config_version)

        async def load() -> BaseAgent:
            return await self._agent_loader(self._config)

        async with self._registry.use(key, load) as agent:
            runner = Runner(
                app_name=context.app_id,
                agent=agent,
                session_service=self._session_service,
                enable_post_turn_processing=False,
                close_session_service_on_close=False,
                close_memory_service_on_close=False,
            )
            metadata: dict[str, object] = {
                "tenant_id": context.tenant_id,
                "app_id": context.app_id,
                "config_version": context.config_version,
                "binding_id": context.channel_binding_id,
                "principal_id": context.principal_id,
                "session_id": context.session_id,
                "turn_id": self._lease.turn_id,
                "lease_owner": self._lease.worker_id,
                "lease_epoch": self._lease.fencing_token,
                "request_id": context.request_id,
                "trace_id": context.trace_id,
            }
            if self._workspace is not None:
                metadata.update(self._workspace.metadata)
            agent_context = new_agent_context(
                timeout=round(self._config.model.timeout_seconds * 1000),
                metadata=metadata,
            )
            content = _message_content(envelope, prepared_media)
            async for event in runner.run_async(
                user_id=context.principal_id,
                session_id=context.session_id,
                new_message=content,
                agent_context=agent_context,
            ):
                yield event


def _message_content(
    envelope: InboundEnvelope, prepared_media: tuple[PreparedMedia, ...]
) -> Content:
    parts: list[Part] = []
    if envelope.text:
        parts.append(Part(text=envelope.text))
    elif prepared_media:
        parts.append(Part(text="The user attached media for this request."))

    for item in prepared_media:
        label = "Attached media"
        if item.filename:
            label = f"Attached media ({item.filename})"
        if item.text:
            parts.append(Part(text=f"{label}:\n{item.text}"))
        elif item.inline_data is None:
            parts.append(Part(text=f"{label}: content unavailable"))
        if item.inline_data is not None:
            parts.append(
                Part(
                    inline_data=Blob(
                        data=item.inline_data,
                        mime_type=item.content_type,
                    )
                )
            )

    if not parts:
        parts.append(Part(text=_media_prompt(envelope)))
    return Content(role="user", parts=parts)


def _media_prompt(envelope: InboundEnvelope) -> str:
    if envelope.media:
        return f"User sent {envelope.payload_kind.value} media ({len(envelope.media)} item(s))."
    if envelope.event_type:
        return f"IM event: {envelope.event_type}"
    return "User sent an empty message."


__all__ = ["AgentLoader", "PreparedMedia", "TenantRunner"]
