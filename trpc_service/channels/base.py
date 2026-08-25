"""Channel contracts shared by webhook and streaming providers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol

from trpc_service.channels.envelopes import (
    DeliveryReceipt,
    InboundEnvelope,
    OutboundEnvelope,
    VerifiedCallback,
)
from trpc_service.tenant.models import ChannelBinding


@dataclass(frozen=True, slots=True)
class WebhookRequest:
    method: str
    query: Mapping[str, str] = field(default_factory=dict)
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""


class WebhookChannelAdapter(Protocol):
    def verify_url(self, request: WebhookRequest, binding: ChannelBinding) -> str: ...

    def verify_and_parse(
        self, request: WebhookRequest, binding: ChannelBinding
    ) -> VerifiedCallback: ...


class ChannelAdapter(Protocol):
    async def send(
        self, envelope: OutboundEnvelope, binding: ChannelBinding
    ) -> DeliveryReceipt: ...


InboundSink = Callable[[str, InboundEnvelope], Awaitable[None]]


class StreamingChannelConnector(Protocol):
    async def run(self, binding: ChannelBinding, sink: InboundSink) -> None: ...


__all__ = [
    "ChannelAdapter",
    "InboundSink",
    "StreamingChannelConnector",
    "WebhookChannelAdapter",
    "WebhookRequest",
]
