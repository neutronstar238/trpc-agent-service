"""IM channel adapters."""

from trpc_service.channels.base import (
    ChannelAdapter,
    StreamingChannelConnector,
    WebhookChannelAdapter,
    WebhookRequest,
)
from trpc_service.channels.envelopes import (
    DeliveryReceipt,
    DeliveryStatus,
    InboundEnvelope,
    OutboundEnvelope,
    PayloadKind,
    VerifiedCallback,
)
from trpc_service.channels.feishu import (
    FeishuAdapter,
    FeishuCallback,
    FeishuMediaError,
    FeishuResource,
    FeishuResourceError,
    FeishuVerificationError,
)

__all__ = [
    "ChannelAdapter",
    "DeliveryReceipt",
    "DeliveryStatus",
    "FeishuAdapter",
    "FeishuCallback",
    "FeishuMediaError",
    "FeishuResource",
    "FeishuResourceError",
    "FeishuVerificationError",
    "InboundEnvelope",
    "OutboundEnvelope",
    "PayloadKind",
    "StreamingChannelConnector",
    "VerifiedCallback",
    "WebhookChannelAdapter",
    "WebhookRequest",
]
