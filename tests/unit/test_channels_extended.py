from __future__ import annotations

from types import SimpleNamespace

import pytest

from trpc_service.channels.envelopes import DeliveryStatus, OutboundEnvelope, PayloadKind
from trpc_service.channels.wecom import WeComConnector, parse_wecom_frame, sdk_client_factory
from trpc_service.config.secrets import LocalSecretProvider, SecretRef
from trpc_service.tenant.models import Channel, ChannelBinding


def outbound(*, kind=PayloadKind.TEXT, text="reply") -> OutboundEnvelope:
    return OutboundEnvelope(
        outbound_id="out",
        tenant_id="tenant",
        binding_id="wecom",
        channel=Channel.WECOM_AI_BOT,
        target_id="user",
        session_id="session",
        payload_kind=kind,
        text=text,
    )


def test_parse_all_wecom_frame_variants() -> None:
    voice = parse_wecom_frame(
        {"body": {"from": {"userid": "u"}, "msgtype": "voice", "voice": {"content": "hi"}}},
        account_id="bot",
    )
    assert voice.text == "hi" and voice.external_message_id.startswith("frame_")
    for kind in ("image", "file", "video"):
        value = parse_wecom_frame(
            {
                "body": {
                    "from": {"userid": "u"},
                    "msgtype": kind,
                    kind: {"url": "https://media", "filename": "file"},
                }
            },
            account_id="bot",
        )
        assert value.media[0].filename == "file"
    event = parse_wecom_frame(
        {
            "body": {
                "from": {"userid": "u"},
                "msgtype": "unknown",
                "event": {"eventtype": "recall"},
            }
        },
        account_id="bot",
    )
    assert event.payload_kind == PayloadKind.EVENT and event.event_type == "recall"
    assert event.provider_metadata["target_id"] == "u"
    with pytest.raises(ValueError, match="body"):
        parse_wecom_frame(SimpleNamespace(body="bad"), account_id="bot")
    with pytest.raises(ValueError, match="sender"):
        parse_wecom_frame({"body": {"from": "bad"}}, account_id="bot")


class Lease:
    def __init__(self, allowed=True) -> None:
        self.allowed = allowed
        self.released = []

    async def acquire_binding(self, binding_id, owner_id):
        return self.allowed

    async def release_binding(self, binding_id, owner_id):
        self.released.append((binding_id, owner_id))


class Client:
    def __init__(self, *, connected=True, async_disconnect=False) -> None:
        self.is_connected = connected
        self.handlers = {}
        self.async_disconnect = async_disconnect
        self.sent = []
        self.send_error = None
        self.response = {"req_id": "provider"}

    def on(self, event, handler):
        self.handlers[event] = handler

    async def connect_async(self):
        handler = self.handlers["message.text"]
        await handler(
            {"body": {"from": {"userid": "u"}, "msgtype": "text", "text": {"content": "x"}}}
        )
        if self.is_connected:
            await self.handlers["disconnected"]()

    def disconnect(self):
        if self.async_disconnect:

            async def done():
                return None

            return done()
        return None

    async def send_message(self, chat_id, body):
        if self.send_error:
            raise self.send_error
        self.sent.append((chat_id, body))
        return self.response


def wecom_binding(*, secret=True) -> ChannelBinding:
    refs = {"bot_secret": SecretRef(uri="literal://bot-secret")} if secret else {}
    return ChannelBinding(
        binding_id="wecom",
        tenant_id="tenant",
        app_id="app",
        channel=Channel.WECOM_AI_BOT,
        account_id="bot",
        secret_refs=refs,
    )


@pytest.mark.asyncio
async def test_wecom_connector_lifecycle_and_send_contract() -> None:
    denied = WeComConnector(
        LocalSecretProvider(allow_literal=True),
        Lease(False),
        owner_id="owner",
        client_factory=lambda *args: Client(),
    )
    with pytest.raises(RuntimeError, match="owns"):
        await denied.run(wecom_binding(), lambda *args: None)

    lease = Lease()
    missing = WeComConnector(
        LocalSecretProvider(allow_literal=True),
        lease,
        owner_id="owner",
        client_factory=lambda *args: Client(),
    )
    with pytest.raises(RuntimeError, match="not configured"):
        await missing.run(wecom_binding(secret=False), lambda *args: None)
    assert lease.released

    client = Client(async_disconnect=True)
    connector = WeComConnector(
        LocalSecretProvider(allow_literal=True),
        lease,
        owner_id="owner",
        client_factory=lambda *args: client,
    )
    accepted = []

    async def sink(binding_id, inbound):
        accepted.append((binding_id, inbound))

    await connector.run(wecom_binding(), sink)
    assert len(accepted) == 1
    assert accepted[0][1].payload_kind == PayloadKind.TEXT
    assert "event" not in client.handlers
    assert lease.released[-1] == ("wecom", "owner")

    unavailable = await connector.send(outbound(), wecom_binding())
    assert unavailable.provider_code == "connector_unavailable"
    connector._clients["wecom"] = client
    unsupported = await connector.send(outbound(kind=PayloadKind.IMAGE, text=None), wecom_binding())
    assert unsupported.provider_code == "unsupported_payload"
    delivered = await connector.send(outbound(), wecom_binding())
    assert delivered.status == DeliveryStatus.DELIVERED
    client.response = SimpleNamespace(req_id="attribute-id")
    assert (await connector.send(outbound(), wecom_binding())).provider_message_id == "attribute-id"
    client.send_error = TimeoutError()
    assert (await connector.send(outbound(), wecom_binding())).status == DeliveryStatus.AMBIGUOUS


def test_sdk_wecom_client_factory_constructs_public_client() -> None:
    client = sdk_client_factory("bot", "secret")
    assert client is not None
