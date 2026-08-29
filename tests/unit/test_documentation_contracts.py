from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_wecom_documentation_uses_websocket_not_http_callback_sequence() -> None:
    architecture = (ROOT / "docs" / "architecture.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "im-channels.md").read_text(encoding="utf-8")

    assert 'wecom["企业微信"] <-->|WSS authenticated frames|' in architecture
    assert 'feishu["飞书"] -->|HTTPS callback|' in architecture
    required = (
        "pg_try_advisory_lock",
        "wss:443",
        "aibot_subscribe",
        "cmd=ping",
        "aibot_msg_callback",
        "durable acceptance",
        "aibot_send_msg",
        "same req_id, errcode/errmsg ACK",
        "ambiguous",
        "pg_advisory_unlock",
        "event.disconnected_event",
    )
    for marker in required:
        assert marker in guide
    assert "no HTTP 2xx" in guide
