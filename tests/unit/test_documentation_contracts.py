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


def test_im_documentation_preserves_independent_evidence_boundaries() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "im-channels.md").read_text(encoding="utf-8")
    testing = (ROOT / "docs" / "testing.md").read_text(encoding="utf-8")
    nginx = (ROOT / "deploy" / "im_probe" / "nginx-server.conf.example").read_text(encoding="utf-8")

    for marker in (
        "wecom_connection_state",
        "im_acceptance_evidence_events",
        "OpenAPI witness",
        "服务侧 replay",
        "provider delivery gap",
    ):
        assert marker in guide
    for marker in (
        "8 个 case",
        "host-only control broker",
        "callback observer",
        "OpenAPI witness",
    ):
        assert marker in testing
    assert "破坏性生产灾备" in readme
    assert "production_gate=not_run" in readme
    assert "mirror /_trpc_feishu_callback_observer" in nginx
    assert "location ^~ /feishu-openapi/" in nginx
