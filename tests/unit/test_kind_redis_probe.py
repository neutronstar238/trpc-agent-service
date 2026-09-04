"""Deterministic tests for the keyless Redis Streams acceptance probe."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest
from redis.exceptions import ResponseError

from scripts import kind_redis_probe


class _FakeRedis:
    """Small Redis Streams model covering the commands used by the probe."""

    def __init__(self, state: dict[str, Any]) -> None:
        self.state = state
        self.closed = False
        self.deleted: list[tuple[str, ...]] = []
        self.group_create_calls = 0
        self.xautoclaim_calls = 0

    async def xgroup_create(self, stream: str, group: str, **_kwargs: Any) -> None:
        self.group_create_calls += 1
        groups = self.state.setdefault("groups", set())
        if (stream, group) in groups:
            raise ResponseError("BUSYGROUP Consumer Group name already exists")
        groups.add((stream, group))

    async def eval(self, script: str, key_count: int, *args: Any) -> Any:
        del key_count
        if "redis.call('SET'" in script and "XADD" in script:
            (
                dedupe_key,
                stream,
                _ttl,
                outbox_id,
                tenant_id,
                event_type,
                aggregate_id,
                payload,
                trace,
            ) = args
            if dedupe_key in self.state["dedupe"]:
                return b""
            self.state["dedupe"].add(dedupe_key)
            counter = self.state.setdefault("next_id", 0) + 1
            self.state["next_id"] = counter
            stream_id = f"{counter}-0".encode()
            fields = {
                b"outbox_id": str(outbox_id).encode(),
                b"tenant_id": str(tenant_id).encode(),
                b"event_type": str(event_type).encode(),
                b"aggregate_id": str(aggregate_id).encode(),
                b"payload": str(payload).encode(),
                b"trace_headers": str(trace).encode(),
            }
            self.state.setdefault("entries", {}).setdefault(stream, []).append((stream_id, fields))
            return stream_id

        stream, group, stream_id, consumer = args
        pending = self.state["pending"].get((stream, group, stream_id))
        if pending is None or pending["consumer"] != consumer:
            return 0
        pending["consumer"] = consumer
        return 1

    async def xreadgroup(
        self,
        group: str,
        consumer: str,
        *,
        streams: Mapping[str, str],
        **_kwargs: Any,
    ) -> list[tuple[str, list[tuple[bytes, dict[bytes, bytes]]]]]:
        stream = next(iter(streams))
        delivered = []
        for entry in self.state.get("entries", {}).get(stream, []):
            stream_id, fields = entry
            pending_key = (stream, group, stream_id.decode())
            if pending_key in self.state["pending"]:
                continue
            self.state["pending"][pending_key] = {
                "consumer": consumer,
                "claim_attempts": 0,
                "fields": fields,
            }
            delivered.append(entry)
            if len(delivered) >= int(_kwargs.get("count", 10)):
                break
        return [(stream, delivered)] if delivered else []

    async def xautoclaim(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        min_idle_time: int,
        start_id: str,
        count: int,
    ) -> tuple[bytes, list[tuple[bytes, dict[bytes, bytes]]], list[bytes]]:
        self.xautoclaim_calls += 1
        del min_idle_time, start_id
        for (pending_stream, pending_group, stream_id), pending in self.state["pending"].items():
            if pending_stream != stream or pending_group != group:
                continue
            if pending["consumer"] == consumer:
                continue
            pending["claim_attempts"] += 1
            if pending["claim_attempts"] >= 2:
                pending["consumer"] = consumer
                return b"0-0", [(stream_id.encode(), pending["fields"])], []
            break
        return b"0-0", [], []

    async def xack(self, stream: str, group: str, stream_id: str) -> int:
        self.state["pending"].pop((stream, group, stream_id), None)
        return 1

    async def xlen(self, stream: str) -> int:
        return len(self.state.get("entries", {}).get(stream, []))

    async def xpending(self, stream: str, group: str) -> dict[str, int]:
        count = sum(
            1
            for (pending_stream, pending_group, _stream_id) in self.state["pending"]
            if pending_stream == stream and pending_group == group
        )
        return {"pending": count}

    async def delete(self, *keys: str) -> int:
        self.deleted.append(tuple(keys))
        for key in keys:
            self.state.get("dedupe", set()).discard(key)
            self.state.get("entries", {}).pop(key, None)
        return len(keys)

    async def aclose(self) -> None:
        self.closed = True


def _factory_pair() -> tuple[dict[str, Any], list[_FakeRedis], Any]:
    state: dict[str, Any] = {"groups": set(), "dedupe": set(), "entries": {}, "pending": {}}
    clients = [_FakeRedis(state), _FakeRedis(state)]

    def factory(_url: str, **_kwargs: Any) -> _FakeRedis:
        return clients.pop(0)

    return state, clients, factory


@pytest.mark.asyncio
async def test_run_probe_uses_queue_idempotency_takeover_and_exact_cleanup() -> None:
    state, clients, factory = _factory_pair()
    client_a, client_b = clients
    report = await kind_redis_probe.run_probe(
        "redis://user:secret@example.invalid/9",
        client_factory=factory,
    )

    assert report["probe"] == "kind_redis_probe"
    assert report["scenario"] == "publish_idempotency_pel_takeover"
    assert report["status"] == "pass"
    assert report["rejection_reasons"] == []
    assert all(item["status"] == "pass" for item in report["checks"].values())
    assert state["next_id"] == 1
    assert clients == []
    assert client_a.closed and client_b.closed
    assert len(client_a.deleted) == 1
    deleted_stream, deleted_dedupe = client_a.deleted[0]
    assert deleted_stream.startswith("trpc:kind:redis:")
    assert deleted_dedupe.startswith("trpc:published:kind-redis-")
    assert client_b.deleted == []
    assert client_b.xautoclaim_calls >= 2
    # The two generated names are deliberately absent from the report, while
    # cleanup still receives exactly the stream and dedupe key for this run.
    serialized = json.dumps(report, sort_keys=True)
    assert "redis://" not in serialized
    assert "secret" not in serialized
    assert len(state["pending"]) == 0


@pytest.mark.asyncio
async def test_run_probe_reports_missing_url_without_constructing_client() -> None:
    called = False

    def factory(*_args: Any, **_kwargs: Any) -> _FakeRedis:
        nonlocal called
        called = True
        raise AssertionError("factory must not be called")

    report = await kind_redis_probe.run_probe("", client_factory=factory)
    assert report["status"] == "not_run"
    assert report["checks"]["publish_once"]["status"] == "not_run"
    assert report["rejection_reasons"] == ["TRPC_SERVICE_REDIS_URL is not configured"]
    assert not called


@pytest.mark.asyncio
async def test_run_probe_sanitizes_client_and_cleanup_failures() -> None:
    state, clients, _factory = _factory_pair()

    class _BrokenClient(_FakeRedis):
        async def xgroup_create(self, stream: str, group: str, **kwargs: Any) -> None:
            del stream, group, kwargs
            raise RuntimeError("dsn=redis://secret must not escape")

        async def delete(self, *keys: str) -> int:
            del keys
            raise OSError("cleanup failed")

    first = _BrokenClient(state)
    second = _FakeRedis(state)
    clients = [first, second]

    def factory(_url: str, **_kwargs: Any) -> _FakeRedis:
        return clients.pop(0)

    report = await kind_redis_probe.run_probe("redis://secret", client_factory=factory)
    assert report["status"] == "fail"
    assert report["checks"]["cleanup"]["status"] == "fail"
    assert any(reason.startswith("runtime_") for reason in report["rejection_reasons"])
    assert any(reason.startswith("delete_") for reason in report["rejection_reasons"])
    serialized = json.dumps(report, sort_keys=True)
    assert "redis://" not in serialized
    assert "secret" not in serialized


def test_source_lineage_is_keyless_and_bounded() -> None:
    lineage = kind_redis_probe._source_lineage()
    assert lineage["algorithm"] == "sha256"
    assert lineage["status"] in {"available", "unavailable"}
    assert "value" not in lineage or len(str(lineage["value"])) == 64
