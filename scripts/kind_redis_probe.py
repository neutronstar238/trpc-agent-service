#!/usr/bin/env python3
"""Run a small, keyless Redis Streams ownership probe.

The probe intentionally uses :class:`RedisStreamQueue`, rather than issuing
the queue protocol from the script itself.  It proves the two properties that
are easy to lose during a deployment change: an outbox record is published
once even when the publisher retries, and a pending delivery can move from a
dead consumer to a surviving consumer without allowing the old owner to
refresh it.

``TRPC_SERVICE_REDIS_URL`` is read only from the environment.  The URL,
generated Redis keys, message fields, and exception text never enter the
report.  A report is always emitted as one JSON line and a missing or failed
live prerequisite exits non-zero.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol, cast

import redis.asyncio as redis_async

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.evidence_lineage import source_fingerprint
from trpc_service.queue.redis_streams import RedisStreamQueue
from trpc_service.storage.models import OutboxRecord

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = "publish_idempotency_pel_takeover"
ASSERTION = "production RedisStreamQueue proves publish idempotency, PEL takeover and exact ACK"
RECLAIM_AFTER_MS = 250
TAKEOVER_TIMEOUT_SECONDS = 5.0
CONSUMER_A = "consumer-a"
CONSUMER_B = "consumer-b"


class _RedisProbeClient(Protocol):
    async def delete(self, *keys: str) -> int: ...

    async def xlen(self, name: str) -> int: ...

    async def xpending(self, name: str, groupname: str) -> Any: ...

    async def aclose(self) -> None: ...


ClientFactory = Callable[..., _RedisProbeClient]


def _safe_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _source_lineage() -> dict[str, Any]:
    """Return only the bounded content fingerprint used by other gates."""

    try:
        lineage = source_fingerprint(ROOT)
        return {key: lineage[key] for key in ("algorithm", "status", "value") if key in lineage}
    except Exception as exc:  # pragma: no cover - defensive report boundary
        return {
            "algorithm": "sha256",
            "status": "unavailable",
            "reason": type(exc).__name__,
        }


def _initial_checks() -> dict[str, dict[str, Any]]:
    return {
        "publish_once": {"status": "not_run"},
        "consumer_a_pel": {"status": "not_run"},
        "consumer_b_takeover": {"status": "not_run"},
        "stale_owner_defer_rejected": {"status": "not_run"},
        "consumer_b_ack_pel_empty": {"status": "not_run"},
        "cleanup": {"status": "not_run"},
    }


def _report(
    *,
    status: str,
    checks: Mapping[str, Mapping[str, Any]],
    rejection_reasons: list[str],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "probe": "kind_redis_probe",
        "scenario": SCENARIO,
        "assertion": ASSERTION,
        "status": status,
        "source_fingerprint": _source_lineage(),
        "checks": {name: dict(value) for name, value in checks.items()},
        "rejection_reasons": list(dict.fromkeys(rejection_reasons)),
    }


async def _pending_count(client: _RedisProbeClient, stream: str, group: str) -> int:
    raw = await client.xpending(stream, group)
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    if isinstance(raw, Mapping):
        value = raw.get("pending", raw.get(b"pending", 0))
        return int(value)
    if isinstance(raw, (tuple, list)) and raw:
        return int(raw[0])
    return 0


async def _run_live_scenario(
    client_a: _RedisProbeClient,
    client_b: _RedisProbeClient,
    *,
    stream: str,
    group: str,
    outbox_id: str,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    checks = _initial_checks()
    reasons: list[str] = []
    queue_a = RedisStreamQueue(
        cast(Any, client_a),
        stream=stream,
        group=group,
        reclaim_after_ms=RECLAIM_AFTER_MS,
    )
    queue_b = RedisStreamQueue(
        cast(Any, client_b),
        stream=stream,
        group=group,
        reclaim_after_ms=RECLAIM_AFTER_MS,
    )
    try:
        await queue_a.ensure_group()
        await queue_b.ensure_group()
        record = OutboxRecord(
            outbox_id=outbox_id,
            tenant_id="kind-redis-probe-tenant",
            event_type="inbound.accepted",
            aggregate_id="kind-redis-probe-aggregate",
            payload={"probe": "kind_redis_probe"},
            trace_headers={"trace_id": _safe_hash(outbox_id)},
        )
        first = await queue_a.publish(record)
        duplicate = await queue_a.publish(record)
        stream_length = await client_a.xlen(stream)
        publish_passed = first is not None and duplicate is None and stream_length == 1
        checks["publish_once"] = {
            "status": "pass" if publish_passed else "fail",
            "first_publish": first is not None,
            "duplicate_suppressed": duplicate is None,
            "stream_entries": stream_length,
        }
        if not publish_passed:
            reasons.append("publish_idempotency_failed")

        delivered = await queue_a.consume(consumer=CONSUMER_A, block_ms=100)
        pending_before = await _pending_count(client_a, stream, group)
        pel_passed = len(delivered) == 1 and pending_before == 1
        checks["consumer_a_pel"] = {
            "status": "pass" if pel_passed else "fail",
            "delivered": len(delivered),
            "pending": pending_before,
        }
        if not pel_passed:
            reasons.append("consumer_a_pel_not_formed")
        if len(delivered) != 1:
            reasons.append("consumer_a_delivery_missing")
            return checks, reasons

        original = delivered[0]
        reclaimed: tuple[Any, ...] = ()
        deadline = asyncio.get_running_loop().time() + TAKEOVER_TIMEOUT_SECONDS
        while asyncio.get_running_loop().time() < deadline:
            reclaimed = await queue_b.consume(consumer=CONSUMER_B, block_ms=1)
            if reclaimed:
                break
            await asyncio.sleep(0.05)
        takeover_passed = len(reclaimed) == 1 and reclaimed[0].stream_id == original.stream_id
        checks["consumer_b_takeover"] = {
            "status": "pass" if takeover_passed else "fail",
            "reclaimed": len(reclaimed),
        }
        if not takeover_passed:
            reasons.append("consumer_b_takeover_failed")
            return checks, reasons

        stale_defer = await queue_a.defer(original, CONSUMER_A, retry_delay_seconds=0)
        defer_passed = stale_defer is False
        checks["stale_owner_defer_rejected"] = {
            "status": "pass" if defer_passed else "fail",
            "accepted": stale_defer,
        }
        if not defer_passed:
            reasons.append("stale_owner_defer_accepted")

        await queue_b.ack(reclaimed[0])
        pending_after = await _pending_count(client_b, stream, group)
        ack_passed = pending_after == 0
        checks["consumer_b_ack_pel_empty"] = {
            "status": "pass" if ack_passed else "fail",
            "pending": pending_after,
        }
        if not ack_passed:
            reasons.append("consumer_b_ack_left_pending_delivery")
    except Exception as exc:
        reasons.append(f"runtime_{type(exc).__name__}")
    return checks, reasons


async def run_probe(
    redis_url: str | None = None,
    *,
    client_factory: ClientFactory | None = None,
) -> dict[str, Any]:
    """Run the live scenario and return a report without secret material."""

    checks = _initial_checks()
    reasons: list[str] = []
    configured_url = os.getenv("TRPC_SERVICE_REDIS_URL", "") if redis_url is None else redis_url
    if not isinstance(configured_url, str) or not configured_url.strip():
        reasons.append("TRPC_SERVICE_REDIS_URL is not configured")
        return _report(status="not_run", checks=checks, rejection_reasons=reasons)

    suffix = uuid.uuid4().hex
    stream = f"trpc:kind:redis:{suffix}"
    group = f"trpc-kind-redis-{suffix}"
    outbox_id = f"kind-redis-{suffix}"
    dedupe_key = f"trpc:published:{outbox_id}"
    factory = redis_async.from_url if client_factory is None else client_factory
    client_a: _RedisProbeClient | None = None
    client_b: _RedisProbeClient | None = None
    cleanup_reasons: list[str] = []
    try:
        client_a = cast(_RedisProbeClient, factory(configured_url, decode_responses=False))
        client_b = cast(_RedisProbeClient, factory(configured_url, decode_responses=False))
        checks, reasons = await _run_live_scenario(
            client_a,
            client_b,
            stream=stream,
            group=group,
            outbox_id=outbox_id,
        )
    except Exception as exc:
        reasons.append(f"client_{type(exc).__name__}")
    finally:
        if client_a is not None:
            try:
                await client_a.delete(stream, dedupe_key)
            except Exception as exc:
                cleanup_reasons.append(f"delete_{type(exc).__name__}")
            try:
                await client_a.aclose()
            except Exception as exc:
                cleanup_reasons.append(f"close_a_{type(exc).__name__}")
        if client_b is not None:
            try:
                await client_b.aclose()
            except Exception as exc:
                cleanup_reasons.append(f"close_b_{type(exc).__name__}")
    if cleanup_reasons:
        checks["cleanup"] = {"status": "fail"}
        reasons.extend(cleanup_reasons)
    else:
        checks["cleanup"] = {"status": "pass"}

    required = tuple(name for name in checks if name != "cleanup")
    if reasons:
        status = "fail"
    elif all(checks[name].get("status") == "pass" for name in required):
        status = "pass"
    else:
        status = "fail"
        reasons.append("required_check_incomplete")
    return _report(status=status, checks=checks, rejection_reasons=reasons)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="retain the keyless JSON-line output")
    parser.parse_args()
    report = asyncio.run(run_probe())
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":  # pragma: no cover - exercised by the image gate
    raise SystemExit(main())
