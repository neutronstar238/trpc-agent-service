#!/usr/bin/env python3
"""Exercise real Feishu gateway idempotency against the kind PostgreSQL.

The probe runs inside the candidate image.  It seeds two synthetic tenants,
sends the same encrypted callback through the Kubernetes Service, and then
checks the authoritative rows under each tenant's RLS scope.  Only synthetic
identifiers and aggregate counts are printed; configured secrets and callback
contents are never included in the report.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import asyncpg
import httpx
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.evidence_lineage import source_fingerprint
from trpc_service.tenant.models import ModelPolicy, StorageSelection, TenantConfig

ROOT = Path(__file__).resolve().parents[1]
ASSERTION = "candidate image proves Feishu callback idempotency, RLS and signature rejection"


def _source_lineage() -> dict[str, Any]:
    try:
        lineage = source_fingerprint(ROOT)
        return {key: lineage[key] for key in ("algorithm", "status", "value") if key in lineage}
    except Exception as error:  # pragma: no cover - defensive report boundary
        return {
            "algorithm": "sha256",
            "status": "unavailable",
            "reason": type(error).__name__,
        }


@dataclass(frozen=True, slots=True)
class _TenantFixture:
    tenant_id: str
    binding_id: str
    account_id: str


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"required probe setting {name} is unavailable")
    return value


def _signed_callback(
    *,
    account_id: str,
    message_id: str,
    verification_token: str,
    encrypt_key: str,
) -> tuple[bytes, dict[str, str]]:
    now_seconds = int(time.time())
    payload = {
        "schema": "2.0",
        "header": {
            "event_id": f"event-{message_id}",
            "event_type": "im.message.receive_v1",
            "create_time": str(now_seconds * 1000),
            "token": verification_token,
            "app_id": account_id,
            "tenant_key": "kind-synthetic",
        },
        "event": {
            "sender": {
                "sender_id": {"open_id": "kind-user"},
                "sender_type": "user",
                "tenant_key": "kind-synthetic",
            },
            "message": {
                "message_id": message_id,
                "create_time": str(now_seconds * 1000),
                "chat_id": "kind-direct-chat",
                "chat_type": "p2p",
                "message_type": "text",
                "content": json.dumps({"text": "kind idempotency probe"}),
            },
        },
    }
    plaintext = json.dumps(payload, separators=(",", ":")).encode()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    key = hashlib.sha256(encrypt_key.encode()).digest()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    body = json.dumps(
        {"encrypt": base64.b64encode(iv + encrypted).decode()}, separators=(",", ":")
    ).encode()
    timestamp = str(now_seconds)
    nonce = secrets.token_hex(8)
    signature = hashlib.sha256(
        timestamp.encode() + nonce.encode() + encrypt_key.encode() + body
    ).hexdigest()
    return body, {
        "Content-Type": "application/json",
        "X-Lark-Request-Timestamp": timestamp,
        "X-Lark-Request-Nonce": nonce,
        "X-Lark-Signature": signature,
    }


async def _seed(
    pool: asyncpg.Pool,
    fixture: _TenantFixture,
    *,
    verification_token_env: str,
    encrypt_key_env: str,
) -> None:
    config = TenantConfig(
        tenant_id=fixture.tenant_id,
        app_id="support",
        version=1,
        model=ModelPolicy(provider="offline", model="deterministic-fake"),
        storage=StorageSelection(profile_id="default"),
    )
    config_text = json.dumps(
        config.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    checksum = hashlib.sha256(config_text.encode()).hexdigest()
    secret_refs = json.dumps(
        {
            "verification_token": f"env://{verification_token_env}",
            "encrypt_key": f"env://{encrypt_key_env}",
        },
        separators=(",", ":"),
    )
    async with pool.acquire() as connection, connection.transaction():
        await connection.execute("SELECT set_config('app.tenant_id', $1, true)", fixture.tenant_id)
        await connection.execute(
            "INSERT INTO tenants (tenant_id,display_name) VALUES ($1,$2)",
            fixture.tenant_id,
            "kind synthetic tenant",
        )
        await connection.execute(
            """INSERT INTO agent_apps (tenant_id,app_id,display_name)
               VALUES ($1,'support','kind synthetic app')""",
            fixture.tenant_id,
        )
        await connection.execute(
            """INSERT INTO config_revisions
                   (tenant_id,app_id,version,config_json,checksum,created_by)
               VALUES ($1,'support',1,$2::jsonb,$3,'kind-gateway-probe')""",
            fixture.tenant_id,
            config_text,
            checksum,
        )
        await connection.execute(
            """INSERT INTO storage_profiles (tenant_id,profile_id,profile_json)
               VALUES ($1,'default','{}'::jsonb)""",
            fixture.tenant_id,
        )
        await connection.execute(
            """INSERT INTO channel_bindings
                   (tenant_id,binding_id,app_id,channel,account_id,
                    secret_refs,capabilities)
               VALUES ($1,$2,'support','feishu',$3,$4::jsonb,
                       '["text"]'::jsonb)""",
            fixture.tenant_id,
            fixture.binding_id,
            fixture.account_id,
            secret_refs,
        )


async def _tenant_counts(pool: asyncpg.Pool, tenant_id: str) -> dict[str, Any]:
    async with pool.acquire() as connection, connection.transaction():
        await connection.execute("SELECT set_config('app.tenant_id', $1, true)", tenant_id)
        row = await connection.fetchrow(
            """SELECT
                   (SELECT count(*) FROM inbound_messages WHERE tenant_id=$1) AS inbound,
                   (SELECT count(*) FROM audit_logs
                     WHERE tenant_id=$1 AND decision='inbound_accepted') AS accepted_audit,
                   (SELECT count(*) FROM session_mailboxes WHERE tenant_id=$1) AS mailboxes,
                   (SELECT count(*) FROM session_mailbox_items WHERE tenant_id=$1) AS mailbox_items,
                   (SELECT count(*) FROM outbox_events
                     WHERE tenant_id=$1 AND event_type='session.ready.v2') AS ready_events,
                   (SELECT min(session_id) FROM inbound_messages
                     WHERE tenant_id=$1) AS session_id""",
            tenant_id,
        )
    assert row is not None
    return {
        "inbound": int(row["inbound"]),
        "accepted_audit": int(row["accepted_audit"]),
        "mailboxes": int(row["mailboxes"]),
        "mailbox_items": int(row["mailbox_items"]),
        "ready_events": int(row["ready_events"]),
        "session_digest": hashlib.sha256(str(row["session_id"]).encode()).hexdigest(),
    }


def _evaluate(
    *,
    duplicate_statuses: list[int],
    second_tenant_status: int,
    invalid_signature_status: int,
    first: dict[str, Any],
    second: dict[str, Any],
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if duplicate_statuses != [200] * 100:
        reasons.append("not_all_duplicate_callbacks_were_acknowledged")
    if second_tenant_status != 200:
        reasons.append("same_message_id_in_second_tenant_was_rejected")
    if invalid_signature_status != 403:
        reasons.append("invalid_signature_did_not_fail_closed")
    expected = {
        "inbound": 1,
        "accepted_audit": 1,
        "mailboxes": 1,
        "mailbox_items": 1,
        "ready_events": 1,
    }
    for label, counts in (("tenant_a", first), ("tenant_b", second)):
        for key, value in expected.items():
            if counts.get(key) != value:
                reasons.append(f"{label}_{key}_was_not_exactly_once")
    if first.get("session_digest") == second.get("session_digest"):
        reasons.append("cross_tenant_session_isolation_failed")
    return not reasons, reasons


async def run() -> dict[str, Any]:
    dsn = _required("TRPC_SERVICE_DATABASE_DSN").replace("postgresql+asyncpg://", "postgresql://")
    gateway = os.getenv("TRPC_KIND_GATEWAY_URL", "http://trpc-gateway:8080").rstrip("/")
    token_name = "TRPC_FEISHU_KIND_VERIFICATION_TOKEN"  # noqa: S105 - env name only
    key_name = "TRPC_FEISHU_KIND_ENCRYPT_KEY"
    token = _required(token_name)
    encrypt_key = _required(key_name)
    suffix = secrets.token_hex(8)
    account_id = f"cli_kind_{suffix}"
    first_fixture = _TenantFixture(
        tenant_id=f"kind-im-a-{suffix}",
        binding_id=f"kind-binding-a-{suffix}",
        account_id=account_id,
    )
    second_fixture = _TenantFixture(
        tenant_id=f"kind-im-b-{suffix}",
        binding_id=f"kind-binding-b-{suffix}",
        account_id=account_id,
    )
    message_id = f"kind-shared-message-{suffix}"
    pool = await asyncpg.create_pool(dsn, min_size=2, max_size=8, command_timeout=30)
    try:
        await asyncio.gather(
            _seed(
                pool,
                first_fixture,
                verification_token_env=token_name,
                encrypt_key_env=key_name,
            ),
            _seed(
                pool,
                second_fixture,
                verification_token_env=token_name,
                encrypt_key_env=key_name,
            ),
        )
        body, headers = _signed_callback(
            account_id=account_id,
            message_id=message_id,
            verification_token=token,
            encrypt_key=encrypt_key,
        )
        async with httpx.AsyncClient(timeout=30) as client:
            first_url = f"{gateway}/v1/channels/feishu/{first_fixture.binding_id}/callback"
            second_url = f"{gateway}/v1/channels/feishu/{second_fixture.binding_id}/callback"
            responses = await asyncio.gather(
                *(client.post(first_url, content=body, headers=headers) for _ in range(100))
            )
            second_response = await client.post(second_url, content=body, headers=headers)
            invalid_headers = {**headers, "X-Lark-Signature": "0" * 64}
            invalid_response = await client.post(first_url, content=body, headers=invalid_headers)
        first_counts, second_counts = await asyncio.gather(
            _tenant_counts(pool, first_fixture.tenant_id),
            _tenant_counts(pool, second_fixture.tenant_id),
        )
        statuses = sorted(response.status_code for response in responses)
        passed, reasons = _evaluate(
            duplicate_statuses=statuses,
            second_tenant_status=second_response.status_code,
            invalid_signature_status=invalid_response.status_code,
            first=first_counts,
            second=second_counts,
        )
        expected_counts = {
            "inbound": 1,
            "accepted_audit": 1,
            "mailboxes": 1,
            "mailbox_items": 1,
            "ready_events": 1,
        }
        tenant_isolation = (
            second_response.status_code == 200
            and all(first_counts.get(name) == value for name, value in expected_counts.items())
            and all(second_counts.get(name) == value for name, value in expected_counts.items())
            and first_counts.get("session_digest") != second_counts.get("session_digest")
        )
        return {
            "schema_version": 1,
            "probe": "kind_im_gateway_probe",
            "status": "pass" if passed else "fail",
            "scenario": "real_feishu_gateway_postgres_idempotency",
            "assertion": ASSERTION,
            "source_fingerprint": _source_lineage(),
            "checks": {
                "duplicate_callbacks": {"status": "pass" if statuses == [200] * 100 else "fail"},
                "tenant_isolation": {"status": "pass" if tenant_isolation else "fail"},
                "signature_rejection": {
                    "status": "pass" if invalid_response.status_code == 403 else "fail"
                },
            },
            "callbacks_sent": 102,
            "duplicate_callback_status_counts": {
                str(code): statuses.count(code) for code in sorted(set(statuses))
            },
            "second_tenant_status": second_response.status_code,
            "invalid_signature_status": invalid_response.status_code,
            "tenant_a": first_counts,
            "tenant_b": second_counts,
            "rejection_reasons": reasons,
            "secrets_reported": False,
        }
    finally:
        await pool.close()


def main() -> int:
    try:
        report = asyncio.run(run())
    except Exception as error:  # fail closed without echoing DSNs or secrets
        report = {
            "schema_version": 1,
            "probe": "kind_im_gateway_probe",
            "status": "fail",
            "scenario": "real_feishu_gateway_postgres_idempotency",
            "assertion": ASSERTION,
            "source_fingerprint": _source_lineage(),
            "checks": {},
            "error_type": type(error).__name__,
            "rejection_reasons": ["probe_execution_failed"],
            "secrets_reported": False,
        }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
