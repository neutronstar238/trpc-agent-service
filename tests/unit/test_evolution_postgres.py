"""Asyncpg-double tests for the durable online evolution control plane."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trpc_service.cell.events import CellAddress, NamespaceViolation
from trpc_service.cell.evolution import (
    CertificateVerifier,
    EvolutionCertificate,
    PromotionAlreadyUsed,
    PromotionApprovalAuthority,
    PromotionCASConflict,
    PromotionReceipt,
    PromotionReceiptError,
    PromotionTarget,
)
from trpc_service.cell.evolution_postgres import (
    PostgresPromotionStore,
    PromotionOutboxConflict,
    _claim_from_row,
)


class _AsyncContext:
    def __init__(self, value: object) -> None:
        self.value = value

    async def __aenter__(self) -> object:
        return self.value

    async def __aexit__(self, *args: object) -> None:
        del args


class _FakeConnection:
    """Small stateful asyncpg double; SQL shape remains visible to tests."""

    def __init__(self) -> None:
        self.targets: dict[tuple[str, str, str, str], dict[str, object]] = {}
        self.receipts: dict[tuple[str, UUID], dict[str, object]] = {}
        self.uses: dict[tuple[str, str], dict[str, object]] = {}
        self.outbox: dict[tuple[str, UUID], dict[str, object]] = {}
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def transaction(self) -> _AsyncContext:
        return _AsyncContext(self)

    @staticmethod
    def _key(args: tuple[object, ...]) -> tuple[str, str, str, str]:
        return tuple(str(item) for item in args[:4])  # type: ignore[return-value]

    def _joined(self, key: tuple[str, UUID]) -> dict[str, object]:
        return {**self.receipts[key], **self.outbox[key]}

    async def execute(self, query: str, *args: object) -> str:
        self.calls.append((query, args))
        if "INSERT INTO cell_promotion_targets" in query:
            key = self._key(args)
            self.targets.setdefault(
                key,
                {
                    "tenant_id": args[0],
                    "app_id": args[1],
                    "cell_id": args[2],
                    "session_id": args[3],
                    "active_capsule_digest": args[4],
                    "control_version": args[5],
                    "updated_at": self.now,
                },
            )
        elif "INSERT INTO cell_promotion_receipts" in query:
            receipt_id = args[1]
            assert isinstance(receipt_id, UUID)
            row = {
                "tenant_id": args[0],
                "receipt_id": receipt_id,
                "certificate_id": args[2],
                "app_id": args[3],
                "cell_id": args[4],
                "session_id": args[5],
                "previous_active_capsule": args[6],
                "active_capsule": args[7],
                "previous_control_version": args[8],
                "control_version": args[9],
                "issued_at": args[10],
                "signing_key_id": args[11],
                "signature": args[12],
                "operation": args[13],
                "rollback_of": args[14],
            }
            self.receipts[(str(args[0]), receipt_id)] = row
        elif "INSERT INTO cell_promotion_outbox" in query:
            receipt_id = args[1]
            assert isinstance(receipt_id, UUID)
            self.outbox[(str(args[0]), receipt_id)] = {
                "tenant_id": args[0],
                "receipt_id": receipt_id,
                "status": "pending",
                "claimed_by": None,
                "lease_epoch": 0,
                "lease_expires_at": None,
                "attempts": 0,
                "available_at": self.now,
                "published_at": None,
                "last_error": None,
                "created_at": self.now,
            }
        elif "INSERT INTO cell_promotion_uses" in query:
            self.uses[(str(args[0]), str(args[1]))] = {
                "tenant_id": args[0],
                "certificate_id": args[1],
                "certificate_digest": args[2],
                "approval_id": args[3],
                "receipt_id": args[7],
            }
        return "OK"

    async def fetchval(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        if "clock_timestamp" in query:
            return self.now
        return None

    async def fetchrow(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        if "FROM cell_promotion_targets" in query:
            key = self._key(args)
            return self.targets.get(key)
        if "FROM cell_promotion_uses" in query:
            use_key = (str(args[0]), str(args[1]))
            return self.uses.get(use_key)
        if "WHERE tenant_id=$1 AND rollback_of=$2" in query:
            rollback_id = UUID(str(args[1]))
            return next(
                (row for row in self.receipts.values() if row["rollback_of"] == rollback_id),
                None,
            )
        if "UPDATE cell_promotion_targets" in query:
            key = self._key(args)
            row = self.targets.get(key)
            if (
                row is None
                or row["active_capsule_digest"] != args[6]
                or row["control_version"] != args[7]
            ):
                return None
            row["active_capsule_digest"] = args[4]
            row["control_version"] = args[5]
            row["updated_at"] = self.now
            return row
        if "UPDATE cell_promotion_outbox" in query:
            tenant, receipt_id = str(args[0]), UUID(str(args[1]))
            row = self.outbox.get((tenant, receipt_id))
            if row is None:
                return None
            if "SET status='claimed'" in query:
                if row["status"] == "published" or row["lease_epoch"] != args[4]:
                    return None
                row["status"] = "claimed"
                row["claimed_by"] = args[2]
                row["lease_epoch"] = cast(int, row["lease_epoch"]) + 1
                row["lease_expires_at"] = self.now + timedelta(seconds=cast(float, args[3]))
                row["attempts"] = cast(int, row["attempts"]) + 1
                row["last_error"] = None
                return row
            if "SET status='published'" in query:
                if (
                    row["status"] != "claimed"
                    or row["claimed_by"] != args[2]
                    or row["lease_epoch"] != args[3]
                ):
                    return None
                row["status"] = "published"
                row["published_at"] = self.now
                row["claimed_by"] = None
                row["lease_expires_at"] = None
                return {"receipt_id": receipt_id}
            if "SET status='pending'" in query:
                if (
                    row["status"] != "claimed"
                    or row["claimed_by"] != args[2]
                    or row["lease_epoch"] != args[3]
                ):
                    return None
                row["status"] = "pending"
                row["claimed_by"] = None
                row["lease_expires_at"] = None
                row["last_error"] = args[5]
                return {"receipt_id": receipt_id}
        if "WHERE tenant_id=$1 AND receipt_id=$2" in query:
            receipt_key = (str(args[0]), UUID(str(args[1])))
            return self.receipts.get(receipt_key)
        return None

    async def fetch(self, query: str, *args: object) -> list[Mapping[str, object]]:
        self.calls.append((query, args))
        rows: list[Mapping[str, object]] = []
        for key, outbox in self.outbox.items():
            if outbox["status"] == "published":
                continue
            if "FOR UPDATE OF o" in query and outbox["status"] == "claimed":
                expires = outbox["lease_expires_at"]
                if isinstance(expires, datetime) and expires > self.now:
                    continue
            rows.append(self._joined(key))
        return rows[: args[-1]] if args and isinstance(args[-1], int) else rows


class _FakePool:
    def __init__(self, connection: _FakeConnection) -> None:
        self.connection = connection

    def acquire(self) -> _AsyncContext:
        return _AsyncContext(self.connection)


def _certificate() -> tuple[EvolutionCertificate, PromotionTarget, PromotionApprovalAuthority]:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    source = "sha256:" + "a" * 64
    candidate = "sha256:" + "b" * 64
    source_address = CellAddress("tenant-a", "cell-a", "session-a", source, "main", "app-a")
    candidate_address = CellAddress(
        "tenant-a", "cell-a", "session-a", candidate, "candidate", "app-a"
    )
    certificate = EvolutionCertificate(
        certificate_id="cert-1",
        source_address=source_address,
        candidate_address=candidate_address,
        source_capsule_digest=source,
        candidate_capsule_digest=candidate,
        fork_sequence=1,
        fork_hash="sha256:" + "c" * 64,
        source_head_hash="sha256:" + "d" * 64,
        candidate_head_hash="sha256:" + "e" * 64,
        dataset_id="dataset",
        runner_id="runner",
        model_id="model",
        policy_digest="policy",
        tool_manifest_digest="tools",
        reducer_id="reducer",
        evidence_digest="sha256:" + "f" * 64,
        judge_policy={},
        expected_active_capsule=source,
        control_version=0,
        signing_key_id="judge",
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )
    key = Ed25519PrivateKey.generate()
    certificate = certificate.with_signature(key)
    target = PromotionTarget(source_address, source, 0)
    authority = PromotionApprovalAuthority(b"approval-secret", clock=lambda: now)
    return certificate, target, authority


def _store(connection: _FakeConnection) -> PostgresPromotionStore:
    certificate, _target, _authority = _certificate()
    del certificate
    # The verifier is replaced by the test-specific certificate verifier in
    # each test; this constructor still models a long-lived shared pool.
    return PostgresPromotionStore(
        _FakePool(connection),
        tenant_id="tenant-a",
        receipt_signing_key=Ed25519PrivateKey.generate(),
        receipt_key_id="online-key",
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )


@pytest.mark.asyncio
async def test_pointer_cas_consumes_use_and_writes_receipt_outbox_atomically() -> None:
    connection = _FakeConnection()
    certificate, target, authority = _certificate()
    store = _store(connection)
    # Replace the verifier with the actual public key while retaining a
    # separate receipt key.
    judge_key = Ed25519PrivateKey.generate()
    certificate = certificate.with_signature(judge_key)
    store.certificate_verifier = CertificateVerifier(
        {"judge": judge_key.public_key()}, clock=lambda: datetime(2026, 1, 1, tzinfo=UTC)
    )
    approval = authority.issue(certificate, target, approved_by="reviewer")
    store.approval_secret = b"approval-secret"
    receipt = await store.compare_and_swap(
        target,
        certificate=certificate,
        approval=approval,
    )
    assert receipt.active_capsule == certificate.candidate_capsule_digest
    assert ("tenant-a", "cert-1") in connection.uses
    assert len(connection.receipts) == 1
    assert len(connection.outbox) == 1
    assert (await store.get(target)).active_capsule_digest == certificate.candidate_capsule_digest  # type: ignore[union-attr]

    with pytest.raises(PromotionCASConflict):
        await store.compare_and_swap(target, certificate=certificate, approval=approval)


@pytest.mark.asyncio
async def test_certificate_scope_and_stale_cas_are_rejected() -> None:
    connection = _FakeConnection()
    certificate, target, authority = _certificate()
    judge_key = Ed25519PrivateKey.generate()
    certificate = certificate.with_signature(judge_key)
    store = _store(connection)
    store.certificate_verifier = CertificateVerifier(
        {"judge": judge_key.public_key()}, clock=lambda: datetime(2026, 1, 1, tzinfo=UTC)
    )
    store.approval_secret = b"approval-secret"
    approval = authority.issue(certificate, target, approved_by="reviewer")
    foreign = PromotionTarget(
        CellAddress(
            "tenant-b", "cell-a", "session-a", target.active_capsule_digest, "main", "app-a"
        ),
        target.active_capsule_digest,
    )
    with pytest.raises(NamespaceViolation):
        await store.compare_and_swap(foreign, certificate=certificate, approval=approval)
    await store.compare_and_swap(target, certificate=certificate, approval=approval)
    with pytest.raises(PromotionCASConflict):
        await store.compare_and_swap(
            target,
            expected_control_version=0,
            new_active_capsule="sha256:" + "c" * 64,
        )


@pytest.mark.asyncio
async def test_outbox_claim_epoch_ack_recovery_and_duplicate_ack() -> None:
    connection = _FakeConnection()
    certificate, target, authority = _certificate()
    judge_key = Ed25519PrivateKey.generate()
    certificate = certificate.with_signature(judge_key)
    store = _store(connection)
    store.certificate_verifier = CertificateVerifier(
        {"judge": judge_key.public_key()}, clock=lambda: datetime(2026, 1, 1, tzinfo=UTC)
    )
    store.approval_secret = b"approval-secret"
    await store.compare_and_swap(
        target,
        certificate=certificate,
        approval=authority.issue(certificate, target, approved_by="reviewer"),
    )
    first = (await store.claim_outbox(owner_id="pod-a"))[0]
    assert first.lease_epoch == 1
    assert not await store.acknowledge(
        first.receipt_id, owner_id="pod-b", lease_epoch=first.lease_epoch
    )
    # A replacement Pod can reclaim only after the old lease expires.
    connection.now += timedelta(seconds=31)
    second = (await store.claim_outbox(owner_id="pod-b"))[0]
    assert second.lease_epoch == 2
    assert not await store.acknowledge(
        first.receipt_id, owner_id="pod-a", lease_epoch=first.lease_epoch
    )
    assert await store.acknowledge(
        second.receipt_id, owner_id="pod-b", lease_epoch=second.lease_epoch
    )
    assert not await store.acknowledge(
        second.receipt_id, owner_id="pod-b", lease_epoch=second.lease_epoch
    )


@pytest.mark.asyncio
async def test_rollback_is_monotonic_and_receipt_is_signed_and_durable() -> None:
    connection = _FakeConnection()
    certificate, target, authority = _certificate()
    judge_key = Ed25519PrivateKey.generate()
    certificate = certificate.with_signature(judge_key)
    store = _store(connection)
    store.certificate_verifier = CertificateVerifier(
        {"judge": judge_key.public_key()}, clock=lambda: datetime(2026, 1, 1, tzinfo=UTC)
    )
    store.approval_secret = b"approval-secret"
    receipt = await store.compare_and_swap(
        target,
        certificate=certificate,
        approval=authority.issue(certificate, target, approved_by="reviewer"),
    )
    rollback = await store.rollback(receipt)
    assert rollback.operation == "rollback"
    assert rollback.rollback_of == receipt.receipt_id
    assert rollback.control_version == 2
    assert (await store.get(target)).active_capsule_digest == target.active_capsule_digest  # type: ignore[union-attr]
    with pytest.raises(PromotionAlreadyUsed):
        await store.rollback(receipt)
    with pytest.raises(PromotionReceiptError):
        await store.rollback(
            replace(receipt, signature=base64.urlsafe_b64encode(b"y" * 64).decode())
        )


@pytest.mark.asyncio
async def test_reconcile_releases_failed_publish_and_async_publish_succeeds() -> None:
    connection = _FakeConnection()
    certificate, target, authority = _certificate()
    judge_key = Ed25519PrivateKey.generate()
    certificate = certificate.with_signature(judge_key)
    store = _store(connection)
    store.certificate_verifier = CertificateVerifier(
        {"judge": judge_key.public_key()}, clock=lambda: datetime(2026, 1, 1, tzinfo=UTC)
    )
    store.approval_secret = b"approval-secret"
    await store.compare_and_swap(
        target,
        certificate=certificate,
        approval=authority.issue(certificate, target, approved_by="reviewer"),
    )

    async def failing(_receipt: object) -> None:
        raise RuntimeError("transport")

    with pytest.raises(RuntimeError):
        await store.reconcile(failing, owner_id="pod-a")
    assert await store.pending_outbox()

    delivered: list[str] = []

    async def publish(receipt: object) -> None:
        delivered.append(cast(PromotionReceipt, receipt).receipt_id)

    assert await store.reconcile(publish, owner_id="pod-b") == tuple(delivered)
    assert await store.pending_outbox() == ()


def test_outbox_claim_row_without_lease_is_fail_closed() -> None:
    # Exercise the public data-contract guard independently of PostgreSQL.
    with pytest.raises(PromotionOutboxConflict):
        _claim_from_row(
            {
                "tenant_id": "tenant-a",
                "receipt_id": str(UUID(int=0)),
                "certificate_id": "cert",
                "app_id": "app-a",
                "cell_id": "cell-a",
                "session_id": "session-a",
                "previous_active_capsule": "sha256:" + "a" * 64,
                "active_capsule": "sha256:" + "b" * 64,
                "previous_control_version": 0,
                "control_version": 1,
                "issued_at": datetime.now(UTC),
                "signing_key_id": "key",
                "signature": base64.urlsafe_b64encode(b"x" * 64).decode().rstrip("="),
                "operation": "promote",
                "rollback_of": None,
                "claimed_by": None,
                "lease_epoch": 1,
                "lease_expires_at": None,
                "attempts": 1,
            }
        )
