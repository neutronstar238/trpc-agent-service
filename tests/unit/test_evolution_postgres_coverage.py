"""High-value branch coverage for the asyncpg-backed promotion adapter.

The production adapter is intentionally exercised only through deterministic
asyncpg-shaped doubles.  The shared basic double is reused from the protocol
tests and extended here only where a database outcome needs to be injected.
"""

from __future__ import annotations

import base64
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import asyncpg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.unit.test_evolution_postgres import (
    _certificate,
    _FakeConnection,
    _FakePool,
    _store,
)
from trpc_service.cell.events import CellAddress, NamespaceViolation
from trpc_service.cell.evolution import (
    ApprovalError,
    CertificateError,
    CertificateVerifier,
    PromotionAlreadyUsed,
    PromotionCASConflict,
    PromotionError,
    PromotionReceipt,
    PromotionReceiptError,
    PromotionTarget,
    VerificationResult,
)
from trpc_service.cell.evolution_postgres import (
    PostgresPromotionStore,
    PromotionOutboxConflict,
    _aware,
    _claim_from_row,
    _int,
    _receipt_from_row,
    _row,
    _target_from_row,
    _text,
    _uuid,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)
SOURCE = "sha256:" + "a" * 64
CANDIDATE = "sha256:" + "b" * 64
OTHER = "sha256:" + "c" * 64


class _ConnectionDouble(_FakeConnection):
    """Inject database outcomes the small protocol double cannot produce."""

    def __init__(self) -> None:
        super().__init__()
        self.fail_pointer_update = False
        self.fail_use_insert = False
        self.claim_update_none = False
        self.ack_false_once = False

    async def execute(self, query: str, *args: object) -> str:
        if "INSERT INTO cell_promotion_uses" in query and self.fail_use_insert:
            self.calls.append((query, args))
            raise asyncpg.UniqueViolationError("duplicate durable use")
        return await super().execute(query, *args)

    async def fetchrow(self, query: str, *args: object) -> object:
        if "UPDATE cell_promotion_targets" in query and self.fail_pointer_update:
            self.calls.append((query, args))
            return None
        if "UPDATE cell_promotion_outbox" in query and "SET status='claimed'" in query:
            if self.claim_update_none:
                self.claim_update_none = False
                self.calls.append((query, args))
                return None
        if "UPDATE cell_promotion_outbox" in query and "SET status='published'" in query:
            tenant, receipt_id = str(args[0]), args[1]
            row = self.outbox.get((tenant, receipt_id))
            if row is not None:
                expires = row["lease_expires_at"]
                if isinstance(expires, datetime) and expires <= self.now:
                    self.calls.append((query, args))
                    return None
            if self.ack_false_once:
                self.ack_false_once = False
                self.calls.append((query, args))
                return None
        return await super().fetchrow(query, *args)


class _NoFetchConnection(_ConnectionDouble):
    """A connection without fetch(), for the adapter's compatibility path."""

    fetch = None  # type: ignore[assignment]

    def __init__(self, fallback: object) -> None:
        super().__init__()
        self.fallback = fallback

    async def fetchrow(self, query: str, *args: object) -> object:
        if "fallback" in query:
            return self.fallback
        return await super().fetchrow(query, *args)


class _NullClockConnection(_ConnectionDouble):
    async def fetchval(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        return None


class _FixedVerifier:
    def __init__(self, result: VerificationResult) -> None:
        self.result = result

    def verify(self, certificate: object, target: object) -> VerificationResult:
        del certificate, target
        return self.result


def _target_row(target: PromotionTarget) -> dict[str, object]:
    return {
        "tenant_id": target.tenant_id,
        "app_id": target.app_id,
        "cell_id": target.cell_id,
        "session_id": target.session_id,
        "active_capsule_digest": target.active_capsule_digest,
        "control_version": target.control_version,
        "updated_at": NOW,
    }


def _receipt_row(receipt: PromotionReceipt) -> dict[str, object]:
    return {
        "tenant_id": receipt.target.tenant_id,
        "receipt_id": receipt.receipt_id,
        "certificate_id": receipt.certificate_id,
        "app_id": receipt.target.app_id,
        "cell_id": receipt.target.cell_id,
        "session_id": receipt.target.session_id,
        "previous_active_capsule": receipt.previous_active_capsule,
        "active_capsule": receipt.active_capsule,
        "previous_control_version": receipt.previous_control_version,
        "control_version": receipt.control_version,
        "issued_at": receipt.issued_at,
        "signing_key_id": receipt.signing_key_id,
        "signature": receipt.signature,
        "operation": receipt.operation,
        "rollback_of": receipt.rollback_of,
    }


def _claim_row(receipt: PromotionReceipt, *, owner: object = "pod-a") -> dict[str, object]:
    return {
        **_receipt_row(receipt),
        "claimed_by": owner,
        "lease_epoch": 1,
        "lease_expires_at": NOW + timedelta(seconds=30),
        "attempts": 1,
    }


def _seed(connection: _FakeConnection, target: PromotionTarget) -> None:
    connection.targets[(target.tenant_id, target.app_id, target.cell_id, target.session_id)] = (
        _target_row(target)
    )


async def _promoted(
    connection: _ConnectionDouble | None = None,
) -> tuple[_ConnectionDouble, PostgresPromotionStore, object, PromotionTarget, PromotionReceipt]:
    connection = connection or _ConnectionDouble()
    certificate, target, authority = _certificate()
    judge_key = Ed25519PrivateKey.generate()
    certificate = certificate.with_signature(judge_key)
    store = _store(connection)
    store.certificate_verifier = CertificateVerifier(
        {"judge": judge_key.public_key()}, clock=lambda: NOW
    )
    store.approval_secret = b"approval-secret"
    approval = authority.issue(certificate, target, approved_by="reviewer")
    receipt = await store.compare_and_swap(target, certificate=certificate, approval=approval)
    return connection, store, certificate, target, receipt


def test_private_coercions_fail_closed_and_normalize_rows() -> None:
    assert _aware("not-a-date") is None
    assert _aware(datetime(2026, 1, 1)) == NOW
    assert _aware(NOW + timedelta(hours=1)) == NOW + timedelta(hours=1)
    assert _row({"x": 1}) == {"x": 1}
    assert _row([("x", 1)]) == {"x": 1}
    with pytest.raises(PromotionError, match="non-mapping"):
        _row(object())
    assert _text("name", "  worker ") == "worker"
    with pytest.raises(ValueError):
        _text("name", " ")
    with pytest.raises(ValueError):
        _text("name", 1)  # type: ignore[arg-type]
    with pytest.raises(PromotionReceiptError, match="UUID"):
        _uuid("bad")
    assert _int(None, default=4) == 4
    assert _int("5") == 5
    with pytest.raises(PromotionError, match="boolean"):
        _int(True)
    with pytest.raises(PromotionError, match="invalid integer"):
        _int("five")


def test_row_builders_cover_timestamp_operation_and_lease_guards() -> None:
    certificate, target, _authority = _certificate()
    receipt = PromotionReceipt(
        receipt_id="00000000-0000-0000-0000-000000000001",
        certificate_id=certificate.certificate_id,
        target=target,
        previous_active_capsule=SOURCE,
        active_capsule=CANDIDATE,
        previous_control_version=0,
        control_version=1,
        issued_at=NOW,
        signing_key_id="key",
        signature=base64.urlsafe_b64encode(b"x" * 64).decode().rstrip("="),
    )
    row = _receipt_row(receipt)
    assert _receipt_from_row({**row, "issued_at": datetime(2026, 1, 1)}) == receipt
    assert _receipt_from_row({**row, "operation": None, "rollback_of": None}).operation == "promote"
    assert (
        _receipt_from_row({**row, "rollback_of": receipt.receipt_id}).rollback_of
        == receipt.receipt_id
    )
    with pytest.raises(PromotionReceiptError, match="timestamp"):
        _receipt_from_row({**row, "issued_at": None})
    assert _target_from_row(_target_row(target)) == target
    assert _target_from_row({**_target_row(target), "control_version": None}).control_version == 0
    assert _claim_from_row(_claim_row(receipt)).owner_id == "pod-a"
    with pytest.raises(PromotionOutboxConflict, match="owner"):
        _claim_from_row(_claim_row(receipt, owner=None))
    with pytest.raises(PromotionOutboxConflict, match="expiry"):
        _claim_from_row({**_claim_row(receipt), "lease_expires_at": None})


def test_store_constructor_and_exact_scope_guards() -> None:
    connection = _ConnectionDouble()
    with pytest.raises(TypeError, match="pool"):
        PostgresPromotionStore(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="tenant_id"):
        PostgresPromotionStore(_FakePool(connection), tenant_id=" ")
    with pytest.raises(ValueError, match="receipt_key_id"):
        PostgresPromotionStore(_FakePool(connection), receipt_key_id=" ")
    store = _store(connection)
    with pytest.raises(NamespaceViolation, match="tenant"):
        store._assert_tenant("tenant-b")
    with pytest.raises(PromotionError, match="CellAddress"):
        store._address(object())  # type: ignore[arg-type]
    wildcard = CellAddress("tenant-a", "cell-a", "session-a", SOURCE, "main", "*")
    with pytest.raises(PromotionError, match="exact"):
        store._address(wildcard)
    candidate_branch = CellAddress("tenant-a", "cell-a", "session-a", SOURCE, "candidate", "app-a")
    with pytest.raises(PromotionError, match="exact"):
        store._address(candidate_branch)


@pytest.mark.asyncio
async def test_get_and_load_pointer_reject_missing_or_cross_namespace_rows() -> None:
    connection = _ConnectionDouble()
    store = _store(connection)
    certificate, target, _authority = _certificate()
    assert await store.get(target) is None
    _seed(connection, target)
    key = (target.tenant_id, target.app_id, target.cell_id, target.session_id)
    connection.targets[key]["app_id"] = "foreign-app"
    with pytest.raises(NamespaceViolation, match="outside requested"):
        await store.get(target)
    connection.targets[key]["app_id"] = target.app_id
    connection.targets[key]["tenant_id"] = "foreign-tenant"
    with pytest.raises(NamespaceViolation, match="outside tenant"):
        await store._load_pointer(connection, target.address)
    del certificate
    empty = _ConnectionDouble()
    with pytest.raises(PromotionCASConflict, match="not initialized"):
        await store._load_pointer(empty, target.address)


@pytest.mark.asyncio
async def test_database_clock_fallback_and_fetch_without_fetch_method() -> None:
    connection = _NullClockConnection()
    store = _store(connection)
    assert await store._database_now(connection) == NOW
    with_fetch = _NoFetchConnection({"value": 1})
    assert await PostgresPromotionStore._fetch_many(with_fetch, "SELECT fallback") == [{"value": 1}]
    no_row = _NoFetchConnection(None)
    assert await PostgresPromotionStore._fetch_many(no_row, "SELECT fallback") == []


def test_certificate_and_approval_verifier_guards() -> None:
    certificate, target, authority = _certificate()
    store = _store(_ConnectionDouble())
    with pytest.raises(CertificateError, match="invalid"):
        store._verify_certificate(object(), target)  # type: ignore[arg-type]
    with pytest.raises(CertificateError, match="trusted"):
        store._verify_certificate(certificate, target)
    store.certificate_verifier = _FixedVerifier(VerificationResult(False))  # type: ignore[assignment]
    with pytest.raises(CertificateError, match="failed"):
        store._verify_certificate(certificate, target)
    store.certificate_verifier = _FixedVerifier(VerificationResult(False, "rejected"))  # type: ignore[assignment]
    with pytest.raises(CertificateError, match="rejected"):
        store._verify_certificate(certificate, target)
    store.certificate_verifier = _FixedVerifier(VerificationResult(True))  # type: ignore[assignment]
    store._verify_certificate(certificate, target)

    approval = authority.issue(certificate, target, approved_by="reviewer")
    store._verify_approval(approval, certificate, target, now=NOW)
    with pytest.raises(ApprovalError, match="invalid"):
        store._verify_approval(object(), certificate, target, now=NOW)  # type: ignore[arg-type]
    with pytest.raises(NamespaceViolation, match="certificate id"):
        store._verify_approval(
            replace(approval, certificate_id="other"), certificate, target, now=NOW
        )
    with pytest.raises(NamespaceViolation, match="digest"):
        store._verify_approval(
            replace(approval, certificate_digest=OTHER), certificate, target, now=NOW
        )
    foreign_target = PromotionTarget(
        CellAddress("tenant-a", "cell-a", "cell-b", SOURCE, "main", "app-a"), SOURCE, 0
    )
    with pytest.raises(NamespaceViolation, match="target"):
        store._verify_approval(
            replace(approval, target=foreign_target), certificate, target, now=NOW
        )
    with pytest.raises(ApprovalError, match="expired"):
        store._verify_approval(replace(approval, expires_at=NOW), certificate, target, now=NOW)
    store.approval_secret = b"approval-secret"
    with pytest.raises(ApprovalError, match="signature"):
        store._verify_approval(replace(approval, mac="bad"), certificate, target, now=NOW)
    store._verify_approval(approval, certificate, target, now=NOW)


@pytest.mark.asyncio
async def test_manual_cas_success_and_input_conflicts() -> None:
    certificate, target, _authority = _certificate()
    del certificate
    connection = _ConnectionDouble()
    store = _store(connection)
    _seed(connection, target)
    receipt = await store.compare_and_swap(
        target.address,
        expected_active_capsule=SOURCE,
        new_active_capsule=CANDIDATE,
    )
    assert receipt.certificate_id == "manual-cas"
    assert await store.get(target) is not None

    fresh = _ConnectionDouble()
    fresh_store = _store(fresh)
    with pytest.raises(PromotionCASConflict, match="integer"):
        await fresh_store.compare_and_swap(
            target, new_active_capsule=CANDIDATE, control_version=True
        )  # type: ignore[arg-type]
    with pytest.raises(PromotionError, match="required"):
        await fresh_store.compare_and_swap(target)
    with pytest.raises(PromotionCASConflict, match="advance"):
        await fresh_store.compare_and_swap(target, new_active_capsule=CANDIDATE, control_version=0)
    with pytest.raises(PromotionCASConflict, match="before CAS"):
        await fresh_store.compare_and_swap(
            target,
            expected_active_capsule=OTHER,
            new_active_capsule=CANDIDATE,
        )


@pytest.mark.asyncio
async def test_certificate_cas_scope_candidate_precondition_and_approval_guards() -> None:
    cases: list[tuple[str, object, dict[str, object]]] = []
    certificate, target, _authority = _certificate()
    foreign_source = CellAddress("tenant-a", "cell-a", "session-a", SOURCE, "main", "app-b")
    foreign_candidate = CellAddress(
        "tenant-a", "cell-a", "session-a", CANDIDATE, "candidate", "app-b"
    )
    cases.append(
        (
            "source",
            replace(
                certificate, source_address=foreign_source, candidate_address=foreign_candidate
            ),
            {},
        )
    )
    cases.append(("candidate", certificate, {"new_active_capsule": SOURCE}))
    cases.append(("expected", replace(certificate, expected_active_capsule=OTHER), {}))
    cases.append(("version", replace(certificate, control_version=1), {}))
    for _name, candidate, kwargs in cases:
        connection = _ConnectionDouble()
        store = _store(connection)
        store.certificate_verifier = _FixedVerifier(VerificationResult(True))  # type: ignore[assignment]
        with pytest.raises((NamespaceViolation, PromotionError, PromotionCASConflict)):
            await store.compare_and_swap(target, certificate=candidate, **kwargs)  # type: ignore[arg-type]

    connection = _ConnectionDouble()
    store = _store(connection)
    store.certificate_verifier = _FixedVerifier(VerificationResult(True))  # type: ignore[assignment]
    with pytest.raises(ApprovalError, match="consumed"):
        await store.compare_and_swap(target, certificate=certificate)

    connection = _ConnectionDouble()
    store = _store(connection)
    store.certificate_verifier = _FixedVerifier(VerificationResult(True))  # type: ignore[assignment]
    receipt = await store.compare_and_swap(
        target,
        certificate=certificate,
        approval_consumed=True,
        approval_id="review-1",
    )
    assert connection.uses[("tenant-a", "cert-1")]["approval_id"] == "review-1"
    assert receipt.control_version == 1


@pytest.mark.asyncio
async def test_certificate_use_repeat_and_unique_violation_are_fenced() -> None:
    connection, store, certificate, _target, _receipt = await _promoted()
    with pytest.raises(PromotionAlreadyUsed, match="consumed"):
        await store._assert_unused_certificate(connection, "tenant-a", certificate)  # type: ignore[arg-type]

    duplicate_connection = _ConnectionDouble()
    duplicate_connection.fail_use_insert = True
    certificate, target, _authority = _certificate()
    judge_key = Ed25519PrivateKey.generate()
    certificate = certificate.with_signature(judge_key)
    duplicate_store = _store(duplicate_connection)
    duplicate_store.certificate_verifier = CertificateVerifier(
        {"judge": judge_key.public_key()}, clock=lambda: NOW
    )
    duplicate_store.approval_secret = b"approval-secret"
    authority = _certificate()[2]
    approval = authority.issue(certificate, target, approved_by="reviewer")
    with pytest.raises(PromotionAlreadyUsed, match="certificate or approval"):
        await duplicate_store.compare_and_swap(target, certificate=certificate, approval=approval)


@pytest.mark.asyncio
async def test_cas_update_conflict_and_persisted_receipt_validation() -> None:
    connection = _ConnectionDouble()
    connection.fail_pointer_update = True
    store = _store(connection)
    _certificate_value, target, _authority = _certificate()
    with pytest.raises(PromotionCASConflict, match="during CAS"):
        await store.compare_and_swap(target, new_active_capsule=CANDIDATE)

    connection, store, _certificate_value, _target, receipt = await _promoted()
    with pytest.raises(PromotionReceiptError, match="does not match"):
        await store._load_persisted_receipt(connection, replace(receipt, active_capsule=OTHER))
    receipt_key = ("tenant-a", UUID(receipt.receipt_id))
    saved = dict(connection.receipts[receipt_key])
    del connection.receipts[receipt_key]
    with pytest.raises(PromotionReceiptError, match="not durable"):
        await store._load_persisted_receipt(connection, receipt)
    connection.receipts[receipt_key] = saved


@pytest.mark.asyncio
async def test_receipt_signature_and_rollback_input_guards() -> None:
    connection, store, _certificate_value, _target, receipt = await _promoted()
    with pytest.raises(PromotionReceiptError, match="invalid"):
        store._verify_receipt(replace(receipt, signing_key_id="other"))
    with pytest.raises(PromotionReceiptError, match="invalid"):
        store._verify_receipt(
            SimpleNamespace(
                signing_key_id=store.receipt_key_id,
                signature="!",
                signing_bytes=lambda: b"receipt",
            )  # type: ignore[arg-type]
        )
    with pytest.raises(PromotionReceiptError, match="invalid"):
        await store.rollback(object())  # type: ignore[arg-type]
    rollback = await store.rollback(receipt)
    with pytest.raises(PromotionReceiptError, match="only"):
        await store.rollback(rollback)
    with pytest.raises(PromotionReceiptError, match="invalid"):
        await store.rollback(
            replace(receipt, signature=base64.urlsafe_b64encode(b"y" * 64).decode())
        )
    del connection


@pytest.mark.asyncio
async def test_rollback_stale_active_version_expected_values_and_cas() -> None:
    connection, store, _certificate_value, target, receipt = await _promoted()
    key = (target.tenant_id, target.app_id, target.cell_id, target.session_id)
    connection.targets[key]["active_capsule_digest"] = OTHER
    with pytest.raises(PromotionCASConflict, match="no longer matches"):
        await store.rollback(receipt)

    connection, store, _certificate_value, target, receipt = await _promoted()
    connection.targets[(target.tenant_id, target.app_id, target.cell_id, target.session_id)][
        "control_version"
    ] = 99
    with pytest.raises(PromotionCASConflict, match="control version no longer"):
        await store.rollback(receipt)

    connection, store, _certificate_value, target, receipt = await _promoted()
    with pytest.raises(PromotionCASConflict, match="caller supplied a stale active"):
        await store.rollback(receipt, expected_active_capsule=OTHER)
    with pytest.raises(PromotionCASConflict, match="caller supplied a stale control"):
        await store.rollback(receipt, expected_control_version=99)

    failing = _ConnectionDouble()
    connection, store, _certificate_value, _target, receipt = await _promoted(failing)
    del connection
    failing.fail_pointer_update = True
    with pytest.raises(PromotionCASConflict, match="during rollback"):
        await store.rollback(receipt)


@pytest.mark.asyncio
async def test_outbox_limits_claim_conflict_and_fetch_fallback() -> None:
    connection, store, _certificate_value, _target, receipt = await _promoted()
    for bad in (0, True, "1"):
        with pytest.raises(ValueError, match="outbox limit"):
            await store.pending_outbox(limit=bad)  # type: ignore[arg-type]
    assert len(await store.pending_outbox(limit=1)) == 1
    assert await store.pending_outbox(limit=1)

    for owner in ("", " "):
        with pytest.raises(ValueError, match="owner_id"):
            await store.claim_outbox(owner_id=owner)
    for lease in (True, 0, -1, float("nan"), "30"):
        with pytest.raises(ValueError, match="lease"):
            await store.claim_outbox(owner_id="pod-a", lease_seconds=lease)  # type: ignore[arg-type]
    for limit in (0, True, "1"):
        with pytest.raises(ValueError, match="outbox limit"):
            await store.claim_outbox(owner_id="pod-a", limit=limit)  # type: ignore[arg-type]

    connection.claim_update_none = True
    assert await store.claim_outbox(owner_id="pod-a") == ()
    assert receipt.receipt_id


@pytest.mark.asyncio
async def test_ack_release_epoch_owner_expiry_and_validation() -> None:
    connection, store, _certificate_value, _target, receipt = await _promoted()
    claim = (await store.claim_outbox(owner_id="pod-a"))[0]
    for epoch in (0, -1, True, "1"):
        with pytest.raises(ValueError, match="lease_epoch"):
            await store.acknowledge(receipt.receipt_id, owner_id="pod-a", lease_epoch=epoch)  # type: ignore[arg-type]
    with pytest.raises(PromotionReceiptError, match="UUID"):
        await store.acknowledge("bad", owner_id="pod-a", lease_epoch=claim.lease_epoch)
    assert not await store.acknowledge(
        receipt.receipt_id, owner_id="pod-b", lease_epoch=claim.lease_epoch
    )
    assert not await store.release(
        receipt.receipt_id, owner_id="pod-b", lease_epoch=claim.lease_epoch
    )

    for delay in (True, -1, float("nan"), "1"):
        with pytest.raises(ValueError, match="delay"):
            await store.release(
                receipt.receipt_id,
                owner_id="pod-a",
                lease_epoch=claim.lease_epoch,
                delay_seconds=delay,  # type: ignore[arg-type]
            )
    assert await store.release(
        receipt.receipt_id,
        owner_id="pod-a",
        lease_epoch=claim.lease_epoch,
        error="x" * 600,
        delay_seconds=0,
    )
    assert connection.outbox[("tenant-a", UUID(receipt.receipt_id))]["last_error"] == "x" * 500

    claim = (await store.claim_outbox(owner_id="pod-a", lease_seconds=1))[0]
    connection.now += timedelta(seconds=2)
    assert not await store.acknowledge(
        receipt.receipt_id, owner_id="pod-a", lease_epoch=claim.lease_epoch
    )
    assert not await store.ack(receipt.receipt_id, owner_id="pod-a", lease_epoch=claim.lease_epoch)


@pytest.mark.asyncio
async def test_reconcile_sync_publisher_and_acknowledge_false_branch() -> None:
    connection, store, _certificate_value, _target, receipt = await _promoted()
    delivered: list[str] = []
    assert await store.reconcile(
        lambda item: delivered.append(item.receipt_id), owner_id="pod-sync"
    ) == (receipt.receipt_id,)
    assert delivered == [receipt.receipt_id]

    connection, store, _certificate_value, _target, receipt = await _promoted()
    connection.ack_false_once = True
    assert await store.reconcile(lambda item: item.receipt_id, owner_id="pod-race") == ()
    assert connection.outbox[("tenant-a", UUID(receipt.receipt_id))]["status"] == "claimed"
