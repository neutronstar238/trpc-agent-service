"""Durable PostgreSQL control plane for Proof-Carrying Evolution.

The offline :class:`~trpc_service.cell.evolution.PromotionStore` is useful for
the demo, but an online deployment has to survive Pod replacement and must
serialize two controllers that promote the same exact Cell.  This adapter is
the small durable boundary for that work:

* every operation runs inside a transaction with ``app.tenant_id`` set
  locally, so PostgreSQL RLS remains effective even when a pool is shared;
* a row lock plus an active-capsule/control-version predicate fences stale
  promotion and rollback callers;
* the certificate/approval use and pointer transition are committed with the
  signed receipt and its outbox row;
* outbox delivery is at-least-once, with an epoch-fenced lease so an old Pod
  cannot acknowledge a message after a replacement Pod has reclaimed it.

No provider or IM call is made by this module.  The outbox publisher belongs
to the channel/evolution controller and must deduplicate by ``receipt_id``.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import math
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

import asyncpg
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from trpc_service.cell.events import CellAddress, NamespaceViolation
from trpc_service.cell.evolution import (
    ApprovalError,
    CertificateError,
    CertificateVerifier,
    EvolutionCertificate,
    PromotionAlreadyUsed,
    PromotionApproval,
    PromotionCASConflict,
    PromotionError,
    PromotionReceipt,
    PromotionReceiptError,
    PromotionTarget,
    _canonical,
    _decode_b64,
    _encode_b64,
    _private_key,
)


class PromotionOutboxConflict(PromotionError):
    """A stale worker tried to acknowledge or release an outbox lease."""


@dataclass(frozen=True, slots=True)
class PromotionOutboxClaim:
    """An epoch-fenced delivery lease returned by :meth:`claim_outbox`."""

    receipt: PromotionReceipt
    owner_id: str
    lease_epoch: int
    lease_expires_at: datetime
    attempts: int

    @property
    def receipt_id(self) -> str:
        return self.receipt.receipt_id


_TARGET_COLUMNS = """
    tenant_id, app_id, cell_id, session_id,
    active_capsule_digest, control_version, updated_at
"""

_RECEIPT_COLUMNS = """
    tenant_id, receipt_id, certificate_id, app_id, cell_id, session_id,
    previous_active_capsule, active_capsule, previous_control_version,
    control_version, issued_at, signing_key_id, signature, operation,
    rollback_of
"""

_OUTBOX_COLUMNS = """
    tenant_id, receipt_id, status, claimed_by, lease_epoch,
    lease_expires_at, attempts, available_at, published_at,
    last_error, created_at
"""

_RECEIPT_SELECT_COLUMNS = """
    r.tenant_id, r.receipt_id, r.certificate_id, r.app_id, r.cell_id,
    r.session_id, r.previous_active_capsule, r.active_capsule,
    r.previous_control_version, r.control_version, r.issued_at,
    r.signing_key_id, r.signature, r.operation, r.rollback_of
"""


def _aware(value: object) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _row(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    try:
        return dict(cast(Any, value))
    except (TypeError, ValueError) as exc:
        raise PromotionError("PostgreSQL returned a non-mapping row") from exc


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")
    return value.strip()


def _uuid(value: str, *, field_name: str = "receipt_id") -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise PromotionReceiptError(f"{field_name} must be a UUID") from exc


def _int(value: object, *, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        raise PromotionError("PostgreSQL returned a boolean where an integer was expected")
    try:
        return int(cast(Any, value))
    except (TypeError, ValueError) as exc:
        raise PromotionError("PostgreSQL returned an invalid integer") from exc


def _target_from_row(row: Mapping[str, object]) -> PromotionTarget:
    tenant = cast(str, row["tenant_id"])
    address = CellAddress(
        tenant_id=tenant,
        app_id=cast(str, row["app_id"]),
        cell_id=cast(str, row["cell_id"]),
        session_id=cast(str, row["session_id"]),
        capsule_digest=cast(str, row["active_capsule_digest"]),
        branch_id="main",
    )
    return PromotionTarget(
        address=address,
        active_capsule_digest=cast(str, row["active_capsule_digest"]),
        control_version=_int(row.get("control_version")),
    )


def _receipt_from_row(row: Mapping[str, object]) -> PromotionReceipt:
    previous = cast(str, row["previous_active_capsule"])
    address = CellAddress(
        tenant_id=cast(str, row["tenant_id"]),
        app_id=cast(str, row["app_id"]),
        cell_id=cast(str, row["cell_id"]),
        session_id=cast(str, row["session_id"]),
        capsule_digest=previous,
        branch_id="main",
    )
    issued = _aware(row.get("issued_at"))
    if issued is None:
        raise PromotionReceiptError("receipt timestamp is missing")
    rollback_of = row.get("rollback_of")
    return PromotionReceipt(
        receipt_id=str(row["receipt_id"]),
        certificate_id=cast(str, row["certificate_id"]),
        target=PromotionTarget(
            address=address,
            active_capsule_digest=previous,
            control_version=_int(row.get("previous_control_version")),
        ),
        previous_active_capsule=previous,
        active_capsule=cast(str, row["active_capsule"]),
        previous_control_version=_int(row.get("previous_control_version")),
        control_version=_int(row.get("control_version")),
        issued_at=issued,
        signing_key_id=cast(str, row["signing_key_id"]),
        signature=cast(str, row["signature"]),
        operation=cast(str, row.get("operation") or "promote"),
        rollback_of=str(rollback_of) if rollback_of is not None else None,
    )


def _claim_from_row(row: Mapping[str, object]) -> PromotionOutboxClaim:
    receipt = _receipt_from_row(row)
    owner = row.get("claimed_by")
    if not isinstance(owner, str) or not owner:
        raise PromotionOutboxConflict("claimed outbox row has no owner")
    expires = _aware(row.get("lease_expires_at"))
    if expires is None:
        raise PromotionOutboxConflict("claimed outbox row has no lease expiry")
    return PromotionOutboxClaim(
        receipt=receipt,
        owner_id=owner,
        lease_epoch=_int(row.get("lease_epoch")),
        lease_expires_at=expires,
        attempts=_int(row.get("attempts")),
    )


class PostgresPromotionStore:
    """Tenant-scoped durable implementation of the promotion protocol.

    ``pool`` is an asyncpg-compatible pool.  A shared pool is safe: every
    method derives the tenant from the exact target/receipt and sets
    ``app.tenant_id`` in a transaction-local setting before touching rows.
    Certificate promotions require ``certificate_verifier``.  An approval can
    be cryptographically checked by passing ``approval_secret``; callers that
    already verified an approval with the in-memory authority may pass
    ``approval_consumed=True`` and an ``approval_id`` so the durable unique
    use fence is still written in the same transaction as the pointer CAS.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        *,
        tenant_id: str | None = None,
        receipt_signing_key: Ed25519PrivateKey | bytes | None = None,
        receipt_key_id: str = "evolution-online",
        certificate_verifier: CertificateVerifier | None = None,
        approval_secret: bytes | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(getattr(pool, "acquire", None)):
            raise TypeError("pool must expose asyncpg-compatible acquire()")
        if tenant_id is not None:
            _text("tenant_id", tenant_id)
        self.pool = pool
        self.tenant_id = tenant_id
        self._receipt_key = (
            _private_key(receipt_signing_key)
            if receipt_signing_key is not None
            else Ed25519PrivateKey.generate()
        )
        self.receipt_key_id = _text("receipt_key_id", receipt_key_id)
        self.certificate_verifier = certificate_verifier
        self.approval_secret = approval_secret
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def receipt_public_key(self) -> Ed25519PublicKey:
        return self._receipt_key.public_key()

    def _assert_tenant(self, tenant_id: str) -> str:
        if self.tenant_id is not None and tenant_id != self.tenant_id:
            raise NamespaceViolation("promotion store tenant does not match its adapter scope")
        return _text("tenant_id", tenant_id)

    @staticmethod
    def _address(target: PromotionTarget | CellAddress) -> CellAddress:
        address = target.address if isinstance(target, PromotionTarget) else target
        if not isinstance(address, CellAddress):
            raise PromotionError("promotion target must be a CellAddress")
        if address.branch_id != "main" or "*" in (
            address.tenant_id,
            address.app_id,
            address.cell_id,
            address.session_id,
        ):
            raise PromotionError("online promotion scope must be one exact main Cell")
        return address

    def _tenant_for(self, target: PromotionTarget | CellAddress) -> str:
        return self._assert_tenant(self._address(target).tenant_id)

    @asynccontextmanager
    async def _tenant_transaction(self, tenant_id: str) -> AsyncIterator[asyncpg.Connection]:
        tenant = self._assert_tenant(tenant_id)
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute(
                    "SELECT set_config('app.tenant_id', $1, true)",
                    tenant,
                )
                yield connection

    async def _database_now(self, connection: asyncpg.Connection) -> datetime:
        value = await connection.fetchval("SELECT clock_timestamp()")
        return _aware(value) or self._clock().astimezone(UTC)

    @staticmethod
    async def _fetch_many(
        connection: asyncpg.Connection, query: str, *args: object
    ) -> list[dict[str, object]]:
        fetch = getattr(connection, "fetch", None)
        if callable(fetch):
            rows = await fetch(query, *args)
            return [_row(item) for item in rows]
        item = await connection.fetchrow(query, *args)
        return [] if item is None else [_row(item)]

    async def get(self, target: PromotionTarget | CellAddress) -> PromotionTarget | None:
        """Read the exact pointer under the target tenant's RLS scope."""

        address = self._address(target)
        tenant = self._tenant_for(address)
        async with self._tenant_transaction(tenant) as connection:
            row = await connection.fetchrow(
                f"""SELECT {_TARGET_COLUMNS}
                      FROM cell_promotion_targets
                     WHERE tenant_id=$1 AND app_id=$2 AND cell_id=$3
                       AND session_id=$4""",  # noqa: S608
                tenant,
                address.app_id,
                address.cell_id,
                address.session_id,
            )
            if row is None:
                return None
            result = _target_from_row(_row(row))
            if (
                result.tenant_id != address.tenant_id
                or result.address.app_id != address.app_id
                or result.address.cell_id != address.cell_id
                or result.address.session_id != address.session_id
            ):
                raise NamespaceViolation("stored promotion pointer is outside requested Cell")
            return result

    current = get

    async def _load_pointer(
        self,
        connection: asyncpg.Connection,
        address: CellAddress,
        *,
        initialize: PromotionTarget | None = None,
    ) -> PromotionTarget:
        if initialize is not None:
            await connection.execute(
                """
                INSERT INTO cell_promotion_targets (
                    tenant_id, app_id, cell_id, session_id,
                    active_capsule_digest, control_version, updated_at
                ) VALUES ($1,$2,$3,$4,$5,$6,clock_timestamp())
                ON CONFLICT (tenant_id, app_id, cell_id, session_id) DO NOTHING
                """,
                address.tenant_id,
                address.app_id,
                address.cell_id,
                address.session_id,
                initialize.active_capsule_digest,
                initialize.control_version,
            )
        row = await connection.fetchrow(
            f"""SELECT {_TARGET_COLUMNS}
                  FROM cell_promotion_targets
                 WHERE tenant_id=$1 AND app_id=$2 AND cell_id=$3
                   AND session_id=$4
                 FOR UPDATE""",  # noqa: S608
            address.tenant_id,
            address.app_id,
            address.cell_id,
            address.session_id,
        )
        if row is None:
            raise PromotionCASConflict("promotion pointer is not initialized")
        result = _target_from_row(_row(row))
        if result.tenant_id != address.tenant_id or result.address.app_id != address.app_id:
            raise NamespaceViolation("stored promotion pointer is outside tenant scope")
        return result

    def _verify_certificate(
        self,
        certificate: EvolutionCertificate,
        target: PromotionTarget,
    ) -> None:
        if not isinstance(certificate, EvolutionCertificate):
            raise CertificateError("certificate is invalid")
        if self.certificate_verifier is None:
            raise CertificateError("a trusted certificate verifier is required")
        result = self.certificate_verifier.verify(certificate, target)
        if not result.valid:
            raise CertificateError(result.reason or "certificate verification failed")

    def _verify_approval(
        self,
        approval: PromotionApproval,
        certificate: EvolutionCertificate,
        target: PromotionTarget,
        *,
        now: datetime,
    ) -> None:
        if not isinstance(approval, PromotionApproval):
            raise ApprovalError("approval credential is invalid")
        if approval.certificate_id != certificate.certificate_id:
            raise NamespaceViolation("approval certificate id does not match")
        if approval.certificate_digest != certificate.digest:
            raise NamespaceViolation("approval certificate digest does not match")
        if approval.target != target:
            raise NamespaceViolation("approval target does not match")
        if approval.expires_at.astimezone(UTC) <= now.astimezone(UTC):
            raise ApprovalError("manual approval is expired")
        if self.approval_secret is not None:
            expected = _encode_b64(
                hmac.new(
                    self.approval_secret,
                    _canonical(approval.unsigned_dict()).encode("utf-8"),
                    hashlib.sha256,
                ).digest()
            )
            if not hmac.compare_digest(expected, approval.mac):
                raise ApprovalError("manual approval signature is invalid")

    async def _assert_unused_certificate(
        self,
        connection: asyncpg.Connection,
        tenant: str,
        certificate: EvolutionCertificate,
    ) -> None:
        # The use ledger is append-only, so the authority intentionally has no
        # UPDATE privilege.  A locking SELECT would demand that privilege in
        # PostgreSQL; the unique certificate/approval constraints remain the
        # authoritative race fence at INSERT time.
        row = await connection.fetchrow(
            """
            SELECT certificate_digest, approval_id, receipt_id
              FROM cell_promotion_uses
             WHERE tenant_id=$1 AND certificate_id=$2
            """,
            tenant,
            certificate.certificate_id,
        )
        if row is not None:
            raise PromotionAlreadyUsed("certificate was already consumed")

    async def _insert_receipt_and_outbox(
        self,
        connection: asyncpg.Connection,
        receipt: PromotionReceipt,
    ) -> None:
        receipt_uuid = _uuid(receipt.receipt_id)
        rollback_uuid = (
            _uuid(receipt.rollback_of, field_name="rollback_of") if receipt.rollback_of else None
        )
        await connection.execute(
            f"""
            INSERT INTO cell_promotion_receipts ({_RECEIPT_COLUMNS})
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
            """,  # noqa: S608
            receipt.target.tenant_id,
            receipt_uuid,
            receipt.certificate_id,
            receipt.target.app_id,
            receipt.target.cell_id,
            receipt.target.session_id,
            receipt.previous_active_capsule,
            receipt.active_capsule,
            receipt.previous_control_version,
            receipt.control_version,
            receipt.issued_at.astimezone(UTC),
            receipt.signing_key_id,
            receipt.signature,
            receipt.operation,
            rollback_uuid,
        )
        await connection.execute(
            """
            INSERT INTO cell_promotion_outbox (
                tenant_id, receipt_id, status, lease_epoch, attempts,
                available_at, created_at
            ) VALUES ($1,$2,'pending',0,0,clock_timestamp(),clock_timestamp())
            """,
            receipt.target.tenant_id,
            receipt_uuid,
        )

    def _signed_receipt(
        self,
        *,
        certificate_id: str,
        current: PromotionTarget,
        active_capsule: str,
        next_version: int,
        operation: str = "promote",
        rollback_of: str | None = None,
        issued_at: datetime,
    ) -> PromotionReceipt:
        receipt = PromotionReceipt(
            receipt_id=str(uuid.uuid4()),
            certificate_id=certificate_id,
            target=current,
            previous_active_capsule=current.active_capsule_digest,
            active_capsule=active_capsule,
            previous_control_version=current.control_version,
            control_version=next_version,
            issued_at=issued_at,
            signing_key_id=self.receipt_key_id,
            operation=operation,
            rollback_of=rollback_of,
        )
        return PromotionReceipt(
            receipt_id=receipt.receipt_id,
            certificate_id=receipt.certificate_id,
            target=receipt.target,
            previous_active_capsule=receipt.previous_active_capsule,
            active_capsule=receipt.active_capsule,
            previous_control_version=receipt.previous_control_version,
            control_version=receipt.control_version,
            issued_at=receipt.issued_at,
            signing_key_id=receipt.signing_key_id,
            signature=_encode_b64(self._receipt_key.sign(receipt.signing_bytes())),
            operation=receipt.operation,
            rollback_of=receipt.rollback_of,
        )

    async def compare_and_swap(
        self,
        target: PromotionTarget | CellAddress,
        expected_active_capsule: str | None = None,
        new_active_capsule: str | None = None,
        *,
        expected_control_version: int | None = None,
        control_version: int | None = None,
        certificate: EvolutionCertificate | None = None,
        approval: PromotionApproval | None = None,
        approval_id: str | None = None,
        approval_consumed: bool = False,
    ) -> PromotionReceipt:
        """Atomically consume proof/approval, advance the pointer and enqueue.

        The pointer row is locked before checking the certificate use fence.
        The final ``UPDATE ... WHERE active/version`` is retained even under
        the lock: it makes the intended CAS precondition visible in SQL and is
        safe if a future implementation changes the lock scope.
        """

        target_obj = target if isinstance(target, PromotionTarget) else None
        address = self._address(target)
        tenant = self._tenant_for(address)
        if target_obj is not None and target_obj.tenant_id != tenant:
            raise NamespaceViolation("promotion target tenant is out of scope")
        if control_version is not None and (
            isinstance(control_version, bool) or not isinstance(control_version, int)
        ):
            raise PromotionCASConflict("control version must be an integer")
        async with self._tenant_transaction(tenant) as connection:
            current = await self._load_pointer(connection, address, initialize=target_obj)
            expected_digest = expected_active_capsule or (
                target_obj.active_capsule_digest
                if target_obj is not None
                else current.active_capsule_digest
            )
            expected_version = expected_control_version
            if expected_version is None:
                expected_version = (
                    target_obj.control_version
                    if target_obj is not None
                    else current.control_version
                )
            if (
                current.active_capsule_digest != expected_digest
                or current.control_version != expected_version
            ):
                raise PromotionCASConflict("active pointer changed before CAS")

            next_digest = new_active_capsule
            if certificate is not None:
                self._verify_certificate(certificate, current)
                if next_digest is None:
                    next_digest = certificate.candidate_capsule_digest
                if certificate.source_address != current.address:
                    raise NamespaceViolation("certificate source does not match pointer Cell")
                if certificate.candidate_capsule_digest != next_digest:
                    raise PromotionError("certificate candidate does not match new pointer")
                if certificate.expected_active_capsule != expected_digest:
                    raise PromotionCASConflict("certificate expected active Capsule is stale")
                if certificate.control_version != expected_version:
                    raise PromotionCASConflict("certificate control version is stale")
                await self._assert_unused_certificate(connection, tenant, certificate)
                now = await self._database_now(connection)
                if approval is not None:
                    self._verify_approval(approval, certificate, current, now=now)
                    consumed_approval_id = approval.approval_id
                elif not approval_consumed:
                    raise ApprovalError("promotion requires a consumed manual approval")
                else:
                    consumed_approval_id = approval_id or f"external:{certificate.certificate_id}"
            else:
                consumed_approval_id = None
                now = await self._database_now(connection)
            if next_digest is None:
                raise PromotionError("new active Capsule is required")
            next_version = control_version if control_version is not None else expected_version + 1
            if next_version <= expected_version:
                raise PromotionCASConflict("new control version must advance")
            transitioned = await connection.fetchrow(
                """
                UPDATE cell_promotion_targets
                   SET active_capsule_digest=$5, control_version=$6,
                       updated_at=clock_timestamp()
                 WHERE tenant_id=$1 AND app_id=$2 AND cell_id=$3
                   AND session_id=$4 AND active_capsule_digest=$7
                   AND control_version=$8
                 RETURNING tenant_id, app_id, cell_id, session_id,
                           active_capsule_digest, control_version, updated_at
                """,
                tenant,
                address.app_id,
                address.cell_id,
                address.session_id,
                next_digest,
                next_version,
                expected_digest,
                expected_version,
            )
            if transitioned is None:
                raise PromotionCASConflict("active pointer changed during CAS")
            receipt = self._signed_receipt(
                certificate_id=certificate.certificate_id
                if certificate is not None
                else "manual-cas",
                current=current,
                active_capsule=next_digest,
                next_version=next_version,
                issued_at=now,
            )
            await self._insert_receipt_and_outbox(connection, receipt)
            if certificate is not None:
                try:
                    await connection.execute(
                        """
                        INSERT INTO cell_promotion_uses (
                            tenant_id, certificate_id, certificate_digest,
                            approval_id, app_id, cell_id, session_id, receipt_id
                        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                        """,
                        tenant,
                        certificate.certificate_id,
                        certificate.digest,
                        consumed_approval_id,
                        address.app_id,
                        address.cell_id,
                        address.session_id,
                        _uuid(receipt.receipt_id),
                    )
                except asyncpg.UniqueViolationError as exc:
                    raise PromotionAlreadyUsed(
                        "certificate or approval was already consumed"
                    ) from exc
            return receipt

    async def _load_persisted_receipt(
        self, connection: asyncpg.Connection, receipt: PromotionReceipt
    ) -> PromotionReceipt:
        row = await connection.fetchrow(
            f"""SELECT {_RECEIPT_COLUMNS}
                  FROM cell_promotion_receipts
                 WHERE tenant_id=$1 AND receipt_id=$2""",  # noqa: S608
            receipt.target.tenant_id,
            _uuid(receipt.receipt_id),
        )
        if row is None:
            raise PromotionReceiptError("promotion receipt is not durable")
        stored = _receipt_from_row(_row(row))
        if stored != receipt:
            raise PromotionReceiptError("promotion receipt does not match durable content")
        return stored

    def _verify_receipt(self, receipt: PromotionReceipt) -> None:
        if receipt.signing_key_id != self.receipt_key_id or not receipt.signature:
            raise PromotionReceiptError("promotion receipt signing identity is invalid")
        try:
            self.receipt_public_key.verify(_decode_b64(receipt.signature), receipt.signing_bytes())
        except (InvalidSignature, CertificateError, TypeError, ValueError) as exc:
            raise PromotionReceiptError("promotion receipt signature is invalid") from exc

    async def rollback(
        self,
        receipt: PromotionReceipt,
        *,
        expected_active_capsule: str | None = None,
        expected_control_version: int | None = None,
    ) -> PromotionReceipt:
        """Rollback one promotion with a monotonic ABA-fencing version."""

        if not isinstance(receipt, PromotionReceipt):
            raise PromotionReceiptError("promotion receipt is invalid")
        if receipt.operation != "promote" or receipt.rollback_of is not None:
            raise PromotionReceiptError("only a promotion receipt can authorize rollback")
        self._verify_receipt(receipt)
        address = self._address(receipt.target)
        tenant = self._tenant_for(address)
        async with self._tenant_transaction(tenant) as connection:
            await self._load_persisted_receipt(connection, receipt)
            duplicate = await connection.fetchrow(
                """
                SELECT receipt_id FROM cell_promotion_receipts
                 WHERE tenant_id=$1 AND rollback_of=$2
                """,
                tenant,
                _uuid(receipt.receipt_id),
            )
            if duplicate is not None:
                raise PromotionAlreadyUsed("promotion receipt was already rolled back")
            current = await self._load_pointer(connection, address)
            if current.active_capsule_digest != receipt.active_capsule:
                raise PromotionCASConflict("active Capsule no longer matches promotion receipt")
            if current.control_version != receipt.control_version:
                raise PromotionCASConflict("control version no longer matches promotion receipt")
            if (
                expected_active_capsule is not None
                and current.active_capsule_digest != expected_active_capsule
            ):
                raise PromotionCASConflict("caller supplied a stale active Capsule")
            if (
                expected_control_version is not None
                and current.control_version != expected_control_version
            ):
                raise PromotionCASConflict("caller supplied a stale control version")
            next_version = current.control_version + 1
            transitioned = await connection.fetchrow(
                """
                UPDATE cell_promotion_targets
                   SET active_capsule_digest=$5, control_version=$6,
                       updated_at=clock_timestamp()
                 WHERE tenant_id=$1 AND app_id=$2 AND cell_id=$3
                   AND session_id=$4 AND active_capsule_digest=$7
                   AND control_version=$8
                 RETURNING tenant_id, app_id, cell_id, session_id,
                           active_capsule_digest, control_version, updated_at
                """,
                tenant,
                address.app_id,
                address.cell_id,
                address.session_id,
                receipt.previous_active_capsule,
                next_version,
                receipt.active_capsule,
                receipt.control_version,
            )
            if transitioned is None:
                raise PromotionCASConflict("active pointer changed during rollback CAS")
            rollback_receipt = self._signed_receipt(
                certificate_id=receipt.certificate_id,
                current=current,
                active_capsule=receipt.previous_active_capsule,
                next_version=next_version,
                operation="rollback",
                rollback_of=receipt.receipt_id,
                issued_at=await self._database_now(connection),
            )
            await self._insert_receipt_and_outbox(connection, rollback_receipt)
            return rollback_receipt

    async def pending_outbox(
        self, *, tenant_id: str | None = None, limit: int | None = None
    ) -> tuple[PromotionReceipt, ...]:
        """Return unpublished receipts, including leases recoverable by a new Pod."""

        tenant = self._assert_tenant(tenant_id or self.tenant_id or "")
        if limit is not None and (
            isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0
        ):
            raise ValueError("outbox limit must be positive")
        async with self._tenant_transaction(tenant) as connection:
            suffix = " LIMIT $2" if limit is not None else ""
            args: tuple[object, ...] = (tenant, limit) if limit is not None else (tenant,)
            rows = await self._fetch_many(
                connection,
                f"""
                SELECT {_RECEIPT_SELECT_COLUMNS},
                       o.status, o.claimed_by, o.lease_epoch,
                       o.lease_expires_at, o.attempts, o.available_at,
                       o.published_at, o.last_error, o.created_at
                  FROM cell_promotion_receipts AS r
                  JOIN cell_promotion_outbox AS o
                    ON o.tenant_id=r.tenant_id AND o.receipt_id=r.receipt_id
                 WHERE o.tenant_id=$1 AND o.status <> 'published'
                 ORDER BY o.created_at, o.receipt_id{suffix}
                """,  # noqa: S608
                *args,
            )
            return tuple(_receipt_from_row(item) for item in rows)

    async def claim_outbox(
        self,
        *,
        owner_id: str,
        lease_seconds: float = 30.0,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> tuple[PromotionOutboxClaim, ...]:
        """Claim ready or expired outbox rows with a monotonically new epoch."""

        owner = _text("owner_id", owner_id)
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, (int, float))
            or not math.isfinite(lease_seconds)
            or lease_seconds <= 0
        ):
            raise ValueError("outbox lease must be positive")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("outbox limit must be positive")
        tenant = self._assert_tenant(tenant_id or self.tenant_id or "")
        async with self._tenant_transaction(tenant) as connection:
            candidates = await self._fetch_many(
                connection,
                f"""
                SELECT {_RECEIPT_SELECT_COLUMNS},
                       o.status, o.claimed_by, o.lease_epoch,
                       o.lease_expires_at, o.attempts, o.available_at,
                       o.published_at, o.last_error, o.created_at
                  FROM cell_promotion_receipts AS r
                  JOIN cell_promotion_outbox AS o
                    ON o.tenant_id=r.tenant_id AND o.receipt_id=r.receipt_id
                 WHERE o.tenant_id=$1 AND o.status <> 'published'
                   AND o.available_at <= clock_timestamp()
                   AND (o.status='pending'
                        OR o.lease_expires_at <= clock_timestamp())
                 ORDER BY o.created_at, o.receipt_id
                 FOR UPDATE OF o SKIP LOCKED
                 LIMIT $2
                """,  # noqa: S608
                tenant,
                limit,
            )
            claims: list[PromotionOutboxClaim] = []
            for candidate in candidates:
                old_epoch = _int(candidate.get("lease_epoch"))
                row = await connection.fetchrow(
                    f"""
                    UPDATE cell_promotion_outbox
                       SET status='claimed', claimed_by=$3,
                           lease_epoch=lease_epoch+1,
                           lease_expires_at=clock_timestamp()
                               + ($4 * interval '1 second'),
                           attempts=attempts+1, last_error=NULL
                     WHERE tenant_id=$1 AND receipt_id=$2
                       AND status <> 'published'
                       AND lease_epoch=$5
                     RETURNING {_OUTBOX_COLUMNS}
                    """,  # noqa: S608
                    tenant,
                    _uuid(str(candidate["receipt_id"])),
                    owner,
                    float(lease_seconds),
                    old_epoch,
                )
                if row is None:
                    continue
                merged = {**candidate, **_row(row)}
                # The UPDATE result contains authoritative lease fields; the
                # receipt columns are copied from the locked candidate row.
                claims.append(_claim_from_row(merged))
            return tuple(claims)

    async def acknowledge(
        self,
        receipt_id: str,
        *,
        owner_id: str,
        lease_epoch: int,
        tenant_id: str | None = None,
    ) -> bool:
        """Acknowledge only the currently owned, unexpired delivery lease."""

        owner = _text("owner_id", owner_id)
        if isinstance(lease_epoch, bool) or not isinstance(lease_epoch, int) or lease_epoch <= 0:
            raise ValueError("lease_epoch must be a positive integer")
        tenant = self._assert_tenant(tenant_id or self.tenant_id or "")
        async with self._tenant_transaction(tenant) as connection:
            row = await connection.fetchrow(
                """
                UPDATE cell_promotion_outbox
                   SET status='published', published_at=clock_timestamp(),
                       claimed_by=NULL, lease_expires_at=NULL
                 WHERE tenant_id=$1 AND receipt_id=$2 AND status='claimed'
                   AND claimed_by=$3 AND lease_epoch=$4
                   AND lease_expires_at > clock_timestamp()
                 RETURNING receipt_id
                """,
                tenant,
                _uuid(receipt_id),
                owner,
                lease_epoch,
            )
            return row is not None

    ack = acknowledge

    async def release(
        self,
        receipt_id: str,
        *,
        owner_id: str,
        lease_epoch: int,
        error: str | None = None,
        delay_seconds: float = 1.0,
        tenant_id: str | None = None,
    ) -> bool:
        """Return a failed delivery to pending without weakening its epoch fence."""

        owner = _text("owner_id", owner_id)
        if (
            isinstance(delay_seconds, bool)
            or not isinstance(delay_seconds, (int, float))
            or not math.isfinite(delay_seconds)
            or delay_seconds < 0
        ):
            raise ValueError("delay_seconds must be non-negative")
        tenant = self._assert_tenant(tenant_id or self.tenant_id or "")
        async with self._tenant_transaction(tenant) as connection:
            row = await connection.fetchrow(
                """
                UPDATE cell_promotion_outbox
                   SET status='pending', claimed_by=NULL,
                       lease_expires_at=NULL,
                       available_at=clock_timestamp()
                           + ($5 * interval '1 second'),
                       last_error=$6
                 WHERE tenant_id=$1 AND receipt_id=$2 AND status='claimed'
                   AND claimed_by=$3 AND lease_epoch=$4
                 RETURNING receipt_id
                """,
                tenant,
                _uuid(receipt_id),
                owner,
                lease_epoch,
                float(delay_seconds),
                error[:500] if isinstance(error, str) else None,
            )
            return row is not None

    async def reconcile(
        self,
        publisher: Callable[[PromotionReceipt], object | Awaitable[object]],
        *,
        owner_id: str,
        lease_seconds: float = 30.0,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> tuple[str, ...]:
        """Publish claimed receipts and leave failed claims recoverable."""

        claims = await self.claim_outbox(
            owner_id=owner_id,
            lease_seconds=lease_seconds,
            limit=limit,
            tenant_id=tenant_id,
        )
        published: list[str] = []
        for claim in claims:
            try:
                result = publisher(claim.receipt)
                if inspect.isawaitable(result):
                    await result
            except Exception as exc:
                await self.release(
                    claim.receipt_id,
                    owner_id=claim.owner_id,
                    lease_epoch=claim.lease_epoch,
                    error=type(exc).__name__,
                    tenant_id=tenant_id,
                )
                raise
            if await self.acknowledge(
                claim.receipt_id,
                owner_id=claim.owner_id,
                lease_epoch=claim.lease_epoch,
                tenant_id=tenant_id,
            ):
                published.append(claim.receipt_id)
        return tuple(published)


__all__ = ["PostgresPromotionStore", "PromotionOutboxClaim", "PromotionOutboxConflict"]
