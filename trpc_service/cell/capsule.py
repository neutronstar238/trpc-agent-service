"""Content-addressed Agent Capsule contracts.

An :class:`AgentCapsule` is the immutable deployment unit used by the Cell
Fabric.  The manifest is deliberately small: it contains references to
versioned Agent assets, policy, knowledge and storage profiles, but never
contains resolved secrets.  ``digest`` and ``signature`` are an envelope
around the canonical manifest and therefore do not change the content
address.

The module is intentionally independent from the runtime and registry.  A
registry can persist the JSON returned by ``model_dump(by_alias=True)`` and a
runtime can verify it before admitting a Cell.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any, Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


class CapsuleVerificationError(ValueError):
    """Base error raised when a capsule cannot be trusted."""


class CapsuleDigestMismatch(CapsuleVerificationError):
    """The declared digest is absent or does not match the manifest."""


class CapsuleSignatureError(CapsuleVerificationError):
    """The signature is absent, malformed, or not trusted."""


class _ImmutableModel(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        populate_by_name=True,
        validate_assignment=True,
    )


def _validate_digest(value: str) -> str:
    if not _DIGEST_RE.fullmatch(value):
        raise ValueError("digest must use the sha256:<64 lowercase hex> format")
    return value


def _validate_non_empty(value: str) -> str:
    if not value.strip():
        raise ValueError("value cannot be empty")
    return value


def _sorted_unique(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized = tuple(item.strip() for item in values)
    if any(not item for item in normalized):
        raise ValueError("capability values cannot be empty")
    return tuple(sorted(set(normalized)))


class SLOProfile(_ImmutableModel):
    """The placement-relevant part of an Agent SLO.

    ``latency_budget_ms`` is a per-turn p95 target.  The scheduler uses the
    target as a soft ranking signal after applying hard admission checks.  A
    target that no node can currently meet still yields the least-bad
    deterministic placement instead of silently dropping a Cell.
    """

    latency_budget_ms: float = Field(default=5_000, gt=0, le=300_000)
    availability_target: float = Field(default=0.99, ge=0, le=1)
    priority: int = Field(default=50, ge=0, le=100)


class CapsuleMetadata(_ImmutableModel):
    """Identity and human-facing metadata for a capsule."""

    tenant_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    version: int = Field(default=1, ge=1)
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)

    @field_validator("tenant_id", "name")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return _validate_non_empty(value)


class CapsuleSpec(_ImmutableModel):
    """References and policy required to materialize a Cell.

    Asset fields are content digests.  The storage profile is a registry
    identity because it describes a runtime adapter rather than an artifact.
    Lists that represent capabilities are canonicalized on input so that
    equivalent manifests receive the same digest regardless of input order.
    """

    graph: str = Field(alias="graph")
    prompt: str = Field(alias="prompt")
    model_policy: str = Field(alias="modelPolicy")
    tool_manifest: str = Field(alias="toolManifest")
    governance_policy: str = Field(alias="governancePolicy")
    knowledge_snapshot: str | None = Field(default=None, alias="knowledgeSnapshot")
    storage_profile: str = Field(alias="storageProfile")
    channel_capabilities: tuple[str, ...] = Field(default=(), alias="channelCapabilities")
    slo: SLOProfile = Field(default_factory=SLOProfile)

    @field_validator(
        "graph",
        "prompt",
        "model_policy",
        "tool_manifest",
        "governance_policy",
        "storage_profile",
    )
    @classmethod
    def validate_reference(cls, value: str) -> str:
        return _validate_non_empty(value)

    @field_validator("knowledge_snapshot")
    @classmethod
    def validate_optional_reference(cls, value: str | None) -> str | None:
        if value is not None:
            return _validate_non_empty(value)
        return value

    @field_validator("channel_capabilities")
    @classmethod
    def canonicalize_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique(value)


class CapsuleSignature(_ImmutableModel):
    """An Ed25519 signature over the canonical unsigned manifest."""

    algorithm: Literal["ed25519"] = "ed25519"
    key_id: str = Field(min_length=1, max_length=256)
    value: str = Field(min_length=1, max_length=256)

    @field_validator("key_id")
    @classmethod
    def validate_key_id(cls, value: str) -> str:
        return _validate_non_empty(value)

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        if not _B64URL_RE.fullmatch(value):
            raise ValueError("signature must be base64url encoded")
        try:
            decoded = _decode_base64url(value)
        except ValueError as exc:
            raise ValueError("signature must be base64url encoded") from exc
        if len(decoded) != 64:
            raise ValueError("ed25519 signatures must decode to 64 bytes")
        return value


def _decode_base64url(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid base64url value") from exc


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class AgentCapsule(_ImmutableModel):
    """An immutable, content-addressed deployment manifest.

    The digest is calculated from ``apiVersion``, ``kind``, ``metadata`` and
    ``spec`` only.  A signature is an envelope and can be replaced by a key
    rotation without changing the content address.  Call ``verify`` before a
    Cell is scheduled.
    """

    api_version: str = Field(default="agent.trpc.io/v1", alias="apiVersion")
    kind: Literal["AgentCapsule"] = "AgentCapsule"
    metadata: CapsuleMetadata
    spec: CapsuleSpec
    digest: str | None = None
    signature: CapsuleSignature | None = None

    @field_validator("api_version")
    @classmethod
    def validate_api_version(cls, value: str) -> str:
        return _validate_non_empty(value)

    @field_validator("digest")
    @classmethod
    def validate_declared_digest(cls, value: str | None) -> str | None:
        if value is not None:
            return _validate_digest(value)
        return value

    def _unsigned_payload(self) -> dict[str, Any]:
        """Return the exact JSON-compatible payload covered by digest/signature."""

        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"digest", "signature"},
            exclude_none=False,
        )

    def canonical_bytes(self) -> bytes:
        """Serialize the unsigned manifest using a stable UTF-8 JSON form."""

        return json.dumps(
            self._unsigned_payload(),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    def compute_digest(self) -> str:
        """Compute the content address of this manifest."""

        return f"sha256:{hashlib.sha256(self.canonical_bytes()).hexdigest()}"

    @property
    def content_digest(self) -> str:
        """Return the computed content address, independent of the envelope."""

        return self.compute_digest()

    def with_digest(self) -> Self:
        """Return a copy carrying its computed digest."""

        return self.model_copy(update={"digest": self.compute_digest()})

    def sign(self, private_key: Ed25519PrivateKey | bytes, *, key_id: str) -> Self:
        """Return a signed copy.

        ``private_key`` may be an Ed25519 key object or its 32-byte raw
        encoding.  Only the public key identifier is stored in the manifest;
        private key material never enters the model or its serialization.
        """

        signer = _private_key(private_key)
        digest = self.compute_digest()
        signature = CapsuleSignature(
            key_id=key_id,
            value=_encode_base64url(signer.sign(self.canonical_bytes())),
        )
        return self.model_copy(update={"digest": digest, "signature": signature})

    def verify_digest(self) -> bool:
        """Return whether the declared digest matches the canonical content."""

        return self.digest is not None and self.digest == self.compute_digest()

    def verify_signature(
        self,
        trusted_keys: Mapping[str, Ed25519PublicKey | bytes],
    ) -> None:
        """Verify the Ed25519 envelope against a key-id trust map."""

        if self.signature is None:
            raise CapsuleSignatureError("capsule signature is required")
        if self.signature.key_id not in trusted_keys:
            raise CapsuleSignatureError("capsule signing key is not trusted")
        try:
            public_key = _public_key(trusted_keys[self.signature.key_id])
            public_key.verify(
                _decode_base64url(self.signature.value),
                self.canonical_bytes(),
            )
        except CapsuleVerificationError:
            # Preserve actionable trust-map/key-shape errors raised by the
            # key adapter instead of relabelling them as bad signatures.
            raise
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise CapsuleSignatureError("capsule signature is invalid") from exc

    def verify(
        self,
        trusted_keys: Mapping[str, Ed25519PublicKey | bytes] | None = None,
        *,
        require_signature: bool = True,
    ) -> None:
        """Verify digest and, by default, the signature.

        Passing ``require_signature=False`` is useful for local development,
        but a production registry should always provide ``trusted_keys`` and
        retain the default.
        """

        if not self.verify_digest():
            raise CapsuleDigestMismatch("capsule digest does not match manifest")
        if require_signature:
            if trusted_keys is None:
                raise CapsuleSignatureError("trusted signing keys are required")
            self.verify_signature(trusted_keys)
        elif self.signature is not None and trusted_keys is not None:
            self.verify_signature(trusted_keys)

    def public_manifest(self) -> dict[str, Any]:
        """Return a safe manifest view for logs and registry listings.

        No key material is stored in a capsule; this method nevertheless
        omits the signature value so logs can identify a capsule without
        copying cryptographic envelope data.
        """

        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"signature"},
            exclude_none=False,
        )


def _private_key(value: Ed25519PrivateKey | bytes) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    if isinstance(value, bytes):
        try:
            return Ed25519PrivateKey.from_private_bytes(value)
        except ValueError as exc:
            raise CapsuleSignatureError("ed25519 private key must be 32 raw bytes") from exc
    raise CapsuleSignatureError("unsupported ed25519 private key type")


def _public_key(value: Ed25519PublicKey | bytes) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value
    if isinstance(value, bytes):
        try:
            return Ed25519PublicKey.from_public_bytes(value)
        except ValueError as exc:
            raise CapsuleSignatureError("ed25519 public key must be 32 raw bytes") from exc
    raise CapsuleSignatureError("unsupported ed25519 public key type")


# The shorter names make the contract pleasant to import while preserving a
# descriptive canonical class name for documentation and type checkers.
CapsuleManifest = AgentCapsule
Capsule = AgentCapsule


__all__ = [
    "AgentCapsule",
    "Capsule",
    "CapsuleDigestMismatch",
    "CapsuleManifest",
    "CapsuleMetadata",
    "CapsuleSignature",
    "CapsuleSignatureError",
    "CapsuleSpec",
    "CapsuleVerificationError",
    "SLOProfile",
]
