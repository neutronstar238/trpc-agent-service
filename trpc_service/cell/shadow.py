"""Side-effect-free validation bridge for gradual Cell effect adoption."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from trpc_service.cell.events import CellAddress
from trpc_service.cell.intents import IntentRisk, PolicyDecision, ToolIntent
from trpc_service.tenant.models import TenantContext, ToolRisk


@dataclass(frozen=True, slots=True)
class ShadowIntentEvidence:
    """In-memory comparison between the legacy call and a native intent.

    Raw arguments are deliberately absent.  A journal must additionally HMAC
    the digest fields before persistence because small argument spaces can be
    vulnerable to dictionary attacks even when represented by SHA-256.
    """

    intent: ToolIntent
    legacy_effect_key: str
    real_provider_call_count: int = 0

    @property
    def native_effect_key(self) -> str:
        return self.intent.effect_key

    @property
    def arguments_hash(self) -> str:
        return self.intent.arguments_hash


class CellEffectShadowValidator:
    """Derive a native intent without authorizing or invoking an effect."""

    def derive(
        self,
        context: TenantContext,
        address: CellAddress,
        *,
        turn_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        risk: ToolRisk,
        legacy_effect_key: str,
    ) -> ShadowIntentEvidence:
        if (
            address.tenant_id != context.tenant_id
            or address.app_id != context.app_id
            or address.session_id != context.session_id
            or address.branch_id != "main"
        ):
            raise ValueError("shadow intent namespace does not match the active main Cell")
        if not legacy_effect_key:
            raise ValueError("legacy effect key must be non-empty")
        intent_id = _intent_id(
            context,
            address,
            turn_id=turn_id,
            tool_name=tool_name,
            arguments=arguments,
        )
        intent = ToolIntent(
            tenant_id=context.tenant_id,
            app_id=context.app_id,
            cell_id=address.cell_id,
            session_id=context.session_id,
            capsule_digest=address.capsule_digest,
            branch_id=address.branch_id,
            intent_id=intent_id,
            tool_name=tool_name,
            arguments=arguments,
            policy_decision=PolicyDecision.DENY,
            risk=_intent_risk(risk),
            principal_id=context.principal_id,
            request_id=context.request_id,
            trace_id=context.trace_id,
            metadata={"mode": "shadow", "turn_id": turn_id},
        )
        intent.validate_integrity()
        return ShadowIntentEvidence(intent=intent, legacy_effect_key=legacy_effect_key)


def _intent_id(
    context: TenantContext,
    address: CellAddress,
    *,
    turn_id: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> str:
    material = json.dumps(
        {
            "tenant_id": context.tenant_id,
            "app_id": context.app_id,
            "cell_id": address.cell_id,
            "session_id": context.session_id,
            "capsule_digest": address.capsule_digest,
            "branch_id": address.branch_id,
            "turn_id": turn_id,
            "tool_name": tool_name,
            "arguments": arguments,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return "shadow-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _intent_risk(risk: ToolRisk) -> IntentRisk:
    return {
        ToolRisk.IDEMPOTENT: IntentRisk.LOW,
        ToolRisk.NON_IDEMPOTENT: IntentRisk.HIGH,
        ToolRisk.UNKNOWN: IntentRisk.UNKNOWN,
    }[risk]


__all__ = ["CellEffectShadowValidator", "ShadowIntentEvidence"]
