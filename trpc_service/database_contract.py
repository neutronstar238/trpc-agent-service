"""Shared database privilege contract for cross-tenant worker processes."""

_LEGACY_WORKER_TABLES = (
    "tenants",
    "agent_apps",
    "config_revisions",
    "storage_profiles",
    "tenant_policies",
    "admin_idempotency",
    "channel_bindings",
    "channel_identities",
    "inbound_messages",
    "outbound_messages",
    "delivery_attempts",
    "sessions",
    "session_turns",
    "turn_intents",
    "session_events",
    "session_summaries",
    "memories",
    "artifacts",
    "knowledge_items",
    "knowledge_embeddings",
    "outbox_events",
    "dead_letters",
    "tool_executions",
    "confirmation_challenges",
    "audit_logs",
    "tenant_budget_usage",
    "fault_stage_controls",
    "session_mailboxes",
    "session_mailbox_items",
)

WORKER_TABLE_PRIVILEGES: dict[str, str] = {
    **{table: "SELECT,INSERT,UPDATE,DELETE" for table in _LEGACY_WORKER_TABLES},
    "agent_capsules": "SELECT",
    "agent_cells": "SELECT,INSERT",
    "cell_events": "SELECT,INSERT",
    "cell_branch_heads": "SELECT,INSERT",
}


WORKER_CELL_FUNCTIONS = (
    "public.ensure_runtime_projection_capsule(text,text,text,jsonb,text,text)",
    "public.lock_cell_branch_head(text,text,text,text,text,text)",
)


_DANGEROUS_TABLE_PRIVILEGES = (
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)


RUNTIME_FORBIDDEN_CELL_PRIVILEGES = tuple(
    (table, privilege)
    for table in (
        "agent_capsules",
        "agent_cells",
        "cell_events",
        "cell_tool_intents",
        "cell_effect_ledger",
        "cell_effect_receipts",
        "cell_branch_heads",
        "cell_placement_reservations",
        "cell_approval_nonces",
        "cell_node_capacity",
    )
    for privilege in _DANGEROUS_TABLE_PRIVILEGES
)


WORKER_FORBIDDEN_CELL_PRIVILEGES = tuple(
    (table, privilege)
    for table, privileges in {
        "agent_capsules": _DANGEROUS_TABLE_PRIVILEGES,
        "agent_cells": ("UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"),
        "cell_events": ("UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"),
        "cell_branch_heads": (
            "UPDATE",
            "DELETE",
            "TRUNCATE",
            "REFERENCES",
            "TRIGGER",
        ),
        "cell_tool_intents": ("SELECT", *_DANGEROUS_TABLE_PRIVILEGES),
        "cell_effect_ledger": ("SELECT", *_DANGEROUS_TABLE_PRIVILEGES),
        "cell_effect_receipts": ("SELECT", *_DANGEROUS_TABLE_PRIVILEGES),
        "cell_placement_reservations": ("SELECT", *_DANGEROUS_TABLE_PRIVILEGES),
        "cell_approval_nonces": ("SELECT", *_DANGEROUS_TABLE_PRIVILEGES),
        "cell_node_capacity": ("SELECT", *_DANGEROUS_TABLE_PRIVILEGES),
    }.items()
    for privilege in privileges
)


__all__ = [
    "RUNTIME_FORBIDDEN_CELL_PRIVILEGES",
    "WORKER_CELL_FUNCTIONS",
    "WORKER_FORBIDDEN_CELL_PRIVILEGES",
    "WORKER_TABLE_PRIVILEGES",
]
