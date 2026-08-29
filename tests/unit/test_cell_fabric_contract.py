from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations" / "versions" / "0017_agent_cell_fabric.py"
ARCHITECTURE = ROOT / "docs" / "agent-cell-fabric.md"


def test_cell_fabric_migration_is_tenant_scoped_and_append_only() -> None:
    source = MIGRATION.read_text(encoding="utf-8")

    assert 'down_revision = "0016_session_ready_backlog_metric"' in source
    for table in (
        "agent_capsules",
        "agent_cells",
        "cell_events",
        "cell_tool_intents",
        "cell_effect_ledger",
        "cell_effect_receipts",
    ):
        assert f'"{table}"' in source

    assert "CREATE POLICY tenant_isolation_{table}" in source
    assert "ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in source
    assert "GRANT SELECT, INSERT ON cell_events" in source
    assert "GRANT SELECT, INSERT, UPDATE ON cell_events" not in source


def test_innovation_document_contains_verifiable_claims_and_diagrams() -> None:
    source = ARCHITECTURE.read_text(encoding="utf-8")

    for concept in (
        "Agent Capsule",
        "Causal Event Kernel",
        "Intent / Effect Split",
        "Replay & Evolution",
        "确定性回放",
        "反事实分支",
        "hash-chain",
    ):
        assert concept in source
    assert "```mermaid" in source
    assert "重复 effect_key 的外部副作用次数" in source
