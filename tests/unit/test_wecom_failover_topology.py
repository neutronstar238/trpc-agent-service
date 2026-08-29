from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
PRODUCTION = ROOT / "deploy" / "kustomize" / "overlays" / "production"
YQZL = ROOT / "deploy" / "yqzl"


def test_production_wecom_replicas_require_distinct_nodes() -> None:
    kustomization = yaml.safe_load((PRODUCTION / "kustomization.yaml").read_text("utf-8"))
    assert {entry["path"] for entry in kustomization["patches"]} >= {
        "replicas-patch.yaml",
        "wecom-ha-patch.yaml",
    }

    patch = yaml.safe_load((PRODUCTION / "wecom-ha-patch.yaml").read_text("utf-8"))
    assert patch["metadata"]["name"] == "trpc-wecom-connector"
    pod_spec = patch["spec"]["template"]["spec"]
    constraints = pod_spec["topologySpreadConstraints"]
    assert any(
        constraint["topologyKey"] == "kubernetes.io/hostname"
        and constraint["whenUnsatisfiable"] == "DoNotSchedule"
        for constraint in constraints
    )
    required = pod_spec["affinity"]["podAntiAffinity"][
        "requiredDuringSchedulingIgnoredDuringExecution"
    ]
    assert any(rule["topologyKey"] == "kubernetes.io/hostname" for rule in required)


def test_yqzl_wecom_standby_has_fixed_role_and_isolated_runtime_state() -> None:
    service = (YQZL / "trpc-agent-wecom-standby.service").read_text("utf-8")
    assert "ExecStart=" in service
    assert "serve --role wecom-connector" in service
    assert "TRPC_SERVICE_RUNTIME_STATE_DIR=/run/trpc-agent-wecom-standby" in service
    assert "RuntimeDirectory=trpc-agent-wecom-standby" in service
    assert "NoNewPrivileges=true" in service
    assert "ProtectSystem=strict" in service

    provision = (YQZL / "provision.sh").read_text("utf-8")
    assert "trpc-agent-wecom-standby.service" in provision
    assert "trpc-agent-wecom-primary.conf" in provision


def test_yqzl_wecom_units_load_the_release_source_tree() -> None:
    standby = (YQZL / "trpc-agent-wecom-standby.service").read_text("utf-8")
    primary = (YQZL / "trpc-agent-wecom-primary.conf").read_text("utf-8")
    expected = "Environment=PYTHONPATH=/www/wwwroot/tx.nstarzx.cn/app"

    assert expected in standby
    assert expected in primary
