from pathlib import Path

ROOT = Path(__file__).parents[2]
YQZL = ROOT / "deploy" / "yqzl"


def test_yqzl_runtime_uses_local_minio_and_secret_references() -> None:
    runtime = (YQZL / "runtime.env.example").read_text(encoding="utf-8")

    assert "TRPC_SERVICE_S3_ENDPOINT=http://127.0.0.1:9000" in runtime
    assert "TRPC_SERVICE_S3_BUCKET=trpc-artifacts" in runtime
    secret_ref = (
        "TRPC_SERVICE_S3_SECRET_KEY_REF="
        "file:///www/wwwroot/tx.nstarzx.cn/secrets/minio_root_password"
    )
    assert secret_ref in runtime
    assert "TRPC_SERVICE_S3_ACCESS_KEY=" not in runtime


def test_yqzl_runtime_pins_mailbox_v2_and_verifies_recovery_role() -> None:
    runtime = (YQZL / "runtime.env.example").read_text(encoding="utf-8")
    verifier = (YQZL / "verify_runtime.sh").read_text(encoding="utf-8")

    assert "TRPC_SERVICE_SCHEDULER_VERSION=v2" in runtime
    assert "TRPC_SERVICE_REDIS_STREAM=trpc:session-ready:v2" in runtime
    assert "TRPC_SERVICE_REDIS_CONSUMER_GROUP=trpc-session-ready-v2" in runtime
    assert "  session-recovery\n" in verifier


def test_yqzl_runtime_has_fail_closed_secret_and_endpoint_policies() -> None:
    runtime = (YQZL / "runtime.env.example").read_text(encoding="utf-8")

    assert "TRPC_SERVICE_RUNTIME_STATE_DIR=/tmp/trpc-agent-service" in runtime
    assert "TRPC_SERVICE_TENANT_SECRET_ROOT=/www/wwwroot/tx.nstarzx.cn/secrets" in runtime
    assert "TRPC_SERVICE_TENANT_SECRET_ENV_NAMES=[]" in runtime
    assert 'TRPC_SERVICE_MODEL_ENDPOINT_HOSTS=["api.openai.com"]' in runtime
    assert "TRPC_SERVICE_FEISHU_ALLOW_STALE_BINDING_CACHE=false" in runtime
    assert "TRPC_SERVICE_EMERGENCY_QUEUE_KEY_VERSION=v1" in runtime
    assert "TRPC_SERVICE_EMERGENCY_QUEUE_PREVIOUS_KEY_REFS={}" in runtime


def test_yqzl_minio_unit_is_pinned_local_only_and_unprivileged_container() -> None:
    unit = (YQZL / "trpc-agent-minio.service").read_text(encoding="utf-8")

    assert "quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z" in unit
    assert "--user 1000:1000" in unit
    assert '--group-add "$(/usr/bin/id -g trpcagent)"' in unit
    assert "--cap-drop=ALL" in unit
    assert "--security-opt=no-new-privileges" in unit
    assert "--memory=512m" in unit
    assert "--pids-limit=256" in unit
    assert "--publish 127.0.0.1:9000:9000" in unit
    assert "--publish 127.0.0.1:9001:9001" in unit
    assert "--privileged" not in unit
    assert "ConditionPathExists=/www/wwwroot/tx.nstarzx.cn/secrets/minio_root_password" in unit


def test_yqzl_provision_installs_and_starts_minio_idempotently() -> None:
    script = (YQZL / "provision.sh").read_text(encoding="utf-8")

    assert "a real deploy/yqzl/runtime.env is required" in script
    assert 'runtime_env_source" == *.example' in script
    assert "runtime.env still contains a placeholder value" in script
    assert 'make_secret "$SITE_ROOT/secrets/minio_root_user" minio_user' in script
    assert 'make_secret "$SITE_ROOT/secrets/minio_root_password" password' in script
    assert 'install -d -m 0750 -o 1000 -g 1000 "$SITE_ROOT/data/minio"' in script
    assert 'install -m 0644 "$APP_ROOT/deploy/yqzl/trpc-agent-minio.service"' in script
    assert "systemctl enable trpc-agent-minio.service" in script
    assert "systemctl start trpc-agent-minio.service" in script
    assert 'docker pull "$MINIO_IMAGE"' in script
    assert "--env MC_CONFIG_DIR=/tmp/.mc" in script
    assert "mc mb --ignore-existing" in script
