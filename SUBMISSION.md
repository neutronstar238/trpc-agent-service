# 评审入口

本分支是多租户节点化 Agent 平台的创新提交版本。建议按以下顺序评审：

1. [`README.md`](README.md)：定位、能力边界、安装与验证。
2. [`docs/agent-cell-fabric.md`](docs/agent-cell-fabric.md)：Agent Capsule、Causal Event Kernel、
   Intent/Effect Split、Semantic Cell Scheduler 与 Replay/Evolution 创新设计。
3. [`docs/architecture.md`](docs/architecture.md)：系统架构图和完整消息时序。
4. [`docs/data-model.md`](docs/data-model.md)：核心 ER 模型与 Cell 扩展表。
5. [`docs/acceptance-matrix.md`](docs/acceptance-matrix.md)：逐项验收追踪。
6. [`docs/ack-acceptance.md`](docs/ack-acceptance.md)：真实 ACK 功能/性能结论及生产边界。

最小离线演示：

```bash
uv sync --extra dev --locked
uv run trpc-service cell-demo --output runs/cell-fabric-demo.json
uv run pytest -q tests/unit
sh coverage.sh
```

部署清单静态验证：

```bash
docker compose config --quiet
kubectl kustomize deploy/kustomize/overlays/production >/dev/null
uv run python -m scripts.mock_production_gate
```

仓库不会提交 `.env*`、kubeconfig、Secret、运行报告、覆盖率数据库或集群测试夹具。真实环境门禁必须
显式注入凭证和 opt-in；缺少外部条件时保持 `not_run`，不得以离线模拟或 ACK 子集证据冒充完整生产
发布通过。
