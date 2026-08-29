# Causal Agent Cell Fabric

面向企业微信 AI Bot 与飞书应用机器人的多租户、因果可回放 Agent 运行平台。它在
`tRPC-Agent-Python 1.1.19` 的公开 Runner/Agent/Event/Tool Safety API 之上提供可靠接入、
事务型 Session、无状态 Worker、租户治理和可观测性，并将 Agent 升级为可部署、可迁移、
可暂停、可回放、可分叉和可验证的逻辑 **Agent Cell**；原有题目归档在
[docs/requirements.md](docs/requirements.md)。

## 创新架构

- **Agent Capsule**：内容寻址、可签名的不可变 Agent 制品，统一 Graph、模型、工具、治理、
  Knowledge snapshot、Storage profile 与 SLO。
- **Causal Event Kernel**：带 sequence、causation、branch 和 hash-chain 的事实日志，可验证投影、
  时间旅行和确定性回放。
- **Intent / Effect Split**：Agent 只能提出 Tool Intent；策略、预算、确认和幂等执行面决定真实副作用。
- **Semantic Cell Scheduler**：按能力、地域合规、数据局部性、SLO、负载与成本调度逻辑 Cell，Worker
  只是可替换宿主。
- **Replay & Evolution**：从生产序号建立隔离的候选分支，对新模型、Prompt、Graph 或策略进行反事实
  评估，再按租户灰度发布。

完整设计、数据协议和演示验收场景见
[Causal Agent Cell Fabric 架构](docs/agent-cell-fabric.md)。

## 已实现能力

- 由已认证 `channel_binding_id` 解析租户，服务端 HMAC 生成 Session ID，外部消息不能声明租户。
- PostgreSQL Inbox/Outbox、幂等键、Session lease 与 fencing token；Redis Streams 只作可重建传输。
- 同一 Session 串行提交、不同 Session 并行；一次 turn 的 event/state/outbound 原子可见。
- 企业微信 AI Bot WebSocket 长连接，以及飞书加密 HTTP 事件回调、URL 校验和 OpenAPI 异步回复。
- OIDC/JWKS、RBAC、ETag 乐观并发、Admin 幂等、审计、DLQ 查询和人工 outbound 重放。
- 工具白名单、预算预留、SDK Tool Safety、一次性确认令牌和非幂等工具歧义状态。
- PostgreSQL/RLS、Redis 单调投影、S3/MinIO staged artifact、pgvector 与外部 Memory 扩展口。
- 隐私优先 OpenTelemetry、Prometheus 指标、Docker Compose 和 Kubernetes/Kustomize。
- `prepare → backfill → shadow-read → dual-write → cutover → verify → cleanup/rollback` 迁移状态机。

项目不包含管理 UI、Telegram、微信公众号或微信客服；InMemory 后端仅用于单进程开发。

## 本地安装

要求 Python 3.11–3.13；生产镜像使用 Python 3.12 + Alpine 3.24。推荐安装
[uv](https://docs.astral.sh/uv/)：

```bash
uv sync --extra dev --locked
uv run trpc-service --help
uv run trpc-service doctor --output runs/multitenant/sdk-upgrade.json
uv run trpc-service cell-demo --output runs/cell-fabric-demo.json
uv run pytest -q
```

`cell-demo` 完全离线运行，展示签名 Capsule、合规节点调度、高风险工具确认、effect-key 去重、
因果日志回放和候选 Capsule 分支；不需要 IM、模型或数据库凭证。

`pyproject.toml` 接受 `trpc-agent-py[openclaw]>=1.1.17,<1.2`，`uv.lock` 精确锁定
`1.1.19`。升级 SDK 时必须先运行 `doctor` 与 `tests/contracts/test_sdk_compat.py`。

## 最小部署

复制 `.env.example` 为 `.env`，替换所有 `change-me` 值，然后：

```bash
docker compose config --quiet
docker compose up --build -d
docker compose ps
```

Gateway 为 `http://localhost:8080`，Admin 为 `http://localhost:8081`，Prometheus、Jaeger
和 MinIO Console 分别使用 9090、16686、9001。停止服务执行 `docker compose down`；默认不会
删除数据卷。

同一镜像通过 `trpc-service serve --role <role>` 运行 `gateway`、`admin`、`worker`、
`outbox-dispatcher`、`channel-dispatcher`、`post-turn-projector` 或 `wecom-connector`。
`trpc-service migrate` 使用迁移账号执行 Alembic expand-contract。

生产清单位于 `deploy/kustomize`。应用前必须替换示例 OIDC/S3 地址，创建
`trpc-service-secrets`，并用迁移账号单独执行 schema Job。不要把密钥提交到仓库。

## 验证

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy trpc_service
uv run pytest --cov=trpc_service --cov-branch
uv run python scripts/mock_production_gate.py
kubectl kustomize deploy/kustomize/overlays/production >/dev/null
```

默认测试完全离线。真实 IM、性能、故障注入和部署门禁需要显式凭证或本地基础设施；没有完成
这些门禁时只能称为“开发候选”，不能称为生产候选。

## 文档

- [创新架构：Causal Agent Cell Fabric](docs/agent-cell-fabric.md)
- [验收追踪矩阵](docs/acceptance-matrix.md)
- [架构与完整消息时序](docs/architecture.md)
- [数据模型](docs/data-model.md)
- [一致性与多后端](docs/consistency.md)
- [IM 接入](docs/im-channels.md)
- [安全、治理与隐私](docs/security.md)
- [运维、容量和故障恢复](docs/operations.md)
- [数据迁移与回滚](docs/migration.md)
- [测试和发布门禁](docs/testing.md)
- [生产风险清单](docs/risks.md)
