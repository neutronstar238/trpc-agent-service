# 验收追踪矩阵

本表把题目验收项映射到可定位的设计、代码和自动化证据。评审可先执行
`trpc-service cell-demo`，再按表抽查；任何一项都不只依赖架构口号。

| # | 验收要求 | 设计证据 | 实现与验证证据 | 状态 |
|---|---|---|---|---|
| 1 | 多租户、节点部署、同步、多后端、IM、治理监控、故障恢复 | `architecture.md`、`consistency.md`、`im-channels.md`、`operations.md`、`security.md` | tenant-scoped Repository、Mailbox v2、Channel Dispatcher、Telemetry、Compose/Kustomize | 完成 |
| 2 | tenant、agent、binding、session、event、memory、summary、audit 关系 | `data-model.md` 及 ER 图 | `0001`—`0017` Alembic 迁移、RLS 契约测试 | 完成 |
| 3 | 至少两类 IM，且含微信/企业微信 | `im-channels.md` 对比企业微信 AI Bot WebSocket 与飞书加密 HTTP callback | `channels/wecom.py`、`channels/feishu.py` 及通道测试 | 完成 |
| 4 | 至少三类后端及同步策略 | `consistency.md`、`migration.md` | PostgreSQL 事实源、Redis 唤醒/投影、pgvector、S3/MinIO、外部 Memory 接口 | 完成 |
| 5 | 完整消息链与 trace/request 贯穿 | `architecture.md` 与 `agent-cell-fabric.md` 时序图 | Gateway → Mailbox → Worker → Runner → Intent/Effect → Outbox 全链字段 | 完成 |
| 6 | 至少八项生产风险 | `risks.md` | 16 项风险、缓解措施与对应门禁 | 完成 |
| 7 | 明确 SDK 复用与平台新增边界 | `agent-cell-fabric.md` 9.1 节 | SDK Runner/Session/Memory/Tool 接口与 Cell Fabric 分层 | 完成 |

## 创新架构的可证伪验收

| 创新主张 | 失败条件 | 自动化证据 |
|---|---|---|
| Capsule 是不可变且可信的部署单元 | 内容被修改后仍验签成功 | digest、Ed25519、篡改与未知 key 测试 |
| Cell 调度满足合规约束 | 非法地域或缺少能力的节点胜出 | scheduler hard-constraint 与解释性评分测试 |
| 事件日志可验证回放 | payload、顺序或 hash 被修改后仍通过 | hash-chain、branch、determinism 测试 |
| 工具副作用精确一次 | 相同 effect key 导致两次外部调用 | 并发与重复执行测试，演示计数必须等于 1 |
| 反事实分支不污染生产 | candidate branch 能提交真实 effect 或改变 main | branch namespace、simulate-only 门禁、主分支指纹测试 |

## 建议评审命令

```bash
uv sync --extra dev --locked
uv run trpc-service cell-demo
uv run pytest -q
uv run ruff format --check trpc_service tests scripts migrations
uv run ruff check trpc_service tests scripts migrations
uv run mypy trpc_service
docker compose config --quiet
kubectl kustomize deploy/kustomize/overlays/production >/dev/null
```

需要真实 PostgreSQL、Redis、S3、向量库或 IM 凭证的测试保持显式 opt-in；没有外部依赖时跳过，不能把
模拟结果标成生产验收。离线 `cell-demo` 只证明创新协议闭环，不替代真实通道和故障注入门禁。
