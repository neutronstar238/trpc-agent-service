# 验收追踪矩阵

本表把题目验收项拆成三层：**设计**证明方案覆盖了问题，**离线**证明仓库内的协议/模型/模拟
可以运行，**生产**只接受真实依赖和真实运行态门禁。三层不能互相替代；特别是离线通过不等于
企业微信、数据库或 Kubernetes 已经通过。

本轮创新另外拆成两个闭环：副作用对账只查询供应商状态并安全收敛，Proof-Carrying Evolution 只在
隔离候选分支中 replay、评测和签发证书。默认 Worker 仍是 legacy 权威，`observe` 为默认，`shadow`
不增加供应商调用，`cutover` 不在本轮验收范围内。

| # | 题目验收要求 | 设计层证据 | 离线层证据 | 生产层证据/当前结论 |
|---:|---|---|---|---|
| 1 | 多租户、节点部署、同步、多后端、IM、治理监控、故障恢复 | `architecture.md`、`consistency.md`、`im-channels.md`、`operations.md`、`security.md`；总图明确 Gateway/Worker/Channel Adapter/Storage Adapter/Admin API/Telemetry Collector | 单元测试、`cell-demo`、Compose/Kustomize 静态渲染与模拟门禁 | 真实多节点、数据库、IM、故障和观测门禁；当前仓库证据为 `not_run` |
| 2 | tenant、agent、binding、session、event、memory、summary、audit 关系 | `data-model.md` 的 ER 图与字段说明；`0001`—`0028` 迁移（当前唯一 head 为 `0028_evolution_least_privilege`） | 迁移契约/RLS 单元测试、离线 schema 检查 | 本机 kind 可执行真实 PostgreSQL/RLS/迁移预验收；ACK/生产仍为 `not_run` |
| 3 | 至少两类 IM，且含微信/企业微信 | `im-channels.md` 对比企业微信 AI Bot WebSocket 与飞书加密 HTTP callback | `channels/wecom.py`、`channels/feishu.py` 及 Fake/协议测试 | 真实账号、回调、发送、重试和限流证据；当前为 `not_run` |
| 4 | 至少三类后端及同步策略 | `consistency.md`、`migration.md`：PostgreSQL、Redis、pgvector/外部向量、S3/MinIO、外部 Memory | 适配器契约、迁移状态机和模拟测试 | 真实 PG/Redis/S3/向量迁移与恢复报告；当前为 `not_run` |
| 5 | 完整消息链与 trace/request 贯穿 | `architecture.md`、`agent-cell-fabric.md` 时序图和 ID 语义 | 离线事件链、`cell-demo`、`SessionReady v2` W3C `trace_headers` 编解码/提取及 fake `queue.consume` span 契约测试 | 真实 OTel 父子 span 串联 IM→Runner→Tool→存储→回复；当前为 `not_run` |
| 6 | 至少八项生产风险 | `risks.md` 统一列出 32 项，包含 Cell/Capsule/Replay/Effect 风险 | 风险对应的负向/模拟门禁 | 真实故障注入、供应链、安全和恢复证据；当前为 `not_run` |
| 7 | 明确 SDK 复用与平台新增边界 | `agent-cell-fabric.md` §9.1、`requirements.md` | SDK 兼容契约、锁文件与离线测试 | 发布候选仍需锁定 SDK、镜像和外部门禁；当前为 `not_run` |
| 8 | 不明确副作用的查询与对账 | `agent-cell-fabric.md` §7.1：三态结果、attempt CAS、不可变脱敏证据 | InMemory 对账协调器、重复/并发、stale attempt、冲突证据和跨租户拒绝测试；`cell-demo` 展示供应商执行次数为一次；kind 可执行真实 PG authority/CAS 与假供应商 response-loss 查询 | 真实供应商状态查询和 ACK 恢复报告；当前为 `production=not_run` |
| 9 | 可证明的候选演进与安全发布 | `agent-cell-fabric.md` §8.3：状态机、Judge、证书绑定、approval/CAS/outbox/rollback | `cell-evolve-demo`、双重 replay、零真实副作用、稳定 Merkle root、篡改/过期/跨租户/stale CAS 拒绝；kind 可执行真实 PG pointer/one-time use/outbox/rollback | 真实模型/工具/KMS、ACK 控制面和生产发布恢复；当前为 `production=not_run` |

## 当前状态的判定规则

- **设计完成**：文档能定位组件职责、数据关系、约束、失败边界和实现边界，不表示代码已在生产
  部署。
- **离线通过**：单元/契约/模拟命令在无外部凭证时通过。`cell-demo` 只证明 Capsule、调度、因果
  事件、Intent/Effect 和分支协议的本地闭环。
- **生产通过**：必须有同一候选镜像 digest、release binding、真实依赖和报告中的
  `production_gate=pass`。未显式 opt-in、缺凭证或当前环境无法连接时，正确状态是 `not_run`。

截至本版本，设计与离线验收路径已入库；离线命令的实际结果以当前环境输出为准，本地仓库没有可据此
宣称真实生产通过的外部运行报告。`scripts/local_innovation_gate.py` 会记录 git SHA、source
fingerprint、每项 case result、拒绝原因和 `offline/development`、`production` 两套结论。真实门禁命令和所需环境见 [`testing.md`](testing.md)、[`real-runtime.md`](real-runtime.md) 与
[`operations.md`](operations.md)。

## 创新架构的可证伪离线验收

| 创新主张 | 失败条件 | 离线证据 | 生产边界 |
|---|---|---|---|
| Capsule 是可验证的部署单元 | manifest 被修改后仍通过 digest/签名校验，或 Worker 证据可授权 placement | Capsule digest、Ed25519、篡改、未知 key、`runtime_projection` 拒绝调度契约 | 外部 KMS/信任根和独立 deployment 登记凭证未接入，当前 `not_run` |
| Cell 调度满足合规约束 | 非法地域、缺能力或超容量节点胜出 | scheduler hard-constraint、解释性评分、tie 与 PG reservation SQL/adapter 契约 | 默认 Worker 尚未由 Semantic Scheduler 接管；真实共享节点与故障证据 `not_run` |
| 事件日志可验证回放 | payload、顺序或 hash 被修改后仍通过 | hash-chain、branch、determinism、PG branch-head CAS/namespace adapter 契约 | PostgreSQL adapter 已实现，但真实多节点写入与投影重建报告 `not_run` |
| 工具副作用受 effect key 保护 | 相同 key 造成两次外部调用 | 原生 Cell Effect ledger 并发测试；默认 Worker 将 legacy fenced execution key 投影到 Cell 事件 | 原生 Cell executor 尚未替换默认 ToolExecutor；真实非幂等供应商 ambiguous 对账 `not_run` |
| 反事实分支不污染生产 | candidate branch 提交真实 effect 或改变 main | branch namespace、simulate-only、主分支指纹测试 | 生产还需 Judge、灰度批准和发布回滚证据 |
| ambiguous 结果可安全收敛 | 对账器重复调用副作用接口、接受 stale/冲突/跨租户证据，或 unknown 触发自动重试 | `applied`/`not_applied`/`unknown` 映射、证据摘要和 ledger CAS 负向测试；kind probe 使用真实 PG 与假供应商只读查询 | 真实供应商 query-only API 与 ACK 网络故障 `not_run` |
| 演进证书能携带证明 | replay 不确定、样本缺失、高危安全、无严格改善或证书可越权发布 | 双重 reducer hash、零 provider call、Judge 硬门禁/Pareto、canonical Ed25519 certificate、Promotion receipt；kind probe 使用真实 PG authority/CAS/outbox | 真实模型质量、KMS 信任根和 ACK 跨节点恢复 `not_run` |

## 建议评审命令

```bash
uv sync --extra dev --locked
uv run trpc-service cell-demo --output runs/cell-fabric-demo.json
uv run python -m scripts.local_innovation_gate --require-core-demo \
  --output runs/multitenant/local-innovation-gate.json
uv run pytest -q
sh coverage.sh
uv run ruff format --check .
uv run ruff check .
uv run mypy trpc_service scripts
uv run python -m scripts.mock_production_gate
docker compose config --quiet
kubectl kustomize deploy/kustomize/overlays/production >/dev/null
```

需要真实 PostgreSQL、Redis、S3、向量库或 IM 凭证的测试保持显式 opt-in；没有外部依赖时跳过并
记录 `not_run` 原因，不能把模拟结果标成生产验收。GitHub Actions 的通过范围与生产候选的额外
门禁见 [`requirements.md`](requirements.md)。

## 双轨能力的基线合入策略

| 能力 | 基线合入建议 | 分块顺序 | 未满足条件时 |
|---|---|---|---|
| Effect reconciliation | 合入 `observe` 与 query-only reconciler | 先内存/CAS，再 PG/RLS/authority，再真实供应商门禁 | 保持 legacy executor 权威，禁止 `cutover` |
| Proof-Carrying Evolution | 合入独立控制面/离线工具 | 先 branch/replay/Judge，再 certificate/approval，再 pointer/outbox/rollback | 候选只可离线证明，不改变 active pointer |
| Native `cutover` | 暂不合入 | 独立 Effect Executor、真实 PG、供应商与回滚证据另行评审 | 明确 `production=not_run` |

## ACK 验收边界

- Kubernetes HPA driver 必须绑定专用 subject
  `system:serviceaccount:trpc-runtime-driver:hpa-driver`；节点硬故障演练必须显式确认
  `I_UNDERSTAND_HARD_NODE_FAILURE_PDB_BYPASS`。
- ACK 镜像链路是 DockerHub push → 轩辕 pull-through；support/MinIO YAML 必须由 renderer 根据当前
  `deploy/runtime-gate.yaml` 生成，不能把仓库模板直接当作部署清单。
- support adapter 的 `APIService.spec.insecureSkipTLSVerify: true` 仅用于隔离验收，不是生产 TLS
  配置；当前没有真实企业微信/飞书账号，在线 IM 及完整生产运行态证据保持 `not_run`。
- 功能灾备使用单副本/`emptyDir`，只能证明恢复代码路径，不证明生产持久性、跨区冗余或 RPO/RTO。
