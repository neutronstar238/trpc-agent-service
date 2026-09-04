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

本分支把创新拆成两个可独立验收的轨道：副作用对账只对 `ambiguous` 结果做供应商只读查询并以
CAS 收敛；Proof-Carrying Evolution 以双重确定性 replay、`simulate_only` shadow、多目标 Judge、
签名证书、一次性批准、pointer CAS 和 receipt 回滚形成离线闭环。默认 Worker 保持 legacy 执行权威，
配置默认 `observe`；`shadow` 只构造并校验 native ToolIntent/namespace/effect key，不增加供应商调用。
本轮没有 `cutover`。

完整设计、数据协议和演示验收场景见
[Causal Agent Cell Fabric 架构](docs/agent-cell-fabric.md)。

## 当前能力与边界

- 由已认证 `channel_binding_id` 解析租户，服务端 HMAC 生成 Session ID，外部消息不能声明租户。
- PostgreSQL Inbox/Outbox、幂等键、Session lease 与 fencing token；Redis Streams 只作可重建传输。
- 同一 Session 串行提交、不同 Session 并行；一次 turn 的 event/state/outbound 原子可见。
- 企业微信 AI Bot WebSocket 长连接，以及飞书加密 HTTP 事件回调、URL 校验和 OpenAPI 异步回复。
- OIDC/JWKS、RBAC、ETag 乐观并发、Admin 幂等、审计、DLQ 查询和人工 outbound 重放。
- 工具白名单、SDK Tool Safety、一次性确认令牌、预算预留和非幂等工具歧义状态。
- PostgreSQL/RLS、Redis 单调投影、S3/MinIO staged artifact、pgvector 与外部 Memory 扩展口。
- 隐私优先 OpenTelemetry、Prometheus 指标、Docker Compose 和 Kubernetes/Kustomize。
- `prepare → backfill → shadow-read → dual-write → cutover → verify → cleanup/rollback` 迁移状态机。
- Agent Cell 的 Capsule、确定性调度、因果事件、Intent/Effect 和 Replay 提供离线可验证闭环。真实
  Worker 默认通过 PostgreSQL `CellTurnJournal` 投影实际 SDK Event、治理决策和 legacy effect key；
  Session lease/fencing 阻止旧 Worker 继续写，`post_turn.ready` 事务 Outbox 会修复 commit/effect 投影
  的崩溃窗口。Worker 生成的 Capsule 明确标为 `runtime_projection`，不能授权节点调度；可授权的
  `deployment` Capsule 仍必须由控制面/KMS 签发。Semantic Cell Scheduler、原生 Cell
  `ExactlyOnceEffectExecutor` 和 Quality Judge 尚未进入默认 Worker 热路径，不由 `cell-demo` 冒充完成。
  数据库对在线 Cell append 强制 Session lease proof，对提交后补投影强制 committed-turn proof；独立
  `trpc_cell_executor` 身份及真实供应商凭证当前也未由默认部署 provision。
- Effect reconciliation 只允许 `applied`、`not_applied`、`unknown` 三种证据结果，并将过期 attempt、
  冲突证据和跨租户输入 fail-closed；`cell_effect_reconciliations` 只保存脱敏摘要，不保存原始参数、
  密钥或供应商敏感响应。
- Proof-Carrying Evolution 的发布证书绑定完整精确 CellAddress、Capsule/head、dataset、runner、
  policy、tool manifest、reducer、evidence digest、有效期、expected active Capsule 和 control
  version；v1 不支持 session/app wildcard。

项目不包含管理 UI、Telegram、微信公众号或微信客服；InMemory 后端仅用于单进程开发。

## 本地安装

要求 Python 3.11–3.13；生产镜像使用 Python 3.12 + Alpine 3.24。推荐安装
[uv](https://docs.astral.sh/uv/)：

```bash
uv sync --extra dev --locked
uv run trpc-service --help
uv run trpc-service doctor --output runs/multitenant/sdk-upgrade.json
uv run trpc-service cell-demo --output runs/cell-fabric-demo.json
uv run trpc-service cell-evolve-demo --output runs/cell-evolution-demo.json
uv run python -m scripts.local_innovation_gate --require-core-demo \
  --output runs/multitenant/local-innovation-gate.json
uv run pytest -q
```

`cell-demo` 完全离线运行，展示签名 Capsule、合规节点调度、高风险工具确认、effect-key 去重、
因果日志回放和候选 Capsule 分支；`cell-evolve-demo` 补充双重 replay、
Judge、证书发布和回滚。`local_innovation_gate` 会记录 git SHA、source fingerprint、每项断言，
并始终把生产结论写成 `production_gate=not_run`；这些命令都不需要 IM、模型、供应商或数据库凭证。

若机器没有 `uv`，先用临时 bootstrap venv 安装锁定的 `uv==0.8.13`，再执行
`uv sync --extra dev --locked`；不要依赖全局 Python 环境。PowerShell 示例：

```powershell
py -m venv .cache\uv-bootstrap
.cache\uv-bootstrap\Scripts\python.exe -m pip install uv==0.8.13
.cache\uv-bootstrap\Scripts\uv.exe sync --extra dev --locked
```

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
uv run mypy trpc_service scripts
sh coverage.sh
uv run python -m scripts.local_innovation_gate --require-core-demo \
  --output runs/multitenant/local-innovation-gate.json
uv run python -m scripts.mock_production_gate
kubectl kustomize deploy/kustomize/overlays/production >/dev/null
```

本地覆盖率路径必须执行独立的 line/branch 门禁：`coverage.sh` 使用 `tests/unit` 生成
`runs/multitenant/coverage.json`，随后调用 `scripts.check_coverage` 生成并校验
`coverage-gate.json`；语句覆盖率和分支覆盖率必须分别不低于 90%。只看 pytest 显示的综合百分比
不构成覆盖率门禁通过。若环境不能运行 `sh coverage.sh`，也必须先生成同一份覆盖率 JSON，再显式执行：

```bash
uv run python -m scripts.check_coverage runs/multitenant/coverage.json \
  --output runs/multitenant/coverage-gate.json
```

`coverage.sh` 与 CI 使用相同的 `tests/unit` 范围；生成的 `coverage-gate.json` 还记录测试范围、
UTC 生成时间、可得的 Git SHA 和源码内容指纹，便于审计未提交变更对应的候选版本。

历史流水线如果仍调用 `lint_flake8.sh`，可直接使用仓库根目录的兼容入口；它实际执行锁文件检查、
Ruff 格式/规则检查和 mypy，不会额外引入一套与 CI 不同的 Flake8 规则。当 GitHub Actions 的静态、
单元、模拟、供应链和清单 job 实际通过时，只代表该提交的源码候选可复现；不能从本地结果推断远端
CI 已通过。真实 IM、真实多节点存储、故障注入、迁移、性能和 OTel 运行态必须在显式凭证/基础设施
下单独执行：未执行是 `not_run`，执行但不满足阈值是 `fail`，只有证据报告明确给出
`production_gate=pass` 才能称为生产门禁通过。

默认测试完全离线。真实 IM、性能、故障注入和部署门禁需要显式凭证或本地基础设施；没有完成
这些门禁时只能称为“开发候选”，不能称为生产候选。

验收报告统一区分 `offline/development=pass` 与 `production=not_run`。未来合入 main 时，副作用
对账应先以 `observe` 形式独立合入，Proof-Carrying Evolution 以控制面/离线工具独立合入；只有
独立 Effect Executor、真实 PostgreSQL/RLS、供应商 query-only 对账、KMS 和回滚证据齐全后，才另行
评审 `cutover`。

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
