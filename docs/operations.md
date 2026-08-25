# 运维、容量与故障恢复

Compose 提供单机验收环境：Gateway、Admin、Worker、两类 Dispatcher、Projector、WeCom
Connector、PostgreSQL/pgvector、Redis、MinIO、OTel Collector、Prometheus、Jaeger 和 Toxiproxy。
Compose 默认启动一个 Worker；多节点/容量验收必须显式使用
`docker compose ... up -d --scale worker=4 --scale outbox-dispatcher=2`，不能依赖
Compose `deploy.replicas`。
Kubernetes base/production overlay 提供 HPA、PDB、NetworkPolicy、探针、非 root、只读文件系统、
滚动升级和优雅停机。生产建议使用托管高可用 PostgreSQL、Redis 与对象存储。

`session-recovery` 是独立的 PostgreSQL mailbox 恢复角色，通过
`trpc-service serve --role session-recovery` 运行 Lease Sweeper、Retry Scheduler 和
Session Reconciler 三个有界循环。它只依赖 PostgreSQL；Compose 只等待 `migrate` 完成，探针
也只检查 PostgreSQL，不要求 Redis readiness 或 Redis Secret。默认每轮每个组件最多处理 25
条记录、每 5 秒轮询，Kubernetes 默认 1 副本、请求 50m CPU/128Mi 内存、上限 250m CPU/256Mi
内存。扩容前应确认 Repository 的行锁/fencing 已实现；多个副本可以并行运行，但默认单副本能
减少无必要的数据库竞争。收到 SIGTERM 时停止新轮次并取消三个循环，终止宽限建议至少 30 秒。

Worker 接收媒体时必须配置 S3-compatible Artifact 后端，否则不会在未持久化原文件的情况下继续处理。
`yqzl` 基线用固定版本 MinIO 容器，仅监听 `127.0.0.1:9000`，数据位于
`/www/wwwroot/tx.nstarzx.cn/data/minio`，凭证位于只读 `secrets/`；容器设置 512 MiB 内存、1 CPU
和 256 PID 上限。小规模图片/PDF 验收时 Worker 常驻约几十 MiB，峰值额外内存主要由当前下载项、
PDF 解析和模型 SDK 决定；每个 Worker 当前顺序消费消息，默认单项 20 MiB 硬上限可避免并发倍增。
更高吞吐应通过增加无状态 Worker 副本扩展，而不是放宽单文件限制。

真实多进程验收使用 `scripts/real_runtime_gate.py`。默认 Compose 应用角色直连依赖；需要
验证网络切断时，必须叠加 `deploy/toxiproxy-runtime.override.yml`，否则切换 Toxiproxy
不会影响 Worker/Dispatcher 的实际连接。该脚本只在显式 opt-in 后执行 `docker kill`，
不会调用 `docker compose down -v`，因此不会删除已保留的数据卷。

| 故障 | 行为 | 告警/恢复 |
|---|---|---|
| Redis 不可用 | PG Outbox 保留；低速 PG 轮询 | queue publish error、outbox age；恢复后补投 |
| PostgreSQL 暂不可用 | 已缓存并验签 binding 的回调连同固定 config revision 进入 AES-GCM Redis 应急流 | consumer group 恢复回灌，PG 成功后才 ACK；若 Redis 也失败返回非 2xx 让 IM 重试 |
| Worker 被杀 | 租约过期后其他节点接管 | lease expiry/conflict；旧 token 不能 commit |
| 模型超时 | 租户 fallback model 或统一降级答复 | model timeout、fallback count |
| 工具失败 | 仅幂等工具退避重试，熔断隔离下游 | tool error/circuit state |
| IM 明确失败 | 限次退避，超过阈值入 DLQ | delivery success/error/DLQ |
| IM 结果未知 | 标记 ambiguous，不自动重发 | 人工审批 replay |
| Projector 落后 | 精确读回退 PG，检索报告 lag | projection age/depth |

配置 revision 不可变。灰度按 Session HMAC 桶选择 candidate 百分比，保证重试稳定；观察错误率、成本、
延迟和业务质量后增加比例。回滚只原子切换 active revision，旧 Worker 继续使用其 Inbox 已固定版本，
新消息立即使用历史稳定版本。数据库变更必须 expand-contract，禁止把 schema 回滚当应用回滚。

容量基线以 100 IM callback/s、200 并发 turn 为首版门槛。压测报告至少记录消息大小、模型 p50/p95、
平均输入/输出 token、工具并发、每 turn event 数、PG/Redis QPS 和 IM 额度。估算：

- Worker 数约为 `峰值 turn/s × p95 turn 秒数 ÷ 每 Worker 安全并发 × 1.3`。
- PG 写 QPS 至少为 callback 事务 + 每 turn commit + outbox/投递/审计更新，并预留 50% 峰值余量。
- Redis Stream 保留量为 `峰值 callback/s × 最长可接受恢复秒数 × 平均消息字节`。
- HPA 同时看 CPU、运行中 turn、队列 age；仅看 CPU 会漏掉外部 API 等待型负载。

发布门禁要求 callback ack p95 <200ms、已接受消息零丢失、错误率 <0.1%、突发结束后队列归零。
PDB 保持关键角色可用，preStop 停止拉新任务并等待当前 turn；终止宽限必须大于 lease 续期间隔和常见
turn p95。备份需要同时验证 PG PITR、对象版本和密钥恢复，季度执行按租户恢复演练。

调度器 `v1` 与 `v2` 的 Redis stream、consumer group 和数据库处理语义不同。相同版本的
代码升级可以使用 Kubernetes RollingUpdate；`v1↔v2` 是协议切换，必须先停入站、排空旧
版本的 PostgreSQL outbox/Redis group 和执行 lease，再在所有相关 Pod 为 0 时切换配置并
按顺序启动新版本。具体 SQL 判据、Redis `XPENDING`/`XINFO` 检查、回滚前的 mailbox 条件
和应急队列处理见 [调度器切换运行手册](scheduler-cutover.md)。禁止以 `DEL`、`XTRIM`、
`XGROUP DESTROY` 或直接改状态字段的方式伪造排空。

## yqzl 服务器发布顺序

在 `/www/wwwroot/tx.nstarzx.cn` 上，发布必须按以下顺序执行：

1. 更新代码并重建 `.venv`，确认 `trpc-service doctor` 与锁文件一致。
2. 由 root 执行 `deploy/yqzl/provision.sh`；生产配置使用
   `deploy/yqzl/runtime.env.example` 复制后的 host-specific 文件，不能使用
   `TRPC_SERVICE_ENVIRONMENT=development` 或 development token。
   同时保留 `TRPC_SERVICE_RUNTIME_STATE_DIR=/tmp/trpc-agent-service`，将
   `TRPC_SERVICE_TENANT_SECRET_ROOT` 指向站点 `secrets/` 目录，并只在确有
   `env://` 租户 Secret 时把对应的 `TRPC_TENANT_*` 名称加入
   `TRPC_SERVICE_TENANT_SECRET_ENV_NAMES`；空列表是 fail-closed 默认值。
   `TRPC_SERVICE_MODEL_ENDPOINT_HOSTS` 必须列出实际批准的 HTTPS 主机，
   `TRPC_SERVICE_FEISHU_ALLOW_STALE_BINDING_CACHE=false` 不得被生产配置覆盖。
   应急队列使用 `TRPC_SERVICE_EMERGENCY_QUEUE_KEY_VERSION` 标识当前密钥；
   轮换期间才填写 `TRPC_SERVICE_EMERGENCY_QUEUE_PREVIOUS_KEY_REFS`，且每个
   引用的旧密钥必须同时存在并在轮换完成后移除。
3. 使用独立 `trpc_migration` 账号执行 `trpc-service migrate --revision head`，确认
   `alembic_version` 为 checkout head；运行角色使用非 owner 的 `trpc_runtime`。
4. 启动 Redis/MinIO，再启动 `gateway`、`admin`、`session-recovery`、`worker`、两个
   dispatcher、projector 和 `wecom-connector` 全部 systemd role。
5. 设置 `TRPC_VERIFY_TENANT_ID` 与 `TRPC_VERIFY_BINDING_ID` 后执行
   `deploy/yqzl/verify_runtime.sh`。该脚本会检查 binding/secret 引用、WeCom connector、
   PostgreSQL/Redis/MinIO 连接、服务重启和日志泄漏；未提供 ID 会 fail-closed，不再使用
   仓库内硬编码租户。

Worker 的 systemd drop-in 将内存上限提升到 2 GiB；其他角色保留 768 MiB 上限。变更
runtime.env 或 secret 后应先执行 verify，再按 role 滚动重启，不能通过重启次数正常来掩盖
配置错误。
