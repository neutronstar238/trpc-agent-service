# 一致性与多后端

*本文定义 Mailbox v2 的权威数据、SessionReady 唤醒、租约 fencing 和重放语义。*

Agent Cell Fabric 不改变这些正确性边界：Mailbox 仍决定哪个 Worker 可以执行；Cell Causal Log 记录
该执行产生了什么。默认 Worker 在 Session commit 前用同一 Session owner/epoch 对 Cell append 做独立
fence，数据库 trigger 再校验这份 lease proof；Session/event/outbound 仍由原有单一事务权威提交。
Cell 投影不是跨表“伪原子事务”：提交事务同时产生 `post_turn.ready` Outbox，Projector 只有在
`session_turns=committed` 且同一 stream 已有 `reply.prepared` 的 committed-turn proof 下才能补齐缺失的
effect/turn commit 事实，既不重放 Agent，也不会把投影失败误判成业务未提交。候选 branch 只能追加到
自己的 `branch_id`，不能取得生产副作用权限。
当前真实 Tool 热路径仍由原有 fenced `PostgresExecutionLedger` 保护，稳定 execution key 被映射为 Cell
`effect_key`；原生 `cell_effect_ledger`/`ExactlyOnceEffectExecutor` 已实现但尚未替换默认 ToolExecutor。

`0018_cell_namespace_and_reservations` 将 Cell 的并发边界收紧为完整地址
`(tenant_id, app_id, cell_id, session_id, capsule_digest, branch_id)`。`cell_branch_heads` 是每个 branch
的 sequence/hash/lease CAS 头，`cell_node_capacity` 与 `cell_placement_reservations` 在数据库事务内
预留 CPU、内存和 Cell 槽位；Scheduler 的本地评分不是最终容量权威。reservation 对普通租户启用 RLS
但不 `FORCE`，仅允许表 owner 的受控调度函数跨租户回收过期行并修正全局容量计数。这样两个 Gateway
即使读取到同一个旧节点快照，也只能有一个 reservation 成功，失败者必须重新放置。

`0019_cell_branch_head_lock` 将 branch-head 的 `FOR UPDATE` 收敛到 tenant-bound
`SECURITY DEFINER` 函数；Worker 只获得该函数的 `EXECUTE`，仍没有表级 `UPDATE`。`0020/0021` 不改变
正常 Session/Cell 的一致性模型：它只允许 `trpc_runtime` 在 checksum、合成租户记录及租约条件成立时，
事务性清理本次性能 fixture。未过期 active reservation 会阻止清理；过期 active 行先转为 expired，
已释放/过期行删除后再从所有剩余 active reservation 重算节点计数，并返回逐表删除计数。

`0022_cell_node_snapshot_generation` 把 producer-owned `observed_generation` 与数据库本地 fence 分开。
该值没有默认值，必须来自 Kubernetes resource version、持久 leader epoch/counter 等跨进程重启仍单调的
控制面来源，不能使用进程内自增计数。节点行只接受严格更大的 observation；重复或迟到的遥测是成功
no-op，只返回当前数据库 generation，因此不能把旧容量、健康或 draining 状态写回新快照之上。
旧 7 参数 SQL 签名在滚动窗口内保留，但固定以 SQLSTATE `0A000` fail-closed，不具备写能力；升级必须
先暂停 Semantic Scheduler 的快照写入，执行迁移并部署 8 参数 adapter 后再恢复。当前默认部署没有
Semantic Scheduler 进程，因此该生产切换证据保持 `not_run`。

---

## 🧭 权威来源与一致性等级

正确性判断只依赖 PostgreSQL。Redis、InMemory 和各类投影都可以丢失或重建，但不能反过来
决定 Session 是否可执行、谁拥有执行权或某个 turn 是否已经提交。

| 数据或动作 | 唯一权威 | 一致性 | 读写规则 |
|---|---|---|---|
| 入站消息和外部幂等 | PostgreSQL `inbound_messages` | 强一致事务 | `(tenant_id, channel, account_id, external_message_id)` 去重 |
| Session 待处理顺序 | PostgreSQL `session_mailboxes` | 单 Session 串行 | `accepted_sequence > resolved_sequence` 表示仍有工作 |
| Session 业务快照 | PostgreSQL `sessions` | fenced commit | mailbox lease 成功后读取；与 mailbox 按固定锁顺序更新 |
| 事件、turn 和最终状态 | PostgreSQL | 强一致、连续 sequence | 运行时事实只接受当前 lease proof；提交后 terminal 投影只接受 committed-turn proof |
| SessionReady outbox | PostgreSQL `outbox_events` | 事务内持久 | 先提交，再由 relay 至少一次发布 |
| SessionReady Stream | Redis `trpc:session-ready:v2` | 至少一次、可重复 | 只作唤醒；不保存 inbound 正文或业务锁 |
| Redis PEL | Redis consumer group | 短交接窗口 | 只由 Reclaimer 恢复 Claim/ACK 未完成的通知 |
| 长任务恢复 | PostgreSQL Lease Sweeper | 强一致接管 | 只扫描过期 `RUNNING` mailbox，并递增 fencing epoch |
| 到期重试 | PostgreSQL Retry Scheduler | 强一致状态转移 | `RETRY_WAIT → QUEUED` 时生成新 generation |
| 丢通知修复 | PostgreSQL Reconciler | 强一致修复 | stale `QUEUED` 复用原 generation；不接管普通过期 `RUNNING` |
| Memory / Summary / Knowledge | PostgreSQL 事实记录 + 投影 | 事实强一致、向量最终一致 | 投影落后回退 PostgreSQL；禁止 sequence 倒退 |
| Artifact bytes | S3/MinIO | 元数据提交后可见 | staging、checksum、提交元数据、孤儿清理 |
| InMemory adapter | 当前进程 | 单节点开发/测试 | 不作为多节点生产权威 |

表中 Memory/Knowledge/Artifact 是内置 PostgreSQL profile 的一致性语义；Redis、InMemory、远端向量库
或外部 Memory 作为替代后端时，需要通过 `ProfileServiceFactory` 注入预注册适配器。仓库未把所有组合
实现或验证为生产后端，真实迁移/恢复证据在验收矩阵中保持 `not_run`。

`sessions` 中的 lease 字段是与旧运行时和业务快照配套的镜像；Mailbox v2 的调度判断以
`session_mailboxes` 为准。清理两处 lease 时必须同时匹配旧的 `lease_owner` 和
`lease_epoch`，不能用 tenant/session 单独清空新 Worker 的 lease。

## 🔐 Mailbox 状态不变量

所有状态转移都在 tenant-scoped PostgreSQL 事务中锁定 mailbox 行；Gateway 接收新消息、
Worker Claim、fenced commit、Sweeper、Retry Scheduler 和 Reconciler 使用同一锁顺序。

```text
session_mailboxes
→ sessions
→ session_turns
→ session_mailbox_items
→ inbound_messages
→ session_events / outbound_messages / outbox_events
```

```text
resolved_sequence <= accepted_sequence
RUNNING  => processing_sequence = resolved_sequence + 1
RUNNING  => processing_inbound_id、lease_owner、lease_expires_at 均非空
非 RUNNING => processing_sequence、processing_inbound_id、lease_owner、lease_expires_at 均为空
有效执行权 => lease_owner + lease_epoch + 未过期 PostgreSQL lease
```

因此：

- `IDLE` 不得拥有未解决 inbound；若 `accepted_sequence > resolved_sequence`，Reconciler 必须重新使其 `QUEUED`。
- `QUEUED` 表示 PostgreSQL 中确实有可执行工作，并且存在或可以重建对应 SessionReady outbox。
- `RETRY_WAIT` 不占用 Agent permit；只有 Scheduler 到期后才转 `QUEUED`。
- `RUNNING` 的失效只能由 Lease Sweeper 或允许直接接管的 Claim 路径处理，Reconciler 不与其竞争。
- 旧 Worker 即使恢复，也只能用原 epoch 访问；epoch 已变化时 renew、commit、retry 和 fail 都必须失败。

## 🔁 SessionReady 的 Claim/ACK 顺序

```mermaid
sequenceDiagram
    accTitle: SessionReady consistency boundary
    accDescr: Redis delivers a hint, PostgreSQL authenticates and claims the mailbox, and Redis is acknowledged only after the short claim transaction succeeds.

    participant redis as Redis Stream
    participant worker as Worker coordinator
    participant pg as PostgreSQL mailbox
    participant agent as Agent turn

    worker->>worker: reserve permit
    redis->>worker: XREADGROUP new or Reclaimer delivery
    worker->>pg: validate event_id + generation
    worker->>pg: SELECT mailbox FOR UPDATE; claim once
    alt claimed
        pg-->>worker: RUNNING + lease_epoch
        worker->>redis: bounded XACK
        worker->>agent: execute one turn
        agent->>pg: fenced commit
    else stale / running / empty
        pg-->>worker: no executable claim
        worker->>redis: bounded XACK
        worker->>worker: release permit; no sleep/reacquire loop
    else database error
        pg-->>worker: error
        worker->>worker: leave delivery pending
    end
```

生产 PostgreSQL Claim 必须同时验证：

1. `event_id` 是该租户、该 Session 的 `session.ready.v2` outbox ID；
2. outbox payload 的 `generation` 与通知一致；
3. mailbox 当前 generation 与通知一致；
4. mailbox 有未解决的下一条 inbound，且没有其他未过期 lease。

Claim 失败但数据库可用时，通知是 stale、already running 或 empty，应 ACK 并释放 permit。
Claim 事务异常时不能 ACK，交给独立 Reclaimer 继续处理。Claim 成功后 ACK 采用有界超时；
ACK 失败不会回滚 PG lease，后续重复通知会被 PG 状态安全去重。

## 🏷️ Generation 与重放语义

`queue_generation` 是可执行唤醒的版本号，不是 Redis fencing token，也不是模型尝试次数。

| 场景 | generation | outbox 行为 | 目的 |
|---|---:|---|---|
| `IDLE → QUEUED` 新工作 | 加一 | 写新 `session.ready.v2` | 新的可执行状态 |
| `RETRY_WAIT` 到期 | 加一 | 写新 `session.ready.v2` | 新的调度机会 |
| 一个 turn 完成后仍有 backlog | 加一 | 写新 `session.ready.v2` | 让出执行权并重新排队 |
| 长期 `QUEUED`，Redis 丢通知 | 不变 | 重开/补回同 generation | 恢复唤醒，不制造 generation 风暴 |
| 已发布事件未被消费 | 不变 | 仅在没有活动 claim 时重新可用 | 不抢占正在交接的事件 |
| Redis 重复投递同一事件 | 不变 | 不新增业务 turn | PG Claim 负责去重 |

PostgreSQL 使用 `(event_type, tenant_id, aggregate_id, generation)` 唯一约束保护
`session.ready.v2`；`ON CONFLICT DO NOTHING` 使 relay、Reconciler 和重复重启安全。InMemory
契约实现必须保持同样的可观察语义：旧状态为 `QUEUED` 时复用 generation，只有从
`RETRY_WAIT` 或 `IDLE` 转为 `QUEUED` 时才生成新 generation。

## ♻️ 四类恢复职责

| 组件 | 扫描/处理范围 | 不得做的事 |
|---|---|---|
| Redis Notification Reclaimer | `XAUTOCLAIM` 发现的 stale PEL SessionReady | 不执行模型、不把 PEL 当业务 lease、不在主消费循环中隐式恢复 |
| PostgreSQL Lease Sweeper | `status='RUNNING' AND lease_expires_at <= clock_timestamp()` | 不处理 Redis 普通通知、不清理新 owner |
| Retry Scheduler | `RETRY_WAIT AND retry_at <= clock_timestamp()` | 不在 Worker permit 内 sleep |
| PostgreSQL Reconciler | 非 RUNNING 异常、committed self-heal、长期 QUEUED 和丢通知 | 不扫描/接管普通过期 RUNNING |

Reclaimer 保存 `XAUTOCLAIM` cursor，并且只覆盖尚未完成 PostgreSQL Claim/ACK 的短窗口。
Redis PEL 不需要在模型执行期间 heartbeat；Agent 长任务只续 PostgreSQL lease。Recovery service
可以多实例运行，行锁和 fencing 负责竞争安全。

## 🧯 故障与可见性矩阵

| 故障 | 可接受结果 | 最终收敛路径 |
|---|---|---|
| Gateway 在 PG commit 前宕机 | IM 重试或返回非 2xx | Inbox 幂等键保证一次接受 |
| XADD 成功、outbox published 更新前宕机 | Redis 出现重复 SessionReady | 同 generation + PG Claim 去重 |
| XREADGROUP 后、PG Claim 前宕机 | 通知留在 PEL | Redis Reclaimer 接管 |
| PG Claim 成功、XACK 前宕机 | 重复通知可能再次到达 | 看到 `RUNNING` 后 ACK，不重复执行 |
| XACK 后、Agent 执行中宕机 | PG lease 过期 | Lease Sweeper 递增 epoch、重新 QUEUED |
| Redis Stream 或 group 全丢 | 唤醒暂时消失 | outbox relay / Reconciler 从 PG 重建 |
| 模型或幂等工具暂时失败 | mailbox 进入 `RETRY_WAIT` | Scheduler 到期生成新 generation |
| 非幂等工具结果未知 | 不自动重放副作用 | effect ledger、对账或人工确认 |

任何故障下都允许重复通知，但不允许两个有效 PG lease，也不允许旧 epoch 提交可见状态。
模型和工具调用期间不得持有数据库事务；最终事件、Session state、outbound 和后续 outbox
必须在当前 lease 的一个 fenced commit 中完成。

## 🧪 契约验证

离线契约至少覆盖：不同租户相同 session 标识的隔离、重复/乱序 SessionReady、Claim 后
ACK 失败、旧 epoch 提交、Lease Sweeper 接管、Retry Scheduler 新 generation、Reconciler
同 generation 重放、Redis 全丢后的 PG 重建，以及不同 Session 并行。生产门禁还应分别记录
Redis PEL 短窗口延迟、PG lease 年龄、queued age、retry wait 数量和 stale epoch 拒绝数。
