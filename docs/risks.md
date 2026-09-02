# 生产风险清单（32 项）

| # | 风险 | 缓解与验证 |
|---:|---|---|
| 1 | 请求伪造 tenant_id 越权 | 只信已验签 binding；跨租户负向测试 |
| 2 | RLS 被 owner 或全局 Worker 角色绕过 | `trpc_runtime` 非 owner/NOBYPASSRLS；`trpc_worker` 明确视为 BYPASSRLS 高权限边界，使用独立 Secret、启动证明、显式允许/禁止权限矩阵、tenant-first SQL/完整 namespace 和跨租户直接 SQL 契约 |
| 3 | 同 Session 并发覆盖 state | lease + fencing + 原子 turn commit；四 Worker 故障注入 |
| 4 | Redis 丢数据导致消息丢失 | PostgreSQL Outbox 权威、至少一次补投、队列归零门禁 |
| 5 | IM 重复/乱序 | 平台消息唯一键、Session 接受序、幂等 outbound/tool execution |
| 6 | IM 超时后盲目重发产生重复回复 | ambiguous 状态 + 人工确认 replay |
| 7 | 非幂等工具重复产生外部副作用 | 稳定 execution key；未知结果停止自动重试 |
| 8 | Worker 脑裂提交旧结果 | 单调 fencing token；旧 token commit 必须失败 |
| 9 | 配置灰度过程中漂移 | Inbox 固定 immutable revision；Session HMAC rollout 桶 |
| 10 | Memory/向量投影滞后影响回答 | PG 权威、projection sequence/lag、落后时回退或提示 |
| 11 | Artifact 跨租户路径或残留 | tenant hash prefix、checksum、staging TTL 和孤儿清理 |
| 12 | 日志/trace 泄露消息与密钥 | recursive redaction + PrivacySpanProcessor + canary 扫描 |
| 13 | OIDC 密钥轮换或 JWKS 不可用 | TTL cache、issuer/audience/alg 固定、过期 fail closed |
| 14 | 飞书事件回调被重放或处理超时 | 时间戳/签名/Token/App ID 四重校验，持久接受后立即确认，ack p95 门禁 |
| 15 | 企业微信多副本重复连接 | 每 binding PG advisory lock、断线重连和锁接管测试 |
| 16 | 数据迁移部分成功或无法回滚 | 分阶段 checkpoint/count/checksum、双写观察窗、revision 回滚 |
| 17 | 数据库迁移破坏滚动发布 | Alembic expand-contract、新旧版本兼容测试 |
| 18 | 下游模型/工具雪崩 | timeout、租户 fallback、熔断、预算和并发隔离 |
| 19 | 单租户耗尽共享资源 | tenant 限流/预算、连接池配额、成本和队列 age 告警 |
| 20 | 备份存在但无法恢复 | PG PITR + 对象版本 + 密钥备份，季度按租户恢复演练 |
| 21 | Capsule manifest 在签名后被替换或 key rotation 处理错误 | Registry 只接受 `verify()` 通过的 canonical manifest；digest 与签名分离轮换；外部 KMS 公钥版本化，篡改/未知 key 负向测试 |
| 22 | Capsule 引用只是格式正确但内容不存在 | 发布前对 graph/prompt/tool/knowledge 引用做 registry existence + checksum 检查；运行时缺失时 fail closed，不把非空字符串当作已发布制品 |
| 23 | Causal event hash-chain 与投影状态分叉，或高权限 Worker 写入伪造 hash | 正常 adapter 计算 canonical payload/event hash，读取/回放逐项复核并从 checkpoint 重建；数据库 trigger 约束 lease、sequence、prev_hash，但不宣称抵御已攻陷 Worker，Worker DSN 必须隔离、轮换并对 verifier 失败告警 |
| 24 | Replay/candidate branch 越过 simulate-only 边界污染生产 | branch namespace 与租户一致性校验；candidate 默认拒绝真实 effect，Policy Judge、人工批准和主分支指纹门禁三重保护 |
| 25 | ToolIntent 参数可变导致确认摘要与执行参数不一致 | Intent 入库前 canonicalize + arguments_hash；确认绑定 tenant/principal/cell/tool/hash/expiry；执行前重新计算并拒绝 mismatch，覆盖并发和重放测试 |
| 26 | Worker 的本地 Capsule 签名被误当成部署授权 | schema 区分 `runtime_projection` 与 `deployment`；Worker 只能写前者，placement SQL 只接受后者；deployment 需独立控制面凭证与 KMS trust root |
| 27 | Session 已提交但 Cell terminal event 写入失败，重试造成重复 Agent/Tool | `reply.prepared` 在前、`post_turn.ready` 与 Session 同事务；Projector 仅补齐 effect/turn terminal facts，不重放 Agent，legacy effect key 保持稳定 |
| 28 | 受损 runtime 伪造合成性能租户的清理记录 | 清理函数只接受严格 `perf-*` 身份并拒绝业务租户；当前明确属于 runtime-trusted 验收工具，不作为独立 ownership proof。零信任运维需另配短期 ops role/一次性 capability，不能复用 runtime 凭据 |
| 29 | Semantic Scheduler 重启后 generation 回退，或旧 adapter 在迁移窗口覆盖新节点状态 | `NodeSnapshot` 强制显式持久 source revision，数据库仅接受严格递增值；7 参数入口固定 `0A000` 拒绝写。切换时暂停 scheduler、迁移、部署 8 参数 adapter、验证独立最小权限身份后再恢复 |
| 30 | 粗粒度 `envFrom` 让非制品角色同时看到对象存储凭据 | 当前验收 Secret 投影仅允许已知键，但 Pod 内仍需按角色拆分 artifact Secret，并改为显式 `secretKeyRef`；生产上线前以 Pod 环境权限矩阵证明 gateway/worker/dispatcher 不获得无关凭据 |
| 31 | 验收用 External Metrics APIService 跳过服务端证书校验 | `insecureSkipTLSVerify` 仅限隔离 ACK 验收；生产使用固定服务证书、受信 CA bundle、轮换演练和 APIService 可用性告警，禁止直接复制验收清单 |
| 32 | ACK support 的单副本与节点本地卷被误当成生产持久化 | 当前集群演练只证明功能恢复与故障路径；生产改用跨可用区托管 PostgreSQL/Redis、对象存储版本化、PITR 和季度恢复演练，未完成前 DR 验收保持 not_run |
