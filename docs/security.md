# 安全、治理与遥测隐私

Admin 生产认证固定 OIDC issuer、audience 与算法白名单，从 JWKS 校验 JWT；角色为
`platform_admin`、`tenant_admin`、`auditor`。生产设置拒绝开发 token、literal SecretRef 和内容 trace。
tenant admin 只能操作 token 中授权的 tenant。所有控制面写操作要求 Idempotency-Key，除创建租户外
还要求 If-Match，避免重放和丢失更新。

数据隔离由 API tenant scope、tenant-first Repository、PostgreSQL RLS、Redis key tenant namespace、
S3 tenant hash prefix 和向量 tenant 条件共同执行。`trpc_runtime` 是非 owner、`NOBYPASSRLS` 的租户
运行账号；跨租户队列协调器使用独立的 `trpc_worker`，它因全局 Claim/恢复职责显式具有
`BYPASSRLS`，因此不能把 RLS 当作该角色的隔离边界。Worker 的边界由专用 Secret、角色启动证明、
tenant-first SQL、完整 Cell namespace、Session lease fencing、显式权限/禁止权限矩阵和跨租户负向契约共同
构成。Worker 只有 Cell/head 的 `SELECT/INSERT`，没有直接 `UPDATE`；event trigger 对在线 append 强制
校验 Session 与 branch 的 owner/epoch/expiry（expiry 由数据库 `clock_timestamp()` 判断），对提交后
terminal 投影强制校验 committed turn 与同 stream 的 `reply.prepared`。新建或 fork 的 branch head
以 `NULL/0/NULL` 作为明确初始化状态；只有锁定的当前 Session proof 才能初始化/续租其 branch mirror，
因此续租和 epoch 接管不依赖可选的 Python check。绑定解析与全局恢复函数使用 `SECURITY DEFINER` 时
固定 `search_path = pg_catalog, public, pg_temp`（`pg_temp` 最后）、限制返回列并显式授权；业务
Gateway/Admin 不得持有 Worker DSN。

`cell_placement_reservations` 启用 RLS 但不 `FORCE`，这是为表 owner 的受控调度函数跨租户清理过期
reservation、维护全局 node counters 保留的窄例外；普通 runtime 仍受 tenant policy，Worker 无该表
直接权限。原生 Intent/Effect 表只在独立 `trpc_cell_executor` 已 provision 时授予最小权限；迁移在
授权前撤销 Cell 表直授，并拒绝 `SUPERUSER`/`BYPASSRLS`/`INHERIT`/非 `LOGIN` 或任何 role membership。
当前部署
脚本未创建该角色，也未配置真实供应商凭证，因此默认 Worker 不获得这些 DML，原生执行面保持
`not_run`。

Capsule 分成两种数据库信任等级：控制面/KMS 验签后登记的 `deployment` 才能授权 placement；Worker
只能调用受控入口写入 `runtime_projection` 执行证据，后者即使带本地签名也不能被 Scheduler 接纳。
数据库函数只校验 envelope/namespace 等结构不变量，不替代 Ed25519 信任根校验；PostgreSQL adapter
对 `deployment` 强制要求 `trusted_keys` 并在调用特权 SQL 前验签。生产控制面还必须使用未授予
`trpc_runtime`/`trpc_worker` 的独立登记凭证。当前仓库未提供外部 KMS、生产信任根及该独立凭证，因此
生产门禁保持 `not_run`。

提交后的 `tool.effect.*` 是受 committed-turn proof 保护的非权威投影；该 trigger 不把任意投影
payload 重新绑定为 `cell_tool_intents`/`cell_effect_ledger` 的外部执行凭据。默认 Worker 是受信的
投影边界，在线外部副作用仍以既有 `tool_executions` 为权威；只有独立 provision 的 executor 才能
写入原生 effect ledger，并由其 owner/attempt/数据库时钟 fencing。

`0018` 将 `0017` 遗留 Capsule 全部回填为 `runtime_projection`，随后移除列默认值；未经过新控制面
信任根重新登记的历史记录不会因升级自动获得 deployment 权限。迁移同时撤销 bootstrap 留给新表的
默认 DML，并由启动/探针同时校验 Cell 必需权限与禁止权限。

`0019` 通过 migration-owned、tenant-bound 的 `lock_cell_branch_head` 函数提供最小行锁能力，且只向
`trpc_worker` 授予 `EXECUTE`。`0020/0021` 的 `cleanup_performance_cell_fixture` 只向 `trpc_runtime` 开放，
固定安全 `search_path` 与 `row_security=on`，并校验合成租户格式、run/checksum、审计记录和 reservation
状态；Worker、executor、scheduler、metrics 与 `PUBLIC` 均无执行权。普通 UPDATE/DELETE 仍由
append-only trigger 拒绝，只有该函数事务内绑定的精确 fixture tenant 可以删除 Cell event。

这条清理边界明确依赖“`trpc_runtime` 是受信平台身份”的威胁模型：runtime 本身具有 tenant/audit 写入
能力，因此审计匹配不是抵御已攻陷 runtime 凭据的独立 ownership proof。它只用于合成 `perf-*` 验收
租户，不能用于业务租户删除；若要把清理纳入零信任运维，必须再 provision 独立短期 ops role 或不可
伪造的一次性 capability。类似地，正常 Worker adapter 计算 event hash，读取/回放会全量复核，但数据库
trigger 只校验 lease、sequence 和 `prev_hash`，不会重新实现 Python canonical hash；Worker DSN 泄露属于
高权限边界失陷，需靠 Secret 隔离/轮换、运行时加固和 verifier 告警处置。

`update_cell_node_snapshot` 只在外部控制面已 provision 独立 `trpc_scheduler` 身份时条件授权；该身份应为
`LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS`，仅有数据库 `CONNECT`、schema
`USAGE` 和指定函数 `EXECUTE`，不得拥有表 DML。仓库默认 Compose/Kubernetes 没有 Semantic Scheduler
进程，也不会创建孤儿 Secret 或复用 migration/runtime 凭据；因此节点快照生产门禁明确为 `not_run`。

审计参数在进入决策前先脱敏；治理顺序固定为身份/租户授权 → 工具白名单 → SDK Tool Safety →
危险操作确认 → 预算预留 → 执行。
确认令牌绑定 tenant、principal、Session、tool、参数摘要和过期时间，账本确保一次性消费。工具声明
`idempotent`、`non_idempotent` 或 `unknown`：只有幂等操作可自动重试；非幂等调用在结果未知时进入
人工状态，防止重复付款、发信或变更外部系统。

配置仅保存 `SecretRef`。Compose 用 Docker secrets，Kubernetes 用 Secret/ExternalSecret；可扩展
Vault/KMS Provider。JSON logger 递归脱敏 token、password、authorization、cookie、API key 和连接串。
异常响应使用固定错误码，不返回内部 SQL、路径或第三方响应正文。

tRPC-Agent 1.1.19 会把 Runner/Tool/LLM 内容写入 span，本项目在 exporter 前使用
`PrivacySpanProcessor` 删除 input/output/state、tool arguments/result 和 LLM request/response。正文采集
只允许显式开发模式，生产模型校验会拒绝它。`audit_logs` schema 支持 tenant、channel、principal、
session、agent、tool、decision、latency、error_type、cost、trace_id、config/policy version、
idempotency key 和是否脱敏；默认治理/入站/出站写入器目前只填充各自可得的字段，完整字段补齐属于
生产门禁，且任何路径都不保留原始消息。Cell Journal 对输入参数摘要、结果摘要、配置引用和错误类型使用部署级 HMAC 再摘要，
避免低熵枚举值可由裸 SHA-256 字典反推；HMAC key 也只能以 SecretRef 注入。

建议在 CI 和镜像发布执行锁文件检查、pip-audit、Trivy、SBOM、secret scan；运行时使用非 root、只读
根文件系统、drop ALL capabilities、NetworkPolicy 和默认拒绝 egress，仅放行 DNS、OIDC、托管后端及
明确的模型/工具/IM endpoint。

截至 2026-08-21 的复扫中，`cryptography` 已提升到 50.x 安全基线。`openclaw` extra 需要
`nanobot-ai`；其 0.3.0 元数据仍限制旧版 Dulwich/PyPDF，而这些版本命中可修复高危漏洞。本服务不调用
nanobot 私有 API，因此在 `tool.uv.override-dependencies` 中把两者提升到已修复版本，并用 SDK 契约和
nanobot 导入测试守住兼容性；上游放宽约束后应删除 override。生产部署必须从 `uv.lock` 构建，不能
脱离锁文件单独用 pip 解析该 extra。运行镜像采用 Python 3.12 Alpine 3.24。Docker Scout 对最终镜像的
CRITICAL/HIGH 扫描和 pip-audit 均必须为零；任一依赖变化都要重新执行 SDK 契约、完整回归和镜像
漏洞门禁。
