# 2026-09-08 本机创新验收

结论：`offline/development=pass`、`local_k8s_gate=pass`、`production=not_run`。
本次没有连接 ACK，没有使用真实 IM、模型或供应商凭据。原基线工作区保持干净，HEAD 始终为
`9d0e14a3a28e8501dea698fed99448e1a358e7f9`；所有修改都在创新仓库的
`submission/cell-fabric-innovation` 分支。

## 候选与证据

这些报告在提交前生成，报告中的基准 Git HEAD 为
`ff19d6d8a87d3f05c52f99e5d06492de037d12a3`，并非把当时的未提交改动冒充该 commit 内容。
被测候选通过以下源码指纹与镜像绑定；本报告和归档证据位于不参与运行镜像指纹的 `docs/` 中。

| 身份 | 值 |
| --- | --- |
| 运行源码指纹 | `f5d6315ec949527b928d29e6e0690fea57136b285c16ae578f87f615862d2a06` |
| 含 unit 测试的指纹 | `c1f5906237c1793bdb1d1e7655db80944a1773066b410644f5b555e6b4134022` |
| 本机镜像 | `trpc-agent-cell-fabric:kind-f5d6315ec949` |
| Docker/Trivy 镜像 ID | `sha256:609b8b54c990d8525acc24d98fe1cb0489c26f661635024f9459ae66317c8a8c` |
| Kind/containerd 运行身份 | `sha256:f4b57ee3eb38459eebf1d6c01b542b145d39699d58c0e0ef9e97bc2d8807fe97` |
| 集群实例指纹 | `cfdcc55bf2dbcb254e2a799b021e83d1a274d0998b6b769c81d213fd543ad1cc` |

Docker 和 Kind 导入后的镜像身份分别由各自运行时读取，不能混用 BuildKit config digest。
门禁同时核验节点上的镜像关联关系与容器内源码指纹，不仅比较一个可变 tag。

## 最终结果

| 检查 | 结果 | 证据 |
| --- | --- | --- |
| Windows unit | 2725 passed，8 个符号链接测试因权限限制跳过 | [JUnit 摘要](evidence/2026-09-08/test-results.json) |
| 最终 Linux 镜像补验 | 上述 8 项全部通过，0 skip | 同上 |
| Contract + simulation | 40 passed，0 skip | 同上 |
| 真实 PostgreSQL/Redis/pgvector/Mailbox/迁移 | 16 passed，0 skip | 同上 |
| 真实 MinIO staged artifact | 另行执行 1 passed；因此主集成命令有 1 deselected | 同上 |
| 独立 statement 门禁 | 95.5378%，最低 90% | [覆盖率门禁](evidence/2026-09-08/coverage-gate-final.json) |
| 独立 branch 门禁 | 91.0548%，最低 90% | 同上 |
| Kind 1 控制面 + 3 Worker 节点 | 8/8 场景通过，最终稳定性通过 | [完整 Kind 报告](evidence/2026-09-08/kind-ack-gate-final.json) |
| 双重 replay、Judge、签名晋级/回滚及拒绝演示 | 9 个演进案例通过，真实 provider 调用 0 | [离线创新门禁](evidence/2026-09-08/local-innovation-gate-final.json) |
| 0028 → 0029 干净升级 | 临时 PostgreSQL 16 升级及合法 active fence 写入通过 | [迁移修复验证](evidence/2026-09-08/migration-0029-guard-final.json) |
| Redis → SQL 完整迁移 | 200/200，checksum 相等；断点恢复、双写、切换、清理、回滚通过 | [完整迁移报告](evidence/2026-09-08/migration-full-live.json) |
| Ruff、format、Mypy、uv lock | 全部通过；Mypy 检查 152 个文件 | 本机命令日志 |
| Compose / Kustomize | Compose 配置及 production、Kind 清单静态渲染通过 | 本机命令日志 |
| 供应链 | 150 个运行依赖无已知漏洞；候选镜像 HIGH/CRITICAL 为 0 | [供应链门禁](evidence/2026-09-08/supply-chain-final.json) |

`mock_production_gate` 的 6 组离线模拟也全部通过，但不是生产压测。其性能样本为
500 callbacks、200 turns、64 并发的内存 smoke，不作为 ACK 吞吐或延迟承诺。
原始 JUnit、覆盖率、SBOM、SARIF 和命令日志保存在本机 `runs/multitenant/`；归档的 JUnit 摘要
移除了宿主机名称，并保留原文件 SHA-256、时间和统计。

## 本轮发现并修复的问题

1. 对账 authority 不能直接修改 ledger：使用受控行锁/CAS 函数，撤销历史列级 UPDATE 权限，
   要求不可变证据，缺失 receipt 时事务回滚；旧 attempt、租户不匹配和冲突证据保持拒绝。
2. Cell 探针最初错误使用 runtime 角色准备数据，随后又漏传 branch fence。现由 worker
   角色准备 fixture，executor/reconciler 分开连接，追加事件同时传 session 与 branch fence。
   修复后跨节点真实查询对账成功，每条被测 applied 副作用只执行一次，unknown 不会自动重试。
3. 0029 的迁移屏障函数将单个 composite 列写入 `%ROWTYPE`，使字段错位。修为三处 `SELECT alias.*`，
   保留原有租户、lease、manifest 校验。0029 在本轮尚未发布：仅在隔离开发库事务性替换函数，
   不删除证据或解除失败 scope 的屏障；另外用干净 PostgreSQL 验证正式升级路径。
4. 晋级证书必须绑定被观察到的 active Capsule/control version，拒绝裸地址、错误基线、无效时间区间、
   未来签发时间及缺少严格改善的策略；对外读取签名 payload 不再暴露可被原地修改的嵌套对象。
5. 基础镜像原有 `libuuid` 的 7 个 HIGH 漏洞，已通过固定 `2.42.3-r1` 消除，没有降低门槛。
   全严重度诊断扫描还报告 pip 的 5 个 MEDIUM 和 1 个 LOW；它们不在当前 HIGH/CRITICAL 门禁范围。
   SBOM 没有 OCI 身份时如实标为 `unbound`，不伪造供应链绑定。

## 能证明什么，不能证明什么

Kind 使用真实 Kubernetes 控制面、独立 Pod、跨节点网络和持久 PostgreSQL/Redis；覆盖签名 callback
去重、RLS、工具与 Cell 对账、证书/CAS/outbox/回滚、队列接管，以及 Worker、provider、数据库、Redis
Pod 替换。Evolution 的网络否定探针也实际拒绝了 fake provider/IM 出站。

但所有 Kind 节点仍共享一台电脑。IM/provider 是测试服务：飞书覆盖加密 HTTP callback，WeCom
覆盖 runtime envelope 幂等，不等于真实 WSS 订阅、真实账号回复或供应商幂等合同。
最终稳定性窗口为 3 秒的恢复 smoke，不是长时间浸泡测试。

ACK 的 Terway、SLB/Ingress、云盘、云 IAM、跨可用区故障、真实 IM 限流/媒体、真实模型/KMS、
生产长时间压测仍为 `not_run`。供应链报告中的 `production_gate=pass` 只代表供应链这一项，
不能覆盖本报告的整体生产结论。默认 Worker 仍由 legacy 执行路径负责，未开放 native cutover。

本轮临时 PostgreSQL、MinIO 和 Linux 测试容器已清理；Kind 集群及合成测试证据保留。集成测试暂停的
dispatcher/recovery 均已恢复到 2 副本，临时端口转发已停止。
