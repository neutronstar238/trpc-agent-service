# ACK 验收记录

本页记录 2026-09-02 对当前创新候选执行的 ACK 功能与性能验收结论，便于评审区分“真实集群验证”与
“完整生产发布门禁”。运行报告、kubeconfig、Secret 和测试夹具均属于环境产物，不进入 Git 历史；
仓库只保留可复现的门禁代码、部署模板和脱敏结论。

## 候选绑定

- release：`release-20260902-cell-final-21472236ceeb`
- 源码指纹：`21472236ceebcb79dbb3e7603aef2a6ac4d885df7bbd79fdddb71a3a19e793db`
- DockerHub 初始镜像：`docker.io/zixuan760/trpc-agent-cell-fabric@sha256:7b5390da15f765720286b15144d867801358418e4bf8ec1bd227225a53d281ac`
- 滚动升级镜像：`docker.io/zixuan760/trpc-agent-cell-fabric@sha256:7d9d047b00e3913ec3d37c121f282c0973c7d1d25e235ca289564ac47dd0af17`
- candidate binding SHA-256：`6b1a0a3fe78640def283fbdcc1029a77b44bf1c45df4dc9d4882c2adca0be614`
- ACK 运行时通过轩辕代理拉取同一不可变 digest；候选锁复核通过。

## 已通过的真实 ACK 验收

Kubernetes 运行时门禁的 `gate` 与 `production_gate` 均为 `pass`，失败和未运行检查均为 0：

- 10 个角色使用同一初始 digest 启动，并全部完成升级 digest 的滚动更新。
- 外部 backlog 指标实测 `0 → 40 → 0`，Worker Ready 副本实测 `3 → 4 → 3`。
- 坏 digest 注入产生预期失败，Deployment undo 后恢复正确 digest 和 readiness。
- PDB eviction、节点 cordon/drain/uncordon、节点恢复和 35.26 秒优雅终止均通过；未使用强制删除。
- 运行结束后随机门禁 Namespace、驱动 Job/Pod 和 HPA 测试数据均已清理。

4 个独立 Worker 的性能门禁同样为 `gate=pass`、`production_gate=pass`：

| 场景 | 请求/接受 | 实际速率 | ACK p95 | 关键结论 |
|---|---:|---:|---:|---|
| 突发 | 200/200 | 105.02 callback/s；turn 重叠 200 | 47.53 ms | 错误、重复、消息丢失均为 0 |
| 持续 | 200/200 | 102.77 HTTP callback/s | 128.13 ms | 超阈值、重复、消息丢失、Redis pending 均为 0 |

持续场景 p99 为 159.08 ms，没有样本超过 200 ms；burst 与 sustained 结束后 Redis pending 和
mailbox unresolved 均为 0。内存观测覆盖 4 个 Worker 与 1 个 Outbox Dispatcher，短时单次采样合计
约 972 MiB；该采样不替代长时间 soak、泄漏趋势和峰值容量测试。

## 本地质量门禁

- 单元测试：2371 passed，8 skipped。
- statement coverage：95.314%；branch coverage：90.820%；两项独立 90% 门禁通过。
- Ruff format/check、mypy 和确定性模拟门禁通过。
- 跳过项只对应未提供的外部 DSN、对象存储、真实 IM 账号或显式生产迁移 opt-in，不能升级为通过。

复现入口见 [`testing.md`](testing.md)、[`real-runtime.md`](real-runtime.md) 和
[`registry-release.md`](registry-release.md)。ACK 渲染、HPA 驱动、性能夹具和证据 lineage 分别由
`scripts/kubernetes_runtime_gate.py`、`scripts/kubernetes_hpa_load_driver.py`、
`scripts/ack_performance_acceptance.py` 与 `scripts/evidence_lineage.py` 实现。

## 未完成的生产发布条件

上述结果证明当前候选在租用 ACK 环境中的节点化部署、HPA、升级回滚、驱逐恢复和规定性能场景已经
通过；它不等价于完整生产发布。最终 release gate 仍保持 `not_run`，主要缺少：

- 企业微信与飞书真实账号、签名探针、限流、媒体和长断线接管证据；
- 独立生产后端的 Compose/control-plane E2E、完整 Toxiproxy 故障集合；
- Redis→SQL、向量库迁移的真实双写、校验、切换和回滚证据；
- 跨可用区高可用、PITR、对象版本、KMS 和灾备演练；
- 同一 release binding 下的完整生产证据 manifest。

验收用 PostgreSQL、Redis、MinIO 和 metrics adapter 属于单集群验证拓扑，不应作为通用生产容量或
灾备承诺。所有生产结论必须继续遵守 [`acceptance-matrix.md`](acceptance-matrix.md) 的 fail-closed
判定规则。
