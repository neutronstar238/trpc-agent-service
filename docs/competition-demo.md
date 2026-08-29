# 参赛展示：Causal Agent Cell Fabric

## 一句话

我们不是把 Agent 部署成更多 Pod，而是把它变成可签名部署、跨节点迁移、因果回放、反事实分叉，
并且不能直接产生未经治理副作用的逻辑 Agent Cell。

## 与常规平台的差异

| 常规 Agent 平台 | Causal Agent Cell Fabric |
|---|---|
| 部署 Prompt、模型和工具配置 | 部署内容寻址且可签名的 Agent Capsule |
| Worker/Pod 是运行实例 | Cell 是逻辑实例，Worker 只是可替换宿主 |
| Session 是一份当前快照 | append-only 因果日志是事实源，Session/Memory 是投影 |
| LLM 直接调用工具 | LLM 产生 Intent，确定性 Effect Plane 执行副作用 |
| Trace 用于观察 | Trace + Causal Log 可重建、校验和分叉 |
| 新模型直接灰度真实用户 | 从生产序号创建候选 Capsule 反事实分支 |
| CPU/队列长度调度 | 能力、合规地域、局部性、SLO、成本和负载联合调度 |

## 五分钟演示

### 0:00–0:40：签名部署

运行：

```bash
trpc-service cell-demo --output runs/cell-fabric-demo.json
```

解释 Capsule 将 Graph、Prompt、模型策略、工具清单、治理策略、Knowledge snapshot、Storage profile
和 SLO 固化成一个 digest。修改任意字段后签名验证失败。

### 0:40–1:30：语义调度

展示两个节点：普通节点缺少 `tool-sandbox` 且地域不合规；上海节点满足企业微信、沙箱、数据局部性
和合规约束。Scheduler 选择上海节点，并输出拒绝原因与 score breakdown。

### 1:30–2:40：副作用防线

Agent 提出 `refund.create`，第一次执行得到 `require_confirmation`，外部调用次数仍为 0。人工确认后
执行一次，再模拟 IM 重投或 Worker 接管；第三次请求返回同一 receipt，外部调用次数仍为 1。

### 2:40–3:40：确定性回放

展示同一个 `trace_id` 下的 message、activation、intent、policy、effect 和 reply 事件。重新 replay 后
state hash 保持一致。修改一个历史 payload，hash-chain 校验失败。

### 3:40–4:30：反事实 Capsule 分支

从 `cell.activated` 的 sequence 创建 `candidate-model-b`，目标 Capsule digest 与生产版本不同。候选回复
只进入影子分支；候选 branch 提交真实退款会被门禁拒绝，但 `simulate_only` 可以生成评估结果；生产
分支 state hash 和事件数量保持不变。

### 4:30–5:00：故障与价值总结

强调三个可以直接量化的结果：

1. 重复投递和节点接管下，非幂等外部副作用次数仍为 1。
2. 历史事件投影 replay checksum 100% 一致，篡改 100% 检出。
3. 候选模型、Prompt 或治理策略可以复用历史前缀评估，不污染生产 Session。

## 建议现场补充的可视化

- 左侧：Cell 的 live causal timeline。
- 中间：Scheduler 候选节点雷达图及硬约束拒绝原因。
- 右侧：main/candidate 两个 branch 的质量、成本、风险 Tool Intent 差异。
- 底部：effect key 状态机，突出 `require_confirmation → succeeded` 与重复调用次数 1。

## 不夸大的边界

- “Exactly once”指平台内的 **exactly-once-by-intent**。外部供应商没有幂等协议时，发送后断线只能
  标记 `ambiguous` 并停止自动重试。
- Replay 的确定性来自复用已经记录的模型/工具响应；重新采样模型属于反事实执行，不宣称确定性。
- 当前离线 demo 使用内存 Registry/Event/Effect Ledger；生产数据库结构由迁移 0017 提供，真实 KMS、
  多节点调度状态和批量影子评估仍需部署环境接入。
