# IM 通道

## 企业微信 AI Bot

每个启用 binding 创建一个官方 `wecom-aibot-sdk-python` WebSocket 客户端，凭证由 `SecretProvider`
按需解析。PostgreSQL advisory lock 防止两个副本同时连接同一 Bot；断线后 SDK 自动重连，失去锁时
主动断开。适配器标准化单聊/群聊、文本、语音转写、mixed、图片、文件、视频和事件/撤回。

### WebSocket 完整时序

企业微信长连接和飞书回调不是同一种入口。它没有进入 Gateway 的 HTTP callback，也没有“收到消息后
返回 2xx”这一步；连接、认证、心跳、入站和最终回复都在同一条出站建立的 WSS 通道上完成：

```mermaid
sequenceDiagram
    accTitle: WeCom AI Bot WebSocket lifecycle
    accDescr: One connector owns a binding lock, authenticates an outbound WSS connection, persists callbacks before asynchronous processing, sends the final reply from the outbox, and reconnects only after releasing connection state.

    participant manager as Connection manager
    participant pg as PostgreSQL
    participant sdk as WeCom SDK
    participant wecom as openws.work.weixin.qq.com
    participant runtime as Inbox / mailbox runtime
    participant worker as Worker
    participant dispatcher as Channel dispatcher

    manager->>pg: pg_try_advisory_lock(hash(binding_id))
    alt another replica owns the binding
        pg-->>manager: false; do not connect
    else lock acquired
        pg-->>manager: true; retain lock connection
        manager->>sdk: create client(bot_id, SecretRef value)
        sdk->>wecom: TLS WebSocket connect (wss:443)
        wecom-->>sdk: connection open
        sdk->>wecom: cmd=aibot_subscribe, req_id, bot_id + secret
        wecom-->>sdk: same req_id, errcode=0
        sdk-->>manager: authenticated; start heartbeat

        loop authenticated connection
            sdk->>wecom: cmd=ping, unique req_id (default 30s)
            wecom-->>sdk: same req_id, errcode=0
            Note over sdk: reset consecutive missed-heartbeat count
        end

        wecom->>sdk: cmd=aibot_msg_callback, req_id, message/event body
        sdk->>runtime: dispatch typed frame
        runtime->>runtime: bound shape/timestamp; normalize; seal media locator
        runtime->>pg: short transaction: dedupe inbound + mailbox + outbox
        pg-->>runtime: COMMIT (durable acceptance)
        Note over runtime,wecom: no HTTP 2xx; callback delivery is a WebSocket frame

        runtime->>worker: SessionReady wake-up then PG claim
        worker->>pg: fenced turn commit + outbound outbox
        dispatcher->>pg: claim outbound.wecom_ai_bot.ready
        dispatcher->>sdk: send_message(chatid, markdown + client_msg_id)
        sdk->>wecom: cmd=aibot_send_msg, new req_id, body
        wecom-->>sdk: same req_id, errcode/errmsg ACK
        sdk-->>dispatcher: delivery receipt
        dispatcher->>pg: delivered / retryable / ambiguous

        alt socket closes or two heartbeat ACKs are missed
            sdk-->>manager: disconnected; pending ACKs fail
            manager->>sdk: close client
            manager->>pg: pg_advisory_unlock(binding_id)
            manager->>manager: bounded exponential backoff + jitter
            Note over manager,pg: reacquire lock before every new WSS connection
        else provider sends disconnected_event (new connection took over)
            wecom->>sdk: event.disconnected_event
            sdk-->>manager: stop this connection; do not fight the new owner
            manager->>pg: release advisory lock
        end
    end
```

认证帧是 `aibot_subscribe`；SDK 只有在相同 `req_id` 返回 `errcode=0` 后才进入 authenticated 并开始
业务心跳。心跳是应用层 `ping` 帧，不是依赖 WebSocket 库默认 ping；连续两次没有成功 ACK 会把连接
判为异常。入站命令是 `aibot_msg_callback`。本服务的 Agent 执行是异步的，因此最终回复从 PostgreSQL
Outbound Outbox 通过 `aibot_send_msg` 主动发送，并等待同 `req_id` 的 ACK；明确限流可按
`Retry-After` 重试，发送后超时或断线属于结果未知，只记为 `ambiguous`，不会自动盲重放。

这里的 advisory lock 是服务侧的第一道单连接约束；企业微信侧也只允许同一机器人同时存在一个有效
长连接。凭证轮换或 binding control version 变化时，manager 先取消旧任务、断开并释放锁，再用新的
SecretRef 建立连接，不在日志或报告中保存 Bot Secret。

### 断线恢复的验收边界

本项目把“断线恢复”分成两种不能混写的情况：

1. **单实例故障/高可用接管（可验收）**：只停止当前持有 binding lease 的一个 connector，另一个
   connector 保持运行并取得 PostgreSQL advisory lock，重新完成 `aibot_subscribe`。至少保持故障窗口
   60 秒；探针必须记录旧 owner 释放、新 owner 接管、接管后的 WSS 认证，以及一个接管后新产生的
   唯一测试消息从入站到 `aibot_send_msg` ACK 的一次交付。这个结果证明的是服务侧 HA 和 Outbox
   收敛，不是供应商重放历史消息。
2. **全部 WSS 同时断开（供应商投递缺口）**：两个 connector 都没有有效长连接时，企业微信没有可供
   本服务接收的 `aibot_msg_callback` 通道。官方协议和 SDK 没有为入站消息定义 replay cursor、resume
   token 或 history pull；因此不能假设供应商会在重连后补投断线期间的消息。断线窗口内未收到的消息
   必须保留为未接收/失败证据，不能标记为恢复成功，也不能用恢复后新发送的消息冒充旧消息。恢复后
   发送的验收 marker 必须使用新的 provider `msgid`/事件 ID，并单独记录为新消息。

   这两种情况的报告字段和 gate 结论必须分别表达：单实例接管可以 `pass`；全部 WSS 断开只能记录
   provider delivery gap（按当前外部能力为 `not_run` 或 `fail`），不能把热备接管的回复倒推为断线
   期间旧消息已恢复。若必须保证这类消息不丢，需要供应商侧可验证的缓冲/重放能力或业务侧另建可重放
   入口；本项目不能凭空重建未收到的消息正文。

单聊 Session HMAC 输入为 tenant + binding + user，群聊为 tenant + binding + chat；principal 仍由外部
user 单独映射，所以同群 Session 共享历史但审计能区分发言人。可丢失流式进度不参与正确性，最终
消息总是先进入 Outbound Outbox。

### 真实验收准备

本项目使用 API 模式的 WebSocket 长连接，不使用群机器人 webhook，也不使用普通自建应用的
CorpID/AgentID/Secret。操作步骤：

1. 使用企业管理员或获授权成员登录最新版企业微信桌面端，进入“工作台 → 智能机器人 → 创建机器人
   → 手动创建 → API 模式”。连接方式选择“使用长连接”。
2. 设置可使用成员、部门或标签，保存 `Bot ID`，点击获取 `Secret`。Secret 只作为 Secret 注入；不要
   写入 binding JSON、Git、日志或聊天消息。重置 Secret 后旧值会立即失效。
3. 不需要为长连接准备公网回调 URL，也不需要把二维码交给服务。管理员登录企业微信时可能需要扫码，
   但服务认证只使用 Bot ID + Secret。运行节点必须能通过 443 端口访问
   `wss://openws.work.weixin.qq.com`。
4. 将 Bot ID 放入 binding 的 `account_id`，将 `bot_secret` 指向
   `file:///run/secrets/wecom_bot_secret`。启动时叠加 `deploy/im-online.override.yml`。
5. 在可见范围内选择一个测试成员，分别完成单聊文本、图片/文件和一个内部群聊；群内添加机器人后再
   测试断线重连与最终回复。不要用生产群做故障注入。

示例 binding 的 SecretRef 部分：

```json
{
  "app_id": "support",
  "channel": "wecom_ai_bot",
  "account_id": "<Bot ID>",
  "secret_refs": {
    "bot_secret": {"uri": "file:///run/secrets/wecom_bot_secret"}
  },
  "enabled": true
}
```

`yqzl` 已提供不把凭证放入进程参数的配置脚本。在服务器上创建一个仅 root 可读的临时文件，填入
Bot ID 和 Secret，然后从标准输入执行脚本：

```bash
install -m 0600 /dev/null /root/wecom-credentials.json
# 用本机编辑器填入两项真实值后保存
python3 /www/wwwroot/tx.nstarzx.cn/app/deploy/yqzl/configure_wecom_binding.py \
  </root/wecom-credentials.json
rm -f /root/wecom-credentials.json
```

输入结构如下。脚本会安全写入 Secret、创建启用的 binding 并输出 binding ID；企业微信长连接模式
没有需要填写的回调 URL：

```json
{
  "wecom_bot_id": "...",
  "wecom_bot_secret": "..."
}
```

## 飞书应用机器人

飞书通过 HTTPS 事件订阅把消息交给 Gateway。回调先校验时间戳新鲜度，并按
`SHA256(timestamp + nonce + Encrypt Key + raw body)` 校验签名，再用 Encrypt Key 派生 AES-256-CBC
密钥解密，最后同时校验 Verification Token 和回调中的 App ID。URL challenge 直接返回；普通消息在
PostgreSQL 完成 Inbox/Outbox 原子提交后立即确认，Agent 的最终回复由 Channel Dispatcher 调用飞书
OpenAPI 异步发送。消息 ID 是幂等键，应用或机器人自己发送的消息会被忽略，避免回复环路。

单聊 Session HMAC 输入为 tenant + binding + Open ID，群聊为 tenant + binding + Chat ID；同一用户在
不同 tenant 或 binding 下不会共享会话。首版标准化文本、富文本、图片、文件、音频、视频和贴纸；
发送端首版交付文本，网络超时的未知结果标记 `ambiguous`，不会盲目重发。

图片和文件不是把 `image_key/file_key` 当作文字传给 Agent。Worker 使用消息 ID 与资源 Key 调用飞书
`GET /open-apis/im/v1/messages/{message_id}/resources/{key}`，流式读取并同时校验声明大小与实际大小；
随后按 tenant scope 写入 S3/MinIO staging、校验 SHA-256、提交 PostgreSQL Artifact 元数据，最后才进入
模型。图片作为真正的多模态 `inline_data` 输入，UTF-8 文本与 PDF 先做有界抽取。原始二进制不会写入
Session Event、日志、trace 或验收报告；Session 只保留 Artifact 占位符与有策略允许的抽取文本。

默认每项 20 MiB、每 turn 4 项/总计 32 MiB、PDF 40 页、抽取文本总计 60,000 字符；这些值由不可变
tenant config 固定，下载层还有相同或更低的进程级硬上限。扫描版 PDF 在未配置 OCR 后端时明确返回
`unavailable`，不会猜测内容；普通图片仍可直接交给支持视觉的模型。飞书自身当前允许该接口下载不超过
100 MB 的资源，但本服务采用更低默认值保护 Worker 内存。

官方 `lark-channel-sdk 1.2.0` 的长连接传输依赖 `websockets<16`，而当前 tRPC-Agent 的 OpenClaw
依赖要求 `websockets>=16`。为保持单镜像和锁文件一致，本项目按官方加密回调与 OpenAPI 协议使用
现有 `httpx`/`cryptography` 实现，不在同一环境中强制降级 `websockets`。若官方后续解除冲突，可以
在通过 SDK 契约测试后增加长连接 Connector；Inbox/Outbox 与 Channel Adapter 接口无需改变。

### 真实验收准备

飞书接入不需要把登录二维码交给服务，也不需要企业 ID。管理员登录飞书开放平台时可能自行扫码，服务
运行时只使用下面四项配置：

1. 在飞书开放平台创建“企业自建应用”，添加机器人能力。在“凭证与基础信息”复制 `App ID`
   （通常以 `cli_` 开头）和 `App Secret`。
2. 在“事件与回调/事件配置”选择将事件发送至开发者服务器，启用加密策略，取得或设置
   `Verification Token` 与 `Encrypt Key`。这两个值必须与服务端 Secret 文件完全一致。
3. 先在本服务创建启用的 binding，再把请求地址填为
   `https://<域名>/v1/channels/feishu/<binding_id>/callback`。飞书会发送 URL challenge；只有返回 200
   和相同 challenge 才能保存。
4. 订阅“接收消息”事件 `im.message.receive_v1`，为应用开通读取用户发给机器人的消息及以应用身份发送
   消息所需权限。媒体下载还需要读取消息资源的权限；机器人必须与消息位于同一会话。按飞书后台提示
   创建并发布应用版本，由企业管理员审核并设置可用范围。
5. 将机器人加入一个非生产测试群，并让一个可用范围内成员完成单聊文本、群内 @、图片/文件和重复事件
   验收。运行节点需要能通过 443 端口访问 `open.feishu.cn`。

示例 binding 的 SecretRef 部分：

```json
{
  "app_id": "support",
  "channel": "feishu",
  "account_id": "<cli_App_ID>",
  "secret_refs": {
    "app_secret": {"uri": "file:///run/secrets/feishu_app_secret"},
    "verification_token": {"uri": "file:///run/secrets/feishu_verification_token"},
    "encrypt_key": {"uri": "file:///run/secrets/feishu_encrypt_key"}
  },
  "capabilities": ["media", "proactive"],
  "enabled": true
}
```

`yqzl` 已提供不把凭证放入进程参数的配置脚本。先由 `provision.sh` 生成不可枚举 binding ID，再在
服务器上创建一个仅 root 可读的临时 JSON 文件：

```bash
install -m 0600 /dev/null /root/feishu-credentials.json
# 用本机编辑器填入四项真实值后保存
python3 /www/wwwroot/tx.nstarzx.cn/app/deploy/yqzl/configure_feishu_binding.py \
  </root/feishu-credentials.json
rm -f /root/feishu-credentials.json
```

输入结构如下；脚本输出的 `callback_url` 就是飞书后台应填写的完整请求地址：

```json
{
  "feishu_app_id": "cli_...",
  "feishu_app_secret": "...",
  "feishu_verification_token": "...",
  "feishu_encrypt_key": "..."
}
```

配置完成后运行 `verify_feishu_callback.py`。它会从服务器 Secret 文件构造一次加密 challenge，经公网
HTTPS/Nginx/Gateway 往返验证，但输出中不包含凭证。

在 PowerShell 中可把 `.env.example` 复制为被 Git 忽略的 `.env.im`，填入真实值后显式启动：

```powershell
docker compose --env-file .env.im `
  -f docker-compose.yml `
  -f deploy/im-online.override.yml up -d
```

验收结束使用 `docker compose ... stop`；不要执行 `down -v`，以保留 PostgreSQL、Redis、MinIO 和
Prometheus 数据卷。

在线门禁探针还必须使用固定部署身份。除 `TRPC_IM_ONLINE_PROBE_URL` 外，生产执行前配置
`TRPC_IM_ONLINE_PROBE_URL_ALLOWLIST`，其值只能是允许访问的精确 HTTPS 基址；探针地址包含
userinfo、query、fragment、非 HTTPS scheme 或未出现在 allowlist 时会被拒绝。配置
`TRPC_IM_ONLINE_PROBE_IDENTITY_SHA256` 绑定已部署探针身份（原始身份只可通过 Secret 管理器注入
`TRPC_IM_ONLINE_PROBE_IDENTITY`），并配置不可变 `TRPC_IM_ONLINE_IMAGE_DIGEST=sha256:<64-hex>`。
探针请求带一次性 run nonce；返回必须证明同一 nonce、镜像 digest 和身份指纹。客户端不跟随 HTTP
重定向，也不会把最终 URL 重新当作已验证的目标。生产探针还必须用 Ed25519 对除
`signature_attestation` 外的完整规范 JSON 响应签名。将 `deploy/im-probe-trust.example.json` 复制为
`deploy/im-probe-trust.json`，填写独立探针的精确 URL、key ID 和 32 字节公钥的 Base64；私钥只能保留在
独立探针服务。信任文件属于源码指纹，缺失、符号链接、重复 JSON 键、公钥/URL 不匹配或任一通道签名
验证失败时，在线门禁只能是 `not_run`，探针自报的 `pass` 不构成生产证据。

探针响应通过验签后，生产报告只保留每个通道的 `signature_response.response_sha256` 和
`binding_sha256`。前者是固定字段投影（运行状态、nonce、镜像/身份指纹、必需 case 状态以及已脱敏的
provider evidence）的 SHA-256，不包含签名字段、原始消息正文、凭证或其他未知字段；后者把通道、
`run_id`、nonce、摘要和当前信任文件的 key/config/file hash 一起绑定。release gate 会从当前的
`deploy/im-probe-trust.json` 重新读取严格 JSON，拒绝重复键、NaN、布尔 `schema_version`、符号链接和
读取期间发生变化的文件，并重新计算这些 hash。信任文件轮换后，旧报告会降级为 `not_run`，必须重新
执行两条通道的在线验收；缺少真实信任文件时同样不会被当成通过。

真实限流验收必须由两条供应商路径共同产生证据：飞书的事件回调与 OpenAPI send ack，企微的
WebSocket 事件与 send ack。`rate_limit_retry_after` 观察项必须包含平台限流码（飞书通常为
`99991400` 等平台码或对应 HTTP 429；企微通常为 `45009`/`45011` 或 HTTP 429）、供应商返回的
`Retry-After`、至少两次发送尝试和实际等待时长；门禁会拒绝只有 `status=pass` 而没有这些字段的
探针响应。`reconnect` 还必须证明断线后的锁释放、下一 owner 接管和新 epoch；`prolonged_outage` 的最小语义是
单实例不可用且冗余 owner 持续服务，至少保持 60 秒后才恢复，并要有接管后的新消息与发送 ACK。
全部 WSS 同时断开时，探针不得把恢复后新消息计入断线窗口；应单独记录 provider delivery gap。
`ambiguous` 还必须由探针明确标记
`drop_response_observed=true`，证明已发生响应丢失/结果未知，并保持自动重放次数为零、生成
人工复核标识。生产执行必须同时注入当前 `TRPC_RELEASE_ID` 与高熵
`TRPC_RELEASE_NONCE`，以便与同一候选的其他生产报告绑定。离线 fake resilience 报告只能是
`production_gate=not_run`，不能替代这两条真实通道的限流、长断线、响应丢失和锁接管窗口。

## 通用投递规则

`ChannelCapabilities` 表示 stream/card/media/recall/proactive 能力。适配器负责长度拆分、速率限制和
平台错误映射；Dispatcher 记录每次 delivery attempt。明确失败可按退避策略重试，并优先遵守供应商
`Retry-After`（包括平台 JSON 中的 retry hint）；HTTP 超时、连接
断开等结果未知状态标记 `ambiguous`，必须由 tenant admin 带 `If-Match`、`Idempotency-Key` 和人工
确认调用 replay。所有日志只记录 tenant/binding/message 哈希和状态，不记录正文或凭证。

## 平台参考

- [企业微信 AI Bot 官方协议文档](https://developer.work.weixin.qq.com/document/path/101463)
- [企业微信官方 Node SDK（固定提交 `80615b987ef69c6028ad764924609247c0725955`）](https://github.com/WecomTeam/aibot-node-sdk/tree/80615b987ef69c6028ad764924609247c0725955)
- [官方 Node SDK WebSocket 实现（固定提交）](https://github.com/WecomTeam/aibot-node-sdk/blob/80615b987ef69c6028ad764924609247c0725955/src/ws.ts)
- [企业微信官方 Python SDK WebSocket 实现（固定提交 `6bcb59a9a636c566f4c6ea5268b228e3def1611a`）](https://github.com/WecomTeam/wecom-aibot-python-sdk/blob/6bcb59a9a636c566f4c6ea5268b228e3def1611a/aibot/ws.py)
- [企业微信 AI Bot Python SDK（WecomTeam）](https://github.com/WecomTeam/wecom-aibot-python-sdk)
- [腾讯云：长连接方式接入企业微信智能机器人](https://cloud.tencent.cn/document/product/1759/121473)
- [飞书官方 Channel SDK](https://github.com/larksuite/channel-sdk-python)
- [飞书 Channel SDK API Reference](https://github.com/larksuite/channel-sdk-python/blob/main/docs/reference.md)
- [飞书 Channel SDK Security](https://github.com/larksuite/channel-sdk-python/blob/main/docs/security.md)
- [飞书：获取消息中的资源文件](https://open.feishu.cn/document/server-docs/im-v1/message/get-2)
