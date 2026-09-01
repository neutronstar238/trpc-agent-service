# 独立 Feishu/WeCom 在线验收探针

`server.py` 是 `scripts/im_online_gate.py` 所需的独立签名端点。它只负责
验证本次请求是否属于已部署候选、调用一个外部 provider runner、验证 runner
返回的供应商证据，并用 Ed25519 私钥签名响应。它不属于 Gateway、Channel
Dispatcher 或 WeCom Connector 进程，因此不会把被测服务自己的状态当作独立证据。

探针不实现或伪造平台行为。没有 `TRPC_IM_PROBE_RUNNER`、runner 非零退出、输出
不是严格 JSON、缺少完整 provider evidence，或者任一 observation 不满足
`im_online_gate.py` 的校验契约时，端点仍可返回签名响应，但 case 全部是
`not_run`，生产门禁不会通过。

## 组件与信任边界

| 组件 | 运行位置 | 能看到的内容 | 不能替代的证据 |
| --- | --- | --- | --- |
| `server.py` | 独立探针主机 | 候选绑定、账号指纹、driver 的脱敏结果 | 供应商 callback/WSS/ACK |
| `provider_runner.py` | checkout 外的固定可执行文件 | 当前通道 profile、账号 ID、Secret 文件路径 | provider observation |
| `control_broker.py` | host-only Unix socket | 固定 profile、固定 action executable/argv | action 执行结果 |
| `feishu_callback_observer.py` | loopback mirror + Unix socket | 独立验签/解密后的域分离哈希 | OpenAPI 发送 ACK |
| `feishu_openapi_witness.py` | loopback HTTPS 代理 + Unix socket | 状态码、平台码、Retry-After、请求 ID/请求体哈希 | callback 入站 |
| `feishu_provider_driver.py` | checkout 外的固定可执行文件 | broker 结果及两条 witness 的哈希 receipt | operator action |
| `wecom_provider_driver.py` | checkout 外的固定可执行文件 | broker 结果及 Admin 的 epoch/lifecycle 哈希快照 | 第二条 WSS 或平台重放 |

broker 的 action executable 是部署/租户特定的受审控制器：它负责按固定 action 对测试账号、ACK 集群
和现有 Connector 执行真实操作，并返回严格 JSON。本仓库故意不提供一份持有 Kubernetes 管理员、
数据库、OIDC 或供应商管理员凭据的通用脚本。缺少任一 action executable 时 broker `--check` 失败；
用静态 JSON、录制结果或 driver 自报字段替代 action 会使真实在线门禁失去独立性。

## 与 yqzl 现有部署的关系

现有凭据来源仍可位于下列 yqzl 路径：

- `/www/wwwroot/tx.nstarzx.cn/secrets/feishu_app_secret`
- `/www/wwwroot/tx.nstarzx.cn/secrets/feishu_verification_token`
- `/www/wwwroot/tx.nstarzx.cn/secrets/feishu_encrypt_key`
- `/www/wwwroot/tx.nstarzx.cn/secrets/wecom_bot_secret`

但探针不会直接读取这些旧路径。部署时应以 root 将凭据原子复制为
`/etc/trpc-im-probe/secrets` 下的同名**普通文件**；目录及其任一父目录、文件本身都不能是
symlink。目录使用 `root:trpcagent 0750`，每个凭据文件和签名私钥使用
`root:trpcagent 0640`，写入临时文件并完成 owner/mode 校验后再原子 rename。不要把旧目录
symlink 到新目录，也不要让 `trpcagent` 对目录或文件拥有写权限；否则 host 预检和探针会
fail closed。`im-probe.env` 与 `feishu-observer.env` 只填写新路径，不复制 secret 值。

账号 ID 通过 `TRPC_IM_PROBE_FEISHU_APP_ID` 和
`TRPC_IM_PROBE_WECOM_BOT_ID` 配置，并且必须与实际 binding/account 一致。
探针只读取 secret 计算指纹；runner 通过环境变量拿到文件路径，不会从探针
响应中得到 secret 内容。

## 安装边界

1. 将 probe/runner/driver/broker/observer/witness 固定版本安装到
   `/opt/trpc-im-probe/current` 和 `/usr/local/libexec`；不要直接执行被测应用的可变 symlink。将
   `im-probe.env.example` 复制为 host-only 的 `/etc/trpc-im-probe/im-probe.env`，填入当前候选镜像 digest、
   固定探针身份指纹、真实账号 ID、secret 路径和经过审查的 runner 绝对路径。
   runner 应安装在应用 checkout 之外（模板使用
   `/usr/local/libexec/trpc-im-provider-runner`），由独立验收代码所有者审查。
   仓库中的 `provider_runner.py`、`feishu_provider_driver.py` 和 `wecom_provider_driver.py` 是可安装的
   fail-closed 编排器；复制到上述路径后设为 `root:root 0755`，且路径任一层都不能是 symlink。
2. 把 `feishu-control-profile.example.json`、`wecom-control-profile.example.json` 和
   `control-broker.example.json` 渲染到 `/etc/trpc-im-probe`。先固定 tenant/binding/account、observer/
   witness socket 和 8 个 action，再对最终文件字节计算 SHA-256；同一值必须同时写入 broker config、
   `TRPC_IM_ONLINE_FEISHU_CONTROL_PROFILE_SHA256` 或
   `TRPC_IM_ONLINE_WECOM_CONTROL_PROFILE_SHA256`。不要对模板或格式化前的文件计算摘要。
   三份渲染文件及两个 env 文件使用 `root:trpcagent 0640`，目录使用 `root:trpcagent 0750`；
   broker action executable 使用 `root:root 0755`，不得 group/other-writable。
3. 生成一份独立的 32 字节 Ed25519 seed，以 Base64 单行形式保存到
   `TRPC_IM_PROBE_SIGNING_KEY_FILE`，权限设为 root:trpcagent `0640`；把对应公钥
   和 key ID 写入 `deploy/im-probe-trust.json`。私钥绝不能进入 Git、报告、日志或
   runner stdout。
4. 以 root 安装 `trpc-im-control-broker.service`、`trpc-im-feishu-callback-observer.service`、
   `trpc-im-feishu-openapi-witness.service` 和 `trpc-im-probe.service`。callback observer 使用独立的
   `feishu-observer.env`，不能加载含另一通道路径的 probe env。执行 `systemctl daemon-reload`、
   `systemctl enable --now`，确认四个单元 active，再确认探针的 `/health/ready` 为 200。探针进程
   只监听 loopback；公网 HTTPS 必须由单独的 nginx vhost 终止并做出口 allowlist。
5. 按 `nginx-server.conf.example` 配置独立 HTTPS 主机、证书和 release-gate
   出口 IP/CIDR allowlist。探针 URL 的 base 必须与 trust 文件和
   `TRPC_IM_ONLINE_PROBE_URL_ALLOWLIST` 完全一致；门禁会自行追加 `/probe`。
   callback vhost 必须异步 mirror 到 8751；`/feishu-openapi/` 只允许 Channel Dispatcher 的固定出口
   CIDR并转发到 8752。不要把这两个 loopback 端口直接暴露到公网。
6. 仅在本次在线验收窗口，把 Channel Dispatcher 设置为
   `TRPC_SERVICE_ONLINE_TESTS_ENABLED=true` 和
   `TRPC_SERVICE_FEISHU_SEND_API_ROOT=https://<probe-host>/feishu-openapi` 后滚动更新。其他角色和正常运行
   始终保留 `https://open.feishu.cn`；验收结束立即恢复默认值并再次等待 rollout。

runner 必须执行真实的外部动作并在 stdout 输出一个严格 JSON 对象：

```json
{"provider_evidence":{"source":"...","independent_paths":["...","..."],"run_nonce":"...","account_fingerprint":"...","observations":{}}}
```

它必须证明飞书 callback + OpenAPI send ack、企微 WebSocket event + send ack，
以及 round trip、idempotency、media、reconnect、rate-limit/Retry-After、credential
rotation、至少 60 秒 prolonged outage 和 response-drop ambiguous 共 8 个 case。
其中测试用户/群、媒体对象、限流触发、旧/新凭证切换、长断线窗口和人工 replay
批准仍需要外部平台账号/租户协调；本探针只提供安全的执行与签名边界，不把这些
缺失动作写成 pass。

| case | 飞书独立证据 | 企业微信独立证据 |
| --- | --- | --- |
| `round_trip` | callback receipt + OpenAPI ACK receipt | WSS event hash + send ACK |
| `idempotency` | 平台真实重投同一 event/message，observer 计数至少 2 | 同一已持久化 event 的 service replay，不同 processing ID |
| `media` | callback media locator 哈希 + 下载产物哈希 | WSS media event 哈希 + 下载产物哈希 |
| `reconnect` | Gateway EndpointSlice replacement 稳定 + 新 callback/ACK | 正常交接 disconnected→released→acquired→authenticated，或硬故障 takeover→authenticated；新 epoch 递增 |
| `rate_limit_retry_after` | witness 的平台限流/Retry-After 与后续成功 ACK | WSS send ACK 的平台限流/退避与后续成功 ACK |
| `credential_rotation` | 旧凭据拒绝、新凭据 callback/ACK | 旧 Secret 失效、新 epoch 认证及 ACK |
| `prolonged_outage` | 单 endpoint 故障至少 60 秒且冗余 endpoint 持续交付 | 单 Connector 故障至少 60 秒且热备接管 |
| `ambiguous` | witness 在真实 ACK 后丢下游响应，自动重放为 0 | send ACK 结果未知，自动重放为 0，人工 replay 标识 |

企业微信全部 WSS 同时断线时没有官方 replay cursor/resume/history pull。断线期间未进入本服务的消息
只能记录为 provider delivery gap（`not_run` 或 `fail`），不得用恢复后的新消息冒充旧消息恢复。
企业微信锁证据必须与 Admin 中的真实生命周期一致：正常交接设置
`old_lock_owner_released=true`，硬故障接管设置为 `false`，且不得为硬故障合成 `released` 事件；
两条路径都要求新 owner 已获取、epoch 至少递增到 2，并继续绑定真实 provider event、reply 和 ACK。

`provider_runner.py` 不直接实现供应商操作，而是把同一严格请求交给当前通道的
driver。driver 的 stdout 必须恰好是
`{"schema_version":1,"observations":{...八个 case...}}`；runner 会再次校验
时间、nonce、平台限流码、重连锁接管、60 秒断线和 ambiguous 无自动重放等语义，
再生成 provider evidence。driver 进程只得到当前通道账号 ID 和 secret 文件路径，
不会得到另一通道配置或应用 `PYTHONPATH`。因此 driver 的 shebang 应使用绝对解释器
路径（例如 `/usr/bin/python3`），不能依赖继承的 `PATH`。

本地只做配置/签名闭环检查：

```powershell
$env:TRPC_IM_PROBE_SIGNING_KEY_FILE = "<test-key-file>"
$env:TRPC_IM_PROBE_KEY_ID = "test-key"
$env:TRPC_IM_PROBE_IMAGE_DIGEST = "sha256:<candidate>"
$env:TRPC_IM_PROBE_IDENTITY_SHA256 = "<fixed-64-hex>"
... # 其余账号、secret 文件和 runner 变量见 im-probe.env.example
.\.venv\Scripts\python.exe deploy\im_probe\server.py --check
```

先用同一个 host-only 配置文件运行完整预检；它不会访问网络、执行 driver 或生成
生产 IM 通过证据：

```powershell
.\.venv\Scripts\python.exe scripts\im_probe_preflight.py `
  --mode local `
  --env-file deploy\im_probe\im-probe.env `
  --candidate-lock runs\multitenant\candidate-lock.json `
  --trust-file deploy\im-probe-trust.json
```

复制到 Linux 探针主机后再运行一次 `--mode host`，只有真实路径、权限、候选镜像、
release binding、URL allowlist、Ed25519 公私钥和两条 driver 全部一致时，预检的
`readiness` 才能是 `pass`；其 `production_gate` 永远保持 `not_run`。配置模板把探针
与 release-gate 的非凭据开关放在同一文件中，真实 provider secret 值仍由 Secret
管理器在执行在线门禁时注入，不能写入该文件。

项目“功能完成”可以用当前候选在真实 Feishu/WeCom 上的基础双向收发闭环：每个通道都必须有唯一
入站、唯一出站和供应商回执。该基础证据不属于 `im-online.json` 的生产 8-case，不能将
`online_im` 或 `production_gate` 写成 `pass`；生产发布和 release manifest 仍要求两个通道的完整
8-case 与破坏性生产灾备全部通过，缺失任一项必须保持 `not_run`。

新集群只承载 Gateway、Worker、Channel Dispatcher、WeCom Connector 和数据后端；
独立探针、签名私钥、runner、driver 继续放在 yqzl/独立主机。这样重建集群不会丢失
探针信任边界，但真实在线验收仍必须等新集群恢复后才能运行。

真正生产验收仍必须由下面这一条（同一候选、同一 release binding）命令发起：

```bash
TRPC_IM_ONLINE_TESTS_ENABLED=true \
TRPC_IM_ONLINE_PROBE_URL=https://probe.example.invalid \
TRPC_IM_ONLINE_PROBE_URL_ALLOWLIST=https://probe.example.invalid \
TRPC_IM_ONLINE_IMAGE_DIGEST=sha256:<candidate-image-digest> \
TRPC_IM_ONLINE_PROBE_IDENTITY_SHA256=<fixed-64-hex> \
TRPC_IM_ONLINE_FEISHU_CONTROL_PROFILE_SHA256=<feishu-profile-sha256> \
TRPC_IM_ONLINE_WECOM_CONTROL_PROFILE_SHA256=<wecom-profile-sha256> \
TRPC_RELEASE_ID=<release-id> TRPC_RELEASE_NONCE=<high-entropy-release-nonce> \
FEISHU_APP_ID=cli_<real-id> FEISHU_APP_SECRET=<secret-from-secret-manager> \
FEISHU_VERIFICATION_TOKEN=<secret-from-secret-manager> FEISHU_ENCRYPT_KEY=<secret-from-secret-manager> \
WECOM_BOT_ID=<real-id> WECOM_BOT_SECRET=<secret-from-secret-manager> \
python scripts/im_online_gate.py --timeout-seconds 240 --require-production \
  --output runs/multitenant/im-online.json
```

其中 `<secret-from-secret-manager>` 只能由不落盘的 Secret 注入机制替换，不能把
真实值写入命令历史、代码或报告。该命令必须在已安装并 ready 的独立探针上运行，
并在同一 release ID、release nonce 和候选镜像 digest 下运行。`server.py` 自己
生成的签名响应不能替代 provider-originated evidence。
