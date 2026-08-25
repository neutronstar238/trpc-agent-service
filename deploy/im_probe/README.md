# 独立 Feishu/WeCom 在线验收探针

`server.py` 是 `scripts/im_online_gate.py` 所需的独立签名端点。它只负责
验证本次请求是否属于已部署候选、调用一个外部 provider runner、验证 runner
返回的供应商证据，并用 Ed25519 私钥签名响应。它不属于 Gateway、Channel
Dispatcher 或 WeCom Connector 进程，因此不会把被测服务自己的状态当作独立证据。

探针不实现或伪造平台行为。没有 `TRPC_IM_PROBE_RUNNER`、runner 非零退出、输出
不是严格 JSON、缺少完整 provider evidence，或者任一 observation 不满足
`im_online_gate.py` 的校验契约时，端点仍可返回签名响应，但 case 全部是
`not_run`，生产门禁不会通过。

## 与 yqzl 现有部署的关系

配置模板默认读取以下现有 secret 文件：

- `/www/wwwroot/tx.nstarzx.cn/secrets/feishu_app_secret`
- `/www/wwwroot/tx.nstarzx.cn/secrets/feishu_verification_token`
- `/www/wwwroot/tx.nstarzx.cn/secrets/feishu_encrypt_key`
- `/www/wwwroot/tx.nstarzx.cn/secrets/wecom_bot_secret`

账号 ID 通过 `TRPC_IM_PROBE_FEISHU_APP_ID` 和
`TRPC_IM_PROBE_WECOM_BOT_ID` 配置，并且必须与实际 binding/account 一致。
探针只读取 secret 计算指纹；runner 通过环境变量拿到文件路径，不会从探针
响应中得到 secret 内容。

## 安装边界

1. 将 `im-probe.env.example` 复制为 host-only 的
   `/www/wwwroot/tx.nstarzx.cn/config/im-probe.env`，填入当前候选镜像 digest、
   固定探针身份指纹、真实账号 ID、secret 路径和经过审查的 runner 绝对路径。
   runner 应安装在应用 checkout 之外（模板使用
   `/usr/local/libexec/trpc-im-provider-runner`），由独立验收代码所有者审查。
2. 生成一份独立的 32 字节 Ed25519 seed，以 Base64 单行形式保存到
   `TRPC_IM_PROBE_SIGNING_KEY_FILE`，权限设为 root:trpcagent `0640`；把对应公钥
   和 key ID 写入 `deploy/im-probe-trust.json`。私钥绝不能进入 Git、报告、日志或
   runner stdout。
3. 以 root 安装 `trpc-im-probe.service`，执行 `systemctl daemon-reload`、
   `systemctl enable --now trpc-im-probe`，再确认 `/health/ready` 为 200。探针进程
   只监听 loopback；公网 HTTPS 必须由单独的 nginx vhost 终止并做出口 allowlist。
4. 按 `nginx-server.conf.example` 配置独立 HTTPS 主机、证书和 release-gate
   出口 IP/CIDR allowlist。探针 URL 的 base 必须与 trust 文件和
   `TRPC_IM_ONLINE_PROBE_URL_ALLOWLIST` 完全一致；门禁会自行追加 `/probe`。

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

本地只做配置/签名闭环检查：

```powershell
$env:TRPC_IM_PROBE_SIGNING_KEY_FILE = "<test-key-file>"
$env:TRPC_IM_PROBE_KEY_ID = "test-key"
$env:TRPC_IM_PROBE_IMAGE_DIGEST = "sha256:<candidate>"
$env:TRPC_IM_PROBE_IDENTITY_SHA256 = "<fixed-64-hex>"
... # 其余账号、secret 文件和 runner 变量见 im-probe.env.example
.\.venv\Scripts\python.exe deploy\im_probe\server.py --check
```

真正生产验收仍必须由下面这一条（同一候选、同一 release binding）命令发起：

```bash
TRPC_IM_ONLINE_TESTS_ENABLED=true \
TRPC_IM_ONLINE_PROBE_URL=https://probe.example.invalid \
TRPC_IM_ONLINE_PROBE_URL_ALLOWLIST=https://probe.example.invalid \
TRPC_IM_ONLINE_IMAGE_DIGEST=sha256:<candidate-image-digest> \
TRPC_IM_ONLINE_PROBE_IDENTITY_SHA256=<fixed-64-hex> \
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
