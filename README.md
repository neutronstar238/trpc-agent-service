# tRPC-Agent-Service

面向企业微信 AI Bot 与飞书应用机器人的多租户 Agent 生产运行时。项目基于
`tRPC-Agent-Python 1.1.19` 的公开 Runner、Agent、Event 与 Tool Safety API，提供可靠 IM
接入、事务型 Session、无状态 Worker、租户隔离、运维治理和可观测性。原始需求归档在
[docs/requirements.md](docs/requirements.md)。

本文既是项目入口，也是正式部署模板。正式版的 Gateway、Admin、Worker、两个 IM 通道、后台任务、
数据依赖与观测组件均属于同一 Kubernetes/ACK 部署。`deploy/yqzl` 只保留为临时联调兼容资产，不是正式
生产拓扑，也不应承载性能或发布门禁。

## 1. 已实现能力

- 由已认证 `channel_binding_id` 解析租户，服务端 HMAC 生成 Session ID，外部消息不能声明租户。
- PostgreSQL Inbox/Outbox、幂等键、Session lease 与 fencing token；Redis Streams 只作可重建传输。
- 同一 Session 串行提交、不同 Session 并行；一次 turn 的 event/state/outbound 原子可见。
- 企业微信 AI Bot WebSocket 长连接，以及飞书加密 HTTP 回调、URL challenge 和 OpenAPI 异步回复。
- 企业微信 fenced connection epoch/租约证据，以及独立签名 IM 探针。
- OIDC/JWKS、RBAC、ETag 乐观并发、Admin 幂等、审计、DLQ 查询和人工 outbound 重放。
- 工具白名单、预算预留、SDK Tool Safety、一次性确认令牌和非幂等工具歧义状态。
- PostgreSQL/RLS、Redis 单调投影、S3/MinIO staged artifact、pgvector 与外部 Memory 扩展口。
- 隐私优先 OpenTelemetry、Prometheus 指标、Docker Compose 和 Kubernetes/Kustomize。
- `prepare → backfill → shadow-read → dual-write → cutover → verify → cleanup/rollback` 迁移状态机。

项目不包含管理 UI、Telegram、微信公众号或微信客服；InMemory 后端仅用于单进程开发。

## 2. 部署模式

| 模式 | 用途 | 配置入口 | 是否为正式部署 |
| --- | --- | --- | --- |
| 本地 Docker Compose | 开发、功能联调、离线故障测试 | `.env` | 否 |
| Kubernetes/ACK production overlay | 完整服务、真实 IM、HPA、迁移、性能与发布验收 | Kustomize + Kubernetes Secret | 是 |
| yqzl 临时联调 | 已有域名/测试账号的短期 IM 验证 | `deploy/yqzl` | 否 |

正式部署只采用第二行。不要把 yqzl 的主机路径、systemd、宝塔 PostgreSQL 或临时测试域名复制进正式
集群配置。

## 3. 正式配置包的组成

本项目使用 Kustomize，不再引入另一套会产生配置漂移的 `values.yaml`。一个环境的正式输入由两份
非敏感文件和五类 Secret 组成：

```text
deploy/kustomize/overlays/production/
├── kustomization.yaml                 # namespace、资源、镜像仓库和不可变 digest
├── production-config-patch.yaml       # OIDC、S3、模型主机、调度器等非敏感设置
├── replicas-patch.yaml                # 固定副本基线
├── wecom-ha-patch.yaml                # 企业微信连接器跨节点约束
├── im-secret-mounts-patch.yaml        # IM Secret 只挂载给需要的角色
└── namespace.yaml

受控 Secret 系统或仓库外目录：
├── service.env                        # runtime、Redis、S3、OIDC、HMAC
├── worker.env                         # 跨租户 worker 数据库身份
├── migration.env                      # schema owner/迁移身份
├── metrics.env                        # 只读 backlog 指标身份
└── im/
    ├── feishu_app_secret
    ├── feishu_verification_token
    ├── feishu_encrypt_key
    └── wecom_bot_secret
```

`kustomization.yaml` 与 `production-config-patch.yaml` 可以放在受审查的私有部署仓库；五类 Secret 只能
进入 Vault、KMS、ExternalSecret 或权限为 0600 的仓库外文件，不能提交到本项目。

## 4. 通用准备与安全规则

### 4.1 工具与版本

- Python 3.11–3.13；生产镜像使用 Python 3.12 + Alpine 3.24。
- Git、Docker Engine 24+ 与 Docker Compose v2。
- 本地开发推荐 [uv](https://docs.astral.sh/uv/)。
- Kubernetes 1.29+、`kubectl` 和内置 Kustomize；ACK 使用受支持版本。
- 首次使用裸 `kubectl` 部署时建议安装 `yq` v4，用于安全拆分迁移和工作负载。
- PostgreSQL 16+，提供 `pgcrypto` 与 `vector` 扩展；Redis 7.4+；S3 兼容对象存储。
- 生产必须有 OIDC issuer/audience、Ingress Controller、TLS 和 External Metrics provider。

初始化开发环境：

```bash
uv sync --extra dev --locked
uv run trpc-service --help
uv run trpc-service doctor --output runs/multitenant/sdk-upgrade.json
```

PowerShell：

```powershell
uv sync --extra dev --locked
uv run trpc-service --help
uv run trpc-service doctor --output runs\multitenant\sdk-upgrade.json
```

### 4.2 密钥规则

1. 不要提交 `.env`、Kubernetes Secret、kubeconfig、机器人 Secret、发布 nonce、签名私钥或测试账号。
2. 不要把 Secret 放在命令行参数、聊天、截图、日志或报告中；使用文件、stdin 或 Secret 管理系统。
3. 租户 binding 只保存 `file://` 或经过白名单批准的 `env://` 引用，不保存明文。
4. Session HMAC 至少 32 个随机字节；Emergency Queue key 解码后必须恰好 32 字节。
5. PostgreSQL 至少拆分 `trpc_migration`、`trpc_runtime`、`trpc_worker`、`trpc_metrics` 四个账号。
6. Gateway/Admin 不得获得 owner、superuser 或 worker 身份；metrics 不得复用 worker DSN。
7. 生产必须禁用 development token、关闭内容采集、关闭飞书陈旧 binding cache，并配置真实 OIDC。
8. 应用镜像必须写成 `repository@sha256:<64-hex>`；tag 不能作为发布身份。

### 4.3 配置命名与 SecretRef

应用设置统一使用 `TRPC_SERVICE_` 前缀。配置由进程环境读取；`*_REF` 再解析 Secret：

- `env://NAME`：读取进程环境变量 `NAME`。
- `file:///absolute/path`：读取绝对路径文件；租户 Secret 必须在
  `TRPC_SERVICE_TENANT_SECRET_ROOT` 下。
- `.env`：只用于本地 Compose。
- Kubernetes：非敏感项放 ConfigMap，敏感项放五类 Secret。

生产禁止 `literal://`。环境专用配置必须覆盖所有 `example.*`、`samples.*`、`REPLACE_*` 值。

## 5. 本地 Docker Compose

### 5.1 填写 `.env`

```bash
cp .env.example .env
```

PowerShell：

```powershell
Copy-Item .env.example .env
```

必须替换：

| 变量 | 说明 |
| --- | --- |
| `POSTGRES_PASSWORD` | Compose 初始化管理员，只用于建库/建角色 |
| `MIGRATION_DATABASE_PASSWORD` | `trpc_migration` 密码 |
| `RUNTIME_DATABASE_PASSWORD` | `trpc_runtime` 密码 |
| `WORKER_DATABASE_PASSWORD` | `trpc_worker` 密码 |
| `METRICS_DATABASE_PASSWORD` | `trpc_metrics` 密码 |
| `REDIS_PASSWORD` | Redis ACL 密码 |
| `MINIO_ROOT_PASSWORD` | 本地 MinIO 密码 |
| `SESSION_HMAC_KEY` | 至少 32 个随机字节 |
| `EMERGENCY_QUEUE_KEY` | 恰好 32 个随机字节 |
| `DEVELOPMENT_TOKEN` | 仅本地使用 |
| `TRPC_SERVICE_MODEL_ENDPOINT_HOSTS` | JSON 数组，只列批准的模型 API 主机 |
| `TRPC_SERVICE_TENANT_SECRET_ENV_NAMES` | 默认 `[]`，只增加精确批准的名称 |

生成随机值：

```bash
openssl rand -base64 36 | tr -d '\r\n'
openssl rand -hex 32
```

PowerShell：

```powershell
$bytes = New-Object byte[] 36
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[Convert]::ToBase64String($bytes)

$key = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($key)
[Convert]::ToHexString($key).ToLowerInvariant()
```

不要随意更换 Emergency Queue key。轮换时先设置新
`TRPC_SERVICE_EMERGENCY_QUEUE_KEY_VERSION`，在
`TRPC_SERVICE_EMERGENCY_QUEUE_PREVIOUS_KEY_REFS` 暂时保留旧版本引用，排空后再删除。

### 5.2 启动、检查和停止

```bash
docker compose --env-file .env config --quiet
docker compose --env-file .env up --build -d
docker compose --env-file .env ps
```

`migrate` 必须先成功。失败时查看：

```bash
docker compose --env-file .env ps --all
docker compose --env-file .env logs --tail=200 migrate gateway worker
```

默认地址：

| 服务 | 地址 |
| --- | --- |
| Gateway | `http://127.0.0.1:8080` |
| Admin | `http://127.0.0.1:8081` |
| PostgreSQL / Redis | `127.0.0.1:5432` / `127.0.0.1:6379` |
| MinIO API / Console | `http://127.0.0.1:9000` / `http://127.0.0.1:9001` |
| Prometheus / Jaeger | `http://127.0.0.1:9090` / `http://127.0.0.1:16686` |

```bash
curl -fsS http://127.0.0.1:8080/health/live
curl -fsS http://127.0.0.1:8080/health/ready
curl -fsS http://127.0.0.1:8081/health/ready
docker compose --env-file .env exec worker python -m trpc_service.probe --role worker
```

停止并保留卷：

```bash
docker compose --env-file .env down
```

`docker compose down --volumes` 会永久删除本地 PostgreSQL、Redis、MinIO 和 Prometheus 数据；不要把它
当普通停止命令。

### 5.3 服务角色

| 角色 | 职责 | 凭据 |
| --- | --- | --- |
| `gateway` | 外部 API、飞书加密回调 | runtime + Feishu Secret |
| `admin` | 租户、binding、DLQ、重放与审计 | runtime + OIDC |
| `worker` | Agent turn、IM 媒体下载 | worker + IM Secret |
| `outbox-dispatcher` | PostgreSQL outbox 投递 | worker |
| `channel-dispatcher` | 飞书 OpenAPI 发送 | worker + Feishu Secret |
| `post-turn-projector` | turn 后投影 | worker |
| `wecom-connector` | 企业微信 WSS 收发 | worker + WeCom Secret |
| `session-recovery` | 过期 lease 与 ready mailbox 恢复 | worker |
| `artifact-gc` | staged artifact 回收 | worker + S3 |

## 6. 构建不可变候选镜像

本地镜像：

```bash
docker build -t trpc-agent-service:dev .
```

生产验收需要初始候选和升级候选两个不同 digest。推荐用仓库脚本统一 build/push、release context 和
candidate lock；Docker credential helper 负责登录：

```powershell
$repository = "docker.io/<owner>/trpc-agent-service"

.venv\Scripts\python.exe -m scripts.candidate_session publish `
  --repository $repository `
  --output runs\multitenant\registry-image-binding.json `
  --lock-output runs\multitenant\candidate-lock.json `
  --private-directory runs\multitenant\.ack-runtime-private `
  --public-directory runs\multitenant

.venv\Scripts\python.exe scripts\candidate_lock.py verify
```

输出的 `images.initial.reference` 与 `images.upgrade.reference` 必须是完整
`repository@sha256:...`。publish 后源码发生任何变化都必须创建新候选；不能复用旧 lock。详见
[镜像候选发布](docs/registry-release.md)。

## 7. 填写生产 Kubernetes 配置

### 7.1 `kustomization.yaml`：镜像和资源

复制 `deploy/kustomize/overlays/production` 到私有部署仓库的环境目录，或在受审查分支维护环境 patch。
填写：

```yaml
namespace: trpc-service

images:
  - name: trpc-agent-service
    newName: docker.io/<owner>/trpc-agent-service
    digest: sha256:<CURRENT_INITIAL_DIGEST>
```

保留资源：base、namespace、`im-external-egress`；保留四个 patch：replicas、production config、WeCom HA、
IM Secret mounts。不要在这里写 registry token 或机器人 Secret。

### 7.2 `production-config-patch.yaml`：非敏感设置

逐项填写或确认：

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: trpc-service-config
data:
  TRPC_SERVICE_ENVIRONMENT: production
  TRPC_SERVICE_ALLOW_DEVELOPMENT_TOKEN: "false"
  TRPC_SERVICE_CAPTURE_CONTENT: "false"
  TRPC_SERVICE_OIDC_ISSUER: https://<OIDC_HOST>/
  TRPC_SERVICE_OIDC_AUDIENCE: <OIDC_AUDIENCE>
  TRPC_SERVICE_S3_ENDPOINT: https://<PRIVATE_S3_OR_OSS_ENDPOINT>
  TRPC_SERVICE_S3_BUCKET: <PRIVATE_BUCKET>
  TRPC_SERVICE_OTLP_ENDPOINT: http://<COLLECTOR>.<NAMESPACE>.svc.cluster.local:4317
  TRPC_SERVICE_MODEL_ENDPOINT_HOSTS: '["api.openai.com"]'
  TRPC_SERVICE_TENANT_SECRET_ROOT: /run/secrets
  TRPC_SERVICE_TENANT_SECRET_ENV_NAMES: "[]"
  TRPC_SERVICE_FEISHU_ALLOW_STALE_BINDING_CACHE: "false"
  TRPC_SERVICE_FEISHU_SEND_API_ROOT: https://open.feishu.cn
  TRPC_SERVICE_ONLINE_TESTS_ENABLED: "false"
  TRPC_SERVICE_SCHEDULER_VERSION: v2
  TRPC_SERVICE_REDIS_STREAM: trpc:session-ready:v2
  TRPC_SERVICE_REDIS_CONSUMER_GROUP: trpc-session-ready-v2
  TRPC_SERVICE_WORKER_CONCURRENCY: "10"
```

不要保留 `samples.auth0.com`、`example.internal` 或与实际区域不符的 S3 endpoint。模型主机列表是出口
白名单，不是模型 Secret。飞书正常运行必须保持官方 API root；只有独立在线验收 witness 才可在显式
启用 online tests 时临时覆盖。

### 7.3 运行时 `service.env`

在 Secret 系统或仓库外创建：

```dotenv
TRPC_SERVICE_DATABASE_DSN=postgresql://trpc_runtime:<URL_ENCODED_PASSWORD>@<PG_HOST>:5432/trpc_service?sslmode=require
TRPC_SERVICE_REDIS_URL=redis://:<URL_ENCODED_PASSWORD>@<REDIS_HOST>:6379/0
TRPC_SERVICE_SESSION_HMAC_KEY=<AT_LEAST_32_RANDOM_BYTES>
TRPC_SERVICE_EMERGENCY_QUEUE_KEY=<EXACTLY_32_RANDOM_BYTES>
TRPC_SERVICE_S3_ACCESS_KEY=<S3_ACCESS_KEY>
TRPC_SERVICE_S3_SECRET_KEY=<S3_SECRET_KEY>
TRPC_SERVICE_OIDC_ISSUER=https://<OIDC_HOST>/
TRPC_SERVICE_OIDC_AUDIENCE=<OIDC_AUDIENCE>
```

OIDC 可放 ConfigMap，但由 Secret 覆盖也受支持。不要在 DSN 中留下未 URL-encode 的 `@`、`:`、`/`。

### 7.4 后台 `worker.env`

```dotenv
TRPC_SERVICE_WORKER_DATABASE_DSN_REF=env://TRPC_SERVICE_WORKER_DATABASE_DSN
TRPC_SERVICE_WORKER_DATABASE_DSN=postgresql://trpc_worker:<URL_ENCODED_PASSWORD>@<PG_HOST>:5432/trpc_service?sslmode=require
TRPC_SERVICE_WORKER_DATABASE_PASSWORD_REF=env://TRPC_SERVICE_WORKER_DATABASE_PASSWORD
TRPC_SERVICE_WORKER_DATABASE_PASSWORD=<RAW_WORKER_PASSWORD>
```

只有 Worker、dispatcher、projector、connector、recovery 与 artifact GC 可以挂载这份 Secret。

### 7.5 迁移 `migration.env`

```dotenv
TRPC_SERVICE_DATABASE_DSN=postgresql://trpc_migration:<URL_ENCODED_PASSWORD>@<PG_HOST>:5432/trpc_service?sslmode=require
```

`trpc_migration` 是 schema owner，只进入 migration Job，不进入任何长期 Pod。

### 7.6 指标 `metrics.env`

```dotenv
TRPC_SERVICE_METRICS_DATABASE_DSN=postgresql://trpc_metrics:<URL_ENCODED_PASSWORD>@<PG_HOST>:5432/trpc_service?sslmode=require
```

`trpc_metrics` 必须是 `NOSUPERUSER NOBYPASSRLS`，只允许执行
`public.count_session_ready_backlog()`。

### 7.7 IM Secret 文件

创建四个无尾随空行的文件，权限 0600：

```text
/secure/trpc-service/im/feishu_app_secret
/secure/trpc-service/im/feishu_verification_token
/secure/trpc-service/im/feishu_encrypt_key
/secure/trpc-service/im/wecom_bot_secret
```

飞书 App ID 和企业微信 Bot ID 不是 Secret，放在 PostgreSQL channel binding 的 `account_id`；四个 Secret
文件挂载到 `/run/secrets/im`。正式 binding 使用：

```text
file:///run/secrets/im/feishu_app_secret
file:///run/secrets/im/feishu_verification_token
file:///run/secrets/im/feishu_encrypt_key
file:///run/secrets/im/wecom_bot_secret
```

## 8. 创建 Kubernetes Secret

先创建 namespace：

```bash
kubectl apply -f deploy/kustomize/overlays/production/namespace.yaml
```

创建四份 env Secret：

```bash
kubectl -n trpc-service create secret generic trpc-service-secrets \
  --from-env-file=/secure/trpc-service/service.env \
  --dry-run=client -o yaml | kubectl apply --server-side -f -

kubectl -n trpc-service create secret generic trpc-worker-secrets \
  --from-env-file=/secure/trpc-service/worker.env \
  --dry-run=client -o yaml | kubectl apply --server-side -f -

kubectl -n trpc-service create secret generic trpc-migration-secrets \
  --from-env-file=/secure/trpc-service/migration.env \
  --dry-run=client -o yaml | kubectl apply --server-side -f -

kubectl -n trpc-service create secret generic trpc-metrics-secrets \
  --from-env-file=/secure/trpc-service/metrics.env \
  --dry-run=client -o yaml | kubectl apply --server-side -f -
```

创建 IM 文件 Secret：

```bash
kubectl -n trpc-service create secret generic trpc-im-secrets \
  --from-file=feishu_app_secret=/secure/trpc-service/im/feishu_app_secret \
  --from-file=feishu_verification_token=/secure/trpc-service/im/feishu_verification_token \
  --from-file=feishu_encrypt_key=/secure/trpc-service/im/feishu_encrypt_key \
  --from-file=wecom_bot_secret=/secure/trpc-service/im/wecom_bot_secret \
  --dry-run=client -o yaml | kubectl apply --server-side -f -
```

生产更推荐 ExternalSecret/Vault/KMS；无论工具为何，Secret 名称和 key 必须完全一致。

## 9. 镜像拉取与 ACK 轩辕加速

ACK 节点使用透明 Docker Hub 镜像加速（例如轩辕）时，Kubernetes 清单和证据仍保留规范引用：

```text
docker.io/<owner>/trpc-agent-service@sha256:<digest>
```

`deploy/runtime-gate.yaml` 保持：

```yaml
kubernetes:
  pull_registry: docker.io
```

镜像加速在 ACK 节点池/containerd 侧配置，不把清单仓库改成镜像站域名。这样节点通过加速器拉取，
candidate lock、Pod `imageID` 和证据仍绑定 Docker Hub 原始 digest。创建或扩容节点池后，先在新节点用
同一 digest 做小 Pod 拉取并核对 `imageID`，避免只在旧节点有缓存。

私有仓库需创建 `kubernetes.io/dockerconfigjson` Secret，并把
`image-pull-secret-patch.example.yaml` 复制为环境 patch 后加入 `kustomization.yaml`。不要把解码后的凭据
写进报告。

## 10. 渲染、迁移与部署

### 10.1 渲染和静态检查

```bash
mkdir -p /tmp/trpc-render
kubectl kustomize deploy/kustomize/overlays/production \
  >/tmp/trpc-render/production.yaml

! grep -E 'REPLACE_|example\.internal|samples\.auth0\.com' \
  /tmp/trpc-render/production.yaml

kubectl apply --dry-run=server -f /tmp/trpc-render/production.yaml
```

确认渲染结果包含：

- 所有应用镜像均为同一个 `repository@sha256`。
- `trpc-im-secrets` 只挂载到 Gateway、Worker、Channel Dispatcher、WeCom Connector。
- Gateway/Worker HPA、PDB、NetworkPolicy、backlog exporter 均存在。
- production namespace、真实 OIDC/S3/OTLP 值，无 placeholder。

### 10.2 先迁移后启动

Argo CD 会把 migration Job 作为 `PreSync`。使用裸 `kubectl` 首次部署时，用 `yq` v4 拆分：

```bash
yq eval 'select(.kind != "Deployment" and .kind != "HorizontalPodAutoscaler" and .kind != "Job")' \
  /tmp/trpc-render/production.yaml >/tmp/trpc-render/prerequisites.yaml
yq eval 'select(.kind == "Job" and .metadata.name == "trpc-schema-migration")' \
  /tmp/trpc-render/production.yaml >/tmp/trpc-render/migration.yaml
yq eval 'select(.kind == "Deployment" or .kind == "HorizontalPodAutoscaler")' \
  /tmp/trpc-render/production.yaml >/tmp/trpc-render/workloads.yaml

kubectl apply --server-side -f /tmp/trpc-render/prerequisites.yaml
kubectl -n trpc-service delete job trpc-schema-migration --ignore-not-found
kubectl apply --server-side -f /tmp/trpc-render/migration.yaml
kubectl -n trpc-service wait --for=condition=complete \
  job/trpc-schema-migration --timeout=1800s
kubectl -n trpc-service logs job/trpc-schema-migration
kubectl apply --server-side -f /tmp/trpc-render/workloads.yaml
kubectl apply --server-side -f /tmp/trpc-render/production.yaml
```

迁移失败时不要启动新工作负载。保存日志，修复数据库权限、扩展或 schema 问题；不要手工修改
`alembic_version`，也不要用 runtime/worker 账号迁移。

### 10.3 启动验收

```bash
kubectl -n trpc-service get pods -o wide
kubectl -n trpc-service get deploy,job,svc,endpointslice
kubectl -n trpc-service rollout status deploy/trpc-gateway --timeout=10m
kubectl -n trpc-service rollout status deploy/trpc-worker --timeout=10m
kubectl -n trpc-service rollout status deploy/trpc-wecom-connector --timeout=10m
kubectl -n trpc-service get hpa
kubectl get --raw \
  '/apis/external.metrics.k8s.io/v1beta1/namespaces/trpc-service/trpc_session_ready_backlog'
kubectl -n trpc-service top pods
```

必须确认：Pod Ready、restart 为 0 或有解释；Pod `imageID` 等于候选 digest；Gateway EndpointSlice 无
unready/terminating endpoint；HPA `ScalingActive=True`；external backlog metric 可读；WeCom 两副本位于
不同节点。

Pod 长时间 `Pending` 时检查 node label、affinity、taint/toleration、配额和可用区。性能验收常用
`trpc-role=workload`、`trpc-role=load-driver` 等标签；它们是验收调度约束，不应无审查写进普通生产池。

## 11. Ingress、TLS 与统一集群 IM 配置

### 11.1 Ingress

Gateway Service 为 `trpc-gateway:8080`，Admin 为 `trpc-admin:8081`。生产应在私有部署仓库添加 Ingress；
示例：

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: trpc-gateway
  namespace: trpc-service
spec:
  ingressClassName: nginx
  tls:
    - hosts: [agent.example.com]
      secretName: trpc-gateway-tls
  rules:
    - host: agent.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: trpc-gateway
                port:
                  number: 8080
```

Admin 建议使用独立内网域名、VPN 或零信任访问。不要暴露 PostgreSQL、Redis、MinIO Console、debug 或
metrics 管理端口。

飞书回调必须公网 HTTPS 可达，证书链完整；企业微信只需要 connector 出站访问
`wss://openws.work.weixin.qq.com:443`。production overlay 的 IM egress 仅选择 Channel Dispatcher 和
WeCom Connector；支持 FQDN policy 的 CNI 应把 `0.0.0.0/0:443` 替换为审核后的供应商域名。

### 11.2 创建租户

所有租户和 channel binding 存 PostgreSQL，通过 Admin API 管理；不要再为每个租户复制一份进程 `.env`。
先取得 platform admin OIDC token：

```bash
export ADMIN_URL=https://admin.internal.example.com
export TOKEN='<OIDC_BEARER_TOKEN>'

curl -i -X POST "$ADMIN_URL/v1/tenants" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Idempotency-Key: create-tenant-example-001' \
  -H 'Content-Type: application/json' \
  --data '{"tenant_id":"tenant-example","display_name":"Example Tenant"}'
```

保存响应 `ETag`。后续写操作每次先 GET 当前 tenant，使用最新 `ETag` 作为 `If-Match`，并使用新的
`Idempotency-Key`。

### 11.3 飞书 binding

在飞书开放平台创建企业自建应用，启用机器人、加密事件回调、`im.message.receive_v1`、消息发送和媒体
权限。App ID 放 `account_id`，Secret 只在 `trpc-im-secrets`：

```bash
export ETAG='"1"'  # 替换为 GET tenant 返回的当前值

curl -i -X PUT \
  "$ADMIN_URL/v1/tenants/tenant-example/channel-bindings/feishu-primary" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Idempotency-Key: bind-feishu-example-001' \
  -H "If-Match: $ETAG" \
  -H 'Content-Type: application/json' \
  --data '{
    "app_id":"support",
    "channel":"feishu",
    "account_id":"cli_REPLACE",
    "secret_refs":{
      "app_secret":{"uri":"file:///run/secrets/im/feishu_app_secret"},
      "verification_token":{"uri":"file:///run/secrets/im/feishu_verification_token"},
      "encrypt_key":{"uri":"file:///run/secrets/im/feishu_encrypt_key"}
    },
    "capabilities":["media","proactive"],
    "enabled":true
  }'
```

飞书后台回调地址：

```text
https://agent.example.com/v1/channels/feishu/feishu-primary/callback
```

完成 URL challenge、应用版本发布和可用范围审批，再用测试成员发送唯一 marker；必须只产生一条 Inbox
和一条最终回复。

### 11.4 企业微信 binding

企业微信使用“智能机器人 → API 模式 → 长连接”，不是群机器人 webhook，也不是普通自建应用
CorpID/AgentID。Bot ID 放 `account_id`：

```bash
export ETAG='"2"'  # 替换为上一步后的当前值

curl -i -X PUT \
  "$ADMIN_URL/v1/tenants/tenant-example/channel-bindings/wecom-primary" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Idempotency-Key: bind-wecom-example-001' \
  -H "If-Match: $ETAG" \
  -H 'Content-Type: application/json' \
  --data '{
    "app_id":"support",
    "channel":"wecom_ai_bot",
    "account_id":"REPLACE_WITH_BOT_ID",
    "secret_refs":{
      "bot_secret":{"uri":"file:///run/secrets/im/wecom_bot_secret"}
    },
    "capabilities":["media","proactive"],
    "enabled":true
  }'
```

企业微信不需要入站公网 callback。确认两个 connector 副本中只有一个 binding owner，另一个可接管；发送
唯一 marker，必须只产生一条回复。企业微信协议没有断线期间的历史补投或 resume cursor：全部 WSS
同时断开期间未送达服务的消息无法由应用恢复，必须记录 provider delivery gap，不能把恢复后的新消息
冒充补投。

### 11.5 多租户统一存储位置

正式配置分层如下：

| 内容 | 存储位置 | 是否含明文 Secret |
| --- | --- | --- |
| 集群级非敏感参数 | ConfigMap/Kustomize patch | 否 |
| 数据库、Redis、S3、OIDC 私密值 | Kubernetes Secret/外部 Secret 管理器 | 是 |
| 飞书/企业微信私密值 | `trpc-im-secrets` | 是 |
| tenant、app、binding、account ID、能力、SecretRef | PostgreSQL 控制面表 | 否 |
| release ID、source、image digest | candidate lock 与审计报告 | 否；nonce 原值不公开 |

因此新增租户通常不创建新 Pod 或复制 `.env`：创建 tenant、配置 agent revision、创建 binding，并让
binding 引用已批准的 Secret key。需要每租户独立凭据时，使用独立 Secret key/CSI 挂载路径并更新
SecretRef；不要把所有租户合并成一个 JSON 明文表。

更完整的通道权限、媒体、群聊、幂等和故障语义见 [IM 通道文档](docs/im-channels.md)。

## 12. 生产运行参数参考

| 变量 | 建议 | 约束/用途 |
| --- | --- | --- |
| `TRPC_SERVICE_ENVIRONMENT` | `production` | 启用生产不变量 |
| `TRPC_SERVICE_ALLOW_DEVELOPMENT_TOKEN` | `false` | 生产必须关闭 |
| `TRPC_SERVICE_CAPTURE_CONTENT` | `false` | 防止正文进入 telemetry |
| `TRPC_SERVICE_OIDC_ISSUER` | 真实 HTTPS issuer | 生产必填 |
| `TRPC_SERVICE_OIDC_AUDIENCE` | 服务 audience | 生产必填 |
| `TRPC_SERVICE_DATABASE_POOL_MIN_SIZE` | 按角色设置 | 不得大于 max |
| `TRPC_SERVICE_DATABASE_POOL_MAX_SIZE` | 按 PG 预算设置 | 所有 Pod 总和不能超过连接预算 |
| `TRPC_SERVICE_WORKER_CONCURRENCY` | 默认 `10` | HPA 20 副本时上限 200 turn |
| `TRPC_SERVICE_SCHEDULER_VERSION` | `v2` | 与 stream/group 成套 |
| `TRPC_SERVICE_REDIS_STREAM` | `trpc:session-ready:v2` | 不可在普通滚动中切版本 |
| `TRPC_SERVICE_REDIS_CONSUMER_GROUP` | `trpc-session-ready-v2` | 不可在普通滚动中切版本 |
| `TRPC_SERVICE_REDIS_RECLAIM_AFTER_MS` | `60000` | 与 lease/恢复策略一致 |
| `TRPC_SERVICE_TENANT_SECRET_ROOT` | `/run/secrets` | file SecretRef 根目录 |
| `TRPC_SERVICE_TENANT_SECRET_ENV_NAMES` | `[]` | 使用文件 Secret 时保持 fail-closed |
| `TRPC_SERVICE_MODEL_ENDPOINT_HOSTS` | 审批后的 JSON 数组 | 阻止租户任意模型出口 |
| `TRPC_SERVICE_FEISHU_ALLOW_STALE_BINDING_CACHE` | `false` | 生产不得放宽 |
| `TRPC_SERVICE_FEISHU_SEND_API_ROOT` | `https://open.feishu.cn` | 正常运行固定官方地址 |
| `TRPC_SERVICE_ONLINE_TESTS_ENABLED` | `false` | 仅在线门禁显式开启 |
| `TRPC_SERVICE_S3_ENDPOINT` | 私有 S3/OSS | 不包含 Secret |
| `TRPC_SERVICE_S3_BUCKET` | 私有 bucket | 禁止匿名 |
| `TRPC_SERVICE_OTLP_ENDPOINT` | 集群内 Collector | 不直发未知公网 |
| `TRPC_SERVICE_MEDIA_DOWNLOAD_MAX_BYTES` | `20971520` | 媒体上限 |
| `TRPC_SERVICE_MEDIA_DOWNLOAD_TIMEOUT_SECONDS` | `30` | 1–300 秒 |
| `TRPC_SERVICE_RECOVERY_BATCH_SIZE` | `25` | recovery 单批数量 |
| `TRPC_SERVICE_ARTIFACT_STAGING_TTL_SECONDS` | `86400` | staged artifact 清理阈值 |

调度器 `v1↔v2` 不是普通滚动升级。必须停入站、排空旧 PostgreSQL outbox 和 Redis group、缩容相关角色
到 0，再切换 stream/group，并按 recovery → dispatcher → worker → ingress 恢复。完整判据见
[调度器切换手册](docs/scheduler-cutover.md)。禁止用 `DEL`、`XTRIM` 或直接改状态伪造排空。

## 13. 运行态、HPA 与性能验收

复制 `deploy/runtime-gate.example.yaml` 为被 Git 忽略的 `deploy/runtime-gate.yaml`，填写：

- 明确 kubeconfig/context 和当前 candidate lock。
- Secret manifest 与可选 image pull Secret。
- `pull_registry: docker.io`，ACK 节点侧走轩辕透明加速。
- workload、load-driver、data/control 节点标签与 taint。
- digest-pinned PostgreSQL、Redis、MinIO、Prometheus、Adapter、load Job 镜像。
- `trpc_session_ready_backlog` 外部指标与 HPA driver 身份。

性能 Job 必须在专用 `trpc-role=load-driver` 节点，不在 yqzl、开发机端口转发或业务 Pod 中执行。性能、
Kubernetes runtime、迁移和故障注入必须串行使用同一候选，不能并发改 namespace、HPA、节点 drain 或
固定报告文件。详见[测试与发布门禁](docs/testing.md)。

完整 `online_im` 还要求每个真实通道证明入站、发送 ACK、幂等、媒体、重连/接管、长故障、真实限流和
ambiguous response。独立签名探针的安装与信任配置见
[在线 IM 探针](deploy/im_probe/README.md)。没有真实证据时必须保持 `production_gate=not_run`。

## 14. 升级、备份与回滚

### 14.1 升级前

1. 备份 PostgreSQL并验证可恢复，记录 `alembic_version`。
2. 备份 Redis AOF/RDB 与对象存储 bucket/versioning 状态。
3. 记录当前 `repository@sha256`、ConfigMap hash、Secret 版本、release ID 与 scheduler 版本。
4. 生成新候选并验证 candidate lock，不复用旧 tag。
5. 先跑 expand-compatible 迁移，再滚动应用；观察期内保留旧字段、旧 key 和旧 transport。

### 14.2 应用回滚

同 scheduler/schema 兼容范围内，把环境 overlay digest 恢复为上一个已验证 digest，并对所有角色使用同一
候选。示例只展示 Gateway：

```bash
kubectl -n trpc-service set image deploy/trpc-gateway \
  gateway=docker.io/<owner>/trpc-agent-service@sha256:<previous-digest>
kubectl -n trpc-service rollout status deploy/trpc-gateway --timeout=10m
```

正式操作应在 Kustomize/GitOps 中回滚，不长期保留命令式漂移。数据库迁移不做盲目 downgrade；按
[迁移与回滚](docs/migration.md)的 verify/rollback 判据执行。

### 14.3 Secret 轮换

- 先把新 Secret 版本写入 Secret 管理器，确认文件 key/路径不变或创建新路径。
- binding 使用新 SecretRef 时携带最新 `If-Match` 与唯一 `Idempotency-Key`。
- 先滚动/重连一小部分实例，验证供应商 ACK，再完成其余实例。
- Emergency Queue key 按版本双读窗口轮换；不能直接覆盖后立即删除旧 key。
- Ed25519 IM probe trust 轮换后旧在线报告失效，必须重跑真实门禁。

## 15. 测试与完成定义

本地离线门禁：

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy trpc_service scripts
uv run pytest --cov=trpc_service --cov-branch
uv run python scripts/mock_production_gate.py
kubectl kustomize deploy/kustomize/overlays/production >/dev/null
```

默认测试不调用外部模型或 IM 平台。真实 IM、性能、故障注入和部署门禁需要显式凭据/基础设施。

“功能完成”至少要求：静态/单元/契约通过；Compose 与 Kubernetes 运行态通过；零成本功能灾备通过；
当前候选在真实飞书和企业微信上证明唯一入站/唯一出站/供应商回执；镜像、源码、release context 与报告
一致。

“生产发布完成”还要求完整 `online_im` 8-case、最终 release manifest，以及按政策显式启用的
破坏性生产灾备。唯一允许的灾备豁免是 `--allow-functional-dr`：它只能授权功能灾备替代未运行的
破坏性 DR，并保留
`production_gate=not_run` 与 `authorized_not_run_gates=[disaster_recovery]`；它不豁免 `online_im`、
任何 `fail` 或其他门禁。

## 16. 常见故障

| 现象 | 首查 |
| --- | --- |
| Compose 服务全部等待 | migration 日志、PG 扩展和数据库密码 |
| `another connector owns this binding` | 是否重复 owner、租约/epoch、主备接管 |
| 同一 IM 消息回复两次 | provider message ID、Inbox 唯一键、旧 connector 是否仍在线 |
| 企业微信停机仍立即回复 | 是否只停一个 owner，另一个 connector 是否接管 |
| 企业微信全断线消息无回复 | 协议无历史补投/resume，记录 delivery gap |
| 飞书 challenge 失败 | TLS、Ingress 路径、binding ID、token/encrypt key、body limit |
| Pod `Pending` | node label、affinity、taint/toleration、配额 |
| HPA `ScalingActive=False` | Metrics Server、exporter、Adapter、metrics DSN 权限 |
| `ImagePullBackOff` | digest、pull Secret、ACK 新节点轩辕/containerd 配置 |
| 报告 identity mismatch | publish 后改了源码、复用了旧 lock/report |
| P95 偶发超门槛 | CPU throttle、DB pool wait、active queries、placement、transport errors、p99/max |

## 17. 文档索引

- [架构与完整消息时序](docs/architecture.md)
- [数据模型](docs/data-model.md)
- [一致性与多后端](docs/consistency.md)
- [IM 接入与真实账号配置](docs/im-channels.md)
- [独立在线 IM 探针](deploy/im_probe/README.md)
- [安全、治理与隐私](docs/security.md)
- [运维、容量和故障恢复](docs/operations.md)
- [数据迁移与回滚](docs/migration.md)
- [调度器版本切换](docs/scheduler-cutover.md)
- [镜像候选发布](docs/registry-release.md)
- [测试和发布门禁](docs/testing.md)
- [生产风险清单](docs/risks.md)
