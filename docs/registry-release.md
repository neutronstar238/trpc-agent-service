# Registry candidate release (DockerHub → Xuanyuan pull-through)

`scripts/registry_image.py` creates the two immutable image references needed by
the production Kubernetes gate: an initial candidate and a distinct rollout
candidate. It computes the current checkout fingerprint, passes it to the
Dockerfile, verifies the image label, pushes both tags, and reads the registry
manifest digest from Docker's push result. The output is bound to
`TRPC_RELEASE_ID` and the SHA-256 of `TRPC_RELEASE_NONCE`; the raw nonce is
never written or printed.

The command uses a single-platform `linux/amd64` build so the digest observed
by the registry and Kubernetes refers to the same manifest. It does not apply
Kubernetes resources.

```powershell
$env:TRPC_RELEASE_ID = "release-20260825-example"
$env:TRPC_RELEASE_NONCE = "<inject-a-random-32-byte-url-safe-value>"
$repository = "docker.io/<owner>/trpc-agent-cell-fabric"

.venv\Scripts\python.exe scripts\registry_image.py publish `
  --repository $repository `
  --output runs\multitenant\registry-image-binding.json `
  --lock-output runs\multitenant\candidate-lock.json
```

The Docker credential helper supplies authentication. The command only prints
the repository, source fingerprint, immutable references, and digest; do not
replace it with `docker login --password` or echo credential variables.

After the command succeeds, load the binding report and pass the values to the
production gates in the same PowerShell session:

```powershell
$binding = Get-Content runs\multitenant\candidate-lock.json -Raw | ConvertFrom-Json
$env:TRPC_REAL_IMAGE_DIGEST = [string]$binding.image_digest
$env:TRPC_MIGRATION_IMAGE_DIGEST = [string]$binding.image_digest
$env:TRPC_K8S_RUNTIME_IMAGE = [string]$binding.images.initial.reference
$env:TRPC_K8S_RUNTIME_UPGRADE_IMAGE = [string]$binding.images.upgrade.reference
```

`TRPC_K8S_RUNTIME_IMAGE` and `TRPC_K8S_RUNTIME_UPGRADE_IMAGE` must remain the
full `repository@sha256:...` values. The release reports, manifest, and
Kubernetes runtime evidence must then be produced with the same release ID,
release nonce, source fingerprint, and initial image digest. A local Docker
image ID or a tag-only reference is not a registry digest and cannot satisfy
the production release gate.

发布命令在两次 push 后重新计算 checkout 指纹，并生成 `candidate-lock.json`。后续 runtime gate 的
`release.image_binding` 必须指向这个 lock，而不是重新读取可被替换的 tag；lock 同时固定原始 binding
内容哈希、release ID/nonce 哈希、源码指纹和两条 `repository@sha256:...` 引用。可在每个生产演练前
再次执行以下只读校验：

```powershell
.venv\Scripts\python.exe scripts\candidate_lock.py verify
```

The repository's production Kustomize overlay keeps a placeholder registry and
digest on purpose. Replace it only in the reviewed deployment input or pass
the digest-pinned references through the runtime gate; never commit credentials
or an unreviewed mutable tag.

在 ACK 验收中，DockerHub 是候选镜像的 canonical push registry，轩辕是集群侧的
pull-through registry。发布成功后在 `deploy/runtime-gate.yaml` 设置
`kubernetes.pull_registry` 为轩辕 registry host（只填 host，不带 scheme 或路径），并使用
`image_pull_secret: xuanyuan-pull`。运行时会保留 DockerHub repository path 和两个
`@sha256` digest，只替换拉取 host；因此 push、candidate lock、renderer 输出和 Kubernetes
实际拉取的内容仍由同一 immutable digest 绑定。support/MinIO 镜像也必须使用轩辕侧的完整
digest 引用。不要把 DockerHub/轩辕凭证写进配置、命令参数、报告或日志。
