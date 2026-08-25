# Registry candidate release

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
$repository = "ghcr.io/<owner>/trpc-agent-service"

.venv\Scripts\python.exe scripts\registry_image.py publish `
  --repository $repository `
  --output runs\multitenant\registry-image-binding.json
```

The Docker credential helper supplies authentication. The command only prints
the repository, source fingerprint, immutable references, and digest; do not
replace it with `docker login --password` or echo credential variables.

After the command succeeds, load the binding report and pass the values to the
production gates in the same PowerShell session:

```powershell
$binding = Get-Content runs\multitenant\registry-image-binding.json -Raw | ConvertFrom-Json
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

The repository's production Kustomize overlay keeps a placeholder registry and
digest on purpose. Replace it only in the reviewed deployment input or pass
the digest-pinned references through the runtime gate; never commit credentials
or an unreviewed mutable tag.
