$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Get-OptionalPropertyValue {
    param(
        [AllowNull()]
        [object]$Value,
        [Parameter(Mandatory = $true)]
        [string[]]$Path
    )

    $current = $Value
    foreach ($segment in $Path) {
        if ($null -eq $current) {
            return $null
        }
        $property = $current.PSObject.Properties[$segment]
        if ($null -eq $property) {
            return $null
        }
        $current = $property.Value
    }
    return $current
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
Set-Location $projectRoot

$python = Join-Path $projectRoot ".venv/Scripts/python.exe"
$kubectl = (Get-Command kubectl -ErrorAction Stop).Source
$kubeconfig = "C:/Users/Z/.kube/trpc-ack.yaml"
$context = "kubernetes-admin-cdecb943ac4bf48f7af5f29e4d7bf0793"
$namespace = "trpc-service"
$supportNamespace = "trpc-runtime-support"
$expectedSource = "41cce1d8d17fffd9969736c9a4f050f221846b69f3676cef56926998e3d07267"
$imageDigest = "sha256:a9765d89aa2f28aeebeb6ebf7aca4ce36a3a9b4ad89b4ad964f5da925008fee6"
$upgradeDigest = "sha256:cde4fa4554ffe24c270858178befe47f80c8728cb6409cdc9ac45b8473f246a8"
$releaseContextInitialDigest = "sha256:a9765d89aa2f28aeebeb6ebf7aca4ce36a3a9b4ad89b4ad964f5da925008fee6"
$releaseContextUpgradeDigest = "sha256:cde4fa4554ffe24c270858178befe47f80c8728cb6409cdc9ac45b8473f246a8"
$dockerHubRepository = "docker.io/zixuan760/trpc-agent-service"
$imageTag = "release-41cce1d8d17f"
$upgradeImageTag = "release-41cce1d8d17f-upgrade"
$releaseId = "release-20260901-41cce1d8"
$configPath = Join-Path $projectRoot "deploy/runtime-gate.yaml"
$bindingPath = Join-Path $projectRoot "runs/multitenant/registry-image-binding.json"
$lockPath = Join-Path $projectRoot "runs/multitenant/candidate-lock.json"
$secretManifest = Join-Path $projectRoot "runs/multitenant/.ack-runtime-private/runtime-secrets-with-pull.yaml"
$renderedSupport = Join-Path $projectRoot "runs/multitenant/rendered/support-41cce1d8d17f"
$renderedPerformance = Join-Path $projectRoot "runs/multitenant/rendered/performance-41cce1d8d17f"
$reportPath = Join-Path $projectRoot "runs/multitenant/real-performance.json"
$fixturePath = Join-Path $projectRoot "runs/multitenant/performance-fixture-ack.json"
$cleanupPath = Join-Path $projectRoot "runs/multitenant/performance-fixture-cleanup-ack.json"
$privateReleaseContext = Join-Path $projectRoot "runs/multitenant/.ack-runtime-private/release-context-41cce1d8d17f-amd64.json"
$publicReleaseContext = Join-Path $projectRoot "runs/multitenant/release-context-binding-41cce1d8d17f-amd64.json"

function Invoke-Kubectl {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & $kubectl --kubeconfig $kubeconfig --context $context @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "kubectl failed: $($Arguments -join ' ')"
    }
}

function New-RandomUrlToken {
    $bytes = [byte[]]::new(32)
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "project Python environment is unavailable"
}
if (-not (Test-Path -LiteralPath $secretManifest -PathType Leaf)) {
    throw "ACK runtime Secret manifest is unavailable"
}

& $python scripts/release_context.py verify `
    --private-context $privateReleaseContext `
    --public-output $publicReleaseContext `
    --release-id $releaseId `
    --source-fingerprint $expectedSource `
    --initial-digest $releaseContextInitialDigest `
    --upgrade-digest $releaseContextUpgradeDigest | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "private release context could not be verified"
}
$releaseContext = Get-Content -LiteralPath $privateReleaseContext -Raw | ConvertFrom-Json
if (
    $releaseContext.release_id -ne $releaseId -or
    $releaseContext.source_fingerprint -ne $expectedSource -or
    $releaseContext.images.initial -ne $releaseContextInitialDigest -or
    $releaseContext.images.upgrade -ne $releaseContextUpgradeDigest -or
    [string]::IsNullOrWhiteSpace([string]$releaseContext.nonce)
) {
    throw "private release context does not match the current candidate"
}

$env:TRPC_RELEASE_ID = $releaseId
$env:TRPC_RELEASE_NONCE = [string]$releaseContext.nonce
& $python runs/multitenant/bind_published_candidate.py `
    --expected-source $expectedSource `
    --repository $dockerHubRepository `
    --initial-tag $imageTag `
    --initial-digest $imageDigest `
    --upgrade-tag $upgradeImageTag `
    --upgrade-digest $upgradeDigest `
    --output $bindingPath `
    --lock-output $lockPath | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "candidate lock creation failed"
}

& $python scripts/render_runtime_support.py `
    --config $configPath `
    --output-dir $renderedSupport `
    --performance-output-dir $renderedPerformance
if ($LASTEXITCODE -ne 0) {
    throw "runtime manifest render failed"
}

$rendered = (& $kubectl kustomize $renderedPerformance)
if ($LASTEXITCODE -ne 0) {
    throw "rendered performance kustomization is invalid"
}
$renderedText = $rendered -join "`n"
if ($renderedText -notmatch [regex]::Escape("$dockerHubRepository@$imageDigest")) {
    throw "rendered performance workload is not pinned to the canonical Docker Hub image"
}

Invoke-Kubectl -Arguments @("apply", "-f", (Join-Path $renderedPerformance "namespace.yaml"))

$env:TRPC_PERF_FIXTURE_UNUSED_APP_SECRET = New-RandomUrlToken
$env:TRPC_PERF_FIXTURE_UNUSED_VERIFICATION_TOKEN = New-RandomUrlToken
$env:TRPC_PERF_FIXTURE_UNUSED_ENCRYPT_KEY = New-RandomUrlToken
$runtimeSecretsYaml = & $python runs/multitenant/project_kubernetes_secrets.py `
    --manifest $secretManifest --namespace $namespace --profile runtime
if ($LASTEXITCODE -ne 0) {
    throw "runtime Secret projection failed"
}
$runtimeSecretsYaml | & $kubectl --kubeconfig $kubeconfig --context $context apply -f -
if ($LASTEXITCODE -ne 0) {
    throw "runtime Secret apply failed"
}

& $kubectl --kubeconfig $kubeconfig --context $context create namespace $supportNamespace `
    --dry-run=client -o yaml |
    & $kubectl --kubeconfig $kubeconfig --context $context apply -f -
if ($LASTEXITCODE -ne 0) {
    throw "runtime support namespace apply failed"
}

$supportSecretsYaml = & $python runs/multitenant/project_kubernetes_secrets.py `
    --manifest $secretManifest --namespace $supportNamespace --profile support
if ($LASTEXITCODE -ne 0) {
    throw "runtime support Secret projection failed"
}
$supportSecretsYaml | & $kubectl --kubeconfig $kubeconfig --context $context apply -f -
if ($LASTEXITCODE -ne 0) {
    throw "runtime support Secret apply failed"
}

Invoke-Kubectl -Arguments @("--namespace", $supportNamespace, "delete", "job/postgres-bootstrap", "job/minio-bucket-bootstrap", "--ignore-not-found=true", "--wait=true")
Invoke-Kubectl -Arguments @("apply", "-f", (Join-Path $renderedSupport "ack-runtime-support.yaml"))
Invoke-Kubectl -Arguments @("apply", "-f", (Join-Path $renderedSupport "ack-runtime-minio.yaml"))
Invoke-Kubectl -Arguments @("--namespace", $supportNamespace, "wait", "--for=condition=complete", "job/postgres-bootstrap", "--timeout=600s")
Invoke-Kubectl -Arguments @("--namespace", $supportNamespace, "wait", "--for=condition=complete", "job/minio-bucket-bootstrap", "--timeout=600s")
foreach ($supportDeployment in @("postgres", "redis", "minio", "backlog-metric-source", "prometheus", "prometheus-adapter")) {
    Invoke-Kubectl -Arguments @("--namespace", $supportNamespace, "rollout", "status", "deployment/$supportDeployment", "--timeout=600s")
}

Invoke-Kubectl -Arguments @("--namespace", $namespace, "delete", "job/trpc-schema-migration", "--ignore-not-found=true", "--wait=true")
Invoke-Kubectl -Arguments @("apply", "-k", $renderedPerformance)

# Remove one-time literal fixture variables used by the previous bootstrap.
# Placement is already rendered exclusively from runtime-gate.yaml.
Invoke-Kubectl -Arguments @(
    "--namespace", $namespace, "set", "env", "deployment/trpc-gateway",
    "TRPC_PERF_FIXTURE_UNUSED_APP_SECRET-",
    "TRPC_PERF_FIXTURE_UNUSED_VERIFICATION_TOKEN-",
    "TRPC_PERF_FIXTURE_UNUSED_ENCRYPT_KEY-"
)

Invoke-Kubectl -Arguments @("--namespace", $namespace, "wait", "--for=condition=complete", "job/trpc-schema-migration", "--timeout=600s")
foreach ($deployment in @("trpc-gateway", "trpc-worker", "trpc-outbox-dispatcher", "trpc-session-recovery", "trpc-backlog-exporter")) {
    Invoke-Kubectl -Arguments @("--namespace", $namespace, "rollout", "status", "deployment/$deployment", "--timeout=600s")
}

$externalMetricReady = $false
for ($attempt = 1; $attempt -le 60; $attempt++) {
    $externalRaw = & $kubectl --kubeconfig $kubeconfig --context $context get --raw "/apis/external.metrics.k8s.io/v1beta1/namespaces/$namespace/trpc_session_ready_backlog" 2>$null
    if ($LASTEXITCODE -eq 0) {
        try {
            $external = $externalRaw | ConvertFrom-Json
            $items = @($external.items)
            $hpa = & $kubectl --kubeconfig $kubeconfig --context $context --namespace $namespace get hpa trpc-worker -o json | ConvertFrom-Json
            $scalingActive = @($hpa.status.conditions | Where-Object { $_.type -eq "ScalingActive" -and $_.status -eq "True" }).Count -eq 1
            if (
                $external.kind -eq "ExternalMetricValueList" -and
                $items.Count -eq 1 -and
                $items[0].metricName -eq "trpc_session_ready_backlog" -and
                $items[0].metricLabels.namespace -eq $namespace -and
                $null -ne ($items[0].value -as [double]) -and
                $scalingActive
            ) {
                $externalMetricReady = $true
                break
            }
        } catch {
            # Adapter discovery and HPA reconciliation are eventually consistent.
        }
    }
    Start-Sleep -Seconds 5
}
if (-not $externalMetricReady) {
    throw "external backlog metric did not become namespace-bound and ScalingActive"
}

$metricsReady = $false
for ($attempt = 1; $attempt -le 30; $attempt++) {
    $metricsRaw = & $kubectl --kubeconfig $kubeconfig --context $context get --raw "/apis/metrics.k8s.io/v1beta1/namespaces/$namespace/pods" 2>$null
    if ($LASTEXITCODE -eq 0) {
        try {
            $metrics = $metricsRaw | ConvertFrom-Json
            $workerMetrics = @($metrics.items | Where-Object { $_.metadata.name -like "trpc-worker-*" }).Count
            $outboxMetrics = @($metrics.items | Where-Object { $_.metadata.name -like "trpc-outbox-dispatcher-*" }).Count
            if ($workerMetrics -eq 4 -and $outboxMetrics -ge 1) {
                $metricsReady = $true
                break
            }
        } catch {
            # Metrics may be momentarily incomplete while new Pods are first scraped.
        }
    }
    Start-Sleep -Seconds 5
}
if (-not $metricsReady) {
    throw "metrics-server did not publish complete worker/outbox evidence"
}

Invoke-Kubectl -Arguments @("--namespace", $namespace, "get", "pods", "-o", "wide")

& $python scripts/ack_performance_acceptance.py `
    --config $configPath `
    --output $reportPath `
    --fixture-output $fixturePath `
    --cleanup-output $cleanupPath
$gateExit = $LASTEXITCODE

if (Test-Path -LiteralPath $reportPath -PathType Leaf) {
    $performanceReport = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    [ordered]@{
        gate = $performanceReport.gate
        production_gate = $performanceReport.production_gate
        rejection_reasons = @($performanceReport.production_rejection_reasons)
        burst_p95_ms = Get-OptionalPropertyValue -Value $performanceReport -Path @("candidate", "burst", "ack_p95_ms")
        sustained_p95_ms = Get-OptionalPropertyValue -Value $performanceReport -Path @("candidate", "sustained", "ack_p95_ms")
        max_parallel = Get-OptionalPropertyValue -Value $performanceReport -Path @("candidate", "burst", "max_turn_overlap_observed")
    } | ConvertTo-Json -Compress
}
if ($gateExit -ne 0) {
    throw "formal ACK Performance gate failed; no automatic rerun was attempted"
}
