param(
    [ValidateRange(1, 8)]
    [int]$StartStage = 1,
    [ValidateRange(1, 8)]
    [int]$EndStage = 8
)

throw "This legacy acceptance wrapper is disabled because it targets the protected fallback namespace. Use deploy/runtime-gate.yaml with the current candidate lock and the canonical Python gates."

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($StartStage -gt $EndStage) {
    throw "StartStage cannot be greater than EndStage"
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
Set-Location $projectRoot

$python = Join-Path $projectRoot ".venv/Scripts/python.exe"
$kubectl = (Get-Command kubectl -ErrorAction Stop).Source
$kubeconfig = "C:/Users/Z/.kube/trpc-ack.yaml"
$context = "kubernetes-admin-ce2b4552918f947c880c02bbf740846a9"
$supportNamespace = "trpc-runtime-support"
$serviceNamespace = "trpc-service"
$hpaDriverNamespace = "trpc-runtime-driver"
$hpaDriverServiceAccount = "hpa-driver"
$hpaDriverContext = "hpa-driver-context"
$hpaDriverKubeconfig = Join-Path $projectRoot "runs/multitenant/.ack-runtime-private/hpa-driver.kubeconfig"
$secretManifest = Join-Path $projectRoot "runs/multitenant/.ack-runtime-private/runtime-secrets-with-pull.yaml"
$candidateDigest = "sha256:ef3bd5c94fe8fdf748019fa40fa21a1b21c9de0f1b8d534451c40ca5bb4dede9"
$initial = "zixuan760/trpc-agent-service:release-da1d5d43d852"
$initialId = $candidateDigest
$releaseContextInitialDigest = "sha256:ef3bd5c94fe8fdf748019fa40fa21a1b21c9de0f1b8d534451c40ca5bb4dede9"
$releaseContextUpgradeDigest = "sha256:87e5d418ed0fb4de1e61d35c343b2aac94ab79438ba566f4a2121a359286c335"
$releaseId = "release-20260828-da1d5d43"
$fp = "da1d5d43d8526b4caf1ebf7afbe876a65aa2b6869f413abdbba4aeef055d69bf"
$releaseContextPath = Join-Path $projectRoot "runs/multitenant/.ack-runtime-private/release-context-da1d5d43d852-amd64.json"
$portForwards = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()

function Invoke-Python {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Failure
    )
    & $python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw $Failure
    }
}

function Test-LoopbackPort {
    param([Parameter(Mandatory = $true)][int]$Port)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $task = $client.ConnectAsync("127.0.0.1", $Port)
        return $task.Wait(250) -and $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Start-VerifiedPortForward {
    param(
        [Parameter(Mandatory = $true)][string]$Service,
        [Parameter(Mandatory = $true)][int]$LocalPort,
        [Parameter(Mandatory = $true)][int]$RemotePort
    )
    if (Test-LoopbackPort -Port $LocalPort) {
        throw "loopback port $LocalPort is already occupied"
    }
    $safeService = $Service.Replace("/", "-")
    $stdout = Join-Path $projectRoot "runs/multitenant/port-forward-$safeService-$LocalPort.out.log"
    $stderr = Join-Path $projectRoot "runs/multitenant/port-forward-$safeService-$LocalPort.err.log"
    $arguments = @(
        "--kubeconfig", $kubeconfig,
        "--context", $context,
        "--namespace", $supportNamespace,
        "port-forward", $Service, "${LocalPort}:${RemotePort}",
        "--address", "127.0.0.1"
    )
    $process = Start-Process -FilePath $kubectl -ArgumentList $arguments -WindowStyle Hidden `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    $portForwards.Add($process)
    for ($attempt = 1; $attempt -le 60; $attempt++) {
        if ($process.HasExited) {
            throw "port-forward for $Service exited early; inspect $stderr"
        }
        if (Test-LoopbackPort -Port $LocalPort) {
            return
        }
        Start-Sleep -Milliseconds 500
    }
    throw "port-forward for $Service did not bind 127.0.0.1:$LocalPort"
}

function Stop-OwnedPortForwards {
    foreach ($process in $portForwards) {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -ErrorAction SilentlyContinue
            $process.WaitForExit(5000) | Out-Null
        }
        $process.Dispose()
    }
    $portForwards.Clear()
}

function Refresh-HpaDriverCredential {
    $token = & $kubectl --kubeconfig $kubeconfig --context $context `
        --namespace $hpaDriverNamespace create token $hpaDriverServiceAccount --duration=2h
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token)) {
        throw "HPA driver TokenRequest failed"
    }
    try {
        & $kubectl --kubeconfig $hpaDriverKubeconfig config set-credentials hpa-driver `
            --token=$($token.Trim()) | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "HPA driver kubeconfig credential update failed"
        }
    }
    finally {
        $token = $null
    }
    $actualSubject = & $kubectl --kubeconfig $hpaDriverKubeconfig --context $hpaDriverContext `
        auth whoami -o "jsonpath={.status.userInfo.username}"
    $expectedSubject = "system:serviceaccount:${hpaDriverNamespace}:${hpaDriverServiceAccount}"
    if ($LASTEXITCODE -ne 0 -or $actualSubject -ne $expectedSubject) {
        throw "HPA driver kubeconfig does not authenticate as its declared ServiceAccount"
    }
}

Invoke-Python -Arguments @(
    "-m", "scripts.release_context", "verify",
    "--private-context", $releaseContextPath,
    "--release-id", $releaseId,
    "--source-fingerprint", $fp,
    "--initial-digest", $releaseContextInitialDigest,
    "--upgrade-digest", $releaseContextUpgradeDigest
) -Failure "private release context verification failed"
$releaseContext = Get-Content -LiteralPath $releaseContextPath -Raw | ConvertFrom-Json
$env:TRPC_RELEASE_ID = [string]$releaseContext.release_id
$env:TRPC_RELEASE_NONCE = [string]$releaseContext.nonce

if ($StartStage -le 1 -and $EndStage -ge 1) {
    Write-Host "[1/8] Performance + external-metric HPA"
    & (Join-Path $PSScriptRoot "run-final-ack-performance.ps1")
    if ($LASTEXITCODE -ne 0) {
        throw "formal ACK Performance gate failed"
    }
}

Invoke-Python -Arguments @("scripts/candidate_lock.py", "verify") `
    -Failure "candidate lock verification failed before acceptance stage $StartStage"

if ($StartStage -le 2 -and $EndStage -ge 2) {
    Write-Host "[2/8] ACK Backend integration"
    try {
        Start-VerifiedPortForward -Service "service/postgres" -LocalPort 35432 -RemotePort 5432
        Start-VerifiedPortForward -Service "service/redis" -LocalPort 36379 -RemotePort 6379
        Start-VerifiedPortForward -Service "service/minio" -LocalPort 39000 -RemotePort 9000
        Invoke-Python -Arguments @(
            "runs/multitenant/run-ack-backend-gate.py",
            "--secret-manifest", $secretManifest,
            "--image-digest", $candidateDigest,
            "--output", "runs/multitenant/backend-ack.json"
        ) -Failure "ACK Backend integration failed; port-forward logs were retained"
    }
    finally {
        Stop-OwnedPortForwards
    }
}

if ($StartStage -le 3 -and $EndStage -ge 3) {
    Write-Host "[3/8] Kubernetes runtime + HPA/drain/upgrade"
    Refresh-HpaDriverCredential
    $drainPatch = Join-Path $projectRoot "runs/multitenant/backlog-exporter-workload-node-patch.yaml"
    & $kubectl --kubeconfig $kubeconfig --context $context --namespace $serviceNamespace `
        patch deployment/trpc-backlog-exporter --type strategic --patch-file $drainPatch
    if ($LASTEXITCODE -ne 0) {
        throw "backlog exporter could not be moved off the dedicated drain node"
    }
    & $kubectl --kubeconfig $kubeconfig --context $context --namespace $serviceNamespace `
        rollout status deployment/trpc-backlog-exporter --timeout=300s
    if ($LASTEXITCODE -ne 0) {
        throw "backlog exporter did not become ready on the workload node"
    }
    $migrationJob = & $kubectl --kubeconfig $kubeconfig --context $context `
        --namespace $serviceNamespace get job/trpc-schema-migration --ignore-not-found -o name
    if ($LASTEXITCODE -ne 0) {
        throw "schema migration Job state could not be observed"
    }
    if (-not [string]::IsNullOrWhiteSpace($migrationJob)) {
        & $kubectl --kubeconfig $kubeconfig --context $context --namespace $serviceNamespace `
            wait --for=condition=complete job/trpc-schema-migration --timeout=60s
        if ($LASTEXITCODE -ne 0) {
            throw "schema migration Job is not complete and cannot be safely removed"
        }
        & $kubectl --kubeconfig $kubeconfig --context $context --namespace $serviceNamespace `
            delete job/trpc-schema-migration --wait=true
        if ($LASTEXITCODE -ne 0) {
            throw "completed schema migration Job could not be removed from the drain node"
        }
    }
    # Stage 1 pins the performance topology at exactly four workers.  Restore
    # the production HPA range before asking Stage 3 to prove a live scale-up.
    $productionHpaManifest = Join-Path $projectRoot "deploy/kustomize/base/autoscaling.yaml"
    & $kubectl --kubeconfig $kubeconfig --context $context --namespace $serviceNamespace `
        apply -f $productionHpaManifest
    if ($LASTEXITCODE -ne 0) {
        throw "production HPA bounds could not be restored after the performance stage"
    }
    $workerHpaBounds = & $kubectl --kubeconfig $kubeconfig --context $context `
        --namespace $serviceNamespace get hpa/trpc-worker `
        -o "jsonpath={.spec.minReplicas}:{.spec.maxReplicas}"
    if ($LASTEXITCODE -ne 0 -or $workerHpaBounds -ne "2:20") {
        throw "worker HPA does not expose the production 2..20 replica range"
    }
    $env:TRPC_K8S_RUNTIME_TESTS_ENABLED = "true"
    Invoke-Python -Arguments @(
        "-m", "scripts.kubernetes_runtime_gate",
        "--config", "deploy/runtime-gate.yaml",
        "--preflight-output", "runs/multitenant/deployment-preflight.json",
        "--output", "runs/multitenant/kubernetes-runtime.json",
        "--require-runtime"
    ) -Failure "Kubernetes runtime gate failed; cluster evidence was retained"
}

if ($StartStage -le 4 -and $EndStage -ge 4) {
    Write-Host "[4/8] Zero-cost functional disaster recovery"
    $env:TRPC_DR_FUNCTIONAL_ENABLED = "true"
    Invoke-Python -Arguments @(
        "-m", "scripts.kubernetes_functional_disaster_recovery",
        "--config", "deploy/runtime-gate.yaml",
        "--output", "runs/multitenant/disaster-recovery-functional.json",
        "--timeout-seconds", "600",
        "--max-rto-seconds", "300",
        "--require-functional"
    ) -Failure "functional disaster recovery gate failed; evidence was retained"
}

if ($StartStage -le 5 -and $EndStage -ge 5) {
    Write-Host "[5/8] Compose Backend + Runtime"
    . (Join-Path $PSScriptRoot "run-final-runtime-gates.ps1")
}

if ($StartStage -le 6 -and $EndStage -ge 6) {
    Write-Host "[6/8] Production Migration"
    . (Join-Path $PSScriptRoot "run-e5b583a0-migration.ps1")
}

if ($StartStage -le 7 -and $EndStage -ge 7) {
    Write-Host "[7/8] Fault injection"
    . (Join-Path $PSScriptRoot "run-final-fault-gate.ps1")
}

if ($StartStage -le 8 -and $EndStage -ge 8) {
    Write-Host "[8/8] Release manifest + aggregate release gate"
    $manifestPath = Join-Path "runs/multitenant" "release-manifest.json"
    if (Test-Path -LiteralPath $manifestPath) {
        $manifestItem = Get-Item -LiteralPath $manifestPath -Force
        if ($manifestItem.PSIsContainer) {
            throw "release manifest path is not a regular file"
        }
        if (($manifestItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "release manifest path is a symlink or reparse point"
        }
        $archiveName = "release-manifest.preflight-{0}-{1}.json" -f `
            (Get-Date -Format "yyyyMMdd-HHmmssfff"),
            ([guid]::NewGuid().ToString("N"))
        $manifestArchivePath = Join-Path "runs/multitenant" $archiveName
        Move-Item -LiteralPath $manifestPath -Destination $manifestArchivePath -ErrorAction Stop
        Write-Output ("RELEASE_MANIFEST_ARCHIVED path={0} backup={1}" -f $manifestPath, $manifestArchivePath)
    }

    # The first aggregate is intentionally non-blocking for production.  It
    # provides the honest current-candidate status used to decide whether an
    # external gate was omitted or whether a required gate actually failed.
    & $python scripts/release_gate.py `
        --directory runs/multitenant `
        --output runs/multitenant/release-gate-current-final.json
    $preflightExit = $LASTEXITCODE
    if ($preflightExit -ne 0) {
        throw "aggregate release preflight failed to run"
    }
    $preflightPath = Join-Path "runs/multitenant" "release-gate-current-final.json"
    if (-not (Test-Path -LiteralPath $preflightPath -PathType Leaf)) {
        throw "aggregate release preflight report is missing"
    }
    $preflight = Get-Content -LiteralPath $preflightPath -Raw | ConvertFrom-Json
    if ($null -eq $preflight.candidate) {
        throw "aggregate release preflight candidate statuses are missing"
    }
    $candidateProperties = @($preflight.candidate.PSObject.Properties)
    $invalidStatuses = @(
        $candidateProperties |
            Where-Object { [string]$_.Value -notin @("pass", "not_run", "fail") } |
            ForEach-Object { $_.Name }
    )
    $failedGates = @(
        $candidateProperties |
            Where-Object { [string]$_.Value -eq "fail" } |
            ForEach-Object { $_.Name }
    )
    $allowedNotRun = @("online_im", "disaster_recovery", "release_bundle")
    $notRunGates = @(
        $candidateProperties |
            Where-Object { [string]$_.Value -eq "not_run" } |
            ForEach-Object { $_.Name }
    )
    $unexpectedNotRun = @(
        $notRunGates | Where-Object { $_ -notin $allowedNotRun }
    )
    if ($invalidStatuses.Count -gt 0) {
        throw ("aggregate release preflight has invalid statuses: {0}" -f ($invalidStatuses -join ", "))
    }
    if ($failedGates.Count -gt 0) {
        throw ("aggregate release preflight has failed gates: {0}" -f ($failedGates -join ", "))
    }
    if ($unexpectedNotRun.Count -gt 0) {
        throw ("aggregate release preflight has unexpected not_run gates: {0}" -f ($unexpectedNotRun -join ", "))
    }

    $externalNotRun = @(
        "online_im", "disaster_recovery" |
            Where-Object {
                $gateName = [string]$_
                [string]$preflight.candidate.PSObject.Properties[$gateName].Value -eq "not_run"
            }
    )
    if ($externalNotRun.Count -gt 0) {
        if ([string]$preflight.gate -ne "not_run") {
            throw "aggregate release preflight did not remain not_run with external gates disabled"
        }
        Write-Output ("RELEASE_STAGE8_RESULT gate=not_run production_manifest=not_generated external_not_run={0}" -f ($externalNotRun -join ","))
    }
    else {
        $nonBundleNotPass = @(
            $candidateProperties |
                Where-Object { $_.Name -ne "release_bundle" -and [string]$_.Value -ne "pass" } |
                ForEach-Object { $_.Name }
        )
        if ($nonBundleNotPass.Count -gt 0) {
            throw ("aggregate release preflight has non-bundle gates that are not pass: {0}" -f ($nonBundleNotPass -join ", "))
        }

        & $python scripts/release_manifest.py `
            --directory runs/multitenant `
            --image-digest $candidateDigest `
            --output $manifestPath
        $manifestExit = $LASTEXITCODE
        if ($manifestExit -ne 0) {
            throw "release manifest generation failed after all requested gates completed"
        }
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw "release manifest generation produced no manifest"
        }

        & $python scripts/release_gate.py `
            --directory runs/multitenant `
            --output runs/multitenant/release-gate-current-final.json `
            --require-production
        $releaseExit = $LASTEXITCODE
        if ($releaseExit -ne 0) {
            throw "aggregate release gate remains blocked; inspect release-gate-current-final.json"
        }
        Write-Output "RELEASE_STAGE8_RESULT gate=pass production_manifest=generated"
    }

    foreach ($name in @(
        "real-performance.json",
        "backend-ack.json",
        "backend-compose.json",
        "real-runtime.json",
        "migration-live.json",
        "fault-injection.json",
        "kubernetes-runtime.json",
        "disaster-recovery.json",
        "disaster-recovery-functional.json",
        "coverage-gate.json",
        "release-gate-current-final.json"
    )) {
        $path = Join-Path "runs/multitenant" $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Write-Output "$name`: missing"
            continue
        }
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $productionGate = "n/a"
        $productionGateProperty = $report.PSObject.Properties["production_gate"]
        if ($null -ne $productionGateProperty) {
            $productionGate = [string]$productionGateProperty.Value
        }
        Write-Output ("{0}: gate={1} production_gate={2}" -f $name, $report.gate, $productionGate)
    }
}
