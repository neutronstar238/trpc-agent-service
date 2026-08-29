param(
  [string]$Context = "kind-trpc-runtime-gate2",
  [int]$TimeoutSeconds = 900,
  [int]$NamespaceStartGraceSeconds = 60
)

$ErrorActionPreference = "Stop"
$startedAt = (Get-Date).ToUniversalTime()
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$namespaceStartFloor = $startedAt.AddSeconds(-1 * $NamespaceStartGraceSeconds)

function Write-WatcherLog {
  param([string]$Message)
  $line = "{0:o} {1}" -f ((Get-Date).ToUniversalTime()), $Message
  [Console]::Error.WriteLine($line)
}

function Convert-ToUniversalDateTime {
  param($Value)
  if ($Value -is [datetime]) {
    if ($Value.Kind -eq [DateTimeKind]::Unspecified) {
      return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc)
    }
    return $Value.ToUniversalTime()
  }
  if ($Value -is [datetimeoffset]) {
    return $Value.UtcDateTime
  }
  return [datetimeoffset]::Parse(
    [string]$Value,
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
  ).UtcDateTime
}

function Get-ManagedNamespaces {
  $json = kubectl --context $Context get namespace `
    -l trpc.io/managed-by=trpc-kubernetes-runtime-gate -o json
  if ($LASTEXITCODE -ne 0) {
    throw "managed namespace list failed with exit code $LASTEXITCODE"
  }
  $payload = $json | ConvertFrom-Json
  if ($null -eq $payload.items) { return @() }
  return @($payload.items)
}

Write-WatcherLog "started context=$Context timeout_seconds=$TimeoutSeconds namespace_grace_seconds=$NamespaceStartGraceSeconds"
$namespace = $null
$lastNamespaceCandidateCount = -1
while ((Get-Date) -lt $deadline -and -not $namespace) {
  try {
    $items = Get-ManagedNamespaces
    $candidates = @(
      foreach ($item in $items) {
        $metadata = $item.metadata
        if ($null -eq $metadata -or $metadata.deletionTimestamp) { continue }
      $created = Convert-ToUniversalDateTime $metadata.creationTimestamp
        if ($created -lt $namespaceStartFloor) { continue }
        [pscustomobject]@{
          Name = [string]$metadata.name
          CreationTimestamp = $created
          ManagedBy = [string]$metadata.labels.'trpc.io/managed-by'
        }
      }
    )
    if ($candidates.Count -ne $lastNamespaceCandidateCount) {
      Write-WatcherLog "namespace candidates=$($candidates.Count)"
      $lastNamespaceCandidateCount = $candidates.Count
    }
    $selected = $candidates | Sort-Object CreationTimestamp -Descending | Select-Object -First 1
    if ($null -ne $selected) {
      $namespace = $selected.Name
      Write-WatcherLog "namespace selected name=$namespace creation=$($selected.CreationTimestamp.ToString('o')) owner=$($selected.ManagedBy)"
    }
  } catch {
    Write-WatcherLog "namespace scan failed; retrying"
  }
  if (-not $namespace) { Start-Sleep -Seconds 1 }
}
if (-not $namespace) { throw "runtime namespace was not observed" }

$hpaObserved = $false
while ((Get-Date) -lt $deadline) {
  kubectl --context $Context get hpa trpc-worker -n $namespace *> $null
  if ($LASTEXITCODE -eq 0) {
    $hpaObserved = $true
    Write-WatcherLog "hpa observed namespace=$namespace"
    break
  }
  Start-Sleep -Seconds 1
}
if (-not $hpaObserved) { throw "HPA was not observed in selected namespace" }
$hpaPatch = '{"spec":{"metrics":[{"type":"External","external":{"metric":{"name":"trpc_session_ready_backlog"},"target":{"type":"AverageValue","averageValue":"25"}}}],"behavior":{"scaleDown":{"stabilizationWindowSeconds":0,"policies":[{"type":"Percent","value":100,"periodSeconds":15}],"selectPolicy":"Max"}}}}'
kubectl --context $Context patch hpa trpc-worker -n $namespace --type merge -p $hpaPatch | Out-Null
if ($LASTEXITCODE -ne 0) { throw "HPA patch failed in selected namespace" }
Write-WatcherLog "hpa patched namespace=$namespace metric=external_only"

$jobName = $null
$lastJobCandidateCount = -1
while ((Get-Date) -lt $deadline -and -not $jobName) {
  try {
    $jobJson = kubectl --context $Context get jobs -n $namespace `
      -l trpc.io/hpa-gate=bounded-job-driver -o json
    if ($LASTEXITCODE -ne 0) { throw "job list failed with exit code $LASTEXITCODE" }
    $jobs = $jobJson | ConvertFrom-Json
    $jobCandidates = @(
      foreach ($item in @($jobs.items)) {
        if ($null -ne $item.metadata -and $item.metadata.name) {
          [pscustomobject]@{
            Name = [string]$item.metadata.name
            CreationTimestamp = Convert-ToUniversalDateTime $item.metadata.creationTimestamp
          }
        }
      }
    )
    if ($jobCandidates.Count -ne $lastJobCandidateCount) {
      Write-WatcherLog "job candidates=$($jobCandidates.Count) namespace=$namespace"
      $lastJobCandidateCount = $jobCandidates.Count
    }
    $selectedJob = $jobCandidates |
      Sort-Object CreationTimestamp -Descending | Select-Object -First 1
    if ($null -ne $selectedJob) {
      $jobName = $selectedJob.Name
      Write-WatcherLog "job selected name=$jobName namespace=$namespace"
    }
  } catch {
    Write-WatcherLog "job scan failed; retrying"
  }
  if (-not $jobName) { Start-Sleep -Seconds 1 }
}
if (-not $jobName) { throw "bounded HPA job was not observed" }

$finalizerPatch = '{"metadata":{"finalizers":["trpc.io/hpa-observation"]}}'
kubectl --context $Context patch job $jobName -n $namespace --type merge -p $finalizerPatch | Out-Null
if ($LASTEXITCODE -ne 0) { throw "HPA job finalizer patch failed" }
Write-WatcherLog "job finalizer installed name=$jobName"

$deleting = $false
while ((Get-Date) -lt $deadline -and -not $deleting) {
  try {
    $jobJson = kubectl --context $Context get job $jobName -n $namespace -o json
    if ($LASTEXITCODE -ne 0) { throw "job get failed with exit code $LASTEXITCODE" }
    $job = $jobJson | ConvertFrom-Json
    $deleting = [bool]$job.metadata.deletionTimestamp
    if ($deleting) { Write-WatcherLog "job deletion observed name=$jobName" }
  } catch {
    Write-WatcherLog "job deletion observation failed; retrying"
  }
  if (-not $deleting) { Start-Sleep -Seconds 1 }
}
if (-not $deleting) { throw "bounded HPA job deletion was not observed" }

# The driver verifies deletion within a bounded 30-second window. Release the
# observation finalizer immediately after the API reports deletion so clear
# can complete instead of waiting behind this watcher.
$removePatch = '{"metadata":{"finalizers":[]}}'
kubectl --context $Context patch job $jobName -n $namespace --type merge -p $removePatch | Out-Null
if ($LASTEXITCODE -ne 0) { throw "HPA job finalizer removal failed" }
Write-WatcherLog "job finalizer removed name=$jobName"
"pass|$namespace|$jobName|metrics=external_only"
