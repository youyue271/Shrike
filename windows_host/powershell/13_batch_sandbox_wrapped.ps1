param(
    [Parameter(Mandatory = $true)]
    [string]$SamplesDir,
    [string]$TaskProfile = "sandbox\profiles\deep_cfg_drio_extended.json",
    [string]$ResultsDir = "results",
    [int]$TimeoutSeconds = 600,
    [int]$WallTimeoutSeconds = 1500,
    [string]$VmName = "rw-sandbox-win10",
    [switch]$Force,
    [int]$Limit = 0
)

. "$PSScriptRoot\common.ps1"

$WhitelistRelative = @(
    "raw\dynamic_cfg_trace.ndjson",
    "raw\dynamic_cfg_trace_summary.json",
    "raw\trace_manifest.json",
    "raw\trace_request.json",
    "raw\trace_backend_diagnostic.json",
    "summary.json",
    "report.md",
    "raw\sample_metadata.json",
    "raw\task_profile.json",
    "raw\task_runtime_context.json",
    "raw\task_summary.json",
    "raw\runner.log",
    "raw\sysmon.evtx",
    "raw\sysmon_diagnostic.json",
    "raw\sysmon_summary.json",
    "raw\sysmon_process_events.json",
    "raw\sysmon_file_events.json",
    "raw\sysmon_network_dns_events.json",
    "raw\sysmon_registry_events.json",
    "raw\sysmon_injection_events.json",
    "raw\sysmon_ipc_wmi_events.json"
)

$IdaSidecarSuffixes = @(".i64", ".id0", ".id1", ".id2", ".nam", ".til", ".patched")
$HealthyTraceStatuses = @("control_flow_trace", "completed")
$TerminalDrrunFailurePatterns = @(
    "unable to load client library",
    "library initializer failed",
    "incompatible api version",
    "should be re-compiled",
    "wrong architecture",
    "registration failed with error code 15"
)

function Convert-WslPathToWindows {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path -match "^/mnt/([A-Za-z])/(.*)$") {
        $drive = $Matches[1].ToUpperInvariant()
        $rest = $Matches[2].Replace("/", "\")
        return ("{0}:\{1}" -f $drive, $rest)
    }
    return $Path
}

function Resolve-ProjectPathCompat {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RepoRoot
    )

    $normalized = Convert-WslPathToWindows -Path $Path
    return Resolve-ProjectPath -Path $normalized -RepoRoot $RepoRoot
}

function ConvertTo-JsonLine {
    param($InputObject)

    return ($InputObject | ConvertTo-Json -Depth 8 -Compress)
}

function Get-ProfileName {
    param([string]$Path)

    try {
        $profile = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($profile.profile_name) {
            return [string]$profile.profile_name
        }
    } catch {}
    return [System.IO.Path]::GetFileNameWithoutExtension($Path)
}

function Get-ProfileIntValue {
    param(
        $Profile,
        [string]$Name,
        [int]$Default = 0
    )

    try {
        $prop = $Profile.PSObject.Properties[$Name]
        if (-not $prop) {
            return $Default
        }
        $value = [int]$prop.Value
        if ($value -lt 0) {
            return $Default
        }
        return $value
    } catch {
        return $Default
    }
}

function Get-RecommendedTimeoutSeconds {
    param([string]$Path)

    try {
        $profile = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        return 600
    }

    $traceMode = if ($profile.trace_mode) { [string]$profile.trace_mode } else { "none" }
    $traceBackend = if ($profile.trace_backend) { [string]$profile.trace_backend } else { "none" }
    $traceModeSlack = if ($traceMode -eq "dynamic_cfg") { 60 } else { 0 }
    $traceBackendSlack = if ($traceBackend -eq "drio") { 60 } else { 0 }

    $recommended = 60 `
        + (Get-ProfileIntValue -Profile $profile -Name "boot_stabilization_seconds") `
        + (Get-ProfileIntValue -Profile $profile -Name "execution_window_seconds") `
        + (Get-ProfileIntValue -Profile $profile -Name "trace_processing_timeout_seconds") `
        + 120 `
        + $traceModeSlack `
        + $traceBackendSlack

    return [Math]::Max(600, $recommended)
}

function Test-SampleCandidate {
    param([System.IO.FileInfo]$File)

    if (-not $File -or -not $File.Exists) {
        return $false
    }
    if ($File.Name.StartsWith(".")) {
        return $false
    }
    if ($IdaSidecarSuffixes -contains $File.Extension.ToLowerInvariant()) {
        return $false
    }
    return ($File.Length -gt 0)
}

function Get-SampleFiles {
    param([string]$Root)

    $files = Get-ChildItem -Path $Root -File -Recurse -Force | Where-Object { Test-SampleCandidate -File $_ } | Sort-Object FullName
    if ($Limit -gt 0) {
        return @($files | Select-Object -First $Limit)
    }
    return @($files)
}

function Get-DrrunStderrHint {
    param([string]$ReportDir)

    $stderrPath = Join-Path $ReportDir "raw\drrun_stderr.txt"
    if (-not (Test-Path $stderrPath)) {
        return $null
    }
    $lines = @(Get-Content -Path $stderrPath -Encoding UTF8 -ErrorAction SilentlyContinue | Where-Object { $_.Trim() })
    foreach ($line in $lines) {
        $lower = $line.ToLowerInvariant()
        if ($lower.Contains("incompatible api version") -or $lower.Contains("should be re-compiled")) {
            return $line.Trim()
        }
    }
    if ($lines.Count -gt 0) {
        return $lines[-1].Trim()
    }
    return $null
}

function Test-TraceHealth {
    param([string]$ReportDir)

    $tracePath = Join-Path $ReportDir "raw\dynamic_cfg_trace.ndjson"
    if (-not (Test-Path $tracePath)) {
        return [PSCustomObject]@{ Healthy = $false; Detail = "dynamic_cfg_trace.ndjson missing" }
    }

    $manifestPath = Join-Path $ReportDir "raw\trace_manifest.json"
    if (-not (Test-Path $manifestPath)) {
        return [PSCustomObject]@{ Healthy = $false; Detail = "trace_manifest.json missing" }
    }

    try {
        $manifest = Get-Content -Path $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $status = [string]$manifest.status
    } catch {
        return [PSCustomObject]@{ Healthy = $false; Detail = ("trace_manifest unreadable: {0}" -f $_.Exception.Message) }
    }

    if ($HealthyTraceStatuses -contains $status) {
        return [PSCustomObject]@{ Healthy = $true; Detail = $status }
    }

    $detail = "trace_status=$status"
    $stderrHint = Get-DrrunStderrHint -ReportDir $ReportDir
    if ($stderrHint) {
        $detail = "$detail drrun_stderr=$stderrHint"
    }
    return [PSCustomObject]@{ Healthy = $false; Detail = $detail }
}

function Test-TerminalDrrunFailure {
    param([string]$Detail)

    if (-not $Detail) {
        return $false
    }
    $lower = $Detail.ToLowerInvariant()
    if (-not $lower.Contains("drrun_stderr=")) {
        return $false
    }
    foreach ($pattern in $TerminalDrrunFailurePatterns) {
        if ($lower.Contains($pattern)) {
            return $true
        }
    }
    return $false
}

function Get-ExistingHealthyRuns {
    param(
        [string]$ResultsRoot,
        [string]$Key
    )

    $base = Join-Path $ResultsRoot $Key
    if (-not (Test-Path $base)) {
        return @()
    }

    $runs = foreach ($dir in (Get-ChildItem -Path $base -Directory -Force | Sort-Object Name)) {
        $health = Test-TraceHealth -ReportDir $dir.FullName
        if ($health.Healthy) {
            $dir
        }
    }
    return @($runs)
}

function Copy-WhitelistedArtifacts {
    param(
        [string]$ReportDir,
        [string]$Destination
    )

    $copied = New-Object System.Collections.Generic.List[string]
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($relative in $WhitelistRelative) {
        $source = Join-Path $ReportDir $relative
        if (-not (Test-Path $source)) {
            $missing.Add($relative.Replace("\", "/"))
            continue
        }
        $target = Join-Path $Destination $relative
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
        Copy-Item -Path $source -Destination $target -Force
        $copied.Add($relative.Replace("\", "/"))
    }

    return [PSCustomObject]@{ Copied = @($copied); Missing = @($missing) }
}

function Get-TailText {
    param(
        [string]$Path,
        [int]$LineCount = 40
    )

    if (-not (Test-Path $Path)) {
        return ""
    }
    return ((Get-Content -Path $Path -Tail $LineCount -ErrorAction SilentlyContinue) -join "`n")
}

function Invoke-SandboxWrapperProcess {
    param(
        [string]$WrapperScript,
        [string]$SamplePath,
        [string]$TaskProfilePath,
        [string]$ReportId,
        [int]$TimeoutSeconds,
        [int]$WallTimeoutSeconds,
        [string]$TempRoot
    )

    New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null
    $runId = [System.Guid]::NewGuid().ToString("N")
    $commandPath = Join-Path $TempRoot ("batch_run_{0}.ps1" -f $runId)
    $stdoutPath = Join-Path $TempRoot ("batch_run_{0}.stdout.log" -f $runId)
    $stderrPath = Join-Path $TempRoot ("batch_run_{0}.stderr.log" -f $runId)

    $command = @(
        '$ErrorActionPreference = "Stop"',
        ('& "{0}" -SamplePath "{1}" -TaskProfile "{2}" -ReportId "{3}" -TimeoutSeconds {4}' -f $WrapperScript, $SamplePath, $TaskProfilePath, $ReportId, $TimeoutSeconds),
        'exit $LASTEXITCODE'
    )
    Set-Content -Path $commandPath -Value ($command -join "`r`n") -Encoding ASCII

    $proc = Start-Process -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $commandPath) `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath

    if (-not $proc.WaitForExit($WallTimeoutSeconds * 1000)) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        return [PSCustomObject]@{
            ExitCode = $null
            TimedOut = $true
            StdoutPath = $stdoutPath
            StderrPath = $stderrPath
        }
    }

    return [PSCustomObject]@{
        ExitCode = $proc.ExitCode
        TimedOut = $false
        StdoutPath = $stdoutPath
        StderrPath = $stderrPath
    }
}

$repoRoot = Resolve-RepoRoot
$samplesRoot = Resolve-ProjectPathCompat -Path $SamplesDir -RepoRoot $repoRoot
$taskProfilePath = Resolve-ProjectPathCompat -Path $TaskProfile -RepoRoot $repoRoot
$resultsRoot = Resolve-ProjectPathCompat -Path $ResultsDir -RepoRoot $repoRoot
$wrapperScript = Join-Path $repoRoot "windows_host\powershell\12_run_sandbox_wrapped.ps1"
$tempRoot = Join-Path $repoRoot "tmp\batch_wrapper"

if (-not (Test-Path $samplesRoot -PathType Container)) {
    throw "SamplesDir not found: $samplesRoot"
}
if (-not (Test-Path $taskProfilePath -PathType Leaf)) {
    throw "TaskProfile not found: $taskProfilePath"
}

New-Item -ItemType Directory -Force -Path $resultsRoot | Out-Null
$manifestPath = Join-Path $resultsRoot "batch_manifest.jsonl"
$errorsPath = Join-Path $resultsRoot "batch_errors.jsonl"
$profileName = Get-ProfileName -Path $taskProfilePath
$recommendedTimeoutSeconds = Get-RecommendedTimeoutSeconds -Path $taskProfilePath
$effectiveTimeoutSeconds = [Math]::Max($TimeoutSeconds, $recommendedTimeoutSeconds)
$effectiveWallTimeoutSeconds = [Math]::Max($WallTimeoutSeconds, ($effectiveTimeoutSeconds + 300))
if ($TimeoutSeconds -lt $recommendedTimeoutSeconds) {
    Write-Host (
        "requested TimeoutSeconds={0} is below profile budget {1}; using {2}" -f
        $TimeoutSeconds,
        $recommendedTimeoutSeconds,
        $effectiveTimeoutSeconds
    )
}
$samples = @(Get-SampleFiles -Root $samplesRoot)

Write-Host ("discovered {0} candidate files under {1}" -f $samples.Count, $samplesRoot)

$counts = @{ completed = 0; failed = 0; skipped = 0 }
$index = 0
foreach ($sample in $samples) {
    $index += 1
    Write-Host ""
    Write-Host ("[{0}/{1}] {2}" -f $index, $samples.Count, $sample.FullName.Substring($samplesRoot.Length).TrimStart("\"))

    $sha = (Get-FileHash -Path $sample.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $sha12 = $sha.Substring(0, 12)
    $key = "{0}_{1}" -f $profileName, $sha12

    if (-not $Force) {
        $runs = @(Get-ExistingHealthyRuns -ResultsRoot $resultsRoot -Key $key)
        if ($runs.Count -gt 0) {
            $counts.skipped += 1
            Write-Host ("  -> skipped (prior result: {0})" -f $runs[-1].Name)
            continue
        }
    }

    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $reportId = "{0}_{1}" -f $key, $timestamp
    $reportDir = Join-Path $repoRoot ("reports\{0}" -f $reportId)
    $errorMessage = $null
    $lastRun = $null
    $attemptsUsed = 0
    $startedAt = Get-Date

    foreach ($attempt in 1, 2) {
        $attemptsUsed = $attempt
        if ($attempt -eq 2) {
            Stop-VM -Name $VmName -TurnOff -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
        }

        $lastRun = Invoke-SandboxWrapperProcess `
            -WrapperScript $wrapperScript `
            -SamplePath $sample.FullName `
            -TaskProfilePath $taskProfilePath `
            -ReportId $reportId `
            -TimeoutSeconds $effectiveTimeoutSeconds `
            -WallTimeoutSeconds $effectiveWallTimeoutSeconds `
            -TempRoot $tempRoot

        if ($lastRun.TimedOut) {
            $errorMessage = "wall_timeout_${effectiveWallTimeoutSeconds}s"
            Stop-VM -Name $VmName -TurnOff -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
            continue
        }

        $health = Test-TraceHealth -ReportDir $reportDir
        if ($health.Healthy) {
            $duration = [Math]::Round(((Get-Date) - $startedAt).TotalSeconds, 2)
            $dest = Join-Path (Join-Path $resultsRoot $key) $timestamp
            New-Item -ItemType Directory -Force -Path $dest | Out-Null
            $copyResult = Copy-WhitelistedArtifacts -ReportDir $reportDir -Destination $dest

            Add-Content -Path $manifestPath -Encoding UTF8 -Value (ConvertTo-JsonLine ([ordered]@{
                status = "completed"
                sample_path = $sample.FullName
                sample_sha256 = $sha
                sample_size = $sample.Length
                profile = $profileName
                stable_key = $key
                report_id = $reportId
                report_dir = $reportDir
                result_dir = $dest
                timestamp_utc = $timestamp
                duration_seconds = $duration
                attempts = $attempt
                wrapper_exit_code = $lastRun.ExitCode
                trace_status = $health.Detail
                whitelist_copied = $copyResult.Copied
                whitelist_missing = $copyResult.Missing
            }))
            $counts.completed += 1
            Write-Host ("  -> completed in {0}s (attempts={1}) key={2}" -f [int]$duration, $attempt, $reportId)
            $errorMessage = $null
            break
        }

        $errorMessage = "exit={0} health={1}" -f $lastRun.ExitCode, $health.Detail
        if (Test-TerminalDrrunFailure -Detail $errorMessage) {
            break
        }
    }

    if ($errorMessage) {
        $duration = [Math]::Round(((Get-Date) - $startedAt).TotalSeconds, 2)
        Add-Content -Path $errorsPath -Encoding UTF8 -Value (ConvertTo-JsonLine ([ordered]@{
            status = "failed"
            sample_path = $sample.FullName
            sample_sha256 = $sha
            profile = $profileName
            stable_key = $key
            report_id = $reportId
            timestamp_utc = $timestamp
            duration_seconds = $duration
            attempts = $attemptsUsed
            error = $errorMessage
            stdout_tail = if ($lastRun) { Get-TailText -Path $lastRun.StdoutPath } else { "" }
            stderr_tail = if ($lastRun) { Get-TailText -Path $lastRun.StderrPath } else { "" }
        }))
        $counts.failed += 1
        Write-Host ("  -> FAILED ({0})" -f $errorMessage)
    }
}

Write-Host ""
Write-Host ("batch done: completed={0} failed={1} skipped={2}" -f $counts.completed, $counts.failed, $counts.skipped)
Write-Host ("manifest: {0}" -f $manifestPath)
Write-Host ("errors:   {0}" -f $errorsPath)

if ($counts.failed -gt 0) {
    exit 1
}
exit 0
