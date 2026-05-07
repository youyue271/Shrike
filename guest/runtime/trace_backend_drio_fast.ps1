param(
    [Parameter(Mandatory = $true)]
    [string]$RequestPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [Parameter(Mandatory = $true)]
    [string]$SummaryPath
)

$ErrorActionPreference = "Stop"

# Fast mode: Just copy raw trace files without parsing
$request = Get-Content -Path $RequestPath -Raw -Encoding UTF8 | ConvertFrom-Json

$logDir = $request.logdir
if (-not $logDir) {
    $logDir = "C:\Sandbox\output\drio_logs"
}

# Create minimal summary
$summary = @{
    trace_mode = $request.trace_mode
    trace_backend = "drio"
    status = "raw_files_exported"
    message = "Raw trace files exported without parsing (fast mode)"
    sample_name = $request.sample_name
    launched_pid = $request.launched_pid
    started_at = $request.started_at
    ended_at = $request.ended_at
    logdir = $logDir
    raw_files = @()
}

# Copy all trace files to artifact directory
if (Test-Path $logDir) {
    $traceFiles = Get-ChildItem -Path $logDir -Filter "*.ndjson" -ErrorAction SilentlyContinue
    $artifactDir = Split-Path -Parent $OutputPath

    foreach ($file in $traceFiles) {
        $destPath = Join-Path $artifactDir $file.Name
        Copy-Item -Path $file.FullName -Destination $destPath -Force
        $summary.raw_files += $file.Name
    }
}

# Write minimal output and summary
"[]" | Set-Content -Path $OutputPath -Encoding UTF8
$summary | ConvertTo-Json -Depth 5 | Set-Content -Path $SummaryPath -Encoding UTF8

Write-Host "Fast trace backend completed. Raw files copied: $($summary.raw_files.Count)"
