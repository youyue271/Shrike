# Intel PT trace backend for Shrike sandbox
# Uses Windows Performance Recorder (WPR) with Intel PT provider

param(
    [Parameter(Mandatory=$true)]
    [string]$SamplePath,

    [Parameter(Mandatory=$true)]
    [string]$OutputDir,

    [Parameter(Mandatory=$false)]
    [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = "Stop"

# Check if Intel PT is available
$ptSupport = (Get-WmiObject -Class Win32_Processor | Select-Object -First 1).Caption
Write-Host "[INFO] Processor: $ptSupport"

# Create WPR profile for Intel PT
$wprProfile = @"
<?xml version="1.0" encoding="utf-8"?>
<WindowsPerformanceRecorder Version="1.0">
  <Profiles>
    <SystemCollector Id="SystemCollector" Name="NT Kernel Logger">
      <BufferSize Value="1024"/>
      <Buffers Value="80"/>
    </SystemCollector>
    <Profile Id="IntelPT.Verbose.File" Name="IntelPT" Description="Intel PT Trace" LoggingMode="File" DetailLevel="Verbose">
      <Collectors>
        <SystemCollectorId Value="SystemCollector">
          <SystemProviderId Value="IntelPT-Provider"/>
        </SystemCollectorId>
      </Collectors>
    </Profile>
  </Profiles>
</WindowsPerformanceRecorder>
"@

$profilePath = Join-Path $env:TEMP "intelpt_profile.wprp"
$wprProfile | Out-File -FilePath $profilePath -Encoding utf8

# Start WPR recording
$etlPath = Join-Path $OutputDir "intelpt_trace.etl"
Write-Host "[INFO] Starting Intel PT recording..."
wpr.exe -start $profilePath -filemode

# Launch sample
Write-Host "[INFO] Launching sample: $SamplePath"
$process = Start-Process -FilePath $SamplePath -PassThru -WindowStyle Hidden

# Wait for execution window
Write-Host "[INFO] Waiting $TimeoutSeconds seconds..."
Start-Sleep -Seconds $TimeoutSeconds

# Stop sample if still running
if (!$process.HasExited) {
    Write-Host "[INFO] Stopping sample process..."
    Stop-Process -Id $process.Id -Force
}

# Stop WPR recording
Write-Host "[INFO] Stopping Intel PT recording..."
wpr.exe -stop $etlPath

Write-Host "[INFO] Trace saved to: $etlPath"
Write-Host "[INFO] Use 'xperf' or 'Windows Performance Analyzer' to decode the trace"
