param(
    [string]$SamplePath = "samples\8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2",
    [string]$TaskProfile = "sandbox\profiles\deep_cfg_drio_extended.json",
    [string]$ReportId = "",
    [int]$TimeoutSeconds = 600,
    [string]$VmName = "rw-sandbox-win10",
    [string]$SnapshotName = "analysis-base",
    [string]$ArtifactDiskPath = "sandbox_data\task_media\artifact-task.vhdx",
    [string]$SampleIsoPath = "sandbox_data\task_media\sample-task.iso",
    [string]$ArtifactStagingDir = "",
    [switch]$SkipParse,
    [switch]$DryRun
)

. "$PSScriptRoot\common.ps1"

function Convert-WslPathToWindows {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path -match "^/mnt/([A-Za-z])/(.*)$") {
        $drive = $Matches[1].ToUpperInvariant()
        $rest = $Matches[2].Replace("/", "\")
        return ("{0}:\{1}" -f $drive, $rest)
    }
    return $Path
}

function Convert-WindowsPathToWsl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full -match "^([A-Za-z]):\\(.*)$") {
        $drive = $Matches[1].ToLowerInvariant()
        $rest = $Matches[2].Replace("\", "/")
        return "/mnt/{0}/{1}" -f $drive, $rest
    }
    throw "Cannot convert non-drive Windows path to WSL path: $Path"
}

function Resolve-ProjectPathCompat {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RepoRoot
    )

    $normalized = Convert-WslPathToWindows -Path $Path
    return Resolve-ProjectPath -Path $normalized -RepoRoot $RepoRoot
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )

    Write-Host ""
    Write-Host ("==> {0}" -f $Label)
    & $Command
    $code = $LASTEXITCODE
    if ($null -ne $code -and $code -ne 0) {
        throw "$Label failed with exit code $code"
    }
}

function Invoke-RobocopyChecked {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    & robocopy $Source $Destination /E /B /R:1 /W:1 /NFL /NDL /NJH /NJS /NP
    $code = $LASTEXITCODE
    if ($code -gt 7) {
        throw "robocopy failed with exit code $code"
    }
    $global:LASTEXITCODE = 0
}

$repoRoot = Resolve-RepoRoot
$logPath = New-LogFilePath -ScriptName "12_run_sandbox_wrapped" -RepoRoot $repoRoot

$sample = Resolve-ProjectPathCompat -Path $SamplePath -RepoRoot $repoRoot
$taskProfilePath = Resolve-ProjectPathCompat -Path $TaskProfile -RepoRoot $repoRoot
$artifactDisk = Resolve-ProjectPathCompat -Path $ArtifactDiskPath -RepoRoot $repoRoot
$sampleIso = Resolve-ProjectPathCompat -Path $SampleIsoPath -RepoRoot $repoRoot

if (-not $ArtifactStagingDir) {
    $suffix = if ($ReportId) { $ReportId } else { "artifact_{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss") }
    $safeSuffix = ($suffix -replace "[^A-Za-z0-9_.-]", "_")
    $ArtifactStagingDir = Join-Path $repoRoot ("tmp\mounted_{0}" -f $safeSuffix)
}
$artifactStaging = Resolve-ProjectPathCompat -Path $ArtifactStagingDir -RepoRoot $repoRoot

$pythonWsl = Convert-WindowsPathToWsl -Path (Join-Path $repoRoot ".venv\bin\python")
$buildIsoWsl = Convert-WindowsPathToWsl -Path (Join-Path $repoRoot "sandbox\scripts\build_sample_iso.py")
$parseArtifactWsl = Convert-WindowsPathToWsl -Path (Join-Path $repoRoot "sandbox\scripts\parse_artifact.py")
$sampleWsl = Convert-WindowsPathToWsl -Path $sample
$taskProfileWsl = Convert-WindowsPathToWsl -Path $taskProfilePath
$sampleIsoWsl = Convert-WindowsPathToWsl -Path $sampleIso
$artifactStagingWsl = Convert-WindowsPathToWsl -Path $artifactStaging

$newArtifactScript = Join-Path $repoRoot "windows_host\powershell\03_new_artifact_disk.ps1"
$invokeTaskScript = Join-Path $repoRoot "windows_host\powershell\04_invoke_offline_task.ps1"
$mountArtifactScript = Join-Path $repoRoot "windows_host\powershell\05_mount_artifact_disk.ps1"

Write-Log -Message ("Sample={0}" -f $sample) -LogPath $logPath
Write-Log -Message ("TaskProfile={0}" -f $taskProfilePath) -LogPath $logPath
Write-Log -Message ("ReportId={0}" -f $(if ($ReportId) { $ReportId } else { "<auto>" })) -LogPath $logPath
Write-Log -Message ("TimeoutSeconds={0}" -f $TimeoutSeconds) -LogPath $logPath
Write-Log -Message ("ArtifactStagingDir={0}" -f $artifactStaging) -LogPath $logPath

if ($DryRun) {
    Write-Host ""
    Write-Host "Dry run resolved successfully."
    Write-Host ("Build ISO: wsl.exe -e {0} {1} {2} --output {3} --task-profile {4}" -f $pythonWsl, $buildIsoWsl, $sampleWsl, $sampleIsoWsl, $taskProfileWsl)
    Write-Host ("Invoke VM: {0} -VmName {1} -SnapshotName {2} -SampleIsoPath {3} -ArtifactDiskPath {4} -TimeoutSeconds {5}" -f $invokeTaskScript, $VmName, $SnapshotName, $sampleIso, $artifactDisk, $TimeoutSeconds)
    Write-Host ("Parse: wsl.exe -e {0} {1} {2}" -f $pythonWsl, $parseArtifactWsl, $artifactStagingWsl)
    exit 0
}

$mounted = $false
try {
    if (-not (Test-Path $sample)) {
        throw "Sample not found: $sample"
    }
    if (-not (Test-Path $taskProfilePath)) {
        throw "Task profile not found: $taskProfilePath"
    }

    Invoke-Checked -Label "Build sample ISO" -Command {
        & wsl.exe -e $pythonWsl $buildIsoWsl $sampleWsl "--output" $sampleIsoWsl "--task-profile" $taskProfileWsl
    }

    Invoke-Checked -Label "Create artifact VHDX" -Command {
        & $newArtifactScript -ArtifactDiskPath $artifactDisk
    }

    Invoke-Checked -Label "Run offline Hyper-V task" -Command {
        & $invokeTaskScript `
            -VmName $VmName `
            -SnapshotName $SnapshotName `
            -SampleIsoPath $sampleIso `
            -ArtifactDiskPath $artifactDisk `
            -TimeoutSeconds $TimeoutSeconds
    }

    Write-Host ""
    Write-Host "==> Mount artifact VHDX"
    $mountOutput = & $mountArtifactScript -ArtifactDiskPath $artifactDisk 2>&1
    $mountText = ($mountOutput | Out-String)
    Write-Host $mountText
    if ($LASTEXITCODE -ne 0) {
        throw "Mount artifact VHDX failed with exit code $LASTEXITCODE"
    }
    $mounted = $true

    $artifactPath = $null
    foreach ($line in $mountOutput) {
        $text = [string]$line
        if ($text -match "Artifact path:\s*(.+)$") {
            $artifactPath = $Matches[1].Trim()
            break
        }
    }
    if (-not $artifactPath) {
        throw "Failed to parse artifact path from mount output."
    }

    Write-Host ""
    Write-Host "==> Copy artifact files"
    Invoke-RobocopyChecked -Source $artifactPath -Destination $artifactStaging

    if (-not $SkipParse) {
        $parseArgs = @("-e", $pythonWsl, $parseArtifactWsl, $artifactStagingWsl)
        if ($ReportId) {
            $parseArgs += @("--report-id", $ReportId)
        }
        Invoke-Checked -Label "Parse artifact report" -Command {
            & wsl.exe @parseArgs
        }
    }

    Write-Host ""
    Write-Host "Sandbox run completed."
    Write-Host ("Artifact staging: {0}" -f $artifactStaging)
    if ($ReportId) {
        Write-Host ("Report directory: {0}" -f (Join-Path $repoRoot ("reports\{0}" -f $ReportId)))
    } elseif (-not $SkipParse) {
        Write-Host "Report directory: reports/<auto-generated id>"
    }
    Write-Host ("Log file: {0}" -f $logPath)
} finally {
    if ($mounted) {
        Dismount-VHD -Path $artifactDisk -ErrorAction SilentlyContinue
    }
}
