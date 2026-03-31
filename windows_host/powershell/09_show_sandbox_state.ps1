param(
    [string]$VmName = "rw-sandbox-win10",
    [string]$AnalysisSnapshotName = "analysis-base",
    [string]$MaintenanceSnapshotName = "maintenance-base",
    [string]$TaskMediaRoot = "sandbox_data\task_media",
    [string]$ArtifactDiskPath = "sandbox_data\task_media\artifact-task.vhdx"
)

. "$PSScriptRoot\common.ps1"

$repoRoot = Resolve-RepoRoot
$logPath = New-LogFilePath -ScriptName "09_show_sandbox_state" -RepoRoot $repoRoot
$TaskMediaRoot = Resolve-ProjectPath -Path $TaskMediaRoot -RepoRoot $repoRoot
$ArtifactDiskPath = Resolve-ProjectPath -Path $ArtifactDiskPath -RepoRoot $repoRoot

try {
    Assert-Admin -LogPath $logPath
    Assert-HyperVAvailable -LogPath $logPath

    $vm = Get-VM -Name $VmName -ErrorAction Stop
    $snapshots = @(Get-VMSnapshot -VMName $VmName -ErrorAction SilentlyContinue)
    $vmDisks = @(Get-VMHardDiskDrive -VMName $VmName -ErrorAction SilentlyContinue)
    $taskMediaDisks = @($vmDisks | Where-Object { $_.Path -and (Test-PathWithinRoot -CandidatePath $_.Path -RootPath $TaskMediaRoot) })
    $dvdDrives = @(Get-VMDvdDrive -VMName $VmName -ErrorAction SilentlyContinue)
    $dvdWithMedia = @($dvdDrives | Where-Object { $_.Path })
    $expectedSnapshots = @($AnalysisSnapshotName, $MaintenanceSnapshotName)
    $unexpectedSnapshots = @($snapshots | Where-Object { $_.Name -notin $expectedSnapshots })
    $staleDiffs = @(Get-TaskMediaDifferencingDisks -TaskMediaRoot $TaskMediaRoot)

    $artifactExists = Test-Path $ArtifactDiskPath
    $artifactAttached = $false
    if ($artifactExists) {
        $artifactVhd = Get-VHD -Path $ArtifactDiskPath -ErrorAction SilentlyContinue
        if ($artifactVhd) {
            $artifactAttached = [bool]$artifactVhd.Attached
        }
    }

    $analysisReady = (
        $vm.State -eq "Off" -and
        (-not $vm.AutomaticCheckpointsEnabled) -and
        ($snapshots.Name -contains $AnalysisSnapshotName) -and
        ($snapshots.Name -contains $MaintenanceSnapshotName) -and
        ($unexpectedSnapshots.Count -eq 0) -and
        ($taskMediaDisks.Count -eq 0) -and
        ($dvdWithMedia.Count -eq 0) -and
        ($staleDiffs.Count -eq 0)
    )

    Write-Log -Message ("VM state={0}; generation={1}; automaticCheckpoints={2}" -f $vm.State, $vm.Generation, $vm.AutomaticCheckpointsEnabled) -LogPath $logPath
    Write-Log -Message ("Snapshots={0}" -f (($snapshots | Select-Object -ExpandProperty Name) -join ", ")) -LogPath $logPath
    Write-Log -Message ("Task-media disks attached to VM={0}" -f $taskMediaDisks.Count) -LogPath $logPath
    Write-Log -Message ("DVD drives with media={0}" -f $dvdWithMedia.Count) -LogPath $logPath
    Write-Log -Message ("Stale task-media differencing disks={0}" -f $staleDiffs.Count) -LogPath $logPath
    Write-Log -Message ("Artifact VHD exists={0}; attached={1}" -f $artifactExists, $artifactAttached) -LogPath $logPath
    Write-Log -Message ("AnalysisReady={0}" -f $analysisReady) -LogPath $logPath

    [PSCustomObject]@{
        VmName = $vm.Name
        VmState = $vm.State.ToString()
        Generation = $vm.Generation
        AutomaticCheckpointsEnabled = [bool]$vm.AutomaticCheckpointsEnabled
        Snapshots = @($snapshots | Sort-Object CreationTime | Select-Object -ExpandProperty Name)
        ExpectedSnapshotsPresent = [PSCustomObject]@{
            Analysis = [bool]($snapshots.Name -contains $AnalysisSnapshotName)
            Maintenance = [bool]($snapshots.Name -contains $MaintenanceSnapshotName)
        }
        UnexpectedSnapshots = @($unexpectedSnapshots | Select-Object -ExpandProperty Name)
        AttachedVmDisks = @($vmDisks | ForEach-Object { $_.Path })
        AttachedTaskMediaDisks = @($taskMediaDisks | ForEach-Object { $_.Path })
        AttachedDvdMedia = @($dvdWithMedia | ForEach-Object { $_.Path })
        StaleTaskMediaDifferencingDisks = @($staleDiffs | ForEach-Object { $_.FullName })
        ArtifactDiskPath = $ArtifactDiskPath
        ArtifactDiskExists = [bool]$artifactExists
        ArtifactDiskAttachedOnHost = [bool]$artifactAttached
        AnalysisReady = [bool]$analysisReady
    } | ConvertTo-Json -Depth 6

    Write-Host ("Log file: {0}" -f $logPath)
} catch {
    Write-Log -Message $_.Exception.Message -LogPath $logPath -Level "ERROR"
    Write-Host ("Log file: {0}" -f $logPath)
    throw
}
