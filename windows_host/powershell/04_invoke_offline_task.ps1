param(
    [string]$VmName = "rw-sandbox-win10",
    [string]$SnapshotName = "analysis-base",
    [string]$BaseDiskPath = "sandbox_data\base_images\rw-sandbox-win10-base.vhdx",
    [Parameter(Mandatory = $true)]
    [string]$SampleIsoPath,
    [Parameter(Mandatory = $true)]
    [string]$ArtifactDiskPath,
    [int]$TimeoutSeconds = 300
)

. "$PSScriptRoot\common.ps1"

$repoRoot = Resolve-RepoRoot
$logPath = New-LogFilePath -ScriptName "04_invoke_offline_task" -RepoRoot $repoRoot
$BaseDiskPath = Resolve-ProjectPath -Path $BaseDiskPath -RepoRoot $repoRoot
$SampleIsoPath = Resolve-ProjectPath -Path $SampleIsoPath -RepoRoot $repoRoot
$ArtifactDiskPath = Resolve-ProjectPath -Path $ArtifactDiskPath -RepoRoot $repoRoot

try {
    Assert-Admin -LogPath $logPath
    Assert-HyperVAvailable -LogPath $logPath

    if (-not (Test-Path $SampleIsoPath)) {
        throw "Sample ISO not found: $SampleIsoPath"
    }
    if (-not (Test-Path $ArtifactDiskPath)) {
        throw "Artifact disk not found: $ArtifactDiskPath"
    }

    $vm = Get-VM -Name $VmName -ErrorAction Stop
    if ($vm.State -ne "Off") {
        throw "VM must be off before starting a task."
    }

    if ($vm.AutomaticCheckpointsEnabled) {
        Set-VM -Name $VmName -AutomaticCheckpointsEnabled $false
        Write-Log -Message "Disabled automatic checkpoints before task run." -LogPath $logPath -Level "WARN"
    }

    $snapshot = Get-VMSnapshot -VMName $VmName -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $SnapshotName } | Select-Object -First 1
    if (-not $snapshot) {
        throw "Snapshot '$SnapshotName' not found on VM '$VmName'. Refresh baselines with .\07_refresh_snapshots.ps1 -Force first."
    }

    Write-Log -Message ("Restoring snapshot {0} on VM {1}" -f $SnapshotName, $VmName) -LogPath $logPath
    Restore-VMSnapshot -VMName $VmName -Name $SnapshotName -Confirm:$false

    Remove-OfflineArtifactDisk -VmName $VmName -ArtifactDiskPath $ArtifactDiskPath -LogPath $logPath

    $systemDisk = Get-PrimarySystemDisk -VmName $VmName -ArtifactDiskPath $ArtifactDiskPath -LogPath $logPath

    $dvd = Get-VMDvdDrive -VMName $VmName -ErrorAction SilentlyContinue
    if (-not $dvd) {
        Add-VMDvdDrive -VMName $VmName -Path $SampleIsoPath | Out-Null
        Write-Log -Message ("Attached sample ISO to new DVD device: {0}" -f $SampleIsoPath) -LogPath $logPath
    } else {
        Set-VMDvdDrive -VMName $VmName -Path $SampleIsoPath | Out-Null
        Write-Log -Message ("Updated sample ISO on DVD device: {0}" -f $SampleIsoPath) -LogPath $logPath
    }

    Add-VMHardDiskDrive -VMName $VmName -Path $ArtifactDiskPath
    Write-Log -Message ("Attached artifact disk: {0}" -f $ArtifactDiskPath) -LogPath $logPath

    Set-OfflineTaskBootOrder -VmName $VmName -SystemDisk $systemDisk -LogPath $logPath

    Start-VM -Name $VmName | Out-Null
    Write-Log -Message ("Started VM {0}" -f $VmName) -LogPath $logPath

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 5
        $state = (Get-VM -Name $VmName).State
        Write-Log -Message ("Current VM state: {0}" -f $state) -LogPath $logPath
        if ($state -eq "Off") {
            break
        }
    } while ((Get-Date) -lt $deadline)

    $finalState = (Get-VM -Name $VmName).State
    if ($finalState -ne "Off") {
        Write-Log -Message ("Timeout reached. Forcing VM shutdown: {0}" -f $VmName) -LogPath $logPath -Level "WARN"
        Stop-VM -Name $VmName -TurnOff -Force
    }

    $taskDisk = Get-VMHardDiskDrive -VMName $VmName | Where-Object { $_.Path -eq $ArtifactDiskPath }
    if ($taskDisk) {
        Remove-VMHardDiskDrive -VMHardDiskDrive $taskDisk
        Write-Log -Message "Detached artifact disk from VM." -LogPath $logPath
    }

    Restore-VMSnapshot -VMName $VmName -Name $SnapshotName -Confirm:$false
    Write-Log -Message "Restored VM back to clean snapshot after task run." -LogPath $logPath

    Write-Log -Message "Offline task invocation completed." -LogPath $logPath
    Write-Host ("Log file: {0}" -f $logPath)
} catch {
    try {
        $vmState = (Get-VM -Name $VmName -ErrorAction SilentlyContinue).State
        if ($vmState -and $vmState -ne "Off") {
            Stop-VM -Name $VmName -TurnOff -Force -ErrorAction SilentlyContinue
        }
        $taskDisk = Get-VMHardDiskDrive -VMName $VmName -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $ArtifactDiskPath }
        if ($taskDisk) {
            Remove-VMHardDiskDrive -VMHardDiskDrive $taskDisk -ErrorAction SilentlyContinue
        }
        Restore-VMSnapshot -VMName $VmName -Name $SnapshotName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {}
    Write-Log -Message $_.Exception.Message -LogPath $logPath -Level "ERROR"
    Write-Host ("Log file: {0}" -f $logPath)
    throw
}
