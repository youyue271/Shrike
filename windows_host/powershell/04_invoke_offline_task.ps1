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

    # Wait for snapshot restore to complete
    Start-Sleep -Seconds 5

    Remove-OfflineArtifactDisk -VmName $VmName -ArtifactDiskPath $ArtifactDiskPath -LogPath $logPath

    $systemDisk = Get-PrimarySystemDisk -VmName $VmName -ArtifactDiskPath $ArtifactDiskPath -LogPath $logPath

    # Set ISO on ALL DVD drives to ensure it's accessible
    $dvdDrives = @(Get-VMDvdDrive -VMName $VmName -ErrorAction SilentlyContinue)
    if ($dvdDrives.Count -eq 0) {
        Add-VMDvdDrive -VMName $VmName -Path $SampleIsoPath -ErrorAction Stop | Out-Null
        Write-Log -Message ("Added sample ISO to new DVD device: {0}" -f $SampleIsoPath) -LogPath $logPath
    } else {
        foreach ($dvd in $dvdDrives) {
            $dvd | Set-VMDvdDrive -Path $SampleIsoPath -ErrorAction Stop
        }
        Write-Log -Message ("Updated {0} DVD device(s) with sample ISO: {1}" -f $dvdDrives.Count, $SampleIsoPath) -LogPath $logPath
    }

    # Verify at least one DVD drive has ISO attached
    $dvdVerify = Get-VMDvdDrive -VMName $VmName | Where-Object { $_.Path -eq $SampleIsoPath }
    if (-not $dvdVerify) {
        throw "Failed to attach sample ISO to DVD drive"
    }

    # Add artifact disk - let Hyper-V choose the controller location automatically
    Add-VMHardDiskDrive -VMName $VmName -Path $ArtifactDiskPath -ErrorAction Stop | Out-Null
    Write-Log -Message ("Attached artifact disk: {0}" -f $ArtifactDiskPath) -LogPath $logPath

    # Verify artifact disk is attached
    $artifactVerify = Get-VMHardDiskDrive -VMName $VmName | Where-Object { $_.Path -eq $ArtifactDiskPath }
    if (-not $artifactVerify) {
        throw "Failed to attach artifact disk"
    }

    Set-OfflineTaskBootOrder -VmName $VmName -SystemDisk $systemDisk -LogPath $logPath

    Start-VM -Name $VmName | Out-Null
    Write-Log -Message ("Started VM {0}" -f $VmName) -LogPath $logPath

    # Wait for VM to boot and then refresh CD-ROM drives to force media detection
    Start-Sleep -Seconds 15
    try {
        $guestCred = New-Object System.Management.Automation.PSCredential("root", (ConvertTo-SecureString "root" -AsPlainText -Force))
        Invoke-Command -VMName $VmName -Credential $guestCred -ScriptBlock {
            # Force CD-ROM refresh
            $drives = Get-WmiObject Win32_CDROMDrive
            foreach ($drive in $drives) {
                try {
                    $drive.Drive | Out-Null
                } catch {}
            }
        } -ErrorAction SilentlyContinue
        Write-Log -Message "Refreshed CD-ROM drives in guest" -LogPath $logPath
    } catch {
        Write-Log -Message ("CD-ROM refresh failed: {0}" -f $_.Exception.Message) -LogPath $logPath -Level "WARN"
    }

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
