param(
    [string]$VmName = "rw-sandbox-win10",
    [string]$AnalysisSnapshotName = "analysis-base",
    [string]$MaintenanceSnapshotName = "maintenance-base",
    [string]$TaskMediaRoot = "sandbox_data\task_media",
    [switch]$Force
)

. "$PSScriptRoot\common.ps1"

$repoRoot = Resolve-RepoRoot
$logPath = New-LogFilePath -ScriptName "07_refresh_snapshots" -RepoRoot $repoRoot
$TaskMediaRoot = Resolve-ProjectPath -Path $TaskMediaRoot -RepoRoot $repoRoot

try {
    Assert-Admin -LogPath $logPath
    Assert-HyperVAvailable -LogPath $logPath

    $vm = Get-VM -Name $VmName -ErrorAction Stop
    if ($vm.State -ne "Off") {
        throw "VM must be off before refreshing snapshots."
    }

    Set-VM -Name $VmName -AutomaticCheckpointsEnabled $false
    Write-Log -Message "Disabled automatic checkpoints before snapshot refresh." -LogPath $logPath

    Remove-TaskMediaDisks -VmName $VmName -TaskMediaRoot $TaskMediaRoot -LogPath $logPath
    Clear-VMDvdMedia -VmName $VmName -LogPath $logPath
    Dismount-TaskMediaVhds -TaskMediaRoot $TaskMediaRoot -LogPath $logPath

    $existing = @(Get-VMSnapshot -VMName $VmName -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) {
        if (-not $Force) {
            $names = $existing | Select-Object -ExpandProperty Name
            throw ("Existing snapshots detected: {0}. Re-run with -Force to rebuild the baseline set." -f ($names -join ", "))
        }

        foreach ($snapshot in ($existing | Sort-Object CreationTime -Descending)) {
            Write-Log -Message ("Removing existing snapshot: {0}" -f $snapshot.Name) -LogPath $logPath -Level "WARN"
            Remove-VMSnapshot -VMName $VmName -Name $snapshot.Name
        }
    }

    $staleDiffs = @(Get-TaskMediaDifferencingDisks -TaskMediaRoot $TaskMediaRoot)
    foreach ($staleDiff in $staleDiffs) {
        Write-Log -Message ("Stale task-media differencing disk detected: {0}" -f $staleDiff.FullName) -LogPath $logPath -Level "WARN"
    }
    if ($staleDiffs.Count -gt 0) {
        throw "Task-media differencing disks are still present under sandbox_data\\task_media. Delete those *.avhd* files before rebuilding snapshots."
    }

    Checkpoint-VM -Name $VmName -SnapshotName $AnalysisSnapshotName | Out-Null
    Write-Log -Message ("Created analysis snapshot: {0}" -f $AnalysisSnapshotName) -LogPath $logPath

    Checkpoint-VM -Name $VmName -SnapshotName $MaintenanceSnapshotName | Out-Null
    Write-Log -Message ("Created maintenance snapshot: {0}" -f $MaintenanceSnapshotName) -LogPath $logPath

    Write-Host ("Log file: {0}" -f $logPath)
} catch {
    Write-Log -Message $_.Exception.Message -LogPath $logPath -Level "ERROR"
    Write-Host ("Log file: {0}" -f $logPath)
    throw
}
