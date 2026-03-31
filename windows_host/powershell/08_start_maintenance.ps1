param(
    [string]$VmName = "rw-sandbox-win10",
    [string]$SnapshotName = "maintenance-base",
    [string]$TaskMediaRoot = "sandbox_data\task_media",
    [switch]$OpenConsole = $true
)

. "$PSScriptRoot\common.ps1"

$repoRoot = Resolve-RepoRoot
$logPath = New-LogFilePath -ScriptName "08_start_maintenance" -RepoRoot $repoRoot
$TaskMediaRoot = Resolve-ProjectPath -Path $TaskMediaRoot -RepoRoot $repoRoot

try {
    Assert-Admin -LogPath $logPath
    Assert-HyperVAvailable -LogPath $logPath

    $vm = Get-VM -Name $VmName -ErrorAction Stop
    if ($vm.State -ne "Off") {
        Stop-VM -Name $VmName -TurnOff -Force
        Write-Log -Message ("Stopped running VM before maintenance restore: {0}" -f $VmName) -LogPath $logPath -Level "WARN"
    }

    Set-VM -Name $VmName -AutomaticCheckpointsEnabled $false
    Remove-TaskMediaDisks -VmName $VmName -TaskMediaRoot $TaskMediaRoot -LogPath $logPath
    Clear-VMDvdMedia -VmName $VmName -LogPath $logPath

    $snapshot = Get-VMSnapshot -VMName $VmName -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $SnapshotName } | Select-Object -First 1
    if (-not $snapshot) {
        throw "Snapshot '$SnapshotName' not found on VM '$VmName'. Refresh baselines with .\07_refresh_snapshots.ps1 -Force first."
    }

    Restore-VMSnapshot -VMName $VmName -Name $SnapshotName -Confirm:$false
    Write-Log -Message ("Restored maintenance snapshot: {0}" -f $SnapshotName) -LogPath $logPath

    Start-VM -Name $VmName | Out-Null
    Write-Log -Message ("Started VM for maintenance: {0}" -f $VmName) -LogPath $logPath

    if ($OpenConsole) {
        Start-Process vmconnect.exe -ArgumentList "localhost", $VmName | Out-Null
        Write-Log -Message "Opened vmconnect console." -LogPath $logPath
    }

    Write-Host ("Log file: {0}" -f $logPath)
} catch {
    Write-Log -Message $_.Exception.Message -LogPath $logPath -Level "ERROR"
    Write-Host ("Log file: {0}" -f $logPath)
    throw
}
