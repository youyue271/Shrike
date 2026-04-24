# Debug script to monitor offline task execution
param(
    [string]$VmName = "rw-sandbox-win10",
    [string]$SnapshotName = "analysis-base",
    [string]$SampleIsoPath = "sandbox_data\task_media\sample-task.iso",
    [string]$ArtifactDiskPath = "sandbox_data\task_media\artifact-task.vhdx",
    [string]$GuestUser = "root",
    [string]$GuestPassword = "root"
)

$ErrorActionPreference = "Stop"

# Resolve paths
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SampleIsoPath = Join-Path $scriptDir $SampleIsoPath
$ArtifactDiskPath = Join-Path $scriptDir $ArtifactDiskPath

Write-Host "Restoring snapshot..."
Restore-VMSnapshot -VMName $VmName -Name $SnapshotName -Confirm:$false

Write-Host "Attaching media..."
$dvd = Get-VMDvdDrive -VMName $VmName | Select-Object -First 1
if ($dvd) {
    $dvd | Set-VMDvdDrive -Path $SampleIsoPath
}
Add-VMHardDiskDrive -VMName $VmName -Path $ArtifactDiskPath

Write-Host "Starting VM..."
Start-VM -Name $VmName

$securePassword = ConvertTo-SecureString $GuestPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($GuestUser, $securePassword)

Write-Host "Waiting for VM to boot and task to start..."
Start-Sleep -Seconds 45

Write-Host "`n=== Checking runner.log ==="
Invoke-Command -VMName $VmName -Credential $credential -ScriptBlock {
    if (Test-Path "C:\Sandbox\output\runner.log") {
        Get-Content "C:\Sandbox\output\runner.log"
    } else {
        Write-Host "runner.log not found"
    }
}

Write-Host "`n=== Checking volumes ==="
Invoke-Command -VMName $VmName -Credential $credential -ScriptBlock {
    Get-Volume | Where-Object { $_.DriveLetter } | Select-Object DriveLetter, FileSystemLabel, Size | Format-Table
}

Write-Host "`n=== Checking scheduled task ==="
Invoke-Command -VMName $VmName -Credential $credential -ScriptBlock {
    Get-ScheduledTask -TaskName "SandboxRunTask" -ErrorAction SilentlyContinue | Select-Object TaskName, State, LastRunTime, LastTaskResult
}

Write-Host "`nWaiting 60 more seconds..."
Start-Sleep -Seconds 60

Write-Host "`n=== Final runner.log ==="
Invoke-Command -VMName $VmName -Credential $credential -ScriptBlock {
    if (Test-Path "C:\Sandbox\output\runner.log") {
        Get-Content "C:\Sandbox\output\runner.log"
    }
}

Write-Host "`nStopping VM..."
Stop-VM -Name $VmName -Force
