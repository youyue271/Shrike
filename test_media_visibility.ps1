# Test script to check media visibility in guest
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

if (-not (Test-Path $SampleIsoPath)) {
    throw "Sample ISO not found: $SampleIsoPath"
}
if (-not (Test-Path $ArtifactDiskPath)) {
    throw "Artifact disk not found: $ArtifactDiskPath"
}

Write-Host "Restoring snapshot..."
Restore-VMSnapshot -VMName $VmName -Name $SnapshotName -Confirm:$false

Write-Host "Attaching media..."
$dvd = Get-VMDvdDrive -VMName $VmName | Select-Object -First 1
if ($dvd) {
    $dvd | Set-VMDvdDrive -Path $SampleIsoPath
} else {
    Add-VMDvdDrive -VMName $VmName -Path $SampleIsoPath
}

Add-VMHardDiskDrive -VMName $VmName -Path $ArtifactDiskPath

Write-Host "Starting VM..."
Start-VM -Name $VmName

Write-Host "Waiting 60 seconds for boot..."
Start-Sleep -Seconds 60

$securePassword = ConvertTo-SecureString $GuestPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($GuestUser, $securePassword)

Write-Host "`nChecking volumes in guest:"
Invoke-Command -VMName $VmName -Credential $credential -ScriptBlock {
    Get-Volume | Select-Object DriveLetter, FileSystemLabel, Size | Format-Table

    Write-Host "`nChecking for sample directory:"
    foreach ($vol in Get-Volume) {
        if ($vol.DriveLetter) {
            $samplePath = "$($vol.DriveLetter):\sample"
            if (Test-Path $samplePath) {
                Write-Host "Found sample directory on $($vol.DriveLetter):"
                Get-ChildItem $samplePath
            }
        }
    }

    Write-Host "`nChecking for ARTIFACT volume:"
    $artifactVol = Get-Volume | Where-Object { $_.FileSystemLabel -eq "ARTIFACT" }
    if ($artifactVol) {
        Write-Host "Found ARTIFACT volume: $($artifactVol.DriveLetter)"
    } else {
        Write-Host "ARTIFACT volume not found"
    }
}

Write-Host "`nStopping VM..."
Stop-VM -Name $VmName -Force
