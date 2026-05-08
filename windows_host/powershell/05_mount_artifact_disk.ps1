param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactDiskPath
)

. "$PSScriptRoot\common.ps1"

$repoRoot = Resolve-RepoRoot
$logPath = New-LogFilePath -ScriptName "05_mount_artifact_disk" -RepoRoot $repoRoot
$ArtifactDiskPath = Resolve-ProjectPath -Path $ArtifactDiskPath -RepoRoot $repoRoot

try {
    Assert-Admin -LogPath $logPath

    if (-not (Test-Path $ArtifactDiskPath)) {
        throw "Artifact disk not found: $ArtifactDiskPath"
    }

    $existingVhd = Get-VHD -Path $ArtifactDiskPath -ErrorAction SilentlyContinue
    if ($existingVhd -and $existingVhd.Attached) {
        Write-Log -Message "Artifact VHDX is already attached. Reusing current mount." -LogPath $logPath -Level "WARN"
    } else {
        Mount-VHD -Path $ArtifactDiskPath -ReadOnly | Out-Null
        Write-Log -Message "Mounted artifact VHDX in read-only mode." -LogPath $logPath
    }

    $image = Get-DiskImage -ImagePath $ArtifactDiskPath
    $disk = $image | Get-Disk
    $volume = $disk | Get-Partition | Get-Volume | Where-Object DriveLetter -ne $null | Select-Object -First 1

    if (-not $volume) {
        throw "Mounted artifact disk has no accessible volume."
    }

    $mountPoint = "{0}:\artifact" -f $volume.DriveLetter
    Write-Log -Message ("Mounted artifact disk at drive letter {0}" -f $volume.DriveLetter) -LogPath $logPath
    Write-Output ("Artifact path: {0}" -f $mountPoint)
    Write-Output ("Log file: {0}" -f $logPath)
} catch {
    Write-Log -Message $_.Exception.Message -LogPath $logPath -Level "ERROR"
    Write-Output ("Log file: {0}" -f $logPath)
    throw
}
