param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactDiskPath,

    [UInt64]$SizeBytes = 2GB,
    [string]$VolumeLabel = "ARTIFACT"
)

. "$PSScriptRoot\common.ps1"

$repoRoot = Resolve-RepoRoot
$logPath = New-LogFilePath -ScriptName "03_new_artifact_disk" -RepoRoot $repoRoot
$ArtifactDiskPath = Resolve-ProjectPath -Path $ArtifactDiskPath -RepoRoot $repoRoot

try {
    Assert-Admin -LogPath $logPath

    $artifactDir = Split-Path -Parent $ArtifactDiskPath
    if (-not (Test-Path $artifactDir)) {
        New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null
        Write-Log -Message ("Created task media directory: {0}" -f $artifactDir) -LogPath $logPath
    }

    if (Test-Path $ArtifactDiskPath) {
        $existingVhd = Get-VHD -Path $ArtifactDiskPath -ErrorAction SilentlyContinue
        if ($existingVhd -and $existingVhd.Attached) {
            Write-Log -Message ("Artifact VHDX is currently attached. Dismounting first: {0}" -f $ArtifactDiskPath) -LogPath $logPath -Level "WARN"
            Dismount-VHD -Path $ArtifactDiskPath -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        Remove-Item -Force $ArtifactDiskPath
        Write-Log -Message ("Removed existing artifact disk: {0}" -f $ArtifactDiskPath) -LogPath $logPath -Level "WARN"
    }

    New-VHD -Path $ArtifactDiskPath -SizeBytes $SizeBytes -Dynamic | Out-Null
    Write-Log -Message ("Created artifact VHDX: {0}" -f $ArtifactDiskPath) -LogPath $logPath

    $mounted = Mount-VHD -Path $ArtifactDiskPath -Passthru
    $disk = $mounted | Get-Disk

    if ($disk.PartitionStyle -eq "RAW") {
        Initialize-Disk -Number $disk.Number -PartitionStyle GPT | Out-Null
        Write-Log -Message ("Initialized disk number {0} with GPT." -f $disk.Number) -LogPath $logPath
    }

    $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
    $volume = Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel $VolumeLabel -Confirm:$false
    $drive = "{0}:" -f $volume.DriveLetter
    New-Item -ItemType Directory -Force -Path (Join-Path $drive "artifact") | Out-Null
    Write-Log -Message ("Created artifact marker directory on {0}" -f $drive) -LogPath $logPath

    Dismount-VHD -Path $ArtifactDiskPath
    Write-Log -Message "Artifact disk creation completed and VHDX dismounted." -LogPath $logPath
    Write-Host ("Log file: {0}" -f $logPath)
} catch {
    try {
        Dismount-VHD -Path $ArtifactDiskPath -ErrorAction SilentlyContinue
    } catch {}
    Write-Log -Message $_.Exception.Message -LogPath $logPath -Level "ERROR"
    Write-Host ("Log file: {0}" -f $logPath)
    throw
}
