. "$PSScriptRoot\common.ps1"

$repoRoot = Resolve-RepoRoot
$logPath = New-LogFilePath -ScriptName "01_prepare_host" -RepoRoot $repoRoot

try {
    Assert-Admin -LogPath $logPath
    Write-Log -Message "Preparing host directories and checking Hyper-V state." -LogPath $logPath

    $relativePaths = @(
        "sandbox_data\base_images",
        "sandbox_data\task_media",
        "sandbox_data\hyperv",
        "sandbox_data\exports",
        "sandbox_data\iso"
    )

    foreach ($relativePath in $relativePaths) {
        $path = Resolve-ProjectPath -Path $relativePath -RepoRoot $repoRoot
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Force -Path $path | Out-Null
            Write-Log -Message ("Created directory: {0}" -f $path) -LogPath $logPath
        } else {
            Write-Log -Message ("Directory already exists: {0}" -f $path) -LogPath $logPath
        }
    }

    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        Write-Log -Message "Hyper-V cmdlets are unavailable. Enabling Hyper-V feature now." -LogPath $logPath -Level "WARN"
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All | Out-Null
        Write-Log -Message "Hyper-V enable command finished. Reboot is required before continuing." -LogPath $logPath -Level "WARN"
    } else {
        Write-Log -Message "Hyper-V cmdlets are already available." -LogPath $logPath
        $vmHost = Get-VMHost
        Write-Log -Message ("Hyper-V host detected: logical processors={0}, memory capacity bytes={1}" -f $vmHost.LogicalProcessorCount, $vmHost.MemoryCapacity) -LogPath $logPath
    }

    Write-Log -Message "Host preparation completed." -LogPath $logPath
    Write-Host ""
    Write-Host ("Log file: {0}" -f $logPath)
} catch {
    Write-Log -Message $_.Exception.Message -LogPath $logPath -Level "ERROR"
    Write-Host ("Log file: {0}" -f $logPath)
    throw
}
