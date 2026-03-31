param(
    [string]$VmName = "rw-sandbox-win10",
    [ValidateSet(1, 2)]
    [int]$Generation = 1,
    [string]$VmPath = "sandbox_data\hyperv",
    [string]$BaseDiskPath = "sandbox_data\base_images\rw-sandbox-win10-base.vhdx",
    [UInt64]$BaseDiskSizeBytes = 100GB,
    [UInt64]$MemoryStartupBytes = 8GB,
    [int]$ProcessorCount = 4,
    [string]$WindowsIsoPath = "sandbox_data\iso\Win10_22H2_x64.iso"
)

. "$PSScriptRoot\common.ps1"

$repoRoot = Resolve-RepoRoot
$logPath = New-LogFilePath -ScriptName "02_new_analysis_vm" -RepoRoot $repoRoot
$VmPath = Resolve-ProjectPath -Path $VmPath -RepoRoot $repoRoot
$BaseDiskPath = Resolve-ProjectPath -Path $BaseDiskPath -RepoRoot $repoRoot
$WindowsIsoPath = Resolve-ProjectPath -Path $WindowsIsoPath -RepoRoot $repoRoot

try {
    Assert-Admin -LogPath $logPath
    Assert-HyperVAvailable -LogPath $logPath

    Write-Log -Message ("Creating or validating analysis VM: {0}" -f $VmName) -LogPath $logPath

    $baseDir = Split-Path -Parent $BaseDiskPath
    foreach ($path in @($VmPath, $baseDir)) {
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Force -Path $path | Out-Null
            Write-Log -Message ("Created directory: {0}" -f $path) -LogPath $logPath
        }
    }

    if (-not (Test-Path $BaseDiskPath)) {
        New-VHD -Path $BaseDiskPath -SizeBytes $BaseDiskSizeBytes -Dynamic | Out-Null
        Write-Log -Message ("Created base VHDX: {0}" -f $BaseDiskPath) -LogPath $logPath
    } else {
        Write-Log -Message ("Base VHDX already exists: {0}" -f $BaseDiskPath) -LogPath $logPath
    }

    $vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
    if (-not $vm) {
        New-VM -Name $VmName -Generation $Generation -MemoryStartupBytes $MemoryStartupBytes -Path $VmPath | Out-Null
        Write-Log -Message ("Created Gen{0} VM shell: {1}" -f $Generation, $VmName) -LogPath $logPath
    } else {
        Write-Log -Message ("VM already exists: {0}" -f $VmName) -LogPath $logPath
        if ($vm.State -ne "Off") {
            throw "VM must be off before reconfiguration."
        }
        if ($vm.Generation -ne $Generation) {
            throw "Existing VM generation is $($vm.Generation), but script requested Generation $Generation. Recreate the VM or pass -Generation $($vm.Generation)."
        }
    }

    Set-VMProcessor -VMName $VmName -Count $ProcessorCount
    Write-Log -Message ("Set processor count to {0}" -f $ProcessorCount) -LogPath $logPath

    Set-VM -Name $VmName -AutomaticCheckpointsEnabled $false
    Write-Log -Message "Disabled automatic checkpoints." -LogPath $logPath

    $existingDisks = Get-VMHardDiskDrive -VMName $VmName -ErrorAction SilentlyContinue
    $baseAttached = $false
    foreach ($disk in $existingDisks) {
        if ($disk.Path -eq $BaseDiskPath) {
            $baseAttached = $true
        }
    }
    if (-not $baseAttached) {
        Add-VMHardDiskDrive -VMName $VmName -Path $BaseDiskPath
        Write-Log -Message ("Attached base VHDX to VM: {0}" -f $BaseDiskPath) -LogPath $logPath
    } else {
        Write-Log -Message "Base VHDX is already attached." -LogPath $logPath
    }

    if ($Generation -eq 2) {
        Set-VMFirmware -VMName $VmName -EnableSecureBoot On
        Write-Log -Message "Enabled Secure Boot for Gen2 VM." -LogPath $logPath
    } else {
        Write-Log -Message "Gen1 VM selected. Secure Boot is not applicable." -LogPath $logPath
    }

    $nics = Get-VMNetworkAdapter -VMName $VmName -ErrorAction SilentlyContinue
    if ($nics) {
        foreach ($nic in $nics) {
            Remove-VMNetworkAdapter -VMNetworkAdapter $nic
            Write-Log -Message ("Removed VM network adapter: {0}" -f $nic.Name) -LogPath $logPath
        }
    } else {
        Write-Log -Message "VM already has no network adapters." -LogPath $logPath
    }

    if (Test-Path $WindowsIsoPath) {
        $dvd = Get-VMDvdDrive -VMName $VmName -ErrorAction SilentlyContinue
        if (-not $dvd) {
            Add-VMDvdDrive -VMName $VmName -Path $WindowsIsoPath | Out-Null
            Write-Log -Message ("Attached Windows ISO: {0}" -f $WindowsIsoPath) -LogPath $logPath
        } else {
            Set-VMDvdDrive -VMName $VmName -Path $WindowsIsoPath | Out-Null
            Write-Log -Message ("Updated DVD ISO path: {0}" -f $WindowsIsoPath) -LogPath $logPath
        }
        if ($Generation -eq 2) {
            $dvd = Get-VMDvdDrive -VMName $VmName
            Set-VMFirmware -VMName $VmName -FirstBootDevice $dvd
            Write-Log -Message "Set Gen2 first boot device to DVD." -LogPath $logPath
        } else {
            Set-VMBios -VMName $VmName -StartupOrder @("CD", "IDE", "LegacyNetworkAdapter", "Floppy")
            Write-Log -Message "Set Gen1 startup order to CD first, IDE second for Windows install." -LogPath $logPath
        }
    } else {
        Write-Log -Message ("Windows ISO not found at {0}. Skipping DVD attach." -f $WindowsIsoPath) -LogPath $logPath -Level "WARN"
    }

    Write-Log -Message "Analysis VM setup completed." -LogPath $logPath
    Write-Host ""
    Write-Host ("Next step: Start-VM -Name `"{0}`" and open vmconnect.exe to install Windows." -f $VmName)
    Write-Host ("Log file: {0}" -f $logPath)
} catch {
    Write-Log -Message $_.Exception.Message -LogPath $logPath -Level "ERROR"
    Write-Host ("Log file: {0}" -f $logPath)
    throw
}
