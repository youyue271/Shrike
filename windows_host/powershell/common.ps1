Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-LogFilePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptName,

        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $logDir = Join-Path $RepoRoot "windows_host\logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    }

    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    return Join-Path $logDir ("{0}_{1}.log" -f $ScriptName, $stamp)
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [string]$LogPath,

        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[{0}] [{1}] {2}" -f $ts, $Level, $Message
    Write-Host $line
    Add-Content -Path $LogPath -Value $line
}

function Assert-Admin {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log -Message "This script must be run in an elevated PowerShell session." -LogPath $LogPath -Level "ERROR"
        throw "Administrator privileges required."
    }
}

function Assert-HyperVAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        Write-Log -Message "Hyper-V PowerShell module is not available. Enable Hyper-V and reboot first." -LogPath $LogPath -Level "ERROR"
        throw "Hyper-V cmdlets unavailable."
    }
}

function Resolve-RepoRoot {
    $scriptDir = Split-Path -Parent $PSScriptRoot
    return Split-Path -Parent $scriptDir
}

function Resolve-ProjectPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
}

function Resolve-WindowsPython {
    $command = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($command -and $command.Source) {
        return $command.Source
    }

    $knownPaths = @(
        "C:\ProgramData\scoop\apps\python312\current\python.exe",
        "C:\Users\YOUYUE\scoop\apps\python311\current\python.exe",
        "D:\project\ransomware\article\.word-mcp-win\Scripts\python.exe"
    )

    foreach ($path in $knownPaths) {
        if (Test-Path $path) {
            return $path
        }
    }

    throw "Windows python.exe not found; ResultServer must run on the Windows host so it can bind the Hyper-V internal IP."
}

function Get-ArtifactPathFromMountOutput {
    param(
        [AllowNull()]
        [object[]]$MountOutput
    )

    foreach ($entry in @($MountOutput)) {
        if ($null -eq $entry) {
            continue
        }

        $text = ([string]$entry) -replace "`0", ""
        foreach ($line in ($text -split "\r?\n")) {
            $normalized = $line.Trim()
            if ($normalized -match "^Artifact path:\s*(.+)$") {
                return $Matches[1].Trim()
            }
        }
    }

    return $null
}

function Test-PathWithinRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CandidatePath,

        [Parameter(Mandatory = $true)]
        [string]$RootPath
    )

    if (-not $CandidatePath -or -not $RootPath) {
        return $false
    }

    $candidateFull = [System.IO.Path]::GetFullPath($CandidatePath)
    $rootFull = [System.IO.Path]::GetFullPath($RootPath)

    return $candidateFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)
}

function Remove-OfflineArtifactDisk {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmName,

        [Parameter(Mandatory = $true)]
        [string]$ArtifactDiskPath,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    $vmDisks = Get-VMHardDiskDrive -VMName $VmName -ErrorAction SilentlyContinue
    foreach ($disk in $vmDisks) {
        if ($disk.Path -and ($disk.Path -eq $ArtifactDiskPath)) {
            Write-Log -Message ("Removing existing artifact disk from VM: {0}" -f $disk.Path) -LogPath $LogPath
            Remove-VMHardDiskDrive -VMHardDiskDrive $disk
        }
    }
}

function Remove-TaskMediaDisks {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmName,

        [Parameter(Mandatory = $true)]
        [string]$TaskMediaRoot,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    $vmDisks = Get-VMHardDiskDrive -VMName $VmName -ErrorAction SilentlyContinue
    foreach ($disk in $vmDisks) {
        if ($disk.Path -and (Test-PathWithinRoot -CandidatePath $disk.Path -RootPath $TaskMediaRoot)) {
            Write-Log -Message ("Removing task-media disk from VM before maintenance or snapshot: {0}" -f $disk.Path) -LogPath $LogPath -Level "WARN"
            Remove-VMHardDiskDrive -VMHardDiskDrive $disk
        }
    }
}

function Clear-VMDvdMedia {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmName,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    $dvdDrives = @(Get-VMDvdDrive -VMName $VmName -ErrorAction SilentlyContinue)
    foreach ($dvd in $dvdDrives) {
        if ($dvd.Path) {
            Set-VMDvdDrive -VMDvdDrive $dvd -Path $null | Out-Null
            Write-Log -Message ("Cleared DVD media from VM: {0}" -f $dvd.Path) -LogPath $LogPath -Level "WARN"
        }
    }
}

function Dismount-TaskMediaVhds {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskMediaRoot,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    if (-not (Test-Path $TaskMediaRoot)) {
        return
    }

    $patterns = @("*.vhd", "*.vhdx", "*.avhd", "*.avhdx")
    foreach ($pattern in $patterns) {
        $candidates = @(Get-ChildItem -Path $TaskMediaRoot -Filter $pattern -File -ErrorAction SilentlyContinue)
        foreach ($candidate in $candidates) {
            $vhd = Get-VHD -Path $candidate.FullName -ErrorAction SilentlyContinue
            if ($vhd -and $vhd.Attached) {
                Dismount-VHD -Path $candidate.FullName -ErrorAction SilentlyContinue
                Write-Log -Message ("Dismounted attached task-media VHD: {0}" -f $candidate.FullName) -LogPath $LogPath -Level "WARN"
            }
        }
    }
}

function Get-TaskMediaDifferencingDisks {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskMediaRoot
    )

    if (-not (Test-Path $TaskMediaRoot)) {
        return @()
    }

    return @(Get-ChildItem -Path $TaskMediaRoot -Filter "*.avhd*" -File -ErrorAction SilentlyContinue)
}

function Get-PrimarySystemDisk {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmName,

        [Parameter(Mandatory = $true)]
        [string]$ArtifactDiskPath,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    $systemDisk = Get-VMHardDiskDrive -VMName $VmName |
        Where-Object { $_.Path -and ($_.Path -ne $ArtifactDiskPath) } |
        Select-Object -First 1

    if (-not $systemDisk) {
        throw "No primary system disk is attached to VM."
    }

    Write-Log -Message ("Detected primary system disk: {0}" -f $systemDisk.Path) -LogPath $LogPath
    return $systemDisk
}

function Set-OfflineTaskBootOrder {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmName,

        [Parameter(Mandatory = $true)]
        [object]$SystemDisk,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    $vm = Get-VM -Name $VmName -ErrorAction Stop
    $dvd = Get-VMDvdDrive -VMName $VmName -ErrorAction SilentlyContinue

    if ($vm.Generation -eq 1) {
        Set-VMBios -VMName $VmName -StartupOrder @("IDE", "CD", "LegacyNetworkAdapter", "Floppy")
        Write-Log -Message "Set Gen1 startup order to IDE first, CD second." -LogPath $LogPath
        return
    }

    if ($dvd) {
        Set-VMFirmware -VMName $VmName -BootOrder @($SystemDisk, $dvd)
        Write-Log -Message "Set Gen2 boot order to hard disk first, DVD second." -LogPath $LogPath
    } else {
        Set-VMFirmware -VMName $VmName -FirstBootDevice $SystemDisk
        Write-Log -Message "Set Gen2 first boot device to hard disk." -LogPath $LogPath
    }
}
