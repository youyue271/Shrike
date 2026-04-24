param(
    [string]$VmName = "rw-sandbox-win10",
    [string]$GuestUser = "analyst",
    [string]$GuestPassword = "analyst",
    [Parameter(Mandatory = $true)]
    [string]$DynamoRIOZipPath,
    [string]$GuestInstallRoot = "C:\Tools\DynamoRIO",
    [string]$GuestTempRoot = "C:\Windows\Temp\shrike-drio-install",
    [switch]$Force
)

. "$PSScriptRoot\common.ps1"

$repoRoot = Resolve-RepoRoot
$logPath = New-LogFilePath -ScriptName "10_install_drio" -RepoRoot $repoRoot
$DynamoRIOZipPath = Resolve-ProjectPath -Path $DynamoRIOZipPath -RepoRoot $repoRoot

try {
    Assert-Admin -LogPath $logPath
    Assert-HyperVAvailable -LogPath $logPath

    if (-not (Test-Path $DynamoRIOZipPath)) {
        throw "DynamoRIO zip package not found: $DynamoRIOZipPath"
    }

    $vm = Get-VM -Name $VmName -ErrorAction Stop
    if ($vm.State -ne "Running") {
        throw "VM must be running before installing DynamoRIO via PowerShell Direct."
    }

    $guestPackagePath = Join-Path $GuestTempRoot ([System.IO.Path]::GetFileName($DynamoRIOZipPath))

    $securePassword = ConvertTo-SecureString $GuestPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($GuestUser, $securePassword)

    $session = $null
    try {
        $session = New-PSSession -VMName $VmName -Credential $credential

        Invoke-Command -Session $session -ScriptBlock {
            param($TempRoot)

            New-Item -ItemType Directory -Force $TempRoot | Out-Null
        } -ArgumentList $GuestTempRoot | Out-Null

        Copy-Item -Path $DynamoRIOZipPath -Destination $guestPackagePath -ToSession $session -Force
        Write-Log -Message ("Copied DynamoRIO package into guest: {0}" -f $guestPackagePath) -LogPath $logPath

        $result = Invoke-Command -Session $session -ScriptBlock {
            param($PackagePath, $InstallRoot, $TempRoot, [bool]$ForceInstall)

            $expandedRoot = Join-Path $TempRoot "expanded"
            if (Test-Path $expandedRoot) {
                Remove-Item -Path $expandedRoot -Recurse -Force
            }
            New-Item -ItemType Directory -Force $expandedRoot | Out-Null

            if (Test-Path $InstallRoot) {
                if (-not $ForceInstall) {
                    throw "Install root already exists. Re-run with -Force to replace it: $InstallRoot"
                }
                Remove-Item -Path $InstallRoot -Recurse -Force
            }

            Expand-Archive -LiteralPath $PackagePath -DestinationPath $expandedRoot -Force

            $expandedChildren = @(Get-ChildItem -Path $expandedRoot -Force)
            if ($expandedChildren.Count -eq 1 -and $expandedChildren[0].PSIsContainer) {
                $installSource = $expandedChildren[0].FullName
            } else {
                $installSource = $expandedRoot
            }

            New-Item -ItemType Directory -Force $InstallRoot | Out-Null
            Copy-Item -Path (Join-Path $installSource "*") -Destination $InstallRoot -Recurse -Force

            $drrun64 = Join-Path $InstallRoot "bin64\drrun.exe"
            $drrun32 = Join-Path $InstallRoot "bin32\drrun.exe"

            [PSCustomObject]@{
                PackagePath = $PackagePath
                InstallRoot = $InstallRoot
                Drrun64Path = $drrun64
                Drrun64Exists = Test-Path $drrun64
                Drrun32Path = $drrun32
                Drrun32Exists = Test-Path $drrun32
            }
        } -ArgumentList $guestPackagePath, $GuestInstallRoot, $GuestTempRoot, $Force.IsPresent
    } finally {
        if ($session) {
            Remove-PSSession -Session $session
        }
    }

    if (-not $result.Drrun64Exists -and -not $result.Drrun32Exists) {
        throw ("DynamoRIO install completed but drrun.exe was not found under {0}" -f $result.InstallRoot)
    }

    Write-Log -Message ("Installed DynamoRIO to {0}" -f $result.InstallRoot) -LogPath $logPath
    Write-Log -Message ("drrun64={0}; exists={1}" -f $result.Drrun64Path, $result.Drrun64Exists) -LogPath $logPath
    Write-Log -Message ("drrun32={0}; exists={1}" -f $result.Drrun32Path, $result.Drrun32Exists) -LogPath $logPath

    [PSCustomObject]@{
        VmName = $VmName
        InstallRoot = $result.InstallRoot
        Drrun64Path = $result.Drrun64Path
        Drrun64Exists = $result.Drrun64Exists
        Drrun32Path = $result.Drrun32Path
        Drrun32Exists = $result.Drrun32Exists
        PackagePath = $result.PackagePath
        LogPath = $logPath
    } | ConvertTo-Json -Depth 5

    Write-Host ("Log file: {0}" -f $logPath)
} catch {
    Write-Log -Message $_.Exception.Message -LogPath $logPath -Level "ERROR"
    Write-Host ("Log file: {0}" -f $logPath)
    throw
}
