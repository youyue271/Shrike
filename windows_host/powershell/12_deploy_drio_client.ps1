param(
    [string]$VmName = "rw-sandbox-win10",
    [string]$GuestUser = "root",
    [string]$GuestPassword = "root",
    [string]$ClientBin32Path = "windows_host\drio_client\bin32\release\shrike_drcov_nudge.dll",
    [string]$ClientBin64Path = "windows_host\drio_client\bin64\release\shrike_drcov_nudge.dll",
    [string]$GuestRuntimeRoot = "C:\Sandbox\runtime\drio"
)

. "$PSScriptRoot\common.ps1"

$repoRoot = Resolve-RepoRoot
$logPath = New-LogFilePath -ScriptName "12_deploy_drio_client" -RepoRoot $repoRoot
$ClientBin32Path = Resolve-ProjectPath -Path $ClientBin32Path -RepoRoot $repoRoot
$ClientBin64Path = Resolve-ProjectPath -Path $ClientBin64Path -RepoRoot $repoRoot

try {
    Assert-Admin -LogPath $logPath
    Assert-HyperVAvailable -LogPath $logPath

    if (-not (Test-Path $ClientBin32Path)) {
        throw "Client DLL (32-bit) not found: $ClientBin32Path"
    }
    if (-not (Test-Path $ClientBin64Path)) {
        throw "Client DLL (64-bit) not found: $ClientBin64Path"
    }

    $vm = Get-VM -Name $VmName -ErrorAction Stop
    if ($vm.State -ne "Running") {
        throw "VM must be running before deploying client DLL via PowerShell Direct."
    }

    if ($GuestPassword) {
        $securePassword = ConvertTo-SecureString $GuestPassword -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($GuestUser, $securePassword)
        Write-Log -Message ("Using explicit PowerShell Direct credential for guest user {0}" -f $GuestUser) -LogPath $logPath
    } else {
        $credential = Get-Credential -UserName $GuestUser -Message "Enter guest credentials for PowerShell Direct"
        Write-Log -Message ("Prompting for interactive PowerShell Direct credential for guest user {0}" -f $GuestUser) -LogPath $logPath
    }

    $session = $null
    try {
        $session = New-PSSession -VMName $VmName -Credential $credential

        $result = Invoke-Command -Session $session -ScriptBlock {
            param($RuntimeRoot)

            $bin32Dir = Join-Path $RuntimeRoot "bin32"
            $bin64Dir = Join-Path $RuntimeRoot "bin64"

            New-Item -ItemType Directory -Force $bin32Dir | Out-Null
            New-Item -ItemType Directory -Force $bin64Dir | Out-Null

            [PSCustomObject]@{
                RuntimeRoot = $RuntimeRoot
                Bin32Dir = $bin32Dir
                Bin64Dir = $bin64Dir
            }
        } -ArgumentList $GuestRuntimeRoot

        $guestBin32Path = Join-Path $result.Bin32Dir "shrike_drcov_nudge.dll"
        $guestBin64Path = Join-Path $result.Bin64Dir "shrike_drcov_nudge.dll"

        Copy-Item -Path $ClientBin32Path -Destination $guestBin32Path -ToSession $session -Force
        Write-Log -Message ("Deployed 32-bit client DLL to {0}" -f $guestBin32Path) -LogPath $logPath

        Copy-Item -Path $ClientBin64Path -Destination $guestBin64Path -ToSession $session -Force
        Write-Log -Message ("Deployed 64-bit client DLL to {0}" -f $guestBin64Path) -LogPath $logPath

        $hostBin32Hash = (Get-FileHash -Path $ClientBin32Path -Algorithm SHA256).Hash
        $hostBin64Hash = (Get-FileHash -Path $ClientBin64Path -Algorithm SHA256).Hash

        Write-Log -Message ("Host 32-bit DLL SHA256: {0}" -f $hostBin32Hash) -LogPath $logPath
        Write-Log -Message ("Host 64-bit DLL SHA256: {0}" -f $hostBin64Hash) -LogPath $logPath

        $verification = Invoke-Command -Session $session -ScriptBlock {
            param($Path32, $Path64)

            $bin32Exists = Test-Path $Path32
            $bin64Exists = Test-Path $Path64

            [PSCustomObject]@{
                Bin32Exists = $bin32Exists
                Bin32Size = if ($bin32Exists) { (Get-Item $Path32).Length } else { 0 }
                Bin32Hash = if ($bin32Exists) { (Get-FileHash -Path $Path32 -Algorithm SHA256).Hash } else { $null }
                Bin32Time = if ($bin32Exists) { (Get-Item $Path32).LastWriteTime } else { $null }
                Bin64Exists = $bin64Exists
                Bin64Size = if ($bin64Exists) { (Get-Item $Path64).Length } else { 0 }
                Bin64Hash = if ($bin64Exists) { (Get-FileHash -Path $Path64 -Algorithm SHA256).Hash } else { $null }
                Bin64Time = if ($bin64Exists) { (Get-Item $Path64).LastWriteTime } else { $null }
            }
        } -ArgumentList $guestBin32Path, $guestBin64Path

        if (-not $verification.Bin32Exists -or -not $verification.Bin64Exists) {
            throw "Deployment verification failed: DLL files not found in guest"
        }

        if ($verification.Bin32Hash -ne $hostBin32Hash) {
            throw "Deployment verification failed: 32-bit DLL hash mismatch (host: $hostBin32Hash, guest: $($verification.Bin32Hash))"
        }

        if ($verification.Bin64Hash -ne $hostBin64Hash) {
            throw "Deployment verification failed: 64-bit DLL hash mismatch (host: $hostBin64Hash, guest: $($verification.Bin64Hash))"
        }

        Write-Log -Message ("Verified 32-bit DLL: size={0}, hash={1}, time={2}" -f $verification.Bin32Size, $verification.Bin32Hash, $verification.Bin32Time) -LogPath $logPath
        Write-Log -Message ("Verified 64-bit DLL: size={0}, hash={1}, time={2}" -f $verification.Bin64Size, $verification.Bin64Hash, $verification.Bin64Time) -LogPath $logPath
        Write-Log -Message ("Hash verification passed: host and guest DLLs match") -LogPath $logPath

    } finally {
        if ($session) {
            Remove-PSSession -Session $session
        }
    }

    [PSCustomObject]@{
        VmName = $VmName
        GuestRuntimeRoot = $GuestRuntimeRoot
        Bin32Deployed = $verification.Bin32Exists
        Bin32Size = $verification.Bin32Size
        Bin32Hash = $verification.Bin32Hash
        Bin32Time = $verification.Bin32Time
        Bin64Deployed = $verification.Bin64Exists
        Bin64Size = $verification.Bin64Size
        Bin64Hash = $verification.Bin64Hash
        Bin64Time = $verification.Bin64Time
        HostBin32Hash = $hostBin32Hash
        HostBin64Hash = $hostBin64Hash
        HashVerified = $true
        LogPath = $logPath
    } | ConvertTo-Json -Depth 5

    Write-Host ("Log file: {0}" -f $logPath)
} catch {
    Write-Log -Message $_.Exception.Message -LogPath $logPath -Level "ERROR"
    Write-Host ("Log file: {0}" -f $logPath)
    throw
}
