param(
    [string]$VmName = "rw-sandbox-win10",
    [string]$GuestUser = "analyst",
    [string]$RuntimeSourcePath = "guest\runtime\run_task.ps1",
    [string]$SysmonConfigSourcePath = "guest\runtime\sysmon_config.xml",
    [string]$TaskName = "SandboxRunTask"
)

. "$PSScriptRoot\common.ps1"

$repoRoot = Resolve-RepoRoot
$logPath = New-LogFilePath -ScriptName "06_install_guest_runtime" -RepoRoot $repoRoot
$RuntimeSourcePath = Resolve-ProjectPath -Path $RuntimeSourcePath -RepoRoot $repoRoot
$SysmonConfigSourcePath = Resolve-ProjectPath -Path $SysmonConfigSourcePath -RepoRoot $repoRoot

try {
    Assert-Admin -LogPath $logPath
    Assert-HyperVAvailable -LogPath $logPath

    if (-not (Test-Path $RuntimeSourcePath)) {
        throw "Guest runtime source file not found: $RuntimeSourcePath"
    }
    if (-not (Test-Path $SysmonConfigSourcePath)) {
        throw "Sysmon config source file not found: $SysmonConfigSourcePath"
    }

    $vm = Get-VM -Name $VmName -ErrorAction Stop
    if ($vm.State -ne "Running") {
        throw "VM must be running before installing guest runtime via PowerShell Direct."
    }

    $scriptContent = Get-Content -Path $RuntimeSourcePath -Raw -Encoding UTF8
    $sysmonConfigContent = Get-Content -Path $SysmonConfigSourcePath -Raw -Encoding UTF8
    Write-Log -Message ("Loaded guest runtime source: {0}" -f $RuntimeSourcePath) -LogPath $logPath
    Write-Log -Message ("Loaded Sysmon config source: {0}" -f $SysmonConfigSourcePath) -LogPath $logPath

    $credential = Get-Credential -UserName $GuestUser -Message "Enter guest credentials for PowerShell Direct"

    $result = Invoke-Command -VMName $VmName -Credential $credential -ScriptBlock {
        param($Content, $SysmonConfigContent, $ScheduledTaskName)

        New-Item -ItemType Directory -Force "C:\Sandbox" | Out-Null
        New-Item -ItemType Directory -Force "C:\Sandbox\input" | Out-Null
        New-Item -ItemType Directory -Force "C:\Sandbox\work" | Out-Null
        New-Item -ItemType Directory -Force "C:\Sandbox\output" | Out-Null
        New-Item -ItemType Directory -Force "C:\Sandbox\runtime" | Out-Null

        Set-Content -Path "C:\Sandbox\runtime\run_task.ps1" -Value $Content -Encoding UTF8
        Set-Content -Path "C:\Sandbox\runtime\sysmon_config.xml" -Value $SysmonConfigContent -Encoding UTF8

        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            "C:\Sandbox\runtime\run_task.ps1",
            [ref]$null,
            [ref]$null
        )

        if (Get-ScheduledTask -TaskName $ScheduledTaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $ScheduledTaskName -Confirm:$false
        }

        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File C:\Sandbox\runtime\run_task.ps1"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
        Register-ScheduledTask -TaskName $ScheduledTaskName -Action $action -Trigger $trigger -Principal $principal | Out-Null

        $sysmonExe = $null
        $sysmonCandidates = @(
            "C:\Sysmon\sysmon64.exe",
            "C:\Windows\sysmon64.exe",
            "C:\Tools\Sysmon\sysmon64.exe"
        )

        foreach ($candidate in $sysmonCandidates) {
            if (Test-Path $candidate) {
                $sysmonExe = $candidate
                break
            }
        }

        if (-not $sysmonExe) {
            foreach ($svcName in @("Sysmon64", "Sysmon")) {
                $svcReg = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
                if (Test-Path $svcReg) {
                    $imagePath = (Get-ItemProperty -Path $svcReg).ImagePath
                    if ($imagePath) {
                        if ($imagePath.StartsWith('"')) {
                            $sysmonExe = $imagePath.Split('"')[1]
                        } else {
                            $sysmonExe = $imagePath.Split(" ")[0]
                        }
                        break
                    }
                }
            }
        }

        $sysmonConfigured = $false
        $sysmonMessage = "Sysmon executable not found"
        if ($sysmonExe -and (Test-Path $sysmonExe)) {
            & $sysmonExe -c "C:\Sandbox\runtime\sysmon_config.xml" | Out-Null
            $sysmonConfigured = $true
            $sysmonMessage = "Sysmon reconfigured from project config"
        }

        [PSCustomObject]@{
            RuntimePath = "C:\Sandbox\runtime\run_task.ps1"
            SysmonConfigPath = "C:\Sandbox\runtime\sysmon_config.xml"
            TaskName = $ScheduledTaskName
            RuntimeSize = (Get-Item "C:\Sandbox\runtime\run_task.ps1").Length
            LastWriteTime = (Get-Item "C:\Sandbox\runtime\run_task.ps1").LastWriteTime
            SysmonConfigured = $sysmonConfigured
            SysmonMessage = $sysmonMessage
        }
    } -ArgumentList $scriptContent, $sysmonConfigContent, $TaskName

    Write-Log -Message ("Installed guest runtime to {0}" -f $result.RuntimePath) -LogPath $logPath
    Write-Log -Message ("Installed Sysmon config to {0}" -f $result.SysmonConfigPath) -LogPath $logPath
    Write-Log -Message ("Registered startup task {0}" -f $result.TaskName) -LogPath $logPath
    Write-Log -Message ("Guest runtime size={0} bytes, lastWriteTime={1}" -f $result.RuntimeSize, $result.LastWriteTime) -LogPath $logPath
    Write-Log -Message ("SysmonConfigured={0}; {1}" -f $result.SysmonConfigured, $result.SysmonMessage) -LogPath $logPath

    Write-Host ("Log file: {0}" -f $logPath)
} catch {
    Write-Log -Message $_.Exception.Message -LogPath $logPath -Level "ERROR"
    Write-Host ("Log file: {0}" -f $logPath)
    throw
}
