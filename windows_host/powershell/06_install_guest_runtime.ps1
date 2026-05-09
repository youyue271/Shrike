param(
    [string]$VmName = "rw-sandbox-win10",
    [string]$GuestUser = "analyst",
    [string]$GuestPassword = "analyst",
    [string]$RuntimeSourcePath = "guest\runtime\run_task.ps1",
    [string]$TraceBackendPlaceholderSourcePath = "guest\runtime\trace_backend_placeholder.ps1",
    [string]$TraceBackendDrioSourcePath = "guest\runtime\trace_backend_drio.ps1",
    [string]$DrioClientBin32SourcePath = "guest\runtime\drio\bin32\shrike_drcov_nudge.dll",
    [string]$DrioClientBin64SourcePath = "guest\runtime\drio\bin64\shrike_drcov_nudge.dll",
    [string]$DynamoRIOGuestInstallRoot = "C:\Tools\DynamoRIO",
    [string]$SysmonConfigSourcePath = "guest\runtime\sysmon_config.xml",
    [string]$SysmonBinarySourcePath = "windows_host\sysmon\sysmon64.exe",
    [string]$TaskName = "SandboxRunTask"
)

. "$PSScriptRoot\common.ps1"

$repoRoot = Resolve-RepoRoot
$logPath = New-LogFilePath -ScriptName "06_install_guest_runtime" -RepoRoot $repoRoot
$RuntimeSourcePath = Resolve-ProjectPath -Path $RuntimeSourcePath -RepoRoot $repoRoot
$TraceBackendPlaceholderSourcePath = Resolve-ProjectPath -Path $TraceBackendPlaceholderSourcePath -RepoRoot $repoRoot
$TraceBackendDrioSourcePath = Resolve-ProjectPath -Path $TraceBackendDrioSourcePath -RepoRoot $repoRoot
$DrioClientBin32SourcePath = Resolve-ProjectPath -Path $DrioClientBin32SourcePath -RepoRoot $repoRoot
$DrioClientBin64SourcePath = Resolve-ProjectPath -Path $DrioClientBin64SourcePath -RepoRoot $repoRoot
$SysmonConfigSourcePath = Resolve-ProjectPath -Path $SysmonConfigSourcePath -RepoRoot $repoRoot
$SysmonBinarySourcePath = Resolve-ProjectPath -Path $SysmonBinarySourcePath -RepoRoot $repoRoot

try {
    Assert-Admin -LogPath $logPath
    Assert-HyperVAvailable -LogPath $logPath

    if (-not (Test-Path $RuntimeSourcePath)) {
        throw "Guest runtime source file not found: $RuntimeSourcePath"
    }
    if (-not (Test-Path $TraceBackendPlaceholderSourcePath)) {
        throw "Trace backend placeholder source file not found: $TraceBackendPlaceholderSourcePath"
    }
    if (-not (Test-Path $TraceBackendDrioSourcePath)) {
        throw "Trace backend drio source file not found: $TraceBackendDrioSourcePath"
    }
    if (-not (Test-Path $SysmonConfigSourcePath)) {
        throw "Sysmon config source file not found: $SysmonConfigSourcePath"
    }

    $vm = Get-VM -Name $VmName -ErrorAction Stop
    if ($vm.State -ne "Running") {
        throw "VM must be running before installing guest runtime via PowerShell Direct."
    }

    $scriptContent = Get-Content -Path $RuntimeSourcePath -Raw -Encoding UTF8
    $traceBackendPlaceholderContent = Get-Content -Path $TraceBackendPlaceholderSourcePath -Raw -Encoding UTF8
    $traceBackendDrioContent = Get-Content -Path $TraceBackendDrioSourcePath -Raw -Encoding UTF8
    $sysmonConfigContent = Get-Content -Path $SysmonConfigSourcePath -Raw -Encoding UTF8

    $sysmonBinaryBase64 = $null
    if (Test-Path $SysmonBinarySourcePath) {
        $sysmonBinaryBase64 = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($SysmonBinarySourcePath))
        Write-Log -Message ("Loaded Sysmon binary source: {0}" -f $SysmonBinarySourcePath) -LogPath $logPath
    } else {
        Write-Log -Message ("Sysmon binary source not found at {0}. Will only try to reconfigure an existing in-guest Sysmon install." -f $SysmonBinarySourcePath) -LogPath $logPath -Level "WARN"
    }
    Write-Log -Message ("Loaded guest runtime source: {0}" -f $RuntimeSourcePath) -LogPath $logPath
    Write-Log -Message ("Loaded trace backend placeholder source: {0}" -f $TraceBackendPlaceholderSourcePath) -LogPath $logPath
    Write-Log -Message ("Loaded trace backend drio source: {0}" -f $TraceBackendDrioSourcePath) -LogPath $logPath
    Write-Log -Message ("Loaded Sysmon config source: {0}" -f $SysmonConfigSourcePath) -LogPath $logPath

    $securePassword = ConvertTo-SecureString $GuestPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($GuestUser, $securePassword)

    $session = $null
    try {
        $session = New-PSSession -VMName $VmName -Credential $credential

        $result = Invoke-Command -Session $session -ScriptBlock {
            param($Content, $TraceBackendPlaceholderContent, $TraceBackendDrioContent, $SysmonConfigContent, $SysmonBinaryBase64, $ScheduledTaskName)

        function Invoke-NativeCommandSafe {
            param(
                [Parameter(Mandatory = $true)]
                [string]$FilePath,

                [Parameter(Mandatory = $false)]
                [string[]]$ArgumentList = @()
            )

            $tempOut = Join-Path $env:TEMP ([System.Guid]::NewGuid().ToString() + ".out.txt")
            $tempErr = Join-Path $env:TEMP ([System.Guid]::NewGuid().ToString() + ".err.txt")
            try {
                $proc = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -Wait -PassThru -NoNewWindow `
                    -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr

                $stdout = if (Test-Path $tempOut) { Get-Content -Path $tempOut -Raw -ErrorAction SilentlyContinue } else { "" }
                $stderr = if (Test-Path $tempErr) { Get-Content -Path $tempErr -Raw -ErrorAction SilentlyContinue } else { "" }

                return [PSCustomObject]@{
                    ExitCode = $proc.ExitCode
                    StdOut = ($stdout | Out-String).Trim()
                    StdErr = ($stderr | Out-String).Trim()
                }
            } finally {
                Remove-Item -Path $tempOut, $tempErr -Force -ErrorAction SilentlyContinue
            }
        }

        New-Item -ItemType Directory -Force "C:\Sandbox" | Out-Null
        New-Item -ItemType Directory -Force "C:\Sandbox\input" | Out-Null
        New-Item -ItemType Directory -Force "C:\Sandbox\work" | Out-Null
        New-Item -ItemType Directory -Force "C:\Sandbox\output" | Out-Null
        New-Item -ItemType Directory -Force "C:\Sandbox\runtime" | Out-Null
        New-Item -ItemType Directory -Force "C:\Sandbox\sysmon" | Out-Null

        Set-Content -Path "C:\Sandbox\runtime\run_task.ps1" -Value $Content -Encoding UTF8
        Set-Content -Path "C:\Sandbox\runtime\trace_backend_placeholder.ps1" -Value $TraceBackendPlaceholderContent -Encoding UTF8
        Set-Content -Path "C:\Sandbox\runtime\trace_backend_drio.ps1" -Value $TraceBackendDrioContent -Encoding UTF8
        Set-Content -Path "C:\Sandbox\runtime\sysmon_config.xml" -Value $SysmonConfigContent -Encoding UTF8

        New-Item -ItemType Directory -Force "C:\Sandbox\runtime\drio\bin32" | Out-Null
        New-Item -ItemType Directory -Force "C:\Sandbox\runtime\drio\bin64" | Out-Null

        $projectSysmonPath = "C:\Sandbox\sysmon\sysmon64.exe"
        $sysmonInstalledFromProject = $false
        if ($SysmonBinaryBase64) {
            [System.IO.File]::WriteAllBytes($projectSysmonPath, [System.Convert]::FromBase64String($SysmonBinaryBase64))
            $sysmonInstalledFromProject = $true
        }

        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            "C:\Sandbox\runtime\run_task.ps1",
            [ref]$null,
            [ref]$null
        )
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            "C:\Sandbox\runtime\trace_backend_placeholder.ps1",
            [ref]$null,
            [ref]$null
        )
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            "C:\Sandbox\runtime\trace_backend_drio.ps1",
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
        Enable-ScheduledTask -TaskName $ScheduledTaskName | Out-Null
        $scheduledTaskState = (Get-ScheduledTask -TaskName $ScheduledTaskName).State.ToString()

        $sysmonExe = $null
        $sysmonCandidates = @(
            $projectSysmonPath,
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
        $sysmonServiceName = $null
        $sysmonServiceStatus = $null
        $sysmonLogAvailable = $false
        $sysmonMessage = "Sysmon executable not found"
        $sysmonCommandExitCode = $null
        $sysmonCommandStdOut = ""
        $sysmonCommandStdErr = ""
        if ($sysmonExe -and (Test-Path $sysmonExe)) {
            $existingService = Get-Service -Name "Sysmon64", "Sysmon" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($existingService) {
                $sysmonCommand = Invoke-NativeCommandSafe -FilePath $sysmonExe -ArgumentList @("-c", "C:\Sandbox\runtime\sysmon_config.xml")
                $sysmonMessage = "Sysmon reconfigured from project config"
            } else {
                $sysmonCommand = Invoke-NativeCommandSafe -FilePath $sysmonExe -ArgumentList @("-accepteula", "-i", "C:\Sandbox\runtime\sysmon_config.xml")
                $sysmonMessage = "Sysmon installed and configured from project assets"
            }

            $sysmonCommandExitCode = $sysmonCommand.ExitCode
            $sysmonCommandStdOut = $sysmonCommand.StdOut
            $sysmonCommandStdErr = $sysmonCommand.StdErr

            if ($sysmonCommandExitCode -ne 0) {
                throw ("Sysmon command failed with exit code {0}. stdout={1} stderr={2}" -f $sysmonCommandExitCode, $sysmonCommandStdOut, $sysmonCommandStdErr)
            }

            Start-Sleep -Seconds 2
            $existingService = Get-Service -Name "Sysmon64", "Sysmon" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($existingService) {
                if ($existingService.Status -ne "Running") {
                    Start-Service -Name $existingService.Name -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 1
                    $existingService = Get-Service -Name $existingService.Name -ErrorAction SilentlyContinue
                }
                $sysmonServiceName = $existingService.Name
                $sysmonServiceStatus = $existingService.Status.ToString()
            }

            try {
                $sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop
            } catch {
                $sysmonLog = $null
                $sysmonMessage = "{0}; Sysmon log query failed: {1}" -f $sysmonMessage, $_.Exception.Message
            }
            $sysmonConfigured = $true
            $sysmonLogAvailable = [bool]$sysmonLog
        }

        [PSCustomObject]@{
            RuntimePath = "C:\Sandbox\runtime\run_task.ps1"
            TraceBackendPlaceholderPath = "C:\Sandbox\runtime\trace_backend_placeholder.ps1"
            TraceBackendDrioPath = "C:\Sandbox\runtime\trace_backend_drio.ps1"
            SysmonConfigPath = "C:\Sandbox\runtime\sysmon_config.xml"
            TaskName = $ScheduledTaskName
            TaskState = $scheduledTaskState
            RuntimeSize = (Get-Item "C:\Sandbox\runtime\run_task.ps1").Length
            LastWriteTime = (Get-Item "C:\Sandbox\runtime\run_task.ps1").LastWriteTime
            ProjectSysmonPath = $projectSysmonPath
            SysmonInstalledFromProject = $sysmonInstalledFromProject
            SysmonConfigured = $sysmonConfigured
            SysmonServiceName = $sysmonServiceName
            SysmonServiceStatus = $sysmonServiceStatus
            SysmonLogAvailable = $sysmonLogAvailable
            SysmonCommandExitCode = $sysmonCommandExitCode
            SysmonCommandStdOut = $sysmonCommandStdOut
            SysmonCommandStdErr = $sysmonCommandStdErr
            SysmonMessage = $sysmonMessage
        }
    } -ArgumentList $scriptContent, $traceBackendPlaceholderContent, $traceBackendDrioContent, $sysmonConfigContent, $sysmonBinaryBase64, $TaskName

    if (Test-Path $DrioClientBin32SourcePath) {
        Copy-Item -Path $DrioClientBin32SourcePath -Destination "C:\Sandbox\runtime\drio\bin32\shrike_drcov_nudge.dll" -ToSession $session -Force
        Write-Log -Message ("Deployed DRIO client 32-bit DLL via Copy-Item -ToSession") -LogPath $logPath
    }
    if (Test-Path $DrioClientBin64SourcePath) {
        Copy-Item -Path $DrioClientBin64SourcePath -Destination "C:\Sandbox\runtime\drio\bin64\shrike_drcov_nudge.dll" -ToSession $session -Force
        Write-Log -Message ("Deployed DRIO client 64-bit DLL via Copy-Item -ToSession") -LogPath $logPath
    }

    Invoke-Command -Session $session -ScriptBlock {
        param($GuestInstallRoot)

        function Copy-DrioClientDependencies {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Bitness
            )

            $libSuffix = $Bitness.Substring(3)
            $runtimeSourceDir = Join-Path $GuestInstallRoot ("lib{0}\release" -f $libSuffix)
            $extensionSourceDir = Join-Path $GuestInstallRoot ("ext\lib{0}\release" -f $libSuffix)
            $destinationDir = Join-Path "C:\Sandbox\runtime\drio" $Bitness
            $dependencySources = @{
                "dynamorio.dll" = $runtimeSourceDir
                "drmgr.dll" = $extensionSourceDir
                "drutil.dll" = $extensionSourceDir
                "drwrap.dll" = $extensionSourceDir
            }

            foreach ($dependencyName in @("dynamorio.dll", "drmgr.dll", "drutil.dll", "drwrap.dll")) {
                $sourcePath = Join-Path $dependencySources[$dependencyName] $dependencyName
                if (-not (Test-Path $sourcePath)) {
                    throw "Required DynamoRIO extension dependency not found: $sourcePath"
                }
                Copy-Item -Path $sourcePath -Destination (Join-Path $destinationDir $dependencyName) -Force
            }
        }

        Copy-DrioClientDependencies -Bitness "bin32"
        Copy-DrioClientDependencies -Bitness "bin64"
    } -ArgumentList $DynamoRIOGuestInstallRoot
    Write-Log -Message ("Deployed DRIO extension dependency DLLs from {0}" -f $DynamoRIOGuestInstallRoot) -LogPath $logPath

    } finally {
        if ($session) {
            Remove-PSSession -Session $session
        }
    }

    Write-Log -Message ("Installed guest runtime to {0}" -f $result.RuntimePath) -LogPath $logPath
    Write-Log -Message ("Installed trace backend placeholder to {0}" -f $result.TraceBackendPlaceholderPath) -LogPath $logPath
    Write-Log -Message ("Installed trace backend drio to {0}" -f $result.TraceBackendDrioPath) -LogPath $logPath
    Write-Log -Message ("Installed Sysmon config to {0}" -f $result.SysmonConfigPath) -LogPath $logPath
    Write-Log -Message ("Registered startup task {0}; state={1}" -f $result.TaskName, $result.TaskState) -LogPath $logPath
    Write-Log -Message ("Guest runtime size={0} bytes, lastWriteTime={1}" -f $result.RuntimeSize, $result.LastWriteTime) -LogPath $logPath
    Write-Log -Message ("ProjectSysmonPath={0}; SysmonInstalledFromProject={1}" -f $result.ProjectSysmonPath, $result.SysmonInstalledFromProject) -LogPath $logPath
    Write-Log -Message ("SysmonCommandExitCode={0}; stdout={1}; stderr={2}" -f $result.SysmonCommandExitCode, $result.SysmonCommandStdOut, $result.SysmonCommandStdErr) -LogPath $logPath
    Write-Log -Message ("SysmonConfigured={0}; service={1}; status={2}; logAvailable={3}; {4}" -f $result.SysmonConfigured, $result.SysmonServiceName, $result.SysmonServiceStatus, $result.SysmonLogAvailable, $result.SysmonMessage) -LogPath $logPath

    Write-Host ("Log file: {0}" -f $logPath)
} catch {
    Write-Log -Message $_.Exception.Message -LogPath $logPath -Level "ERROR"
    Write-Host ("Log file: {0}" -f $logPath)
    throw
}
