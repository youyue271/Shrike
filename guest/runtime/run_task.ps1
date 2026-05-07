$ErrorActionPreference = "Stop"

$runnerLog = "C:\Sandbox\output\runner.log"
$localOutputRoot = "C:\Sandbox\output"
$executionWindowSeconds = 120
$mediaWaitTimeoutSeconds = 120
$mediaPollIntervalSeconds = 3
$bootStabilizationSeconds = 30

New-Item -ItemType Directory -Force $localOutputRoot | Out-Null
Set-Content -Path $runnerLog -Value ""

function Write-RunnerLog {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $runnerLog -Value $line
}

function Export-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string]) -and @($InputObject).Count -eq 0) {
        Set-Content -Path $Path -Value "[]" -Encoding UTF8
        return
    }

    $InputObject | ConvertTo-Json -Depth 8 | Set-Content -Path $Path -Encoding UTF8
}

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

function Export-ProcessSnapshot {
    param([string]$Path)

    Get-CimInstance Win32_Process |
        Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine, CreationDate |
        Sort-Object Name, ProcessId |
        Export-Csv $Path -NoTypeInformation
}

function Export-ServiceSnapshot {
    param([string]$Path)

    Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, PathName |
        Sort-Object Name |
        Export-Csv $Path -NoTypeInformation
}

function Export-ScheduledTaskSnapshot {
    param([string]$Path)

    Get-ScheduledTask |
        Select-Object TaskName, TaskPath, State, Author, Description |
        Sort-Object TaskPath, TaskName |
        Export-Csv $Path -NoTypeInformation
}

function Export-TcpSnapshot {
    param([string]$Path)

    try {
        Get-NetTCPConnection |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
            Sort-Object LocalAddress, LocalPort, RemoteAddress, RemotePort |
            Export-Csv $Path -NoTypeInformation
    } catch {
        @() | Export-Csv $Path -NoTypeInformation
    }
}

function Export-UdpSnapshot {
    param([string]$Path)

    try {
        Get-NetUDPEndpoint |
            Select-Object LocalAddress, LocalPort, OwningProcess |
            Sort-Object LocalAddress, LocalPort |
            Export-Csv $Path -NoTypeInformation
    } catch {
        @() | Export-Csv $Path -NoTypeInformation
    }
}

function Export-DnsCacheSnapshot {
    param([string]$Path)

    try {
        Get-DnsClientCache |
            Select-Object Entry, RecordType, Data, TimeToLive, Status |
            Sort-Object Entry, RecordType |
            Export-Csv $Path -NoTypeInformation
    } catch {
        @() | Export-Csv $Path -NoTypeInformation
    }
}

function Export-RegistrySnapshot {
    param([string]$Path)

    $targets = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    $result = @()
    foreach ($target in $targets) {
        if (Test-Path $target) {
            $props = Get-ItemProperty -Path $target
            $entry = [ordered]@{
                Path = $target
                Values = @{}
            }

            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -notmatch "^PS") {
                    $entry.Values[$p.Name] = $p.Value
                }
            }

            $result += [PSCustomObject]$entry
        } else {
            $result += [PSCustomObject]@{
                Path = $target
                Values = @{}
            }
        }
    }

    Export-JsonFile -InputObject $result -Path $Path
}

function Export-StartupFolderSnapshot {
    param([string]$Path)

    $folders = @(
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    $entries = foreach ($folder in $folders) {
        if (Test-Path $folder) {
            Get-ChildItem -Path $folder -Force |
                Select-Object @{
                    Name = "Folder"
                    Expression = { $folder }
                }, Name, FullName, Length, LastWriteTime
        }
    }

    @($entries) | Export-Csv $Path -NoTypeInformation
}

function Export-SnapshotBundle {
    param(
        [string]$Prefix,
        [string]$ArtifactDir
    )

    Export-ProcessSnapshot -Path (Join-Path $ArtifactDir ("process_snapshot_{0}.csv" -f $Prefix))
    Export-ServiceSnapshot -Path (Join-Path $ArtifactDir ("service_snapshot_{0}.csv" -f $Prefix))
    Export-ScheduledTaskSnapshot -Path (Join-Path $ArtifactDir ("scheduled_task_snapshot_{0}.csv" -f $Prefix))
    Export-TcpSnapshot -Path (Join-Path $ArtifactDir ("tcp_snapshot_{0}.csv" -f $Prefix))
    Export-UdpSnapshot -Path (Join-Path $ArtifactDir ("udp_snapshot_{0}.csv" -f $Prefix))
    Export-DnsCacheSnapshot -Path (Join-Path $ArtifactDir ("dns_cache_{0}.csv" -f $Prefix))
    Export-RegistrySnapshot -Path (Join-Path $ArtifactDir ("autorun_registry_{0}.json" -f $Prefix))
    Export-StartupFolderSnapshot -Path (Join-Path $ArtifactDir ("startup_folders_{0}.csv" -f $Prefix))
    Write-RunnerLog ("exported {0} snapshot bundle" -f $Prefix)
}

function Publish-StagingArtifacts {
    param(
        [string]$StagingDir,
        [string]$ArtifactDir,
        [string]$Reason
    )

    if (-not (Test-Path $StagingDir)) {
        Write-RunnerLog ("staging publish skipped ({0}): staging directory missing" -f $Reason)
        return
    }

    New-Item -ItemType Directory -Force $ArtifactDir | Out-Null
    Write-RunnerLog ("copying staging to artifact disk ({0})" -f $Reason)
    Get-ChildItem -Path $StagingDir -Force -ErrorAction SilentlyContinue |
        Copy-Item -Destination $ArtifactDir -Recurse -Force -ErrorAction SilentlyContinue
}

function Get-SysmonEventObject {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

    $xml = [xml]$Event.ToXml()
    $data = [ordered]@{
        RecordId = $Event.RecordId
        TimeCreated = if ($Event.TimeCreated) { $Event.TimeCreated.ToString("o") } else { $null }
        Id = $Event.Id
        LevelDisplayName = $Event.LevelDisplayName
        ProviderName = $Event.ProviderName
        MachineName = $Event.MachineName
    }

    foreach ($node in $xml.Event.EventData.Data) {
        $name = $node.Name
        if (-not $name) { continue }
        $value = $node.'#text'
        if ($data.Contains($name)) {
            $name = "EventData_{0}" -f $name
        }
        $data[$name] = $value
    }

    [PSCustomObject]$data
}

function Export-SysmonCategory {
    param(
        [array]$Events,
        [int[]]$Ids,
        [string]$BaseName,
        [string]$ArtifactDir
    )

    $selected = $Events | Where-Object { $_.Id -in $Ids }
    $jsonPath = Join-Path $ArtifactDir ("{0}.json" -f $BaseName)

    if (-not $selected -or $selected.Count -eq 0) {
        Export-JsonFile -InputObject @() -Path $jsonPath
        Write-RunnerLog ("exported empty {0}.json" -f $BaseName)
        return
    }

    $objects = @($selected | ForEach-Object { Get-SysmonEventObject -Event $_ })
    Export-JsonFile -InputObject $objects -Path $jsonPath
    Write-RunnerLog ("exported {0}.json with {1} events" -f $BaseName, $objects.Count)
}

function Get-SysmonDataValue {
    param(
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event,
        [string]$Name
    )

    try {
        $xml = [xml]$Event.ToXml()
        foreach ($node in $xml.Event.EventData.Data) {
            if ($node.Name -eq $Name) {
                return $node.'#text'
            }
        }
    } catch {}

    return $null
}

function Get-RecentSysmonEvents {
    param([int]$MaxEvents = 16384)

    try {
        return @(Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents $MaxEvents -ErrorAction Stop)
    } catch {
        Write-RunnerLog ("recent sysmon query failed: {0}" -f $_.Exception.Message)
        return @()
    }
}

function Get-SysmonEventsInWindow {
    param(
        [array]$Events,
        [datetime]$WindowStart,
        [datetime]$WindowEnd
    )

    return @(
        $Events | Where-Object {
            $_.TimeCreated -and $_.TimeCreated -ge $WindowStart -and $_.TimeCreated -le $WindowEnd
        }
    )
}

function Get-SampleRelatedSysmonEvents {
    param(
        [array]$Events,
        [string]$SampleName,
        [int]$LaunchedPid
    )

    $sampleStem = [System.IO.Path]::GetFileNameWithoutExtension($SampleName).ToLowerInvariant()
    return @(
        $Events | Where-Object {
            $fields = @(
                (Get-SysmonDataValue -Event $_ -Name "Image"),
                (Get-SysmonDataValue -Event $_ -Name "ParentImage"),
                (Get-SysmonDataValue -Event $_ -Name "TargetFilename"),
                (Get-SysmonDataValue -Event $_ -Name "TargetObject"),
                (Get-SysmonDataValue -Event $_ -Name "QueryName"),
                (Get-SysmonDataValue -Event $_ -Name "SourceImage"),
                (Get-SysmonDataValue -Event $_ -Name "TargetImage"),
                (Get-SysmonDataValue -Event $_ -Name "CommandLine")
            ) | Where-Object { $_ }

            $textMatch = $false
            foreach ($field in $fields) {
                if ($field.ToString().ToLowerInvariant().Contains($sampleStem)) {
                    $textMatch = $true
                    break
                }
            }

            $pidFields = @(
                (Get-SysmonDataValue -Event $_ -Name "ProcessId"),
                (Get-SysmonDataValue -Event $_ -Name "ParentProcessId"),
                (Get-SysmonDataValue -Event $_ -Name "SourceProcessId"),
                (Get-SysmonDataValue -Event $_ -Name "TargetProcessId")
            ) | Where-Object { $_ }

            $pidMatch = $false
            foreach ($pidField in $pidFields) {
                if ($pidField -eq $LaunchedPid.ToString()) {
                    $pidMatch = $true
                    break
                }
            }

            return $textMatch -or $pidMatch
        }
    )
}

function Find-OfflineTaskMedia {
    $sampleDrive = $null
    $artifactDrive = $null

    Write-RunnerLog "=== Searching for media ==="
    $volumes = @(Get-Volume)
    Write-RunnerLog ("Found {0} volumes total" -f $volumes.Count)

    foreach ($vol in $volumes) {
        $letter = $vol.DriveLetter
        $label = $vol.FileSystemLabel
        $type = $vol.DriveType
        Write-RunnerLog ("Volume: DriveLetter={0} Label='{1}' Type={2}" -f $letter, $label, $type)

        if ($vol.DriveLetter) {
            $root = "$($vol.DriveLetter):\"
            $hasSampleFolder = Test-Path (Join-Path $root "sample")
            Write-RunnerLog ("  Checking {0} for 'sample' folder: {1}" -f $root, $hasSampleFolder)

            if ((-not $sampleDrive) -and $hasSampleFolder) {
                $sampleDrive = "$($vol.DriveLetter):"
                Write-RunnerLog ("  -> Found sample drive: {0}" -f $sampleDrive)
            }
            if ((-not $artifactDrive) -and ($vol.FileSystemLabel -eq "ARTIFACT")) {
                $artifactDrive = "$($vol.DriveLetter):"
                Write-RunnerLog ("  -> Found artifact drive: {0}" -f $artifactDrive)
            }
        }
    }

    Write-RunnerLog ("Media search result: SampleDrive={0} ArtifactDrive={1}" -f $sampleDrive, $artifactDrive)

    return [PSCustomObject]@{
        SampleDrive = $sampleDrive
        ArtifactDrive = $artifactDrive
    }
}

function Wait-ForOfflineTaskMedia {
    param(
        [int]$TimeoutSeconds,
        [int]$PollIntervalSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attemptCount = 0

    do {
        $attemptCount++

        # Try to refresh CD-ROM drives to force media detection
        if ($attemptCount -eq 1 -or ($attemptCount % 5) -eq 0) {
            try {
                $shell = New-Object -ComObject Shell.Application
                $drives = Get-WmiObject Win32_CDROMDrive
                foreach ($drive in $drives) {
                    try {
                        $drive.Drive | Out-Null
                    } catch {}
                }
            } catch {
                Write-RunnerLog ("CD-ROM refresh attempt failed: {0}" -f $_.Exception.Message)
            }
        }

        $media = Find-OfflineTaskMedia
        if ($media.SampleDrive -and $media.ArtifactDrive) {
            return $media
        }

        Start-Sleep -Seconds $PollIntervalSeconds
    } while ((Get-Date) -lt $deadline)

    return Find-OfflineTaskMedia
}

function Wait-ForBootStabilization {
    param([int]$Seconds)

    if ($Seconds -le 0) {
        return
    }

    Write-RunnerLog ("waiting {0} seconds for post-boot stabilization before pre snapshot" -f $Seconds)
    Start-Sleep -Seconds $Seconds
}

function Import-TaskProfile {
    param([string]$SampleDrive)

    $taskProfilePath = Join-Path $SampleDrive "task\task_profile.json"
    if (-not (Test-Path $taskProfilePath)) {
        return $null
    }

    try {
        $content = Get-Content -Path $taskProfilePath -Raw -Encoding UTF8
        return $content | ConvertFrom-Json
    } catch {
        throw ("failed to parse task profile: {0}" -f $_.Exception.Message)
    }
}

function Get-TaskProfileValue {
    param(
        $TaskProfile,
        [string]$Name,
        $Default = $null
    )

    if ($null -eq $TaskProfile) {
        return $Default
    }

    $prop = $TaskProfile.PSObject.Properties[$Name]
    if ($null -eq $prop) {
        return $Default
    }

    return $prop.Value
}

function Export-TraceArtifacts {
    param(
        $TaskProfile,
        $TaskRuntimeContext,
        [string]$ArtifactDir,
        [string]$SampleName,
        [string]$SamplePath,
        [int]$LaunchedPid,
        [datetime]$StartedAt,
        [datetime]$EndedAt,
        [string]$DrioLogDir = $null,
        [bool]$BypassAntidebug = $false
    )

    $traceMode = Get-TaskProfileValue -TaskProfile $TaskProfile -Name "trace_mode" -Default "none"
    $traceBackend = Get-TaskProfileValue -TaskProfile $TaskProfile -Name "trace_backend" -Default "none"
    $capture = Get-TaskProfileValue -TaskProfile $TaskProfile -Name "capture" -Default @{}
    $backendOptions = Get-TaskProfileValue -TaskProfile $TaskProfile -Name "backend_options" -Default @{}

    $traceRequest = [ordered]@{
        profile_name = Get-TaskProfileValue -TaskProfile $TaskProfile -Name "profile_name" -Default "default"
        trace_mode = $traceMode
        trace_backend = $traceBackend
        capture = $capture
        backend_options = $backendOptions
        sample_name = $SampleName
        sample_path = $SamplePath
        launched_pid = $LaunchedPid
        started_at = $StartedAt.ToString("o")
        ended_at = $EndedAt.ToString("o")
        drio_log_dir = $DrioLogDir
        bypass_antidebug_requested = $BypassAntidebug
    }
    Export-JsonFile -InputObject $traceRequest -Path (Join-Path $ArtifactDir "trace_request.json")
    Write-RunnerLog "exported trace_request.json"

    $expectedArtifacts = @("trace_request.json", "trace_manifest.json")
    $collectedArtifacts = @("trace_request.json")
    $traceStatus = "disabled"
    $traceReason = "task profile requested no deep trace backend"
    $backendDiagnostic = [ordered]@{
        command = $null
        exit_code = $null
        stdout = ""
        stderr = ""
    }

    if ($traceMode -ne "none") {
        $expectedArtifacts += @("dynamic_cfg_trace_summary.json", "dynamic_cfg_trace.ndjson", "trace_backend_diagnostic.json")

        $traceOutputPath = Join-Path $ArtifactDir "dynamic_cfg_trace.ndjson"
        $traceSummaryPath = Join-Path $ArtifactDir "dynamic_cfg_trace_summary.json"
        $traceDiagnosticPath = Join-Path $ArtifactDir "trace_backend_diagnostic.json"

        if ($traceMode -eq "dynamic_cfg" -and ($traceBackend -eq "placeholder" -or $traceBackend -eq "drio")) {
            $backendScript = if ($traceBackend -eq "drio") {
                "C:\Sandbox\runtime\trace_backend_drio.ps1"
            } else {
                "C:\Sandbox\runtime\trace_backend_placeholder.ps1"
            }

            if (-not (Test-Path $backendScript)) {
                $traceStatus = "backend_missing"
                $traceReason = ("trace backend script not found: {0}" -f $backendScript)
                Write-RunnerLog $traceReason
            } else {
                Write-RunnerLog ("invoking trace backend script={0}" -f $backendScript)

                # Pre-compute paths to avoid null issues in ArgumentList
                $requestJsonPath = Join-Path $ArtifactDir "trace_request.json"

                $backendDiagnostic.command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $backendScript -RequestPath $requestJsonPath -OutputPath $traceOutputPath -SummaryPath $traceSummaryPath"
                $backendResult = Invoke-NativeCommandSafe -FilePath "powershell.exe" -ArgumentList @(
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-File", $backendScript,
                    "-RequestPath", $requestJsonPath,
                    "-OutputPath", $traceOutputPath,
                    "-SummaryPath", $traceSummaryPath
                )
                $backendDiagnostic.exit_code = $backendResult.ExitCode
                $backendDiagnostic.stdout = $backendResult.StdOut
                $backendDiagnostic.stderr = $backendResult.StdErr

                if ($backendResult.ExitCode -ne 0) {
                    $traceStatus = "backend_failed"
                    $traceReason = ("trace backend exited with code {0}" -f $backendResult.ExitCode)
                    Write-RunnerLog $traceReason
                    if ($backendResult.StdOut) {
                        Write-RunnerLog ("trace backend stdout: {0}" -f $backendResult.StdOut)
                    }
                    if ($backendResult.StdErr) {
                        Write-RunnerLog ("trace backend stderr: {0}" -f $backendResult.StdErr)
                    }
                } else {
                    $traceStatus = "completed"
                    $traceReason = "trace backend completed successfully"
                    if (Test-Path $traceSummaryPath) {
                        try {
                            $backendSummary = Get-Content -Path $traceSummaryPath -Raw -Encoding UTF8 | ConvertFrom-Json
                            if ($backendSummary.status) {
                                $traceStatus = [string]$backendSummary.status
                            }
                            if ($backendSummary.notes -and $backendSummary.notes.Count -gt 0) {
                                $traceReason = [string]$backendSummary.notes[0]
                            }
                        } catch {
                            Write-RunnerLog ("trace backend summary parse failed: {0}" -f $_.Exception.Message)
                        }
                    }
                    Write-RunnerLog "trace backend completed"
                }
            }
        } else {
            $traceStatus = "backend_not_supported"
            $traceReason = ("unsupported trace backend '{0}' for mode '{1}'" -f $traceBackend, $traceMode)
            Write-RunnerLog $traceReason
        }

        foreach ($artifactName in @("dynamic_cfg_trace_summary.json", "dynamic_cfg_trace.ndjson")) {
            if (Test-Path (Join-Path $ArtifactDir $artifactName)) {
                $collectedArtifacts += $artifactName
            }
        }
        Export-JsonFile -InputObject $backendDiagnostic -Path $traceDiagnosticPath
        $collectedArtifacts += "trace_backend_diagnostic.json"
    }

    $collectedArtifacts += "trace_manifest.json"
    $traceManifest = [ordered]@{
        trace_mode = $traceMode
        trace_backend = $traceBackend
        status = $traceStatus
        reason = $traceReason
        expected_artifacts = $expectedArtifacts
        collected_artifacts = $collectedArtifacts
        runtime_context = $TaskRuntimeContext
    }
    Export-JsonFile -InputObject $traceManifest -Path (Join-Path $ArtifactDir "trace_manifest.json")
    Write-RunnerLog "exported trace_manifest.json"
}

try {
    Write-RunnerLog "task start"

    Write-RunnerLog ("waiting for sample/artifact media up to {0} seconds" -f $mediaWaitTimeoutSeconds)
    $media = Wait-ForOfflineTaskMedia -TimeoutSeconds $mediaWaitTimeoutSeconds -PollIntervalSeconds $mediaPollIntervalSeconds
    $sampleDrive = $media.SampleDrive
    $artifactDrive = $media.ArtifactDrive

    Write-RunnerLog ("sampleDrive={0}" -f $sampleDrive)
    Write-RunnerLog ("artifactDrive={0}" -f $artifactDrive)

    if (-not $sampleDrive -or -not $artifactDrive) {
        Write-RunnerLog "sample or artifact media not present; exiting without analysis"
        Stop-Computer -Force
        exit 0
    }

    $taskProfile = Import-TaskProfile -SampleDrive $sampleDrive
    if ($taskProfile) {
        $profileName = Get-TaskProfileValue -TaskProfile $taskProfile -Name "profile_name" -Default "unnamed"
        $traceMode = Get-TaskProfileValue -TaskProfile $taskProfile -Name "trace_mode" -Default "none"
        $traceBackend = Get-TaskProfileValue -TaskProfile $taskProfile -Name "trace_backend" -Default "none"
        $networkMode = Get-TaskProfileValue -TaskProfile $taskProfile -Name "network_mode" -Default "airgap"
        $userSimulation = Get-TaskProfileValue -TaskProfile $taskProfile -Name "user_simulation" -Default "none"
        Write-RunnerLog ("loaded task profile name={0} trace_mode={1} trace_backend={2} network_mode={3} user_simulation={4}" -f $profileName, $traceMode, $traceBackend, $networkMode, $userSimulation)

        $profileExecutionWindowSeconds = Get-TaskProfileValue -TaskProfile $taskProfile -Name "execution_window_seconds" -Default $executionWindowSeconds
        if ($profileExecutionWindowSeconds) {
            $executionWindowSeconds = [int]$profileExecutionWindowSeconds
        }

        $profileBootStabilizationSeconds = Get-TaskProfileValue -TaskProfile $taskProfile -Name "boot_stabilization_seconds" -Default $bootStabilizationSeconds
        if ($profileBootStabilizationSeconds -or $profileBootStabilizationSeconds -eq 0) {
            $bootStabilizationSeconds = [int]$profileBootStabilizationSeconds
        }
    } else {
        Write-RunnerLog "no task profile present on sample media; using built-in defaults"
    }

    Wait-ForBootStabilization -Seconds $bootStabilizationSeconds

    # Configure network for ResultServer communication (non-fatal)
    Write-RunnerLog "configuring network for ResultServer"
    try {
        & "$PSScriptRoot\configure_network.ps1" -ErrorAction SilentlyContinue
        Write-RunnerLog "network configuration completed"
    } catch {
        Write-RunnerLog "network configuration skipped: $_"
    }

    $sampleDir = Join-Path $sampleDrive "sample"
    $artifactDir = Join-Path $artifactDrive "artifact"
    $stagingDir = Join-Path $localOutputRoot "staging"
    $drioLogDirRoot = Join-Path $localOutputRoot "drio_logs"
    $localInput = "C:\Sandbox\input"

    Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $drioLogDirRoot -Recurse -Force -ErrorAction SilentlyContinue

    New-Item -ItemType Directory -Force $localInput | Out-Null
    New-Item -ItemType Directory -Force $artifactDir | Out-Null
    New-Item -ItemType Directory -Force $stagingDir | Out-Null
    Get-ChildItem -Path $localInput -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    Export-SnapshotBundle -Prefix "pre" -ArtifactDir $stagingDir

    Get-ChildItem $sampleDir | Copy-Item -Destination $localInput -Force
    Write-RunnerLog "copied sample to local input"

    $sample = Get-ChildItem $localInput | Select-Object -First 1
    if (-not $sample) { throw "no sample found" }

    $start = Get-Date
    $sampleHash = Get-FileHash -Path $sample.FullName -Algorithm SHA256
    Write-RunnerLog ("launching sample {0}" -f $sample.FullName)

    $drioLogDir = $null
    $bypassAntidebug = $false
    $traceBackendName = Get-TaskProfileValue -TaskProfile $taskProfile -Name "trace_backend" -Default "none"
    $traceModeName = Get-TaskProfileValue -TaskProfile $taskProfile -Name "trace_mode" -Default "none"

    if ($traceModeName -eq "dynamic_cfg" -and $traceBackendName -eq "drio") {
        $drioLogDir = $drioLogDirRoot
        New-Item -ItemType Directory -Force $drioLogDir | Out-Null

        $is32bit = $false
        try {
            $fs = [System.IO.File]::Open($sample.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $br = New-Object System.IO.BinaryReader($fs)
            $fs.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
            $peOffset = $br.ReadInt32()
            $fs.Seek($peOffset + 4, [System.IO.SeekOrigin]::Begin) | Out-Null
            $machine = $br.ReadUInt16()
            if ($machine -eq 0x014C) { $is32bit = $true }
            $fs.Dispose()
        } catch {
            Write-RunnerLog ("PE header read failed: {0}; assuming 64-bit" -f $_.Exception.Message)
        }

        $drrunExe = if ($is32bit) { "C:\Tools\DynamoRIO\bin32\drrun.exe" } else { "C:\Tools\DynamoRIO\bin64\drrun.exe" }
        $clientDll = if ($is32bit) { "C:\Sandbox\runtime\drio\bin32\shrike_drcov_nudge.dll" } else { "C:\Sandbox\runtime\drio\bin64\shrike_drcov_nudge.dll" }

        if ((Test-Path $drrunExe) -and (Test-Path $clientDll)) {
            $backendOpts = Get-TaskProfileValue -TaskProfile $taskProfile -Name "backend_options" -Default @{}
            $bypassAntidebug = $false
            if ($backendOpts) {
                $prop = $backendOpts.PSObject.Properties["bypass_antidebug"]
                if ($prop -and $prop.Value -eq $true) { $bypassAntidebug = $true }
            }

            $launchPath = $sample.FullName
            if (-not $sample.Extension) {
                $launchPath = Join-Path $sample.DirectoryName ("{0}.exe" -f $sample.Name)
                Copy-Item -Path $sample.FullName -Destination $launchPath -Force
                Write-RunnerLog ("created .exe copy for extensionless DRIO sample: {0}" -f $launchPath)
            }

            $drrunArgs = @("-c", $clientDll, "-logdir", $drioLogDir, "-result_server_host", "192.168.100.1", "-result_server_port", "2042")
            if ($bypassAntidebug) {
                $drrunArgs += "-bypass_antidebug"
            }
            $drrunArgs += @("--", $launchPath)

            $drrunStdoutPath = Join-Path $stagingDir "drrun_stdout.txt"
            $drrunStderrPath = Join-Path $stagingDir "drrun_stderr.txt"
            Write-RunnerLog ("launching via drrun: {0} {1}" -f $drrunExe, ($drrunArgs -join " "))
            $proc = Start-Process -FilePath $drrunExe -ArgumentList $drrunArgs -RedirectStandardOutput $drrunStdoutPath -RedirectStandardError $drrunStderrPath -PassThru
        } else {
            Write-RunnerLog ("drrun or client DLL not found (drrun={0} client={1}); launching sample directly" -f $drrunExe, $clientDll)
            $launchPath = $sample.FullName
            if (-not $sample.Extension) {
                $launchPath = Join-Path $sample.DirectoryName ("{0}.exe" -f $sample.Name)
                Copy-Item -Path $sample.FullName -Destination $launchPath -Force
                Write-RunnerLog ("created .exe copy for extensionless sample: {0}" -f $launchPath)
            }
            $proc = Start-Process -FilePath $launchPath -PassThru
        }
    } else {
        $launchPath = $sample.FullName
        if (-not $sample.Extension) {
            $launchPath = Join-Path $sample.DirectoryName ("{0}.exe" -f $sample.Name)
            Copy-Item -Path $sample.FullName -Destination $launchPath -Force
            Write-RunnerLog ("created .exe copy for extensionless sample: {0}" -f $launchPath)
        }
        $proc = Start-Process -FilePath $launchPath -PassThru
    }
    Write-RunnerLog ("launched sample pid={0}" -f $proc.Id)
    $plannedTraceEnd = $start.AddSeconds($executionWindowSeconds)

    $sampleMetadata = [ordered]@{
        sample_name = $sample.Name
        sample_path = $sample.FullName
        sample_sha256 = $sampleHash.Hash
        sample_size = $sample.Length
        launched_pid = $proc.Id
        execution_window_seconds = $executionWindowSeconds
    }
    Export-JsonFile -InputObject $sampleMetadata -Path (Join-Path $stagingDir "sample_metadata.json")
    Write-RunnerLog "exported sample_metadata.json"

    if ($taskProfile) {
        Export-JsonFile -InputObject $taskProfile -Path (Join-Path $stagingDir "task_profile.json")
        Write-RunnerLog "exported task_profile.json"
    }

    $taskRuntimeContext = [ordered]@{
        execution_window_seconds = $executionWindowSeconds
        boot_stabilization_seconds = $bootStabilizationSeconds
        trace_mode = Get-TaskProfileValue -TaskProfile $taskProfile -Name "trace_mode" -Default "none"
        trace_backend = Get-TaskProfileValue -TaskProfile $taskProfile -Name "trace_backend" -Default "none"
        network_mode = Get-TaskProfileValue -TaskProfile $taskProfile -Name "network_mode" -Default "airgap"
        user_simulation = Get-TaskProfileValue -TaskProfile $taskProfile -Name "user_simulation" -Default "none"
        profile_name = Get-TaskProfileValue -TaskProfile $taskProfile -Name "profile_name" -Default "default"
    }
    Export-JsonFile -InputObject $taskRuntimeContext -Path (Join-Path $stagingDir "task_runtime_context.json")
    Write-RunnerLog "exported task_runtime_context.json"

    if ($traceBackendName -ne "drio") {
        Export-TraceArtifacts -TaskProfile $taskProfile -TaskRuntimeContext $taskRuntimeContext -ArtifactDir $stagingDir -SampleName $sample.Name -SamplePath $sample.FullName -LaunchedPid $proc.Id -StartedAt $start -EndedAt $plannedTraceEnd -DrioLogDir $drioLogDir -BypassAntidebug $bypassAntidebug
        Copy-Item $runnerLog -Destination (Join-Path $stagingDir "runner.log") -Force
        Publish-StagingArtifacts -StagingDir $stagingDir -ArtifactDir $artifactDir -Reason "after trace export"
    }

    Start-Sleep -Seconds $executionWindowSeconds

    $end = Get-Date
    Write-RunnerLog "execution window ended"

    try {
        $sampleProc = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
        if ($sampleProc -and -not $sampleProc.HasExited) {
            $sampleProc.Kill()
            Write-RunnerLog ("killed sample process pid={0}" -f $proc.Id)
        }
    } catch {}
    try {
        Get-Process | Where-Object { $_.Path -and $_.Path -like "*\Sandbox\input\*" } | ForEach-Object {
            $_.Kill()
            Write-RunnerLog ("killed child process pid={0} path={1}" -f $_.Id, $_.Path)
        }
    } catch {}

    if ($traceBackendName -eq "drio") {
        Export-TraceArtifacts -TaskProfile $taskProfile -TaskRuntimeContext $taskRuntimeContext -ArtifactDir $stagingDir -SampleName $sample.Name -SamplePath $sample.FullName -LaunchedPid $proc.Id -StartedAt $start -EndedAt $plannedTraceEnd -DrioLogDir $drioLogDir -BypassAntidebug $bypassAntidebug
        Copy-Item $runnerLog -Destination (Join-Path $stagingDir "runner.log") -Force
        Publish-StagingArtifacts -StagingDir $stagingDir -ArtifactDir $artifactDir -Reason "after trace export"
    }

    Export-SnapshotBundle -Prefix "post" -ArtifactDir $stagingDir

    try {
        wevtutil epl Microsoft-Windows-Sysmon/Operational (Join-Path $stagingDir "sysmon.evtx")
        Write-RunnerLog "exported sysmon.evtx"
    } catch {
        Write-RunnerLog ("sysmon export failed: {0}" -f $_.Exception.Message)
    }

    try {
        wevtutil epl Microsoft-Windows-PowerShell/Operational (Join-Path $stagingDir "powershell_operational.evtx")
        Write-RunnerLog "exported powershell_operational.evtx"
    } catch {
        Write-RunnerLog ("powershell operational export failed: {0}" -f $_.Exception.Message)
    }

    $windowStart = $start.AddSeconds(-10)
    $windowEnd = $end.AddSeconds(10)
    $recentSysmonEvents = Get-RecentSysmonEvents -MaxEvents 16384
    Write-RunnerLog ("collected {0} recent sysmon events from live log" -f $recentSysmonEvents.Count)

    $sysmonEvents = Get-SysmonEventsInWindow -Events $recentSysmonEvents -WindowStart $windowStart -WindowEnd $windowEnd
    if ($sysmonEvents.Count -gt 0) {
        Write-RunnerLog ("collected {0} sysmon events in time window" -f $sysmonEvents.Count)
    } else {
        $sysmonEvents = Get-SampleRelatedSysmonEvents -Events $recentSysmonEvents -SampleName $sample.Name -LaunchedPid $proc.Id
        if ($sysmonEvents.Count -gt 0) {
            Write-RunnerLog ("time-window sysmon query returned 0 events; fallback sample-related query collected {0} events" -f $sysmonEvents.Count)
        } else {
            Write-RunnerLog "sysmon query failed: no events found in time window or sample-related fallback query"
        }
    }

    Export-JsonFile -InputObject @(
        [PSCustomObject]@{
            recent_event_count = $recentSysmonEvents.Count
            selected_event_count = $sysmonEvents.Count
            window_start = $windowStart.ToString("o")
            window_end = $windowEnd.ToString("o")
            sample_name = $sample.Name
            launched_pid = $proc.Id
        }
    ) -Path (Join-Path $stagingDir "sysmon_diagnostic.json")
    Write-RunnerLog "exported sysmon_diagnostic.json"

    $sysmonSummary = $sysmonEvents |
        Group-Object Id |
        Sort-Object Name |
        ForEach-Object {
            [PSCustomObject]@{
                EventId = [int]$_.Name
                Count = $_.Count
            }
        }
    Export-JsonFile -InputObject @($sysmonSummary) -Path (Join-Path $stagingDir "sysmon_summary.json")
    Write-RunnerLog "exported sysmon_summary.json"

    Export-SysmonCategory -Events $sysmonEvents -Ids @(1, 5) -BaseName "sysmon_process_events" -ArtifactDir $stagingDir
    Export-SysmonCategory -Events $sysmonEvents -Ids @(3, 22) -BaseName "sysmon_network_dns_events" -ArtifactDir $stagingDir
    Export-SysmonCategory -Events $sysmonEvents -Ids @(2, 11, 15, 23, 26, 29) -BaseName "sysmon_file_events" -ArtifactDir $stagingDir
    Export-SysmonCategory -Events $sysmonEvents -Ids @(12, 13, 14) -BaseName "sysmon_registry_events" -ArtifactDir $stagingDir
    Export-SysmonCategory -Events $sysmonEvents -Ids @(8, 10, 25) -BaseName "sysmon_injection_events" -ArtifactDir $stagingDir
    Export-SysmonCategory -Events $sysmonEvents -Ids @(17, 18, 19, 20, 21) -BaseName "sysmon_ipc_wmi_events" -ArtifactDir $stagingDir

    @{
        started_at = $start.ToString("o")
        ended_at = $end.ToString("o")
        sample_name = $sample.Name
        sample_sha256 = $sampleHash.Hash
        sample_size = $sample.Length
        launched_pid = $proc.Id
        execution_window_seconds = $executionWindowSeconds
        sysmon_event_count = $sysmonEvents.Count
    } |
        ConvertTo-Json |
        Set-Content (Join-Path $stagingDir "task_summary.json")
    Write-RunnerLog "exported task_summary.json"

    Copy-Item $runnerLog -Destination (Join-Path $stagingDir "runner.log") -Force

    Publish-StagingArtifacts -StagingDir $stagingDir -ArtifactDir $artifactDir -Reason "final"

    Stop-Computer -Force
} catch {
    Write-RunnerLog ("fatal error: {0}" -f $_.Exception.Message)
    try {
        if ($artifactDrive) {
            $artifactDir = Join-Path $artifactDrive "artifact"
            New-Item -ItemType Directory -Force $artifactDir | Out-Null
            Copy-Item $runnerLog -Destination (Join-Path $artifactDir "runner.log") -Force
        }
    } catch {}
    throw
}
