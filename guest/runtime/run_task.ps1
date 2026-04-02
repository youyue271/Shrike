$ErrorActionPreference = "Stop"

$runnerLog = "C:\Sandbox\output\runner.log"
$localOutputRoot = "C:\Sandbox\output"
$executionWindowSeconds = 120
$mediaWaitTimeoutSeconds = 90
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

    foreach ($vol in Get-Volume) {
        if ($vol.DriveLetter) {
            $root = "$($vol.DriveLetter):\"
            if ((-not $sampleDrive) -and (Test-Path (Join-Path $root "sample"))) {
                $sampleDrive = "$($vol.DriveLetter):"
            }
            if ((-not $artifactDrive) -and (Test-Path (Join-Path $root "artifact"))) {
                $artifactDrive = "$($vol.DriveLetter):"
            }
        }
    }

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
    do {
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
        [int]$LaunchedPid,
        [datetime]$StartedAt,
        [datetime]$EndedAt
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
        launched_pid = $LaunchedPid
        started_at = $StartedAt.ToString("o")
        ended_at = $EndedAt.ToString("o")
    }
    Export-JsonFile -InputObject $traceRequest -Path (Join-Path $ArtifactDir "trace_request.json")
    Write-RunnerLog "exported trace_request.json"

    $expectedArtifacts = @("trace_request.json", "trace_manifest.json")
    $collectedArtifacts = @("trace_request.json")
    $traceStatus = "disabled"
    $traceReason = "task profile requested no deep trace backend"

    if ($traceMode -eq "none") {
    } else {
        $traceStatus = "placeholder_not_implemented"
        $traceReason = "trace profile propagated end-to-end, but no collector backend is wired into the guest runtime yet"

        if ($traceMode -eq "dynamic_cfg") {
            $expectedArtifacts += @("dynamic_cfg_trace_summary.json", "dynamic_cfg_trace.ndjson")

            $dynamicCfgSummary = [ordered]@{
                trace_mode = $traceMode
                trace_backend = $traceBackend
                status = $traceStatus
                sample_name = $SampleName
                launched_pid = $LaunchedPid
                started_at = $StartedAt.ToString("o")
                ended_at = $EndedAt.ToString("o")
                basic_block_count = 0
                edge_count = 0
                module_count = 0
                modules = @()
                notes = @(
                    "This profile now requests dynamic CFG capture.",
                    "A real backend still needs to be integrated in the dev branch.",
                    "The intended future artifact is dynamic_cfg_trace.ndjson."
                )
            }
            Export-JsonFile -InputObject $dynamicCfgSummary -Path (Join-Path $ArtifactDir "dynamic_cfg_trace_summary.json")
            Export-JsonFile -InputObject @() -Path (Join-Path $ArtifactDir "dynamic_cfg_trace.ndjson")
            $collectedArtifacts += @("dynamic_cfg_trace_summary.json", "dynamic_cfg_trace.ndjson")
            Write-RunnerLog "exported dynamic_cfg trace placeholder artifacts"
        }
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

    $sampleDir = Join-Path $sampleDrive "sample"
    $artifactDir = Join-Path $artifactDrive "artifact"
    $localInput = "C:\Sandbox\input"

    New-Item -ItemType Directory -Force $localInput | Out-Null
    New-Item -ItemType Directory -Force $artifactDir | Out-Null
    Get-ChildItem -Path $localInput -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    Export-SnapshotBundle -Prefix "pre" -ArtifactDir $artifactDir

    Get-ChildItem $sampleDir | Copy-Item -Destination $localInput -Force
    Write-RunnerLog "copied sample to local input"

    $sample = Get-ChildItem $localInput | Select-Object -First 1
    if (-not $sample) { throw "no sample found" }

    $start = Get-Date
    $sampleHash = Get-FileHash -Path $sample.FullName -Algorithm SHA256
    Write-RunnerLog ("launching sample {0}" -f $sample.FullName)

    $proc = Start-Process -FilePath $sample.FullName -PassThru
    Write-RunnerLog ("launched sample pid={0}" -f $proc.Id)
    Start-Sleep -Seconds $executionWindowSeconds

    $end = Get-Date
    Write-RunnerLog "execution window ended"

    Export-SnapshotBundle -Prefix "post" -ArtifactDir $artifactDir

    try {
        wevtutil epl Microsoft-Windows-Sysmon/Operational (Join-Path $artifactDir "sysmon.evtx")
        Write-RunnerLog "exported sysmon.evtx"
    } catch {
        Write-RunnerLog ("sysmon export failed: {0}" -f $_.Exception.Message)
    }

    try {
        wevtutil epl Microsoft-Windows-PowerShell/Operational (Join-Path $artifactDir "powershell_operational.evtx")
        Write-RunnerLog "exported powershell_operational.evtx"
    } catch {
        Write-RunnerLog ("powershell operational export failed: {0}" -f $_.Exception.Message)
    }

    $sampleMetadata = [ordered]@{
        sample_name = $sample.Name
        sample_path = $sample.FullName
        sample_sha256 = $sampleHash.Hash
        sample_size = $sample.Length
        launched_pid = $proc.Id
        execution_window_seconds = $executionWindowSeconds
    }
    Export-JsonFile -InputObject $sampleMetadata -Path (Join-Path $artifactDir "sample_metadata.json")
    Write-RunnerLog "exported sample_metadata.json"

    if ($taskProfile) {
        Export-JsonFile -InputObject $taskProfile -Path (Join-Path $artifactDir "task_profile.json")
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
    Export-JsonFile -InputObject $taskRuntimeContext -Path (Join-Path $artifactDir "task_runtime_context.json")
    Write-RunnerLog "exported task_runtime_context.json"

    Export-TraceArtifacts -TaskProfile $taskProfile -TaskRuntimeContext $taskRuntimeContext -ArtifactDir $artifactDir -SampleName $sample.Name -LaunchedPid $proc.Id -StartedAt $start -EndedAt $end

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
    ) -Path (Join-Path $artifactDir "sysmon_diagnostic.json")
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
    Export-JsonFile -InputObject @($sysmonSummary) -Path (Join-Path $artifactDir "sysmon_summary.json")
    Write-RunnerLog "exported sysmon_summary.json"

    Export-SysmonCategory -Events $sysmonEvents -Ids @(1, 5) -BaseName "sysmon_process_events" -ArtifactDir $artifactDir
    Export-SysmonCategory -Events $sysmonEvents -Ids @(3, 22) -BaseName "sysmon_network_dns_events" -ArtifactDir $artifactDir
    Export-SysmonCategory -Events $sysmonEvents -Ids @(2, 11, 15, 23, 26, 29) -BaseName "sysmon_file_events" -ArtifactDir $artifactDir
    Export-SysmonCategory -Events $sysmonEvents -Ids @(12, 13, 14) -BaseName "sysmon_registry_events" -ArtifactDir $artifactDir
    Export-SysmonCategory -Events $sysmonEvents -Ids @(8, 10, 25) -BaseName "sysmon_injection_events" -ArtifactDir $artifactDir
    Export-SysmonCategory -Events $sysmonEvents -Ids @(17, 18, 19, 20, 21) -BaseName "sysmon_ipc_wmi_events" -ArtifactDir $artifactDir

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
        Set-Content (Join-Path $artifactDir "task_summary.json")
    Write-RunnerLog "exported task_summary.json"

    Copy-Item $runnerLog -Destination (Join-Path $artifactDir "runner.log") -Force

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
