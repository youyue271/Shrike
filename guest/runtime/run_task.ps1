$ErrorActionPreference = "Stop"

$runnerLog = "C:\Sandbox\output\runner.log"
$localOutputRoot = "C:\Sandbox\output"
$executionWindowSeconds = 120
$mediaWaitTimeoutSeconds = 90
$mediaPollIntervalSeconds = 3

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

    $sampleDir = Join-Path $sampleDrive "sample"
    $artifactDir = Join-Path $artifactDrive "artifact"
    $localInput = "C:\Sandbox\input"

    New-Item -ItemType Directory -Force $localInput | Out-Null
    New-Item -ItemType Directory -Force $artifactDir | Out-Null

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

    $windowStart = $start.AddSeconds(-10)
    $windowEnd = $end.AddSeconds(10)
    try {
        $sysmonEvents = @(Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-Sysmon/Operational"
            StartTime = $windowStart
            EndTime = $windowEnd
        } -ErrorAction Stop)
        Write-RunnerLog ("collected {0} sysmon events in time window" -f $sysmonEvents.Count)
    } catch {
        $sysmonEvents = @()
        Write-RunnerLog ("sysmon query failed: {0}" -f $_.Exception.Message)
    }

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
