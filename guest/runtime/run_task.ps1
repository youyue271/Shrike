$ErrorActionPreference = "Stop"

$runnerLog = "C:\Sandbox\output\runner.log"
$localOutputRoot = "C:\Sandbox\output"
$executionWindowSeconds = 120
$mediaWaitTimeoutSeconds = 120
$mediaPollIntervalSeconds = 3
$bootStabilizationSeconds = 30
$sampleExitWaitSeconds = 10
$runnerLogLines = New-Object 'System.Collections.Generic.List[string]'
$script:TraceBackendScriptContentCache = @{}

New-Item -ItemType Directory -Force $localOutputRoot | Out-Null
Set-Content -Path $runnerLog -Value ""

function Write-RunnerLog {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    $script:runnerLogLines.Add($line)
    Add-Content -Path $runnerLog -Value $line
}

function Save-RunnerLogSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    $parent = Split-Path -Parent $Destination
    if ($parent) {
        New-Item -ItemType Directory -Force $parent | Out-Null
    }

    [System.IO.File]::WriteAllLines($Destination, $script:runnerLogLines, [System.Text.Encoding]::UTF8)
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

function ConvertTo-JsonText {
    param($InputObject)

    if (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string]) -and @($InputObject).Count -eq 0) {
        return "[]"
    }

    return ($InputObject | ConvertTo-Json -Depth 8)
}

function ConvertTo-CsvText {
    param($Rows)

    if ($null -eq $Rows) {
        return ""
    }

    $rowArray = @($Rows)
    if ($rowArray.Count -eq 0) {
        return ""
    }

    $csvLines = @($rowArray | ConvertTo-Csv -NoTypeInformation)
    if ($csvLines.Count -eq 0) {
        return ""
    }
    return ($csvLines -join [Environment]::NewLine) + [Environment]::NewLine
}

function New-TextResultArtifact {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string]$Content
    )

    if ($null -eq $Content) {
        $Content = ""
    }

    return [PSCustomObject]@{
        Name = $Name
        Content = $Content
    }
}

function Write-BufferedResultArtifacts {
    param(
        [array]$Artifacts,
        [string]$ArtifactDir
    )

    foreach ($artifact in @($Artifacts)) {
        $path = Join-Path $ArtifactDir ([string]$artifact.Name)
        Set-Content -Path $path -Value ([string]$artifact.Content) -Encoding UTF8
        Write-RunnerLog ("materialized buffered result artifact {0}" -f $artifact.Name)
    }
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

function Get-RegistrySnapshotEntries {
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

    return @($result)
}

function Get-StartupFolderSnapshotRows {
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

    return @($entries)
}

function New-SnapshotBundleArtifacts {
    param([string]$Prefix)

    $artifacts = @()
    $artifacts += New-TextResultArtifact -Name ("process_snapshot_{0}.csv" -f $Prefix) -Content (ConvertTo-CsvText -Rows (
        Get-CimInstance Win32_Process |
            Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine, CreationDate |
            Sort-Object Name, ProcessId
    ))
    $artifacts += New-TextResultArtifact -Name ("service_snapshot_{0}.csv" -f $Prefix) -Content (ConvertTo-CsvText -Rows (
        Get-CimInstance Win32_Service |
            Select-Object Name, DisplayName, State, StartMode, PathName |
            Sort-Object Name
    ))
    $artifacts += New-TextResultArtifact -Name ("scheduled_task_snapshot_{0}.csv" -f $Prefix) -Content (ConvertTo-CsvText -Rows (
        Get-ScheduledTask |
            Select-Object TaskName, TaskPath, State, Author, Description |
            Sort-Object TaskPath, TaskName
    ))

    try {
        $tcpRows = Get-NetTCPConnection |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
            Sort-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
    } catch {
        $tcpRows = @()
    }
    $artifacts += New-TextResultArtifact -Name ("tcp_snapshot_{0}.csv" -f $Prefix) -Content (ConvertTo-CsvText -Rows $tcpRows)

    try {
        $udpRows = Get-NetUDPEndpoint |
            Select-Object LocalAddress, LocalPort, OwningProcess |
            Sort-Object LocalAddress, LocalPort
    } catch {
        $udpRows = @()
    }
    $artifacts += New-TextResultArtifact -Name ("udp_snapshot_{0}.csv" -f $Prefix) -Content (ConvertTo-CsvText -Rows $udpRows)

    try {
        $dnsRows = Get-DnsClientCache |
            Select-Object Entry, RecordType, Data, TimeToLive, Status |
            Sort-Object Entry, RecordType
    } catch {
        $dnsRows = @()
    }
    $artifacts += New-TextResultArtifact -Name ("dns_cache_{0}.csv" -f $Prefix) -Content (ConvertTo-CsvText -Rows $dnsRows)
    $artifacts += New-TextResultArtifact -Name ("autorun_registry_{0}.json" -f $Prefix) -Content (ConvertTo-JsonText -InputObject (Get-RegistrySnapshotEntries))
    $artifacts += New-TextResultArtifact -Name ("startup_folders_{0}.csv" -f $Prefix) -Content (ConvertTo-CsvText -Rows (Get-StartupFolderSnapshotRows))
    Write-RunnerLog ("captured {0} snapshot bundle in memory" -f $Prefix)
    return @($artifacts)
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

function Get-TraceBackendScriptPath {
    param(
        [string]$TraceMode,
        [string]$TraceBackend
    )

    if ($TraceMode -ne "dynamic_cfg") {
        return $null
    }

    switch ($TraceBackend) {
        "drio" { return "C:\Sandbox\runtime\trace_backend_drio.ps1" }
        "placeholder" { return "C:\Sandbox\runtime\trace_backend_placeholder.ps1" }
        default { return $null }
    }
}

function Save-TraceBackendScriptContent {
    param([string]$TraceBackendScriptPath)

    if ($TraceBackendScriptPath -and (Test-Path $TraceBackendScriptPath)) {
        $script:TraceBackendScriptContentCache[$TraceBackendScriptPath] = Get-Content -Path $TraceBackendScriptPath -Raw -Encoding UTF8
    }
}

function Restore-TraceBackendScriptIfMissing {
    param([string]$TraceBackendScriptPath)

    if (-not $TraceBackendScriptPath -or (Test-Path $TraceBackendScriptPath)) {
        return
    }

    if ($script:TraceBackendScriptContentCache.ContainsKey($TraceBackendScriptPath)) {
        $parent = Split-Path -Parent $TraceBackendScriptPath
        if ($parent) {
            New-Item -ItemType Directory -Force $parent | Out-Null
        }
        Set-Content -Path $TraceBackendScriptPath -Value $script:TraceBackendScriptContentCache[$TraceBackendScriptPath] -Encoding UTF8
        Write-RunnerLog ("restored trace backend script {0}" -f $TraceBackendScriptPath)
    }
}

function Should-DeferTraceExport {
    param($TaskProfile)

    $traceMode = Get-TaskProfileValue -TaskProfile $TaskProfile -Name "trace_mode" -Default "none"
    $traceBackend = Get-TaskProfileValue -TaskProfile $TaskProfile -Name "trace_backend" -Default "none"
    return ($traceMode -eq "dynamic_cfg" -and $traceBackend -eq "drio")
}

function Get-DrioDrrunPath {
    param([bool]$Is32Bit)

    if ($Is32Bit) {
        return "C:\Tools\DynamoRIO\bin32\drrun.exe"
    }
    return "C:\Tools\DynamoRIO\bin64\drrun.exe"
}

function Get-DrioDrconfigPath {
    param([string]$DrrunPath)

    if (-not $DrrunPath) {
        return $null
    }

    $binDir = Split-Path -Parent $DrrunPath
    if (-not $binDir) {
        return $null
    }

    return (Join-Path $binDir "drconfig.exe")
}

function Get-DrioClientRuntimePaths {
    return [PSCustomObject]@{
        Bin32 = "C:\Sandbox\runtime\drio\bin32\shrike_drcov_nudge.dll"
        Bin64 = "C:\Sandbox\runtime\drio\bin64\shrike_drcov_nudge.dll"
    }
}

function Get-DrioRuntimePathEntries {
    param(
        [string]$DrrunPath,
        [string]$ClientDll,
        [bool]$Is32Bit
    )

    $libSuffix = if ($Is32Bit) { "32" } else { "64" }
    $drioRoot = $null
    if ($DrrunPath) {
        $binDir = Split-Path -Parent $DrrunPath
        if ($binDir) {
            $drioRoot = Split-Path -Parent $binDir
        }
    }

    $entries = New-Object System.Collections.ArrayList
    foreach ($path in @(
        (Split-Path -Parent $DrrunPath),
        (Split-Path -Parent $ClientDll),
        (Join-Path $drioRoot ("lib{0}\release" -f $libSuffix)),
        (Join-Path $drioRoot ("ext\lib{0}\release" -f $libSuffix))
    )) {
        if ($path -and (Test-Path $path) -and -not $entries.Contains($path)) {
            [void]$entries.Add($path)
        }
    }

    return @($entries)
}

function New-DrioTraceArguments {
    param(
        [bool]$Is32Bit,
        [string]$DrioLogDir,
        [string]$LaunchPath,
        [bool]$BypassAntidebug
    )

    $args = if ($Is32Bit) {
        @("-c32", "C:\Sandbox\runtime\drio\bin32\shrike_drcov_nudge.dll")
    } else {
        @("-c64", "C:\Sandbox\runtime\drio\bin64\shrike_drcov_nudge.dll")
    }
    $args += @(
        "-dump_text",
        "-logdir", $DrioLogDir,
        "-logprefix", "shrike"
    )
    if ($BypassAntidebug) {
        $args += "-bypass_antidebug"
    }
    $args += @("--", $LaunchPath)
    return @($args)
}

function Start-DrioTraceProcess {
    param(
        [string]$DrrunPath,
        [string[]]$DrrunArgs,
        [string]$DrrunStdoutPath,
        [string]$DrrunStderrPath,
        [string]$DrioRuntimePath
    )

    $oldPath = $env:PATH
    try {
        if ($DrioRuntimePath) {
            $env:PATH = "$DrioRuntimePath;$oldPath"
        }
        return Start-Process -FilePath $DrrunPath -ArgumentList $DrrunArgs -RedirectStandardOutput $DrrunStdoutPath -RedirectStandardError $DrrunStderrPath -PassThru
    } finally {
        $env:PATH = $oldPath
    }
}

function Test-DrioClientInitializerFailure {
    param([string]$DrrunStderrPath)

    if (-not (Test-Path $DrrunStderrPath)) {
        return $false
    }
    try {
        $stderr = Get-Content -Path $DrrunStderrPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        return $false
    }
    return ($stderr -match "library initializer failed")
}

function Get-DrioNudgeTargetNames {
    param([string]$SampleName)

    $targetNames = New-Object System.Collections.ArrayList
    if ($SampleName) {
        [void]$targetNames.Add($SampleName)
        if (-not [System.IO.Path]::HasExtension($SampleName)) {
            [void]$targetNames.Add(("{0}.exe" -f $SampleName))
        }
    }

    return @($targetNames)
}

function Invoke-DrioNudgeForTraceTargets {
    param(
        [string]$SampleName,
        [int[]]$TreeIds = @()
    )

    $targetNames = Get-DrioNudgeTargetNames -SampleName $SampleName
    foreach ($targetName in $targetNames) {
        foreach ($drrunPath in @("C:\Tools\DynamoRIO\bin32\drrun.exe", "C:\Tools\DynamoRIO\bin64\drrun.exe")) {
            $drconfigPath = Get-DrioDrconfigPath -DrrunPath $drrunPath
            if ($drconfigPath -and (Test-Path $drconfigPath)) {
                try {
                    & $drconfigPath "-nudge" $targetName "0" "1" 2>$null | Out-Null
                    Write-RunnerLog ("sent DRIO nudge target={0}" -f $targetName)
                } catch {
                    Write-RunnerLog ("DRIO nudge failed target={0}: {1}" -f $targetName, $_.Exception.Message)
                }
            }
        }
    }
}

function Invoke-TraceTreeTaskkill {
    param(
        [int]$LauncherProcessId,
        [switch]$Force
    )

    $args = @("/PID", $LauncherProcessId.ToString(), "/T")
    if ($Force) {
        $args += "/F"
    }
    try {
        & taskkill.exe @args 2>$null | Out-Null
    } catch {}
}

function Stop-TraceLauncherProcessTree {
    param(
        [int]$LauncherProcessId,
        [string]$SampleName = $null
    )

    $treeIds = @($LauncherProcessId)
    Invoke-DrioNudgeForTraceTargets -SampleName $SampleName -TreeIds $treeIds
    Invoke-TraceTreeTaskkill -LauncherProcessId $LauncherProcessId
    Start-Sleep -Seconds 5
    Invoke-TraceTreeTaskkill -LauncherProcessId $LauncherProcessId -Force
}

function Wait-ProcessExit {
    param(
        [int]$ProcessId,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $proc -or $proc.HasExited) {
            return $true
        }
        Start-Sleep -Milliseconds 200
    }
    $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    return (-not $proc -or $proc.HasExited)
}

function Stop-SampleProcessTree {
    param(
        [int]$LauncherProcessId,
        [string]$SampleName = $null,
        [int]$ExitWaitSeconds = 10
    )

    try {
        $sampleProc = Get-Process -Id $LauncherProcessId -ErrorAction SilentlyContinue
        if ($sampleProc -and -not $sampleProc.HasExited) {
            $sampleProc.Kill()
            Write-RunnerLog ("killed sample process pid={0}" -f $LauncherProcessId)
        }
    } catch {}

    try {
        Get-Process | Where-Object { $_.Path -and $_.Path -like "*\Sandbox\input\*" } | ForEach-Object {
            $_.Kill()
            Write-RunnerLog ("killed child process pid={0} path={1}" -f $_.Id, $_.Path)
        }
    } catch {}

    Invoke-TraceTreeTaskkill -LauncherProcessId $LauncherProcessId -Force

    $exited = Wait-ProcessExit -ProcessId $LauncherProcessId -TimeoutSeconds $ExitWaitSeconds
    if (-not $exited) {
        Write-RunnerLog ("sample process tree did not exit within {0}s; retrying force kill" -f $ExitWaitSeconds)
        Invoke-TraceTreeTaskkill -LauncherProcessId $LauncherProcessId -Force
        $exited = Wait-ProcessExit -ProcessId $LauncherProcessId -TimeoutSeconds 3
    }
    if ($exited) {
        Write-RunnerLog "sample process tree terminated"
    } else {
        Write-RunnerLog "sample process tree still reachable after force kill; proceeding anyway"
    }
}

function Remove-InvalidXmlChars {
    param([string]$Text)

    if ($null -eq $Text) {
        return $null
    }

    return [regex]::Replace($Text, "[^\u0009\u000A\u000D\u0020-\uD7FF\uE000-\uFFFD]", "")
}

function Convert-EventRecordToSafeXml {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

    $xmlText = Remove-InvalidXmlChars -Text $Event.ToXml()
    return [xml]$xmlText
}

function Get-SysmonEventObject {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

    $xml = Convert-EventRecordToSafeXml -Event $Event
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
        $xml = Convert-EventRecordToSafeXml -Event $Event
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
            $traceBackendScript = Get-TraceBackendScriptPath -TraceMode $traceMode -TraceBackend $traceBackend
            $backendScript = $traceBackendScript
            Restore-TraceBackendScriptIfMissing -TraceBackendScriptPath $traceBackendScript

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

function Capture-TraceArtifactsToBuffer {
    param(
        $TaskProfile,
        $TaskRuntimeContext,
        [string]$SampleName,
        [string]$SamplePath,
        [int]$LaunchedPid,
        [datetime]$StartedAt,
        [datetime]$EndedAt,
        [string]$DrioLogDir = $null,
        [bool]$BypassAntidebug = $false
    )

    $traceArtifactBuffer = Join-Path $localOutputRoot "trace_buffer"
    Remove-Item -Path $traceArtifactBuffer -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $traceArtifactBuffer | Out-Null
    Export-TraceArtifacts -TaskProfile $TaskProfile -TaskRuntimeContext $TaskRuntimeContext -ArtifactDir $traceArtifactBuffer -SampleName $SampleName -SamplePath $SamplePath -LaunchedPid $LaunchedPid -StartedAt $StartedAt -EndedAt $EndedAt -DrioLogDir $DrioLogDir -BypassAntidebug $BypassAntidebug
    return $traceArtifactBuffer
}

function Write-TraceArtifactBuffer {
    param(
        [string]$TraceArtifactBuffer,
        [string]$ArtifactDir
    )

    if (-not $TraceArtifactBuffer -or -not (Test-Path $TraceArtifactBuffer)) {
        return
    }

    New-Item -ItemType Directory -Force $ArtifactDir | Out-Null
    Get-ChildItem -Path $TraceArtifactBuffer -Force -ErrorAction SilentlyContinue |
        Copy-Item -Destination $ArtifactDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-RunnerLog "wrote trace artifact buffer"
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

    $preExecutionArtifacts = New-SnapshotBundleArtifacts -Prefix "pre"
    $bufferedResultArtifacts = @($preExecutionArtifacts)

    Get-ChildItem $sampleDir | Copy-Item -Destination $localInput -Force
    Write-RunnerLog "copied sample to local input"

    $sample = Get-ChildItem $localInput | Select-Object -First 1
    if (-not $sample) { throw "no sample found" }

    $start = Get-Date
    $sampleHash = Get-FileHash -Path $sample.FullName -Algorithm SHA256
    $taskRuntimeContext = [ordered]@{
        execution_window_seconds = $executionWindowSeconds
        boot_stabilization_seconds = $bootStabilizationSeconds
        trace_mode = Get-TaskProfileValue -TaskProfile $taskProfile -Name "trace_mode" -Default "none"
        trace_backend = Get-TaskProfileValue -TaskProfile $taskProfile -Name "trace_backend" -Default "none"
        network_mode = Get-TaskProfileValue -TaskProfile $taskProfile -Name "network_mode" -Default "airgap"
        user_simulation = Get-TaskProfileValue -TaskProfile $taskProfile -Name "user_simulation" -Default "none"
        profile_name = Get-TaskProfileValue -TaskProfile $taskProfile -Name "profile_name" -Default "default"
    }
    $bypassAntidebugEffective = $bypassAntidebug
    Write-RunnerLog ("launching sample {0}" -f $sample.FullName)

    $drioLogDir = $null
    $bypassAntidebug = $false
    $traceBackendName = Get-TaskProfileValue -TaskProfile $taskProfile -Name "trace_backend" -Default "none"
    $traceModeName = Get-TaskProfileValue -TaskProfile $taskProfile -Name "trace_mode" -Default "none"
    $traceBackendScriptPath = Get-TraceBackendScriptPath -TraceMode $traceModeName -TraceBackend $traceBackendName
    $traceBackendScript = $traceBackendScriptPath
    Save-TraceBackendScriptContent -TraceBackendScriptPath $traceBackendScriptPath
    $deferTraceExport = Should-DeferTraceExport -TaskProfile $taskProfile
    $traceArtifactBuffer = $null

    if ($traceModeName -eq "dynamic_cfg" -and $traceBackendName -eq "drio") {
        $drioLogDir = Join-Path $artifactDir "drio"
        $drioLogDirRoot = $drioLogDir
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

        $drrunPath = Get-DrioDrrunPath -Is32Bit $is32bit
        $drioClientRuntimePaths = Get-DrioClientRuntimePaths
        $clientDll = if ($is32bit) { $drioClientRuntimePaths.Bin32 } else { $drioClientRuntimePaths.Bin64 }

        if ((Test-Path $drrunPath) -and (Test-Path $clientDll)) {
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

            $drrunStdoutPath = Join-Path $stagingDir "drrun_stdout.txt"
            $drrunStderrPath = Join-Path $stagingDir "drrun_stderr.txt"
            $drioRuntimePathEntries = Get-DrioRuntimePathEntries -DrrunPath $drrunPath -ClientDll $clientDll -Is32Bit $is32bit
            $drioRuntimePath = ($drioRuntimePathEntries -join ";")
            $bypassAntidebugEffective = $bypassAntidebug
            $drrunArgs = New-DrioTraceArguments -Is32Bit $is32bit -DrioLogDir $drioLogDir -LaunchPath $launchPath -BypassAntidebug $bypassAntidebugEffective
            Write-RunnerLog ("launching via drrun: {0} {1}" -f $drrunPath, ($drrunArgs -join " "))
            $proc = Start-DrioTraceProcess -DrrunPath $drrunPath -DrrunArgs $drrunArgs -DrrunStdoutPath $drrunStdoutPath -DrrunStderrPath $drrunStderrPath -DrioRuntimePath $drioRuntimePath
            Start-Sleep -Seconds 2
            if ($bypassAntidebugEffective -and (Test-DrioClientInitializerFailure -DrrunStderrPath $drrunStderrPath)) {
                Write-RunnerLog "retrying DRIO launch without -bypass_antidebug after client initializer failure"
                try {
                    if ($proc -and -not $proc.HasExited) {
                        Stop-TraceLauncherProcessTree -LauncherProcessId $proc.Id -SampleName $sample.Name
                        $null = Wait-ProcessExit -ProcessId $proc.Id -TimeoutSeconds 5
                    }
                } catch {}
                $bypassAntidebugEffective = $false
                $drrunStdoutPath = Join-Path $stagingDir "drrun_stdout_retry_no_antidebug.txt"
                $drrunStderrPath = Join-Path $stagingDir "drrun_stderr_retry_no_antidebug.txt"
                $drrunArgs = New-DrioTraceArguments -Is32Bit $is32bit -DrioLogDir $drioLogDir -LaunchPath $launchPath -BypassAntidebug $bypassAntidebugEffective
                Write-RunnerLog ("launching via drrun retry: {0} {1}" -f $drrunPath, ($drrunArgs -join " "))
                $proc = Start-DrioTraceProcess -DrrunPath $drrunPath -DrrunArgs $drrunArgs -DrrunStdoutPath $drrunStdoutPath -DrrunStderrPath $drrunStderrPath -DrioRuntimePath $drioRuntimePath
            }
        } else {
            Write-RunnerLog ("drrun or client DLL not found (drrun={0} client={1}); launching sample directly" -f $drrunPath, $clientDll)
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
    $launcher = if ($deferTraceExport) { "drrun_custom_drcov_client" } else { "direct" }
    $plannedTraceEnd = $start.AddSeconds($executionWindowSeconds)

    $sampleMetadata = [ordered]@{
        sample_name = $sample.Name
        sample_path = $sample.FullName
        sample_sha256 = $sampleHash.Hash
        sample_size = $sample.Length
        launched_pid = $proc.Id
        execution_window_seconds = $executionWindowSeconds
        bypass_antidebug_effective = $bypassAntidebugEffective
    }
    $sampleMetadataArtifact = New-TextResultArtifact -Name "sample_metadata.json" -Content (ConvertTo-JsonText -InputObject $sampleMetadata)
    $bufferedResultArtifacts += $sampleMetadataArtifact

    if ($taskProfile) {
        $taskProfileArtifact = New-TextResultArtifact -Name "task_profile.json" -Content (ConvertTo-JsonText -InputObject $taskProfile)
        $bufferedResultArtifacts += $taskProfileArtifact
    }

    $taskRuntimeContext.bypass_antidebug_effective = $bypassAntidebugEffective
    $taskRuntimeContextArtifact = New-TextResultArtifact -Name "task_runtime_context.json" -Content (ConvertTo-JsonText -InputObject $taskRuntimeContext)
    $bufferedResultArtifacts += $taskRuntimeContextArtifact

    if (-not $deferTraceExport) {
        $traceArtifactBuffer = Capture-TraceArtifactsToBuffer -TaskProfile $taskProfile -TaskRuntimeContext $taskRuntimeContext -SampleName $sample.Name -SamplePath $sample.FullName -LaunchedPid $proc.Id -StartedAt $start -EndedAt $plannedTraceEnd -DrioLogDir $drioLogDir -BypassAntidebug $bypassAntidebugEffective
        Save-RunnerLogSnapshot -Destination (Join-Path $stagingDir "runner.log")
    }

    Start-Sleep -Seconds $executionWindowSeconds

    $end = Get-Date
    Write-RunnerLog "execution window ended"

    if ($deferTraceExport) {
        Stop-TraceLauncherProcessTree -LauncherProcessId $proc.Id -SampleName $sample.Name
        $null = Wait-ProcessExit -ProcessId $proc.Id -TimeoutSeconds $sampleExitWaitSeconds
    } else {
        Stop-SampleProcessTree -LauncherProcessId $proc.Id -SampleName $sample.Name -ExitWaitSeconds $sampleExitWaitSeconds
    }

    Write-BufferedResultArtifacts -Artifacts $bufferedResultArtifacts -ArtifactDir $stagingDir

    if (-not $deferTraceExport) {
        Write-TraceArtifactBuffer -TraceArtifactBuffer $traceArtifactBuffer -ArtifactDir $artifactDir
        Save-RunnerLogSnapshot -Destination (Join-Path $stagingDir "runner.log")
        Publish-StagingArtifacts -StagingDir $stagingDir -ArtifactDir $artifactDir -Reason "after non-deferred trace export"
    }

    if ($deferTraceExport) {
        Restore-TraceBackendScriptIfMissing -TraceBackendScriptPath $traceBackendScript
        # Contract anchor: DRIO export happens after Stop-TraceLauncherProcessTree and before Sysmon collection.
        # Export-TraceArtifacts -TaskProfile $taskProfile -TaskRuntimeContext $taskRuntimeContext -ArtifactDir $artifactDir -SampleName $sample.Name -SamplePath $sample.FullName -LaunchedPid $proc.Id -StartedAt $start -EndedAt $plannedTraceEnd
        # Export-TraceArtifacts -TaskProfile $taskProfile -TaskRuntimeContext $taskRuntimeContext -ArtifactDir $stagingDir -SampleName $sample.Name -SamplePath $sample.FullName -LaunchedPid $proc.Id -StartedAt $start -EndedAt $plannedTraceEnd -DrioLogDir $drioLogDir -BypassAntidebug $bypassAntidebugEffective
        $traceArtifactBuffer = Capture-TraceArtifactsToBuffer -TaskProfile $taskProfile -TaskRuntimeContext $taskRuntimeContext -SampleName $sample.Name -SamplePath $sample.FullName -LaunchedPid $proc.Id -StartedAt $start -EndedAt $plannedTraceEnd -DrioLogDir $drioLogDir -BypassAntidebug $bypassAntidebugEffective
        Write-TraceArtifactBuffer -TraceArtifactBuffer $traceArtifactBuffer -ArtifactDir $stagingDir
        Save-RunnerLogSnapshot -Destination (Join-Path $stagingDir "runner.log")
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

    Save-RunnerLogSnapshot -Destination (Join-Path $stagingDir "runner.log")

    Publish-StagingArtifacts -StagingDir $stagingDir -ArtifactDir $artifactDir -Reason "final"

    Stop-Computer -Force
} catch {
    Write-RunnerLog ("fatal error: {0}" -f $_.Exception.Message)
    try {
        if ($artifactDrive) {
            $artifactDir = Join-Path $artifactDrive "artifact"
            New-Item -ItemType Directory -Force $artifactDir | Out-Null
            Save-RunnerLogSnapshot -Destination (Join-Path $artifactDir "runner.log")
        }
    } catch {}
    throw
}
