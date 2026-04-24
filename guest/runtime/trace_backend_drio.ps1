param(
    [Parameter(Mandatory = $true)]
    [string]$RequestPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [Parameter(Mandatory = $true)]
    [string]$SummaryPath
)

$ErrorActionPreference = "Stop"

$request = Get-Content -Path $RequestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$message = "DRIO backend parsed control-flow trace events."

function Parse-NdjsonTraceLog {
    param([string]$Path)

    $events = @()
    foreach ($line in Get-Content -Path $Path -Encoding UTF8) {
        $trimmedLine = $line.Trim()
        if (-not $trimmedLine) {
            continue
        }
        try {
            $event = $trimmedLine | ConvertFrom-Json
            $events += $event
        } catch {
            continue
        }
    }
    return $events
}

function Get-LoadedModuleForAddress {
    param(
        [string]$Address,
        [array]$Modules
    )

    $addressValue = Convert-NumberStringToUInt64 $Address
    if ($null -eq $addressValue) {
        return $null
    }

    foreach ($moduleRecord in $Modules) {
        $baseValue = Convert-NumberStringToUInt64 $moduleRecord.base
        $endValue = Convert-NumberStringToUInt64 $moduleRecord.end
        if ($null -eq $baseValue -or $null -eq $endValue) {
            continue
        }
        if ($addressValue -ge $baseValue -and $addressValue -lt $endValue) {
            return $moduleRecord
        }
    }

    return $null
}

function Get-ModuleNameFromPath {
    param([string]$Path)

    if (-not $Path) {
        return "unknown"
    }

    return [System.IO.Path]::GetFileNameWithoutExtension($Path)
}

function Test-IsSampleModulePath {
    param(
        [string]$Path,
        $Request
    )

    if (-not $Path -or -not $Request.sample_name) {
        return $false
    }

    return $Path -like "*$($Request.sample_name)*"
}

function Convert-NdjsonEventsToStandardFormat {
    param(
        [array]$RawEvents,
        $Request
    )

    $standardEvents = @(
        [PSCustomObject][ordered]@{
            event = "trace_status"
            trace_mode = $Request.trace_mode
            trace_backend = "drio"
            status = "control_flow_trace"
            message = $message
            sample_name = $Request.sample_name
            launched_pid = $Request.launched_pid
            started_at = $Request.started_at
            ended_at = $Request.ended_at
        },
        [PSCustomObject][ordered]@{
            event = "trace_window"
            sample_name = $Request.sample_name
            launched_pid = $Request.launched_pid
            started_at = $Request.started_at
            ended_at = $Request.ended_at
        }
    )

    $modulesSeen = @{}
    $basicBlocksSeen = @{}
    $previousBlockByThread = @{}
    $modulesLoaded = @()

    foreach ($rawEvent in $RawEvents) {
        $eventType = [string]$rawEvent.event
        $tid = $rawEvent.tid
        $src = $rawEvent.src
        $target = $rawEvent.target

        if ($eventType -eq "client_metadata") {
            $standardEvents += [PSCustomObject][ordered]@{
                event = "client_metadata"
                build_id = $rawEvent.build_id
                bypass_antidebug = $rawEvent.bypass_antidebug
                pid = $rawEvent.pid
                logdir = $rawEvent.logdir
                logprefix = $rawEvent.logprefix
            }
            continue
        }

        if ($eventType -eq "module_load") {
            $moduleRecord = [PSCustomObject][ordered]@{
                module = Get-ModuleNameFromPath -Path $rawEvent.path
                path = $rawEvent.path
                base = $rawEvent.base
                end = $rawEvent.end
                size = $rawEvent.size
            }
            $moduleKey = "{0}|{1}|{2}" -f $moduleRecord.path, $moduleRecord.base, $moduleRecord.end
            if (-not $modulesSeen.ContainsKey($moduleKey)) {
                $modulesSeen[$moduleKey] = $true
                $modulesLoaded += $moduleRecord
                $standardEvents += [PSCustomObject][ordered]@{
                    event = "module_load"
                    module = $moduleRecord.module
                    path = $moduleRecord.path
                    base = $moduleRecord.base
                    end = $moduleRecord.end
                    size = $moduleRecord.size
                }
            }
            continue
        }

        if ($eventType -eq "sample_execution") {
            $sourceModule = Get-LoadedModuleForAddress -Address $rawEvent.pc -Modules $modulesLoaded
            $standardEvents += [PSCustomObject][ordered]@{
                event = "sample_execution"
                module = if ($sourceModule) { $sourceModule.module } elseif ($rawEvent.path) { Get-ModuleNameFromPath -Path $rawEvent.path } else { "unknown" }
                path = if ($sourceModule) { $sourceModule.path } elseif ($rawEvent.path) { $rawEvent.path } else { $null }
                pc = $rawEvent.pc
                base = if ($sourceModule) { $sourceModule.base } else { $rawEvent.base }
                offset = $rawEvent.offset
                tid = $tid
                ts = $rawEvent.ts
                kind = "client_probe"
            }
            continue
        }

        if ($eventType -eq "exception_dispatch") {
            $sourceModule = Get-LoadedModuleForAddress -Address $rawEvent.address -Modules $modulesLoaded
            $standardEvents += [PSCustomObject][ordered]@{
                event = "exception_dispatch"
                api = $rawEvent.api
                module = if ($sourceModule) { $sourceModule.module } else { "unknown" }
                path = if ($sourceModule) { $sourceModule.path } else { $null }
                code = $rawEvent.code
                address = $rawEvent.address
                flags = $rawEvent.flags
                tid = $tid
                ts = $rawEvent.ts
                kind = "client_probe"
            }
            continue
        }

        if ($eventType -eq "raise_exception") {
            $standardEvents += [PSCustomObject][ordered]@{
                event = "raise_exception"
                api = $rawEvent.api
                code = $rawEvent.code
                flags = $rawEvent.flags
                arg_count = $rawEvent.arg_count
                tid = $tid
                ts = $rawEvent.ts
                kind = "client_probe"
            }
            continue
        }

        if ($eventType -eq "exception_handler_install") {
            $standardEvents += [PSCustomObject][ordered]@{
                event = "exception_handler_install"
                api = $rawEvent.api
                handler = $rawEvent.handler
                first = $rawEvent.first
                tid = $tid
                ts = $rawEvent.ts
                kind = "client_probe"
            }
            continue
        }

        $sourceModule = if ($src) { Get-LoadedModuleForAddress -Address $src -Modules $modulesLoaded } else { $null }
        $targetModule = if ($target) { Get-LoadedModuleForAddress -Address $target -Modules $modulesLoaded } else { $null }
        $sourceModuleName = if ($sourceModule) { $sourceModule.module } else { "unknown" }
        $sourcePath = if ($sourceModule) { $sourceModule.path } else { $null }
        $targetModuleName = if ($targetModule) { $targetModule.module } else { "unknown" }
        $targetPath = if ($targetModule) { $targetModule.path } else { $null }

        if ($eventType -eq "basic_block") {
            $blockKey = "{0}|{1}" -f $sourcePath, $src
            if (-not $basicBlocksSeen.ContainsKey($blockKey)) {
                $basicBlocksSeen[$blockKey] = $true
                $standardEvents += [PSCustomObject][ordered]@{
                    event = "basic_block"
                    module = $sourceModuleName
                    path = $sourcePath
                    start = $src
                    end = $src
                    size = 0
                    kind = "cfg_trace"
                    tid = $tid
                }
            }

            $standardEvents += [PSCustomObject][ordered]@{
                event = "sampled_block_execution"
                module = $sourceModuleName
                path = $sourcePath
                thread_id = $tid
                round = 0
                sequence = $standardEvents.Count
                block_start = $src
                block_end = $src
                instruction_pointer = $src
                tid = $tid
                kind = "cfg_trace_ordered"
            }

            $threadKey = [string]$tid
            if ($previousBlockByThread.ContainsKey($threadKey)) {
                $previousBlock = $previousBlockByThread[$threadKey]
                if ($previousBlock.source -ne $src) {
                    $standardEvents += [PSCustomObject][ordered]@{
                        event = "edge"
                        module = $previousBlock.module
                        path = $previousBlock.path
                        target_module = $sourceModuleName
                        target_path = $sourcePath
                        source = $previousBlock.source
                        target = $src
                        tid = $tid
                        count = 1
                        kind = "cfg_trace_implicit"
                    }
                }
            }
            $previousBlockByThread[$threadKey] = [PSCustomObject]@{
                source = $src
                module = $sourceModuleName
                path = $sourcePath
            }
            continue
        }

        if ($eventType -eq "call") {
            $standardEvents += [PSCustomObject][ordered]@{
                event = "call"
                module = $sourceModuleName
                path = $sourcePath
                target_module = $targetModuleName
                target_path = $targetPath
                source = $src
                target = $target
                tid = $tid
                kind = "direct_call"
            }
            $standardEvents += [PSCustomObject][ordered]@{
                event = "edge"
                module = $sourceModuleName
                path = $sourcePath
                target_module = $targetModuleName
                target_path = $targetPath
                source = $src
                target = $target
                tid = $tid
                count = 1
                kind = "call_edge"
            }
            continue
        }

        if ($eventType -eq "ret") {
            $standardEvents += [PSCustomObject][ordered]@{
                event = "ret"
                module = $sourceModuleName
                path = $sourcePath
                target_module = $targetModuleName
                target_path = $targetPath
                source = $src
                target = $target
                tid = $tid
                kind = "return"
            }
            $standardEvents += [PSCustomObject][ordered]@{
                event = "edge"
                module = $sourceModuleName
                path = $sourcePath
                target_module = $targetModuleName
                target_path = $targetPath
                source = $src
                target = $target
                tid = $tid
                count = 1
                kind = "return_edge"
            }
            continue
        }

        if ($eventType -eq "branch_taken" -or $eventType -eq "branch_not_taken") {
            $taken = $eventType -eq "branch_taken"
            $standardEvents += [PSCustomObject][ordered]@{
                event = "branch"
                module = $sourceModuleName
                path = $sourcePath
                target_module = $targetModuleName
                target_path = $targetPath
                source = $src
                target = $target
                taken = $taken
                tid = $tid
                kind = "conditional_branch"
            }
            $standardEvents += [PSCustomObject][ordered]@{
                event = "edge"
                module = $sourceModuleName
                path = $sourcePath
                target_module = $targetModuleName
                target_path = $targetPath
                source = $src
                target = $target
                tid = $tid
                count = 1
                kind = if ($taken) { "branch_taken_edge" } else { "branch_not_taken_edge" }
            }
            continue
        }

        if ($eventType -eq "indirect_call") {
            $standardEvents += [PSCustomObject][ordered]@{
                event = "indirect_call"
                module = $sourceModuleName
                path = $sourcePath
                target_module = $targetModuleName
                target_path = $targetPath
                source = $src
                target = $target
                tid = $tid
                kind = "indirect_call"
            }
            $standardEvents += [PSCustomObject][ordered]@{
                event = "edge"
                module = $sourceModuleName
                path = $sourcePath
                target_module = $targetModuleName
                target_path = $targetPath
                source = $src
                target = $target
                tid = $tid
                count = 1
                kind = "indirect_call_edge"
            }
            continue
        }

        if ($eventType -eq "indirect_jump") {
            $standardEvents += [PSCustomObject][ordered]@{
                event = "indirect_jump"
                module = $sourceModuleName
                path = $sourcePath
                target_module = $targetModuleName
                target_path = $targetPath
                source = $src
                target = $target
                tid = $tid
                kind = "indirect_jump"
            }
            $standardEvents += [PSCustomObject][ordered]@{
                event = "edge"
                module = $sourceModuleName
                path = $sourcePath
                target_module = $targetModuleName
                target_path = $targetPath
                source = $src
                target = $target
                tid = $tid
                count = 1
                kind = "indirect_jump_edge"
            }
        }
    }

    return $standardEvents
}

function Get-DrcovLogProcessId {
    param([string]$Path)

    if (-not $Path) {
        return $null
    }

    $name = [System.IO.Path]::GetFileName($Path)
    if ($name -match '\.(\d+)\.\d+\.proc\.log$') {
        return [int]$matches[1]
    }

    return $null
}

function Convert-NumberStringToUInt64 {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    $text = ([string]$Value).Trim()
    if (-not $text) {
        return $null
    }

    try {
        if ($text.StartsWith("0x", [System.StringComparison]::OrdinalIgnoreCase)) {
            return [Convert]::ToUInt64($text.Substring(2), 16)
        }
        return [Convert]::ToUInt64($text, 10)
    } catch {
        return $null
    }
}

function Parse-DrcovTextLog {
    param([string]$Path)

    $moduleMap = @{}
    $basicBlocks = @()
    $processId = Get-DrcovLogProcessId -Path $Path
    $inModuleTable = $false
    $inBasicBlockTable = $false

    foreach ($line in Get-Content -Path $Path -Encoding UTF8) {
        if ($line -match '^Module Table:') {
            $inModuleTable = $true
            $inBasicBlockTable = $false
            continue
        }
        if ($line -match '^BB Table:') {
            $inModuleTable = $false
            $inBasicBlockTable = $true
            continue
        }
        if (-not $line.Trim()) {
            continue
        }

        if ($inModuleTable) {
            if ($line -match '^\s*Columns:') {
                continue
            }

            $parts = $line -split ',\s*', 10
            if ($parts.Count -lt 3) {
                continue
            }

            $moduleId = Convert-NumberStringToUInt64 $parts[0]
            if ($null -eq $moduleId) {
                continue
            }

            if ($parts.Count -ge 10) {
                $baseValue = Convert-NumberStringToUInt64 $parts[2]
                $endValue = Convert-NumberStringToUInt64 $parts[3]
                $pathValue = $parts[9].Trim()
            } else {
                $baseValue = Convert-NumberStringToUInt64 $parts[1]
                $endValue = if ($parts.Count -ge 3) { Convert-NumberStringToUInt64 $parts[2] } else { $null }
                $pathValue = $parts[$parts.Count - 1].Trim()
            }
            $sizeValue = if ($null -ne $baseValue -and $null -ne $endValue -and $endValue -ge $baseValue) {
                [UInt64]($endValue - $baseValue)
            } else {
                0
            }

            $moduleMap[[int]$moduleId] = [PSCustomObject]@{
                module_id = [int]$moduleId
                path = [string]$pathValue
                module = if ($pathValue) { [System.IO.Path]::GetFileNameWithoutExtension([string]$pathValue) } else { "module_$moduleId" }
                base_value = if ($null -ne $baseValue) { [UInt64]$baseValue } else { [UInt64]0 }
                base = if ($null -ne $baseValue) { "0x{0:X}" -f $baseValue } else { $null }
                size = [UInt64]$sizeValue
            }
            continue
        }

        if ($inBasicBlockTable) {
            if ($line -match '^\s*module id,\s*start,\s*size') {
                continue
            }

            if ($line -match '^\s*module\[\s*(\d+)\]\s*:\s*(0x[0-9A-Fa-f]+|\d+)\s*,\s*(0x[0-9A-Fa-f]+|\d+)') {
                $moduleId = [int]$matches[1]
                $startOffset = Convert-NumberStringToUInt64 $matches[2]
                $blockSize = Convert-NumberStringToUInt64 $matches[3]
                if ($null -eq $startOffset -or $null -eq $blockSize) {
                    continue
                }

                $basicBlocks += [PSCustomObject]@{
                    module_id = $moduleId
                    start_offset = [UInt64]$startOffset
                    size = [UInt64]$blockSize
                    sequence = $basicBlocks.Count
                }
            }
        }
    }

    return [PSCustomObject]@{
        process_id = $processId
        log_path = $Path
        modules = @($moduleMap.Values | Sort-Object module_id)
        basic_blocks = @($basicBlocks)
    }
}

function Convert-DrcovEntriesToEvents {
    param(
        [array]$Logs,
        $Request
    )

    $events = @(
        [ordered]@{
            event = "trace_status"
            trace_mode = $Request.trace_mode
            trace_backend = "drio"
            status = "drcov_basic_blocks"
            message = "DRIO backend parsed DynamoRIO drcov basic-block coverage logs."
            sample_name = $Request.sample_name
            launched_pid = $Request.launched_pid
            started_at = $Request.started_at
            ended_at = $Request.ended_at
        },
        [ordered]@{
            event = "trace_window"
            sample_name = $Request.sample_name
            launched_pid = $Request.launched_pid
            started_at = $Request.started_at
            ended_at = $Request.ended_at
        }
    )

    foreach ($log in $Logs) {
        $logProcessId = if ($log.process_id) { [int]$log.process_id } else { [int]$Request.launched_pid }
        $previousOrderedBlock = $null

        foreach ($moduleRecord in $log.modules) {
            $events += [ordered]@{
                event = "module_load"
                module = $moduleRecord.module
                path = $moduleRecord.path
                base = $moduleRecord.base
                size = [UInt64]$moduleRecord.size
                kind = "drcov_text"
                pid = $logProcessId
            }
        }

        foreach ($blockRecord in $log.basic_blocks) {
            $moduleRecord = $log.modules | Where-Object { $_.module_id -eq $blockRecord.module_id } | Select-Object -First 1
            if (-not $moduleRecord) {
                continue
            }

            $startValue = [UInt64]($moduleRecord.base_value + $blockRecord.start_offset)
            $endValue = [UInt64]($startValue + $blockRecord.size)

            $events += [ordered]@{
                event = "basic_block"
                module = $moduleRecord.module
                path = $moduleRecord.path
                start = ("0x{0:X}" -f $startValue)
                end = ("0x{0:X}" -f $endValue)
                size = [UInt64]$blockRecord.size
                kind = "drcov_text"
                pid = $logProcessId
            }

            $orderedBlockEvent = [ordered]@{
                event = "sampled_block_execution"
                module = $moduleRecord.module
                path = $moduleRecord.path
                thread_id = $logProcessId
                round = 0
                sequence = [int]$blockRecord.sequence
                block_start = ("0x{0:X}" -f $startValue)
                block_end = ("0x{0:X}" -f $endValue)
                instruction_pointer = ("0x{0:X}" -f $startValue)
                pid = $logProcessId
                kind = "drcov_first_seen_order"
            }
            $events += $orderedBlockEvent

            if ($previousOrderedBlock -and $previousOrderedBlock.module -eq $orderedBlockEvent.module) {
                $events += [ordered]@{
                    event = "edge"
                    module = $orderedBlockEvent.module
                    path = $orderedBlockEvent.path
                    source = $previousOrderedBlock.start
                    target = $orderedBlockEvent.block_start
                    pid = $logProcessId
                    count = 1
                    kind = "drcov_first_seen_order"
                }
            }

            $previousOrderedBlock = [PSCustomObject]@{
                module = $orderedBlockEvent.module
                start = $orderedBlockEvent.block_start
            }
        }
    }

    return $events
}

function Write-TraceSummary {
    param(
        [array]$Events,
        [array]$Notes,
        $Request,
        [string]$CoverageMode,
        [string]$EdgeSource
    )

    $moduleSeen = @{}
    $moduleRecords = @()
    $basicBlockSeen = @{}
    $basicBlocks = @()
    $orderedThreadSeen = @{}
    $orderedBlockSampleCount = 0
    $edgeSeen = @{}
    $callCount = 0
    $retCount = 0
    $branchCount = 0
    $indirectCallCount = 0
    $indirectJumpCount = 0
    $clientMetadata = $null
    $sampleModuleSeen = $false
    $sampleBasicBlockCount = 0
    $sampleCallCount = 0
    $sampleExecutionSeen = $false
    $sampleExecutionEventCount = 0
    $exceptionDispatchCount = 0
    $raiseExceptionCount = 0
    $exceptionHandlerInstallCount = 0
    $systemOnlyTrace = $true

    foreach ($event in $Events) {
        if ($event.event -eq "client_metadata") {
            $clientMetadata = $event
            continue
        }

        if ($event.event -eq "module_load") {
            $moduleKey = "{0}|{1}|{2}|{3}" -f $event.module, $event.path, $event.base, $event.size
            if (-not $moduleSeen.ContainsKey($moduleKey)) {
                $moduleSeen[$moduleKey] = $true
                $moduleRecords += $event
                if (Test-IsSampleModulePath -Path $event.path -Request $Request) {
                    $sampleModuleSeen = $true
                }
            }
            continue
        }

        if ($event.event -eq "basic_block") {
            $blockKey = "{0}|{1}|{2}" -f $event.module, $event.start, $event.end
            if (-not $basicBlockSeen.ContainsKey($blockKey)) {
                $basicBlockSeen[$blockKey] = $true
                $basicBlocks += $event
                if (Test-IsSampleModulePath -Path $event.path -Request $Request) {
                    $sampleBasicBlockCount += 1
                    $sampleModuleSeen = $true
                }
            }
            continue
        }

        if ($event.event -eq "sampled_block_execution") {
            $orderedBlockSampleCount += 1
            $threadKey = [string]$event.thread_id
            if ($threadKey) {
                $orderedThreadSeen[$threadKey] = $true
            }
            continue
        }

        if ($event.event -eq "sample_execution") {
            $sampleExecutionSeen = $true
            $sampleExecutionEventCount += 1
            if (Test-IsSampleModulePath -Path $event.path -Request $Request) {
                $sampleModuleSeen = $true
            }
            continue
        }

        if ($event.event -eq "exception_dispatch") {
            $exceptionDispatchCount += 1
            continue
        }

        if ($event.event -eq "raise_exception") {
            $raiseExceptionCount += 1
            continue
        }

        if ($event.event -eq "exception_handler_install") {
            $exceptionHandlerInstallCount += 1
            continue
        }

        if ($event.event -eq "edge") {
            $edgeKey = "{0}|{1}|{2}|{3}" -f $event.module, $event.path, $event.source, $event.target
            if (-not $edgeSeen.ContainsKey($edgeKey)) {
                $edgeSeen[$edgeKey] = $true
            }
        }

        if ($event.event -eq "call") {
            $callCount += 1
            if (Test-IsSampleModulePath -Path $event.path -Request $Request) {
                $sampleCallCount += 1
                $sampleModuleSeen = $true
            }
        }
        if ($event.event -eq "ret") { $retCount += 1 }
        if ($event.event -eq "branch") { $branchCount += 1 }
        if ($event.event -eq "indirect_call") { $indirectCallCount += 1 }
        if ($event.event -eq "indirect_jump") { $indirectJumpCount += 1 }
    }

    if ($moduleRecords.Count -gt 0) {
        $systemOnlyTrace = -not ($sampleBasicBlockCount -gt 0 -or $sampleCallCount -gt 0 -or $sampleExecutionSeen)
    }

    $bypassAntiDebugFromRequest = if ($Request.PSObject.Properties['bypass_antidebug_requested']) {
        $Request.bypass_antidebug_requested
    } else {
        $null
    }

    $summary = [ordered]@{
        trace_mode = $Request.trace_mode
        trace_backend = "drio"
        status = if ($CoverageMode -eq "control_flow_trace") { "control_flow_trace" } else { "drcov_basic_blocks" }
        sample_name = $Request.sample_name
        launched_pid = $Request.launched_pid
        started_at = $Request.started_at
        ended_at = $Request.ended_at
        event_count = @($Events).Count
        basic_block_count = @($basicBlocks).Count
        edge_count = $edgeSeen.Count
        module_count = @($moduleRecords).Count
        ordered_block_sample_count = $orderedBlockSampleCount
        ordered_thread_count = $orderedThreadSeen.Count
        coverage_mode = $CoverageMode
        edge_source = $EdgeSource
        has_call_graph = ($callCount -gt 0 -or $retCount -gt 0)
        has_indirect_targets = ($indirectCallCount -gt 0 -or $indirectJumpCount -gt 0)
        call_count = $callCount
        ret_count = $retCount
        branch_count = $branchCount
        indirect_call_count = $indirectCallCount
        indirect_jump_count = $indirectJumpCount
        drio_mode = if ($CoverageMode -eq "control_flow_trace") { "cfg_tracer" } else { "drcov_text_first_seen_order" }
        client_build_id = if ($clientMetadata) { $clientMetadata.build_id } else { $null }
        bypass_antidebug_requested = $bypassAntiDebugFromRequest
        bypass_antidebug_client = if ($clientMetadata) { $clientMetadata.bypass_antidebug } else { $null }
        sample_module_seen = $sampleModuleSeen
        sample_basic_block_count = $sampleBasicBlockCount
        sample_call_count = $sampleCallCount
        sample_execution_seen = $sampleExecutionSeen
        sample_execution_event_count = $sampleExecutionEventCount
        exception_dispatch_count = $exceptionDispatchCount
        raise_exception_count = $raiseExceptionCount
        exception_handler_install_count = $exceptionHandlerInstallCount
        system_only_trace = $systemOnlyTrace
        modules = @(
            $moduleRecords | ForEach-Object {
                [ordered]@{
                    module = $_.module
                    path = $_.path
                    base = $_.base
                    size = $_.size
                }
            }
        )
        notes = $Notes
    }
    $summary | ConvertTo-Json -Depth 8 | Set-Content -Path $SummaryPath -Encoding UTF8
}

function Invoke-PlaceholderFallback {
    param([string]$Reason)

    $fallbackScript = Join-Path $PSScriptRoot "trace_backend_placeholder.ps1"
    if (-not (Test-Path $fallbackScript)) {
        Set-Content -Path $OutputPath -Value "" -Encoding UTF8
        $summary = [ordered]@{
            trace_mode = $request.trace_mode
            trace_backend = "drio"
            status = "drio_fallback_missing"
            event_count = 0
            basic_block_count = 0
            edge_count = 0
            module_count = 0
            ordered_block_sample_count = 0
            ordered_thread_count = 0
            coverage_mode = "none"
            edge_source = "none"
            has_call_graph = $false
            has_indirect_targets = $false
            modules = @()
            notes = @(
                $Reason,
                "DRIO backend fallback failed because trace_backend_placeholder.ps1 was not found."
            )
        }
        $summary | ConvertTo-Json -Depth 8 | Set-Content -Path $SummaryPath -Encoding UTF8
        return
    }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fallbackScript `
        -RequestPath $RequestPath `
        -OutputPath $OutputPath `
        -SummaryPath $SummaryPath
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        exit $exitCode
    }

    $summary = Get-Content -Path $SummaryPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $summaryObject = [ordered]@{}
    foreach ($prop in $summary.PSObject.Properties) {
        $summaryObject[$prop.Name] = $prop.Value
    }

    $notes = @($Reason)
    if ($summary.notes) {
        $notes += @($summary.notes)
    }

    $summaryObject.trace_backend = "drio"
    $summaryObject.drio_mode = "placeholder_fallback"
    $summaryObject.coverage_mode = "basic_blocks_only"
    $summaryObject.edge_source = "inferred_from_order"
    $summaryObject.has_call_graph = $false
    $summaryObject.has_indirect_targets = $false
    $summaryObject.notes = $notes
    $summaryObject | ConvertTo-Json -Depth 8 | Set-Content -Path $SummaryPath -Encoding UTF8
}

# Use the temp directory path from trace_request where drrun actually wrote the files
# The trace backend runs BEFORE artifacts are published, so files are still in temp location
$drcovLogDir = $request.drio_log_dir

# Diagnostic logging to artifact directory so it gets copied to report
$diagLog = Join-Path (Split-Path -Parent $OutputPath) "trace_backend_diagnostic.txt"
"=== Trace Backend Diagnostic ===" | Out-File $diagLog
"Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $diagLog -Append
"drcovLogDir: $drcovLogDir" | Out-File $diagLog -Append
"Test-Path result: $(Test-Path $drcovLogDir)" | Out-File $diagLog -Append

if (Test-Path $drcovLogDir) {
    "Directory exists, listing all contents:" | Out-File $diagLog -Append
    try {
        Get-ChildItem -Path $drcovLogDir -Force -ErrorAction Stop | ForEach-Object {
            "  $($_.Name) - $($_.Length) bytes - LastWrite: $($_.LastWriteTime)" | Out-File $diagLog -Append
        }
    } catch {
        "  Error listing directory: $($_.Exception.Message)" | Out-File $diagLog -Append
    }
} else {
    "Directory does NOT exist" | Out-File $diagLog -Append
}

# Use .NET Directory API for more reliable file detection
Start-Sleep -Seconds 2
$ndjsonLogs = @()
for ($i = 0; $i -lt 5; $i++) {
    "Attempt $($i+1) of 5" | Out-File $diagLog -Append
    if (Test-Path $drcovLogDir) {
        try {
            # Use .NET API instead of Get-ChildItem for better reliability
            $files = [System.IO.Directory]::GetFiles($drcovLogDir, "*.ndjson")
            "  .NET API found $($files.Count) files" | Out-File $diagLog -Append
            if ($files.Count -gt 0) {
                $files | ForEach-Object { "    $_" | Out-File $diagLog -Append }
                $ndjsonLogs = @($files | ForEach-Object { Get-Item $_ } | Sort-Object LastWriteTime, Name)
                "  Successfully loaded $($ndjsonLogs.Count) ndjson files" | Out-File $diagLog -Append
                break
            }
        } catch {
            "  .NET API failed: $($_.Exception.Message)" | Out-File $diagLog -Append
            # Fallback to Get-ChildItem if .NET API fails
            $ndjsonLogs = @(Get-ChildItem -Path $drcovLogDir -Filter "*.ndjson" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime, Name)
            "  Get-ChildItem found $($ndjsonLogs.Count) files" | Out-File $diagLog -Append
            if ($ndjsonLogs.Count -gt 0) {
                break
            }
        }
    } else {
        "  Directory does not exist on attempt $($i+1)" | Out-File $diagLog -Append
    }
    if ($i -lt 4) {
        Start-Sleep -Seconds 1
    }
}

"Final result: $($ndjsonLogs.Count) ndjson files found" | Out-File $diagLog -Append

if ($ndjsonLogs.Count -gt 0) {
    $allRawEvents = @()
    foreach ($ndjsonLog in $ndjsonLogs) {
        $rawEvents = Parse-NdjsonTraceLog -Path $ndjsonLog.FullName
        $allRawEvents += $rawEvents
    }

    if ($allRawEvents.Count -eq 0) {
        Invoke-PlaceholderFallback -Reason ("NDJSON trace logs were present under {0}, but no events were parsed; falling back to placeholder sampling." -f $drcovLogDir)
        exit 0
    }

    $events = Convert-NdjsonEventsToStandardFormat -RawEvents $allRawEvents -Request $request

    $encodedLines = @()
    foreach ($event in $events) {
        $encodedLines += ($event | ConvertTo-Json -Compress -Depth 8)
    }
    Set-Content -Path $OutputPath -Value ($encodedLines -join [Environment]::NewLine) -Encoding UTF8

    Write-TraceSummary -Events $events -Notes @(
        $message,
        "Control-flow trace from upgraded DRIO client with call/ret/branch/indirect-jump instrumentation.",
        ("NDJSON log directory: {0}" -f $drcovLogDir),
        ("NDJSON log files parsed: {0}" -f $ndjsonLogs.Count)
    ) -Request $request -CoverageMode "control_flow_trace" -EdgeSource "instrumented"

    exit 0
}

$drcovLogs = @()
if (Test-Path $drcovLogDir) {
    $drcovLogs = @(Get-ChildItem -Path $drcovLogDir -Filter "*.log" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime, Name)
}

if ($drcovLogs.Count -eq 0) {
    Invoke-PlaceholderFallback -Reason ("No drcov log files were found under {0}; falling back to placeholder sampling." -f $drcovLogDir)
    exit 0
}

$parsedLogs = @()
foreach ($drcovLog in $drcovLogs) {
    $parsedLogs += Parse-DrcovTextLog -Path $drcovLog.FullName
}

$events = Convert-DrcovEntriesToEvents -Logs $parsedLogs -Request $request
if (@($events | Where-Object { $_.event -eq "basic_block" }).Count -eq 0) {
    Invoke-PlaceholderFallback -Reason ("drcov logs were present under {0}, but no basic blocks were parsed; falling back to placeholder sampling." -f $drcovLogDir)
    exit 0
}

$encodedLines = @()
foreach ($event in $events) {
    $encodedLines += ($event | ConvertTo-Json -Compress -Depth 8)
}
Set-Content -Path $OutputPath -Value ($encodedLines -join [Environment]::NewLine) -Encoding UTF8

Write-TraceSummary -Events $events -Notes @(
    "DRIO backend parsed DynamoRIO drcov basic-block coverage logs.",
    "Order source: first-seen basic-block order from drcov per-process text logs; process-scoped and deduplicated, not exact thread-level execution.",
    ("drcov log directory: {0}" -f $drcovLogDir),
    ("drcov log files parsed: {0}" -f $drcovLogs.Count)
) -Request $request -CoverageMode "basic_blocks_only" -EdgeSource "inferred_from_order"
