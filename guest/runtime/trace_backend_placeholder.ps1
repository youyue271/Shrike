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
$message = "Seed collector executed; this is not yet a full dynamic basic-block trace."

function Get-BackendOptionValue {
    param(
        $Options,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        $Default
    )

    if ($null -eq $Options) {
        return $Default
    }

    $value = $null
    if ($Options -is [System.Collections.IDictionary]) {
        if (-not $Options.Contains($Name)) {
            return $Default
        }
        $value = $Options[$Name]
    } else {
        $prop = $Options.PSObject.Properties[$Name]
        if ($null -eq $prop) {
            return $Default
        }
        $value = $prop.Value
    }

    if ($null -eq $value) {
        return $Default
    }

    if ($Default -is [int]) {
        try {
            return [int]$value
        } catch {
            return [int]$Default
        }
    }

    return $value
}

function Get-PeImageInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        return $null
    }

    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $br = New-Object System.IO.BinaryReader($fs)
        $fs.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peOffset = $br.ReadInt32()

        $fs.Seek($peOffset + 4, [System.IO.SeekOrigin]::Begin) | Out-Null
        $machine = $br.ReadUInt16()
        $numberOfSections = $br.ReadUInt16()
        $fs.Seek(12, [System.IO.SeekOrigin]::Current) | Out-Null
        $sizeOfOptionalHeader = $br.ReadUInt16()
        $fs.Seek(2, [System.IO.SeekOrigin]::Current) | Out-Null

        $optionalHeaderStart = $fs.Position
        $magic = $br.ReadUInt16()
        $entryOffset = 16
        $imageBaseOffset = switch ($magic) {
            0x10B { 28 }
            0x20B { 24 }
            default { return $null }
        }

        $fs.Seek($optionalHeaderStart + $entryOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $addressOfEntryPoint = $br.ReadUInt32()

        $fs.Seek($optionalHeaderStart + $imageBaseOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $imageBaseValue = switch ($magic) {
            0x10B { [UInt64]$br.ReadUInt32() }
            0x20B { $br.ReadUInt64() }
            default { return $null }
        }

        $fs.Seek($optionalHeaderStart + 56, [System.IO.SeekOrigin]::Begin) | Out-Null
        $sizeOfImage = [UInt64]$br.ReadUInt32()

        return [PSCustomObject]@{
            Machine = ("0x{0:X4}" -f $machine)
            NumberOfSections = $numberOfSections
            SizeOfOptionalHeader = $sizeOfOptionalHeader
            ImageBase = ("0x{0:X}" -f $imageBaseValue)
            ImageBaseValue = $imageBaseValue
            SizeOfImage = $sizeOfImage
            EntryPointRva = ("0x{0:X}" -f $addressOfEntryPoint)
            EntryPointRvaValue = [UInt64]$addressOfEntryPoint
        }
    } finally {
        $fs.Dispose()
    }
}

function Try-GetProcessByIdSafe {
    param([int]$TargetProcessId)

    try {
        return [System.Diagnostics.Process]::GetProcessById($TargetProcessId)
    } catch {
        return $null
    }
}

function Ensure-ThreadInstructionSamplerType {
    if ("Shrike.Runtime.ThreadInstructionSampler" -as [type]) {
        return
    }

    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Shrike.Runtime
{
    public sealed class ModuleRecord
    {
        public string Module { get; set; }
        public string Path { get; set; }
        public string Base { get; set; }
        public ulong BaseValue { get; set; }
        public int Size { get; set; }
    }

    public sealed class ThreadInstructionSample
    {
        public int ThreadId { get; set; }
        public ulong InstructionPointerValue { get; set; }
        public string InstructionPointer { get; set; }
        public string Architecture { get; set; }
        public int RoundIndex { get; set; }
        public int Sequence { get; set; }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct M128A
    {
        public ulong High;
        public long Low;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct CONTEXT64
    {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;
        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;
        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
        public M128A[] VectorRegister;
        public ulong VectorControl;
        public ulong DebugControl;
        public ulong LastBranchToRip;
        public ulong LastBranchFromRip;
        public ulong LastExceptionToRip;
        public ulong LastExceptionFromRip;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WOW64_FLOATING_SAVE_AREA
    {
        public uint ControlWord;
        public uint StatusWord;
        public uint TagWord;
        public uint ErrorOffset;
        public uint ErrorSelector;
        public uint DataOffset;
        public uint DataSelector;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
        public byte[] RegisterArea;
        public uint Cr0NpxState;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WOW64_CONTEXT
    {
        public uint ContextFlags;
        public uint Dr0;
        public uint Dr1;
        public uint Dr2;
        public uint Dr3;
        public uint Dr6;
        public uint Dr7;
        public WOW64_FLOATING_SAVE_AREA FloatSave;
        public uint SegGs;
        public uint SegFs;
        public uint SegEs;
        public uint SegDs;
        public uint Edi;
        public uint Esi;
        public uint Ebx;
        public uint Edx;
        public uint Ecx;
        public uint Eax;
        public uint Ebp;
        public uint Eip;
        public uint SegCs;
        public uint EFlags;
        public uint Esp;
        public uint SegSs;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] ExtendedRegisters;
    }

    internal static class NativeMethods
    {
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        public const uint THREAD_SUSPEND_RESUME = 0x0002;
        public const uint THREAD_GET_CONTEXT = 0x0008;
        public const uint THREAD_QUERY_INFORMATION = 0x0040;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint TH32CS_SNAPMODULE = 0x00000008;
        public const uint TH32CS_SNAPMODULE32 = 0x00000010;

        public const uint CONTEXT_AMD64 = 0x00100000;
        public const uint CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001;

        public const uint WOW64_CONTEXT_I386 = 0x00010000;
        public const uint WOW64_CONTEXT_CONTROL = WOW64_CONTEXT_I386 | 0x00000001;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(uint desiredAccess, bool inheritHandle, uint threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SuspendThread(IntPtr threadHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr threadHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsWow64Process(IntPtr processHandle, out bool wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr threadHandle, ref CONTEXT64 context);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Wow64GetThreadContext(IntPtr threadHandle, ref WOW64_CONTEXT context);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct MODULEENTRY32
        {
            public uint dwSize;
            public uint th32ModuleID;
            public uint th32ProcessID;
            public uint GlblcntUsage;
            public uint ProccntUsage;
            public IntPtr modBaseAddr;
            public uint modBaseSize;
            public IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExePath;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);
    }

    public static class ThreadInstructionSampler
    {
        public static List<ModuleRecord> EnumerateModules(int processId)
        {
            var result = new List<ModuleRecord>();
            IntPtr snapshot = NativeMethods.CreateToolhelp32Snapshot(
                NativeMethods.TH32CS_SNAPMODULE | NativeMethods.TH32CS_SNAPMODULE32,
                (uint)processId
            );
            if (snapshot == NativeMethods.INVALID_HANDLE_VALUE)
            {
                return result;
            }

            try
            {
                var module = new NativeMethods.MODULEENTRY32();
                module.dwSize = (uint)Marshal.SizeOf(typeof(NativeMethods.MODULEENTRY32));

                if (!NativeMethods.Module32First(snapshot, ref module))
                {
                    return result;
                }

                do
                {
                    ulong baseValue = (ulong)module.modBaseAddr.ToInt64();
                    result.Add(new ModuleRecord
                    {
                        Module = module.szModule,
                        Path = module.szExePath,
                        Base = "0x" + baseValue.ToString("X"),
                        BaseValue = baseValue,
                        Size = unchecked((int)module.modBaseSize)
                    });

                    module.dwSize = (uint)Marshal.SizeOf(typeof(NativeMethods.MODULEENTRY32));
                }
                while (NativeMethods.Module32Next(snapshot, ref module));
            }
            finally
            {
                NativeMethods.CloseHandle(snapshot);
            }

            return result;
        }

        public static List<ThreadInstructionSample> Collect(int processId)
        {
            var result = new List<ThreadInstructionSample>();
            using (var process = Process.GetProcessById(processId))
            {
                bool isWow64 = false;
                var processHandle = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_INFORMATION, false, (uint)processId);
                if (processHandle != IntPtr.Zero)
                {
                    try
                    {
                        bool wow64Value;
                        if (NativeMethods.IsWow64Process(processHandle, out wow64Value))
                        {
                            isWow64 = wow64Value;
                        }
                    }
                    finally
                    {
                        NativeMethods.CloseHandle(processHandle);
                    }
                }

                foreach (ProcessThread thread in process.Threads)
                {
                    IntPtr threadHandle = NativeMethods.OpenThread(
                        NativeMethods.THREAD_SUSPEND_RESUME | NativeMethods.THREAD_GET_CONTEXT | NativeMethods.THREAD_QUERY_INFORMATION,
                        false,
                        (uint)thread.Id
                    );
                    if (threadHandle == IntPtr.Zero)
                    {
                        continue;
                    }

                    bool suspended = false;
                    try
                    {
                        uint suspendResult = NativeMethods.SuspendThread(threadHandle);
                        if (suspendResult == 0xFFFFFFFF)
                        {
                            continue;
                        }
                        suspended = true;

                        if (isWow64)
                        {
                            var context = new WOW64_CONTEXT
                            {
                                ContextFlags = NativeMethods.WOW64_CONTEXT_CONTROL,
                                FloatSave = new WOW64_FLOATING_SAVE_AREA
                                {
                                    RegisterArea = new byte[80]
                                },
                                ExtendedRegisters = new byte[512]
                            };
                            if (NativeMethods.Wow64GetThreadContext(threadHandle, ref context))
                            {
                                result.Add(new ThreadInstructionSample
                                {
                                    ThreadId = thread.Id,
                                    InstructionPointerValue = context.Eip,
                                    InstructionPointer = "0x" + context.Eip.ToString("X"),
                                    Architecture = "x86_wow64"
                                });
                            }
                        }
                        else
                        {
                            var context = new CONTEXT64
                            {
                                ContextFlags = NativeMethods.CONTEXT_CONTROL,
                                VectorRegister = new M128A[26]
                            };
                            if (NativeMethods.GetThreadContext(threadHandle, ref context))
                            {
                                result.Add(new ThreadInstructionSample
                                {
                                    ThreadId = thread.Id,
                                    InstructionPointerValue = context.Rip,
                                    InstructionPointer = "0x" + context.Rip.ToString("X"),
                                    Architecture = "x64"
                                });
                            }
                        }
                    }
                    finally
                    {
                        if (suspended)
                        {
                            NativeMethods.ResumeThread(threadHandle);
                        }
                        NativeMethods.CloseHandle(threadHandle);
                    }
                }
            }

            return result;
        }

        public static List<ThreadInstructionSample> CollectMultiple(int processId, int rounds, int sleepMilliseconds)
        {
            var result = new List<ThreadInstructionSample>();
            int sequence = 0;

            for (int i = 0; i < rounds; i++)
            {
                List<ThreadInstructionSample> roundSamples;
                try
                {
                    roundSamples = Collect(processId);
                }
                catch (ArgumentException)
                {
                    break;
                }
                catch (InvalidOperationException)
                {
                    break;
                }

                foreach (var sample in roundSamples)
                {
                    sample.RoundIndex = i;
                    sample.Sequence = sequence++;
                    result.Add(sample);
                }

                if (i + 1 < rounds && sleepMilliseconds > 0)
                {
                    System.Threading.Thread.Sleep(sleepMilliseconds);
                }
            }

            return result;
        }
    }
}
"@ -Language CSharp
}

function Convert-HexStringToUInt64 {
    param([string]$HexString)

    if (-not $HexString) {
        return $null
    }

    try {
        return [Convert]::ToUInt64(($HexString -replace '^0x', ''), 16)
    } catch {
        return $null
    }
}

function Resolve-InstructionModuleRecord {
    param(
        [Parameter(Mandatory = $true)]
        [UInt64]$InstructionPointerValue,

        [Parameter(Mandatory = $true)]
        [array]$ModuleRecords
    )

    foreach ($moduleRecord in $ModuleRecords) {
        $baseValue = Convert-HexStringToUInt64 -HexString $moduleRecord.base
        if ($null -eq $baseValue) {
            continue
        }

        $sizeValue = 0
        try {
            $sizeValue = [UInt64]$moduleRecord.size
        } catch {
            $sizeValue = 0
        }

        if ($sizeValue -gt 0 -and $InstructionPointerValue -ge $baseValue -and $InstructionPointerValue -lt ($baseValue + $sizeValue)) {
            return $moduleRecord
        }
    }

    return $null
}

function Convert-RequestTimestampToUtc {
    param([string]$Timestamp)

    if (-not $Timestamp) {
        return (Get-Date).ToUniversalTime()
    }

    try {
        return ([datetimeoffset]::Parse($Timestamp)).UtcDateTime
    } catch {
        return (Get-Date).ToUniversalTime()
    }
}

function Get-TraceWindowSamplePlan {
    param($Request)

    $sampleRounds = Get-BackendOptionValue -Options $Request.backend_options -Name "sample_rounds" -Default 24
    $minimumSleepMilliseconds = Get-BackendOptionValue -Options $Request.backend_options -Name "sample_sleep_milliseconds" -Default 5
    if ($sampleRounds -lt 1) {
        $sampleRounds = 24
    }
    if ($minimumSleepMilliseconds -lt 0) {
        $minimumSleepMilliseconds = 5
    }

    $deadlineUtc = Convert-RequestTimestampToUtc -Timestamp $Request.ended_at
    $nowUtc = (Get-Date).ToUniversalTime()
    $remainingMilliseconds = [Math]::Max(0, [int][Math]::Ceiling(($deadlineUtc - $nowUtc).TotalMilliseconds))

    $sleepMilliseconds = 0
    if ($sampleRounds -gt 1 -and $remainingMilliseconds -gt 0) {
        $calculatedSleepMilliseconds = [Math]::Floor($remainingMilliseconds / [Math]::Max(1, ($sampleRounds - 1)))
        $sleepMilliseconds = [int][Math]::Max($minimumSleepMilliseconds, [int]$calculatedSleepMilliseconds)
    }

    return [PSCustomObject]@{
        SampleRounds = $sampleRounds
        SleepMilliseconds = $sleepMilliseconds
        DeadlineUtc = $deadlineUtc
    }
}

function Collect-ThreadSamplesForTraceWindow {
    param(
        [int]$LaunchedPid,
        $SamplePlan
    )

    $process = Try-GetProcessByIdSafe -TargetProcessId $LaunchedPid
    if (-not $process) {
        return @()
    }

    $threadSamples = [Shrike.Runtime.ThreadInstructionSampler]::CollectMultiple([int]$LaunchedPid, [int]$SamplePlan.SampleRounds, [int]$SamplePlan.SleepMilliseconds)
    return @($threadSamples)
}

function Get-SampledBlockTransitions {
    param([array]$OrderedBlockSamples)

    $transitionMap = @{}
    $sortedSamples = @($OrderedBlockSamples | Sort-Object thread_id, sequence)

    foreach ($threadGroup in @($sortedSamples | Group-Object thread_id)) {
        $threadSamples = @($threadGroup.Group | Sort-Object sequence)
        for ($index = 1; $index -lt $threadSamples.Count; $index++) {
            $previousSample = $threadSamples[$index - 1]
            $currentSample = $threadSamples[$index]

            if ($previousSample.module -ne $currentSample.module) {
                continue
            }
            if (($previousSample.path -or "") -ne ($currentSample.path -or "")) {
                continue
            }
            if ($previousSample.block_start -eq $currentSample.block_start) {
                continue
            }

            $transitionKey = "{0}|{1}|{2}|{3}" -f $previousSample.module, ($previousSample.path -or ""), $previousSample.block_start, $currentSample.block_start
            if (-not $transitionMap.ContainsKey($transitionKey)) {
                $transitionMap[$transitionKey] = [PSCustomObject]@{
                    Module = $previousSample.module
                    Path = $previousSample.path
                    Source = $previousSample.block_start
                    Target = $currentSample.block_start
                    Count = 0
                }
            }

            $transitionMap[$transitionKey].Count += 1
        }
    }

    return @($transitionMap.Values | Sort-Object Module, Source, Target)
}

$events = @(
    [ordered]@{
        event = "trace_status"
        trace_mode = $request.trace_mode
        trace_backend = $request.trace_backend
        status = "seeded_from_runtime_metadata"
        message = $message
        sample_name = $request.sample_name
        launched_pid = $request.launched_pid
        started_at = $request.started_at
        ended_at = $request.ended_at
    },
    [ordered]@{
        event = "trace_window"
        sample_name = $request.sample_name
        launched_pid = $request.launched_pid
        started_at = $request.started_at
        ended_at = $request.ended_at
    }
)

$moduleRecords = @()
$process = $null
$threadSamples = @()
$orderedBlockSamples = @()
$samplePlan = Get-TraceWindowSamplePlan -Request $request
if ($request.launched_pid) {
    $process = Try-GetProcessByIdSafe -TargetProcessId ([int]$request.launched_pid)
}

if ($process) {
    try {
        Ensure-ThreadInstructionSamplerType
        $threadSamples = Collect-ThreadSamplesForTraceWindow -LaunchedPid ([int]$request.launched_pid) -SamplePlan $samplePlan
    } catch {
        $events += [ordered]@{
            event = "trace_status"
            trace_mode = $request.trace_mode
            trace_backend = $request.trace_backend
            status = "seed_partial"
            message = ("Thread context sampling failed: {0}" -f $_.Exception.Message)
            sample_name = $request.sample_name
            launched_pid = $request.launched_pid
            started_at = $request.started_at
            ended_at = $request.ended_at
        }
    }
}

if ($process) {
    try {
        Ensure-ThreadInstructionSamplerType
        foreach ($module in [Shrike.Runtime.ThreadInstructionSampler]::EnumerateModules([int]$request.launched_pid)) {
            $moduleName = if ($module.Module) { [string]$module.Module } else { [System.IO.Path]::GetFileNameWithoutExtension($module.Path) }
            $moduleRecord = [ordered]@{
                event = "module_load"
                module = $moduleName
                path = $module.Path
                base = $module.Base
                size = $module.Size
                pid = $request.launched_pid
            }
            $events += $moduleRecord
            $moduleRecords += [PSCustomObject]@{
                module = $moduleName
                path = $module.Path
                base = $module.Base
                size = $module.Size
            }
        }
    } catch {
        $events += [ordered]@{
            event = "trace_status"
            trace_mode = $request.trace_mode
            trace_backend = $request.trace_backend
            status = "seed_partial"
            message = ("Module enumeration failed: {0}" -f $_.Exception.Message)
            sample_name = $request.sample_name
            launched_pid = $request.launched_pid
            started_at = $request.started_at
            ended_at = $request.ended_at
        }
    }
}

foreach ($threadSample in $threadSamples) {
    $resolvedModule = Resolve-InstructionModuleRecord -InstructionPointerValue ([UInt64]$threadSample.InstructionPointerValue) -ModuleRecords $moduleRecords
    $resolvedModuleName = if ($resolvedModule) { $resolvedModule.module } else { "unknown" }
    $resolvedModulePath = if ($resolvedModule) { $resolvedModule.path } else { $null }

    $events += [ordered]@{
        event = "thread_context"
        module = $resolvedModuleName
        path = $resolvedModulePath
        thread_id = $threadSample.ThreadId
        instruction_pointer = $threadSample.InstructionPointer
        architecture = $threadSample.Architecture
        pid = $request.launched_pid
    }
    $events += [ordered]@{
        event = "basic_block"
        module = $resolvedModuleName
        path = $resolvedModulePath
        start = $threadSample.InstructionPointer
        end = $threadSample.InstructionPointer
        kind = "thread_ip_seed"
        thread_id = $threadSample.ThreadId
        architecture = $threadSample.Architecture
        pid = $request.launched_pid
    }

    $orderedBlockSample = [ordered]@{
        event = "sampled_block_execution"
        module = $resolvedModuleName
        path = $resolvedModulePath
        thread_id = $threadSample.ThreadId
        round = $threadSample.RoundIndex
        sequence = $threadSample.Sequence
        block_start = $threadSample.InstructionPointer
        block_end = $threadSample.InstructionPointer
        instruction_pointer = $threadSample.InstructionPointer
        architecture = $threadSample.Architecture
        pid = $request.launched_pid
    }
    $events += $orderedBlockSample
    $orderedBlockSamples += [PSCustomObject]$orderedBlockSample
}

$sampledTransitions = Get-SampledBlockTransitions -OrderedBlockSamples $orderedBlockSamples
foreach ($transition in $sampledTransitions) {
    $events += [ordered]@{
        event = "edge"
        module = $transition.Module
        path = $transition.Path
        source = $transition.Source
        target = $transition.Target
        count = $transition.Count
        kind = "sampled_transition"
        pid = $request.launched_pid
    }
}

$fallbackSamplePath = if ($request.sample_path) { [string]$request.sample_path } else { $null }
$fallbackPeImage = $null
if ($moduleRecords.Count -eq 0 -and $fallbackSamplePath) {
    $fallbackPeImage = Get-PeImageInfo -Path $fallbackSamplePath
    if ($fallbackPeImage) {
        $fallbackModuleName = if ($request.sample_name) {
            [System.IO.Path]::GetFileName([string]$request.sample_name)
        } else {
            [System.IO.Path]::GetFileName($fallbackSamplePath)
        }

        $moduleRecords += [PSCustomObject]@{
            module = $fallbackModuleName
            path = $fallbackSamplePath
            base = $fallbackPeImage.ImageBase
            size = [int]$fallbackPeImage.SizeOfImage
        }
        $events += [ordered]@{
            event = "module_load"
            module = $fallbackModuleName
            path = $fallbackSamplePath
            base = $fallbackPeImage.ImageBase
            size = [int]$fallbackPeImage.SizeOfImage
            kind = "pe_header_fallback"
            pid = $request.launched_pid
        }
    }
}

$mainModuleRecord = $moduleRecords | Where-Object { $_.path -and ([System.IO.Path]::GetFileName($_.path) -ieq $request.sample_name) } | Select-Object -First 1
if (-not $mainModuleRecord) {
    $mainModuleRecord = $moduleRecords | Select-Object -First 1
}

if ($threadSamples.Count -eq 0 -and $mainModuleRecord -and $mainModuleRecord.path) {
    $entryPoint = if ($fallbackPeImage -and $mainModuleRecord.path -eq $fallbackSamplePath) {
        $fallbackPeImage
    } else {
        Get-PeImageInfo -Path $mainModuleRecord.path
    }

    if ($entryPoint) {
        $entryAddress = if ($mainModuleRecord.base) {
            try {
                $baseValue = [Convert]::ToUInt64(($mainModuleRecord.base -replace '^0x', ''), 16)
                "0x{0:X}" -f ($baseValue + $entryPoint.EntryPointRvaValue)
            } catch {
                $entryPoint.EntryPointRva
            }
        } else {
            $entryPoint.EntryPointRva
        }

        $events += [ordered]@{
            event = "basic_block"
            module = $mainModuleRecord.module
            path = $mainModuleRecord.path
            start = $entryAddress
            end = $entryAddress
            kind = "entry_seed"
            pid = $request.launched_pid
        }
    }
}

$encodedLines = @()
foreach ($event in $events) {
    $encodedLines += ($event | ConvertTo-Json -Compress -Depth 8)
}
Set-Content -Path $OutputPath -Value ($encodedLines -join [Environment]::NewLine) -Encoding UTF8

$uniqueBlocks = @($events | Where-Object { $_.event -eq "basic_block" } | Group-Object module, start, end)
$uniqueModules = @($moduleRecords | Sort-Object module -Unique)

$summaryStatus = if ($orderedBlockSamples.Count -gt 0) { "sampled_block_order" } else { "seeded_from_runtime_metadata" }
$summaryNotes = @(
    $message,
    "Backend contract executed through C:\Sandbox\runtime\trace_backend_placeholder.ps1."
)
if ($orderedBlockSamples.Count -gt 0) {
    $summaryNotes += "Current seed source: ordered runtime thread instruction-pointer samples plus process module enumeration."
} else {
    $summaryNotes += "Current seed source: process module enumeration or on-disk PE image plus PE entrypoint extraction."
}

$summary = [ordered]@{
    trace_mode = $request.trace_mode
    trace_backend = $request.trace_backend
    status = $summaryStatus
    sample_name = $request.sample_name
    launched_pid = $request.launched_pid
    started_at = $request.started_at
    ended_at = $request.ended_at
    event_count = $events.Count
    basic_block_count = $uniqueBlocks.Count
    edge_count = $sampledTransitions.Count
    module_count = $uniqueModules.Count
    ordered_block_sample_count = $orderedBlockSamples.Count
    ordered_thread_count = @($orderedBlockSamples | Group-Object thread_id).Count
    modules = @($uniqueModules)
    notes = $summaryNotes
}
$summary | ConvertTo-Json -Depth 8 | Set-Content -Path $SummaryPath -Encoding UTF8
