# Shrike

Shrike is a lightweight, single-machine, offline malware analysis sandbox built around:

1. Windows host with Hyper-V
2. WSL as the control plane
3. one air-gapped Windows guest (credentials: root / root)
4. sample delivery by ISO
5. artifact extraction by a dedicated VHDX
6. dynamic CFG extraction via DynamoRIO

The current implementation is intentionally minimal. It is designed as a modern, portable replacement for an old single-node Cuckoo-style workflow without nested virtualization.

## Design

The sandbox uses two explicit guest baselines:

1. `analysis-base`
   Immutable baseline for automated runs.
2. `maintenance-base`
   Manual baseline for guest updates, runtime refresh, and troubleshooting.

The default execution flow is:

1. WSL builds a sample ISO containing the binary and task profile.
2. Windows host creates a fresh artifact disk.
3. Hyper-V restores `analysis-base` snapshot.
4. The guest boots with no network adapter (air-gapped).
5. A startup task runs the guest runtime (`run_task.ps1`).
6. Guest runtime launches the sample under instrumentation (DynamoRIO or placeholder).
7. Artifacts (CFG traces, Sysmon logs, snapshots) are exported to the artifact VHDX.
8. WSL parses the raw artifacts into a structured report.

## Trace Backends

Shrike supports multiple trace backends for dynamic analysis:

### DynamoRIO Backend (`drio`)
- Uses DynamoRIO with custom `drcov` client for basic block coverage
- Captures control flow graph (CFG) with basic blocks and edges
- Supports both 32-bit and 64-bit samples
- Custom client DLL: `shrike_drcov_nudge.dll`
- Provides detailed execution traces in `dynamic_cfg_trace.ndjson`

### Placeholder Backend (`placeholder`)
- Lightweight sampling-based approach
- Periodically samples thread instruction pointers
- Lower overhead but less complete coverage
- Useful for quick behavioral analysis

### Task Profiles

Task profiles (JSON) control execution parameters:

```json
{
  "profile_name": "deep_cfg_drio",
  "trace_mode": "dynamic_cfg",
  "trace_backend": "drio",
  "network_mode": "airgap",
  "execution_window_seconds": 180,
  "boot_stabilization_seconds": 30,
  "backend_options": {
    "sample_rounds": 24,
    "sample_sleep_milliseconds": 5,
    "bypass_antidebug": true
  },
  "capture": {
    "cfg": true,
    "memory_writes": true
  }
}
```

Profiles are located in `sandbox/profiles/`.

## Anti-Analysis Evasion

The sandbox implements several anti-analysis evasion techniques:

1. **Air-gapped execution**: No network adapter attached by default
2. **Minimal VM fingerprints**: Clean Windows installation with minimal artifacts
3. **DynamoRIO instrumentation**: Transparent binary instrumentation
4. **Configurable execution windows**: Adjustable sample runtime (10-180+ seconds)
5. **Boot stabilization delay**: Allows system to settle before sample execution
6. **Sysmon telemetry**: Captures behavioral indicators even if sample detects sandbox

### Known Limitations and Mitigations

#### 1. ISO Media Loading (RESOLVED)
- **Issue**: Gen1 VMs had issues with ISO recognition after snapshot restore
- **Status**: ✅ Fixed - ISO media loads correctly and is accessible in guest
- **Solution**: Proper DVD drive configuration and media refresh via PowerShell Direct

#### 2. DynamoRIO Module Detection (PARTIALLY MITIGATED)
- **Issue**: Advanced malware detects DynamoRIO by enumerating loaded modules
- **Evidence**: Trace data shows DynamoRIO DLLs visible in module enumeration:
  - `dynamorio.dll`, `drmgr.dll`, `drwrap.dll`, `drutil.dll`, `shrike_drcov_nudge.dll`
- **Impact**: Some samples may reduce behavior or crash when software instrumentation is visible.
- **Diagnosis**:
  - DynamoRIO control-flow tracing works and captures sample-module execution.
  - PEB BeingDebugged flag patching is active.
  - API hooking is active for anti-debug and module-enumeration APIs.
  - PEB unlinking remains disabled because it caused VM blue screens.
  - DynamoRIO/private extension DLLs can still be observed by sufficiently deep checks.
- **Root Cause**: DynamoRIO uses private module loading that bypasses standard Windows loader, so modules don't appear in PEB `InLoadOrderModuleList`. PEB unlinking cannot hide what isn't there.
- **Attempted Solutions**:
  1. PEB Module Unlinking - implemented, then disabled for stability.
  2. API Hooking - implemented for module enumeration and common anti-debug APIs.
  3. Memory-protection hooks - implemented for `VirtualAlloc`, `VirtualProtect`, `NtAllocateVirtualMemory`, and `NtProtectVirtualMemory`.
- **Current Status**: **STABLE (PEB unlinking disabled)** - deep DRIO runs now reach sample code and ransomware behavior.
- **Recommendation**: Keep DRIO for repeatable software CFG extraction; consider Intel PT for lower-observable tracing when evasion fidelity matters more than instrumentation detail.

#### 3. Current CFG Result (VALIDATED 2026-05-07)
- **Validated run**: `reports/drio_extended_8c716101_20260507_091234`
- **Profile**: `sandbox/profiles/deep_cfg_drio_extended.json`
- **Sample**: `8C716101E118AC65D7BDB900E0100D012256ABB1D7CDF64830E5943A795CCCE2`
- **CFG Evidence**:
  - `trace.status = control_flow_trace`
  - `event_count = 98418`
  - `sample_basic_block_count = 724`
  - `edge_count = 1197`
  - `call_count = 2034`
  - `ordered_block_sample_count = 44317`
  - sample module loaded at `0x7c0000`
- **Behavior Evidence**:
  - Ransom note landed as `xb7n5-readme.txt`.
  - Multiple sandbox artifacts were renamed/encrypted with the `.xb7n5` extension, including `sample_metadata.json.xb7n5`, `task_profile.json.xb7n5`, and `process_snapshot_pre.csv.xb7n5`.
  - Sysmon captured sample-origin DNS activity and file creation activity.
- **CFG Interpretation**:
  - The trace is no longer limited to system DLLs; CFG events are dominated by the sample module.
  - Hot blocks around runtime addresses `0x820120` and `0x8201a8` map to static RVAs near `0x60120` and `0x601a8`, a tight byte-processing loop consistent with encrypted/decrypted buffer transformation.
  - External indirect calls show file-enumeration related KERNEL32 targets near `FindFirstFileW` and `FindClose`, but API names are not yet recorded directly in the CFG.
- **Current Gap**:
  - The CFG currently records target addresses and modules, not resolved API names. Add file-API hooks or export-name resolution for `CreateFile*`, `ReadFile`, `WriteFile`, `MoveFile*`, `DeleteFile*`, `FindFirstFile*`, `FindNextFile*`, and `FindClose` if exact file-operation attribution is needed.

#### 4. WSL / PowerShell Interop Limitation (WORKAROUND AVAILABLE)
- **Issue**: launching Windows executables from nested WSL child processes can fail with `UtilBindVsockAnyPort: socket failed 1`.
- **Observed Pattern**:
  - top-level `powershell.exe -File ...` calls from the shell work.
  - Python `subprocess.run(["powershell.exe", ...])` from WSL fails on this host.
- **Impact**: `sandbox/scripts/analyze_sample.py` may fail because it invokes Windows PowerShell from a Python child process.
- **Workaround**: use the top-level wrapper `windows_host/powershell/12_run_sandbox_wrapped.ps1`, which keeps Windows orchestration inside a single PowerShell process and only calls WSL for ISO build/report parsing.

#### 5. Result Artifact Staging (MITIGATED 2026-05-07)
- **Issue**: pre-execution sandbox artifacts written under `C:\Sandbox\output\staging` were visible to ransomware during the execution window and could be encrypted as `.xb7n5`.
- **Mitigation**: small pre-execution artifacts now use the host ResultServer artifact channel first. The guest sends `pre` snapshots, `sample_metadata.json`, `task_profile.json`, and `task_runtime_context.json` over TCP to the host before or during launch instead of writing them directly to staging.
- **Fallback**: if the ResultServer channel is unavailable, those artifacts are deferred and materialized to staging only after the sample execution window ends and the sample process is terminated.
- **Host merge**: `analyze_sample.py`, `collect_report.py`, and `windows_host/powershell/12_run_sandbox_wrapped.ps1` merge `tmp/result_server_artifacts` into the mounted artifact staging directory before parsing.

#### 6. Hyper-V Detection
- **Issue**: VM-aware malware can detect Hyper-V environment
- **Mitigation**: Minimal VM fingerprints, but hardware-level detection remains possible
- **Future**: Consider Intel PT for hardware-level tracing (no software artifacts)

## Repository Layout

1. `sandbox/`
   WSL-side orchestration and report parsing scripts.
   - `scripts/analyze_sample.py` - Main entry point for sample analysis
   - `scripts/build_sample_iso.py` - Creates ISO with sample and task profile
   - `scripts/parse_artifact.py` - Parses raw artifacts into reports
   - `scripts/task_profile.py` - Task profile validation and utilities
   - `profiles/` - Task profile templates (quick_test, deep_cfg_drio, etc.)

2. `windows_host/`
   Hyper-V automation scripts and host-side documentation.
   - `powershell/04_invoke_offline_task.ps1` - Main VM orchestration script
   - `powershell/06_install_guest_runtime.ps1` - Deploys runtime to guest
   - `powershell/07_refresh_snapshots.ps1` - Rebuilds analysis snapshots
   - `powershell/12_run_sandbox_wrapped.ps1` - Top-level PowerShell wrapper for hosts where WSL Python cannot launch Windows executables reliably
   - `drio_client/` - DynamoRIO client DLL source code

3. `guest/`
   Guest runtime and configuration.
   - `runtime/run_task.ps1` - Main guest-side execution script
   - `runtime/trace_backend_drio.ps1` - DynamoRIO trace backend
   - `runtime/trace_backend_placeholder.ps1` - Placeholder trace backend
   - `runtime/drio/` - DynamoRIO client DLLs (32/64-bit)
   - `runtime/sysmon_config.xml` - Sysmon configuration

4. `reports/`
   Generated analysis reports (JSON format).

5. Documentation:
   - `SANDBOX_WORKFLOW.md` - Detailed workflow documentation
   - `INSTALL_HYPERV_AIRGAPPED.md` - Installation guide

## Prerequisites

1. Windows 11 Pro, Enterprise, or Education
2. Hyper-V enabled
3. WSL2 installed
4. a Windows installation ISO placed under `sandbox_data/iso/`
5. Python 3 in WSL
6. `pycdlib` installed in the WSL venv

WSL setup:

```bash
cd /path/to/Shrike
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install pycdlib
```

## Quick Start

### 1. Prepare the host

Run in Windows admin PowerShell:

```powershell
cd .\windows_host\powershell
.\01_prepare_host.ps1
.\02_new_analysis_vm.ps1 -WindowsIsoPath "sandbox_data\iso\Windows.iso"
```

Install Windows in the guest through `vmconnect.exe`.

### 2. Install DynamoRIO (for CFG extraction)

Download DynamoRIO and extract to `C:\Tools\DynamoRIO` in the guest VM.

Build the custom drcov client:

```powershell
cd .\windows_host\powershell
.\11_build_drio_nudge_client.ps1
```

### 3. Install the guest runtime

Boot the maintenance baseline:

```powershell
cd .\windows_host\powershell
.\08_start_maintenance.ps1
```

Then from WSL:

```bash
cd /path/to/Shrike
source .venv/bin/activate
python sandbox/scripts/install_guest_runtime.py --guest-user root --guest-password root
```

This deploys:
- Guest runtime scripts
- DynamoRIO client DLLs
- Sysmon configuration
- Scheduled task for automatic execution

After that, rebuild the two snapshots:

```powershell
cd .\windows_host\powershell
Stop-VM -Name "rw-sandbox-win10" -TurnOff -Force
.\07_refresh_snapshots.ps1 -Force
.\09_show_sandbox_state.ps1
```

### 4. Run sample analysis

From WSL:

```bash
cd /path/to/Shrike
source .venv/bin/activate

# Quick test with placeholder backend
python sandbox/scripts/analyze_sample.py "samples/your_sample.exe" \
  --task-profile sandbox/profiles/quick_test.json

# Deep CFG extraction with DynamoRIO
python sandbox/scripts/analyze_sample.py "samples/your_sample.exe" \
  --task-profile sandbox/profiles/deep_cfg_drio.json
```

On hosts affected by the WSL/Python interop limitation, use the top-level PowerShell wrapper instead:

```bash
powershell.exe -NoProfile -ExecutionPolicy Bypass \
  -File 'D:\project\ransomware\method12-dev\windows_host\powershell\12_run_sandbox_wrapped.ps1' \
  -SamplePath 'samples\8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2' \
  -TaskProfile 'sandbox\profiles\deep_cfg_drio_extended.json' \
  -ReportId 'drio_extended_8c716101_manual' \
  -TimeoutSeconds 600
```

The parsed report is written under `reports/<sample_hash>_<timestamp>/`.

### 5. Inspect results

```bash
# View summary
cat reports/<sample_hash>_<timestamp>/summary.json

# View CFG trace
cat reports/<sample_hash>_<timestamp>/raw/dynamic_cfg_trace.ndjson

# View Sysmon events
cat reports/<sample_hash>_<timestamp>/raw/sysmon_process_events.json
```

## Workflow Commands

### Sample Analysis
```bash
# Analyze with default profile
python sandbox/scripts/analyze_sample.py <sample_path>

# Analyze with specific profile
python sandbox/scripts/analyze_sample.py <sample_path> \
  --task-profile sandbox/profiles/deep_cfg_drio.json

# Analyze with custom timeout
python sandbox/scripts/analyze_sample.py <sample_path> \
  --timeout-seconds 300

# Workaround wrapper for WSL/Python interop failures
powershell.exe -NoProfile -ExecutionPolicy Bypass \
  -File 'D:\project\ransomware\method12-dev\windows_host\powershell\12_run_sandbox_wrapped.ps1' \
  -SamplePath '<sample_path>' \
  -TaskProfile 'sandbox\profiles\deep_cfg_drio_extended.json' \
  -ReportId '<report_id>' \
  -TimeoutSeconds 600
```

### Guest Runtime Management
```bash
# Install/update guest runtime
python sandbox/scripts/install_guest_runtime.py \
  --guest-user root --guest-password root

# Install DynamoRIO runtime components
python sandbox/scripts/install_drio_runtime.py
```

### Snapshot Management
```powershell
# Refresh snapshots after guest changes
.\07_refresh_snapshots.ps1 -Force

# Start maintenance mode
.\08_start_maintenance.ps1

# Show current sandbox state
.\09_show_sandbox_state.ps1
```

#### Current Snapshot Backup

Before enabling the ResultServer artifact-channel runtime and refreshing the sandbox baseline, the existing checkpoints were exported:

- **Backup time**: `2026-05-07 16:14:50`
- **VM**: `rw-sandbox-win10`
- **Snapshots**: `analysis-base`, `maintenance-base`
- **Backup path**: `sandbox_data\snapshot_backups\pre_network_artifact_20260507_161450`
- **Export size**: `8` files, `32967419020` bytes

## Important Operating Rules

1. Do not modify the guest from the `analysis-base` lineage.
2. Only use `maintenance-base` for guest-side updates.
3. Keep the guest offline by default.
4. Do not keep task media attached when refreshing snapshots.
5. Treat artifact VHDX contents and `reports/` as the persistent output of a run. Guest-local files on `C:` are rolled back when the snapshot is restored.
6. Always refresh snapshots after installing/updating guest runtime.

## Troubleshooting

### ISO not recognized in guest
**Symptom**: Guest runtime reports "sample or artifact media not present"

**Cause**: Hyper-V Gen1 VM ISO media loading issue after snapshot restore

**Workaround**: 
- Increase `mediaWaitTimeoutSeconds` in `run_task.ps1`
- Use VHD instead of ISO for sample delivery (future enhancement)
- Consider migrating to Gen2 VM

### DynamoRIO trace empty
**Symptom**: `dynamic_cfg_trace.ndjson` is empty or has very few blocks

**Possible causes**:
- Sample detected DynamoRIO and exited early
- Sample requires user interaction
- Execution window too short

**Solutions**:
- Increase `execution_window_seconds` in task profile
- Enable `bypass_antidebug` in backend options
- Use placeholder backend for comparison

### VM timeout
**Symptom**: VM runs for full timeout period then forced shutdown

**Cause**: Guest runtime not executing or stuck

**Debug steps**:
1. Check `windows_host/logs/04_invoke_offline_task_*.log`
2. Boot maintenance VM and check `C:\Sandbox\output\runner.log`
3. Verify scheduled task: `Get-ScheduledTask -TaskName SandboxRunTask`

### WSL child process cannot launch PowerShell
**Symptom**: `analyze_sample.py` fails before VM orchestration with:

```text
UtilBindVsockAnyPort: socket failed 1
```

**Cause**: WSL interop works for top-level `powershell.exe` calls, but fails when Python or another WSL child process launches Windows executables.

**Workaround**: run the top-level wrapper:

```bash
powershell.exe -NoProfile -ExecutionPolicy Bypass \
  -File 'D:\project\ransomware\method12-dev\windows_host\powershell\12_run_sandbox_wrapped.ps1' \
  -ReportId 'drio_extended_8c716101_manual'
```

## Scope

This repository currently focuses on:

1. offline single-node execution
2. repeatable Hyper-V restore and cleanup
3. guest runtime installation
4. artifact export with CFG traces
5. DynamoRIO-based dynamic instrumentation
6. basic sample-centric report generation
7. Sysmon behavioral telemetry

It does not yet include:

1. queue management
2. multi-VM scheduling
3. fake internet services
4. distributed storage
5. production hardening
6. advanced anti-evasion techniques
7. memory dump analysis
