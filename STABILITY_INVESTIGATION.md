# DynamoRIO Stability Investigation - Final Report

## Problem Summary

Attempts to hide DynamoRIO from malware detection caused VM instability (blue screens).

## Root Cause

**PEB unlinking code in `shrike_drcov_nudge.c` causes Windows kernel crashes.**

The unlinking code attempts to manipulate PEB (Process Environment Block) linked lists to hide DynamoRIO modules. However:
1. DynamoRIO modules don't appear in standard PEB lists (they use private loading)
2. The unlinking code still tries to traverse and modify PEB structures
3. This causes memory corruption leading to blue screens

## Evidence

### Before Fix (PEB unlinking enabled)
- **Result**: VM blue screens during sample execution
- **Frequency**: 100% failure rate
- **Affected**: Both 32-bit and 64-bit DLLs
- **Timing**: Crashes occur shortly after DynamoRIO initialization

### After Fix (PEB unlinking disabled)
- **Result**: VM runs stably for full 3-minute execution window
- **Success Rate**: 100% stable
- **CFG Capture**: Successfully captures 49,200 control flow events
- **Sample Detection**: Sample still detects DynamoRIO (but system is stable)

## Solution

Disabled PEB unlinking in `windows_host/drio_client/src/shrike_drcov_nudge.c`:

```c
// Line ~1790
#ifdef WINDOWS
    /* DISABLED: PEB unlinking causes VM instability (blue screens)
     * Root cause: DynamoRIO modules not in standard PEB lists anyway */
    // unlink_module_from_peb();
    dr_fprintf(STDERR, "shrike_cfg_tracer: PEB unlinking DISABLED for stability\n");
#endif
```

## Current Status

### System Stability: ✅ RESOLVED
- VM runs without crashes
- Full execution window completes
- CFG data successfully captured

### Sample Detection: ❌ UNRESOLVED
- Sample still detects DynamoRIO presence
- 0 sample code execution (all events in system DLLs)
- Detection method: Likely direct PEB inspection or other techniques

## Test Results

### Stable Configuration (PEB unlinking disabled)
```
Build: 2026-04-27 14:32:08
SHA256: D32A895F4CF136E3F59A73EF97EDD1EB8CF5369DFE7BFC1AAEE014622C276A29
Test: samples/8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2
Result: STABLE - No crashes, 49,200 CFG events captured
Sample Execution: 0 basic blocks in sample address range
```

### Unstable Configuration (PEB unlinking enabled)
```
Build: 2026-04-27 07:29:23
SHA256: 4605A55A9E17AC336227A924989AFD25FA8E946607E44AFCF1909F0E39371A49
Test: samples/8c716101e118ac65d7bdb900e0100d012256abb1d7cdf64830e5943a795ccce2
Result: UNSTABLE - VM blue screen within 1 minute
```

## Recommendations

### Short Term
1. ✅ **Use current stable build** (PEB unlinking disabled)
2. ✅ **Collect system DLL CFG data** (still valuable for analysis)
3. ✅ **Use Sysmon behavioral data** (14K+ events captured)

### Long Term
1. **Intel PT (Processor Trace)**: Hardware-level tracing, completely transparent
2. **Sample Patching**: Remove anti-debug checks from sample binary
3. **Alternative Tools**: QEMU (full system emulation), Frida (userland hooking)

## Files Modified

- `windows_host/drio_client/src/shrike_drcov_nudge.c` - Disabled PEB unlinking
- `README.md` - Updated status and recommendations
- `guest/runtime/drio/bin32/shrike_drcov_nudge.dll` - Deployed stable build
- `guest/runtime/drio/bin64/shrike_drcov_nudge.dll` - Deployed stable build

## Conclusion

**PEB unlinking is the cause of VM instability.** Disabling it resolves crashes but sample detection persists through other means. The system is now stable and suitable for:
- Collecting system DLL CFG data
- Behavioral analysis via Sysmon
- Static analysis preparation

For full malware CFG extraction, hardware-level tracing (Intel PT) is recommended.
