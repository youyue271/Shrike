# Shrike

Shrike is a lightweight, single-machine, offline malware analysis sandbox built around:

1. Windows host with Hyper-V
2. WSL as the control plane
3. one air-gapped Windows guest
4. sample delivery by ISO
5. artifact extraction by a dedicated VHDX

The current implementation is intentionally minimal. It is designed as a modern, portable replacement for an old single-node Cuckoo-style workflow without nested virtualization.

## Design

The sandbox uses two explicit guest baselines:

1. `analysis-base`
   Immutable baseline for automated runs.
2. `maintenance-base`
   Manual baseline for guest updates, runtime refresh, and troubleshooting.

The default execution flow is:

1. WSL builds a sample ISO.
2. Windows host creates a fresh artifact disk.
3. Hyper-V restores `analysis-base`.
4. The guest boots with no network adapter.
5. A startup task runs the guest runtime.
6. Artifacts are exported to the artifact VHDX.
7. WSL parses the raw artifacts into a local report.

## Repository Layout

1. `sandbox/`
   WSL-side orchestration and report parsing scripts.
2. `windows_host/`
   Hyper-V automation scripts and host-side documentation.
3. `guest/`
   Guest runtime and Sysmon configuration.
4. `SANDBOX_MVP.md`
   Architecture and design notes.
5. `INSTALL_HYPERV_AIRGAPPED.md`
   Installation and operating guide.

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

### 2. Install the guest runtime

Boot the maintenance baseline:

```powershell
cd .\windows_host\powershell
.\08_start_maintenance.ps1
```

Then from WSL:

```bash
cd /path/to/Shrike
source .venv/bin/activate
python sandbox/scripts/install_guest_runtime.py --guest-user analyst
```

After that, rebuild the two snapshots:

```powershell
cd .\windows_host\powershell
Stop-VM -Name "rw-sandbox-win10" -TurnOff -Force
.\07_refresh_snapshots.ps1 -Force
.\09_show_sandbox_state.ps1
```

### 3. Run one sample

From WSL:

```bash
cd /path/to/Shrike
source .venv/bin/activate
python sandbox/scripts/analyze_sample.py "samples/your_sample.exe"
```

The parsed report is written under `reports/`.

## Important Operating Rules

1. Do not modify the guest from the `analysis-base` lineage.
2. Only use `maintenance-base` for guest-side updates.
3. Keep the guest offline by default.
4. Do not keep task media attached when refreshing snapshots.
5. Treat artifact VHDX contents and `reports/` as the persistent output of a run. Guest-local files on `C:` are rolled back when the snapshot is restored.

## Scope

This repository currently focuses on:

1. offline single-node execution
2. repeatable Hyper-V restore and cleanup
3. guest runtime installation
4. artifact export
5. basic sample-centric report generation

It does not yet include:

1. queue management
2. multi-VM scheduling
3. fake internet services
4. distributed storage
5. production hardening
