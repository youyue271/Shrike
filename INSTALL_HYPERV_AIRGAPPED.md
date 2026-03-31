# Hyper-V Air-Gapped Sandbox Installation Guide

This guide matches the current upgraded architecture in this repository.

## 1. Target Architecture

The sandbox now has two explicit guest baselines:

1. `analysis-base`
   Immutable baseline for automated runs.
2. `maintenance-base`
   Manual baseline for guest updates, Sysmon changes, runtime replacement, and troubleshooting.

The execution path is:

1. WSL builds a sample ISO.
2. Windows host creates a fresh artifact VHDX.
3. Hyper-V restores `analysis-base`.
4. The guest boots without network.
5. The guest startup task runs `C:\Sandbox\runtime\run_task.ps1`.
6. Artifacts are written to the artifact VHDX.
7. Host detaches task media and restores `analysis-base` again.

Important consequence:

1. guest local files on `C:` are not the final evidence store for automated runs
2. after host-side snapshot restore, guest-local logs are rolled back with the system disk
3. the persistent result of one run is the artifact VHDX and the parsed report under `reports/`

Important constraints:

1. default VM generation is `Gen1`
2. guest has no network adapter
3. Hyper-V automatic checkpoints must stay disabled
4. task media must not remain attached when snapshots are refreshed

## 2. Host Requirements

You need:

1. Windows 11 Pro, Enterprise, or Education
2. admin PowerShell
3. Hyper-V enabled
4. WSL2 installed
5. one Windows installation ISO placed under the project tree

Recommended guest sizing:

1. memory: `8 GB`
2. vCPUs: `4`
3. base disk: `100 GB`

## 3. Prepare the Project-Local Sandbox Layout

Open admin PowerShell:

```powershell
cd D:\project\ransomware\method12\windows_host\powershell
.\01_prepare_host.ps1
```

This creates project-local asset directories under:

1. `sandbox_data\base_images`
2. `sandbox_data\task_media`
3. `sandbox_data\hyperv`
4. `sandbox_data\exports`
5. `sandbox_data\iso`

## 4. Put the Windows ISO into the Project

Place your Windows ISO here:

1. [`sandbox_data/iso/Windows.iso`](/mnt/d/project/ransomware/method12/sandbox_data/iso/Windows.iso)

You can also keep another name, but then pass it explicitly.

## 5. Create the Analysis VM

Open admin PowerShell:

```powershell
cd D:\project\ransomware\method12\windows_host\powershell
.\02_new_analysis_vm.ps1 -WindowsIsoPath "sandbox_data\iso\Windows.iso"
```

Notes:

1. the script defaults to `Gen1`
2. automatic checkpoints are disabled
3. all guest NICs are removed
4. the Windows ISO is attached to the DVD drive

Check the current host state:

```powershell
.\09_show_sandbox_state.ps1
```

## 6. Install Windows in the Guest

Open admin PowerShell:

```powershell
Start-VM -Name "rw-sandbox-win10"
vmconnect.exe localhost "rw-sandbox-win10"
```

Inside the guest:

1. install Windows normally
2. create a local user such as `analyst`
3. finish OOBE
4. reach the desktop

Recommended inside the guest before taking baselines:

1. disable unnecessary consumer software
2. install Sysmon if it is not already present
3. confirm `C:\Sandbox` exists or let the runtime installer create it later

## 7. Enter Maintenance Mode

After Windows installation, boot the guest through the maintenance path:

```powershell
cd D:\project\ransomware\method12\windows_host\powershell
.\08_start_maintenance.ps1
```

This path is used whenever you want to:

1. update the guest runtime
2. reconfigure Sysmon
3. change Windows settings
4. inspect the guest manually

## 8. Install the Guest Runtime

With the VM running in maintenance mode, open WSL:

```bash
cd /mnt/d/project/ransomware/method12
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install pycdlib
python sandbox/scripts/install_guest_runtime.py --guest-user analyst
```

What this installs inside the guest:

1. `C:\Sandbox\runtime\run_task.ps1`
2. `C:\Sandbox\runtime\sysmon_config.xml`
3. a startup scheduled task named `SandboxRunTask`

The startup task is intentionally quiet when no sample ISO and artifact VHDX are present.

## 9. Rebuild the Dual Baselines

After guest maintenance is complete, shut the guest down cleanly. Then in admin PowerShell:

```powershell
cd D:\project\ransomware\method12\windows_host\powershell
Stop-VM -Name "rw-sandbox-win10" -TurnOff -Force
.\07_refresh_snapshots.ps1 -Force
.\09_show_sandbox_state.ps1
```

Expected result:

1. `analysis-base` exists
2. `maintenance-base` exists
3. no unexpected snapshots remain
4. no task disks are attached
5. no DVD media remain attached
6. `AnalysisReady` is `true`

If `07_refresh_snapshots.ps1` reports stale `*.avhd*` files under `sandbox_data\task_media`, delete those task-media differencing disks first and rerun the command.

## 10. Run One Sample

In WSL:

```bash
cd /mnt/d/project/ransomware/method12
source .venv/bin/activate
python sandbox/scripts/analyze_sample.py "samples/PotPlayerSetup64.exe"
```

This will:

1. build `sandbox_data/task_media/sample-task.iso`
2. create `sandbox_data/task_media/artifact-task.vhdx`
3. restore `analysis-base`
4. boot the guest
5. wait for the guest runtime to finish
6. mount the artifact VHDX
7. parse the raw output into `reports/<report_id>/`

## 11. Inspect Host State

Any time you want to know whether the VM is safe for the next run:

```powershell
cd D:\project\ransomware\method12\windows_host\powershell
.\09_show_sandbox_state.ps1
```

Key fields:

1. `UnexpectedSnapshots`
2. `AttachedTaskMediaDisks`
3. `AttachedDvdMedia`
4. `ArtifactDiskAttachedOnHost`
5. `AnalysisReady`

If `AnalysisReady` is `false`, do not start a new automated task until the state is fixed.

## 12. Maintenance Workflow

Whenever you need to update guest-side tools:

1. start maintenance mode

```powershell
cd D:\project\ransomware\method12\windows_host\powershell
.\08_start_maintenance.ps1
```

2. push the new runtime from WSL

```bash
cd /mnt/d/project/ransomware/method12
source .venv/bin/activate
python sandbox/scripts/install_guest_runtime.py --guest-user analyst
```

3. shut the VM down and refresh baselines again

```powershell
cd D:\project\ransomware\method12\windows_host\powershell
Stop-VM -Name "rw-sandbox-win10" -TurnOff -Force
.\07_refresh_snapshots.ps1 -Force
.\09_show_sandbox_state.ps1
```

## 13. Failure Recovery Rules

If automated runs stop behaving correctly:

1. do not patch the guest from `analysis-base`
2. inspect the current state with `.\09_show_sandbox_state.ps1`
3. remove stale task-media `*.avhd*` files if snapshot refresh complains about broken differencing chains
4. boot only through `maintenance-base`
5. after fixing the guest, rebuild both snapshots again

The architecture deliberately avoids a long-lived running analysis snapshot. For this disk-centric offline design, that path is more brittle than restoring a cold immutable baseline each run.
