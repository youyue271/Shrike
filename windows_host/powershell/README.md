# PowerShell Scripts

These scripts automate the Windows-host side of the offline Hyper-V sandbox.

Baseline policy:

1. `analysis-base` is the immutable automation snapshot.
2. `maintenance-base` is the manual update snapshot.
3. Automatic checkpoints must stay disabled.
4. Task media must never remain attached when baselines are refreshed.

## Scripts

1. `01_prepare_host.ps1`
   Prepares host directories and checks Hyper-V availability.
2. `02_new_analysis_vm.ps1`
   Creates the air-gapped analysis VM and attaches the Windows installation ISO. Default VM generation is `Gen1`.
3. `03_new_artifact_disk.ps1`
   Creates one fresh artifact `VHDX` for a task.
4. `04_invoke_offline_task.ps1`
   Restores `analysis-base`, attaches task media, boots the VM, waits, detaches the artifact disk, and restores `analysis-base` again.
5. `05_mount_artifact_disk.ps1`
   Mounts an artifact `VHDX` read-only and prints the artifact directory path.
6. `06_install_guest_runtime.ps1`
   Pushes the guest runtime script into the running VM by PowerShell Direct and registers the startup task.
7. `07_refresh_snapshots.ps1`
   Rebuilds the dual snapshot layout after clearing task disks, DVD media, and automatic checkpoints.
8. `08_start_maintenance.ps1`
   Restores `maintenance-base`, starts the VM, and optionally opens `vmconnect` for manual guest maintenance.
9. `09_show_sandbox_state.ps1`
   Prints a JSON status view of VM state, snapshots, attached media, and whether the sandbox is ready for automated analysis.
10. `10_install_drio.ps1`
   Copies a DynamoRIO Windows zip package into the running guest through Hyper-V guest services, extracts it, and validates that `drrun.exe` is present.

## Typical usage

Run in admin PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
cd .\windows_host\powershell
.\01_prepare_host.ps1
.\02_new_analysis_vm.ps1
.\09_show_sandbox_state.ps1
```

Install guest runtime after Windows is installed and the VM is booted:

```powershell
.\08_start_maintenance.ps1
.\06_install_guest_runtime.ps1 -GuestUser "root" -GuestPassword "root"
.\10_install_drio.ps1 -GuestUser "root" -DynamoRIOZipPath "windows_host\third_party\DynamoRIO-Windows.zip"
Stop-VM -Name "rw-sandbox-win10" -TurnOff -Force
.\07_refresh_snapshots.ps1 -Force
```

Refresh the dual snapshot layout after clean shutdown:

```powershell
Stop-VM -Name "rw-sandbox-win10" -TurnOff -Force
.\07_refresh_snapshots.ps1 -Force
.\09_show_sandbox_state.ps1
```

Start a maintenance session from the maintenance baseline:

```powershell
.\08_start_maintenance.ps1
```

Default project-relative locations:

1. Windows installation ISO: `sandbox_data\iso\Win10_22H2_x64.iso`
2. base VHDX: `sandbox_data\base_images\rw-sandbox-win10-base.vhdx`
3. task media: `sandbox_data\task_media\`
4. Hyper-V VM files: `sandbox_data\hyperv\`

Log files are written under:

1. `windows_host/logs/`
