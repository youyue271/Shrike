# Modern Lightweight Ransomware Sandbox MVP

## 1. Goal

This document defines a single-machine, batch-oriented sandbox MVP for defensive ransomware analysis.

Design constraints:

1. no nested virtualization
2. Windows host remains the hypervisor owner
3. WSL is used only as the control plane and data-processing environment
4. the analysis guest is air-gapped by default
5. batch execution must be simple and repeatable
6. packaging and migration should be straightforward

This is intentionally not a full CAPE replacement. It is a minimal "modern Cuckoo-style" system focused on:

1. task submission
2. VM snapshot restore
3. guest execution
4. artifact collection
5. report generation

## 2. Recommended Host Model

Use this topology:

1. Windows 11 Pro host
2. WSL2 Ubuntu for controller, queue, parsing, and report generation
3. one Windows analysis VM running directly on the Windows host hypervisor
4. no guest network for the default execution mode
5. sample input and artifact output use offline virtual media

Important consequence:

1. do not try to run KVM inside WSL
2. do not try to run VMware inside another VM
3. the Windows host owns virtualization
4. WSL calls Windows-side control commands

## 3. Hypervisor Choice

### 3.1 Preferred: Hyper-V

Why prefer it:

1. WSL2 already coexists naturally with Hyper-V
2. PowerShell automation is strong
3. checkpoints, switches, and guest lifecycle are scriptable
4. no VMware nested-virtualization issue exists because WSL is not the hypervisor layer

Use Hyper-V if:

1. your Windows edition supports it
2. you want the cleanest Windows + WSL automation path
3. you are willing to keep the guest fully offline and move data by ISO plus VHDX

Practical project default:

1. VM generation should default to `Gen1` for this repository because that is the boot path already verified on the target machine
2. the host must disable automatic checkpoints
3. the guest must have no network adapter in the default profile

### 3.2 Fallback: VMware Workstation

Use VMware only if:

1. Hyper-V is unavailable for your edition or policy
2. you already have stable VMware images
3. you are comfortable driving it through `vmrun` or PowerShell wrappers

In this design, VMware still runs on the Windows host directly. WSL only orchestrates it.

## 4. MVP Architecture

The MVP has six parts.

### 4.1 Controller

Runs in WSL.

Responsibilities:

1. accept sample submission
2. create tasks
3. manage queue state
4. enforce timeout and retries
5. mark results and failures

Suggested implementation:

1. Python
2. SQLite for first version
3. filesystem-based artifact storage

### 4.2 Runner

Runs in WSL, but invokes Windows commands.

Responsibilities:

1. prepare task media
2. attach sample ISO and artifact disk
3. restore VM to clean state
4. start VM
5. wait for execution time budget
6. power off or stop VM
7. detach and collect artifact media
8. discard run-state changes

This is the core replacement for old Cuckoo machinery.

### 4.3 Guest Runtime

Runs inside the Windows analysis VM.

Responsibilities:

1. discover the attached sample media
2. copy the sample to a local execution directory
3. launch the sample with the selected local policy
4. collect local logs during and after execution
5. export artifacts onto the attached artifact disk
6. shut the VM down cleanly when the local script completes

The guest runtime should remain small and offline-first. It does not depend on guest-to-host networking.

### 4.4 Telemetry Layer

For the MVP, collect only the most stable telemetry:

1. process tree and command lines
2. file operations
3. registry activity
4. network connections and DNS
5. basic execution metadata
6. optional Sysmon event logs

Recommended first version:

1. Sysmon
2. Windows Event Log export
3. optional packet capture on host-side virtual switch

### 4.5 Network Policy

The default MVP mode is air-gapped.

Default policy:

1. do not attach a guest network adapter
2. do not provide a default gateway
3. do not depend on fake internet in V1
4. do not depend on guest-to-host network transfer

Optional later mode:

1. add a separate simulated-LAN profile only if some families clearly require it
2. keep the default profile air-gapped even after simulated-LAN exists

### 4.6 Report Builder

Runs in WSL.

Responsibilities:

1. normalize raw logs
2. build a single JSON report per task
3. attach hashes, timing, and failure reason
4. optionally derive features for later ML use

## 5. Packaging Strategy

The easiest packaging model is:

1. WSL repository for controller, runner, parsers, and report builder
2. one Windows bootstrap directory for host PowerShell scripts
3. one guest-image build directory for VM template preparation
4. one portable base image directory for the guest VHDX template

Recommended layout:

```text
method12/
  SANDBOX_MVP.md
  sandbox/
    controller/
    runner/
    parsers/
    schemas/
    scripts/
  windows_host/
    powershell/
    sysmon/
    config/
  guest/
    agent/
    bootstrap/
    config/
  samples/
  artifacts/
  reports/
```

Why this packages well:

1. WSL code stays portable and source-controlled
2. host setup is a small set of Windows scripts
3. guest image prep is reproducible
4. there is no dependency on nested virtualization

## 6. Execution Flow

One task should follow this state machine:

1. `queued`
2. `building_sample_iso`
3. `creating_artifact_disk`
4. `restoring_vm`
5. `booting_vm`
6. `running`
7. `powering_off`
8. `collecting_artifacts`
9. `discarding_run_state`
10. `completed` or `failed`

Each task should produce:

1. original sample hash
2. task metadata
3. execution timestamps
4. raw guest artifacts
5. normalized report
6. failure code if not successful

Snapshot policy:

1. `analysis-base` is restored before and after every automated sample run
2. `maintenance-base` is reserved for manual guest access, runtime updates, and guest configuration changes
3. do not modify the guest from the `analysis-base` lineage and then continue using it as the automation baseline
4. before rebuilding snapshots, remove task disks, clear DVD media, and make sure no task-media `*.avhd*` files remain

Operational rule:

1. `analysis-base` is cold and immutable
2. `maintenance-base` is the only place where you log into the guest
3. after maintenance, shut down cleanly and rebuild both snapshots
4. do not attempt to keep a long-lived "running analysis snapshot" because attached task media and checkpoint chains become brittle

## 7. Disk-Centric Offline Design

The default execution path is based on three storage roles.

### 7.1 Base Disk

Purpose:

1. holds the clean Windows template
2. includes Sysmon, local runtime scripts, and fixed guest configuration
3. is never used as a long-lived dirty execution disk

Recommended form:

1. one golden `VHDX`
2. one documented rebuild path
3. two explicit checkpoints:
   `analysis-base` and `maintenance-base`

### 7.2 Run-State Disk

Purpose:

1. absorbs temporary changes produced during a task
2. prevents task residue from contaminating the base image

Recommended policy:

1. create a fresh differencing disk or revertible run state per task
2. delete it after artifact collection
3. never reuse it across samples

### 7.3 Artifact Disk

Purpose:

1. stores logs exported by the guest runtime
2. gives the host and WSL a clean offline retrieval channel

Recommended contents:

1. Sysmon export
2. event-log export
3. task metadata
4. process summary
5. file, registry, and network summaries
6. optional screenshots or custom logs

Recommended policy:

1. create one fresh artifact `VHDX` per task
2. attach it read-write to the guest during execution
3. detach it after shutdown
4. mount it read-only on the host for parsing

### 7.4 Sample Input Media

Purpose:

1. deliver the target sample without guest networking
2. keep the input path simple and auditable

Recommended form:

1. build one small ISO per task
2. attach it as read-only media
3. let the guest runtime copy the sample locally before execution

Why use ISO:

1. simple to generate
2. naturally read-only
3. reduces accidental bidirectional file flow

## 8. Network Design

The default profile is no guest networking at all.

### 8.1 Default Air-Gapped Layout

1. do not attach a virtual NIC to the guest
2. do not expose host services into the guest
3. do not depend on SMB, HTTP, or RPC between guest and host

This is the recommended V1 configuration.

### 8.2 Optional Simulated-LAN Layout

Only add this later if necessary.

1. create one isolated internal switch
2. assign host and guest static IPs
3. do not bridge to the real LAN
4. expose only deliberate fake services
5. keep this as a separate execution profile from the default air-gapped mode

### 8.3 Transfer Channel

The default transfer model is offline media:

1. sample enters by ISO
2. artifacts leave by artifact disk
3. no guest network channel is required

## 9. Storage Design

Keep three separate roots:

1. `samples/` for input binaries
2. `artifacts/` for raw logs and exports
3. `reports/` for normalized JSON summaries

In addition, keep VM image assets in a separate location:

1. `base_images/` for golden VHDX files
2. `task_media/` for per-task ISO and artifact disks

Do not mix VM disk images with analysis artifacts.

## 10. Guest Template Design

Create one golden Windows VM image and never analyze samples on the template directly.

Golden image should include:

1. Windows 10 22H2 or Windows 11 23H2
2. guest runtime launcher
3. Sysmon
4. analysis user account
5. disabled unnecessary consumer software
6. no active network dependency for the local run path
7. optional document decoys if you want light realism

Before each run:

1. prepare task ISO and artifact disk
2. attach them to the VM
3. restore clean base state
4. boot
5. execute local runtime script
6. export logs onto the artifact disk
7. power off
8. detach task media
9. discard run state

## 11. What Not To Build In V1

Avoid these in the MVP:

1. distributed workers
2. multi-VM parallel scheduling
3. full memory forensics pipeline
4. custom kernel drivers
5. complex web UI
6. anti-evasion research logic
7. internet passthrough
8. online guest agent protocols

The first milestone is not sophistication. It is stable batch execution.

## 12. Step-By-Step Build Plan

### Step 1. Prepare the Windows host

1. use a dedicated Windows machine if possible
2. update Windows fully before building the lab
3. create a separate directory for sandbox host scripts and outputs
4. ensure you have enough disk for:
   a. base VM image
   b. checkpoints
   c. artifact retention

For a practical minimum:

1. 32 GB RAM recommended
2. 8 CPU threads recommended
3. 300 GB free SSD space recommended

### Step 2. Enable the hypervisor

Preferred path:

1. enable Hyper-V
2. reboot
3. verify that Hyper-V Manager and PowerShell VM commands work

Fallback path:

1. install VMware Workstation
2. verify `vmrun` works from PowerShell

### Step 3. Decide the execution profile

For V1, use:

1. no guest network adapter
2. offline sample delivery
3. offline artifact collection

Do not add fake internet in the first build.

### Step 5. Create the guest template

1. install Windows 10 or 11 in a new VM
2. apply base updates
3. create a local analysis user
4. install Sysmon with a known config
5. install the guest runtime launcher
6. verify the launcher can:
   a. discover the sample ISO
   b. run a local test binary
   c. export logs to the artifact disk
7. shut down and create a clean base state

### Step 6. Build the WSL control plane

Inside WSL, create:

1. a task queue
2. a runner script
3. a report builder
4. directories for samples, artifacts, and reports

The runner should call Windows-side commands through:

1. `powershell.exe`
2. Hyper-V cmdlets or `vmrun`

The runner should also manage:

1. sample ISO creation
2. fresh artifact-disk creation
3. task-media attachment and detachment
4. post-run artifact mounting for parsing

### Step 7. Implement one end-to-end happy path

Do not start with batch mode.

First prove this works for one sample:

1. queue one task
2. build one sample ISO
3. create one fresh artifact disk
4. attach media
5. restore clean base state
6. boot guest
7. execute a harmless test binary
8. power off
9. detach and mount the artifact disk
10. produce one JSON report
11. discard run-state changes

Only after this is stable should you switch to real batch execution.

### Step 8. Add batch execution

For batch mode:

1. process tasks serially first
2. use a hard runtime limit
3. mark every failure explicitly
4. never reuse guest state between samples
5. always create fresh task media per sample

Recommended first-run policy:

1. task timeout: `5-10` minutes
2. boot timeout: `2-3` minutes
3. retry count: `0` or `1`

### Step 9. Normalize outputs

Each task report should include:

1. task id
2. file name
3. SHA256
4. guest start and end time
5. VM platform
6. process tree summary
7. file event counts
8. registry event counts
9. network summary
10. exit condition
11. timeout flag
12. artifact paths

### Step 10. Freeze the MVP

Once the single-VM serial runner is stable:

1. freeze the host image
2. export the WSL repository
3. export host-side PowerShell scripts
4. document one rebuild path from scratch

That is the point where the system becomes portable.

## 13. Practical Recommendation For Your Environment

Given your constraint that you work in WSL and do not want nested virtualization:

1. use WSL only for controller and parsing
2. use Hyper-V on the Windows host if available
3. use VMware only as a fallback
4. do not attempt Linux-host KVM inside WSL
5. package the project as:
   a. WSL repo
   b. Windows PowerShell bootstrap scripts
   c. one documented guest template
   d. one portable base VHDX

For your current preferred security posture:

1. keep the guest air-gapped by default
2. avoid guest-host networking in V1
3. use ISO input and artifact-disk output
4. treat WSL as an offline orchestrator and parser, not a live telemetry endpoint

That is the cleanest path to a single-machine, batch-capable, easy-to-package modern sandbox.

## 14. Suggested Immediate Next Milestones

Build in this order:

1. guest golden image
2. sample-ISO builder
3. artifact-disk builder
4. WSL runner calling Windows hypervisor commands
5. single-task offline run
6. serial batch queue
7. report normalization

If one stage is unstable, do not continue stacking features on top of it.
