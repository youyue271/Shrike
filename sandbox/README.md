# Sandbox Code Layout

This directory is the WSL-side control plane for the upgraded offline sandbox.

Planned subdirectories:

1. `controller/` for task queue and task lifecycle logic
2. `runner/` for VM orchestration wrappers
3. `parsers/` for raw artifact normalization
4. `schemas/` for task and report schemas
5. `scripts/` for local helper scripts

Current helper scripts:

1. `scripts/build_sample_iso.py`
   Builds a read-only sample ISO inside `sandbox_data/task_media/`.
2. `scripts/run_offline_task.py`
   Runs the end-to-end offline task flow from WSL by calling the Windows PowerShell scripts and restoring `analysis-base`.
3. `scripts/install_guest_runtime.py`
   Pushes the project guest runtime and Sysmon config into the running guest through PowerShell Direct. Use this from `maintenance-base`, not from the analysis baseline.
4. `scripts/parse_artifact.py`
   Parses one mounted artifact directory into `reports/<report_id>/`.
5. `scripts/collect_report.py`
   Mounts the artifact VHDX through Windows PowerShell and parses it into a report from WSL.
6. `scripts/analyze_sample.py`
   Main one-command entry point: optionally installs guest runtime, runs the sample, and collects the parsed report.

Baseline model:

1. WSL orchestrates tasks only.
2. Guest modifications happen only through the maintenance snapshot lineage.
3. Automated runs always restore `analysis-base` before boot and after shutdown.
