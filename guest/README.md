# Guest Layout

This directory is reserved for the Windows analysis guest image assets.

Planned subdirectories:

1. `agent/` for the guest heartbeat and task agent
2. `bootstrap/` for image preparation scripts
3. `config/` for guest runtime configuration

Current runtime assets:

1. `runtime/run_task.ps1`
   Offline guest execution and artifact export script.
2. `runtime/sysmon_config.xml`
   Project Sysmon configuration used to collect process, file, registry, network, IPC, WMI, and tampering events.
