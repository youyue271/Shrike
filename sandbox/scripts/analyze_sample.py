#!/usr/bin/env python3

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one offline sample through the Hyper-V sandbox and collect a parsed report."
    )
    parser.add_argument(
        "sample",
        help="Path to the sample file, relative to the project root unless absolute.",
    )
    parser.add_argument(
        "--report-id",
        default=None,
        help="Optional report id for the parsed report output.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=None,
        help="Maximum task runtime before forced shutdown. Auto-selected from task profile when omitted.",
    )
    parser.add_argument(
        "--vm-name",
        default="rw-sandbox-win10",
        help="Hyper-V VM name.",
    )
    parser.add_argument(
        "--snapshot-name",
        default="analysis-base",
        help="Hyper-V snapshot name restored before and after the task.",
    )
    parser.add_argument(
        "--task-profile",
        default=None,
        help="Optional JSON task profile to pass through to run_offline_task.py.",
    )
    parser.add_argument(
        "--guest-user",
        default="root",
        help="Guest Windows username for PowerShell Direct when --install-runtime is used.",
    )
    parser.add_argument(
        "--guest-password",
        default="root",
        help="Guest Windows password for PowerShell Direct when --install-runtime is used.",
    )
    parser.add_argument(
        "--install-runtime",
        action="store_true",
        help="Push the current guest runtime and Sysmon config into the running guest before analysis.",
    )
    return parser.parse_args()


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def run(cmd: list[str], cwd: Path) -> None:
    print("+", " ".join(cmd))
    result = subprocess.run(cmd, cwd=cwd, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def run_capture(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd))
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)


def wsl_to_windows(path: Path) -> str:
    result = subprocess.run(
        ["wslpath", "-w", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def powershell_array(values: list[str]) -> str:
    return "@(" + ", ".join(ps_quote(value) for value in values) + ")"


def start_windows_result_server(root: Path, script: Path, output_dir: Path, stdout_log: Path, stderr_log: Path) -> int | None:
    common_script = root / "windows_host" / "powershell" / "common.ps1"
    command = "\n".join(
        [
            f". {ps_quote(wsl_to_windows(common_script))}",
            "$python = Resolve-WindowsPython",
            "$args = "
            + powershell_array(
                [
                    wsl_to_windows(script),
                    "--host",
                    "192.168.100.1",
                    "--port",
                    "42042",
                    "--output-dir",
                    wsl_to_windows(output_dir),
                ]
            ),
            "$proc = Start-Process -FilePath $python -ArgumentList $args -PassThru -WindowStyle Hidden "
            + f"-RedirectStandardOutput {ps_quote(wsl_to_windows(stdout_log))} "
            + f"-RedirectStandardError {ps_quote(wsl_to_windows(stderr_log))}",
            "Start-Sleep -Seconds 1",
            "if ($proc.HasExited) { exit 2 }",
            "Write-Output $proc.Id",
        ]
    )
    result = run_capture(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        cwd=root,
    )
    if result.returncode != 0:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        print("WARNING: ResultServer startup failed; guest runtime will defer pre-execution artifacts.", file=sys.stderr)
        return None
    try:
        return int(result.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        print("WARNING: ResultServer startup did not return a process id; guest runtime will defer pre-execution artifacts.", file=sys.stderr)
        return None


def stop_windows_process(root: Path, pid: int) -> None:
    run_capture(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue",
        ],
        cwd=root,
    )


def main() -> int:
    args = parse_args()
    root = project_root()

    install_runtime_script = root / "sandbox" / "scripts" / "install_guest_runtime.py"
    run_task_script = root / "sandbox" / "scripts" / "run_offline_task.py"
    collect_report_script = root / "sandbox" / "scripts" / "collect_report.py"
    result_server_script = root / "sandbox" / "scripts" / "result_server.py"

    if args.install_runtime:
        run(
            [
                sys.executable,
                str(install_runtime_script),
                "--vm-name",
                args.vm_name,
                "--guest-user",
                args.guest_user,
                "--guest-password",
                args.guest_password,
            ],
            cwd=root,
        )

    result_server_output_dir = root / "tmp" / "result_server_artifacts"
    result_server_stdout = root / "tmp" / "result_server.stdout.log"
    result_server_stderr = root / "tmp" / "result_server.stderr.log"
    if result_server_output_dir.exists():
        shutil.rmtree(result_server_output_dir)
    result_server_output_dir.mkdir(parents=True, exist_ok=True)
    result_server_stdout.parent.mkdir(parents=True, exist_ok=True)
    result_server_pid = start_windows_result_server(
        root,
        result_server_script,
        result_server_output_dir,
        result_server_stdout,
        result_server_stderr,
    )
    time.sleep(1)

    run_cmd = [
        sys.executable,
        str(run_task_script),
        args.sample,
        "--vm-name",
        args.vm_name,
        "--snapshot-name",
        args.snapshot_name,
    ]
    if args.timeout_seconds is not None:
        run_cmd.extend(["--timeout-seconds", str(args.timeout_seconds)])
    if args.task_profile:
        run_cmd.extend(["--task-profile", args.task_profile])

    try:
        run(run_cmd, cwd=root)
    finally:
        if result_server_pid is not None:
            stop_windows_process(root, result_server_pid)

    collect_cmd = [sys.executable, str(collect_report_script)]
    if args.report_id:
        collect_cmd.extend(["--report-id", args.report_id])
    collect_cmd.extend(["--merge-artifact-dir", str(result_server_output_dir)])
    run(collect_cmd, cwd=root)

    print("")
    print("Sample analysis completed.")
    print("The parsed report is available under reports/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
