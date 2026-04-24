#!/usr/bin/env python3

from __future__ import annotations

import argparse
import subprocess
import sys
import threading
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

    # Start ResultServer in background
    result_server_output_dir = root / "tmp" / "result_server_artifacts"
    result_server_output_dir.mkdir(parents=True, exist_ok=True)

    result_server_proc = subprocess.Popen(
        [
            sys.executable,
            str(result_server_script),
            "--host", "192.168.100.1",
            "--port", "2042",
            "--output-dir", str(result_server_output_dir),
        ],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    # Give ResultServer time to start
    time.sleep(2)

    try:
        run_cmd = [
            sys.executable,
            str(run_task_script),
            args.sample,
            "--vm-name",
            args.vm_name,
            "--snapshot-name",
            args.snapshot_name,
            *(
                [
                    "--timeout-seconds",
                    str(args.timeout_seconds),
                ]
                if args.timeout_seconds is not None
                else []
            ),
            *(
                [
                    "--task-profile",
                    args.task_profile,
                ]
                if args.task_profile
                else []
            ),
        ]
        run(run_cmd, cwd=root)
    finally:
        # Stop ResultServer
        result_server_proc.terminate()
        try:
            result_server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            result_server_proc.kill()

    collect_cmd = [
        sys.executable,
        str(collect_report_script),
    ]
    if args.report_id:
        collect_cmd.extend(["--report-id", args.report_id])
    run(collect_cmd, cwd=root)

    print("")
    print("Sample analysis completed.")
    print("The parsed report is available under reports/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
