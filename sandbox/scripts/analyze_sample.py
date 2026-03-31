#!/usr/bin/env python3

from __future__ import annotations

import argparse
import subprocess
import sys
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
        default=300,
        help="Maximum task runtime before forced shutdown.",
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
        "--guest-user",
        default="analyst",
        help="Guest Windows username for PowerShell Direct when --install-runtime is used.",
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

    if args.install_runtime:
        run(
            [
                sys.executable,
                str(install_runtime_script),
                "--vm-name",
                args.vm_name,
                "--guest-user",
                args.guest_user,
            ],
            cwd=root,
        )

    run_cmd = [
        sys.executable,
        str(run_task_script),
        args.sample,
        "--vm-name",
        args.vm_name,
        "--snapshot-name",
        args.snapshot_name,
        "--timeout-seconds",
        str(args.timeout_seconds),
    ]
    run(run_cmd, cwd=root)

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
