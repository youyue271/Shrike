#!/usr/bin/env python3

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install a DynamoRIO runtime package into the Hyper-V guest from WSL."
    )
    parser.add_argument("package_path", help="Path to the DynamoRIO Windows zip package.")
    parser.add_argument("--vm-name", default="rw-sandbox-win10", help="Hyper-V VM name.")
    parser.add_argument("--guest-user", default="analyst", help="Guest Windows username for PowerShell Direct.")
    parser.add_argument("--guest-install-root", default=r"C:\Tools\DynamoRIO", help="Target install root inside the guest.")
    parser.add_argument("--force", action="store_true", help="Replace an existing guest DynamoRIO install.")
    return parser.parse_args()


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def wsl_to_windows(path: Path) -> str:
    result = subprocess.run(
        ["wslpath", "-w", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def main() -> int:
    args = parse_args()
    root = project_root()
    script = root / "windows_host" / "powershell" / "10_install_drio.ps1"
    package_path = Path(args.package_path).expanduser().resolve()

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        wsl_to_windows(script),
        "-VmName",
        args.vm_name,
        "-GuestUser",
        args.guest_user,
        "-DynamoRIOZipPath",
        wsl_to_windows(package_path),
        "-GuestInstallRoot",
        args.guest_install_root,
    ]
    if args.force:
        cmd.append("-Force")

    print("+", " ".join(cmd))
    result = subprocess.run(cmd, check=False)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
