#!/usr/bin/env python3

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build sample ISO and invoke one offline Hyper-V sandbox task from WSL."
    )
    parser.add_argument(
        "sample",
        help="Path to the sample file, relative to the project root unless absolute.",
    )
    parser.add_argument(
        "--vm-name",
        default="rw-sandbox-win10",
        help="Hyper-V VM name.",
    )
    parser.add_argument(
        "--snapshot-name",
        default="analysis-base",
        help="Hyper-V snapshot name to restore before and after the task.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=300,
        help="Maximum task runtime before forced shutdown.",
    )
    parser.add_argument(
        "--artifact-disk",
        default="sandbox_data/task_media/artifact-task.vhdx",
        help="Artifact disk path relative to the project root unless absolute.",
    )
    parser.add_argument(
        "--sample-iso",
        default="sandbox_data/task_media/sample-task.iso",
        help="Sample ISO path relative to the project root unless absolute.",
    )
    parser.add_argument(
        "--task-profile",
        default=None,
        help="Optional JSON task profile to stage into the sample ISO.",
    )
    return parser.parse_args()


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def resolve_path(root: Path, raw: str) -> Path:
    path = Path(raw)
    if path.is_absolute():
        return path
    return (root / path).resolve()


def run(cmd: list[str], cwd: Path | None = None) -> None:
    print("+", " ".join(cmd))
    result = subprocess.run(cmd, cwd=cwd, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def wsl_to_windows(path: Path) -> str:
    result = subprocess.run(
        ["wslpath", "-w", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def powershell_script(script_path: Path, *args: str) -> None:
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        wsl_to_windows(script_path),
        *args,
    ]
    run(cmd)


def main() -> int:
    args = parse_args()
    root = project_root()

    sample_path = resolve_path(root, args.sample)
    artifact_disk = resolve_path(root, args.artifact_disk)
    sample_iso = resolve_path(root, args.sample_iso)
    task_profile = resolve_path(root, args.task_profile) if args.task_profile else None

    if not sample_path.exists():
        print(f"ERROR: sample not found: {sample_path}", file=sys.stderr)
        return 1
    if task_profile and not task_profile.exists():
        print(f"ERROR: task profile not found: {task_profile}", file=sys.stderr)
        return 1

    build_iso_script = root / "sandbox" / "scripts" / "build_sample_iso.py"
    ps_dir = root / "windows_host" / "powershell"
    new_artifact_ps = ps_dir / "03_new_artifact_disk.ps1"
    invoke_task_ps = ps_dir / "04_invoke_offline_task.ps1"
    mount_artifact_ps = ps_dir / "05_mount_artifact_disk.ps1"

    run(
        [
            sys.executable,
            str(build_iso_script),
            str(sample_path),
            "--output",
            str(sample_iso),
            *(
                [
                    "--task-profile",
                    str(task_profile),
                ]
                if task_profile
                else []
            ),
        ],
        cwd=root,
    )

    powershell_script(
        new_artifact_ps,
        "-ArtifactDiskPath",
        wsl_to_windows(artifact_disk),
    )

    powershell_script(
        invoke_task_ps,
        "-VmName",
        args.vm_name,
        "-SnapshotName",
        args.snapshot_name,
        "-SampleIsoPath",
        wsl_to_windows(sample_iso),
        "-ArtifactDiskPath",
        wsl_to_windows(artifact_disk),
        "-TimeoutSeconds",
        str(args.timeout_seconds),
    )

    powershell_script(
        mount_artifact_ps,
        "-ArtifactDiskPath",
        wsl_to_windows(artifact_disk),
    )

    print("")
    print("Task completed.")
    print(f"Sample ISO: {sample_iso}")
    print(f"Artifact disk: {artifact_disk}")
    if task_profile:
        print(f"Task profile: {task_profile}")
    print("If you finish inspecting the mounted artifact disk on Windows, dismount it with PowerShell:")
    print(
        f'Dismount-VHD -Path "{wsl_to_windows(artifact_disk)}"'
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
