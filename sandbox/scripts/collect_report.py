#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import shutil
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mount an artifact VHDX on Windows and parse it into a project-local report."
    )
    parser.add_argument(
        "--artifact-disk",
        default="sandbox_data/task_media/artifact-task.vhdx",
        help="Artifact VHDX path relative to the project root unless absolute.",
    )
    parser.add_argument(
        "--report-id",
        default=None,
        help="Optional report id to pass to the parser.",
    )
    parser.add_argument(
        "--merge-artifact-dir",
        default=None,
        help="Optional directory of host-received result-server artifacts to merge before parsing.",
    )
    return parser.parse_args()


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def resolve_path(root: Path, raw: str) -> Path:
    path = Path(raw)
    if path.is_absolute():
        return path
    return (root / path).resolve()


def wsl_to_windows(path: Path) -> str:
    result = subprocess.run(
        ["wslpath", "-w", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def windows_to_wsl(path: str) -> str:
    match = re.match(r"^([A-Za-z]):\\(.*)$", path)
    if match:
        drive = match.group(1).lower()
        rest = match.group(2).replace("\\", "/")
        return f"/mnt/{drive}/{rest}"

    result = subprocess.run(
        ["wslpath", path],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def run_capture(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def extract_artifact_path(output: str) -> str:
    match = re.search(r"Artifact path:\s*(.+)", output)
    if not match:
        raise RuntimeError("failed to parse Artifact path from mount script output")
    return match.group(1).strip()


def merge_artifact_dir(src_dir: Path, dst_dir: Path) -> None:
    if not src_dir.exists():
        return
    for item in sorted(src_dir.rglob("*")):
        if item.is_file():
            relative = item.relative_to(src_dir)
            destination = dst_dir / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, destination)


def main() -> int:
    args = parse_args()
    root = project_root()
    artifact_disk = resolve_path(root, args.artifact_disk)
    mount_script = root / "windows_host" / "powershell" / "05_mount_artifact_disk.ps1"
    parse_script = root / "sandbox" / "scripts" / "parse_artifact.py"
    staging_dir = root / "tmp" / "mounted_artifact"

    mount_cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        wsl_to_windows(mount_script),
        "-ArtifactDiskPath",
        wsl_to_windows(artifact_disk),
    ]
    mount_result = run_capture(mount_cmd)
    sys.stdout.write(mount_result.stdout)
    sys.stderr.write(mount_result.stderr)
    if mount_result.returncode != 0:
        return mount_result.returncode

    artifact_path_win = extract_artifact_path(mount_result.stdout)
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    copy_cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        (
            f'$src = "{artifact_path_win}"; '
            f'$dst = "{wsl_to_windows(staging_dir)}"; '
            'New-Item -ItemType Directory -Force -Path $dst | Out-Null; '
            'Copy-Item -Path (Join-Path $src "*") -Destination $dst -Recurse -Force'
        ),
    ]
    copy_result = run_capture(copy_cmd)
    sys.stdout.write(copy_result.stdout)
    sys.stderr.write(copy_result.stderr)
    if copy_result.returncode != 0:
        return copy_result.returncode

    if args.merge_artifact_dir:
        merge_artifact_dir(resolve_path(root, args.merge_artifact_dir), staging_dir)

    parse_cmd = [sys.executable, str(parse_script), str(staging_dir)]
    if args.report_id:
        parse_cmd.extend(["--report-id", args.report_id])
    parse_result = run_capture(parse_cmd)
    sys.stdout.write(parse_result.stdout)
    sys.stderr.write(parse_result.stderr)
    if parse_result.returncode != 0:
        return parse_result.returncode

    print("")
    print("To dismount the artifact VHDX after inspection, run in Windows admin PowerShell:")
    print(f'Dismount-VHD -Path "{wsl_to_windows(artifact_disk)}"')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
