#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

import pycdlib

from task_profile import validate_task_profile_dict


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a read-only sample ISO for the offline Hyper-V sandbox."
    )
    parser.add_argument(
        "sample",
        help="Path to the sample executable. Relative paths are resolved from the project root.",
    )
    parser.add_argument(
        "--output",
        default="sandbox_data/task_media/sample-task.iso",
        help="Output ISO path relative to the project root unless absolute.",
    )
    parser.add_argument(
        "--volume-id",
        default="SAMPLEISO",
        help="ISO volume identifier.",
    )
    parser.add_argument(
        "--task-profile",
        default=None,
        help="Optional JSON task profile to stage into the ISO as /task/task_profile.json.",
    )
    return parser.parse_args()


def resolve_project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def resolve_path(project_root: Path, raw_path: str) -> Path:
    path = Path(raw_path)
    if path.is_absolute():
        return path
    return (project_root / path).resolve()


def validate_sample(sample_path: Path) -> None:
    if not sample_path.exists():
        raise FileNotFoundError(f"sample not found: {sample_path}")
    if not sample_path.is_file():
        raise ValueError(f"sample is not a file: {sample_path}")


def validate_task_profile(task_profile_path: Path | None) -> None:
    if task_profile_path is None:
        return
    if not task_profile_path.exists():
        raise FileNotFoundError(f"task profile not found: {task_profile_path}")
    if not task_profile_path.is_file():
        raise ValueError(f"task profile is not a file: {task_profile_path}")

    data = json.loads(task_profile_path.read_text(encoding="utf-8"))
    validate_task_profile_dict(data)


def build_iso(sample_path: Path, output_path: Path, volume_id: str, task_profile_path: Path | None = None) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()

    project_root = resolve_project_root()
    tmp_root = project_root / "tmp" / "sample_iso_build"
    sample_dir = tmp_root / "sample"
    task_dir = tmp_root / "task"

    if tmp_root.exists():
        shutil.rmtree(tmp_root)
    sample_dir.mkdir(parents=True, exist_ok=True)

    staged_sample = sample_dir / sample_path.name
    shutil.copy2(sample_path, staged_sample)

    staged_task_profile: Path | None = None
    if task_profile_path is not None:
        task_dir.mkdir(parents=True, exist_ok=True)
        staged_task_profile = task_dir / "task_profile.json"
        shutil.copy2(task_profile_path, staged_task_profile)

    iso = pycdlib.PyCdlib()
    try:
        iso.new(joliet=3, vol_ident=volume_id[:32])
        iso.add_directory(joliet_path="/sample")
        iso.add_file(str(staged_sample), joliet_path=f"/sample/{sample_path.name}")
        if staged_task_profile is not None:
            iso.add_directory(joliet_path="/task")
            iso.add_file(str(staged_task_profile), joliet_path="/task/task_profile.json")
        iso.write(str(output_path))
    finally:
        iso.close()


def main() -> int:
    args = parse_args()
    project_root = resolve_project_root()
    sample_path = resolve_path(project_root, args.sample)
    output_path = resolve_path(project_root, args.output)
    task_profile_path = resolve_path(project_root, args.task_profile) if args.task_profile else None

    try:
        validate_sample(sample_path)
        validate_task_profile(task_profile_path)
        build_iso(sample_path, output_path, args.volume_id, task_profile_path)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"sample: {sample_path}")
    print(f"iso: {output_path}")
    if task_profile_path:
        print(f"task_profile: {task_profile_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
