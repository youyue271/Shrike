#!/usr/bin/env python3

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import pycdlib


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


def build_iso(sample_path: Path, output_path: Path, volume_id: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()

    project_root = resolve_project_root()
    tmp_root = project_root / "tmp" / "sample_iso_build"
    sample_dir = tmp_root / "sample"

    if tmp_root.exists():
        shutil.rmtree(tmp_root)
    sample_dir.mkdir(parents=True, exist_ok=True)

    staged_sample = sample_dir / sample_path.name
    shutil.copy2(sample_path, staged_sample)

    iso = pycdlib.PyCdlib()
    try:
        iso.new(joliet=3, vol_ident=volume_id[:32])
        iso.add_directory(joliet_path="/sample")
        iso.add_file(str(staged_sample), joliet_path=f"/sample/{sample_path.name}")
        iso.write(str(output_path))
    finally:
        iso.close()


def main() -> int:
    args = parse_args()
    project_root = resolve_project_root()
    sample_path = resolve_path(project_root, args.sample)
    output_path = resolve_path(project_root, args.output)

    try:
        validate_sample(sample_path)
        build_iso(sample_path, output_path, args.volume_id)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"sample: {sample_path}")
    print(f"iso: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
