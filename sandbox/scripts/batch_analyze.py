#!/usr/bin/env python3
"""Batch sandbox runner: walks a sample tree, runs each sample through the
Hyper-V sandbox via windows_host/powershell/12_run_sandbox_wrapped.ps1, and
stages whitelisted artifacts under results/{profile}_{sha12}/{timestamp}/.

Resume strategy:
- Stable key = profile + first 12 chars of sample sha256
- Default skips any sample whose stable key already has at least one timestamp
  dir containing dynamic_cfg_trace.ndjson. --force reprocesses anyway.

Failure strategy:
- Run 1: standard timeout from --timeout-seconds
- Run 2 (retry): Stop-VM first to reset state, then re-run
- Both fail: record to batch_errors.jsonl and move on
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

WHITELIST_RELATIVE = [
    # graph data
    "raw/dynamic_cfg_trace.ndjson",
    "raw/dynamic_cfg_trace_summary.json",
    "raw/trace_manifest.json",
    "raw/trace_request.json",
    "raw/trace_backend_diagnostic.json",
    # metadata / provenance
    "summary.json",
    "report.md",
    "raw/sample_metadata.json",
    "raw/task_profile.json",
    "raw/task_runtime_context.json",
    "raw/task_summary.json",
    # debug
    "raw/runner.log",
    # sysmon
    "raw/sysmon.evtx",
    "raw/sysmon_diagnostic.json",
    "raw/sysmon_summary.json",
    "raw/sysmon_process_events.json",
    "raw/sysmon_file_events.json",
    "raw/sysmon_network_dns_events.json",
    "raw/sysmon_registry_events.json",
    "raw/sysmon_injection_events.json",
    "raw/sysmon_ipc_wmi_events.json",
]

IDA_SIDECAR_SUFFIXES = {
    ".i64", ".id0", ".id1", ".id2", ".nam", ".til", ".patched",
}


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def sha256_of(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            buf = fh.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def is_sample_candidate(path: Path) -> bool:
    if not path.is_file():
        return False
    suf = path.suffix.lower()
    if suf in IDA_SIDECAR_SUFFIXES:
        return False
    if path.name.startswith("."):
        return False
    if path.stat().st_size == 0:
        return False
    return True


def discover_samples(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if is_sample_candidate(p))


def load_profile_name(profile_path: Path) -> str:
    try:
        return json.loads(profile_path.read_text(encoding="utf-8"))["profile_name"]
    except Exception:
        return profile_path.stem


def stable_key(profile_name: str, sha12: str) -> str:
    return f"{profile_name}_{sha12}"


def existing_runs(results_root: Path, key: str) -> list[Path]:
    base = results_root / key
    if not base.is_dir():
        return []
    return [p for p in sorted(base.iterdir()) if p.is_dir() and (p / "raw" / "dynamic_cfg_trace.ndjson").is_file()]


def run_wrapper(
    root: Path,
    sample: Path,
    task_profile: Path,
    report_id: str,
    timeout_seconds: int,
    wall_timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    wrapper = root / "windows_host" / "powershell" / "12_run_sandbox_wrapped.ps1"
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        win_path(wrapper),
        "-SamplePath",
        win_path(sample),
        "-TaskProfile",
        win_path(task_profile),
        "-ReportId",
        report_id,
        "-TimeoutSeconds",
        str(timeout_seconds),
    ]
    return subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=wall_timeout_seconds)


def win_path(p: Path) -> str:
    result = subprocess.run(
        ["wslpath", "-w", str(p)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def stop_vm(vm_name: str) -> None:
    subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            f"Stop-VM -Name '{vm_name}' -TurnOff -Force -ErrorAction SilentlyContinue",
        ],
        capture_output=True,
    )


def copy_whitelist(report_dir: Path, dest: Path) -> tuple[list[str], list[str]]:
    copied: list[str] = []
    missing: list[str] = []
    for rel in WHITELIST_RELATIVE:
        src = report_dir / rel
        if not src.is_file():
            missing.append(rel)
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
        copied.append(rel)
    return copied, missing


@dataclass
class RunResult:
    status: str  # "completed" | "failed" | "skipped"
    report_id: str
    report_dir: Path | None
    duration_seconds: float
    attempts: int
    error: str | None
    stdout_tail: str | None
    stderr_tail: str | None


def tail(text: str, n: int = 40) -> str:
    lines = text.splitlines()
    return "\n".join(lines[-n:]) if lines else ""


def process_sample(
    *,
    root: Path,
    sample: Path,
    task_profile: Path,
    profile_name: str,
    results_root: Path,
    manifest_fh,
    errors_fh,
    timeout_seconds: int,
    wall_timeout_seconds: int,
    vm_name: str,
    force: bool,
) -> RunResult:
    sha = sha256_of(sample)
    sha12 = sha[:12]
    key = stable_key(profile_name, sha12)

    if not force:
        runs = existing_runs(results_root, key)
        if runs:
            return RunResult(
                status="skipped",
                report_id="(already has " + runs[-1].name + ")",
                report_dir=runs[-1],
                duration_seconds=0.0,
                attempts=0,
                error=None,
                stdout_tail=None,
                stderr_tail=None,
            )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_id = f"{key}_{timestamp}"
    report_dir = root / "reports" / report_id

    error = None
    last_stdout = ""
    last_stderr = ""
    start = time.monotonic()
    for attempt in (1, 2):
        try:
            if attempt == 2:
                stop_vm(vm_name)
                time.sleep(5)
            completed = run_wrapper(root, sample, task_profile, report_id, timeout_seconds, wall_timeout_seconds)
            last_stdout = completed.stdout or ""
            last_stderr = completed.stderr or ""
            if completed.returncode == 0 and (report_dir / "raw" / "dynamic_cfg_trace.ndjson").is_file():
                duration = time.monotonic() - start
                dest = results_root / key / timestamp
                dest.mkdir(parents=True, exist_ok=True)
                copied, missing = copy_whitelist(report_dir, dest)
                manifest_fh.write(json.dumps({
                    "status": "completed",
                    "sample_path": str(sample.relative_to(root)) if sample.is_relative_to(root) else str(sample),
                    "sample_sha256": sha,
                    "sample_size": sample.stat().st_size,
                    "profile": profile_name,
                    "stable_key": key,
                    "report_id": report_id,
                    "report_dir": str(report_dir.relative_to(root)),
                    "result_dir": str(dest.relative_to(root)),
                    "timestamp_utc": timestamp,
                    "duration_seconds": round(duration, 2),
                    "attempts": attempt,
                    "whitelist_copied": copied,
                    "whitelist_missing": missing,
                }, ensure_ascii=False) + "\n")
                manifest_fh.flush()
                return RunResult(
                    status="completed",
                    report_id=report_id,
                    report_dir=report_dir,
                    duration_seconds=duration,
                    attempts=attempt,
                    error=None,
                    stdout_tail=None,
                    stderr_tail=None,
                )
            error = f"exit={completed.returncode} trace_missing={not (report_dir / 'raw' / 'dynamic_cfg_trace.ndjson').is_file()}"
        except subprocess.TimeoutExpired:
            error = f"wall_timeout_{wall_timeout_seconds}s"
            stop_vm(vm_name)
            time.sleep(5)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"

    duration = time.monotonic() - start
    errors_fh.write(json.dumps({
        "status": "failed",
        "sample_path": str(sample.relative_to(root)) if sample.is_relative_to(root) else str(sample),
        "sample_sha256": sha,
        "profile": profile_name,
        "stable_key": key,
        "report_id": report_id,
        "timestamp_utc": timestamp,
        "duration_seconds": round(duration, 2),
        "attempts": 2,
        "error": error,
        "stdout_tail": tail(last_stdout),
        "stderr_tail": tail(last_stderr),
    }, ensure_ascii=False) + "\n")
    errors_fh.flush()
    return RunResult(
        status="failed",
        report_id=report_id,
        report_dir=report_dir,
        duration_seconds=duration,
        attempts=2,
        error=error,
        stdout_tail=tail(last_stdout),
        stderr_tail=tail(last_stderr),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch runner for Shrike sandbox")
    parser.add_argument("samples_dir", help="Root directory to walk for sample files.")
    parser.add_argument(
        "--task-profile",
        default="sandbox/profiles/deep_cfg_drio_extended.json",
        help="Task profile JSON (relative to repo root unless absolute).",
    )
    parser.add_argument(
        "--results-dir",
        default="results",
        help="Output root for whitelisted per-sample copies (default: results/).",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=600,
        help="Per-run guest execution budget passed to the wrapper (default: 600).",
    )
    parser.add_argument(
        "--wall-timeout-seconds",
        type=int,
        default=1500,
        help="Wall-clock kill budget for the wrapper subprocess (default: 1500).",
    )
    parser.add_argument("--vm-name", default="rw-sandbox-win10")
    parser.add_argument("--force", action="store_true", help="Re-run samples even if a prior result exists.")
    parser.add_argument("--limit", type=int, default=None, help="Stop after N samples (useful for smoke-testing the batch runner).")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = project_root()

    samples_dir = (root / args.samples_dir).resolve() if not Path(args.samples_dir).is_absolute() else Path(args.samples_dir).resolve()
    if not samples_dir.is_dir():
        print(f"ERROR: samples_dir not a directory: {samples_dir}", file=sys.stderr)
        return 2

    task_profile = (root / args.task_profile).resolve() if not Path(args.task_profile).is_absolute() else Path(args.task_profile).resolve()
    if not task_profile.is_file():
        print(f"ERROR: task_profile not found: {task_profile}", file=sys.stderr)
        return 2
    profile_name = load_profile_name(task_profile)

    results_root = (root / args.results_dir).resolve() if not Path(args.results_dir).is_absolute() else Path(args.results_dir).resolve()
    results_root.mkdir(parents=True, exist_ok=True)
    manifest_path = results_root / "batch_manifest.jsonl"
    errors_path = results_root / "batch_errors.jsonl"

    samples = discover_samples(samples_dir)
    if args.limit is not None:
        samples = samples[: args.limit]
    print(f"discovered {len(samples)} candidate files under {samples_dir}")
    if not samples:
        return 0

    interrupted = {"flag": False}

    def _sigint(_signum, _frame):
        interrupted["flag"] = True
        print("\nSIGINT received; will stop after current sample.", file=sys.stderr)

    signal.signal(signal.SIGINT, _sigint)

    counts = {"completed": 0, "failed": 0, "skipped": 0}
    with manifest_path.open("a", encoding="utf-8") as mfh, errors_path.open("a", encoding="utf-8") as efh:
        for index, sample in enumerate(samples, 1):
            if interrupted["flag"]:
                break
            print(f"\n[{index}/{len(samples)}] {sample.relative_to(samples_dir)}")
            result = process_sample(
                root=root,
                sample=sample,
                task_profile=task_profile,
                profile_name=profile_name,
                results_root=results_root,
                manifest_fh=mfh,
                errors_fh=efh,
                timeout_seconds=args.timeout_seconds,
                wall_timeout_seconds=args.wall_timeout_seconds,
                vm_name=args.vm_name,
                force=args.force,
            )
            counts[result.status] += 1
            if result.status == "completed":
                print(f"  -> completed in {result.duration_seconds:.0f}s (attempts={result.attempts}) key={result.report_id}")
            elif result.status == "skipped":
                print(f"  -> skipped (prior result: {result.report_dir.name if result.report_dir else '?'})")
            else:
                print(f"  -> FAILED ({result.error})")

    print(f"\nbatch done: completed={counts['completed']} failed={counts['failed']} skipped={counts['skipped']}")
    print(f"manifest: {manifest_path}")
    print(f"errors:   {errors_path}")
    return 0 if counts["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
