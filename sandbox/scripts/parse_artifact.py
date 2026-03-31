#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import json
import shutil
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse a mounted artifact directory into a sample-centric offline sandbox report."
    )
    parser.add_argument(
        "artifact_dir",
        help="Path to the mounted artifact directory, relative to the project root unless absolute.",
    )
    parser.add_argument(
        "--report-id",
        default=None,
        help="Optional report id. Defaults to sample name plus current timestamp.",
    )
    return parser.parse_args()


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def resolve_path(root: Path, raw_path: str) -> Path:
    path = Path(raw_path)
    if path.is_absolute():
        return path
    return (root / path).resolve()


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def copy_raw_artifacts(src_dir: Path, dst_dir: Path) -> list[str]:
    dst_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for item in sorted(src_dir.iterdir()):
        if item.is_file():
            shutil.copy2(item, dst_dir / item.name)
            copied.append(item.name)
    return copied


def normalize_sample_name(task_summary: dict[str, Any] | None, sample_metadata: dict[str, Any] | None) -> str:
    for source in (sample_metadata, task_summary):
        if isinstance(source, dict) and source.get("sample_name"):
            return str(source["sample_name"])
    return "unknown_sample"


def safe_report_id(sample_name: str) -> str:
    stem = Path(sample_name).stem
    cleaned = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in stem).strip("_")
    if not cleaned:
        cleaned = "unknown_sample"
    return f"{cleaned}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"


def key_by(rows: list[dict[str, str]], keys: tuple[str, ...]) -> dict[tuple[str, ...], dict[str, str]]:
    result: dict[tuple[str, ...], dict[str, str]] = {}
    for row in rows:
        key = tuple((row.get(k, "") or "") for k in keys)
        result[key] = row
    return result


def diff_rows(
    pre_rows: list[dict[str, str]],
    post_rows: list[dict[str, str]],
    keys: tuple[str, ...],
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, Any]]]:
    pre_map = key_by(pre_rows, keys)
    post_map = key_by(post_rows, keys)

    new_items = [post_map[k] for k in sorted(post_map.keys()) if k not in pre_map]
    removed_items = [pre_map[k] for k in sorted(pre_map.keys()) if k not in post_map]

    changed_items = []
    for k in sorted(set(pre_map.keys()) & set(post_map.keys())):
        before = pre_map[k]
        after = post_map[k]
        diffs = {}
        for field in sorted(set(before.keys()) | set(after.keys())):
            if (before.get(field, "") or "") != (after.get(field, "") or ""):
                diffs[field] = {"before": before.get(field, ""), "after": after.get(field, "")}
        if diffs:
            changed_items.append({"key": k, "diff": diffs})

    return new_items, removed_items, changed_items


def load_runner_log(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8-sig", errors="replace")


def extract_runner_errors(runner_log: str) -> list[str]:
    lines = []
    for line in runner_log.splitlines():
        lower = line.lower()
        if "fatal error" in lower or "failed" in lower:
            lines.append(line)
    return lines


def to_int(value: Any) -> int | None:
    try:
        return int(str(value))
    except Exception:
        return None


def load_event_list(path: Path) -> list[dict[str, Any]]:
    data = load_json(path)
    if isinstance(data, list):
        return data
    return []


def derive_related_pids(sample_metadata: dict[str, Any] | None, process_events: list[dict[str, Any]]) -> set[int]:
    related: set[int] = set()
    launched_pid = to_int((sample_metadata or {}).get("launched_pid"))
    if launched_pid is not None:
        related.add(launched_pid)

    changed = True
    while changed:
        changed = False
        for ev in process_events:
            pid = to_int(ev.get("ProcessId"))
            ppid = to_int(ev.get("ParentProcessId"))
            if pid is None:
                continue
            if ppid in related and pid not in related:
                related.add(pid)
                changed = True
    return related


def filter_related_events(
    events: list[dict[str, Any]],
    related_pids: set[int],
    sample_name: str,
) -> list[dict[str, Any]]:
    sample_stem = Path(sample_name).stem.lower()
    filtered = []
    for ev in events:
        pid = to_int(ev.get("ProcessId"))
        image = str(ev.get("Image", "") or "").lower()
        parent_image = str(ev.get("ParentImage", "") or "").lower()
        if pid in related_pids or sample_stem in image or sample_stem in parent_image:
            filtered.append(ev)
    return filtered


def summarize_process_behavior(process_events: list[dict[str, Any]]) -> dict[str, Any]:
    created = []
    terminated = []
    for ev in process_events:
        row = {
            "ProcessId": ev.get("ProcessId"),
            "ParentProcessId": ev.get("ParentProcessId"),
            "Image": ev.get("Image"),
            "ParentImage": ev.get("ParentImage"),
            "CommandLine": ev.get("CommandLine"),
            "UtcTime": ev.get("UtcTime") or ev.get("TimeCreated"),
        }
        if int(ev.get("Id", 0)) == 1:
            created.append(row)
        elif int(ev.get("Id", 0)) == 5:
            terminated.append(row)
    return {
        "created_count": len(created),
        "terminated_count": len(terminated),
        "created": created[:50],
        "terminated": terminated[:50],
    }


def summarize_file_behavior(file_events: list[dict[str, Any]]) -> dict[str, Any]:
    touched = sorted({ev.get("TargetFilename") for ev in file_events if ev.get("TargetFilename")})
    by_event = Counter(str(ev.get("Id")) for ev in file_events)
    return {
        "count": len(file_events),
        "event_id_counts": dict(sorted(by_event.items())),
        "touched_paths": touched[:200],
    }


def summarize_registry_behavior(reg_events: list[dict[str, Any]]) -> dict[str, Any]:
    touched = sorted({ev.get("TargetObject") for ev in reg_events if ev.get("TargetObject")})
    by_event = Counter(str(ev.get("Id")) for ev in reg_events)
    return {
        "count": len(reg_events),
        "event_id_counts": dict(sorted(by_event.items())),
        "touched_keys": touched[:200],
    }


def summarize_network_behavior(network_events: list[dict[str, Any]]) -> dict[str, Any]:
    dns_queries = sorted({ev.get("QueryName") for ev in network_events if ev.get("QueryName")})
    connections = sorted(
        {
            "{host}:{port}".format(
                host=ev.get("DestinationHostname") or ev.get("DestinationIp") or "unknown",
                port=ev.get("DestinationPort") or "",
            )
            for ev in network_events
            if ev.get("DestinationHostname") or ev.get("DestinationIp")
        }
    )
    by_event = Counter(str(ev.get("Id")) for ev in network_events)
    return {
        "count": len(network_events),
        "event_id_counts": dict(sorted(by_event.items())),
        "dns_queries": dns_queries[:100],
        "connections": connections[:100],
    }


def summarize_injection_behavior(injection_events: list[dict[str, Any]]) -> dict[str, Any]:
    interesting = []
    for ev in injection_events:
        interesting.append(
            {
                "Id": ev.get("Id"),
                "SourceImage": ev.get("SourceImage") or ev.get("Image"),
                "TargetImage": ev.get("TargetImage"),
                "SourceProcessId": ev.get("SourceProcessId") or ev.get("ProcessId"),
                "TargetProcessId": ev.get("TargetProcessId"),
                "UtcTime": ev.get("UtcTime") or ev.get("TimeCreated"),
            }
        )
    return {"count": len(injection_events), "events": interesting[:50]}


def flatten_registry_values(entries: list[dict[str, Any]] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    if not isinstance(entries, list):
        return result
    for entry in entries:
        path = entry.get("Path", "")
        values = entry.get("Values", {}) or {}
        for key, value in values.items():
            result[f"{path}|{key}"] = str(value)
    return result


def diff_registry(pre: list[dict[str, Any]] | None, post: list[dict[str, Any]] | None) -> dict[str, Any]:
    pre_flat = flatten_registry_values(pre)
    post_flat = flatten_registry_values(post)
    created = {k: post_flat[k] for k in sorted(post_flat.keys() - pre_flat.keys())}
    removed = {k: pre_flat[k] for k in sorted(pre_flat.keys() - post_flat.keys())}
    changed = {
        k: {"before": pre_flat[k], "after": post_flat[k]}
        for k in sorted(pre_flat.keys() & post_flat.keys())
        if pre_flat[k] != post_flat[k]
    }
    return {"created": created, "removed": removed, "changed": changed}


def summarize_snapshot_diffs(artifact_dir: Path) -> dict[str, Any]:
    process_pre = load_csv(artifact_dir / "process_snapshot_pre.csv")
    process_post = load_csv(artifact_dir / "process_snapshot_post.csv")
    service_pre = load_csv(artifact_dir / "service_snapshot_pre.csv")
    service_post = load_csv(artifact_dir / "service_snapshot_post.csv")
    task_pre = load_csv(artifact_dir / "scheduled_task_snapshot_pre.csv")
    task_post = load_csv(artifact_dir / "scheduled_task_snapshot_post.csv")
    tcp_pre = load_csv(artifact_dir / "tcp_snapshot_pre.csv")
    tcp_post = load_csv(artifact_dir / "tcp_snapshot_post.csv")
    udp_pre = load_csv(artifact_dir / "udp_snapshot_pre.csv")
    udp_post = load_csv(artifact_dir / "udp_snapshot_post.csv")
    dns_pre = load_csv(artifact_dir / "dns_cache_pre.csv")
    dns_post = load_csv(artifact_dir / "dns_cache_post.csv")
    startup_pre = load_csv(artifact_dir / "startup_folders_pre.csv")
    startup_post = load_csv(artifact_dir / "startup_folders_post.csv")
    reg_pre = load_json(artifact_dir / "autorun_registry_pre.json")
    reg_post = load_json(artifact_dir / "autorun_registry_post.json")

    proc_new, proc_removed, _ = diff_rows(process_pre, process_post, ("ProcessId", "Name"))
    svc_new, svc_removed, svc_changed = diff_rows(service_pre, service_post, ("Name",))
    task_new, task_removed, task_changed = diff_rows(task_pre, task_post, ("TaskPath", "TaskName"))
    tcp_new, _, _ = diff_rows(tcp_pre, tcp_post, ("LocalAddress", "LocalPort", "RemoteAddress", "RemotePort", "State", "OwningProcess"))
    udp_new, _, _ = diff_rows(udp_pre, udp_post, ("LocalAddress", "LocalPort", "OwningProcess"))
    dns_new, _, _ = diff_rows(dns_pre, dns_post, ("Entry", "RecordType", "Data"))
    startup_new, startup_removed, _ = diff_rows(startup_pre, startup_post, ("FullName",))
    reg_diff = diff_registry(reg_pre, reg_post)

    return {
        "new_processes": proc_new[:100],
        "terminated_or_missing_processes": proc_removed[:100],
        "new_services": svc_new[:100],
        "removed_services": svc_removed[:100],
        "changed_services": svc_changed[:100],
        "new_scheduled_tasks": task_new[:100],
        "removed_scheduled_tasks": task_removed[:100],
        "changed_scheduled_tasks": task_changed[:100],
        "new_tcp_connections": tcp_new[:100],
        "new_udp_endpoints": udp_new[:100],
        "new_dns_cache_entries": dns_new[:100],
        "new_startup_entries": startup_new[:100],
        "removed_startup_entries": startup_removed[:100],
        "autorun_registry_diff": reg_diff,
    }


def build_summary(artifact_dir: Path, copied_files: list[str]) -> dict[str, Any]:
    task_summary = load_json(artifact_dir / "task_summary.json") or {}
    sample_metadata = load_json(artifact_dir / "sample_metadata.json") or {}
    runner_log = load_runner_log(artifact_dir / "runner.log")
    sysmon_summary = load_json(artifact_dir / "sysmon_summary.json") or []

    process_events = load_event_list(artifact_dir / "sysmon_process_events.json")
    file_events = load_event_list(artifact_dir / "sysmon_file_events.json")
    registry_events = load_event_list(artifact_dir / "sysmon_registry_events.json")
    network_events = load_event_list(artifact_dir / "sysmon_network_dns_events.json")
    injection_events = load_event_list(artifact_dir / "sysmon_injection_events.json")
    ipc_wmi_events = load_event_list(artifact_dir / "sysmon_ipc_wmi_events.json")

    related_pids = derive_related_pids(sample_metadata, process_events)
    sample_name = normalize_sample_name(task_summary, sample_metadata)

    related_process_events = filter_related_events(process_events, related_pids, sample_name)
    related_file_events = filter_related_events(file_events, related_pids, sample_name)
    related_registry_events = filter_related_events(registry_events, related_pids, sample_name)
    related_network_events = filter_related_events(network_events, related_pids, sample_name)
    related_injection_events = filter_related_events(injection_events, related_pids, sample_name)
    related_ipc_wmi_events = filter_related_events(ipc_wmi_events, related_pids, sample_name)

    return {
        "task_summary": task_summary,
        "sample_metadata": sample_metadata,
        "runner_log_errors": extract_runner_errors(runner_log),
        "runner_log_tail": runner_log.splitlines()[-50:],
        "sysmon_summary": sysmon_summary,
        "related_pids": sorted(related_pids),
        "behavior": {
            "process": summarize_process_behavior(related_process_events),
            "file": summarize_file_behavior(related_file_events),
            "registry": summarize_registry_behavior(related_registry_events),
            "network": summarize_network_behavior(related_network_events),
            "injection": summarize_injection_behavior(related_injection_events),
            "ipc_wmi_event_count": len(related_ipc_wmi_events),
        },
        "pre_post_diff": summarize_snapshot_diffs(artifact_dir),
        "raw_files": copied_files,
    }


def build_markdown_report(summary: dict[str, Any]) -> str:
    task = summary.get("task_summary", {})
    sample = summary.get("sample_metadata", {})
    behavior = summary.get("behavior", {})
    diffs = summary.get("pre_post_diff", {})

    lines = []
    lines.append("# Offline Sandbox Report")
    lines.append("")
    lines.append("## Sample")
    lines.append("")
    lines.append(f"- Name: `{sample.get('sample_name') or task.get('sample_name') or 'unknown'}`")
    lines.append(f"- SHA256: `{sample.get('sample_sha256', task.get('sample_sha256', 'unknown'))}`")
    lines.append(f"- Size: `{sample.get('sample_size', task.get('sample_size', 'unknown'))}`")
    lines.append(f"- Started: `{task.get('started_at', 'unknown')}`")
    lines.append(f"- Ended: `{task.get('ended_at', 'unknown')}`")
    lines.append(f"- Launched PID: `{sample.get('launched_pid', task.get('launched_pid', 'unknown'))}`")
    lines.append(f"- Related PIDs: `{summary.get('related_pids', [])}`")
    lines.append("")
    lines.append("## Behavior Summary")
    lines.append("")
    proc = behavior.get("process", {})
    file_behavior = behavior.get("file", {})
    reg_behavior = behavior.get("registry", {})
    net_behavior = behavior.get("network", {})
    inj_behavior = behavior.get("injection", {})
    lines.append(f"- Process creates: `{proc.get('created_count', 0)}`")
    lines.append(f"- Process terminates: `{proc.get('terminated_count', 0)}`")
    lines.append(f"- File-touch events: `{file_behavior.get('count', 0)}`")
    lines.append(f"- Registry events: `{reg_behavior.get('count', 0)}`")
    lines.append(f"- Network/DNS events: `{net_behavior.get('count', 0)}`")
    lines.append(f"- Injection/tampering events: `{inj_behavior.get('count', 0)}`")
    lines.append(f"- IPC/WMI events: `{behavior.get('ipc_wmi_event_count', 0)}`")
    lines.append("")
    lines.append("## Process Tree Candidates")
    lines.append("")
    created = proc.get("created", [])
    if created:
        for row in created[:20]:
            lines.append(
                f"- pid=`{row.get('ProcessId')}` ppid=`{row.get('ParentProcessId')}` image=`{row.get('Image')}`"
            )
            if row.get("CommandLine"):
                lines.append(f"  cmd=`{row.get('CommandLine')}`")
    else:
        lines.append("- No related process creation events found.")
    lines.append("")
    lines.append("## Files Touched")
    lines.append("")
    for path in file_behavior.get("touched_paths", [])[:50]:
        lines.append(f"- `{path}`")
    if not file_behavior.get("touched_paths"):
        lines.append("- No related file paths found.")
    lines.append("")
    lines.append("## Registry Keys Touched")
    lines.append("")
    for path in reg_behavior.get("touched_keys", [])[:50]:
        lines.append(f"- `{path}`")
    if not reg_behavior.get("touched_keys"):
        lines.append("- No related registry keys found.")
    lines.append("")
    lines.append("## DNS And Network")
    lines.append("")
    for value in net_behavior.get("dns_queries", [])[:20]:
        lines.append(f"- DNS `{value}`")
    for value in net_behavior.get("connections", [])[:20]:
        lines.append(f"- NET `{value}`")
    if not net_behavior.get("dns_queries") and not net_behavior.get("connections"):
        lines.append("- No related DNS or network endpoints found.")
    lines.append("")
    lines.append("## Pre/Post Diffs")
    lines.append("")
    lines.append(f"- New processes: `{len(diffs.get('new_processes', []))}`")
    lines.append(f"- New services: `{len(diffs.get('new_services', []))}`")
    lines.append(f"- New scheduled tasks: `{len(diffs.get('new_scheduled_tasks', []))}`")
    lines.append(f"- New TCP connections: `{len(diffs.get('new_tcp_connections', []))}`")
    lines.append(f"- New startup entries: `{len(diffs.get('new_startup_entries', []))}`")
    autorun_diff = diffs.get("autorun_registry_diff", {})
    lines.append(
        f"- Autorun registry changes: created=`{len(autorun_diff.get('created', {}))}` changed=`{len(autorun_diff.get('changed', {}))}` removed=`{len(autorun_diff.get('removed', {}))}`"
    )
    lines.append("")
    lines.append("## Raw Files")
    lines.append("")
    for name in summary.get("raw_files", []):
        lines.append(f"- `{name}`")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    root = project_root()
    artifact_dir = resolve_path(root, args.artifact_dir)

    if not artifact_dir.exists():
        raise SystemExit(f"artifact directory not found: {artifact_dir}")
    if not artifact_dir.is_dir():
        raise SystemExit(f"artifact path is not a directory: {artifact_dir}")

    sample_name = normalize_sample_name(
        load_json(artifact_dir / "task_summary.json"),
        load_json(artifact_dir / "sample_metadata.json"),
    )
    report_id = args.report_id or safe_report_id(sample_name)
    report_dir = root / "reports" / report_id
    raw_dir = report_dir / "raw"

    copied_files = copy_raw_artifacts(artifact_dir, raw_dir)
    summary = build_summary(artifact_dir, copied_files)

    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    (report_dir / "report.md").write_text(build_markdown_report(summary), encoding="utf-8")

    print(f"artifact_dir: {artifact_dir}")
    print(f"report_dir: {report_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
