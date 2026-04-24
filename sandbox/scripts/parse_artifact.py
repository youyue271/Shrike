#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import shutil
from collections import Counter
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Any

from task_profile import expected_trace_artifacts

SYSMON_CATEGORY_IDS: dict[str, tuple[int, ...]] = {
    "sysmon_process_events": (1, 5),
    "sysmon_network_dns_events": (3, 22),
    "sysmon_file_events": (2, 11, 15, 23, 26, 29),
    "sysmon_registry_events": (12, 13, 14),
    "sysmon_injection_events": (8, 10, 25),
    "sysmon_ipc_wmi_events": (17, 18, 19, 20, 21),
}
SYSMON_NON_BEHAVIOR_EVENT_IDS = {4, 16}


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


def wsl_to_windows(path: Path) -> str:
    result = subprocess.run(
        ["wslpath", "-w", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8-sig", errors="replace").replace("\x00", "").strip()
    if not text:
        return None
    return json.loads(text)


def load_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        return []

    if text.startswith("["):
        data = json.loads(text)
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        if isinstance(row, dict):
            rows.append(row)
    return rows


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def copy_raw_artifacts(src_dir: Path, dst_dir: Path) -> list[str]:
    dst_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for item in sorted(src_dir.rglob("*")):
        if item.is_file():
            relative_path = item.relative_to(src_dir)
            destination = dst_dir / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, destination)
            copied.append(relative_path.as_posix())
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


def parse_number_string(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text[2:], 16)
        return int(text, 10)
    except Exception:
        return None


def load_event_list(path: Path) -> list[dict[str, Any]]:
    data = load_json(path)
    if isinstance(data, list):
        return data
    return []


def parse_drcov_log_process_id(path: Path) -> int | None:
    match = re.search(r"\.(\d+)\.\d+\.proc\.log$", path.name)
    if not match:
        return None
    return to_int(match.group(1))


def parse_drcov_text_log(path: Path) -> dict[str, Any]:
    modules: dict[int, dict[str, Any]] = {}
    basic_blocks: list[dict[str, Any]] = []
    in_module_table = False
    in_basic_block_table = False

    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw_line.startswith("Module Table:"):
            in_module_table = True
            in_basic_block_table = False
            continue
        if raw_line.startswith("BB Table:"):
            in_module_table = False
            in_basic_block_table = True
            continue

        line = raw_line.strip()
        if not line:
            continue

        if in_module_table:
            if line.startswith("Columns:"):
                continue
            parts = re.split(r",\s*", line, maxsplit=9)
            if len(parts) < 3:
                continue
            module_id = parse_number_string(parts[0])
            if module_id is None:
                continue
            if len(parts) >= 10:
                base_value = parse_number_string(parts[2])
                end_value = parse_number_string(parts[3])
                path_value = parts[9].strip()
            else:
                base_value = parse_number_string(parts[1])
                end_value = parse_number_string(parts[2]) if len(parts) >= 3 else None
                path_value = parts[-1].strip()
            size_value = 0
            if base_value is not None and end_value is not None and end_value >= base_value:
                size_value = end_value - base_value
            module_name = PureWindowsPath(path_value).stem if path_value else f"module_{module_id}"
            modules[int(module_id)] = {
                "module_id": int(module_id),
                "path": path_value,
                "module": module_name,
                "base_value": int(base_value or 0),
                "base": f"0x{base_value:X}" if base_value is not None else None,
                "size": int(size_value),
            }
            continue

        if in_basic_block_table:
            if re.match(r"^module id,\s*start,\s*size", line, flags=re.IGNORECASE):
                continue
            match = re.match(
                r"^module\[\s*(\d+)\]\s*:\s*(0x[0-9A-Fa-f]+|\d+)\s*,\s*(0x[0-9A-Fa-f]+|\d+)",
                line,
            )
            if not match:
                continue
            module_id = parse_number_string(match.group(1))
            start_offset = parse_number_string(match.group(2))
            block_size = parse_number_string(match.group(3))
            if module_id is None or start_offset is None or block_size is None:
                continue
            basic_blocks.append(
                {
                    "module_id": int(module_id),
                    "start_offset": int(start_offset),
                    "size": int(block_size),
                    "sequence": len(basic_blocks),
                }
            )

    return {
        "process_id": parse_drcov_log_process_id(path),
        "log_path": str(path),
        "modules": [modules[module_id] for module_id in sorted(modules)],
        "basic_blocks": basic_blocks,
    }


def recover_drio_dynamic_cfg(
    artifact_dir: Path,
    trace_request: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], str] | None:
    drio_dir = artifact_dir / "drio"
    if not drio_dir.is_dir():
        return None

    log_paths = sorted(drio_dir.glob("*.log"))
    if not log_paths:
        return None

    parsed_logs = [parse_drcov_text_log(path) for path in log_paths]
    events: list[dict[str, Any]] = [
        {
            "event": "trace_status",
            "trace_mode": trace_request.get("trace_mode", "dynamic_cfg"),
            "trace_backend": "drio",
            "status": "drcov_basic_blocks",
            "message": "Recovered dynamic CFG from raw DynamoRIO drcov logs.",
            "sample_name": trace_request.get("sample_name"),
            "launched_pid": trace_request.get("launched_pid"),
            "started_at": trace_request.get("started_at"),
            "ended_at": trace_request.get("ended_at"),
        },
        {
            "event": "trace_window",
            "sample_name": trace_request.get("sample_name"),
            "launched_pid": trace_request.get("launched_pid"),
            "started_at": trace_request.get("started_at"),
            "ended_at": trace_request.get("ended_at"),
        },
    ]
    process_ids: list[int] = []

    for log in parsed_logs:
        module_map = {int(module["module_id"]): module for module in log.get("modules", [])}
        log_process_id = to_int(log.get("process_id")) or to_int(trace_request.get("launched_pid"))
        if log_process_id is not None and log_process_id not in process_ids:
            process_ids.append(log_process_id)
        previous_ordered_block: dict[str, str] | None = None

        for module in module_map.values():
            events.append(
                {
                    "event": "module_load",
                    "module": module.get("module"),
                    "path": module.get("path"),
                    "base": module.get("base"),
                    "size": module.get("size"),
                    "kind": "drcov_text",
                    "pid": log_process_id,
                }
            )

        for block in log.get("basic_blocks", []):
            module = module_map.get(int(block["module_id"]))
            if not module:
                continue
            start_value = int(module["base_value"]) + int(block["start_offset"])
            end_value = start_value + int(block["size"])
            start_text = f"0x{start_value:X}"
            end_text = f"0x{end_value:X}"

            events.append(
                {
                    "event": "basic_block",
                    "module": module.get("module"),
                    "path": module.get("path"),
                    "start": start_text,
                    "end": end_text,
                    "size": block.get("size"),
                    "kind": "drcov_text",
                    "pid": log_process_id,
                }
            )
            events.append(
                {
                    "event": "sampled_block_execution",
                    "module": module.get("module"),
                    "path": module.get("path"),
                    "thread_id": log_process_id,
                    "round": 0,
                    "sequence": block.get("sequence"),
                    "block_start": start_text,
                    "block_end": end_text,
                    "instruction_pointer": start_text,
                    "pid": log_process_id,
                    "kind": "drcov_first_seen_order",
                }
            )
            if previous_ordered_block and previous_ordered_block.get("module") == module.get("module"):
                events.append(
                    {
                        "event": "edge",
                        "module": module.get("module"),
                        "path": module.get("path"),
                        "source": previous_ordered_block.get("start"),
                        "target": start_text,
                        "pid": log_process_id,
                        "count": 1,
                        "kind": "drcov_first_seen_order",
                    }
                )
            previous_ordered_block = {"module": str(module.get("module", "")), "start": start_text}

    basic_block_events = [event for event in events if event.get("event") == "basic_block"]
    if not basic_block_events:
        return None

    return (
        {
            "status": "drcov_basic_blocks",
            "drio_mode": "drcov_text_first_seen_order",
            "process_ids": sorted(process_ids),
            "notes": [
                "Recovered dynamic CFG directly from raw drcov logs because trace export files were missing."
            ],
        },
        events,
        "Recovered dynamic CFG directly from raw drcov logs because the guest did not export trace summary files.",
    )


def count_meaningful_sysmon_events(sysmon_summary: list[dict[str, Any]]) -> int:
    total = 0
    for row in sysmon_summary:
        event_id = to_int(row.get("EventId"))
        count = to_int(row.get("Count")) or 0
        if event_id is None or event_id in SYSMON_NON_BEHAVIOR_EVENT_IDS:
            continue
        total += count
    return total


def category_event_count(artifact_dir: Path) -> int:
    total = 0
    for name in SYSMON_CATEGORY_IDS:
        events = load_event_list(artifact_dir / f"{name}.json")
        total += len(events)
    return total


def should_rebuild_sysmon_categories(
    artifact_dir: Path,
    sysmon_summary: list[dict[str, Any]],
) -> bool:
    counts_by_event_id: dict[int, int] = {}
    for row in sysmon_summary:
        event_id = to_int(row.get("EventId"))
        count = to_int(row.get("Count")) or 0
        if event_id is None:
            continue
        counts_by_event_id[event_id] = counts_by_event_id.get(event_id, 0) + count

    for name, ids in SYSMON_CATEGORY_IDS.items():
        expected_count = sum(counts_by_event_id.get(event_id, 0) for event_id in ids)
        if expected_count <= 0:
            continue
        events = load_event_list(artifact_dir / f"{name}.json")
        if len(events) == 0:
            return True

    return False


def should_materialize_sysmon_from_evtx(artifact_dir: Path) -> bool:
    sysmon_evtx = artifact_dir / "sysmon.evtx"
    if not sysmon_evtx.exists():
        return False

    sysmon_summary = load_json(artifact_dir / "sysmon_summary.json")
    if not isinstance(sysmon_summary, list):
        return True

    if should_rebuild_sysmon_categories(artifact_dir, sysmon_summary):
        return True

    if count_meaningful_sysmon_events(sysmon_summary) > 0:
        return False

    return category_event_count(artifact_dir) == 0


def materialize_sysmon_from_evtx(artifact_dir: Path) -> None:
    if not should_materialize_sysmon_from_evtx(artifact_dir):
        return

    artifact_dir_win = wsl_to_windows(artifact_dir)
    category_entries = "; ".join(
        f"[PSCustomObject]@{{ Name = '{name}'; Ids = @({','.join(str(v) for v in ids)}) }}"
        for name, ids in SYSMON_CATEGORY_IDS.items()
    )
    command = f"""
$artifactDir = '{artifact_dir_win}'
$evtxPath = Join-Path $artifactDir 'sysmon.evtx'
if (-not (Test-Path $evtxPath)) {{
    exit 0
}}

function Export-JsonFile {{
    param(
        [Parameter(Mandatory = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string]) -and @($InputObject).Count -eq 0) {{
        Set-Content -Path $Path -Value '[]' -Encoding UTF8
        return
    }}

    $InputObject | ConvertTo-Json -Depth 8 | Set-Content -Path $Path -Encoding UTF8
}}

function Get-SysmonEventObject {{
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

    $xml = [xml]$Event.ToXml()
    $data = [ordered]@{{
        RecordId = $Event.RecordId
        TimeCreated = if ($Event.TimeCreated) {{ $Event.TimeCreated.ToString('o') }} else {{ $null }}
        Id = $Event.Id
        LevelDisplayName = $Event.LevelDisplayName
        ProviderName = $Event.ProviderName
        MachineName = $Event.MachineName
    }}

    foreach ($node in $xml.Event.EventData.Data) {{
        $name = $node.Name
        if (-not $name) {{ continue }}
        $value = $node.'#text'
        if ($data.Contains($name)) {{
            $name = 'EventData_' + $name
        }}
        $data[$name] = $value
    }}

    [PSCustomObject]$data
}}

$maxEvents = 50000
$events = @(Get-WinEvent -Path $evtxPath -Oldest -MaxEvents $maxEvents -ErrorAction Stop)

$summary = @{{}}
$categoryData = @{{}}
$categories = @({category_entries})
foreach ($category in $categories) {{
    $categoryData[$category.Name] = @()
}}

foreach ($event in $events) {{
    $eventId = $event.Id
    if (-not $summary.ContainsKey($eventId)) {{
        $summary[$eventId] = 0
    }}
    $summary[$eventId]++

    $obj = Get-SysmonEventObject -Event $event
    foreach ($category in $categories) {{
        if ($eventId -in $category.Ids) {{
            $categoryData[$category.Name] += $obj
        }}
    }}
}}

$summaryArray = @(
    $summary.GetEnumerator() |
        Sort-Object Name |
        ForEach-Object {{
            [PSCustomObject]@{{
                EventId = [int]$_.Name
                Count = $_.Value
            }}
        }}
)
Export-JsonFile -InputObject $summaryArray -Path (Join-Path $artifactDir 'sysmon_summary.json')

foreach ($category in $categories) {{
    Export-JsonFile -InputObject $categoryData[$category.Name] -Path (Join-Path $artifactDir ($category.Name + '.json'))
}}
"""
    subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=True,
    )


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


def build_sample_indicators(sample_metadata: dict[str, Any] | None, sample_name: str) -> set[str]:
    indicators = set()
    sample_name = (sample_name or "").strip().lower()
    if sample_name:
        indicators.add(sample_name)

    sample_stem = Path(sample_name).stem.strip().lower()
    if sample_stem:
        indicators.add(sample_stem)

    sample_path = str((sample_metadata or {}).get("sample_path", "") or "").strip().lower()
    if sample_path:
        indicators.add(sample_path)

    return {value for value in indicators if value}


def event_matches_related_context(
    event: dict[str, Any],
    related_pids: set[int],
    sample_indicators: set[str],
) -> bool:
    pid_keys = (
        "ProcessId",
        "ParentProcessId",
        "SourceProcessId",
        "TargetProcessId",
        "OwningProcess",
    )
    for key in pid_keys:
        if to_int(event.get(key)) in related_pids:
            return True

    text_keys = (
        "Image",
        "ParentImage",
        "CommandLine",
        "TargetFilename",
        "TargetObject",
        "QueryName",
        "SourceImage",
        "TargetImage",
        "DestinationHostname",
        "DestinationIp",
        "Details",
    )
    text_values = [str(event.get(key, "") or "").lower() for key in text_keys]
    for indicator in sample_indicators:
        if any(indicator in value for value in text_values):
            return True

    return False


def filter_related_events(
    events: list[dict[str, Any]],
    related_pids: set[int],
    sample_metadata: dict[str, Any] | None,
    sample_name: str,
) -> list[dict[str, Any]]:
    sample_indicators = build_sample_indicators(sample_metadata, sample_name)
    filtered = []
    for ev in events:
        if event_matches_related_context(ev, related_pids, sample_indicators):
            filtered.append(ev)
    return filtered


def derive_related_pids_from_snapshot_rows(
    sample_metadata: dict[str, Any] | None,
    snapshot_rows: list[dict[str, str]],
    sample_name: str,
    seed_pids: set[int] | None = None,
) -> set[int]:
    related = set(seed_pids or set())
    launched_pid = to_int((sample_metadata or {}).get("launched_pid"))
    if launched_pid is not None:
        related.add(launched_pid)

    sample_stem = Path(sample_name).stem.lower()
    for row in snapshot_rows:
        pid = to_int(row.get("ProcessId"))
        if pid is None:
            continue
        text = " ".join(
            [
                str(row.get("Name", "") or ""),
                str(row.get("ExecutablePath", "") or ""),
                str(row.get("CommandLine", "") or ""),
            ]
        ).lower()
        if sample_stem and sample_stem in text:
            related.add(pid)

    changed = True
    while changed:
        changed = False
        for row in snapshot_rows:
            pid = to_int(row.get("ProcessId"))
            ppid = to_int(row.get("ParentProcessId"))
            if pid is None:
                continue
            if ppid in related and pid not in related:
                related.add(pid)
                changed = True
    return related


def derive_related_pids_from_trace(
    trace_summary: dict[str, Any] | None,
    seed_pids: set[int] | None = None,
) -> set[int]:
    related = set(seed_pids or set())
    dynamic_cfg = ((trace_summary or {}).get("dynamic_cfg", {}) or {})

    for pid in dynamic_cfg.get("process_ids", []) or []:
        parsed = to_int(pid)
        if parsed is not None:
            related.add(parsed)

    for thread_entry in dynamic_cfg.get("ordered_threads", []) or []:
        parsed = to_int(thread_entry.get("thread_id"))
        if parsed is not None:
            related.add(parsed)

    return related


def filter_related_snapshot_process_rows(
    rows: list[dict[str, str]],
    related_pids: set[int],
    sample_name: str,
) -> list[dict[str, str]]:
    sample_stem = Path(sample_name).stem.lower()
    filtered = []
    for row in rows:
        pid = to_int(row.get("ProcessId"))
        ppid = to_int(row.get("ParentProcessId"))
        text = " ".join(
            [
                str(row.get("Name", "") or ""),
                str(row.get("ExecutablePath", "") or ""),
                str(row.get("CommandLine", "") or ""),
            ]
        ).lower()
        if pid in related_pids or ppid in related_pids or (sample_stem and sample_stem in text):
            filtered.append(row)
    return filtered


def filter_related_snapshot_network_rows(
    rows: list[dict[str, str]],
    related_pids: set[int],
) -> list[dict[str, str]]:
    filtered = []
    for row in rows:
        owning_pid = to_int(row.get("OwningProcess"))
        if owning_pid in related_pids:
            filtered.append(row)
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


def summarize_snapshot_process_behavior(rows: list[dict[str, str]]) -> dict[str, Any]:
    created = []
    for row in rows:
        created.append(
            {
                "ProcessId": row.get("ProcessId"),
                "ParentProcessId": row.get("ParentProcessId"),
                "Image": row.get("ExecutablePath") or row.get("Name"),
                "ParentImage": None,
                "CommandLine": row.get("CommandLine"),
                "UtcTime": row.get("CreationDate"),
            }
        )
    return {
        "created_count": len(created),
        "terminated_count": 0,
        "created": created[:50],
        "terminated": [],
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


def summarize_snapshot_network_behavior(
    tcp_rows: list[dict[str, str]],
    udp_rows: list[dict[str, str]],
    dns_rows: list[dict[str, str]],
) -> dict[str, Any]:
    connections = sorted(
        {
            "{host}:{port}".format(
                host=row.get("RemoteAddress") or row.get("LocalAddress") or "unknown",
                port=row.get("RemotePort") or row.get("LocalPort") or "",
            )
            for row in tcp_rows
        }
    )
    udp_endpoints = sorted(
        {
            "{host}:{port}/udp".format(
                host=row.get("LocalAddress") or "unknown",
                port=row.get("LocalPort") or "",
            )
            for row in udp_rows
        }
    )
    dns_queries = sorted({row.get("Entry") for row in dns_rows if row.get("Entry")})
    return {
        "count": len(tcp_rows) + len(udp_rows) + len(dns_rows),
        "event_id_counts": {},
        "dns_queries": dns_queries[:100],
        "connections": (connections + udp_endpoints)[:100],
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


def summarize_persistence(pre_post_diff: dict[str, Any]) -> dict[str, Any]:
    autorun = pre_post_diff.get("autorun_registry_diff", {}) or {}
    startup_entries = pre_post_diff.get("new_startup_entries", []) or []
    scheduled_tasks = pre_post_diff.get("new_scheduled_tasks", []) or []
    services = pre_post_diff.get("new_services", []) or []

    return {
        "autorun_registry_created": autorun.get("created", {}),
        "autorun_registry_changed": autorun.get("changed", {}),
        "startup_entries": startup_entries[:50],
        "scheduled_tasks": scheduled_tasks[:50],
        "services": services[:50],
    }


def summarize_analysis_quality(
    sysmon_summary: list[dict[str, Any]],
    runner_errors: list[str],
    raw_files: list[str],
    runner_log: str,
) -> dict[str, Any]:
    sysmon_json_present = any(name.startswith("sysmon_") and name.endswith(".json") for name in raw_files)
    meaningful_sysmon_events = count_meaningful_sysmon_events(sysmon_summary)
    sysmon_available = meaningful_sysmon_events > 0 and sysmon_json_present

    mode = "sysmon" if sysmon_available else "snapshot_fallback"
    warnings = list(runner_errors)
    if "collected 16384 recent sysmon events" in runner_log or "collected 4096 recent sysmon events" in runner_log:
        warnings.append("The Sysmon live-log query hit its MaxEvents cap; early events may have been truncated.")
    if not sysmon_available:
        if sysmon_summary and meaningful_sysmon_events == 0 and "sysmon.evtx" in raw_files:
            warnings.append("Sysmon is installed, but the exported log contains only non-behavioral events.")
        warnings.append("Sysmon telemetry is unavailable; sample behavior falls back to weaker pre/post snapshots.")

    return {
        "mode": mode,
        "sysmon_available": sysmon_available,
        "warnings": warnings,
    }


def summarize_trace_artifacts(
    task_profile: dict[str, Any],
    task_runtime_context: dict[str, Any],
    artifact_dir: Path,
) -> dict[str, Any]:
    trace_manifest = load_json(artifact_dir / "trace_manifest.json") or {}
    dynamic_cfg_summary = load_json(artifact_dir / "dynamic_cfg_trace_summary.json") or {}
    trace_request = load_json(artifact_dir / "trace_request.json") or {}

    trace_mode = (
        trace_manifest.get("trace_mode")
        or trace_request.get("trace_mode")
        or task_runtime_context.get("trace_mode")
        or task_profile.get("trace_mode")
        or "none"
    )
    trace_backend = (
        trace_manifest.get("trace_backend")
        or trace_request.get("trace_backend")
        or task_runtime_context.get("trace_backend")
        or task_profile.get("trace_backend")
        or "none"
    )
    expected_artifacts = []
    for artifact_name in trace_manifest.get("expected_artifacts", []):
        if isinstance(artifact_name, str) and artifact_name not in expected_artifacts:
            expected_artifacts.append(artifact_name)
    for artifact_name in expected_trace_artifacts(trace_mode):
        if artifact_name not in expected_artifacts:
            expected_artifacts.append(artifact_name)

    collected_artifacts = []
    candidate_artifacts = list(expected_artifacts)
    for artifact_name in trace_manifest.get("collected_artifacts", []):
        if isinstance(artifact_name, str) and artifact_name not in candidate_artifacts:
            candidate_artifacts.append(artifact_name)

    for artifact_name in candidate_artifacts:
        if isinstance(artifact_name, str) and (artifact_dir / artifact_name).exists() and artifact_name not in collected_artifacts:
            collected_artifacts.append(artifact_name)

    recovered_reason = None
    if trace_mode == "dynamic_cfg":
        dynamic_cfg_events = load_ndjson(artifact_dir / "dynamic_cfg_trace.ndjson")
        if dynamic_cfg_events:
            dynamic_cfg_summary = summarize_dynamic_cfg_trace(dynamic_cfg_summary, dynamic_cfg_events)
        elif trace_backend == "drio":
            recovered = recover_drio_dynamic_cfg(artifact_dir, trace_request)
            if recovered is not None:
                recovered_summary, recovered_events, recovered_reason = recovered
                dynamic_cfg_summary = summarize_dynamic_cfg_trace(recovered_summary, recovered_events)

    return {
        "mode": trace_mode,
        "backend": trace_backend,
        "status": trace_manifest.get("status")
        or dynamic_cfg_summary.get("status")
        or ("disabled" if trace_mode == "none" else "unknown"),
        "reason": trace_manifest.get("reason") or recovered_reason,
        "expected_artifacts": expected_artifacts,
        "collected_artifacts": collected_artifacts,
        "dynamic_cfg": dynamic_cfg_summary,
    }


def summarize_dynamic_cfg_trace(
    summary: dict[str, Any],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    if not summary and not events:
        return {}

    merged = dict(summary)
    if not events:
        return merged

    modules_by_name: dict[str, dict[str, Any]] = {}
    basic_blocks: set[tuple[str, str, str]] = set()
    edges: set[tuple[str, str, str]] = set()
    ordered_threads: dict[int, list[dict[str, Any]]] = {}
    notes: list[str] = []
    call_count = 0
    ret_count = 0
    branch_count = 0
    indirect_call_count = 0
    indirect_jump_count = 0

    def ensure_module_entry(module_name: str, path: Any = None) -> dict[str, Any]:
        entry = modules_by_name.setdefault(
            module_name or "unknown",
            {
                "module": module_name or "unknown",
                "path": path,
                "base": None,
                "size": None,
                "_basic_blocks": set(),
                "_edges": set(),
            },
        )
        if not entry.get("path") and path:
            entry["path"] = path
        return entry

    for event in events:
        event_type = str(event.get("event", "") or "")
        module_name = str(event.get("module", "") or "")

        if event_type == "module_load" and module_name:
            module_entry = ensure_module_entry(module_name, event.get("path"))
            if not module_entry.get("path") and event.get("path"):
                module_entry["path"] = event.get("path")
            if not module_entry.get("base") and event.get("base"):
                module_entry["base"] = event.get("base")
            if not module_entry.get("size") and event.get("size") is not None:
                module_entry["size"] = event.get("size")
        elif event_type == "basic_block":
            start = str(event.get("start", "") or "")
            end = str(event.get("end", "") or "")
            if start and end:
                block_key = (module_name, start, end)
                basic_blocks.add(block_key)
                module_entry = ensure_module_entry(module_name, event.get("path"))
                module_entry["_basic_blocks"].add(block_key)
        elif event_type == "edge":
            source = str(event.get("source", "") or "")
            target = str(event.get("target", "") or "")
            if source and target:
                edge_key = (module_name, source, target)
                edges.add(edge_key)
                module_entry = ensure_module_entry(module_name, event.get("path"))
                module_entry["_edges"].add(edge_key)
        elif event_type == "sampled_block_execution":
            start = str(event.get("block_start", "") or "")
            end = str(event.get("block_end", "") or "")
            if start and end:
                block_key = (module_name, start, end)
                basic_blocks.add(block_key)
                module_entry = ensure_module_entry(module_name, event.get("path"))
                module_entry["_basic_blocks"].add(block_key)

            thread_id = to_int(event.get("thread_id"))
            if thread_id is not None:
                ordered_threads.setdefault(thread_id, []).append(
                    {
                        "thread_id": thread_id,
                        "sequence": to_int(event.get("sequence")),
                        "round": to_int(event.get("round")),
                        "module": module_name or "unknown",
                        "path": event.get("path"),
                        "block_start": start,
                        "block_end": end,
                        "instruction_pointer": event.get("instruction_pointer"),
                        "architecture": event.get("architecture"),
                    }
                )
        elif event_type == "call":
            source = str(event.get("source", "") or "")
            target = str(event.get("target", "") or "")
            if source and target:
                call_count += 1
                edge_key = (module_name, source, target)
                edges.add(edge_key)
                module_entry = ensure_module_entry(module_name, event.get("path"))
                module_entry["_edges"].add(edge_key)
        elif event_type == "ret":
            source = str(event.get("source", "") or "")
            target = str(event.get("target", "") or "")
            if source and target:
                ret_count += 1
                edge_key = (module_name, source, target)
                edges.add(edge_key)
                module_entry = ensure_module_entry(module_name, event.get("path"))
                module_entry["_edges"].add(edge_key)
        elif event_type == "branch":
            source = str(event.get("source", "") or "")
            target = str(event.get("target", "") or "")
            if source and target:
                branch_count += 1
                edge_key = (module_name, source, target)
                edges.add(edge_key)
                module_entry = ensure_module_entry(module_name, event.get("path"))
                module_entry["_edges"].add(edge_key)
        elif event_type == "indirect_call":
            source = str(event.get("source", "") or "")
            target = str(event.get("target", "") or "")
            if source and target:
                indirect_call_count += 1
                edge_key = (module_name, source, target)
                edges.add(edge_key)
                module_entry = ensure_module_entry(module_name, event.get("path"))
                module_entry["_edges"].add(edge_key)
        elif event_type == "indirect_jump":
            source = str(event.get("source", "") or "")
            target = str(event.get("target", "") or "")
            if source and target:
                indirect_jump_count += 1
                edge_key = (module_name, source, target)
                edges.add(edge_key)
                module_entry = ensure_module_entry(module_name, event.get("path"))
                module_entry["_edges"].add(edge_key)
        elif event_type == "trace_status":
            message = str(event.get("message", "") or "").strip()
            if message:
                notes.append(message)
            if event.get("status") and not merged.get("status"):
                merged["status"] = event.get("status")

    existing_notes = list(merged.get("notes", []) or [])
    for note in notes:
        if note not in existing_notes:
            existing_notes.append(note)

    normalized_ordered_threads = []
    total_ordered_samples = 0
    for thread_id in sorted(ordered_threads):
        samples = sorted(
            ordered_threads[thread_id],
            key=lambda item: (
                item.get("sequence") if item.get("sequence") is not None else 10**9,
                item.get("round") if item.get("round") is not None else 10**9,
                str(item.get("block_start", "") or ""),
            ),
        )
        total_ordered_samples += len(samples)
        normalized_ordered_threads.append(
            {
                "thread_id": thread_id,
                "sample_count": len(samples),
                "samples": samples,
            }
        )

        previous_sample: dict[str, Any] | None = None
        for sample in samples:
            if previous_sample is None:
                previous_sample = sample
                continue

            previous_module = str(previous_sample.get("module", "") or "")
            current_module = str(sample.get("module", "") or "")
            previous_start = str(previous_sample.get("block_start", "") or "")
            current_start = str(sample.get("block_start", "") or "")
            if (
                previous_module
                and previous_module == current_module
                and previous_start
                and current_start
                and previous_start != current_start
            ):
                edge_key = (current_module, previous_start, current_start)
                if edge_key not in edges:
                    edges.add(edge_key)
                    module_entry = ensure_module_entry(current_module, sample.get("path") or previous_sample.get("path"))
                    module_entry["_edges"].add(edge_key)

            previous_sample = sample

    normalized_modules = []
    for module_entry in modules_by_name.values():
        normalized_modules.append(
            {
                "module": module_entry.get("module"),
                "path": module_entry.get("path"),
                "base": module_entry.get("base"),
                "size": module_entry.get("size"),
                "basic_block_count": len(module_entry.get("_basic_blocks", set())),
                "edge_count": len(module_entry.get("_edges", set())),
            }
        )
    merged["event_count"] = len(events)
    merged["basic_block_count"] = len(basic_blocks)
    merged["edge_count"] = len(edges)
    merged["module_count"] = len(modules_by_name)
    merged["modules"] = sorted(normalized_modules, key=lambda item: str(item.get("module", "")))
    merged["ordered_block_sample_count"] = total_ordered_samples
    merged["ordered_thread_count"] = len(normalized_ordered_threads)
    merged["ordered_threads"] = normalized_ordered_threads

    # Add control flow statistics
    if call_count > 0 or ret_count > 0 or branch_count > 0 or indirect_call_count > 0 or indirect_jump_count > 0:
        merged["call_count"] = call_count
        merged["ret_count"] = ret_count
        merged["branch_count"] = branch_count
        merged["indirect_call_count"] = indirect_call_count
        merged["indirect_jump_count"] = indirect_jump_count
        merged["coverage_mode"] = "control_flow_trace"
        merged["edge_source"] = "instrumented"
        merged["has_call_graph"] = call_count > 0 or ret_count > 0
        merged["has_indirect_targets"] = indirect_call_count > 0 or indirect_jump_count > 0
    else:
        merged["coverage_mode"] = merged.get("coverage_mode", "basic_blocks_only")
        merged["edge_source"] = merged.get("edge_source", "inferred_from_order")
        merged["has_call_graph"] = merged.get("has_call_graph", False)
        merged["has_indirect_targets"] = merged.get("has_indirect_targets", False)

    if existing_notes:
        merged["notes"] = existing_notes

    return merged


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
    task_profile = load_json(artifact_dir / "task_profile.json") or {}
    task_runtime_context = load_json(artifact_dir / "task_runtime_context.json") or {}
    trace_request = load_json(artifact_dir / "trace_request.json") or {}
    runner_log = load_runner_log(artifact_dir / "runner.log")
    sysmon_summary = load_json(artifact_dir / "sysmon_summary.json") or []

    for key in ("sample_name", "launched_pid", "started_at", "ended_at"):
        if key not in task_summary and trace_request.get(key) is not None:
            task_summary[key] = trace_request.get(key)

    process_events = load_event_list(artifact_dir / "sysmon_process_events.json")
    file_events = load_event_list(artifact_dir / "sysmon_file_events.json")
    registry_events = load_event_list(artifact_dir / "sysmon_registry_events.json")
    network_events = load_event_list(artifact_dir / "sysmon_network_dns_events.json")
    injection_events = load_event_list(artifact_dir / "sysmon_injection_events.json")
    ipc_wmi_events = load_event_list(artifact_dir / "sysmon_ipc_wmi_events.json")

    pre_post_diff = summarize_snapshot_diffs(artifact_dir)
    sample_name = normalize_sample_name(task_summary, sample_metadata)
    related_pids = derive_related_pids(sample_metadata, process_events)
    related_pids = derive_related_pids_from_snapshot_rows(
        sample_metadata,
        pre_post_diff.get("new_processes", []),
        sample_name,
        related_pids,
    )
    trace_summary = summarize_trace_artifacts(task_profile, task_runtime_context, artifact_dir)
    related_pids = derive_related_pids_from_trace(trace_summary, related_pids)

    related_process_events = filter_related_events(process_events, related_pids, sample_metadata, sample_name)
    related_file_events = filter_related_events(file_events, related_pids, sample_metadata, sample_name)
    related_registry_events = filter_related_events(registry_events, related_pids, sample_metadata, sample_name)
    related_network_events = filter_related_events(network_events, related_pids, sample_metadata, sample_name)
    related_injection_events = filter_related_events(injection_events, related_pids, sample_metadata, sample_name)
    related_ipc_wmi_events = filter_related_events(ipc_wmi_events, related_pids, sample_metadata, sample_name)
    related_snapshot_process_rows = filter_related_snapshot_process_rows(
        pre_post_diff.get("new_processes", []),
        related_pids,
        sample_name,
    )
    related_snapshot_tcp_rows = filter_related_snapshot_network_rows(
        pre_post_diff.get("new_tcp_connections", []),
        related_pids,
    )
    related_snapshot_udp_rows = filter_related_snapshot_network_rows(
        pre_post_diff.get("new_udp_endpoints", []),
        related_pids,
    )
    related_snapshot_dns_rows: list[dict[str, str]] = []
    analysis_quality = summarize_analysis_quality(
        sysmon_summary,
        extract_runner_errors(runner_log),
        copied_files,
        runner_log,
    )

    process_behavior = summarize_process_behavior(related_process_events)
    if process_behavior["created_count"] == 0 and related_snapshot_process_rows:
        process_behavior = summarize_snapshot_process_behavior(related_snapshot_process_rows)

    network_behavior = summarize_network_behavior(related_network_events)
    if network_behavior["count"] == 0 and (related_snapshot_tcp_rows or related_snapshot_udp_rows):
        network_behavior = summarize_snapshot_network_behavior(
            related_snapshot_tcp_rows,
            related_snapshot_udp_rows,
            related_snapshot_dns_rows,
        )

    return {
        "task_summary": task_summary,
        "sample_metadata": sample_metadata,
        "task_profile": task_profile,
        "task_runtime_context": task_runtime_context,
        "trace": trace_summary,
        "runner_log_errors": extract_runner_errors(runner_log),
        "runner_log_tail": runner_log.splitlines()[-50:],
        "sysmon_summary": sysmon_summary,
        "analysis_quality": analysis_quality,
        "related_pids": sorted(related_pids),
        "behavior": {
            "process": process_behavior,
            "file": summarize_file_behavior(related_file_events),
            "registry": summarize_registry_behavior(related_registry_events),
            "network": network_behavior,
            "injection": summarize_injection_behavior(related_injection_events),
            "ipc_wmi_event_count": len(related_ipc_wmi_events),
            "persistence": summarize_persistence(pre_post_diff),
        },
        "pre_post_diff": pre_post_diff,
        "raw_files": copied_files,
    }


def build_markdown_report(summary: dict[str, Any]) -> str:
    task = summary.get("task_summary", {})
    sample = summary.get("sample_metadata", {})
    task_profile = summary.get("task_profile", {})
    runtime_context = summary.get("task_runtime_context", {})
    trace = summary.get("trace", {})
    quality = summary.get("analysis_quality", {})
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
    if task_profile or runtime_context:
        lines.append("## Execution Profile")
        lines.append("")
        lines.append(f"- Profile name: `{task_profile.get('profile_name', runtime_context.get('profile_name', 'default'))}`")
        lines.append(f"- Trace mode: `{task_profile.get('trace_mode', runtime_context.get('trace_mode', 'none'))}`")
        lines.append(f"- Trace backend: `{task_profile.get('trace_backend', runtime_context.get('trace_backend', 'none'))}`")
        lines.append(f"- Network mode: `{task_profile.get('network_mode', runtime_context.get('network_mode', 'airgap'))}`")
        lines.append(f"- User simulation: `{task_profile.get('user_simulation', runtime_context.get('user_simulation', 'none'))}`")
        lines.append(
            f"- Effective windows: execution=`{runtime_context.get('execution_window_seconds', sample.get('execution_window_seconds', 'unknown'))}` "
            f"boot_stabilization=`{runtime_context.get('boot_stabilization_seconds', 'unknown')}`"
        )
        lines.append("")
    if trace:
        lines.append("## Deep Trace")
        lines.append("")
        lines.append(f"- Requested mode: `{trace.get('mode', 'none')}`")
        lines.append(f"- Backend: `{trace.get('backend', 'none')}`")
        lines.append(f"- Status: `{trace.get('status', 'unknown')}`")
        if trace.get("reason"):
            lines.append(f"- Note: `{trace.get('reason')}`")
        dynamic_cfg = trace.get("dynamic_cfg", {}) or {}
        if dynamic_cfg:
            if "event_count" in dynamic_cfg:
                lines.append(f"- Trace events: `{dynamic_cfg.get('event_count', 0)}`")
            lines.append(
                f"- Dynamic CFG stats: basic_blocks=`{dynamic_cfg.get('basic_block_count', 0)}` "
                f"edges=`{dynamic_cfg.get('edge_count', 0)}` modules=`{dynamic_cfg.get('module_count', 0)}`"
            )
            if dynamic_cfg.get("ordered_block_sample_count", 0):
                lines.append(
                    f"- Ordered block samples: samples=`{dynamic_cfg.get('ordered_block_sample_count', 0)}` "
                    f"threads=`{dynamic_cfg.get('ordered_thread_count', 0)}`"
                )
        lines.append("")
    ordered_threads = (((trace or {}).get("dynamic_cfg", {}) or {}).get("ordered_threads", []) if trace else [])
    if ordered_threads:
        lines.append("## Sampled Block Order")
        lines.append("")
        for thread_entry in ordered_threads[:8]:
            thread_id = thread_entry.get("thread_id", "unknown")
            samples = thread_entry.get("samples", [])[:12]
            if samples:
                sequence = " -> ".join(
                    f"{sample.get('module', 'unknown')}:{sample.get('block_start', '?')}"
                    for sample in samples
                )
                lines.append(f"- thread=`{thread_id}` samples=`{thread_entry.get('sample_count', len(thread_entry.get('samples', [])))}`")
                lines.append(f"  sequence=`{sequence}`")
            else:
                lines.append(f"- thread=`{thread_id}` samples=`0`")
        lines.append("")
    lines.append("## Analysis Quality")
    lines.append("")
    lines.append(f"- Telemetry mode: `{quality.get('mode', 'unknown')}`")
    lines.append(f"- Sysmon available: `{quality.get('sysmon_available', False)}`")
    for warning in quality.get("warnings", [])[:10]:
        lines.append(f"- Warning: `{warning}`")
    lines.append("")
    lines.append("## Behavior Summary")
    lines.append("")
    proc = behavior.get("process", {})
    file_behavior = behavior.get("file", {})
    reg_behavior = behavior.get("registry", {})
    net_behavior = behavior.get("network", {})
    inj_behavior = behavior.get("injection", {})
    persistence = behavior.get("persistence", {})
    lines.append(f"- Process creates: `{proc.get('created_count', 0)}`")
    lines.append(f"- Process terminates: `{proc.get('terminated_count', 0)}`")
    lines.append(f"- File-touch events: `{file_behavior.get('count', 0)}`")
    lines.append(f"- Registry events: `{reg_behavior.get('count', 0)}`")
    lines.append(f"- Network/DNS events: `{net_behavior.get('count', 0)}`")
    lines.append(f"- Injection/tampering events: `{inj_behavior.get('count', 0)}`")
    lines.append(f"- IPC/WMI events: `{behavior.get('ipc_wmi_event_count', 0)}`")
    lines.append(
        f"- Persistence hints: autorun_created=`{len(persistence.get('autorun_registry_created', {}))}` "
        f"autorun_changed=`{len(persistence.get('autorun_registry_changed', {}))}` "
        f"startup_entries=`{len(persistence.get('startup_entries', []))}` "
        f"scheduled_tasks=`{len(persistence.get('scheduled_tasks', []))}` "
        f"services=`{len(persistence.get('services', []))}`"
    )
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
    lines.append("## Persistence")
    lines.append("")
    if persistence.get("autorun_registry_created"):
        for key, value in list(persistence.get("autorun_registry_created", {}).items())[:20]:
            lines.append(f"- Autorun create `{key}` => `{value}`")
    if persistence.get("autorun_registry_changed"):
        for key, value in list(persistence.get("autorun_registry_changed", {}).items())[:20]:
            lines.append(f"- Autorun change `{key}` => `{value}`")
    for row in persistence.get("startup_entries", [])[:20]:
        lines.append(f"- Startup `{row.get('FullName')}`")
    for row in persistence.get("scheduled_tasks", [])[:20]:
        lines.append(f"- Task `{row.get('TaskPath')}{row.get('TaskName')}`")
    for row in persistence.get("services", [])[:20]:
        lines.append(f"- Service `{row.get('Name')}` path=`{row.get('PathName')}`")
    if (
        not persistence.get("autorun_registry_created")
        and not persistence.get("autorun_registry_changed")
        and not persistence.get("startup_entries")
        and not persistence.get("scheduled_tasks")
        and not persistence.get("services")
    ):
        lines.append("- No persistence-oriented changes found in the captured window.")
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

    materialize_sysmon_from_evtx(artifact_dir)

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
