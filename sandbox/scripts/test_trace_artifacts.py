from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from parse_artifact import (
    build_markdown_report,
    build_summary,
    load_json,
    should_materialize_sysmon_from_evtx,
    summarize_trace_artifacts,
)
from task_profile import expected_trace_artifacts, recommended_timeout_seconds, validate_task_profile_dict

REPO_ROOT = Path(__file__).resolve().parents[2]


def write_minimal_drcov_log(path: Path, pid: int, block_offsets: list[int]) -> None:
    lines = [
        "DRCOV VERSION: 3",
        "DRCOV FLAVOR: drcov",
        "Module Table: version 5, count 2",
        "Columns: id, containing_id, start, end, entry, offset, preferred_base, checksum, timestamp, path",
        "  0,   0, 0x0000000140000000, 0x0000000140004000, 0x0000000140001000, 0000000000000000, 0x0000000140000000, 0x00000000, 0x00000000,  C:\\Sandbox\\input\\sample.exe",
        "  1,   1, 0x00007FFB811B0000, 0x00007FFB813A8000, 0x00007FFB811B0000, 0000000000000000, 0x00007FFB811B0000, 0x00000000, 0x00000000,  C:\\Windows\\System32\\ntdll.dll",
        f"BB Table: {len(block_offsets)} bbs",
        "module id, start, size:",
    ]
    for offset in block_offsets:
        lines.append(f"module[  0]: 0x{offset:016X},  16")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TraceArtifactSummaryTests(unittest.TestCase):
    def test_load_json_treats_nul_padded_empty_artifact_as_missing(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "nul_only.json"
            path.write_bytes(b"\x00" * 128)

            self.assertIsNone(load_json(path))

    def test_should_materialize_sysmon_when_summary_has_events_but_category_files_are_broken(self) -> None:
        with TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)
            (artifact_dir / "sysmon.evtx").write_bytes(b"placeholder")
            (artifact_dir / "sysmon_summary.json").write_text(
                json.dumps(
                    [
                        {"EventId": 1, "Count": 5},
                        {"EventId": 11, "Count": 7},
                        {"EventId": 12, "Count": 3},
                    ]
                ),
                encoding="utf-8",
            )
            (artifact_dir / "sysmon_process_events.json").write_text("[]", encoding="utf-8")
            (artifact_dir / "sysmon_file_events.json").write_bytes(b"\x00" * 64)

            self.assertTrue(should_materialize_sysmon_from_evtx(artifact_dir))

    def test_summarize_trace_artifacts_infers_collected_files_from_disk(self) -> None:
        with TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)

            (artifact_dir / "trace_request.json").write_text("{}", encoding="utf-8")
            (artifact_dir / "trace_manifest.json").write_text(
                json.dumps(
                    {
                        "trace_mode": "dynamic_cfg",
                        "trace_backend": "placeholder",
                        "status": "placeholder_not_implemented",
                        "expected_artifacts": [
                            "trace_request.json",
                            "trace_manifest.json",
                            "dynamic_cfg_trace_summary.json",
                            "dynamic_cfg_trace.ndjson",
                        ],
                        "collected_artifacts": [],
                    }
                ),
                encoding="utf-8",
            )
            (artifact_dir / "dynamic_cfg_trace_summary.json").write_text("{}", encoding="utf-8")
            (artifact_dir / "dynamic_cfg_trace.ndjson").write_text("[]", encoding="utf-8")

            summary = summarize_trace_artifacts(
                {"trace_mode": "dynamic_cfg", "trace_backend": "placeholder"},
                {"trace_mode": "dynamic_cfg", "trace_backend": "placeholder"},
                artifact_dir,
            )

            self.assertEqual(summary["expected_artifacts"], expected_trace_artifacts("dynamic_cfg"))
            self.assertEqual(
                summary["collected_artifacts"],
                [
                    "trace_request.json",
                    "trace_manifest.json",
                    "dynamic_cfg_trace_summary.json",
                    "dynamic_cfg_trace.ndjson",
                ],
            )

    def test_summarize_trace_artifacts_builds_dynamic_cfg_counts_from_ndjson(self) -> None:
        with TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)

            (artifact_dir / "trace_request.json").write_text("{}", encoding="utf-8")
            (artifact_dir / "trace_manifest.json").write_text(
                json.dumps(
                    {
                        "trace_mode": "dynamic_cfg",
                        "trace_backend": "placeholder",
                        "status": "seeded_from_runtime_metadata",
                        "expected_artifacts": [
                            "trace_request.json",
                            "trace_manifest.json",
                            "dynamic_cfg_trace_summary.json",
                            "dynamic_cfg_trace.ndjson",
                        ],
                        "collected_artifacts": [
                            "trace_request.json",
                            "trace_manifest.json",
                            "dynamic_cfg_trace.ndjson",
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (artifact_dir / "dynamic_cfg_trace.ndjson").write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "event": "module_load",
                                "module": "sample",
                                "path": r"C:\\Sandbox\\input\\sample.exe",
                                "base": "0x140000000",
                                "size": 4096,
                            }
                        ),
                        json.dumps(
                            {
                                "event": "basic_block",
                                "module": "sample",
                                "start": "0x140001000",
                                "end": "0x140001020",
                            }
                        ),
                        json.dumps(
                            {
                                "event": "basic_block",
                                "module": "sample",
                                "start": "0x140001020",
                                "end": "0x140001040",
                            }
                        ),
                        json.dumps(
                            {
                                "event": "edge",
                                "module": "sample",
                                "source": "0x140001000",
                                "target": "0x140001020",
                                "count": 3,
                            }
                        ),
                        json.dumps(
                            {
                                "event": "edge",
                                "module": "sample",
                                "source": "0x140001020",
                                "target": "0x140001040",
                                "count": 1,
                            }
                        ),
                        json.dumps(
                            {
                                "event": "basic_block",
                                "module": "sample",
                                "start": "0x140001020",
                                "end": "0x140001040",
                            }
                        ),
                        json.dumps(
                            {
                                "event": "edge",
                                "module": "sample",
                                "source": "0x140001020",
                                "target": "0x140001040",
                                "count": 7,
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            summary = summarize_trace_artifacts(
                {"trace_mode": "dynamic_cfg", "trace_backend": "placeholder"},
                {"trace_mode": "dynamic_cfg", "trace_backend": "placeholder"},
                artifact_dir,
            )

            self.assertEqual(summary["status"], "seeded_from_runtime_metadata")
            self.assertEqual(summary["dynamic_cfg"]["basic_block_count"], 2)
            self.assertEqual(summary["dynamic_cfg"]["edge_count"], 2)
            self.assertEqual(summary["dynamic_cfg"]["module_count"], 1)
            self.assertEqual(summary["dynamic_cfg"]["event_count"], 7)
            self.assertEqual(summary["dynamic_cfg"]["modules"][0]["module"], "sample")
            self.assertEqual(summary["dynamic_cfg"]["modules"][0]["basic_block_count"], 2)
            self.assertEqual(summary["dynamic_cfg"]["modules"][0]["edge_count"], 2)

    def test_summarize_trace_artifacts_preserves_sampled_block_execution_order(self) -> None:
        with TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)

            (artifact_dir / "trace_request.json").write_text("{}", encoding="utf-8")
            (artifact_dir / "trace_manifest.json").write_text(
                json.dumps(
                    {
                        "trace_mode": "dynamic_cfg",
                        "trace_backend": "placeholder",
                        "status": "sampled_thread_contexts",
                        "expected_artifacts": [
                            "trace_request.json",
                            "trace_manifest.json",
                            "dynamic_cfg_trace_summary.json",
                            "dynamic_cfg_trace.ndjson",
                        ],
                        "collected_artifacts": [
                            "trace_request.json",
                            "trace_manifest.json",
                            "dynamic_cfg_trace.ndjson",
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (artifact_dir / "dynamic_cfg_trace.ndjson").write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "event": "module_load",
                                "module": "sample",
                                "path": r"C:\\Sandbox\\input\\sample.exe",
                                "base": "0x140000000",
                                "size": 4096,
                            }
                        ),
                        json.dumps(
                            {
                                "event": "sampled_block_execution",
                                "module": "sample",
                                "path": r"C:\\Sandbox\\input\\sample.exe",
                                "thread_id": 101,
                                "sequence": 0,
                                "round": 0,
                                "block_start": "0x140001000",
                                "block_end": "0x140001000",
                                "instruction_pointer": "0x140001000",
                            }
                        ),
                        json.dumps(
                            {
                                "event": "sampled_block_execution",
                                "module": "sample",
                                "path": r"C:\\Sandbox\\input\\sample.exe",
                                "thread_id": 101,
                                "sequence": 1,
                                "round": 1,
                                "block_start": "0x140001020",
                                "block_end": "0x140001020",
                                "instruction_pointer": "0x140001020",
                            }
                        ),
                        json.dumps(
                            {
                                "event": "sampled_block_execution",
                                "module": "sample",
                                "path": r"C:\\Sandbox\\input\\sample.exe",
                                "thread_id": 202,
                                "sequence": 0,
                                "round": 0,
                                "block_start": "0x140002000",
                                "block_end": "0x140002000",
                                "instruction_pointer": "0x140002000",
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            summary = summarize_trace_artifacts(
                {"trace_mode": "dynamic_cfg", "trace_backend": "placeholder"},
                {"trace_mode": "dynamic_cfg", "trace_backend": "placeholder"},
                artifact_dir,
            )

            self.assertEqual(summary["dynamic_cfg"]["ordered_block_sample_count"], 3)
            self.assertEqual(summary["dynamic_cfg"]["ordered_thread_count"], 2)
            self.assertEqual(summary["dynamic_cfg"]["edge_count"], 1)
            self.assertEqual(summary["dynamic_cfg"]["ordered_threads"][0]["thread_id"], 101)
            self.assertEqual(
                [sample["block_start"] for sample in summary["dynamic_cfg"]["ordered_threads"][0]["samples"]],
                ["0x140001000", "0x140001020"],
            )
            self.assertEqual(summary["dynamic_cfg"]["ordered_threads"][1]["thread_id"], 202)
            self.assertEqual(summary["dynamic_cfg"]["modules"][0]["edge_count"], 1)

    def test_summarize_trace_artifacts_recovers_drio_trace_from_raw_logs_without_manifest(self) -> None:
        with TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)
            drio_dir = artifact_dir / "drio"
            drio_dir.mkdir()

            (artifact_dir / "trace_request.json").write_text(
                json.dumps(
                    {
                        "trace_mode": "dynamic_cfg",
                        "trace_backend": "drio",
                        "sample_name": "sample.exe",
                        "launched_pid": 4000,
                    }
                ),
                encoding="utf-8",
            )
            write_minimal_drcov_log(drio_dir / "drcov.sample.exe.04096.0000.proc.log", 4096, [0x1000, 0x1010])
            write_minimal_drcov_log(drio_dir / "drcov.sample.exe.04112.0000.proc.log", 4112, [0x1000])

            summary = summarize_trace_artifacts(
                {"trace_mode": "dynamic_cfg", "trace_backend": "drio"},
                {"trace_mode": "dynamic_cfg", "trace_backend": "drio"},
                artifact_dir,
            )

            self.assertEqual(summary["status"], "drcov_basic_blocks")
            self.assertEqual(summary["backend"], "drio")
            self.assertEqual(summary["dynamic_cfg"]["drio_mode"], "drcov_text_first_seen_order")
            self.assertEqual(summary["dynamic_cfg"]["basic_block_count"], 2)
            self.assertEqual(summary["dynamic_cfg"]["edge_count"], 1)
            self.assertEqual(summary["dynamic_cfg"]["ordered_block_sample_count"], 3)
            self.assertEqual(summary["dynamic_cfg"]["ordered_thread_count"], 2)
            self.assertEqual(summary["dynamic_cfg"]["process_ids"], [4096, 4112])
            self.assertEqual(summary["dynamic_cfg"]["ordered_threads"][0]["thread_id"], 4096)
            self.assertEqual(
                [sample["block_start"] for sample in summary["dynamic_cfg"]["ordered_threads"][0]["samples"]],
                ["0x140001000", "0x140001010"],
            )

    def test_build_summary_uses_recovered_drio_process_ids_as_related_pids(self) -> None:
        with TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)
            drio_dir = artifact_dir / "drio"
            drio_dir.mkdir()

            (artifact_dir / "sample_metadata.json").write_text(
                json.dumps(
                    {
                        "sample_name": "sample.exe",
                        "sample_path": r"C:\\Sandbox\\input\\sample.exe",
                        "launched_pid": 4000,
                    }
                ),
                encoding="utf-8",
            )
            (artifact_dir / "task_profile.json").write_text(
                json.dumps({"profile_name": "deep_cfg_drio", "trace_mode": "dynamic_cfg", "trace_backend": "drio"}),
                encoding="utf-8",
            )
            (artifact_dir / "task_runtime_context.json").write_text(
                json.dumps({"trace_mode": "dynamic_cfg", "trace_backend": "drio"}),
                encoding="utf-8",
            )
            (artifact_dir / "trace_request.json").write_text(
                json.dumps(
                    {
                        "trace_mode": "dynamic_cfg",
                        "trace_backend": "drio",
                        "sample_name": "sample.exe",
                        "launched_pid": 4000,
                        "started_at": "2026-04-06T15:04:27.8045552-07:00",
                        "ended_at": "2026-04-06T15:07:27.8045552-07:00",
                    }
                ),
                encoding="utf-8",
            )
            write_minimal_drcov_log(drio_dir / "drcov.sample.exe.04096.0000.proc.log", 4096, [0x1000, 0x1010])
            write_minimal_drcov_log(drio_dir / "drcov.sample.exe.04112.0000.proc.log", 4112, [0x1000])

            summary = build_summary(
                artifact_dir,
                sorted(path.name for path in artifact_dir.iterdir() if path.is_file()),
            )

            self.assertEqual(summary["trace"]["status"], "drcov_basic_blocks")
            self.assertEqual(summary["related_pids"], [4000, 4096, 4112])


class TaskProfileValidationTests(unittest.TestCase):
    def test_validate_task_profile_rejects_unsupported_backend_for_mode(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported trace_backend"):
            validate_task_profile_dict(
                {
                    "profile_name": "bad_profile",
                    "trace_mode": "dynamic_cfg",
                    "trace_backend": "none",
                }
            )

    def test_validate_task_profile_accepts_deep_cfg_baseline_shape(self) -> None:
        validate_task_profile_dict(
            {
                "profile_name": "deep_cfg_baseline",
                "trace_mode": "dynamic_cfg",
                "trace_backend": "placeholder",
                "capture": {
                    "cfg": True,
                    "dfg": False,
                    "memory_writes": True,
                    "register_snapshots": False,
                },
                "backend_options": {
                    "sample_rounds": 24,
                    "sample_sleep_milliseconds": 5,
                },
            }
        )

    def test_validate_task_profile_accepts_drio_backend_shape(self) -> None:
        validate_task_profile_dict(
            {
                "profile_name": "deep_cfg_drio",
                "trace_mode": "dynamic_cfg",
                "trace_backend": "drio",
                "capture": {
                    "cfg": True,
                    "dfg": False,
                    "memory_writes": True,
                    "register_snapshots": False,
                },
                "backend_options": {
                    "sample_rounds": 24,
                    "sample_sleep_milliseconds": 5,
                },
            }
        )

    def test_recommended_timeout_seconds_accounts_for_drio_export_slack(self) -> None:
        timeout_seconds = recommended_timeout_seconds(
            {
                "profile_name": "deep_cfg_drio",
                "trace_mode": "dynamic_cfg",
                "trace_backend": "drio",
                "execution_window_seconds": 180,
                "boot_stabilization_seconds": 30,
            }
        )

        self.assertEqual(timeout_seconds, 510)

    def test_recommended_timeout_seconds_accounts_for_trace_processing_budget(self) -> None:
        timeout_seconds = recommended_timeout_seconds(
            {
                "profile_name": "deep_cfg_drio_extended",
                "trace_mode": "dynamic_cfg",
                "trace_backend": "drio",
                "execution_window_seconds": 180,
                "boot_stabilization_seconds": 30,
                "trace_processing_timeout_seconds": 600,
            }
        )

        self.assertEqual(timeout_seconds, 1110)

    def test_recommended_timeout_seconds_falls_back_to_default_without_profile(self) -> None:
        self.assertEqual(recommended_timeout_seconds(None), 300)


class GuestRuntimeTraceTimingTests(unittest.TestCase):
    def test_run_task_buffers_non_deferred_trace_collection_around_execution_window_sleep(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")
        capture_call = "Capture-TraceArtifactsToBuffer -TaskProfile $taskProfile -TaskRuntimeContext $taskRuntimeContext -SampleName $sample.Name -SamplePath $sample.FullName -LaunchedPid $proc.Id -StartedAt $start -EndedAt $plannedTraceEnd"
        sleep_call = "Start-Sleep -Seconds $executionWindowSeconds"
        write_call = "Write-TraceArtifactBuffer -TraceArtifactBuffer $traceArtifactBuffer -ArtifactDir $artifactDir"

        self.assertIn(capture_call, script)
        self.assertIn(sleep_call, script)
        self.assertIn(write_call, script)
        self.assertLess(script.index(capture_call), script.index(sleep_call))
        self.assertLess(script.index(sleep_call), script.index(write_call))

    def test_run_task_propagates_sample_path_into_trace_request(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn("[string]$SamplePath", script)
        self.assertIn("sample_path = $SamplePath", script)
        self.assertIn(
            "Export-TraceArtifacts -TaskProfile $taskProfile -TaskRuntimeContext $taskRuntimeContext -ArtifactDir $artifactDir -SampleName $sample.Name -SamplePath $sample.FullName -LaunchedPid $proc.Id -StartedAt $start -EndedAt $plannedTraceEnd",
            script,
        )

    def test_run_task_dispatches_drio_backend_script(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn("function Get-TraceBackendScriptPath {", script)
        self.assertIn('"drio" { return "C:\\Sandbox\\runtime\\trace_backend_drio.ps1" }', script)
        self.assertIn('$traceBackendScript = Get-TraceBackendScriptPath -TraceMode $traceMode -TraceBackend $traceBackend', script)

    def test_run_task_launches_drio_sample_through_drrun_custom_client(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn("function Get-DrioDrrunPath {", script)
        self.assertIn("function Get-DrioClientRuntimePaths {", script)
        self.assertIn('$drioLogDir = Join-Path $artifactDir "drio"', script)
        self.assertIn('return Start-Process -FilePath $DrrunPath -ArgumentList $DrrunArgs', script)
        self.assertIn("function Get-DrioRuntimePathEntries {", script)
        self.assertIn("$drioRuntimePathEntries = Get-DrioRuntimePathEntries -DrrunPath $drrunPath -ClientDll $clientDll -Is32Bit $is32bit", script)
        self.assertIn('$drioRuntimePath = ($drioRuntimePathEntries -join ";")', script)
        self.assertIn('$oldPath = $env:PATH', script)
        self.assertIn('$env:PATH = "$DrioRuntimePath;$oldPath"', script)
        self.assertIn('$env:PATH = $oldPath', script)
        self.assertIn('"-c32", "C:\\Sandbox\\runtime\\drio\\bin32\\shrike_drcov_nudge.dll"', script)
        self.assertIn('"-c64", "C:\\Sandbox\\runtime\\drio\\bin64\\shrike_drcov_nudge.dll"', script)
        self.assertIn('"-dump_text"', script)
        self.assertIn('"-logdir"', script)
        self.assertIn('"-logprefix"', script)
        self.assertIn('launcher = if ($deferTraceExport) { "drrun_custom_drcov_client" } else { "direct" }', script)

    def test_run_task_uses_matching_drrun_and_client_bitness(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")
        drrun_body = script[
            script.index("function Get-DrioDrrunPath {") :
            script.index("function Get-DrioDrconfigPath {")
        ]
        args_body = script[
            script.index("function New-DrioTraceArguments {") :
            script.index("function Start-DrioTraceProcess {")
        ]

        self.assertIn('if ($Is32Bit) {', drrun_body)
        self.assertLess(
            drrun_body.index('if ($Is32Bit) {'),
            drrun_body.index('return "C:\\Tools\\DynamoRIO\\bin32\\drrun.exe"'),
        )
        self.assertIn('return "C:\\Tools\\DynamoRIO\\bin64\\drrun.exe"', drrun_body)
        self.assertIn('$args = if ($Is32Bit) {', args_body)
        self.assertIn('@("-c32", "C:\\Sandbox\\runtime\\drio\\bin32\\shrike_drcov_nudge.dll")', args_body)
        self.assertIn('@("-c64", "C:\\Sandbox\\runtime\\drio\\bin64\\shrike_drcov_nudge.dll")', args_body)

    def test_run_task_retries_drio_without_antidebug_when_client_initializer_fails(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn("function Start-DrioTraceProcess {", script)
        self.assertIn("function Test-DrioClientInitializerFailure {", script)
        self.assertIn('library initializer failed', script)
        self.assertIn('retrying DRIO launch without -bypass_antidebug after client initializer failure', script)
        self.assertIn('$bypassAntidebugEffective = $false', script)
        self.assertIn('$taskRuntimeContext.bypass_antidebug_effective = $bypassAntidebugEffective', script)
        self.assertIn('bypass_antidebug_effective = $bypassAntidebugEffective', script)

    def test_run_task_does_not_hide_custom_client_initializer_failure_with_stock_drcov(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertNotIn("function New-DrioStockDrcovArguments {", script)
        self.assertNotIn("Get-DrioStockDrcovClientPath -DrrunPath $drrunPath", script)
        self.assertNotIn('falling back to stock DynamoRIO drcov client after custom client initializer failure', script)
        self.assertNotIn('drrun_stdout_stock_drcov.txt', script)
        self.assertNotIn('drrun_stderr_stock_drcov.txt', script)

    def test_windows_batch_requires_custom_control_flow_trace(self) -> None:
        script = (REPO_ROOT / "windows_host" / "powershell" / "13_batch_sandbox_wrapped.ps1").read_text(encoding="utf-8")

        self.assertIn('$HealthyTraceStatuses = @("control_flow_trace", "completed")', script)
        self.assertNotIn('"drcov_basic_blocks", "completed"', script)
        self.assertIn("if ($health.Healthy) {", script)
        self.assertIn("wrapper_exit_code = $lastRun.ExitCode", script)
        self.assertNotIn("if ($lastRun.ExitCode -eq 0 -and $health.Healthy)", script)

    def test_run_task_defers_drio_trace_export_until_after_sleep(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn("function Should-DeferTraceExport {", script)
        self.assertIn('$deferTraceExport = Should-DeferTraceExport -TaskProfile $taskProfile', script)
        self.assertIn('if (-not $deferTraceExport) {', script)
        self.assertIn('if ($deferTraceExport) {', script)

    def test_run_task_waits_for_drio_process_exit_before_trace_export(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn("function Stop-TraceLauncherProcessTree {", script)
        self.assertIn("Stop-TraceLauncherProcessTree -LauncherProcessId $proc.Id", script)
        self.assertLess(
            script.index("Stop-TraceLauncherProcessTree -LauncherProcessId $proc.Id"),
            script.index("Export-TraceArtifacts -TaskProfile $taskProfile -TaskRuntimeContext $taskRuntimeContext -ArtifactDir $artifactDir -SampleName $sample.Name -SamplePath $sample.FullName -LaunchedPid $proc.Id -StartedAt $start -EndedAt $plannedTraceEnd"),
        )

    def test_run_task_force_terminates_drio_process_tree_after_grace_period(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn('"/T"', script)
        self.assertIn('"/F"', script)

    def test_run_task_attempts_graceful_drio_process_tree_shutdown_before_force_kill(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn("Invoke-TraceTreeTaskkill -LauncherProcessId $LauncherProcessId", script)
        self.assertIn("Invoke-TraceTreeTaskkill -LauncherProcessId $LauncherProcessId -Force", script)
        self.assertLess(
            script.index("Invoke-TraceTreeTaskkill -LauncherProcessId $LauncherProcessId"),
            script.index("Invoke-TraceTreeTaskkill -LauncherProcessId $LauncherProcessId -Force"),
        )

    def test_run_task_attempts_drio_nudge_before_taskkill_shutdown(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn("function Get-DrioDrconfigPath {", script)
        self.assertIn("function Invoke-DrioNudgeForTraceTargets {", script)
        self.assertIn('$drconfigPath = Get-DrioDrconfigPath -DrrunPath $drrunPath', script)
        self.assertIn('& $drconfigPath "-nudge" $targetName "0" "1"', script)
        self.assertIn("Invoke-DrioNudgeForTraceTargets -SampleName $SampleName -TreeIds $treeIds", script)
        self.assertLess(
            script.index("Invoke-DrioNudgeForTraceTargets -SampleName $SampleName -TreeIds $treeIds"),
            script.index("Invoke-TraceTreeTaskkill -LauncherProcessId $LauncherProcessId"),
        )

    def test_run_task_restores_missing_trace_backend_script_from_cached_content(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn("$script:TraceBackendScriptContentCache = @{}", script)
        self.assertIn("function Save-TraceBackendScriptContent {", script)
        self.assertIn("function Restore-TraceBackendScriptIfMissing {", script)
        self.assertIn("Save-TraceBackendScriptContent -TraceBackendScriptPath $traceBackendScriptPath", script)
        self.assertIn("Restore-TraceBackendScriptIfMissing -TraceBackendScriptPath $traceBackendScript", script)

    def test_run_task_sanitizes_invalid_sysmon_xml_chars_before_parsing(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn("function Remove-InvalidXmlChars {", script)
        self.assertIn("function Convert-EventRecordToSafeXml {", script)
        self.assertIn("$xmlText = Remove-InvalidXmlChars -Text $Event.ToXml()", script)
        self.assertIn("$xml = Convert-EventRecordToSafeXml -Event $Event", script)

    def test_run_task_expands_drio_nudge_targets_for_extensionless_samples(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn("function Get-DrioNudgeTargetNames {", script)
        self.assertIn('[void]$targetNames.Add($SampleName)', script)
        self.assertIn('[void]$targetNames.Add(("{0}.exe" -f $SampleName))', script)
        self.assertIn("Stop-TraceLauncherProcessTree -LauncherProcessId $proc.Id -SampleName $sample.Name", script)

    def test_run_task_suppresses_arraylist_indexes_when_building_drio_target_names(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn('[void]$targetNames.Add($SampleName)', script)
        self.assertIn('[void]$targetNames.Add(("{0}.exe" -f $SampleName))', script)

    def test_run_task_publishes_trace_artifacts_before_slow_sysmon_collection(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")
        trace_export = "Export-TraceArtifacts -TaskProfile $taskProfile -TaskRuntimeContext $taskRuntimeContext -ArtifactDir $stagingDir -SampleName $sample.Name -SamplePath $sample.FullName -LaunchedPid $proc.Id -StartedAt $start -EndedAt $plannedTraceEnd -DrioLogDir $drioLogDir -BypassAntidebug $bypassAntidebug"
        publish_trace = 'Publish-StagingArtifacts -StagingDir $stagingDir -ArtifactDir $artifactDir -Reason "after trace export"'
        sysmon_export = 'wevtutil epl Microsoft-Windows-Sysmon/Operational (Join-Path $stagingDir "sysmon.evtx")'

        self.assertIn("function Publish-StagingArtifacts {", script)
        self.assertIn(publish_trace, script)
        self.assertLess(script.index(trace_export), script.index(publish_trace))
        self.assertLess(script.index(publish_trace), script.index(sysmon_export))

    def test_run_task_buffers_pre_execution_artifacts_before_sample_launch_without_staging_writes(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")
        before_launch = script[: script.index('Write-RunnerLog ("launching sample {0}" -f $sample.FullName)')]

        self.assertIn('$bufferedResultArtifacts = @($preExecutionArtifacts)', before_launch)
        self.assertNotIn('Export-SnapshotBundle -Prefix "pre" -ArtifactDir $stagingDir', before_launch)
        self.assertNotIn('Join-Path $stagingDir "sample_metadata.json"', before_launch)
        self.assertNotIn('Join-Path $stagingDir "task_profile.json"', before_launch)
        self.assertNotIn('Join-Path $stagingDir "task_runtime_context.json"', before_launch)

    def test_run_task_materializes_buffered_pre_execution_artifacts_after_sample_shutdown(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn("Write-BufferedResultArtifacts -Artifacts $bufferedResultArtifacts -ArtifactDir $stagingDir", script)
        self.assertLess(
            script.index('Write-RunnerLog "execution window ended"'),
            script.index("Write-BufferedResultArtifacts -Artifacts $bufferedResultArtifacts -ArtifactDir $stagingDir"),
        )

    def test_run_task_waits_for_sample_process_exit_before_materializing_buffer(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertLess(
            script.index("Stop-SampleProcessTree -LauncherProcessId $proc.Id"),
            script.index("Write-BufferedResultArtifacts -Artifacts $bufferedResultArtifacts -ArtifactDir $stagingDir"),
        )
        self.assertIn("Wait-ProcessExit -ProcessId $LauncherProcessId -TimeoutSeconds $ExitWaitSeconds", script)

    def test_run_task_launches_extensionless_drio_samples_via_exe_copy(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn('$launchPath = $sample.FullName', script)
        self.assertIn('created .exe copy for extensionless DRIO sample', script)
        self.assertIn('$args += @("--", $LaunchPath)', script)
        self.assertLess(
            script.index('created .exe copy for extensionless DRIO sample'),
            script.index('$drrunArgs = New-DrioTraceArguments'),
        )

    def test_drio_client_matches_extensionless_sample_and_renamed_client_modules(self) -> None:
        source = (REPO_ROOT / "windows_host" / "drio_client" / "src" / "shrike_drcov_nudge.c").read_text(encoding="utf-8")

        self.assertIn("is_probable_sample_module_name", source)
        self.assertIn('string_contains_case_insensitive(name, ".dll")', source)
        self.assertIn('"shrike_drcov_nudge_final.dll"', source)
        self.assertIn('string_contains_case_insensitive(name, "shrike_drcov_nudge")', source)


class PlaceholderBackendFallbackTests(unittest.TestCase):
    def test_placeholder_backend_uses_sample_path_for_pe_fallback(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "trace_backend_placeholder.ps1").read_text(encoding="utf-8")

        self.assertIn("function Get-PeImageInfo {", script)
        self.assertIn("$fallbackSamplePath = if ($request.sample_path) { [string]$request.sample_path } else { $null }", script)
        self.assertIn("$fallbackPeImage = Get-PeImageInfo -Path $fallbackSamplePath", script)
        self.assertIn('kind = "pe_header_fallback"', script)
        self.assertIn('kind = "entry_seed"', script)

    def test_placeholder_backend_emits_ordered_sampled_block_execution_events(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "trace_backend_placeholder.ps1").read_text(encoding="utf-8")

        self.assertIn("public int RoundIndex { get; set; }", script)
        self.assertIn("public int Sequence { get; set; }", script)
        self.assertIn('event = "sampled_block_execution"', script)
        self.assertIn("ordered_block_sample_count = $orderedBlockSamples.Count", script)
        self.assertIn('$summaryStatus = if ($orderedBlockSamples.Count -gt 0) { "sampled_block_order" } else { "seeded_from_runtime_metadata" }', script)

    def test_placeholder_backend_uses_configurable_fast_sampling_before_module_enumeration(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "trace_backend_placeholder.ps1").read_text(encoding="utf-8")
        sample_rounds_line = '$sampleRounds = Get-BackendOptionValue -Options $request.backend_options -Name "sample_rounds" -Default 24'
        sample_sleep_line = '$sampleSleepMilliseconds = Get-BackendOptionValue -Options $request.backend_options -Name "sample_sleep_milliseconds" -Default 5'
        sample_call = '$threadSamples = [Shrike.Runtime.ThreadInstructionSampler]::CollectMultiple([int]$request.launched_pid, $sampleRounds, $sampleSleepMilliseconds)'
        module_enum_call = 'foreach ($module in [Shrike.Runtime.ThreadInstructionSampler]::EnumerateModules([int]$request.launched_pid)) {'

        self.assertIn("function Get-BackendOptionValue {", script)
        self.assertIn(sample_rounds_line, script)
        self.assertIn(sample_sleep_line, script)
        self.assertIn(sample_call, script)
        self.assertIn(module_enum_call, script)
        self.assertLess(script.index(sample_call), script.index(module_enum_call))


class GuestRuntimeInstallTests(unittest.TestCase):
    def test_install_guest_runtime_includes_drio_backend_and_custom_clients(self) -> None:
        script = (REPO_ROOT / "windows_host" / "powershell" / "06_install_guest_runtime.ps1").read_text(encoding="utf-8")

        self.assertIn('[string]$TraceBackendDrioSourcePath = "guest\\runtime\\trace_backend_drio.ps1"', script)
        self.assertIn('[string]$DrioClientBin32SourcePath = "guest\\runtime\\drio\\bin32\\shrike_drcov_nudge.dll"', script)
        self.assertIn('[string]$DrioClientBin64SourcePath = "guest\\runtime\\drio\\bin64\\shrike_drcov_nudge.dll"', script)
        self.assertIn('[string]$DynamoRIOGuestInstallRoot = "C:\\Tools\\DynamoRIO"', script)
        self.assertIn('$DrioClientBin32SourcePath = Resolve-ProjectPath -Path $DrioClientBin32SourcePath -RepoRoot $repoRoot', script)
        self.assertIn('$DrioClientBin64SourcePath = Resolve-ProjectPath -Path $DrioClientBin64SourcePath -RepoRoot $repoRoot', script)
        self.assertIn('$TraceBackendDrioSourcePath = Resolve-ProjectPath -Path $TraceBackendDrioSourcePath -RepoRoot $repoRoot', script)
        self.assertIn('$traceBackendDrioContent = Get-Content -Path $TraceBackendDrioSourcePath -Raw -Encoding UTF8', script)
        self.assertIn('Set-Content -Path "C:\\Sandbox\\runtime\\trace_backend_drio.ps1" -Value $TraceBackendDrioContent -Encoding UTF8', script)
        self.assertIn('Enable-ScheduledTask -TaskName $ScheduledTaskName | Out-Null', script)
        self.assertIn('"dynamorio.dll", "drmgr.dll", "drutil.dll", "drwrap.dll"', script)
        self.assertIn('$runtimeSourceDir = Join-Path $GuestInstallRoot ("lib{0}\\release" -f $libSuffix)', script)
        self.assertIn('$extensionSourceDir = Join-Path $GuestInstallRoot ("ext\\lib{0}\\release" -f $libSuffix)', script)
        self.assertIn('Copy-DrioClientDependencies -Bitness "bin32"', script)
        self.assertIn('Copy-DrioClientDependencies -Bitness "bin64"', script)

    def test_run_task_adds_drio_extension_dependency_dirs_to_path(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn('(Join-Path $drioRoot ("lib{0}\\release" -f $libSuffix))', script)
        self.assertIn('(Join-Path $drioRoot ("ext\\lib{0}\\release" -f $libSuffix))', script)
        self.assertIn('Get-DrioRuntimePathEntries -DrrunPath $drrunPath -ClientDll $clientDll -Is32Bit $is32bit', script)
        self.assertIn('($drioRuntimePathEntries -join ";")', script)

    def test_drio_client_unregisters_instruction_callback_with_existing_api_contract(self) -> None:
        source = (REPO_ROOT / "windows_host" / "drio_client" / "src" / "shrike_drcov_nudge.c").read_text(encoding="utf-8")

        self.assertIn("drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL)", source)
        self.assertIn("drmgr_unregister_bb_instrumentation_event(event_app_instruction)", source)


class DrioBackendTests(unittest.TestCase):
    def test_drio_backend_parses_drcov_text_logs(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "trace_backend_drio.ps1").read_text(encoding="utf-8")

        self.assertIn("function Parse-DrcovTextLog {", script)
        self.assertIn("function Convert-DrcovEntriesToEvents {", script)
        self.assertIn('status = "drcov_basic_blocks"', script)
        self.assertIn('kind = "drcov_text"', script)
        self.assertIn('event = "basic_block"', script)
        self.assertIn('$drcovLogDir = if ($request.drio_log_dir) {', script)

    def test_drio_backend_uses_version5_module_table_columns_for_base_end_and_path(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "trace_backend_drio.ps1").read_text(encoding="utf-8")

        self.assertIn("$parts = $line -split ',\\s*', 10", script)
        self.assertIn("Convert-NumberStringToUInt64 $parts[2]", script)
        self.assertIn("Convert-NumberStringToUInt64 $parts[3]", script)
        self.assertIn("$parts[9].Trim()", script)

    def test_drio_backend_trims_numeric_fields_before_uint64_conversion(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "trace_backend_drio.ps1").read_text(encoding="utf-8")

        self.assertIn("$text = ([string]$Value).Trim()", script)

    def test_drio_backend_summary_uses_explicit_keys_for_unique_modules_and_blocks(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "trace_backend_drio.ps1").read_text(encoding="utf-8")

        self.assertIn("$moduleSeen = @{}", script)
        self.assertIn("$basicBlockSeen = @{}", script)

    def test_drio_backend_emits_process_scoped_ordered_block_samples(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "trace_backend_drio.ps1").read_text(encoding="utf-8")

        self.assertIn('function Get-DrcovLogProcessId {', script)
        self.assertIn('event = "sampled_block_execution"', script)
        self.assertIn('thread_id = $logProcessId', script)
        self.assertIn('kind = "drcov_first_seen_order"', script)

    def test_drio_backend_emits_edges_from_adjacent_first_seen_blocks(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "trace_backend_drio.ps1").read_text(encoding="utf-8")

        self.assertIn('event = "edge"', script)
        self.assertIn('$previousOrderedBlock = $null', script)
        self.assertIn('source = $previousOrderedBlock.start', script)
        self.assertIn('target = $orderedBlockEvent.block_start', script)

    def test_drio_backend_summary_counts_ordered_process_sequences_with_explicit_keys(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "trace_backend_drio.ps1").read_text(encoding="utf-8")

        self.assertIn("$orderedThreadSeen = @{}", script)

    def test_drio_backend_avoids_quadratic_array_appends_on_large_trace_logs(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "trace_backend_drio.ps1").read_text(encoding="utf-8")

        self.assertIn("New-Object System.Collections.Generic.List[object]", script)
        self.assertNotIn("$events += ", script)
        self.assertNotIn("$standardEvents += ", script)
        self.assertNotIn("$allRawEvents += ", script)
        self.assertNotIn("$encodedLines += ", script)

    def test_drio_backend_precomputes_conditional_summary_values_for_windows_powershell(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "trace_backend_drio.ps1").read_text(encoding="utf-8")

        self.assertIn("$summaryStatus = if ($CoverageMode -eq \"control_flow_trace\")", script)
        self.assertIn("$summaryDrioMode = if ($CoverageMode -eq \"control_flow_trace\")", script)
        self.assertIn("$clientBuildId = if ($clientMetadata)", script)
        self.assertIn("$clientBypassAntidebug = if ($clientMetadata)", script)
        self.assertIn("$hasCallGraph = ($callCount -gt 0 -or $retCount -gt 0)", script)
        self.assertIn("$hasIndirectTargets = ($indirectCallCount -gt 0 -or $indirectJumpCount -gt 0)", script)
        self.assertIn("$summaryModules = @(", script)
        self.assertIn("status = $summaryStatus", script)
        self.assertIn("drio_mode = $summaryDrioMode", script)
        self.assertIn("client_build_id = $clientBuildId", script)
        self.assertIn("bypass_antidebug_client = $clientBypassAntidebug", script)
        self.assertIn("has_call_graph = $hasCallGraph", script)
        self.assertIn("has_indirect_targets = $hasIndirectTargets", script)
        self.assertIn("modules = $summaryModules", script)
        self.assertNotIn('status = if ($CoverageMode -eq "control_flow_trace")', script)
        self.assertNotIn('drio_mode = if ($CoverageMode -eq "control_flow_trace")', script)
        self.assertNotIn("client_build_id = if ($clientMetadata)", script)
        self.assertNotIn("bypass_antidebug_client = if ($clientMetadata)", script)


class DrioInstallScriptTests(unittest.TestCase):
    def test_host_installer_copies_and_extracts_dynamorio_zip_into_guest(self) -> None:
        script = (REPO_ROOT / "windows_host" / "powershell" / "10_install_drio.ps1").read_text(encoding="utf-8")

        self.assertIn('[Parameter(Mandatory = $true)]', script)
        self.assertIn('[string]$DynamoRIOZipPath', script)
        self.assertIn('[string]$GuestInstallRoot = "C:\\Tools\\DynamoRIO"', script)
        self.assertIn('$session = New-PSSession -VMName $VmName -Credential $credential', script)
        self.assertIn('Copy-Item -Path $DynamoRIOZipPath -Destination $guestPackagePath -ToSession $session -Force', script)
        self.assertIn('if ($session) {', script)
        self.assertIn('Remove-PSSession -Session $session', script)
        self.assertIn('Expand-Archive -LiteralPath $PackagePath -DestinationPath $expandedRoot -Force', script)
        self.assertIn('Join-Path $InstallRoot "bin64\\drrun.exe"', script)

    def test_wsl_wrapper_invokes_host_drio_installer(self) -> None:
        script = (REPO_ROOT / "sandbox" / "scripts" / "install_drio_runtime.py").read_text(encoding="utf-8")

        self.assertIn('description="Install a DynamoRIO runtime package into the Hyper-V guest from WSL."', script)
        self.assertIn('parser.add_argument("package_path", help="Path to the DynamoRIO Windows zip package.")', script)
        self.assertIn('script = root / "windows_host" / "powershell" / "10_install_drio.ps1"', script)
        self.assertIn('"-DynamoRIOZipPath"', script)


class DrioClientBuildTests(unittest.TestCase):
    def test_host_build_script_compiles_custom_drio_client_for_both_bitnesses(self) -> None:
        script = (REPO_ROOT / "windows_host" / "powershell" / "11_build_drio_nudge_client.ps1").read_text(encoding="utf-8")

        self.assertIn('[string]$DynamoRIOZipPath = "windows_host\\third_party\\DynamoRIO-Windows.zip"', script)
        self.assertIn('[string]$ClientSourcePath = "windows_host\\drio_client\\src\\shrike_drcov_nudge.c"', script)
        self.assertIn("cmake.exe", script)
        self.assertIn('set(CMAKE_CONFIGURATION_TYPES "RelWithDebInfo" CACHE STRING "" FORCE)', script)
        self.assertIn("set(DynamoRIO_USE_LIBC OFF)", script)
        self.assertIn('set(PREFERRED_BASE 0x72000000)', script)
        self.assertIn('configure_DynamoRIO_global(OFF ON)', script)
        self.assertIn('set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /GS- /wd4100 /wd4127 /wd4054")', script)
        self.assertIn("configure_DynamoRIO_client(shrike_drcov_nudge)", script)
        self.assertIn("use_DynamoRIO_extension(shrike_drcov_nudge drmgr)", script)
        self.assertIn("use_DynamoRIO_extension(shrike_drcov_nudge drutil)", script)
        self.assertIn("use_DynamoRIO_extension(shrike_drcov_nudge drwrap)", script)
        self.assertIn('/SUBSYSTEM:CONSOLE,5.02 /OSVERSION:5.02 /GUARD:NO', script)
        self.assertNotIn("/GUARD:CF-", script)
        self.assertNotIn("/GUARD:EHCONT-", script)
        self.assertNotIn("/CETCOMPAT:NO", script)
        self.assertIn("find_package(DynamoRIO REQUIRED)", script)
        self.assertIn("DynamoRIO_DIR", script)
        self.assertNotIn("target_link_libraries(shrike_drcov_nudge ws2_32)", script)
        self.assertNotIn("target_link_libraries(shrike_drcov_nudge drmgr drutil drwrap ws2_32)", script)
        self.assertIn("bin32\\release\\shrike_drcov_nudge.dll", script)
        self.assertIn("bin64\\release\\shrike_drcov_nudge.dll", script)
        self.assertNotIn("cl.exe /nologo /LD /O2 /MT", script)

    def test_custom_drio_client_registers_nudge_callback_and_uses_drmgr(self) -> None:
        script = (REPO_ROOT / "windows_host" / "drio_client" / "src" / "shrike_drcov_nudge.c").read_text(encoding="utf-8")

        self.assertIn('#include "dr_api.h"', script)
        self.assertIn('#include "dr_events.h"', script)
        self.assertIn("dr_register_nudge_event", script)
        self.assertIn("wrap_GetModuleFileNameA_post", script)
        self.assertIn("wrap_GetVersionExA_post", script)
        self.assertIn("wrap_K32EnumProcessModules_post", script)
        self.assertIn('g_enable_peb_unlinking = has_client_option(argc, argv, "-enable_peb_unlinking")', script)
        self.assertIn("PEB unlinking disabled", script)

    def test_custom_drio_client_does_not_link_dead_result_server_socket_path(self) -> None:
        source = (REPO_ROOT / "windows_host" / "drio_client" / "src" / "shrike_drcov_nudge.c").read_text(encoding="utf-8")
        build_script = (REPO_ROOT / "windows_host" / "powershell" / "11_build_drio_nudge_client.ps1").read_text(encoding="utf-8")

        self.assertNotIn("#include <winsock2.h>", source)
        self.assertNotIn("#include <ws2tcpip.h>", source)
        self.assertNotIn("WSAStartup", source)
        self.assertNotIn("result_server", source)
        self.assertNotIn("result_socket", source)
        self.assertNotIn("send(data->result_socket", source)
        self.assertNotIn("target_link_libraries(shrike_drcov_nudge ws2_32)", build_script)

    def test_custom_drio_client_has_execution_triggered_dump_fallback(self) -> None:
        script = (REPO_ROOT / "windows_host" / "drio_client" / "src" / "shrike_drcov_nudge.c").read_text(encoding="utf-8")

        self.assertIn('#include "drmgr.h"', script)
        self.assertIn('#include "dr_ir_utils.h"', script)
        self.assertIn("drmgr_init", script)
        self.assertIn("drmgr_register_bb_instrumentation_event", script)
        self.assertIn("dr_insert_clean_call", script)
        self.assertIn("dr_atomic_add32_return_sum", script)

    def test_custom_drio_client_limits_cfg_instrumentation_to_interesting_code(self) -> None:
        script = (REPO_ROOT / "windows_host" / "drio_client" / "src" / "shrike_drcov_nudge.c").read_text(encoding="utf-8")

        self.assertIn("should_trace_sample_pc", script)
        self.assertIn("should_trace_dynamic_exec_pc", script)
        self.assertIn("should_trace_interesting_pc", script)
        self.assertIn("if (!should_trace_interesting_pc(pc))", script)
        self.assertIn("return DR_EMIT_DEFAULT;", script)

    def test_custom_drio_client_flushes_sample_cfg_events_immediately(self) -> None:
        script = (REPO_ROOT / "windows_host" / "drio_client" / "src" / "shrike_drcov_nudge.c").read_text(encoding="utf-8")

        self.assertIn("if (should_trace_interesting_pc(source))", script)
        self.assertIn("flush_trace_buffer(drcontext, data);", script)

    def test_custom_drio_client_does_not_clobber_app_registers_for_branch_logging(self) -> None:
        script = (REPO_ROOT / "windows_host" / "drio_client" / "src" / "shrike_drcov_nudge.c").read_text(encoding="utf-8")
        branch_block = script[script.index("} else if (instr_is_cbr(inst))") : script.index("} else if (instr_is_ubr(inst)")]

        self.assertNotIn("opnd_create_reg(DR_REG_XAX)", branch_block)
        self.assertNotIn("opnd_create_reg(DR_REG_XCX)", branch_block)
        self.assertNotIn("XINST_CREATE_load_int", branch_block)

    def test_custom_drio_client_does_not_insert_clean_calls_before_conditional_branches(self) -> None:
        script = (REPO_ROOT / "windows_host" / "drio_client" / "src" / "shrike_drcov_nudge.c").read_text(encoding="utf-8")
        branch_block = script[script.index("} else if (instr_is_cbr(inst))") : script.index("} else if (instr_is_ubr(inst)")]

        self.assertNotIn("dr_insert_clean_call", branch_block)
        self.assertIn("instr_is_cbr(inst)", branch_block)

    def test_custom_drio_client_traces_anonymous_executable_regions(self) -> None:
        script = (REPO_ROOT / "windows_host" / "drio_client" / "src" / "shrike_drcov_nudge.c").read_text(encoding="utf-8")

        self.assertIn("dynamic_exec_region", script)
        self.assertIn("dr_query_memory(pc", script)
        self.assertIn("DR_MEMPROT_EXEC", script)
        self.assertIn("dr_lookup_module(pc)", script)
        self.assertIn("should_trace_interesting_pc(pc)", script)

    def test_custom_drio_client_logs_executable_memory_api_events(self) -> None:
        script = (REPO_ROOT / "windows_host" / "drio_client" / "src" / "shrike_drcov_nudge.c").read_text(encoding="utf-8")

        self.assertIn("write_memory_region_event", script)
        self.assertIn('\\"memory_region\\"', script)
        self.assertIn('\\"executable\\"', script)
        self.assertIn("wrap_VirtualAlloc_post", script)
        self.assertIn("wrap_VirtualProtect_post", script)
        self.assertIn("wrap_NtAllocateVirtualMemory_post", script)
        self.assertIn("wrap_NtProtectVirtualMemory_post", script)
        self.assertIn('dr_get_proc_address(kernel32->handle, "VirtualAlloc")', script)
        self.assertIn('dr_get_proc_address(kernel32->handle, "VirtualProtect")', script)
        self.assertIn('dr_get_proc_address(ntdll->handle, "NtAllocateVirtualMemory")', script)
        self.assertIn('dr_get_proc_address(ntdll->handle, "NtProtectVirtualMemory")', script)


class OfflineTaskTimeoutBudgetTests(unittest.TestCase):
    def test_run_offline_task_derives_timeout_from_task_profile_when_unspecified(self) -> None:
        script = (REPO_ROOT / "sandbox" / "scripts" / "run_offline_task.py").read_text(encoding="utf-8")

        self.assertIn("recommended_timeout_seconds", script)
        self.assertIn("args.timeout_seconds if args.timeout_seconds is not None else recommended_timeout_seconds(task_profile_data)", script)
        self.assertIn('print(f"Auto-selected timeout_seconds={effective_timeout_seconds} from task profile budget.")', script)

    def test_run_offline_task_warns_when_manual_timeout_is_below_recommended_budget(self) -> None:
        script = (REPO_ROOT / "sandbox" / "scripts" / "run_offline_task.py").read_text(encoding="utf-8")

        self.assertIn("if recommended_timeout is not None and args.timeout_seconds is not None and args.timeout_seconds < recommended_timeout:", script)
        self.assertIn('print(f"WARNING: requested timeout_seconds={args.timeout_seconds} is below the recommended profile budget {recommended_timeout}.")', script)

    def test_analyze_sample_only_forwards_timeout_when_explicitly_set(self) -> None:
        script = (REPO_ROOT / "sandbox" / "scripts" / "analyze_sample.py").read_text(encoding="utf-8")

        self.assertIn("if args.timeout_seconds is not None:", script)
        self.assertIn('run_cmd.extend(["--timeout-seconds", str(args.timeout_seconds)])', script)

    def test_windows_batch_runner_keeps_powershell_orchestration_on_windows_side(self) -> None:
        script = (REPO_ROOT / "windows_host" / "powershell" / "13_batch_sandbox_wrapped.ps1").read_text(encoding="utf-8")

        self.assertIn("12_run_sandbox_wrapped.ps1", script)
        self.assertIn("Get-RecommendedTimeoutSeconds", script)
        self.assertIn("$effectiveTimeoutSeconds = [Math]::Max($TimeoutSeconds, $recommendedTimeoutSeconds)", script)
        self.assertIn("$effectiveWallTimeoutSeconds = [Math]::Max($WallTimeoutSeconds, ($effectiveTimeoutSeconds + 300))", script)
        self.assertIn("requested TimeoutSeconds={0} is below profile budget {1}; using {2}", script)
        self.assertIn("batch_manifest.jsonl", script)
        self.assertIn("batch_errors.jsonl", script)
        self.assertIn("Test-TraceHealth", script)
        self.assertIn("Copy-WhitelistedArtifacts", script)
        self.assertIn('Start-Process -FilePath "powershell.exe"', script)


class RawArtifactCopyTests(unittest.TestCase):
    def test_copy_raw_artifacts_preserves_nested_drio_logs(self) -> None:
        from parse_artifact import copy_raw_artifacts

        with TemporaryDirectory() as src_tmp, TemporaryDirectory() as dst_tmp:
            src_dir = Path(src_tmp)
            dst_dir = Path(dst_tmp)
            (src_dir / "top.json").write_text("{}", encoding="utf-8")
            drio_dir = src_dir / "drio"
            drio_dir.mkdir()
            (drio_dir / "drcov.sample.0001.proc.log").write_text("DRCOV VERSION: 3\n", encoding="utf-8")

            copied = copy_raw_artifacts(src_dir, dst_dir)

            self.assertIn("top.json", copied)
            self.assertIn("drio/drcov.sample.0001.proc.log", copied)
            self.assertTrue((dst_dir / "drio" / "drcov.sample.0001.proc.log").exists())

    def test_build_summary_classifies_encrypted_and_raw_artifacts(self) -> None:
        with TemporaryDirectory() as tmp:
            artifact_dir = Path(tmp)
            (artifact_dir / "task_summary.json").write_text("{}", encoding="utf-8")
            copied_files = [
                "dynamic_cfg_trace.ndjson",
                "sysmon_file_events.json",
                "process_snapshot_pre.csv.xb7n5",
                "runner.log",
                "xb7n5-readme.txt",
            ]

            summary = build_summary(artifact_dir, copied_files)

            artifacts = summary["artifacts"]
            self.assertEqual(artifacts["encrypted_count"], 1)
            self.assertEqual(artifacts["encrypted_artifacts"][0]["name"], "process_snapshot_pre.csv.xb7n5")
            self.assertEqual(artifacts["encrypted_artifacts"][0]["original_name"], "process_snapshot_pre.csv")
            self.assertIn("dynamic_cfg_trace.ndjson", artifacts["by_category"]["trace"])
            self.assertIn("sysmon_file_events.json", artifacts["by_category"]["sysmon"])
            self.assertIn("runner.log", artifacts["by_category"]["logs"])
            self.assertIn("xb7n5-readme.txt", artifacts["by_category"]["ransom_notes"])

    def test_markdown_report_highlights_encrypted_artifacts_before_raw_groups(self) -> None:
        summary = {
            "task_summary": {},
            "sample_metadata": {"sample_name": "sample.exe"},
            "analysis_quality": {},
            "behavior": {},
            "pre_post_diff": {},
            "related_pids": [],
            "raw_files": [
                "dynamic_cfg_trace.ndjson",
                "sysmon_file_events.json",
                "process_snapshot_pre.csv.xb7n5",
                "runner.log",
            ],
            "artifacts": {
                "total_count": 4,
                "encrypted_count": 1,
                "encrypted_artifacts": [
                    {
                        "name": "process_snapshot_pre.csv.xb7n5",
                        "original_name": "process_snapshot_pre.csv",
                        "family": "xb7n5",
                    }
                ],
                "by_category": {
                    "trace": ["dynamic_cfg_trace.ndjson"],
                    "sysmon": ["sysmon_file_events.json"],
                    "logs": ["runner.log"],
                    "encrypted": ["process_snapshot_pre.csv.xb7n5"],
                },
            },
        }

        report = build_markdown_report(summary)

        self.assertIn("## Extracted Artifacts", report)
        self.assertIn("- Total raw files: `4`", report)
        self.assertIn("- Encrypted artifacts: `1`", report)
        self.assertIn("### Encrypted Artifacts", report)
        self.assertIn("`process_snapshot_pre.csv.xb7n5` original=`process_snapshot_pre.csv` family=`xb7n5`", report)
        self.assertIn("### Raw Artifact Groups", report)
        self.assertIn("- Trace: `1`", report)


class RunTaskCleanupTests(unittest.TestCase):
    def test_run_task_clears_drio_logs_and_staging_before_each_run(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn('$drioLogDirRoot = Join-Path $localOutputRoot "drio_logs"', script)
        self.assertIn('Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue', script)
        self.assertIn('Remove-Item -Path $drioLogDirRoot -Recurse -Force -ErrorAction SilentlyContinue', script)
        self.assertLess(
            script.index('Remove-Item -Path $drioLogDirRoot -Recurse -Force -ErrorAction SilentlyContinue'),
            script.index('Write-RunnerLog ("launching via drrun: {0} {1}" -f $drrunPath, ($drrunArgs -join " "))'),
        )


if __name__ == "__main__":
    unittest.main()
