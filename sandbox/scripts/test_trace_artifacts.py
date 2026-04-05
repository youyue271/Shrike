from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from parse_artifact import summarize_trace_artifacts
from task_profile import expected_trace_artifacts, validate_task_profile_dict

REPO_ROOT = Path(__file__).resolve().parents[2]


class TraceArtifactSummaryTests(unittest.TestCase):
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
            self.assertEqual(summary["dynamic_cfg"]["ordered_threads"][0]["thread_id"], 101)
            self.assertEqual(
                [sample["block_start"] for sample in summary["dynamic_cfg"]["ordered_threads"][0]["samples"]],
                ["0x140001000", "0x140001020"],
            )
            self.assertEqual(summary["dynamic_cfg"]["ordered_threads"][1]["thread_id"], 202)


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


class GuestRuntimeTraceTimingTests(unittest.TestCase):
    def test_run_task_invokes_trace_collection_before_execution_window_sleep(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")
        export_call = "Export-TraceArtifacts -TaskProfile $taskProfile -TaskRuntimeContext $taskRuntimeContext -ArtifactDir $artifactDir -SampleName $sample.Name -SamplePath $sample.FullName -LaunchedPid $proc.Id -StartedAt $start -EndedAt $plannedTraceEnd"
        sleep_call = "Start-Sleep -Seconds $executionWindowSeconds"

        self.assertIn(export_call, script)
        self.assertIn(sleep_call, script)
        self.assertLess(script.index(export_call), script.index(sleep_call))

    def test_run_task_propagates_sample_path_into_trace_request(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn("[string]$SamplePath", script)
        self.assertIn("sample_path = $SamplePath", script)
        self.assertIn(
            "Export-TraceArtifacts -TaskProfile $taskProfile -TaskRuntimeContext $taskRuntimeContext -ArtifactDir $artifactDir -SampleName $sample.Name -SamplePath $sample.FullName -LaunchedPid $proc.Id -StartedAt $start -EndedAt $plannedTraceEnd",
            script,
        )


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


if __name__ == "__main__":
    unittest.main()
