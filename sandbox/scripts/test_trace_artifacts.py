from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from parse_artifact import summarize_trace_artifacts
from task_profile import expected_trace_artifacts, validate_task_profile_dict


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
            }
        )


if __name__ == "__main__":
    unittest.main()
