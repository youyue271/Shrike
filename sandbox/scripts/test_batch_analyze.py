from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from batch_analyze import is_terminal_drrun_failure, trace_health


class BatchAnalyzeHealthTests(unittest.TestCase):
    def test_trace_health_accepts_control_flow_trace(self) -> None:
        with TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            raw = report_dir / "raw"
            raw.mkdir()
            (raw / "dynamic_cfg_trace.ndjson").write_text("{}\n", encoding="utf-8")
            (raw / "trace_manifest.json").write_text(
                json.dumps({"status": "control_flow_trace"}),
                encoding="utf-8",
            )

            ok, detail = trace_health(report_dir)

            self.assertTrue(ok)
            self.assertEqual(detail, "control_flow_trace")

    def test_trace_health_rejects_basic_block_only_trace(self) -> None:
        with TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            raw = report_dir / "raw"
            raw.mkdir()
            (raw / "dynamic_cfg_trace.ndjson").write_text("{}\n", encoding="utf-8")
            (raw / "trace_manifest.json").write_text(
                json.dumps({"status": "drcov_basic_blocks"}),
                encoding="utf-8",
            )

            ok, detail = trace_health(report_dir)

            self.assertFalse(ok)
            self.assertEqual(detail, "trace_status=drcov_basic_blocks")

    def test_trace_health_reports_drrun_client_api_mismatch(self) -> None:
        with TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            raw = report_dir / "raw"
            raw.mkdir()
            (raw / "dynamic_cfg_trace.ndjson").write_text("{}\n", encoding="utf-8")
            (raw / "trace_manifest.json").write_text(
                json.dumps({"status": "seeded_from_runtime_metadata"}),
                encoding="utf-8",
            )
            (raw / "drrun_stderr.txt").write_text(
                "Client library targets an incompatible API version and should be re-compiled.\n",
                encoding="utf-8",
            )

            ok, detail = trace_health(report_dir)

            self.assertFalse(ok)
            self.assertIn("trace_status=seeded_from_runtime_metadata", detail)
            self.assertIn("drrun_stderr=Client library targets an incompatible API version", detail)

    def test_drrun_loader_initializer_failure_is_terminal(self) -> None:
        self.assertTrue(
            is_terminal_drrun_failure(
                "exit=0 health=trace_status=seeded_from_runtime_metadata "
                "drrun_stderr=<Application C:\\Sandbox\\input\\sample.exe (5336). "
                "Unable to load client library: shrike_drcov_nudge.dll: library initializer failed..>"
            )
        )

    def test_drrun_missing_trace_is_not_terminal(self) -> None:
        self.assertFalse(is_terminal_drrun_failure("exit=1 health=dynamic_cfg_trace.ndjson missing"))


if __name__ == "__main__":
    unittest.main()
