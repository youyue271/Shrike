from __future__ import annotations

import base64
import json
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from result_server import ResultServer


class ResultServerArtifactTests(unittest.TestCase):
    def test_artifact_message_writes_named_file_from_base64_content(self) -> None:
        with TemporaryDirectory() as tmp:
            server = ResultServer(output_dir=tmp)
            payload = {
                "type": "artifact",
                "name": "process_snapshot_pre.csv",
                "content_base64": base64.b64encode(b"Name,ProcessId\nsample.exe,4016\n").decode("ascii"),
            }

            self.assertTrue(server.process_json_message(json.dumps(payload), None))

            artifact = Path(tmp) / "process_snapshot_pre.csv"
            self.assertEqual(artifact.read_text(encoding="utf-8"), "Name,ProcessId\nsample.exe,4016\n")

    def test_artifact_message_rejects_path_traversal(self) -> None:
        with TemporaryDirectory() as tmp:
            server = ResultServer(output_dir=tmp)
            payload = {
                "type": "artifact",
                "name": "../outside.txt",
                "content": "bad",
            }

            with self.assertRaises(ValueError):
                server.process_json_message(json.dumps(payload), None)

            self.assertFalse((Path(tmp).parent / "outside.txt").exists())


if __name__ == "__main__":
    unittest.main()
