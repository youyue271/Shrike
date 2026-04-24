from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


class GuestRuntimeOfflineLaunchTests(unittest.TestCase):
    def test_run_task_uses_extensionless_pe_launch_copy_for_offline_mode(self) -> None:
        script = (REPO_ROOT / "guest" / "runtime" / "run_task.ps1").read_text(encoding="utf-8")

        self.assertIn("function Test-PeExecutableFile {", script)
        self.assertIn("function Resolve-SampleLaunchPath {", script)
        self.assertIn('if ([string]::IsNullOrWhiteSpace($extension) -and (Test-PeExecutableFile -Path $Sample.FullName)) {', script)
        self.assertIn('$launchPath = Join-Path $Sample.DirectoryName ("{0}.exe" -f $Sample.Name)', script)
        self.assertIn('Write-RunnerLog ("created extensionless PE launch copy {0} -> {1}" -f $Sample.FullName, $launchPath)', script)
        self.assertIn("$launchTarget = Resolve-SampleLaunchPath -Sample $sample", script)
        self.assertIn("$proc = Start-Process -FilePath $launchTarget.LaunchPath -PassThru", script)
        self.assertIn("launch_path = $launchTarget.LaunchPath", script)
        self.assertIn("launch_source_path = $sample.FullName", script)


if __name__ == "__main__":
    unittest.main()
