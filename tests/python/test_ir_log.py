import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "bin" / "ir-log"


class IrLogTests(unittest.TestCase):
    def test_writes_daily_log_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["BRJOTSKEL_LOG_DIR"] = tmpdir
            env["USER"] = "unit-tester"

            subprocess.run(
                ["bash", str(SCRIPT), "checked host 10.0.0.5"],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                text=True,
                capture_output=True,
            )

            files = list(Path(tmpdir).glob("audit-*.log"))
            self.assertEqual(len(files), 1)
            content = files[0].read_text()
            self.assertIn("operator=unit-tester", content)
            self.assertIn(r"event=checked\ host\ 10.0.0.5", content)
            self.assertRegex(content, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z ")

    def test_auth_context_is_logged_when_present(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["BRJOTSKEL_LOG_DIR"] = tmpdir
            env["USER"] = "unit-tester"
            env["BRJOTSKEL_AUTH_CONTEXT"] = "corp\\alice"

            subprocess.run(
                ["bash", str(SCRIPT), "secretsdump against dc01"],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                text=True,
                capture_output=True,
            )

            log_file = next(Path(tmpdir).glob("audit-*.log"))
            content = log_file.read_text()
            self.assertIn(r"auth=corp\\alice", content)
            self.assertIn(r"event=secretsdump\ against\ dc01", content)

    def test_appends_multiple_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["BRJOTSKEL_LOG_DIR"] = tmpdir
            env["USER"] = "unit-tester"

            for event in ("first action", "second action"):
                subprocess.run(
                    ["bash", str(SCRIPT), event],
                    cwd=REPO_ROOT,
                    env=env,
                    check=True,
                    text=True,
                    capture_output=True,
                )

            log_file = next(Path(tmpdir).glob("audit-*.log"))
            lines = [line for line in log_file.read_text().splitlines() if line.strip()]
            self.assertEqual(len(lines), 2)
            self.assertTrue(lines[0].endswith(r"event=first\ action"))
            self.assertTrue(lines[1].endswith(r"event=second\ action"))


if __name__ == "__main__":
    unittest.main()
