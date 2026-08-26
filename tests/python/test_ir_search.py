import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "bin" / "ir-search"


class IrSearchTests(unittest.TestCase):

    def test_record_hit_appends_timestamped_selection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["BRJOTSKEL_LOG_DIR"] = tmpdir

            result = subprocess.run(
                ["bash", str(SCRIPT), "--record-hit", "audit-20260825.log  2026-08-25T10:00:00Z event=netexec"],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                text=True,
                capture_output=True,
            )

            hits = Path(tmpdir) / "ir-search-hits.txt"
            self.assertTrue(hits.exists())
            line = hits.read_text().strip()
            self.assertRegex(line, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\t")
            self.assertIn("audit-20260825.log", line)
            self.assertIn("event=netexec", line)
            self.assertIn(str(hits), result.stdout)

    def test_record_hit_honors_custom_hits_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            custom = Path(tmpdir) / "workspace" / "hits.txt"
            env = os.environ.copy()
            env["BRJOTSKEL_LOG_DIR"] = str(Path(tmpdir) / "logs")
            env["BRJOTSKEL_IR_SEARCH_HITS"] = str(custom)

            subprocess.run(
                ["bash", str(SCRIPT), "--record-hit", "session.log  whoami"],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                text=True,
                capture_output=True,
            )

            self.assertTrue(custom.exists())
            self.assertIn("session.log  whoami", custom.read_text())

    def test_no_clipboard_tools_in_enter_bind(self):
        content = SCRIPT.read_text()
        self.assertNotIn("xclip", content)
        self.assertNotIn("pbcopy", content)
        self.assertIn("--record-hit", content)
        self.assertIn("Enter=save hit", content)

    def test_record_hit_requires_selection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["BRJOTSKEL_LOG_DIR"] = tmpdir
            result = subprocess.run(
                ["bash", str(SCRIPT), "--record-hit"],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("Usage:", result.stderr)
            self.assertFalse((Path(tmpdir) / "ir-search-hits.txt").exists())


if __name__ == "__main__":
    unittest.main()
