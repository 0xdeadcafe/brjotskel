import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "bin" / "clean-local"


class TestCleanLocal(unittest.TestCase):

    def test_dry_run_lists_targets_but_does_not_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "temp").mkdir()
            (root / "temp" / "scratch.txt").write_text("x")
            (root / ".pytest_cache").mkdir()
            (root / "pkg" / "__pycache__").mkdir(parents=True)
            (root / "pkg" / "__pycache__" / "m.pyc").write_bytes(b"pyc")
            (root / "logs").mkdir()
            (root / "workspace").mkdir()

            result = subprocess.run(["python3", str(SCRIPT), "--root", str(root)], text=True, capture_output=True)

            self.assertEqual(result.returncode, 0)
            self.assertIn("DRY-RUN", result.stdout)
            self.assertIn("temp", result.stdout)
            self.assertIn(".pytest_cache", result.stdout)
            self.assertIn("case data protected", result.stdout)
            self.assertTrue((root / "temp").exists())
            self.assertTrue((root / "pkg" / "__pycache__").exists())
            self.assertTrue((root / "logs").exists())
            self.assertTrue((root / "workspace").exists())

    def test_execute_removes_generated_targets_but_preserves_case_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "temp").mkdir()
            (root / "temp" / "scratch.txt").write_text("x")
            (root / "pkg" / "__pycache__").mkdir(parents=True)
            (root / "pkg" / "__pycache__" / "m.pyc").write_bytes(b"pyc")
            (root / "logs").mkdir()
            (root / "workspace").mkdir()

            result = subprocess.run(["python3", str(SCRIPT), "--root", str(root), "--execute"], text=True, capture_output=True)

            self.assertEqual(result.returncode, 0)
            self.assertFalse((root / "temp").exists())
            self.assertFalse((root / "pkg" / "__pycache__").exists())
            self.assertTrue((root / "logs").exists())
            self.assertTrue((root / "workspace").exists())

    def test_include_case_data_requires_explicit_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "logs").mkdir()
            (root / "workspace").mkdir()

            result = subprocess.run([
                "python3", str(SCRIPT), "--root", str(root), "--include-case-data", "--execute"
            ], text=True, capture_output=True)

            self.assertEqual(result.returncode, 0)
            self.assertFalse((root / "logs").exists())
            self.assertFalse((root / "workspace").exists())


if __name__ == "__main__":
    unittest.main()
