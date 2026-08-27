import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


class TestDocsHygiene(unittest.TestCase):

    def test_tool_inventory_checker_passes(self):
        import subprocess
        result = subprocess.run(
            [str(REPO_ROOT / "bin" / "check-tool-inventory")],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("tool inventory check: OK", result.stdout)

    def test_analyst_runbook_is_stub_not_duplicate(self):
        canonical = (REPO_ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")
        alias = (REPO_ROOT / "docs" / "analyst-runbook.md").read_text(encoding="utf-8")
        self.assertIn("[runbook.md](runbook.md)", alias)
        self.assertLess(len(alias), 1000)
        self.assertNotEqual(canonical, alias)


if __name__ == "__main__":
    unittest.main()
