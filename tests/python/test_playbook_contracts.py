import os
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = REPO_ROOT / "bin" / "check-playbook-contracts"
LINUX_FIRST_LOOK = REPO_ROOT / ".pi" / "skills" / "gather-playbooks" / "linux" / "first-look.sh"
CISCO_IOS = REPO_ROOT / ".pi" / "skills" / "gather-playbooks" / "network-device" / "cisco-ios.sh"
WIN_HASHDUMP = REPO_ROOT / ".pi" / "skills" / "gather-playbooks" / "windows" / "hashdump.ps1"
WIN_LSASS = REPO_ROOT / ".pi" / "skills" / "gather-playbooks" / "windows" / "lsass-dump.ps1"


class PlaybookContractTests(unittest.TestCase):

    def test_contract_checker_passes_for_operator_playbooks(self):
        result = subprocess.run(
            [str(CONTRACTS)],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn("playbook contract check: OK (101 scripts", result.stdout)
        self.assertIn("sensitive-output labeled", result.stdout)

    def test_representative_linux_readonly_script_executes(self):
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        result = subprocess.run(
            ["sh", str(LINUX_FIRST_LOOK)],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("=== IDENTITY & HOST ===", result.stdout)
        self.assertIn("=== WHO IS ON RIGHT NOW ===", result.stdout)
        self.assertIn("=== LISTENING SERVICES ===", result.stdout)

    def test_network_device_reference_contains_actionable_commands(self):
        content = CISCO_IOS.read_text()
        self.assertIn("show users", content)
        self.assertIn("show tcp brief", content)
        self.assertIn("show running-config", content)
        self.assertIn("Sensitive-output: YES", content)

    def test_high_impact_windows_credential_dumps_require_confirmation(self):
        for path in (WIN_HASHDUMP, WIN_LSASS):
            with self.subTest(path=path.name):
                content = path.read_text()
                self.assertIn("Confirmation: set $ConfirmDump = $true", content)
                self.assertIn("Get-Variable -Name ConfirmDump", content)
                self.assertIn("exit 1", content)


if __name__ == "__main__":
    unittest.main()
