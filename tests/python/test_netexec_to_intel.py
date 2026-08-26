import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "bin" / "netexec-to-intel"


def make_intel_dir(tmp: str) -> str:
    d = Path(tmp) / "intel"
    d.mkdir(parents=True, exist_ok=True)
    (d / "hosts.yaml").write_text(yaml.dump({
        "hosts": {
            "web01": {"ip": "10.10.10.5", "platform": "linux", "status": "in-scope", "source": {"method": "test"}},
            "dc01": {"ip": "10.10.10.20", "platform": "windows", "status": "in-scope", "source": {"method": "test"}},
        }
    }))
    return str(d)


class TestNetexecToIntel(unittest.TestCase):

    def run_tool(self, input_text: str, *args: str, intel_dir: str | None = None):
        env = {**os.environ}
        if intel_dir:
            env["BRJOTSKEL_INTEL_DIR"] = intel_dir
        return subprocess.run(
            ["python3", str(SCRIPT), "--cred-id", "admin-ntlm", *args],
            input=input_text,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            env=env,
        )

    def test_parses_netexec_successes_and_maps_ips_to_host_ids(self):
        sample = """
SMB         10.10.10.5     445    WEB01    [-] CORP\\admin:bad STATUS_LOGON_FAILURE
SMB         10.10.10.5     445    WEB01    [+] CORP\\admin:hash
WINRM       10.10.10.20    5985   DC01     [+] CORP\\admin:hash (Pwn3d!)
SSH         10.10.10.20    22     DC01     [+] CORP\\admin:hash
"""
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_tool(sample, intel_dir=make_intel_dir(tmp))
        self.assertEqual(result.returncode, 0)
        self.assertIn("# smb 10.10.10.5 -> web01", result.stdout)
        self.assertIn("# winrm 10.10.10.20 -> dc01", result.stdout)
        self.assertIn('intel_update(category="credential", id="admin-ntlm"', result.stdout)
        self.assertIn('fields="valid_on:\\n  - web01\\n  - dc01\\nstatus: confirmed\\n"', result.stdout)
        self.assertIn('summary="admin-ntlm confirmed on web01, dc01 via NetExec"', result.stdout)

    def test_warns_and_uses_ip_for_unmapped_success(self):
        sample = "SMB 10.10.99.9 445 UNKNOWN [+] CORP\\admin:hash\n"
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_tool(sample, intel_dir=make_intel_dir(tmp))
        self.assertEqual(result.returncode, 0)
        self.assertIn("WARNING: 10.10.99.9 not found in hosts.yaml", result.stdout)
        self.assertIn("  - 10.10.99.9", result.stdout)

    def test_no_success_lines_outputs_noop_comment(self):
        result = self.run_tool("SMB 10.10.10.5 445 WEB01 [-] bad\n")
        self.assertEqual(result.returncode, 0)
        self.assertIn("No NetExec success lines found", result.stdout)
        self.assertNotIn("intel_update", result.stdout)


if __name__ == "__main__":
    unittest.main()
