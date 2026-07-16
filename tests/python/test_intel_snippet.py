import subprocess
import unittest
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "bin" / "intel-snippet"


def run_snippet(*args: str) -> str:
    proc = subprocess.run(
        ["python3", str(SCRIPT), *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return proc.stdout


def extract_yaml_block(output: str) -> str:
    start = output.index("=== YAML ===") + len("=== YAML ===")
    end = output.index("=== intel_add ===")
    return output[start:end].strip() + "\n"


class IntelSnippetTests(unittest.TestCase):
    def test_host_endpoint_omits_empty_fields(self):
        output = run_snippet(
            "host-endpoint",
            "--id", "db01",
            "--ip", "10.10.20.10",
            "--platform", "linux",
            "--endpoint", "ssh://deploy@10.10.20.10:22",
        )
        data = yaml.safe_load(extract_yaml_block(output))

        self.assertEqual(data["ip"], "10.10.20.10")
        self.assertEqual(data["platform"], "linux")
        self.assertEqual(data["endpoints"], ["ssh://deploy@10.10.20.10:22"])
        self.assertNotIn("source", data)
        self.assertNotIn("access", data)

    def test_credential_keeps_lists_and_source(self):
        output = run_snippet(
            "credential",
            "--id", "deploy-ssh-key",
            "--type", "ssh-key",
            "--username", "deploy",
            "--key-file", "keys/deploy-ed25519",
            "--valid-on", "db01",
            "--valid-on", "app01",
            "--related-host", "jump01",
            "--source-host", "web01",
            "--source-method", "found in user ssh directory",
        )
        data = yaml.safe_load(extract_yaml_block(output))

        self.assertEqual(data["type"], "ssh-key")
        self.assertEqual(data["valid_on"], ["db01", "app01"])
        self.assertEqual(data["related_hosts"], ["jump01"])
        self.assertEqual(data["source"]["host"], "web01")
        self.assertEqual(data["source"]["method"], "found in user ssh directory")

    def test_psreadline_credential_sets_default_history_path_and_line(self):
        output = run_snippet(
            "psreadline-credential",
            "--id", "aws-token-user1",
            "--type", "token",
            "--username", "user1",
            "--secret", "ABC123",
            "--user-profile", "user1",
            "--line-number", "42",
            "--source-host", "win01",
        )
        data = yaml.safe_load(extract_yaml_block(output))

        self.assertEqual(data["source"]["host"], "win01")
        self.assertEqual(data["source"]["method"], "PSReadLine history")
        self.assertEqual(data["source"]["line_number"], 42)
        self.assertIn("ConsoleHost_history.txt", data["source"]["path"])
        self.assertIn("line 42", data["notes"])

    def test_windows_paths_and_quotes_are_yaml_safe(self):
        output = run_snippet(
            "credential",
            "--id", "svc-pass",
            "--type", "password",
            "--username", "svc_sql",
            "--secret", 'pa:ss"word',
            "--source-path", r"C:\Users\alice\AppData\Roaming\tool\config.txt",
            "--source-method", "config:artifact",
        )
        data = yaml.safe_load(extract_yaml_block(output))

        self.assertEqual(data["secret"], 'pa:ss"word')
        self.assertEqual(data["source"]["path"], r"C:\Users\alice\AppData\Roaming\tool\config.txt")
        self.assertEqual(data["source"]["method"], "config:artifact")

    def test_output_contains_ready_to_paste_intel_add_call(self):
        output = run_snippet(
            "vpn-pivot",
            "--id", "to-vpn-gw",
            "--target", "vpn-gw",
            "--hop", "web01",
            "--config-path", "/etc/openvpn/client.conf",
            "--remote-host", "vpn.corp.local",
            "--remote-port", "1194",
            "--source-host", "web01",
        )

        self.assertIn('intel_add(category="pivot", id="to-vpn-gw"', output)
        self.assertIn("VPN endpoint vpn.corp.local:1194", output)


if __name__ == "__main__":
    unittest.main()
