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


def extract_intel_add_kwargs(output: str) -> dict:
    call = output.split("=== intel_add ===", 1)[1].strip()
    captured = {}

    def intel_add(**kwargs):
        captured.update(kwargs)

    exec(call, {"intel_add": intel_add}, {})
    return captured


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

    def test_stringy_secrets_and_summary_are_safe(self):
        output = run_snippet(
            "credential",
            "--id", "strange\\id\"42",
            "--type", "password",
            "--username", "svc",
            "--secret", "true",
            "--notes", "1234\nnull\n2026-08-18",
            "--summary", "quoted \"summary\" with \\ slash\nand newline",
        )
        data = yaml.safe_load(extract_yaml_block(output))
        kwargs = extract_intel_add_kwargs(output)

        self.assertEqual(data["secret"], "true")
        self.assertEqual(data["notes"], "1234\nnull\n2026-08-18")
        self.assertEqual(kwargs["category"], "credential")
        self.assertEqual(kwargs["id"], "strange\\id\"42")
        self.assertEqual(kwargs["summary"], "quoted \"summary\" with \\ slash\nand newline")
        self.assertEqual(yaml.safe_load(kwargs["data"])["secret"], "true")

    def test_kerberos_ticket_tgs_with_cracked_password(self):
        out = run_snippet(
            'kerberos-ticket',
            '--id', 'svc-sql-tgs',
            '--username', 'svc_sql',
            '--domain', 'corp.local',
            '--ticket-type', 'tgs',
            '--spn', 'MSSQLSvc/sql01.corp.local:1433',
            '--cracked-password', 'Winter2024!',
            '--source-host', 'dc01',
        )
        data = yaml.safe_load(extract_yaml_block(out))
        self.assertEqual(data['type'], 'kerberos-tgs')
        self.assertEqual(data['username'], 'svc_sql')
        self.assertEqual(data['domain'], 'corp.local')
        self.assertEqual(data['secret'], 'Winter2024!')
        self.assertIn('MSSQLSvc', data.get('notes', ''))
        kwargs = extract_intel_add_kwargs(out)
        self.assertEqual(kwargs['category'], 'credential')
        self.assertEqual(kwargs['id'], 'svc-sql-tgs')

    def test_kerberos_ticket_asrep_no_crack(self):
        out = run_snippet(
            'kerberos-ticket',
            '--id', 'svc-backup-asrep',
            '--username', 'svc_backup',
            '--domain', 'corp.local',
            '--ticket-type', 'asrep',
            '--ticket-file', 'workspace/intel/tickets/svc_backup.ccache',
            '--source-host', 'dc01',
        )
        data = yaml.safe_load(extract_yaml_block(out))
        self.assertEqual(data['type'], 'kerberos-tgt')
        self.assertNotIn('secret', data)
        self.assertEqual(data['ticket_file'], 'workspace/intel/tickets/svc_backup.ccache')

    def test_cloud_role_aws(self):
        out = run_snippet(
            'cloud-role',
            '--id', 'ec2-prod-role',
            '--provider', 'aws',
            '--role-name', 'EC2-ProdRole-FullS3',
            '--access-key-id', 'ASIAIOSFODNN7EXAMPLE',
            '--secret-access-key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            '--expiry', '2026-08-25T18:00:00Z',
            '--source-host', 'web01',
        )
        data = yaml.safe_load(extract_yaml_block(out))
        self.assertEqual(data['type'], 'token')
        self.assertEqual(data['username'], 'EC2-ProdRole-FullS3')
        self.assertIn('ASIAIOSFODNN7EXAMPLE', data['secret'])
        self.assertIn('aws', data['notes'].lower())
        kwargs = extract_intel_add_kwargs(out)
        self.assertEqual(kwargs['category'], 'credential')

    def test_cloud_role_azure(self):
        out = run_snippet(
            'cloud-role',
            '--id', 'azure-mi-webapp',
            '--provider', 'azure',
            '--role-name', 'webapp-managed-identity',
            '--token', 'eyJ0eXAiOiJKV1Qi...',
            '--source-host', 'webapp01',
        )
        data = yaml.safe_load(extract_yaml_block(out))
        self.assertEqual(data['type'], 'token')
        self.assertIn('azure', data['notes'].lower())


if __name__ == "__main__":
    unittest.main()
