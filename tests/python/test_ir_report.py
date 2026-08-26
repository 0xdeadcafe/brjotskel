import subprocess
import json
import os
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "bin" / "ir-report"


def run_report(*args: str, intel_dir: str | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ}
    if intel_dir:
        env["BRJOTSKEL_INTEL_DIR"] = intel_dir
    return subprocess.run(
        ["python3", str(SCRIPT), *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        env=env,
    )


def make_intel_dir(tmp: str, hosts=None, credentials=None,
                   accounts=None, pivots=None, timeline=None) -> str:
    d = Path(tmp) / "intel"
    d.mkdir(parents=True, exist_ok=True)
    if hosts is not None:
        (d / "hosts.yaml").write_text(yaml.dump({"hosts": hosts}))
    if credentials is not None:
        (d / "credentials.yaml").write_text(yaml.dump({"credentials": credentials}))
    if accounts is not None:
        (d / "accounts.yaml").write_text(yaml.dump({"accounts": accounts}))
    if pivots is not None:
        (d / "pivots.yaml").write_text(yaml.dump({"paths": pivots}))
    if timeline is not None:
        (d / "timeline.yaml").write_text(yaml.dump({"timeline": timeline}))
    return str(d)


class TestIrReportBasic(unittest.TestCase):

    def test_missing_intel_dir_exits_nonzero(self):
        result = run_report("--intel-dir", "/nonexistent/path")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not found", result.stderr.lower())

    def test_empty_store_produces_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "intel"
            d.mkdir()
            result = run_report(intel_dir=str(d))
            self.assertEqual(result.returncode, 0)
            self.assertIn("# Incident Report", result.stdout)
            self.assertIn("Executive Summary", result.stdout)

    def test_markdown_contains_expected_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_intel_dir(
                tmp,
                hosts={"web01": {"ip": "10.10.10.5", "platform": "linux", "status": "compromised",
                                  "source": {"method": "test"}}},
                credentials={"deploy-key": {"type": "ssh-key", "username": "deploy",
                                             "status": "active", "source": {"method": "test"},
                                             "key_file": "keys/k"}},
                timeline=[{"ts": "2026-08-25T10:00:00Z", "type": "host", "action": "discovered",
                            "target": "web01", "summary": "Initial host"}],
            )
            result = run_report(intel_dir=d)
            self.assertEqual(result.returncode, 0)
            out = result.stdout
            self.assertIn("## Executive Summary", out)
            self.assertIn("## Host Inventory", out)
            self.assertIn("## Credential Chain", out)
            self.assertIn("## Timeline", out)
            self.assertIn("web01", out)
            self.assertIn("deploy-key", out)

    def test_full_markdown_uses_timestamp_timeline_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_intel_dir(
                tmp,
                timeline=[
                    {"timestamp": "2026-08-25T10:00:00Z", "type": "host", "action": "discovered",
                     "target": "web01", "summary": "Initial host"},
                    {"timestamp": "2026-08-25T11:30:00Z", "type": "credential", "action": "confirmed",
                     "target": "admin-ntlm", "summary": "Hash confirmed"},
                ],
            )
            result = run_report(intel_dir=d)
            self.assertEqual(result.returncode, 0)
            self.assertIn("| Investigation start | 2026-08-25T10:00:00Z |", result.stdout)
            self.assertIn("| Last activity | 2026-08-25T11:30:00Z |", result.stdout)

    def test_rotation_warning_for_active_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_intel_dir(
                tmp,
                credentials={"admin-hash": {"type": "ntlm-hash", "username": "admin",
                                             "status": "active", "source": {"method": "test"},
                                             "secret": "aad3b..."}},
            )
            result = run_report(intel_dir=d)
            self.assertEqual(result.returncode, 0)
            self.assertIn("rotation", result.stdout.lower())

    def test_no_rotation_warning_for_terminal_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_intel_dir(
                tmp,
                credentials={"old-key": {"type": "ssh-key", "username": "deploy",
                                          "status": "rotated", "source": {"method": "test"},
                                          "key_file": "keys/k"}},
            )
            result = run_report(intel_dir=d)
            self.assertEqual(result.returncode, 0)
            # No urgent rotation warning for terminal credentials
            self.assertNotIn("require rotation", result.stdout)

    def test_json_format_is_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_intel_dir(
                tmp,
                hosts={"db01": {"ip": "10.10.20.10", "platform": "linux",
                                 "status": "cleared", "source": {"method": "test"}}},
            )
            result = run_report("--format", "json", intel_dir=d)
            self.assertEqual(result.returncode, 0)
            parsed = json.loads(result.stdout)
            self.assertIn("hosts", parsed)
            self.assertIn("credentials", parsed)
            self.assertIn("timeline", parsed)
            self.assertIn("generated_at", parsed)

    def test_json_contains_host_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_intel_dir(
                tmp,
                hosts={"dc01": {"ip": "10.10.20.20", "platform": "windows",
                                 "status": "compromised", "source": {"method": "test"}}},
            )
            result = run_report("--format", "json", intel_dir=d)
            self.assertEqual(result.returncode, 0)
            parsed = json.loads(result.stdout)
            self.assertIn("dc01", parsed["hosts"])

    def test_output_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_intel_dir(tmp)
            out_file = Path(tmp) / "report.md"
            result = run_report("--output", str(out_file), intel_dir=d)
            self.assertEqual(result.returncode, 0)
            self.assertTrue(out_file.exists())
            content = out_file.read_text()
            self.assertIn("# Incident Report", content)

    def test_accounts_section_present_when_accounts_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_intel_dir(
                tmp,
                accounts={"corp\\backdoor": {"type": "domain", "username": "backdoor",
                                              "domain": "corp.local", "status": "compromised",
                                              "source": {"method": "test"},
                                              "attacker_use": "backdoor DA"}},
            )
            result = run_report(intel_dir=d)
            self.assertEqual(result.returncode, 0)
            self.assertIn("Accounts of Interest", result.stdout)
            self.assertIn("backdoor", result.stdout)

    def test_pivot_section_present_when_pivots_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_intel_dir(
                tmp,
                pivots={"to-dc01": {"target": "dc01", "status": "active",
                                     "chain": [{"hop": "web01", "method": "ssh-tunnel"}],
                                     "source": {"method": "test"}}},
            )
            result = run_report(intel_dir=d)
            self.assertEqual(result.returncode, 0)
            self.assertIn("Pivot Paths", result.stdout)
            self.assertIn("to-dc01", result.stdout)


    def test_short_format_contains_key_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_intel_dir(
                tmp,
                hosts={
                    "web01": {"ip": "10.10.10.5", "platform": "linux",
                              "status": "compromised", "source": {"method": "test"}},
                    "db01": {"ip": "10.10.20.10", "platform": "linux",
                             "status": "cleared", "source": {"method": "test"}},
                },
                credentials={
                    "admin-hash": {"type": "ntlm-hash", "username": "admin",
                                   "status": "active", "source": {"method": "test"},
                                   "secret": "aad3b...", "valid_on": ["web01"]},
                    "old-cred": {"type": "password", "username": "svc",
                                 "status": "rotated", "source": {"method": "test"},
                                 "secret": "x"},
                },
                timeline=[
                    {"ts": "2026-08-25T10:00:00Z", "type": "host",
                     "action": "discovered", "target": "web01", "summary": "Initial host"},
                ],
            )
            result = run_report("--short", intel_dir=d)
            self.assertEqual(result.returncode, 0)
            out = result.stdout
            # Key sections present
            self.assertIn("INCIDENT BRIEF", out)
            self.assertIn("ROTATION REQUIRED", out)
            self.assertIn("admin-hash", out)
            # Rotated credential should NOT appear in rotation list
            self.assertNotIn("old-cred", out)
            # Should NOT contain full timeline or host inventory tables
            self.assertNotIn("## Timeline", out)
            self.assertNotIn("## Host Inventory", out)

    def test_short_format_no_rotation_when_all_terminal(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_intel_dir(
                tmp,
                credentials={
                    "done": {"type": "password", "username": "svc",
                             "status": "rotated", "source": {"method": "test"}, "secret": "x"},
                },
            )
            result = run_report("--short", intel_dir=d)
            self.assertEqual(result.returncode, 0)
            self.assertNotIn("ROTATION REQUIRED", result.stdout)
            self.assertIn("No credentials pending rotation", result.stdout)

    def test_short_and_full_are_different(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_intel_dir(
                tmp,
                hosts={"h": {"ip": "1.2.3.4", "platform": "linux",
                              "status": "compromised", "source": {"method": "t"}}},
                credentials={"c": {"type": "password", "username": "u",
                                   "status": "active", "source": {"method": "t"}, "secret": "s"}},
            )
            short_result = run_report("--short", intel_dir=d)
            full_result  = run_report(intel_dir=d)
            self.assertEqual(short_result.returncode, 0)
            self.assertEqual(full_result.returncode, 0)
            # Short output should be substantially smaller
            self.assertLess(len(short_result.stdout), len(full_result.stdout))


if __name__ == "__main__":
    unittest.main()
