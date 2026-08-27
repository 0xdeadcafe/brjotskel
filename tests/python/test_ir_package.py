import json
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "bin" / "ir-package"


def make_case(tmp: str, active_cred: bool = True) -> tuple[Path, Path, Path]:
    root = Path(tmp)
    intel = root / "intel"
    logs = root / "logs"
    evidence = root / "evidence.txt"
    intel.mkdir()
    logs.mkdir()
    (intel / "hosts.yaml").write_text(yaml.dump({"hosts": {"web01": {"ip": "10.10.10.5", "status": "compromised", "source": {"method": "test"}}}}))
    creds = {
        "svc-pass": {
            "type": "password",
            "username": "svc",
            "secret": "secret",
            "status": "active" if active_cred else "rotated",
            "source": {"method": "test"},
        }
    }
    (intel / "credentials.yaml").write_text(yaml.dump({"credentials": creds}))
    (intel / "timeline.yaml").write_text(yaml.dump({"timeline": [{"timestamp": "2026-08-27T10:00:00Z", "type": "host", "action": "discovered", "target": "web01", "summary": "found"}]}))
    (logs / "audit-20260827.log").write_text("2026-08-27T10:00:00Z event=test\n")
    evidence.write_text("attacker artifact\n")
    return intel, logs, evidence


def run_package(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["python3", str(SCRIPT), *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        env={**os.environ, **(env or {})},
    )


class IrPackageTests(unittest.TestCase):
    def test_creates_sensitive_tarball_with_report_manifest_logs_intel_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            intel, logs, evidence = make_case(tmp)
            outdir = Path(tmp) / "packages"

            result = run_package(
                "--intel-dir", str(intel),
                "--log-dir", str(logs),
                "--output-dir", str(outdir),
                "--case-id", "case-123",
                "--evidence", str(evidence),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Package:", result.stdout)
            self.assertIn("active/unrotated", result.stderr)

            tarballs = list(outdir.glob("case-123-*-ir-package.tar.gz"))
            self.assertEqual(len(tarballs), 1)
            self.assertEqual(stat.S_IMODE(tarballs[0].stat().st_mode), 0o600)

            with tarfile.open(tarballs[0], "r:gz") as tf:
                names = tf.getnames()
                root = names[0].split("/")[0]
                wanted = {
                    f"{root}/incident-report.md",
                    f"{root}/MANIFEST.json",
                    f"{root}/MANIFEST.sha256",
                    f"{root}/WARNING.txt",
                    f"{root}/intel/hosts.yaml",
                    f"{root}/intel/credentials.yaml",
                    f"{root}/logs/audit-20260827.log",
                    f"{root}/evidence/evidence.txt",
                }
                self.assertTrue(wanted.issubset(set(names)))

                manifest = json.load(tf.extractfile(f"{root}/MANIFEST.json"))
                paths = {entry["path"] for entry in manifest["files"]}
                self.assertIn("incident-report.md", paths)
                self.assertIn("intel/hosts.yaml", paths)
                self.assertTrue(all("sha256" in entry and len(entry["sha256"]) == 64 for entry in manifest["files"]))
                warning = tf.extractfile(f"{root}/WARNING.txt").read().decode()
                self.assertIn("SENSITIVE INCIDENT PACKAGE", warning)
                self.assertIn("svc-pass", warning)
                self.assertIn("Gather logs are not equivalent to credentials.yaml", warning)
                self.assertIn("bin/ir-report --format json --redact-secrets", warning)
                self.assertEqual(manifest["metadata"]["secret_handling"], "Archive is raw credential-bearing evidence; logs may contain secrets outside credentials.yaml.")

    def test_no_active_credential_warning_when_all_terminal(self):
        with tempfile.TemporaryDirectory() as tmp:
            intel, logs, _evidence = make_case(tmp, active_cred=False)
            outdir = Path(tmp) / "packages"

            result = run_package("--intel-dir", str(intel), "--log-dir", str(logs), "--output-dir", str(outdir))

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("no active/unrotated", result.stdout.lower())
            self.assertEqual(result.stderr, "")

    def test_missing_intel_dir_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_package("--intel-dir", str(Path(tmp) / "missing"), "--output-dir", str(Path(tmp) / "packages"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("intel dir not found", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
