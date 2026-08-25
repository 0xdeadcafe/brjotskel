# Changelog

All notable changes to brjotskel are documented here.

Format: each entry lists the version, release date (or "unreleased"), and a summary of what changed. Changes within a section are ordered by user impact.

---

## [0.3.0] — 2026-08-25

### Added

**Incident report export**
- `bin/ir-report` — generates a structured markdown or JSON incident report directly from the intel store. Covers executive summary, host inventory, credential chain, pivot paths, timeline, and rotation requirements. Output to stdout or a file via `--output`.

**macOS eradication coverage**
- `eradication-playbooks/macos/remove-cron.sh` — crontab and /etc/cron.d removal
- `eradication-playbooks/macos/remove-profile-hook.sh` — .zshrc, .zprofile, .zlogin, /etc/profile.d/ hook removal
- `eradication-playbooks/macos/remove-ssh-key.sh` — attacker SSH key removal from authorized_keys (dscl home resolution)
- `eradication-playbooks/macos/remove-btm-login-item.sh` — BTM login items (macOS 13+) and legacy login items

**Network scan → intel store**
- `intel_scan` tool — runs nmap from the harness, parses greppable output, and auto-populates the intel store with discovered hosts (status: `in-scope`, platform inferred from open ports)

**Credential validation hint on discovery**
- `intel_add` for `category="credential"` now appends a ready-to-run `netexec` validation command to the result when known host IPs exist in the intel store

**WinRM over HTTPS**
- `remote_connect` for WinRM now accepts `use_ssl=true` and `skip_cert_check=true` parameters for environments using HTTPS-only WinRM or self-signed certificates

**macOS host IR**
- `host-ir-playbooks/macos/initial-assessment.sh` — attacker-perspective investigation: non-Apple persistence, unified log spawn/exec/auth, suspicious process paths, credential exposure, security state

**macOS containment**
- `containment-playbooks/macos/disable-account.sh` — evidence-first account disablement via dscl

### Fixed
- `docs/analyst-runbook.md` — removed hashcat-inside-container framing; Kerberoasting hash files are now correctly documented as external-cracking workflow via mounted `workspace/`

### Documentation
- Added `docs/getting-started.md`, `docs/scenario-walkthrough.md`, `docs/playbooks.md`, `docs/README.md`
- Moved contributing guide to `CONTRIBUTING.md` at root
- README rewritten with product-first structure and differentiation table
- `docs/analyst-improvement-plan.md` replaced with redirect stub

### Tests
- `tests/node/tunnel-manager.test.mjs` (8 tests) — closeTunnel, closeAllTunnels lifecycle
- `tests/node/relay-manager.test.mjs` (9 tests) — setupRelay/teardownRelay orchestration
- `tests/node/intel-scan.test.mjs` (10 tests) — nmap greppable parser, platform inference
- `tests/python/test_ir_report.py` (10 tests) — ir-report output validation

---

## [0.2.0] — 2026-07-22

### Added

**Playbook coverage**
- Linux gather: `collect-evidence.sh`, `enum-cloud-credentials.sh`, `enum-reachability.sh` (19 total)
- Windows gather: `collect-evidence.ps1`, `lsass-dump.ps1`, `enum-av-exclusions.ps1`, `enum-reachability.ps1` (27 total)
- macOS gather: `collect-evidence.sh` (10 total)
- Host IR Linux: `integrity-check.sh`
- Host IR Windows: `integrity-check.ps1`
- Network device CLI references: Cisco IOS, NX-OS, Juniper JunOS

**Intelligence**
- `/scope` slash command — situational dump
- `/map` + `intel_map` — text attack graph with blast radius edges
- `intel_timeline` filtering — by host, category, action, since
- Cloud credential enumeration — EC2/Azure/GCP IMDS + `intel-snippet cloud-role`
- Kerberoasting + AS-REP roast workflows (GetUserSPNs.py, GetNPUsers.py) in runbook
- `bin/intel-snippet kerberos-ticket` subcommand

**Tooling**
- `ir-search` — fzf-based interactive search across audit and session logs (JSONL and text)
- `bin/ir-log` JSONL output mode via `BRJOTSKEL_LOG_FORMAT=jsonl`

**Architecture**
- `remote-session.ts` refactored 1,827 → 1,219 lines; extracted to `lib/protocol-adapters/`, `lib/tunnel-manager.ts`, `lib/relay-manager.ts`
- Executable bit policy enforced by `bin/smoke-check`

---

## [0.1.0] — 2026-07-08

### Initial release

- AI agent with Ghost IR persona and live intel state injection
- Persistent remote sessions: SSH, WinRM, TCP, telnet
- SSH tunnels (local, remote, dynamic SOCKS) + native TCP relays
- Structured intel store: hosts, credentials, accounts, pivots, timeline with lifecycle validation
- Phase shortcuts: `/land`, `/assess`, `/pursue`, `/contain`, `/eradicate`, `/verify`
- Linux gather playbooks (16), Windows gather playbooks (24), macOS gather playbooks (9)
- Containment playbooks: Linux/Windows/macOS (kill-process, block-c2, disable-account, isolate-host)
- Eradication playbooks: Linux/Windows/macOS
- Privilege escalation assessment: Linux/Windows/macOS
- `bin/intel-snippet` — normalized intel_add generation with schema validation
- CONSTITUTION.md safety model and rules of engagement

---

## Versioning

brjotskel uses [Semantic Versioning](https://semver.org/). The version is embedded in the Docker image as a `LABEL` and can be read at runtime:

```sh
docker inspect brjotskel:local --format '{{ index .Config.Labels "version" }}'
```

To bump the version when releasing:
1. Update the `LABEL version=` in `Dockerfile`
2. Add an entry to this file
3. Tag the commit: `git tag v0.x.0`
