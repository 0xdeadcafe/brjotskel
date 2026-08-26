# TODO

Product backlog and engineering roadmap. Ghost review pass — attacker-first framing throughout.

> **Test status:** `bash bin/test` — 41 Python + 95 Node tests, all passing. Docker smoke build is configured in CI; rerun locally after dependency pinning or Dockerfile changes.

---

## Priority lens

- **P0**: blocks safe operation now or creates uncontrolled evidence/secret exposure by default.
- **P1**: fix before the next real incident image is trusted — reproducibility, integrity, report correctness.
- **P2**: high operator leverage — reduces manual misses and closes workflow gaps.
- **P3**: simplification, drift control, developer ergonomics, bloat reduction.

## Recommended execution order

1. **#44** — P0. Stop default raw secret sprawl. Current Linux/cloud/credential gather paths can leak usable material into session logs.
2. **#14** — P1. Pin the build before trusting a new incident image. Reproducibility is part of evidence credibility.
3. **#48** — P2. Package evidence/reports after #44, so archives do not preserve today’s secret leakage.
4. **#20** — P3. Cheap image-size/CI cleanup; safe to batch with #14 if already editing Dockerfile.
5. **#52** — P3. Defer tmux backend as a prototype only; useful for SSH/telnet, risky until secret-output policy is settled.

---

## 🔴 P0 — Blocker

### 44. Secret handling is split-brain: gather scripts dump secrets into logs, intel store separately stores secrets

Credential recovery currently means secrets often appear in remote session logs, then the operator manually copies them into `workspace/intel` and `intel_add`. That creates two secret stores: intel and logs. Current defaults are too hot: Linux `ssh-keys.sh` and `triage.sh` can print private keys, Linux/cloud scripts can print static keys/tokens, and Windows credential/cloud/LAPS paths can print usable credential material. This expands rotation scope to operator logs, report packages, terminal scrollback, and any copied transcript.

- **Risk:** Dirty by default. A normal gather run can leak usable credentials into long-lived logs before the operator chooses to promote them into intel.
- **Action:** Define a secret-output policy: default output fingerprints/paths/context/redacted values only; raw material requires explicit `--reveal` or clearly named reveal scripts. Add a promotion path that writes recovered key/token material to `workspace/intel/keys/` or `workspace/intel/secrets/` with 0600 permissions and records provenance. Update gather scripts and docs to match. Add tests/grep guard for banned default raw-secret patterns where practical.
- **Files:** `.pi/skills/gather-playbooks/linux/ssh-keys.sh`, `.pi/skills/gather-playbooks/linux/triage.sh`, `.pi/skills/gather-playbooks/linux/enum-cloud-credentials.sh`, `.pi/skills/gather-playbooks/macos/ssh-keys.sh`, `.pi/skills/gather-playbooks/windows/enum-credentials.ps1`, `.pi/skills/gather-playbooks/windows/enum-cloud-credentials.ps1`, `.pi/skills/gather-playbooks/windows/enum-ad.ps1`, `docs/runbook.md`, `docs/intel-import-workflow.md`, `bin/smoke-check`

---

## 🟠 P1 — Fix before the next incident image is trusted

### 14. Pin Docker builds — supply chain risk

NetExec installs from GitHub HEAD. pi installs from npm latest. A CI build can silently change behavior. For a security tool, non-reproducible builds are a credibility problem.

- **Action:** Pin NetExec to a specific commit/tag. Pin pi to a specific npm version. Pin Impacket to a version. Pin Node with `.nvmrc` and a Docker `ARG NODE_MAJOR`/version note matching CI. Document update cadence and a deliberate dependency-bump workflow.
- **Files:** `Dockerfile`, `.nvmrc`, `.github/workflows/ci.yml`, README or CONTRIBUTING update cadence note

---

## 🟡 P2 — High operator leverage

### 48. Evidence packaging should move from strategic idea to operator workflow

At incident close, I need to hand off `workspace/intel`, audit logs, session logs, reports, and selected evidence. Today that is manual. Manual packaging means missed files and uncontrolled secret sprawl. This is core IR hygiene, not long-term wishlist.

- **Dependency:** Do after #44. Packaging before secret-output cleanup just formalizes dirty logs into an archive.
- **Action:** Build `bin/ir-package`: generate `ir-report`, collect intel/logs/evidence into a timestamped tarball, produce a manifest with SHA-256 hashes, and warn if active/unrotated credentials remain. Keep signing optional if no key is configured.
- **Files:** `bin/ir-package`, `tests/python/test_ir_package.py`, `docs/runbook.md`, `README.md`

---

## 🟢 P3 — Simplify / de-risk maintenance

### 20. Make nvim config optional in the image

Adds image weight in non-interactive/CI deployments. Low risk and cheap after higher-risk incident workflow fixes.

- **Action:** `ARG INCLUDE_NVIM_CONFIG=true`, conditional `COPY`. Keep default as `true`.
- **Files:** `Dockerfile`, `.config/nvim/**`

---

### 52. Consider tmux-backed remote sessions for simpler interaction + capture

Past operator workflow used tmux capture for SSH/telnet. That model is attractive: one terminal owns the real interactive session, the agent sends keys, and capture-pane/pipe-pane becomes the log. It could simplify telnet/network-device handling and let humans attach to the same live session.

Risks: command-boundary detection is harder than pipe markers, scrollback can truncate evidence, secrets stay in terminal history, concurrent `remote_exec` calls can race, and WinRM/PowerShell remoting should likely stay on the current command-oriented adapter.

- **Dependency:** Do after #44. tmux scrollback/pipe-pane can amplify raw-secret leakage if reveal/default modes are not clear.
- **Action:** Prototype optional `tmux` backend for SSH/telnet/network-device only: spawn session in named window/pane, `pipe-pane` to `${BRJOTSKEL_LOG_DIR}/remote-sessions`, send commands via `tmux send-keys`, collect output via `capture-pane`, and compare reliability against current marker-based adapter. Keep WinRM/PowerShell on the command adapter.
- **Files:** `.pi/extensions/remote-session.ts`, `.pi/extensions/lib/protocol-adapters/**`, `Dockerfile` (tmux), `tests/node/**`, `docs/architecture.md`

---

## Strategic / longer-term

**Cloud-native IR.** EC2/Azure/GCP SDK-based collection — not just IMDS metadata, but IAM policy enumeration, CloudTrail review, S3 access log analysis, Security Hub findings ingestion. The current cloud credential scripts find the token; they don't investigate what that token can reach.

---

## Validated strengths — preserve these

- **CONSTITUTION.md** defines the safety model clearly. Don't let it drift or become aspirational.
- **Phase shortcuts** (`/land` → `/verify`) are the right mental model. Keep the phase structure.
- **Full-platform isolation** — Linux (iptables), Windows (Firewall default-block), macOS (pf). All three platforms now have the complete containment suite. Keep this symmetry.
- **Intel store lifecycle enforcement** — credentials can't be retrieved post-rotation, lifecycle transitions are validated. This is correct behavior; don't soften it.
- **Evidence-first pattern** in every containment and eradication script. Non-negotiable.
- **Native-OS-only playbooks** — no third-party binary uploads to targets. Temporary script text staging is allowed with cleanup.
- **Audit logging** — every session, command, and finding is timestamped and logged. The reconstruction capability is a key differentiator.
- **`intel-snippet`** normalized intel_add generation — reduces schema errors under pressure.
- **`/scope` → `/map` → `/pursue` loop** — the right situational awareness rhythm. Keep it tight.

---

## Completed (archive)

<details>
<summary>P2 — #26 resolved</summary>

- ✅ **#26** Replaced the dead headless clipboard bind in `bin/ir-search`. Enter now saves the selected line to `${BRJOTSKEL_LOG_DIR:-logs}/ir-search-hits.txt` (or `BRJOTSKEL_IR_SEARCH_HITS`) with a UTC timestamp and still prints/accepts the selection. Added `--record-hit` helper coverage and updated docs.

</details>

<details>
<summary>P3 — #50–#51 resolved</summary>

- ✅ **#50** Split operator slash-command runtime, intel snapshot reading, and scope rendering out of `remote-session.ts` into `.pi/extensions/lib/operator-runtime.ts`. `remote-session.ts` dropped from ~1,274 to ~927 lines while preserving behavior. Added Node coverage for intel snapshot and scope rendering.
- ✅ **#51** Added `bin/clean-local` dry-run cleanup for ignored scratch/cache paths (`temp/`, `.pytest_cache/`, `__pycache__`, `*.pyc`, `.pi/npm/node_modules`, etc.). Logs/workspace are protected unless `--include-case-data --execute` is explicit. Added Python coverage and README/CONTRIBUTING docs.

</details>

<details>
<summary>P2/P3 — #43, #47, #49 resolved</summary>

- ✅ **#43** Added `bin/check-playbook-inventory`, wired it into `bin/test`, and normalized README/docs/playbook counts to the enforced rule: 101 operator-facing native OS playbooks under core platform directories; helper lookup scripts excluded.
- ✅ **#47** Normalized target-footprint language: no third-party binaries/tools on targets; native commands only; script text may run inline or be temporarily staged with cleanup.
- ✅ **#49** Replaced duplicate `docs/analyst-runbook.md` with a stub pointing to canonical `docs/runbook.md`; added docs hygiene coverage to prevent the full duplicate returning.

</details>

<details>
<summary>P1/P2 — #42, #45, #46 resolved</summary>

- ✅ **#42** Full `ir-report` now accepts both `ts` and `timestamp` timeline fields for investigation start and last activity. Added Python coverage for timestamp-only full markdown reports.
- ✅ **#46** Remote session logs now resolve under `BRJOTSKEL_LOG_DIR/remote-sessions` when configured, matching `ir-log` and `ir-search`. Added Node coverage for path resolution.
- ✅ **#45** Added `bin/netexec-to-intel` to parse NetExec success output, map hit IPs to host IDs from `hosts.yaml`, and emit ready-to-paste `intel_update(valid_on=...)` snippets. Added Python coverage and runbook/README references.

</details>

<details>
<summary>P2 — #41 resolved</summary>

- ✅ **#41** Added Reporting section to `docs/runbook.md` and mirrored `docs/analyst-runbook.md`: `/report` in-session brief, `bin/ir-report` markdown, `--format json`, `--output`, and alternate intel-dir usage. Added `/report` and `bin/ir-report` to the quick-reference table.

</details>

<details>
<summary>P2 — #38, #40 resolved</summary>

- ✅ **#38** `intel_scan` now supports `via_socks_port` for pivot-only segments. It checks for `proxychains4`, writes a temporary SOCKS config for `127.0.0.1:<port>`, routes nmap through it, records SOCKS provenance in host source metadata, and warns when no hosts answer from a harness-local scan.
- ✅ **#40** Added `gather-playbooks/macos/ssh-keys.sh`: per-user `/Users` SSH directory sweep, private key metadata + SHA-256 + `ssh-keygen -l` fingerprints, `authorized_keys`, SSH config, known_hosts pivot hints, and system SSH key/config coverage. Documentation counts updated to 97 scripts.

</details>

<details>
<summary>P2 — #36–#37 resolved</summary>

- ✅ **#36** `/pursue` and `intel_add` credential validation hints now emit SMB, WinRM, and SSH `netexec` commands for password and NTLM hash material. Shared command generator added with coverage.
- ✅ **#37** `/pursue` now shows confirmed/active credential blast-radius work, and adds contextual `secretsdump.py <domain>/<user> -hashes :<hash> @<host-ip>` hints for NTLM hashes already valid on Windows hosts/DC candidates.

</details>

<details>
<summary>P1 — #39 resolved</summary>

- ✅ **#39** `intel_scan` timeline entries now include `timestamp: new Date().toISOString()`. Added Node coverage that executes `intel_scan` with a fake harness-local `nmap` and verifies the generated timeline timestamp is non-empty ISO-8601.

</details>

<details>
<summary>P1 — #33–#35 resolved</summary>

- ✅ **#33** Windows and macOS host isolation scripts — `containment-playbooks/windows/isolate-host.ps1` (allow-analyst-only Windows Firewall rules, default-block all profiles, cleanup reminder) and `containment-playbooks/macos/isolate-host.sh` (pf ruleset, does not persist across reboots). `operator-shortcuts.ts` updated: `containIsolate` added to all three platforms.
- ✅ **#34** `gather-playbooks/windows/enum-cloud-credentials.ps1` — EC2 IMDSv1/v2, Azure IMDS managed identity, GCP metadata server. Expiry calculation. Static credential files. Windows gather count: 27→28.
- ✅ **#35** `/report` slash command + `--short` flag for `bin/ir-report` — TUI-friendly brief: host status, rotation list, last 3 timeline events. 3 new `--short` tests.

</details>

<details>
<summary>P1/P2 — #27–#32 resolved</summary>

- ✅ **#27** `bin/ir-report` — markdown/JSON incident report from intel store.
- ✅ **#28** macOS eradication gap closed — remove-cron, remove-profile-hook, remove-ssh-key, remove-btm-login-item.
- ✅ **#29** Credential validation hint on `intel_add` — reactive netexec command at point of discovery.
- ✅ **#30** `intel_scan` — nmap→intel store auto-population with platform inference.
- ✅ **#31** CHANGELOG and versioning — `CHANGELOG.md`, `LABEL version=0.3.0`.
- ✅ **#32** WinRM HTTPS — `use_ssl=true` and `skip_cert_check=true` parameters.

</details>

<details>
<summary>P1/P2 — #21–#25 resolved</summary>

- ✅ **#21** README stale tables corrected.
- ✅ **#22** Kerberoasting runbook gap — hashcat external-only framing.
- ✅ **#23** macOS `disable-account.sh`.
- ✅ **#24** macOS `host-ir-playbooks/macos/initial-assessment.sh`.
- ✅ **#25** Tunnel/relay manager test coverage.

</details>

<details>
<summary>P3 — #13, #16–#19 resolved</summary>

- ✅ **#13** `remote-session.ts` refactored 1,827 → 1,219 lines.
- ✅ **#16** JSONL audit log + `ir-search` fzf log search.
- ✅ **#17** Network device CLI references.
- ✅ **#18** CONTRIBUTING.md at root.
- ✅ **#19** Executable bit policy enforced.

</details>

<details>
<summary>P2 — #5–#12, #15 resolved</summary>

- ✅ **#5** `/scope`. ✅ **#6** Kerberoasting workflows. ✅ **#7** `/pursue` chase board. ✅ **#8** `intel_map`. ✅ **#9** Reachability probes. ✅ **#10** Binary integrity verification. ✅ **#11** LSASS dump. ✅ **#12** Cloud credential enumeration. ✅ **#15** Timeline filtering.

</details>

<details>
<summary>P1 — #1–#4 resolved</summary>

- ✅ **#1** Containment playbooks. ✅ **#2** Eradication playbooks. ✅ **#3** Pre-containment evidence collection. ✅ **#4** Persona intel state injection.

</details>

<details>
<summary>Original P0/P1/P2/P3</summary>

- ✅ `.dockerignore`, relay hardening, POSIX quoting, intel store permissions (P0)
- ✅ NetExec build, intel-snippet YAML safety, overwrite prevention, credential timeline semantics (P1)
- ✅ Schema validation, lifecycle transitions, remote_tunnel improvements, TCP/telnet parsing (P2)
- ✅ smoke-check banned-pattern phase (P3)

</details>
