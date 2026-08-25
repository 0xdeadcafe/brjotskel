# TODO

Product backlog and engineering roadmap. Ghost review pass — attacker-first framing throughout.

> **Test status:** `bash bin/test` — 29 Python + 88 Node tests, all passing. Docker smoke build: ✅.

---

## 🔴 P0 — Blocker

*Nothing currently at P0.*

---

## 🟠 P1 — Bug: fix before the next incident

### 39. `intel_scan` writes timeline entries without a timestamp

`intel-scan.ts` calls `appendTimelineEntry()` with no `timestamp` field. The `/scope` command reads `e.timestamp || ""` — blank. `ir-report --short` reads `entry.get("ts") or entry.get("timestamp") or ""` — also blank. Every host discovered via `intel_scan` shows a blank timestamp in the last-5-events view and in the incident brief.

This is a one-line fix.

- **Action:** Add `timestamp: new Date().toISOString()` to the `appendTimelineEntry` call in `intel-scan.ts` (lines 174–179). Add a test in `tests/node/intel-scan.test.mjs` that confirms the timeline entry includes a non-empty `timestamp` field.
- **Files:** `.pi/extensions/intel-scan.ts`, `tests/node/intel-scan.test.mjs`

---

## 🟡 P2 — Meaningful capability gaps

### 36. `/pursue` only validates SMB for password and NTLM hash credentials

`credValidationCmd()` generates `netexec smb <hosts>` for NTLM hashes and `netexec smb` for passwords. In hardened environments — DMZs, segmented Windows networks — SMB (445) is commonly blocked while WinRM (5985) and SSH (22) are open. Ghost sprays SMB, gets nothing, thinks the credential is dead. It works fine on WinRM. Missed pivot.

The chase board should emit three commands for password and NTLM-hash type credentials: SMB, WinRM, and SSH. SSH is already generated for ssh-key types. It's missing for password and hash.

- **Action:** Update `credValidationCmd()` in `lib/operator-shortcuts.ts` so password and ntlm-hash types generate all three validation commands: `netexec smb`, `netexec winrm`, `netexec ssh` against the same host list. The same applies to the credential validation hint in `intel_add` (`intel-store.ts`). Add test coverage for the multi-protocol output.
- **Files:** `.pi/extensions/lib/operator-shortcuts.ts`, `.pi/extensions/intel-store.ts`, `tests/node/operator-shortcuts.test.mjs`

---

### 37. `/pursue` doesn't surface `secretsdump` when a hash is confirmed on a Windows host

When an NTLM hash is validated and `valid_on` includes a host, the natural next move depends on the host's role. If it's a Domain Controller — `secretsdump.py` against NTDS, not more netexec spraying. The chase board doesn't surface this. Ghost finds a Domain Admin hash, confirms it on dc01, and has to manually remember to run secretsdump. The runbook documents it; the chase board doesn't surface it contextually.

- **Action:** In `formatPursueShortcut`, after the validation commands for ntlm-hash type credentials that already have `valid_on` entries, append: `secretsdump.py <domain>/<user> -hashes :<hash> @<host-ip>  # NTDS dump if target is DC`. The hint should appear on confirmed credentials, not unvalidated ones. Detect Windows hosts from the host list (platform: windows or common Windows ports in endpoints). Update tests.
- **Files:** `.pi/extensions/lib/operator-shortcuts.ts`, `tests/node/operator-shortcuts.test.mjs`

---

### 38. `intel_scan` is harness-local — scanning through a pivot is undocumented and silently fails

`intel_scan` runs nmap from the harness container. If Ghost pivoted through web01 and calls `intel_scan("10.10.20.0/24")`, the harness can't reach that segment — zero results, no error, no explanation. Time wasted before realising the problem.

The better fix is a `via_socks_port` parameter: when set, prepend `proxychains` to the nmap spawn with the configured proxy port. Minimum fix: add it to the tool description and `promptGuidelines`.

- **Action (better):** Add `via_socks_port: Type.Optional(Type.Number())` to `intel_scan` parameters. When set, check that `proxychains4` is available, then prepend `proxychains` to the spawn args and document the requirement for a live SOCKS tunnel on that port. Update tests.
- **Action (minimum):** Add a `promptGuidelines` entry: "intel_scan runs from the harness — for internal segments only reachable through a pivot, first run `remote_tunnel(type='dynamic', via='root@web01', local_port=1080)`, then use `proxychains nmap` manually from the harness shell. intel_scan cannot currently route through a SOCKS proxy."
- **Files:** `.pi/extensions/intel-scan.ts`, `tests/node/intel-scan.test.mjs`

---

### 40. macOS has no `ssh-keys.sh` gather script

Linux has `gather-playbooks/linux/ssh-keys.sh` — a dedicated sweep of all user home directories for SSH private keys, `authorized_keys`, and `known_hosts`, with per-key fingerprint display. On macOS, `enum-credentials.sh` has four lines in a broader credential script (`cat ~/.ssh/authorized_keys known_hosts`). No per-user sweep, no private key discovery across profiles, no fingerprint output.

macOS developer machines are high-value IR targets precisely because they carry SSH keys — GitHub deploy keys, bastion host keys, corporate jump host keys, personal AWS CLI key pairs. Ghost lands on a dev machine, runs `enum-credentials.sh`, gets a surface-level glance. The dedicated script with full per-user, per-key coverage is the right tool.

- **Action:** Write `gather-playbooks/macos/ssh-keys.sh`. Mirror `linux/ssh-keys.sh`: sweep all user home directories under `/Users/`, list private key files (`id_rsa`, `id_ed25519`, `*.pem`, `*.key`), show `authorized_keys` per user, display fingerprints with `ssh-keygen -l`, check `known_hosts` for pivot hints. macOS uses `shasum -a 256` not `sha256sum`. Update `gather-playbooks/SKILL.md`, `docs/playbooks.md`, README count.
- **Files:** `.pi/skills/gather-playbooks/macos/ssh-keys.sh`, `gather-playbooks/SKILL.md`, `docs/playbooks.md`, `README.md`

---

### 41. `ir-report` and `/report` are not documented in the runbook

`bin/ir-report` generates a structured incident report. `/report` surfaces the short brief in the TUI. Neither appears anywhere in `docs/runbook.md`. An analyst who doesn't know to look for it won't find it — and the post-incident report step will be done manually from `intel_summary()` output, which is what `ir-report` was built to replace.

- **Action:** Add a "Reporting" section to `docs/runbook.md` (near the end, after Verify phase) covering: `/report` for in-session brief, `ir-report` for full markdown export, `ir-report --format json` for SIEM/programmatic use, `ir-report --output report.md` for writing to file. Add `/report` to the tool quick-reference table.
- **Files:** `docs/runbook.md`

---

## 🟢 P3 — Engineering housekeeping

### 14. Pin Docker builds — supply chain risk

NetExec installs from GitHub HEAD. pi installs from npm latest. A CI build can silently change behavior. For a security tool, non-reproducible builds are a credibility problem.

**Action:** Pin NetExec to a specific commit/tag. Pin pi to a specific npm version. Pin Node via `.nvmrc` or `node-version` label. Document update cadence. **Files:** `Dockerfile`

---

### 20. Make nvim config optional in the image

Adds image weight in non-interactive/CI deployments.

**Action:** `ARG INCLUDE_NVIM_CONFIG=true`, conditional `COPY`. Keep default as `true`. **Files:** `Dockerfile`, `.config/nvim/**`

---

### 26. ir-search clipboard bind silently no-ops

`xclip` not in image, requires X11 anyway. `pbcopy` is macOS-only. The `enter`-to-copy bind always fails silently in a headless container.

**Action:** Write selected line to `workspace/ir-search-hits.txt` (append + timestamp) or drop the bind. **Files:** `bin/ir-search`

---

## Strategic / longer-term

**Cloud-native IR.** EC2/Azure/GCP SDK-based collection — not just IMDS metadata, but IAM policy enumeration, CloudTrail review, S3 access log analysis, Security Hub findings ingestion. The current cloud credential scripts find the token; they don't investigate what that token can reach.

**Evidence packaging.** A `bin/ir-package` tool that bundles `workspace/intel/`, `logs/`, and selected evidence files into a timestamped, signed archive. Useful for handoffs, legal holds, and post-incident review.

---

## Validated strengths — preserve these

- **CONSTITUTION.md** defines the safety model clearly. Don't let it drift or become aspirational.
- **Phase shortcuts** (`/land` → `/verify`) are the right mental model. Keep the phase structure.
- **Full-platform isolation** — Linux (iptables), Windows (Firewall default-block), macOS (pf). All three platforms now have the complete containment suite. Keep this symmetry.
- **Intel store lifecycle enforcement** — credentials can't be retrieved post-rotation, lifecycle transitions are validated. This is correct behavior; don't soften it.
- **Evidence-first pattern** in every containment and eradication script. Non-negotiable.
- **Native-OS-only playbooks** — no binary uploads to targets. This is the core promise.
- **Audit logging** — every session, command, and finding is timestamped and logged. The reconstruction capability is a key differentiator.
- **`intel-snippet`** normalized intel_add generation — reduces schema errors under pressure.
- **`/scope` → `/map` → `/pursue` loop** — the right situational awareness rhythm. Keep it tight.

---

## Completed (archive)

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
