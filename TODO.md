# TODO

Product backlog and engineering roadmap. Maintained from both a user-impact and technical-debt perspective.

> **Test status:** `bash bin/test` — 26 Python + 88 Node tests, all passing. Docker smoke build: ✅.

---

## 🔴 P0 — Blocker

*Nothing currently at P0.*

---

## 🟠 P1 — High user impact

*All P1 items resolved. See completed archive below.*

---

## 🟡 P2 — Meaningful capability improvements

*All P2 items resolved. See completed archive below.*

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

Items worth tracking but not committed to a sprint.

**Cloud-native IR.** EC2/Azure/GCP SDK-based collection — not just IMDS metadata, but IAM policy enumeration, CloudTrail review, S3 access log analysis, Security Hub findings ingestion. The current `enum-cloud-credentials.sh` finds tokens; it doesn't investigate what those tokens can reach.

**Evidence packaging.** A `bin/ir-package` tool that bundles `workspace/intel/`, `logs/`, and selected evidence files into a timestamped, signed archive. Useful for handoffs, legal holds, and post-incident review.

---

## Validated strengths — preserve these

- **CONSTITUTION.md** defines the safety model clearly. Don't let it drift or become aspirational.
- **Phase shortcuts** (`/land` → `/verify`) are the right mental model. Keep the phase structure.
- **Intel store lifecycle enforcement** — credentials can't be retrieved post-rotation, lifecycle transitions are validated. This is correct behavior; don't soften it.
- **Evidence-first pattern** in every containment and eradication script. Non-negotiable.
- **Native-OS-only playbooks** — no binary uploads to targets. This is the core promise.
- **Audit logging** — every session, command, and finding is timestamped and logged. The reconstruction capability is a key differentiator.
- **`intel-snippet`** normalized intel_add generation — reduces schema errors under pressure.

---

## Completed (archive)

<details>
<summary>P1/P2 — #27–#32 resolved</summary>

- ✅ **#27** `bin/ir-report` — markdown and JSON incident report from intel store. Sections: executive summary, host inventory, credential chain with rotation requirements, accounts, pivot paths, full timeline. `--format md|json`, `--output FILE`. 10 tests.
- ✅ **#28** macOS eradication gap closed — added `remove-cron.sh`, `remove-profile-hook.sh`, `remove-ssh-key.sh` (dscl home resolution), `remove-btm-login-item.sh` (sfltool + pluginkit + osascript). macOS now at 5 scripts, parity with Linux/Windows.
- ✅ **#29** Credential validation hint on discovery — `intel_add` for `category="credential"` appends a ready-to-run `netexec` command when known host IPs exist. Reactive at point of discovery.
- ✅ **#30** `intel_scan` — spawns nmap, parses greppable output, auto-creates `in-scope` hosts with platform inference. `lib/intel-scan-core.ts` extracted for testability. 10 tests.
- ✅ **#31** CHANGELOG and versioning — `CHANGELOG.md` with three release entries. `LABEL version=0.3.0` in Dockerfile.
- ✅ **#32** WinRM HTTPS — `remote_connect` now accepts `use_ssl=true` and `skip_cert_check=true` for HTTPS-only WinRM and self-signed cert environments.

</details>

<details>
<summary>P1/P2 — #21–#25 resolved</summary>

- ✅ **#21** README stale playbook tables and CI counts corrected.
- ✅ **#22** Kerberoasting runbook gap fixed — hashcat external-only framing.
- ✅ **#23** macOS `disable-account.sh` written (evidence → dscl → pkill → verify).
- ✅ **#24** macOS `host-ir-playbooks/macos/initial-assessment.sh` written.
- ✅ **#25** Test coverage for `tunnel-manager.ts` (8 tests) and `relay-manager.ts` (9 tests).

</details>

<details>
<summary>P3 — #13, #16–#19 resolved</summary>

- ✅ **#13** `remote-session.ts` refactored 1,827 → 1,219 lines, extracted to lib/ modules.
- ✅ **#16** JSONL audit log format + `ir-search` fzf log search.
- ✅ **#17** Network device CLI references (Cisco IOS/NX-OS, Juniper JunOS).
- ✅ **#18** `docs/analyst-improvement-plan.md` reconciled (now `CONTRIBUTING.md`).
- ✅ **#19** Executable bit policy enforced across all tracked shebang scripts.

</details>

<details>
<summary>P2 — #5–#12, #15 resolved</summary>

- ✅ **#5** `/scope` — situational dump.
- ✅ **#6** Kerberoasting + AS-REP roast workflows + `intel-snippet kerberos-ticket`.
- ✅ **#7** `/pursue` live credential chase board.
- ✅ **#8** `intel_map` + `/map` attack graph.
- ✅ **#9** Network reachability probes (Linux + Windows).
- ✅ **#10** Binary integrity verification (Linux + Windows).
- ✅ **#11** Windows LSASS dump playbook.
- ✅ **#12** Cloud credential enumeration (EC2/Azure/GCP).
- ✅ **#15** `intel_timeline` filtering.

</details>

<details>
<summary>P1 — #1–#4 resolved</summary>

- ✅ **#1** Containment playbooks — Linux/Windows/macOS.
- ✅ **#2** Eradication playbooks — Linux/Windows/macOS.
- ✅ **#3** Pre-containment evidence collection.
- ✅ **#4** Persona intel state injection.

</details>

<details>
<summary>Original P0/P1/P2/P3</summary>

- ✅ `.dockerignore`, hardened relay construction, POSIX quoting, intel store permissions (P0)
- ✅ NetExec build, intel-snippet YAML safety, silent overwrite prevention, credential timeline semantics, session timeout recovery (P1)
- ✅ Schema validation, lifecycle transitions, remote_tunnel improvements, TCP/telnet parsing (P2)
- ✅ smoke-check banned-pattern phase (P3)

</details>
