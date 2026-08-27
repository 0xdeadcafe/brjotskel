# TODO

Product backlog and engineering roadmap. Ghost review pass — attacker-first framing throughout.

> **Test status:** `bash bin/test` — strict TypeScript typecheck + 52 Python + 102 Node tests, all passing. Docker smoke build is configured in CI; rerun locally after dependency pinning or Dockerfile changes.

---

## Priority lens

- **P0**: blocks safe operation now or can corrupt evidence immediately.
- **P1**: fix before the next real incident image is trusted — reproducibility, integrity, report correctness.
- **P2**: high operator leverage — reduces manual misses and closes workflow gaps.
- **P3**: simplification, drift control, developer ergonomics, bloat reduction.

## Recommended execution order

*No active TODOs.*

---

## 🔴 P0 — Blocker

*Nothing currently at P0.*

---

## 🟠 P1 — Fix before the next incident image is trusted

*Nothing currently at P1.*

## 🟡 P2 — High operator leverage

*Nothing currently at P2.*

## 🟢 P3 — Simplify / de-risk maintenance

*Nothing currently at P3.*

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
<summary>Won't do — #20 nvim optionalization skipped</summary>

- ⛔ **#20** Skipped by operator decision. Keep the nvim config baked into the incident image by default instead of adding conditional Docker build paths. The image-size win is low leverage, while preserving a consistent interactive recovery workspace is more useful during live incidents.

</details>

<details>
<summary>Won't do — #52 tmux backend skipped</summary>

- ⛔ **#52** Skipped by operator decision. The current command-oriented remote-session adapter remains the canonical path. The tmux model has useful human-attach ergonomics but adds command-boundary ambiguity, scrollback truncation risk, raw credential exposure in terminal/log history, and concurrency race surface. Keep WinRM/PowerShell on the current adapter and do not add tmux/Dockerfile complexity unless a future mission proves the need.

</details>

<details>
<summary>P3 — #44 resolved</summary>

- ✅ **#44** Made split secret handling explicit without blocking evidence. Credential-focused gather paths now have redacted-by-default modes where practical (`BRJOTSKEL_REVEAL_SECRETS=1` reveals raw material for validation/import): Linux cloud/credential/triage/container token paths, Windows cloud/credential paths, and macOS credential history/token searches. `ir-report` now warns that intel, transcripts, and packages may contain raw secrets and supports `--format json --redact-secrets` for shareable JSON exports. `ir-package` warning/manifest metadata now call out that logs may contain secrets outside `credentials.yaml` and preserves raw evidence instead of blocking on active credentials. README/runbook/import workflow docs updated; Python coverage added. Tests now 52 Python + 102 Node.

</details>

<details>
<summary>P2 — #60 resolved</summary>

- ✅ **#60** Generated extension tool inventory docs. Added `bin/check-tool-inventory` to extract `pi.registerTool({ name: ... })` from `.pi/extensions/*.ts`, rewrite marked README/architecture blocks with `--write`, and fail CI when docs drift. Wired it into `bin/test`, Docker image chmod/symlink setup, README/toolchain docs, architecture docs, and Python docs coverage. Current generated inventory tracks 17 registered extension tools across `intel-scan.ts`, `intel-store.ts`, and `remote-session.ts`.

</details>

<details>
<summary>P2 — #59 resolved</summary>

- ✅ **#59** Added strict TypeScript typechecking. New `tsconfig.json` runs `strict`/`noEmit`/unused checks across `.pi/extensions/**/*.ts`; `package.json` and `package-lock.json` pin TypeScript and Node types; `bin/test` installs compiler deps when missing and runs `node_modules/.bin/tsc --noEmit` before unit tests. CI now runs `npm ci --ignore-scripts`. Added local declaration stubs for pi/typebox extension APIs and Node coverage to keep the typecheck contract from drifting. Cleaned stale unused imports and typed intel category indexing/fallback host summaries caught by the compiler.

</details>

<details>
<summary>P1 — #58 resolved</summary>

- ✅ **#58** Finished build integrity beyond version pins. `Dockerfile` now records OCI image labels and writes `/opt/brjotskel/BUILD-MANIFEST.json` with pinned inputs, source metadata, tool versions, selected file hashes, dpkg inventory, pip freeze, npm global packages, pi package config, and known non-hermetic inputs. CI validates the manifest, generates `artifacts/brjotskel-sbom.cdx.json` with `bin/image-sbom`, and uploads the SBOM plus manifest. Docs now call out the remaining incident-release lane: controlled mirrors or hash-locked caches for Debian/Microsoft apt, PyPI, npm, and rustup.

</details>

<details>
<summary>P1 — #57 resolved</summary>

- ✅ **#57** Hardened the container trust boundary. `Dockerfile` now creates a non-root `brjotskel` runtime user with configurable UID/GID, leaves baked-in `.pi` settings/extensions/skills plus docs/bin/nvim config root-owned and read-only to runtime, allows only transient pi lock entries in the `.pi` parent, and limits case-data writes to logs/workspace/home. `compose.yaml` now passes UID/GID build args, sets `no-new-privileges:true`, drops all capabilities, and labels writable `.pi` live-reload as dirty/dev-only. README, architecture docs, and contributing guidance document production read-only `.pi` mode and local capability overrides.

</details>

<details>
<summary>P1 — #48 resolved</summary>

- ✅ **#48** Added `bin/ir-package` incident handoff workflow. It generates `incident-report.md`, copies `workspace/intel/`, `logs/`, and repeatable `--evidence` paths into a timestamped sensitive package, writes `MANIFEST.json` and `MANIFEST.sha256` with per-file SHA-256 hashes, excludes `.intel.lock`, sets output directory 0700 and tarball 0600, and warns on active/unrotated credentials via stderr and `WARNING.txt`. Added Python coverage and README/runbook/architecture docs. Tests now 49 Python + 101 Node.

</details>

<details>
<summary>P1 — #56 resolved</summary>

- ✅ **#56** Made logging evidence-grade enough for the next layer. `bin/ir-log` now writes `entry_hash` and `previous_entry_hash` for tamper-evident daily audit logs in text and JSONL modes. Remote session logging now fails loud by default, with explicit `BRJOTSKEL_ALLOW_DEGRADED_LOGGING=1` escape hatch. Every `remote_exec` completion/timeout writes a structured hash-chained JSONL command record with command ID, session/target/protocol, timing, status, output SHA-256, byte/line counts, duration, and taint state. Human-readable session logs remain. Added Python and Node coverage; tests now 46 Python + 101 Node.

</details>

<details>
<summary>P1 — #55 resolved</summary>

- ✅ **#55** Added cross-process intel store locking. New `.pi/extensions/lib/intel-lock.ts` uses an atomic directory lock at `.intel.lock`, serializes write sections across concurrent pi/tool processes, reclaims stale locks, times out on fresh held locks, and releases on errors. `intel-store.ts` now wraps every read-modify-write path, including credential access timeline writes. `intel-scan.ts` writes hosts and timeline under the same lock. Added `tests/node/intel-lock.test.mjs`; Node tests now 99.

</details>

<details>
<summary>Won't do — #54 mission-boundary model accepted</summary>

- ⛔ **#54** Scope allowlist enforcement closed as won't-do. Operator decision: brjotskel runs against a mission, not a static scope file. Authorized boundaries remain an operational/legal control, not an in-tool network allowlist. Keep command confirmations, provenance, and audit logging; do not add `workspace/scope.yaml` gating unless the mission model changes.

</details>

<details>
<summary>P1 — #14 resolved</summary>

- ✅ **#14** Docker/build dependencies pinned. `Dockerfile` now uses a Debian base digest and explicit pins for Node.js version + SHA-256, pi, `pi-smart-fetch`, PowerShell, and Rust. `requirements-harness.txt` pins Impacket, NetExec, direct Git dependencies, and Python transitives. Added `.nvmrc`, switched CI to `node-version-file`, pinned `.pi/settings.json` package spec, and documented the dependency bump workflow.

</details>

<details>
<summary>P1 — #53 resolved</summary>

- ✅ **#53** Added `bin/check-playbook-contracts`, wired it into `bin/test`, and normalized metadata across the 101 operator-facing target-side scripts. The checker validates required privilege/read-only/state-changing metadata, sensitive-output labels, predictable section headers, evidence/action/verify patterns, mutation guards, and banned target-side bootstrap/drop patterns. Added Python coverage that runs the checker, executes representative safe Linux read-only playbook output, verifies network-device command references, and confirms high-impact Windows dump scripts require `$ConfirmDump = $true`. CI now sets `BRJOTSKEL_REQUIRE_PWSH=1` so PowerShell syntax cannot silently skip in GitHub Actions.

</details>

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
