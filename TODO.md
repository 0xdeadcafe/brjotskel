# TODO — Deep Repo Review (2026-08-07)

## Review snapshot

- Validation run: `bash bin/test` ✅ (smoke check, Python unit tests, Node helper tests all pass).
- Tracked repo size is small (~864 KB). Local bloat/secrets live in ignored state (`temp/`, `.env`, `.pi/npm/`, `workspace/intel/`) and are now excluded from Docker build context via `.dockerignore`.
- This replaces the prior stale review. Confirmed non-issues: `.env`, `temp/`, `workspace/intel/`, and `__pycache__/` are **not tracked** by git.

---

## 🔴 P0 — Fix immediately

### 1. ✅ Add `.dockerignore` and stop copying local pi package state into the image
- **Files:** `Dockerfile`, missing `.dockerignore`, `.pi/npm/`, `temp/`, `.env`, `workspace/`, `logs/`
- **Issue:** `docker build .` currently sends the entire working tree as build context, including ignored local files: `temp/` (~1.8 GB), `.pi/npm/node_modules/` (~86 MB), `.env`, logs, and `workspace/intel/`. Even though most are not copied intentionally, they are still exposed to the Docker builder/cache. Also `COPY .pi/ /opt/brjotskel/.pi/` copies ignored `.pi/npm/` into the final image when it exists locally.
- **Action:** Add `.dockerignore` excluding `.git/`, `.env*`, `temp/`, `logs/**`, `workspace/**`, `.pi/npm/**`, `node_modules/`, caches, and pyc files. Replace broad `COPY .pi/` with explicit copies for `.pi/extensions/`, `.pi/skills/`, `.pi/settings.json`, and any required prompts.
- **Status:** ✅ Addressed. Added `.dockerignore`; Dockerfile now copies tracked pi settings/extensions/skills explicitly and creates workspace/log dirs.

### 2. ✅ Harden `remote_relay` command construction and cleanup
- **Files:** `.pi/extensions/remote-session.ts`, `.pi/extensions/lib/remote-session-core.ts`
- **Issues:**
  - `buildRelayCommand()` interpolates `target_host` and `listen_address` directly into shell / `netsh` commands with no validation or quoting.
  - Port values accept any `number`; no integer/range validation (1-65535).
  - `RelayInfo` does not store `listenAddress`, so `remote_relay_close()` deletes Windows `netsh portproxy` rules with the default `0.0.0.0` even if the relay was created with a custom listen address.
  - `bash-devtcp` relay is not a real bidirectional relay: target output goes to the remote shell stdout, not back to the connecting client.
  - Relays are recorded as active even when verification says listening is unconfirmed.
- **Action:** Validate host/address/port inputs, quote shell parameters safely, store `listenAddress` in `RelayInfo`, remove/fix `bash-devtcp`, and either fail or mark relays clearly inactive when verification fails.
- **Status:** ✅ Addressed. Added relay spec validation, removed broken `bash-devtcp` selection, preserved custom listen addresses for cleanup, and fail/cleanup on unverified relays.

### 3. ✅ Fix broken POSIX quoting helper
- **Files:** `.pi/extensions/lib/remote-helpers.ts`, `.pi/extensions/lib/remote-session-core.ts`, `tests/node/remote-helpers.test.mjs`, `tests/node/remote-session-core.test.mjs`
- **Issue:** `shellSingleQuote("o'hare")` returns `o"'"'hare`; callers wrap it as `'o"'"'hare'`, which is invalid shell syntax. Existing tests assert the broken form. This affects `remote_upload` paths containing apostrophes and any future command builder using this helper with user-controlled input.
- **Action:** Replace with a standard POSIX quote helper that returns a fully quoted string, e.g. `'foo'\''bar'`, or clearly document that callers must not wrap it. Add tests that execute the generated string through `bash -n` / `printf`.
- **Status:** ✅ Addressed. `shellSingleQuote()` now returns a complete POSIX-safe token; callers were updated; regression test round-trips through bash.

### 4. ✅ Restrict permissions for intel stores containing secrets
- **Files:** `.pi/extensions/intel-store.ts`, `workspace/intel/` runtime output
- **Issue:** `writeYaml()` writes `credentials.yaml`, timeline, keys, and loot using the process umask. Harvested passwords, hashes, tokens, key paths, and host intel may end up group/world-readable depending on the environment.
- **Action:** Create intel directories with `0700`; write credential/key/loot files with `0600`; consider all intel YAML sensitive by default. Add a migration/check command that warns on permissive existing files.
- **Status:** ✅ Addressed. Intel dirs are created/chmodded `0700`; YAML temp/final files are chmodded `0600`; existing intel YAML and key/loot files are hardened opportunistically when the store is opened.

---

## 🟠 P1 — Important reliability / correctness work

### 5. Make NetExec availability deterministic and standardize command names
- **Files:** `Dockerfile`, `README.md`, `docs/**`, `.pi/extensions/lib/remote-session-core.ts`, `.pi/skills/shell-commands/reference/**`
- **Issue:** Docker silently ignores NetExec install failures (`|| echo 'NetExec install skipped'`) while docs claim NetExec is included. References mix `netexec`, `crackmapexec`, and no `nxc` fallback.
- **Action:** Fail the build if required NetExec install fails, or document it as optional. Add a smoke check for the installed command name and standardize examples (`netexec` vs `nxc`; remove stale `crackmapexec` references unless actually installed).

### 6. Replace fragile YAML/string generation in `intel-snippet`
- **File:** `bin/intel-snippet`
- **Issues:** Custom `y()` serializer can type-shift strings such as `true`, `null`, numbers, or timestamps into non-strings, and has incomplete YAML edge-case handling. The emitted `intel_add(... summary="...")` call does not escape quotes, backslashes, or newlines in `summary` / IDs / YAML triple-quote boundaries.
- **Action:** Use PyYAML for YAML output and `json.dumps()` for Python-string-safe `category`, `id`, `data`, and `summary` arguments. Add tests for secrets like `true`, `1234`, multiline notes, quotes, and summaries with `"`.

### 7. Prevent silent intel overwrites
- **Files:** `.pi/extensions/lib/intel-store-core.ts`, `.pi/extensions/intel-store.ts`
- **Issue:** `intel_add` overwrites an existing entry with the same ID without warning, which can destroy provenance during an incident.
- **Action:** Default to error on duplicate IDs. Add explicit `overwrite: true` or an `intel_update` merge tool that appends a timeline event and preserves previous source/history.

### 8. Fix misleading credential timeline semantics
- **File:** `.pi/extensions/intel-store.ts`
- **Issue:** `intel_get_cred` appends a `credential/confirmed` timeline entry whenever a secret is retrieved. Retrieval is not validation and can pollute the incident timeline with false confirmations.
- **Action:** Use a distinct action such as `retrieved`/`accessed`, or log retrieval separately. Warn or refuse when credential status is `rotated`, `expired`, `revoked`, or otherwise inactive.

### 9. Expand CI beyond happy-path helper tests
- **Files:** `.github/workflows/ci.yml`, `bin/smoke-check`, `tests/**`
- **Current gap:** CI does not build the Docker image, does not import/register the actual extension entrypoints with a mocked pi API, does not syntax-check all shell scripts, and does not parse PowerShell scripts.
- **Action:** Add: Docker build smoke test; all tracked shell scripts `bash -n`; PowerShell parser check when `pwsh` is available; extension import/registration tests with mocked `registerTool`; regression tests for quoting, relay validation, duplicate intel IDs, malformed YAML, and inactive credentials.

### 10. Handle remote command timeout recovery
- **File:** `.pi/extensions/remote-session.ts`
- **Issue:** On timeout, `execCommand()` clears the buffer and resolves with partial output, but the remote command may still be running. The next command can interleave with stale output or execute while the previous operation is still active.
- **Action:** Mark the session `tainted` after timeout and require reconnect, or send interrupt (`Ctrl-C`) plus drain-to-prompt before accepting another command.

### 11. Replace Python subprocess YAML parsing in the intel extension
- **File:** `.pi/extensions/intel-store.ts`
- **Issue:** Every YAML read/write shells out to `python3` + PyYAML with `execSync` and a 5s timeout. This is slow, blocks the event loop, and adds a runtime dependency that tests do not exercise.
- **Action:** Use a JS YAML library, or centralize YAML I/O with better errors. Add graceful handling for malformed/partially-written YAML (clear error with file path and recovery guidance; do not crash unrelated queries when possible).

---

## 🟡 P2 — Moderate value / design cleanup

### 12. Strengthen intel schema validation
- **Files:** `.pi/extensions/lib/intel-helpers.ts`, docs for intel schema
- **Issue:** Hosts and accounts can be nearly empty; `source` is recommended in prompts but not enforced; credential types are free-form; statuses are inconsistent across docs/examples.
- **Action:** Define category schemas with required fields, allowed status/type enums, and source requirements. Return actionable validation errors from `intel_add`.

### 13. Add `intel_update` / status lifecycle operations
- **Files:** `.pi/extensions/intel-store.ts`, `.pi/extensions/lib/intel-store-core.ts`
- **Issue:** Operators can add and query intel, but cannot safely mark a host contained, credential rotated, pivot cleared, or append validation results without editing YAML by hand.
- **Action:** Add `intel_update(category, id, fields, summary)` with merge semantics, status transitions, and automatic timeline entries.

### 14. Support password and ProxyJump options for `remote_tunnel`
- **File:** `.pi/extensions/remote-session.ts`
- **Issue:** `remote_tunnel` supports `identity` but not password auth or ProxyJump chains, while `remote_connect` supports password and ProxyJump. Password-only pivots are common in incident response.
- **Action:** Add `password` via `sshpass` and optional `proxy_jump` to `remote_tunnel`, matching `remote_connect` behavior.

### 15. Improve TCP/telnet target parsing and no-banner handling
- **File:** `.pi/extensions/remote-session.ts`
- **Issue:** `target.split(":")` breaks IPv6 and ambiguous host:port strings. TCP/telnet sessions time out when a service accepts connections but sends no banner.
- **Action:** Add a robust host/port parser and a connection-ready fallback for no-banner services, with clear best-effort warnings.

### 16. Make Docker builds reproducible and auditable
- **File:** `Dockerfile`
- **Issue:** Build pulls live NodeSource setup script, global pi latest, Impacket latest, and NetExec from GitHub HEAD. This is convenient but not reproducible and increases supply-chain risk.
- **Action:** Pin versions/commits, document update cadence, and add image labels with tool versions.

### 17. Align Docker image layout with docs
- **Files:** `Dockerfile`, `README.md`, `docs/intel-import-workflow.md`
- **Issue:** Docker copies `ir-log` and `intel-snippet` to `/usr/local/bin`, but does not copy `bin/test` or `bin/smoke-check` into `/opt/brjotskel/bin`. Docs sometimes reference `bin/intel-snippet` as if the repo `bin/` exists inside the container.
- **Action:** Either copy the full `bin/` directory into the image or update docs to use PATH commands inside the container and repo-relative commands outside it.

### 18. Break up the `remote-session.ts` monolith
- **File:** `.pi/extensions/remote-session.ts`
- **Issue:** The file is ~1,500 lines and mixes protocol connection code, command execution, upload logic, tunnels, relays, slash commands, logging, and tool registration.
- **Action:** Extract connection adapters, upload builders, tunnel manager, relay manager, and slash-command handlers into testable modules. Keep the extension entrypoint thin.

---

## 🟢 P3 — Cleanup / bloat / consistency

### 19. Remove stale one-off checks from `smoke-check`
- **File:** `bin/smoke-check`
- **Issue:** Step `[4/5]` only greps for a past auth-context migration. This is not a general regression check.
- **Action:** Replace with a generic banned-patterns file or delete once the migration is fully trusted.

### 20. Reconcile stale planning docs with current state
- **Files:** `TODO.md`, `docs/analyst-improvement-plan.md`, `README.md`
- **Issue:** `docs/analyst-improvement-plan.md` still lists some already-implemented gaps (for example first-look and analyst runbook) and overlaps with this TODO.
- **Action:** Convert it into a current roadmap, archive completed sections, or link to this TODO as the source of truth.

### 21. Normalize executable bits for helper/playbook scripts
- **Files:** `bin/smoke-check`, several `.pi/skills/**.sh`
- **Issue:** Some shell scripts with shebangs are executable and others are not. This is harmless for inline/paste workflows but confusing for local direct execution.
- **Action:** Decide policy: either all runnable scripts executable, or docs always invoke them through `sh`/`bash`.

### 22. Make optional editor config optional in the image
- **Files:** `.config/nvim/**`, `Dockerfile`
- **Issue:** Neovim config is useful for operator shells but not required for the pi-first workflow.
- **Action:** Keep it, but consider a build arg or dev image layer if image minimalism becomes a priority.

### 23. Use structured logs for machine parsing
- **Files:** `bin/ir-log`, `.pi/extensions/remote-session.ts`
- **Issue:** Audit/session logs use custom shell-ish text (`%q`, `[timestamp] host=... >>> command`). Human-readable, but awkward to replay or parse reliably.
- **Action:** Add JSONL mode or a log conversion helper while preserving current human-readable output.

---

## Validated strengths to preserve

- Clear mission/safety model in `CONSTITUTION.md`.
- Good separation of testable helper modules under `.pi/extensions/lib/`.
- Useful native-only gather/IR/escalation playbooks across Linux, Windows, and macOS.
- Strong operational primitives: persistent sessions, tunnels, relays, intel store, timeline.
- Current unit tests are fast and pass; keep that speed while adding targeted edge-case coverage.
