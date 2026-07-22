# TODO — Prioritized Codebase Review

## Summary

**brjotskel** is a well-structured, focused IR operator harness. The core extensions (intel-store, remote-session) are solid with good test coverage and clean separation into testable library modules. The main issues are: bloat from a 1.8 GB `temp/` directory, over-engineering in `intel-snippet`, a committed `.env` with secrets, and some operational gaps.

---

## 🔴 P0 — Fix Immediately

### 1. ~~Secrets committed in `.env`~~ — FALSE ALARM
- **File:** `.env`
- **Status:** ✅ NOT committed. The file is correctly `.gitignore`d, never tracked, and not in git history. Local-only.
- **Minor concern:** The file exists on disk with a real AWS token. Ensure it's not accidentally baked into Docker images (it isn't — `COPY .env` is not in the Dockerfile).

### 2. ~~`temp/` directory is 1.8 GB of cloned repos~~ — INTENTIONAL
- **Files:** `temp/metasploit-framework`, `temp/hayabusa`, `temp/hayabusa-rules`, `temp/chainsaw`
- **Status:** ✅ Kept intentionally as local reference documentation. Already excluded by `.gitignore`.

---

## 🟠 P1 — Important Improvements

### 3. `intel-snippet` is over-engineered (~350 lines of argparse boilerplate)
- **File:** `bin/intel-snippet`
- **Issue:** 14 subcommands with massive argparse definitions, each producing nearly identical YAML snippets. The custom `y()` YAML serializer reimplements PyYAML poorly (doesn't handle multiline strings, nested quoting edge cases). Most of the value is in the `source` field defaults per artifact type.
- **Action:**
  - Replace `y()` with `yaml.dump(data, default_flow_style=False)` (PyYAML is already a dependency).
  - Consider collapsing to fewer subcommands with a `--template` flag, or a single generic command plus a small template registry (JSON/YAML file mapping template names to default source fields).
  - The `compact()` helper is fine but could be a one-liner with a recursive dict comprehension.

### 4. YAML parsing via `python3` subprocess in extensions
- **File:** `.pi/extensions/intel-store.ts`
- **Issue:** Every YAML read/write shells out to `python3 -c "import yaml,json..."`. This is slow (process spawn per operation), fragile (relies on python3 + pyyaml in PATH), and blocks on `execSync`.
- **Action:** Use a JS YAML library (`yaml` npm package — it's ~50KB). Add to `.pi/npm/package.json`. This also eliminates the 5s timeout risk on large files.

### 5. `__pycache__` committed to repo
- **Files:** `bin/__pycache__/`, `tests/python/__pycache__/`
- **Issue:** Bytecode cache files checked in.
- **Action:** Remove and add `__pycache__/` to `.gitignore` (already partially there but the files exist).

### 6. No error handling for intel YAML corruption
- **File:** `.pi/extensions/intel-store.ts`
- **Issue:** If a YAML file is malformed or partially written (e.g., crash during `writeYaml`), the extension throws with an unhelpful message. The atomic write (`tmp + rename`) is good, but reads have no recovery.
- **Action:** Add graceful degradation: if parse fails, log warning and return empty collection rather than crashing the tool.

---

## 🟡 P2 — Moderate Value

### 7. `remote-session.ts` is a 1278-line monolith
- **File:** `.pi/extensions/remote-session.ts`
- **Issue:** While logically sound, the extension mixes connection management, command execution, tunneling, slash commands, and all 7 tool registrations in one file. Hard to navigate.
- **Action:** Extract connection functions (`connectSSH`, `connectWinRM`, `connectTCP`, `connectTelnet`) into `lib/remote-connections.ts`. Keep tool registrations in the main file as thin wrappers.

### 8. Duplicate session-alive checks
- **File:** `.pi/extensions/remote-session.ts`
- **Issue:** `remote_exec`, `remote_upload`, and the `execCommand` function all independently check `session.process.killed` with slightly different error messages and cleanup logic.
- **Action:** Extract a single `assertSessionAlive(session)` helper.

### 9. No credential rotation/expiry tracking
- **Gap:** Credentials are stored with `status: active` but there's no TTL, last-validated timestamp, or rotation tracking.
- **Action:** Add optional `last_validated` and `expires` fields. The `intel_get_cred` tool already shows `expires` for Kerberos tickets — generalize.

### 10. No `intel_update` or `intel_delete` tool
- **Gap:** Once intel is added, there's no tool to update status (e.g., mark a credential as rotated, mark a host as contained). Operators must manually edit YAML.
- **Action:** Add `intel_update(category, id, fields)` that merges fields into existing entries and appends a timeline event.

### 11. Test coverage gap — no integration test for the full extension tool flow
- **Gap:** Unit tests cover helpers well, but nothing tests `intel_add` → `intel_query` round-trip through the actual extension `execute()` methods.
- **Action:** Add a small integration test that mocks the pi extension API and exercises the tools end-to-end against a temp directory.

---

## 🟢 P3 — Nice to Have

### 12. `.config/nvim/` adds container weight for marginal value
- **Files:** `.config/nvim/init.lua`, syntax files
- **Issue:** Neovim config is baked into the container for syntax highlighting, but the primary interface is `pi` (not an editor). Only relevant if operator shells into the container.
- **Action:** Keep but make optional — only COPY if a build arg is set, or move to a separate "dev" layer.

### 13. `smoke-check` step 4 is brittle grep-based regression check
- **File:** `bin/smoke-check`
- **Issue:** Step `[4/5]` greps for removed auth-context references — this is a one-time migration check, not an ongoing concern.
- **Action:** Remove once confident the migration is complete, or replace with a generic "banned patterns" file.

### 14. `docs/architecture.md` duplicates README content
- **Issue:** The architecture doc repeats the tool list, platform support table, and workflow descriptions already in README.
- **Action:** Trim `architecture.md` to architectural decisions and diagrams. Link to README for tool inventory.

### 15. Session log format is not structured
- **File:** Remote session logs (`logs/remote-sessions/`)
- **Issue:** Logs use a custom `[timestamp] host=... >>> command` format that's hard to parse programmatically.
- **Action:** Consider JSONL format for machine-parseable session reconstruction, or at minimum add a log-replay helper.

### 16. `ir-log` uses shell quoting that's hard to parse back
- **File:** `bin/ir-log`
- **Issue:** `printf '%q'` produces bash-escaped strings. Multi-word events become `event=checked\ host\ 10.0.0.5` which is awkward to grep/parse.
- **Action:** Switch to a structured format (JSONL or tab-separated) for machine parsing while keeping human readability.

### 17. Missing container health/readiness signal
- **Gap:** The Dockerfile starts `pi` but has no HEALTHCHECK.
- **Action:** Add `HEALTHCHECK CMD ["pgrep", "-x", "node"]` or similar.

### 18. `workspace/intel/*.yaml` files are empty stubs
- **Files:** `workspace/intel/hosts.yaml`, etc.
- **Issue:** These are empty files tracked via `workspace/.gitkeep`. Since `.gitignore` excludes `workspace/**`, they won't persist anyway.
- **Action:** Remove the stub YAML files. The extension creates them on first use. Keep only `.gitkeep`.

---

## Architecture Assessment

### What's good:
- **Clean separation**: Extensions split into `lib/` testable modules + registration layer
- **Test coverage**: All helper functions have unit tests with meaningful assertions
- **Safety model**: CONSTITUTION.md is thoughtful and actionable
- **Audit logging**: Both `ir-log` and extension-level session logging
- **Atomic writes**: Intel store uses tmp+rename pattern
- **Write serialization**: `withIntelWriteLock` prevents concurrent corruption

### What's not bloat (looks complex but earned):
- The remote-session extension's marker-based output detection — this is the correct approach for persistent shell sessions
- Telnet negotiation handling — necessary for network device support
- The intel store's multi-file YAML layout — right trade-off for human editability vs. single-DB complexity
- Multiple `intel-snippet` templates — the templates encode real domain knowledge about source provenance per artifact type

---

## Suggested Priority Order

1. Rotate and remove the `.env` secret (5 min)
2. Delete `temp/` (or document why it's needed) (5 min)
3. Remove `__pycache__` from git (2 min)
4. Replace python3 subprocess YAML with JS yaml package (30 min)
5. Simplify `intel-snippet` YAML serializer (15 min)
6. Add `intel_update` tool (45 min)
7. Extract connection functions from remote-session.ts (30 min)
8. Add graceful YAML parse error handling (15 min)
9. Everything else as time permits
