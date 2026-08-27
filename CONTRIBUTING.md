# Contributing

How to add playbooks, extend the agent, run tests, and keep the tool sharp.

---

## Ground rules

- **Native OS commands only on target hosts.** No curl downloads, no pip installs, no third-party binary uploads inside playbooks. Script text may be staged temporarily only when cleaned up.
- **Read-only by default.** Playbooks that change host state must say so prominently at the top.
- **Evidence first.** Any script that destroys volatile state (killing processes, locking accounts) must capture that state first.
- **Test before pushing.** `bash bin/test` must pass cleanly — syntax checks, strict TypeScript typecheck, unit tests, executable bit policy.
- **Record as you go.** New capabilities belong in the appropriate SKILL.md inventory table and, if relevant, in the README platform coverage table.

---

## Adding playbooks

### Where to put them

```
.pi/skills/gather-playbooks/linux/         # bash, read-only collection
.pi/skills/gather-playbooks/windows/       # PowerShell, read-only collection
.pi/skills/gather-playbooks/macos/         # bash, read-only collection
.pi/skills/gather-playbooks/network-device/ # command references, not automated
.pi/skills/host-ir-playbooks/linux/        # bash, investigation-focused
.pi/skills/host-ir-playbooks/windows/      # PowerShell, investigation-focused
.pi/skills/host-ir-playbooks/macos/        # bash, investigation-focused
.pi/skills/containment-playbooks/linux/    # bash, state-changing
.pi/skills/containment-playbooks/windows/  # PowerShell, state-changing
.pi/skills/containment-playbooks/macos/    # bash, state-changing
.pi/skills/eradication-playbooks/linux/    # bash, state-changing
.pi/skills/eradication-playbooks/windows/  # PowerShell, state-changing
.pi/skills/eradication-playbooks/macos/    # bash, state-changing
```

### Script standards

```sh
#!/bin/sh
# category/platform/name.sh — One-line description
# Requires: root / admin / user context
# State-changing: YES/NO — brief note on what changes if YES
# Pattern: EVIDENCE → ACT → VERIFY  (for state-changing scripts)
#
# Parameters:
#   TARGET_FOO  — description (required/optional)
#
# Usage:
#   TARGET_FOO=bar remote_exec(session="host01", command="<paste>")
```

- Shebang (`#!/...`) is required. `bin/smoke-check` enforces the executable bit on every tracked shebang script.
- Section headers: `sec(){ printf '\n=== %s ===\n' "$1"; }` — consistent with existing scripts.
- Declare `Sensitive-output: YES` if the script can print hashes, tokens, keys, passwords, configs containing secrets, shell history credential hits, or credential-bearing artifacts.
- For state-changing scripts: include `Pattern: EVIDENCE/RECORD → ACTION → VERIFY`, require an explicit target parameter or confirmation variable, and end with an `INTEL UPDATE SNIPPET` section that emits a ready-to-paste `intel_update(...)` call.
- No persistent artifacts on target unless the playbook explicitly documents the staging path and handoff/cleanup step.

### After adding a script

1. Add the script to the relevant `SKILL.md` inventory table in its skill directory
2. Add it to `docs/playbooks.md`
3. Run `bin/check-playbook-inventory` and update docs if the enforced count changes
4. Run `bin/check-playbook-contracts` and normalize metadata/safety headers if it fails
5. Run `bash bin/test` — the smoke check will fail if the shebang is present but `+x` is missing

---

## Adding intel-snippet subcommands

`bin/intel-snippet` is a Python script. To add a subcommand:

1. Add a `cmd_<name>` handler function
2. Add a `sub.add_parser('<name>', parents=[common])` with appropriate arguments
3. Call `add_common_source(data, args)` for provenance
4. Call `print_result(category, id, data, summary)`
5. Add a test in `tests/python/test_intel_snippet.py`

---

## Extension development

Extensions live in `.pi/extensions/`. Pi loads all `.ts` files in that directory automatically. Shared library code lives in `.pi/extensions/lib/`.

```
.pi/extensions/
  remote-session.ts        — remote tool registration + session execution
  intel-store.ts           — intel store tools
  persona.ts               — Ghost persona + live intel state injection
  lib/
    remote-types.ts        — shared types, constants, logging
    remote-helpers.ts      — shell quoting, platform detection
    remote-session-core.ts — marker commands, relay builders, tunnel arg builders
    protocol-adapters/
      ssh.ts               — SSH connection adapter
      winrm.ts             — WinRM/pwsh adapter
      tcp-telnet.ts        — TCP + telnet adapters
    tunnel-manager.ts      — SSH tunnel spawn + lifecycle
    relay-manager.ts       — relay setup, verification, teardown
    operator-shortcuts.ts  — phase shortcut formatters + prompts
    operator-runtime.ts    — slash command handlers, intel snapshot, scope rendering
    intel-helpers.ts       — intel schema validation, status enums
    intel-store-core.ts    — intel CRUD, attack graph, timeline filtering
    intel-permissions.ts   — file permission hardening
    simple-yaml.ts         — in-process YAML parser/dumper
```

**Live-reload during development:** use the `dev` compose service so extension and skill changes are visible without rebuilding:

```sh
docker compose run --rm dev
```

Or without Compose:

```sh
docker run --rm -it \
  -v "$PWD/.pi:/opt/brjotskel/.pi" \
  -v "$PWD/workspace:/opt/brjotskel/workspace" \
  -v "$PWD/logs:/opt/brjotskel/logs" \
  brjotskel:local
```

Rebuild the image only when changing `bin/`, `Dockerfile`, or base OS dependencies.

---

## Running tests

```sh
bash bin/test
```

The test suite:
- Shell, Python, TypeScript, PowerShell syntax checks
- Strict TypeScript compiler check (`tsc --noEmit`) for `.pi/extensions/**/*.ts`
- Playbook inventory drift check
- Extension tool inventory drift check
- Playbook contract check for all 101 target-side scripts/snippets
- Shebang executable bit policy check
- Banned-pattern checks (stale tool references and unsafe target-side bootstraps)
- **Python unit tests** (`tests/python/`): `intel-snippet`, `ir-log`, `ir-search`, `ir-report`, `netexec-to-intel`, playbook contracts, docs hygiene, local cleanup
- **Node unit tests** (`tests/node/`): extension registration, intel store CRUD and validation, relay helpers, session management, operator shortcuts/runtime, YAML round-trip, attack graph, timeline filtering, tunnel manager lifecycle, relay manager orchestration

Current counts: **50 Python** | **102 Node** — all must pass before pushing.

---

## Local cleanup

```sh
bin/clean-local              # dry-run: show ignored scratch/cache targets
bin/clean-local --execute    # remove temp/, caches, __pycache__, *.pyc
```

`logs/` and `workspace/` are never touched unless `--include-case-data --execute` is supplied. Treat that as local incident-state destruction.

---

## CI

GitHub Actions runs the full test harness, builds the Docker image, validates `/opt/brjotskel/BUILD-MANIFEST.json`, generates a CycloneDX JSON SBOM with `bin/image-sbom`, and uploads both integrity artifacts on every push and pull request. See `.github/workflows/ci.yml`.

---

## Container trust boundary

Production incident containers must stay non-root and least-privilege:

- Keep the image `USER` as `brjotskel`; use `BRJOTSKEL_UID`/`BRJOTSKEL_GID` build args to match host bind-mount ownership instead of running as root.
- Keep production Compose on `no-new-privileges:true` with `cap_drop: [ALL]`. Add capabilities only in local mission overrides, and document the reason (for example raw-socket scans).
- Treat `.pi/` as executable code. Production runs use baked-in root-owned read-only settings/extensions/skills, or a read-only bind mount. The baked-in `.pi/` parent may accept transient pi lock directories only; writable `.pi/` bind mounts are dirty/dev-only for live reload.
- Only `logs/` and `workspace/` should be writable case-data mounts in production. Do not add broad writable mounts unless the evidence plan requires them.

---

## Dependency pinning and update workflow

Incident images must be reproducible enough to defend the evidence chain. Do not switch back to floating package installs.

Pinned in `Dockerfile`:
- Debian base image digest
- Node.js version + Linux tarball SHA-256
- pi coding agent npm version
- `pi-smart-fetch` package version
- PowerShell apt package version
- Rust toolchain used for Python build dependencies

Pinned in repo config:
- `requirements-harness.txt` pins Impacket, NetExec, their direct Git dependencies, and Python transitive dependencies
- `.nvmrc` matches the Docker Node.js version and CI `setup-node` input
- `package-lock.json` pins TypeScript compiler dependencies used by `tsc --noEmit`
- `.pi/settings.json` uses a versioned `npm:pi-smart-fetch@...` package spec

Build integrity artifacts:
- `bin/build-manifest` runs inside the Docker build and writes `/opt/brjotskel/BUILD-MANIFEST.json` with pinned inputs, source metadata, tool versions, package inventories, selected file hashes, and known non-hermetic inputs.
- CI runs `bin/image-sbom brjotskel:ci` and uploads `artifacts/brjotskel-sbom.cdx.json` plus `artifacts/BUILD-MANIFEST.json`.
- Incident-release images are not fully hermetic until Debian apt, Microsoft apt, PyPI, npm, and rustup inputs come from controlled mirrors or hash-locked caches. For now, preserve the SBOM/manifest pair with the case package and record any local mirror override used.

To bump dependencies:
1. Update the relevant Docker `ARG` value(s), `requirements-harness.txt`, `.nvmrc`, and `.pi/settings.json` together.
2. Prefer immutable refs: commit SHA for Git dependencies, exact versions for npm/pip/apt.
3. Refresh SHA-256 values from upstream release checksum files; do not trust a copied blog/snippet hash.
4. Run `bash bin/test`.
5. Run `docker build --no-cache --build-arg BRJOTSKEL_BUILD_REF=$(git rev-parse HEAD) -t brjotskel:dependency-bump .` and record key tool versions in the PR.
6. After a successful image build, verify `docker run --rm --entrypoint python3 brjotskel:dependency-bump -m json.tool /opt/brjotskel/BUILD-MANIFEST.json >/dev/null` and review the `tool_versions`, `pinned_inputs`, and `known_non_hermetic_inputs` sections.
7. Verify `docker run --rm --entrypoint python3 brjotskel:dependency-bump -m pip freeze --all | sort` matches `requirements-harness.txt` plus the NetExec line for `NETEXEC_COMMIT`.
8. Generate a local SBOM when changing image dependencies: `bin/image-sbom brjotskel:dependency-bump > brjotskel-sbom.cdx.json`.
9. Add a CHANGELOG entry describing operator-impacting changes.

---

## Current capability status

| Capability | Status |
|-----------|--------|
| AI-native investigation agent (pi) | ✅ |
| Persistent multi-protocol remote sessions — SSH, WinRM, TCP, telnet | ✅ |
| SSH tunnels (local, remote, dynamic SOCKS) | ✅ |
| Native TCP relays (socat, ncat, nc, netsh portproxy) | ✅ |
| Structured intel store with schema validation and lifecycle management | ✅ |
| Phase shortcuts: `/land`, `/assess`, `/pursue`, `/contain`, `/eradicate`, `/verify` | ✅ |
| `/scope`, `/map`, `/brief`, `/incident` agent commands | ✅ |
| Linux gather playbooks — 19 scripts | ✅ |
| Windows gather playbooks — 28 scripts | ✅ |
| macOS gather playbooks — 11 scripts | ✅ |
| Network device CLI references — Cisco IOS/NX-OS, Juniper JunOS | ✅ |
| Host IR playbooks — Linux (2), Windows (8), macOS (2) | ✅ |
| Containment playbooks — Linux/Windows/macOS | ✅ |
| Eradication playbooks — Linux/Windows/macOS | ✅ |
| Privilege escalation assessment — Linux, Windows, macOS | ✅ |
| Kerberoasting + AS-REP roast workflows | ✅ |
| Cloud credential enumeration — EC2/Azure/GCP IMDS | ✅ |
| Binary integrity verification — Linux, Windows | ✅ |
| Operator audit logging — text and JSONL | ✅ |
| `ir-search` — fzf-based interactive log search with saved selected hits | ✅ |
| `ir-package` — sensitive incident handoff archive with manifests | ✅ |
| `intel-snippet` — normalized `intel_add(...)` generation | ✅ |
| `netexec-to-intel` — NetExec success output to `intel_update(valid_on=...)` | ✅ |
| `check-playbook-contracts` — metadata/safety contract gate for all 101 target-side scripts | ✅ |
| `check-tool-inventory` — generated extension tool inventory drift gate | ✅ |
| `clean-local` — dry-run local scratch/cache cleanup | ✅ |
| Persona auto-surfaces live intel state in every agent turn | ✅ |

For the open backlog, see [TODO.md](TODO.md).
