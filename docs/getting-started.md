# Getting Started

You have access to a compromised host. You need to determine scope, follow the credential trail, and eradicate the attacker. This guide gets you from container start to first triage in under five minutes.

---

## Prerequisites

- Docker installed
- SSH access (or WinRM credentials) to at least one host in scope
- Authorized to investigate

---

## 1. Build and launch

```sh
git clone https://github.com/0xdeadcafe/brjotskel
cd brjotskel
docker compose build
docker compose run --rm brjotskel
```

The container starts directly in the [pi](https://github.com/earendil-works/pi) agent session, with the Ghost IR persona active. You are ready to work.

> The `logs/` and `workspace/` mounts are important — they persist your audit log and intel store across container restarts. Without them, everything is lost when the container exits.

---

## 2. Start an incident

Type `/incident` followed by a brief description of what you know:

```
/incident web server 10.10.10.5 suspected compromised — customer reported unusual outbound traffic
```

The agent will:
1. Ask for anything it's missing (scope, credentials, platform)
2. Record the initial host in the intel store
3. Suggest the first `nmap` connectivity check
4. Walk you to `remote_connect`

Or, if you prefer to drive manually:

```
Record web01 at 10.10.10.5 as a suspected Linux host. Then connect via SSH with password rootpass123.
```

---

## 3. Land and assess

Once the agent connects, type:

```
/assess web01
```

This triggers a platform-specific first look: live sessions, outbound connections, staging areas, immediate persistence indicators. The agent reads the output and flags anything suspicious.

Follow-up based on what you find:
- Suspicious outbound connection → credential recovery and pivot mapping
- Persistence artifact → full persistence sweep before touching anything
- Nothing obvious → deeper triage

---

## 4. Recover credentials and follow the trail

```
/pursue
```

This shows a live chase board: every unvalidated credential in the intel store with a pre-built `netexec` command to test it against every known host IP. Run the commands, update the intel store with what works.

As you find credentials, the blast radius expands. Follow each one.

---

## 5. Contain when the footprint is mapped

Don't contain prematurely. Premature containment tips off the attacker and drives them to hosts you haven't mapped yet.

When you're confident you've traced the full credential chain:

```
/contain web01
```

This produces an evidence-first containment pack: volatile state capture first, then targeted process kill, C2 block, and account disable — with verification steps for each action.

---

## 6. Eradicate and verify

```
/eradicate web01
/verify web01
```

`/eradicate` provides evidence-backed persistence removal scripts. Each one exports artifact evidence, removes it, and verifies the removal.

`/verify` re-runs first-look and persistence checks, confirms no C2 reconnection, and checks that accounts are locked.

---

## 7. Force credential rotation

After eradication, flag everything the attacker touched for rotation:

```
intel_query(query_type="all_credentials")
```

Coordinate with the identity team to reset each active credential, then record:

```
intel_update(category="credential", id="admin-ntlm",
  fields="status: rotated",
  summary="Domain admin password reset by identity team post-incident")
```

Once a credential is marked `rotated`, the intel store blocks retrieval of its secret — enforcing that stale credentials can't be accidentally reused.

---

## Key concepts

**Intel store** — `workspace/intel/` holds five YAML files: `hosts.yaml`, `credentials.yaml`, `accounts.yaml`, `pivots.yaml`, `timeline.yaml`. The agent writes to these on every finding. You can query, update, and view them at any point.

**Sessions** — every `remote_connect` call opens a named persistent shell session. Multiple sessions can be active simultaneously. All commands and output are logged to `logs/remote-sessions/`.

**Playbooks** — 96 native-OS scripts covering credentials, persistence, network, AD, cloud, and more. The agent reads and runs them inline — nothing is uploaded to the target. See [playbooks.md](playbooks.md) for the full list.

**Phase shortcuts** — `/assess`, `/pursue`, `/contain`, `/eradicate`, `/verify` are the fast path. They produce targeted command packs based on the current session state and intel store. Senior analysts can move through an incident entirely via shortcuts; the agent handles the rest.

---

## Useful commands at any point

```
/scope          — current sessions, tunnels, intel counts, last 5 timeline events
/map            — attack graph showing credential blast radius edges
/brief          — tactical intel brief: status, open leads, recommended next move
intel_summary() — host/credential/account/pivot counts and status breakdown
ir-log "note"   — append a manual note to the audit log
ir-search       — interactive fzf search across all audit and session logs
```

---

## Where to go next

- [scenario-walkthrough.md](scenario-walkthrough.md) — full end-to-end incident example
- [runbook.md](runbook.md) — complete command reference for every phase
- [intel-import-workflow.md](intel-import-workflow.md) — recording findings with full provenance
- [relay-pivoting.md](relay-pivoting.md) — reaching hosts you can't connect to directly
