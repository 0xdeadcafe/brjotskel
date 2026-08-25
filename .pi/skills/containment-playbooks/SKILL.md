---
name: containment-playbooks
zero_key: false
description: "Evidence-first containment scripts for Linux, Windows, and macOS. Each script follows: capture volatile state → perform the minimum action → verify success → emit intel_update output. State-changing — read each script before running."
---

# Containment Playbooks

Structured, runnable containment scripts for active incident response. Each follows the same discipline:

1. **Evidence** — capture the volatile state that the action will destroy
2. **Act** — perform the minimum targeted action
3. **Verify** — confirm the action succeeded and nothing snuck back
4. **Record** — emit an `intel_update` or `intel_timeline` snippet ready to paste

## ⚠️ Rules before running any containment script

1. **Run `collect-evidence` first.** Evidence dies when you act. Always capture volatile state before touching anything: `.pi/skills/gather-playbooks/<platform>/collect-evidence.{sh,ps1}`.
2. **These scripts are state-changing.** They kill processes, modify firewall rules, lock accounts. Read each one before running.
3. **Supply parameters explicitly.** Scripts require environment variables or parameters — set them, don't run blindly.
4. **Verify each step.** Every script has a VERIFY section. Read the output, confirm the action worked.
5. **Don't tip off the attacker prematurely.** Premature containment drives them to unmapped hosts.
6. **Coordinate with incident commander** before host isolation (nuclear option).

## Timing guidance

| Action | When |
|--------|------|
| Kill process | When C2 callback confirmed, blast radius mapped, or active exfil detected |
| Block C2 IP | After recording the IP — can be done while preserving the session |
| Disable account | When confirmed compromised and rotation is coordinated |
| Isolate host | Last resort — only after all credential and pivot paths are mapped |

## Script inventory

### Linux

| Script | What it does |
|--------|-------------|
| `linux/kill-process.sh` | Identify, document (hash, cmdline, env), kill, verify gone |
| `linux/block-c2.sh` | Record C2 IP, add iptables/nft drop rules, verify, note analyst-IP safe |
| `linux/disable-account.sh` | Lock user, expire password, kill sessions, verify |
| `linux/isolate-host.sh` | Allow-analyst-only iptables, drop all other I/O, verify, document |

### Windows

| Script | What it does |
|--------|-------------|
| `windows/kill-process.ps1` | Document, Stop-Process, verify, hash binary |
| `windows/block-c2.ps1` | Record IP, New-NetFirewallRule (inbound + outbound), verify |
| `windows/disable-account.ps1` | Local and AD variants, kill sessions, verify |
| `windows/isolate-host.ps1` | Allow-analyst-only Windows Firewall rules, block-all default policy, verify |

### macOS

| Script | What it does |
|--------|-------------|
| `macos/kill-process.sh` | Document, kill, verify gone |
| `macos/block-c2.sh` | Record IP, pf rule, verify |
| `macos/disable-account.sh` | Disable password, set shell to /usr/bin/false, kill sessions, verify |
| `macos/isolate-host.sh` | Allow-analyst-only pf ruleset, block all other I/O, verify |

## Workflow

```
# 1. Collect evidence (ALWAYS first)
read .pi/skills/gather-playbooks/linux/collect-evidence.sh
remote_exec(session="host01", command="<paste collect-evidence>")
# Save output → workspace/evidence/host01/volatile-<ts>.txt

# 2. Run targeted containment
read .pi/skills/containment-playbooks/linux/kill-process.sh
remote_exec(session="host01", command="TARGET_PID=4523 <paste kill-process>")

# 3. Record in intel store
intel_update(category="host", id="host01",
  fields="status: contained\nnotes: PID 4523 killed, C2 185.x.x.x blocked",
  summary="host01 contained — process killed, C2 blocked")
```
