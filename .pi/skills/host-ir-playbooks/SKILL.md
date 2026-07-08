---
name: host-ir-playbooks
zero_key: false
description: "Host-centric incident response playbooks for investigating whether a specific Linux, Windows, or macOS system shows signs of compromise, what artifacts exist, how the attacker persisted, and what the host's role is in the environment. Native OS commands only on target hosts."
---

# Host IR Playbooks — Compromise Artifact Hunting

Host-specific incident response playbooks for answering:

- Is this host compromised?
- What artifacts support that conclusion?
- What persistence exists?
- What credentials, sessions, or remote access paths were exposed?
- What role does this host play in the environment?
- What should be collected before containment or eradication?

## Purpose and scope

- **Purpose**: Drive focused investigation on a single host using native OS commands and small read-only scripts.
- **Scope**: Host-centric artifact hunting, environment understanding, and evidence-first triage.
- **Not the same as** `gather-playbooks`: that skill is broad collection-oriented; this skill is centered on proving or disproving compromise on one host.

## Core principles

1. **Host-first** — optimize for understanding one system deeply before expanding scope.
2. **Evidence first** — prefer collecting volatile and high-signal artifacts before making changes.
3. **Native commands only** — no binary uploads to the target.
4. **Read-only by default** — do not change host state unless the user explicitly asks for containment/eradication steps.
5. **Explain significance** — findings should help distinguish suspicious from routine administration.

## Use when

- A newly identified host may be compromised
- You need to confirm attacker presence on a specific system
- You need to understand how the attacker persisted or moved from that host
- You need host context before containment
- You need to identify what evidence to preserve from that host

## Do not use when

- You need broad post-exploitation collection across many hosts
- You already know the host is compromised and just need generic enumeration
- You need destructive containment or eradication without first preserving evidence

## Investigation goals

For each host, prioritize:

1. **Host role** — what the system is and what it normally does
2. **Live activity** — processes, sessions, network connections, scheduled jobs, services
3. **Persistence** — startup mechanisms, launch points, scheduled execution
4. **Execution history** — shell history, recent tasks, recent files, event logs
5. **Credential exposure** — local secrets, key material, cached auth artifacts
6. **Lateral movement** — inbound/outbound admin access, shares, remote tooling, pivots
7. **Defense state** — AV/EDR/firewall status and signs of tampering
8. **Collection priorities** — what to save before containment

## Starter playbooks

This skill currently ships as a **starter set**: a few focused host-IR playbooks that establish platform parity for first-pass assessment, plus one deeper Windows persistence playbook.

| Path | Platform | Focus |
|---|---|---|
| `linux/initial-assessment.sh` | Linux | Initial compromise assessment, live activity, persistence clues, recent execution clues, and security state |
| `windows/triage.ps1` | Windows | Recommended first-pass wrapper for host context, high-signal event review, and Sysmon triage |
| `windows/initial-assessment.ps1` | Windows | Initial compromise assessment, live activity, recent execution clues, persistence indicators, and security state |
| `windows/persistence-hunt.ps1` | Windows | Deeper Windows persistence review: services, Run keys, scheduled tasks, WMI, startup folders, and remote-access clues |
| `windows/eventlog-hunt-lite.ps1` | Windows | Quick high-signal Windows event review for logons, PowerShell, services, tasks, WMI, RDP, Defender, and log clearing |
| `windows/eventlog-hunt.ps1` | Windows | Host-centric Windows event investigation for logons, PowerShell, service/task creation, WMI, RDP, Defender, log clearing, and Sysmon |
| `windows/powershell-reconstruction.ps1` | Windows | Reconstruct PowerShell activity from 4103/4104/4105/4106, classic PowerShell logs, history, and execution-policy artifacts |
| `windows/sysmon-hunt.ps1` | Windows | Sysmon-focused hunt for execution, network, registry/file changes, injection/process access, DNS, WMI, pipes, and tampering |
| `macos/live-response.sh` | macOS | Live-response triage, launchd persistence, recent execution clues, and security state |

## Playbook categories

### Linux
- Initial host assessment
- Suspicious process and connection review
- Persistence hunting (`systemd`, cron, rc scripts, SSH keys)
- Auth and shell-history review
- Recent file/change review
- Credential exposure review (`shadow`, keys, tokens, `.env`)
- Security control review
- Server-role understanding (web/db/app/container)

### Windows
- Initial host assessment
- Suspicious process, service, task, and connection review
- Persistence hunting (Run keys, services, tasks, WMI, startup folders)
- Logon, PowerShell, and event-log review
- Event-centric hunt for Security, System, TaskScheduler, PowerShell, WMI-Activity, TerminalServices, Defender, and Sysmon channels
- PowerShell reconstruction using operational logs (`4103`, `4104`, `4105`, `4106`), classic PowerShell engine events, and host history
- Sysmon-centric hunt for process execution (`1`), network (`3`), timestomping (`2`), process access/injection (`8`,`10`,`25`), registry/file changes (`11`,`12`,`13`,`15`), DNS (`22`), WMI persistence (`19`,`20`,`21`), and config tampering (`16`)
- Credential access artifact review
- Lateral movement artifact review (SMB, WinRM, RDP, PsExec/WMI clues)
- Defender/EDR tampering checks
- Host-role understanding (workstation/server/DC)

### macOS
- Initial host assessment
- Suspicious process and connection review
- Persistence hunting (`launchd`, login items, shell/profile hooks)
- Unified log and recent execution review
- Keychain / SSH / history artifact review
- Browser and user-artifact review
- Security-state review (FileVault, SIP, controls)
- Host-role understanding

## Expected workflow

1. Identify platform and host role
2. Collect volatile live-state artifacts first
3. Hunt persistence and recent execution artifacts
4. Review credential and lateral movement clues
5. Record findings with `intel_add`
6. Add major conclusions to the timeline
7. Recommend next host-specific actions

### Recommended Windows first-pass order

1. `windows/triage.ps1`
2. `windows/eventlog-hunt.ps1`
3. `windows/sysmon-hunt.ps1` (if Sysmon is present)
4. `windows/powershell-reconstruction.ps1` (if PowerShell activity is suspected)
5. `windows/persistence-hunt.ps1`

## Output expectations

When using this skill, produce:

- A short host assessment summary
- Commands or small scripts grouped by objective
- Notes on why each artifact matters
- Clear separation between:
  - evidence collection
  - analysis
  - containment-ready actions
- Where practical, explicit `SUSPICIOUS SIGNS` and `NEXT ACTIONS` guidance in the playbook output

## Relationship to other skills

- Use **`gather-playbooks`** for broad host collection and structured enumeration
- Use **`shell-commands`** for precise one-off command generation
- Use **`host-ir-playbooks`** when the key question is: **"what happened on this host?"**

## After-playbook recording examples

When a host-level finding is confirmed, record it immediately.

Example host update:

```text
intel_add(category="host", id="db01", data="ip: 10.10.20.15
platform: linux
status: compromised
notes: suspicious systemd service and outbound SSH pivot observed
source:
  discovered_from: host-ir-playbooks/linux/initial-assessment.sh
  method: live triage
", summary="db01 shows suspicious systemd persistence and outbound SSH activity")
```

Example account update:

```text
intel_add(category="account", id="corp\\backupsvc", data="type: domain-user
status: compromised
access_to:
  - db01
source:
  host: db01
  method: suspicious scheduled task / service context
", summary="backupsvc appears tied to suspicious persistence on db01")
```

Example pivot update:

```text
intel_add(category="pivot", id="db01-to-adminws", data="target: adminws
status: suspected
chain:
  - hop: db01
notes: outbound management connection observed during host IR triage
source:
  host: db01
  method: live connection review
", summary="Suspected pivot path from db01 to adminws discovered during host triage")
```

## Suggested playbook structure

For future sub-playbooks under this skill, use sections like:

```text
=== OBJECTIVE ===
=== COMMANDS ===
=== WHY IT MATTERS ===
=== SUSPICIOUS SIGNS ===
=== NEXT ACTIONS ===
```

## Validation checklist

- [ ] Focused on one host, not generic multi-host collection
- [ ] Native OS commands only
- [ ] Read-only unless containment is explicitly requested
- [ ] Volatile artifacts prioritized first
- [ ] Findings tied to compromise questions
- [ ] Recommendations distinguish evidence collection from response actions
