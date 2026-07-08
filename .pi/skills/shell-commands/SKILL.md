---
name: shell-commands
zero_key: false
description: "Generate shell commands for security investigation and IR across PowerShell, Windows CMD, and Unix/Linux. Covers forensic triage, threat hunting, persistence detection, credential harvesting, lateral movement, pivoting, active containment, and eradication using native OS tools."
---

# Shell Commands — Incident Response & Threat Pursuit Command Generator

Generate precise, ready-to-run shell commands for incident response, threat pursuit, and attacker eradication across three platforms: **PowerShell**, **Windows CMD**, and **Unix/Linux (bash)**.

## Purpose and scope

- **Purpose**: Given an IR task (e.g., "dump cached credentials from compromised host", "pivot through jump box to internal segment", "eradicate attacker persistence"), produce the correct command(s) for the analyst's target platform.
- **Scope**: Command generation and explanation only. Does NOT execute commands on remote systems. The operator copies and runs commands in their authorized environment.

## ⚠️ Core Constraint: Living off the Land + Harness Tools

**Prefer commands using built-in OS tools and utilities on target hosts.**

Do NOT suggest uploading binaries to compromised endpoints unless specifically authorized.

**Allowed on target hosts**: Native OS binaries, built-in PowerShell modules, standard Unix utilities, tools already present on the system.

**Allowed from harness**: Impacket, CrackMapExec/NetExec, proxychains, SSH, nmap — these run from the operator's container, not on the target.

**Exception — Active Pursuit & Eradication**: When following an attacker through the environment, the skill MAY generate offensive-style commands (credential harvesting, pivoting, tunnel establishment, persistence removal) using techniques documented in the offensive reference corpus. This is defensive use of offensive knowledge — pursuing the adversary to map and eliminate their presence.

## Use when

- Generating forensic/IR commands for triage
- **Credential harvesting** from confirmed compromised hosts (SAM/LSASS/shadow/keys/tickets)
- **Pivoting** through compromised systems to follow attacker's path
- **Lateral movement** using recovered credentials to map attacker's scope
- **Persistence discovery** and eradication across platforms
- **Active containment** — killing sessions, blocking C2, disabling accounts
- **Privilege escalation analysis** — understanding how attacker elevated
- Building triage scripts or one-liners for live response
- Translating tasks across platforms (PowerShell/CMD/Linux)
- Hunting for persistence, lateral movement, credential access, exfiltration artifacts
- Network forensics and tunnel detection
- Red team command reference for purple team exercises

## Do not use when

- The task targets systems outside the authorized incident scope
- The task requires attacking external/third-party infrastructure
- The task is SIEM query construction (use investigate-loganalytic, investigate-splunk, etc.)
- You need API calls to security platforms (use platform-specific skills)

## Scripted Shortcuts

`script/shell-lookup.sh` is a corpus search helper for the reference library. It does not replace the skill's synthesis step; it helps locate relevant sections and command patterns quickly.

```bash
# Look up commands by category and platform
./scripts/shell-lookup.sh --platform powershell --category persistence
./scripts/shell-lookup.sh --platform linux --category credentials
./scripts/shell-lookup.sh --platform cmd --category lateral-offense
./scripts/shell-lookup.sh --search "LSASS"
./scripts/shell-lookup.sh --search "pivot"
./scripts/shell-lookup.sh --list-categories
```

## Inputs required

| Context | Input |
|---------|-------|
| Platform | `powershell`, `cmd`, or `linux` (can request multiple) |
| Task | Natural language description |
| Category (optional) | `processes`, `network`, `persistence`, `users`, `files`, `logs`, `memory`, `registry`, `services`, `lateral-movement`, `credentials`, `exfiltration`, `privesc`, `tunneling`, `persist-implant`, `lateral-offense`, `containment`, `eradication`, `anti-forensics`, `browser`, `evidence`, `lolbas`, `gtfobins` |

## Generation steps

1. Identify the platform and desired outcome.
2. Consult reference corpus (`reference/`) for validated commands.
3. Generate the smallest useful command.
4. Include comments and privilege requirements.
5. Mark state-changing commands clearly.
6. For credential harvesting: note what is recovered and recommend forced rotation.
7. For pivoting: document the tunnel/proxy chain being established.
8. For eradication: provide verification commands after removal.

## Output format

Commands are returned in fenced code blocks with the platform noted:

```powershell
# Dump SAM/SYSTEM hives from compromised host (requires local admin).
# State-changing: creates registry save files.
reg save HKLM\SAM C:\temp\sam.hiv
reg save HKLM\SYSTEM C:\temp\system.hiv
# Transfer to harness, then: secretsdump.py -sam sam.hiv -system system.hiv LOCAL
```

```bash
# Establish SOCKS proxy through compromised pivot host for internal scanning.
# Read-only on pivot (SSH session only).
ssh -D 1080 -f -N -o StrictHostKeyChecking=no user@pivot-host
# Then from harness: proxychains nmap -sT -Pn 10.10.10.0/24 -p 22,445,3389
```

Each command includes:
- What it does
- Platform and privilege requirements
- Whether it changes system state
- Post-action steps (credential rotation, verification, etc.)

## Reference

The reference corpus covers both defensive detection and offensive execution:

### Defensive (Blue Team)
- **`reference/living-off-the-land.md`** — Native OS tools for IR; LOLBAS/GTFOBins awareness
- **`reference/lolbas-full.md`** — Complete LOLBAS detection reference (150+ Windows binaries)
- **`reference/gtfobins-full.md`** — Complete GTFOBins detection reference (400+ Unix binaries)
- **`reference/windows-powershell.md`** — PowerShell forensics, hunting, and IR commands
- **`reference/windows-cmd.md`** — Native Windows CMD forensic triage commands
- **`reference/linux-ir.md`** — Linux/Unix incident response and forensics
- **`reference/network-forensics.md`** — Cross-platform network investigation
- **`reference/persistence-detection.md`** — Persistence mechanism detection
- **`reference/lateral-movement.md`** — Lateral movement artifact discovery
- **`reference/anti-forensics-evidence.md`** — Anti-forensics detection, browser forensics, evidence safety

### Offensive (Threat Pursuit & Eradication)
- **`reference/active-containment.md`** — Kill processes, block C2, disable accounts, remove persistence
- **`reference/privilege-escalation.md`** — Privilege escalation techniques with detection signatures
- **`reference/tunneling-relaying.md`** — SSH tunnels, Chisel, Ligolo, SOCKS, NTLM relay, DNS/ICMP tunnels
- **`reference/persistence-implant.md`** — How attackers implant persistence (registry, cron, services, WMI, SSH keys, webshells)
- **`reference/lateral-movement-offensive.md`** — PsExec, WMI, WinRM, DCOM, PTH, PTT, credential harvesting, SSH pivoting

## Validation checklist

- [ ] Commands are syntactically correct for the target platform
- [ ] Privilege requirements are noted
- [ ] State-changing commands include clear warning
- [ ] Credential harvesting commands note what to rotate after incident
- [ ] Pivot commands document the chain being established
- [ ] Eradication commands include post-action verification
- [ ] Operations stay within authorized incident scope
- [ ] Evidence collection occurs before destructive actions where feasible

## Failure and fallback handling

- **Unknown platform**: Ask operator to specify powershell/cmd/linux
- **No exact match in corpus**: Synthesize from reference patterns; note source
- **Requires tool not in harness**: Note dependency and suggest native alternative
- **Using `shell-lookup.sh`**: `--search` performs a literal keyword search; `--category` uses curated regex patterns
- **Outside scope**: Refuse and clarify incident boundaries

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/shell-lookup.sh` | Search reference corpus by platform, category, or keyword |
