---
name: escalate-playbook
zero_key: false
description: "Privilege-escalation assessment playbooks for Linux, Windows, and macOS, focused on native-binary abuse, sudo/service/task misconfigurations, writable privileged paths, and LOLBAS/GTFOBins-style escalation opportunities."
---

# Escalate Playbook — Native Privilege Escalation Assessment

Privilege-escalation playbooks for answering:

- Can this foothold become admin/root/SYSTEM?
- Which escalation paths are realistic from the current context?
- Which paths rely on native binaries or misconfigurations already present?
- What evidence should be preserved before any exploit or containment action?

## Purpose and scope

- **Purpose**: Assess local privilege-escalation opportunities on a confirmed in-scope host using native commands and small read-only playbooks.
- **Scope**: Detection, validation, and prioritization of privesc paths inspired by **LOLBAS**, **GTFOBins**, and common misconfiguration playbooks.
- **Default posture**: **Read-only assessment first.** Identify exploitable conditions before suggesting any state-changing action.

## Core principles

1. **Native tools first** — prefer built-in OS tooling and binaries already present on the host.
2. **Read-only by default** — enumerate and validate conditions before attempting exploitation.
3. **Misconfigurations over exploits** — prioritize sudo, service, task, ACL, token, and writable-path issues before kernel exploitation.
4. **LOLBAS / GTFOBins awareness** — identify binaries that can be abused if present with elevated execution context.
5. **Preserve evidence** — note exact binary paths, service names, ACLs, registry keys, and task names.
6. **Stay role-aware** — distinguish admin tooling intentionally present from suspicious privilege pathways.

## Use when

- A compromised host has low privileges and you need to assess escalation options
- You need a structured, native-command privesc review during IR or threat pursuit
- You suspect the attacker used LOLBAS / GTFOBins style escalation
- You want to know which local misconfigurations should be fixed during eradication

## Do not use when

- The host is out of scope or not confirmed for investigation
- You need memory corruption or exploit-dev work
- The operator wants automatic exploitation without first validating conditions

## Playbook inventory

| Path | Platform | Focus |
|---|---|---|
| `linux/local-privesc-audit.sh` | Linux | Sudo, SUID/SGID, capabilities, writable privileged paths, cron/systemd, GTFOBins candidates |
| `windows/local-privesc-audit.ps1` | Windows | Privileges, token-abuse indicators, services, AlwaysInstallElevated, autologon, writable PATH, LOLBAS candidates |
| `macos/local-privesc-audit.sh` | macOS | Sudo, setuid, launchd/system paths, writable roots, TCC / authdb / installer clues |
| `scripts/escalate-lookup.sh` | helper | Search privesc and LOTL reference material quickly |

## Workflow

1. Confirm current user, groups, and privileges
2. Check **misconfigurations first**:
   - sudo / runas / saved creds
   - services and scheduled tasks
   - writable privileged directories or search paths
   - SUID / capabilities / setuid binaries
   - autologon / installer policy / token privileges
3. Map native-binary abuse opportunities:
   - **Windows**: LOLBAS-style binaries in elevated contexts
   - **Linux/macOS**: GTFOBins-style binaries with sudo or setuid context
4. Preserve exact evidence paths and ACLs
5. Record major findings with `intel_add` if they expose new accounts, credentials, or pivot paths
6. Only after validation, provide an explicit exploit plan if the user asks for it and scope allows it

## Investigation priorities

### Linux
- `sudo -l` and env/preserve rules
- SUID / SGID binaries, especially GTFOBins-relevant ones
- file capabilities (`getcap -r /`)
- writable root-owned scripts referenced by cron or systemd
- writable directories in `$PATH`
- docker/lxd/libvirt group membership
- kernel version only **after** simpler misconfigurations are checked

### Windows
- `whoami /priv` and token-abuse relevant rights
- unquoted service paths
- service registry/file ACL weaknesses
- AlwaysInstallElevated
- autologon, saved credentials, unattended-install files
- writable directories in machine/user `PATH`
- scheduled tasks running as high integrity
- LOLBAS candidates present in elevated or policy-bypass contexts

### macOS
- `sudo -l`
- setuid root binaries and unusual third-party tools
- writable launchd plists, scripts, and privileged helper paths
- installer receipts / package helpers
- authorization database and TCC clues
- admin group membership and passwordless sudo patterns

## LOLBAS / GTFOBins framing

This skill is inspired by native-binary abuse references:

- **LOLBAS**: Windows binaries/scripts that become dangerous when launched in elevated or policy-bypass contexts
- **GTFOBins**: Unix/macOS binaries that become dangerous when granted `sudo`, SUID, or similar elevated execution

The playbooks focus on **finding the condition** that would make those binaries abusable.

Examples:
- `sudo vim`, `sudo find`, `sudo python3`, or SUID `bash` on Linux/macOS
- writable service path + `sc.exe`/service restart opportunity on Windows
- `msiexec`, `schtasks`, `eventvwr`, `fodhelper`, `regsvr32`, `rundll32`, or `cmdkey` related evidence on Windows

## Helper usage

```bash
./scripts/escalate-lookup.sh --search sudo
./scripts/escalate-lookup.sh --search SeImpersonatePrivilege
./scripts/escalate-lookup.sh --search AlwaysInstallElevated
./scripts/escalate-lookup.sh --topic linux
./scripts/escalate-lookup.sh --topic windows
```

## Output expectations

When using this skill, return:

- current privilege context
- prioritized escalation findings
- exact evidence paths / names / ACLs
- which finding is **validated**, **suspected**, or **blocked**
- a separate **next-step** section if exploitation is requested

Prefer sections like:

```text
=== OBJECTIVE ===
=== CURRENT_CONTEXT ===
=== VALIDATED_PATHS ===
=== SUSPICIOUS_MISCONFIGS ===
=== LOLBAS_GTFOBINS_CANDIDATES ===
=== EVIDENCE_TO_PRESERVE ===
=== NEXT_ACTIONS ===
```

## Relationship to other skills

- Use **`gather-playbooks`** for broad host collection
- Use **`host-ir-playbooks`** when the question is whether the host is compromised
- Use **`shell-commands`** for one-off privesc, containment, or eradication command generation
- Use **`escalate-playbook`** when the key question is: **"how can this foothold become admin/root, using what is already on the host?"**

## Reference material

This skill's helper searches the following reference docs already present in the skill corpus:

- `../shell-commands/reference/privilege-escalation.md`
- `../shell-commands/reference/living-off-the-land.md`
- `../shell-commands/reference/lolbas-full.md`
- `../shell-commands/reference/gtfobins-full.md`
- `../shell-commands/reference/windows-powershell.md`
- `../shell-commands/reference/linux-ir.md`

## Validation checklist

- [ ] Read-only by default
- [ ] Native OS commands only in playbooks
- [ ] Misconfigurations prioritized over kernel exploits
- [ ] LOLBAS / GTFOBins candidates tied to actual elevated execution context
- [ ] Exact evidence paths, service names, ACLs, and task names preserved
- [ ] Findings clearly separated into validated vs suspected
- [ ] Any state-changing exploit step only proposed after explicit request
