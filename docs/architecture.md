# Architecture

## Goal

Provide a containerized pi harness for authorized incident response, active threat pursuit, and attacker eradication across mixed environments.

## Non-Goals

- Attacking external or third-party systems outside incident scope.
- Operating without authorization context.
- Replacing mature orchestration systems before they are needed.

## Components

### Container Image

The image contains client-side IR and administration tools. It does not run a daemon by default.

Tools include:
- OpenSSH client (pivoting, tunneling, key-based access)
- PowerShell 7 (remote Windows administration)
- Impacket suite (PsExec, WMIExec, SMBExec, secretsdump, ntlmrelayx)
- CrackMapExec / NetExec (credential validation, lateral movement)
- proxychains4 (SOCKS proxying through pivot chains)
- nmap / ncat / nc (reconnaissance and relay)
- Standard Unix utilities

### Inventory

During active incidents, track discovered hosts in `workspace/scope.yaml` for reporting.

### Tools

All tools (`ssh`, `nmap`, `secretsdump.py`, `crackmapexec`, etc.) are used directly. No allowlist gates.

`bin/ir-log` is a minimal audit utility that appends timestamped entries to `logs/audit-YYYYMMDD.log`. It requires `BRJOTSKEL_AUTH_CONTEXT`.

The `remote-session` extension (`.pi/extensions/remote-session.ts`) provides persistent multi-session management with built-in audit logging for all commands.

### Logs

Logs are local plain-text append-only operational records. For production, mount `logs/` to durable storage and ship it to your central logging system. Every credential harvest, pivot, and eradication action is recorded.

## Operational Workflows

### 1. Reconnaissance & Scoping
- Network scanning of internal ranges to identify attacker infrastructure.
- Service enumeration on suspected compromised hosts.
- Passive credential harvesting (network captures, cached auth).

### 2. Credential Recovery
- Dump SAM/SYSTEM/SECURITY from confirmed compromised Windows hosts.
- Extract LSASS memory for cached credentials and Kerberos tickets.
- Collect /etc/shadow, SSH keys, and keyrings from compromised Linux hosts.
- Collect keychain metadata, SSH material, shell histories, and autologin/FileVault indicators from compromised macOS hosts.
- Validate recovered credentials against other systems to map attacker's reach.

### 3. Pivoting & Pursuit
- Establish SSH tunnels / SOCKS proxies through compromised hosts.
- Follow attacker's lateral movement path using recovered credentials.
- Map the full extent of compromised systems ("attacker's real estate").
- Normalize recovered profile/config artifacts into intel:
  - host `endpoints` from PuTTY / SSH / Ansible / VPN / remote-admin profiles
  - credential `source.path` / `source.tool` / `source.playbook` for provenance
  - pivot `evidence` entries from saved sessions, inventories, and config files
- Document all pivot paths for the incident timeline.

### 4. Active Containment
- Block C2 communications at host and network level.
- Kill attacker processes and sessions.
- Disable compromised accounts.
- Isolate systems pending full eradication.

### 5. Eradication
- Remove all identified persistence mechanisms.
- Force credential rotation for all harvested/exposed credentials.
- Verify eradication with post-action checks.
- Document all changes for the incident report.

## Platform Strategy

- Linux: SSH and native shell commands, plus gather playbooks for credentials, network, persistence, and protections.
- macOS: SSH and native shell commands, plus gather playbooks for `launchd`, keychain metadata, Wi-Fi preferences, autologin checks, FileVault/SIP state, and user persistence artifacts.
- Windows: PowerShell 7, PowerShell Remoting, WMI, SMB, RDP, or OpenSSH.
- Cisco/Juniper: SSH to device CLI or approved automation interfaces.
- Active Directory: Impacket, CrackMapExec for credential validation and lateral movement mapping.

## Proxy & Pivot Strategy

- First hop: Direct SSH/WinRM from harness to compromised host.
- Multi-hop: SSH ProxyJump or dynamic SOCKS through pivot chain.
- Windows pivoting: netsh portproxy, SSH tunnels, or Impacket SOCKS.
- All pivots documented in `workspace/pivot-chain.md`.

## Future Enhancements

Add only when required:

- Automated credential spray validation
- Graphical pivot/relationship mapping
- Integration with SIEM for real-time IOC correlation
- Automated persistence scanner across scope
- Session recording and replay
- Integration with ticketing/approval systems
