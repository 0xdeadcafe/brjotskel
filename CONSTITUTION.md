# Constitution

This project is an authorized incident response and threat pursuit harness for environments where an active compromise is being investigated.

## Mission

When an attacker is operating inside our environment, defenders must be able to **follow** the adversary — pivoting through compromised hosts, harvesting credentials the attacker has already exposed or cached, mapping persistence, and identifying all attacker-controlled "real estate" — in order to **eradicate** the threat completely.

## Principles

### KISS
- Prefer small shell/Python wrappers over frameworks.
- Keep configuration readable and versionable.
- Make failure modes obvious.

### YAGNI
- Do not add plugins, daemons, credential stores, or databases until required.
- Start with explicit inventories and operator-supplied credentials.

### Reuse before writing
- First ask whether a new wrapper, extension, or script needs to exist at all.
- Prefer existing platform tools, pi tools, shared scripts, and standard libraries before adding new code.
- Keep new code focused on the gaps that cannot be solved by composition.

### Operator-first
- Optimize for the responder under pressure: clear errors, low setup overhead, readable logs, and sane defaults.
- Favor workflows that work during active incidents without ceremony.
- Make common investigative paths fast and obvious.

### Understand before changing
- Trace the real incident workflow, host state, and likely operational impact before changing code or taking disruptive action.
- Prefer simplicity that comes from understanding the environment, not from skipping analysis.
- Investigate the shared cause, not just the visible symptom, when fixing workflows or tooling.

### Unix Philosophy
- Tools should do one thing well.
- Prefer files, stdin/stdout, and clear exit codes.
- Compose existing platform tools instead of reimplementing them.

## Safety Rules

- Only operate within the scope of the authorized incident.
- Log all operations locally with enough context to reconstruct what happened.
- Do not operate against systems outside the authorized scope.
- Do not exfiltrate data outside the authorized response environment.
- Do not destroy evidence; prefer collection before action.
- Prefer reversible actions where feasible.
- Use automation to collect, enrich, validate, and document. For disruptive actions, keep operator intent explicit.

## Authorized Threat Pursuit Activities

The following are explicitly authorized during active incident response:

### Credential Harvesting (from compromised hosts)
- Dump cached credentials, hashes, Kerberos tickets from hosts the attacker has already compromised.
- Recover credentials from memory (LSASS, /proc), registry (SAM/SYSTEM/SECURITY), shadow files, SSH keys, keyrings.
- Purpose: identify what the attacker has access to; determine lateral movement scope; invalidate stolen credentials.

### Pivoting & Lateral Movement
- Use compromised hosts as pivot points to reach attacker-controlled infrastructure within our environment.
- SSH tunneling, port forwarding, SOCKS proxying, ProxyJump through owned systems.
- Follow the attacker's path: use the same credentials/access paths they used to reach additional compromised hosts.
- Purpose: map attacker's full footprint; identify all compromised systems.

### Persistence Discovery & Eradication
- Identify attacker persistence mechanisms (registry, scheduled tasks, services, cron, SSH keys, webshells, WMI subscriptions, systemd units, startup scripts).
- Remove or disable persistence once documented.
- Purpose: ensure attacker cannot return after eradication.

### Privilege Escalation Analysis
- Identify how the attacker escalated privileges on each compromised host.
- Reproduce or validate escalation paths to understand scope of compromise.
- Purpose: close the vulnerability; determine what level of access attacker achieved.

### Active Containment & Eradication
- Kill attacker processes and sessions.
- Block C2 communications.
- Disable compromised accounts.
- Remove persistence artifacts.
- Isolate compromised systems.

## Rules of Engagement

1. **Scope**: Only pursue within the boundaries of the authorized incident. Never touch third-party or external systems.
2. **Evidence first**: Capture forensic snapshots before making state changes when feasible.
3. **Document everything**: Every pivot, credential harvest, and eradication action is logged with enough detail to reconstruct timestamp, host, and operator intent.
4. **Proportional action**: Use the minimum access needed to confirm and eradicate.
5. **Automation boundary**: Automation may reduce operator busywork, but containment, account disablement, host isolation, and eradication actions require explicit operator intent and, when feasible, incident-command coordination.
6. **Coordination**: Coordinate with the incident commander when expanding scope to new systems.
7. **Credential lifecycle**: All harvested credentials are reported for forced rotation after the incident.

## Supported Operations

- Linux/macOS: SSH using operator or recovered credentials/keys.
- Windows: PowerShell Remoting, WMI, SMB, RDP, or SSH using operator or recovered credentials.
- Cisco/Juniper: SSH/CLI using operator or recovered credentials.
- Internal pivoting: SSH tunnels, port forwards, SOCKS proxies through compromised hosts.
- Credential recovery: SAM/SYSTEM dump, LSASS access, shadow file reads, SSH key collection, Kerberos ticket extraction.
- Persistence eradication: Kill, disable, delete attacker artifacts across all platforms.

## Living off the Land

Use native administrative interfaces and tools already present on managed and compromised systems. When third-party tooling is required (e.g., Impacket from the harness), execute from the harness container — never drop tools onto compromised endpoints unless specifically authorized.
