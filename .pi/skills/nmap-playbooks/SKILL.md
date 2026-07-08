---
name: nmap-playbooks
description: Use when the task involves authorized network discovery, service fingerprinting, NSE script selection, host/service validation, or safe scan design with nmap, ncat, nping, ndiff, and installed NSE scripts.
allowed-tools: read bash
---

# Nmap Playbooks

Use this skill to design and run **authorized** Nmap workflows from the container.

Default posture:
- Prefer **safe, discovery, and version** workflows first.
- Prefer **targeted** scans over broad noisy scans.
- Save results with `-oA` when findings matter.
- Use **`-sT`** when scanning through SOCKS/ProxyChains or from unprivileged contexts.
- Use **`-Pn`** when host discovery is blocked or misleading.
- Do **not** use intrusive/brute/exploit/dos/broadcast scripts unless the operator explicitly wants that and the scope allows it.

## Tools available

- `nmap` — discovery, port scan, service/version detection, NSE
- `ncat` — banner grabbing, ad hoc TCP/UDP/SSL tests, listeners and relays
- `nping` — packet-level validation, latency, TCP/UDP/ICMP probing
- `ndiff` — compare two XML scan results to spot changes
- NSE scripts in `/usr/share/nmap/scripts/`

## When to use

- Identify live hosts in an authorized segment
- Find exposed services on compromised or adjacent systems
- Select relevant NSE scripts for SMB, HTTP, DNS, TLS, SSH, RDP, databases, or mail
- Re-scan after containment/eradication to validate exposed surface
- Compare before/after scans with `ndiff`
- Validate connectivity through pivots, tunnels, or ACL changes

## Quick workflow

1. Confirm scope, network path, and whether direct SYN scanning is allowed.
2. Choose **host discovery** or **service validation** first.
3. Run the smallest useful scan.
4. Add `-sV`, `-O`, or targeted NSE only when needed.
5. Save results with `-oA <prefix>` for evidence.
6. Escalate to intrusive categories only with explicit justification.

## Core scan patterns

### Fast service validation

```bash
nmap -Pn -n -sT --open -p 22,80,135,139,445,3389,5985,5986 <target>
```

### Top ports on a host

```bash
nmap -Pn -n -sT --top-ports 1000 --open <target>
```

### Version detection on known ports

```bash
nmap -Pn -n -sT -sV -p 22,80,443,445,3389,5985,8443 <target>
```

### Careful subnet sweep

```bash
nmap -sn -n <cidr>
```

### SYN scan when direct/root access is available

```bash
nmap -Pn -n -sS --top-ports 1000 --open <target>
```

### Targeted UDP validation

```bash
nmap -Pn -n -sU --top-ports 20 --open <target>
```

### Evidence-preserving output

```bash
mkdir -p workspace/scans
nmap -Pn -n -sT -sV --top-ports 200 --open -oA workspace/scans/web01-top200 <target>
```

## Working through pivots

### Through SOCKS / ProxyChains

Use TCP connect scans because raw packet scans usually will not work through SOCKS.

```bash
proxychains4 nmap -Pn -n -sT -sV -p 22,80,443,445,3389 <target>
```

### Through SSH local forwards

If a service is forwarded locally, scan the local bind port instead of the remote host.

```bash
nmap -Pn -n -sT -sV -p <local_port> 127.0.0.1
```

## NSE usage

### Discover scripts by name or category

Use the helper:

```bash
./scripts/nse-lookup.sh --category safe
./scripts/nse-lookup.sh --category vuln --search smb
./scripts/nse-lookup.sh --search http
./scripts/nse-lookup.sh --file smb-enum-shares.nse
```

Or native Nmap help:

```bash
nmap --script-help default
nmap --script-help smb-*
nmap --script-help "http-* and safe"
```

### Default-safe starting point

```bash
nmap -Pn -n -sT -sV --script "default or safe" <target>
```

### Useful category guidance

- `default` — sensible baseline scripts
- `safe` — generally low-risk enumeration
- `discovery` — identify service/host details
- `version` — supplement service detection
- `auth` — auth-related checks and light enumeration
- `vuln` — vulnerability checks; review before use
- `brute`, `intrusive`, `exploit`, `dos`, `broadcast`, `external` — higher risk or noisier; use only with intent and authorization

## Common service playbooks

### SMB / Windows exposure

```bash
nmap -Pn -n -sT -p 139,445 -sV --script smb-os-discovery,smb-protocols,smb-security-mode,smb-enum-shares,smb-enum-users <target>
```

If credentials are available and explicitly approved:

```bash
nmap -Pn -n -sT -p 445 --script smb-enum-shares,smb-enum-users \
  --script-args smbusername='<user>',smbpassword='<pass>' <target>
```

### HTTP / HTTPS

```bash
nmap -Pn -n -sT -p 80,443,8080,8443 -sV \
  --script http-title,http-headers,http-methods,http-enum,ssl-cert <target>
```

### TLS surface

```bash
nmap -Pn -n -sT -p 443,636,993,995,8443 \
  --script ssl-cert,ssl-enum-ciphers <target>
```

### DNS

```bash
nmap -Pn -n -sU -p 53 -sV --script dns-recursion,dns-service-discovery <target>
```

### SSH

```bash
nmap -Pn -n -sT -p 22 -sV --script ssh-hostkey,ssh-auth-methods <target>
```

### RDP

```bash
nmap -Pn -n -sT -p 3389 -sV --script rdp-enum-encryption,rdp-ntlm-info <target>
```

### WinRM

```bash
nmap -Pn -n -sT -p 5985,5986 -sV --script http-title,http-auth-finder <target>
```

## Companion tools

### ncat for manual validation

```bash
ncat -nv <target> 443
ncat --ssl -nv <target> 443
ncat -ulnv <target> 53
```

### nping for reachability / latency / packet behavior

```bash
nping --tcp -p 443 <target>
nping --udp -p 53 <target>
nping --icmp <target>
```

### ndiff for before/after comparison

```bash
ndiff workspace/scans/pre.xml workspace/scans/post.xml
```

## Output expectations

When using this skill for a user task:
- recommend the exact `nmap` command
- explain why the scan type fits the network path
- call out noise/risk level
- suggest relevant NSE scripts and categories
- prefer `-oA workspace/scans/<name>` when the result matters
- mention follow-on validation with `ncat`, `nping`, or `ndiff` when useful

## Safety guardrails

- Stay inside authorized scope only.
- Prefer safe/discovery scripts first.
- Warn before using `-O`, `-A`, `-p-`, UDP broad scans, or intrusive NSE categories.
- Avoid credentialed NSE unless credentials are already authorized for that host.
- For scans through SOCKS, prefer `-sT`; `-sS` and some NSE behavior may fail.
