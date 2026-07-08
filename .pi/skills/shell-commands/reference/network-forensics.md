# Network Forensics — Cross-Platform Commands

> Sources: Blue Team Field Manual, RTFM v3, IR best practices

---

## Connection Analysis

### PowerShell

```powershell
# All established connections with process info
Get-NetTCPConnection -State Established | ForEach-Object {
  $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  [PSCustomObject]@{
    Local = "$($_.LocalAddress):$($_.LocalPort)"
    Remote = "$($_.RemoteAddress):$($_.RemotePort)"
    PID = $_.OwningProcess
    Process = $proc.ProcessName
    Path = $proc.Path
  }
} | Sort-Object Remote | Format-Table -AutoSize

# Connections to non-standard ports (not 80, 443, 53)
Get-NetTCPConnection -State Established | Where-Object {
  $_.RemotePort -notin @(80, 443, 53, 22) -and $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)'
} | ForEach-Object {
  $proc = Get-Process -Id $_.OwningProcess -EA 0
  [PSCustomObject]@{ Remote="$($_.RemoteAddress):$($_.RemotePort)"; Process=$proc.ProcessName; PID=$_.OwningProcess }
}

# Connection frequency (beaconing detection)
$conns = @{}
1..60 | ForEach-Object {
  Get-NetTCPConnection -State Established | ForEach-Object {
    $key = "$($_.RemoteAddress):$($_.RemotePort)"
    if (!$conns[$key]) { $conns[$key] = 0 }
    $conns[$key]++
  }
  Start-Sleep -Seconds 1
}
$conns.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 20
```

### Linux

```bash
# All established connections with process
ss -tnp state established | column -t

# Connections to non-standard ports
ss -tnp state established | awk '$5 !~ /:(80|443|53|22)$/ {print}'

# Connection frequency (beaconing)
for i in $(seq 1 60); do
  ss -tn state established | awk '{print $5}' | sort
  sleep 1
done | sort | uniq -c | sort -rn | head -20

# Unique remote IPs communicating
ss -tn state established | awk '{print $5}' | cut -d: -f1 | sort -u

# Bandwidth per connection (requires nethogs or iftop)
nethogs -t -c 5 2>/dev/null
iftop -t -s 10 2>/dev/null
```

### CMD

```cmd
:: Established connections with PID
netstat -ano | findstr "ESTABLISHED"

:: Resolve PIDs to process names
for /f "tokens=5" %a in ('netstat -ano ^| findstr ESTABLISHED') do @tasklist /fi "pid eq %a" /fo csv /nh
```

## DNS Investigation

### PowerShell

```powershell
# DNS cache
Get-DnsClientCache | Where-Object { $_.Entry -notmatch 'microsoft|windows|bing' } |
  Select-Object Entry, RecordName, RecordType, Data | Sort-Object Entry

# DNS query logging (requires DNS debug logging enabled)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational'} -MaxEvents 100 -EA 0 |
  Select-Object TimeCreated, Message

# Suspicious DNS patterns (long subdomains = possible tunneling)
Get-DnsClientCache | Where-Object { $_.Entry.Length -gt 40 } | Select-Object Entry, Data

# Flush and monitor new queries
Clear-DnsClientCache
Start-Sleep -Seconds 60
Get-DnsClientCache | Select-Object Entry, RecordType, Data
```

### Linux

```bash
# DNS cache (systemd-resolved)
resolvectl statistics
resolvectl query --cache

# Monitor DNS queries in real-time
tcpdump -i any port 53 -nn -l 2>/dev/null | head -50

# DNS queries from pcap
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e frame.time -e ip.src -e dns.qry.name 2>/dev/null

# Long DNS queries (tunneling indicator)
tcpdump -i any port 53 -nn -l 2>/dev/null | awk '{print $NF}' | awk -F. 'length > 50'

# Check resolv.conf for poisoning
cat /etc/resolv.conf
ls -la /etc/resolv.conf  # check if symlink was changed

# Query specific DNS server
dig @8.8.8.8 <domain> ANY
nslookup -type=any <domain> 8.8.8.8
```

## Firewall & Traffic Control

### PowerShell

```powershell
# Firewall profiles status
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Recently added firewall rules
Get-NetFirewallRule | Where-Object { $_.DisplayName -notmatch 'Core Networking|Windows' } |
  Select-Object DisplayName, Direction, Action, Enabled, Profile | Sort-Object DisplayName

# Block an IP immediately
New-NetFirewallRule -DisplayName "Block IOC" -Direction Outbound -RemoteAddress "1.2.3.4" -Action Block

# Find rules allowing inbound
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
  Get-NetFirewallPortFilter | Select-Object LocalPort, Protocol

# Windows Filtering Platform (WFP) audit
netsh wfp show state
```

### Linux

```bash
# Current iptables rules
iptables -L -n -v --line-numbers
iptables -t nat -L -n -v

# nftables
nft list ruleset

# Block an IP immediately
iptables -A OUTPUT -d 1.2.3.4 -j DROP
iptables -A INPUT -s 1.2.3.4 -j DROP

# UFW (if available)
ufw status verbose
ufw deny from 1.2.3.4

# Recent firewall drops
dmesg | grep -i "iptables\|nftables\|DROP\|REJECT" | tail -20
journalctl -k | grep -i "DROP\|REJECT" | tail -20

# Connection tracking
conntrack -L 2>/dev/null | head -30
cat /proc/net/nf_conntrack 2>/dev/null | head -30
```

## Packet Capture & Analysis

### PowerShell

```powershell
# Built-in packet capture (pktmon — Windows 10+)
pktmon start --capture --file-name C:\evidence\capture.etl
# ... wait ...
pktmon stop
pktmon etl2pcap C:\evidence\capture.etl --out C:\evidence\capture.pcap

# Network trace (netsh)
netsh trace start capture=yes maxSize=500 tracefile=C:\evidence\nettrace.etl
# ... wait ...
netsh trace stop
```

### Linux

```bash
# Capture all traffic
tcpdump -i any -w /tmp/capture.pcap -c 10000

# Capture specific host
tcpdump -i any host 1.2.3.4 -w /tmp/host.pcap

# Capture specific port
tcpdump -i any port 4444 -w /tmp/port4444.pcap

# Capture DNS only
tcpdump -i any port 53 -w /tmp/dns.pcap

# Capture with rotation (long-running)
tcpdump -i any -w /tmp/capture-%Y%m%d-%H%M.pcap -G 3600 -W 24

# Quick analysis without saving
tcpdump -i any -nn -c 100 'tcp[tcpflags] & (tcp-syn) != 0 and not src net 10.0.0.0/8'
```

## ARP & Layer 2

### PowerShell

```powershell
# ARP table
Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias |
  Where-Object { $_.State -ne 'Unreachable' }

# Detect ARP spoofing (duplicate MACs)
Get-NetNeighbor | Group-Object LinkLayerAddress | Where-Object { $_.Count -gt 1 } |
  ForEach-Object { $_.Group | Select-Object IPAddress, LinkLayerAddress }
```

### Linux

```bash
# ARP table
ip neigh show
arp -a

# Detect ARP spoofing
ip neigh | awk '{print $5}' | sort | uniq -d | while read mac; do
  echo "Duplicate MAC: $mac"
  ip neigh | grep "$mac"
done

# Watch ARP changes
ip monitor neigh
```

## SSL/TLS Investigation

### Linux/Cross-platform

```bash
# Check certificate of remote host
openssl s_client -connect <host>:443 < /dev/null 2>/dev/null | openssl x509 -noout -text

# Certificate dates
openssl s_client -connect <host>:443 < /dev/null 2>/dev/null | openssl x509 -noout -dates

# Certificate chain
openssl s_client -connect <host>:443 -showcerts < /dev/null 2>/dev/null

# Check for weak ciphers
nmap --script ssl-enum-ciphers -p 443 <host> 2>/dev/null

# Extract JA3/JA4 from pcap (with tshark)
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields \
  -e ip.src -e ip.dst -e tcp.dstport -e tls.handshake.extensions.server_name
```
