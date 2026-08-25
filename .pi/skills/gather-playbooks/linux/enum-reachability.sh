#!/bin/sh
# gather/linux/enum-reachability.sh — Map what this host can reach
# Requires: Any user
# Read-only: YES — probe-only, no writes
# Footprint: Zero (no temp files)
# Purpose: Pivot planning — discover live services reachable FROM this host
#          that the harness cannot see directly.
#
# ⚠️  Probes only ports that suggest exploitable services or pivot paths.
#     Not a port scanner — targeted service discovery only.
#
# Run inline: remote_exec(session="host01", command="<paste>")

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }

# Target ports to check: SSH, SMB, WinRM, RDP, web admin
PORTS="22 445 3389 5985 5986 80 443 8080 8443 135 139"

probe_tcp() {
  host="$1"
  port="$2"
  # Use bash /dev/tcp — available in bash without any binaries
  (echo >/dev/tcp/"$host"/"$port") 2>/dev/null && printf 'OPEN  %-20s %s\n' "$host" "$port"
}

sec 'REACHABILITY HEADER'
printf 'Host:       %s\n' "$(hostname 2>/dev/null)"
printf 'Timestamp:  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Probing:    %s\n' "$PORTS"

sec 'DISCOVERED TARGETS FROM ARP / ROUTING / HOSTS'
# Collect candidate IPs from: ARP cache, /etc/hosts (non-loopback), known_hosts
candidates=""

echo "--- ARP cache ---"
arp -n 2>/dev/null | awk 'NR>1 && $1!~/127\.|169\.254/{print $1}' | sort -u
candidates="$candidates $(arp -n 2>/dev/null | awk 'NR>1 && $1!~/127\.|169\.254/{print $1}')"

echo "--- /etc/hosts (non-loopback) ---"
grep -v '^#\|^$\|^127\.\|^::1' /etc/hosts 2>/dev/null | awk '{print $1}' | sort -u
candidates="$candidates $(grep -v '^#\|^$\|^127\.\|^::1' /etc/hosts 2>/dev/null | awk '{print $1}')"

echo "--- SSH known_hosts (first 30) ---"
for home in /root /home/*; do
  kh="$home/.ssh/known_hosts"
  [ -f "$kh" ] || continue
  cut -d, -f1 "$kh" 2>/dev/null | awk '{print $1}' | grep -v '^\[' | head -30
  candidates="$candidates $(cut -d, -f1 "$kh" 2>/dev/null | awk '{print $1}' | grep -v '^\[' | head -30)"
done

echo "--- Direct routing table gateways ---"
ip route show 2>/dev/null | awk '/via/{print $3}' | sort -u || \
  netstat -rn 2>/dev/null | awk 'NR>2 && $2!="0.0.0.0" && $2!="UG"{print $2}'

sec 'TCP REACHABILITY PROBE'
echo "Probing candidate hosts on common service ports..."
echo "Format: OPEN  <host>  <port>"
echo ""

# Deduplicate candidates
unique_candidates=$(printf '%s\n' $candidates | sort -u | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')

for host in $unique_candidates; do
  for port in $PORTS; do
    probe_tcp "$host" "$port"
  done
done

sec 'ACTIVE NETWORK INTERFACES AND ROUTES (PIVOT CONTEXT)'
ip addr show 2>/dev/null | grep -E 'inet |UP ' | head -20
echo ""
ip route show 2>/dev/null | head -20

sec 'REACHABILITY COMPLETE'
echo "Record newly reachable hosts with:"
echo "  intel_add(category=\"host\", id=\"<id>\", data=\"ip: <ip>\\nstatus: suspected\\nsource:\\n  host: $(hostname)\\n  method: reachability probe\", summary=\"...\")"
