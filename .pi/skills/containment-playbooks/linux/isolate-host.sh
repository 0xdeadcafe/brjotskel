#!/bin/sh
# containment/linux/isolate-host.sh — Network isolation (nuclear option)
# Requires: root
# State-changing: YES — replaces firewall rules; host loses all network except analyst SSH
# Pattern: LOCK IN ANALYST → DROP EVERYTHING ELSE → VERIFY
#
# Parameters:
#   ANALYST_IP  — your IP address to keep SSH access (REQUIRED — get this wrong and you're locked out)
#   SSH_PORT    — SSH port (default: 22)
#
# Usage:
#   ANALYST_IP=10.10.0.5 remote_exec(session="host01", command="<paste>")
#   ANALYST_IP=10.10.0.5 SSH_PORT=2222 remote_exec(session="host01", command="<paste>")
#
# ⚠️  VERIFY YOUR ANALYST_IP BEFORE RUNNING — wrong IP = locked out
# ⚠️  Run collect-evidence.sh FIRST — isolation kills all other connections
# ⚠️  Coordinate with incident commander — hosts on shared network may be affected
# ⚠️  NOT reversible without console access if ANALYST_IP is wrong

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }

ANALYST_IP="${ANALYST_IP:-}"
SSH_PORT="${SSH_PORT:-22}"

[ -z "$ANALYST_IP" ] && die "ANALYST_IP is required — set to your harness container's IP"

# Validate IP
printf '%s' "$ANALYST_IP" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || \
  die "ANALYST_IP='$ANALYST_IP' does not look like an IPv4 address"

sec 'PRE-ISOLATION EVIDENCE'
printf 'Timestamp:    %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Analyst IP:   %s\n' "$ANALYST_IP"
printf 'SSH port:     %s\n' "$SSH_PORT"
printf 'Host:         %s\n' "$(hostname)"

echo "--- All current connections (will be killed) ---"
ss -tunap 2>/dev/null | grep -v "^Netid"
echo "--- Current iptables state ---"
iptables -L -n --line-numbers 2>/dev/null | head -30

# Final connectivity check from this script's perspective
printf '\n[CONFIRM] Analyst IP %s will keep SSH on port %s\n' "$ANALYST_IP" "$SSH_PORT"
printf '[CONFIRM] ALL OTHER network traffic will be blocked\n'
printf '[CONFIRM] Running on: %s\n\n' "$(hostname)"

sec 'ISOLATION — IPTABLES'
# Flush existing rules
iptables -F 2>/dev/null
iptables -X 2>/dev/null
iptables -Z 2>/dev/null
echo "[OK] Rules flushed"

# Default policy: DROP everything
iptables -P INPUT   DROP
iptables -P OUTPUT  DROP
iptables -P FORWARD DROP
echo "[OK] Default policy: DROP"

# Allow established/related traffic (keep current analyst SSH session alive)
iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
echo "[OK] ESTABLISHED/RELATED allowed (keeps this session alive)"

# Allow analyst IP inbound SSH
iptables -A INPUT  -s "$ANALYST_IP" -p tcp --dport "$SSH_PORT" -j ACCEPT
iptables -A OUTPUT -d "$ANALYST_IP" -p tcp --sport "$SSH_PORT" -j ACCEPT
printf '[OK] Analyst %s ↔ port %s allowed\n' "$ANALYST_IP" "$SSH_PORT"

# Allow loopback
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
echo "[OK] Loopback allowed"

sec 'VERIFY — ISOLATION IN PLACE'
echo "--- Active rules ---"
iptables -L -n --line-numbers 2>/dev/null

echo "--- Remaining connections ---"
ss -tunap 2>/dev/null | grep ESTAB | grep -v "$ANALYST_IP" && \
  echo "[!] Non-analyst ESTABLISHED connections remain — may drop shortly" || \
  echo "[OK] No non-analyst established connections"

echo "--- Analyst SSH rule present ---"
iptables -L INPUT -n 2>/dev/null | grep "$ANALYST_IP" && \
  echo "[OK] Analyst IP allow rule confirmed" || \
  echo "[FAIL] Analyst IP rule missing — check now"

sec 'INTEL UPDATE SNIPPET'
printf '\nintel_update(category="host", id="<HOST_ID>",\n'
printf '  fields="status: contained\\nnotes: Host network-isolated at %s. Analyst %s keeps SSH on port %s only.",\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$ANALYST_IP" "$SSH_PORT"
printf '  summary="<HOST_ID>: network isolated")\n'
printf '\nintel_timeline(action="add", entry_type="containment", entry_action="contained",\n'
printf '  target="<HOST_ID>", summary="<HOST_ID> network-isolated — analyst-only iptables")\n'
