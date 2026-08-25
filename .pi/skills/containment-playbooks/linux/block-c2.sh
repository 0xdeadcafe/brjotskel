#!/bin/sh
# containment/linux/block-c2.sh — Block attacker C2 IP with firewall rules
# Requires: root
# State-changing: YES — adds firewall drop rules
# Pattern: RECORD → ACT → VERIFY
#
# Parameters (set before running):
#   C2_IP    — attacker C2 IP address to block (required)
#   C2_NOTE  — short description, e.g. "beacon callback port 4444" (optional)
#
# Usage:
#   C2_IP=185.220.101.45 remote_exec(session="host01", command="<paste>")
#
# ⚠️  Record C2_IP in intel store BEFORE blocking — you need it for the record
# ⚠️  This does NOT block the attacker from lateral-moving to other hosts on the network

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }

C2_IP="${C2_IP:-}"
C2_NOTE="${C2_NOTE:-attacker C2}"

[ -z "$C2_IP" ] && die "Set C2_IP=<ip> before running"

# Validate IP format (basic)
printf '%s' "$C2_IP" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || \
  die "C2_IP='$C2_IP' does not look like an IPv4 address — set correctly"

sec 'PRE-BLOCK EVIDENCE'
printf 'Timestamp: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'C2 IP:     %s\n' "$C2_IP"
printf 'Note:      %s\n' "$C2_NOTE"

echo "--- Active connections TO/FROM C2 IP (snapshot before block) ---"
ss -tunap 2>/dev/null | grep "$C2_IP" || \
  netstat -tunap 2>/dev/null | grep "$C2_IP" || \
  echo "(no current connections found)"

echo "--- Processes with open connections to C2 ---"
ss -tunap 2>/dev/null | awk -v ip="$C2_IP" '$0 ~ ip {print}' || true
lsof -i "@$C2_IP" -nP 2>/dev/null || true

echo "--- Current firewall state ---"
iptables -L OUTPUT -n --line-numbers 2>/dev/null | head -10 || \
  nft list ruleset 2>/dev/null | head -20

sec 'DETECT FIREWALL TOOL'
FW_TOOL=""
if command -v iptables >/dev/null 2>&1; then
  FW_TOOL="iptables"
elif command -v nft >/dev/null 2>&1; then
  FW_TOOL="nft"
else
  echo "[!] Neither iptables nor nft found — manual block required"
  FW_TOOL="none"
fi
printf 'Using: %s\n' "$FW_TOOL"

sec 'BLOCK'
case "$FW_TOOL" in
  iptables)
    # Block outbound AND inbound (C2 may push commands back)
    iptables -I OUTPUT -d "$C2_IP" -j DROP && \
      echo "[OK] iptables OUTPUT DROP for $C2_IP added" || echo "[FAIL] OUTPUT rule failed"
    iptables -I INPUT  -s "$C2_IP" -j DROP && \
      echo "[OK] iptables INPUT DROP for $C2_IP added"  || echo "[FAIL] INPUT rule failed"
    ;;
  nft)
    nft add rule inet filter output ip daddr "$C2_IP" drop && \
      echo "[OK] nft output drop for $C2_IP added" || echo "[FAIL] nft output rule failed"
    nft add rule inet filter input  ip saddr "$C2_IP" drop && \
      echo "[OK] nft input drop for $C2_IP added"  || echo "[FAIL] nft input rule failed"
    ;;
  none)
    echo "Manual block options:"
    echo "  route add -host $C2_IP reject    (route blackhole)"
    echo "  echo '$C2_IP' > /proc/net/... (kernel-level, platform-specific)"
    ;;
esac

sec 'VERIFY — C2 BLOCKED'
echo "--- Rules in place ---"
case "$FW_TOOL" in
  iptables)
    iptables -L OUTPUT -n --line-numbers 2>/dev/null | grep "$C2_IP" && \
      echo "[OK] OUTPUT rule found" || echo "[FAIL] OUTPUT rule not found"
    iptables -L INPUT  -n --line-numbers 2>/dev/null | grep "$C2_IP" && \
      echo "[OK] INPUT rule found"  || echo "[FAIL] INPUT rule not found"
    ;;
  nft)
    nft list ruleset 2>/dev/null | grep "$C2_IP" && \
      echo "[OK] nft rules found" || echo "[FAIL] nft rules not found"
    ;;
esac

echo "--- Any remaining connections to C2 ---"
ss -tunap 2>/dev/null | grep "$C2_IP" && \
  echo "[!] Connections still present — process may need killing" || \
  echo "[OK] No active connections to $C2_IP"

sec 'INTEL UPDATE SNIPPET'
printf '\n# Record C2 indicator in intel store:\n'
printf 'intel_timeline(action="add", entry_type="containment", entry_action="contained",\n'
printf '  target="<HOST_ID>", summary="C2 %s blocked — %s")\n' "$C2_IP" "$C2_NOTE"
printf '\n# Update host status:\n'
printf 'intel_update(category="host", id="<HOST_ID>",\n'
printf '  fields="status: contained\\nnotes: C2 %s blocked via iptables at %s",\n' \
  "$C2_IP" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '  summary="<HOST_ID>: C2 %s blocked")\n' "$C2_IP"
