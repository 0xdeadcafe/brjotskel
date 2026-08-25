#!/bin/sh
# containment/macos/block-c2.sh — Block attacker C2 IP via pf
# Requires: root
# State-changing: YES — modifies pf firewall rules
# Pattern: RECORD → ACT → VERIFY
#
# Parameters:
#   C2_IP    — attacker C2 IP to block (required)
#   C2_NOTE  — short note (optional)
#
# Usage:
#   C2_IP=185.220.101.45 remote_exec(session="mac01", command="<paste>")
#
# ⚠️  Record C2_IP in intel store BEFORE blocking

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }

C2_IP="${C2_IP:-}"
C2_NOTE="${C2_NOTE:-attacker C2}"

[ -z "$C2_IP" ] && die "Set C2_IP=<ip> before running"
printf '%s' "$C2_IP" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || \
  die "C2_IP='$C2_IP' does not look like an IPv4 address"

sec 'PRE-BLOCK EVIDENCE'
printf 'Timestamp: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'C2 IP:     %s\n' "$C2_IP"
printf 'Note:      %s\n' "$C2_NOTE"

echo "--- Active connections to C2 ---"
lsof -i "@$C2_IP" -nP 2>/dev/null | grep -E 'ESTABLISHED|LISTEN' || \
  netstat -an 2>/dev/null | grep "$C2_IP" || \
  echo "(no current connections)"

echo "--- Current pf rules ---"
pfctl -sr 2>/dev/null | head -20 || echo "(pf not running or no access)"

sec 'BLOCK VIA PF'
# Build a small anchor rule and load it
anchor_rules="block drop from any to $C2_IP
block drop from $C2_IP to any"

# Try pf first (standard macOS firewall)
if pfctl -si >/dev/null 2>&1 || pfctl -e 2>/dev/null; then
  printf '%s\n' "$anchor_rules" | pfctl -f - 2>/dev/null && \
    echo "[OK] pf rules loaded — $C2_IP blocked (in+out)" || \
    echo "[FAIL] pfctl -f failed — check pf is enabled"
else
  echo "[!] pf not active — attempting to enable..."
  pfctl -e 2>/dev/null
  printf '%s\n' "$anchor_rules" | pfctl -f - 2>/dev/null && \
    echo "[OK] pf enabled and rules loaded" || \
    echo "[FAIL] pf rules could not be loaded"
fi

# Fallback: Application Firewall rule via socketfilterfw (less effective for IP blocking)
# Note: socketfilterfw blocks by application, not by IP — pf is the right tool here

sec 'VERIFY'
echo "--- pf rules containing C2 IP ---"
pfctl -sr 2>/dev/null | grep "$C2_IP" && echo "[OK] block rules present" || echo "[FAIL] rules not found"

echo "--- Remaining connections to C2 ---"
lsof -i "@$C2_IP" -nP 2>/dev/null | grep ESTABLISHED && \
  echo "[!] Connections still present — kill the process" || \
  echo "[OK] No active connections to $C2_IP"

sec 'INTEL UPDATE SNIPPET'
printf '\nintel_timeline(action="add", entry_type="containment", entry_action="contained",\n'
printf '  target="<HOST_ID>", summary="C2 %s blocked on <HOST_ID> via pf")\n' "$C2_IP"
printf '\nintel_update(category="host", id="<HOST_ID>",\n'
printf '  fields="status: contained\\nnotes: C2 %s blocked via pf at %s",\n' \
  "$C2_IP" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '  summary="<HOST_ID>: C2 %s blocked")\n' "$C2_IP"
