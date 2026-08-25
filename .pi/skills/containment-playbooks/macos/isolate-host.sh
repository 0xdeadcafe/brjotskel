#!/bin/sh
# containment/macos/isolate-host.sh — Network isolation (nuclear option) on macOS
# Requires: root
# State-changing: YES — replaces pf rules; host loses all network except analyst SSH
# Pattern: EVIDENCE → LOCK IN ANALYST → BLOCK EVERYTHING → VERIFY
#
# Parameters:
#   ANALYST_IP  — your IP address to keep SSH access (REQUIRED — get this wrong and you're locked out)
#   SSH_PORT    — SSH port (default: 22)
#
# Usage:
#   ANALYST_IP=10.10.0.5 remote_exec(session="mac01", command="<paste>")
#   ANALYST_IP=10.10.0.5 SSH_PORT=2222 remote_exec(session="mac01", command="<paste>")
#
# ⚠️  VERIFY YOUR ANALYST_IP BEFORE RUNNING — wrong IP = locked out, requires console access
# ⚠️  Run collect-evidence.sh FIRST — isolation kills all other connections
# ⚠️  Coordinate with incident commander — hosts on shared network may be affected
# ⚠️  pf rules do NOT persist across reboots by default (unlike Windows Firewall)
#
# UNDO:
#   pfctl -F all && pfctl -d    # flush all rules and disable pf
#   or reboot if pfctl access is lost

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }

ANALYST_IP="${ANALYST_IP:-}"
SSH_PORT="${SSH_PORT:-22}"

[ -z "$ANALYST_IP" ] && die "ANALYST_IP is required — set to your harness container's IP"

printf '%s' "$ANALYST_IP" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || \
  die "ANALYST_IP='$ANALYST_IP' does not look like a valid IPv4 address"

sec 'PRE-ISOLATION EVIDENCE'
printf 'Timestamp:    %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Analyst IP:   %s\n' "$ANALYST_IP"
printf 'SSH port:     %s\n' "$SSH_PORT"
printf 'Host:         %s\n' "$(hostname)"

echo "--- All current connections (will be severed) ---"
lsof -i -n -P 2>/dev/null | grep ESTABLISHED | head -30 || \
  netstat -an 2>/dev/null | grep ESTABLISHED | head -30

echo "--- Current pf state ---"
pfctl -si 2>/dev/null | head -5 || echo "(pf status unavailable)"
echo "--- Current pf rules ---"
pfctl -sr 2>/dev/null | head -20 || echo "(no rules loaded)"

printf '\n[CONFIRM] Analyst IP %s will keep SSH on port %s\n' "$ANALYST_IP" "$SSH_PORT"
printf '[CONFIRM] ALL OTHER network traffic will be blocked\n'
printf '[CONFIRM] Running on: %s\n\n' "$(hostname)"

sec 'BUILD ISOLATION RULESET'
# Write a pf ruleset to a temp file
PF_CONF="/tmp/.pi-isolate-$(date +%Y%m%dT%H%M%S).conf"

cat > "$PF_CONF" << PFRULES
# brjotskel host isolation — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Analyst: $ANALYST_IP  SSH port: $SSH_PORT

# Allow loopback
set skip on lo0

# Keep existing analyst session alive (stateful — established traffic)
pass in quick from $ANALYST_IP to any port $SSH_PORT proto tcp flags S/SA
pass out quick to $ANALYST_IP proto tcp
pass in quick proto tcp from any to any flags A/A  # allow ACKs on established sessions

# Block everything else
block in all
block out all
PFRULES

printf '[OK] pf ruleset written to %s\n' "$PF_CONF"
cat "$PF_CONF"

sec 'LOAD ISOLATION RULES'
# Enable pf if not already running
pfctl -e 2>/dev/null && echo "[OK] pf enabled" || echo "(pf already enabled or enable returned non-zero)"

# Load the rules — this replaces the active ruleset
pfctl -f "$PF_CONF" 2>/dev/null && \
  echo "[OK] Isolation ruleset loaded" || \
  die "pfctl -f failed — rules not loaded"

sec 'VERIFY — ISOLATION IN PLACE'
echo "--- Active pf rules ---"
pfctl -sr 2>/dev/null

echo "--- pf statistics ---"
pfctl -si 2>/dev/null | head -10

echo "--- Analyst rule present ---"
pfctl -sr 2>/dev/null | grep "$ANALYST_IP" && \
  echo "[OK] Analyst IP allow rule confirmed" || \
  echo "[FAIL] Analyst IP rule missing — check now"

echo "--- Remaining connections ---"
lsof -i -n -P 2>/dev/null | grep ESTABLISHED | grep -v "$ANALYST_IP" && \
  echo "[!] Non-analyst ESTABLISHED connections remain — may drop shortly" || \
  echo "[OK] No non-analyst established connections"

sec 'CLEANUP REMINDER'
echo "To RESTORE network access:"
echo "  pfctl -F all && pfctl -d   # flush all rules and disable pf"
echo "  (or simply reboot if access is lost)"
printf 'Ruleset file saved at: %s\n' "$PF_CONF"

sec 'INTEL UPDATE SNIPPET'
printf '\nintel_update(category="host", id="<HOST_ID>",\n'
printf '  fields="status: contained\\nnotes: Host network-isolated at %s. Analyst %s keeps SSH on port %s only. pf ruleset active.",\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$ANALYST_IP" "$SSH_PORT"
printf '  summary="<HOST_ID>: network isolated")\n'
printf '\nintel_timeline(action="add", entry_type="containment", entry_action="contained",\n'
printf '  target="<HOST_ID>", summary="<HOST_ID> network-isolated — analyst-only pf rules")\n'
