#!/bin/sh
# eradication/macos/remove-btm-login-item.sh — Remove attacker login item / BTM entry on macOS
# Requires: root
# State-changing: YES — removes login items registered via BTM or legacy login item APIs
# Pattern: EVIDENCE → REMOVE → VERIFY
#
# Covers:
#   - Background Task Management items (macOS 13+ Ventura+) via sfltool/pluginkit
#   - Legacy login items via osascript (macOS 12 and earlier)
#   - Remaining LaunchAgent items — use remove-launch-item.sh for those
#
# Parameters:
#   ITEM_NAME       — display name of the login item (for legacy osascript removal)
#   ITEM_IDENTIFIER — bundle identifier or UUID (for BTM pluginkit removal)
#                     Get from: sfltool dumpbtm | grep -A3 "<name>"
#
# Usage:
#   ITEM_NAME="SoftwareUpdate" remote_exec(session="mac01", command="<paste>")
#   ITEM_IDENTIFIER="com.evil.updater" remote_exec(session="mac01", command="<paste>")
#
# ⚠️  Containment first. Run collect-evidence.sh before this.
# ⚠️  LaunchDaemons and LaunchAgents → use remove-launch-item.sh instead.
# ⚠️  sfltool dumpbtm may require SIP disabled or running as root on some macOS versions.

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }

ITEM_NAME="${ITEM_NAME:-}"
ITEM_IDENTIFIER="${ITEM_IDENTIFIER:-}"

[ -z "$ITEM_NAME" ] && [ -z "$ITEM_IDENTIFIER" ] && \
  die "Set ITEM_NAME=<display name> and/or ITEM_IDENTIFIER=<bundle id / UUID>"

sec 'EVIDENCE — LOGIN ITEM STATE BEFORE REMOVAL'
printf 'Timestamp:  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Item name:  %s\n' "${ITEM_NAME:-(not specified)}"
printf 'Identifier: %s\n' "${ITEM_IDENTIFIER:-(not specified)}"

echo "--- BTM database (sfltool dumpbtm) ---"
sfltool dumpbtm 2>/dev/null | head -200 || echo "(sfltool not available or BTM not supported on this macOS version)"

echo "--- Legacy login items (osascript) ---"
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || \
  echo "(osascript query failed)"

echo "--- launchctl list (filtering by name/identifier) ---"
if [ -n "$ITEM_IDENTIFIER" ]; then
  launchctl list 2>/dev/null | grep "$ITEM_IDENTIFIER" || echo "(not found in launchctl list)"
fi
if [ -n "$ITEM_NAME" ]; then
  launchctl list 2>/dev/null | grep "$ITEM_NAME" || echo "(not found in launchctl list)"
fi

echo "--- User login items per-user ---"
for home in /Users/*; do
  [ -d "$home" ] || continue
  u=$(basename "$home")
  plist="$home/Library/Preferences/com.apple.loginitems.plist"
  [ -f "$plist" ] && printf '# %s login items plist:\n' "$u" && plutil -p "$plist" 2>/dev/null | head -20
done

sec 'REMOVE'
removed=0

# 1. BTM / pluginkit (macOS 13+)
if [ -n "$ITEM_IDENTIFIER" ]; then
  echo "--- Attempting pluginkit disable (BTM) ---"
  pluginkit -e ignore -i "$ITEM_IDENTIFIER" 2>/dev/null && \
    printf '[OK] pluginkit: disabled identifier %s\n' "$ITEM_IDENTIFIER" && removed=1 || \
    echo "(pluginkit disable failed or not applicable)"
fi

# 2. Legacy login item removal via osascript
if [ -n "$ITEM_NAME" ]; then
  echo "--- Attempting legacy login item removal (osascript) ---"
  osascript -e "tell application \"System Events\" to delete login item \"$ITEM_NAME\"" 2>/dev/null && \
    printf '[OK] Legacy login item removed: %s\n' "$ITEM_NAME" && removed=1 || \
    echo "(osascript removal failed — item may not exist or may be BTM-managed)"
fi

# 3. sfltool remove (macOS 13+ direct BTM removal — may require SIP off)
if [ -n "$ITEM_IDENTIFIER" ]; then
  echo "--- Attempting sfltool remove ---"
  sfltool remove "$ITEM_IDENTIFIER" 2>/dev/null && \
    printf '[OK] sfltool removed: %s\n' "$ITEM_IDENTIFIER" && removed=1 || \
    echo "(sfltool remove failed — may require SIP disabled)"
fi

[ "$removed" -eq 0 ] && echo "[!] No removal method succeeded — verify item exists and try the specific method for this macOS version"

sec 'VERIFY — ITEM REMOVED'
echo "--- BTM database after removal ---"
sfltool dumpbtm 2>/dev/null | head -100 || echo "(sfltool unavailable)"

echo "--- Legacy login items after removal ---"
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null

if [ -n "$ITEM_IDENTIFIER" ]; then
  sfltool dumpbtm 2>/dev/null | grep -i "$ITEM_IDENTIFIER" && \
    echo "[FAIL] Identifier still in BTM database" || \
    printf '[OK] Identifier "%s" not found in BTM database\n' "$ITEM_IDENTIFIER"
fi

if [ -n "$ITEM_NAME" ]; then
  osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null | grep -i "$ITEM_NAME" && \
    echo "[FAIL] Item name still in legacy login items" || \
    printf '[OK] Item name "%s" not found in legacy login items\n' "$ITEM_NAME"
fi

echo ""
echo "Note: Wait 30–60s and re-check — some login items recreate from a paired LaunchAgent."
echo "If the item returns, check: launchctl list | grep '$ITEM_IDENTIFIER$ITEM_NAME'"
echo "and use remove-launch-item.sh to remove the underlying daemon/agent plist."

sec 'INTEL TIMELINE SNIPPET'
printf '\nintel_timeline(action="add", entry_type="eradication", entry_action="eradicated",\n'
printf '  target="<HOST_ID>",\n'
printf '  summary="<HOST_ID>: login item %s removed at %s")\n' \
  "${ITEM_NAME:-$ITEM_IDENTIFIER}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
