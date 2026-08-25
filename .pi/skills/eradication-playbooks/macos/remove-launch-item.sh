#!/bin/sh
# eradication/macos/remove-launch-item.sh — Evidence-backed LaunchDaemon/Agent removal
# Requires: root
# State-changing: YES — bootout and removes the plist
# Pattern: EVIDENCE → BOOTOUT → DELETE → VERIFY
#
# Parameters:
#   PLIST_PATH   — full path to the plist file, e.g. /Library/LaunchDaemons/com.evil.plist
#
# Usage:
#   PLIST_PATH=/Library/LaunchDaemons/com.sysupdate.plist \
#     remote_exec(session="mac01", command="<paste>")
#
# ⚠️  Containment first. Run collect-evidence.sh before this.
# ⚠️  Know which UID to use for user LaunchAgents: root=0, other users by UID

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
hsh(){ shasum -a 256 "$1" 2>/dev/null || md5 "$1" 2>/dev/null; }

PLIST_PATH="${PLIST_PATH:-}"
[ -z "$PLIST_PATH" ] && die "Set PLIST_PATH=<path> before running"
[ -f "$PLIST_PATH" ] || die "Plist file not found: $PLIST_PATH"

# Determine domain for launchctl
case "$PLIST_PATH" in
  /Library/LaunchDaemons/*) DOMAIN="system" ;;
  /Library/LaunchAgents/*)  DOMAIN="gui/$(id -u 2>/dev/null || echo 0)" ;;
  */LaunchAgents/*)          DOMAIN="gui/$(id -u 2>/dev/null || echo 0)" ;;
  *) DOMAIN="system" ;;
esac

sec 'EVIDENCE — PLIST BEFORE REMOVAL'
printf 'Timestamp:   %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Plist path:  %s\n' "$PLIST_PATH"
printf 'Domain:      %s\n' "$DOMAIN"

echo "--- Plist hash ---"
hsh "$PLIST_PATH"

echo "--- Plist metadata ---"
stat "$PLIST_PATH" 2>/dev/null

echo "--- Plist contents ---"
cat "$PLIST_PATH" 2>/dev/null || plutil -p "$PLIST_PATH" 2>/dev/null

# Extract label and program for hash
label=$(defaults read "$PLIST_PATH" Label 2>/dev/null || \
        plutil -extract Label raw "$PLIST_PATH" 2>/dev/null || \
        grep -A1 '<key>Label</key>' "$PLIST_PATH" 2>/dev/null | tail -1 | sed 's/.*<string>//;s/<\/string>//')
program=$(defaults read "$PLIST_PATH" Program 2>/dev/null || \
          grep -A1 '<key>Program</key>' "$PLIST_PATH" 2>/dev/null | tail -1 | sed 's/.*<string>//;s/<\/string>//')

printf 'Label:   %s\n' "${label:-(unknown)}"
printf 'Program: %s\n' "${program:-(none set — see ProgramArguments)}"

if [ -n "$program" ] && [ -f "$program" ]; then
  echo "--- Program binary hash ---"
  hsh "$program"
fi

echo "--- launchctl list state ---"
launchctl list 2>/dev/null | grep "${label:-__none__}" || echo "(not loaded)"

sec 'SAVE EVIDENCE'
bak="${PLIST_PATH}.evidence-$(date +%Y%m%dT%H%M%S)"
cp "$PLIST_PATH" "$bak" && printf '[OK] Evidence backup: %s\n' "$bak" || echo "[FAIL] Could not backup"
echo "     Pull to: workspace/evidence/<host>/launchd-$(basename "$PLIST_PATH")"

sec 'BOOTOUT AND REMOVE'
echo "--- Boot out the service ---"
if [ -n "$label" ]; then
  launchctl bootout "$DOMAIN/$label" 2>/dev/null && \
    printf '[OK] bootout: %s/%s\n' "$DOMAIN" "$label" || \
    printf '(bootout returned non-zero — may not have been loaded)\n'
else
  launchctl bootout "$DOMAIN" "$PLIST_PATH" 2>/dev/null && \
    echo "[OK] bootout (by path)" || \
    echo "(bootout by path returned non-zero)"
fi

echo "--- Delete plist ---"
rm -f "$PLIST_PATH" && printf '[OK] Deleted: %s\n' "$PLIST_PATH" || echo "[FAIL] Could not delete plist"

sec 'VERIFY — LAUNCH ITEM GONE'
[ -f "$PLIST_PATH" ] && echo "[FAIL] Plist still exists" || echo "[OK] Plist is gone"

if [ -n "$label" ]; then
  state=$(launchctl list 2>/dev/null | grep "$label")
  [ -n "$state" ] && printf '[FAIL] Label still in launchctl list: %s\n' "$state" || \
    printf '[OK] Label "%s" not in launchctl list\n' "$label"
fi

echo ""
echo "Wait 60s and verify the item did not recreate."
echo "Re-check: launchctl list | grep '$label'"

sec 'INTEL TIMELINE SNIPPET'
printf '\nintel_timeline(action="add", entry_type="eradication", entry_action="eradicated",\n'
printf '  target="<HOST_ID>",\n'
printf '  summary="<HOST_ID>: LaunchItem %s removed at %s")\n' \
  "${label:-$(basename "$PLIST_PATH")}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
