#!/bin/sh
# eradication/macos/remove-cron.sh — Evidence-backed cron entry removal on macOS
# Requires: root
# State-changing: YES — removes cron entries
# Pattern: EVIDENCE → REMOVE → VERIFY
#
# Parameters:
#   TARGET_USER     — user whose crontab to edit (for user crontab removal)
#   CRON_PATTERN    — grep pattern matching the malicious cron line to remove
#   CRON_FILE       — full path to /etc/cron.d/<file> to delete entirely (if removing a file)
#
# Usage:
#   TARGET_USER=deploy CRON_PATTERN="curl.*192.168" remote_exec(session="mac01", command="<paste>")
#   CRON_FILE=/etc/cron.d/sysupdate remote_exec(session="mac01", command="<paste>")
#
# ⚠️  Containment first. Run collect-evidence.sh before this.
# Note: cron is uncommon on macOS — check LaunchDaemons/Agents first (remove-launch-item.sh)

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
hsh(){ shasum -a 256 "$1" 2>/dev/null || md5 "$1" 2>/dev/null; }

TARGET_USER="${TARGET_USER:-}"
CRON_PATTERN="${CRON_PATTERN:-}"
CRON_FILE="${CRON_FILE:-}"

[ -z "$TARGET_USER" ] && [ -z "$CRON_FILE" ] && \
  die "Set TARGET_USER+CRON_PATTERN (for user crontab) or CRON_FILE (for /etc/cron.d file)"

sec 'EVIDENCE — CRON STATE BEFORE REMOVAL'
printf 'Timestamp: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ -n "$CRON_FILE" ]; then
  echo "--- Target cron file ---"
  printf 'Path: %s\n' "$CRON_FILE"
  [ -f "$CRON_FILE" ] && hsh "$CRON_FILE" || echo "(file not found — already removed?)"
  echo "--- Contents ---"
  cat "$CRON_FILE" 2>/dev/null || echo "(cannot read)"
  echo "--- File metadata ---"
  stat "$CRON_FILE" 2>/dev/null
fi

if [ -n "$TARGET_USER" ]; then
  echo "--- User crontab ($TARGET_USER) ---"
  crontab -l -u "$TARGET_USER" 2>/dev/null || echo "(empty or no crontab)"
  if [ -n "$CRON_PATTERN" ]; then
    echo "--- Matching lines ---"
    crontab -l -u "$TARGET_USER" 2>/dev/null | grep -n "$CRON_PATTERN" || \
      echo "(no matching lines — already removed?)"
  fi
fi

echo "--- All cron state ---"
ls -la /etc/cron.d/ 2>/dev/null || echo "(no /etc/cron.d)"
ls -la /var/at/tabs/ 2>/dev/null | head -10

sec 'REMOVE'
if [ -n "$CRON_FILE" ]; then
  if [ -f "$CRON_FILE" ]; then
    bak="/tmp/evidence-cron-$(basename "$CRON_FILE")-$(date +%Y%m%dT%H%M%S)"
    cp "$CRON_FILE" "$bak" && printf '[OK] Evidence copy: %s\n' "$bak"
    rm -f "$CRON_FILE" && printf '[OK] Deleted: %s\n' "$CRON_FILE" || echo "[FAIL] Could not delete $CRON_FILE"
  else
    echo "[SKIP] File not found: $CRON_FILE"
  fi
fi

if [ -n "$TARGET_USER" ] && [ -n "$CRON_PATTERN" ]; then
  bak="/tmp/evidence-crontab-$TARGET_USER-$(date +%Y%m%dT%H%M%S).bak"
  crontab -l -u "$TARGET_USER" 2>/dev/null > "$bak"
  printf '[OK] Crontab evidence saved to %s\n' "$bak"
  new_crontab=$(crontab -l -u "$TARGET_USER" 2>/dev/null | grep -v "$CRON_PATTERN")
  printf '%s\n' "$new_crontab" | crontab -u "$TARGET_USER" - && \
    printf '[OK] Removed lines matching "%s" from %s crontab\n' "$CRON_PATTERN" "$TARGET_USER" || \
    echo "[FAIL] crontab update failed"
fi

sec 'VERIFY — CRON ENTRY GONE'
if [ -n "$CRON_FILE" ]; then
  [ -f "$CRON_FILE" ] && echo "[FAIL] $CRON_FILE still exists" || echo "[OK] $CRON_FILE is gone"
fi

if [ -n "$TARGET_USER" ] && [ -n "$CRON_PATTERN" ]; then
  remaining=$(crontab -l -u "$TARGET_USER" 2>/dev/null | grep "$CRON_PATTERN")
  [ -n "$remaining" ] && printf '[FAIL] Pattern still present: %s\n' "$remaining" || \
    printf '[OK] Pattern "%s" not found in %s crontab\n' "$CRON_PATTERN" "$TARGET_USER"
fi

echo "Note: Verify no launchd job is recreating this cron entry — check remove-launch-item.sh"

sec 'INTEL TIMELINE SNIPPET'
printf '\nintel_timeline(action="add", entry_type="eradication", entry_action="eradicated",\n'
printf '  target="<HOST_ID>",\n'
printf '  summary="<HOST_ID>: cron persistence removed — %s at %s")\n' \
  "${CRON_FILE:-$TARGET_USER crontab}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
