#!/bin/sh
# eradication/linux/remove-cron.sh — Evidence-backed cron entry removal
# Requires: root
# State-changing: YES — removes cron entries
# Pattern: EVIDENCE → REMOVE → VERIFY
#
# Parameters:
#   TARGET_USER     — user whose crontab to edit (for user crontab removal)
#   CRON_PATTERN    — grep pattern matching the malicious cron line to remove
#   CRON_FILE       — full path to /etc/cron.d/<file> to delete entirely (if removing a file)
#
# Usage examples:
#   # Remove a line from a user crontab:
#   TARGET_USER=deploy CRON_PATTERN="curl.*192.168" remote_exec(session="host01", command="<paste>")
#
#   # Delete an entire /etc/cron.d file:
#   CRON_FILE=/etc/cron.d/systemupdate remote_exec(session="host01", command="<paste>")
#
# ⚠️  Containment first. Run collect-evidence.sh before this.

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
hsh(){ sha256sum "$1" 2>/dev/null || md5sum "$1" 2>/dev/null; }

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
  echo "--- Matching lines ---"
  if [ -n "$CRON_PATTERN" ]; then
    crontab -l -u "$TARGET_USER" 2>/dev/null | grep -n "$CRON_PATTERN" || \
      echo "(no matching lines — already removed?)"
  fi
fi

echo "--- All system cron state (reference) ---"
ls -la /etc/cron.d/ 2>/dev/null
ls -la /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null | head -20

sec 'REMOVE'
if [ -n "$CRON_FILE" ]; then
  if [ -f "$CRON_FILE" ]; then
    # Move to temp as evidence before deleting
    bak="/tmp/evidence-cron-$(basename "$CRON_FILE")-$(date +%Y%m%dT%H%M%S)"
    cp "$CRON_FILE" "$bak" 2>/dev/null && printf '[OK] Evidence copy: %s\n' "$bak"
    rm -f "$CRON_FILE" && printf '[OK] Deleted: %s\n' "$CRON_FILE" || echo "[FAIL] Could not delete $CRON_FILE"
  else
    echo "[SKIP] File not found: $CRON_FILE"
  fi
fi

if [ -n "$TARGET_USER" ] && [ -n "$CRON_PATTERN" ]; then
  # Export full crontab as evidence
  crontab -l -u "$TARGET_USER" 2>/dev/null > "/tmp/evidence-crontab-$TARGET_USER-$(date +%Y%m%dT%H%M%S).bak"
  printf '[OK] Crontab evidence saved to %s\n' "/tmp/evidence-crontab-$TARGET_USER-$(date +%Y%m%dT%H%M%S).bak"

  # Remove matching lines (portable: write new crontab without the bad lines)
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

echo "--- Watch for respawn (wait 60s and re-check) ---"
echo "Re-run: crontab -l -u $TARGET_USER | grep '$CRON_PATTERN'"

sec 'INTEL TIMELINE SNIPPET'
printf '\nintel_timeline(action="add", entry_type="eradication", entry_action="eradicated",\n'
printf '  target="<HOST_ID>",\n'
printf '  summary="<HOST_ID>: cron persistence removed — %s at %s")\n' \
  "${CRON_FILE:-$TARGET_USER crontab}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
