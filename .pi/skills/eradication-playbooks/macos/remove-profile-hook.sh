#!/bin/sh
# eradication/macos/remove-profile-hook.sh — Remove malicious shell profile/rc hook on macOS
# Requires: root
# State-changing: YES — edits or deletes shell profile files
# Pattern: EVIDENCE → REMOVE → VERIFY
#
# Parameters:
#   HOOK_FILE     — full path to the profile file to edit or delete
#   HOOK_PATTERN  — grep pattern matching the malicious line(s) to remove
#   DELETE_FILE   — set to "1" to delete the entire file (e.g. for /etc/profile.d/evil.sh)
#
# Usage:
#   # Remove lines from a zsh profile:
#   HOOK_FILE=/Users/deploy/.zshrc HOOK_PATTERN="curl\|wget\|base64" \
#     remote_exec(session="mac01", command="<paste>")
#
#   # Delete an entire profile.d file:
#   HOOK_FILE=/etc/profile.d/sysenv.sh DELETE_FILE=1 \
#     remote_exec(session="mac01", command="<paste>")
#
# Common macOS profile locations:
#   ~/.zshrc, ~/.zprofile, ~/.zlogin   (zsh — default shell since macOS Catalina)
#   ~/.bash_profile, ~/.bashrc         (bash — older macOS or user preference)
#   /etc/profile.d/<name>.sh           (system-wide, sourced by sh/bash)
#   /etc/zshrc, /etc/zprofile          (system-wide zsh)
#
# ⚠️  Containment first. Run collect-evidence.sh before this.

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
hsh(){ shasum -a 256 "$1" 2>/dev/null || md5 "$1" 2>/dev/null; }

HOOK_FILE="${HOOK_FILE:-}"
HOOK_PATTERN="${HOOK_PATTERN:-}"
DELETE_FILE="${DELETE_FILE:-0}"

[ -z "$HOOK_FILE" ] && die "Set HOOK_FILE=<path>"
[ "$DELETE_FILE" = "0" ] && [ -z "$HOOK_PATTERN" ] && \
  die "Set HOOK_PATTERN=<pattern> or DELETE_FILE=1"
[ -f "$HOOK_FILE" ] || die "File not found: $HOOK_FILE"

sec 'EVIDENCE — FILE BEFORE CHANGE'
printf 'Timestamp:   %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Hook file:   %s\n' "$HOOK_FILE"

echo "--- File metadata ---"
stat "$HOOK_FILE" 2>/dev/null
echo "--- File hash ---"
hsh "$HOOK_FILE"

echo "--- Contents ---"
cat -n "$HOOK_FILE" 2>/dev/null

if [ "$DELETE_FILE" != "1" ] && [ -n "$HOOK_PATTERN" ]; then
  echo "--- Matching lines (to be removed) ---"
  grep -n "$HOOK_PATTERN" "$HOOK_FILE" 2>/dev/null || echo "(no matching lines)"
fi

sec 'SAVE EVIDENCE BACKUP'
bak="${HOOK_FILE}.evidence-$(date +%Y%m%dT%H%M%S)"
cp "$HOOK_FILE" "$bak" && printf '[OK] Evidence backup: %s\n' "$bak" || echo "[FAIL] Could not backup"

sec 'REMOVE'
if [ "$DELETE_FILE" = "1" ]; then
  rm -f "$HOOK_FILE" && printf '[OK] Deleted: %s\n' "$HOOK_FILE" || echo "[FAIL] Could not delete"
else
  grep -v "$HOOK_PATTERN" "$HOOK_FILE" > "${HOOK_FILE}.new" && \
    mv "${HOOK_FILE}.new" "$HOOK_FILE" && \
    printf '[OK] Lines matching "%s" removed from %s\n' "$HOOK_PATTERN" "$HOOK_FILE" || \
    echo "[FAIL] File update failed"
fi

sec 'VERIFY — HOOK REMOVED'
if [ "$DELETE_FILE" = "1" ]; then
  [ -f "$HOOK_FILE" ] && echo "[FAIL] File still exists" || echo "[OK] File is gone"
else
  remaining=$(grep "$HOOK_PATTERN" "$HOOK_FILE" 2>/dev/null)
  [ -n "$remaining" ] && printf '[FAIL] Pattern still present: %s\n' "$remaining" || \
    printf '[OK] Pattern "%s" is gone\n' "$HOOK_PATTERN"
  echo "--- Remaining contents ---"
  cat -n "$HOOK_FILE" 2>/dev/null
fi

echo ""
echo "Note: macOS zsh sources /etc/zshrc and ~/.zshrc on every new shell."
echo "Verify no loaded shell still has the hook active in its current environment."

sec 'INTEL TIMELINE SNIPPET'
printf '\nintel_timeline(action="add", entry_type="eradication", entry_action="eradicated",\n'
printf '  target="<HOST_ID>",\n'
printf '  summary="<HOST_ID>: shell profile hook removed from %s at %s")\n' \
  "$HOOK_FILE" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
