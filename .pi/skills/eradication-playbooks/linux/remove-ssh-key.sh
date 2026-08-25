#!/bin/sh
# eradication/linux/remove-ssh-key.sh — Remove attacker SSH public key from authorized_keys
# Requires: root (or the target user)
# State-changing: YES — edits authorized_keys
# Pattern: EVIDENCE → REMOVE → VERIFY
#
# Parameters:
#   TARGET_USER    — user whose authorized_keys to clean
#   KEY_PATTERN    — grep pattern matching the attacker key (comment, fingerprint fragment, or key material)
#
# Usage:
#   TARGET_USER=deploy KEY_PATTERN="attacker@kali" remote_exec(session="host01", command="<paste>")
#   TARGET_USER=root KEY_PATTERN="AAAA.*suspicious" remote_exec(session="host01", command="<paste>")
#
# ⚠️  Make sure you know which key is the attacker's vs. the operator's key.
#     Cross-check with the operator's public key fingerprint before removing.

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }

TARGET_USER="${TARGET_USER:-}"
KEY_PATTERN="${KEY_PATTERN:-}"

[ -z "$TARGET_USER" ] && die "Set TARGET_USER=<username>"
[ -z "$KEY_PATTERN" ] && die "Set KEY_PATTERN=<grep pattern matching attacker key>"

id "$TARGET_USER" >/dev/null 2>&1 || die "User '$TARGET_USER' not found"

home=$(getent passwd "$TARGET_USER" | cut -d: -f6)
auth_keys="$home/.ssh/authorized_keys"

sec 'EVIDENCE — AUTHORIZED_KEYS BEFORE REMOVAL'
printf 'Timestamp:       %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Target user:     %s\n' "$TARGET_USER"
printf 'authorized_keys: %s\n' "$auth_keys"

[ -f "$auth_keys" ] || die "No authorized_keys file found at $auth_keys"

echo "--- Current contents ---"
nl "$auth_keys" 2>/dev/null

echo "--- Matching lines (to be removed) ---"
grep -n "$KEY_PATTERN" "$auth_keys" 2>/dev/null || echo "(no matching lines — already removed?)"

echo "--- File hash before change ---"
sha256sum "$auth_keys" 2>/dev/null || md5sum "$auth_keys" 2>/dev/null

echo "--- File metadata ---"
stat "$auth_keys" 2>/dev/null

sec 'FINGERPRINT MATCHING KEYS'
# Generate fingerprints for all keys — helps operator confirm which key is attacker's
while IFS= read -r line; do
  case "$line" in '#'*|'') continue ;; esac
  fp=$(printf '%s\n' "$line" | ssh-keygen -l -f /dev/stdin 2>/dev/null || echo "(fingerprint failed)")
  printf 'FP: %s\n' "$fp"
done < "$auth_keys"

sec 'REMOVE MATCHING KEY(S)'
# Save evidence backup
bak="${auth_keys}.evidence-$(date +%Y%m%dT%H%M%S)"
cp "$auth_keys" "$bak" && printf '[OK] Evidence backup: %s\n' "$bak" || echo "[FAIL] Could not backup"

# Remove matching lines
match_count=$(grep -c "$KEY_PATTERN" "$auth_keys" 2>/dev/null || echo 0)
printf '[INFO] Lines matching pattern: %s\n' "$match_count"

grep -v "$KEY_PATTERN" "$auth_keys" > "${auth_keys}.new" && \
  mv "${auth_keys}.new" "$auth_keys" && \
  chown "$TARGET_USER" "$auth_keys" 2>/dev/null && \
  chmod 600 "$auth_keys" 2>/dev/null && \
  printf '[OK] Key(s) removed and permissions restored\n' || \
  echo "[FAIL] File update failed"

sec 'VERIFY — KEY REMOVED'
echo "--- Contents after removal ---"
nl "$auth_keys" 2>/dev/null

remaining=$(grep "$KEY_PATTERN" "$auth_keys" 2>/dev/null)
[ -n "$remaining" ] && printf '[FAIL] Pattern still found: %s\n' "$remaining" || \
  printf '[OK] Pattern "%s" is gone from authorized_keys\n' "$KEY_PATTERN"

echo "--- File hash after change ---"
sha256sum "$auth_keys" 2>/dev/null || md5sum "$auth_keys" 2>/dev/null

echo ""
echo "Note: Check known_hosts entries too — the attacker may have cached pivot hosts:"
echo "  cat $home/.ssh/known_hosts"

sec 'INTEL TIMELINE SNIPPET'
printf '\nintel_timeline(action="add", entry_type="eradication", entry_action="eradicated",\n'
printf '  target="<HOST_ID>",\n'
printf '  summary="<HOST_ID>: attacker SSH key removed from %s authorized_keys at %s")\n' \
  "$TARGET_USER" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
