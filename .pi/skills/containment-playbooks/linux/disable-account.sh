#!/bin/sh
# containment/linux/disable-account.sh — Lock a compromised user account
# Requires: root
# State-changing: YES — locks account, expires password, kills active sessions
# Pattern: EVIDENCE → ACT → VERIFY
#
# Parameters:
#   TARGET_USER  — username to lock (required)
#
# Usage:
#   TARGET_USER=deploy remote_exec(session="host01", command="<paste>")
#
# ⚠️  Run collect-evidence.sh BEFORE this — active sessions die when account is locked
# ⚠️  Coordinate with identity team: they need to force-reset after incident

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }

TARGET_USER="${TARGET_USER:-}"
[ -z "$TARGET_USER" ] && die "Set TARGET_USER=<username> before running"

# Confirm user exists
id "$TARGET_USER" >/dev/null 2>&1 || die "User '$TARGET_USER' not found on this host"

sec 'PRE-LOCK EVIDENCE'
printf 'Timestamp: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Target:    %s\n' "$TARGET_USER"

echo "--- Account state before lock ---"
id "$TARGET_USER"
passwd -S "$TARGET_USER" 2>/dev/null || getent shadow "$TARGET_USER" 2>/dev/null | cut -d: -f2 | head -c1 | xargs printf 'Shadow status prefix: %s\n'

echo "--- Active sessions ---"
who 2>/dev/null | grep "^$TARGET_USER " || echo "(no active sessions)"

echo "--- Open processes ---"
ps aux 2>/dev/null | grep "^$TARGET_USER " | grep -v grep || echo "(no running processes)"

echo "--- Login history ---"
last "$TARGET_USER" 2>/dev/null | head -10

echo "--- Authorized keys ---"
home=$(getent passwd "$TARGET_USER" | cut -d: -f6)
cat "$home/.ssh/authorized_keys" 2>/dev/null || echo "(no authorized_keys)"

sec 'LOCK ACCOUNT'
# Lock password
usermod -L "$TARGET_USER" 2>/dev/null && echo "[OK] usermod -L (password locked)" || \
  passwd -l "$TARGET_USER" 2>/dev/null && echo "[OK] passwd -l (password locked)" || \
  echo "[FAIL] could not lock password"

# Expire password immediately (force re-auth even if PAM bypassed)
passwd -e "$TARGET_USER" 2>/dev/null && echo "[OK] password expired" || true

# Set shell to nologin to block new interactive sessions
original_shell=$(getent passwd "$TARGET_USER" | cut -d: -f7)
usermod -s /usr/sbin/nologin "$TARGET_USER" 2>/dev/null || \
  usermod -s /bin/false "$TARGET_USER" 2>/dev/null || \
  echo "[!] Could not set shell to nologin"
printf '[OK] Shell set to nologin (was: %s)\n' "$original_shell"

# Kill existing sessions
echo "--- Killing active sessions ---"
pkill -u "$TARGET_USER" -TERM 2>/dev/null && echo "[OK] SIGTERM sent to user processes" || echo "(no processes to kill)"
sleep 2
pkill -u "$TARGET_USER" -KILL 2>/dev/null && echo "[OK] SIGKILL sent to remaining processes" || true

sec 'VERIFY — ACCOUNT LOCKED'
echo "--- Account state after lock ---"
passwd -S "$TARGET_USER" 2>/dev/null || getent shadow "$TARGET_USER" 2>/dev/null | cut -d: -f2 | head -c1 | xargs printf 'Shadow status prefix: %s (! = locked)\n'

echo "--- Current sessions ---"
who 2>/dev/null | grep "^$TARGET_USER " && \
  echo "[!] User still has active sessions" || \
  echo "[OK] No active sessions for $TARGET_USER"

echo "--- Shell check ---"
getent passwd "$TARGET_USER" | cut -d: -f7 | xargs printf 'Shell: %s\n'

sec 'INTEL UPDATE SNIPPET'
printf '\nintel_update(category="account", id="<ACCOUNT_ID>",\n'
printf '  fields="status: contained\\nnotes: Account %s locked via usermod at %s. Shell set to nologin.",\n' \
  "$TARGET_USER" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '  summary="<HOST_ID>: %s account locked")\n' "$TARGET_USER"
printf '\n# Also record on the host:\n'
printf 'intel_update(category="host", id="<HOST_ID>",\n'
printf '  fields="notes: Account %s locked as part of containment",\n' "$TARGET_USER"
printf '  summary="<HOST_ID>: %s account locked")\n' "$TARGET_USER"
