#!/bin/sh
# containment/macos/disable-account.sh — Disable a compromised local macOS user account
# Requires: root
# State-changing: YES — disables account password, blocks shell login, kills active sessions
# Pattern: EVIDENCE → ACT → VERIFY
#
# Parameters:
#   TARGET_USER  — username to disable (required)
#
# Usage:
#   TARGET_USER=deploy remote_exec(session="mac01", command="<paste>")
#
# ⚠️  Run collect-evidence.sh BEFORE this — active sessions die when account is disabled
# ⚠️  Coordinate with identity team: force-rotate credentials after incident
# ⚠️  For directory-bound accounts (AD, Okta, MDM): dscl will fail or only affect the
#      local cache — use your identity provider's API or Directory Utility to disable there

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }

TARGET_USER="${TARGET_USER:-}"
[ -z "$TARGET_USER" ] && die "Set TARGET_USER=<username> before running"

id "$TARGET_USER" >/dev/null 2>&1 || die "User '$TARGET_USER' not found on this host"

sec 'PRE-DISABLE EVIDENCE'
printf 'Timestamp: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Target:    %s\n' "$TARGET_USER"

echo "--- Account state before disable ---"
id "$TARGET_USER"
dscl . -read "/Users/$TARGET_USER" AuthenticationAuthority 2>/dev/null | head -5
dscl . -read "/Users/$TARGET_USER" UserShell 2>/dev/null
dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null

echo "--- Active sessions ---"
who 2>/dev/null | grep "^$TARGET_USER " || echo "(no active sessions)"

echo "--- Open processes ---"
ps aux 2>/dev/null | grep "^$TARGET_USER " | grep -v grep || echo "(no running processes)"

echo "--- Login history ---"
last "$TARGET_USER" 2>/dev/null | head -10

echo "--- Authorized keys ---"
home=$(dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null | awk '/NFSHomeDirectory:/{print $2}')
cat "${home}/.ssh/authorized_keys" 2>/dev/null || echo "(no authorized_keys or path unresolvable)"

sec 'DISABLE ACCOUNT'
# 1. Disable password auth — set password field to non-matching sentinel
dscl . -passwd "/Users/$TARGET_USER" '*' 2>/dev/null && \
  echo "[OK] Password disabled (set to '*')" || \
  echo "[!] dscl -passwd failed — directory-bound account may need IdP action"

# 2. Set shell to /usr/bin/false to block new interactive logins
original_shell=$(dscl . -read "/Users/$TARGET_USER" UserShell 2>/dev/null | awk '/UserShell:/{print $2}')
dscl . -create "/Users/$TARGET_USER" UserShell /usr/bin/false 2>/dev/null && \
  printf '[OK] Shell set to /usr/bin/false (was: %s)\n' "${original_shell:-unknown}" || \
  echo "[!] Could not change UserShell"

# 3. Kill all processes owned by this user
uid=$(id -u "$TARGET_USER" 2>/dev/null)
if [ -n "$uid" ]; then
  pkill -U "$uid" -TERM 2>/dev/null && echo "[OK] SIGTERM sent to user processes" || \
    echo "(no processes to kill or pkill failed)"
  sleep 2
  pkill -U "$uid" -KILL 2>/dev/null && echo "[OK] SIGKILL sent to remaining processes" || true
fi

sec 'VERIFY — ACCOUNT DISABLED'
echo "--- Account state after disable ---"
shell_now=$(dscl . -read "/Users/$TARGET_USER" UserShell 2>/dev/null | awk '/UserShell:/{print $2}')
printf 'Shell: %s\n' "${shell_now:-unresolvable}"
[ "$shell_now" = "/usr/bin/false" ] && echo "[OK] Shell is /usr/bin/false" || \
  echo "[!] Shell is not /usr/bin/false — manual verification required"

echo "--- Auth authority after ---"
dscl . -read "/Users/$TARGET_USER" AuthenticationAuthority 2>/dev/null | head -3

echo "--- Remaining sessions ---"
who 2>/dev/null | grep "^$TARGET_USER " && \
  echo "[!] User still has active sessions" || \
  echo "[OK] No active sessions for $TARGET_USER"

echo "--- Remaining processes ---"
if [ -n "$uid" ]; then
  pgrep -U "$uid" 2>/dev/null && echo "[!] User processes still running" || \
    echo "[OK] No processes for uid $uid"
fi

sec 'INTEL UPDATE SNIPPET'
printf '\nintel_update(category="account", id="<ACCOUNT_ID>",\n'
printf '  fields="status: contained\\nnotes: Account %s disabled on macOS via dscl at %s. Shell set to /usr/bin/false, sessions killed.",\n' \
  "$TARGET_USER" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '  summary="<HOST_ID>: %s account disabled")\n' "$TARGET_USER"
printf '\nintel_update(category="host", id="<HOST_ID>",\n'
printf '  fields="notes: Account %s disabled as part of containment at %s",\n' \
  "$TARGET_USER" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '  summary="<HOST_ID>: %s account disabled")\n' "$TARGET_USER"
