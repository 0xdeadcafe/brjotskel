#!/bin/sh
# containment/macos/kill-process.sh — Evidence-first process termination
# Requires: root or process owner
# State-changing: YES — kills the target process
# Pattern: EVIDENCE → KILL → VERIFY
#
# Parameters:
#   TARGET_PID   — PID to kill (preferred)
#   TARGET_NAME  — process name if PID unknown
#
# Usage:
#   TARGET_PID=1234 remote_exec(session="mac01", command="<paste>")
#
# ⚠️  Run collect-evidence.sh BEFORE this script

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
hsh(){ shasum -a 256 "$1" 2>/dev/null || md5 "$1" 2>/dev/null || printf '(no hash) %s\n' "$1"; }

TARGET_PID="${TARGET_PID:-}"
TARGET_NAME="${TARGET_NAME:-}"

[ -z "$TARGET_PID" ] && [ -z "$TARGET_NAME" ] && \
  die "Set TARGET_PID=<pid> or TARGET_NAME=<name> before running"

if [ -z "$TARGET_PID" ] && [ -n "$TARGET_NAME" ]; then
  TARGET_PID=$(pgrep -x "$TARGET_NAME" 2>/dev/null | head -1)
  [ -z "$TARGET_PID" ] && die "No process found matching TARGET_NAME='$TARGET_NAME'"
  printf '[!] Resolved TARGET_NAME=%s to PID=%s\n' "$TARGET_NAME" "$TARGET_PID"
fi

sec 'PRE-KILL EVIDENCE'
printf 'Timestamp: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Target PID: %s\n' "$TARGET_PID"

echo "--- Full process entry ---"
ps -p "$TARGET_PID" -o pid,ppid,user,stat,start,time,args 2>/dev/null

echo "--- Executable path ---"
lsof -p "$TARGET_PID" -nP 2>/dev/null | awk '/txt/{print $9}' | head -5

echo "--- Binary hash ---"
bin=$(lsof -p "$TARGET_PID" 2>/dev/null | awk '/txt.*REG/{print $9; exit}')
[ -n "$bin" ] && [ -f "$bin" ] && hsh "$bin" || echo "(binary path unresolvable)"

echo "--- Open network connections ---"
lsof -p "$TARGET_PID" -i -nP 2>/dev/null | grep -E 'ESTABLISHED|LISTEN'

echo "--- Parent process ---"
ppid=$(ps -p "$TARGET_PID" -o ppid= 2>/dev/null | tr -d ' ')
[ -n "$ppid" ] && ps -p "$ppid" -o pid,ppid,user,args 2>/dev/null

sec 'KILL'
echo "Sending SIGTERM..."
kill -TERM "$TARGET_PID" 2>/dev/null && echo "SIGTERM sent" || echo "(SIGTERM failed)"
sleep 2

if kill -0 "$TARGET_PID" 2>/dev/null; then
  echo "Process still alive — sending SIGKILL..."
  kill -KILL "$TARGET_PID" 2>/dev/null && echo "SIGKILL sent" || echo "(SIGKILL failed)"
  sleep 1
fi

sec 'VERIFY — PROCESS GONE'
if kill -0 "$TARGET_PID" 2>/dev/null; then
  printf '[FAIL] PID %s still running\n' "$TARGET_PID"
  ps -p "$TARGET_PID" 2>/dev/null
else
  printf '[OK] PID %s is gone\n' "$TARGET_PID"
fi

if [ -n "$TARGET_NAME" ]; then
  new_pid=$(pgrep -x "$TARGET_NAME" 2>/dev/null | head -1)
  if [ -n "$new_pid" ]; then
    printf '[!] %s reappeared as PID %s — persistence active\n' "$TARGET_NAME" "$new_pid"
    echo "Run enum-persistence.sh and escalate to eradication"
  else
    printf '[OK] %s did not respawn\n' "$TARGET_NAME"
  fi
fi

sec 'INTEL UPDATE SNIPPET'
printf '\nintel_update(category="host", id="<HOST_ID>",\n'
printf '  fields="status: contained\\nnotes: PID %s killed at %s",\n' \
  "$TARGET_PID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '  summary="<HOST_ID>: PID %s killed")\n' "$TARGET_PID"
