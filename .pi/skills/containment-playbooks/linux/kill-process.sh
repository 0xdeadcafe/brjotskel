#!/bin/sh
# containment/linux/kill-process.sh — Evidence-first process termination
# Requires: root or process owner
# State-changing: YES — kills the target process
# Pattern: EVIDENCE → KILL → VERIFY
#
# Parameters (set before running):
#   TARGET_PID   — PID to kill (preferred: exact)
#   TARGET_NAME  — process name to match if PID unknown (kills ALL matching — confirm first)
#
# Usage:
#   TARGET_PID=4523 remote_exec(session="host01", command="<paste>")
#   TARGET_NAME=implant remote_exec(session="host01", command="<paste>")
#
# ⚠️  Run collect-evidence.sh BEFORE this script

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
hsh(){ sha256sum "$1" 2>/dev/null || md5sum "$1" 2>/dev/null || printf '(no hash util) %s\n' "$1"; }

TARGET_PID="${TARGET_PID:-}"
TARGET_NAME="${TARGET_NAME:-}"

[ -z "$TARGET_PID" ] && [ -z "$TARGET_NAME" ] && \
  die "Set TARGET_PID=<pid> or TARGET_NAME=<name> before running"

# Resolve PID if only name given
if [ -z "$TARGET_PID" ] && [ -n "$TARGET_NAME" ]; then
  TARGET_PID=$(pgrep -x "$TARGET_NAME" 2>/dev/null || pgrep -f "$TARGET_NAME" 2>/dev/null | head -1)
  [ -z "$TARGET_PID" ] && die "No process found matching TARGET_NAME='$TARGET_NAME'"
  printf '[!] Resolved TARGET_NAME=%s to PID=%s\n' "$TARGET_NAME" "$TARGET_PID"
fi

sec 'PRE-KILL EVIDENCE — PROCESS STATE'
printf 'Timestamp: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Target PID: %s\n' "$TARGET_PID"

# Full command line
echo "--- Command line ---"
cat /proc/"$TARGET_PID"/cmdline 2>/dev/null | tr '\0' ' ' && echo
# Executable path (may be deleted)
echo "--- Executable path ---"
readlink /proc/"$TARGET_PID"/exe 2>/dev/null || echo "(unresolvable — binary may be deleted)"
# Hash the binary while still running
echo "--- Binary hash ---"
bin=$(readlink /proc/"$TARGET_PID"/exe 2>/dev/null)
[ -n "$bin" ] && [ -f "$bin" ] && hsh "$bin" || echo "(binary path unresolvable)"
# Full ps entry
echo "--- Full ps entry ---"
ps -p "$TARGET_PID" -o pid,ppid,user,stat,start,time,args 2>/dev/null
# Environment variables (attacker payloads, tokens)
echo "--- Environment (first 20 vars) ---"
tr '\0' '\n' < /proc/"$TARGET_PID"/environ 2>/dev/null | head -20
# Open network connections
echo "--- Open connections ---"
ss -tunap 2>/dev/null | grep "pid=$TARGET_PID" || \
  lsof -p "$TARGET_PID" -nP 2>/dev/null | grep -E 'IPv4|IPv6|STREAM'
# Parent process
echo "--- Parent process ---"
ppid=$(cat /proc/"$TARGET_PID"/status 2>/dev/null | awk '/^PPid:/{print $2}')
[ -n "$ppid" ] && ps -p "$ppid" -o pid,ppid,user,args 2>/dev/null

sec 'KILL'
echo "Sending SIGTERM (graceful)..."
kill -TERM "$TARGET_PID" 2>/dev/null && echo "SIGTERM sent" || echo "(SIGTERM failed — process may have already exited)"
sleep 2

# Check if still running, escalate to SIGKILL
if kill -0 "$TARGET_PID" 2>/dev/null; then
  echo "Process still alive — sending SIGKILL..."
  kill -KILL "$TARGET_PID" 2>/dev/null && echo "SIGKILL sent" || echo "(SIGKILL failed)"
  sleep 1
fi

sec 'VERIFY — PROCESS GONE'
if kill -0 "$TARGET_PID" 2>/dev/null; then
  printf '[FAIL] PID %s is still running after SIGKILL\n' "$TARGET_PID"
  ps -p "$TARGET_PID" 2>/dev/null
  echo "Manual intervention required."
else
  printf '[OK] PID %s is not running\n' "$TARGET_PID"
fi

# Check for respawn (named process reappeared under a new PID)
if [ -n "$TARGET_NAME" ]; then
  new_pid=$(pgrep -x "$TARGET_NAME" 2>/dev/null || pgrep -f "$TARGET_NAME" 2>/dev/null | head -1)
  if [ -n "$new_pid" ]; then
    printf '[!] WARNING: %s reappeared as PID %s — persistence mechanism active\n' "$TARGET_NAME" "$new_pid"
    echo "Run enum-persistence.sh and escalate to eradication"
  else
    printf '[OK] %s did not respawn\n' "$TARGET_NAME"
  fi
fi

sec 'INTEL UPDATE SNIPPET'
printf '\nintel_update(category="host", id="<HOST_ID>",\n'
printf '  fields="status: contained\\nnotes: PID %s (%s) killed at %s",\n' \
  "$TARGET_PID" "${TARGET_NAME:-$(readlink /proc/"$TARGET_PID"/exe 2>/dev/null || 'unknown')}" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '  summary="<HOST_ID>: PID %s killed")\n' "$TARGET_PID"
