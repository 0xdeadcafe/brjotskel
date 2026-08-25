#!/bin/sh
# eradication/linux/remove-systemd-unit.sh — Evidence-backed systemd unit removal
# Requires: root
# State-changing: YES — stops, disables, masks, and deletes the unit
# Pattern: EVIDENCE → STOP → DISABLE → MASK → DELETE → VERIFY
#
# Parameters:
#   UNIT_NAME  — systemd unit name, e.g. "malicious.service" or "backdoor.timer"
#
# Usage:
#   UNIT_NAME=sysupdate.service remote_exec(session="host01", command="<paste>")
#
# ⚠️  Containment first. Run collect-evidence.sh before this.

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
hsh(){ sha256sum "$1" 2>/dev/null || md5sum "$1" 2>/dev/null; }

UNIT_NAME="${UNIT_NAME:-}"
[ -z "$UNIT_NAME" ] && die "Set UNIT_NAME=<unit.service> before running"

sec 'EVIDENCE — UNIT STATE BEFORE REMOVAL'
printf 'Timestamp: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Unit:      %s\n' "$UNIT_NAME"

echo "--- systemctl status ---"
systemctl status "$UNIT_NAME" --no-pager 2>/dev/null || echo "(unit not loaded)"

echo "--- Unit file location ---"
unit_path=$(systemctl show "$UNIT_NAME" -p FragmentPath 2>/dev/null | cut -d= -f2)
printf 'FragmentPath: %s\n' "$unit_path"

echo "--- Unit file contents ---"
[ -n "$unit_path" ] && [ -f "$unit_path" ] && cat "$unit_path" || echo "(no unit file found)"

echo "--- Unit file hash ---"
[ -n "$unit_path" ] && [ -f "$unit_path" ] && hsh "$unit_path" || echo "(no file to hash)"

echo "--- Unit file metadata ---"
[ -n "$unit_path" ] && [ -f "$unit_path" ] && stat "$unit_path"

echo "--- Binary in ExecStart ---"
exec_bin=$(grep -i 'ExecStart' "$unit_path" 2>/dev/null | head -1 | sed 's/.*=//;s/ .*//' | tr -d '"'"'")
if [ -n "$exec_bin" ] && [ -f "$exec_bin" ]; then
  printf 'ExecStart binary: %s\n' "$exec_bin"
  hsh "$exec_bin"
  stat "$exec_bin" 2>/dev/null
fi

echo "--- Journal entries (last 30 lines) ---"
journalctl -u "$UNIT_NAME" -n 30 --no-pager 2>/dev/null || echo "(no journal entries)"

sec 'SAVE EVIDENCE'
bak="/tmp/evidence-unit-${UNIT_NAME}-$(date +%Y%m%dT%H%M%S)"
[ -n "$unit_path" ] && [ -f "$unit_path" ] && cp "$unit_path" "$bak" && \
  printf '[OK] Unit file saved to: %s\n' "$bak" || \
  echo "(no unit file to back up)"

sec 'STOP AND DISABLE'
echo "--- Stop unit ---"
systemctl stop "$UNIT_NAME" 2>/dev/null && echo "[OK] Stopped" || echo "(stop returned non-zero — may have already stopped)"

echo "--- Disable unit ---"
systemctl disable "$UNIT_NAME" 2>/dev/null && echo "[OK] Disabled" || echo "(disable returned non-zero)"

echo "--- Mask unit (prevent re-enable) ---"
systemctl mask "$UNIT_NAME" 2>/dev/null && echo "[OK] Masked" || echo "(mask returned non-zero)"

echo "--- Delete unit file ---"
if [ -n "$unit_path" ] && [ -f "$unit_path" ]; then
  rm -f "$unit_path" && printf '[OK] Deleted: %s\n' "$unit_path" || echo "[FAIL] Could not delete unit file"
fi

echo "--- Reload systemd daemon ---"
systemctl daemon-reload 2>/dev/null && echo "[OK] daemon-reload complete"

echo "--- Remove ExecStart binary if in staging area ---"
if [ -n "$exec_bin" ]; then
  case "$exec_bin" in
    /tmp/*|/dev/shm/*|/var/tmp/*|/run/*)
      echo "[!] ExecStart binary is in a staging area: $exec_bin"
      echo "    Hash recorded above. Remove manually after confirming it is attacker-owned:"
      printf '    rm -f %s\n' "$exec_bin"
      ;;
    *)
      printf '[INFO] ExecStart binary not in staging area: %s — review manually\n' "$exec_bin"
      ;;
  esac
fi

sec 'VERIFY — UNIT GONE'
active=$(systemctl is-active "$UNIT_NAME" 2>/dev/null)
enabled=$(systemctl is-enabled "$UNIT_NAME" 2>/dev/null)
printf 'Active: %s | Enabled: %s\n' "$active" "$enabled"

[ "$active" = "inactive" ] || [ "$active" = "failed" ] && echo "[OK] Unit is not running" || \
  printf '[FAIL] Unit state is: %s\n' "$active"

[ "$enabled" = "masked" ] || [ "$enabled" = "disabled" ] && echo "[OK] Unit is disabled/masked" || \
  printf '[FAIL] Unit enable state is: %s\n' "$enabled"

[ -z "$unit_path" ] || [ ! -f "$unit_path" ] && echo "[OK] Unit file is gone" || \
  printf '[FAIL] Unit file still present: %s\n' "$unit_path"

echo ""
echo "Wait 60s and verify the unit did not restart."
echo "Re-check: systemctl status $UNIT_NAME"

sec 'INTEL TIMELINE SNIPPET'
printf '\nintel_timeline(action="add", entry_type="eradication", entry_action="eradicated",\n'
printf '  target="<HOST_ID>",\n'
printf '  summary="<HOST_ID>: systemd unit %s removed — stopped/masked/deleted at %s")\n' \
  "$UNIT_NAME" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
