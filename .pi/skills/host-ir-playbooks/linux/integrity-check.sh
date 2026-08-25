#!/bin/sh
# host-ir-playbooks/linux/integrity-check.sh — Binary integrity verification
# Requires: root for full coverage
# Read-only: YES
# Purpose: Verify system binary integrity before trusting command output
#          on a host where rootkit/trojan replacement is suspected.
#          Run BEFORE trusting ps/ss/ls/netstat output.
#
# MITRE ATT&CK: T1014 (Rootkit), T1574 (Hijack Execution Flow)
#
# Run inline: remote_exec(session="host01", command="<paste>")

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
warn(){ printf '[!] %s\n' "$*"; }

sec 'INTEGRITY CHECK HEADER'
printf 'Host:      %s\n' "$(hostname 2>/dev/null)"
printf 'Timestamp: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

sec 'PACKAGE MANAGER VERIFICATION'
# rpam -Va / dpkg --verify — flags modified files with their change type
# S=size, M=mode, 5=hash, U=user, G=group, T=mtime, D=device, L=symlink
if command -v rpm >/dev/null 2>&1; then
  echo "--- rpm -Va (changed system files) ---"
  rpm -Va 2>/dev/null | grep -v '^........  /etc/' | head -60 || echo "(no discrepancies)"
elif command -v dpkg >/dev/null 2>&1; then
  echo "--- dpkg --verify (changed system files) ---"
  dpkg --verify 2>/dev/null | head -60 || echo "(no discrepancies)"
else
  echo "(no rpm or dpkg — manual verification required)"
fi

sec 'LD_PRELOAD / LIBRARY INJECTION CHECK'
echo "--- LD_PRELOAD environment variable ---"
env | grep LD_PRELOAD && warn "LD_PRELOAD is set" || echo "(not set in current env)"

echo "--- /etc/ld.so.preload ---"
if [ -f /etc/ld.so.preload ]; then
  warn "/etc/ld.so.preload exists:"
  cat /etc/ld.so.preload
  echo "  These libraries load into EVERY process — high-value rootkit persistence"
else
  echo "(not present — OK)"
fi

echo "--- /etc/ld.so.conf.d/ (non-standard paths) ---"
for f in /etc/ld.so.conf.d/*.conf; do
  [ -f "$f" ] || continue
  grep -v '^#\|^$' "$f" | while IFS= read -r path; do
    case "$path" in
      /lib*|/usr/lib*|/usr/local/lib*) : ;; # standard
      *) warn "Non-standard library path in $f: $path" ;;
    esac
  done
done

sec 'RUNNING PROCESS BINARY VERIFICATION'
# Cross-check each running process binary against package manager
echo "--- Unpackaged binaries in standard paths ---"
ps auxww 2>/dev/null | awk 'NR>1 && $11!="" {print $11}' | sort -u | while IFS= read -r bin; do
  case "$bin" in
    /usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*)
      # Check if owned by a package
      if command -v rpm >/dev/null 2>&1; then
        rpm -qf "$bin" >/dev/null 2>&1 || warn "UNPACKAGED running binary: $bin"
      elif command -v dpkg >/dev/null 2>&1; then
        dpkg -S "$bin" >/dev/null 2>&1 || warn "UNPACKAGED running binary: $bin"
      fi
      ;;
    /tmp/*|/dev/shm/*|/var/tmp/*|/run/*)
      warn "STAGING AREA process binary: $bin"
      ;;
  esac
done

sec '/proc/*/maps — UNEXPECTED LIBRARY PATHS'
# Look for libraries loaded by processes that are not in standard paths
echo "--- Non-standard library paths in process memory maps ---"
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
  maps=$(cat /proc/$pid/maps 2>/dev/null) || continue
  printf '%s' "$maps" | awk '/\.so/{print $6}' | grep -v '^$' | while IFS= read -r lib; do
    case "$lib" in
      /lib*|/usr/lib*|/usr/local/lib*|/dev/shm/*) : ;;
      /tmp/*|/var/tmp/*|/run/*)
        warn "PID $pid: suspicious library from staging area: $lib"
        ;;
    esac
  done
done 2>/dev/null | sort -u | head -40

sec 'SUID/SGID BINARY CHECK'
echo "--- SUID binaries not owned by a package ---"
find / -perm -4000 -type f 2>/dev/null | while IFS= read -r f; do
  if command -v rpm >/dev/null 2>&1; then
    rpm -qf "$f" >/dev/null 2>&1 || warn "UNPACKAGED SUID: $f ($(stat -c '%U %G %a' "$f" 2>/dev/null))"
  elif command -v dpkg >/dev/null 2>&1; then
    dpkg -S "$f" >/dev/null 2>&1 || warn "UNPACKAGED SUID: $f ($(stat -c '%U %G %a' "$f" 2>/dev/null))"
  fi
done

sec 'KEY BINARY HASH SPOT-CHECK'
echo "--- Hashes of key triage tools used above (verify against known-good) ---"
for bin in /bin/ps /bin/ls /usr/bin/ss /bin/netstat /sbin/ss /usr/bin/netstat; do
  [ -f "$bin" ] && printf '%s  %s\n' "$(sha256sum "$bin" 2>/dev/null | awk '{print $1}')" "$bin"
done

sec 'INTEGRITY CHECK COMPLETE'
echo "If discrepancies were found:"
echo "  1. Do not trust ps/ls/ss/netstat output on this host"
echo "  2. Use /proc directly for process and network state"
echo "  3. Boot from known-good media for authoritative verification"
echo "  4. Record findings with intel_update(category='host', ...)"
