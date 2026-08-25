#!/bin/sh
# gather/linux/enum-user-history.sh — Enumerate user shell history and suspicious execution patterns
# Requires: read access to user homes
# Read-only: YES
# MITRE ATT&CK: T1059 / T1552

homes() {
  cut -d: -f6 /etc/passwd 2>/dev/null | sort -u
}

echo "=== OBJECTIVE ==="
echo "Collect shell history artifacts and highlight suspicious command patterns tied to download, execution, tunneling, and credential use."

echo ""
echo "=== HISTORY_FILES ==="
homes | while IFS= read -r d; do
  for f in .bash_history .zsh_history .sh_history .python_history .sqlite_history; do
    [ -f "$d/$f" ] || continue
    ls -l "$d/$f" 2>/dev/null
  done
 done

echo ""
echo "=== HISTORY_RECENT_LINES ==="
homes | while IFS= read -r d; do
  for f in .bash_history .zsh_history .sh_history; do
    [ -f "$d/$f" ] || continue
    echo "--- $d/$f ---"
    tail -40 "$d/$f" 2>/dev/null
  done
 done

echo ""
echo "=== HISTORY_SUSPICIOUS_HITS ==="
pat='curl|wget|sshpass|scp |sftp |rsync |nc |ncat |socat|proxychains|chisel|ssh -D|ssh -L|ssh -R|base64|openssl enc|python -c|perl -e|bash -c|nohup|screen |tmux |mysql .* -p|psql .*://|export .*TOKEN|export .*SECRET|aws .*configure|kubectl|ansible|openvpn|wg-quick|mount -t cifs|smbclient'
homes | while IFS= read -r d; do
  for f in .bash_history .zsh_history .sh_history; do
    [ -f "$d/$f" ] || continue
    hits=$(grep -inE "$pat" "$d/$f" 2>/dev/null | tail -80)
    [ -n "$hits" ] && echo "--- $d/$f ---" && echo "$hits"
  done
 done

echo ""
echo "=== KNOWN_HOSTS_AND_SSH_CONFIG_REFERENCES ==="
find /home /root -maxdepth 3 \( -path '*/.ssh/known_hosts' -o -path '*/.ssh/config' \) 2>/dev/null | sort | while IFS= read -r f; do
  echo "--- $f ---"
  sed -n '1,120p' "$f" 2>/dev/null
 done
