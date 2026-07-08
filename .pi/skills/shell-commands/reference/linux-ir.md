# Linux/Unix — Security Investigation & Incident Response Commands

> Sources: Blue Team Field Manual, RTFM v3, Linux Incident Response Script (vm32), various IR playbooks

---

## System Information & Triage

```bash
# System overview
uname -a
cat /etc/os-release
hostnamectl

# Uptime and load
uptime
cat /proc/loadavg

# Running kernel and modules
uname -r
lsmod

# Mount points and disk usage
df -h
mount | column -t

# Hardware info
lscpu
free -h
cat /proc/meminfo | head -5

# System time and timezone (important for timeline)
date
timedatectl
cat /etc/timezone 2>/dev/null

# Boot time
who -b
last reboot | head -5

# Environment variables
env | sort
```

## Process Investigation

```bash
# All processes with full command line
ps auxww

# Process tree
ps auxf
pstree -p

# Processes sorted by CPU/memory
ps aux --sort=-%cpu | head -20
ps aux --sort=-%mem | head -20

# Find suspicious processes
# Processes running from /tmp, /dev/shm, or hidden dirs
ps aux | grep -E '(/tmp/|/dev/shm/|/var/tmp/|\./)'

# Processes with deleted binaries (common for malware)
ls -la /proc/*/exe 2>/dev/null | grep '(deleted)'

# Process open files
lsof -p <pid>

# All open files by all processes
lsof +L1  # unlinked (deleted) files still open

# Process environment
cat /proc/<pid>/environ | tr '\0' '\n'

# Process maps (loaded libraries)
cat /proc/<pid>/maps

# Process command line
cat /proc/<pid>/cmdline | tr '\0' ' '

# Find processes communicating on network
lsof -i -P -n

# Recently started processes (by /proc creation time)
find /proc -maxdepth 1 -type d -name '[0-9]*' -newer /proc/1 2>/dev/null | while read d; do
  pid=$(basename "$d")
  echo "$pid $(cat "$d/cmdline" 2>/dev/null | tr '\0' ' ')"
done

# Hidden processes (compare ps to /proc)
diff <(ps aux | awk '{print $2}' | sort -n) <(ls /proc | grep -E '^[0-9]+$' | sort -n)
```

## Network Investigation

```bash
# Active connections
ss -tunapl
netstat -tunapl 2>/dev/null

# Established connections only
ss -tnp state established

# Listening services
ss -tlnp
netstat -tlnp 2>/dev/null

# DNS resolution config
cat /etc/resolv.conf

# DNS cache (systemd-resolved)
resolvectl statistics 2>/dev/null
resolvectl query <domain> 2>/dev/null

# Hosts file
cat /etc/hosts

# ARP table
ip neigh
arp -a 2>/dev/null

# Routing table
ip route
route -n 2>/dev/null

# Firewall rules
iptables -L -n -v 2>/dev/null
nft list ruleset 2>/dev/null
ufw status verbose 2>/dev/null

# Network interfaces and IPs
ip addr show
ifconfig -a 2>/dev/null

# Promiscuous mode check (sniffing)
ip link | grep PROMISC

# Connections per remote IP (find beaconing)
ss -tn state established | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20

# Network connections by process
lsof -i -P -n | grep ESTABLISHED

# Open ports to PID mapping
ss -tlnp | awk 'NR>1 {print $4, $6}'

# Packet captures (live - requires root)
tcpdump -i eth0 -w /tmp/capture.pcap -c 1000
tcpdump -i any port 53 -nn  # DNS only
tcpdump -i any 'tcp[tcpflags] & (tcp-syn) != 0' -nn  # SYN packets
```

## User & Account Investigation

```bash
# All users
cat /etc/passwd
getent passwd

# Users with login shells
grep -v '/nologin\|/false' /etc/passwd

# Users with UID 0 (root equivalent)
awk -F: '$3 == 0 {print}' /etc/passwd

# Groups
cat /etc/group

# Sudo configuration
cat /etc/sudoers
cat /etc/sudoers.d/* 2>/dev/null

# Currently logged in
who
w
last -20

# Failed login attempts
lastb | head -30
grep -i "failed password" /var/log/auth.log 2>/dev/null | tail -30
journalctl -u sshd | grep -i "failed" | tail -30

# Successful SSH logins
grep "Accepted" /var/log/auth.log 2>/dev/null | tail -20
journalctl -u sshd | grep "Accepted" | tail -20

# Recently modified user files
find /etc/passwd /etc/shadow /etc/group /etc/sudoers -newer /etc/hostname 2>/dev/null

# SSH authorized keys and known_hosts metadata (do not collect key material by default)
find /home /root -name "authorized_keys" -o -name "known_hosts" 2>/dev/null -exec ls -la {} \;

# User shell history metadata (review contents only under approved IR procedures)
find /home /root -name ".bash_history" -type f 2>/dev/null -exec ls -la {} \;

# Recently created accounts
grep -E "useradd|adduser|new user" /var/log/auth.log 2>/dev/null
```

## Persistence Mechanisms

```bash
# Cron jobs (all users)
for user in $(cut -f1 -d: /etc/passwd); do
  echo "=== $user ==="; crontab -u "$user" -l 2>/dev/null
done

# System cron
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/
cat /etc/cron.d/* 2>/dev/null

# At jobs
atq
find /var/spool/at* -type f 2>/dev/null

# Systemd timers
systemctl list-timers --all

# Systemd services (enabled)
systemctl list-unit-files --type=service --state=enabled

# Recently modified service files
find /etc/systemd /usr/lib/systemd /run/systemd -name "*.service" -mtime -7 2>/dev/null

# Init scripts
ls -la /etc/init.d/
ls -la /etc/rc*.d/

# Shell profile persistence
cat /etc/profile
cat /etc/bash.bashrc
find /etc/profile.d/ -type f -exec echo "=== {} ===" \; -exec cat {} \;
find /home /root -name ".bashrc" -o -name ".profile" -o -name ".bash_profile" | while read f; do
  echo "=== $f ==="; grep -v "^#\|^$" "$f"
done

# LD_PRELOAD hijacking
cat /etc/ld.so.preload 2>/dev/null
env | grep LD_PRELOAD

# Shared library modifications
find /lib /usr/lib /lib64 /usr/lib64 -name "*.so*" -mtime -7 2>/dev/null | head -20

# Kernel modules (rootkit check)
lsmod
find /lib/modules -name "*.ko" -mtime -30 2>/dev/null

# SUID/SGID binaries (privilege escalation)
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# World-writable directories in PATH
echo "$PATH" | tr ':' '\n' | while read dir; do
  [ -d "$dir" ] && [ -w "$dir" ] && echo "WRITABLE: $dir"
done

# Docker/container persistence
docker ps -a 2>/dev/null
cat /etc/docker/daemon.json 2>/dev/null

# SSH daemon config
cat /etc/ssh/sshd_config | grep -v "^#\|^$"
```

## File System Investigation

```bash
# Recently modified files (last 24h)
find / -mtime -1 -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -50

# Recently accessed files
find / -atime -1 -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -50

# Files modified in last hour (critical directories)
find /etc /usr/bin /usr/sbin /usr/lib /bin /sbin -mmin -60 -type f 2>/dev/null

# Find executables in temp/unusual locations
find /tmp /var/tmp /dev/shm /run -type f -executable 2>/dev/null
find /tmp /var/tmp /dev/shm -type f -name ".*" 2>/dev/null  # hidden files

# World-writable files
find / -perm -o+w -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -30

# Immutable files (may indicate rootkit protection)
lsattr / -R 2>/dev/null | grep "\-i-"

# File hashes
sha256sum /path/to/file
md5sum /path/to/file
find /usr/bin -type f -exec sha256sum {} \; > /tmp/bin-hashes.txt

# Find large files (staging/exfil)
find / -type f -size +100M -not -path "/proc/*" 2>/dev/null

# Deleted files still open (can recover)
lsof +L1 | grep deleted

# Timestamp analysis (stomp detection)
stat /path/to/suspicious/file

# Find files with no user/group (orphaned)
find / -nouser -o -nogroup 2>/dev/null

# Webshells (common patterns in web dirs)
find /var/www /srv/www /opt -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.asp" \) -mtime -7 2>/dev/null
grep -rl "eval\|base64_decode\|system\|exec\|passthru\|shell_exec" /var/www 2>/dev/null

# Package integrity verification
rpm -Va 2>/dev/null  # RPM-based
dpkg --verify 2>/dev/null  # Debian-based
debsums -c 2>/dev/null  # Debian checksum verification
```

## Log Analysis

```bash
# Auth log (logins, sudo, su)
tail -100 /var/log/auth.log 2>/dev/null
tail -100 /var/log/secure 2>/dev/null

# System log
tail -100 /var/log/syslog 2>/dev/null
tail -100 /var/log/messages 2>/dev/null

# Journalctl (systemd)
journalctl --since "1 hour ago"
journalctl -u sshd --since today
journalctl -p err --since "24 hours ago"

# Failed SSH attempts
grep "Failed password" /var/log/auth.log 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
journalctl -u sshd | grep "Failed" | awk '{print $NF}' | tr -d '()' | sort | uniq -c | sort -rn

# Successful privilege escalation
grep -E "sudo:|su:" /var/log/auth.log 2>/dev/null | tail -20

# Kernel messages (module loads, errors)
dmesg | tail -50
dmesg | grep -iE "error|warn|segfault|oom|killed"

# Apache/Nginx access (web attacks)
tail -100 /var/log/apache2/access.log 2>/dev/null
tail -100 /var/log/nginx/access.log 2>/dev/null
# Find SQL injection / path traversal attempts
grep -iE "union.*select|%27|\.\.\/|<script" /var/log/apache2/access.log 2>/dev/null

# Cron logs
grep CRON /var/log/syslog 2>/dev/null | tail -20

# Package install history
cat /var/log/dpkg.log 2>/dev/null | grep "install" | tail -20
cat /var/log/yum.log 2>/dev/null | tail -20
dnf history 2>/dev/null

# Audit log (if auditd running)
ausearch -ts recent 2>/dev/null
ausearch -m execve -ts today 2>/dev/null | head -50
aureport --auth 2>/dev/null
aureport --login --failed 2>/dev/null
```

## Credential & Authentication

```bash
# Shadow file permissions
ls -la /etc/shadow

# Check for unexpected shadow file exposure without printing hashes
stat -c "%A %U:%G %n" /etc/shadow 2>/dev/null

# SSH/GPG/private-key file metadata only; do not print or copy key material
find /home /root -name "id_rsa*" -o -name "id_ed25519*" -o -name "id_ecdsa*" -o -name "*.pem" -o -name "*.key" -o -name "*.gpg" -o -name "secring*" 2>/dev/null -exec ls -la {} \; | head -50

# Potential secret-bearing config files by filename only; do not print secrets
find /etc /home /root -type f \( -name "*.conf" -o -name "*.env" -o -name "*.ini" \) 2>/dev/null | head -50

# AWS/Cloud credentials
find / -name "credentials" -path "*.aws*" 2>/dev/null
find / -name ".env" -type f 2>/dev/null
cat /home/*/.aws/credentials 2>/dev/null

# Kerberos tickets
klist 2>/dev/null
find /tmp -name "krb5cc_*" 2>/dev/null
```

## Network Services & Lateral Movement

```bash
# Running services
systemctl list-units --type=service --state=running

# Open ports and associated services
ss -tlnp
lsof -i -P -n | grep LISTEN

# SSH sessions (active)
who | grep pts
ss -tnp | grep :22

# NFS shares
showmount -e localhost 2>/dev/null
cat /etc/exports 2>/dev/null

# Samba shares
smbclient -L localhost -N 2>/dev/null
cat /etc/samba/smb.conf 2>/dev/null | grep -E "^\[|path"

# Docker containers (lateral movement vector)
docker ps -a 2>/dev/null
docker inspect $(docker ps -q) 2>/dev/null | grep -E "Binds|Mounts|NetworkMode|Privileged"

# Recently connected remote hosts (from known_hosts, bash history)
cat /root/.ssh/known_hosts /home/*/.ssh/known_hosts 2>/dev/null | awk '{print $1}'
grep -h "ssh\|scp\|rsync" /root/.bash_history /home/*/.bash_history 2>/dev/null
```

## Memory & Rootkit Detection

```bash
# Check for common rootkits
chkrootkit 2>/dev/null
rkhunter --check --skip-keypress 2>/dev/null

# Hidden processes (compare ps and /proc)
diff <(ps -eo pid --no-headers | sort -n) <(ls /proc | grep '^[0-9]' | sort -n)

# Kernel modules loaded recently
dmesg | grep -i "module"

# /proc anomalies
ls -la /proc/*/exe 2>/dev/null | grep -v "Permission denied" | sort
cat /proc/*/status 2>/dev/null | grep -E "^Name:|^Pid:" | paste - - | sort -k4 -n

# Volatile memory collection (for offline analysis)
# Requires tools: LiME, AVML, or /proc/kcore
cat /proc/kcore > /tmp/memory.raw 2>/dev/null  # May not work on all kernels
# Preferred: Use LiME module
# insmod lime.ko "path=/tmp/memory.lime format=lime"
```

## Data Collection & Triage Script

```bash
# Quick IR triage collection
IR_DIR="/tmp/ir-$(hostname)-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$IR_DIR"

# Collect system info
uname -a > "$IR_DIR/system-info.txt"
uptime >> "$IR_DIR/system-info.txt"
cat /etc/os-release >> "$IR_DIR/system-info.txt"

# Collect process info
ps auxww > "$IR_DIR/processes.txt"
lsof -i -P -n > "$IR_DIR/open-connections.txt"

# Collect network info
ss -tunapl > "$IR_DIR/network-connections.txt"
ip addr > "$IR_DIR/ip-addresses.txt"
ip route > "$IR_DIR/routes.txt"
iptables -L -n -v > "$IR_DIR/firewall.txt" 2>/dev/null

# Collect user info
who > "$IR_DIR/logged-in.txt"
last -50 > "$IR_DIR/last-logins.txt"
lastb > "$IR_DIR/failed-logins.txt" 2>/dev/null

# Collect persistence
crontab -l > "$IR_DIR/root-cron.txt" 2>/dev/null
systemctl list-unit-files --type=service --state=enabled > "$IR_DIR/enabled-services.txt"
find /tmp /var/tmp /dev/shm -type f -executable > "$IR_DIR/suspicious-executables.txt" 2>/dev/null

# Collect logs
cp /var/log/auth.log "$IR_DIR/" 2>/dev/null
cp /var/log/secure "$IR_DIR/" 2>/dev/null
journalctl --since "24 hours ago" > "$IR_DIR/journal-24h.txt" 2>/dev/null

# Hash collection
sha256sum "$IR_DIR"/* > "$IR_DIR/collection-hashes.txt"

# Archive
tar czf "${IR_DIR}.tar.gz" "$IR_DIR"
echo "Collection saved to: ${IR_DIR}.tar.gz"
```
