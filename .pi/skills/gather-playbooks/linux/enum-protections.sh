#!/bin/sh
# gather/linux/enum-protections.sh — Detect security tools and hardening
# Requires: standard user
# Read-only: YES
# MITRE ATT&CK: T1518.001 — Security Software Discovery

echo "=== KERNEL HARDENING ==="
echo "ASLR: $(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)"
echo "kptr_restrict: $(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)"
echo "dmesg_restrict: $(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)"
echo "perf_event_paranoid: $(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)"
echo "unprivileged_bpf: $(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)"
echo "ptrace_scope: $(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)"

echo ""
echo "=== SELINUX ==="
getenforce 2>/dev/null || echo "[*] SELinux not available"
sestatus 2>/dev/null || true

echo ""
echo "=== APPARMOR ==="
aa-status 2>/dev/null || cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo "[*] AppArmor not available"

echo ""
echo "=== EDR / AV / SECURITY AGENTS ==="
for path in /opt/CrowdStrike /opt/carbonblack /opt/SentinelOne \
            /opt/McAfee /opt/Trellix /opt/Tanium /opt/Symantec \
            /opt/wazuh /var/ossec /opt/splunkforwarder /opt/osquery \
            /etc/osquery /etc/falco /opt/f-secure /opt/kaspersky \
            /opt/bitdefender-security-tools /opt/cisco/amp \
            /opt/FortiEDRCollector /opt/ds_agent \
            /opt/fortinet /opt/secureworks /opt/traps \
            /usr/local/qualys /etc/fluent-bit; do
  [ -e "$path" ] && echo "FOUND: $path"
done

echo ""
echo "=== SECURITY PROCESSES ==="
ps aux 2>/dev/null | grep -iE "falcon|crowdstrike|sentinel|cbagent|cbdefense|ossec|wazuh|auditd|falco|osquery|elastic-agent|splunk|tanium|fireeye|trellix|mcafee|cylance|sophos" | grep -v grep

echo ""
echo "=== AUDIT FRAMEWORK ==="
auditctl -l 2>/dev/null | head -20 || echo "[*] Cannot read audit rules"
systemctl is-active auditd 2>/dev/null | xargs -I{} echo "auditd: {}"

echo ""
echo "=== FIREWALL STATUS ==="
systemctl is-active firewalld 2>/dev/null | xargs -I{} echo "firewalld: {}"
systemctl is-active ufw 2>/dev/null | xargs -I{} echo "ufw: {}"
ufw status 2>/dev/null || true

echo ""
echo "=== INTEGRITY MONITORING ==="
for bin in aide tripwire ossec-control rkhunter chkrootkit; do
  command -v "$bin" >/dev/null 2>&1 && echo "FOUND: $bin ($(command -v $bin))"
done

echo ""
echo "=== LOGGING ==="
for bin in rsyslogd syslog-ng journald; do
  pgrep -x "$bin" >/dev/null 2>&1 && echo "RUNNING: $bin"
done
echo "--- log forwarding ---"
grep -r "^[^#]*@@" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | head -5

echo ""
echo "=== CPU VULNERABILITIES ==="
grep -r . /sys/devices/system/cpu/vulnerabilities/ 2>/dev/null
