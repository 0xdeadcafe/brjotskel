#!/bin/sh
set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
run(){ printf '$ %s\n' "$*"; sh -c "$*" 2>/dev/null || true; }

sec OBJECTIVE
printf '%s\n' 'Initial Linux host IR assessment: role, live activity, persistence clues, recent execution, and security state.'

sec HOST_ROLE
run 'hostname'
run 'id'
run 'uname -a'
run 'uptime'
run 'ip -brief addr 2>/dev/null || ifconfig -a'
run 'ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null'
run 'ps -ef --forest 2>/dev/null || ps aux'
run 'systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null'

sec LIVE_ACCESS
run 'who'
run 'w'
run 'last -a | head -50'
run 'ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null'

sec PERSISTENCE_CLUES
run 'systemctl list-unit-files --type=service 2>/dev/null | grep enabled'
run 'find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -maxdepth 2 -type f 2>/dev/null | sort | head -200'
run 'for d in /etc/cron* /var/spool/cron /var/spool/cron/crontabs; do [ -e "$d" ] && ls -laR "$d"; done'
run 'find /etc/init.d /etc/rc*.d -maxdepth 2 -type f 2>/dev/null | sort'
run 'find /home /root -maxdepth 3 \( -name authorized_keys -o -name ".bashrc" -o -name ".profile" -o -name ".bash_profile" -o -name ".zshrc" \) 2>/dev/null | sort | head -200'

sec AUTOMATION_AND_PIVOT_ARTIFACTS
run 'find /etc/ansible /opt /srv /home /root -maxdepth 3 \( -name ansible.cfg -o -name hosts -o -name inventory -o -name "*.ini" -o -name "*.yml" -o -name "*.yaml" \) 2>/dev/null | grep -E "/ansible/|/inventory|/hosts$" | sort | head -100'
run 'grep -RniE "private_key_file|ansible_ssh_private_key_file|ansible_host|ansible_user|remote " /etc/ansible /opt /srv /home /root 2>/dev/null | head -120'
run 'find /etc/openvpn /home /root -maxdepth 3 \( -name "*.ovpn" -o -name "*.conf" -o -name auth.txt -o -name credentials \) 2>/dev/null | sort | head -100'
run 'grep -RniE "username=|password=|credentials|domain=|vers=|user=" /etc/fstab /etc/mtab /root /home 2>/dev/null | grep -E "cifs|smb|mount" | head -100'

sec RECENT_EXECUTION
run 'find /tmp /var/tmp /dev/shm -maxdepth 2 -type f -mtime -3 2>/dev/null | sort | head -100'
run 'journalctl -n 120 --no-pager 2>/dev/null'
run 'find /home /root -maxdepth 2 \( -name ".bash_history" -o -name ".zsh_history" -o -name ".sh_history" \) -type f 2>/dev/null -exec grep -nE "curl|wget|sshpass|nc |bash -c|python -c|socat|scp|rsync" {} \; | head -100'

sec SECURITY_STATE
run 'iptables -S 2>/dev/null || nft list ruleset 2>/dev/null'
run 'getenforce 2>/dev/null || sestatus 2>/dev/null'
run 'aa-status 2>/dev/null'

sec SUSPICIOUS_SIGNS
printf '%s\n' '[!] Review unexpected listening ports, outbound admin sessions, newly modified shell init files, non-standard systemd services, recent files in tmp paths, and history entries showing download/exec or remote admin tooling.'

sec NEXT_ACTIONS
printf '%s\n' '[*] If suspicious artifacts are confirmed, record the host, accounts, and remote peers with intel_add, preserve exact service/task/file paths, and follow up with gather playbooks linux/enum-user-history.sh, linux/ansible-triage.sh, linux/enum-vpn-creds.sh, and linux/enum-cifs-creds.sh for deeper credential and pivot artifact review.'
