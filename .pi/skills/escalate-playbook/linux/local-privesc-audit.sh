#!/bin/sh
set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
run(){ printf '$ %s\n' "$*"; sh -c "$*" 2>/dev/null || true; }

sec OBJECTIVE
printf '%s\n' 'Assess Linux privilege-escalation paths using native commands: sudo, SUID/SGID, file capabilities, writable privileged paths, automation, and GTFOBins-style candidates.'

sec CURRENT_CONTEXT
run 'id'
run 'whoami'
run 'groups'
run 'sudo -n -l'

sec SUDO_AND_GTFOBINS
run 'sudo -l'
run 'sudo -V | head -20'
run 'sudo -l 2>/dev/null | grep -iE "vim|vi|nvim|find|bash|sh|env|python|python3|perl|ruby|awk|less|more|tar|zip|cp|mv|tee|git|man|nmap|docker|rsync"'

sec SUID_SGID
run 'find / -perm -4000 -type f 2>/dev/null | sort'
run 'find / -perm -2000 -type f 2>/dev/null | sort | head -200'
run 'find / -perm -4000 -type f 2>/dev/null | grep -E "/(bash|sh|dash|find|vim|nvim|less|more|nano|python|python3|perl|ruby|awk|tar|cp|env|mount|umount|systemctl|ssh-agent|rsync|gdb|node|php)$"'

sec FILE_CAPABILITIES
run 'getcap -r / 2>/dev/null'
run 'getcap -r / 2>/dev/null | grep -iE "cap_setuid|cap_setgid|cap_sys_admin|cap_dac_override|cap_dac_read_search|cap_chown|cap_fowner"'

sec WRITABLE_PRIVILEGED_PATHS
run 'for d in $(printf "%s" "$PATH" | tr ":" " "); do [ -d "$d" ] && [ -w "$d" ] && ls -ld "$d"; done'
run 'find /etc /usr/local/bin /usr/local/sbin /opt -maxdepth 3 -type d -writable 2>/dev/null | head -200'
run 'find /etc /usr/local/bin /usr/local/sbin /opt -maxdepth 3 -type f -writable 2>/dev/null | head -200'

sec AUTOMATION_AND_EXECUTION_PATHS
run 'for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs; do [ -e "$d" ] && ls -laR "$d"; done'
run 'systemctl list-timers --all 2>/dev/null'
run 'find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -maxdepth 2 -type f 2>/dev/null | sort | head -250'
run 'grep -RniE "ExecStart=|ExecStartPre=|ExecStartPost=|User=|Group=" /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system 2>/dev/null | head -250'

sec CONTAINERS_AND_GROUPS
run 'id | tr " " "\n" | grep -iE "docker|lxd|libvirt|kvm|podman"'
run 'ls -l /var/run/docker.sock /run/docker.sock /var/run/podman/podman.sock 2>/dev/null'

sec KERNEL_AND_PLATFORM
run 'uname -a'
run 'cat /etc/os-release'
run 'mount'

sec SUSPICIOUS_MISCONFIGS
printf '%s\n' '[!] High-signal findings: sudo rights to GTFOBins-capable binaries, SUID shell/interpreter tools, dangerous file capabilities, writable root-executed scripts, writable PATH entries before privileged binaries, and membership in docker/lxd/libvirt-style admin-equivalent groups.'

sec EVIDENCE_TO_PRESERVE
printf '%s\n' '[*] Preserve exact sudoers entries, binary full paths, file ownership/permissions, systemd unit names, cron file paths, and capability strings before any exploit or remediation.'

sec NEXT_ACTIONS
printf '%s\n' '[*] If the user requests exploitation guidance, map validated binaries to GTFOBins semantics and prefer the smallest deterministic path. Otherwise hand off to shell-commands for exact one-liners.'
