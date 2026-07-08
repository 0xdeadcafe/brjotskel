#!/bin/sh
set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
run(){ printf '$ %s\n' "$*"; sh -c "$*" 2>/dev/null || true; }

sec LAUNCHD_SYSTEM
run 'find /Library/LaunchDaemons /Library/LaunchAgents -maxdepth 1 \( -type f -o -type l \) 2>/dev/null | sort'
run 'grep -R -nE "Program|ProgramArguments|RunAtLoad|KeepAlive|MachServices" /Library/LaunchDaemons /Library/LaunchAgents 2>/dev/null'

sec LAUNCHD_USER
for d in /Users/*/Library/LaunchAgents; do
  [ -d "$d" ] || continue
  printf '## %s\n' "$d"
  find "$d" -maxdepth 1 \( -type f -o -type l \) 2>/dev/null | sort
  grep -R -nE 'Program|ProgramArguments|RunAtLoad|KeepAlive|MachServices' "$d" 2>/dev/null || true
done

sec LOGIN_AND_SHELL
run 'defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null'
run 'ls -la /etc/periodic /etc/rc.common /etc/zprofile /etc/zshrc /etc/profile 2>/dev/null'
for home in /Users/*; do
  [ -d "$home" ] || continue
  printf '## %s\n' "$home"
  ls -la "$home"/.zshrc "$home"/.zprofile "$home"/.zlogin "$home"/.bash_profile "$home"/.bashrc "$home"/.profile 2>/dev/null || true
done

sec CRON_AND_AT
run 'crontab -l 2>/dev/null'
run 'ls -la /usr/lib/cron /var/at /private/var/at 2>/dev/null'
