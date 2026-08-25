#!/bin/sh
set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
run(){ printf '$ %s\n' "$*"; sh -c "$*" 2>/dev/null || true; }

sec CURRENT_USER
run 'whoami'
run 'security list-keychains 2>/dev/null'
run 'security default-keychain 2>/dev/null'
run 'security dump-keychain -d login.keychain-db 2>/dev/null | egrep "acct|desc|srvr|svce"'

sec SSH_AND_GPG
run 'find ~/.ssh -maxdepth 2 -type f 2>/dev/null -exec ls -la {} \;'
run 'find ~/.gnupg -maxdepth 2 -type f 2>/dev/null -exec ls -la {} \;'
run 'cat ~/.ssh/authorized_keys ~/.ssh/known_hosts 2>/dev/null'

sec HISTORIES_AND_TOKENS
run 'tail -100 ~/.zsh_history 2>/dev/null'
run 'tail -100 ~/.bash_history 2>/dev/null'
run 'grep -R -nE "(AKIA|aws_access_key_id|aws_secret_access_key|BEGIN [A-Z ]*PRIVATE KEY|token|password=)" ~/.aws ~/.config ~/.ssh ~/.kube ~ 2>/dev/null | head -200'

sec AUTOLOGIN_AND_FILEVAULT
run 'defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null'
run 'fdesetup list 2>/dev/null'
