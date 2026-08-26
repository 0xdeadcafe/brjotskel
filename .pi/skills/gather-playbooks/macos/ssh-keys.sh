#!/bin/sh
# gather/macos/ssh-keys.sh — Sweep SSH keys, authorized_keys, known_hosts across /Users
# Requires: read access to user home directories
# Read-only: YES
# MITRE ATT&CK: T1552.004 — Unsecured Credentials: Private Keys

set -u

sec(){ printf '\n=== %s ===\n' "$1"; }
has(){ command -v "$1" >/dev/null 2>&1; }

list_user_homes(){
  if [ -d /Users ]; then
    find /Users -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | sort
  fi
}

sha256_file(){
  if has shasum; then
    shasum -a 256 "$1" 2>/dev/null || true
  else
    printf 'shasum unavailable: %s\n' "$1"
  fi
}

fingerprint_key(){
  if has ssh-keygen; then
    ssh-keygen -l -f "$1" 2>/dev/null || printf 'ssh-keygen could not fingerprint: %s\n' "$1"
  else
    printf 'ssh-keygen unavailable: %s\n' "$1"
  fi
}

show_file_meta(){
  f=$1
  echo "--- $f ---"
  ls -lOe "$f" 2>/dev/null || ls -l "$f" 2>/dev/null || true
  sha256_file "$f"
  first_line=$(sed -n '1p' "$f" 2>/dev/null || true)
  case "$first_line" in
    *"PRIVATE KEY"*) printf 'header: %s\n' "$first_line" ;;
    *) printf 'header: %s\n' "${first_line:-unreadable-or-empty}" ;;
  esac
  fingerprint_key "$f"
}

sec HOST_CONTEXT
hostname 2>/dev/null || true
whoami 2>/dev/null || true
sw_vers 2>/dev/null || true

sec SSH_DIRECTORIES
list_user_homes | while IFS= read -r home; do
  [ -d "$home/.ssh" ] || continue
  echo "--- $home/.ssh ---"
  ls -laOe "$home/.ssh" 2>/dev/null || ls -la "$home/.ssh" 2>/dev/null || true
done

sec PRIVATE_KEY_FILES
list_user_homes | while IFS= read -r home; do
  sshdir="$home/.ssh"
  [ -d "$sshdir" ] || continue
  find "$sshdir" -maxdepth 2 -type f \( \
    -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' -o -name 'id_dsa' -o \
    -name '*.pem' -o -name '*.key' \
  \) -print 2>/dev/null | sort | while IFS= read -r f; do
    show_file_meta "$f"
  done
  # Catch non-standard OpenSSH private key names without dumping full private material.
  find "$sshdir" -maxdepth 2 -type f \
    ! -name '*.pub' ! -name 'known_hosts*' ! -name 'authorized_keys*' ! -name 'config' \
    ! -name 'id_rsa' ! -name 'id_ed25519' ! -name 'id_ecdsa' ! -name 'id_dsa' \
    ! -name '*.pem' ! -name '*.key' -print 2>/dev/null | sort | while IFS= read -r f; do
      sed -n '1p' "$f" 2>/dev/null | grep -q 'PRIVATE KEY' || continue
      show_file_meta "$f"
    done
done

sec AUTHORIZED_KEYS
list_user_homes | while IFS= read -r home; do
  for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
    [ -f "$f" ] || continue
    echo "--- $f ---"
    ls -lOe "$f" 2>/dev/null || ls -l "$f" 2>/dev/null || true
    cat "$f" 2>/dev/null || true
  done
done

sec SSH_CONFIG
list_user_homes | while IFS= read -r home; do
  f="$home/.ssh/config"
  [ -f "$f" ] || continue
  echo "--- $f ---"
  ls -lOe "$f" 2>/dev/null || ls -l "$f" 2>/dev/null || true
  cat "$f" 2>/dev/null || true
done

sec KNOWN_HOSTS_PIVOT_HINTS
list_user_homes | while IFS= read -r home; do
  for f in "$home/.ssh/known_hosts" "$home/.ssh/known_hosts2"; do
    [ -f "$f" ] || continue
    echo "--- $f ---"
    ls -lOe "$f" 2>/dev/null || ls -l "$f" 2>/dev/null || true
    printf 'hashed entries: '
    grep '^|' "$f" 2>/dev/null | wc -l | tr -d ' '
    printf 'cleartext host hints (first 100):\n'
    grep -v '^#' "$f" 2>/dev/null | grep -v '^|' | awk 'NF {print $1}' | head -100 || true
  done
done

sec SYSTEM_SSH
ls -laOe /etc/ssh 2>/dev/null || ls -la /etc/ssh 2>/dev/null || true
for f in /etc/ssh/ssh_host_* /etc/ssh/ssh_config /etc/ssh/sshd_config; do
  [ -f "$f" ] || continue
  echo "--- $f ---"
  ls -lOe "$f" 2>/dev/null || ls -l "$f" 2>/dev/null || true
  case "$f" in
    /etc/ssh/ssh_host_*_key)
      sha256_file "$f"
      fingerprint_key "$f"
      ;;
    /etc/ssh/ssh_config|/etc/ssh/sshd_config)
      grep -iE '^[[:space:]]*(Host|HostName|User|IdentityFile|ProxyJump|ProxyCommand|AuthorizedKeysFile|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)' "$f" 2>/dev/null || true
      ;;
  esac
done

sec OTHER_USER_KEY_FILES
if [ -d /Users ]; then
  find /Users -maxdepth 5 -type f \( -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' \) -print 2>/dev/null | sort | head -100 | while IFS= read -r f; do
    echo "--- $f ---"
    ls -lOe "$f" 2>/dev/null || ls -l "$f" 2>/dev/null || true
    sha256_file "$f"
  done
fi
