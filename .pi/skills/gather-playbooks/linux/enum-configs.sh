#!/bin/sh
# gather/linux/enum-configs.sh — Service configuration files
# Requires: read access to /etc
# Read-only: YES
# MITRE ATT&CK: T1005 — Data from Local System

echo "=== SSHD CONFIG ==="
cat /etc/ssh/sshd_config 2>/dev/null | grep -v "^#" | grep -v "^$"

echo ""
echo "=== APACHE / NGINX ==="
for f in /etc/apache2/apache2.conf /etc/apache2/sites-enabled/* \
         /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/* \
         /etc/nginx/nginx.conf /etc/nginx/sites-enabled/*; do
  [ -f "$f" ] || continue
  echo "--- $f ---"
  cat "$f" 2>/dev/null | grep -v "^#" | grep -v "^$" | grep -v "^\s*#"
done

echo ""
echo "=== MYSQL / MARIADB ==="
for f in /etc/mysql/my.cnf /etc/mysql/debian.cnf /etc/mysql/mysql.conf.d/mysqld.cnf /etc/my.cnf; do
  [ -f "$f" ] || continue
  echo "--- $f ---"
  cat "$f" 2>/dev/null
done

echo ""
echo "=== POSTGRESQL ==="
find /etc/postgresql -name "pg_hba.conf" 2>/dev/null | while IFS= read -r f; do
  echo "--- $f ---"
  cat "$f" 2>/dev/null | grep -v "^#" | grep -v "^$"
done

echo ""
echo "=== SAMBA ==="
[ -f /etc/samba/smb.conf ] && echo "--- /etc/samba/smb.conf ---" && cat /etc/samba/smb.conf 2>/dev/null | grep -v "^[;#]" | grep -v "^$"

echo ""
echo "=== LDAP ==="
for f in /etc/ldap/ldap.conf /etc/openldap/ldap.conf; do
  [ -f "$f" ] && echo "--- $f ---" && cat "$f" 2>/dev/null
done

echo ""
echo "=== SYSTEMD OVERRIDES ==="
find /etc/systemd/system \( -name "*.conf" -o -name "override.conf" \) 2>/dev/null | while IFS= read -r f; do
  echo "--- $f ---"
  cat "$f" 2>/dev/null
done

echo ""
echo "=== INTERESTING /etc FILES ==="
for f in /etc/exports /etc/fstab /etc/crypttab /etc/auto.master; do
  [ -f "$f" ] || continue
  echo "--- $f ---"
  cat "$f" 2>/dev/null | grep -v "^#" | grep -v "^$"
done
