#!/bin/sh
# gather/linux/ansible-triage.sh — Enumerate Ansible artifacts, inventory, and key references
# Requires: Read access to Ansible paths and user homes
# Read-only: YES
# MITRE ATT&CK: T1087 / T1021 / credential and pivot discovery

find_ansible_inventory() {
  for p in /usr/bin/ansible-inventory /usr/local/bin/ansible-inventory; do
    [ -x "$p" ] && { echo "$p"; return; }
  done
}

find_ansible_cfg() {
  for p in /etc/ansible/ansible.cfg /playbook/ansible.cfg "$HOME/.ansible.cfg"; do
    [ -f "$p" ] && { echo "$p"; return; }
  done
}

echo "=== OBJECTIVE ==="
echo "Collect Ansible config, inventory, key references, and target host hints for pivot and credential triage."

echo ""
echo "=== ANSIBLE_BINARIES ==="
command -v ansible 2>/dev/null || true
command -v ansible-playbook 2>/dev/null || true
ANSIBLE_INV="$(find_ansible_inventory)"
[ -n "$ANSIBLE_INV" ] && echo "$ANSIBLE_INV"

echo ""
echo "=== ANSIBLE_CONFIG_PATHS ==="
CFG="$(find_ansible_cfg)"
[ -n "$CFG" ] && echo "$CFG"
find /etc/ansible /opt /srv /home /root -maxdepth 3 \( -name ansible.cfg -o -name hosts -o -name inventory -o -name '*.ini' -o -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | grep -E '/ansible/|/inventory|/hosts$' | sort | head -200

echo ""
echo "=== ANSIBLE_CONFIG_CONTENT ==="
if [ -n "$CFG" ]; then
  echo "--- $CFG ---"
  sed -n '1,200p' "$CFG" 2>/dev/null
fi

echo ""
echo "=== ANSIBLE_PRIVATE_KEY_REFERENCES ==="
for f in $(find /etc/ansible /opt /srv /home /root -maxdepth 4 \( -name ansible.cfg -o -name hosts -o -name '*.ini' -o -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | head -200); do
  grep -HnE 'private_key_file|ansible_ssh_private_key_file|--private-key' "$f" 2>/dev/null
 done

echo ""
echo "=== ANSIBLE_INVENTORY_TARGET_HINTS ==="
for f in $(find /etc/ansible /opt /srv /home /root -maxdepth 4 \( -name hosts -o -name inventory -o -name '*.ini' -o -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | head -200); do
  echo "--- $f ---"
  grep -HnE 'ansible_host|ansible_user|ansible_port|^[[:alnum:]_.-]+[[:space:]]+ansible_host=|^[[:alnum:]_.-]+$' "$f" 2>/dev/null | head -100
 done

echo ""
echo "=== ANSIBLE_INVENTORY_LIST ==="
if [ -n "$ANSIBLE_INV" ]; then
  "$ANSIBLE_INV" --list 2>/dev/null | sed -n '1,200p'
fi

echo ""
echo "=== ANSIBLE_KNOWN_HOSTS_AND_SSH_CONFIG ==="
find /home /root -maxdepth 3 \( -path '*/.ssh/config' -o -path '*/.ssh/known_hosts' \) 2>/dev/null | sort | while IFS= read -r f; do
  echo "--- $f ---"
  sed -n '1,120p' "$f" 2>/dev/null
 done
