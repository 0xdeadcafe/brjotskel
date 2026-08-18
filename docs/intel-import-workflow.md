# Intel Import Workflow

Use gather-playbook findings to create normalized `intel_add(...)` entries with provenance.

## Helper

- `bin/intel-snippet`

It prints:
- YAML for the entry
- a ready-to-paste `intel_add(...)` call

## Common patterns

### Fast templates for specific playbooks

#### PuTTY saved session → host

```bash
bin/intel-snippet putty-host \
  --id adminws \
  --host 10.10.30.20 \
  --username admin \
  --session-name adminws \
  --source-host workstation01
```

#### Ansible inventory target → host

```bash
bin/intel-snippet ansible-host \
  --id db01 \
  --host 10.10.20.10 \
  --inventory-name db01 \
  --username deploy \
  --access-credential deploy-ssh-key \
  --source-host web01
```

#### PSReadLine history hit → credential

```bash
bin/intel-snippet psreadline-credential \
  --id aws-token-user1 \
  --type token \
  --username user1 \
  --secret ABC123 \
  --user-profile user1 \
  --line-number 42 \
  --source-host win01
```

#### AV exclusion path → host artifact

```bash
bin/intel-snippet av-path-host \
  --id temp-tools \
  --exclusion-path 'C:\Users\Public\Tools' \
  --source-host win01
```

#### DNS cache hit → host artifact

```bash
bin/intel-snippet dnscache-host \
  --id adminws \
  --entry adminws.corp.local \
  --record-type A \
  --data-value 10.10.30.20 \
  --source-host win01
```

#### USB history artifact → host artifact

```bash
bin/intel-snippet usb-artifact-host \
  --id usb-kingston \
  --friendly-name 'Kingston DataTraveler' \
  --container-id ABCD \
  --source-host win01
```

#### VPN config → pivot

```bash
bin/intel-snippet vpn-pivot \
  --id to-vpn-gw \
  --target vpn-gw \
  --hop web01 \
  --config-path /etc/openvpn/client.conf \
  --remote-host vpn.corp.local \
  --remote-port 1194 \
  --source-host web01
```

#### AD user/group finding → account

```bash
bin/intel-snippet ad-account \
  --id 'corp\\sqlsvc' \
  --username sqlsvc \
  --domain corp.local \
  --privilege 'Domain Users' \
  --access-to sql01 \
  --source-host dc01 \
  --source-method 'AD user enumeration' \
  --source-playbook windows/enum-ad-users.ps1
```

#### RDP artifact → host

```bash
bin/intel-snippet rdp-host \
  --id adminws \
  --host adminws.corp.local \
  --source-host win01
```

#### Browser/admin-console artifact → host

```bash
bin/intel-snippet browser-host \
  --id aws-console \
  --endpoint 'https://console.aws.amazon.com/' \
  --host console.aws.amazon.com \
  --browser chrome \
  --source-host win01
```

#### CIFS mount artifact → pivot

```bash
bin/intel-snippet cifs-pivot \
  --id to-fileshare \
  --target fileshare01 \
  --hop web01 \
  --share-path '//fileshare01/finance' \
  --config-path /etc/fstab \
  --source-host web01
```

### 1. Host from profile/config artifact

Example: Ansible inventory reveals `db01`.

```bash
bin/intel-snippet host-endpoint \
  --id db01 \
  --ip 10.10.20.10 \
  --hostname db01.corp.local \
  --platform linux \
  --role db \
  --endpoint 'ssh://deploy@10.10.20.10:22' \
  --profile-artifact ansible-inventory \
  --source-host web01 \
  --source-method 'ansible inventory' \
  --source-path /etc/ansible/hosts \
  --source-tool ansible \
  --source-playbook linux/ansible-triage.sh
```

### 2. Credential from recovered key or token

```bash
bin/intel-snippet credential \
  --id deploy-ssh-key \
  --type ssh-key \
  --username deploy \
  --key-file keys/deploy-ed25519 \
  --valid-on db01 \
  --valid-on app01 \
  --related-host jump01 \
  --source-host web01 \
  --source-method 'found in user ssh directory' \
  --source-path /home/deploy/.ssh/id_ed25519 \
  --source-tool ssh \
  --source-playbook linux/ssh-keys.sh
```

### 3. Pivot from saved session / config evidence

```bash
bin/intel-snippet pivot \
  --id to-db01 \
  --target db01 \
  --hop web01 \
  --method ssh-proxy-jump \
  --credential deploy-ssh-key \
  --command 'ssh -J root@10.10.10.5 deploy@10.10.20.10' \
  --related-host adminws \
  --evidence-kind putty-session \
  --evidence-host adminws \
  --evidence-path 'HKCU\Software\SimonTatham\PuTTY\Sessions\db01' \
  --source-host adminws \
  --source-method 'saved PuTTY session' \
  --source-path 'HKCU\Software\SimonTatham\PuTTY\Sessions\db01' \
  --source-playbook windows/putty-sessions.ps1
```

## Required schema and lifecycle fields

`intel_add` and `intel_update` validate entries before writing them. Validation errors are intentionally actionable and list the missing field or allowed enum values.

### Required by every category

- `status`: one of the category-specific values below
- `source.method`: how this intel was discovered
- Prefer also adding `source.host`, `source.path`, `source.tool`, and/or `source.playbook` when known

### Hosts

Required:
- `status`
- `source.method`
- at least one locator: `ip`, `hostname`, non-empty `endpoints`, or non-empty `profile_artifacts`

Allowed `status` values:
- `unknown`, `in-scope`, `out-of-scope`, `suspected`, `confirmed`, `compromised`, `contained`, `remediated`, `eradicated`, `cleared`, `unreachable`, `decommissioned`

### Credentials

Required:
- `type`
- `username`
- `status`
- `source.method`
- credential material: `secret`, `key_file`, or `ticket_file`

Allowed `type` values:
- `password`, `ntlm-hash`, `lm-hash`, `ssh-key`, `private-key`, `kerberos-tgt`, `kerberos-tgs`, `token`, `api-key`, `cookie`, `certificate`, `other`

Allowed `status` values:
- `unvalidated`, `suspected`, `compromised`, `active`, `confirmed`, `invalid`, `rotated`, `expired`, `revoked`, `disabled`, `inactive`

### Accounts

Required:
- `type`
- `username`
- `status`
- `source.method`

Allowed `type` values:
- `local`, `local-user`, `domain`, `domain-user`, `service-account`, `machine-account`, `group`, `cloud-user`, `other`

Allowed `status` values:
- `unknown`, `suspected`, `confirmed`, `compromised`, `active`, `contained`, `remediated`, `cleared`, `disabled`, `locked`, `inactive`

### Pivots

Required:
- `target`
- `status`
- `source.method`
- non-empty `chain` list with at least `hop` per item

Allowed `status` values:
- `suspected`, `confirmed`, `active`, `contained`, `blocked`, `cleared`, `inactive`

### Updating lifecycle state

Use `intel_update` instead of replacing entries by hand:

```text
intel_update(category="host", id="web01", fields="status: contained\nnotes: C2 blocked and persistence disabled", summary="web01 contained")
intel_update(category="credential", id="admin-hash", fields="status: rotated", summary="admin hash rotated by identity team")
intel_update(category="pivot", id="to-db01", fields="status: cleared", summary="Pivot path no longer active")
```

Arrays are union-merged by default, so adding a new `valid_on` host does not erase existing validation results. Set `replace_arrays=true` only when intentionally replacing a list. Credential terminal statuses (`rotated`, `expired`, `revoked`, `disabled`, `inactive`, `invalid`) are not reactivated without `force=true`; prefer a new credential ID for replacement secrets.

## Normalized fields

### Hosts

- `endpoints`
- `profile_artifacts`
- `source.host`
- `source.method`
- `source.path`
- `source.tool`
- `source.playbook`

### Credentials

- `valid_on`
- `related_hosts`
- `source.*`

### Pivots

- `chain`
- `evidence`
- `related_hosts`
- `source.*`

## Recommended operator flow

1. Run gather playbook
2. Identify host / credential / pivot artifact
3. Use `bin/intel-snippet ...` to build normalized YAML
4. Paste the emitted `intel_add(...)` call into pi
5. Confirm with:

```text
intel_query(query_type="for_host", target="db01")
intel_summary()
```
