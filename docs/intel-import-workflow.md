# Intel Store

Tracks every host, credential, pivot path, and account discovered during an investigation. Stored as YAML in `workspace/intel/` — persists across container restarts and is queryable at any point in the incident.

## Four categories

| Category | What it tracks | Lifecycle |
|----------|---------------|-----------|
| `host` | Compromised systems, suspected targets, discovered endpoints | `suspected` → `compromised` → `contained` → `cleared` |
| `credential` | Passwords, NTLM hashes, SSH keys, tokens, Kerberos tickets | `unvalidated` → `active` → `rotated` |
| `account` | Domain and local accounts encountered during investigation | `suspected` → `compromised` → `disabled` |
| `pivot` | Access paths from harness through the network to each target | `suspected` → `confirmed` → `active` → `cleared` |

Every entry requires a `source.method` field so findings can be traced back to the playbook or command that found them.

---

## Recording findings

Three paths — use whichever fits the moment:

### 1. Direct intel_add (fastest)

```text
intel_add(category="host", id="db01",
  data="ip: 10.10.20.10\nplatform: linux\nstatus: suspected\nsource:\n  host: web01\n  method: ansible inventory\n  path: /etc/ansible/hosts\n  playbook: linux/ansible-triage.sh",
  summary="db01 found in Ansible inventory on web01")
```

### 2. bin/intel-snippet (for structured artifact types)

Generates normalized YAML and a ready-to-paste `intel_add(...)` call. Use when the source is a specific artifact type — PuTTY session, PSReadLine hit, DNS cache entry, etc.

```bash
bin/intel-snippet <subcommand> [options]
```

### 3. Ask pi

Describe the finding: *"Record db01 at 10.10.20.10, found in the Ansible inventory on web01"*. Pi generates and executes the call.

---

## intel-snippet templates

### PuTTY saved session → host

```bash
bin/intel-snippet putty-host \
  --id adminws \
  --host 10.10.30.20 \
  --username admin \
  --session-name adminws \
  --source-host workstation01
```

### Ansible inventory target → host

```bash
bin/intel-snippet ansible-host \
  --id db01 \
  --host 10.10.20.10 \
  --inventory-name db01 \
  --username deploy \
  --access-credential deploy-ssh-key \
  --source-host web01
```

### PSReadLine history hit → credential

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

### DNS cache hit → host artifact

```bash
bin/intel-snippet dnscache-host \
  --id adminws \
  --entry adminws.corp.local \
  --record-type A \
  --data-value 10.10.30.20 \
  --source-host win01
```

### AV exclusion path → host artifact

```bash
bin/intel-snippet av-path-host \
  --id temp-tools \
  --exclusion-path 'C:\Users\Public\Tools' \
  --source-host win01
```

### USB history → host artifact

```bash
bin/intel-snippet usb-artifact-host \
  --id usb-kingston \
  --friendly-name 'Kingston DataTraveler' \
  --container-id ABCD \
  --source-host win01
```

### VPN config → pivot

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

### AD user/group finding → account

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

### RDP artifact → host

```bash
bin/intel-snippet rdp-host \
  --id adminws \
  --host adminws.corp.local \
  --source-host win01
```

### Browser / admin-console artifact → host

```bash
bin/intel-snippet browser-host \
  --id aws-console \
  --endpoint 'https://console.aws.amazon.com/' \
  --host console.aws.amazon.com \
  --browser chrome \
  --source-host win01
```

### CIFS mount → pivot

```bash
bin/intel-snippet cifs-pivot \
  --id to-fileshare \
  --target fileshare01 \
  --hop web01 \
  --share-path '//fileshare01/finance' \
  --config-path /etc/fstab \
  --source-host web01
```

### Host with full endpoint detail

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

### SSH key credential

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

### Pivot from saved session evidence

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

---

## Lifecycle transitions

Use `intel_update` for all status changes. It validates the transition, union-merges arrays, logs a timeline entry, and — for credentials — blocks future retrieval once terminal status is set.

```text
# Host through its lifecycle
intel_update(category="host", id="web01",
  fields="status: compromised", summary="Confirmed attacker presence on web01")

intel_update(category="host", id="web01",
  fields="status: contained\nnotes: C2 185.x.x.x blocked, PID 4523 killed",
  summary="web01 contained")

intel_update(category="host", id="web01",
  fields="status: cleared\nnotes: Persistence removed, re-triage clean",
  summary="web01 cleared")

# Credential rotation — blocks intel_get_cred from returning the secret
intel_update(category="credential", id="admin-ntlm",
  fields="status: rotated", summary="Domain admin password reset by identity team")

# Pivot cleanup
intel_update(category="pivot", id="to-dc01",
  fields="status: cleared", summary="Tunnel torn down, relay closed")
```

**Array merging:** Arrays union-merge by default — adding a new host to `valid_on` won't erase previous entries. Use `replace_arrays=true` only when intentionally replacing a list.

**Terminal credential statuses:** `intel_get_cred` refuses to return secrets for credentials with status `rotated`, `expired`, `revoked`, `disabled`, `inactive`, or `invalid`. Use `force=true` on `intel_update` only to correct an erroneously set terminal status; for new secrets after rotation, create a new credential ID.

**Split secret stores:** `credentials.yaml` is not the only place secrets can live. Remote session transcripts and gather output may contain raw passwords, hashes, keys, and tokens captured before import. Some gather credential scripts redact obvious values by default and accept `BRJOTSKEL_REVEAL_SECRETS=1` when raw material is needed, but archive/report handling must still treat logs as credential-bearing evidence. Use `bin/ir-report --format json --redact-secrets` for shareable JSON exports; `bin/ir-package` intentionally preserves raw evidence and warns instead of blocking.

---

## Querying the store

```text
# All intel for a specific host: credentials, accounts, pivots
intel_query(query_type="for_host", target="dc01")

# All hosts where a credential is valid
intel_query(query_type="for_credential", target="admin-ntlm")

# Full listing by category
intel_query(query_type="all_hosts")
intel_query(query_type="all_credentials")
intel_query(query_type="all_accounts")
intel_query(query_type="all_pivots")

# Cross-category keyword search
intel_query(query_type="search", keyword="corp.local")

# Counts and status breakdown
intel_summary()

# Chronological investigation record
intel_timeline(action="view")
intel_timeline(action="view", count=50)
```

---

## Schema reference

### Required fields — all categories

| Field | Required | Notes |
|-------|----------|-------|
| `status` | ✓ | Per-category enum below |
| `source.method` | ✓ | How this intel was discovered |
| `source.host` | recommended | Which compromised host it came from |
| `source.path` | recommended | File, registry key, or URL |
| `source.playbook` | recommended | Playbook that found it |

### Hosts

Required: `status`, `source.method`, plus at least one of: `ip`, `hostname`, non-empty `endpoints`, or non-empty `profile_artifacts`.

| Status | Meaning |
|--------|---------|
| `unknown` | In scope but not yet assessed |
| `in-scope` | Within incident scope |
| `out-of-scope` | Outside authorized scope |
| `suspected` | May be compromised |
| `confirmed` | Confirmed accessible |
| `compromised` | Confirmed attacker presence |
| `contained` | Isolated / C2 cut / processes killed |
| `remediated` | Persistence removed |
| `eradicated` | Full cleanup complete |
| `cleared` | Post-eradication triage clean |
| `unreachable` | Cannot currently access |
| `decommissioned` | No longer active |

### Credentials

Required: `type`, `username`, `status`, `source.method`, plus one of: `secret`, `key_file`, `ticket_file`.

| Type | Notes |
|------|-------|
| `password` | Plaintext password |
| `ntlm-hash` | LM:NT format or just `:NT` |
| `lm-hash` | LM hash only |
| `ssh-key` | Use `key_file` pointing to `workspace/intel/keys/` |
| `private-key` | Non-SSH private key |
| `kerberos-tgt` | TGT ticket — use `ticket_file` |
| `kerberos-tgs` | Service ticket |
| `token` | API or auth token |
| `api-key` | API key |
| `cookie` | Session cookie |
| `certificate` | Client certificate |
| `other` | Anything else |

| Status | Meaning |
|--------|---------|
| `unvalidated` | Found, not yet tested |
| `suspected` | Likely valid |
| `active` | Confirmed working |
| `confirmed` | Alias for active |
| `compromised` | Known to the attacker |
| `invalid` | Tested, doesn't work ← terminal |
| `rotated` | Secret changed ← terminal |
| `expired` | Past expiry ← terminal |
| `revoked` | Explicitly revoked ← terminal |
| `disabled` | Account disabled ← terminal |
| `inactive` | No longer in use ← terminal |

### Accounts

Required: `type`, `username`, `status`, `source.method`.

`type`: `local`, `local-user`, `domain`, `domain-user`, `service-account`, `machine-account`, `group`, `cloud-user`, `other`

`status`: `unknown`, `suspected`, `confirmed`, `compromised`, `active`, `contained`, `remediated`, `cleared`, `disabled`, `locked`, `inactive`

### Pivots

Required: `target`, `status`, `source.method`, plus `chain` list with at least one entry containing `hop`.

`status`: `suspected`, `confirmed`, `active`, `contained`, `blocked`, `cleared`, `inactive`

---

## LSASS dump credentials

After pulling and analysing a dump file with `secretsdump.py`, record each recovered credential:

```bash
# NTLM hash from LSASS dump
bin/intel-snippet credential \
  --id "admin-ntlm-lsass" \
  --type ntlm-hash \
  --username Administrator \
  --domain corp.local \
  --secret "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0" \
  --status active \
  --source-host dc01 \
  --source-method "lsass-dump (comsvcs.dll MiniDump)" \
  --source-playbook "windows/lsass-dump.ps1"
```

Key notes:
- Domain cached credentials (DCC2) are `ntlm-hash` type with `domain: corp.local`
- Kerberos tickets pulled from LSASS are `kerberos-tgt` type with `ticket_file:` pointing to extracted `.ccache`
- WDigest plaintext (if present) is `password` type
- Remove the dump file from the target immediately after retrieval; note the removal in `intel_timeline`

---

## Cloud identity credentials

### AWS EC2 — attached IAM role

```bash
bin/intel-snippet cloud-role \
  --id "ec2-prod-role" \
  --provider aws \
  --role-name "EC2-ProdRole-FullS3" \
  --access-key-id "ASIA..." \
  --session-token "FQo..." \
  --expiry "2026-08-25T18:00:00Z" \
  --source-host web01 \
  --summary "EC2 IAM role EC2-ProdRole-FullS3 on web01"
```

### Azure — managed identity

```bash
bin/intel-snippet cloud-role \
  --id "azure-mi-webapp" \
  --provider azure \
  --role-name "webapp-managed-identity" \
  --token "<bearer token from IMDS>" \
  --expiry "2026-08-25T19:00:00Z" \
  --source-host webapp01 \
  --summary "Azure managed identity webapp-managed-identity on webapp01"
```

### GCP — service account

```bash
bin/intel-snippet cloud-role \
  --id "gcp-sa-compute" \
  --provider gcp \
  --role-name "123456-compute@developer.gserviceaccount.com" \
  --token "<access_token from metadata service>" \
  --expiry "2026-08-25T17:30:00Z" \
  --source-host gce-instance01 \
  --summary "GCP service account on gce-instance01"
```

Cloud credential blast radius mapping:
- AWS: use `aws iam simulate-principal-policy` or enumerate role policies from harness
- Azure: `az role assignment list --assignee <object-id>` from harness
- GCP: `gcloud projects get-iam-policy <project>` from harness
- Record the scope in `notes:` field — this drives pivot decisions
