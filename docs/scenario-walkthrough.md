# Scenario Walkthrough: Compromised Linux Web Server to AD Domain Controller

A realistic end-to-end incident. Scope: a customer reports unusual outbound traffic from their web tier. No EDR. SIEM shows an alert but no agent data. You have SSH to the web server and domain admin credentials are unconfirmed.

This walkthrough follows the full lifecycle: landing → credential recovery → lateral movement → AD compromise → containment → eradication.

---

## Initial state

- Confirmed host in scope: `web01` at `10.10.10.5` (Linux)
- Credential in hand: `root` / `rootpass123` (SSH)
- Unknown blast radius

---

## Phase 1: Land

Record initial scope in the intel store before touching anything:

```
intel_add(category="host", id="web01",
  data="ip: 10.10.10.5\nplatform: linux\nstatus: suspected\nsource:\n  method: incident brief",
  summary="Initial suspected compromised host — customer report of unusual outbound traffic")
```

Connect:

```
remote_connect(protocol="ssh", target="root@10.10.10.5", name="web01", password="rootpass123")
```

---

## Phase 2: Assess

```
/assess web01
```

The agent runs `first-look.sh`. Output shows:
- Established outbound connection on port 4444 to `185.220.101.45`
- PID `3821` bound to that connection — process name `kworker` (suspicious: kworker doesn't make outbound connections)
- File `/tmp/.x` — recently modified, 847KB

**That's a C2 callback. Don't contain yet — map the blast radius first.**

The agent automatically follows up with `enum-network.sh` and `enum-persistence.sh`. Additional findings:
- Systemd unit `/etc/systemd/system/kworker-io.service` — ExecStart points to `/tmp/.x`
- `/home/deploy/.ssh/authorized_keys` — two keys, one not in the known-good list
- Ansible inventory at `/etc/ansible/hosts` — references `db01` (10.10.20.10) and `dc01` (10.10.20.20)

Record C2:

```
intel_add(category="host", id="c2-185-220-101-45",
  data="ip: 185.220.101.45\nstatus: out-of-scope\nattacker_role: c2\nsource:\n  host: web01\n  method: outbound connection / first-look.sh",
  summary="Attacker C2: 185.220.101.45:4444 — active callback from PID 3821 on web01")
```

Record the persistence:

```
intel_timeline(action="add", entry_type="persistence", entry_action="discovered",
  target="web01", summary="Malicious systemd unit kworker-io.service → /tmp/.x")
```

---

## Phase 3: Pursue

The Ansible inventory reveals two reachable hosts. Record them:

```
intel_add(category="host", id="db01",
  data="ip: 10.10.20.10\nplatform: linux\nstatus: suspected\nsource:\n  host: web01\n  method: ansible inventory\n  path: /etc/ansible/hosts\n  playbook: linux/ansible-triage.sh",
  summary="db01 found in Ansible inventory on web01")

intel_add(category="host", id="dc01",
  data="ip: 10.10.20.20\nplatform: windows\nstatus: suspected\nsource:\n  host: web01\n  method: ansible inventory\n  path: /etc/ansible/hosts\n  playbook: linux/ansible-triage.sh",
  summary="dc01 found in Ansible inventory on web01")
```

Run credential recovery:

```
The agent runs: linux/hashdump.sh, linux/ssh-keys.sh, linux/enum-credentials.sh on web01
```

Findings:
- `/home/deploy/.ssh/id_ed25519` — private key for the `deploy` user
- `/home/web/.env` — `DB_PASS=Prod2024!`

Record both:

```
intel_add(category="credential", id="deploy-key",
  data="type: ssh-key\nusername: deploy\nkey_file: workspace/intel/keys/deploy-ed25519\nstatus: unvalidated\nsource:\n  host: web01\n  method: user SSH directory\n  path: /home/deploy/.ssh/id_ed25519\n  playbook: linux/ssh-keys.sh",
  summary="deploy SSH key recovered from web01")

intel_add(category="credential", id="db-password",
  data="type: password\nusername: web\nsecret: Prod2024!\nstatus: unvalidated\nsource:\n  host: web01\n  method: .env file\n  path: /home/web/.env\n  playbook: linux/enum-credentials.sh",
  summary="DB password recovered from .env on web01")
```

Validate at scale from the harness:

```bash
# From harness terminal:
netexec ssh 10.10.20.0/24 -u deploy --key workspace/intel/keys/deploy-ed25519
# Result: db01 (10.10.20.10) — SUCCESS

netexec smb 10.10.20.0/24 -u web -p 'Prod2024!' --no-bruteforce
# Result: no hits
```

Update intel:

```
intel_update(category="credential", id="deploy-key",
  fields="status: active\nvalid_on:\n  - db01",
  summary="deploy key confirmed working on db01")
```

---

## Phase 4: Pivot to db01

```
remote_connect(protocol="ssh", target="deploy@10.10.20.10", name="db01",
  identity="workspace/intel/keys/deploy-ed25519")

intel_add(category="host", id="db01",
  data="ip: 10.10.20.10\nplatform: linux\nstatus: compromised\nsource:\n  method: pivot via deploy key from web01",
  summary="db01 compromised — deploy key valid, landing confirmed")

/assess db01
```

First-look on db01 shows:
- `sudo -l` for deploy: `(ALL) NOPASSWD: ALL` — full sudo without password
- `/root/.ssh/authorized_keys` contains the same unknown key seen on web01
- `/etc/ansible` references `dc01` with a service account key at `/root/.ansible/dc01_key`

The attacker has admin on db01 and a path to dc01. Recover the Ansible key:

```
# Saved to workspace/intel/keys/dc01-ansible-key
intel_add(category="credential", id="dc01-ansible-key",
  data="type: ssh-key\nusername: svc_ansible\nkey_file: workspace/intel/keys/dc01-ansible-key\nstatus: unvalidated\nsource:\n  host: db01\n  method: ansible key reference\n  path: /root/.ansible/dc01_key\n  playbook: linux/ansible-triage.sh",
  summary="Ansible service account key for dc01 recovered from db01")
```

Test against dc01 (Windows):

```bash
netexec winrm 10.10.20.20 -u svc_ansible --key workspace/intel/keys/dc01-ansible-key
# Result: dc01 (10.10.20.20) — SUCCESS (Pwn3d!)
```

The attacker has a path to dc01.

---

## Phase 5: dc01 assessment

Tunnel in through db01 (dc01 not directly reachable from harness):

```
remote_tunnel(type="local", via="deploy@db01", local_port=5985,
  remote_host="dc01", remote_port=5985,
  identity="workspace/intel/keys/deploy-ed25519")

remote_connect(protocol="winrm", target="svc_ansible@localhost", port=5985, name="dc01",
  identity="workspace/intel/keys/dc01-ansible-key")

/assess dc01
```

`first-look.ps1` on dc01 shows:
- `svc_ansible` is a member of Domain Admins
- PSReadLine history contains: `net user backdoor B@ckd00r2024! /add /domain` and `net group "Domain Admins" backdoor /add /domain`
- Account `backdoor` exists, is active, in Domain Admins

The attacker has a domain admin backdoor account.

```
intel_add(category="account", id="corp\\backdoor",
  data="type: domain\nusername: backdoor\ndomain: corp.local\nprivileges:\n  - Domain Admins\nstatus: compromised\nattacker_use: backdoor domain admin account created by attacker\nsource:\n  host: dc01\n  method: PSReadLine history + AD enumeration\n  playbook: windows/psreadline-history.ps1",
  summary="Backdoor domain admin account created by attacker on dc01")

intel_add(category="credential", id="backdoor-pass",
  data="type: password\nusername: backdoor\ndomain: corp.local\nsecret: B@ckd00r2024!\nstatus: active\nvalid_on:\n  - dc01\nsource:\n  host: dc01\n  method: PSReadLine history\n  playbook: windows/psreadline-history.ps1",
  summary="Backdoor account password recovered from PSReadLine history on dc01")
```

Check `/map` — the attack graph now shows: web01 → db01 → dc01, with two credential chains and one attacker-created account.

---

## Phase 6: Contain

Blast radius is mapped. Three dirty hosts, one backdoor account, one C2 active.

**Order matters:** disable the attacker backdoor account first (they can't recover), then contain hosts.

Disable backdoor account immediately from dc01 session:

```
/contain dc01
# Agent runs collect-evidence.ps1 first, then disable-account.ps1 for "backdoor"
```

Then contain web01 (kill C2 process, block IP):

```
/contain web01
# Agent runs collect-evidence.sh, then kill-process.sh (PID 3821), then block-c2.sh (185.220.101.45)
```

Contain db01 (revoke deploy key's sudo, lock the unknown authorized_key):

```
/contain db01
```

Record containment:

```
intel_update(category="host", id="web01", fields="status: contained\nnotes: PID 3821 killed, C2 185.220.101.45 blocked", summary="web01 contained")
intel_update(category="host", id="db01",  fields="status: contained\nnotes: sudo revoked for deploy, unknown authorized_key removed", summary="db01 contained")
intel_update(category="host", id="dc01",  fields="status: contained\nnotes: backdoor account disabled", summary="dc01 contained")
intel_update(category="account", id="corp\\backdoor", fields="status: disabled", summary="Attacker backdoor account disabled")
```

---

## Phase 7: Eradicate

```
/eradicate web01   # removes kworker-io.service systemd unit, /tmp/.x
/eradicate db01    # removes attacker authorized_key from root
/eradicate dc01    # verifies no other persistence (Run keys, scheduled tasks, WMI subscriptions)
```

Each eradication script: export evidence → remove → verify removal.

---

## Phase 8: Verify and rotate

```
/verify web01
/verify db01
/verify dc01
```

No re-connections, no persistence remaining, accounts locked.

Coordinate credential rotation with the identity team:

```
intel_update(category="credential", id="deploy-key",   fields="status: rotated", summary="deploy SSH key rotated — new key issued")
intel_update(category="credential", id="db-password",  fields="status: rotated", summary="DB password rotated")
intel_update(category="credential", id="dc01-ansible-key", fields="status: rotated", summary="Ansible service account key rotated")
intel_update(category="credential", id="backdoor-pass", fields="status: revoked", summary="Backdoor account deleted and password invalidated")
```

Mark hosts cleared:

```
intel_update(category="host", id="web01", fields="status: cleared", summary="web01 cleared — re-triage clean")
intel_update(category="host", id="db01",  fields="status: cleared", summary="db01 cleared")
intel_update(category="host", id="dc01",  fields="status: cleared", summary="dc01 cleared")
```

---

## Final state

```
intel_summary()
```

- Hosts: 3 cleared, 1 out-of-scope (C2)
- Credentials: all rotated or revoked
- Accounts: backdoor disabled
- Timeline: full reconstruction from first alert to cleared

The intel store at `workspace/intel/` contains the full provenance trail for the incident report.

---

## What this scenario exercised

- Multi-hop pivoting: harness → web01 (SSH) → db01 (SSH via key) → dc01 (WinRM via tunnel)
- Credential blast radius: SSH key valid on db01, Ansible key valid on dc01
- AD-level compromise: service account in Domain Admins, attacker backdoor account
- Evidence-first containment: volatile capture before every disruptive action
- Lifecycle tracking: every host, credential, and account through its full lifecycle

For command references and decision heuristics at each phase, see [runbook.md](runbook.md).
