---
name: eradication-playbooks
zero_key: false
description: "Evidence-backed persistence removal scripts for Linux, Windows, and macOS. Each script pairs removal with evidence capture and post-removal verification. State-changing — read each script before running. Always run containment and evidence collection first."
---

# Eradication Playbooks

Structured persistence removal scripts. Every script enforces the same discipline:

1. **Evidence** — document the artifact (path, hash, contents) before removing it
2. **Remove** — execute the minimum removal action
3. **Verify** — confirm the artifact is gone and did not recreate
4. **Record** — emit an `intel_timeline` or `intel_update` snippet ready to paste

## ⚠️ Rules before running any eradication script

1. **Containment first.** Eradication is pointless if the attacker still has an active session. Run containment scripts before eradication.
2. **Evidence before removal.** Every script captures a before-snapshot. Do not skip it.
3. **These scripts are state-changing.** They remove cron jobs, systemd units, registry keys, WMI subscriptions. Read before running.
4. **Verify after every removal.** Persistence can recreate from a second mechanism. The verify step in each script is mandatory.
5. **Watch for respawn.** After removal, wait 30–60 seconds and re-run the verify section before marking clean.

## Workflow

```
# 1. Confirm the artifact (evidence-first)
# 2. Run the targeted eradication script
# 3. Verify it's gone and did not recreate
# 4. Re-run first-look to check for unexpected activity
# 5. Record in intel store

intel_timeline(action="add", entry_type="eradication", entry_action="eradicated",
  target="<host>", summary="<artifact> removed — verified clean")

intel_update(category="host", id="<host>",
  fields="status: eradicated\nnotes: Persistence removed and verified",
  summary="<host>: eradication complete")
```

## Script inventory

### Linux

| Script | Removes |
|--------|---------|
| `linux/remove-cron.sh` | Cron entries — system crontab, /etc/cron.d, and user crontabs |
| `linux/remove-systemd-unit.sh` | Systemd service or timer unit |
| `linux/remove-ssh-key.sh` | Attacker SSH public key from authorized_keys |
| `linux/remove-profile-hook.sh` | Shell profile/rc hook (bashrc, profile, profile.d) |

### Windows

| Script | Removes |
|--------|---------|
| `windows/remove-scheduled-task.ps1` | Scheduled task with evidence export |
| `windows/remove-service.ps1` | Service with evidence export and verification |
| `windows/remove-registry-run.ps1` | Registry Run/RunOnce key entry |
| `windows/remove-wmi-subscription.ps1` | WMI event subscription (Filter + Consumer + Binding) |

### macOS

| Script | Removes |
|--------|----------|
| `macos/remove-launch-item.sh` | LaunchDaemon or LaunchAgent plist |
| `macos/remove-cron.sh` | User crontab entries and /etc/cron.d files |
| `macos/remove-profile-hook.sh` | Shell profile/rc hooks (.zshrc, .zprofile, .zlogin, /etc/profile.d/) |
| `macos/remove-ssh-key.sh` | Attacker SSH public key from authorized_keys |
| `macos/remove-btm-login-item.sh` | BTM login items (macOS 13+) and legacy login items via osascript/pluginkit |
| `macos/remove-launch-item.sh` | LaunchDaemon or LaunchAgent plist |
