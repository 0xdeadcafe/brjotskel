# Active Containment Command Reference

Commands for authorized incident response when an owned asset is actively compromised and responders need to regain control.

## Rules of Engagement

Before running active commands:

- Confirm authorization and incident/ticket ID.
- Prefer scoped action over broad action.
- Capture minimal evidence first when feasible.
- Record commands, timestamps, operator, host, and expected impact.
- Prefer reversible controls where possible.
- Do not harvest credentials, dump secrets, implant persistence, exploit unrelated systems, or pivot through third-party assets.

## Windows PowerShell

### Capture quick context before containment

```powershell
# Read-only context snapshot. Run as Administrator for full visibility.
Get-Date
hostname
whoami /all
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Id,ProcessName,Path,CPU
Get-NetTCPConnection | Sort-Object State,RemoteAddress | Select-Object -First 50
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskName,TaskPath,State,Author
```

### Kill a malicious process

```powershell
# State-changing: terminates a specific process by PID.
# Replace <PID> after validating the process.
Stop-Process -Id <PID> -Force
```

### Disable a malicious service

```powershell
# State-changing: stops and disables a specific service.
# Replace <ServiceName> after validating service name/path.
Stop-Service -Name '<ServiceName>' -Force
Set-Service -Name '<ServiceName>' -StartupType Disabled
```

### Disable a malicious scheduled task

```powershell
# State-changing: disables a specific scheduled task without deleting it.
Disable-ScheduledTask -TaskPath '<TaskPath>' -TaskName '<TaskName>'
```

### Disable a compromised local account

```powershell
# State-changing: disables a local account.
Disable-LocalUser -Name '<Username>'
```

### Block active command-and-control IP

```powershell
# State-changing: adds a Windows Firewall outbound block rule.
New-NetFirewallRule -DisplayName 'IR Block C2 <IP>' -Direction Outbound -RemoteAddress <IP> -Action Block

# Optional inbound block as well.
New-NetFirewallRule -DisplayName 'IR Block Inbound <IP>' -Direction Inbound -RemoteAddress <IP> -Action Block
```

### Remove malicious Run key value

```powershell
# Preview first.
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

# State-changing: remove only the confirmed malicious value.
Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name '<ValueName>'
```

### Clear malicious WinRM sessions by stopping service temporarily

```powershell
# State-changing and disruptive: stops WinRM. Use only when remote management impact is acceptable.
Stop-Service WinRM -Force
```

## Windows CMD

### Kill process

```cmd
:: State-changing: terminate process by PID.
taskkill /PID <PID> /F
```

### Stop and disable service

```cmd
:: State-changing: stop and disable service.
sc stop <ServiceName>
sc config <ServiceName> start= disabled
```

### Disable scheduled task

```cmd
:: State-changing: disable a confirmed malicious scheduled task.
schtasks /Change /TN "<TaskPath\TaskName>" /DISABLE
```

### Disable local account

```cmd
:: State-changing: disable a local account.
net user <Username> /active:no
```

### Block IP with Windows Firewall

```cmd
:: State-changing: add outbound block rule.
netsh advfirewall firewall add rule name="IR Block C2 <IP>" dir=out action=block remoteip=<IP>
```

## Linux / Unix

### Capture quick context before containment

```bash
# Read-only context snapshot.
date -u
hostname
id
ps auxww --sort=-%cpu | head -25
ss -tunap 2>/dev/null | head -80
systemctl list-units --type=service --state=running 2>/dev/null | head -80
```

### Kill malicious process

```bash
# State-changing: terminate a specific process by PID.
kill -TERM <PID>
sleep 2
kill -KILL <PID> 2>/dev/null || true
```

### Stop and disable malicious service

```bash
# State-changing: stop and disable a confirmed malicious service.
sudo systemctl stop '<service-name>'
sudo systemctl disable '<service-name>'
```

### Block C2 IP with nftables

```bash
# State-changing: temporary runtime block with nftables.
sudo nft add table inet ir 2>/dev/null || true
sudo nft add chain inet ir output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true
sudo nft add rule inet ir output ip daddr <IP> drop
```

### Block C2 IP with iptables

```bash
# State-changing: temporary runtime outbound block.
sudo iptables -I OUTPUT -d <IP> -j DROP
```

### Lock compromised local account

```bash
# State-changing: lock account password and expire active access paths where applicable.
sudo passwd -l <username>
sudo usermod --expiredate 1 <username>
```

### Disable malicious cron entry safely

```bash
# State-changing: backs up user crontab then opens editor for manual removal.
user='<username>'
sudo crontab -u "$user" -l > "/tmp/ir-crontab-$user-$(date -u +%Y%m%dT%H%M%SZ).bak"
sudo crontab -u "$user" -e
```

### Remove malicious SSH authorized key safely

```bash
# State-changing: backup authorized_keys, then edit manually.
user='<username>'
home_dir=$(getent passwd "$user" | cut -d: -f6)
sudo cp -a "$home_dir/.ssh/authorized_keys" "/tmp/ir-authorized_keys-$user-$(date -u +%Y%m%dT%H%M%SZ).bak"
sudoedit "$home_dir/.ssh/authorized_keys"
```

## macOS

### Capture context

```bash
# Read-only context snapshot.
date -u
hostname
id
ps auxww -r | head -25
lsof -i -n -P | head -80
launchctl list | head -80
```

### Kill malicious process

```bash
# State-changing: terminate process by PID.
sudo kill -TERM <PID>
sleep 2
sudo kill -KILL <PID> 2>/dev/null || true
```

### Unload malicious LaunchAgent/LaunchDaemon

```bash
# State-changing: unload confirmed malicious launch item.
sudo launchctl bootout system '<path-to-plist>'
```

### Block C2 IP with pf

```bash
# State-changing: requires an approved pf workflow. Prefer MDM/EDR firewall controls where available.
echo 'block drop out to <IP>' | sudo pfctl -a ir -f -
sudo pfctl -e
```

## Cisco IOS / IOS-XE

### Capture context

```text
show clock
show users
show ip interface brief
show ip route
show logging | include LOGIN|SEC|AUTH|CONFIG|SYS
show running-config | include username|aaa|access-list|line vty|transport input
```

### Block hostile IP with ACL

```text
configure terminal
ip access-list extended IR-BLOCK-C2
 deny ip host <IP> any log
 permit ip any any
exit
interface <interface>
 ip access-group IR-BLOCK-C2 in
end
write memory
```

> Impact: applying ACLs can disrupt traffic. Validate interface direction and existing ACLs first.

### Disable compromised local user

```text
configure terminal
no username <username>
end
write memory
```

## Juniper Junos

### Capture context

```text
show system uptime
show system users
show interfaces terse
show route summary
show log messages | match "LOGIN|AUTH|UI|UI_CMDLINE"
show configuration system login
```

### Block hostile IP with firewall filter

```text
configure
set firewall family inet filter IR-BLOCK-C2 term block-c2 from source-address <IP>/32
set firewall family inet filter IR-BLOCK-C2 term block-c2 then discard
set firewall family inet filter IR-BLOCK-C2 term allow-rest then accept
set interfaces <interface> unit <unit> family inet filter input IR-BLOCK-C2
commit confirmed 5 comment "IR block C2 <IP>"
```

> Use `commit confirmed` so the change auto-rolls back if access is lost.

### Disable compromised local user

```text
configure
delete system login user <username>
commit confirmed 5 comment "IR disable compromised local user"
```
