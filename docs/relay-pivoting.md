# Relay Pivoting — When SSH Tunnels Aren't an Option

## When to Use Relays vs SSH Tunnels

| Situation | Use |
|-----------|-----|
| Pivot host has SSH and you can tunnel through it | `remote_tunnel` (SSH local/dynamic) |
| Pivot host has SSH but target only speaks non-SSH (SMB, WinRM) | `remote_tunnel(type="local")` to forward the port |
| Pivot host is Windows **without OpenSSH** | `remote_relay` (netsh portproxy) |
| Middle hop firewall blocks SSH but allows other ports | `remote_relay` (socat/ncat on allowed port) |
| Pivot host has no SSH server, only a shell via WinRM/other | `remote_relay` (native relay tools) |
| Need to reach a host two segments away | Chain: `remote_tunnel` + `remote_relay`, or relay + relay |

## The `remote_relay` Tool

Sets up a TCP port relay **on an existing session's host** using whatever native tools are available.

### Auto-detection

When `method="auto"` (default), the tool probes the pivot host for available tools and picks the best one:

**Priority order (Linux/macOS):**
1. `socat` — most robust, handles multiple connections, forks
2. `ncat` — reliable, handles `--sh-exec` for bidirectional relay
3. `nc` (OpenBSD) — works but requires fifo hack for bidirectional
4. `nc` (traditional) — same as OpenBSD variant with `-p` syntax
5. `bash /dev/tcp` — last resort, single connection only

**Priority order (Windows):**
1. `netsh portproxy` — always available, persistent across reboots
2. `ncat` — if installed (e.g., via nmap bundle)

### Basic Usage

```text
# Analyst harness cannot reach 10.10.20.5, but web01 can.
# web01 is already connected via remote_connect.

remote_relay(
  session="web01",
  target_host="10.10.20.5",
  target_port=22,
  listen_port=4422
)

# Now connect through the relay:
remote_connect(protocol="ssh", target="admin@10.10.10.5", port=4422, name="db01")
```

### Windows Pivot (WinRM session, no SSH)

```text
# dc01 is connected via WinRM. Internal host sql01 (10.10.30.10) is only reachable from dc01.

remote_relay(
  session="dc01",
  target_host="10.10.30.10",
  target_port=445,
  listen_port=44450,
  method="netsh-portproxy"
)

# From harness:
netexec smb 10.10.10.20 --port 44450 -u admin -H <hash>
```

### Chaining Relays

```text
# Harness → web01 (SSH) → dc01 (WinRM) → sql01 (SMB only)

# Step 1: SSH tunnel from harness through web01 to reach dc01's WinRM
remote_tunnel(type="local", via="root@web01", local_port=5985, remote_host="dc01", remote_port=5985)

# Step 2: Connect to dc01 via the tunnel
remote_connect(protocol="winrm", target="administrator@localhost", port=5985, name="dc01")

# Step 3: Relay from dc01 to sql01
remote_relay(session="dc01", target_host="10.10.30.10", target_port=445, listen_port=44450)

# Step 4: Access sql01 SMB through dc01's relay (via the SSH tunnel to dc01)
# Need another tunnel: harness → web01 → dc01:44450
remote_tunnel(type="local", via="root@web01", local_port=44450, remote_host="dc01", remote_port=44450)

# Now from harness: netexec smb localhost --port 44450 -u sa -H <hash>
```

### Cleanup

```text
# Close a specific relay
remote_relay_close(id="relay-1")

# Close all relays
remote_relay_close()
```

**Important:** Relays are processes running on remote hosts. If the harness shuts down without cleanup, relays persist on the pivot host. The shutdown handler logs orphaned relays so you know what to clean up manually.

## Method Reference

### socat (best for Linux)
```bash
socat TCP-LISTEN:4422,bind=0.0.0.0,fork,reuseaddr TCP:10.10.20.5:22 &
# Cleanup: pkill -f 'socat TCP-LISTEN:4422'
```
- ✅ Multiple simultaneous connections (fork)
- ✅ Bidirectional
- ✅ Backgrounded

### ncat (good cross-platform)
```bash
ncat -l 0.0.0.0 4422 --sh-exec 'ncat 10.10.20.5 22' &
# Cleanup: pkill -f 'ncat -l.*4422'
```
- ✅ Bidirectional per connection
- ✅ Handles multiple sequential connections
- ⚠️ Not always installed

### nc with fifo (fallback)
```bash
rm -f /tmp/.r4422 && mkfifo /tmp/.r4422
(nc -l 0.0.0.0 4422 < /tmp/.r4422 | nc 10.10.20.5 22 > /tmp/.r4422 &)
# Cleanup: pkill -f 'nc -l.*4422'; rm -f /tmp/.r4422
```
- ⚠️ Single connection only (must restart for next connection)
- ⚠️ Leaves a fifo artifact in /tmp

### netsh portproxy (Windows)
```powershell
netsh interface portproxy add v4tov4 listenport=4422 listenaddress=0.0.0.0 connectport=22 connectaddress=10.10.20.5
# Cleanup: netsh interface portproxy delete v4tov4 listenport=4422 listenaddress=0.0.0.0
# Verify: netsh interface portproxy show v4tov4
```
- ✅ Persistent (survives logoff)
- ✅ Multiple connections
- ✅ Always available on Windows
- ⚠️ Survives reboot — must explicitly clean up
- ⚠️ Requires admin privileges

### bash /dev/tcp (last resort)
```bash
# Single-connection only, limited reliability
bash -c 'exec 3<>/dev/tcp/10.10.20.5/22; cat <&3 & cat >&3'
```
- ❌ Single connection only
- ❌ No fork/backgrounding easily
- ✅ Zero dependencies beyond bash

## Decision Tree

```
Can the harness reach the target directly?
  YES → Just connect directly (remote_connect)
  NO ↓

Is there an SSH-capable pivot between harness and target?
  YES → Use remote_tunnel (local forward or dynamic SOCKS)
  NO ↓

Do you have a shell on an intermediate host that CAN reach the target?
  YES → Use remote_relay through that session
  NO ↓

Can you chain? (harness → SSH pivot → relay pivot → target)
  YES → remote_tunnel to reach relay host, then remote_relay from there
  NO → You need to find another path or introduce tooling (chisel, etc.)
```

## OPSEC Notes

- Relays leave processes and (for nc) fifo files on the pivot host
- `netsh portproxy` entries persist across sessions — always clean up
- All relay creation/teardown is audit-logged
- Prefer `socat` or `ncat` over fifo-based nc when available (cleaner, no artifacts)
- Consider using non-standard high ports (>40000) to avoid conflict with services
