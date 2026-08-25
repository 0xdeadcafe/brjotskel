# Relay Pivoting

A reference for reaching hosts that the harness cannot access directly.

## Decision tree

```
Can the harness reach the target directly?
  YES → remote_connect directly

  NO: Is there an SSH-capable pivot between the harness and the target?
    YES → remote_tunnel (local forward or dynamic SOCKS)

    NO: Do you have a shell on an intermediate host that can reach the target?
      YES → remote_relay through that session

      NO: Can you chain? (SSH pivot → relay pivot → target)
        YES → remote_tunnel to the relay host, then remote_relay from there

        NO → Find another authorized path
```

## When to use what

| Situation | Method |
|-----------|--------|
| Pivot has SSH; reach one specific service (WinRM, SMB, RDP) | `remote_tunnel(type="local")` |
| Pivot has SSH; route many tools through the pivot | `remote_tunnel(type="dynamic")` + proxychains |
| Pivot has SSH; multi-hop SSH chain | `remote_connect(proxy_jump="...")` or chained tunnels |
| Pivot is Windows without OpenSSH | `remote_relay(method="netsh-portproxy")` |
| Middle hop firewall blocks SSH but allows other ports | `remote_relay` on an allowed port |
| Pivot has only a WinRM or TCP shell | `remote_relay` (auto-detects available tools) |
| Two network segments away | Chain: `remote_tunnel` + `remote_relay`, or relay + relay |

`remote_tunnel` supports key auth (`identity=`), password auth (`password=` via sshpass), and SSH jump chains (`proxy_jump=`).

---

## remote_relay: native TCP relays

`remote_relay` sets up a TCP port relay **on an existing session's host** using whatever native tools are available. `method="auto"` (default) probes the pivot and picks the best available tool.

**Linux/macOS priority:** socat → ncat → nc (OpenBSD) → nc (traditional)

**Windows priority:** netsh portproxy → ncat

---

## Examples

### Basic: Linux pivot, unreachable target

```text
# Harness cannot reach 10.10.20.5. web01 (10.10.10.5) can.

remote_relay(
  session="web01",
  target_host="10.10.20.5",
  target_port=22,
  listen_port=4422
)

# SSH through the relay — connect to web01:4422, forwarded to 10.10.20.5:22
remote_connect(protocol="ssh", target="admin@10.10.10.5", port=4422, name="db01")
```

### Windows pivot — WinRM session, no SSH

```text
# dc01 connected via WinRM. sql01 (10.10.30.10) only reachable from dc01.

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

### Multi-hop chain: harness → SSH pivot → WinRM pivot → SMB target

```text
# Layout: harness → web01 (SSH, 10.10.10.5) → dc01 (WinRM, 10.10.20.10) → sql01 (SMB, 10.10.30.10)

# Step 1: SSH tunnel through web01 to expose dc01's WinRM to the harness
remote_tunnel(type="local", via="root@web01", local_port=5985,
  remote_host="dc01", remote_port=5985)

# Step 2: Connect to dc01 through the tunnel
remote_connect(protocol="winrm", target="administrator@localhost", port=5985, name="dc01")

# Step 3: Relay from dc01 to sql01
remote_relay(session="dc01", target_host="10.10.30.10", target_port=445, listen_port=44450)

# Step 4: Expose dc01's relay listener back to the harness via the existing SSH tunnel
remote_tunnel(type="local", via="root@web01", local_port=44450,
  remote_host="dc01", remote_port=44450)

# From harness:
netexec smb localhost --port 44450 -u sa -H <hash>
```

---

## Cleanup

Always clean up relays and tunnels when done. Both are tracked in `remote_sessions`.

```text
remote_relay_close(id="relay-1")     # close specific relay
remote_relay_close()                 # close all relays

remote_tunnel_close(id="tun-1")      # close specific tunnel
remote_tunnel_close()                # close all tunnels
```

**Relays persist on the remote host** if the container shuts down without cleanup. The shutdown handler logs orphaned relays. Clean them manually if needed:

```bash
# Linux — socat or ncat
pkill -f 'socat TCP-LISTEN:4422'
pkill -f 'ncat -l.*4422'
rm -f /tmp/.r4422    # nc fifo artifact, if present

# Windows
netsh interface portproxy delete v4tov4 listenport=44450 listenaddress=0.0.0.0
netsh interface portproxy show v4tov4    # verify cleared
```

---

## Method reference

### socat — best for Linux

```bash
socat TCP-LISTEN:4422,bind=0.0.0.0,fork,reuseaddr TCP:10.10.20.5:22 &
# Cleanup: pkill -f 'socat TCP-LISTEN:4422'
```

✅ Multiple simultaneous connections &nbsp; ✅ Bidirectional &nbsp; ✅ Backgrounds cleanly

### ncat — reliable cross-platform

```bash
ncat -l 0.0.0.0 4422 --sh-exec 'ncat 10.10.20.5 22' &
# Cleanup: pkill -f 'ncat -l.*4422'
```

✅ Bidirectional per connection &nbsp; ✅ Multiple sequential connections &nbsp; ⚠️ Not always installed

### nc with fifo — last resort

```bash
rm -f /tmp/.r4422 && mkfifo /tmp/.r4422
(nc -l 0.0.0.0 4422 < /tmp/.r4422 | nc 10.10.20.5 22 > /tmp/.r4422 &)
# Cleanup: pkill -f 'nc -l.*4422'; rm -f /tmp/.r4422
```

⚠️ Single connection only — relay must restart after each session &nbsp; ⚠️ Leaves a named pipe in `/tmp`

### netsh portproxy — Windows

```powershell
netsh interface portproxy add v4tov4 listenport=4422 listenaddress=0.0.0.0 connectport=22 connectaddress=10.10.20.5
# Cleanup: netsh interface portproxy delete v4tov4 listenport=4422 listenaddress=0.0.0.0
# Verify:  netsh interface portproxy show v4tov4
```

✅ Always available on Windows &nbsp; ✅ Multiple connections &nbsp; ✅ Survives logoff  
⚠️ **Persists across reboots** — highest cleanup priority on Windows pivots &nbsp; ⚠️ Requires admin

---

## OPSEC

- **All relay creation and teardown is audit-logged** in `logs/`
- `netsh portproxy` survives reboot — always verify removal, not just session teardown
- `nc` fifo leaves a named pipe in `/tmp` — always confirm cleanup
- Prefer socat or ncat over nc fifo (cleaner, no /tmp artifacts, multi-connection capable)
- Use high ports (>40000) to avoid colliding with running services
- Relays listen on `0.0.0.0` by default — use `listen_address` to restrict if the network allows it
- If in doubt, run `remote_sessions` to confirm what's still active before wrapping up
