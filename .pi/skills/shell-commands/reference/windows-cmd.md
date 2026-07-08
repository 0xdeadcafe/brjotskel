# Windows CMD — Security Investigation & Incident Response Commands

> Sources: Blue Team Field Manual, RTFM v3, Ridgeline Cyber Windows Forensic Commands, RomelSan Windows Forensics Gist

---

## System Information & Triage

```cmd
:: System information
systeminfo
hostname
ver

:: OS version and build
wmic os get Caption, Version, BuildNumber, OSArchitecture

:: Uptime
net statistics server | find "since"

:: Environment variables
set

:: Installed patches
wmic qfe list brief /format:table

:: Installed software
wmic product get name, version, vendor /format:table
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr "DisplayName DisplayVersion"
```

## Process Investigation

```cmd
:: List all processes
tasklist /v
tasklist /svc

:: Process with full command line
wmic process get ProcessId, ParentProcessId, Name, CommandLine, CreationDate /format:list

:: Find specific process
tasklist /fi "imagename eq powershell.exe"
tasklist /fi "imagename eq cmd.exe"

:: Process to PID mapping with services
tasklist /svc /fi "services ne N/A"

:: Processes with DLLs loaded
tasklist /m

:: Specific DLL loaded by processes
tasklist /m ntdll.dll

:: Process tree (parent-child)
wmic process get processid, parentprocessid, name, executablepath /format:csv

:: Find process by network connection
netstat -ano | findstr "ESTABLISHED"
:: Then: tasklist /fi "pid eq <PID>"

:: Kill suspicious process
taskkill /PID <pid> /F
```

## Network Investigation

```cmd
:: Active connections with PIDs
netstat -ano
netstat -anob

:: Established connections only
netstat -ano | findstr "ESTABLISHED"

:: Listening ports
netstat -ano | findstr "LISTENING"

:: DNS cache
ipconfig /displaydns

:: ARP table
arp -a

:: Route table
route print

:: Network interfaces
ipconfig /all

:: Network shares (local)
net share

:: Mapped network drives
net use

:: Connected sessions to this host
net session

:: Open files on shares
net file

:: Firewall status
netsh advfirewall show allprofiles

:: Firewall rules
netsh advfirewall firewall show rule name=all

:: Flush DNS cache
ipconfig /flushdns

:: NSLookup
nslookup <domain>

:: Traceroute
tracert <host>

:: Wi-Fi profiles
netsh wlan show profiles
netsh wlan show profile name="<SSID>" key=clear

:: Hosts file check
type C:\Windows\System32\drivers\etc\hosts
```

## User & Account Investigation

```cmd
:: Local users
net user

:: Detailed user info
net user <username>

:: Local administrators
net localgroup Administrators

:: All local groups
net localgroup

:: Domain users (if domain-joined)
net user /domain

:: Currently logged on
query user
whoami /all

:: Logged on sessions
qwinsta

:: Recently created accounts
wmic useraccount get name, sid, status, disabled, passwordchanged

:: Account policy
net accounts
```

## Persistence Mechanisms

```cmd
:: Scheduled tasks
schtasks /query /fo TABLE /v
schtasks /query /fo LIST | findstr /i "taskname task_to_run"

:: Startup entries (Run keys)
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"

:: Services
sc query state= all
wmic service get name, displayname, state, startmode, pathname /format:table

:: Services with unusual paths
wmic service where "not PathName like '%%System32%%'" get Name, PathName, State, StartMode

:: Startup folder contents
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

:: Auto-start programs
wmic startup get caption, command, user

:: BITSAdmin jobs (persistence mechanism)
bitsadmin /list /allusers /verbose

:: DLL search order hijacking check
:: Look for DLLs in writable paths that shadow System32
dir /s /b C:\Users\*.dll 2>nul
dir /s /b C:\ProgramData\*.dll 2>nul
```

## File System Investigation

```cmd
:: Find recently modified files (last 1 day)
forfiles /P C:\ /S /D +0 /C "cmd /c echo @path @fdate @ftime" 2>nul

:: Find executables in temp directories
dir /s /b "%TEMP%\*.exe" "%TEMP%\*.dll" "%TEMP%\*.ps1" "%TEMP%\*.bat" "%TEMP%\*.vbs" 2>nul
dir /s /b "%APPDATA%\*.exe" "%APPDATA%\*.dll" 2>nul

:: Directory listing with timestamps
dir /a /o-d /t:w C:\Windows\Temp

:: Hidden files
dir /a:h C:\Users\<username> /s

:: Alternate Data Streams
dir /r C:\Users\<username>

:: File hashes (certutil)
certutil -hashfile <file> SHA256
certutil -hashfile <file> MD5

:: Find files by extension
dir /s /b C:\*.ps1
dir /s /b C:\*.vbs
dir /s /b C:\*.hta

:: Prefetch files
dir C:\Windows\Prefetch\*.pf /o-d

:: Recent items
dir "%APPDATA%\Microsoft\Windows\Recent" /o-d

:: Find large files (possible staging)
forfiles /P C:\ /S /M *.* /C "cmd /c if @fsize GEQ 104857600 echo @path @fsize" 2>nul

:: Recycle bin (admin)
dir /s /a C:\$Recycle.Bin
```

## Event Log Analysis

```cmd
:: List available logs
wevtutil el

:: Query security log (recent logons)
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /c:20 /f:text /rd:true

:: Failed logons
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:20 /f:text /rd:true

:: New service installed
wevtutil qe System /q:"*[System[(EventID=7045)]]" /c:10 /f:text /rd:true

:: PowerShell script blocks
wevtutil qe "Microsoft-Windows-PowerShell/Operational" /q:"*[System[(EventID=4104)]]" /c:10 /f:text /rd:true

:: Log clearing events
wevtutil qe Security /q:"*[System[(EventID=1102)]]" /f:text /rd:true

:: Export log
wevtutil epl Security C:\evidence\security.evtx

:: Process creation (4688)
wevtutil qe Security /q:"*[System[(EventID=4688)]]" /c:20 /f:text /rd:true

:: Account created (4720)
wevtutil qe Security /q:"*[System[(EventID=4720)]]" /c:10 /f:text /rd:true

:: Scheduled task created (4698)
wevtutil qe Security /q:"*[System[(EventID=4698)]]" /c:10 /f:text /rd:true

:: Clear specific log (use with caution — document before clearing!)
:: wevtutil cl Security
```

## Registry Forensics

```cmd
:: Winlogon (shell, userinit)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

:: Image File Execution Options (debugger hijack)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s | findstr "Debugger"

:: AppInit_DLLs
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs

:: Security packages (credential interception)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages"

:: USB history
reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" /s

:: TypedURLs (IE/Edge URL history)
reg query "HKCU\Software\Microsoft\Internet Explorer\TypedURLs"

:: MRU (Most Recently Used) lists
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /s
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

:: Network connections history
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" /s
```

## Credential & Authentication

```cmd
:: Cached credentials
cmdkey /list

:: Kerberos tickets
klist

:: LSA secrets location
reg query "HKLM\SECURITY\Policy\Secrets" /s 2>nul

:: SAM hive location
reg query "HKLM\SAM\SAM\Domains\Account\Users" 2>nul

:: Credential vault
vaultcmd /list
vaultcmd /listcreds:"Windows Credentials"

:: NTLM settings
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel
```

## Remote Execution & Lateral Movement

```cmd
:: PsExec connections (look for service installs)
wevtutil qe System /q:"*[System[(EventID=7045)]] and *[EventData[Data='PSEXESVC']]" /f:text

:: Remote desktop sessions
qwinsta /server:<host>

:: Admin shares accessible
net view \\<host>
dir \\<host>\c$ 2>nul

:: WMI execution (remote)
wmic /node:<host> process list brief

:: At jobs (legacy)
at

:: Open handles to remote files
openfiles /query

:: Net sessions (inbound connections)
net session

:: Named pipes
dir \\.\pipe\
```

## Data Collection

```cmd
:: Create evidence directory
mkdir C:\evidence

:: Copy key files for analysis
copy C:\Windows\System32\config\SAM C:\evidence\SAM 2>nul
copy C:\Windows\System32\config\SYSTEM C:\evidence\SYSTEM 2>nul
copy C:\Windows\System32\config\SECURITY C:\evidence\SECURITY 2>nul

:: Export registry hives
reg save HKLM\SYSTEM C:\evidence\system.hiv
reg save HKLM\SAM C:\evidence\sam.hiv
reg save HKLM\SECURITY C:\evidence\security.hiv

:: Memory dump (using built-in — limited)
:: For full memory dump, use tools like winpmem, DumpIt, or Magnet RAM Capture

:: Collect prefetch
xcopy C:\Windows\Prefetch\*.pf C:\evidence\prefetch\ /Y

:: Collect event logs
xcopy C:\Windows\System32\winevt\Logs\*.evtx C:\evidence\logs\ /Y
```
