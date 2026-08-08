export type OperatorPlatform = "windows" | "linux" | "macos" | "network-device" | "unknown";

export interface OperatorSessionSummary {
  name: string;
  protocol: string;
  target: string;
  platform: OperatorPlatform;
  commandCount?: number;
}

export interface ShortcutArgs {
  sessionName?: string;
  prompt: boolean;
  help: boolean;
}

export function parseShortcutArgs(args?: string): ShortcutArgs {
  const tokens = (args || "").trim().split(/\s+/).filter(Boolean);
  const flags = new Set(tokens.filter(t => t.startsWith("--")));
  const sessionName = tokens.find(t => !t.startsWith("--"));
  return {
    sessionName,
    prompt: flags.has("--prompt") || flags.has("--stage"),
    help: flags.has("--help") || flags.has("-h"),
  };
}

function activeSessionLine(sessions: OperatorSessionSummary[]): string {
  if (sessions.length === 0) return "Active sessions: none";
  return `Active sessions: ${sessions.map(s => `${s.name}(${s.platform}/${s.protocol})`).join(", ")}`;
}

function sessionHeader(phase: string, session?: OperatorSessionSummary, sessions: OperatorSessionSummary[] = []): string {
  if (session) {
    return `=== ${phase.toUpperCase()} — ${session.name} (${session.platform}/${session.protocol} → ${session.target}) ===`;
  }
  return `=== ${phase.toUpperCase()} ===\n${activeSessionLine(sessions)}`;
}

function scriptPaths(platform: OperatorPlatform): { firstLook: string; network: string; persistence: string; credentials: string; ir: string; verify: string[] } {
  switch (platform) {
    case "windows":
      return {
        firstLook: ".pi/skills/gather-playbooks/windows/first-look.ps1",
        network: ".pi/skills/gather-playbooks/windows/enum-network.ps1",
        persistence: ".pi/skills/gather-playbooks/windows/enum-persistence.ps1",
        credentials: ".pi/skills/gather-playbooks/windows/enum-credentials.ps1",
        ir: ".pi/skills/host-ir-playbooks/windows/initial-assessment.ps1",
        verify: [
          ".pi/skills/gather-playbooks/windows/first-look.ps1",
          ".pi/skills/host-ir-playbooks/windows/persistence-hunt.ps1",
          ".pi/skills/host-ir-playbooks/windows/eventlog-hunt-lite.ps1",
        ],
      };
    case "macos":
      return {
        firstLook: ".pi/skills/gather-playbooks/macos/first-look.sh",
        network: ".pi/skills/gather-playbooks/macos/enum-network.sh",
        persistence: ".pi/skills/gather-playbooks/macos/enum-persistence.sh",
        credentials: ".pi/skills/gather-playbooks/macos/enum-credentials.sh",
        ir: ".pi/skills/host-ir-playbooks/macos/live-response.sh",
        verify: [
          ".pi/skills/gather-playbooks/macos/first-look.sh",
          ".pi/skills/gather-playbooks/macos/enum-persistence.sh",
          ".pi/skills/host-ir-playbooks/macos/live-response.sh",
        ],
      };
    case "linux":
    default:
      return {
        firstLook: ".pi/skills/gather-playbooks/linux/first-look.sh",
        network: ".pi/skills/gather-playbooks/linux/enum-network.sh",
        persistence: ".pi/skills/gather-playbooks/linux/enum-persistence.sh",
        credentials: ".pi/skills/gather-playbooks/linux/enum-credentials.sh",
        ir: ".pi/skills/host-ir-playbooks/linux/initial-assessment.sh",
        verify: [
          ".pi/skills/gather-playbooks/linux/first-look.sh",
          ".pi/skills/gather-playbooks/linux/enum-persistence.sh",
          ".pi/skills/gather-playbooks/linux/enum-network.sh",
        ],
      };
  }
}

function runPlaybookPrompt(sessionName: string, path: string): string {
  return `Read ${path}, then run it inline on remote session "${sessionName}" with remote_exec. Keep the result concise and call out high-signal findings.`;
}

export function buildAssessPrompt(session: OperatorSessionSummary): string {
  const p = scriptPaths(session.platform);
  return `${runPlaybookPrompt(session.name, p.firstLook)} If first-look shows active compromise, follow with ${p.network} and ${p.persistence}. Record discovered hosts, credentials, pivots, and compromised accounts with intel_add as you go.`;
}

export function buildContainPrompt(session: OperatorSessionSummary): string {
  return `Prepare evidence-first containment options for remote session "${session.name}". First capture process/network/session state, then propose the minimal commands to stop a malicious process, block a C2 IP, disable a task/service/user, or isolate networking. Do not execute disruptive commands without explicit confirmation.`;
}

export function buildEradicatePrompt(session: OperatorSessionSummary): string {
  return `Prepare eradication steps for remote session "${session.name}". Identify persistence evidence first, propose removal/disable commands with rollback notes, and verify removal. Do not execute destructive changes without explicit confirmation.`;
}

export function buildVerifyPrompt(session: OperatorSessionSummary): string {
  const p = scriptPaths(session.platform);
  return `Verify remote session "${session.name}" after containment/eradication. Re-run ${p.verify.join(", ")} as appropriate, check no suspicious listeners/reconnections/persistence remain, and summarize residual risk.`;
}

export function buildPursuePrompt(): string {
  return "Use intel_summary plus intel_query(all_hosts/all_credentials/all_pivots) to build a concise pursuit board: credentials not validated, suspected hosts not assessed, active pivot paths, and the next 3 highest-value moves. Do not generate a report.";
}

export function formatLandShortcut(sessions: OperatorSessionSummary[]): string {
  return [
    sessionHeader("land", undefined, sessions),
    "Fast landing primitives:",
    "1. Check known access before connecting:",
    "   intel_query(query_type=\"for_host\", target=\"<host-id>\")",
    "2. SSH / WinRM:",
    "   remote_connect(protocol=\"ssh\", target=\"user@host\", name=\"host01\", password=\"...\")",
    "   remote_connect(protocol=\"winrm\", target=\"administrator@host\", name=\"dc01\", password=\"...\")",
    "3. If direct path fails, pivot:",
    "   remote_tunnel(type=\"local\", via=\"user@pivot\", local_port=2222, remote_host=\"internal\", remote_port=22)",
    "   remote_relay(session=\"pivot-session\", target_host=\"internal\", target_port=445, listen_port=44450)",
    "4. Immediately after landing:",
    "   /assess <session>",
  ].join("\n");
}

export function formatAssessShortcut(session: OperatorSessionSummary | undefined, sessions: OperatorSessionSummary[]): string {
  if (!session) {
    return [
      sessionHeader("assess", undefined, sessions),
      "Usage: /assess <session> [--prompt]",
      "Purpose: first-look + high-signal follow-up commands without a case/report workflow.",
    ].join("\n");
  }
  const p = scriptPaths(session.platform);
  return [
    sessionHeader("assess", session),
    "Fast path:",
    `1. First-look: ${p.firstLook}`,
    `   ${runPlaybookPrompt(session.name, p.firstLook)}`,
    "2. If suspicious connections/listeners: ",
    `   ${runPlaybookPrompt(session.name, p.network)}`,
    "3. If persistence suspected:",
    `   ${runPlaybookPrompt(session.name, p.persistence)}`,
    "4. If host role/compromise is unclear:",
    `   ${runPlaybookPrompt(session.name, p.ir)}`,
    "5. Save only high-signal findings as you move:",
    "   intel_add(category=\"host|credential|account|pivot\", ...)",
  ].join("\n");
}

export function formatPursueShortcut(sessions: OperatorSessionSummary[]): string {
  return [
    sessionHeader("pursue", undefined, sessions),
    "Chase board commands:",
    "1. Current map:",
    "   intel_summary()",
    "   intel_query(query_type=\"all_hosts\")",
    "   intel_query(query_type=\"all_credentials\")",
    "   intel_query(query_type=\"all_pivots\")",
    "2. Pull material for an access path:",
    "   intel_get_cred(id=\"<credential-id>\")",
    "   intel_query(query_type=\"for_host\", target=\"<host-id>\")",
    "3. Validate/pivot manually from the harness:",
    "   netexec smb <target/range> -u <user> -H <hash>",
    "   remote_tunnel(...) / remote_relay(...) / remote_connect(...) ",
    "4. Record only new truths:",
    "   credential valid_on, new host, pivot path, compromised account, containment/eradication timeline event",
  ].join("\n");
}

export function formatContainShortcut(session: OperatorSessionSummary | undefined, sessions: OperatorSessionSummary[]): string {
  if (!session) return `${sessionHeader("contain", undefined, sessions)}\nUsage: /contain <session> [--prompt]`;
  const windows = session.platform === "windows";
  return [
    sessionHeader("contain", session),
    "Evidence-first containment pack (do not auto-run blindly):",
    windows
      ? "1. Snapshot: Get-Process | Sort CPU -Desc | Select -First 30; Get-NetTCPConnection -State Established,Listen"
      : "1. Snapshot: ps auxfww --sort=-%cpu | head -40; ss -tunap || netstat -tunap",
    windows
      ? "2. Kill process: Stop-Process -Id <pid> -Force; verify with Get-Process -Id <pid>"
      : "2. Kill process: kill -TERM <pid>; sleep 2; kill -0 <pid> || echo stopped",
    windows
      ? "3. Block C2: New-NetFirewallRule -DisplayName 'IR Block C2 <ip>' -Direction Outbound -RemoteAddress <ip> -Action Block"
      : "3. Block C2: iptables -I OUTPUT -d <ip> -j DROP  # or nft equivalent",
    windows
      ? "4. Disable persistence temporarily: Disable-ScheduledTask / Stop-Service + Set-Service -StartupType Disabled"
      : "4. Disable persistence temporarily: systemctl stop/disable <unit>, comment cron, or move authorized_keys after copying evidence",
    "5. Record action: intel_timeline(action=\"add\", entry_type=\"containment\", entry_action=\"contained\", ...)",
  ].join("\n");
}

export function formatEradicateShortcut(session: OperatorSessionSummary | undefined, sessions: OperatorSessionSummary[]): string {
  if (!session) return `${sessionHeader("eradicate", undefined, sessions)}\nUsage: /eradicate <session> [--prompt]`;
  const windows = session.platform === "windows";
  return [
    sessionHeader("eradicate", session),
    "Evidence-backed removal pack:",
    windows
      ? "1. Reconfirm persistence: scheduled tasks, services, Run keys, WMI subscriptions, startup folders"
      : "1. Reconfirm persistence: cron, systemd units/timers, shell profiles, SSH keys, rc.local, launchd on macOS",
    "2. Preserve minimal evidence: path, owner, timestamps, hashes, config/value contents",
    windows
      ? "3. Remove/disable: Unregister-ScheduledTask, sc.exe delete, Remove-ItemProperty, Remove-CimInstance for WMI bindings"
      : "3. Remove/disable: rm/quarantine artifact, systemctl disable/mask, crontab edit, remove rogue authorized_keys entry",
    "4. Verify persistence did not recreate; watch for reconnect/listener/process return",
    "5. Record action: intel_timeline(action=\"add\", entry_type=\"eradication\", entry_action=\"eradicated\", ...)",
  ].join("\n");
}

export function formatVerifyShortcut(session: OperatorSessionSummary | undefined, sessions: OperatorSessionSummary[]): string {
  if (!session) return `${sessionHeader("verify", undefined, sessions)}\nUsage: /verify <session> [--prompt]`;
  const p = scriptPaths(session.platform);
  return [
    sessionHeader("verify", session),
    "Post-action verification:",
    `1. Re-run first-look: ${p.verify[0]}`,
    `2. Re-check persistence: ${p.verify[1]}`,
    `3. Re-check host/network activity: ${p.verify[2]}`,
    "4. Validate no suspicious session/process/listener/C2 reconnection remains",
    "5. Confirm credential lifecycle items: intel_query(query_type=\"all_credentials\") then mark rotations in timeline",
  ].join("\n");
}
