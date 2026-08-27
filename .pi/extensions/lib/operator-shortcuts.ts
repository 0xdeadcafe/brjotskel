export type OperatorPlatform = "windows" | "linux" | "macos" | "network-device" | "unknown";

export interface OperatorSessionSummary {
  name: string;
  protocol: string;
  target: string;
  platform: OperatorPlatform;
  commandCount?: number;
}

export interface PursueCredentialSummary {
  id: string;
  type: string;
  username: string;
  domain?: string;
  keyFile?: string;
  status?: string;
  validOn?: string[];
}

export interface PursueHostSummary {
  id: string;
  ip?: string;
  hostname?: string;
  platform?: OperatorPlatform | string;
  role?: string;
  endpoints?: string[];
}

export interface PursueIntelSnapshot {
  unvalidatedCreds: PursueCredentialSummary[];
  activeCreds: PursueCredentialSummary[];
  knownHostIps: string[];
  knownHostIds: string[];
  knownHosts?: PursueHostSummary[];
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

function scriptPaths(platform: OperatorPlatform): { firstLook: string; network: string; persistence: string; credentials: string; ir: string; verify: string[]; collectEvidence: string; containKill: string; containBlock: string; containDisable: string; containIsolate: string; eradScripts: string[] } {
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
        collectEvidence: ".pi/skills/gather-playbooks/windows/collect-evidence.ps1",
        containKill: ".pi/skills/containment-playbooks/windows/kill-process.ps1",
        containBlock: ".pi/skills/containment-playbooks/windows/block-c2.ps1",
        containDisable: ".pi/skills/containment-playbooks/windows/disable-account.ps1",
        containIsolate: ".pi/skills/containment-playbooks/windows/isolate-host.ps1",
        eradScripts: [
          ".pi/skills/eradication-playbooks/windows/remove-scheduled-task.ps1",
          ".pi/skills/eradication-playbooks/windows/remove-service.ps1",
          ".pi/skills/eradication-playbooks/windows/remove-registry-run.ps1",
          ".pi/skills/eradication-playbooks/windows/remove-wmi-subscription.ps1",
        ],
      };
    case "macos":
      return {
        firstLook: ".pi/skills/gather-playbooks/macos/first-look.sh",
        network: ".pi/skills/gather-playbooks/macos/enum-network.sh",
        persistence: ".pi/skills/gather-playbooks/macos/enum-persistence.sh",
        credentials: ".pi/skills/gather-playbooks/macos/enum-credentials.sh",
        ir: ".pi/skills/host-ir-playbooks/macos/initial-assessment.sh",
        verify: [
          ".pi/skills/gather-playbooks/macos/first-look.sh",
          ".pi/skills/gather-playbooks/macos/enum-persistence.sh",
          ".pi/skills/host-ir-playbooks/macos/initial-assessment.sh",
        ],
        collectEvidence: ".pi/skills/gather-playbooks/macos/collect-evidence.sh",
        containKill: ".pi/skills/containment-playbooks/macos/kill-process.sh",
        containBlock: ".pi/skills/containment-playbooks/macos/block-c2.sh",
        containDisable: ".pi/skills/containment-playbooks/macos/disable-account.sh",
        containIsolate: ".pi/skills/containment-playbooks/macos/isolate-host.sh",
        eradScripts: [
          ".pi/skills/eradication-playbooks/macos/remove-launch-item.sh",
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
        collectEvidence: ".pi/skills/gather-playbooks/linux/collect-evidence.sh",
        containKill: ".pi/skills/containment-playbooks/linux/kill-process.sh",
        containBlock: ".pi/skills/containment-playbooks/linux/block-c2.sh",
        containDisable: ".pi/skills/containment-playbooks/linux/disable-account.sh",
        containIsolate: ".pi/skills/containment-playbooks/linux/isolate-host.sh",
        eradScripts: [
          ".pi/skills/eradication-playbooks/linux/remove-cron.sh",
          ".pi/skills/eradication-playbooks/linux/remove-systemd-unit.sh",
          ".pi/skills/eradication-playbooks/linux/remove-ssh-key.sh",
          ".pi/skills/eradication-playbooks/linux/remove-profile-hook.sh",
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
  const p = scriptPaths(session.platform);
  return `Prepare evidence-first containment for remote session "${session.name}". Step 1: read and run ${p.collectEvidence} to capture volatile state — save output to workspace/evidence/${session.name}/. Step 2: based on findings, run targeted containment using the appropriate script: kill-process (${p.containKill}), block-c2 (${p.containBlock}), disable-account (${p.containDisable}), or isolate (${p.containIsolate}). Read each script first — they are parameterised. Step 3: verify each action. Do not execute disruptive commands without explicit operator confirmation.`;
}

export function buildEradicatePrompt(session: OperatorSessionSummary): string {
  const p = scriptPaths(session.platform);
  return `Prepare evidence-backed eradication for remote session "${session.name}". For each confirmed persistence mechanism, use the appropriate eradication script: ${p.eradScripts.join(", ")}. Read each script — they are parameterised and require explicit values. Each script: captures evidence, removes the artifact, and verifies removal. Do not execute without confirming the target artifact matches attacker persistence. After removal, re-run ${p.verify[0]} and ${p.verify[1]} to confirm clean state.`;
}

export function buildVerifyPrompt(session: OperatorSessionSummary): string {
  const p = scriptPaths(session.platform);
  return `Verify remote session "${session.name}" after containment/eradication. Re-run ${p.verify.join(", ")} as appropriate, check no suspicious listeners/reconnections/persistence remain, and summarize residual risk.`;
}

export function buildPursuePrompt(): string {
  return "Call intel_map() to render the attack graph, then intel_query(query_type='all_credentials') to list all credentials. For each active or unvalidated credential call intel_get_cred to retrieve the secret and generate the correct netexec validation command against all known host IPs. Update valid_on with intel_update for every confirmed hit. Do not generate a report — produce the chase board and execute it.";
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

export function formatPursueShortcut(sessions: OperatorSessionSummary[], intel?: PursueIntelSnapshot | null): string {
  const header = sessionHeader("pursue", undefined, sessions);
  const lines: string[] = [header, ""];

  // Live chase board from intel store
  if (intel && (intel.unvalidatedCreds.length > 0 || intel.activeCreds.length > 0)) {
    const hostList = intel.knownHostIps.length > 0 ? intel.knownHostIps.join(",") : "<host-ip>";

    if (intel.unvalidatedCreds.length > 0) {
      lines.push(`UNVALIDATED CREDENTIALS (${intel.unvalidatedCreds.length}) — validate against known hosts:`);
      for (const c of intel.unvalidatedCreds) {
        const cmds = credValidationCmds(c.type, c.username, c.id, hostList, c.keyFile);
        lines.push(`  [${c.type}] ${c.id} / ${c.username}`);
        lines.push(`    intel_get_cred(id="${c.id}")`);
        for (const cmd of cmds) lines.push(`    ${cmd}`);
        lines.push(`    intel_update(category="credential", id="${c.id}", fields="valid_on:\\n  - <host-id>", summary="${c.id} confirmed on <host>"`);
      }
      lines.push("");
    }

    if (intel.activeCreds.length > 0) {
      lines.push(`CONFIRMED / ACTIVE CREDENTIALS (${intel.activeCreds.length}) — expand blast radius:`);
      for (const c of intel.activeCreds) {
        const cmds = credValidationCmds(c.type, c.username, c.id, hostList, c.keyFile);
        const validOn = (c.validOn || []).length > 0 ? ` valid_on=${(c.validOn || []).join(",")}` : "";
        lines.push(`  [${c.type}] ${c.id} / ${c.username}${validOn}`);
        lines.push(`    intel_get_cred(id="${c.id}")`);
        for (const cmd of cmds) lines.push(`    ${cmd}`);
        for (const dumpCmd of secretsDumpCmds(c, intel)) lines.push(`    ${dumpCmd}`);
      }
      lines.push("");
    }

    if (intel.knownHostIps.length > 0) {
      lines.push(`Known hosts: ${intel.knownHostIds.join("  ")}`);
      lines.push(`Known IPs:   ${intel.knownHostIps.join("  ")}`);
      lines.push("");
    }
  } else if (intel) {
    lines.push("No unvalidated credentials. Run gather credential playbooks to recover material.");
    lines.push("");
  }

  // Static fallback / manual commands
  lines.push("Manual commands:");
  lines.push("  intel_map()  — attack graph");
  lines.push("  intel_query(query_type=\"all_credentials\")  — all creds");
  lines.push("  intel_get_cred(id=\"<id>\")  — retrieve secret");
  lines.push("  netexec smb/ssh/winrm <range> -u <user> -H <hash>  — validate");
  lines.push("  bin/netexec-to-intel --cred-id <id> --input <netexec-output>  — convert hits to valid_on update");
  lines.push("  remote_tunnel / remote_relay / remote_connect  — pivot");
  lines.push("  intel_update(valid_on / new host / pivot path / account)");

  return lines.join("\n");
}

export function credValidationCmds(type: string, username: string, id: string, hostList: string, keyFile?: string): string[] {
  switch (type) {
    case "ntlm-hash": {
      const hash = `<hash from intel_get_cred(id="${id}")>`;
      return [
        `netexec smb ${hostList} -u ${username} -H ${hash} --no-bruteforce`,
        `netexec winrm ${hostList} -u ${username} -H ${hash} --no-bruteforce`,
        `netexec ssh ${hostList} -u ${username} -H ${hash} --no-bruteforce`,
      ];
    }
    case "password": {
      const password = `'<password from intel_get_cred(id="${id}")>'`;
      return [
        `netexec smb ${hostList} -u ${username} -p ${password} --no-bruteforce`,
        `netexec winrm ${hostList} -u ${username} -p ${password} --no-bruteforce`,
        `netexec ssh ${hostList} -u ${username} -p ${password} --no-bruteforce`,
      ];
    }
    case "ssh-key":
    case "private-key":{
      const kf = keyFile ? `<key_file from intel_get_cred(id="${id}")>` : `<key_file from intel_get_cred(id="${id}")>`;
      return [`netexec ssh ${hostList} -u ${username} --key-file ${kf}`];
    }
    case "kerberos-tgt":
    case "kerberos-tgs":
      return [`netexec smb ${hostList} -u ${username} --use-kcache  # set KRB5CCNAME first`];
    case "token":
    case "api-key":
      return [`# token type — validate manually based on service`];
    default:
      return [`netexec smb ${hostList} -u ${username} -p '<secret from intel_get_cred(id="${id}")>'`];
  }
}

function secretsDumpCmds(cred: PursueCredentialSummary, intel: PursueIntelSnapshot): string[] {
  if (cred.type !== "ntlm-hash" || !cred.validOn || cred.validOn.length === 0) return [];

  const hosts: PursueHostSummary[] = intel.knownHosts || intel.knownHostIds.map((id, idx) => ({ id, ip: intel.knownHostIps[idx] }));
  const targets: string[] = [];
  const seen = new Set<string>();

  for (const validTarget of cred.validOn) {
    const host = hosts.find(h => h.id === validTarget || h.ip === validTarget || h.hostname === validTarget);
    if (!host || !isWindowsHost(host) || !host.ip || seen.has(host.ip)) continue;
    seen.add(host.ip);
    const account = `${cred.domain || "<domain>"}/${cred.username || "<user>"}`;
    targets.push(`secretsdump.py ${account} -hashes :<hash from intel_get_cred(id="${cred.id}")> @${host.ip}  # NTDS dump if target is DC (${host.id})`);
  }

  return targets;
}

function isWindowsHost(host: PursueHostSummary): boolean {
  if (String(host.platform || "").toLowerCase() === "windows") return true;
  const endpoints = host.endpoints || [];
  return endpoints.some(endpoint => /:(445|3389|5985|5986)(?:\D|$)/.test(String(endpoint)));
}

export function formatContainShortcut(session: OperatorSessionSummary | undefined, sessions: OperatorSessionSummary[]): string {
  if (!session) return `${sessionHeader("contain", undefined, sessions)}\nUsage: /contain <session> [--prompt]`;
  const p = scriptPaths(session.platform);
  return [
    sessionHeader("contain", session),
    "⚠️  EVIDENCE FIRST — run collect-evidence before any action:",
    `   Read ${p.collectEvidence}`,
    `   ${runPlaybookPrompt(session.name, p.collectEvidence)}`,
    "   Save output → workspace/evidence/" + session.name + "/volatile-<ts>.txt",
    "",
    "Containment scripts (read, set params, run inline):",
    `   Kill process:    ${p.containKill}  (TARGET_PID=<pid>)`,
    `   Block C2:        ${p.containBlock}  (C2_IP=<ip>)`,
    `   Disable account: ${p.containDisable}  (TARGET_USER=<user>)`,
    `   Isolate host:    ${p.containIsolate}  (ANALYST_IP=<your-ip>)`,
    "",
    "After action — record:",
    "   intel_update(category=\"host\", id=\"<host>\", fields=\"status: contained\\nnotes: ...\", summary=\"...\")",
  ].join("\n");
}

export function formatEradicateShortcut(session: OperatorSessionSummary | undefined, sessions: OperatorSessionSummary[]): string {
  if (!session) return `${sessionHeader("eradicate", undefined, sessions)}\nUsage: /eradicate <session> [--prompt]`;
  const p = scriptPaths(session.platform);
  return [
    sessionHeader("eradicate", session),
    "Evidence-backed eradication scripts (read, set params, run inline):",
    ...p.eradScripts.map(s => `   ${s}`),
    "",
    "Pattern for each: EVIDENCE → REMOVE → VERIFY → RECORD",
    "Each script: exports artifact evidence, removes, verifies removal, emits intel_timeline snippet.",
    "",
    "After each removal — re-run persistence check:",
    `   ${p.verify[1]}`,
    "",
    "After all removals — re-run first-look:",
    `   ${p.verify[0]}`,
    "",
    "Mark clean:",
    "   intel_update(category=\"host\", id=\"<host>\", fields=\"status: eradicated\\nnotes: ...\", summary=\"...\")",
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
