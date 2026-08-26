import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { parseYaml } from "./simple-yaml.ts";
import { resolveIntelDir } from "./intel-helpers.ts";
import { buildIntelMap } from "./intel-store-core.ts";
import { killTrackedProcess, type RemoteSession, type TunnelInfo, type RelayInfo } from "./remote-types.ts";
import {
  parseShortcutArgs,
  formatLandShortcut,
  formatAssessShortcut,
  formatPursueShortcut,
  formatContainShortcut,
  formatEradicateShortcut,
  formatVerifyShortcut,
  buildAssessPrompt,
  buildPursuePrompt,
  buildContainPrompt,
  buildEradicatePrompt,
  buildVerifyPrompt,
  type OperatorSessionSummary,
  type PursueIntelSnapshot,
} from "./operator-shortcuts.ts";

export interface RawIntelSnapshot {
  hosts: Record<string, any>;
  credentials: Record<string, any>;
  accounts: Record<string, any>;
  pivots: Record<string, any>;
  timeline: any[];
}

export interface IntelSnapshotBundle {
  pursue: PursueIntelSnapshot | null;
  raw: RawIntelSnapshot | null;
}

export interface RemoteSlashCommandDeps {
  sessions: Map<string, RemoteSession>;
  activeTunnels: TunnelInfo[];
  activeRelays: RelayInfo[];
  getDefaultSessionName: () => string | null;
  setDefaultSessionName: (name: string | null) => void;
  log: (sessionName: string, direction: ">>>" | "<<<" | "---", content: string) => void;
}

const INACTIVE_CREDENTIAL_STATUSES = new Set(["rotated", "expired", "revoked", "disabled", "inactive", "invalid"]);

export function readIntelSnapshot(cwd = process.cwd(), env: NodeJS.ProcessEnv = process.env): IntelSnapshotBundle {
  try {
    const intelDir = resolveIntelDir(cwd, env.BRJOTSKEL_INTEL_DIR);
    if (!existsSync(intelDir)) return { pursue: null, raw: null };
    const read = (file: string): any => {
      const p = join(intelDir, file);
      if (!existsSync(p)) return {};
      try { return parseYaml(readFileSync(p, "utf8")) ?? {}; } catch { return {}; }
    };
    const hosts       = read("hosts.yaml").hosts       ?? {};
    const credentials = read("credentials.yaml").credentials ?? {};
    const accounts    = read("accounts.yaml").accounts    ?? {};
    const pivots      = read("pivots.yaml").paths         ?? {};
    const timeline    = read("timeline.yaml").timeline    ?? [];
    const credentialSummary = ([id, c]: [string, any]) => ({
      id,
      type: c.type || "unknown",
      username: c.username || "",
      domain: c.domain,
      keyFile: c.key_file,
      status: c.status,
      validOn: Array.isArray(c.valid_on) ? c.valid_on : [],
    });
    const unvalidatedCreds = Object.entries(credentials)
      .filter(([_, c]: [string, any]) => !INACTIVE_CREDENTIAL_STATUSES.has(c.status ?? ""))
      .filter(([_, c]: [string, any]) => !c.valid_on || (c.valid_on as string[]).length === 0)
      .map(credentialSummary);
    const activeCreds = Object.entries(credentials)
      .filter(([_, c]: [string, any]) => !INACTIVE_CREDENTIAL_STATUSES.has(c.status ?? ""))
      .filter(([_, c]: [string, any]) => Array.isArray(c.valid_on) && (c.valid_on as string[]).length > 0)
      .map(credentialSummary);
    const knownHosts = Object.entries(hosts).map(([id, h]: [string, any]) => ({
      id,
      ip: h.ip,
      hostname: h.hostname,
      platform: h.platform,
      role: h.role,
      endpoints: Array.isArray(h.endpoints) ? h.endpoints : [],
    }));
    const knownHostIps = knownHosts.map((h: any) => h.ip).filter(Boolean) as string[];
    const knownHostIds = knownHosts.map((h: any) => h.id);
    return { pursue: { unvalidatedCreds, activeCreds, knownHostIps, knownHostIds, knownHosts }, raw: { hosts, credentials, accounts, pivots, timeline } };
  } catch {
    return { pursue: null, raw: null };
  }
}

export function operatorSessionSummaries(sessions: Map<string, RemoteSession>): OperatorSessionSummary[] {
  return [...sessions.values()].map(session => ({
    name: session.info.name,
    protocol: session.info.protocol,
    target: session.info.target,
    platform: session.info.platform,
    commandCount: session.info.commandCount,
  }));
}

export function buildScopeText(
  sessions: Map<string, RemoteSession>,
  activeTunnels: TunnelInfo[],
  activeRelays: RelayInfo[],
  defaultSessionName: string | null,
  raw: RawIntelSnapshot | null,
): string {
  const lines: string[] = ["=== SCOPE ===", ""];

  if (sessions.size === 0) {
    lines.push("Sessions: none");
  } else {
    lines.push(`Sessions (${sessions.size}):`);
    for (const [name, s] of sessions) {
      const isDefault = name === defaultSessionName ? " *" : "";
      const taint = s.tainted ? " [TAINTED]" : "";
      lines.push(`  ${s.process.killed ? "✗" : "✓"} ${name}${isDefault} → ${s.info.protocol}://${s.info.target} (${s.info.platform}, ${s.info.commandCount} cmds)${taint}`);
    }
  }

  if (activeTunnels.length > 0) {
    lines.push("", `Tunnels (${activeTunnels.length}):`);
    for (const t of activeTunnels) {
      const alive = !t.process.killed && t.process.exitCode === null;
      lines.push(`  ${alive ? "✓" : "✗"} [${t.id}] ${t.type} :${t.localPort} via ${t.via}`);
    }
  }

  if (activeRelays.length > 0) {
    lines.push("", `Relays (${activeRelays.length}):`);
    for (const r of activeRelays) {
      lines.push(`  [${r.id}] ${r.method} ${r.session}:${r.listenPort} → ${r.targetHost}:${r.targetPort}`);
    }
  }

  lines.push("");
  if (!raw) {
    lines.push("Intel: not initialized");
  } else {
    const hCount  = Object.keys(raw.hosts).length;
    const cCount  = Object.keys(raw.credentials).length;
    const aCount  = Object.keys(raw.accounts).length;
    const pCount  = Object.keys(raw.pivots).length;
    const tCount  = Array.isArray(raw.timeline) ? raw.timeline.length : 0;
    const dirty   = Object.values(raw.hosts).filter((h: any) => h.status === "compromised").length;
    const activeCreds = Object.values(raw.credentials).filter((c: any) => c.status === "active").length;
    const unvalidated = Object.values(raw.credentials).filter((c: any) => !INACTIVE_CREDENTIAL_STATUSES.has(c.status ?? "") && (!c.valid_on || (c.valid_on as string[]).length === 0)).length;
    lines.push(`Intel: ${hCount} hosts (${dirty} compromised) | ${cCount} creds (${activeCreds} active, ${unvalidated} unvalidated) | ${aCount} accounts | ${pCount} pivots | ${tCount} events`);
    if (Array.isArray(raw.timeline) && raw.timeline.length > 0) {
      lines.push("", "Last 5 events:");
      raw.timeline.slice(-5).reverse().forEach((e: any) => {
        const ts = (e.timestamp || e.ts || "").slice(0, 19).replace("T", " ");
        lines.push(`  ${ts}  ${e.summary || ""}`);
      });
    }
  }

  return lines.join("\n");
}

function pickOperatorSession(args: string | undefined, sessions: Map<string, RemoteSession>, defaultSessionName: string | null): OperatorSessionSummary | undefined {
  const parsed = parseShortcutArgs(args);
  const available = operatorSessionSummaries(sessions);
  const selectedName = parsed.sessionName || (defaultSessionName && sessions.has(defaultSessionName) ? defaultSessionName : (available.length === 1 ? available[0].name : undefined));
  return selectedName ? available.find(s => s.name === selectedName) : undefined;
}

function sessionCompletions(sessions: Map<string, RemoteSession>, prefix: string) {
  const base = [...sessions.keys()].map(name => ({ value: name, label: name, description: "active remote session" }));
  if (!prefix) return base;
  return base.filter(item => item.value.startsWith(prefix));
}

function showOrStage(ctx: any, shouldStage: boolean, promptText: string | undefined, displayText: string): void {
  if (shouldStage && promptText) {
    ctx.ui.setEditorText(promptText);
    ctx.ui.notify("Staged phase prompt in editor. Press Enter to run or edit first.", "info");
    return;
  }
  ctx.ui.notify(displayText, "info");
}

export function registerRemoteSlashCommands(pi: ExtensionAPI, deps: RemoteSlashCommandDeps): void {
  const operatorSessions = () => operatorSessionSummaries(deps.sessions);
  const currentDefault = () => deps.getDefaultSessionName();

  pi.registerCommand("land", {
    description: "Operator shortcut: landing/access primitives and immediate next action",
    handler: async (args, ctx) => {
      const parsed = parseShortcutArgs(args);
      if (parsed.help) {
        ctx.ui.notify("Usage: /land\nShows fast access, pivot, and post-landing prompts. No case/report workflow.", "info");
        return;
      }
      ctx.ui.notify(formatLandShortcut(operatorSessions()), "info");
    },
  });

  pi.registerCommand("assess", {
    description: "Operator shortcut: first-look and high-signal assessment commands for a session",
    getArgumentCompletions: (prefix: string) => sessionCompletions(deps.sessions, prefix),
    handler: async (args, ctx) => {
      const parsed = parseShortcutArgs(args);
      const session = pickOperatorSession(args, deps.sessions, currentDefault());
      const display = formatAssessShortcut(session, operatorSessions());
      showOrStage(ctx, parsed.prompt, session ? buildAssessPrompt(session) : undefined, display);
    },
  });

  pi.registerCommand("pursue", {
    description: "Operator shortcut: credential/pivot chase board with pre-built validation commands",
    handler: async (args, ctx) => {
      const parsed = parseShortcutArgs(args);
      const { pursue: intelSnap } = readIntelSnapshot();
      const display = formatPursueShortcut(operatorSessions(), intelSnap);
      showOrStage(ctx, parsed.prompt, buildPursuePrompt(), display);
    },
  });

  pi.registerCommand("contain", {
    description: "Operator shortcut: evidence-first containment command pack for a session",
    getArgumentCompletions: (prefix: string) => sessionCompletions(deps.sessions, prefix),
    handler: async (args, ctx) => {
      const parsed = parseShortcutArgs(args);
      const session = pickOperatorSession(args, deps.sessions, currentDefault());
      const display = formatContainShortcut(session, operatorSessions());
      showOrStage(ctx, parsed.prompt, session ? buildContainPrompt(session) : undefined, display);
    },
  });

  pi.registerCommand("eradicate", {
    description: "Operator shortcut: evidence-backed eradication command pack for a session",
    getArgumentCompletions: (prefix: string) => sessionCompletions(deps.sessions, prefix),
    handler: async (args, ctx) => {
      const parsed = parseShortcutArgs(args);
      const session = pickOperatorSession(args, deps.sessions, currentDefault());
      const display = formatEradicateShortcut(session, operatorSessions());
      showOrStage(ctx, parsed.prompt, session ? buildEradicatePrompt(session) : undefined, display);
    },
  });

  pi.registerCommand("verify", {
    description: "Operator shortcut: post-containment/eradication verification commands for a session",
    getArgumentCompletions: (prefix: string) => sessionCompletions(deps.sessions, prefix),
    handler: async (args, ctx) => {
      const parsed = parseShortcutArgs(args);
      const session = pickOperatorSession(args, deps.sessions, currentDefault());
      const display = formatVerifyShortcut(session, operatorSessions());
      showOrStage(ctx, parsed.prompt, session ? buildVerifyPrompt(session) : undefined, display);
    },
  });

  pi.registerCommand("scope", {
    description: "Situational dump: active sessions, tunnels, intel counts, and last 5 timeline entries",
    handler: async (_args, ctx) => {
      const { raw } = readIntelSnapshot();
      ctx.ui.notify(buildScopeText(deps.sessions, deps.activeTunnels, deps.activeRelays, currentDefault(), raw), "info");
    },
  });

  pi.registerCommand("map", {
    description: "Attack graph: host nodes, credential blast radius, accounts, pivot chains",
    handler: async (_args, ctx) => {
      const { raw } = readIntelSnapshot();
      if (!raw) {
        ctx.ui.notify("Intel store not initialized. Run intel_add to record findings first.", "info");
        return;
      }
      const activeSessionNames = new Set([...deps.sessions.keys()]);
      const map = buildIntelMap(raw.hosts, raw.credentials, raw.accounts, raw.pivots, { activeSessions: activeSessionNames });
      ctx.ui.notify(map, "info");
    },
  });

  pi.registerCommand("report", {
    description: "Incident summary: host status, credential rotation requirements, last 3 timeline events",
    handler: async (_args, ctx) => {
      const irReportBin = spawnSync("which", ["ir-report"], { encoding: "utf8" }).stdout?.trim() || "/opt/brjotskel/bin/ir-report";
      const intelDir = process.env.BRJOTSKEL_INTEL_DIR || join(process.cwd(), "workspace", "intel");
      const result = spawnSync("python3", [irReportBin, "--short", "--intel-dir", intelDir], { encoding: "utf8", timeout: 15_000 });
      if (result.error) {
        ctx.ui.notify(`/report failed: ${result.error.message}`, "error");
        return;
      }
      if (result.status !== 0) {
        const errMsg = result.stderr?.trim() || `exit ${result.status}`;
        ctx.ui.notify(`/report failed: ${errMsg}`, "error");
        return;
      }
      ctx.ui.notify(result.stdout?.trim() || "(no output)", "info");
    },
  });

  pi.registerCommand("remote-connect", {
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /remote-connect <ssh|winrm|tcp|telnet> <target> --name <name> (preview only; use remote_connect tool to connect)", "info");
        return;
      }
      const parts = args.trim().split(/\s+/);
      const protocol = parts[0];
      const target = parts[1];
      const nameIdx = parts.indexOf("--name");
      const name = nameIdx >= 0 ? parts[nameIdx + 1] : target?.replace(/[^a-zA-Z0-9-]/g, "-") || "default";
      ctx.ui.notify(`Preview: remote_connect(protocol="${protocol}", target="${target}", name="${name}")`, "info");
    },
  });

  pi.registerCommand("remote-disconnect", {
    description: "Disconnect: /remote-disconnect <name|--all>",
    handler: async (args, ctx) => {
      if (args === "--all") {
        for (const [name, session] of deps.sessions) {
          deps.log(name, "---", "[SESSION END via /command]");
          try { session.process.stdin!.write("exit\n"); } catch { /* ignore */ }
          killTrackedProcess(session.process);
        }
        const count = deps.sessions.size;
        deps.sessions.clear();
        deps.setDefaultSessionName(null);
        ctx.ui.setStatus("remote", undefined);
        ctx.ui.notify(`Disconnected all ${count} session(s)`, "info");
        return;
      }
      const name = args?.trim();
      if (!name) {
        ctx.ui.notify(`Active sessions: ${[...deps.sessions.keys()].join(", ") || "none"}`, "info");
        return;
      }
      const session = deps.sessions.get(name);
      if (!session) {
        ctx.ui.notify(`Session '${name}' not found`, "error");
        return;
      }
      deps.log(name, "---", "[SESSION END via /command]");
      try { session.process.stdin!.write("exit\n"); } catch { /* ignore */ }
      killTrackedProcess(session.process);
      deps.sessions.delete(name);
      if (currentDefault() === name) deps.setDefaultSessionName(deps.sessions.size > 0 ? deps.sessions.keys().next().value! : null);
      ctx.ui.setStatus("remote", deps.sessions.size > 0 ? ctx.ui.theme.fg("accent", `🔗 Sessions: ${[...deps.sessions.keys()].join(", ")}`) : undefined);
      ctx.ui.notify(`Disconnected '${name}'`, "info");
    },
  });

  pi.registerCommand("sessions", {
    description: "List active remote sessions, tunnels, and relays",
    handler: async (_args, ctx) => {
      if (deps.sessions.size === 0 && deps.activeTunnels.length === 0 && deps.activeRelays.length === 0) {
        ctx.ui.notify("No active sessions, tunnels, or relays", "info");
        return;
      }
      const lines: string[] = [];
      for (const [name, session] of deps.sessions) {
        const alive = !session.process.killed;
        const isDefault = name === currentDefault() ? " *" : "";
        lines.push(`${alive ? "✓" : "✗"} ${name}${isDefault} → ${session.info.protocol}://${session.info.target} (${session.info.platform}, ${session.info.commandCount} cmds)`);
      }
      if (deps.activeTunnels.length > 0) {
        lines.push("");
        for (const t of deps.activeTunnels) {
          const alive = !t.process.killed && t.process.exitCode === null;
          lines.push(`${alive ? "✓" : "✗"} [${t.id}] ${t.type} localhost:${t.localPort} via ${t.via}`);
        }
      }
      if (deps.activeRelays.length > 0) {
        lines.push("");
        for (const r of deps.activeRelays) {
          const sessionAlive = deps.sessions.has(r.session) && !deps.sessions.get(r.session)!.process.killed;
          lines.push(`${sessionAlive ? "✓" : "⚠"} [${r.id}] ${r.method} ${r.session}:${r.listenPort} → ${r.targetHost}:${r.targetPort}`);
        }
      }
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });

  pi.registerCommand("tunnels", {
    description: "List active SSH tunnels",
    handler: async (_args, ctx) => {
      if (deps.activeTunnels.length === 0) {
        ctx.ui.notify("No active tunnels", "info");
        return;
      }
      const lines = deps.activeTunnels.map(t => {
        const alive = !t.process.killed && t.process.exitCode === null;
        return `${alive ? "✓" : "✗"} [${t.id}] ${t.type} localhost:${t.localPort} via ${t.via} — ${t.description}`;
      });
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });
}
