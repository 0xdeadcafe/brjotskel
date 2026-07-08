/**
 * Intel Store Extension
 *
 * Provides tools for the agent to read and write operational intelligence
 * gathered during incident response: hosts, credentials, accounts, pivots.
 *
 * The store lives in workspace/intel/ as YAML files, human-readable and
 * editable, but also programmatically accessible via these tools.
 *
 * Registered tools:
 *   intel_add        — Add a host, credential, account, or pivot entry
 *   intel_query      — Look up entries (e.g., "what creds work on db01?")
 *   intel_get_cred   — Retrieve a specific credential for use in remote_connect
 *   intel_timeline   — Append a timeline entry
 *   intel_summary    — Overview of all known intel (counts, status)
 *
 * Slash commands:
 *   /intel           — Quick summary of intel store
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, renameSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { Type } from "typebox";
import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

// -------------------------------------------------------------------
// Paths
// -------------------------------------------------------------------

function getIntelDir(): string {
  const base = process.env.BRJOTSKEL_INTEL_DIR || join(process.cwd(), "intel");
  mkdirSync(base, { recursive: true });
  mkdirSync(join(base, "keys"), { recursive: true });
  mkdirSync(join(base, "loot"), { recursive: true });
  return base;
}

function parseYaml(content: string, source = "input"): any {
  try {
    const { execSync } = require("node:child_process");
    const result = execSync(`python3 -c "import yaml,json,sys; print(json.dumps(yaml.safe_load(sys.stdin.read()) or {}))"`, {
      input: content,
      encoding: "utf-8",
      timeout: 5000,
    });
    return JSON.parse(result);
  } catch (err: any) {
    throw new Error(`Failed to parse YAML from ${source}: ${err.message}`);
  }
}

function readYaml(filePath: string): any {
  if (!existsSync(filePath)) return {};
  const content = readFileSync(filePath, "utf-8");
  return parseYaml(content, filePath);
}

function writeYaml(filePath: string, data: any): void {
  try {
    const { execSync } = require("node:child_process");
    const json = JSON.stringify(data);
    const yaml = execSync(`python3 -c "import yaml,json,sys; data=json.loads(sys.stdin.read()); print(yaml.dump(data, default_flow_style=False, sort_keys=False))"`, {
      input: json,
      encoding: "utf-8",
      timeout: 5000,
    });
    const tempPath = `${filePath}.tmp-${process.pid}-${Date.now()}`;
    writeFileSync(tempPath, yaml);
    renameSync(tempPath, filePath);
  } catch (err: any) {
    throw new Error(`Failed to write YAML: ${err.message}`);
  }
}

let intelWriteChain: Promise<unknown> = Promise.resolve();

function withIntelWriteLock<T>(fn: () => T | Promise<T>): Promise<T> {
  const next = intelWriteChain.then(fn, fn) as Promise<T>;
  intelWriteChain = next.then(() => undefined, () => undefined);
  return next;
}

function appendTimeline(intelDir: string, entry: Record<string, any>): void {
  const timelinePath = join(intelDir, "timeline.yaml");
  const timeline = readYaml(timelinePath);
  if (!timeline.timeline) timeline.timeline = [];
  timeline.timeline.push(entry);
  writeYaml(timelinePath, timeline);
}

function ensureArray<T>(value: T | T[] | undefined | null): T[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function normalizeSource(source: any): any {
  if (!source) return undefined;
  if (typeof source === "string") return { method: source };
  if (typeof source !== "object" || Array.isArray(source)) return { method: String(source) };

  const out = { ...source };
  if (!out.method && out.discovered_from) out.method = out.discovered_from;
  return out;
}

function normalizeIntelEntry(category: "host" | "credential" | "account" | "pivot", entryData: any): any {
  const normalized = { ...entryData };

  if (normalized.source) normalized.source = normalizeSource(normalized.source);
  if (normalized.discovered && typeof normalized.discovered === "object" && !Array.isArray(normalized.discovered)) {
    normalized.discovered = { ...normalized.discovered };
    if (!normalized.discovered.source && normalized.source?.method) normalized.discovered.source = normalized.source.method;
  }

  if (category === "host") {
    if (normalized.access && typeof normalized.access === "object" && !Array.isArray(normalized.access)) {
      normalized.access = { ...normalized.access };
    }
    normalized.endpoints = ensureArray(normalized.endpoints);
    normalized.profile_artifacts = ensureArray(normalized.profile_artifacts);
  }

  if (category === "credential") {
    normalized.valid_on = ensureArray(normalized.valid_on);
    normalized.related_hosts = ensureArray(normalized.related_hosts);
  }

  if (category === "account") {
    normalized.access_to = ensureArray(normalized.access_to);
    normalized.credentials = ensureArray(normalized.credentials);
    normalized.related_hosts = ensureArray(normalized.related_hosts);
  }

  if (category === "pivot") {
    normalized.chain = ensureArray(normalized.chain);
    normalized.evidence = ensureArray(normalized.evidence);
    normalized.related_hosts = ensureArray(normalized.related_hosts);
  }

  return normalized;
}

function validateIntelEntry(category: "host" | "credential" | "account" | "pivot", entryData: any): void {
  if (!entryData || typeof entryData !== "object" || Array.isArray(entryData)) {
    throw new Error("Intel entry must be a YAML object/map.");
  }

  if (category === "credential") {
    if (!entryData.type || !entryData.username) {
      throw new Error("Credential entries require at least 'type' and 'username'.");
    }
  }
  if (category === "pivot" && !entryData.target) {
    throw new Error("Pivot entries require 'target'.");
  }
}

function resolveStoredPath(intelDir: string, path?: string): string {
  if (!path) return "(not stored)";
  return isAbsolute(path) ? path : join(intelDir, path);
}

// -------------------------------------------------------------------
// Extension
// -------------------------------------------------------------------

export default function (pi: ExtensionAPI) {

  // -------------------------------------------------------------------
  // Tool: intel_add
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "intel_add",
    label: "Intel Add",
    description: "Add a discovered host, credential, account, or pivot path to the intel store. Automatically appends to the timeline.",
    promptSnippet: "Record a discovered host, credential, account, or pivot path",
    promptGuidelines: [
      "Use intel_add immediately when discovering new hosts, credentials, or accounts during investigation.",
      "Always include source information (which host it came from, how it was found).",
      "For credentials: specify valid_on hosts where the credential has been confirmed working.",
      "intel_add auto-appends a timeline entry — no need to call intel_timeline separately.",
    ],
    parameters: Type.Object({
      category: StringEnum(["host", "credential", "account", "pivot"] as const),
      id: Type.String({ description: "Unique identifier (e.g., 'web01', 'admin-ntlm', 'corp\\\\admin', 'to-dc01')" }),
      data: Type.String({ description: "YAML-formatted entry data (follows the schema in the respective intel file)" }),
      summary: Type.Optional(Type.String({ description: "One-line summary for the timeline entry" })),
    }),

    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      const intelDir = getIntelDir();

      const fileMap: Record<string, string> = {
        host: "hosts.yaml",
        credential: "credentials.yaml",
        account: "accounts.yaml",
        pivot: "pivots.yaml",
      };

      const collectionKey: Record<string, string> = {
        host: "hosts",
        credential: "credentials",
        account: "accounts",
        pivot: "paths",
      };

      const filePath = join(intelDir, fileMap[params.category]);
      const key = collectionKey[params.category];
      const entryData = normalizeIntelEntry(params.category, parseYaml(params.data, `intel_add:${params.category}:${params.id}`));
      validateIntelEntry(params.category, entryData);

      const total = await withIntelWriteLock(async () => {
        const store = readYaml(filePath);
        if (!store[key]) store[key] = {};
        store[key][params.id] = entryData;
        writeYaml(filePath, store);

        appendTimeline(intelDir, {
          timestamp: new Date().toISOString(),
          type: params.category,
          action: "discovered",
          target: params.id,
          summary: params.summary || `Added ${params.category}: ${params.id}`,
          operator: process.env.USER || "unknown",
        });

        return Object.keys(store[key]).length;
      });

      return {
        content: [{ type: "text", text: `Added ${params.category} '${params.id}' to intel store.\nFile: ${filePath}\nTotal ${key}: ${total}` }],
        details: { category: params.category, id: params.id, file: filePath },
      };
    },
  });

  // -------------------------------------------------------------------
  // Tool: intel_query
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "intel_query",
    label: "Intel Query",
    description: "Query the intel store. Find credentials for a host, hosts accessible with a credential, all entries of a category, or search by keyword.",
    promptSnippet: "Query intel store (creds for host, hosts for cred, search by keyword)",
    promptGuidelines: [
      "Use intel_query to find credentials before connecting to a host.",
      "Use intel_query with query_type='for_host' to see what access you have to a specific system.",
      "Use intel_query with query_type='search' for free-text search across all intel.",
    ],
    parameters: Type.Object({
      query_type: StringEnum(["for_host", "for_credential", "all_hosts", "all_credentials", "all_accounts", "all_pivots", "search"] as const),
      target: Type.Optional(Type.String({ description: "Host name or credential ID to query about" })),
      keyword: Type.Optional(Type.String({ description: "Search keyword (for query_type='search')" })),
    }),

    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      const intelDir = getIntelDir();

      const hosts = readYaml(join(intelDir, "hosts.yaml")).hosts || {};
      const credentials = readYaml(join(intelDir, "credentials.yaml")).credentials || {};
      const accounts = readYaml(join(intelDir, "accounts.yaml")).accounts || {};
      const pivots = readYaml(join(intelDir, "pivots.yaml")).paths || {};

      let result = "";

      switch (params.query_type) {
        case "for_host": {
          if (!params.target) throw new Error("'target' parameter required for for_host query");
          const hostInfo = hosts[params.target];
          const hostCreds = Object.entries(credentials).filter(([_, c]: [string, any]) =>
            c.valid_on?.includes(params.target)
          );
          const hostAccounts = Object.entries(accounts).filter(([_, a]: [string, any]) =>
            a.access_to?.includes(params.target)
          );
          const hostPivots = Object.entries(pivots).filter(([_, p]: [string, any]) =>
            p.target === params.target
          );

          result = `=== Host: ${params.target} ===\n`;
          if (hostInfo) {
            result += `IP: ${hostInfo.ip || "unknown"}\nHostname: ${hostInfo.hostname || params.target}\nPlatform: ${hostInfo.platform || "unknown"}\nRole: ${hostInfo.role || "unknown"}\nStatus: ${hostInfo.status || "unknown"}\nAttacker role: ${hostInfo.attacker_role || "unknown"}\n`;
            if (hostInfo.access?.method) {
              result += `Access: ${hostInfo.access.method} via ${hostInfo.access.via || "unknown"}`;
              if (hostInfo.access.credential) result += ` using ${hostInfo.access.credential}`;
              if (hostInfo.access.port) result += ` port ${hostInfo.access.port}`;
              result += `\n`;
            }
            if (hostInfo.source) {
              result += `Source: ${hostInfo.source.host || "?"} via ${hostInfo.source.method || "?"}`;
              if (hostInfo.source.path) result += ` path=${hostInfo.source.path}`;
              if (hostInfo.source.tool) result += ` tool=${hostInfo.source.tool}`;
              if (hostInfo.source.playbook) result += ` playbook=${hostInfo.source.playbook}`;
              result += `\n`;
            }
            if ((hostInfo.endpoints || []).length > 0) {
              result += `Endpoints: ${(hostInfo.endpoints || []).slice(0, 6).join(", ")}`;
              if ((hostInfo.endpoints || []).length > 6) result += ` ...`;
              result += `\n`;
            }
            if ((hostInfo.profile_artifacts || []).length > 0) {
              result += `Profile artifacts: ${(hostInfo.profile_artifacts || []).slice(0, 6).join(", ")}`;
              if ((hostInfo.profile_artifacts || []).length > 6) result += ` ...`;
              result += `\n`;
            }
          } else {
            result += "(not in hosts.yaml)\n";
          }
          result += `\nCredentials valid on this host (${hostCreds.length}):\n`;
          for (const [id, c] of hostCreds as [string, any][]) {
            result += `  ${id}: ${c.type} — ${c.username}${c.domain ? "@" + c.domain : ""} [${c.status}]\n`;
          }
          result += `\nAccounts with access (${hostAccounts.length}):\n`;
          for (const [id, a] of hostAccounts as [string, any][]) {
            result += `  ${id}: ${a.type} — ${(a.privileges || []).join(", ")} [${a.status}]\n`;
          }
          result += `\nPivot paths (${hostPivots.length}):\n`;
          for (const [id, p] of hostPivots as [string, any][]) {
            const hops = (p.chain || []).map((h: any) => h.hop).join(" → ");
            result += `  ${id}: ${hops} [${p.status}]\n`;
          }
          break;
        }

        case "for_credential": {
          if (!params.target) throw new Error("'target' parameter required for for_credential query");
          const cred = credentials[params.target];
          if (!cred) {
            result = `Credential '${params.target}' not found.\nAvailable: ${Object.keys(credentials).join(", ") || "none"}`;
          } else {
            result = `=== Credential: ${params.target} ===\n`;
            result += `Type: ${cred.type}\nUsername: ${cred.username}\nDomain: ${cred.domain || "local"}\n`;
            result += `Status: ${cred.status}\n`;
            result += `Valid on: ${(cred.valid_on || []).join(", ")}\n`;
            result += `Source: ${cred.source?.host || "?"} via ${cred.source?.method || "?"}`;
            if (cred.source?.path) result += ` path=${cred.source.path}`;
            if (cred.source?.tool) result += ` tool=${cred.source.tool}`;
            if (cred.source?.playbook) result += ` playbook=${cred.source.playbook}`;
            result += `\n`;
            if ((cred.related_hosts || []).length > 0) result += `Related hosts: ${(cred.related_hosts || []).join(", ")}\n`;
            if (cred.key_file) result += `Key file: ${cred.key_file}\n`;
            if (cred.ticket_file) result += `Ticket: ${cred.ticket_file}\n`;
            if (cred.notes) result += `Notes: ${cred.notes}\n`;
          }
          break;
        }

        case "all_hosts":
          result = `=== All Hosts (${Object.keys(hosts).length}) ===\n`;
          for (const [id, h] of Object.entries(hosts) as [string, any][]) {
            result += `  ${id}: ${h.ip || "?"} | ${h.platform || "?"} | ${h.role || "?"} | ${h.status || "?"} | ${h.attacker_role || "?"}\n`;
          }
          break;

        case "all_credentials":
          result = `=== All Credentials (${Object.keys(credentials).length}) ===\n`;
          for (const [id, c] of Object.entries(credentials) as [string, any][]) {
            result += `  ${id}: ${c.type} — ${c.username}${c.domain ? "@" + c.domain : ""} | valid_on: ${(c.valid_on || []).join(",")} | related_hosts: ${(c.related_hosts || []).join(",")} | ${c.status}\n`;
          }
          break;

        case "all_accounts":
          result = `=== All Accounts (${Object.keys(accounts).length}) ===\n`;
          for (const [id, a] of Object.entries(accounts) as [string, any][]) {
            result += `  ${id}: ${a.type} — ${(a.privileges || []).slice(0, 3).join(",")} | ${a.status}\n`;
          }
          break;

        case "all_pivots":
          result = `=== All Pivot Paths (${Object.keys(pivots).length}) ===\n`;
          for (const [id, p] of Object.entries(pivots) as [string, any][]) {
            const hops = (p.chain || []).map((h: any) => h.hop).join(" → ");
            const evidence = (p.evidence || []).map((e: any) => e.kind || e.path || e.host || JSON.stringify(e)).slice(0, 2).join(", ");
            result += `  ${id}: → ${p.target} via [${hops}] | ${p.status}${evidence ? ` | evidence: ${evidence}` : ""}\n`;
          }
          break;

        case "search": {
          if (!params.keyword) throw new Error("'keyword' parameter required for search query");
          const kw = params.keyword.toLowerCase();
          const matches: string[] = [];

          for (const [id, h] of Object.entries(hosts) as [string, any][]) {
            if (id.toLowerCase().includes(kw) || JSON.stringify(h).toLowerCase().includes(kw)) matches.push(`host:${id}`);
          }
          for (const [id, c] of Object.entries(credentials) as [string, any][]) {
            if (id.toLowerCase().includes(kw) || JSON.stringify(c).toLowerCase().includes(kw)) matches.push(`credential:${id}`);
          }
          for (const [id, a] of Object.entries(accounts) as [string, any][]) {
            if (id.toLowerCase().includes(kw) || JSON.stringify(a).toLowerCase().includes(kw)) matches.push(`account:${id}`);
          }
          for (const [id, p] of Object.entries(pivots) as [string, any][]) {
            if (id.toLowerCase().includes(kw) || JSON.stringify(p).toLowerCase().includes(kw)) matches.push(`pivot:${id}`);
          }

          result = `Search: "${params.keyword}" — ${matches.length} match(es)\n`;
          result += matches.map(m => `  ${m}`).join("\n") || "  (no matches)";
          break;
        }
      }

      return {
        content: [{ type: "text", text: result }],
        details: { query_type: params.query_type, target: params.target },
      };
    },
  });

  // -------------------------------------------------------------------
  // Tool: intel_get_cred
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "intel_get_cred",
    label: "Intel Get Credential",
    description: "Retrieve a specific credential's secret value for use in authentication. Returns the password, hash, or key file path needed for remote_connect or manual tool use.",
    promptSnippet: "Get a credential's secret (password/hash/key path) for authentication",
    promptGuidelines: [
      "Use intel_get_cred to retrieve credentials before using them in remote_connect or command-line tools.",
      "For SSH keys: the returned key_file path can be passed to remote_connect's identity parameter.",
      "For NTLM hashes: use with Impacket tools (secretsdump.py -hashes :HASH ...).",
    ],
    parameters: Type.Object({
      id: Type.String({ description: "Credential ID from credentials.yaml" }),
    }),

    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      const intelDir = getIntelDir();
      const credentials = readYaml(join(intelDir, "credentials.yaml")).credentials || {};

      const cred = credentials[params.id];
      if (!cred) {
        const available = Object.keys(credentials).join(", ");
        throw new Error(`Credential '${params.id}' not found. Available: ${available || "none"}`);
      }

      const lines: string[] = [
        `Credential: ${params.id}`,
        `Type: ${cred.type}`,
        `Username: ${cred.username}`,
        `Domain: ${cred.domain || "(local)"}`,
      ];

      switch (cred.type) {
        case "password":
          lines.push(`Secret: ${cred.secret}`);
          lines.push(`Usage: ssh ${cred.username}@<host> or use in remote_connect`);
          break;
        case "ntlm-hash":
          lines.push(`Hash: ${cred.secret}`);
          lines.push(`Usage: secretsdump.py -hashes ${cred.secret} ${cred.domain}/${cred.username}@<host>`);
          lines.push(`  or: proxychains wmiexec.py -hashes ${cred.secret} ${cred.domain}/${cred.username}@<host>`);
          break;
        case "ssh-key":
          const keyPath = resolveStoredPath(intelDir, cred.key_file);
          lines.push(`Key file: ${keyPath}`);
          lines.push(`Passphrase: ${cred.passphrase || "(none)"}`);
          lines.push(`Usage: ssh -i ${keyPath} ${cred.username}@<host>`);
          lines.push(`  or: remote_connect(identity="${keyPath}", ...)`);
          break;
        case "kerberos-tgt":
        case "kerberos-tgs":
          const ticketPath = resolveStoredPath(intelDir, cred.ticket_file);
          lines.push(`Ticket: ${ticketPath}`);
          lines.push(`Expires: ${cred.expires || "unknown"}`);
          lines.push(`Usage: export KRB5CCNAME=${ticketPath} && psexec.py -k -no-pass ${cred.domain}/${cred.username}@<host>`);
          break;
        case "token":
          lines.push(`Token: ${cred.secret}`);
          break;
        default:
          lines.push(`Secret: ${cred.secret || "(see file)"}`);
      }

      lines.push(`Valid on: ${(cred.valid_on || []).join(", ")}`);
      lines.push(`Status: ${cred.status}`);

      await withIntelWriteLock(async () => {
        appendTimeline(intelDir, {
          timestamp: new Date().toISOString(),
          type: "credential",
          action: "confirmed",
          target: params.id,
          summary: `Credential secret retrieved for operational use: ${params.id}`,
          operator: process.env.USER || "unknown",
        });
      });

      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: { id: params.id, type: cred.type, username: cred.username, valid_on: cred.valid_on },
      };
    },
  });

  // -------------------------------------------------------------------
  // Tool: intel_timeline
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "intel_timeline",
    label: "Intel Timeline",
    description: "Append a manual timeline entry or view recent timeline entries.",
    promptSnippet: "Add or view entries in the investigation timeline",
    parameters: Type.Object({
      action: StringEnum(["add", "view"] as const),
      entry_type: Type.Optional(StringEnum(["host", "credential", "account", "persistence", "c2", "pivot", "eradication", "containment"] as const)),
      entry_action: Type.Optional(StringEnum(["discovered", "confirmed", "eradicated", "rotated", "contained", "cleared"] as const)),
      target: Type.Optional(Type.String({ description: "What this entry is about" })),
      summary: Type.Optional(Type.String({ description: "One-line summary" })),
      count: Type.Optional(Type.Number({ description: "Number of recent entries to show (default: 20)" })),
    }),

    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      const intelDir = getIntelDir();
      const timelinePath = join(intelDir, "timeline.yaml");
      const timeline = readYaml(timelinePath);
      if (!timeline.timeline) timeline.timeline = [];

      if (params.action === "add") {
        if (!params.summary) throw new Error("'summary' is required when adding a timeline entry");
        await withIntelWriteLock(async () => {
          const current = readYaml(timelinePath);
          if (!current.timeline) current.timeline = [];
          current.timeline.push({
            timestamp: new Date().toISOString(),
            type: params.entry_type || "unknown",
            action: params.entry_action || "discovered",
            target: params.target || "unknown",
            summary: params.summary,
            operator: process.env.USER || "unknown",
          });
          writeYaml(timelinePath, current);
          timeline.timeline = current.timeline;
        });
        return {
          content: [{ type: "text", text: `Timeline entry added. Total entries: ${timeline.timeline.length}` }],
          details: { total: timeline.timeline.length },
        };
      } else {
        // View recent
        const count = params.count || 20;
        const recent = timeline.timeline.slice(-count);
        if (recent.length === 0) {
          return { content: [{ type: "text", text: "Timeline is empty." }], details: {} };
        }
        const lines = recent.map((e: any) =>
          `[${e.timestamp}] ${e.type}/${e.action} — ${e.target}: ${e.summary} (${e.operator})`
        );
        return {
          content: [{ type: "text", text: `=== Timeline (last ${recent.length} of ${timeline.timeline.length}) ===\n${lines.join("\n")}` }],
          details: { shown: recent.length, total: timeline.timeline.length },
        };
      }
    },
  });

  // -------------------------------------------------------------------
  // Tool: intel_summary
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "intel_summary",
    label: "Intel Summary",
    description: "Quick overview of all intel collected: host count, credential count, account count, and status breakdown.",
    promptSnippet: "Overview of all collected intel (counts and status)",
    parameters: Type.Object({}),

    async execute(_toolCallId, _params, _signal, _onUpdate, _ctx) {
      const intelDir = getIntelDir();

      const hosts = readYaml(join(intelDir, "hosts.yaml")).hosts || {};
      const credentials = readYaml(join(intelDir, "credentials.yaml")).credentials || {};
      const accounts = readYaml(join(intelDir, "accounts.yaml")).accounts || {};
      const pivots = readYaml(join(intelDir, "pivots.yaml")).paths || {};
      const timeline = readYaml(join(intelDir, "timeline.yaml")).timeline || [];

      // Status breakdowns
      const hostStatuses: Record<string, number> = {};
      for (const h of Object.values(hosts) as any[]) {
        const s = h.status || "unknown";
        hostStatuses[s] = (hostStatuses[s] || 0) + 1;
      }

      const credTypes: Record<string, number> = {};
      for (const c of Object.values(credentials) as any[]) {
        const t = c.type || "unknown";
        credTypes[t] = (credTypes[t] || 0) + 1;
      }

      const profileDerivedHosts = Object.values(hosts).filter((h: any) => (h.endpoints || []).length > 0 || (h.profile_artifacts || []).length > 0).length;
      const sourcePathEntries = ([] as any[])
        .concat(Object.values(hosts) as any[])
        .concat(Object.values(credentials) as any[])
        .concat(Object.values(accounts) as any[])
        .concat(Object.values(pivots) as any[])
        .filter((x: any) => x.source?.path).length;
      const evidencePivots = Object.values(pivots).filter((p: any) => (p.evidence || []).length > 0).length;

      const lines = [
        "=== Intel Store Summary ===",
        "",
        `Hosts: ${Object.keys(hosts).length}`,
        ...Object.entries(hostStatuses).map(([s, n]) => `  ${s}: ${n}`),
        `  profile-derived/artifact-rich: ${profileDerivedHosts}`,
        "",
        `Credentials: ${Object.keys(credentials).length}`,
        ...Object.entries(credTypes).map(([t, n]) => `  ${t}: ${n}`),
        "",
        `Accounts: ${Object.keys(accounts).length}`,
        `Pivot paths: ${Object.keys(pivots).length}`,
        `  with evidence: ${evidencePivots}`,
        `Entries with source.path: ${sourcePathEntries}`,
        `Timeline entries: ${timeline.length}`,
        "",
        `Intel dir: ${intelDir}`,
      ];

      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: {
          hosts: Object.keys(hosts).length,
          credentials: Object.keys(credentials).length,
          accounts: Object.keys(accounts).length,
          pivots: Object.keys(pivots).length,
          timeline: timeline.length,
        },
      };
    },
  });

  // -------------------------------------------------------------------
  // Slash command: /intel
  // -------------------------------------------------------------------
  pi.registerCommand("intel", {
    description: "Quick intel store summary",
    handler: async (_args, ctx) => {
      const intelDir = getIntelDir();
      const hosts = readYaml(join(intelDir, "hosts.yaml")).hosts || {};
      const credentials = readYaml(join(intelDir, "credentials.yaml")).credentials || {};
      const accounts = readYaml(join(intelDir, "accounts.yaml")).accounts || {};
      const pivots = readYaml(join(intelDir, "pivots.yaml")).paths || {};

      ctx.ui.notify(
        `Intel: ${Object.keys(hosts).length} hosts | ${Object.keys(credentials).length} creds | ${Object.keys(accounts).length} accounts | ${Object.keys(pivots).length} pivots`,
        "info",
      );
    },
  });
}
