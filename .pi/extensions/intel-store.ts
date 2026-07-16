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
import { execSync } from "node:child_process";
import { join } from "node:path";
import { Type } from "typebox";
import { normalizeIntelEntry, validateIntelEntry, resolveStoredPath, resolveIntelDir } from "./lib/intel-helpers.ts";
import { getFileMap, getCollectionKeyMap, addIntelRecord, appendTimelineEntry, formatHostQueryResult, formatCredentialQueryResult, searchIntel, formatSearchResult, buildIntelSummary } from "./lib/intel-store-core.ts";
import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

// -------------------------------------------------------------------
// Paths
// -------------------------------------------------------------------

function getIntelDir(): string {
  const base = resolveIntelDir(process.cwd(), process.env.BRJOTSKEL_INTEL_DIR);
  mkdirSync(base, { recursive: true });
  mkdirSync(join(base, "keys"), { recursive: true });
  mkdirSync(join(base, "loot"), { recursive: true });
  return base;
}

function parseYaml(content: string, source = "input"): any {
  try {
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
  writeYaml(timelinePath, appendTimelineEntry(timeline, entry));
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

      const filePath = join(intelDir, getFileMap()[params.category]);
      const key = getCollectionKeyMap()[params.category];
      const entryData = normalizeIntelEntry(params.category, parseYaml(params.data, `intel_add:${params.category}:${params.id}`));
      validateIntelEntry(params.category, entryData);

      const total = await withIntelWriteLock(async () => {
        const store = readYaml(filePath);
        const updatedStore = addIntelRecord(store, key, params.id, entryData);
        writeYaml(filePath, updatedStore);

        appendTimeline(intelDir, {
          timestamp: new Date().toISOString(),
          type: params.category,
          action: "discovered",
          target: params.id,
          summary: params.summary || `Added ${params.category}: ${params.id}`,
          operator: process.env.USER || "unknown",
        });

        return Object.keys(updatedStore[key]).length;
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
          result = formatHostQueryResult(hosts, credentials, accounts, pivots, params.target);
          break;
        }

        case "for_credential": {
          if (!params.target) throw new Error("'target' parameter required for for_credential query");
          result = formatCredentialQueryResult(credentials, params.target);
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
          const matches = searchIntel(hosts, credentials, accounts, pivots, params.keyword);
          result = formatSearchResult(params.keyword, matches);
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

      return {
        content: [{ type: "text", text: buildIntelSummary(hosts, credentials, accounts, pivots, timeline, intelDir) }],
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
