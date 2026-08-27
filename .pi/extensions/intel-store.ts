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
 *   intel_update     — Merge updates into an existing intel entry
 *   intel_query      — Look up entries (e.g., "what creds work on db01?")
 *   intel_get_cred   — Retrieve a specific credential for use in remote_connect
 *   intel_timeline   — Append a timeline entry
 *   intel_summary    — Overview of all known intel (counts, status)
 *
 * Slash commands:
 *   /intel           — Quick summary of intel store
 */

import { readFileSync, writeFileSync, existsSync, renameSync } from "node:fs";
import { join } from "node:path";
import { Type } from "typebox";
import { normalizeIntelEntry, validateIntelEntry, validateIntelStatusTransition, resolveStoredPath, resolveIntelDir, type IntelCategory } from "./lib/intel-helpers.ts";
import { ensurePrivateDir, ensurePrivateFile, hardenExistingPrivateFiles } from "./lib/intel-permissions.ts";
import { withIntelFileLock } from "./lib/intel-lock.ts";
import { parseYaml as parseYamlDocument, dumpYaml } from "./lib/simple-yaml.ts";
import { getFileMap, getCollectionKeyMap, addIntelRecord, updateIntelRecord, appendTimelineEntry, formatHostQueryResult, formatCredentialQueryResult, searchIntel, formatSearchResult, buildIntelSummary, buildIntelMap, filterTimeline, isInactiveCredentialStatus, timelineActionForIntelUpdate } from "./lib/intel-store-core.ts";
import { credValidationCmds } from "./lib/operator-shortcuts.ts";
import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

type IntelAddParams = { category: IntelCategory; id: string; data: string; summary?: string; overwrite?: boolean };
type IntelUpdateParams = { category: IntelCategory; id: string; fields: string; summary?: string; replace_arrays?: boolean; force?: boolean };
type IntelQueryParams = {
  query_type: "for_host" | "for_credential" | "all_hosts" | "all_credentials" | "all_accounts" | "all_pivots" | "search";
  target?: string;
  keyword?: string;
};
type IntelGetCredParams = { id: string };
type IntelTimelineParams = {
  action: "add" | "view";
  entry_type?: string;
  entry_action?: string;
  target?: string;
  summary?: string;
  count?: number;
  filter_host?: string;
  filter_category?: string;
  filter_action?: string;
  filter_since?: string;
};

// -------------------------------------------------------------------
// Paths
// -------------------------------------------------------------------

function getIntelDir(): string {
  const base = resolveIntelDir(process.cwd(), process.env.BRJOTSKEL_INTEL_DIR);
  const keysDir = join(base, "keys");
  const lootDir = join(base, "loot");
  ensurePrivateDir(base);
  ensurePrivateDir(keysDir);
  ensurePrivateDir(lootDir);
  for (const fileName of ["hosts.yaml", "credentials.yaml", "accounts.yaml", "pivots.yaml", "timeline.yaml"]) {
    ensurePrivateFile(join(base, fileName));
  }
  hardenExistingPrivateFiles(base, 4);
  return base;
}

function parseYaml(content: string, source = "input"): any {
  try {
    return parseYamlDocument(content) || {};
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
    const yaml = dumpYaml(data);
    const tempPath = `${filePath}.tmp-${process.pid}-${Date.now()}`;
    writeFileSync(tempPath, yaml, { mode: 0o600 });
    ensurePrivateFile(tempPath);
    renameSync(tempPath, filePath);
    ensurePrivateFile(filePath);
  } catch (err: any) {
    throw new Error(`Failed to write YAML to ${filePath}: ${err.message}`);
  }
}

let intelWriteChain: Promise<unknown> = Promise.resolve();

function withIntelWriteLock<T>(intelDir: string, fn: () => T | Promise<T>): Promise<T> {
  const next = intelWriteChain.then(() => withIntelFileLock(intelDir, fn), () => withIntelFileLock(intelDir, fn)) as Promise<T>;
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
      "Always include source.method, plus source.host/source.path when available, so provenance is preserved.",
      "Use documented status/type values; validation errors list allowed enums and missing required fields.",
      "For credentials: specify valid_on hosts where the credential has been confirmed working.",
      "Duplicate IDs are refused by default; prefer intel_update for lifecycle changes and set overwrite=true only when intentionally replacing an entry.",
      "intel_add auto-appends a timeline entry — no need to call intel_timeline separately.",
    ],
    parameters: Type.Object({
      category: StringEnum(["host", "credential", "account", "pivot"] as const),
      id: Type.String({ description: "Unique identifier (e.g., 'web01', 'admin-ntlm', 'corp\\\\admin', 'to-dc01')" }),
      data: Type.String({ description: "YAML-formatted entry data (follows the schema in the respective intel file)" }),
      summary: Type.Optional(Type.String({ description: "One-line summary for the timeline entry" })),
      overwrite: Type.Optional(Type.Boolean({ description: "Allow replacing an existing entry with the same ID (default: false)" })),
    }),

    async execute(_toolCallId, params: IntelAddParams, _signal, _onUpdate, _ctx) {
      const intelDir = getIntelDir();
      const category = params.category as IntelCategory;

      const filePath = join(intelDir, getFileMap()[category]);
      const key = getCollectionKeyMap()[category];
      const entryData = normalizeIntelEntry(category, parseYaml(params.data, `intel_add:${category}:${params.id}`));
      validateIntelEntry(category, entryData);

      const total = await withIntelWriteLock(intelDir, async () => {
        const store = readYaml(filePath);
        const updatedStore = addIntelRecord(store, key, params.id, entryData, { overwrite: params.overwrite === true });
        writeYaml(filePath, updatedStore);

        const action = params.overwrite === true ? "updated" : "discovered";
        appendTimeline(intelDir, {
          timestamp: new Date().toISOString(),
          type: params.category,
          action,
          target: params.id,
          summary: params.summary || `${params.overwrite === true ? "Updated" : "Added"} ${params.category}: ${params.id}`,
          operator: process.env.USER || "unknown",
        });

        return Object.keys(updatedStore[key]).length;
      });

      // For credentials: surface a validation hint if known hosts exist
      let validationHint = "";
      if (category === "credential") {
        try {
          const hosts = readYaml(join(intelDir, "hosts.yaml")).hosts || {};
          const hostIps = Object.values(hosts as Record<string, any>)
            .map((h: any) => h?.ip)
            .filter((ip): ip is string => typeof ip === "string" && ip.length > 0);
          if (hostIps.length > 0) {
            const cred = entryData;
            const username = cred.username || "?";
            const ipList = hostIps.slice(0, 4).join(",");
            const ipNote = hostIps.length > 4 ? ` (and ${hostIps.length - 4} more)` : "";
            const cmds = credValidationCmds(cred.type, username, params.id, ipList, cred.key_file);
            validationHint = `\n\n💡 Validate against ${hostIps.length} known host(s)${ipNote}:\n  ${cmds.join("\n  ")}`;
          }
        } catch {
          // hint is best-effort — never fail the add
        }
      }

      return {
        content: [{ type: "text", text: `${params.overwrite === true ? "Updated" : "Added"} ${params.category} '${params.id}' in intel store.\nFile: ${filePath}\nTotal ${key}: ${total}${validationHint}` }],
        details: { category: params.category, id: params.id, file: filePath },
      };
    },
  });

  // -------------------------------------------------------------------
  // Tool: intel_update
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "intel_update",
    label: "Intel Update",
    description: "Safely merge updates into an existing intel entry, validate lifecycle/status transitions, and append a timeline entry.",
    promptSnippet: "Update intel entry fields or lifecycle status with automatic timeline logging",
    promptGuidelines: [
      "Use intel_update for lifecycle changes such as host contained/cleared, credential rotated/revoked, account disabled, or pivot cleared.",
      "fields is a YAML object containing only the fields to merge into the existing entry.",
      "Arrays are union-merged by default; set replace_arrays=true only when intentionally replacing a list.",
      "Credential terminal statuses (rotated/expired/revoked/disabled/inactive/invalid) are not reactivated without force=true; prefer a new credential ID for replacement secrets.",
      "intel_update auto-appends a timeline entry — no need to call intel_timeline separately.",
    ],
    parameters: Type.Object({
      category: StringEnum(["host", "credential", "account", "pivot"] as const),
      id: Type.String({ description: "Existing intel entry ID to update" }),
      fields: Type.String({ description: "YAML-formatted partial fields to merge into the existing entry" }),
      summary: Type.Optional(Type.String({ description: "One-line summary for the timeline entry" })),
      replace_arrays: Type.Optional(Type.Boolean({ description: "Replace arrays instead of union-merging them (default: false)" })),
      force: Type.Optional(Type.Boolean({ description: "Allow otherwise discouraged lifecycle correction transitions (default: false)" })),
    }),

    async execute(_toolCallId, params: IntelUpdateParams, _signal, _onUpdate, _ctx) {
      const intelDir = getIntelDir();
      const category = params.category as IntelCategory;
      const filePath = join(intelDir, getFileMap()[category]);
      const key = getCollectionKeyMap()[category];
      const rawUpdates = parseYaml(params.fields, `intel_update:${category}:${params.id}`);
      if (!rawUpdates || typeof rawUpdates !== "object" || Array.isArray(rawUpdates) || Object.keys(rawUpdates).length === 0) {
        throw new Error("intel_update fields must be a non-empty YAML object/map.");
      }
      const updates = normalizeIntelEntry(params.category, rawUpdates, { partial: true });

      const result = await withIntelWriteLock(intelDir, async () => {
        const store = readYaml(filePath);
        const existing = store[key]?.[params.id];
        if (!existing) throw new Error(`Intel entry '${params.id}' not found in '${key}'. Use intel_add for new entries.`);

        const previousStatus = existing.status;
        const updatedStore = updateIntelRecord(store, key, params.id, updates, { replaceArrays: params.replace_arrays === true });
        const mergedEntry = normalizeIntelEntry(params.category, updatedStore[key][params.id]);
        const statusChanged = updates.status !== undefined && String(previousStatus || "").trim().toLowerCase() !== String(mergedEntry.status || "").trim().toLowerCase();
        if (statusChanged) {
          validateIntelStatusTransition(params.category, previousStatus, mergedEntry.status, { force: params.force === true });
        }
        validateIntelEntry(params.category, mergedEntry);
        updatedStore[key][params.id] = mergedEntry;
        writeYaml(filePath, updatedStore);

        const action = statusChanged ? timelineActionForIntelUpdate(params.category, mergedEntry.status) : "updated";
        appendTimeline(intelDir, {
          timestamp: new Date().toISOString(),
          type: params.category,
          action,
          target: params.id,
          summary: params.summary || `Updated ${params.category}: ${params.id}`,
          operator: process.env.USER || "unknown",
        });

        return {
          fieldNames: Object.keys(rawUpdates),
          previousStatus,
          currentStatus: mergedEntry.status,
          action,
        };
      });

      const statusLine = result.previousStatus !== result.currentStatus
        ? `\nStatus: ${result.previousStatus || "(unset)"} → ${result.currentStatus || "(unset)"}`
        : "";
      return {
        content: [{ type: "text", text: `Updated ${params.category} '${params.id}' in intel store.\nFile: ${filePath}\nMerged fields: ${result.fieldNames.join(", ")}${statusLine}\nTimeline action: ${result.action}` }],
        details: { category: params.category, id: params.id, file: filePath, fields: result.fieldNames, action: result.action },
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

    async execute(_toolCallId, params: IntelQueryParams, _signal, _onUpdate, _ctx) {
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
      "Secrets for rotated, expired, revoked, disabled, inactive, or invalid credentials are refused.",
      "For SSH keys: the returned key_file path can be passed to remote_connect's identity parameter.",
      "For NTLM hashes: use with Impacket tools (secretsdump.py -hashes :HASH ...).",
    ],
    parameters: Type.Object({
      id: Type.String({ description: "Credential ID from credentials.yaml" }),
    }),

    async execute(_toolCallId, params: IntelGetCredParams, _signal, _onUpdate, _ctx) {
      const intelDir = getIntelDir();

      const result = await withIntelWriteLock(intelDir, async () => {
        const credentials = readYaml(join(intelDir, "credentials.yaml")).credentials || {};
        const cred = credentials[params.id];
        if (!cred) {
          const available = Object.keys(credentials).join(", ");
          throw new Error(`Credential '${params.id}' not found. Available: ${available || "none"}`);
        }

        if (isInactiveCredentialStatus(cred.status)) {
          throw new Error(`Credential '${params.id}' has inactive status '${cred.status}'. Refusing to retrieve secret; rotate/validate or update the intel entry before operational use.`);
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

        appendTimeline(intelDir, {
          timestamp: new Date().toISOString(),
          type: "credential",
          action: "accessed",
          target: params.id,
          summary: `Credential secret accessed for operational use: ${params.id}`,
          operator: process.env.USER || "unknown",
        });

        return {
          lines,
          details: { id: params.id, type: cred.type, username: cred.username, valid_on: cred.valid_on },
        };
      });

      return {
        content: [{ type: "text", text: result.lines.join("\n") }],
        details: result.details,
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
      entry_action: Type.Optional(StringEnum(["discovered", "confirmed", "accessed", "updated", "eradicated", "rotated", "contained", "cleared"] as const)),
      target: Type.Optional(Type.String({ description: "What this entry is about" })),
      summary: Type.Optional(Type.String({ description: "One-line summary" })),
      count: Type.Optional(Type.Number({ description: "Number of recent entries to show (default: 20)" })),
      filter_host: Type.Optional(Type.String({ description: "Filter view to entries mentioning this host ID or target" })),
      filter_category: Type.Optional(StringEnum(["host", "credential", "account", "persistence", "c2", "pivot", "eradication", "containment"] as const, { description: "Filter view to this entry type" })),
      filter_action: Type.Optional(StringEnum(["discovered", "confirmed", "accessed", "updated", "eradicated", "rotated", "contained", "cleared"] as const, { description: "Filter view to this action" })),
      filter_since: Type.Optional(Type.String({ description: "Filter view to entries at or after this ISO datetime, e.g. 2026-08-25T10:00:00Z" })),
    }),

    async execute(_toolCallId, params: IntelTimelineParams, _signal, _onUpdate, _ctx) {
      const intelDir = getIntelDir();
      const timelinePath = join(intelDir, "timeline.yaml");
      const timeline = readYaml(timelinePath);
      if (!timeline.timeline) timeline.timeline = [];

      if (params.action === "add") {
        if (!params.summary) throw new Error("'summary' is required when adding a timeline entry");
        await withIntelWriteLock(intelDir, async () => {
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
        // View recent (with optional filters)
        const allEntries: any[] = timeline.timeline || [];
        const filtered = filterTimeline(allEntries, {
          host:     params.filter_host,
          category: params.filter_category,
          action:   params.filter_action,
          since:    params.filter_since,
        });
        const count = params.count || 20;
        const recent = filtered.slice(-count);
        const hasFilters = params.filter_host || params.filter_category || params.filter_action || params.filter_since;
        if (recent.length === 0) {
          return { content: [{ type: "text", text: hasFilters ? "No timeline entries match the filter criteria." : "Timeline is empty." }], details: {} };
        }
        const filterDesc = hasFilters ? ` [filtered${params.filter_host ? ` host=${params.filter_host}` : ""}${params.filter_category ? ` type=${params.filter_category}` : ""}${params.filter_action ? ` action=${params.filter_action}` : ""}${params.filter_since ? ` since=${params.filter_since}` : ""}]` : "";
        const lines = recent.map((e: any) =>
          `[${e.timestamp}] ${e.type}/${e.action} — ${e.target}: ${e.summary} (${e.operator})`
        );
        return {
          content: [{ type: "text", text: `=== Timeline (last ${recent.length} of ${filtered.length}${filtered.length !== allEntries.length ? ` matching, ${allEntries.length} total` : ""})${filterDesc} ===\n${lines.join("\n")}` }],
          details: { shown: recent.length, matched: filtered.length, total: allEntries.length },
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
  // Tool: intel_map
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "intel_map",
    label: "Intel Map",
    description: "Render a text-format attack graph: hosts by status, credential blast radius (valid_on), accounts, and pivot chains. Shows the threat shape at a glance.",
    promptSnippet: "Render text-format attack graph: blast radius, credential edges, pivot chains",
    parameters: Type.Object({}),

    async execute(_toolCallId, _params, _signal, _onUpdate, _ctx) {
      const intelDir = getIntelDir();
      const hosts       = readYaml(join(intelDir, "hosts.yaml")).hosts       || {};
      const credentials = readYaml(join(intelDir, "credentials.yaml")).credentials || {};
      const accounts    = readYaml(join(intelDir, "accounts.yaml")).accounts    || {};
      const pivots      = readYaml(join(intelDir, "pivots.yaml")).paths         || {};
      const map = buildIntelMap(hosts, credentials, accounts, pivots);
      return {
        content: [{ type: "text", text: map }],
        details: {
          hosts: Object.keys(hosts).length,
          credentials: Object.keys(credentials).length,
          accounts: Object.keys(accounts).length,
          pivots: Object.keys(pivots).length,
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
