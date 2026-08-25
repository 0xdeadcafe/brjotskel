export type IntelCategory = "host" | "credential" | "account" | "pivot";

function isPlainObject(value: any): boolean {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function stableStringify(value: any): string {
  if (!isPlainObject(value)) return JSON.stringify(value);
  return JSON.stringify(Object.keys(value).sort().reduce((out: Record<string, any>, key) => {
    out[key] = value[key];
    return out;
  }, {}));
}

export function mergeIntelEntry(existing: any, updates: any, options: { replaceArrays?: boolean } = {}): any {
  if (!isPlainObject(existing)) return updates;
  if (!isPlainObject(updates)) return updates;

  const merged: Record<string, any> = { ...existing };
  for (const [key, value] of Object.entries(updates)) {
    if (value === undefined) continue;

    if (Array.isArray(value) && Array.isArray(merged[key]) && !options.replaceArrays) {
      const seen = new Set(merged[key].map(stableStringify));
      merged[key] = [...merged[key]];
      for (const item of value) {
        const marker = stableStringify(item);
        if (!seen.has(marker)) {
          seen.add(marker);
          merged[key].push(item);
        }
      }
      continue;
    }

    if (isPlainObject(value) && isPlainObject(merged[key])) {
      merged[key] = mergeIntelEntry(merged[key], value, options);
      continue;
    }

    merged[key] = value;
  }
  return merged;
}

export function getFileMap(): Record<IntelCategory, string> {
  return {
    host: "hosts.yaml",
    credential: "credentials.yaml",
    account: "accounts.yaml",
    pivot: "pivots.yaml",
  };
}

export function getCollectionKeyMap(): Record<IntelCategory, string> {
  return {
    host: "hosts",
    credential: "credentials",
    account: "accounts",
    pivot: "paths",
  };
}

export function addIntelRecord(store: Record<string, any>, collectionKey: string, id: string, entryData: any, options: { overwrite?: boolean } = {}): Record<string, any> {
  const next = { ...store };
  next[collectionKey] = { ...(next[collectionKey] || {}) };
  if (Object.prototype.hasOwnProperty.call(next[collectionKey], id) && !options.overwrite) {
    throw new Error(`Intel entry '${id}' already exists in '${collectionKey}'. Use overwrite=true only when replacing it intentionally.`);
  }
  next[collectionKey][id] = entryData;
  return next;
}

export function updateIntelRecord(store: Record<string, any>, collectionKey: string, id: string, updates: any, options: { replaceArrays?: boolean } = {}): Record<string, any> {
  const next = { ...store };
  next[collectionKey] = { ...(next[collectionKey] || {}) };
  if (!Object.prototype.hasOwnProperty.call(next[collectionKey], id)) {
    throw new Error(`Intel entry '${id}' not found in '${collectionKey}'. Use intel_add for new entries.`);
  }
  next[collectionKey][id] = mergeIntelEntry(next[collectionKey][id], updates, options);
  return next;
}

export function timelineActionForIntelUpdate(category: IntelCategory, status?: string): string {
  const normalizedStatus = String(status || "").trim().toLowerCase();
  if (normalizedStatus === "rotated") return "rotated";
  if (normalizedStatus === "contained") return "contained";
  if (normalizedStatus === "cleared") return "cleared";
  if (normalizedStatus === "eradicated" || normalizedStatus === "remediated") return "eradicated";
  if (normalizedStatus === "confirmed" || (category === "credential" && normalizedStatus === "active")) return "confirmed";
  return "updated";
}

const INACTIVE_CREDENTIAL_STATUSES = new Set(["rotated", "expired", "revoked", "disabled", "inactive", "invalid"]);

export function isInactiveCredentialStatus(status?: string): boolean {
  return INACTIVE_CREDENTIAL_STATUSES.has(String(status || "").trim().toLowerCase());
}

export function appendTimelineEntry(timelineDoc: Record<string, any>, entry: Record<string, any>): Record<string, any> {
  return {
    ...timelineDoc,
    timeline: [...(timelineDoc.timeline || []), entry],
  };
}

export function formatHostQueryResult(hosts: Record<string, any>, credentials: Record<string, any>, accounts: Record<string, any>, pivots: Record<string, any>, target: string): string {
  const hostInfo = hosts[target];
  const hostCreds = Object.entries(credentials).filter(([_, c]: [string, any]) => c.valid_on?.includes(target));
  const hostAccounts = Object.entries(accounts).filter(([_, a]: [string, any]) => a.access_to?.includes(target));
  const hostPivots = Object.entries(pivots).filter(([_, p]: [string, any]) => p.target === target);

  let result = `=== Host: ${target} ===\n`;
  if (hostInfo) {
    result += `IP: ${hostInfo.ip || "unknown"}\nHostname: ${hostInfo.hostname || target}\nPlatform: ${hostInfo.platform || "unknown"}\nRole: ${hostInfo.role || "unknown"}\nStatus: ${hostInfo.status || "unknown"}\nAttacker role: ${hostInfo.attacker_role || "unknown"}\n`;
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
  return result;
}

export function formatCredentialQueryResult(credentials: Record<string, any>, target: string): string {
  const cred = credentials[target];
  if (!cred) {
    return `Credential '${target}' not found.\nAvailable: ${Object.keys(credentials).join(", ") || "none"}`;
  }

  let result = `=== Credential: ${target} ===\n`;
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
  return result;
}

export function searchIntel(hosts: Record<string, any>, credentials: Record<string, any>, accounts: Record<string, any>, pivots: Record<string, any>, keyword: string): string[] {
  const kw = keyword.toLowerCase();
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

  return matches;
}

export function formatSearchResult(keyword: string, matches: string[]): string {
  let result = `Search: "${keyword}" — ${matches.length} match(es)\n`;
  result += matches.map(m => `  ${m}`).join("\n") || "  (no matches)";
  return result;
}

export function buildIntelSummary(hosts: Record<string, any>, credentials: Record<string, any>, accounts: Record<string, any>, pivots: Record<string, any>, timeline: any[], intelDir: string): string {
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

  return lines.join("\n");
}

// -------------------------------------------------------------------
// buildIntelMap — text-format attack graph
// -------------------------------------------------------------------
export function buildIntelMap(
  hosts: Record<string, any>,
  credentials: Record<string, any>,
  accounts: Record<string, any>,
  pivots: Record<string, any>,
  options?: { activeSessions?: Set<string> }
): string {
  const activeSessions = options?.activeSessions ?? new Set<string>();
  const pad = (s: string, n: number) => s.length >= n ? s : s + " ".repeat(n - s.length);
  const lines: string[] = ["=== Attack Graph ===", ""];

  // HOSTS
  const hostEntries = Object.entries(hosts) as [string, any][];
  lines.push(`HOSTS (${hostEntries.length})`);
  if (hostEntries.length === 0) {
    lines.push("  (none recorded)");
  } else {
    for (const [id, h] of hostEntries) {
      const ip       = h.ip || h.hostname || "—";
      const platform = h.platform || "—";
      const status   = h.status || "unknown";
      const session  = activeSessions.has(id) ? "  ← SESSION ACTIVE" : "";
      lines.push(`  ${pad(id, 16)}  ${pad(status, 14)}  ${pad(platform, 10)}  ${ip}${session}`);
    }
  }

  // CREDENTIALS → BLAST RADIUS
  lines.push("");
  const credEntries = Object.entries(credentials) as [string, any][];
  lines.push(`CREDENTIALS → VALID ON (${credEntries.length})`);
  if (credEntries.length === 0) {
    lines.push("  (none recorded)");
  } else {
    const inactiveStatuses = new Set(["rotated", "expired", "revoked", "disabled", "inactive", "invalid"]);
    for (const [id, c] of credEntries) {
      const type     = c.type || "?";
      const user     = c.username || "?";
      const status   = c.status || "unknown";
      const validOn  = (c.valid_on as string[] | undefined) ?? [];
      const inactive = inactiveStatuses.has(status);
      const target   = inactive ? `(${status})`
                     : validOn.length > 0 ? validOn.join(", ")
                     : "(unvalidated)";
      lines.push(`  ${pad(id, 20)}  ${pad(type, 14)}  ${pad(user, 16)}  ${pad(status, 12)}  → ${target}`);
    }
  }

  // ACCOUNTS
  lines.push("");
  const acctEntries = Object.entries(accounts) as [string, any][];
  lines.push(`ACCOUNTS (${acctEntries.length})`);
  if (acctEntries.length === 0) {
    lines.push("  (none recorded)");
  } else {
    for (const [id, a] of acctEntries) {
      const type    = a.type || "?";
      const status  = a.status || "unknown";
      const domain  = a.domain ? `${a.domain}\\` : "";
      const user    = `${domain}${a.username || id}`;
      const accTo   = ((a.access_to as string[] | undefined) ?? []).join(", ") || "—";
      lines.push(`  ${pad(user, 26)}  ${pad(type, 14)}  ${pad(status, 12)}  → ${accTo}`);
    }
  }

  // PIVOT PATHS
  lines.push("");
  const pivotEntries = Object.entries(pivots) as [string, any][];
  lines.push(`PIVOT PATHS (${pivotEntries.length})`);
  if (pivotEntries.length === 0) {
    lines.push("  (none recorded)");
  } else {
    for (const [id, p] of pivotEntries) {
      const status = p.status || "?";
      const target = p.target || "?";
      const chain  = (p.chain as any[] | undefined ?? []).map((h: any) => `${h.hop}→${h.method || "?"}`).join(" ");
      lines.push(`  ${pad(id, 18)}  ${pad(status, 12)}  ${chain}  target:${target}`);
    }
  }

  // ACTIVE SESSIONS
  if (activeSessions.size > 0) {
    lines.push("");
    lines.push(`ACTIVE SESSIONS: ${[...activeSessions].join(", ")}`);
  }

  return lines.join("\n");
}

// -------------------------------------------------------------------
// filterTimeline — apply optional filter predicates to timeline entries
// -------------------------------------------------------------------
export function filterTimeline(
  entries: any[],
  opts: { host?: string; category?: string; action?: string; since?: string }
): any[] {
  let result = entries;
  if (opts.host) {
    const h = opts.host.toLowerCase();
    result = result.filter((e: any) =>
      String(e.target || "").toLowerCase().includes(h) ||
      String(e.summary || "").toLowerCase().includes(h)
    );
  }
  if (opts.category) {
    result = result.filter((e: any) => (e.type || "") === opts.category);
  }
  if (opts.action) {
    result = result.filter((e: any) => (e.action || "") === opts.action);
  }
  if (opts.since) {
    const since = new Date(opts.since).getTime();
    if (!isNaN(since)) {
      result = result.filter((e: any) => {
        const ts = new Date(e.timestamp || 0).getTime();
        return !isNaN(ts) && ts >= since;
      });
    }
  }
  return result;
}
