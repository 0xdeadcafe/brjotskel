export type IntelCategory = "host" | "credential" | "account" | "pivot";

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

export function addIntelRecord(store: Record<string, any>, collectionKey: string, id: string, entryData: any): Record<string, any> {
  const next = { ...store };
  next[collectionKey] = { ...(next[collectionKey] || {}) };
  next[collectionKey][id] = entryData;
  return next;
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
