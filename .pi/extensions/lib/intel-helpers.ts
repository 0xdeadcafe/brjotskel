import { isAbsolute, join } from "node:path";

export function resolveIntelDir(cwd: string, envIntelDir?: string): string {
  return envIntelDir || join(cwd, "workspace", "intel");
}

export function ensureArray<T>(value: T | T[] | undefined | null): T[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

export function normalizeSource(source: any): any {
  if (!source) return undefined;
  if (typeof source === "string") return { method: source };
  if (typeof source !== "object" || Array.isArray(source)) return { method: String(source) };

  const out = { ...source };
  if (!out.method && out.discovered_from) out.method = out.discovered_from;
  return out;
}

export function normalizeIntelEntry(category: "host" | "credential" | "account" | "pivot", entryData: any): any {
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

export function validateIntelEntry(category: "host" | "credential" | "account" | "pivot", entryData: any): void {
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

export function resolveStoredPath(intelDir: string, path?: string): string {
  if (!path) return "(not stored)";
  return isAbsolute(path) ? path : join(intelDir, path);
}
