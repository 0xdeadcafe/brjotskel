import { isAbsolute, join } from "node:path";

export type IntelCategory = "host" | "credential" | "account" | "pivot";

export const INTEL_STATUS_ENUMS: Record<IntelCategory, readonly string[]> = {
  host: [
    "unknown",
    "in-scope",
    "out-of-scope",
    "suspected",
    "confirmed",
    "compromised",
    "contained",
    "remediated",
    "eradicated",
    "cleared",
    "unreachable",
    "decommissioned",
  ],
  credential: [
    "unvalidated",
    "suspected",
    "compromised",
    "active",
    "confirmed",
    "invalid",
    "rotated",
    "expired",
    "revoked",
    "disabled",
    "inactive",
  ],
  account: [
    "unknown",
    "suspected",
    "confirmed",
    "compromised",
    "active",
    "contained",
    "remediated",
    "cleared",
    "disabled",
    "locked",
    "inactive",
  ],
  pivot: [
    "suspected",
    "confirmed",
    "active",
    "contained",
    "blocked",
    "cleared",
    "inactive",
  ],
};

export const CREDENTIAL_TYPE_VALUES = [
  "password",
  "ntlm-hash",
  "lm-hash",
  "ssh-key",
  "private-key",
  "kerberos-tgt",
  "kerberos-tgs",
  "token",
  "api-key",
  "cookie",
  "certificate",
  "other",
] as const;

export const ACCOUNT_TYPE_VALUES = [
  "local",
  "local-user",
  "domain",
  "domain-user",
  "service-account",
  "machine-account",
  "group",
  "cloud-user",
  "other",
] as const;

const CREDENTIAL_TERMINAL_STATUSES = new Set(["rotated", "expired", "revoked", "disabled", "inactive", "invalid"]);

function normalizeEnumValue(value: any): any {
  return typeof value === "string" ? value.trim().toLowerCase() : value;
}

function isPlainObject(value: any): boolean {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value: any): boolean {
  return typeof value === "string" && value.trim().length > 0;
}

function hasNonEmptyArray(value: any): boolean {
  return Array.isArray(value) && value.length > 0;
}

function allowed(values: readonly string[]): string {
  return values.join(", ");
}

function validateRequiredString(entryData: any, field: string, errors: string[], label = field): void {
  if (!nonEmptyString(entryData[field])) errors.push(`Missing required '${label}' string.`);
}

function validateEnum(value: any, values: readonly string[], field: string, errors: string[]): void {
  if (value === undefined || value === null || value === "") return;
  if (!nonEmptyString(value) || !values.includes(String(value))) {
    errors.push(`Invalid '${field}' value '${String(value)}'. Allowed values: ${allowed(values)}.`);
  }
}

function validateStringArray(value: any, field: string, errors: string[]): void {
  if (value === undefined || value === null) return;
  if (!Array.isArray(value)) {
    errors.push(`Field '${field}' must be a list of strings.`);
    return;
  }
  value.forEach((item, idx) => {
    if (!nonEmptyString(item)) errors.push(`Field '${field}[${idx}]' must be a non-empty string.`);
  });
}

function validateSource(entryData: any, errors: string[]): void {
  if (!entryData.source) {
    errors.push("Missing required 'source.method'. Include provenance for how this intel was discovered (and source.host/source.path when available).");
    return;
  }
  const source = normalizeSource(entryData.source);
  if (!isPlainObject(source)) {
    errors.push("Field 'source' must be a map/object or shorthand string with at least 'method'.");
    return;
  }
  if (!nonEmptyString(source.method)) {
    errors.push("Missing required 'source.method'. Describe how this intel was discovered, e.g. 'PSReadLine history' or 'live triage'.");
  }
  for (const field of ["host", "path", "tool", "playbook"] as const) {
    if (source[field] !== undefined && !nonEmptyString(source[field])) {
      errors.push(`Field 'source.${field}' must be a non-empty string when present.`);
    }
  }
}

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

export function normalizeIntelEntry(category: IntelCategory, entryData: any, options: { partial?: boolean } = {}): any {
  if (!entryData || typeof entryData !== "object" || Array.isArray(entryData)) return entryData;
  const normalized = { ...entryData };
  const shouldNormalize = (field: string) => !options.partial || Object.prototype.hasOwnProperty.call(normalized, field);

  if (typeof normalized.status === "string") normalized.status = normalizeEnumValue(normalized.status);
  if ((category === "credential" || category === "account") && typeof normalized.type === "string") {
    normalized.type = normalizeEnumValue(normalized.type);
  }

  if (normalized.source) normalized.source = normalizeSource(normalized.source);
  if (normalized.discovered && typeof normalized.discovered === "object" && !Array.isArray(normalized.discovered)) {
    normalized.discovered = { ...normalized.discovered };
    if (!normalized.discovered.source && normalized.source?.method) normalized.discovered.source = normalized.source.method;
  }

  if (category === "host") {
    if (normalized.access && typeof normalized.access === "object" && !Array.isArray(normalized.access)) {
      normalized.access = { ...normalized.access };
    }
    if (shouldNormalize("endpoints")) normalized.endpoints = ensureArray(normalized.endpoints);
    if (shouldNormalize("profile_artifacts")) normalized.profile_artifacts = ensureArray(normalized.profile_artifacts);
  }

  if (category === "credential") {
    if (shouldNormalize("valid_on")) normalized.valid_on = ensureArray(normalized.valid_on);
    if (shouldNormalize("related_hosts")) normalized.related_hosts = ensureArray(normalized.related_hosts);
  }

  if (category === "account") {
    if (shouldNormalize("privileges")) normalized.privileges = ensureArray(normalized.privileges);
    if (shouldNormalize("access_to")) normalized.access_to = ensureArray(normalized.access_to);
    if (shouldNormalize("credentials")) normalized.credentials = ensureArray(normalized.credentials);
    if (shouldNormalize("related_hosts")) normalized.related_hosts = ensureArray(normalized.related_hosts);
  }

  if (category === "pivot") {
    if (shouldNormalize("chain")) normalized.chain = ensureArray(normalized.chain);
    if (shouldNormalize("evidence")) normalized.evidence = ensureArray(normalized.evidence);
    if (shouldNormalize("related_hosts")) normalized.related_hosts = ensureArray(normalized.related_hosts);
  }

  return normalized;
}

export function validateIntelEntry(category: IntelCategory, entryData: any): void {
  if (!entryData || typeof entryData !== "object" || Array.isArray(entryData)) {
    throw new Error("Intel entry must be a YAML object/map.");
  }

  const errors: string[] = [];
  validateRequiredString(entryData, "status", errors);
  validateEnum(entryData.status, INTEL_STATUS_ENUMS[category], "status", errors);
  validateSource(entryData, errors);

  if (category === "host") {
    const hasLocator = nonEmptyString(entryData.ip)
      || nonEmptyString(entryData.hostname)
      || hasNonEmptyArray(entryData.endpoints)
      || hasNonEmptyArray(entryData.profile_artifacts);
    if (!hasLocator) {
      errors.push("Host entries require at least one locator: 'ip', 'hostname', non-empty 'endpoints', or non-empty 'profile_artifacts'.");
    }
    validateStringArray(entryData.endpoints, "endpoints", errors);
    validateStringArray(entryData.profile_artifacts, "profile_artifacts", errors);
    if (entryData.access !== undefined && !isPlainObject(entryData.access)) errors.push("Field 'access' must be a map/object when present.");
    if (entryData.access?.port !== undefined && (!Number.isInteger(entryData.access.port) || entryData.access.port < 1 || entryData.access.port > 65535)) {
      errors.push("Field 'access.port' must be an integer from 1 to 65535.");
    }
  }

  if (category === "credential") {
    validateRequiredString(entryData, "type", errors);
    validateRequiredString(entryData, "username", errors);
    validateEnum(entryData.type, CREDENTIAL_TYPE_VALUES, "type", errors);
    validateStringArray(entryData.valid_on, "valid_on", errors);
    validateStringArray(entryData.related_hosts, "related_hosts", errors);
    const hasMaterial = nonEmptyString(entryData.secret) || nonEmptyString(entryData.key_file) || nonEmptyString(entryData.ticket_file);
    if (!hasMaterial) {
      errors.push("Credential entries require credential material: provide 'secret', 'key_file', or 'ticket_file'.");
    }
    if ((entryData.type === "ssh-key" || entryData.type === "private-key" || entryData.type === "certificate") && !nonEmptyString(entryData.key_file) && !nonEmptyString(entryData.secret)) {
      errors.push(`Credential type '${entryData.type}' requires 'key_file' or 'secret'.`);
    }
    if ((entryData.type === "kerberos-tgt" || entryData.type === "kerberos-tgs") && !nonEmptyString(entryData.ticket_file) && !nonEmptyString(entryData.secret)) {
      errors.push(`Credential type '${entryData.type}' requires 'ticket_file' or 'secret'.`);
    }
  }

  if (category === "account") {
    validateRequiredString(entryData, "type", errors);
    validateRequiredString(entryData, "username", errors);
    validateEnum(entryData.type, ACCOUNT_TYPE_VALUES, "type", errors);
    validateStringArray(entryData.privileges, "privileges", errors);
    validateStringArray(entryData.access_to, "access_to", errors);
    validateStringArray(entryData.credentials, "credentials", errors);
    validateStringArray(entryData.related_hosts, "related_hosts", errors);
  }

  if (category === "pivot") {
    validateRequiredString(entryData, "target", errors);
    if (!hasNonEmptyArray(entryData.chain)) {
      errors.push("Pivot entries require a non-empty 'chain' list with at least one hop.");
    } else {
      entryData.chain.forEach((hop: any, idx: number) => {
        if (!isPlainObject(hop)) {
          errors.push(`Field 'chain[${idx}]' must be a map/object.`);
          return;
        }
        if (!nonEmptyString(hop.hop)) errors.push(`Field 'chain[${idx}].hop' is required.`);
        if (hop.method !== undefined && !nonEmptyString(hop.method)) errors.push(`Field 'chain[${idx}].method' must be a non-empty string when present.`);
      });
    }
    if (entryData.evidence !== undefined && !Array.isArray(entryData.evidence)) errors.push("Field 'evidence' must be a list when present.");
    validateStringArray(entryData.related_hosts, "related_hosts", errors);
  }

  if (errors.length > 0) {
    throw new Error(`Invalid ${category} intel entry:\n- ${errors.join("\n- ")}`);
  }
}

export function validateIntelStatusTransition(category: IntelCategory, fromStatus: any, toStatus: any, options: { force?: boolean } = {}): void {
  const from = normalizeEnumValue(fromStatus);
  const to = normalizeEnumValue(toStatus);
  if (!to || from === to) return;

  const allowedStatuses = INTEL_STATUS_ENUMS[category];
  if (!allowedStatuses.includes(to)) {
    throw new Error(`Invalid ${category} status transition target '${String(toStatus)}'. Allowed values: ${allowed(allowedStatuses)}.`);
  }

  if (category === "credential" && CREDENTIAL_TERMINAL_STATUSES.has(from) && !CREDENTIAL_TERMINAL_STATUSES.has(to) && !options.force) {
    throw new Error(`Refusing credential status transition '${from}' → '${to}' without force=true. Prefer creating a new credential ID for replacement secrets, or force only when correcting intel.`);
  }
}

export function resolveStoredPath(intelDir: string, path?: string): string {
  if (!path) return "(not stored)";
  return isAbsolute(path) ? path : join(intelDir, path);
}
