/**
 * Remote session shared types, constants, and low-level utilities.
 *
 * Extracted from remote-session.ts so protocol adapters, the tunnel manager,
 * and the relay manager can import them without circular dependencies.
 */
import { mkdirSync, appendFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import type { ChildProcess } from "node:child_process";

// -------------------------------------------------------------------
// Types
// -------------------------------------------------------------------

export type Protocol = "ssh" | "winrm" | "tcp" | "telnet";
export type TunnelType = "local" | "remote" | "dynamic";

export interface SessionInfo {
  name: string;
  protocol: Protocol;
  target: string;
  connectedAt: Date;
  commandCount: number;
  lastCommandAt: Date | null;
  platform: "windows" | "linux" | "macos" | "network-device" | "unknown";
  shellFamily: "posix" | "powershell" | "cmd" | "unknown";
}

export interface RemoteSession {
  info: SessionInfo;
  process: ChildProcess;
  buffer: string;
  ready: boolean;
  commandQueue: Array<{
    id: string;
    command: string;
    marker?: string;
    resolve: (output: string) => void;
    reject: (err: Error) => void;
    timeout: ReturnType<typeof setTimeout>;
  }>;
  execChain: Promise<unknown>;
  telnetState?: {
    mode: "data" | "iac" | "iac-command" | "sb" | "sb-iac";
    command?: number;
  };
  tainted?: {
    reason: string;
    at: Date;
    command: string;
  };
}

export interface TunnelInfo {
  id: string;
  type: TunnelType;
  via: string;
  localPort: number;
  remoteHost: string;
  remotePort: number;
  process: ChildProcess;
  createdAt: Date;
  description: string;
}

export interface RelayInfo {
  id: string;
  session: string;
  method: string;
  listenPort: number;
  targetHost: string;
  targetPort: number;
  listenAddress?: string;
  createdAt: Date;
  description: string;
}

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

export const MARKER_PREFIX = "__PI_CMD_DONE_";
export const MARKER_SUFFIX = "__";
export const COMMAND_TIMEOUT_MS = 60_000;

// -------------------------------------------------------------------
// ID / marker generators
// -------------------------------------------------------------------

export function generateMarker(): string {
  return `${MARKER_PREFIX}${Date.now()}_${Math.random().toString(36).slice(2, 8)}${MARKER_SUFFIX}`;
}

export function generateId(prefix = "cmd"): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

// -------------------------------------------------------------------
// Process utilities
// -------------------------------------------------------------------

export function killTrackedProcess(proc: ChildProcess): void {
  try {
    if (proc.pid) process.kill(-proc.pid, "SIGTERM");
  } catch {
    try { proc.kill("SIGTERM"); } catch { /* ignore */ }
  }
}

// -------------------------------------------------------------------
// Logging utilities
// -------------------------------------------------------------------

export interface RemoteCommandLogEvent {
  commandId: string;
  command: string;
  status: "completed" | "timeout" | "failed";
  startedAt: Date;
  completedAt: Date;
  output: string;
  tainted?: boolean;
}

export function getLocalHostname(): string {
  return process.env.HOSTNAME || process.env.COMPUTERNAME || "unknown-host";
}

export function resolveRemoteSessionLogDir(cwd = process.cwd(), env: NodeJS.ProcessEnv = process.env): string {
  return join(env.BRJOTSKEL_LOG_DIR || join(cwd, "logs"), "remote-sessions");
}

export function sha256Text(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function allowDegradedLogging(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.BRJOTSKEL_ALLOW_DEGRADED_LOGGING === "1";
}

function appendEvidenceLine(filePath: string, line: string): void {
  try {
    appendFileSync(filePath, line);
  } catch (err: any) {
    const message = `Failed to write evidence log ${filePath}: ${err.message}`;
    if (allowDegradedLogging()) {
      console.error(`[BRJOTSKEL DEGRADED LOGGING] ${message}`);
      return;
    }
    throw new Error(message);
  }
}

function previousEntryHash(filePath: string): string | undefined {
  if (!existsSync(filePath)) return undefined;
  const lines = readFileSync(filePath, "utf-8").split(/\r?\n/).filter(line => line.trim().length > 0);
  return lines.length > 0 ? sha256Text(lines[lines.length - 1]) : undefined;
}

function addHashChain(filePath: string, event: Record<string, any>): Record<string, any> {
  const previous = previousEntryHash(filePath);
  const base = previous ? { ...event, previous_entry_hash: previous } : { ...event };
  const canonical = JSON.stringify(base, Object.keys(base).sort());
  return { ...base, entry_hash: sha256Text(canonical) };
}

export function getLogPath(logDir: string, sessionName: string): string {
  mkdirSync(logDir, { recursive: true });
  const ts = new Date().toISOString().slice(0, 10);
  return join(logDir, `${sessionName}-${ts}.log`);
}

export function getJsonlLogPath(logDir: string, sessionName: string): string {
  mkdirSync(logDir, { recursive: true });
  const ts = new Date().toISOString().slice(0, 10);
  return join(logDir, `${sessionName}-${ts}.jsonl`);
}

export function logToSession(logDir: string, sessionName: string, direction: ">>>" | "<<<" | "---", content: string): void {
  const logPath = getLogPath(logDir, sessionName);
  const ts = new Date().toISOString();
  const host = getLocalHostname();
  const line = `[${ts}] host=${host} ${direction} ${content}\n`;
  appendEvidenceLine(logPath, line);
}

export function logRemoteCommandEvent(logDir: string, session: RemoteSession, event: RemoteCommandLogEvent): void {
  const logPath = getJsonlLogPath(logDir, session.info.name);
  const outputBytes = Buffer.byteLength(event.output, "utf-8");
  const outputLines = event.output.length === 0 ? 0 : event.output.split(/\r?\n/).length;
  const payload = addHashChain(logPath, {
    ts: event.completedAt.toISOString(),
    event: "remote_command",
    command_id: event.commandId,
    session: session.info.name,
    target: session.info.target,
    protocol: session.info.protocol,
    platform: session.info.platform,
    shell: session.info.shellFamily,
    status: event.status,
    started_at: event.startedAt.toISOString(),
    completed_at: event.completedAt.toISOString(),
    duration_ms: Math.max(0, event.completedAt.getTime() - event.startedAt.getTime()),
    command: event.command,
    output_sha256: sha256Text(event.output),
    output_bytes: outputBytes,
    output_lines: outputLines,
    tainted: event.tainted === true,
  });
  appendEvidenceLine(logPath, `${JSON.stringify(payload)}\n`);
}
