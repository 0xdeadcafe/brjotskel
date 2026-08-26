/**
 * Remote session shared types, constants, and low-level utilities.
 *
 * Extracted from remote-session.ts so protocol adapters, the tunnel manager,
 * and the relay manager can import them without circular dependencies.
 */
import { mkdirSync, appendFileSync } from "node:fs";
import { join } from "node:path";
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

export function getLocalHostname(): string {
  return process.env.HOSTNAME || process.env.COMPUTERNAME || "unknown-host";
}

export function resolveRemoteSessionLogDir(cwd = process.cwd(), env: NodeJS.ProcessEnv = process.env): string {
  return join(env.BRJOTSKEL_LOG_DIR || join(cwd, "logs"), "remote-sessions");
}

export function getLogPath(logDir: string, sessionName: string): string {
  try { mkdirSync(logDir, { recursive: true }); } catch { /* ignore */ }
  const ts = new Date().toISOString().slice(0, 10);
  return join(logDir, `${sessionName}-${ts}.log`);
}

export function logToSession(logDir: string, sessionName: string, direction: ">>>" | "<<<" | "---", content: string): void {
  const logPath = getLogPath(logDir, sessionName);
  const ts = new Date().toISOString();
  const host = getLocalHostname();
  const line = `[${ts}] host=${host} ${direction} ${content}\n`;
  try { appendFileSync(logPath, line); } catch { /* ignore */ }
}
