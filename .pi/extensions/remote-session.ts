/**
 * Remote Shell Session Manager Extension — Multi-Session
 *
 * Provides persistent remote shell sessions that the agent can interact with
 * over SSH, WinRM/PowerShell Remoting, raw TCP, or telnet.
 *
 * Supports MULTIPLE concurrent sessions for threat pursuit workflows:
 *   - Connect to several compromised hosts simultaneously
 *   - Pivot through chains of hosts
 *   - Compare state across systems
 *   - Maintain access while mapping attacker infrastructure
 *
 * Sessions maintain state (cwd, environment, variables) across commands,
 * unlike one-shot SSH execution where each command starts fresh.
 *
 * Usage:
 *   Place in .pi/extensions/ for auto-discovery
 *
 * Registered tools:
 *   remote_connect     — Establish a named session (SSH, WinRM, TCP, or telnet)
 *   remote_exec        — Execute a command in a session (by name or default)
 *   remote_upload      — Upload text content to remote via stdin pipe
 *   remote_sessions    — List all active sessions and tunnels
 *   remote_disconnect  — Close a specific session or all sessions
 *   remote_tunnel      — Create SSH port forward (local, remote, or dynamic SOCKS)
 *   remote_tunnel_close — Close a specific tunnel or all tunnels
 *
 * Slash commands:
 *   /remote-connect ssh user@host --name pivot01
 *   /remote-disconnect pivot01
 *   /remote-disconnect --all
 *   /sessions
 *   /tunnels
 *
 * Multi-session workflow example:
 *   remote_connect(protocol="ssh", target="admin@compromised-web", name="web01")
 *   remote_connect(protocol="ssh", target="root@compromised-db", name="db01")
 *   remote_exec(session="web01", command="cat /etc/shadow")
 *   remote_exec(session="db01", command="ss -tunap")
 *
 * Multi-hop pivot example:
 *   remote_tunnel(type="local", via="user@jumpbox", local_port=2222, remote_host="internal", remote_port=22)
 *   remote_connect(protocol="ssh", target="admin@localhost", port=2222, name="internal01")
 *   remote_exec(session="internal01", command="whoami")
 *
 * Design Principles:
 *   - Living off the Land: uses ssh/nc already in the container
 *   - No binaries uploaded to the target
 *   - Sessions are persistent (kept-alive with marker-based output detection)
 *   - All commands are audit-logged
 *   - Output is truncated per pi conventions (50KB / 2000 lines)
 *
 * Container Dependencies:
 *   - openssh-client (ssh) — included in Docker image
 *   - netcat-openbsd (nc) — included in Docker image
 *   - pwsh (PowerShell) — optional, for WinRM
 */

import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, appendFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { Type } from "typebox";
import { StringEnum } from "@earendil-works/pi-ai";
import { psSingleQuote, shellSingleQuote, detectSshShell, cleanCommandOutput, type ShellFamily } from "./lib/remote-helpers.ts";
import { chooseSessionName, buildMarkerCommand, buildTunnelSpec, buildTunnelDescription, buildTunnelUsageHint, processTelnetBytes, parseWinRmTarget } from "./lib/remote-session-core.ts";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { truncateTail, DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES, formatSize } from "@earendil-works/pi-coding-agent";

// -------------------------------------------------------------------
// Types
// -------------------------------------------------------------------

type Protocol = "ssh" | "winrm" | "tcp" | "telnet";
type TunnelType = "local" | "remote" | "dynamic";

interface SessionInfo {
  name: string;
  protocol: Protocol;
  target: string;
  connectedAt: Date;
  commandCount: number;
  lastCommandAt: Date | null;
  platform: "windows" | "linux" | "macos" | "network-device" | "unknown";
  shellFamily: "posix" | "powershell" | "cmd" | "unknown";
}


interface RemoteSession {
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
}

interface TunnelInfo {
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

// -------------------------------------------------------------------
// Marker for command boundary detection
// -------------------------------------------------------------------
const MARKER_PREFIX = "__PI_CMD_DONE_";
const MARKER_SUFFIX = "__";

function generateMarker(): string {
  return `${MARKER_PREFIX}${Date.now()}_${Math.random().toString(36).slice(2, 8)}${MARKER_SUFFIX}`;
}

function generateId(prefix = "cmd"): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

// -------------------------------------------------------------------
// Session Manager State
// -------------------------------------------------------------------

const sessions = new Map<string, RemoteSession>();
const activeTunnels: TunnelInfo[] = [];
let tunnelCounter = 0;
let defaultSessionName: string | null = null;

const LOG_DIR = join(process.env.BRJOTSKEL_LOG_DIR || join(process.cwd(), "logs"), "remote-sessions");
const COMMAND_TIMEOUT_MS = 60_000;


function killTrackedProcess(proc: ChildProcess): void {
  try {
    if (proc.pid) process.kill(-proc.pid, "SIGTERM");
  } catch {
    try { proc.kill("SIGTERM"); } catch { /* ignore */ }
  }
}

function processTelnetChunk(session: RemoteSession, data: Buffer): string {
  const result = processTelnetBytes(session.telnetState, data);
  for (const reply of result.replies) {
    session.process.stdin?.write(Buffer.from(reply));
  }
  session.telnetState = result.state;
  return result.text;
}

function getLocalHostname(): string {
  return process.env.HOSTNAME || process.env.COMPUTERNAME || "unknown-host";
}

function getLogPath(sessionName: string): string {
  try { mkdirSync(LOG_DIR, { recursive: true }); } catch { /* ignore */ }
  const ts = new Date().toISOString().slice(0, 10);
  return join(LOG_DIR, `${sessionName}-${ts}.log`);
}

function logToSession(sessionName: string, direction: ">>>" | "<<<" | "---", content: string): void {
  const logPath = getLogPath(sessionName);
  const ts = new Date().toISOString();
  const host = getLocalHostname();
  const line = `[${ts}] host=${host} ${direction} ${content}\n`;
  try { appendFileSync(logPath, line); } catch { /* ignore */ }
}

function getSession(name?: string): RemoteSession {
  const selectedName = chooseSessionName(name, [...sessions.keys()], defaultSessionName);
  return sessions.get(selectedName)!;
}

// -------------------------------------------------------------------
// SSH Connection
// -------------------------------------------------------------------


function connectSSH(name: string, target: string, options: { port?: number; identity?: string; proxyJump?: string; password?: string; platformHint?: SessionInfo["platform"]; shellHint?: ShellFamily } = {}): Promise<RemoteSession> {
  return new Promise((resolve, reject) => {
    const args = [
      "-tt",
      "-o", "StrictHostKeyChecking=accept-new",
      "-o", "ServerAliveInterval=30",
      "-o", "ServerAliveCountMax=3",
      "-o", "LogLevel=ERROR",
      "-o", "PreferredAuthentications=publickey,password,keyboard-interactive",
    ];
    if (options.port) args.push("-p", String(options.port));
    if (options.identity) args.push("-i", options.identity);
    if (options.proxyJump) args.push("-J", options.proxyJump);
    args.push(target);

    const sshpassPath = existsSync("/usr/bin/sshpass") ? "/usr/bin/sshpass" : (existsSync("/bin/sshpass") ? "/bin/sshpass" : null);
    if (options.password && !sshpassPath) {
      reject(new Error("SSH password authentication requested, but sshpass is not installed in the container. Install sshpass or use key-based auth / remote_connect(password=...)."));
      return;
    }

    const proc = options.password
      ? spawn(sshpassPath!, ["-e", "ssh", ...args], {
          stdio: ["pipe", "pipe", "pipe"],
          env: { ...process.env, TERM: "dumb", SSHPASS: options.password },
        })
      : spawn("ssh", args, {
          stdio: ["pipe", "pipe", "pipe"],
          env: { ...process.env, TERM: "dumb" },
        });

    const session: RemoteSession = {
      info: {
        name,
        protocol: "ssh",
        target,
        connectedAt: new Date(),
        commandCount: 0,
        lastCommandAt: null,
        platform: options.platformHint || "unknown",
        shellFamily: options.shellHint || (options.platformHint === "linux" || options.platformHint === "macos" ? "posix" : "unknown"),
      },
      process: proc,
      buffer: "",
      ready: false,
      commandQueue: [],
      execChain: Promise.resolve(),
    };

    let connectTimeout = setTimeout(() => {
      proc.kill();
      reject(new Error(`SSH connection to ${target} timed out (30s)`));
    }, 30_000);

    proc.stdout!.on("data", (data: Buffer) => {
      const text = data.toString();
      session.buffer += text;

      if (!session.ready) {
        const detected = detectSshShell(session.buffer, options.platformHint, options.shellHint);
        if (detected) {
          session.info.platform = detected.platform;
          session.info.shellFamily = detected.shellFamily;
          session.ready = true;
          clearTimeout(connectTimeout);
          resolve(session);
          return;
        }
      }

      // Check command queue for marker completion
      const item = session.commandQueue[0];
      if (item?.marker) {
        const markerStart = session.buffer.indexOf(item.marker);
        if (markerStart !== -1) {
          const output = session.buffer.slice(0, markerStart).trim();
          session.buffer = session.buffer.slice(markerStart + item.marker.length);
          session.commandQueue.shift();
          clearTimeout(item.timeout);
          item.resolve(output);
        }
      }
    });

    proc.stderr!.on("data", (data: Buffer) => {
      const text = data.toString();
      if (text.includes("Permission denied") || text.includes("Connection refused") ||
          text.includes("No route to host") || text.includes("Connection timed out")) {
        clearTimeout(connectTimeout);
        proc.kill();
        reject(new Error(`SSH connection failed: ${text.trim()}`));
      }
    });

    proc.on("close", (code) => {
      clearTimeout(connectTimeout);
      if (!session.ready) {
        reject(new Error(`SSH process exited with code ${code} before session was ready`));
      }
      for (const item of session.commandQueue) {
        clearTimeout(item.timeout);
        item.reject(new Error("Session closed"));
      }
      session.commandQueue = [];
      sessions.delete(name);
      if (defaultSessionName === name) defaultSessionName = null;
    });

    proc.on("error", (err) => {
      clearTimeout(connectTimeout);
      reject(new Error(`Failed to spawn SSH: ${err.message}`));
    });
  });
}

// -------------------------------------------------------------------
// WinRM Connection (via PowerShell)
// -------------------------------------------------------------------

function connectWinRM(name: string, target: string, options: { user?: string; password?: string; port?: number } = {}): Promise<RemoteSession> {
  return new Promise((resolve, reject) => {
    const parsed = parseWinRmTarget(target, options.user);
    const safeTarget = psSingleQuote(parsed.computerName);
    const portArg = options.port ? ` -Port ${options.port}` : "";
    const psCommand = options.password
      ? `$pw = ConvertTo-SecureString '${psSingleQuote(options.password)}' -AsPlainText -Force; $cred = New-Object PSCredential('${psSingleQuote(parsed.user || "")}', $pw); Enter-PSSession -ComputerName '${safeTarget}'${portArg} -Credential $cred`
      : `Enter-PSSession -ComputerName '${safeTarget}'${portArg}`;

    const proc = spawn("pwsh", ["-NoProfile", "-NoLogo", "-Command", "-"], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, TERM: "dumb" },
    });

    const session: RemoteSession = {
      info: {
        name,
        protocol: "winrm",
        target,
        connectedAt: new Date(),
        commandCount: 0,
        lastCommandAt: null,
        platform: "windows",
        shellFamily: "powershell",
      },
      process: proc,
      buffer: "",
      ready: false,
      commandQueue: [],
      execChain: Promise.resolve(),
    };

    proc.stdin!.write(psCommand + "\n");

    let connectTimeout = setTimeout(() => {
      proc.kill();
      reject(new Error(`WinRM connection to ${target} timed out (30s)`));
    }, 30_000);

    proc.stdout!.on("data", (data: Buffer) => {
      session.buffer += data.toString();

      if (!session.ready && session.buffer.includes("PS ")) {
        session.ready = true;
        clearTimeout(connectTimeout);
        session.buffer = "";
        resolve(session);
      }

      const item = session.commandQueue[0];
      if (item?.marker) {
        const markerStart = session.buffer.indexOf(item.marker);
        if (markerStart !== -1) {
          const output = session.buffer.slice(0, markerStart).trim();
          session.buffer = session.buffer.slice(markerStart + item.marker.length);
          session.commandQueue.shift();
          clearTimeout(item.timeout);
          item.resolve(output);
        }
      }
    });

    proc.stderr!.on("data", (data: Buffer) => {
      const text = data.toString();
      if (text.includes("Access is denied") || text.includes("WinRM cannot")) {
        clearTimeout(connectTimeout);
        proc.kill();
        reject(new Error(`WinRM connection failed: ${text.trim()}`));
      }
    });

    proc.on("close", () => {
      clearTimeout(connectTimeout);
      for (const item of session.commandQueue) {
        clearTimeout(item.timeout);
        item.reject(new Error("Session closed"));
      }
      sessions.delete(name);
      if (defaultSessionName === name) defaultSessionName = null;
    });

    proc.on("error", (err) => {
      clearTimeout(connectTimeout);
      reject(new Error(`Failed to spawn pwsh for WinRM: ${err.message}`));
    });
  });
}

// -------------------------------------------------------------------
// TCP / Telnet Connection (network devices / legacy services)
// -------------------------------------------------------------------

function connectTCP(name: string, host: string, port: number): Promise<RemoteSession> {
  return new Promise((resolve, reject) => {
    const proc = spawn("nc", [host, String(port)], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    const session: RemoteSession = {
      info: {
        name,
        protocol: "tcp",
        target: `${host}:${port}`,
        connectedAt: new Date(),
        commandCount: 0,
        lastCommandAt: null,
        platform: "unknown",
        shellFamily: "unknown",
      },
      process: proc,
      buffer: "",
      ready: false,
      commandQueue: [],
      execChain: Promise.resolve(),
    };

    let connectTimeout = setTimeout(() => {
      proc.kill();
      reject(new Error(`TCP connection to ${host}:${port} timed out (15s)`));
    }, 15_000);

    proc.stdout!.on("data", (data: Buffer) => {
      session.buffer += data.toString();
      if (!session.ready) {
        session.ready = true;
        clearTimeout(connectTimeout);
        if (session.buffer.match(/[#>]\s*$/)) {
          session.info.platform = "network-device";
          session.info.shellFamily = "unknown";
        }
        resolve(session);
      }
    });

    proc.on("close", () => {
      clearTimeout(connectTimeout);
      sessions.delete(name);
      if (defaultSessionName === name) defaultSessionName = null;
    });

    proc.on("error", (err) => {
      clearTimeout(connectTimeout);
      reject(new Error(`TCP connection failed: ${err.message}`));
    });
  });
}

function connectTelnet(name: string, host: string, port: number): Promise<RemoteSession> {
  return new Promise((resolve, reject) => {
    const proc = spawn("nc", [host, String(port)], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    const session: RemoteSession = {
      info: {
        name,
        protocol: "telnet",
        target: `${host}:${port}`,
        connectedAt: new Date(),
        commandCount: 0,
        lastCommandAt: null,
        platform: "unknown",
        shellFamily: "unknown",
      },
      process: proc,
      buffer: "",
      ready: false,
      commandQueue: [],
      execChain: Promise.resolve(),
      telnetState: { mode: "data" },
    };

    let connectTimeout = setTimeout(() => {
      proc.kill();
      reject(new Error(`Telnet connection to ${host}:${port} timed out (15s)`));
    }, 15_000);

    proc.stdout!.on("data", (data: Buffer) => {
      const text = processTelnetChunk(session, data);
      session.buffer += text;
      if (!session.ready && text.length > 0) {
        session.ready = true;
        clearTimeout(connectTimeout);
        if (session.buffer.match(/[#>:]\s*$/)) {
          session.info.platform = "network-device";
          session.info.shellFamily = "unknown";
        }
        resolve(session);
      }
    });

    proc.on("close", () => {
      clearTimeout(connectTimeout);
      sessions.delete(name);
      if (defaultSessionName === name) defaultSessionName = null;
    });

    proc.on("error", (err) => {
      clearTimeout(connectTimeout);
      reject(new Error(`Telnet connection failed: ${err.message}`));
    });
  });
}

// -------------------------------------------------------------------
// Command Execution
// -------------------------------------------------------------------


function execCommand(session: RemoteSession, command: string, timeoutMs = COMMAND_TIMEOUT_MS): Promise<string> {
  session.execChain = session.execChain.catch(() => undefined).then(() => new Promise<string>((resolve, reject) => {
    if (!session.process || session.process.killed) {
      sessions.delete(session.info.name);
      reject(new Error(`Session '${session.info.name}' has been disconnected.`));
      return;
    }

    session.info.commandCount++;
    session.info.lastCommandAt = new Date();
    logToSession(session.info.name, ">>>", command);

    if (session.info.protocol === "tcp" || session.info.protocol === "telnet") {
      // TCP/telnet modes are best-effort only: output is collected by timeout/prompt heuristics.
      session.buffer = "";
      session.process.stdin!.write(command + "\r\n");

      const collectTimeout = setTimeout(() => {
        const output = session.buffer.trim();
        session.buffer = "";
        logToSession(session.info.name, "<<<", output);
        resolve(output);
      }, Math.min(timeoutMs, 5000));

      const checkInterval = setInterval(() => {
        if (session.buffer.match(/[#>$%]\s*$/)) {
          clearTimeout(collectTimeout);
          clearInterval(checkInterval);
          const output = session.buffer.trim();
          session.buffer = "";
          logToSession(session.info.name, "<<<", output);
          resolve(output);
        }
      }, 200);

      setTimeout(() => clearInterval(checkInterval), timeoutMs);
      return;
    }

    const marker = generateMarker();
    const commandId = generateId();
    session.buffer = "";

    const timeout = setTimeout(() => {
      const idx = session.commandQueue.findIndex(q => q.id === commandId);
      if (idx !== -1) session.commandQueue.splice(idx, 1);
      const partial = session.buffer.trim();
      session.buffer = "";
      logToSession(session.info.name, "<<<", `[TIMEOUT after ${timeoutMs / 1000}s] ${partial}`);
      resolve(`[Command timed out after ${timeoutMs / 1000}s]\n${partial}`);
    }, timeoutMs);

    session.commandQueue.push({
      id: commandId,
      command,
      marker,
      resolve: (output) => {
        const cleaned = cleanCommandOutput(session, command, output);
        logToSession(session.info.name, "<<<", cleaned);
        resolve(cleaned);
      },
      reject,
      timeout,
    });

    session.process.stdin!.write(buildMarkerCommand(session.info.shellFamily, command, marker) + "\n");
  }));

  return session.execChain as Promise<string>;
}

// -------------------------------------------------------------------
// Extension Registration
// -------------------------------------------------------------------

export default function (pi: ExtensionAPI) {

  // -------------------------------------------------------------------
  // Tool: remote_connect
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "remote_connect",
    label: "Remote Connect",
    description: "Establish a persistent remote shell session via SSH, WinRM, TCP, or telnet. Supports multiple concurrent sessions identified by name. Sessions maintain state (cwd, env) across commands. Supports ProxyJump for multi-hop pivoting. TCP and telnet modes are best-effort for line-oriented or legacy services.",
    promptSnippet: "Connect to a remote host for interactive investigation (SSH/WinRM/TCP). Supports multiple named sessions.",
    promptGuidelines: [
      "Use remote_connect to establish a persistent named session before running remote_exec commands.",
      "Give each session a meaningful name (e.g., 'web01', 'dc01', 'pivot-box') for clarity.",
      "Use remote_disconnect when investigation of a host is complete.",
      "For password-based SSH, pass the password directly to remote_connect rather than shelling out to sshpass manually.",
      "If SSH auto-detection is unreliable, set platform_hint (e.g., linux) and/or shell_hint (e.g., posix) so remote_exec uses the correct shell markers.",
      "For pivoting: use proxy_jump parameter or remote_tunnel + connect to localhost.",
      "Multiple sessions can be active simultaneously for cross-host investigation.",
    ],
    parameters: Type.Object({
      protocol: StringEnum(["ssh", "winrm", "tcp", "telnet"] as const),
      target: Type.String({ description: "Connection target: user@host or host for SSH/WinRM, host:port for TCP/telnet" }),
      name: Type.String({ description: "Session name for identification (e.g., 'web01', 'dc01', 'pivot-host')" }),
      port: Type.Optional(Type.Number({ description: "Override port (SSH default: 22, WinRM: 5985, TCP: required in target)" })),
      identity: Type.Optional(Type.String({ description: "SSH identity file path (e.g., recovered key from compromised host)" })),
      proxy_jump: Type.Optional(Type.String({ description: "SSH ProxyJump host for multi-hop (e.g., 'user@jumpbox' or 'user@hop1,user@hop2')" })),
      user: Type.Optional(Type.String({ description: "Username for WinRM" })),
      password: Type.Optional(Type.String({ description: "Password for SSH or WinRM. For SSH, remote_connect uses sshpass when available." })),
      platform_hint: Type.Optional(Type.String({ description: "Override/assist platform detection when the remote shell is known or auto-detection is unreliable (e.g., linux, windows, macos, network-device)" })),
      shell_hint: Type.Optional(Type.String({ description: "Override shell framing when known (posix, powershell, cmd). Useful when auto-detection is unreliable." })),
      set_default: Type.Optional(Type.Boolean({ description: "Set this as the default session for remote_exec (default: true if first session)" })),
    }),

    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      if (sessions.has(params.name)) {
        throw new Error(`Session '${params.name}' already exists. Disconnect it first or use a different name.`);
      }

      // Safety: require analyst confirmation
      if (ctx.hasUI) {
        const confirmed = await ctx.ui.confirm(
          "Remote Connection",
          `Connect to ${params.target} via ${params.protocol.toUpperCase()} as session '${params.name}'?`,
        );
        if (!confirmed) {
          throw new Error("Connection cancelled by operator");
        }
      }

      logToSession(params.name, "---", `[SESSION START] ${params.protocol}://${params.target}`);

      try {
        let session: RemoteSession;

        switch (params.protocol) {
          case "ssh":
            session = await connectSSH(params.name, params.target, {
              port: params.port,
              identity: params.identity,
              proxyJump: params.proxy_jump,
              password: params.password,
              platformHint: params.platform_hint as SessionInfo["platform"] | undefined,
              shellHint: params.shell_hint as ShellFamily | undefined,
            });
            break;
          case "winrm":
            session = await connectWinRM(params.name, params.target, {
              user: params.user,
              password: params.password,
              port: params.port,
            });
            break;
          case "tcp": {
            const [host, portStr] = params.target.includes(":") ? params.target.split(":") : [params.target, "23"];
            const port = params.port || parseInt(portStr, 10);
            session = await connectTCP(params.name, host, port);
            break;
          }
          case "telnet": {
            const [host, portStr] = params.target.includes(":") ? params.target.split(":") : [params.target, "23"];
            const port = params.port || parseInt(portStr, 10);
            session = await connectTelnet(params.name, host, port);
            break;
          }
        }

        sessions.set(params.name, session!);

        // Set default session
        if (params.set_default !== false && (sessions.size === 1 || params.set_default === true)) {
          defaultSessionName = params.name;
        }

        if (ctx.hasUI) {
          const sessionList = [...sessions.keys()].join(", ");
          ctx.ui.setStatus("remote", ctx.ui.theme.fg("accent", `🔗 Sessions: ${sessionList}`));
        }

        const proxyInfo = params.proxy_jump ? `\nProxy jump: ${params.proxy_jump}` : "";
        const modeNote = params.protocol === "tcp"
          ? "\nMode: TCP best-effort (raw line-oriented service)"
          : params.protocol === "telnet"
            ? "\nMode: Telnet best-effort with basic option negotiation"
            : "";
        return {
          content: [{ type: "text", text: `Connected: session '${params.name}' → ${params.target} via ${params.protocol.toUpperCase()}\nPlatform: ${session!.info.platform}${proxyInfo}${modeNote}\nActive sessions: ${sessions.size}\nLog: ${getLogPath(params.name)}` }],
          details: { session: session!.info, totalSessions: sessions.size },
        };
      } catch (err: any) {
        throw new Error(`Connection failed: ${err.message}`);
      }
    },
  });

  // -------------------------------------------------------------------
  // Tool: remote_exec
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "remote_exec",
    label: "Remote Exec",
    description: "Execute a command in a remote shell session. Specify session by name, or uses default/only session. Session maintains state (cwd, env variables) between calls.",
    promptSnippet: "Run a command in a named remote shell session",
    promptGuidelines: [
      "Use remote_exec after remote_connect has established a session.",
      "Specify session name when multiple sessions are active.",
      "Session state persists — cd, export, variable assignments carry across calls.",
      "Prefer native OS commands — do not upload binaries to remote hosts.",
    ],
    parameters: Type.Object({
      command: Type.String({ description: "Command to execute in the remote shell" }),
      session: Type.Optional(Type.String({ description: "Session name (required if multiple sessions are active)" })),
      timeout: Type.Optional(Type.Number({ description: "Timeout in seconds (default: 60)" })),
    }),

    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      const session = getSession(params.session);

      if (!session.process || session.process.killed) {
        sessions.delete(session.info.name);
        throw new Error(`Session '${session.info.name}' has been disconnected. Use remote_connect to reconnect.`);
      }

      const timeoutMs = (params.timeout || 60) * 1000;
      const output = await execCommand(session, params.command, timeoutMs);

      const truncation = truncateTail(output, {
        maxLines: DEFAULT_MAX_LINES,
        maxBytes: DEFAULT_MAX_BYTES,
      });

      let result = truncation.content;
      if (truncation.truncated) {
        result += `\n\n[Output truncated: ${truncation.outputLines} lines shown of ${truncation.totalLines} total (${formatSize(truncation.outputBytes)} of ${formatSize(truncation.totalBytes)}). Full output in session log.]`;
      }

      return {
        content: [{ type: "text", text: result || "(no output)" }],
        details: {
          session: session.info.name,
          target: session.info.target,
          command: params.command,
          truncated: truncation.truncated,
        },
      };
    },
  });

  // -------------------------------------------------------------------
  // Tool: remote_upload
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "remote_upload",
    label: "Remote Upload",
    description: "Upload text content to the remote host via stdin pipe (no scp needed). Creates or overwrites a file using heredoc or echo redirection. Useful for deploying small scripts or config snippets.",
    promptSnippet: "Upload text content to a remote session via stdin (heredoc)",
    promptGuidelines: [
      "Use remote_upload for small text files (scripts, configs). For large files, use scp separately.",
      "remote_upload uses heredoc redirection — no additional tools needed on target.",
    ],
    parameters: Type.Object({
      content: Type.String({ description: "Text content to write to the remote file" }),
      remote_path: Type.String({ description: "Absolute path on remote host where file will be written" }),
      session: Type.Optional(Type.String({ description: "Session name" })),
      executable: Type.Optional(Type.Boolean({ description: "Make the file executable after writing (default: false)" })),
    }),

    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      const session = getSession(params.session);

      if (!session.process || session.process.killed) {
        sessions.delete(session.info.name);
        throw new Error(`Session '${session.info.name}' has been disconnected.`);
      }

      // Use heredoc to write content
      const delimiter = `__EOF_${Date.now()}__`;
      let writeCmd: string;

      if (session.info.platform === "windows") {
        // PowerShell: use Set-Content
        const escapedContent = psSingleQuote(params.content);
        const escapedPath = psSingleQuote(params.remote_path);
        writeCmd = `Set-Content -Path '${escapedPath}' -Value '${escapedContent}'`;
      } else {
        // Unix: heredoc
        const escapedPath = shellSingleQuote(params.remote_path);
        writeCmd = `cat > '${escapedPath}' << '${delimiter}'\n${params.content}\n${delimiter}`;
        if (params.executable) {
          writeCmd += `\nchmod +x '${escapedPath}'`;
        }
      }

      logToSession(session.info.name, ">>>", `[UPLOAD] ${params.remote_path} (${params.content.length} bytes)`);
      const output = await execCommand(session, writeCmd);

      return {
        content: [{ type: "text", text: `Uploaded ${params.content.length} bytes to ${params.remote_path} on session '${session.info.name}'${params.executable ? " (executable)" : ""}\n${output || "(success)"}` }],
        details: { session: session.info.name, path: params.remote_path, bytes: params.content.length },
      };
    },
  });

  // -------------------------------------------------------------------
  // Tool: remote_sessions
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "remote_sessions",
    label: "Remote Sessions",
    description: "List all active remote shell sessions and SSH tunnels with their status.",
    promptSnippet: "Show all active remote sessions and tunnels",
    parameters: Type.Object({}),

    async execute(_toolCallId, _params, _signal, _onUpdate, _ctx) {
      const lines: string[] = [];

      if (sessions.size === 0 && activeTunnels.length === 0) {
        return {
          content: [{ type: "text", text: "No active sessions or tunnels." }],
          details: { sessions: 0, tunnels: 0 },
        };
      }

      if (sessions.size > 0) {
        lines.push(`=== Active Sessions (${sessions.size}) ===`);
        lines.push("");
        for (const [name, session] of sessions) {
          const info = session.info;
          const alive = !session.process.killed;
          const duration = Math.round((Date.now() - info.connectedAt.getTime()) / 1000);
          const isDefault = name === defaultSessionName ? " [DEFAULT]" : "";
          const status = alive ? "✓" : "✗";

          lines.push(`  ${status} ${name}${isDefault}`);
          lines.push(`    Target: ${info.protocol.toUpperCase()} → ${info.target}`);
          lines.push(`    Platform: ${info.platform} | Commands: ${info.commandCount} | Uptime: ${duration}s`);
          lines.push(`    Last command: ${info.lastCommandAt?.toISOString() || "none"}`);
          lines.push("");
        }
      }

      if (activeTunnels.length > 0) {
        lines.push(`=== Active Tunnels (${activeTunnels.length}) ===`);
        lines.push("");
        for (const t of activeTunnels) {
          const alive = !t.process.killed && t.process.exitCode === null;
          const duration = Math.round((Date.now() - t.createdAt.getTime()) / 1000);
          const status = alive ? "✓" : "✗";

          let forward: string;
          if (t.type === "local") forward = `localhost:${t.localPort} → ${t.remoteHost}:${t.remotePort}`;
          else if (t.type === "remote") forward = `${t.via}:${t.remotePort} → localhost:${t.localPort}`;
          else forward = `SOCKS5 localhost:${t.localPort}`;

          lines.push(`  ${status} [${t.id}] ${t.type.toUpperCase()} | ${forward} | via ${t.via} | ${duration}s`);
          lines.push(`    ${t.description}`);
          lines.push("");
        }
      }

      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: { sessions: sessions.size, tunnels: activeTunnels.length, default: defaultSessionName },
      };
    },
  });

  // -------------------------------------------------------------------
  // Tool: remote_disconnect
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "remote_disconnect",
    label: "Remote Disconnect",
    description: "Close a specific remote session by name, or close all sessions.",
    promptSnippet: "Disconnect a remote session (by name or all)",
    parameters: Type.Object({
      session: Type.Optional(Type.String({ description: "Session name to disconnect. Omit to disconnect all sessions." })),
    }),

    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      if (sessions.size === 0) {
        return {
          content: [{ type: "text", text: "No active sessions to disconnect." }],
          details: { closed: 0 },
        };
      }

      let closed = 0;

      if (params.session) {
        const session = sessions.get(params.session);
        if (!session) {
          const available = [...sessions.keys()].join(", ");
          throw new Error(`Session '${params.session}' not found. Available: ${available}`);
        }
        logToSession(params.session, "---", "[SESSION END]");
        try { session.process.stdin!.write("exit\n"); } catch { /* ignore */ }
        await new Promise(resolve => setTimeout(resolve, 500));
        killTrackedProcess(session.process);
        sessions.delete(params.session);
        if (defaultSessionName === params.session) {
          defaultSessionName = sessions.size > 0 ? sessions.keys().next().value! : null;
        }
        closed = 1;
      } else {
        // Disconnect all
        for (const [name, session] of sessions) {
          logToSession(name, "---", "[SESSION END — disconnect all]");
          try { session.process.stdin!.write("exit\n"); } catch { /* ignore */ }
          killTrackedProcess(session.process);
        }
        closed = sessions.size;
        sessions.clear();
        defaultSessionName = null;
      }

      if (ctx.hasUI) {
        if (sessions.size === 0) {
          ctx.ui.setStatus("remote", undefined);
        } else {
          const sessionList = [...sessions.keys()].join(", ");
          ctx.ui.setStatus("remote", ctx.ui.theme.fg("accent", `🔗 Sessions: ${sessionList}`));
        }
      }

      return {
        content: [{ type: "text", text: `Closed ${closed} session(s). ${sessions.size} remaining.` }],
        details: { closed, remaining: sessions.size },
      };
    },
  });

  // -------------------------------------------------------------------
  // Tool: remote_tunnel
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "remote_tunnel",
    label: "Remote Tunnel",
    description: "Create an SSH port forward or SOCKS proxy through a remote host. Essential for pivoting through compromised systems to reach internal attacker infrastructure. Supports local forward (access remote service locally), remote forward (expose local service to remote), and dynamic SOCKS proxy.",
    promptSnippet: "Create SSH tunnel/port forward for pivoting through compromised hosts",
    promptGuidelines: [
      "Use remote_tunnel to pivot through compromised hosts and reach internal systems.",
      "For multi-hop: create a local forward to SSH on next hop, then remote_connect to localhost on that port.",
      "Use type=dynamic for SOCKS proxy when routing multiple tools (nmap, crackmapexec) through a pivot.",
      "Always close tunnels with remote_tunnel_close when no longer needed.",
    ],
    parameters: Type.Object({
      type: StringEnum(["local", "remote", "dynamic"] as const),
      via: Type.String({ description: "SSH hop: user@host (the compromised system to tunnel through)" }),
      local_port: Type.Number({ description: "Local port to bind (e.g., 2222, 1080 for SOCKS)" }),
      remote_host: Type.Optional(Type.String({ description: "Target host reachable from the hop (required for local forwards; ignored for remote forwards)" })),
      remote_port: Type.Optional(Type.Number({ description: "Target port on remote_host for local forwards, or listening port on the remote SSH host for remote forwards" })),
      ssh_port: Type.Optional(Type.Number({ description: "SSH port on the hop host (default: 22)" })),
      identity: Type.Optional(Type.String({ description: "SSH identity file for the hop" })),
      description: Type.Optional(Type.String({ description: "Human description (e.g., 'SOCKS through web01 to DB segment')" })),
    }),

    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      if (params.type === "local" && (!params.remote_host || !params.remote_port)) {
        throw new Error("remote_host and remote_port are required for local forwards.");
      }

      if (params.type === "remote" && !params.remote_port) {
        throw new Error("remote_port is required for remote forwards.");
      }

      if (ctx.hasUI) {
        let desc: string;
        if (params.type === "local") {
          desc = `Local forward: localhost:${params.local_port} → ${params.remote_host}:${params.remote_port} (via ${params.via})`;
        } else if (params.type === "remote") {
          desc = `Remote forward: ${params.via}:${params.remote_port} → localhost:${params.local_port}`;
        } else {
          desc = `Dynamic SOCKS proxy: localhost:${params.local_port} (via ${params.via})`;
        }

        const confirmed = await ctx.ui.confirm(
          "Create SSH Tunnel",
          desc,
        );
        if (!confirmed) {
          throw new Error("Tunnel creation cancelled by operator");
        }
      }

      const args: string[] = [
        "-N",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-o", "ExitOnForwardFailure=yes",
      ];

      if (params.ssh_port) args.push("-p", String(params.ssh_port));
      if (params.identity) args.push("-i", params.identity);

      const tunnelSpec = buildTunnelSpec(params.type, params.local_port, params.remote_host, params.remote_port);
      const forwardSpec = tunnelSpec.forwardSpec;
      args.push(...tunnelSpec.sshArgs);

      args.push(params.via);

      const proc = spawn("ssh", args, {
        stdio: ["ignore", "pipe", "pipe"],
      });

      const result = await new Promise<{ success: boolean; error?: string }>((resolve) => {
        let settled = false;
        let stderr = "";
        const fatalPattern = /(permission denied|connection refused|no route to host|connection timed out|could not resolve hostname|network is unreachable|administratively prohibited|address already in use|bad local forwarding specification|bad remote forwarding specification|channel_setup_fwd_listener: cannot listen)/i;

        const finish = (value: { success: boolean; error?: string }) => {
          if (settled) return;
          settled = true;
          clearTimeout(successTimer);
          resolve(value);
        };

        proc.stderr!.on("data", (data: Buffer) => {
          stderr += data.toString();
          if (fatalPattern.test(stderr)) {
            finish({ success: false, error: stderr.trim() });
          }
        });

        proc.on("close", (code) => {
          if (settled) return;
          finish({ success: false, error: stderr.trim() || `SSH exited with code ${code}` });
        });

        proc.on("error", (err) => finish({ success: false, error: err.message }));

        const successTimer = setTimeout(() => {
          if (!proc.killed && proc.exitCode === null) {
            finish({ success: true });
          } else {
            finish({ success: false, error: stderr.trim() || `SSH exited with code ${proc.exitCode}` });
          }
        }, 5000);
      });

      if (!result.success) {
        throw new Error(`Tunnel creation failed: ${result.error}`);
      }

      tunnelCounter++;
      const tunnelId = `tun-${tunnelCounter}`;
      const description = buildTunnelDescription(params.type, params.via, params.local_port, params.remote_host, params.remote_port, params.description);

      const tunnel: TunnelInfo = {
        id: tunnelId,
        type: params.type,
        via: params.via,
        localPort: params.local_port,
        remoteHost: params.remote_host || "*",
        remotePort: params.remote_port || params.local_port,
        process: proc,
        createdAt: new Date(),
        description,
      };

      activeTunnels.push(tunnel);
      logToSession("_tunnels", "---", `[TUNNEL CREATED] ${tunnelId}: -${forwardSpec!} ${params.via}`);

      proc.on("close", (code) => {
        const idx = activeTunnels.findIndex(t => t.id === tunnelId);
        if (idx !== -1) {
          activeTunnels.splice(idx, 1);
          logToSession("_tunnels", "---", `[TUNNEL CLOSED] ${tunnelId} exit=${code ?? "unknown"}`);
          if (ctx.hasUI) {
            if (activeTunnels.length === 0) {
              ctx.ui.setStatus("tunnels", undefined);
            } else {
              ctx.ui.setStatus("tunnels", ctx.ui.theme.fg("accent", `🔀 ${activeTunnels.length} tunnel(s)`));
            }
          }
        }
      });

      if (ctx.hasUI) {
        ctx.ui.setStatus("tunnels", ctx.ui.theme.fg("accent", `🔀 ${activeTunnels.length} tunnel(s)`));
      }

      const usageHint = buildTunnelUsageHint(params.type, params.via, params.local_port, params.remote_port);

      return {
        content: [{ type: "text", text: `Tunnel created: ${tunnelId}\n${description}\n\n${usageHint}` }],
        details: { tunnel: { id: tunnelId, type: params.type, localPort: params.local_port, via: params.via } },
      };
    },
  });

  // -------------------------------------------------------------------
  // Tool: remote_tunnel_close
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "remote_tunnel_close",
    label: "Remote Tunnel Close",
    description: "Close a specific SSH tunnel by ID, or close all tunnels.",
    promptSnippet: "Close SSH tunnel(s)",
    parameters: Type.Object({
      id: Type.Optional(Type.String({ description: "Tunnel ID (e.g., 'tun-1'). Omit to close all." })),
    }),

    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      if (activeTunnels.length === 0) {
        return {
          content: [{ type: "text", text: "No active tunnels." }],
          details: { closed: 0 },
        };
      }

      let closed = 0;

      if (params.id) {
        const idx = activeTunnels.findIndex(t => t.id === params.id);
        if (idx === -1) {
          const available = activeTunnels.map(t => t.id).join(", ");
          throw new Error(`Tunnel '${params.id}' not found. Available: ${available}`);
        }
        const tunnel = activeTunnels[idx];
        killTrackedProcess(tunnel.process);
        activeTunnels.splice(idx, 1);
        logToSession("_tunnels", "---", `[TUNNEL CLOSED] ${tunnel.id}`);
        closed = 1;
      } else {
        for (const tunnel of activeTunnels) {
          killTrackedProcess(tunnel.process);
          logToSession("_tunnels", "---", `[TUNNEL CLOSED] ${tunnel.id}`);
        }
        closed = activeTunnels.length;
        activeTunnels.length = 0;
      }

      if (ctx.hasUI) {
        if (activeTunnels.length === 0) {
          ctx.ui.setStatus("tunnels", undefined);
        } else {
          ctx.ui.setStatus("tunnels", ctx.ui.theme.fg("accent", `🔀 ${activeTunnels.length} tunnel(s)`));
        }
      }

      return {
        content: [{ type: "text", text: `Closed ${closed} tunnel(s). ${activeTunnels.length} remaining.` }],
        details: { closed, remaining: activeTunnels.length },
      };
    },
  });

  // -------------------------------------------------------------------
  // Slash Commands
  // -------------------------------------------------------------------
  pi.registerCommand("remote-connect", {
    description: "Preview connection arguments; use the remote_connect tool for the actual connection",
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
      ctx.ui.notify(`Preview: remote_connect(protocol=\"${protocol}\", target=\"${target}\", name=\"${name}\")`, "info");
    },
  });

  pi.registerCommand("remote-disconnect", {
    description: "Disconnect: /remote-disconnect <name|--all>",
    handler: async (args, ctx) => {
      if (args === "--all") {
        for (const [name, session] of sessions) {
          logToSession(name, "---", "[SESSION END via /command]");
          try { session.process.stdin!.write("exit\n"); } catch { /* ignore */ }
          killTrackedProcess(session.process);
        }
        const count = sessions.size;
        sessions.clear();
        defaultSessionName = null;
        ctx.ui.setStatus("remote", undefined);
        ctx.ui.notify(`Disconnected all ${count} session(s)`, "info");
        return;
      }
      const name = args?.trim();
      if (!name) {
        ctx.ui.notify(`Active sessions: ${[...sessions.keys()].join(", ") || "none"}`, "info");
        return;
      }
      const session = sessions.get(name);
      if (!session) {
        ctx.ui.notify(`Session '${name}' not found`, "error");
        return;
      }
      logToSession(name, "---", "[SESSION END via /command]");
      try { session.process.stdin!.write("exit\n"); } catch { /* ignore */ }
      killTrackedProcess(session.process);
      sessions.delete(name);
      if (defaultSessionName === name) defaultSessionName = sessions.size > 0 ? sessions.keys().next().value! : null;
      ctx.ui.setStatus("remote", sessions.size > 0 ? ctx.ui.theme.fg("accent", `🔗 Sessions: ${[...sessions.keys()].join(", ")}`) : undefined);
      ctx.ui.notify(`Disconnected '${name}'`, "info");
    },
  });

  pi.registerCommand("sessions", {
    description: "List active remote sessions",
    handler: async (_args, ctx) => {
      if (sessions.size === 0 && activeTunnels.length === 0) {
        ctx.ui.notify("No active sessions or tunnels", "info");
        return;
      }
      const lines: string[] = [];
      for (const [name, session] of sessions) {
        const alive = !session.process.killed;
        const isDefault = name === defaultSessionName ? " *" : "";
        lines.push(`${alive ? "✓" : "✗"} ${name}${isDefault} → ${session.info.protocol}://${session.info.target} (${session.info.platform}, ${session.info.commandCount} cmds)`);
      }
      if (activeTunnels.length > 0) {
        lines.push("");
        for (const t of activeTunnels) {
          const alive = !t.process.killed && t.process.exitCode === null;
          lines.push(`${alive ? "✓" : "✗"} [${t.id}] ${t.type} localhost:${t.localPort} via ${t.via}`);
        }
      }
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });

  pi.registerCommand("tunnels", {
    description: "List active SSH tunnels",
    handler: async (_args, ctx) => {
      if (activeTunnels.length === 0) {
        ctx.ui.notify("No active tunnels", "info");
        return;
      }
      const lines = activeTunnels.map(t => {
        const alive = !t.process.killed && t.process.exitCode === null;
        return `${alive ? "✓" : "✗"} [${t.id}] ${t.type} localhost:${t.localPort} via ${t.via} — ${t.description}`;
      });
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });

  // -------------------------------------------------------------------
  // Cleanup on shutdown
  // -------------------------------------------------------------------
  pi.on("session_shutdown", async () => {
    // Gracefully close all sessions
    for (const [name, session] of sessions) {
      logToSession(name, "---", "[SESSION END — pi shutdown]");
      try { session.process.stdin!.write("exit\n"); } catch { /* ignore */ }
      killTrackedProcess(session.process);
    }
    sessions.clear();
    defaultSessionName = null;

    // Close all tunnels
    for (const tunnel of activeTunnels) {
      logToSession("_tunnels", "---", `[TUNNEL CLOSED — pi shutdown] ${tunnel.id}`);
      killTrackedProcess(tunnel.process);
    }
    activeTunnels.length = 0;
  });
}
