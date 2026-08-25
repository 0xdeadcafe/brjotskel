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
 *   remote_relay       — Set up a TCP relay on a pivot host using native tools
 *   remote_relay_close — Tear down a relay on a pivot host
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
import { mkdirSync, appendFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Type } from "typebox";
import { StringEnum } from "@earendil-works/pi-ai";
import { psSingleQuote, shellSingleQuote, detectSshShell, cleanCommandOutput, type ShellFamily } from "./lib/remote-helpers.ts";
import { chooseSessionName, buildMarkerCommand, buildTunnelSshArgs, buildTunnelDescription, buildTunnelUsageHint, processTelnetBytes, parseHostPortTarget, parseWinRmTarget, detectRelayMethods, buildRelayCommand, buildRelayCleanupCommand, buildRelayProbeCommand, buildRelayVerifyCommand, relayVerifyOutputConfirmsListening, validateRelaySpec, type RelayMethod, type RelaySpec } from "./lib/remote-session-core.ts";
import { parseShortcutArgs, formatLandShortcut, formatAssessShortcut, formatPursueShortcut, formatContainShortcut, formatEradicateShortcut, formatVerifyShortcut, buildAssessPrompt, buildPursuePrompt, buildContainPrompt, buildEradicatePrompt, buildVerifyPrompt, type OperatorSessionSummary, type PursueIntelSnapshot } from "./lib/operator-shortcuts.ts";
import { parseYaml } from "./lib/simple-yaml.ts";
import { resolveIntelDir } from "./lib/intel-helpers.ts";
import { buildIntelMap } from "./lib/intel-store-core.ts";
import { type Protocol, type TunnelType, type SessionInfo, type RemoteSession, type TunnelInfo, type RelayInfo, MARKER_PREFIX, MARKER_SUFFIX, COMMAND_TIMEOUT_MS, generateMarker, generateId, killTrackedProcess, logToSession as _logToSession, getLogPath as _getLogPath } from "./lib/remote-types.ts";
import { connectSSH } from "./lib/protocol-adapters/ssh.ts";
import { connectWinRM } from "./lib/protocol-adapters/winrm.ts";
import { connectTCP, connectTelnet } from "./lib/protocol-adapters/tcp-telnet.ts";
import { spawnSSHTunnel, closeTunnel, closeAllTunnels } from "./lib/tunnel-manager.ts";
import { setupRelay, teardownRelay } from "./lib/relay-manager.ts";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { truncateTail, DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES, formatSize } from "@earendil-works/pi-coding-agent";

// -------------------------------------------------------------------
// State & helpers
// -------------------------------------------------------------------

const sessions = new Map<string, RemoteSession>();
const activeTunnels: TunnelInfo[] = [];
const activeRelays: RelayInfo[] = [];
let tunnelCounter = 0;
let relayCounter = 0;
let defaultSessionName: string | null = null;

const LOG_DIR = join(process.cwd(), "logs", "remote-sessions");

// Bound log helper — avoids repeating LOG_DIR on every call
function log(sessionName: string, direction: ">>>" | "<<<" | "---", content: string): void {
  _logToSession(LOG_DIR, sessionName, direction, content);
}

function getSession(name?: string): RemoteSession {
  const selectedName = chooseSessionName(name, [...sessions.keys()], defaultSessionName);
  return sessions.get(selectedName)!;
}

// Shared session-cleanup callback — passed to every protocol adapter
function makeCleanup() {
  return (name: string) => {
    sessions.delete(name);
    if (defaultSessionName === name) defaultSessionName = null;
  };
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

    if (session.tainted) {
      reject(new Error(`Session '${session.info.name}' is tainted: ${session.tainted.reason}. Disconnect and reconnect before running more commands.`));
      return;
    }

    session.info.commandCount++;
    session.info.lastCommandAt = new Date();
    log(session.info.name, ">>>", command);

    if (session.info.protocol === "tcp" || session.info.protocol === "telnet") {
      // TCP/telnet modes are best-effort only: output is collected by timeout/prompt heuristics.
      session.buffer = "";
      session.process.stdin!.write(command + "\r\n");

      const collectTimeout = setTimeout(() => {
        const output = session.buffer.trim();
        session.buffer = "";
        log(session.info.name, "<<<", output);
        resolve(output);
      }, Math.min(timeoutMs, 5000));

      const checkInterval = setInterval(() => {
        if (session.buffer.match(/[#>$%]\s*$/)) {
          clearTimeout(collectTimeout);
          clearInterval(checkInterval);
          const output = session.buffer.trim();
          session.buffer = "";
          log(session.info.name, "<<<", output);
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
      const reason = `previous command timed out after ${timeoutMs / 1000}s and may still be running`;
      session.tainted = { reason, at: new Date(), command };
      log(session.info.name, "<<<", `[TIMEOUT after ${timeoutMs / 1000}s; SESSION TAINTED] ${partial}`);
      resolve(`[Command timed out after ${timeoutMs / 1000}s]\nSession marked tainted because the remote command may still be running. Disconnect and reconnect before issuing more commands.\n${partial}`);
    }, timeoutMs);

    session.commandQueue.push({
      id: commandId,
      command,
      marker,
      resolve: (output) => {
        const cleaned = cleanCommandOutput(session, command, output);
        log(session.info.name, "<<<", cleaned);
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
      target: Type.String({ description: "Connection target: user@host or host for SSH/WinRM; host:port, host with port=, or [IPv6]:port for TCP/telnet" }),
      name: Type.String({ description: "Session name for identification (e.g., 'web01', 'dc01', 'pivot-host')" }),
      port: Type.Optional(Type.Number({ description: "Override port (SSH default: 22, WinRM: 5985, TCP: required in target)" })),
      identity: Type.Optional(Type.String({ description: "SSH identity file path (e.g., recovered key from compromised host)" })),
      proxy_jump: Type.Optional(Type.String({ description: "SSH ProxyJump host for multi-hop (e.g., 'user@jumpbox' or 'user@hop1,user@hop2')" })),
      user: Type.Optional(Type.String({ description: "Username for WinRM" })),
      password: Type.Optional(Type.String({ description: "Password for SSH or WinRM. For SSH, remote_connect uses sshpass when available." })),
      use_ssl: Type.Optional(Type.Boolean({ description: "WinRM: connect over HTTPS (port 5986). Use when the target has HTTP disabled or only accepts HTTPS WinRM." })),
      skip_cert_check: Type.Optional(Type.Boolean({ description: "WinRM HTTPS: skip CA and CN certificate validation. Use for self-signed certificates. Adds -SkipCACheck -SkipCNCheck to the PSSessionOption." })),
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

      log(params.name, "---", `[SESSION START] ${params.protocol}://${params.target}`);

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
              onCleanup: makeCleanup(),
            });
            break;
          case "winrm":
            session = await connectWinRM(params.name, params.target, {
              user: params.user,
              password: params.password,
              port: params.port,
              useSsl: params.use_ssl === true,
              skipCertCheck: params.skip_cert_check === true,
              onCleanup: makeCleanup(),
            });
            break;
          case "tcp": {
            const parsed = parseHostPortTarget(params.target, params.port ?? 23);
            const port = params.port ?? parsed.port;
            session = await connectTCP(params.name, parsed.host, port, { onCleanup: makeCleanup() });
            break;
          }
          case "telnet": {
            const parsed = parseHostPortTarget(params.target, params.port ?? 23);
            const port = params.port ?? parsed.port;
            session = await connectTelnet(params.name, parsed.host, port, { onCleanup: makeCleanup() });
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
          content: [{ type: "text", text: `Connected: session '${params.name}' → ${params.target} via ${params.protocol.toUpperCase()}\nPlatform: ${session!.info.platform}${proxyInfo}${modeNote}\nActive sessions: ${sessions.size}\nLog: ${_getLogPath(LOG_DIR, params.name)}` }],
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
        const escapedDelimiter = shellSingleQuote(delimiter);
        writeCmd = `cat > ${escapedPath} << ${escapedDelimiter}\n${params.content}\n${delimiter}`;
        if (params.executable) {
          writeCmd += `\nchmod +x ${escapedPath}`;
        }
      }

      log(session.info.name, ">>>", `[UPLOAD] ${params.remote_path} (${params.content.length} bytes)`);
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

      if (sessions.size === 0 && activeTunnels.length === 0 && activeRelays.length === 0) {
        return {
          content: [{ type: "text", text: "No active sessions, tunnels, or relays." }],
          details: { sessions: 0, tunnels: 0, relays: 0 },
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
          const status = session.tainted ? "⚠" : (alive ? "✓" : "✗");

          lines.push(`  ${status} ${name}${isDefault}`);
          lines.push(`    Target: ${info.protocol.toUpperCase()} → ${info.target}`);
          lines.push(`    Platform: ${info.platform} | Commands: ${info.commandCount} | Uptime: ${duration}s`);
          if (session.tainted) lines.push(`    State: TAINTED since ${session.tainted.at.toISOString()} — ${session.tainted.reason}`);
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

      if (activeRelays.length > 0) {
        lines.push(`=== Active Relays (${activeRelays.length}) ===`);
        lines.push("");
        for (const r of activeRelays) {
          const sessionAlive = sessions.has(r.session) && !sessions.get(r.session)!.process.killed;
          const duration = Math.round((Date.now() - r.createdAt.getTime()) / 1000);
          const status = sessionAlive ? "✓" : "⚠";
          lines.push(`  ${status} [${r.id}] ${r.method.toUpperCase()} | ${r.session}:${r.listenPort} → ${r.targetHost}:${r.targetPort} | ${duration}s`);
          lines.push(`    ${r.description}`);
          lines.push("");
        }
      }

      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: { sessions: sessions.size, tunnels: activeTunnels.length, relays: activeRelays.length, default: defaultSessionName },
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
        log(params.session, "---", "[SESSION END]");
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
          log(name, "---", "[SESSION END — disconnect all]");
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
      "For multi-hop: use proxy_jump or create a local forward to SSH on next hop, then remote_connect to localhost on that port.",
      "Password-only SSH pivots are supported via password=... when sshpass is available.",
      "Use type=dynamic for SOCKS proxy when routing multiple tools (nmap, netexec) through a pivot.",
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
      password: Type.Optional(Type.String({ description: "SSH password for the hop. Uses sshpass when available." })),
      proxy_jump: Type.Optional(Type.String({ description: "SSH ProxyJump host/chain to reach the hop (e.g., 'user@jumpbox' or 'user@hop1,user@hop2')" })),
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

      tunnelCounter++;
      const tunnelId = `tun-${tunnelCounter}`;
      const description = buildTunnelDescription(params.type, params.via, params.local_port, params.remote_host, params.remote_port, params.description);

      const proc = await spawnSSHTunnel(
        {
          type:       params.type,
          via:        params.via,
          localPort:  params.local_port,
          remoteHost: params.remote_host,
          remotePort: params.remote_port,
          sshPort:    params.ssh_port,
          identity:   params.identity,
          password:   params.password,
          proxyJump:  params.proxy_jump,
        },
        tunnelId,
        (id, code) => {
          const idx = activeTunnels.findIndex(t => t.id === id);
          if (idx !== -1) {
            activeTunnels.splice(idx, 1);
            log("_tunnels", "---", `[TUNNEL CLOSED] ${id} exit=${code ?? "unknown"}`);
            if (ctx.hasUI) {
              activeTunnels.length === 0
                ? ctx.ui.setStatus("tunnels", undefined)
                : ctx.ui.setStatus("tunnels", ctx.ui.theme.fg("accent", `🔀 ${activeTunnels.length} tunnel(s)`));
            }
          }
        },
      );

      const { forwardSpec } = buildTunnelSshArgs({
        type: params.type, via: params.via, localPort: params.local_port,
        remoteHost: params.remote_host, remotePort: params.remote_port,
        sshPort: params.ssh_port, identity: params.identity, proxyJump: params.proxy_jump,
      });

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
      log("_tunnels", "---", `[TUNNEL CREATED] ${tunnelId}: -${forwardSpec ?? params.local_port} ${params.via}`);

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
        const tunnel = activeTunnels.find(t => t.id === params.id);
        if (!tunnel) {
          const available = activeTunnels.map(t => t.id).join(", ");
          throw new Error(`Tunnel '${params.id}' not found. Available: ${available}`);
        }
        log("_tunnels", "---", `[TUNNEL CLOSED] ${tunnel.id}`);
        closeTunnel(activeTunnels, params.id);
        closed = 1;
      } else {
        for (const tunnel of activeTunnels) log("_tunnels", "---", `[TUNNEL CLOSED] ${tunnel.id}`);
        closed = closeAllTunnels(activeTunnels);
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
  // Tool: remote_relay
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "remote_relay",
    label: "Remote Relay",
    description: "Set up a TCP port relay on a compromised pivot host using native tools (socat, ncat, nc, or netsh portproxy). Use when SSH tunneling is unavailable or the next target is only reachable from the pivot. Automatically detects available relay methods on the pivot host.",
    promptSnippet: "Create a TCP relay on a pivot host to reach systems the harness cannot directly access",
    promptGuidelines: [
      "Use remote_relay when the harness cannot reach the target directly but an existing session can.",
      "remote_relay auto-detects available tools (socat, ncat, nc, netsh) on the pivot host.",
      "After relay is set up, connect through the pivot host's listen port (e.g., SSH to pivot:listen_port to reach internal:22).",
      "Use remote_relay_close to tear down relays when no longer needed.",
      "For SSH-capable pivots, prefer remote_tunnel instead — it's more reliable.",
    ],
    parameters: Type.Object({
      session: Type.String({ description: "Session name of the pivot host where the relay will run" }),
      target_host: Type.String({ description: "Target host reachable from the pivot (e.g., '10.10.20.5')" }),
      target_port: Type.Number({ description: "Target port on the remote host (e.g., 22, 445, 3389)" }),
      listen_port: Type.Number({ description: "Port to listen on the pivot host (e.g., 4422)" }),
      method: Type.Optional(StringEnum(["socat", "ncat", "nc-openbsd", "nc-traditional", "netsh-portproxy", "auto"] as const)),
      listen_address: Type.Optional(Type.String({ description: "Bind address on pivot (default: 0.0.0.0)" })),
      description: Type.Optional(Type.String({ description: "Human description of this relay" })),
    }),

    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const session = getSession(params.session);

      if (!session.process || session.process.killed) {
        sessions.delete(session.info.name);
        throw new Error(`Session '${session.info.name}' has been disconnected.`);
      }

      // Operator confirmation
      if (ctx.hasUI) {
        const confirmed = await ctx.ui.confirm(
          "Create Relay",
          `Set up relay on '${session.info.name}':\n${session.info.target}:${params.listen_port} → ${params.target_host}:${params.target_port}`,
        );
        if (!confirmed) throw new Error("Relay creation cancelled by operator");
      }

      relayCounter++;
      const relayId = `relay-${relayCounter}`;

      const relayInfo = await setupRelay(
        {
          session,
          targetHost:    params.target_host,
          targetPort:    params.target_port,
          listenPort:    params.listen_port,
          listenAddress: params.listen_address,
          method:        params.method as RelayMethod | "auto" | undefined,
          description:   params.description,
          relayId,
        },
        (s, cmd, timeout) => execCommand(s, cmd, timeout),
        (name, dir, content) => log(name, dir, content),
      );

      activeRelays.push(relayInfo);

      const pivotTarget = session.info.target.includes("@") ? session.info.target.split("@")[1] : session.info.target;
      const pivotHost   = pivotTarget.split(":")[0];
      const { method }  = relayInfo;

      const usageLines = [
        `Relay created: ${relayId}`,
        `Method: ${method}`,
        `Path: ${session.info.name} (${pivotHost}):${params.listen_port} → ${params.target_host}:${params.target_port}`,
        `Verified listening: yes`,
        "",
        "Usage from harness:",
      ];

      if (params.target_port === 22) {
        usageLines.push(`  ssh user@${pivotHost} -p ${params.listen_port}`);
        usageLines.push(`  remote_connect(protocol="ssh", target="user@${pivotHost}", port=${params.listen_port}, name="next-hop")`);
      } else if (params.target_port === 445) {
        usageLines.push(`  netexec smb ${pivotHost} --port ${params.listen_port} -u <user> -H <hash>`);
        usageLines.push(`  smbclient -p ${params.listen_port} //${pivotHost}/share -U <user>`);
      } else if (params.target_port === 5985 || params.target_port === 5986) {
        usageLines.push(`  remote_connect(protocol="winrm", target="user@${pivotHost}", port=${params.listen_port}, name="next-hop")`);
      } else if (params.target_port === 3389) {
        usageLines.push(`  xfreerdp /v:${pivotHost}:${params.listen_port} /u:<user> /p:<pass>`);
      } else {
        usageLines.push(`  Connect to ${pivotHost}:${params.listen_port} to reach ${params.target_host}:${params.target_port}`);
      }
      usageLines.push("", `Cleanup: remote_relay_close(id="${relayId}")`);

      return {
        content: [{ type: "text", text: usageLines.join("\n") }],
        details: { relay: { id: relayId, method, session: session.info.name, listenPort: params.listen_port, target: `${params.target_host}:${params.target_port}` } },
      };
    },
  });

  // -------------------------------------------------------------------
  // Tool: remote_relay_close
  // -------------------------------------------------------------------
  pi.registerTool({
    name: "remote_relay_close",
    label: "Remote Relay Close",
    description: "Tear down a relay running on a pivot host. Sends the appropriate kill/cleanup command to the session where the relay was created.",
    promptSnippet: "Close a TCP relay on a pivot host",
    parameters: Type.Object({
      id: Type.Optional(Type.String({ description: "Relay ID (e.g., 'relay-1'). Omit to close all relays." })),
    }),

    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      if (activeRelays.length === 0) {
        return {
          content: [{ type: "text", text: "No active relays." }],
          details: { closed: 0 },
        };
      }

      const toClose = params.id
        ? activeRelays.filter(r => r.id === params.id)
        : [...activeRelays];

      if (params.id && toClose.length === 0) {
        const available = activeRelays.map(r => r.id).join(", ");
        throw new Error(`Relay '${params.id}' not found. Available: ${available}`);
      }

      const results: string[] = [];
      for (const relay of toClose) {
        const msg = await teardownRelay(
          relay,
          activeRelays,
          (name) => sessions.get(name),
          (s, cmd, timeout) => execCommand(s, cmd, timeout),
          (name, dir, content) => log(name, dir, content),
        );
        results.push(msg);
      }

      const closed = results.length;
      return {
        content: [{ type: "text", text: `Closed ${closed} relay(s). ${activeRelays.length} remaining.\n${results.join("\n")}` }],
        details: { closed, remaining: activeRelays.length },
      };
    },
  });

  // -------------------------------------------------------------------
  // Slash Commands
  // -------------------------------------------------------------------

  // Intel snapshot helper for /pursue and /scope
  function readIntelSnapshot(): { pursue: PursueIntelSnapshot | null; raw: { hosts: Record<string, any>; credentials: Record<string, any>; accounts: Record<string, any>; pivots: Record<string, any>; timeline: any[] } | null } {
    try {
      const intelDir = resolveIntelDir(process.cwd(), process.env.BRJOTSKEL_INTEL_DIR);
      if (!existsSync(intelDir)) return { pursue: null, raw: null };
      const read = (file: string): any => {
        const p = join(intelDir, file);
        if (!existsSync(p)) return {};
        try { return parseYaml(readFileSync(p, "utf8")) ?? {}; } catch { return {}; }
      };
      const hosts       = read("hosts.yaml").hosts       ?? {};
      const credentials = read("credentials.yaml").credentials ?? {};
      const accounts    = read("accounts.yaml").accounts    ?? {};
      const pivots      = read("pivots.yaml").paths         ?? {};
      const timeline    = read("timeline.yaml").timeline    ?? [];
      const inactiveStatuses = new Set(["rotated", "expired", "revoked", "disabled", "inactive", "invalid"]);
      const unvalidatedCreds = Object.entries(credentials)
        .filter(([_, c]: [string, any]) => !inactiveStatuses.has(c.status ?? ""))
        .filter(([_, c]: [string, any]) => !c.valid_on || (c.valid_on as string[]).length === 0)
        .map(([id, c]: [string, any]) => ({ id, type: c.type || "unknown", username: c.username || "", keyFile: c.key_file }));
      const activeCreds = Object.entries(credentials)
        .filter(([_, c]: [string, any]) => c.status === "active")
        .map(([id, c]: [string, any]) => ({ id, type: c.type || "unknown", username: c.username || "", keyFile: c.key_file }));
      const knownHostIps = Object.values(hosts).map((h: any) => h.ip).filter(Boolean) as string[];
      const knownHostIds = Object.keys(hosts);
      return { pursue: { unvalidatedCreds, activeCreds, knownHostIps, knownHostIds }, raw: { hosts, credentials, accounts, pivots, timeline } };
    } catch {
      return { pursue: null, raw: null };
    }
  }

  function operatorSessions(): OperatorSessionSummary[] {
    return [...sessions.values()].map(session => ({
      name: session.info.name,
      protocol: session.info.protocol,
      target: session.info.target,
      platform: session.info.platform,
      commandCount: session.info.commandCount,
    }));
  }

  function pickOperatorSession(args?: string): OperatorSessionSummary | undefined {
    const parsed = parseShortcutArgs(args);
    const available = operatorSessions();
    const selectedName = parsed.sessionName || (defaultSessionName && sessions.has(defaultSessionName) ? defaultSessionName : (available.length === 1 ? available[0].name : undefined));
    return selectedName ? available.find(s => s.name === selectedName) : undefined;
  }

  function sessionCompletions(prefix: string) {
    const base = [...sessions.keys()].map(name => ({ value: name, label: name, description: "active remote session" }));
    if (!prefix) return base;
    return base.filter(item => item.value.startsWith(prefix));
  }

  function showOrStage(ctx: any, shouldStage: boolean, promptText: string | undefined, displayText: string): void {
    if (shouldStage && promptText) {
      ctx.ui.setEditorText(promptText);
      ctx.ui.notify("Staged phase prompt in editor. Press Enter to run or edit first.", "info");
      return;
    }
    ctx.ui.notify(displayText, "info");
  }

  pi.registerCommand("land", {
    description: "Operator shortcut: landing/access primitives and immediate next action",
    handler: async (args, ctx) => {
      const parsed = parseShortcutArgs(args);
      if (parsed.help) {
        ctx.ui.notify("Usage: /land\nShows fast access, pivot, and post-landing prompts. No case/report workflow.", "info");
        return;
      }
      ctx.ui.notify(formatLandShortcut(operatorSessions()), "info");
    },
  });

  pi.registerCommand("assess", {
    description: "Operator shortcut: first-look and high-signal assessment commands for a session",
    getArgumentCompletions: sessionCompletions,
    handler: async (args, ctx) => {
      const parsed = parseShortcutArgs(args);
      const session = pickOperatorSession(args);
      const display = formatAssessShortcut(session, operatorSessions());
      showOrStage(ctx, parsed.prompt, session ? buildAssessPrompt(session) : undefined, display);
    },
  });

  pi.registerCommand("pursue", {
    description: "Operator shortcut: credential/pivot chase board with pre-built validation commands",
    handler: async (args, ctx) => {
      const parsed = parseShortcutArgs(args);
      const { pursue: intelSnap } = readIntelSnapshot();
      const display = formatPursueShortcut(operatorSessions(), intelSnap);
      showOrStage(ctx, parsed.prompt, buildPursuePrompt(), display);
    },
  });

  pi.registerCommand("contain", {
    description: "Operator shortcut: evidence-first containment command pack for a session",
    getArgumentCompletions: sessionCompletions,
    handler: async (args, ctx) => {
      const parsed = parseShortcutArgs(args);
      const session = pickOperatorSession(args);
      const display = formatContainShortcut(session, operatorSessions());
      showOrStage(ctx, parsed.prompt, session ? buildContainPrompt(session) : undefined, display);
    },
  });

  pi.registerCommand("eradicate", {
    description: "Operator shortcut: evidence-backed eradication command pack for a session",
    getArgumentCompletions: sessionCompletions,
    handler: async (args, ctx) => {
      const parsed = parseShortcutArgs(args);
      const session = pickOperatorSession(args);
      const display = formatEradicateShortcut(session, operatorSessions());
      showOrStage(ctx, parsed.prompt, session ? buildEradicatePrompt(session) : undefined, display);
    },
  });

  pi.registerCommand("verify", {
    description: "Operator shortcut: post-containment/eradication verification commands for a session",
    getArgumentCompletions: sessionCompletions,
    handler: async (args, ctx) => {
      const parsed = parseShortcutArgs(args);
      const session = pickOperatorSession(args);
      const display = formatVerifyShortcut(session, operatorSessions());
      showOrStage(ctx, parsed.prompt, session ? buildVerifyPrompt(session) : undefined, display);
    },
  });

  pi.registerCommand("scope", {
    description: "Situational dump: active sessions, tunnels, intel counts, and last 5 timeline entries",
    handler: async (_args, ctx) => {
      const lines: string[] = ["=== SCOPE ===", ""];

      // Active sessions
      if (sessions.size === 0) {
        lines.push("Sessions: none");
      } else {
        lines.push(`Sessions (${sessions.size}):`);
        for (const [name, s] of sessions) {
          const isDefault = name === defaultSessionName ? " *" : "";
          const taint = s.tainted ? " [TAINTED]" : "";
          lines.push(`  ${s.process.killed ? "✗" : "✓"} ${name}${isDefault} → ${s.info.protocol}://${s.info.target} (${s.info.platform}, ${s.info.commandCount} cmds)${taint}`);
        }
      }

      // Tunnels & relays
      if (activeTunnels.length > 0) {
        lines.push("");
        lines.push(`Tunnels (${activeTunnels.length}):`);
        for (const t of activeTunnels) {
          const alive = !t.process.killed && t.process.exitCode === null;
          lines.push(`  ${alive ? "✓" : "✗"} [${t.id}] ${t.type} :${t.localPort} via ${t.via}`);
        }
      }
      if (activeRelays.length > 0) {
        lines.push("");
        lines.push(`Relays (${activeRelays.length}):`);
        for (const r of activeRelays) {
          lines.push(`  [${r.id}] ${r.method} ${r.session}:${r.listenPort} → ${r.targetHost}:${r.targetPort}`);
        }
      }

      // Intel store snapshot
      const { raw } = readIntelSnapshot();
      lines.push("");
      if (!raw) {
        lines.push("Intel: not initialized");
      } else {
        const hCount  = Object.keys(raw.hosts).length;
        const cCount  = Object.keys(raw.credentials).length;
        const aCount  = Object.keys(raw.accounts).length;
        const pCount  = Object.keys(raw.pivots).length;
        const tCount  = Array.isArray(raw.timeline) ? raw.timeline.length : 0;
        const dirty   = Object.values(raw.hosts).filter((h: any) => h.status === "compromised").length;
        const activeCreds = Object.values(raw.credentials).filter((c: any) => c.status === "active").length;
        const unvalidated = Object.values(raw.credentials).filter((c: any) => !(["rotated","expired","revoked","disabled","inactive","invalid"].includes(c.status ?? "")) && (!c.valid_on || (c.valid_on as string[]).length === 0)).length;
        lines.push(`Intel: ${hCount} hosts (${dirty} compromised) | ${cCount} creds (${activeCreds} active, ${unvalidated} unvalidated) | ${aCount} accounts | ${pCount} pivots | ${tCount} events`);
        // Last 5 timeline entries
        if (Array.isArray(raw.timeline) && raw.timeline.length > 0) {
          lines.push("");
          lines.push("Last 5 events:");
          raw.timeline.slice(-5).reverse().forEach((e: any) => {
            lines.push(`  ${(e.timestamp || "").slice(0, 19).replace("T", " ")}  ${e.summary || ""}`);
          });
        }
      }

      ctx.ui.notify(lines.join("\n"), "info");
    },
  });

  pi.registerCommand("map", {
    description: "Attack graph: host nodes, credential blast radius, accounts, pivot chains",
    handler: async (_args, ctx) => {
      const { raw } = readIntelSnapshot();
      if (!raw) {
        ctx.ui.notify("Intel store not initialized. Run intel_add to record findings first.", "info");
        return;
      }
      const activeSessionNames = new Set([...sessions.keys()]);
      const map = buildIntelMap(raw.hosts, raw.credentials, raw.accounts, raw.pivots, { activeSessions: activeSessionNames });
      ctx.ui.notify(map, "info");
    },
  });

  pi.registerCommand("remote-connect", {
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
          log(name, "---", "[SESSION END via /command]");
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
      log(name, "---", "[SESSION END via /command]");
      try { session.process.stdin!.write("exit\n"); } catch { /* ignore */ }
      killTrackedProcess(session.process);
      sessions.delete(name);
      if (defaultSessionName === name) defaultSessionName = sessions.size > 0 ? sessions.keys().next().value! : null;
      ctx.ui.setStatus("remote", sessions.size > 0 ? ctx.ui.theme.fg("accent", `🔗 Sessions: ${[...sessions.keys()].join(", ")}`) : undefined);
      ctx.ui.notify(`Disconnected '${name}'`, "info");
    },
  });

  pi.registerCommand("sessions", {
    description: "List active remote sessions, tunnels, and relays",
    handler: async (_args, ctx) => {
      if (sessions.size === 0 && activeTunnels.length === 0 && activeRelays.length === 0) {
        ctx.ui.notify("No active sessions, tunnels, or relays", "info");
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
      if (activeRelays.length > 0) {
        lines.push("");
        for (const r of activeRelays) {
          const sessionAlive = sessions.has(r.session) && !sessions.get(r.session)!.process.killed;
          lines.push(`${sessionAlive ? "✓" : "⚠"} [${r.id}] ${r.method} ${r.session}:${r.listenPort} → ${r.targetHost}:${r.targetPort}`);
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
      log(name, "---", "[SESSION END — pi shutdown]");
      try { session.process.stdin!.write("exit\n"); } catch { /* ignore */ }
      killTrackedProcess(session.process);
    }
    sessions.clear();
    defaultSessionName = null;

    // Close all tunnels
    for (const tunnel of activeTunnels) {
      log("_tunnels", "---", `[TUNNEL CLOSED — pi shutdown] ${tunnel.id}`);
      killTrackedProcess(tunnel.process);
    }
    activeTunnels.length = 0;

    // Note: relays are processes on remote hosts — they persist after harness shutdown.
    // Log them so the operator knows cleanup is needed.
    for (const relay of activeRelays) {
      log(relay.session, "---", `[RELAY ORPHANED — pi shutdown] ${relay.id}: ${relay.method} :${relay.listenPort} → ${relay.targetHost}:${relay.targetPort}`);
    }
    activeRelays.length = 0;
  });
}
