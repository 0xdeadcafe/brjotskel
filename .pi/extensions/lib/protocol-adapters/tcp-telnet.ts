/**
 * TCP and Telnet protocol adapters.
 *
 * Both use nc (netcat) as the transport. TCP sessions are treated as
 * line-oriented best-effort shells. Telnet sessions additionally handle
 * IAC negotiation bytes before delivering text.
 *
 * Neither protocol has reliable command-boundary markers, so execCommand
 * uses a short timeout-based output collection path for both.
 */
import { spawn } from "node:child_process";
import type { RemoteSession } from "../remote-types.ts";
import { processTelnetBytes } from "../remote-session-core.ts";

export interface TCPConnectOptions {
  onCleanup?: (name: string) => void;
}

export function connectTCP(
  name: string,
  host: string,
  port: number,
  options: TCPConnectOptions = {},
): Promise<RemoteSession> {
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

    let settled = false;
    let stderr = "";

    const connectTimeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { proc.kill(); } catch { /* ignore */ }
      reject(new Error(`TCP connection to ${host}:${port} timed out (15s)`));
    }, 15_000);

    // Become ready after 1.5 s if the socket stays open with no banner
    const readyFallback = setTimeout(() => {
      if (settled || proc.killed || proc.exitCode !== null) return;
      settled = true;
      session.ready = true;
      clearTimeout(connectTimeout);
      resolve(session);
    }, 1500);

    const clearConnectTimers = () => {
      clearTimeout(connectTimeout);
      clearTimeout(readyFallback);
    };

    proc.stdout!.on("data", (data: Buffer) => {
      session.buffer += data.toString();
      if (!session.ready && !settled) {
        settled = true;
        session.ready = true;
        clearConnectTimers();
        if (session.buffer.match(/[#>]\s*$/)) {
          session.info.platform    = "network-device";
          session.info.shellFamily = "unknown";
        }
        resolve(session);
      }
    });

    proc.stderr!.on("data", (data: Buffer) => { stderr += data.toString(); });

    proc.on("close", (code) => {
      clearConnectTimers();
      options.onCleanup?.(name);
      if (!settled) {
        settled = true;
        reject(new Error(
          `TCP connection to ${host}:${port} closed before ready` +
          (stderr.trim() ? `: ${stderr.trim()}` : ` (exit=${code ?? "unknown"})`),
        ));
      }
    });

    proc.on("error", (err) => {
      clearConnectTimers();
      if (!settled) {
        settled = true;
        reject(new Error(`TCP connection failed: ${err.message}`));
      }
    });
  });
}

export function connectTelnet(
  name: string,
  host: string,
  port: number,
  options: TCPConnectOptions = {},
): Promise<RemoteSession> {
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

    let settled = false;
    let stderr = "";

    const connectTimeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { proc.kill(); } catch { /* ignore */ }
      reject(new Error(`Telnet connection to ${host}:${port} timed out (15s)`));
    }, 15_000);

    const readyFallback = setTimeout(() => {
      if (settled || proc.killed || proc.exitCode !== null) return;
      settled = true;
      session.ready = true;
      clearTimeout(connectTimeout);
      resolve(session);
    }, 1500);

    const clearConnectTimers = () => {
      clearTimeout(connectTimeout);
      clearTimeout(readyFallback);
    };

    proc.stdout!.on("data", (data: Buffer) => {
      // Process IAC negotiation and extract clean text
      const result = processTelnetBytes(session.telnetState, data);
      for (const reply of result.replies) {
        session.process.stdin?.write(Buffer.from(reply));
      }
      session.telnetState = result.state;
      const text = result.text;

      session.buffer += text;
      if (!session.ready && text.length > 0 && !settled) {
        settled = true;
        session.ready = true;
        clearConnectTimers();
        if (session.buffer.match(/[#>:]\s*$/)) {
          session.info.platform    = "network-device";
          session.info.shellFamily = "unknown";
        }
        resolve(session);
      }
    });

    proc.stderr!.on("data", (data: Buffer) => { stderr += data.toString(); });

    proc.on("close", (code) => {
      clearConnectTimers();
      options.onCleanup?.(name);
      if (!settled) {
        settled = true;
        reject(new Error(
          `Telnet connection to ${host}:${port} closed before ready` +
          (stderr.trim() ? `: ${stderr.trim()}` : ` (exit=${code ?? "unknown"})`),
        ));
      }
    });

    proc.on("error", (err) => {
      clearConnectTimers();
      if (!settled) {
        settled = true;
        reject(new Error(`Telnet connection failed: ${err.message}`));
      }
    });
  });
}
