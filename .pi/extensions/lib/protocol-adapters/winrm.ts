/**
 * WinRM protocol adapter.
 * Launches pwsh, sends an Enter-PSSession command, and resolves once the
 * remote prompt appears.
 */
import { spawn } from "node:child_process";
import type { RemoteSession } from "../remote-types.ts";
import { psSingleQuote } from "../remote-helpers.ts";
import { parseWinRmTarget } from "../remote-session-core.ts";

export interface WinRMConnectOptions {
  user?: string;
  password?: string;
  port?: number;
  useSsl?: boolean;
  skipCertCheck?: boolean;
  onCleanup?: (name: string) => void;
}

export function connectWinRM(
  name: string,
  target: string,
  options: WinRMConnectOptions = {},
): Promise<RemoteSession> {
  return new Promise((resolve, reject) => {
    const parsed = parseWinRmTarget(target, options.user);
    const safeTarget = psSingleQuote(parsed.computerName);
    const portArg    = options.port ? ` -Port ${options.port}` : "";
    const sslArg     = options.useSsl ? " -UseSSL" : "";
    const sessionOpt = options.skipCertCheck
      ? " -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck)"
      : "";

    const psCommand = options.password
      ? `$pw = ConvertTo-SecureString '${psSingleQuote(options.password)}' -AsPlainText -Force; ` +
        `$cred = New-Object PSCredential('${psSingleQuote(parsed.user || "")}', $pw); ` +
        `Enter-PSSession -ComputerName '${safeTarget}'${portArg}${sslArg}${sessionOpt} -Credential $cred`
      : `Enter-PSSession -ComputerName '${safeTarget}'${portArg}${sslArg}${sessionOpt}`;

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

    const connectTimeout = setTimeout(() => {
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
      options.onCleanup?.(name);
    });

    proc.on("error", (err) => {
      clearTimeout(connectTimeout);
      reject(new Error(`Failed to spawn pwsh for WinRM: ${err.message}`));
    });
  });
}
