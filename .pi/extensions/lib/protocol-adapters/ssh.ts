/**
 * SSH protocol adapter.
 * Spawns an SSH subprocess and resolves to a RemoteSession once the shell
 * prompt is detected. Accepts an onCleanup callback so the caller can
 * remove the session from its map without creating a circular dependency.
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import type { RemoteSession } from "../remote-types.ts";
import type { ShellFamily } from "../remote-helpers.ts";
import { detectSshShell } from "../remote-helpers.ts";

export interface SSHConnectOptions {
  port?: number;
  identity?: string;
  proxyJump?: string;
  password?: string;
  platformHint?: RemoteSession["info"]["platform"];
  shellHint?: ShellFamily;
  /** Called when the underlying SSH process closes so the caller can remove
   *  the session from its registry (e.g. sessions.delete(name)). */
  onCleanup?: (name: string) => void;
}

export function connectSSH(
  name: string,
  target: string,
  options: SSHConnectOptions = {},
): Promise<RemoteSession> {
  return new Promise((resolve, reject) => {
    const args = [
      "-tt",
      "-o", "StrictHostKeyChecking=accept-new",
      "-o", "ServerAliveInterval=30",
      "-o", "ServerAliveCountMax=3",
      "-o", "LogLevel=ERROR",
      "-o", "PreferredAuthentications=publickey,password,keyboard-interactive",
    ];
    if (options.port)      args.push("-p", String(options.port));
    if (options.identity)  args.push("-i", options.identity);
    if (options.proxyJump) args.push("-J", options.proxyJump);
    args.push(target);

    const sshpassPath =
      existsSync("/usr/bin/sshpass") ? "/usr/bin/sshpass" :
      existsSync("/bin/sshpass")     ? "/bin/sshpass" : null;

    if (options.password && !sshpassPath) {
      reject(new Error(
        "SSH password authentication requested, but sshpass is not installed. " +
        "Install sshpass or use key-based auth.",
      ));
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
        shellFamily:
          options.shellHint ||
          (options.platformHint === "linux" || options.platformHint === "macos"
            ? "posix"
            : "unknown"),
      },
      process: proc,
      buffer: "",
      ready: false,
      commandQueue: [],
      execChain: Promise.resolve(),
    };

    const connectTimeout = setTimeout(() => {
      proc.kill();
      reject(new Error(`SSH connection to ${target} timed out (30s)`));
    }, 30_000);

    proc.stdout!.on("data", (data: Buffer) => {
      session.buffer += data.toString();

      if (!session.ready) {
        const detected = detectSshShell(session.buffer, options.platformHint, options.shellHint);
        if (detected) {
          session.info.platform    = detected.platform;
          session.info.shellFamily = detected.shellFamily;
          session.ready = true;
          clearTimeout(connectTimeout);
          resolve(session);
          return;
        }
      }

      // Deliver output to any waiting command via marker detection
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
      if (
        text.includes("Permission denied") ||
        text.includes("Connection refused") ||
        text.includes("No route to host") ||
        text.includes("Connection timed out")
      ) {
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
      options.onCleanup?.(name);
    });

    proc.on("error", (err) => {
      clearTimeout(connectTimeout);
      reject(new Error(`Failed to spawn SSH: ${err.message}`));
    });
  });
}
