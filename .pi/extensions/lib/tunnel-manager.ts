/**
 * SSH tunnel lifecycle manager.
 *
 * Extracted from remote-session.ts so tunnel spawn logic can be tested
 * independently of the tool registration layer.
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import type { ChildProcess } from "node:child_process";
import type { TunnelInfo, TunnelType } from "./remote-types.ts";
import { buildTunnelSshArgs } from "./remote-session-core.ts";

export interface TunnelSpawnOptions {
  type: TunnelType;
  via: string;
  localPort: number;
  remoteHost?: string;
  remotePort?: number;
  sshPort?: number;
  identity?: string;
  password?: string;
  proxyJump?: string;
}

/**
 * Spawn an SSH tunnel process and wait up to 5 seconds for it to confirm
 * it is alive (no fatal error on stderr).
 *
 * @param options    Tunnel parameters
 * @param tunnelId   Pre-assigned ID (caller manages the ID counter)
 * @param onClose    Called when the SSH process exits so the caller can
 *                   remove the tunnel from its registry
 * @returns          The live ChildProcess on success
 */
export function spawnSSHTunnel(
  options: TunnelSpawnOptions,
  tunnelId: string,
  onClose?: (id: string, code: number | null) => void,
): Promise<ChildProcess> {
  return new Promise((resolve, reject) => {
    const { sshArgs: args } = buildTunnelSshArgs({
      type:       options.type,
      via:        options.via,
      localPort:  options.localPort,
      remoteHost: options.remoteHost,
      remotePort: options.remotePort,
      sshPort:    options.sshPort,
      identity:   options.identity,
      proxyJump:  options.proxyJump,
    });

    const sshpassPath =
      existsSync("/usr/bin/sshpass") ? "/usr/bin/sshpass" :
      existsSync("/bin/sshpass")     ? "/bin/sshpass" : null;

    if (options.password && !sshpassPath) {
      reject(new Error(
        "SSH password authentication requested for remote_tunnel, " +
        "but sshpass is not installed. Install sshpass or use key-based auth.",
      ));
      return;
    }

    const proc = options.password
      ? spawn(sshpassPath!, ["-e", "ssh", ...args], {
          stdio: ["ignore", "pipe", "pipe"],
          env: { ...process.env, SSHPASS: options.password },
        })
      : spawn("ssh", args, {
          stdio: ["ignore", "pipe", "pipe"],
        });

    let settled = false;
    let stderr = "";

    const fatalPattern =
      /(permission denied|connection refused|no route to host|connection timed out|could not resolve hostname|network is unreachable|administratively prohibited|address already in use|bad local forwarding specification|bad remote forwarding specification|channel_setup_fwd_listener: cannot listen)/i;

    const finish = (ok: boolean, err?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(successTimer);
      if (ok) {
        resolve(proc);
      } else {
        try { proc.kill(); } catch { /* ignore */ }
        reject(new Error(`Tunnel creation failed: ${err}`));
      }
    };

    proc.stderr!.on("data", (data: Buffer) => {
      stderr += data.toString();
      if (fatalPattern.test(stderr)) finish(false, stderr.trim());
    });

    proc.on("close", (code) => {
      // If we haven't settled yet, it exited too early
      if (!settled) finish(false, stderr.trim() || `SSH exited with code ${code}`);
      onClose?.(tunnelId, code);
    });

    proc.on("error", (err) => finish(false, err.message));

    // After 5 s with no fatal error, the tunnel is considered up
    const successTimer = setTimeout(() => {
      if (!proc.killed && proc.exitCode === null) {
        finish(true);
      } else {
        finish(false, stderr.trim() || `SSH exited with code ${proc.exitCode}`);
      }
    }, 5000);
  });
}

/**
 * Gracefully close a single tunnel from an array and remove it in-place.
 * Returns true if the tunnel was found and closed.
 */
export function closeTunnel(tunnels: TunnelInfo[], id: string): boolean {
  const idx = tunnels.findIndex(t => t.id === id);
  if (idx === -1) return false;
  const tunnel = tunnels[idx];
  try { tunnel.process.kill(); } catch { /* ignore */ }
  tunnels.splice(idx, 1);
  return true;
}

/**
 * Close all tunnels in the array (modifies in-place). Returns count closed.
 */
export function closeAllTunnels(tunnels: TunnelInfo[]): number {
  const count = tunnels.length;
  for (const t of tunnels) {
    try { t.process.kill(); } catch { /* ignore */ }
  }
  tunnels.length = 0;
  return count;
}
