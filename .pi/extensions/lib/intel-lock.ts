import { mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface IntelLockOptions {
  timeoutMs?: number;
  pollMs?: number;
  staleMs?: number;
}

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_POLL_MS = 100;
const DEFAULT_STALE_MS = 10 * 60_000;

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function lockHolder(token: string): Record<string, any> {
  return {
    token,
    pid: process.pid,
    host: process.env.HOSTNAME || process.env.COMPUTERNAME || "unknown-host",
    acquired_at: new Date().toISOString(),
  };
}

function holderToken(lockDir: string): string | undefined {
  try {
    const parsed = JSON.parse(readFileSync(join(lockDir, "holder.json"), "utf-8"));
    return typeof parsed?.token === "string" ? parsed.token : undefined;
  } catch {
    return undefined;
  }
}

export function intelLockPath(intelDir: string): string {
  return join(intelDir, ".intel.lock");
}

export async function withIntelFileLock<T>(intelDir: string, fn: () => T | Promise<T>, options: IntelLockOptions = {}): Promise<T> {
  const lockDir = intelLockPath(intelDir);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pollMs = options.pollMs ?? DEFAULT_POLL_MS;
  const staleMs = options.staleMs ?? DEFAULT_STALE_MS;
  const token = `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const start = Date.now();
  let acquired = false;

  while (!acquired) {
    try {
      mkdirSync(lockDir, { mode: 0o700 });
      writeFileSync(join(lockDir, "holder.json"), JSON.stringify(lockHolder(token), null, 2), { mode: 0o600 });
      acquired = true;
      break;
    } catch (err: any) {
      if (err?.code !== "EEXIST") throw new Error(`Failed to acquire intel lock ${lockDir}: ${err.message}`);

      let stale = false;
      try {
        const ageMs = Date.now() - statSync(lockDir).mtimeMs;
        stale = ageMs > staleMs;
      } catch {
        stale = true;
      }

      if (stale) {
        try { rmSync(lockDir, { recursive: true, force: true }); } catch { /* another process may be racing */ }
        continue;
      }

      if (Date.now() - start > timeoutMs) {
        throw new Error(`Timed out waiting for intel store lock: ${lockDir}`);
      }

      await sleep(pollMs);
    }
  }

  try {
    return await fn();
  } finally {
    if (holderToken(lockDir) === token) {
      rmSync(lockDir, { recursive: true, force: true });
    }
  }
}
