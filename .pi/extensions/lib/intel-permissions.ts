import { chmodSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";

export function ensurePrivateDir(dirPath: string): void {
  mkdirSync(dirPath, { recursive: true, mode: 0o700 });
  try { chmodSync(dirPath, 0o700); } catch { /* ignore chmod failures on non-POSIX mounts */ }
}

export function ensurePrivateFile(filePath: string): void {
  try { if (existsSync(filePath)) chmodSync(filePath, 0o600); } catch { /* ignore chmod failures on non-POSIX mounts */ }
}

export function hardenExistingPrivateFiles(dirPath: string, depth = 2): void {
  if (depth < 0 || !existsSync(dirPath)) return;
  try {
    for (const entry of readdirSync(dirPath, { withFileTypes: true })) {
      const entryPath = join(dirPath, entry.name);
      if (entry.isDirectory()) {
        ensurePrivateDir(entryPath);
        hardenExistingPrivateFiles(entryPath, depth - 1);
      } else if (entry.isFile()) {
        ensurePrivateFile(entryPath);
      }
    }
  } catch { /* ignore unreadable/private-store migration failures */ }
}
