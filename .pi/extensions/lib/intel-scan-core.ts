/**
 * Intel scan core — nmap output parsing and platform inference.
 *
 * Extracted from intel-scan.ts so the parsing logic can be tested
 * independently of the tool registration layer (which imports typebox).
 */

export interface ScanHost {
  ip: string;
  hostname: string;
  openPorts: Array<{ port: number; proto: string; service: string }>;
  platform: "windows" | "linux" | "macos" | "network-device" | "unknown";
}

const WINDOWS_PORT_HINTS = new Set([445, 3389, 5985, 5986, 135, 139]);
const LINUX_PORT_HINTS   = new Set([22]);
const NETWORK_PORT_HINTS = new Set([23, 179, 161, 162, 830, 2222]);

export function inferPlatform(ports: Array<{ port: number }>): ScanHost["platform"] {
  const portSet = new Set(ports.map(p => p.port));
  const windowsHits = [...portSet].filter(p => WINDOWS_PORT_HINTS.has(p)).length;
  const linuxHits   = [...portSet].filter(p => LINUX_PORT_HINTS.has(p)).length;
  const networkHits = [...portSet].filter(p => NETWORK_PORT_HINTS.has(p)).length;

  if (windowsHits >= 2) return "windows";
  if (windowsHits === 1 && linuxHits === 0) return "windows";
  if (linuxHits > 0 && windowsHits === 0) return "linux";
  if (networkHits > 0 && windowsHits === 0 && linuxHits === 0) return "network-device";
  return "unknown";
}

/**
 * Parse nmap greppable output (-oG -) into ScanHost objects.
 * Only "open" ports are included. Closed/filtered ports are ignored.
 */
export function parseNmapGreppable(output: string): ScanHost[] {
  // Nmap greppable output emits two Host: lines per responding host:
  //   Host: 10.10.10.5 (hostname)  Status: Up
  //   Host: 10.10.10.5 (hostname)  Ports: 22/open/tcp//ssh///
  // We collect by IP, merging port data from any line that has it.
  const byIp = new Map<string, ScanHost>();

  for (const line of output.split("\n")) {
    if (!line.startsWith("Host:")) continue;

    const hostMatch = line.match(/^Host:\s+(\S+)\s+\(([^)]*)\)/);
    if (!hostMatch) continue;

    const ip       = hostMatch[1];
    const hostname = hostMatch[2] || "";

    if (!byIp.has(ip)) {
      byIp.set(ip, { ip, hostname, openPorts: [], platform: "unknown" });
    }
    const entry = byIp.get(ip)!;
    if (hostname && !entry.hostname) entry.hostname = hostname;

    // Ports: 22/open/tcp//ssh///, 445/open/tcp//microsoft-ds///
    const portsMatch = line.match(/Ports:\s+(.+?)(?:\t|$)/);
    if (portsMatch) {
      for (const portEntry of portsMatch[1].split(",")) {
        const parts = portEntry.trim().split("/");
        if (parts[1] === "open" && parts[0]) {
          entry.openPorts.push({
            port:    parseInt(parts[0], 10),
            proto:   parts[2] || "tcp",
            service: parts[4] || "",
          });
        }
      }
    }
  }

  // Infer platform for each host now that all ports are collected
  for (const entry of byIp.values()) {
    entry.platform = inferPlatform(entry.openPorts);
  }

  return [...byIp.values()];
}
