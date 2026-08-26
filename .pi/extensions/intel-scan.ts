/**
 * Intel Scan Extension
 *
 * Provides the intel_scan tool: run an nmap scan from the harness, parse the
 * results, and auto-populate the intel store with discovered hosts.
 *
 * Each responding host is added with status "in-scope" so /assess and /pursue
 * can act on them immediately. Existing entries are not overwritten.
 *
 * Registered tool:
 *   intel_scan — nmap a target range and populate intel store hosts
 */

import { spawn, spawnSync } from "node:child_process";
import { join } from "node:path";
import { readFileSync, writeFileSync, existsSync, renameSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { parseYaml, dumpYaml } from "./lib/simple-yaml.ts";
import { addIntelRecord, appendTimelineEntry } from "./lib/intel-store-core.ts";
import { resolveIntelDir } from "./lib/intel-helpers.ts";
import { parseNmapGreppable } from "./lib/intel-scan-core.ts";
import type { ScanHost } from "./lib/intel-scan-core.ts";
import { Type } from "typebox";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

// ---------------------------------------------------------------------------
// Nmap runner
// ---------------------------------------------------------------------------

function requireProxychains4(): void {
  const probe = spawnSync("proxychains4", ["-h"], { stdio: "ignore" });
  if ((probe.error as any)?.code === "ENOENT") {
    throw new Error("via_socks_port requires proxychains4 in the harness PATH");
  }
  if (probe.error) {
    throw new Error(`Failed to probe proxychains4: ${probe.error.message}`);
  }
}

function proxychainsConfig(port: number): string {
  return [
    "strict_chain",
    "proxy_dns",
    "tcp_read_time_out 15000",
    "tcp_connect_time_out 8000",
    "[ProxyList]",
    `socks5 127.0.0.1 ${port}`,
    "",
  ].join("\n");
}

function runNmap(target: string, ports: number[], timeoutMs: number, viaSocksPort?: number): Promise<string> {
  return new Promise((resolve, reject) => {
    if (viaSocksPort !== undefined) {
      if (!Number.isInteger(viaSocksPort) || viaSocksPort < 1 || viaSocksPort > 65535) {
        reject(new Error("via_socks_port must be an integer from 1 to 65535"));
        return;
      }
      try { requireProxychains4(); } catch (err) { reject(err); return; }
    }

    const portArg = ports.length > 0 ? `-p ${ports.join(",")}` : "-p 22,80,443,445,3389,5985,5986,23,8080,8443";
    const nmapArgs = ["-Pn", "-sT", "--open", "-oG", "-", ...portArg.split(" "), target];

    let command = "nmap";
    let args = nmapArgs;
    let proxyTempDir: string | undefined;

    if (viaSocksPort !== undefined) {
      proxyTempDir = mkdtempSync(join(tmpdir(), "brjotskel-proxychains-"));
      const configPath = join(proxyTempDir, "proxychains.conf");
      writeFileSync(configPath, proxychainsConfig(viaSocksPort), { mode: 0o600 });
      command = "proxychains4";
      args = ["-q", "-f", configPath, "nmap", ...nmapArgs];
    }

    const cleanup = () => {
      if (proxyTempDir) rmSync(proxyTempDir, { recursive: true, force: true });
    };

    const proc = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (d: Buffer) => { stdout += d.toString(); });
    proc.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });

    const timer = setTimeout(() => {
      proc.kill();
      cleanup();
      reject(new Error(`nmap timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs);

    proc.on("close", (code) => {
      clearTimeout(timer);
      cleanup();
      if (code !== 0 && stdout.trim() === "") {
        reject(new Error(`nmap exited ${code}: ${stderr.trim()}`));
      } else {
        resolve(stdout);
      }
    });

    proc.on("error", (err) => {
      clearTimeout(timer);
      cleanup();
      reject(new Error(`Failed to spawn ${command}: ${err.message}`));
    });
  });
}

// ---------------------------------------------------------------------------
// Intel store helpers (minimal — avoids importing all of intel-store.ts)
// ---------------------------------------------------------------------------

function getIntelDir(): string {
  const base = resolveIntelDir(process.cwd(), process.env.BRJOTSKEL_INTEL_DIR);
  mkdirSync(base, { recursive: true });
  return base;
}

function readYamlFile(filePath: string): any {
  if (!existsSync(filePath)) return {};
  try { return parseYaml(readFileSync(filePath, "utf-8")) ?? {}; } catch { return {}; }
}

function writeYamlFile(filePath: string, data: any): void {
  const yaml = dumpYaml(data);
  const tmp = `${filePath}.tmp-${process.pid}-${Date.now()}`;
  writeFileSync(tmp, yaml, { mode: 0o600 });
  renameSync(tmp, filePath);
}

// ---------------------------------------------------------------------------
// Extension registration
// ---------------------------------------------------------------------------

export default function intelScanExtension(pi: ExtensionAPI) {
  pi.registerTool({
    name: "intel_scan",
    label: "Intel Scan",
    description: "Run an nmap scan from the harness against a target range and auto-populate the intel store with discovered hosts. Each responding host is added with status 'in-scope'. Existing entries are preserved — they are not overwritten. Set via_socks_port to route through an existing local SOCKS pivot using proxychains4.",
    promptSnippet: "Scan a network range and auto-populate the intel store with discovered hosts",
    promptGuidelines: [
      "Use intel_scan to map a new network segment quickly. It runs nmap from the harness — not on the target.",
      "After scanning, run /assess on each new session to triage discovered hosts.",
      "Default ports cover common IR targets: SSH (22), SMB (445), RDP (3389), WinRM (5985/5986), HTTP(S), telnet.",
      "Provide ports as an array of integers to narrow the scan.",
      "intel_scan runs from the harness. For pivot-only segments, first create a dynamic SOCKS tunnel with remote_tunnel(type='dynamic', via='user@pivot', local_port=1080), then call intel_scan with via_socks_port=1080.",
      "via_socks_port requires proxychains4 in the harness PATH and a live SOCKS listener on 127.0.0.1:<port>.",
    ],
    parameters: Type.Object({
      target: Type.String({
        description: "Scan target: CIDR range (10.10.20.0/24), IP (10.10.10.5), or hostname",
      }),
      ports: Type.Optional(Type.Array(Type.Number(), {
        description: "TCP ports to probe. Default: [22, 80, 443, 445, 3389, 5985, 5986, 23, 8080, 8443]",
      })),
      timeout_seconds: Type.Optional(Type.Number({
        description: "nmap scan timeout in seconds (default: 120)",
      })),
      via_socks_port: Type.Optional(Type.Number({
        description: "Route nmap through proxychains4 using a live local SOCKS tunnel on 127.0.0.1:<port> (for pivot-only segments)",
      })),
    }),

    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      const timeoutMs = (params.timeout_seconds ?? 120) * 1000;
      const ports = params.ports ?? [];

      // Run the scan
      let nmapOutput: string;
      try {
        nmapOutput = await runNmap(params.target, ports, timeoutMs, params.via_socks_port);
      } catch (err: any) {
        throw new Error(`Scan failed: ${err.message}`);
      }

      // Parse results
      const discovered = parseNmapGreppable(nmapOutput);
      if (discovered.length === 0) {
        return {
          content: [{ type: "text", text: [
            `Scan complete: no responding hosts found in ${params.target}`,
            params.via_socks_port
              ? `Scan routed through SOCKS 127.0.0.1:${params.via_socks_port}; verify the tunnel and proxy reachability if this segment should answer.`
              : "intel_scan ran from the harness. If this is a pivot-only segment, create a dynamic SOCKS tunnel and rerun with via_socks_port.",
          ].join("\n") }],
          details: { target: params.target, hosts_found: 0, via_socks_port: params.via_socks_port },
        };
      }

      // Write to intel store
      const intelDir = getIntelDir();
      const hostsFile = join(intelDir, "hosts.yaml");
      const timelineFile = join(intelDir, "timeline.yaml");

      const added: string[] = [];
      const skipped: string[] = [];

      let store = readYamlFile(hostsFile);

      for (const h of discovered) {
        const id = `host-${h.ip.replace(/\./g, "-")}`;
        const portSummary = h.openPorts.map(p => `${p.port}/${p.proto}(${p.service || "?"})"`).join(", ");

        const entry = {
          ip: h.ip,
          hostname: h.hostname || undefined,
          platform: h.platform,
          status: "in-scope",
          endpoints: h.openPorts.map(p => `${p.proto === "tcp" ? "tcp" : p.proto}://${h.ip}:${p.port}`),
          notes: `Discovered by intel_scan: open ports ${portSummary}`,
          source: {
            method: params.via_socks_port ? `nmap scan (intel_scan via SOCKS 127.0.0.1:${params.via_socks_port})` : `nmap scan (intel_scan)`,
            path: params.target,
          },
        };

        try {
          store = addIntelRecord(store, "hosts", id, entry, { overwrite: false });
          added.push(id);
        } catch {
          // Duplicate — already exists, skip
          skipped.push(id);
        }
      }

      writeYamlFile(hostsFile, store);

      // Append timeline entries for added hosts
      let timelineStore = readYamlFile(timelineFile);
      for (const id of added) {
        timelineStore = appendTimelineEntry(timelineStore, {
          timestamp: new Date().toISOString(),
          type: "host",
          action: "discovered",
          target: id,
          summary: `Host ${id} discovered by intel_scan of ${params.target}`,
        });
      }
      writeYamlFile(timelineFile, timelineStore);

      const lines = [
        `Scan complete: ${params.target}`,
        `  Responding hosts: ${discovered.length}`,
        ...(params.via_socks_port ? [`  Via SOCKS: 127.0.0.1:${params.via_socks_port}`] : []),
        `  Added to intel store: ${added.length}`,
        ...(skipped.length > 0 ? [`  Skipped (already recorded): ${skipped.length}`] : []),
        "",
        "Discovered hosts:",
        ...discovered.map(h => {
          const portList = h.openPorts.map(p => `${p.port}/${p.service || p.proto}`).join("  ");
          return `  ${h.ip.padEnd(16)} ${h.platform.padEnd(10)} ports: ${portList}`;
        }),
        "",
        added.length > 0
          ? `Run /assess <session> after connecting to any of these hosts.`
          : `All ${skipped.length} host(s) already in the intel store.`,
      ];

      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: {
          target: params.target,
          hosts_found: discovered.length,
          added: added.length,
          skipped: skipped.length,
          host_ids: added,
          via_socks_port: params.via_socks_port,
        },
      };
    },
  });
}
