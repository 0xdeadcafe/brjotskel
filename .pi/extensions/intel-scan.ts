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

import { spawn } from "node:child_process";
import { join } from "node:path";
import { readFileSync, writeFileSync, existsSync, renameSync, mkdirSync } from "node:fs";
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

function runNmap(target: string, ports: number[], timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const portArg = ports.length > 0 ? `-p ${ports.join(",")}` : "-p 22,80,443,445,3389,5985,5986,23,8080,8443";
    const args = ["-Pn", "-sT", "--open", "-oG", "-", ...portArg.split(" "), target];

    const proc = spawn("nmap", args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (d: Buffer) => { stdout += d.toString(); });
    proc.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });

    const timer = setTimeout(() => {
      proc.kill();
      reject(new Error(`nmap timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs);

    proc.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0 && stdout.trim() === "") {
        reject(new Error(`nmap exited ${code}: ${stderr.trim()}`));
      } else {
        resolve(stdout);
      }
    });

    proc.on("error", (err) => {
      clearTimeout(timer);
      reject(new Error(`Failed to spawn nmap: ${err.message}`));
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
    description: "Run an nmap scan from the harness against a target range and auto-populate the intel store with discovered hosts. Each responding host is added with status 'in-scope'. Existing entries are preserved — they are not overwritten.",
    promptSnippet: "Scan a network range and auto-populate the intel store with discovered hosts",
    promptGuidelines: [
      "Use intel_scan to map a new network segment quickly. It runs nmap from the harness — not on the target.",
      "After scanning, run /assess on each new session to triage discovered hosts.",
      "Default ports cover common IR targets: SSH (22), SMB (445), RDP (3389), WinRM (5985/5986), HTTP(S), telnet.",
      "Provide ports as an array of integers to narrow the scan.",
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
    }),

    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      const timeoutMs = (params.timeout_seconds ?? 120) * 1000;
      const ports = params.ports ?? [];

      // Run the scan
      let nmapOutput: string;
      try {
        nmapOutput = await runNmap(params.target, ports, timeoutMs);
      } catch (err: any) {
        throw new Error(`Scan failed: ${err.message}`);
      }

      // Parse results
      const discovered = parseNmapGreppable(nmapOutput);
      if (discovered.length === 0) {
        return {
          content: [{ type: "text", text: `Scan complete: no responding hosts found in ${params.target}` }],
          details: { target: params.target, hosts_found: 0 },
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
            method: `nmap scan (intel_scan)`,
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
        },
      };
    },
  });
}
