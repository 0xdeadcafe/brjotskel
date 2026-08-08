import { psSingleQuote, shellSingleQuote, type ShellFamily } from "./remote-helpers.ts";

export type TunnelType = "local" | "remote" | "dynamic";

export function parseWinRmTarget(target: string, explicitUser?: string): { computerName: string; user?: string } {
  const at = target.lastIndexOf("@");
  const parsedUser = at === -1 ? undefined : target.slice(0, at) || undefined;
  const computerName = at === -1 ? target : target.slice(at + 1);
  const user = explicitUser || parsedUser;
  return user ? { computerName, user } : { computerName };
}

export interface TelnetState {
  mode: "data" | "iac" | "iac-command" | "sb" | "sb-iac";
  command?: number;
}

export function chooseSessionName(requestedName: string | undefined, availableNames: string[], defaultSessionName: string | null): string {
  if (!requestedName) {
    if (!defaultSessionName || !availableNames.includes(defaultSessionName)) {
      if (availableNames.length === 0) {
        throw new Error("No active remote sessions. Use remote_connect first.");
      }
      if (availableNames.length === 1) {
        return availableNames[0];
      }
      throw new Error(`Multiple sessions active (${availableNames.join(", ")}). Specify which session to use with the 'session' parameter.`);
    }
    return defaultSessionName;
  }

  if (!availableNames.includes(requestedName)) {
    const available = availableNames.length > 0 ? ` Available: ${availableNames.join(", ")}` : "";
    throw new Error(`Session '${requestedName}' not found.${available}`);
  }
  return requestedName;
}

export function buildMarkerCommand(shellFamily: ShellFamily, command: string, marker: string): string {
  return shellFamily === "powershell"
    ? `${command}\nWrite-Host '${psSingleQuote(marker)}'`
    : shellFamily === "cmd"
      ? `${command}\r\necho ${marker}`
      : `${command}\necho ${shellSingleQuote(marker)}`;
}

export function buildTunnelSpec(type: TunnelType, localPort: number, remoteHost?: string, remotePort?: number): { forwardSpec: string; sshArgs: string[] } {
  switch (type) {
    case "local":
      return {
        forwardSpec: `L ${localPort}:${remoteHost}:${remotePort}`,
        sshArgs: ["-L", `${localPort}:${remoteHost}:${remotePort}`],
      };
    case "remote":
      return {
        forwardSpec: `R ${remotePort}:localhost:${localPort}`,
        sshArgs: ["-R", `${remotePort}:localhost:${localPort}`],
      };
    case "dynamic":
      return {
        forwardSpec: `D ${localPort}`,
        sshArgs: ["-D", String(localPort)],
      };
  }
}

export function buildTunnelDescription(type: TunnelType, via: string, localPort: number, remoteHost?: string, remotePort?: number, description?: string): string {
  if (description) return description;
  return type === "dynamic"
    ? `SOCKS proxy via ${via}`
    : type === "local"
      ? `local forward ${localPort}→${remoteHost}:${remotePort} via ${via}`
      : `remote forward ${remotePort}→localhost:${localPort} via ${via}`;
}

export function buildTunnelUsageHint(type: TunnelType, via: string, localPort: number, remotePort?: number): string {
  if (type === "local") {
    return `Access via: localhost:${localPort}\nPivot: remote_connect(protocol="ssh", target="user@localhost", port=${localPort}, name="next-hop")`;
  }
  if (type === "dynamic") {
    return `SOCKS5 proxy at: localhost:${localPort}\nUsage: proxychains nmap -sT -Pn <targets> or proxychains crackmapexec smb <targets>`;
  }
  return `Remote forward active: connections to ${via}:${remotePort} are forwarded to localhost:${localPort} on the harness.`;
}

// -------------------------------------------------------------------
// Relay helpers
// -------------------------------------------------------------------

export type RelayMethod = "ncat" | "socat" | "nc-openbsd" | "nc-traditional" | "netsh-portproxy";

export interface RelaySpec {
  method: RelayMethod;
  listenPort: number;
  targetHost: string;
  targetPort: number;
  listenAddress?: string;
}

const SAFE_RELAY_HOST_RE = /^[A-Za-z0-9_.:-]+$/;
const RELAY_METHODS = new Set<RelayMethod>(["ncat", "socat", "nc-openbsd", "nc-traditional", "netsh-portproxy"]);

export function validateRelayPort(port: number, fieldName = "port"): void {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${fieldName} must be an integer from 1 to 65535.`);
  }
}

export function validateRelayHost(value: string | undefined, fieldName: string): void {
  if (!value) throw new Error(`${fieldName} is required.`);
  if (value.length > 255) throw new Error(`${fieldName} is too long.`);
  if (value.startsWith("-")) throw new Error(`${fieldName} must not start with '-'.`);
  if (!SAFE_RELAY_HOST_RE.test(value)) {
    throw new Error(`${fieldName} contains unsafe characters. Use only hostnames or IP addresses.`);
  }
}

export function validateRelaySpec(spec: RelaySpec): void {
  if (!RELAY_METHODS.has(spec.method)) throw new Error(`Unsupported relay method: ${String(spec.method)}`);
  validateRelayPort(spec.listenPort, "listen_port");
  validateRelayPort(spec.targetPort, "target_port");
  validateRelayHost(spec.targetHost, "target_host");
  if (spec.listenAddress) validateRelayHost(spec.listenAddress, "listen_address");
}

function hasCommand(probeOutput: string, command: string): boolean {
  const re = new RegExp(`(^|[\\s/])${command}($|[\\s:])`, "i");
  return re.test(probeOutput);
}

/**
 * Detect which relay tools are available on a host given the output of
 * a probe command. Returns methods in priority order.
 */
export function detectRelayMethods(probeOutput: string, platform: string): RelayMethod[] {
  const methods: RelayMethod[] = [];
  const out = probeOutput.toLowerCase();

  if (platform === "windows") {
    // netsh is always available on Windows
    methods.push("netsh-portproxy");
    if (hasCommand(probeOutput, "ncat")) methods.push("ncat");
    return methods;
  }

  // Unix/Linux/macOS priority order
  if (hasCommand(probeOutput, "socat")) methods.push("socat");
  if (hasCommand(probeOutput, "ncat")) methods.push("ncat");
  // nc detection: check flavor. Do not treat "ncat" as "nc".
  if (out.includes("openbsd") || out.includes("netcat-openbsd")) methods.push("nc-openbsd");
  else if (hasCommand(probeOutput, "nc") || hasCommand(probeOutput, "netcat")) methods.push("nc-traditional");

  return methods;
}

/**
 * Build the relay command string for a given method and spec.
 */
export function buildRelayCommand(spec: RelaySpec): string {
  validateRelaySpec(spec);
  const { method, listenPort, targetHost, targetPort, listenAddress } = spec;
  const bindAddr = listenAddress || "0.0.0.0";

  switch (method) {
    case "socat":
      return `socat TCP-LISTEN:${listenPort},bind=${bindAddr},fork,reuseaddr TCP:${targetHost}:${targetPort} &`;

    case "ncat":
      return `ncat -l ${bindAddr} ${listenPort} --sh-exec 'ncat ${targetHost} ${targetPort}' &`;

    case "nc-openbsd":
      // OpenBSD nc doesn't have --sh-exec; use a fifo
      return `rm -f /tmp/.r${listenPort} && mkfifo /tmp/.r${listenPort} && (nc -l ${bindAddr} ${listenPort} < /tmp/.r${listenPort} | nc ${targetHost} ${targetPort} > /tmp/.r${listenPort} &)`;

    case "nc-traditional":
      return `rm -f /tmp/.r${listenPort} && mkfifo /tmp/.r${listenPort} && (nc -l -p ${listenPort} < /tmp/.r${listenPort} | nc ${targetHost} ${targetPort} > /tmp/.r${listenPort} &)`;

    case "netsh-portproxy":
      return `netsh interface portproxy add v4tov4 listenport=${listenPort} listenaddress=${bindAddr} connectport=${targetPort} connectaddress=${targetHost}`;

    default:
      throw new Error(`Unsupported relay method: ${String(method)}`);
  }
}

/**
 * Build the cleanup command to tear down a relay.
 */
export function buildRelayCleanupCommand(spec: RelaySpec): string {
  validateRelaySpec(spec);
  const { method, listenPort, listenAddress } = spec;
  const bindAddr = listenAddress || "0.0.0.0";

  switch (method) {
    case "socat":
      return `pkill -f 'socat TCP-LISTEN:${listenPort}' 2>/dev/null; echo 'relay stopped'`;

    case "ncat":
      return `pkill -f 'ncat -l.*${listenPort}' 2>/dev/null; echo 'relay stopped'`;

    case "nc-openbsd":
    case "nc-traditional":
      return `pkill -f 'nc -l.*${listenPort}' 2>/dev/null; rm -f /tmp/.r${listenPort}; echo 'relay stopped'`;

    case "netsh-portproxy":
      return `netsh interface portproxy delete v4tov4 listenport=${listenPort} listenaddress=${bindAddr}`;

    default:
      throw new Error(`Unsupported relay method: ${String(method)}`);
  }
}

/**
 * Build the probe command to detect available relay tools on a host.
 */
export function buildRelayProbeCommand(platform: string): string {
  if (platform === "windows") {
    return `Write-Output 'netsh'; if (Get-Command ncat -ErrorAction SilentlyContinue) { Write-Output 'ncat' }`;
  }
  return `which socat ncat nc netcat 2>/dev/null; nc -h 2>&1 | head -3; file /bin/nc 2>/dev/null`;
}

/**
 * Build a verification command to check if the relay is listening.
 */
export function buildRelayVerifyCommand(spec: RelaySpec): string {
  validateRelaySpec(spec);
  if (spec.method === "netsh-portproxy") {
    return `netsh interface portproxy show v4tov4`;
  }
  return `ss -tlnp 2>/dev/null | grep ':${spec.listenPort}' || netstat -tlnp 2>/dev/null | grep ':${spec.listenPort}' || echo 'unable to verify listener'`;
}

export function processTelnetBytes(state: TelnetState | undefined, data: Buffer | number[]): { text: string; replies: number[][]; state: TelnetState } {
  const nextState: TelnetState = state ? { ...state } : { mode: "data" };
  const out: number[] = [];
  const replies: number[][] = [];
  const IAC = 255;
  const DO = 253;
  const DONT = 254;
  const WILL = 251;
  const WONT = 252;
  const SB = 250;
  const SE = 240;

  for (const byte of data) {
    switch (nextState.mode) {
      case "data":
        if (byte === IAC) nextState.mode = "iac";
        else out.push(byte);
        break;
      case "iac":
        if (byte === IAC) {
          out.push(byte);
          nextState.mode = "data";
        } else if ([DO, DONT, WILL, WONT].includes(byte)) {
          nextState.command = byte;
          nextState.mode = "iac-command";
        } else if (byte === SB) {
          nextState.mode = "sb";
        } else {
          nextState.mode = "data";
        }
        break;
      case "iac-command":
        if (nextState.command === DO) replies.push([IAC, WONT, byte]);
        else if (nextState.command === WILL) replies.push([IAC, DONT, byte]);
        nextState.command = undefined;
        nextState.mode = "data";
        break;
      case "sb":
        if (byte === IAC) nextState.mode = "sb-iac";
        break;
      case "sb-iac":
        nextState.mode = byte === SE ? "data" : "sb";
        break;
    }
  }

  return { text: Buffer.from(out).toString(), replies, state: nextState };
}
