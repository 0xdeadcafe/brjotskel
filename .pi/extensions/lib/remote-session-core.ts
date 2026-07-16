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
      : `${command}\necho '${shellSingleQuote(marker)}'`;
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
