export type Platform = "windows" | "linux" | "macos" | "network-device" | "unknown";
export type ShellFamily = "posix" | "powershell" | "cmd" | "unknown";

export function psSingleQuote(value: string): string {
  return value.replace(/'/g, "''");
}

export function shellSingleQuote(value: string): string {
  return value.replace(/'/g, `"'"'`);
}

export function detectSshShell(buffer: string, platformHint?: Platform, shellHint?: ShellFamily): { platform: Platform; shellFamily: ShellFamily } | null {
  const text = buffer.replace(/\r/g, "");
  const lines = text.split("\n").map(line => line.trim()).filter(Boolean);

  if (shellHint === "posix") {
    if (lines.length > 0) return { platform: platformHint === "macos" ? "macos" : (platformHint === "linux" ? "linux" : "linux"), shellFamily: "posix" };
  }
  if (shellHint === "powershell") {
    if (lines.length > 0) return { platform: "windows", shellFamily: "powershell" };
  }
  if (shellHint === "cmd") {
    if (lines.length > 0) return { platform: "windows", shellFamily: "cmd" };
  }

  for (const line of lines) {
    if (/^PS\s+.*>\s*$/.test(line)) return { platform: "windows", shellFamily: "powershell" };
    if (/^[A-Za-z]:\\.*>\s*$/.test(line)) return { platform: "windows", shellFamily: "cmd" };
    if (/^[^\s@]+@[^\s:]+:.*[$#]\s*$/.test(line)) return { platform: "linux", shellFamily: "posix" };
    if (/^.*\s[#$>]\s*$/.test(line) && platformHint === "network-device") {
      return { platform: "network-device", shellFamily: "unknown" };
    }
  }

  if (platformHint === "linux" || platformHint === "macos") {
    if (lines.some(line => /[$#]\s*$/.test(line) || /^(Linux|Darwin)$/i.test(line))) {
      return { platform: platformHint, shellFamily: "posix" };
    }
  }

  if (platformHint === "windows") {
    if (lines.some(line => /^PS\s+.*>\s*$/.test(line))) return { platform: "windows", shellFamily: "powershell" };
    if (lines.some(line => /^[A-Za-z]:\\.*>\s*$/.test(line))) return { platform: "windows", shellFamily: "cmd" };
  }

  return null;
}

export function cleanCommandOutput(_session: unknown, command: string, output: string): string {
  let text = output.replace(/\r/g, "").trim();
  if (!text) return text;

  const lines = text.split("\n");
  const trimmedCommand = command.trim();

  while (lines.length > 0) {
    const first = lines[0].trim();
    if (!first) {
      lines.shift();
      continue;
    }
    if (first === trimmedCommand) {
      lines.shift();
      continue;
    }
    if (trimmedCommand && first.endsWith(trimmedCommand)) {
      lines.shift();
      continue;
    }
    break;
  }

  while (lines.length > 0) {
    const last = lines[lines.length - 1].trim();
    if (!last) {
      lines.pop();
      continue;
    }
    if (/^PS\s+.*>\s*$/.test(last) || /^[A-Za-z]:\\.*>\s*$/.test(last) || /^[^\s@]+@[^\s:]+:.*[$#]\s*$/.test(last)) {
      lines.pop();
      continue;
    }
    break;
  }

  text = lines.join("\n").trim();
  return text;
}
