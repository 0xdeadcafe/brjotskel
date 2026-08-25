/**
 * Relay lifecycle manager.
 *
 * Handles relay method detection, command construction, execution, and
 * verification on pivot hosts. Accepts execFn and logFn so it has no
 * direct dependency on the session registry or the main extension closure.
 */
import type { RelayInfo, RemoteSession } from "./remote-types.ts";
import type { RelayMethod, RelaySpec } from "./remote-session-core.ts";
import {
  buildRelayProbeCommand,
  buildRelayCommand,
  buildRelayCleanupCommand,
  buildRelayVerifyCommand,
  buildRelayDescription,
  detectRelayMethods,
  relayVerifyOutputConfirmsListening,
  validateRelaySpec,
} from "./remote-session-core.ts";

export type ExecFn = (session: RemoteSession, command: string, timeoutMs: number) => Promise<string>;
export type LogFn  = (sessionName: string, direction: ">>>" | "<<<" | "---", content: string) => void;

export interface RelaySetupOptions {
  session: RemoteSession;
  targetHost: string;
  targetPort: number;
  listenPort: number;
  listenAddress?: string;
  method?: RelayMethod | "auto";
  description?: string;
  relayId: string;
}

/**
 * Detect tools, validate, execute the relay command, and verify it is
 * listening. Returns the populated RelayInfo on success; throws on failure
 * (including unverified listening — cleanup is attempted before throwing).
 */
export async function setupRelay(
  options: RelaySetupOptions,
  execFn: ExecFn,
  logFn: LogFn,
): Promise<RelayInfo> {
  const { session } = options;

  // Determine relay method
  let method: RelayMethod;
  if (!options.method || options.method === "auto") {
    const probeCmd    = buildRelayProbeCommand(session.info.platform);
    const probeOutput = await execFn(session, probeCmd, 10_000);
    const available   = detectRelayMethods(probeOutput, session.info.platform);
    if (available.length === 0) {
      throw new Error(
        `No relay tools detected on '${session.info.name}' (${session.info.platform}). ` +
        `Probe output:\n${probeOutput}\n\nTry specifying method manually or use remote_tunnel ` +
        `through an SSH-capable pivot.`,
      );
    }
    method = available[0];
  } else {
    method = options.method as RelayMethod;
  }

  const spec: RelaySpec = {
    method,
    listenPort:    options.listenPort,
    targetHost:    options.targetHost,
    targetPort:    options.targetPort,
    listenAddress: options.listenAddress,
  };
  validateRelaySpec(spec);

  logFn(session.info.name, ">>>", `[RELAY SETUP] ${method} :${options.listenPort} → ${options.targetHost}:${options.targetPort}`);
  await execFn(session, buildRelayCommand(spec), 10_000);

  // Brief pause then verify listening
  await new Promise(r => setTimeout(r, 1000));
  const verifyOutput = await execFn(session, buildRelayVerifyCommand(spec), 10_000);
  const listening    = relayVerifyOutputConfirmsListening(spec, verifyOutput);

  if (!listening) {
    let cleanupNote = "cleanup not run";
    try {
      const out = await execFn(session, buildRelayCleanupCommand(spec), 10_000);
      cleanupNote = out.trim() || "cleanup command sent";
    } catch (err: any) {
      cleanupNote = `cleanup failed: ${err.message}`;
    }
    logFn(session.info.name, "---", `[RELAY SETUP FAILED] ${method} :${options.listenPort} → ${options.targetHost}:${options.targetPort}; ${cleanupNote}`);
    throw new Error(
      `Relay not verified as listening on port ${options.listenPort}; cleanup attempted.\n` +
      `Verify output:\n${verifyOutput}\nCleanup: ${cleanupNote}`,
    );
  }

  const description =
    options.description ||
    buildRelayDescription(method, session.info.name, options.listenPort, options.targetHost, options.targetPort);

  const info: RelayInfo = {
    id:            options.relayId,
    session:       session.info.name,
    method,
    listenPort:    options.listenPort,
    targetHost:    options.targetHost,
    targetPort:    options.targetPort,
    listenAddress: options.listenAddress,
    createdAt:     new Date(),
    description,
  };

  logFn(session.info.name, "---", `[RELAY CREATED] ${options.relayId}: ${method} :${options.listenPort} → ${options.targetHost}:${options.targetPort}`);
  return info;
}

/**
 * Tear down a single relay: run the cleanup command on the pivot session
 * (if available) and remove from the relay list. Returns a status string
 * suitable for operator display.
 */
export async function teardownRelay(
  relay: RelayInfo,
  relays: RelayInfo[],
  sessionFn: (name: string) => RemoteSession | undefined,
  execFn: ExecFn,
  logFn: LogFn,
): Promise<string> {
  const session = sessionFn(relay.session);
  const spec: RelaySpec = {
    method:        relay.method as RelayMethod,
    listenPort:    relay.listenPort,
    targetHost:    relay.targetHost,
    targetPort:    relay.targetPort,
    listenAddress: relay.listenAddress,
  };

  let statusMsg: string;
  if (session && !session.process.killed) {
    try {
      const out = await execFn(session, buildRelayCleanupCommand(spec), 10_000);
      statusMsg = `${relay.id}: closed (${out.trim()})`;
    } catch {
      statusMsg = `${relay.id}: cleanup command failed (session may be dead)`;
    }
  } else {
    statusMsg = `${relay.id}: session '${relay.session}' unavailable — relay may still be running on host`;
  }

  logFn(relay.session, "---", `[RELAY CLOSED] ${relay.id}`);
  const idx = relays.findIndex(r => r.id === relay.id);
  if (idx !== -1) relays.splice(idx, 1);
  return statusMsg;
}
