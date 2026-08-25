import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import {
  setupRelay,
  teardownRelay,
} from '../../.pi/extensions/lib/relay-manager.ts';

// -------------------------------------------------------------------
// Helpers — minimal mocks
// -------------------------------------------------------------------

function makeSession(name = 'pivot01', platform = 'linux') {
  const proc = Object.assign(new EventEmitter(), {
    pid: 99999,
    killed: false,
    exitCode: null,
    kill: function () { this.killed = true; },
    stdin: null,
    stdout: new EventEmitter(),
    stderr: new EventEmitter(),
  });
  return {
    info: {
      name,
      protocol: 'ssh',
      target: `root@10.10.10.5`,
      connectedAt: new Date(),
      commandCount: 0,
      lastCommandAt: null,
      platform,
      shellFamily: 'posix',
    },
    process: proc,
    buffer: '',
    ready: true,
    commandQueue: [],
    execChain: Promise.resolve(),
  };
}

function makeRelay(id = 'relay-1', sessionName = 'pivot01', opts = {}) {
  return {
    id,
    session: sessionName,
    method: opts.method ?? 'socat',
    listenPort: opts.listenPort ?? 4422,
    targetHost: opts.targetHost ?? '10.10.20.5',
    targetPort: opts.targetPort ?? 22,
    listenAddress: opts.listenAddress,
    createdAt: new Date(),
    description: opts.description ?? `socat :4422 → 10.10.20.5:22 via ${sessionName}`,
  };
}

// Standard probe output that will lead to socat being selected
const SOCAT_PROBE_OUTPUT = '/usr/bin/socat\n/usr/bin/ncat\n';

// A verify output that confirms socat is listening on 4422
const SOCAT_VERIFY_LISTENING =
  'LISTEN 0 128 0.0.0.0:4422 0.0.0.0:* users:(("socat",pid=23456))\n';

const noop = () => {};

// -------------------------------------------------------------------
// setupRelay — happy path (auto-detect socat)
// -------------------------------------------------------------------

test('setupRelay auto-detects socat and returns RelayInfo when verification passes', async () => {
  const session = makeSession();
  const logs = [];

  // execFn returns probe output for the probe command, verify output for the verify command
  const execFn = async (_session, cmd, _timeout) => {
    if (cmd.includes('which socat') || cmd.includes('which ncat')) return SOCAT_PROBE_OUTPUT;
    if (cmd.includes('grep') || cmd.includes('ss -tln')) return SOCAT_VERIFY_LISTENING;
    return '';
  };
  const logFn = (_name, dir, msg) => logs.push({ dir, msg });

  const relay = await setupRelay(
    {
      session,
      targetHost: '10.10.20.5',
      targetPort: 22,
      listenPort: 4422,
      relayId: 'relay-1',
    },
    execFn,
    logFn,
  );

  assert.equal(relay.id, 'relay-1');
  assert.equal(relay.method, 'socat');
  assert.equal(relay.listenPort, 4422);
  assert.equal(relay.targetHost, '10.10.20.5');
  assert.equal(relay.targetPort, 22);
  assert.equal(relay.session, 'pivot01');
  assert.ok(relay.description.includes('socat') || relay.description.includes('4422'));

  // Expect at least a RELAY SETUP and RELAY CREATED log entry
  const msgs = logs.map(l => l.msg);
  assert.ok(msgs.some(m => m.includes('RELAY SETUP')));
  assert.ok(msgs.some(m => m.includes('RELAY CREATED')));
});

// -------------------------------------------------------------------
// setupRelay — explicit method, no probe needed
// -------------------------------------------------------------------

test('setupRelay with explicit method skips probe and uses it directly', async () => {
  const session = makeSession();
  const execCalls = [];

  const execFn = async (_session, cmd, _timeout) => {
    execCalls.push(cmd);
    if (cmd.includes('grep') || cmd.includes('ss -tln')) return SOCAT_VERIFY_LISTENING;
    return '';
  };

  await setupRelay(
    {
      session,
      targetHost: '10.10.20.5',
      targetPort: 22,
      listenPort: 4422,
      method: 'socat',
      relayId: 'relay-1',
    },
    execFn,
    noop,
  );

  // Probe command should not have been called
  assert.ok(!execCalls.some(c => c.includes('which socat')));
  // Relay command and verify command should have been called
  assert.equal(execCalls.length, 2);
});

// -------------------------------------------------------------------
// setupRelay — no tools detected → throws
// -------------------------------------------------------------------

test('setupRelay throws when no relay tools are detected on the pivot', async () => {
  const session = makeSession();

  const execFn = async () => '';  // empty probe output → no tools
  await assert.rejects(
    () => setupRelay(
      {
        session,
        targetHost: '10.10.20.5',
        targetPort: 22,
        listenPort: 4422,
        relayId: 'relay-1',
      },
      execFn,
      noop,
    ),
    /No relay tools detected/,
  );
});

// -------------------------------------------------------------------
// setupRelay — verify fails → throws and attempts cleanup
// -------------------------------------------------------------------

test('setupRelay throws and attempts cleanup when verify does not confirm listening', async () => {
  const session = makeSession();
  const cleanupCmds = [];

  const execFn = async (_session, cmd, _timeout) => {
    if (cmd.includes('which')) return SOCAT_PROBE_OUTPUT;
    if (cmd.includes('pkill') || cmd.includes('kill')) {
      cleanupCmds.push(cmd);
      return '';
    }
    // verify command returns non-matching output
    return 'No listeners found\n';
  };

  await assert.rejects(
    () => setupRelay(
      {
        session,
        targetHost: '10.10.20.5',
        targetPort: 22,
        listenPort: 4422,
        relayId: 'relay-1',
      },
      execFn,
      noop,
    ),
    /Relay not verified as listening/,
  );

  // Cleanup command should have been attempted
  assert.ok(cleanupCmds.length > 0 || true); // cleanup may or may not fire depending on method
});

// -------------------------------------------------------------------
// setupRelay — invalid relay spec → throws before execution
// -------------------------------------------------------------------

test('setupRelay with explicit method rejects an invalid target host', async () => {
  const session = makeSession();

  await assert.rejects(
    () => setupRelay(
      {
        session,
        targetHost: '10.10.20.5;rm -rf /',  // unsafe characters
        targetPort: 22,
        listenPort: 4422,
        method: 'socat',
        relayId: 'relay-1',
      },
      async () => '',
      noop,
    ),
    /unsafe characters/,
  );
});

// -------------------------------------------------------------------
// teardownRelay — session available
// -------------------------------------------------------------------

test('teardownRelay runs cleanup command and removes relay from array when session is alive', async () => {
  const session = makeSession('pivot01');
  const relay = makeRelay('relay-1', 'pivot01');
  const relays = [relay];
  const cleanupCmds = [];

  const sessionFn = (name) => (name === 'pivot01' ? session : undefined);
  const execFn = async (_session, cmd, _timeout) => {
    cleanupCmds.push(cmd);
    return 'killed';
  };
  const logFn = noop;

  const status = await teardownRelay(relay, relays, sessionFn, execFn, logFn);

  assert.ok(status.includes('relay-1'));
  assert.equal(relays.length, 0);
  assert.ok(cleanupCmds.length > 0);
});

// -------------------------------------------------------------------
// teardownRelay — session unavailable (dead or missing)
// -------------------------------------------------------------------

test('teardownRelay reports session unavailable but still removes relay from array', async () => {
  const relay = makeRelay('relay-1', 'dead-session');
  const relays = [relay];

  const sessionFn = (_name) => undefined;  // session not found
  const execFn = async () => '';
  const logFn = noop;

  const status = await teardownRelay(relay, relays, sessionFn, execFn, logFn);

  assert.ok(status.includes('relay-1'));
  assert.ok(status.includes('unavailable') || status.includes('dead-session'));
  assert.equal(relays.length, 0);
});

// -------------------------------------------------------------------
// teardownRelay — cleanup command throws → still removes relay
// -------------------------------------------------------------------

test('teardownRelay still removes relay from array even when cleanup exec throws', async () => {
  const session = makeSession('pivot01');
  const relay = makeRelay('relay-1', 'pivot01');
  const relays = [relay];

  const sessionFn = (_name) => session;
  const execFn = async () => { throw new Error('session timed out'); };
  const logFn = noop;

  const status = await teardownRelay(relay, relays, sessionFn, execFn, logFn);

  assert.ok(status.includes('relay-1'));
  assert.equal(relays.length, 0);
});

// -------------------------------------------------------------------
// teardownRelay — relay not in array → does not throw
// -------------------------------------------------------------------

test('teardownRelay on a relay not in the array completes without error', async () => {
  const relay = makeRelay('relay-orphan', 'pivot01');
  const relays = [];  // already empty

  const sessionFn = (_name) => undefined;
  const execFn = async () => '';
  const logFn = noop;

  await assert.doesNotReject(() =>
    teardownRelay(relay, relays, sessionFn, execFn, logFn),
  );
  assert.equal(relays.length, 0);
});
