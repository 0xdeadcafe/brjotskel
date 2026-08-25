import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import {
  closeTunnel,
  closeAllTunnels,
} from '../../.pi/extensions/lib/tunnel-manager.ts';

// -------------------------------------------------------------------
// Minimal mock ChildProcess — enough for kill/exit tracking
// -------------------------------------------------------------------
function makeMockProcess(opts = {}) {
  const emitter = new EventEmitter();
  const proc = Object.assign(emitter, {
    pid: 12345,
    killed: false,
    exitCode: null,
    kill: function (signal) {
      this.killed = true;
      this.killSignal = signal;
    },
    killSignal: undefined,
    stderr: new EventEmitter(),
    stdout: new EventEmitter(),
    ...opts,
  });
  return proc;
}

function makeTunnel(id, proc) {
  return {
    id,
    type: 'local',
    via: 'root@web01',
    localPort: 2222,
    remoteHost: 'internal01',
    remotePort: 22,
    process: proc,
    createdAt: new Date(),
    description: `local forward 2222→internal01:22 via root@web01`,
  };
}

// -------------------------------------------------------------------
// closeTunnel
// -------------------------------------------------------------------

test('closeTunnel kills the process and removes it from the array', () => {
  const proc = makeMockProcess();
  const tunnels = [makeTunnel('tun-1', proc)];

  const result = closeTunnel(tunnels, 'tun-1');

  assert.equal(result, true);
  assert.equal(tunnels.length, 0);
  assert.equal(proc.killed, true);
});

test('closeTunnel returns false and leaves array intact when ID is not found', () => {
  const proc = makeMockProcess();
  const tunnels = [makeTunnel('tun-1', proc)];

  const result = closeTunnel(tunnels, 'tun-999');

  assert.equal(result, false);
  assert.equal(tunnels.length, 1);
  assert.equal(proc.killed, false);
});

test('closeTunnel only removes the matching entry when multiple tunnels are present', () => {
  const proc1 = makeMockProcess({ pid: 111 });
  const proc2 = makeMockProcess({ pid: 222 });
  const tunnels = [makeTunnel('tun-1', proc1), makeTunnel('tun-2', proc2)];

  closeTunnel(tunnels, 'tun-1');

  assert.equal(tunnels.length, 1);
  assert.equal(tunnels[0].id, 'tun-2');
  assert.equal(proc1.killed, true);
  assert.equal(proc2.killed, false);
});

test('closeTunnel survives if process.kill() throws', () => {
  const proc = makeMockProcess({
    kill: function () { throw new Error('ESRCH: no such process'); },
  });
  const tunnels = [makeTunnel('tun-1', proc)];

  // Should not throw; tunnel still removed
  assert.doesNotThrow(() => closeTunnel(tunnels, 'tun-1'));
  assert.equal(tunnels.length, 0);
});

// -------------------------------------------------------------------
// closeAllTunnels
// -------------------------------------------------------------------

test('closeAllTunnels kills all processes and empties the array', () => {
  const procs = [makeMockProcess({ pid: 1 }), makeMockProcess({ pid: 2 }), makeMockProcess({ pid: 3 })];
  const tunnels = procs.map((p, i) => makeTunnel(`tun-${i + 1}`, p));

  const count = closeAllTunnels(tunnels);

  assert.equal(count, 3);
  assert.equal(tunnels.length, 0);
  for (const p of procs) {
    assert.equal(p.killed, true);
  }
});

test('closeAllTunnels on an empty array returns 0 and does not throw', () => {
  const tunnels = [];
  const count = closeAllTunnels(tunnels);
  assert.equal(count, 0);
  assert.equal(tunnels.length, 0);
});

test('closeAllTunnels returns the count of tunnels that were present', () => {
  const tunnels = [
    makeTunnel('tun-1', makeMockProcess()),
    makeTunnel('tun-2', makeMockProcess()),
  ];
  const count = closeAllTunnels(tunnels);
  assert.equal(count, 2);
});

test('closeAllTunnels survives if one process.kill() throws', () => {
  const good = makeMockProcess({ pid: 1 });
  const bad = makeMockProcess({
    pid: 2,
    kill: function () { throw new Error('already dead'); },
  });
  const tunnels = [makeTunnel('tun-1', good), makeTunnel('tun-2', bad)];

  assert.doesNotThrow(() => closeAllTunnels(tunnels));
  assert.equal(tunnels.length, 0);
  assert.equal(good.killed, true);
});
