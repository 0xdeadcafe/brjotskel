import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { readIntelSnapshot, buildScopeText } from '../../.pi/extensions/lib/operator-runtime.ts';

function writeYaml(path, content) {
  writeFileSync(path, content);
}

test('readIntelSnapshot maps credentials and host metadata for operator commands', () => {
  const root = mkdtempSync(join(tmpdir(), 'brjotskel-runtime-'));
  const intel = join(root, 'workspace', 'intel');
  try {
    writeFileSync(join(root, 'marker'), '');
    mkdirSync(intel, { recursive: true });
    writeYaml(join(intel, 'hosts.yaml'), `hosts:
  dc01:
    ip: 10.10.10.20
    platform: windows
    endpoints:
      - tcp://10.10.10.20:445
  web01:
    ip: 10.10.10.5
    platform: linux
`);
    writeYaml(join(intel, 'credentials.yaml'), `credentials:
  admin-ntlm:
    type: ntlm-hash
    username: Administrator
    domain: CORP
    status: confirmed
    valid_on:
      - dc01
  stale:
    type: password
    username: old
    status: rotated
  newpass:
    type: password
    username: svc
    status: active
`);
    const snap = readIntelSnapshot(root, {});
    assert.ok(snap.raw);
    assert.equal(snap.pursue.knownHostIds.length, 2);
    assert.deepEqual(snap.pursue.activeCreds.map(c => c.id), ['admin-ntlm']);
    assert.deepEqual(snap.pursue.unvalidatedCreds.map(c => c.id), ['newpass']);
    assert.equal(snap.pursue.knownHosts.find(h => h.id === 'dc01').platform, 'windows');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('buildScopeText renders sessions, pivots, and timestamp or ts timeline entries', () => {
  const proc = { killed: false, exitCode: null };
  const sessions = new Map([
    ['web01', { process: proc, info: { name: 'web01', protocol: 'ssh', target: 'root@10.10.10.5', platform: 'linux', commandCount: 2 } }],
  ]);
  const text = buildScopeText(
    sessions,
    [{ id: 'tun-1', type: 'dynamic', localPort: 1080, via: 'root@web01', process: proc }],
    [{ id: 'relay-1', method: 'socat', session: 'web01', listenPort: 4445, targetHost: 'dc01', targetPort: 445 }],
    'web01',
    {
      hosts: { web01: { status: 'compromised' } },
      credentials: { c1: { status: 'active' }, c2: { status: 'active', valid_on: ['web01'] } },
      accounts: {},
      pivots: {},
      timeline: [{ ts: '2026-08-25T10:00:00Z', summary: 'old' }, { timestamp: '2026-08-25T11:00:00Z', summary: 'new' }],
    },
  );
  assert.match(text, /Sessions \(1\):/);
  assert.match(text, /web01 \*/);
  assert.match(text, /Tunnels \(1\):/);
  assert.match(text, /Relays \(1\):/);
  assert.match(text, /1 hosts \(1 compromised\).*2 creds \(2 active, 1 unvalidated\)/);
  assert.match(text, /2026-08-25 11:00:00  new/);
  assert.match(text, /2026-08-25 10:00:00  old/);
});
