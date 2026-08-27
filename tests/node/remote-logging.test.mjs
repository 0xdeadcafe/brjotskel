import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  getJsonlLogPath,
  logRemoteCommandEvent,
  logToSession,
  sha256Text,
} from '../../.pi/extensions/lib/remote-types.ts';

function tmpLogDir() {
  return mkdtempSync(join(tmpdir(), 'brjotskel-remote-log-test-'));
}

function fakeSession() {
  return {
    info: {
      name: 'web01',
      protocol: 'ssh',
      target: 'root@10.10.10.5',
      connectedAt: new Date(),
      commandCount: 1,
      lastCommandAt: new Date(),
      platform: 'linux',
      shellFamily: 'posix',
    },
    process: {},
    buffer: '',
    ready: true,
    commandQueue: [],
    execChain: Promise.resolve(),
  };
}

test('logToSession fails loud when the log path cannot be written', () => {
  assert.throws(
    () => logToSession('/dev/null', 'web01', '---', 'cannot create under file'),
    /Failed to write evidence log|ENOTDIR|EEXIST/,
  );
});

test('logRemoteCommandEvent writes hash-chained JSONL command evidence', () => {
  const logDir = tmpLogDir();
  const session = fakeSession();
  const startedAt = new Date('2026-08-27T10:00:00Z');

  logRemoteCommandEvent(logDir, session, {
    commandId: 'cmd-1',
    command: 'whoami',
    status: 'completed',
    startedAt,
    completedAt: new Date('2026-08-27T10:00:01Z'),
    output: 'root',
  });
  logRemoteCommandEvent(logDir, session, {
    commandId: 'cmd-2',
    command: 'id',
    status: 'completed',
    startedAt,
    completedAt: new Date('2026-08-27T10:00:02Z'),
    output: 'uid=0(root)',
  });

  const lines = readFileSync(getJsonlLogPath(logDir, 'web01'), 'utf-8').trim().split('\n');
  assert.equal(lines.length, 2);
  const first = JSON.parse(lines[0]);
  const second = JSON.parse(lines[1]);

  assert.equal(first.event, 'remote_command');
  assert.equal(first.command_id, 'cmd-1');
  assert.equal(first.output_sha256, sha256Text('root'));
  assert.equal(first.output_bytes, 4);
  assert.equal(first.duration_ms, 1000);
  assert.match(first.entry_hash, /^[0-9a-f]{64}$/);
  assert.equal(second.previous_entry_hash, sha256Text(lines[0]));
  assert.match(second.entry_hash, /^[0-9a-f]{64}$/);
});
