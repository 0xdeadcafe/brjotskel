import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, existsSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { intelLockPath, withIntelFileLock } from '../../.pi/extensions/lib/intel-lock.ts';

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function tmpIntelDir() {
  return mkdtempSync(join(tmpdir(), 'brjotskel-intel-lock-test-'));
}

test('withIntelFileLock serializes concurrent read-modify-write sections', async () => {
  const intelDir = tmpIntelDir();
  const events = [];

  const first = withIntelFileLock(intelDir, async () => {
    events.push('first:start');
    await sleep(80);
    events.push('first:end');
  }, { pollMs: 5, timeoutMs: 1000 });

  await sleep(10);

  const second = withIntelFileLock(intelDir, async () => {
    events.push('second:start');
    events.push('second:end');
  }, { pollMs: 5, timeoutMs: 1000 });

  await Promise.all([first, second]);
  assert.deepEqual(events, ['first:start', 'first:end', 'second:start', 'second:end']);
  assert.equal(existsSync(intelLockPath(intelDir)), false);
});

test('withIntelFileLock releases the lock when the critical section throws', async () => {
  const intelDir = tmpIntelDir();

  await assert.rejects(
    withIntelFileLock(intelDir, async () => {
      throw new Error('boom');
    }, { pollMs: 5, timeoutMs: 1000 }),
    /boom/,
  );

  assert.equal(existsSync(intelLockPath(intelDir)), false);
});

test('withIntelFileLock reclaims stale locks', async () => {
  const intelDir = tmpIntelDir();
  const lockDir = intelLockPath(intelDir);
  mkdirSync(lockDir, { mode: 0o700 });
  const old = new Date(Date.now() - 60_000);
  utimesSync(lockDir, old, old);

  const result = await withIntelFileLock(intelDir, () => 'acquired', { staleMs: 1, pollMs: 5, timeoutMs: 1000 });
  assert.equal(result, 'acquired');
  assert.equal(existsSync(lockDir), false);
});

test('withIntelFileLock times out when another process holds a fresh lock', async () => {
  const intelDir = tmpIntelDir();
  mkdirSync(intelLockPath(intelDir), { mode: 0o700 });

  await assert.rejects(
    withIntelFileLock(intelDir, () => 'nope', { staleMs: 60_000, pollMs: 5, timeoutMs: 30 }),
    /Timed out waiting for intel store lock/,
  );
});
