import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  ensurePrivateDir,
  ensurePrivateFile,
  hardenExistingPrivateFiles,
} from '../../.pi/extensions/lib/intel-permissions.ts';

function mode(path) {
  return statSync(path).mode & 0o777;
}

test('intel permission helpers create private dirs and files', { skip: process.platform === 'win32' }, () => {
  const root = mkdtempSync(join(tmpdir(), 'brjotskel-intel-perms-'));
  try {
    const intelDir = join(root, 'intel');
    ensurePrivateDir(intelDir);
    assert.equal(mode(intelDir), 0o700);

    const creds = join(intelDir, 'credentials.yaml');
    writeFileSync(creds, 'credentials: {}\n', { mode: 0o666 });
    chmodSync(creds, 0o666);
    ensurePrivateFile(creds);
    assert.equal(mode(creds), 0o600);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('hardenExistingPrivateFiles recursively migrates permissive intel stores', { skip: process.platform === 'win32' }, () => {
  const root = mkdtempSync(join(tmpdir(), 'brjotskel-intel-migrate-'));
  try {
    const nested = join(root, 'keys');
    ensurePrivateDir(nested);
    chmodSync(root, 0o755);
    chmodSync(nested, 0o755);

    const timeline = join(root, 'timeline.yaml');
    const keyFile = join(nested, 'id_ed25519');
    writeFileSync(timeline, 'timeline: []\n', { mode: 0o644 });
    writeFileSync(keyFile, 'private-key\n', { mode: 0o644 });
    chmodSync(timeline, 0o644);
    chmodSync(keyFile, 0o644);

    hardenExistingPrivateFiles(root);

    assert.equal(mode(nested), 0o700);
    assert.equal(mode(timeline), 0o600);
    assert.equal(mode(keyFile), 0o600);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
