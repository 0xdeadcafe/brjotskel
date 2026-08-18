import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ensureArray,
  normalizeSource,
  normalizeIntelEntry,
  validateIntelEntry,
  validateIntelStatusTransition,
  INTEL_STATUS_ENUMS,
  CREDENTIAL_TYPE_VALUES,
  resolveIntelDir,
  resolveStoredPath,
} from '../../.pi/extensions/lib/intel-helpers.ts';

test('ensureArray normalizes scalars, arrays, and empty values', () => {
  assert.deepEqual(ensureArray('db01'), ['db01']);
  assert.deepEqual(ensureArray(['db01', 'app01']), ['db01', 'app01']);
  assert.deepEqual(ensureArray(undefined), []);
  assert.deepEqual(ensureArray(null), []);
});

test('normalizeSource upgrades shorthand forms', () => {
  assert.deepEqual(normalizeSource('saved PuTTY session'), { method: 'saved PuTTY session' });
  assert.deepEqual(normalizeSource({ discovered_from: 'ansible inventory', host: 'web01' }), {
    discovered_from: 'ansible inventory',
    host: 'web01',
    method: 'ansible inventory',
  });
});

test('normalizeIntelEntry expands category-specific arrays and discovered source', () => {
  const host = normalizeIntelEntry('host', {
    endpoints: 'ssh://deploy@10.10.20.10:22',
    profile_artifacts: 'ansible-inventory',
    source: 'ansible inventory',
    discovered: {},
  });

  assert.deepEqual(host.endpoints, ['ssh://deploy@10.10.20.10:22']);
  assert.deepEqual(host.profile_artifacts, ['ansible-inventory']);
  assert.equal(host.discovered.source, 'ansible inventory');

  const credential = normalizeIntelEntry('credential', {
    type: 'ssh-key',
    username: 'deploy',
    valid_on: 'db01',
    related_hosts: 'jump01',
  });

  assert.deepEqual(credential.valid_on, ['db01']);
  assert.deepEqual(credential.related_hosts, ['jump01']);

  const partial = normalizeIntelEntry('credential', { status: 'Confirmed' }, { partial: true });
  assert.deepEqual(partial, { status: 'confirmed' });
});

test('validateIntelEntry enforces category schemas, source, and enums', () => {
  assert.ok(INTEL_STATUS_ENUMS.host.includes('contained'));
  assert.ok(CREDENTIAL_TYPE_VALUES.includes('ssh-key'));

  assert.throws(
    () => validateIntelEntry('credential', { username: 'alice', status: 'active', source: { method: 'test' }, secret: 'pw' }),
    /Missing required 'type'/,
  );
  assert.throws(
    () => validateIntelEntry('credential', { type: 'magic', username: 'alice', status: 'active', source: { method: 'test' }, secret: 'pw' }),
    /Invalid 'type' value 'magic'/,
  );
  assert.throws(
    () => validateIntelEntry('host', { status: 'compromised', ip: '10.0.0.5' }),
    /source\.method/,
  );
  assert.throws(
    () => validateIntelEntry('host', { status: 'compromised', source: { method: 'scan' } }),
    /at least one locator/,
  );
  assert.throws(
    () => validateIntelEntry('pivot', { target: 'db01', status: 'suspected', chain: [], source: { method: 'test' } }),
    /non-empty 'chain'/,
  );
  assert.throws(
    () => validateIntelEntry('account', { type: 'domain-user', status: 'compromised', source: { method: 'AD enum' } }),
    /Missing required 'username'/,
  );

  assert.doesNotThrow(() => validateIntelEntry('credential', {
    type: 'password',
    username: 'alice',
    secret: 'pw',
    status: 'active',
    source: 'shadow file',
  }));
  assert.doesNotThrow(() => validateIntelEntry('credential', {
    type: 'ssh-key',
    username: 'deploy',
    key_file: 'keys/deploy',
    status: 'active',
    source: { host: 'web01', method: 'ssh directory' },
  }));
});

test('validateIntelStatusTransition blocks unsafe credential reactivation unless forced', () => {
  assert.doesNotThrow(() => validateIntelStatusTransition('host', 'compromised', 'contained'));
  assert.doesNotThrow(() => validateIntelStatusTransition('credential', 'active', 'rotated'));
  assert.throws(
    () => validateIntelStatusTransition('credential', 'rotated', 'active'),
    /without force=true/,
  );
  assert.doesNotThrow(() => validateIntelStatusTransition('credential', 'rotated', 'active', { force: true }));
});

test('resolveIntelDir defaults to workspace/intel and honors env override', () => {
  assert.equal(resolveIntelDir('/opt/brjotskel'), '/opt/brjotskel/workspace/intel');
  assert.equal(resolveIntelDir('/opt/brjotskel', '/custom/intel'), '/custom/intel');
});

test('resolveStoredPath preserves absolute paths and expands relative ones', () => {
  assert.equal(resolveStoredPath('/tmp/intel', '/etc/krb5cc'), '/etc/krb5cc');
  assert.equal(resolveStoredPath('/tmp/intel', 'keys/deploy-ed25519'), '/tmp/intel/keys/deploy-ed25519');
  assert.equal(resolveStoredPath('/tmp/intel'), '(not stored)');
});
