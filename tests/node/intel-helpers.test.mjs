import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ensureArray,
  normalizeSource,
  normalizeIntelEntry,
  validateIntelEntry,
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
});

test('validateIntelEntry enforces minimal required fields', () => {
  assert.throws(() => validateIntelEntry('credential', { username: 'alice' }), /type' and 'username/);
  assert.throws(() => validateIntelEntry('pivot', { chain: [] }), /require 'target'/);
  assert.doesNotThrow(() => validateIntelEntry('credential', { type: 'password', username: 'alice' }));
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
