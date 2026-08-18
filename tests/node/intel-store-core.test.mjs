import test from 'node:test';
import assert from 'node:assert/strict';

import {
  getFileMap,
  getCollectionKeyMap,
  addIntelRecord,
  updateIntelRecord,
  mergeIntelEntry,
  timelineActionForIntelUpdate,
  isInactiveCredentialStatus,
  appendTimelineEntry,
  formatHostQueryResult,
  formatCredentialQueryResult,
  searchIntel,
  formatSearchResult,
  buildIntelSummary,
} from '../../.pi/extensions/lib/intel-store-core.ts';
import { hosts, credentials, accounts, pivots, timeline } from '../fixtures/intel/sample-intel.mjs';

test('file and collection maps match store layout', () => {
  assert.equal(getFileMap().host, 'hosts.yaml');
  assert.equal(getFileMap().pivot, 'pivots.yaml');
  assert.equal(getCollectionKeyMap().account, 'accounts');
  assert.equal(getCollectionKeyMap().pivot, 'paths');
});

test('addIntelRecord inserts entries and refuses accidental duplicate IDs', () => {
  const updated = addIntelRecord({ hosts: { ...hosts } }, 'hosts', 'db01', { ip: '10.10.20.10' });
  assert.equal(updated.hosts.db01.ip, '10.10.20.10');
  assert.equal(updated.hosts.web01.ip, '10.10.10.5');

  assert.throws(
    () => addIntelRecord(updated, 'hosts', 'web01', { ip: '10.10.10.6' }),
    /already exists/,
  );

  const overwritten = addIntelRecord(updated, 'hosts', 'web01', { ip: '10.10.10.6' }, { overwrite: true });
  assert.equal(overwritten.hosts.web01.ip, '10.10.10.6');
});

test('updateIntelRecord deep-merges objects and union-merges arrays by default', () => {
  const updated = updateIntelRecord(
    { credentials: { ...credentials } },
    'credentials',
    'deploy-ssh-key',
    { valid_on: ['db01', 'web01'], source: { tool: 'ssh' }, status: 'confirmed' },
  );

  assert.deepEqual(updated.credentials['deploy-ssh-key'].valid_on, ['web01', 'db01']);
  assert.equal(updated.credentials['deploy-ssh-key'].source.host, 'web01');
  assert.equal(updated.credentials['deploy-ssh-key'].source.tool, 'ssh');
  assert.equal(updated.credentials['deploy-ssh-key'].status, 'confirmed');

  const replaced = mergeIntelEntry({ tags: ['a', 'b'] }, { tags: ['c'] }, { replaceArrays: true });
  assert.deepEqual(replaced.tags, ['c']);
  assert.throws(() => updateIntelRecord({ credentials: {} }, 'credentials', 'missing', { status: 'active' }), /not found/);
});

test('timelineActionForIntelUpdate maps lifecycle statuses to timeline actions', () => {
  assert.equal(timelineActionForIntelUpdate('host', 'contained'), 'contained');
  assert.equal(timelineActionForIntelUpdate('credential', 'rotated'), 'rotated');
  assert.equal(timelineActionForIntelUpdate('pivot', 'cleared'), 'cleared');
  assert.equal(timelineActionForIntelUpdate('credential', 'active'), 'confirmed');
  assert.equal(timelineActionForIntelUpdate('account', 'disabled'), 'updated');
});

test('isInactiveCredentialStatus identifies credentials that must not be retrieved', () => {
  assert.equal(isInactiveCredentialStatus('rotated'), true);
  assert.equal(isInactiveCredentialStatus('Expired'), true);
  assert.equal(isInactiveCredentialStatus('revoked'), true);
  assert.equal(isInactiveCredentialStatus('invalid'), true);
  assert.equal(isInactiveCredentialStatus('active'), false);
  assert.equal(isInactiveCredentialStatus('unvalidated'), false);
});

test('appendTimelineEntry appends to existing timeline docs', () => {
  const updated = appendTimelineEntry({ timeline }, { type: 'credential', action: 'confirmed', target: 'deploy-ssh-key' });
  assert.equal(updated.timeline.length, 2);
  assert.equal(updated.timeline.at(-1).target, 'deploy-ssh-key');
});

test('formatHostQueryResult reports linked credentials, accounts, and pivots', () => {
  const output = formatHostQueryResult(hosts, credentials, accounts, pivots, 'web01');
  assert.match(output, /=== Host: web01 ===/);
  assert.match(output, /Credentials valid on this host \(1\):/);
  assert.match(output, /deploy-ssh-key: ssh-key — deploy \[active\]/);
  assert.match(output, /corp\\sqlsvc: domain — Domain Users \[compromised\]/);
  assert.match(output, /to-web01: adminws \[confirmed\]/);
});

test('formatCredentialQueryResult includes provenance and key material path', () => {
  const output = formatCredentialQueryResult(credentials, 'deploy-ssh-key');
  assert.match(output, /=== Credential: deploy-ssh-key ===/);
  assert.match(output, /Source: web01 via found in user ssh directory path=\/home\/deploy\/.ssh\/id_ed25519/);
  assert.match(output, /Key file: keys\/deploy-ed25519/);
});

test('searchIntel and formatSearchResult find cross-category matches', () => {
  const matches = searchIntel(hosts, credentials, accounts, pivots, 'putty');
  assert.deepEqual(matches.sort(), ['host:web01', 'pivot:to-web01']);

  const output = formatSearchResult('putty', matches);
  assert.match(output, /Search: "putty" — 2 match\(es\)/);
  assert.match(output, /host:web01/);
  assert.match(output, /pivot:to-web01/);
});

test('buildIntelSummary reports counts and evidence metrics', () => {
  const output = buildIntelSummary(hosts, credentials, accounts, pivots, timeline, '/tmp/intel');
  assert.match(output, /Hosts: 1/);
  assert.match(output, /compromised: 1/);
  assert.match(output, /Credentials: 1/);
  assert.match(output, /ssh-key: 1/);
  assert.match(output, /Pivot paths: 1/);
  assert.match(output, /with evidence: 1/);
  assert.match(output, /Timeline entries: 1/);
  assert.match(output, /Intel dir: \/tmp\/intel/);
});
