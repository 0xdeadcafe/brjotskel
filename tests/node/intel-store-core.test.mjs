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
  buildIntelMap,
  filterTimeline,
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

test('buildIntelMap renders host nodes, credential edges, accounts, and pivots', () => {
  const map = buildIntelMap(hosts, credentials, accounts, pivots);
  assert.match(map, /Attack Graph/);
  assert.match(map, /web01/);
  assert.match(map, /compromised/);
  assert.match(map, /CREDENTIALS/);
  assert.match(map, /deploy-ssh-key/);
  assert.match(map, /deploy/);
  assert.match(map, /web01/);   // valid_on
  assert.match(map, /ACCOUNTS/);
  assert.match(map, /sqlsvc/);
  assert.match(map, /PIVOT PATHS/);
  assert.match(map, /to-web01/);
});

test('buildIntelMap annotates active sessions on host nodes', () => {
  const map = buildIntelMap(hosts, credentials, accounts, pivots, { activeSessions: new Set(['web01']) });
  assert.match(map, /SESSION ACTIVE/);
  assert.match(map, /ACTIVE SESSIONS: web01/);
});

test('filterTimeline filters by host target', () => {
  const entries = [
    { timestamp: '2026-08-01T00:00:00Z', type: 'host', action: 'discovered', target: 'web01', summary: 'found web01', operator: 'x' },
    { timestamp: '2026-08-02T00:00:00Z', type: 'credential', action: 'discovered', target: 'admin-ntlm', summary: 'hash found', operator: 'x' },
  ];
  const result = filterTimeline(entries, { host: 'web01' });
  assert.equal(result.length, 1);
  assert.equal(result[0].target, 'web01');
});

test('filterTimeline filters by category and action', () => {
  const entries = [
    { timestamp: '2026-08-01T00:00:00Z', type: 'host',       action: 'discovered', target: 'web01',      summary: '', operator: 'x' },
    { timestamp: '2026-08-02T00:00:00Z', type: 'credential', action: 'confirmed',   target: 'admin-ntlm', summary: '', operator: 'x' },
    { timestamp: '2026-08-03T00:00:00Z', type: 'host',       action: 'contained',   target: 'web01',      summary: '', operator: 'x' },
  ];
  assert.equal(filterTimeline(entries, { category: 'host' }).length, 2);
  assert.equal(filterTimeline(entries, { action: 'contained' }).length, 1);
  assert.equal(filterTimeline(entries, { category: 'credential', action: 'confirmed' }).length, 1);
});

test('filterTimeline filters by since datetime', () => {
  const entries = [
    { timestamp: '2026-08-01T00:00:00Z', type: 'host', action: 'discovered', target: 'web01', summary: '', operator: 'x' },
    { timestamp: '2026-08-10T00:00:00Z', type: 'host', action: 'contained',  target: 'web01', summary: '', operator: 'x' },
  ];
  const result = filterTimeline(entries, { since: '2026-08-05T00:00:00Z' });
  assert.equal(result.length, 1);
  assert.equal(result[0].action, 'contained');
});
