import test from 'node:test';
import assert from 'node:assert/strict';

import {
  getFileMap,
  getCollectionKeyMap,
  addIntelRecord,
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

test('addIntelRecord inserts entries under the requested collection', () => {
  const updated = addIntelRecord({ hosts: { ...hosts } }, 'hosts', 'db01', { ip: '10.10.20.10' });
  assert.equal(updated.hosts.db01.ip, '10.10.20.10');
  assert.equal(updated.hosts.web01.ip, '10.10.10.5');
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
