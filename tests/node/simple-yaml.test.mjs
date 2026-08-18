import test from 'node:test';
import assert from 'node:assert/strict';

import { parseYaml, dumpYaml } from '../../.pi/extensions/lib/simple-yaml.ts';

test('parseYaml handles PyYAML-style nested lists and inline map list items', () => {
  const data = parseYaml(`credentials:\n  deploy-ssh-key:\n    type: ssh-key\n    valid_on:\n    - db01\n    - app01\npaths:\n  to-web01:\n    chain:\n    - hop: jump01\n      method: ssh\n    - hop: web01\n      method: winrm\n`);

  assert.deepEqual(data.credentials['deploy-ssh-key'].valid_on, ['db01', 'app01']);
  assert.deepEqual(data.paths['to-web01'].chain, [
    { hop: 'jump01', method: 'ssh' },
    { hop: 'web01', method: 'winrm' },
  ]);
});

test('parseYaml handles simple flow-style lists and maps', () => {
  const data = parseYaml('valid_on: [web01, "db01", 1234]\nsource: {host: web01, method: "config:file"}\n');
  assert.deepEqual(data.valid_on, ['web01', 'db01', 1234]);
  assert.deepEqual(data.source, { host: 'web01', method: 'config:file' });
});

test('parseYaml handles PyYAML multiline quoted strings from older intel stores', () => {
  const data = parseYaml("credentials:\n  svc-pass:\n    notes: 'line1\n\n      line2'\n");
  assert.equal(data.credentials['svc-pass'].notes, 'line1\nline2');
});

test('dumpYaml quotes string-like secrets and round-trips safely', () => {
  const original = {
    credentials: {
      'corp\\svc:sql': {
        type: 'password',
        username: 'svc_sql',
        secret: 'true',
        notes: '1234\nnull\n2026-08-18',
        source: { path: 'C:\\Users\\alice\\config.txt' },
      },
    },
  };

  const dumped = dumpYaml(original);
  assert.match(dumped, /secret: "true"/);
  assert.match(dumped, /notes: "1234\\nnull\\n2026-08-18"/);

  const parsed = parseYaml(dumped);
  assert.deepEqual(parsed, original);
});

test('parseYaml reports malformed YAML with line context', () => {
  assert.throws(() => parseYaml('hosts:\n    web01:\n  bad-indent: true\n'), /Unexpected content|Unexpected indentation|line/);
  assert.throws(() => parseYaml('hosts\n  web01: true\n'), /Expected 'key: value'/);
});
