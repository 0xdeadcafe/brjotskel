import test from 'node:test';
import assert from 'node:assert/strict';

import {
  parseShortcutArgs,
  formatAssessShortcut,
  formatPursueShortcut,
  formatContainShortcut,
  buildAssessPrompt,
} from '../../.pi/extensions/lib/operator-shortcuts.ts';

const linuxSession = {
  name: 'web01',
  protocol: 'ssh',
  target: 'root@10.10.10.5',
  platform: 'linux',
  commandCount: 3,
};

const windowsSession = {
  name: 'dc01',
  protocol: 'winrm',
  target: 'administrator@10.10.10.20',
  platform: 'windows',
};

test('parseShortcutArgs handles session and prompt flags', () => {
  assert.deepEqual(parseShortcutArgs('web01 --prompt'), { sessionName: 'web01', prompt: true, help: false });
  assert.deepEqual(parseShortcutArgs('--stage dc01'), { sessionName: 'dc01', prompt: true, help: false });
  assert.deepEqual(parseShortcutArgs('--help'), { sessionName: undefined, prompt: false, help: true });
});

test('formatAssessShortcut selects platform-specific playbooks', () => {
  const linux = formatAssessShortcut(linuxSession, [linuxSession]);
  assert.match(linux, /ASSESS — web01/);
  assert.match(linux, /gather-playbooks\/linux\/first-look\.sh/);
  assert.match(linux, /host-ir-playbooks\/linux\/initial-assessment\.sh/);

  const windows = formatAssessShortcut(windowsSession, [windowsSession]);
  assert.match(windows, /gather-playbooks\/windows\/first-look\.ps1/);
  assert.match(windows, /host-ir-playbooks\/windows\/initial-assessment\.ps1/);
});

test('formatPursueShortcut stays lightweight and intel-focused', () => {
  const output = formatPursueShortcut([linuxSession, windowsSession]);
  assert.match(output, /intel_get_cred/);
  assert.match(output, /intel_map/);
  assert.match(output, /netexec/);
  assert.doesNotMatch(output, /report/i);
});

test('formatPursueShortcut generates chase board from intel snapshot', () => {
  const snap = {
    unvalidatedCreds: [
      { id: 'admin-ntlm', type: 'ntlm-hash', username: 'Administrator' },
      { id: 'deploy-key', type: 'ssh-key',   username: 'deploy', keyFile: 'keys/deploy-ed25519' },
    ],
    activeCreds: [],
    knownHostIps: ['10.10.10.5', '10.10.10.20'],
    knownHostIds: ['web01', 'dc01'],
  };
  const output = formatPursueShortcut([linuxSession], snap);
  assert.match(output, /UNVALIDATED CREDENTIALS/);
  assert.match(output, /admin-ntlm/);
  assert.match(output, /deploy-key/);
  assert.match(output, /10.10.10.5,10.10.10.20/);
  assert.match(output, /intel_update.*valid_on/);
});

test('formatPursueShortcut shows fallback when no intel', () => {
  const output = formatPursueShortcut([linuxSession], null);
  assert.match(output, /Manual commands/);
  assert.doesNotMatch(output, /UNVALIDATED/);
});

test('formatContainShortcut is evidence-first and does not auto-execute', () => {
  const output = formatContainShortcut(windowsSession, [windowsSession]);
  assert.match(output, /EVIDENCE FIRST/);
  assert.match(output, /collect-evidence/);
  assert.match(output, /kill-process\.ps1/);
  assert.match(output, /block-c2\.ps1/);
  assert.match(output, /disable-account\.ps1/);
  assert.match(output, /intel_update/);
});

test('buildAssessPrompt stages an agent prompt rather than executing directly', () => {
  const prompt = buildAssessPrompt(linuxSession);
  assert.match(prompt, /Read \.pi\/skills\/gather-playbooks\/linux\/first-look\.sh/);
  assert.match(prompt, /remote session "web01"/);
  assert.match(prompt, /intel_add/);
});
