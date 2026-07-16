import test from 'node:test';
import assert from 'node:assert/strict';

import {
  psSingleQuote,
  shellSingleQuote,
  detectSshShell,
  cleanCommandOutput,
} from '../../.pi/extensions/lib/remote-helpers.ts';

test('quote helpers escape apostrophes for powershell and posix shells', () => {
  assert.equal(psSingleQuote("o'hare"), "o''hare");
  assert.equal(shellSingleQuote("o'hare"), "o\"'\"'hare");
});

test('detectSshShell identifies posix, powershell, cmd, and hinted network devices', () => {
  assert.deepEqual(detectSshShell('user@host:~$\n'), { platform: 'linux', shellFamily: 'posix' });
  assert.deepEqual(detectSshShell('PS C:\\Users\\alice>\n'), { platform: 'windows', shellFamily: 'powershell' });
  assert.deepEqual(detectSshShell('C:\\Windows\\System32>\n'), { platform: 'windows', shellFamily: 'cmd' });
  assert.deepEqual(detectSshShell('switch01 >\n', 'network-device'), { platform: 'network-device', shellFamily: 'unknown' });
});

test('detectSshShell honors explicit shell hints', () => {
  assert.deepEqual(detectSshShell('welcome\n', 'macos', 'posix'), { platform: 'macos', shellFamily: 'posix' });
  assert.deepEqual(detectSshShell('banner\n', undefined, 'powershell'), { platform: 'windows', shellFamily: 'powershell' });
});

test('cleanCommandOutput strips echoed commands and trailing prompts', () => {
  const output = cleanCommandOutput({}, 'whoami', 'whoami\nroot\nroot@host:~$\n');
  assert.equal(output, 'root');

  const psOutput = cleanCommandOutput({}, 'Get-ChildItem', 'PS C:\\> Get-ChildItem\nfile.txt\nPS C:\\>\n');
  assert.equal(psOutput, 'file.txt');
});
