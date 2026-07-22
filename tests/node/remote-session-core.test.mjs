import test from 'node:test';
import assert from 'node:assert/strict';

import {
  chooseSessionName,
  buildMarkerCommand,
  buildTunnelSpec,
  buildTunnelDescription,
  buildTunnelUsageHint,
  processTelnetBytes,
  parseWinRmTarget,
  detectRelayMethods,
  buildRelayCommand,
  buildRelayCleanupCommand,
  buildRelayProbeCommand,
  buildRelayVerifyCommand,
} from '../../.pi/extensions/lib/remote-session-core.ts';

test('chooseSessionName resolves default, single-session, and explicit selection', () => {
  assert.equal(chooseSessionName(undefined, ['web01'], null), 'web01');
  assert.equal(chooseSessionName(undefined, ['web01', 'db01'], 'db01'), 'db01');
  assert.equal(chooseSessionName('web01', ['web01', 'db01'], 'db01'), 'web01');
});

test('chooseSessionName raises clear errors for none, many, and missing sessions', () => {
  assert.throws(() => chooseSessionName(undefined, [], null), /No active remote sessions/);
  assert.throws(() => chooseSessionName(undefined, ['web01', 'db01'], null), /Multiple sessions active \(web01, db01\)/);
  assert.throws(() => chooseSessionName('app01', ['web01', 'db01'], 'db01'), /Session 'app01' not found\. Available: web01, db01/);
});

test('buildMarkerCommand emits shell-specific marker wrappers', () => {
  assert.equal(buildMarkerCommand('powershell', 'whoami', "abc'def"), "whoami\nWrite-Host 'abc''def'");
  assert.equal(buildMarkerCommand('cmd', 'dir', 'marker123'), 'dir\r\necho marker123');
  assert.equal(buildMarkerCommand('posix', 'id', "ab'cd"), "id\necho 'ab\"'\"'cd'");
});

test('buildTunnelSpec, description, and usage hint format each tunnel type', () => {
  assert.deepEqual(buildTunnelSpec('local', 2222, 'internal01', 22), {
    forwardSpec: 'L 2222:internal01:22',
    sshArgs: ['-L', '2222:internal01:22'],
  });
  assert.deepEqual(buildTunnelSpec('remote', 8080, undefined, 8443), {
    forwardSpec: 'R 8443:localhost:8080',
    sshArgs: ['-R', '8443:localhost:8080'],
  });
  assert.deepEqual(buildTunnelSpec('dynamic', 1080), {
    forwardSpec: 'D 1080',
    sshArgs: ['-D', '1080'],
  });

  assert.equal(buildTunnelDescription('dynamic', 'root@web01', 1080), 'SOCKS proxy via root@web01');
  assert.equal(buildTunnelDescription('local', 'root@web01', 2222, 'internal01', 22), 'local forward 2222→internal01:22 via root@web01');
  assert.equal(buildTunnelDescription('remote', 'root@web01', 8080, undefined, 8443, 'custom desc'), 'custom desc');

  assert.match(buildTunnelUsageHint('local', 'root@web01', 2222), /remote_connect\(protocol="ssh", target="user@localhost", port=2222, name="next-hop"\)/);
  assert.match(buildTunnelUsageHint('dynamic', 'root@web01', 1080), /SOCKS5 proxy at: localhost:1080/);
  assert.match(buildTunnelUsageHint('remote', 'root@web01', 8080, 8443), /connections to root@web01:8443 are forwarded to localhost:8080/);
});

test('parseWinRmTarget supports user@host targets and explicit user override', () => {
  assert.deepEqual(parseWinRmTarget('administrator@dc01'), { computerName: 'dc01', user: 'administrator' });
  assert.deepEqual(parseWinRmTarget('corp\\alice@dc01', 'corp\\bob'), { computerName: 'dc01', user: 'corp\\bob' });
  assert.deepEqual(parseWinRmTarget('dc01'), { computerName: 'dc01' });
});

test('processTelnetBytes strips negotiations and emits reply frames', () => {
  const IAC = 255;
  const DO = 253;
  const WILL = 251;
  const ECHO = 1;
  const SGA = 3;

  const result = processTelnetBytes(undefined, [
    ...Buffer.from('login: '),
    IAC, DO, ECHO,
    IAC, WILL, SGA,
  ]);

  assert.equal(result.text, 'login: ');
  assert.deepEqual(result.replies, [
    [IAC, 252, ECHO],
    [IAC, 254, SGA],
  ]);
  assert.deepEqual(result.state, { mode: 'data', command: undefined });
});

test('processTelnetBytes handles escaped IAC and subnegotiation blocks', () => {
  const IAC = 255;
  const SB = 250;
  const SE = 240;

  const result = processTelnetBytes({ mode: 'data' }, [
    ...Buffer.from('A'),
    IAC, IAC,
    ...Buffer.from('B'),
    IAC, SB, 24, 1, 2, IAC, SE,
    ...Buffer.from('C'),
  ]);

  assert.equal(result.text, 'A�BC');
  assert.deepEqual(result.replies, []);
  assert.deepEqual(result.state, { mode: 'data' });
});

// --- Relay helper tests ---

test('detectRelayMethods identifies tools from probe output (Linux)', () => {
  const probe = '/usr/bin/socat\n/usr/bin/ncat\n/bin/nc\nnetcat-openbsd\n/bin/bash\n';
  const methods = detectRelayMethods(probe, 'linux');
  assert.equal(methods[0], 'socat');
  assert.ok(methods.includes('ncat'));
  assert.ok(methods.includes('nc-openbsd'));
  assert.ok(methods.includes('bash-devtcp'));
});

test('detectRelayMethods returns netsh-portproxy for Windows', () => {
  const probe = 'netsh\nncat';
  const methods = detectRelayMethods(probe, 'windows');
  assert.equal(methods[0], 'netsh-portproxy');
  assert.ok(methods.includes('ncat'));
});

test('detectRelayMethods returns empty array when nothing found', () => {
  const methods = detectRelayMethods('', 'linux');
  assert.deepEqual(methods, []);
});

test('buildRelayCommand generates correct commands for each method', () => {
  const base = { listenPort: 4422, targetHost: '10.10.20.5', targetPort: 22 };

  const socat = buildRelayCommand({ ...base, method: 'socat' });
  assert.match(socat, /socat TCP-LISTEN:4422,bind=0\.0\.0\.0,fork,reuseaddr TCP:10\.10\.20\.5:22 &/);

  const ncat = buildRelayCommand({ ...base, method: 'ncat' });
  assert.match(ncat, /ncat -l 0\.0\.0\.0 4422 --sh-exec 'ncat 10\.10\.20\.5 22' &/);

  const netsh = buildRelayCommand({ ...base, method: 'netsh-portproxy' });
  assert.match(netsh, /netsh interface portproxy add v4tov4 listenport=4422 listenaddress=0\.0\.0\.0 connectport=22 connectaddress=10\.10\.20\.5/);

  const ncBsd = buildRelayCommand({ ...base, method: 'nc-openbsd' });
  assert.match(ncBsd, /mkfifo/);
  assert.match(ncBsd, /nc -l 0\.0\.0\.0 4422/);
});

test('buildRelayCleanupCommand generates correct teardown for each method', () => {
  const base = { listenPort: 4422, targetHost: '10.10.20.5', targetPort: 22 };

  const socat = buildRelayCleanupCommand({ ...base, method: 'socat' });
  assert.match(socat, /pkill -f.*socat TCP-LISTEN:4422/);

  const netsh = buildRelayCleanupCommand({ ...base, method: 'netsh-portproxy' });
  assert.match(netsh, /netsh interface portproxy delete v4tov4 listenport=4422/);

  const nc = buildRelayCleanupCommand({ ...base, method: 'nc-openbsd' });
  assert.match(nc, /rm -f \/tmp\/.r4422/);
});

test('buildRelayProbeCommand returns platform-appropriate probe', () => {
  const linux = buildRelayProbeCommand('linux');
  assert.match(linux, /which socat ncat nc/);

  const win = buildRelayProbeCommand('windows');
  assert.match(win, /Write-Output.*netsh/);
});

test('buildRelayVerifyCommand checks listener presence', () => {
  const verify = buildRelayVerifyCommand({ method: 'socat', listenPort: 4422, targetHost: '10.10.20.5', targetPort: 22 });
  assert.match(verify, /grep.*:4422/);

  const netshVerify = buildRelayVerifyCommand({ method: 'netsh-portproxy', listenPort: 4422, targetHost: '10.10.20.5', targetPort: 22 });
  assert.match(netshVerify, /netsh interface portproxy show/);
});
