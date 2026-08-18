import test from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createServer } from 'node:net';

import { parseYaml } from '../../.pi/extensions/lib/simple-yaml.ts';

const stubModules = new Map([
  ['typebox', `
    const schema = (type, options = {}) => ({ type, ...options });
    export const Type = {
      Object: (properties = {}, options = {}) => ({ type: 'object', properties, ...options }),
      String: (options = {}) => schema('string', options),
      Number: (options = {}) => schema('number', options),
      Boolean: (options = {}) => schema('boolean', options),
      Optional: (inner) => ({ ...inner, optional: true }),
    };
  `],
  ['@earendil-works/pi-ai', `
    export function StringEnum(values) { return { type: 'string', enum: values }; }
  `],
  ['@earendil-works/pi-coding-agent', `
    export const DEFAULT_MAX_BYTES = 65536;
    export const DEFAULT_MAX_LINES = 2000;
    export function truncateTail(text) {
      return { content: text, truncated: false, outputLines: text.split('\\n').length, totalLines: text.split('\\n').length, outputBytes: Buffer.byteLength(text), totalBytes: Buffer.byteLength(text) };
    }
    export function formatSize(bytes) { return String(bytes) + ' B'; }
  `],
]);

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (stubModules.has(specifier)) {
      return {
        shortCircuit: true,
        url: `data:text/javascript,${encodeURIComponent(stubModules.get(specifier))}`,
      };
    }
    return nextResolve(specifier, context);
  },
});

function createMockPi() {
  const tools = [];
  const commands = [];
  return {
    tools,
    commands,
    registerTool(tool) { tools.push(tool); },
    registerCommand(name, spec) { commands.push({ name, ...spec }); },
    on() {},
  };
}

async function loadIntelExtension() {
  const mod = await import(`../../.pi/extensions/intel-store.ts?test=${Date.now()}-${Math.random()}`);
  return mod.default;
}

async function loadRemoteExtension() {
  const mod = await import(`../../.pi/extensions/remote-session.ts?test=${Date.now()}-${Math.random()}`);
  return mod.default;
}

test('extension entrypoints import and register tools with a mocked pi API', async () => {
  const intelPi = createMockPi();
  const remotePi = createMockPi();

  (await loadIntelExtension())(intelPi);
  (await loadRemoteExtension())(remotePi);

  assert.deepEqual(intelPi.tools.map(t => t.name).sort(), [
    'intel_add',
    'intel_get_cred',
    'intel_query',
    'intel_summary',
    'intel_timeline',
    'intel_update',
  ]);
  assert.ok(intelPi.commands.some(c => c.name === 'intel'));

  for (const name of ['remote_connect', 'remote_exec', 'remote_upload', 'remote_sessions', 'remote_disconnect', 'remote_tunnel', 'remote_tunnel_close', 'remote_relay', 'remote_relay_close']) {
    assert.ok(remotePi.tools.some(t => t.name === name), `missing ${name}`);
  }
  const remoteTunnel = remotePi.tools.find(t => t.name === 'remote_tunnel');
  assert.ok(remoteTunnel.parameters.properties.password, 'remote_tunnel should support password auth');
  assert.ok(remoteTunnel.parameters.properties.proxy_jump, 'remote_tunnel should support ProxyJump');
  for (const name of ['land', 'assess', 'pursue', 'contain', 'eradicate', 'verify']) {
    assert.ok(remotePi.commands.some(c => c.name === name), `missing /${name}`);
  }
});

test('remote TCP connections become ready for no-banner services', async () => {
  const pi = createMockPi();
  (await loadRemoteExtension())(pi);
  const remoteConnect = pi.tools.find(t => t.name === 'remote_connect');
  const remoteDisconnect = pi.tools.find(t => t.name === 'remote_disconnect');
  assert.ok(remoteConnect);
  assert.ok(remoteDisconnect);

  const server = createServer((socket) => {
    socket.on('data', () => {});
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === 'object');

  try {
    const result = await remoteConnect.execute('connect-silent', {
      protocol: 'tcp',
      target: `127.0.0.1:${address.port}`,
      name: 'silent-tcp-test',
    }, undefined, undefined, { hasUI: false });
    assert.match(result.content[0].text, /Connected: session 'silent-tcp-test'/);
  } finally {
    try {
      await remoteDisconnect.execute('disconnect-silent', { session: 'silent-tcp-test' }, undefined, undefined, { hasUI: false });
    } catch { /* session may not exist if connect failed */ }
    await new Promise(resolve => server.close(resolve));
  }
});

test('intel extension refuses duplicate IDs and logs credential access accurately', async () => {
  const pi = createMockPi();
  (await loadIntelExtension())(pi);
  const intelAdd = pi.tools.find(t => t.name === 'intel_add');
  const intelGetCred = pi.tools.find(t => t.name === 'intel_get_cred');
  const intelUpdate = pi.tools.find(t => t.name === 'intel_update');
  assert.ok(intelAdd);
  assert.ok(intelGetCred);
  assert.ok(intelUpdate);

  const intelDir = mkdtempSync(join(tmpdir(), 'brjotskel-intel-extension-'));
  const previousIntelDir = process.env.BRJOTSKEL_INTEL_DIR;
  process.env.BRJOTSKEL_INTEL_DIR = intelDir;

  try {
    await intelAdd.execute('add-1', {
      category: 'credential',
      id: 'svc-pass',
      data: 'type: "password"\nusername: "svc"\nsecret: "1234"\nstatus: "active"\nsource:\n  host: "web01"\n  method: "test fixture"\n',
      summary: 'active credential',
    });

    await assert.rejects(
      () => intelAdd.execute('add-dup', {
        category: 'credential',
        id: 'svc-pass',
        data: 'type: "password"\nusername: "svc"\nsecret: "replacement"\nstatus: "active"\nsource:\n  host: "web01"\n  method: "test fixture"\n',
      }),
      /already exists/,
    );

    await intelAdd.execute('add-2', {
      category: 'credential',
      id: 'old-pass',
      data: 'type: "password"\nusername: "old"\nsecret: "expired"\nstatus: "rotated"\nsource:\n  host: "web01"\n  method: "test fixture"\n',
    });

    await assert.rejects(
      () => intelGetCred.execute('get-old', { id: 'old-pass' }),
      /inactive status 'rotated'/,
    );

    await intelUpdate.execute('update-active', {
      category: 'credential',
      id: 'svc-pass',
      fields: 'valid_on:\n  - web01\n  - db01\nstatus: confirmed\n',
      summary: 'confirmed credential on db01',
    });

    await assert.rejects(
      () => intelUpdate.execute('reactivate-old', {
        category: 'credential',
        id: 'old-pass',
        fields: 'status: active\n',
      }),
      /without force=true/,
    );

    const result = await intelGetCred.execute('get-active', { id: 'svc-pass' });
    assert.match(result.content[0].text, /Secret: 1234/);
    assert.match(result.content[0].text, /Valid on: web01, db01/);

    const credentialsDoc = parseYaml(readFileSync(join(intelDir, 'credentials.yaml'), 'utf8')).credentials;
    assert.deepEqual(credentialsDoc['svc-pass'].valid_on, ['web01', 'db01']);

    const timeline = parseYaml(readFileSync(join(intelDir, 'timeline.yaml'), 'utf8')).timeline;
    assert.ok(timeline.some(entry => entry.action === 'confirmed' && entry.target === 'svc-pass'));
    assert.equal(timeline.at(-1).action, 'accessed');
    assert.equal(timeline.at(-1).target, 'svc-pass');
  } finally {
    if (previousIntelDir === undefined) delete process.env.BRJOTSKEL_INTEL_DIR;
    else process.env.BRJOTSKEL_INTEL_DIR = previousIntelDir;
    rmSync(intelDir, { recursive: true, force: true });
  }
});
