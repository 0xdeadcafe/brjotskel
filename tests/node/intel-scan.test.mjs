import test from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { tmpdir } from 'node:os';

import { parseNmapGreppable } from '../../.pi/extensions/lib/intel-scan-core.ts';
import { parseYaml } from '../../.pi/extensions/lib/simple-yaml.ts';

const stubModules = new Map([
  ['typebox', `
    const schema = (type, options = {}) => ({ type, ...options });
    export const Type = {
      Object: (properties = {}, options = {}) => ({ type: 'object', properties, ...options }),
      String: (options = {}) => schema('string', options),
      Number: (options = {}) => schema('number', options),
      Array: (items = {}, options = {}) => ({ type: 'array', items, ...options }),
      Optional: (inner) => ({ ...inner, optional: true }),
    };
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
  return {
    tools,
    registerTool(tool) { tools.push(tool); },
  };
}

async function loadIntelScanExtension() {
  const mod = await import(`../../.pi/extensions/intel-scan.ts?test=${Date.now()}-${Math.random()}`);
  return mod.default;
}

// Sample greppable nmap output fixtures
const LINUX_SSH_ONLY = `
# Nmap 7.94 scan initiated
Host: 10.10.10.5 (web01.corp.local)	Status: Up
Host: 10.10.10.5 (web01.corp.local)	Ports: 22/open/tcp//ssh///	Ignored State: closed (999)
# Nmap done: 1 IP address (1 host up) scanned in 3.01 seconds
`.trim();

const WINDOWS_MULTI = `
# Nmap 7.94 scan initiated
Host: 10.10.20.10 ()	Status: Up
Host: 10.10.20.10 ()	Ports: 445/open/tcp//microsoft-ds///, 3389/open/tcp//ms-wbt-server///, 5985/open/tcp//wsman///	Ignored State: closed (997)
# Nmap done
`.trim();

const MULTI_HOST = `
Host: 10.10.10.5 ()	Status: Up
Host: 10.10.10.5 ()	Ports: 22/open/tcp//ssh///
Host: 10.10.10.20 ()	Status: Up
Host: 10.10.10.20 ()	Ports: 445/open/tcp//microsoft-ds///, 3389/open/tcp//ms-wbt-server///
Host: 10.10.10.30 ()	Status: Up
Host: 10.10.10.30 ()	Ports: 23/open/tcp//telnet///
`.trim();

const NO_HOSTS = `
# Nmap 7.94 scan initiated
# Nmap done: 256 IP addresses (0 hosts up) scanned in 30.00 seconds
`.trim();

const WITH_HOSTNAME = `
Host: 10.10.20.20 (dc01.corp.local)	Status: Up
Host: 10.10.20.20 (dc01.corp.local)	Ports: 445/open/tcp//microsoft-ds///, 5985/open/tcp//wsman///
`.trim();

// -------------------------------------------------------------------
// parseNmapGreppable
// -------------------------------------------------------------------

test('parses a single Linux SSH-only host', () => {
  const hosts = parseNmapGreppable(LINUX_SSH_ONLY);
  assert.equal(hosts.length, 1);
  assert.equal(hosts[0].ip, '10.10.10.5');
  assert.equal(hosts[0].hostname, 'web01.corp.local');
  assert.equal(hosts[0].platform, 'linux');
  assert.equal(hosts[0].openPorts.length, 1);
  assert.equal(hosts[0].openPorts[0].port, 22);
  assert.equal(hosts[0].openPorts[0].service, 'ssh');
});

test('parses a Windows host with SMB + RDP + WinRM and infers platform', () => {
  const hosts = parseNmapGreppable(WINDOWS_MULTI);
  assert.equal(hosts.length, 1);
  assert.equal(hosts[0].ip, '10.10.20.10');
  assert.equal(hosts[0].platform, 'windows');
  assert.equal(hosts[0].openPorts.length, 3);
  const ports = hosts[0].openPorts.map(p => p.port);
  assert.ok(ports.includes(445));
  assert.ok(ports.includes(3389));
  assert.ok(ports.includes(5985));
});

test('parses multiple hosts from a single output block', () => {
  const hosts = parseNmapGreppable(MULTI_HOST);
  assert.equal(hosts.length, 3);
  assert.equal(hosts[0].ip, '10.10.10.5');
  assert.equal(hosts[0].platform, 'linux');
  assert.equal(hosts[1].ip, '10.10.10.20');
  assert.equal(hosts[1].platform, 'windows');
  assert.equal(hosts[2].ip, '10.10.10.30');
  assert.equal(hosts[2].platform, 'network-device');
});

test('returns empty array when no hosts are up', () => {
  const hosts = parseNmapGreppable(NO_HOSTS);
  assert.equal(hosts.length, 0);
});

test('returns empty array for empty string', () => {
  assert.equal(parseNmapGreppable('').length, 0);
});

test('preserves hostname from greppable output', () => {
  const hosts = parseNmapGreppable(WITH_HOSTNAME);
  assert.equal(hosts.length, 1);
  assert.equal(hosts[0].hostname, 'dc01.corp.local');
  assert.equal(hosts[0].platform, 'windows');
});

test('infers unknown platform when no port hints match', () => {
  const out = `Host: 192.168.1.1 ()\tStatus: Up\nHost: 192.168.1.1 ()\tPorts: 80/open/tcp//http///`;
  const hosts = parseNmapGreppable(out);
  assert.equal(hosts.length, 1);
  assert.equal(hosts[0].platform, 'unknown');
});

test('handles host with no open ports gracefully', () => {
  const out = `Host: 10.0.0.1 ()\tStatus: Up`;
  const hosts = parseNmapGreppable(out);
  assert.equal(hosts.length, 1);
  assert.equal(hosts[0].ip, '10.0.0.1');
  assert.equal(hosts[0].openPorts.length, 0);
  assert.equal(hosts[0].platform, 'unknown');
});

test('parses port fields: port, proto, service', () => {
  const out = `Host: 10.0.0.1 ()\tPorts: 443/open/tcp//https///, 8443/open/tcp//https-alt///`;
  const hosts = parseNmapGreppable(out);
  assert.equal(hosts[0].openPorts.length, 2);
  assert.equal(hosts[0].openPorts[0].port, 443);
  assert.equal(hosts[0].openPorts[0].proto, 'tcp');
  assert.equal(hosts[0].openPorts[0].service, 'https');
  assert.equal(hosts[0].openPorts[1].port, 8443);
});

test('skips closed/filtered port lines', () => {
  const out = `Host: 10.0.0.1 ()\tPorts: 22/open/tcp//ssh///, 80/closed/tcp//http///`;
  const hosts = parseNmapGreppable(out);
  assert.equal(hosts[0].openPorts.length, 1);
  assert.equal(hosts[0].openPorts[0].port, 22);
});

test('intel_scan timeline entries include a non-empty timestamp', async () => {
  const pi = createMockPi();
  (await loadIntelScanExtension())(pi);
  const intelScan = pi.tools.find(t => t.name === 'intel_scan');
  assert.ok(intelScan);
  assert.ok(intelScan.parameters.properties.via_socks_port);

  const intelDir = mkdtempSync(join(tmpdir(), 'brjotskel-intel-scan-intel-'));
  const binDir = mkdtempSync(join(tmpdir(), 'brjotskel-intel-scan-bin-'));
  const previousIntelDir = process.env.BRJOTSKEL_INTEL_DIR;
  const previousPath = process.env.PATH;

  const fakeNmapPath = join(binDir, 'nmap');
  writeFileSync(fakeNmapPath, `#!/usr/bin/env bash
cat <<'EOF'
${LINUX_SSH_ONLY}
EOF
`);
  chmodSync(fakeNmapPath, 0o700);

  process.env.BRJOTSKEL_INTEL_DIR = intelDir;
  process.env.PATH = `${binDir}${delimiter}${previousPath || ''}`;

  try {
    await intelScan.execute('scan-1', {
      target: '10.10.10.5',
      ports: [22],
      timeout_seconds: 5,
    });

    const timelineDoc = parseYaml(readFileSync(join(intelDir, 'timeline.yaml'), 'utf8'));
    const entry = timelineDoc.timeline.find(e => e.target === 'host-10-10-10-5');
    assert.ok(entry, 'missing intel_scan timeline entry');
    assert.equal(typeof entry.timestamp, 'string');
    assert.match(entry.timestamp, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  } finally {
    if (previousIntelDir === undefined) delete process.env.BRJOTSKEL_INTEL_DIR;
    else process.env.BRJOTSKEL_INTEL_DIR = previousIntelDir;
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    rmSync(intelDir, { recursive: true, force: true });
    rmSync(binDir, { recursive: true, force: true });
  }
});

test('intel_scan routes through proxychains4 when via_socks_port is set', async () => {
  const pi = createMockPi();
  (await loadIntelScanExtension())(pi);
  const intelScan = pi.tools.find(t => t.name === 'intel_scan');
  assert.ok(intelScan);

  const intelDir = mkdtempSync(join(tmpdir(), 'brjotskel-intel-scan-intel-'));
  const binDir = mkdtempSync(join(tmpdir(), 'brjotskel-intel-scan-bin-'));
  const previousIntelDir = process.env.BRJOTSKEL_INTEL_DIR;
  const previousPath = process.env.PATH;
  const previousProxyLog = process.env.BRJOTSKEL_PROXYCHAINS_LOG;
  const previousProxyConfLog = process.env.BRJOTSKEL_PROXYCHAINS_CONF_LOG;
  const proxyLog = join(binDir, 'proxychains-args.log');
  const proxyConfLog = join(binDir, 'proxychains.conf.copy');

  const fakeProxychainsPath = join(binDir, 'proxychains4');
  writeFileSync(fakeProxychainsPath, `#!/usr/bin/env bash
printf '%s\n' "$*" > "$BRJOTSKEL_PROXYCHAINS_LOG"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-f" ]; then
    shift
    cp "$1" "$BRJOTSKEL_PROXYCHAINS_CONF_LOG"
  fi
  shift || break
done
cat <<'EOF'
${LINUX_SSH_ONLY}
EOF
`);
  chmodSync(fakeProxychainsPath, 0o700);

  process.env.BRJOTSKEL_INTEL_DIR = intelDir;
  process.env.PATH = `${binDir}${delimiter}${previousPath || ''}`;
  process.env.BRJOTSKEL_PROXYCHAINS_LOG = proxyLog;
  process.env.BRJOTSKEL_PROXYCHAINS_CONF_LOG = proxyConfLog;

  try {
    const result = await intelScan.execute('scan-socks', {
      target: '10.10.20.0/24',
      ports: [22, 445],
      timeout_seconds: 5,
      via_socks_port: 1080,
    });

    assert.match(result.content[0].text, /Via SOCKS: 127\.0\.0\.1:1080/);
    assert.equal(result.details.via_socks_port, 1080);
    assert.match(readFileSync(proxyLog, 'utf8'), /-q -f .*proxychains\.conf nmap -Pn -sT --open -oG - -p 22,445 10\.10\.20\.0\/24/);
    assert.match(readFileSync(proxyConfLog, 'utf8'), /socks5 127\.0\.0\.1 1080/);

    const hostsDoc = parseYaml(readFileSync(join(intelDir, 'hosts.yaml'), 'utf8'));
    assert.equal(hostsDoc.hosts['host-10-10-10-5'].source.method, 'nmap scan (intel_scan via SOCKS 127.0.0.1:1080)');
  } finally {
    if (previousIntelDir === undefined) delete process.env.BRJOTSKEL_INTEL_DIR;
    else process.env.BRJOTSKEL_INTEL_DIR = previousIntelDir;
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    if (previousProxyLog === undefined) delete process.env.BRJOTSKEL_PROXYCHAINS_LOG;
    else process.env.BRJOTSKEL_PROXYCHAINS_LOG = previousProxyLog;
    if (previousProxyConfLog === undefined) delete process.env.BRJOTSKEL_PROXYCHAINS_CONF_LOG;
    else process.env.BRJOTSKEL_PROXYCHAINS_CONF_LOG = previousProxyConfLog;
    rmSync(intelDir, { recursive: true, force: true });
    rmSync(binDir, { recursive: true, force: true });
  }
});
