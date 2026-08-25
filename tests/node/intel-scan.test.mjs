import test from 'node:test';
import assert from 'node:assert/strict';

import { parseNmapGreppable } from '../../.pi/extensions/lib/intel-scan-core.ts';

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
