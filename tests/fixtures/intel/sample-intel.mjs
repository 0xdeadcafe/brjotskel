export const hosts = {
  web01: {
    ip: '10.10.10.5',
    hostname: 'web01.corp.local',
    platform: 'linux',
    role: 'web',
    status: 'compromised',
    attacker_role: 'pivot',
    endpoints: ['ssh://root@10.10.10.5:22'],
    profile_artifacts: ['putty-session'],
    source: { host: 'adminws', method: 'saved PuTTY session', path: 'HKCU\\Software\\SimonTatham\\PuTTY\\Sessions\\web01' },
  },
};

export const credentials = {
  'deploy-ssh-key': {
    type: 'ssh-key',
    username: 'deploy',
    status: 'active',
    valid_on: ['web01'],
    related_hosts: ['jump01'],
    source: { host: 'web01', method: 'found in user ssh directory', path: '/home/deploy/.ssh/id_ed25519' },
    key_file: 'keys/deploy-ed25519',
  },
};

export const accounts = {
  'corp\\sqlsvc': {
    type: 'domain',
    privileges: ['Domain Users'],
    status: 'compromised',
    access_to: ['web01'],
  },
};

export const pivots = {
  'to-web01': {
    target: 'web01',
    status: 'confirmed',
    chain: [{ hop: 'adminws', method: 'ssh-proxy-jump' }],
    evidence: [{ kind: 'putty-session', path: 'HKCU\\Software\\SimonTatham\\PuTTY\\Sessions\\web01' }],
  },
};

export const timeline = [
  {
    timestamp: '2026-07-16T00:00:00Z',
    type: 'host',
    action: 'discovered',
    target: 'web01',
    summary: 'Confirmed compromised Linux web host',
    operator: 'tester',
  },
];
