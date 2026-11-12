import { describe, it, expect } from 'vitest';
import { parseGcpFirewallRules } from '../src/parsers/gcp-fw-parser.js';

const NETWORK = 'projects/p/global/networks/vpc1';

describe('GCP firewall parser priority', () => {
  it('treats priority 0 as the highest precedence, not the 1000 default', () => {
    const rules = [
      { name: 'allow-ssh', network: NETWORK, direction: 'INGRESS', priority: 500, sourceRanges: ['192.0.2.0/24'], allowed: [{ IPProtocol: 'tcp', ports: ['22'] }] },
      { name: 'deny-ssh', network: NETWORK, direction: 'INGRESS', priority: 0, sourceRanges: ['192.0.2.0/24'], denied: [{ IPProtocol: 'tcp', ports: ['22'] }] },
    ];
    const names = parseGcpFirewallRules(JSON.stringify(rules)).intermediateConfig
      .security_policies.filter(policy => !policy._implicit).map(policy => policy.name);
    expect(names).toEqual(['deny-ssh', 'allow-ssh']);
  });
});
