import { describe, it, expect } from 'vitest';
import { AnalysisEngine } from '../src/analysis/config-analyzer.js';

describe('unused objects: NAT translated addresses count as references', () => {
  it('keeps objects referenced only as NAT translations', () => {
    const config = {
      address_objects: [
        { name: 'web-private', value: '192.168.1.10/32' },
        { name: 'web-public', value: '203.0.113.10/32' },
        { name: 'pool-addr', value: '203.0.113.20/32' },
        { name: 'dnat-target', value: '192.168.1.20/32' },
        { name: 'dnat-target-obj', value: '192.168.1.30/32' },
        { name: 'orphan', value: '10.9.9.9/32' },
      ],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      application_groups: [],
      security_policies: [],
      nat_rules: [
        { type: 'static', src_addresses: ['any'], dst_addresses: ['web-public'], translated_src: { type: 'static', address: 'web-private' } },
        { type: 'source', src_addresses: ['any'], dst_addresses: ['any'], translated_src: { type: 'dynamic-ip-pool', addresses: ['pool-addr'] } },
        { type: 'destination', src_addresses: ['any'], dst_addresses: ['any'], translated_dst: 'dnat-target' },
        { type: 'destination', src_addresses: ['any'], dst_addresses: ['any'], translated_dst: { address: 'dnat-target-obj' } },
      ],
    };
    AnalysisEngine._markUsed(config);
    const unused = config.address_objects.filter(object => !object._used).map(object => object.name);
    expect(unused).toEqual(['orphan']);
  });
});
