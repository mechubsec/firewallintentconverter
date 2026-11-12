import { describe, it, expect } from 'vitest';
import { parseCiscoAsaConfig } from '../src/parsers/cisco-asa-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

const INTERFACES = `interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.0.2.1 255.255.255.0
!
object-group service SVCGRP tcp
 port-object eq 80
!
`;

const parse = (lines) => parseCiscoAsaConfig(INTERFACES + lines).intermediateConfig;
const explicitPolicies = (config) => config.security_policies.filter(policy => !policy._implicit && !policy.name.startsWith('Implicit'));

describe('ASA access-list parsing', () => {
  it('reads an object-group service reference in the protocol position as the service, not the source', () => {
    const [policy] = explicitPolicies(parse('access-list OUT extended permit object-group SVCGRP any host 192.0.2.10\naccess-group OUT in interface outside\n'));
    expect(policy.src_addresses).toEqual(['any']);
    expect(policy.dst_addresses).toEqual(['192.0.2.10']);
    expect(policy.services).toEqual(['SVCGRP']);
  });

  it('reads an object service reference in the protocol position as the service', () => {
    const [policy] = explicitPolicies(parse('access-list OUT extended permit object SVCOBJ 198.51.100.0 255.255.255.0 host 192.0.2.10\naccess-group OUT in interface outside\n'));
    expect(policy.src_addresses).toEqual(['198.51.100.0/24']);
    expect(policy.dst_addresses).toEqual(['192.0.2.10']);
    expect(policy.services).toEqual(['SVCOBJ']);
  });

  it('expands neq/gt/lt into the full port ranges they match', () => {
    const policies = explicitPolicies(parse([
      'access-list OUT extended deny tcp any host 192.0.2.10 neq 80',
      'access-list OUT extended permit tcp any host 192.0.2.10 gt 1023',
      'access-list OUT extended permit udp any host 192.0.2.10 lt 1024',
      'access-group OUT in interface outside',
    ].join('\n') + '\n'));
    expect(policies.map(policy => policy.services)).toEqual([
      ['tcp/1-79', 'tcp/81-65535'],
      ['tcp/1024-65535'],
      ['udp/1-1023'],
    ]);
  });

  it('converts gt to a range application on SRX', () => {
    const commands = convertToSrxSetCommands(structuredClone(parse('access-list OUT extended permit tcp any host 192.0.2.10 gt 1023\naccess-group OUT in interface outside\n'))).commands;
    expect(commands).toContain('set applications application tcp-1024-65535 destination-port 1024-65535');
  });

  it('gives the same remark-named ACL bound to two interfaces unique policy names', () => {
    const config = parse('access-list WEB remark Allow web\naccess-list WEB extended permit tcp any host 192.0.2.10 eq 80\naccess-group WEB in interface outside\naccess-group WEB in interface inside\n');
    const names = explicitPolicies(config).map(policy => policy.name);
    expect(new Set(names).size).toBe(names.length);
    expect(() => convertToSrxSetCommands(structuredClone(config))).not.toThrow();
  });

  it('does not invent a "global" zone for access-group ... global', () => {
    const [policy] = explicitPolicies(parse('access-list GL extended permit tcp any host 192.0.2.10 eq 80\naccess-group GL global\n'));
    expect(policy.src_zones).not.toContain('global');
  });

  it('accepts ACL names that collide with Object.prototype members', () => {
    for (const aclName of ['constructor', '__proto__', 'toString']) {
      const config = parse(`access-list ${aclName} extended permit tcp any host 192.0.2.10 eq 80\naccess-group ${aclName} in interface outside\n`);
      expect(explicitPolicies(config)).toHaveLength(1);
    }
  });

  it('keeps any4 and any6 distinct from any', () => {
    const [v6, v4] = explicitPolicies(parse('access-list OUT extended deny ip any6 any\naccess-list OUT extended deny ip any4 any\naccess-group OUT in interface outside\n'));
    expect(v6.src_addresses).toEqual(['::/0']);
    expect(v4.src_addresses).toEqual(['0.0.0.0/0']);
  });
});
