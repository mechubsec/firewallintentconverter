import { describe, it, expect } from 'vitest';
import { parseHuaweiConfig } from '../src/parsers/huawei-parser.js';

const CONFIG = `ip address-set NET type object
 address 0 192.0.2.0 0.0.0.255
 address 1 198.51.100.0 255.255.255.0
#
ip service-set WEB type object
 service 0 protocol tcp source-port 0 to 65535 destination-port 80
#
ip service-set SRCRANGE type object
 service 0 protocol udp source-port 1024 to 2000 destination-port 53
#
ip service-set PING type object
 service 0 protocol icmp icmp-type 8 code 0
#
ip service-set ANYTCP type object
 service 0 protocol tcp
#
security-policy
 rule name prefix
  source-zone trust
  destination-zone untrust
  source-address 192.0.2.0 24
  destination-address 198.51.100.0 mask 255.255.255.0
  action permit
 rule name wild
  source-address 203.0.113.0 0.0.0.255
  action permit
 rule name ranged
  source-address range 192.0.2.1 192.0.2.9
  action permit
`;

const { intermediateConfig: parsed, warnings } = parseHuaweiConfig(CONFIG);
const policy = name => parsed.security_policies.find(item => item.name === name);
const service = name => parsed.service_objects.find(item => item.name === name);

describe('Huawei service-set and inline address parsing', () => {
  it('reads wildcard masks in address-set entries', () => {
    const values = Object.fromEntries(parsed.address_objects.map(item => [item.value, item.name]));
    expect(Object.keys(values)).toEqual(expect.arrayContaining(['192.0.2.0/24', '198.51.100.0/24']));
  });

  it('parses services with a source-port range or no ports', () => {
    expect(service('WEB')).toMatchObject({ protocol: 'tcp', port_range: '80', source_port: '' });
    expect(service('SRCRANGE')).toMatchObject({ protocol: 'udp', port_range: '53', source_port: '1024-2000' });
    expect(service('ANYTCP')).toMatchObject({ protocol: 'tcp', port_range: 'any' });
  });

  it('keeps icmp type and code', () => {
    expect(service('PING')).toMatchObject({ protocol: 'icmp', icmp_type: '8', icmp_code: '0' });
  });

  it('parses prefix-length, netmask and wildcard inline addresses', () => {
    expect(policy('prefix').src_addresses).toEqual(['192.0.2.0/24']);
    expect(policy('prefix').dst_addresses).toEqual(['198.51.100.0/24']);
    expect(policy('wild').src_addresses).toEqual(['203.0.113.0/24']);
  });

  it('deactivates a rule with an inline address it cannot read instead of matching any', () => {
    expect(policy('ranged').disabled).toBe(true);
    expect(warnings.some(item => item.message.includes('ranged') && item.message.includes('range 192.0.2.1'))).toBe(true);
  });
});
