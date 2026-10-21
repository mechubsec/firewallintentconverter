import { describe, it, expect } from 'vitest';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

const CONFIG = `config system interface
    edit "port1"
        set alias "wan"
        set ip 203.0.113.2 255.255.255.248
    next
    edit "port2"
        set alias "lan"
        set ip 192.168.10.1 255.255.255.0
    next
end
config firewall address
    edit "lan-net"
        set subnet 192.168.10.0 255.255.255.0
    next
    edit "web-01"
        set subnet 192.168.10.20 255.255.255.255
    next
end
config firewall service custom
    edit "HTTPS"
        set tcp-portrange 443
    next
end
config firewall vip
    edit "vip-web-01"
        set extip 203.0.113.3
        set extintf "port1"
        set mappedip "192.168.10.20"
    next
end
config firewall policy
    edit 1
        set name "web-inbound"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "lan-net"
        set dstaddr "web-01"
        set action accept
        set service "HTTPS"
    next
end`;

function convert(mutate = (config) => config) {
  const config = mutate(parseFortigateConfig(CONFIG).intermediateConfig);
  return convertToSrxSetCommands(config, {}, null, {}).commands;
}

describe('FortiGate to SRX output', () => {
  it('keeps interface masks', () => {
    const commands = convert();
    expect(commands.some((line) => line.endsWith('family inet address 203.0.113.2/29'))).toBe(true);
    expect(commands.some((line) => line.endsWith('family inet address 192.168.10.1/24'))).toBe(true);
  });

  it('keeps address-object masks', () => {
    const commands = convert();
    expect(commands).toContain('set security address-book global address lan-net 192.168.10.0/24');
    expect(commands).toContain('set security address-book global address web-01 192.168.10.20/32');
  });

  it('never labels FortiGate output as PAN-OS or prints the internal implicit-rule tag', () => {
    const text = convert().join('\n');
    expect(text).not.toContain('PAN-OS');
    expect(text).not.toContain('added_by_fpic');
  });

  it('matches VIP destination NAT from the ingress zone only', () => {
    const fromZones = convert().filter((line) => /^set security nat destination rule-set \S+ from zone /.test(line));
    expect(fromZones).toHaveLength(1);
    expect(fromZones[0]).toMatch(/ from zone port1$/);
  });

  it('labels source tags by vendor', () => {
    const withTag = (vendor) => (config) => ({
      ...config,
      metadata: { ...config.metadata, source_vendor: vendor },
      security_policies: config.security_policies.map((policy) =>
        policy.name === 'web-inbound' ? { ...policy, tags: ['web'] } : policy),
    });
    expect(convert(withTag('panos')).join('\n')).toContain('[PAN-OS tags: web]');
    expect(convert(withTag('fortigate')).join('\n')).toContain('[Source tags: web]');
  });
});
