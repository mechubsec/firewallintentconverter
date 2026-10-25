import { describe, it, expect } from 'vitest';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';

const BASE = `config system interface
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
end
`;

const policy = (id, name, action, extra = '') => `    edit ${id}
        set name "${name}"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "lan-net"
        set dstaddr "all"
        set action ${action}
        set service "ALL"
${extra}    next
`;

const snat = (id, comment) => `    edit ${id}
        set comments "${comment}"
        set srcintf "port2"
        set dstintf "port1"
        set orig-addr "lan-net"
        set dst-addr "all"
    next
`;

const pbr = (id, src) => `    edit ${id}
        set input-device "port2"
        set src "${src}"
        set gateway 203.0.113.1
        set output-device "port1"
    next
`;

const parse = (text) => parseFortigateConfig(BASE + text).intermediateConfig;

describe('FortiGate config order (#110)', () => {
  it('keeps firewall policies in config order, not ID order', () => {
    const config = parse(`config firewall policy
${policy(5, 'moved-to-top', 'deny')}${policy(2, 'second-in-config', 'accept')}end
`);
    const names = config.security_policies.map((p) => p.name).filter((n) => /^(moved|second)/.test(n));
    expect(names).toEqual(['moved-to-top', 'second-in-config']);
  });

  it('keeps central SNAT rules in config order', () => {
    const config = parse(`config firewall central-snat-map
${snat(3, 'third-id')}${snat(1, 'first-id')}end
`);
    expect(config.nat_rules.map((r) => r.name)).toEqual(['third-id', 'first-id']);
  });

  it('keeps policy-NAT rules in config order', () => {
    const nat = '        set nat enable\n';
    const config = parse(`config firewall policy
${policy(5, 'nat-five', 'accept', nat)}${policy(2, 'nat-two', 'accept', nat)}end
`);
    const names = config.nat_rules.map((r) => r.name);
    expect(names).toEqual(['nat-five', 'nat-two']);
  });

  it('keeps router policy (PBR) in config order', () => {
    const config = parse(`config router policy
${pbr(7, '10.0.0.0 255.0.0.0')}${pbr(3, '172.16.0.0 255.240.0.0')}end
`);
    expect(config.pbf_rules.map((r) => r.name)).toEqual(['pbf-7', 'pbf-3']);
  });

  it('a repeated edit keeps the first position', () => {
    const config = parse(`config firewall policy
${policy(2, 'two', 'accept')}${policy(1, 'one', 'accept')}    edit 2
        set comments "again"
    next
end
`);
    const names = config.security_policies.map((p) => p.name).filter((n) => ['one', 'two'].includes(n));
    expect(names).toEqual(['two', 'one']);
  });
});
