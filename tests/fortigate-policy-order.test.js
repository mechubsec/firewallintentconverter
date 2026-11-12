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

describe('FortiGate policy fail-closed parsing', () => {
  const rule = (name, body) => `config firewall policy
    edit 1
        set name "${name}"
        set srcintf "port2"
        set dstintf "port1"
${body}    next
end
`;
  const find = (config, name) => config.security_policies.find((p) => p.name === name);

  it('defaults a policy without "set action" to deny', () => {
    const config = parse(rule('no-action', '        set srcaddr "lan-net"\n        set dstaddr "all"\n        set service "ALL"\n'));
    expect(find(config, 'no-action').action).toBe('deny');
  });

  it('deactivates a policy with service-negate instead of inverting it', () => {
    const body = '        set srcaddr "lan-net"\n        set dstaddr "all"\n        set action accept\n        set service "HTTP"\n        set service-negate enable\n';
    const { intermediateConfig, warnings } = parseFortigateConfig(BASE + rule('neg-svc', body));
    expect(find(intermediateConfig, 'neg-svc').disabled).toBe(true);
    expect(warnings.some((w) => w.element === 'security-rule/neg-svc' && /service-negate/.test(w.message))).toBe(true);
  });

  it.each([
    ['internet-service', '        set internet-service enable\n        set internet-service-name "Google-Web"\n'],
    ['internet-service-src', '        set internet-service-src enable\n        set internet-service-src-name "Google-Web"\n'],
    ['IPv6 destination', '        set srcaddr "lan-net"\n        set dstaddr6 "all"\n'],
  ])('deactivates a policy that selects traffic with %s', (label, body) => {
    const { intermediateConfig, warnings } = parseFortigateConfig(BASE + rule('ignored-sel', `${body}        set action accept\n        set service "ALL"\n`));
    expect(find(intermediateConfig, 'ignored-sel').disabled).toBe(true);
    expect(warnings.some((w) => w.element === 'security-rule/ignored-sel')).toBe(true);
  });

  it('warns when a multi-VDOM backup hides its objects under global/vdom', () => {
    const { warnings } = parseFortigateConfig(`config global
config system interface
    edit "port1"
        set vdom "tenant1"
    next
end
end
config vdom
edit tenant1
config firewall address
    edit "lan-net"
        set subnet 192.168.10.0 255.255.255.0
    next
end
end
`);
    expect(warnings.some((w) => w.severity === 'error' && /VDOM/.test(w.message))).toBe(true);
  });

  it('does not let "edit __proto__" write onto Object.prototype', () => {
    try {
      parse('config firewall policy\n    edit __proto__\n        set srcintf "evil"\n    next\nend\n');
      expect({}.srcintf).toBeUndefined();
    } finally {
      delete Object.prototype.srcintf;
    }
  });
});
