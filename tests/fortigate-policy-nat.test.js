import { describe, it, expect } from 'vitest';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';

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
    edit "dmz-net"
        set subnet 192.168.20.0 255.255.255.0
    next
    edit "guest-net"
        set subnet 192.168.30.0 255.255.255.0
    next
end
config firewall ippool
    edit "pool-1"
        set startip 203.0.113.10
        set endip 203.0.113.20
    next
end
config firewall policy
    edit 1
        set name "lan-out"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "lan-net"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set nat enable
    next
    edit 2
        set name "dmz-out-pool"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "dmz-net"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set nat enable
        set ippool enable
        set poolname "pool-1"
    next
    edit 3
        set name "guest-out-no-nat"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "guest-net"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end`;

const config = parseFortigateConfig(CONFIG).intermediateConfig;
const commands = convertToSrxSetCommands(config, {}, null, {}).commands;
const natLines = commands.filter((line) => line.includes('security nat source'));

describe('FortiGate policy "set nat enable"', () => {
  it('emits interface source NAT from the policy zones and addresses', () => {
    expect(natLines.some((l) => /rule-set \S+ from zone port2$/.test(l))).toBe(true);
    expect(natLines.some((l) => /rule-set \S+ to zone port1$/.test(l))).toBe(true);
    expect(natLines.some((l) => l.includes('match source-address 192.168.10.0/24'))).toBe(true);
    expect(natLines.some((l) => l.endsWith('then source-nat interface'))).toBe(true);
  });

  it('resolves ippool poolname to the pool range', () => {
    expect(natLines.some((l) => l.includes('pool') && l.endsWith('address 203.0.113.10/32 to 203.0.113.20/32'))).toBe(true);
    expect(natLines.some((l) => l.includes('match source-address 192.168.20.0/24'))).toBe(true);
    expect(natLines.some((l) => /then source-nat pool /.test(l))).toBe(true);
  });

  it('emits no source NAT for a policy without nat', () => {
    expect(natLines.some((l) => l.includes('192.168.30.0/24'))).toBe(false);
  });

  it('emits an ippool only where a rule uses it, never as a catch-all', () => {
    expect(natLines.some((l) => l.includes('match source-address 0.0.0.0/0'))).toBe(false);
    expect(natLines.filter((l) => / pool \S+ address /.test(l))).toHaveLength(1);
  });

  it('resolves a central SNAT nat-ippool to the pool range', () => {
    const central = CONFIG.replace(/config firewall policy[\s\S]*$/, `config firewall central-snat-map
    edit 1
        set srcintf "port2"
        set dstintf "port1"
        set orig-addr "lan-net"
        set dst-addr "all"
        set nat-ippool "pool-1"
    next
end`);
    const centralLines = convertToSrxSetCommands(parseFortigateConfig(central).intermediateConfig, {}, null, {}).commands;
    expect(centralLines.some((l) => / pool \S+ address 203\.0\.113\.10\/32 to 203\.0\.113\.20\/32$/.test(l))).toBe(true);
    expect(centralLines.some((l) => /then source-nat pool /.test(l))).toBe(true);
  });

  it('flags a zone pair whose policies translate differently', () => {
    expect(commands.some((l) => l.startsWith('# CAVEAT: source NAT for policy "lan-out" ignores policy order'))).toBe(true);
    expect(commands.some((l) => l.includes('"guest-out-no-nat"') && l.startsWith('# CAVEAT:'))).toBe(true);
  });

  it('adds no caveat when one policy NATs its zone pair', () => {
    const single = CONFIG.replace(/    edit 2\n[\s\S]*    next\n(?=end$)/, '');
    const singleLines = convertToSrxSetCommands(parseFortigateConfig(single).intermediateConfig, {}, null, {}).commands;
    expect(singleLines.some((l) => l.endsWith('then source-nat interface'))).toBe(true);
    expect(singleLines.some((l) => l.startsWith('# CAVEAT: source NAT'))).toBe(false);
  });

  it('ignores policy nat flags in central NAT mode', () => {
    const central = `config system settings\n    set central-nat enable\nend\n${CONFIG}`;
    const centralRules = parseFortigateConfig(central).intermediateConfig.nat_rules;
    expect(centralRules.some((rule) => rule.name === 'lan-out' || rule.name === 'dmz-out-pool')).toBe(false);
  });

  it('converts only source pool ranges, never a range VIP into an unmatched DNAT rule', () => {
    const withRangeVip = `${CONFIG}\nconfig firewall vip
    edit "vip-range"
        set extip 203.0.113.30-203.0.113.31
        set extintf "port1"
        set mappedip "192.168.10.30-192.168.10.31"
    next
end`;
    const rangeLines = convertToSrxSetCommands(parseFortigateConfig(withRangeVip).intermediateConfig, {}, null, {}).commands;
    expect(rangeLines.some((l) => / match (source|destination)-address \S+ to /.test(l))).toBe(false);
    expect(rangeLines.some((l) => l.includes('rule vip-range then destination-nat'))).toBe(false);
  });

  it('emits the pool range in Junos XML form', () => {
    const { xml } = buildSrxXml(config);
    expect(xml).toContain('<address><name>203.0.113.10/32</name><to><ipaddr>203.0.113.20/32</ipaddr></to></address>');
  });

  it('treats the built-in "all" as any address', () => {
    const { xml } = buildSrxXml(config);
    const natXml = xml.slice(xml.indexOf('<nat>'), xml.indexOf('</nat>'));
    expect(natXml).toContain('<source>');
    expect(natXml).not.toContain('>all<');
    expect(natLines.some((l) => l.includes('rule lan-out match destination-address 0.0.0.0/0'))).toBe(true);
  });

  it('warns when a referenced ippool is not an overload pool', () => {
    const oneToOne = CONFIG.replace('        set endip 203.0.113.20\n', '        set endip 203.0.113.20\n        set type one-to-one\n');
    const { warnings } = parseFortigateConfig(oneToOne);
    expect(warnings.filter((warning) => /IP pool "pool-1" is type one-to-one/.test(warning.message))).toHaveLength(1);
  });

  it('caps the conflicting policy names in a caveat', () => {
    const extraPolicies = [10, 11, 12, 13].map((id) => `    edit ${id}
        set name "no-nat-${id}"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "guest-net"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
`).join('');
    const many = CONFIG.replace(/end$/, `${extraPolicies}end`);
    const lines = convertToSrxSetCommands(parseFortigateConfig(many).intermediateConfig, {}, null, {}).commands;
    expect(lines.some((l) => l.startsWith('# CAVEAT: source NAT for policy "lan-out"') && / and \d+ more in the same zone pair/.test(l))).toBe(true);
  });

  it('does not convert NAT on a negated address', () => {
    const negated = CONFIG.replace('        set srcaddr "lan-net"\n', '        set srcaddr "lan-net"\n        set srcaddr-negate enable\n');
    const { intermediateConfig, warnings } = parseFortigateConfig(negated);
    expect(intermediateConfig.nat_rules.some((rule) => rule.name === 'lan-out')).toBe(false);
    expect(warnings.some((warning) => /lan-out.*negated address/.test(warning.message))).toBe(true);
  });
});
