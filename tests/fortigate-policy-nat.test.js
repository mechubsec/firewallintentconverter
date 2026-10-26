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

  it('maps central SNAT interfaces to their zones (#114)', () => {
    const zoned = CONFIG.replace(/config firewall policy[\s\S]*$/, `config system zone
    edit "inside"
        set interface "port2"
    next
    edit "outside"
        set interface "port1"
    next
end
config firewall central-snat-map
    edit 1
        set srcintf "port2"
        set dstintf "port1"
        set orig-addr "lan-net"
        set dst-addr "all"
    next
end`);
    const zonedLines = convertToSrxSetCommands(parseFortigateConfig(zoned).intermediateConfig, {}, null, {}).commands;
    expect(zonedLines.some((l) => /nat source rule-set \S+ from zone inside$/.test(l))).toBe(true);
    expect(zonedLines.some((l) => /nat source rule-set \S+ to zone outside$/.test(l))).toBe(true);
    expect(zonedLines.some((l) => / zone port[12]$/.test(l))).toBe(false);
  });

  it('skips central SNAT on a member of a multi-interface zone (#114)', () => {
    const shared = CONFIG.replace(/config firewall policy[\s\S]*$/, `config system zone
    edit "inside"
        set interface "port2" "port3"
    next
end
config firewall central-snat-map
    edit 1
        set srcintf "port2"
        set dstintf "port1"
        set orig-addr "lan-net"
        set dst-addr "all"
    next
end`);
    const { intermediateConfig, warnings } = parseFortigateConfig(shared);
    expect(intermediateConfig.nat_rules.some((rule) => rule.name === 'Central-SNAT-1')).toBe(false);
    expect(warnings.some((warning) => /interface "port2", one of several members of zone "inside" — not converted/.test(warning.message))).toBe(true);
  });

  it('warns that fixed-port interface NAT is not preserved', () => {
    const fixedPort = CONFIG.replace('        set nat enable\n    next\n    edit 2', '        set nat enable\n        set fixedport enable\n    next\n    edit 2');
    const { warnings } = parseFortigateConfig(fixedPort);
    expect(warnings.filter((warning) => /Policy "lan-out" uses fixed-port NAT/.test(warning.message))).toHaveLength(1);
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

  it('warns when a policy names an undefined ippool', () => {
    const missingPool = CONFIG.replace('set poolname "pool-1"', 'set poolname "pool-missing"');
    const { intermediateConfig, warnings } = parseFortigateConfig(missingPool);
    expect(intermediateConfig.nat_rules.find((rule) => rule.name === 'dmz-out-pool').translated_src).toEqual({ type: 'interface' });
    expect(warnings.filter((warning) => /IP pool "pool-missing" is not defined/.test(warning.message))).toHaveLength(1);
  });

  it('does not convert NAT on a negated address', () => {
    const negated = CONFIG.replace('        set srcaddr "lan-net"\n', '        set srcaddr "lan-net"\n        set srcaddr-negate enable\n');
    const { intermediateConfig, warnings } = parseFortigateConfig(negated);
    expect(intermediateConfig.nat_rules.some((rule) => rule.name === 'lan-out')).toBe(false);
    expect(warnings.some((warning) => /lan-out.*negated address/.test(warning.message))).toBe(true);
  });

  it('keeps policy order, with no caveat when every policy can be restated (#115)', () => {
    expect(commands.some((l) => l.startsWith('# CAVEAT: source NAT'))).toBe(false);
    const ruleOrder = natLines.filter((l) => / rule \S+ then source-nat /.test(l)).map((l) => l.match(/ rule (\S+) then/)[1]);
    expect(ruleOrder).toEqual(['lan-out', 'dmz-out-pool']);
  });
});

const NAT_BASE = `config system interface
    edit "port1"
        set ip 203.0.113.2 255.255.255.248
    next
    edit "port2"
        set ip 192.168.10.1 255.255.255.0
    next
end
config firewall address
    edit "lan-net"
        set subnet 192.168.10.0 255.255.255.0
    next
    edit "srv"
        set subnet 192.168.10.50 255.255.255.255
    next
end
config firewall service custom
    edit "web-alt"
        set tcp-portrange 8080-8090 9000
    next
    edit "dns-both"
        set tcp-portrange 53
        set udp-portrange 53
    next
end
config firewall service group
    edit "web-group"
        set member "HTTP" "HTTPS"
    next
end
config firewall ippool
    edit "pba"
        set type port-block-allocation
        set startip 203.0.113.10
        set endip 203.0.113.20
        set block-size 256
        set num-blocks-per-user 4
    next
    edit "fpr"
        set type fixed-port-range
        set startip 203.0.113.30
        set endip 203.0.113.40
        set source-startip 192.168.10.0
        set source-endip 192.168.10.255
    next
    edit "fpr-nosource"
        set type fixed-port-range
        set startip 203.0.113.30
        set endip 203.0.113.40
    next
    edit "o2o"
        set type one-to-one
        set startip 203.0.113.50
        set endip 203.0.113.60
    next
    edit "pba2"
        set type port-block-allocation
        set startip 203.0.113.70
        set endip 203.0.113.80
        set block-size 128
    next
    edit "ovl"
        set startip 203.0.113.90
        set endip 203.0.113.95
    next
end
`;

const policy = (id, name, { src = 'lan-net', service = 'ALL', action = 'accept', extra = '' } = {}) => `    edit ${id}
        set name "${name}"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "${src}"
        set dstaddr "all"
        set action ${action}
        set service "${service}"
${extra}    next
`;
const NAT = '        set nat enable\n';
const poolPolicy = (pool, more = '') => `${NAT}        set ippool enable\n        set poolname "${pool}"\n${more}`;

const convert = (policies) => {
  const parsed = parseFortigateConfig(`${NAT_BASE}config firewall policy\n${policies}end`);
  return {
    parsed,
    lines: convertToSrxSetCommands(parsed.intermediateConfig, {}, null, {}).commands,
    xml: buildSrxXml(parsed.intermediateConfig).xml,
  };
};
const rulePrefix = 'set security nat source rule-set port2-to-port1 rule';

describe('FortiGate policy NAT order and service (#115)', () => {
  it('emits a no-NAT policy above a NAT policy as source-nat off at the same position', () => {
    const { lines, xml } = convert(policy(1, 'srv-direct', { src: 'srv' }) + policy(2, 'lan-out', { extra: NAT }));
    const natRules = lines.filter((l) => /nat source rule-set .* rule \S+ then source-nat/.test(l));
    expect(natRules).toEqual([
      `${rulePrefix} srv-direct then source-nat off`,
      `${rulePrefix} lan-out then source-nat interface`,
    ]);
    expect(lines).toContain(`${rulePrefix} srv-direct match source-address 192.168.10.50/32`);
    expect(lines.some((l) => l.startsWith('# CAVEAT: source NAT'))).toBe(false);
    expect(xml.indexOf('<name>srv-direct</name>', xml.indexOf('<nat>'))).toBeLessThan(xml.indexOf('<name>lan-out</name>', xml.indexOf('<nat>')));
    expect(xml).toContain('<source-nat><off/></source-nat>');
  });

  it('emits no source-nat off for a no-NAT policy below the last NAT policy, or a deny policy', () => {
    const { lines } = convert(policy(1, 'lan-out', { extra: NAT })
      + policy(2, 'srv-direct', { src: 'srv' })
      + policy(3, 'blocked', { src: 'srv', action: 'deny' }));
    expect(lines.some((l) => l.endsWith('then source-nat off'))).toBe(false);
    expect(lines.some((l) => l.includes('rule blocked'))).toBe(false);
  });

  it('adds protocol and destination ports for a service that differs by policy', () => {
    const { lines, xml } = convert(policy(1, 'web-nat', { service: 'web-alt', extra: NAT })
      + policy(2, 'https-pool', { service: 'HTTPS', extra: poolPolicy('o2o') })
      + policy(3, 'rest', { extra: NAT }));
    expect(lines).toEqual(expect.arrayContaining([
      `${rulePrefix} web-nat match protocol tcp`,
      `${rulePrefix} web-nat match destination-port 8080 to 8090`,
      `${rulePrefix} web-nat match destination-port 9000`,
      `${rulePrefix} https-pool match destination-port 443`,
    ]));
    expect(lines.some((l) => l.startsWith(`${rulePrefix} rest match destination-port`))).toBe(false);
    expect(lines.some((l) => l.startsWith(`${rulePrefix} rest match protocol`))).toBe(false);
    expect(xml).toContain('<destination-port><name>8080</name><to><high>8090</high></to></destination-port>');
    expect(xml).toContain('<destination-port><name>9000</name></destination-port>');
    expect(xml).toContain('<protocol>tcp</protocol>');
  });

  it('merges a service group of one protocol into several destination ports', () => {
    const { lines } = convert(policy(1, 'web', { service: 'web-group', extra: NAT }));
    expect(lines).toEqual(expect.arrayContaining([
      `${rulePrefix} web match destination-port 80`,
      `${rulePrefix} web match destination-port 443`,
    ]));
  });

  it('keeps a caveat only when the service cannot be expressed and another policy translates differently', () => {
    const inexact = convert(policy(1, 'multi', { service: 'dns-both', extra: NAT }) + policy(2, 'plain', { src: 'srv' }));
    expect(inexact.lines.some((l) => l.startsWith('# CAVEAT: source NAT for policy "multi"') && l.includes('"plain"'))).toBe(true);
    expect(inexact.lines.some((l) => l.startsWith(`${rulePrefix} multi match protocol`))).toBe(false);
    const alone = convert(policy(1, 'multi', { service: 'dns-both', extra: NAT }));
    expect(alone.lines.some((l) => l.startsWith('# CAVEAT: source NAT'))).toBe(false);
  });

  it('caveats the NAT rule below a no-NAT policy whose service cannot be expressed', () => {
    const { lines } = convert(policy(1, 'ping-direct', { src: 'srv', service: 'PING' }) + policy(2, 'lan-out', { extra: NAT }));
    expect(lines.some((l) => l.includes('rule ping-direct then source-nat off'))).toBe(false);
    expect(lines.some((l) => l.startsWith('# CAVEAT: source NAT for policy "lan-out"') && l.includes('"ping-direct"'))).toBe(true);
  });

  it('maps one-to-one, block allocation and fixed-port-range pools (set and XML)', () => {
    const { lines, xml, parsed } = convert(policy(1, 'o2o-nat', { extra: poolPolicy('o2o') })
      + policy(2, 'pba-nat', { extra: poolPolicy('pba') })
      + policy(3, 'fpr-nat', { extra: poolPolicy('fpr') }));
    expect(lines).toEqual(expect.arrayContaining([
      'set security nat source pool pool-o2o-nat port no-translation',
      'set security nat source pool pool-pba-nat port block-allocation block-size 256',
      'set security nat source pool pool-pba-nat port block-allocation maximum-blocks-per-host 4',
      'set security nat source pool pool-fpr-nat port deterministic host address 192.168.10.0/24',
    ]));
    expect(xml).toContain('<port><no-translation/></port>');
    expect(xml).toContain('<port><block-allocation><block-size>256</block-size><maximum-blocks-per-host>4</maximum-blocks-per-host></block-allocation></port>');
    expect(xml).toContain('<port><deterministic><host><address>192.168.10.0/24</address></host></deterministic></port>');
    expect(lines.some((l) => l.includes('pool-fpr-nat host-address-base'))).toBe(false);
    expect(parsed.warnings.some((warning) => /IP pool "o2o" is type one-to-one/.test(warning.message))).toBe(true);
  });

  it('falls back to a default pool for fixed-port-range without a source range', () => {
    const { lines, parsed } = convert(policy(1, 'fpr-nat', { extra: poolPolicy('fpr-nosource') }));
    expect(lines.some((l) => /pool-fpr-nat (port|host-address-base)/.test(l))).toBe(false);
    expect(lines.some((l) => l.endsWith('then source-nat pool pool-fpr-nat'))).toBe(true);
    expect(parsed.warnings.some((warning) => /fixed-port-range without a usable source-startip/.test(warning.message))).toBe(true);
  });

  it('maps fixedport with a pool to port no-translation, and warns for interface NAT', () => {
    const pooled = convert(policy(1, 'fixed-pool', { extra: poolPolicy('pba', '        set fixedport enable\n') }));
    expect(pooled.lines).toContain('set security nat source pool pool-fixed-pool port no-translation');
    expect(pooled.lines.some((l) => l.includes('block-allocation'))).toBe(false);
    expect(pooled.parsed.warnings.some((warning) => /fixed-port NAT/.test(warning.message))).toBe(false);
    expect(pooled.xml).toContain('<port><no-translation/></port>');
    const interfaceNat = convert(policy(1, 'fixed-if', { extra: `${NAT}        set fixedport enable\n` }));
    expect(interfaceNat.parsed.warnings.some((warning) => /Policy "fixed-if" uses fixed-port NAT/.test(warning.message))).toBe(true);
  });

  it('keeps a plain overload pool free of port flags (control)', () => {
    const { lines } = convert(policy(1, 'lan-out', { extra: `${NAT}        set ippool enable\n        set poolname "missing"\n` }));
    expect(lines.some((l) => / port /.test(l) && l.includes('security nat source pool'))).toBe(false);
  });

  it('does not exempt a no-NAT policy with a schedule or user selector, and caveats the NAT rule below it', () => {
    for (const selector of ['        set schedule "work-hours"\n', '        set users "alice"\n', '        set internet-service enable\n']) {
      const { lines } = convert(policy(1, 'sel-direct', { src: 'srv', extra: selector }) + policy(2, 'lan-out', { extra: NAT }));
      expect(lines.some((l) => l.includes('rule sel-direct'))).toBe(false);
      expect(lines.some((l) => l.startsWith('# CAVEAT: source NAT for policy "lan-out"') && l.includes('"sel-direct"'))).toBe(true);
    }
    const always = convert(policy(1, 'srv-direct', { src: 'srv', extra: '        set schedule "always"\n' }) + policy(2, 'lan-out', { extra: NAT }));
    expect(always.lines).toContain(`${rulePrefix} srv-direct then source-nat off`);
  });

  it('does not emit an exemption across a wildcard and a concrete zone pair', () => {
    const wildcard = policy(1, 'any-direct', { src: 'srv' }).replace('srcintf "port2"', 'srcintf "any"');
    const { lines } = convert(wildcard + policy(2, 'lan-out', { extra: NAT }));
    expect(lines.some((l) => l.includes('rule any-direct'))).toBe(false);
    expect(lines.some((l) => l.startsWith('# CAVEAT: source NAT for policy "lan-out"') && l.includes('"any-direct"'))).toBe(true);
    const matching = convert(wildcard + policy(2, 'any-out', { extra: NAT }).replace('srcintf "port2"', 'srcintf "any"'));
    expect(matching.lines.some((l) => l.includes('rule any-direct then source-nat off'))).toBe(true);
  });

  it('treats service-negate as an inexact policy: no match, no exemption, a caveat below it', () => {
    const negatedService = convert(policy(1, 'not-https', { src: 'srv', service: 'HTTPS', extra: '        set service-negate enable\n' }) + policy(2, 'lan-out', { extra: NAT }));
    expect(negatedService.lines.some((l) => l.includes('rule not-https'))).toBe(false);
    expect(negatedService.lines.some((l) => l.startsWith('# CAVEAT: source NAT for policy "lan-out"') && l.includes('"not-https"'))).toBe(true);
    const natPolicy = convert(policy(1, 'not-https-nat', { service: 'HTTPS', extra: `${NAT}        set service-negate enable\n` }));
    expect(natPolicy.lines.some((l) => l.includes('rule not-https-nat'))).toBe(false);
    expect(natPolicy.parsed.warnings.some((warning) => /not-https-nat.*negated address or service/.test(warning.message))).toBe(true);
  });

  it('caveats differently translating policies that overlap through an any zone', () => {
    const anyOut = policy(1, 'any-out', { extra: NAT }).replace('srcintf "port2"', 'srcintf "any"');
    const { lines } = convert(anyOut + policy(2, 'lan-pool', { extra: poolPolicy('o2o') }));
    expect(lines.some((l) => l.startsWith('# CAVEAT: source NAT for policy "lan-pool"') && l.includes('"any-out"'))).toBe(true);
    const same = convert(anyOut + policy(2, 'lan-also', { extra: NAT }));
    expect(same.lines.some((l) => l.startsWith('# CAVEAT: source NAT'))).toBe(false);
  });

  it('converts 10k alternating NAT and no-NAT policies in linear time', () => {
    const policies = Array.from({ length: 10000 }, (_, index) => policy(index + 1, `p${index + 1}`, { src: index % 2 ? 'lan-net' : 'srv', extra: index % 2 ? NAT : '' })).join('');
    const { intermediateConfig } = parseFortigateConfig(`${NAT_BASE}config firewall policy\n${policies}end`);
    const offRules = intermediateConfig.nat_rules.filter((rule) => rule.translated_src.type === 'no-nat');
    expect(offRules).toHaveLength(5000);
    expect(intermediateConfig.nat_rules).toHaveLength(10000);
  });

  it('treats application and url-category selectors as inexact', () => {
    for (const selector of ['        set application 1 2\n', '        set url-category 26\n', '        set app-category 2\n']) {
      const { lines } = convert(policy(1, 'app-direct', { src: 'srv', extra: selector }) + policy(2, 'lan-out', { extra: NAT }));
      expect(lines.some((l) => l.includes('rule app-direct'))).toBe(false);
      expect(lines.some((l) => l.startsWith('# CAVEAT: source NAT for policy "lan-out"') && l.includes('"app-direct"'))).toBe(true);
    }
  });

  it('falls back to a default pool when block-allocation pools differ in size', () => {
    const { lines, parsed } = convert(policy(1, 'multi-pba', { extra: poolPolicy('pba" "pba2') }));
    expect(lines.some((l) => l.includes('block-allocation'))).toBe(false);
    expect(parsed.warnings.some((warning) => /Policy "multi-pba" uses port-block-allocation pools .* different block-size/.test(warning.message))).toBe(true);
  });

  it('warns at every use of a mixed pool set, even when the pool was already used alone', () => {
    const { lines, parsed } = convert(policy(1, 'alone', { extra: poolPolicy('o2o') })
      + policy(2, 'mixed-a', { extra: poolPolicy('o2o" "ovl') })
      + policy(3, 'mixed-b', { extra: poolPolicy('o2o" "ovl') }));
    for (const name of ['mixed-a', 'mixed-b']) {
      expect(parsed.warnings.some((warning) => new RegExp(`Policy "${name}" uses IP pools`).test(warning.message))).toBe(true);
      expect(lines).not.toContain(`set security nat source pool pool-${name} port no-translation`);
    }
    expect(lines).toContain('set security nat source pool pool-alone port no-translation');
  });

  it('drops an empty match port instead of crashing the emitters', () => {
    const { parsed } = convert(policy(1, 'lan-out', { service: 'HTTPS', extra: NAT }));
    parsed.intermediateConfig.nat_rules[0].match_ports = [''];
    const lines = convertToSrxSetCommands(parsed.intermediateConfig, {}, null, {}).commands;
    expect(lines.some((l) => l.includes('match destination-port'))).toBe(false);
    expect(() => buildSrxXml(parsed.intermediateConfig)).not.toThrow();
  });

  it('emits block allocation as one set command per leaf', () => {
    const { lines } = convert(policy(1, 'pba-nat', { extra: poolPolicy('pba') }));
    expect(lines).toContain('set security nat source pool pool-pba-nat port block-allocation block-size 256');
    expect(lines).toContain('set security nat source pool pool-pba-nat port block-allocation maximum-blocks-per-host 4');
  });

  it('keeps the exemption for a no-NAT policy with an application-list profile', () => {
    const { lines } = convert(policy(1, 'srv-direct', { src: 'srv', extra: '        set application-list "default"\n' }) + policy(2, 'lan-out', { extra: NAT }));
    expect(lines).toContain(`${rulePrefix} srv-direct then source-nat off`);
  });

  it('maps ALL_TCP to a protocol-only match above a differently translated UDP policy', () => {
    const { lines } = convert(policy(1, 'tcp-nat', { service: 'ALL_TCP', extra: NAT }) + policy(2, 'udp-pool', { service: 'ALL_UDP', extra: poolPolicy('o2o') }));
    expect(lines).toContain(`${rulePrefix} tcp-nat match protocol tcp`);
    expect(lines).toContain(`${rulePrefix} udp-pool match protocol udp`);
    expect(lines.some((l) => l.includes('match destination-port'))).toBe(false);
    expect(lines.some((l) => l.startsWith('# CAVEAT: source NAT'))).toBe(false);
  });

  it('keeps the exemption when wildcard policies share every overlapping zone pair', () => {
    const wide = policy(1, 'any-direct', { src: 'srv' }).replace('srcintf "port2"', 'srcintf "any"').replace('dstintf "port1"', 'dstintf "port1" "port3"');
    const narrow = policy(2, 'any-out', { extra: NAT }).replace('srcintf "port2"', 'srcintf "any"');
    const { lines } = convert(wide + narrow);
    expect(lines.some((l) => l.includes('rule any-direct then source-nat off'))).toBe(true);
    expect(lines.some((l) => l.startsWith('# CAVEAT: source NAT'))).toBe(false);
  });
});
