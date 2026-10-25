import { describe, it, expect } from 'vitest';
import { parseCiscoAsaConfig } from '../src/parsers/cisco-asa-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

const asaConfig = natLine => `interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.0
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.1.1 255.255.255.0
!
object network LAN
 subnet 192.168.1.0 255.255.255.0
object network WEB
 host 192.168.1.10
object network WEB-PUB
 host 203.0.113.10
${natLine}
`;

describe('ASA twice NAT with a description', () => {
  it('converts a dynamic rule that has a description', () => {
    const { intermediateConfig } = parseCiscoAsaConfig(asaConfig('nat (inside,outside) source dynamic LAN interface description outbound hide'));
    expect(intermediateConfig.nat_rules).toHaveLength(1);
    expect(intermediateConfig.nat_rules[0]).toMatchObject({ type: 'source', src_addresses: ['LAN'] });
    const { commands } = convertToSrxSetCommands(structuredClone(intermediateConfig), {}, null, {});
    expect(commands.some(line => /source rule-set \S+ rule \S+ then source-nat interface$/.test(line))).toBe(true);
  });

  it('does not read option keywords from the description text', () => {
    const { intermediateConfig, warnings } = parseCiscoAsaConfig(asaConfig(
      'nat (inside,outside) source static WEB WEB-PUB description not unidirectional, not inactive, no no-proxy-arp',
    ));
    expect(intermediateConfig.nat_rules).toHaveLength(1);
    expect(intermediateConfig.nat_rules[0].type).toBe('static');
    expect(intermediateConfig.nat_rules[0].arp_reply).toBeUndefined();
    expect(warnings.some(item => item.element === 'nat/static/Manual-NAT-1' || item.element === 'nat/Manual-NAT-1')).toBe(false);
  });

  it('still honours the options before the description', () => {
    const { intermediateConfig } = parseCiscoAsaConfig(asaConfig(
      'nat (inside,outside) source static WEB WEB-PUB no-proxy-arp description web publish',
    ));
    expect(intermediateConfig.nat_rules[0]).toMatchObject({ type: 'static', arp_reply: false });
  });
});

describe('ASA twice NAT prefixes', () => {
  it.each([
    ['nat (inside,outside) after-auto source dynamic LAN interface description documented'],
    ['nat (inside,outside) 1 source dynamic LAN interface'],
    ['nat (inside,outside) after-auto 2 source dynamic LAN interface'],
  ])('keeps the source match after a section or line prefix (%s)', natLine => {
    const { intermediateConfig } = parseCiscoAsaConfig(asaConfig(natLine));
    expect(intermediateConfig.nat_rules).toHaveLength(1);
    expect(intermediateConfig.nat_rules[0]).toMatchObject({ type: 'source', src_addresses: ['LAN'] });
  });

  it('skips a line it cannot parse instead of emitting any-to-any interface NAT', () => {
    const { intermediateConfig, warnings } = parseCiscoAsaConfig(asaConfig('nat (inside,outside) bogus-keyword source dynamic LAN interface'));
    expect(intermediateConfig.nat_rules).toHaveLength(0);
    expect(warnings.some(item => item.element === 'nat/Manual-NAT-1' && item.message.includes('could not be parsed'))).toBe(true);
  });
});

describe('ASA identity twice NAT (NAT exemption)', () => {
  const exemptConfig = extra => asaConfig(`object network REMOTE
 subnet 10.20.0.0 255.255.0.0
object network LAN-OBJ
 subnet 192.168.1.0 255.255.255.0
 nat (inside,outside) dynamic interface
nat (inside,outside) source static LAN LAN destination static REMOTE REMOTE no-proxy-arp route-lookup${extra}`);

  it.each([[''], [' description VPN exemption']])('becomes source-nat off ahead of object NAT (%s)', extra => {
    const { intermediateConfig } = parseCiscoAsaConfig(exemptConfig(extra));
    const rules = intermediateConfig.nat_rules;
    expect(rules[0]).toMatchObject({
      type: 'source', src_addresses: ['LAN'], dst_addresses: ['REMOTE'], translated_src: { type: 'no-nat' },
    });
    expect(rules[1].name).toBe('Auto-NAT-LAN-OBJ');
    const { commands } = convertToSrxSetCommands(structuredClone(intermediateConfig), {}, null, {});
    const nat = commands.filter(line => line.startsWith('set security nat source rule-set'));
    const offIndex = nat.findIndex(line => line.endsWith('then source-nat off'));
    const hideIndex = nat.findIndex(line => line.endsWith('then source-nat interface'));
    expect(offIndex).toBeGreaterThan(-1);
    expect(hideIndex).toBeGreaterThan(offIndex);
    expect(commands.some(line => /source pool|destination pool/.test(line))).toBe(false);
  });

  it('keeps after-auto twice NAT behind object NAT', () => {
    const { intermediateConfig } = parseCiscoAsaConfig(asaConfig(`object network LAN-OBJ
 subnet 192.168.1.0 255.255.255.0
 nat (inside,outside) dynamic interface
nat (inside,outside) after-auto source dynamic LAN interface`));
    expect(intermediateConfig.nat_rules.map(rule => rule.name)).toEqual(['Auto-NAT-LAN-OBJ', 'Manual-NAT-2']);
  });
});
