import { describe, it, expect } from 'vitest';
import { parseCiscoAsaConfig } from '../src/parsers/cisco-asa-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

const asaConfig = (natLines) => `interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.0
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.1.1 255.255.255.0
!
object network WEB
 host 192.168.1.10
${natLines}
object network WEB-PUB
 host 203.0.113.10
`;

const convert = (text) => {
  const { intermediateConfig, warnings } = parseCiscoAsaConfig(text);
  const result = convertToSrxSetCommands(structuredClone(intermediateConfig), {}, null, {});
  return { intermediateConfig, warnings, natLines: result.commands.filter((line) => line.startsWith('set security nat')) };
};

describe('Cisco ASA static NAT', () => {
  it('object NAT static becomes Junos static NAT from the outside zone', () => {
    const { intermediateConfig, natLines } = convert(asaConfig(' nat (inside,outside) static 203.0.113.10'));
    expect(intermediateConfig.nat_rules[0]).toMatchObject({
      type: 'static',
      src_zones: ['outside'],
      dst_zones: ['inside'],
      dst_addresses: ['203.0.113.10'],
      translated_src: { type: 'static', address: 'WEB' },
    });
    expect(natLines.some((line) => /static rule-set \S+ from zone outside$/.test(line))).toBe(true);
    expect(natLines.some((line) => /match destination-address 203\.0\.113\.10\/32$/.test(line))).toBe(true);
    expect(natLines.some((line) => /then static-nat prefix 192\.168\.1\.10\/32$/.test(line))).toBe(true);
  });

  it('no-proxy-arp suppresses the proxy ARP entry', () => {
    const withArp = convert(asaConfig(' nat (inside,outside) static 203.0.113.10'));
    const withoutArp = convert(asaConfig(' nat (inside,outside) static 203.0.113.10 no-proxy-arp'));
    expect(withArp.natLines.some((line) => line.includes('proxy-arp'))).toBe(true);
    expect(withoutArp.natLines.some((line) => line.includes('proxy-arp'))).toBe(false);
  });

  it('twice NAT source static is bidirectional', () => {
    const text = asaConfig('').replace('object network WEB-PUB', 'nat (inside,outside) source static WEB WEB-PUB\nobject network WEB-PUB');
    const { intermediateConfig, natLines } = convert(text);
    expect(intermediateConfig.nat_rules[0]).toMatchObject({ type: 'static', src_zones: ['outside'], dst_zones: ['inside'] });
    expect(natLines.some((line) => /static rule-set \S+ from zone outside$/.test(line))).toBe(true);
  });

  it('twice NAT unidirectional is one-way, so it is dropped with a warning', () => {
    const text = asaConfig('').replace('object network WEB-PUB', 'nat (inside,outside) source static WEB WEB-PUB unidirectional\nobject network WEB-PUB');
    const { intermediateConfig, warnings, natLines } = convert(text);
    expect(intermediateConfig.nat_rules).toHaveLength(0);
    expect(natLines.some((line) => line.startsWith('set security nat static'))).toBe(false);
    expect(warnings.some((item) => item.element === 'nat/static/Manual-NAT-1' && item.message.includes('one-way'))).toBe(true);
  });

  it.each([
    ['source static WEB interface'],
    ['source static WEB interface service HTTP HTTP-ALT'],
  ])('twice NAT static to the interface is dropped with a warning (%s)', (command) => {
    const text = asaConfig('').replace('object network WEB-PUB', `nat (inside,outside) ${command}\nobject network WEB-PUB`);
    const { intermediateConfig, warnings, natLines } = convert(text);
    expect(intermediateConfig.nat_rules).toHaveLength(0);
    expect(natLines).toHaveLength(0);
    expect(warnings.some((item) => item.element === 'nat/static/Manual-NAT-1' && item.message.includes('interface'))).toBe(true);
  });

  it('twice NAT identity mapping is not turned into static NAT', () => {
    const text = asaConfig('').replace('object network WEB-PUB', 'nat (inside,any) source static WEB WEB\nobject network WEB-PUB');
    const { intermediateConfig, warnings, natLines } = convert(text);
    expect(intermediateConfig.nat_rules).toHaveLength(0);
    expect(natLines.some((line) => line.includes('static') || line.includes('proxy-arp'))).toBe(false);
    expect(warnings.some((item) => item.message.includes('identity NAT'))).toBe(true);
  });

  it('static to the interface is skipped with a warning', () => {
    const { intermediateConfig, warnings } = convert(asaConfig(' nat (inside,outside) static interface service tcp 80 8080'));
    expect(intermediateConfig.nat_rules).toHaveLength(0);
    expect(warnings.some((item) => item.element === 'nat/static/Auto-NAT-WEB')).toBe(true);
  });
});

describe('Cisco ASA static NAT with a service', () => {
  it('twice NAT source static with a service is skipped, not widened to every port', () => {
    const text = asaConfig('').replace('object network WEB-PUB',
      'nat (inside,outside) source static WEB WEB-PUB service HTTP HTTP-ALT\nobject network WEB-PUB');
    const { intermediateConfig, warnings, natLines } = convert(text);
    expect(intermediateConfig.nat_rules).toHaveLength(0);
    expect(natLines.some((line) => line.startsWith('set security nat static'))).toBe(false);
    expect(warnings.some((item) => item.element === 'nat/static/Manual-NAT-1' && item.message.includes('HTTP-ALT'))).toBe(true);
  });
});
