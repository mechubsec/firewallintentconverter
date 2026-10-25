import { describe, it, expect } from 'vitest';
import { parseHuaweiConfig } from '../src/parsers/huawei-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';

const CONFIG = `nat-policy
 rule name vpn-exempt
  source-zone trust
  destination-zone untrust
  action no-nat
 rule name hide
  source-zone trust
  destination-zone untrust
  action source-nat easy-ip
`;

const { intermediateConfig } = parseHuaweiConfig(CONFIG);

describe('Huawei nat-policy action no-nat', () => {
  it('parses as source/no-nat ahead of the source NAT rule', () => {
    const rules = intermediateConfig.nat_rules;
    expect(rules.map(rule => rule.name)).toEqual(['vpn-exempt', 'hide']);
    expect(rules[0].type).toBe('source');
    expect(rules[0].translated_src).toEqual({ type: 'no-nat' });
    expect(rules[1].translated_src.type).toBe('interface');
  });

  it('renders source-nat off before the hide rule in set output', () => {
    const { commands } = convertToSrxSetCommands(structuredClone(intermediateConfig), {}, null, {});
    const exemptIndex = commands.findIndex(line => line.includes('rule vpn-exempt then source-nat off'));
    const hideIndex = commands.findIndex(line => line.includes('rule hide '));
    expect(exemptIndex).toBeGreaterThan(-1);
    expect(hideIndex).toBeGreaterThan(exemptIndex);
  });

  it('renders the off element in XML output', () => {
    const { xml } = buildSrxXml(structuredClone(intermediateConfig), {});
    const exemptBlock = xml.slice(xml.indexOf('<name>vpn-exempt</name>'));
    expect(exemptBlock.slice(0, exemptBlock.indexOf('</rule>'))).toContain('<source-nat><off/></source-nat>');
  });
});

describe('Huawei nat-policy no-nat match clauses', () => {
  const ruleConfig = clauses => `nat-policy
 rule name vpn-exempt
  source-zone trust
  destination-zone untrust
${clauses.map(clause => `  ${clause}\n`).join('')}  action no-nat
`;

  it('keeps inline addresses on the exemption, and ignores service any', () => {
    const { intermediateConfig: parsed } = parseHuaweiConfig(ruleConfig([
      'source-address 10.0.0.0 mask 255.255.255.0',
      'destination-address 172.16.0.0 16',
      'service any',
    ]));
    expect(parsed.nat_rules[0].src_addresses).toEqual(['10.0.0.0/24']);
    expect(parsed.nat_rules[0].dst_addresses).toEqual(['172.16.0.0/16']);
    const { commands } = convertToSrxSetCommands(structuredClone(parsed), {}, null, {});
    expect(commands).toContain('set security nat source rule-set trust-to-untrust rule vpn-exempt match source-address 10.0.0.0/24');
    expect(commands.some(line => line.includes('rule vpn-exempt match source-address 0.0.0.0/0'))).toBe(false);
  });

  it.each([
    ['source-address range 10.0.0.1 10.0.0.9'],
    ['source-address 10.0.0.0 0.0.0.255'],
    ['service http'],
  ])('drops an exemption it cannot fully read (%s) with a warning', clause => {
    const { intermediateConfig: parsed, warnings } = parseHuaweiConfig(ruleConfig([clause]));
    expect(parsed.nat_rules).toHaveLength(0);
    expect(warnings.some(item => item.severity === 'warning' && item.message.includes('vpn-exempt') && item.message.includes(clause))).toBe(true);
  });
});
