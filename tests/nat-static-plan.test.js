import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';

// Junos convention: dst_addresses is the public address, translated_src.address the private prefix.
const staticRule = (overrides = {}) => ({
  name: 'web',
  type: 'static',
  src_zones: ['untrust'],
  dst_zones: ['trust'],
  src_addresses: ['any'],
  dst_addresses: ['203.0.113.10/32'],
  translated_src: { type: 'static', address: '192.168.1.10/32' },
  ...overrides,
});

const config = (rules) => ({
  zones: [{ name: 'trust', interfaces: ['lan'] }, { name: 'untrust', interfaces: ['wan'] }],
  interfaces: [{ name: 'wan', ip: '203.0.113.1/24' }, { name: 'lan', ip: '192.168.1.1/24' }],
  nat_rules: rules,
});
const mappings = { wan: 'ge-0/0/0', lan: 'ge-0/0/1' };
const convert = (cfg) => convertToSrxSetCommands(structuredClone(cfg), mappings, null, {});
const natLines = (cfg) => convert(cfg).commands.filter((line) => line.startsWith('set security nat'));

describe('static NAT plan', () => {
  it('renders from zone, public match, private prefix and proxy ARP', () => {
    const lines = natLines(config([staticRule()]));
    expect(lines).toContain('set security nat static rule-set STATIC-NAT-untrust from zone untrust');
    expect(lines).toContain('set security nat static rule-set STATIC-NAT-untrust rule web match destination-address 203.0.113.10/32');
    expect(lines).toContain('set security nat static rule-set STATIC-NAT-untrust rule web then static-nat prefix 192.168.1.10/32');
    expect(lines).toContain('set security nat proxy-arp interface ge-0/0/0.0 address 203.0.113.10/32');
  });

  it('puts rules from different zones in separate rule-sets', () => {
    const lines = natLines(config([
      staticRule(),
      staticRule({ name: 'other', src_zones: ['trust'], dst_addresses: ['192.168.1.200/32'], translated_src: { type: 'static', address: '192.168.1.20/32' } }),
    ]));
    expect(lines.filter((line) => / static rule-set \S+ from zone /.test(line))).toHaveLength(2);
  });

  it('skips a rule reached from several zones instead of duplicating its mapping', () => {
    const cfg = config([staticRule({ src_zones: ['untrust', 'trust'] })]);
    const result = convert(cfg);
    expect(result.commands.some((line) => line.startsWith('set security nat static'))).toBe(false);
    expect(result.warnings.filter((item) => item.element === 'nat/static/web')).toHaveLength(1);
    expect(buildSrxXml(structuredClone(cfg), mappings).xml).not.toContain('<static>');
  });

  it('skips proxy ARP when arp_reply is false', () => {
    const lines = natLines(config([staticRule({ arp_reply: false })]));
    expect(lines.some((line) => line.includes('proxy-arp'))).toBe(false);
  });

  it('skips a rule whose public and private prefix lengths differ', () => {
    const result = convert(config([staticRule({ translated_src: { type: 'static', address: '192.168.1.0/24' } })]));
    expect(result.commands.some((line) => line.startsWith('set security nat static'))).toBe(false);
    expect(result.warnings.some((item) => item.element === 'nat/static/web')).toBe(true);
  });

  it('renders the same from zone in XML', () => {
    const { xml } = buildSrxXml(structuredClone(config([staticRule()])), mappings);
    expect(xml).toMatch(/<static>\s*<rule-set>\s*<name>STATIC-NAT-untrust<\/name>\s*<from><zone>untrust<\/zone><\/from>/);
    expect(xml).toContain('<dst-addr>203.0.113.10/32</dst-addr>');
    expect(xml).toContain('<addr-prefix>192.168.1.10/32</addr-prefix>');
  });
});
