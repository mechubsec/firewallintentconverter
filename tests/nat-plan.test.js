import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';

const baseConfig = (natRule) => ({
  zones: [{ name: 'trust', interfaces: [] }, { name: 'untrust', interfaces: [] }],
  address_objects: [{ name: 'lan-net', value: '192.168.10.0/24' }],
  nat_rules: [{
    name: 'snat',
    type: 'source',
    src_zones: ['trust'],
    dst_zones: ['untrust'],
    src_addresses: ['any'],
    dst_addresses: ['any'],
    translated_src: { type: 'interface' },
    ...natRule,
  }],
});

const natLines = (config) => convertToSrxSetCommands(config, {}, null, {}).commands
  .filter((line) => line.includes('security nat') || line.includes('NAT:'));

describe('NAT plan: never widen a match', () => {
  it('skips a rule whose only source address does not resolve', () => {
    const result = convertToSrxSetCommands(baseConfig({ src_addresses: ['ghost'] }), {}, null, {});
    expect(result.commands.some((line) => line.includes('rule snat'))).toBe(false);
    expect(result.commands.some((line) => /# NAT: source rule "snat" skipped/.test(line))).toBe(true);
    expect(result.warnings.some((warning) => /skipped/.test(warning.message))).toBe(true);
  });

  it('keeps the resolved addresses when only some resolve', () => {
    const lines = natLines(baseConfig({ src_addresses: ['ghost', 'lan-net'] }));
    expect(lines).toContain('set security nat source rule-set trust-to-untrust rule snat match source-address 192.168.10.0/24');
  });

  it('does not skip a rule that matches any', () => {
    const lines = natLines(baseConfig({}));
    expect(lines).toContain('set security nat source rule-set trust-to-untrust rule snat match source-address 0.0.0.0/0');
  });

  it('treats the FortiGate "all" address of a central SNAT as any', () => {
    const { intermediateConfig } = parseFortigateConfig(`config firewall central-snat-map
    edit 1
        set srcintf "any"
        set dstintf "port1"
        set orig-addr "all"
        set dst-addr "all"
    next
end`);
    expect(intermediateConfig.nat_rules[0].src_addresses).toEqual(['any']);
    expect(intermediateConfig.nat_rules[0].dst_addresses).toEqual(['any']);
  });
  it('skips a static rule that has a destination match but no translated prefix', () => {
    const config = baseConfig({ type: 'static', src_zones: [], dst_zones: [], dst_addresses: ['203.0.113.5'], translated_src: null });
    const result = convertToSrxSetCommands(config, {}, null, {});
    expect(result.commands.some((line) => line.startsWith('set security nat static'))).toBe(false);
    expect(result.commands.some((line) => /# NAT: static rule "snat" skipped/.test(line))).toBe(true);
  });
  it('gives a bare IPv6 source-pool address a /128 prefix', () => {
    const config = baseConfig({ translated_src: { type: 'dynamic-ip-pool', addresses: ['2001:db8::1'] } });
    expect(natLines(config)).toContain('set security nat source pool pool-snat address 2001:db8::1/128');
  });

  it('resolves an address object whose name looks like IPv6', () => {
    const config = baseConfig({ src_addresses: ['dead:beef'] });
    config.address_objects.push({ name: 'dead:beef', value: '10.9.9.0/24' });
    expect(natLines(config).some(line => line.endsWith('match source-address 10.9.9.0/24'))).toBe(true);
  });
  it('keeps the wildcard when a DNAT rule lists a host and any', () => {
    const config = baseConfig({ type: 'destination', dst_zones: [], dst_addresses: ['203.0.113.5', 'any'], translated_dst: '192.168.10.10', translated_src: null });
    const lines = natLines(config);
    expect(lines.some(line => line.endsWith('match destination-address 0.0.0.0/0'))).toBe(true);
    expect(lines.some(line => line.endsWith('match destination-address 203.0.113.5'))).toBe(false);
  });

  it('matches IPv6 any for a DNAT rule with a string IPv6 target', () => {
    const config = baseConfig({ type: 'destination', dst_zones: [], dst_addresses: ['any'], translated_dst: '2001:db8::10', translated_src: null });
    expect(natLines(config).some(line => line.endsWith('match destination-address ::/0'))).toBe(true);
  });

  it('prefers a defined group over a literal-looking name', () => {
    const config = baseConfig({ src_addresses: ['2001:db8::1'] });
    config.address_groups = [{ name: '2001:db8::1', members: ['lan-net'] }];
    expect(natLines(config).some(line => /match source-address-name n-2001-db8-1$/.test(line))).toBe(true);
  });
});
