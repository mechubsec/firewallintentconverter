import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';
import { ipv4RangeToPrefixes } from '../src/converters/nat-plan.js';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';

const FORTIGATE_RANGE_SNAT = `
config firewall address
    edit "lan-range"
        set type iprange
        set start-ip 192.168.10.50
        set end-ip 192.168.10.60
    next
end
config firewall central-snat-map
    edit 1
        set srcintf "port2"
        set dstintf "port1"
        set orig-addr "lan-range"
        set dst-addr "all"
    next
end
`;

const PREFIXES = ['192.168.10.50/31', '192.168.10.52/30', '192.168.10.56/30', '192.168.10.60/32'];

describe('NAT range match address', () => {
  it('set output expands a range into covering prefixes', () => {
    const { intermediateConfig } = parseFortigateConfig(FORTIGATE_RANGE_SNAT);
    const { commands } = convertToSrxSetCommands(intermediateConfig, {}, null, {});
    const matches = commands.filter(line => line.includes('match source-address'));
    for (const prefix of PREFIXES) {
      expect(matches.some(line => line.endsWith(`match source-address ${prefix}`))).toBe(true);
    }
    expect(commands.join('\n')).not.toMatch(/source-address 192\.168\.10\.50-/);
  });

  it('XML output has the same prefixes', () => {
    const { intermediateConfig } = parseFortigateConfig(FORTIGATE_RANGE_SNAT);
    const { xml } = buildSrxXml(intermediateConfig, {});
    for (const prefix of PREFIXES) expect(xml).toContain(`<source-address>${prefix}</source-address>`);
    expect(xml).not.toContain('192.168.10.50-192.168.10.60');
  });

  it('expander handles edge cases', () => {
    expect(ipv4RangeToPrefixes('10.0.0.5', '10.0.0.5')).toEqual(['10.0.0.5/32']);
    expect(ipv4RangeToPrefixes('10.0.1.0', '10.0.1.255')).toEqual(['10.0.1.0/24']);
    expect(ipv4RangeToPrefixes('10.0.0.9', '10.0.0.1')).toBeNull();
    expect(ipv4RangeToPrefixes('10.0.0.1', '10.0.0.300')).toBeNull();
    expect(ipv4RangeToPrefixes('0.0.0.0', '255.255.255.255')).toEqual(['0.0.0.0/0']);
    expect(ipv4RangeToPrefixes('128.0.0.0', '255.255.255.255')).toEqual(['128.0.0.0/1']);
  });

  const rangeConfig = (natRule, rangeValue = '203.0.113.10-203.0.113.13') => ({
    zones: [{ name: 'trust', interfaces: [] }, { name: 'untrust', interfaces: [] }],
    address_objects: [{ name: 'pub-range', type: 'range', value: rangeValue }],
    nat_rules: [natRule],
  });
  const dnatRule = {
    name: 'dnat', type: 'destination', src_zones: ['untrust'], dst_zones: ['trust'],
    src_addresses: ['any'], dst_addresses: ['pub-range'], translated_dst: '192.168.1.5',
  };

  it('destination NAT matching a multi-prefix range warns that it keeps one', () => {
    const { commands, warnings } = convertToSrxSetCommands(rangeConfig(dnatRule), {}, null, {});
    expect(commands.join('\n')).toContain('destination-address 203.0.113.10/31');
    expect(warnings.some(item => item.element === 'nat/destination/dnat' && /dropped 203\.0\.113\.12\/31/.test(item.message))).toBe(true);
  });

  it('IPv6 and reversed ranges are unresolved: warned and the rule skipped', () => {
    for (const value of ['2001:db8::1-2001:db8::5', '10.0.0.9-10.0.0.1']) {
      const { commands, warnings } = convertToSrxSetCommands(rangeConfig(dnatRule, value), {}, null, {});
      expect(commands.join('\n')).not.toContain('destination-address');
      expect(warnings.some(item => item.element === 'nat/destination/dnat')).toBe(true);
    }
  });
});

describe('NAT match address limit', () => {
  it('skips a source NAT rule whose range needs more than eight prefixes', () => {
    const config = `config firewall address
    edit "wide-range"
        set type iprange
        set start-ip 10.0.0.1
        set end-ip 10.0.0.254
    next
end
config firewall central-snat-map
    edit 1
        set srcintf "port2"
        set dstintf "port1"
        set orig-addr "wide-range"
        set dst-addr "all"
    next
end
`;
    const { intermediateConfig } = parseFortigateConfig(config);
    const result = convertToSrxSetCommands(structuredClone(intermediateConfig), {}, null, {});
    expect(result.commands.some(line => line.includes('rule Central-SNAT-1 match'))).toBe(false);
    expect(result.warnings.some(item => item.severity === 'warning' && item.message.includes('need 14 prefixes'))).toBe(true);
    const { xml } = buildSrxXml(structuredClone(intermediateConfig), {});
    expect(xml).not.toContain('10.0.0.1/32');
  });
});
