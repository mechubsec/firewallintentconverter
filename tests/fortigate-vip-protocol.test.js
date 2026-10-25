import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';

const vip = (name, protocol, extip) => `    edit "${name}"
        set extip ${extip}
        set extintf "port1"
        set portforward enable
        set protocol ${protocol}
        set extport 2905
        set mappedport 2905
        set mappedip "192.168.10.25"
    next
`;

const config = `config firewall vip
${vip('vip-sctp', 'sctp', '203.0.113.5')}${vip('vip-icmp', 'icmp', '203.0.113.6')}${vip('vip-tcp', 'tcp', '203.0.113.7')}end
`;

describe('FortiGate VIP port-forward protocol', () => {
  it('skips sctp/icmp VIPs with a warning and still converts tcp', () => {
    const { intermediateConfig, warnings } = parseFortigateConfig(config);
    expect(intermediateConfig.nat_rules.map(rule => rule.name)).toEqual(['vip-tcp']);
    for (const name of ['vip-sctp', 'vip-icmp']) {
      expect(warnings.some(item => item.severity === 'warning' && item.message.includes(`"${name}"`))).toBe(true);
    }

    const mappings = { port1: 'ge-0/0/0' };
    const set = convertToSrxSetCommands(structuredClone(intermediateConfig), mappings, null, {});
    const xml = buildSrxXml(structuredClone(intermediateConfig), mappings);
    const setText = set.commands.join('\n');
    expect(setText).toContain('203.0.113.7');
    expect(setText).not.toContain('203.0.113.5');
    expect(setText).not.toContain('203.0.113.6');
    expect(xml.xml).toContain('203.0.113.7');
    expect(xml.xml).not.toContain('203.0.113.5');
    expect(xml.xml).not.toContain('203.0.113.6');
  });
});
