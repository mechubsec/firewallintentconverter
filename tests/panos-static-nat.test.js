import { describe, it, expect } from 'vitest';
import { parsePanosConfig } from '../src/parsers/panos-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

const panosStatic = ({ bidirectional, destination = 'any' }) => `<?xml version="1.0"?>
<config>
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="trust"><network><layer3/></network></entry>
            <entry name="untrust"><network><layer3/></network></entry>
          </zone>
          <address>
            <entry name="srv"><ip-netmask>192.168.1.10/32</ip-netmask></entry>
            <entry name="srv-pub"><ip-netmask>203.0.113.10/32</ip-netmask></entry>
          </address>
          <rulebase>
            <nat>
              <rules>
                <entry name="srv-static">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>srv</member></source>
                  <destination><member>${destination}</member></destination>
                  <source-translation>
                    <static-ip>
                      <translated-address>srv-pub</translated-address>
                      <bi-directional>${bidirectional}</bi-directional>
                    </static-ip>
                  </source-translation>
                </entry>
              </rules>
            </nat>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>`;

const convert = (xml) => {
  const { intermediateConfig } = parsePanosConfig(xml);
  return { intermediateConfig, ...convertToSrxSetCommands(structuredClone(intermediateConfig), {}, null, {}) };
};
const natLines = (commands) => commands.filter((line) => line.startsWith('set security nat'));

describe('PAN-OS static-ip NAT', () => {
  it('bi-directional yes becomes Junos static NAT from the outside zone', () => {
    const { intermediateConfig, commands } = convert(panosStatic({ bidirectional: 'yes' }));
    expect(intermediateConfig.nat_rules[0]).toMatchObject({
      type: 'static',
      src_zones: ['untrust'],
      dst_zones: ['trust'],
      src_addresses: ['any'],
      dst_addresses: ['srv-pub'],
      translated_src: { type: 'static', address: 'srv' },
    });
    const lines = natLines(commands);
    expect(lines.some((line) => /static rule-set \S+ from zone untrust$/.test(line))).toBe(true);
    expect(lines.some((line) => /static rule-set \S+ rule \S+ match destination-address 203\.0\.113\.10\/32$/.test(line))).toBe(true);
    expect(lines.some((line) => /then static-nat prefix 192\.168\.1\.10\/32$/.test(line))).toBe(true);
  });

  it('bi-directional no is one-way, so it is dropped with a warning rather than opened inbound', () => {
    const result = parsePanosConfig(panosStatic({ bidirectional: 'no' }));
    expect(result.intermediateConfig.nat_rules).toHaveLength(0);
    expect(result.warnings.some((item) => item.element === 'nat/static/srv-static' && item.message.includes('one-way'))).toBe(true);
  });

  it('a missing bi-directional element defaults to one-way', () => {
    const xml = panosStatic({ bidirectional: 'no' }).replace(/<bi-directional>no<\/bi-directional>/, '');
    expect(parsePanosConfig(xml).intermediateConfig.nat_rules).toHaveLength(0);
  });

  it.each([['service-https'], ['443']])('a bi-directional rule scoped to service %s is dropped rather than widened to every port', (service) => {
    const xml = panosStatic({ bidirectional: 'yes' }).replace('<source-translation>', `<service>${service}</service>\n                  <source-translation>`);
    const result = parsePanosConfig(xml);
    expect(result.intermediateConfig.nat_rules).toHaveLength(0);
    expect(result.warnings.some((item) => item.element === 'nat/static/srv-static' && item.message.includes(service))).toBe(true);
  });

  it('a bi-directional rule with a destination filter is dropped with a warning', () => {
    const result = parsePanosConfig(panosStatic({ bidirectional: 'yes', destination: 'srv-pub' }));
    expect(result.intermediateConfig.nat_rules).toHaveLength(0);
    expect(result.warnings.some((item) => item.element === 'nat/static/srv-static')).toBe(true);
  });
});
