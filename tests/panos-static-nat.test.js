import { describe, it, expect } from 'vitest';
import { parsePanosConfig } from '../src/parsers/panos-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';

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

  it('bi-directional no becomes a source rule with a no-port-translation pool', () => {
    const { intermediateConfig, commands } = convert(panosStatic({ bidirectional: 'no' }));
    expect(intermediateConfig.nat_rules[0]).toMatchObject({
      type: 'source',
      src_zones: ['trust'],
      dst_zones: ['untrust'],
      src_addresses: ['srv'],
      translated_src: { type: 'static', address: 'srv-pub', one_way: true },
    });
    const lines = natLines(commands);
    expect(lines.some((line) => /^set security nat static/.test(line))).toBe(false);
    expect(lines.some((line) => /source pool \S+ address 203\.0\.113\.10\/32$/.test(line))).toBe(true);
    expect(lines.some((line) => /source pool \S+ port no-translation$/.test(line))).toBe(true);
    expect(lines.some((line) => line.includes('host-address-base'))).toBe(false);
    expect(lines.some((line) => /rule \S+ match source-address 192\.168\.1\.10\/32$/.test(line))).toBe(true);
  });

  it('a missing bi-directional element defaults to one-way', () => {
    const xml = panosStatic({ bidirectional: 'no' }).replace(/<bi-directional>no<\/bi-directional>/, '');
    expect(parsePanosConfig(xml).intermediateConfig.nat_rules[0].type).toBe('source');
  });

  const subnetXml = (publicValue) => panosStatic({ bidirectional: 'no' })
    .replace('192.168.1.10/32', '192.168.1.0/29').replace('203.0.113.10/32', publicValue);

  it('a one-way subnet mapping keeps host numbers with host-address-base, in set and XML', () => {
    const { intermediateConfig, commands } = convert(subnetXml('203.0.113.8/29'));
    const lines = natLines(commands);
    expect(lines.some((line) => /source pool \S+ host-address-base 192\.168\.1\.0\/29$/.test(line))).toBe(true);
    expect(lines.some((line) => /source pool \S+ port no-translation$/.test(line))).toBe(true);
    const xml = buildSrxXml(structuredClone(intermediateConfig), {}).xml;
    expect(xml).toContain('<address><name>203.0.113.8/29</name></address>');
    expect(xml).toMatch(/<host-address-base>192\.168\.1\.0\/29<\/host-address-base>\s*<port><no-translation\/><\/port>/);
  });

  it('a one-way host mapping renders port no-translation in XML without host-address-base', () => {
    const { intermediateConfig } = convert(panosStatic({ bidirectional: 'no' }));
    const xml = buildSrxXml(structuredClone(intermediateConfig), {}).xml;
    expect(xml).toContain('<port><no-translation/></port>');
    expect(xml).not.toContain('host-address-base');
  });

  it('a one-way mapping whose sides differ in size is skipped with a warning', () => {
    const { commands, warnings } = convert(subnetXml('203.0.113.8/30'));
    expect(natLines(commands).some((line) => line.includes('pool'))).toBe(false);
    expect(warnings.some((item) => item.element === 'nat/static/srv-static' && item.message.includes('differ in size'))).toBe(true);
  });

  it('a one-way rule whose translated address does not resolve is skipped, not turned into interface NAT', () => {
    const xml = panosStatic({ bidirectional: 'no' }).replace(/<entry name="srv-pub">.*?<\/entry>/, '');
    const { commands, warnings } = convert(xml);
    expect(natLines(commands).some((line) => line.includes('source-nat'))).toBe(false);
    expect(warnings.some((item) => item.element === 'nat/static/srv-static' && item.message.includes('could not be resolved'))).toBe(true);
  });

  it('an IPv6 one-way mapping built from address objects matches ::/0 in set and XML', () => {
    const xml = panosStatic({ bidirectional: 'no' })
      .replace('192.168.1.10/32', '2001:db8:1::10/128').replace('203.0.113.10/32', '2001:db8:2::10/128');
    const { intermediateConfig, commands } = convert(xml);
    const lines = natLines(commands);
    expect(lines.some((line) => /match destination-address ::\/0$/.test(line))).toBe(true);
    expect(lines.some((line) => line.includes('0.0.0.0/0'))).toBe(false);
    const output = buildSrxXml(structuredClone(intermediateConfig), {}).xml;
    expect(output).toContain('<destination-address>::/0</destination-address>');
  });

  it('a one-way rule with a specific destination keeps it as the source rule destination match', () => {
    const { intermediateConfig, commands } = convert(panosStatic({ bidirectional: 'no', destination: 'srv-pub' }));
    expect(intermediateConfig.nat_rules[0]).toMatchObject({ type: 'source', dst_addresses: ['srv-pub'] });
    const lines = natLines(commands);
    expect(lines.some((line) => /source pool \S+ port no-translation$/.test(line))).toBe(true);
    expect(lines.some((line) => line.endsWith('match destination-address 203.0.113.10/32'))).toBe(true);
  });

  it('a one-way rule scoped to a service is skipped with a warning', () => {
    const xml = panosStatic({ bidirectional: 'no' }).replace('<source-translation>', '<service>service-https</service>\n                  <source-translation>');
    const result = parsePanosConfig(xml);
    expect(result.intermediateConfig.nat_rules).toHaveLength(0);
    expect(result.warnings.some((item) => item.element === 'nat/static/srv-static' && item.message.includes('service-https'))).toBe(true);
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
