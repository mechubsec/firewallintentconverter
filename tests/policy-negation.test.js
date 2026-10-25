/**
 * Negated source/destination addresses must reach the SRX output as Junos
 * `*-address-excluded`, or the policy must be deactivated with a caveat.
 * Emitting the list as a positive match would invert a deny-except rule.
 */
import { describe, it, expect } from 'vitest';
import { parsePanosConfig } from '../src/parsers/panos-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';

function buildConfig(policyOverrides) {
  return {
    metadata: { source_vendor: 'fortigate' },
    zones: [{ name: 'lan', interfaces: [] }, { name: 'wan', interfaces: [] }],
    address_objects: [
      { name: 'bad-host', type: 'ip-netmask', value: '198.51.100.7/32' },
      { name: 'lan-net', type: 'ip-netmask', value: '192.168.10.0/24' },
    ],
    address_groups: [],
    service_objects: [],
    service_groups: [],
    applications: [],
    security_policies: [{
      name: 'deny-except',
      action: 'deny',
      src_zones: ['lan'],
      dst_zones: ['wan'],
      src_addresses: ['bad-host'],
      dst_addresses: ['lan-net'],
      negate_source: false,
      negate_destination: false,
      applications: [],
      services: ['any'],
      disabled: false,
      ...policyOverrides,
    }],
  };
}

const convert = (config, policyStructure) => (
  convertToSrxSetCommands(config, policyStructure ? { policyStructure } : {}, null, {}).commands.join('\n')
);
const buildXml = (config) => buildSrxXml(config).xml;

describe('negated addresses emit Junos excluded flags', () => {
  it('negated source', () => {
    const config = buildConfig({ negate_source: true });
    const commands = convert(config);
    expect(commands).toMatch(/match source-address bad-host\n.*match source-address-excluded/s);
    expect(commands).not.toMatch(/destination-address-excluded/);
    expect(commands).not.toMatch(/CAVEAT: policy deactivated/);

    const xml = buildXml(config);
    expect(xml).toMatch(/<source-address>bad-host<\/source-address>\s*<source-address-excluded\/>/);
    expect(xml).not.toMatch(/destination-address-excluded/);
    expect(xml).not.toMatch(/inactive=/);
  });

  it('negated destination', () => {
    const config = buildConfig({ negate_destination: true });
    const commands = convert(config);
    expect(commands).toMatch(/match destination-address lan-net\n.*match destination-address-excluded/s);
    expect(commands).not.toMatch(/source-address-excluded/);

    const xml = buildXml(config);
    expect(xml).toMatch(/<destination-address>lan-net<\/destination-address>\s*<destination-address-excluded\/>/);
    expect(xml).not.toMatch(/<source-address-excluded/);
  });

  it('both sides, in zone-pair structure too', () => {
    const config = buildConfig({ negate_source: true, negate_destination: true });
    for (const structure of [undefined, 'zone-pair']) {
      const commands = convert(config, structure);
      expect(commands).toMatch(/source-address-excluded/);
      expect(commands).toMatch(/destination-address-excluded/);
      expect(commands).not.toMatch(/CAVEAT: policy deactivated/);
    }
    const xml = buildXml(config);
    expect(xml).toMatch(/<source-address-excluded\/>/);
    expect(xml).toMatch(/<destination-address-excluded\/>/);
  });

  it('non-negated policy is unchanged', () => {
    const config = buildConfig({});
    expect(convert(config)).not.toMatch(/-excluded/);
    expect(buildXml(config)).not.toMatch(/-excluded/);
  });
});

describe('negation that cannot be represented fails closed', () => {
  it.each([
    ['any', ['any']],
    ['empty list', []],
  ])('negated source with %s is deactivated with a caveat', (_label, srcAddresses) => {
    const config = buildConfig({ negate_source: true, src_addresses: srcAddresses });
    const commands = convert(config);
    expect(commands).toMatch(/# CAVEAT: policy deactivated — negated address match not representable/);
    expect(commands).toMatch(/deactivate security policies global policy deny-except/);

    const xml = buildXml(config);
    expect(xml).toMatch(/<!-- CAVEAT: policy deactivated — negated address match not representable/);
    expect(xml).toMatch(/<policy inactive="inactive">\s*<name>deny-except<\/name>/);
  });

  it('negated destination containing any is deactivated', () => {
    const config = buildConfig({ negate_destination: true, dst_addresses: ['lan-net', 'any'] });
    expect(convert(config)).toMatch(/deactivate security policies global policy deny-except/);
    expect(buildXml(config)).toMatch(/<policy inactive="inactive">/);
  });

  it('negated list with a dropped SecIntel block-list address is deactivated', () => {
    const config = buildConfig({ negate_source: true, _secIntelAddresses: ['bad-host'] });
    expect(convert(config)).toMatch(/deactivate security policies global policy deny-except/);
    expect(buildXml(config)).toMatch(/<policy inactive="inactive">/);
  });
});

describe('PAN-OS negate-source end to end', () => {
  const panosXml = `<?xml version="1.0"?>
<config>
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1">
          <address>
            <entry name="bad-host"><ip-netmask>198.51.100.7/32</ip-netmask></entry>
          </address>
          <rulebase>
            <security>
              <rules>
                <entry name="deny-all-but-bad">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>bad-host</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <negate-source>yes</negate-source>
                  <action>deny</action>
                </entry>
              </rules>
            </security>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>`;

  it('carries negation into set and XML output', () => {
    const { intermediateConfig } = parsePanosConfig(panosXml);
    expect(intermediateConfig.security_policies[0].negate_source).toBe(true);

    const commands = convert(intermediateConfig);
    expect(commands).toMatch(/match source-address bad-host\n.*match source-address-excluded/s);
    expect(commands).not.toMatch(/destination-address-excluded/);
    expect(buildXml(intermediateConfig)).toMatch(/<source-address>bad-host<\/source-address>\s*<source-address-excluded\/>/);
  });
});
