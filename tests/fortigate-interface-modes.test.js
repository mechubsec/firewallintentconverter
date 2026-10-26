import { describe, it, expect } from 'vitest';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';
import { convertToSrxSetCommands, convertMergedToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildDefaultMappings, cleanMappings } from '../public/components/InterfaceMapper.jsx';
import { mapInterfaceToSrx } from '../public/utils/srx-view-transforms.js';
import { buildSrxXml, buildMergedSrxXml } from '../src/converters/srx-xml-builder.js';

const FORTIGATE = `config system interface
    edit "port1"
        set ip 203.0.113.2 255.255.255.248
        set allowaccess https
    next
    edit "port2"
        set mode dhcp
    next
    edit "port3"
        config ipv6
            set ip6-address 2001:db8:3::1/64
        end
    next
    edit "port4"
        set mode pppoe
    next
    edit "port5"
        config ipv6
            set ip6-address ::/0
        end
    next
    edit "port6"
    next
    edit "port7"
    next
    edit "agg1"
        set type aggregate
        set member "port6" "port7"
        set ip 10.9.9.1 255.255.255.0
        set allowaccess ping
    next
end
config firewall policy
    edit 1
        set srcintf "port2" "port3" "port4" "agg1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
    edit 2
        set srcintf "port1"
        set dstintf "agg1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set nat enable
    next
end
`;

// The XML builder does not auto-map FortiGate names, so give it the same mapping the set output derives.
const XML_MAPPINGS = { port1: 'ge-0/0/0', port2: 'ge-0/0/1', port3: 'ge-0/0/2' };

describe('FortiGate interface modes, IPv6 and aggregates', () => {
  const { intermediateConfig, warnings } = parseFortigateConfig(FORTIGATE);
  const set = convertToSrxSetCommands(structuredClone(intermediateConfig)).commands.join('\n');
  const xml = buildSrxXml(structuredClone(intermediateConfig), XML_MAPPINGS).xml;

  it('keeps static IPv4 unchanged (control)', () => {
    expect(set).toContain('set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.2/29');
    expect(xml).toMatch(/<name>ge-0\/0\/0<\/name>\s*<unit>\s*<name>0<\/name>\s*<family>\s*<inet>\s*<address><name>203\.0\.113\.2\/29<\/name>/);
  });

  it('emits family inet dhcp and dhcp host-inbound for mode dhcp', () => {
    expect(set).toContain('set interfaces ge-0/0/1 unit 0 family inet dhcp');
    expect(set).not.toMatch(/set interfaces ge-0\/0\/1 unit 0 family inet$/m);
    expect(set).toContain('set security zones security-zone port2 interfaces ge-0/0/1.0 host-inbound-traffic system-services dhcp');
    expect(xml).toMatch(/<name>ge-0\/0\/1<\/name>\s*<unit>\s*<name>0<\/name>\s*<family>\s*<inet>\s*<dhcp\/>/);
    expect(xml).toMatch(/<name>ge-0\/0\/1\.0<\/name>\s*<host-inbound-traffic>\s*<system-services>\s*<name>dhcp<\/name>/);
  });

  it('emits family inet6 address and no bare family inet for an IPv6-only port', () => {
    expect(set).toContain('set interfaces ge-0/0/2 unit 0 family inet6 address 2001:db8:3::1/64');
    expect(set).not.toMatch(/set interfaces ge-0\/0\/2 unit 0 family inet$/m);
    expect(xml).toMatch(/<name>ge-0\/0\/2<\/name>\s*<unit>\s*<name>0<\/name>\s*<family>\s*<inet6>\s*<address><name>2001:db8:3::1\/64<\/name><\/address>\s*<\/inet6>\s*<\/family>/);
  });

  it('ignores a ::/0 IPv6 address', () => {
    expect(intermediateConfig.interfaces.find(iface => iface.name === 'port5').ipv6).toBe('');
  });

  it('warns that PPPoE needs a manual pp0 interface and builds no pp0', () => {
    expect(warnings.some(w => w.message.includes('port4') && /pppoe/i.test(w.message) && /pp0/.test(w.message + w.recommendation))).toBe(true);
    expect(set).not.toContain('pp0');
  });

  it('puts the aggregate zone, address and host-inbound on ae0.0', () => {
    expect(set).toContain('set security zones security-zone agg1 interfaces ae0.0');
    expect(set).toContain('set security zones security-zone agg1 interfaces ae0.0 host-inbound-traffic system-services ping');
    expect(set).toContain('set interfaces ae0 unit 0 family inet address 10.9.9.1/24');
    expect(set).toContain('set chassis aggregated-devices ethernet device-count 1');
    expect(set).not.toMatch(/interfaces agg1/);
    expect(xml).toMatch(/<name>ae0<\/name>\s*<unit>\s*<name>0<\/name>\s*<family>\s*<inet>\s*<address><name>10\.9\.9\.1\/24<\/name>/);
    expect(xml).toMatch(/<name>ae0\.0<\/name>\s*<host-inbound-traffic>/);
    expect(xml).not.toMatch(/<name>agg1<\/name>\s*<host-inbound/);
  });

  it('emits the LAG chassis device-count, ae and member bindings in XML like the set output', () => {
    const lagXml = buildSrxXml(structuredClone(intermediateConfig), { ...XML_MAPPINGS, port6: 'ge-0/0/5', port7: 'ge-0/0/6' }).xml;
    expect(lagXml).toContain('<chassis><aggregated-devices><ethernet><device-count>1</device-count></ethernet></aggregated-devices></chassis>');
    for (const member of ['ge-0/0/5', 'ge-0/0/6']) {
      expect(set).toContain(`set interfaces ${member} ether-options 802.3ad ae0`);
      expect(lagXml).toMatch(new RegExp(`<name>${member}</name>\\s*<ether-options><ieee-802\\.3ad><bundle>ae0</bundle></ieee-802\\.3ad></ether-options>`));
    }
    expect(lagXml.split('\n').filter(line => line.trim() === '<interfaces>' && line.startsWith('  <')).length).toBe(1);
  });

  it('uses one effective aggregate name when the user overrides it (set and XML)', () => {
    const mappings = { agg1: 'ae5', port6: 'ge-0/0/5', port7: 'ge-0/0/6' };
    const custom = convertToSrxSetCommands(structuredClone(intermediateConfig), mappings).commands.join('\n');
    expect(custom).toContain('set security zones security-zone agg1 interfaces ae5.0');
    expect(custom).toContain('set interfaces ae5 unit 0 family inet address 10.9.9.1/24');
    expect(custom).toContain('set interfaces ge-0/0/5 ether-options 802.3ad ae5');
    expect(custom).toContain('set chassis aggregated-devices ethernet device-count 6');
    expect(custom).not.toMatch(/\bae0\b/);
    const customXml = buildSrxXml(structuredClone(intermediateConfig), mappings).xml;
    expect(customXml).toContain('<device-count>6</device-count>');
    expect(customXml).toContain('<bundle>ae5</bundle>');
    expect(customXml).not.toMatch(/\bae0\b/);
  });

  it('keeps the generated aeN and warns when the override is not an ae name', () => {
    const result = convertToSrxSetCommands(structuredClone(intermediateConfig), { agg1: 'ge-0/0/9' });
    expect(result.commands.join('\n')).toContain('set security zones security-zone agg1 interfaces ae0.0');
    expect(result.warnings.some(w => w.message.includes('agg1') && w.message.includes('not an aeN'))).toBe(true);
  });

  it('keeps chassis aggregated-devices at the root under a logical-system', () => {
    const context = { type: 'logical-system', name: 'ls1' };
    const lsSet = convertToSrxSetCommands(structuredClone(intermediateConfig), {}, context).commands;
    expect(lsSet).toContain('set chassis aggregated-devices ethernet device-count 1');
    expect(lsSet.some(line => line.startsWith('set logical-systems ls1 chassis'))).toBe(false);
    const lsXml = buildSrxXml(structuredClone(intermediateConfig), {}, context).xml;
    expect(lsXml.indexOf('<chassis>')).toBeGreaterThan(-1);
    expect(lsXml.indexOf('<chassis>')).toBeLessThan(lsXml.indexOf('<logical-systems>'));
  });

  it('emits chassis aggregated-devices once for merged output', () => {
    const slots = ['lsa', 'lsb'].map(lsName => ({ lsName, intermediateConfig: structuredClone(intermediateConfig), interfaceMappings: {} }));
    const mergedSet = convertMergedToSrxSetCommands(slots, []).commands;
    expect(mergedSet.filter(line => line.includes('aggregated-devices'))).toEqual(['set chassis aggregated-devices ethernet device-count 1']);
    const mergedXml = buildMergedSrxXml(slots, []).xml;
    expect(mergedXml.match(/<chassis>/g)).toHaveLength(1);
  });

  it('binds PAN-OS aggregate members through their source-name mapping (set and XML)', () => {
    const panos = {
      lag_interfaces: [{ name: 'ae1', source_name: 'ae1', members: ['ge-0/0/0'], source_members: ['ethernet1/1'], lacp_mode: 'active' }],
      zones: [], interfaces: [],
    };
    const mappings = { 'ethernet1/1': 'ge-0/0/7' };
    expect(convertToSrxSetCommands(structuredClone(panos), mappings).commands)
      .toContain('set interfaces ge-0/0/7 ether-options 802.3ad ae1');
    expect(buildSrxXml(structuredClone(panos), mappings).xml)
      .toMatch(/<name>ge-0\/0\/7<\/name>\s*<ether-options><ieee-802\.3ad><bundle>ae1<\/bundle>/);
  });

  it('keeps the generated name and warns when an override duplicates another aggregate', () => {
    const lags = [
      { name: 'ae0', source_name: 'aggA', members: [], source_members: [] },
      { name: 'ae1', source_name: 'aggB', members: [], source_members: [] },
    ];
    const result = convertToSrxSetCommands({ lag_interfaces: lags, zones: [], interfaces: [] }, { aggA: 'ae1' });
    expect(result.warnings.some(w => w.message.includes('aggA') && w.message.includes('already used'))).toBe(true);
    expect(result.commands).toContain('set chassis aggregated-devices ethernet device-count 2');
  });

  it('maps LAG parents and units to their generated aeN in the default mappings', () => {
    const target = { ports: [{ name: 'ge-0/0/0' }, { name: 'ge-0/0/1' }] };
    const mappings = buildDefaultMappings({
      zones: [{ name: 'Z', interfaces: ['ae1', 'ae1.100', 'agg1', 'ethernet1/2'] }],
      lag_interfaces: [{ name: 'ae1', source_name: 'ae1' }, { name: 'ae0', source_name: 'agg1' }],
    }, target);
    expect(mappings['ae1']).toBe('ae1');
    expect(mappings['ae1.100']).toBe('ae1.100');
    expect(mappings['agg1']).toBe('ae0');
    expect(mappings['ethernet1/2']).toBe('ge-0/0/0');
    expect(mapInterfaceToSrx('agg1', mappings)).toContain('ae0');
  });

  it('gives each aggregate a distinct ae when both are overridden to the same name', () => {
    const lags = [
      { name: 'ae0', source_name: 'aggA', members: ['m1'], source_members: ['m1'] },
      { name: 'ae1', source_name: 'aggB', members: ['m2'], source_members: ['m2'] },
    ];
    const mappings = { aggA: 'ae1', aggB: 'ae1', m1: 'ge-0/0/1', m2: 'ge-0/0/2' };
    const result = convertToSrxSetCommands({ lag_interfaces: lags, zones: [], interfaces: [] }, mappings);
    expect(result.commands).toContain('set interfaces ge-0/0/1 ether-options 802.3ad ae1');
    expect(result.commands).toContain('set interfaces ge-0/0/2 ether-options 802.3ad ae0');
    expect(result.commands).toContain('set chassis aggregated-devices ethernet device-count 2');
    expect(result.warnings.some(w => w.message.includes('aggB') && w.message.includes('already used'))).toBe(true);
  });

  it('bundles unmapped FortiGate aggregate members on identical ge ports in set and XML', () => {
    const bareXml = buildSrxXml(structuredClone(intermediateConfig)).xml;
    for (const port of ['ge-0/0/5', 'ge-0/0/6']) {
      expect(set).toContain(`set interfaces ${port} ether-options 802.3ad ae0`);
      expect(bareXml).toMatch(new RegExp(`<name>${port}</name>\\s*<ether-options><ieee-802\\.3ad><bundle>ae0</bundle>`));
    }
  });

  it('maps LAG members to free ports in the default mappings', () => {
    const mappings = buildDefaultMappings({
      zones: [{ name: 'Z', interfaces: ['ethernet1/2'] }],
      lag_interfaces: [{ name: 'ae1', source_name: 'ae1', source_members: ['ethernet1/5', 'ethernet1/6'] }],
    }, { ports: [{ name: 'ge-0/0/0' }, { name: 'ge-0/0/1' }, { name: 'ge-0/0/2' }] });
    expect([mappings['ethernet1/2'], mappings['ethernet1/5'], mappings['ethernet1/6']]).toEqual(['ge-0/0/0', 'ge-0/0/1', 'ge-0/0/2']);
  });

  it('keeps aeN mappings and drops stale ports when cleaning saved mappings', () => {
    const cleaned = cleanMappings(
      { agg1: 'ae5', 'ae1.100': 'ae1.100', stale: 'ge-9/9/9', ok: 'ge-0/0/0', 'tunnel.1': 'st0.1' },
      { ports: [{ name: 'ge-0/0/0' }] },
    );
    expect(cleaned).toEqual({ agg1: 'ae5', 'ae1.100': 'ae1.100', ok: 'ge-0/0/0', 'tunnel.1': 'st0.1' });
  });
});
