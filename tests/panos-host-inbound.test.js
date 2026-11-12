import { describe, it, expect } from 'vitest';
import { parsePanosConfig } from '../src/parsers/panos-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';

const PANOS = `<?xml version="1.0"?>
<config version="11.1.0">
  <devices><entry name="localhost.localdomain">
    <network>
      <profiles><interface-management-profile>
        <entry name="mgmt"><ping>yes</ping><ssh>yes</ssh><https>yes</https><http>no</http><response-pages>yes</response-pages></entry>
        <entry name="restricted"><ping>yes</ping><permitted-ip><entry name="10.0.0.0/8"/></permitted-ip></entry>
      </interface-management-profile></profiles>
      <interface>
        <ethernet>
          <entry name="ethernet1/1"><layer3><ip><entry name="10.1.1.1/24"/></ip><interface-management-profile>mgmt</interface-management-profile></layer3></entry>
          <entry name="ethernet1/2"><layer3><ip><entry name="203.0.113.2/29"/></ip></layer3></entry>
          <entry name="ethernet1/3"><layer3><units>
            <entry name="ethernet1/3.10"><ip><entry name="10.3.1.1/24"/></ip><interface-management-profile>restricted</interface-management-profile></entry>
          </units></layer3></entry>
          <entry name="ethernet1/4"><layer3><ip><entry name="10.4.1.1/24"/></ip><interface-management-profile>mgmt</interface-management-profile></layer3></entry>
        </ethernet>
        <loopback><units>
          <entry name="loopback.1"><ip><entry name="10.255.0.1/32"/></ip><interface-management-profile>mgmt</interface-management-profile></entry>
        </units></loopback>
      </interface>
    </network>
    <vsys><entry name="vsys1">
      <zone>
        <entry name="trust"><network><layer3><member>ethernet1/1</member><member>ethernet1/3.10</member></layer3></network></entry>
        <entry name="untrust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
        <entry name="loop"><network><layer3><member>loopback.1</member></layer3></network></entry>
      </zone>
    </entry></vsys>
  </entry></devices>
</config>`;

const hostLines = (commands) => commands.filter(line => line.includes('host-inbound-traffic'));

describe('PAN-OS interface management profiles', () => {
  const { intermediateConfig, warnings: parseWarnings } = parsePanosConfig(PANOS);
  const set = convertToSrxSetCommands(structuredClone(intermediateConfig));
  const xml = buildSrxXml(structuredClone(intermediateConfig));

  it('emits per-interface services from the profile in set output', () => {
    const lines = hostLines(set.commands);
    expect(lines).toEqual([
      expect.stringMatching(/security-zone trust interfaces \S+ host-inbound-traffic system-services ping$/),
      expect.stringMatching(/security-zone trust interfaces \S+ host-inbound-traffic system-services ssh$/),
      expect.stringMatching(/security-zone trust interfaces \S+ host-inbound-traffic system-services https$/),
      expect.stringMatching(/security-zone loop interfaces \S+ host-inbound-traffic system-services ping$/),
      expect.stringMatching(/security-zone loop interfaces \S+ host-inbound-traffic system-services ssh$/),
      expect.stringMatching(/security-zone loop interfaces \S+ host-inbound-traffic system-services https$/),
    ]);
    expect(set.warnings.filter(w => /No host-inbound-traffic data/.test(w.message))).toHaveLength(0);
  });

  it('emits the same services in XML', () => {
    expect(xml.xml.match(/<system-services>/g)).toHaveLength(6);
    expect(xml.xml).toMatch(/<system-services>\s*<name>https<\/name>/);
    expect(xml.xml).not.toContain('response-pages');
  });

  it('records an interface without a profile as known-empty, emitting nothing', () => {
    expect(intermediateConfig.zones.find(z => z.name === 'untrust').interface_host_inbound_traffic)
      .toEqual({ 'ethernet1/2': { system_services: [], protocols: [] } });
    expect(hostLines(set.commands).some(line => line.includes('security-zone untrust'))).toBe(false);
  });

  it('does not grant the services of a profile with permitted-ip (fails closed)', () => {
    const trust = intermediateConfig.zones.find(z => z.name === 'trust');
    expect(trust.interface_host_inbound_traffic['ethernet1/3.10']).toEqual({ system_services: [], protocols: [] });
    const warning = parseWarnings.find(w => w.message.includes('"restricted"') && w.message.includes('10.0.0.0/8'));
    expect(warning.message).toContain('not converted');
  });

  it('warns about unmapped flags and permitted-ip, naming the profile', () => {
    expect(parseWarnings.filter(w => w.message.includes('"mgmt"') && w.message.includes('response-pages'))).toHaveLength(1);
  });

  it('reads management profiles on loopback units', () => {
    const loop = intermediateConfig.zones.find(z => z.name === 'loop');
    expect(loop.interface_host_inbound_traffic['loopback.1'].system_services).toEqual(['ping', 'ssh', 'https']);
  });

  it('warns about an interface with a profile that is in no zone', () => {
    expect(parseWarnings.some(w => w.element === 'interfaces/management-profile' && w.message.includes('ethernet1/4'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Parser fidelity: rule-type, multi-vsys, numeric-looking names, schedules
// ---------------------------------------------------------------------------

const zoneXml = (name, iface) =>
  `<entry name="${name}"><network><layer3><member>${iface}</member></layer3></network></entry>`;
const ruleXml = (name, { ruleType = '', from = 'any', to = 'any', source = 'any', action = 'allow' } = {}) =>
  `<entry name="${name}">${ruleType ? `<rule-type>${ruleType}</rule-type>` : ''}<from><member>${from}</member></from><to><member>${to}</member></to><source><member>${source}</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><action>${action}</action></entry>`;
const vsysXml = (name, body) => `<entry name="${name}">${body}</entry>`;
const wrapPanos = vsysEntries =>
  `<config version="10.1.0"><devices><entry name="localhost.localdomain"><vsys>${vsysEntries}</vsys></entry></devices></config>`;
const threeZones = `<zone>${zoneXml('trust', 'ethernet1/1')}${zoneXml('dmz', 'ethernet1/2')}${zoneXml('untrust', 'ethernet1/3')}</zone>`;
const zonePairs = rules => rules.map(rule => `${rule.src_zones}>${rule.dst_zones}`);

describe('PAN-OS parser — rule-type', () => {
  const parseRules = rules => parsePanosConfig(wrapPanos(vsysXml('vsys1',
    `${threeZones}<rulebase><security><rules>${rules}</rules></security></rulebase>`)))
    .intermediateConfig.security_policies.filter(policy => !policy._implicit);

  it('keeps an intrazone rule inside its source zone', () => {
    const rules = parseRules(ruleXml('intra', { ruleType: 'intrazone', from: 'trust' }));
    expect(zonePairs(rules)).toEqual(['trust>trust']);
  });

  it('expands an intrazone any rule to one rule per zone, never a cross-zone pair', () => {
    const rules = parseRules(ruleXml('intra-any', { ruleType: 'intrazone' }));
    expect(zonePairs(rules)).toEqual(['trust>trust', 'dmz>dmz', 'untrust>untrust']);
  });

  it('excludes same-zone pairs from an interzone any-to-any rule', () => {
    const rules = parseRules(ruleXml('inter', { ruleType: 'interzone', action: 'drop' }));
    expect(zonePairs(rules)).toEqual(['trust>dmz,untrust', 'dmz>trust,untrust', 'untrust>trust,dmz']);
  });

  it('leaves universal rules unchanged', () => {
    const rules = parseRules(ruleXml('uni', { ruleType: 'universal', from: 'trust' }));
    expect(zonePairs(rules)).toEqual(['trust>any']);
  });
});

describe('PAN-OS parser — multi-vsys and numeric-looking names', () => {
  it('converts a two-vsys config without duplicate implicit rule names', () => {
    const xml = wrapPanos(
      vsysXml('vsys1', `<zone>${zoneXml('a', 'ethernet1/1')}</zone>`) +
      vsysXml('vsys2', `<zone>${zoneXml('b', 'ethernet1/2')}</zone>`));
    const { intermediateConfig } = parsePanosConfig(xml);
    expect(() => convertToSrxSetCommands(intermediateConfig, {})).not.toThrow();
  });

  it('keeps numeric-looking member names as written', () => {
    const xml = wrapPanos(vsysXml('vsys1',
      `${threeZones}<address><entry name="007"><ip-netmask>198.51.100.1/32</ip-netmask></entry><entry name="1e3"><ip-netmask>192.0.2.0/24</ip-netmask></entry></address>
       <rulebase><security><rules>${ruleXml('r1', { from: 'trust', to: 'untrust', source: '007' })}${ruleXml('r2', { from: 'trust', to: 'untrust', source: '1e3' })}</rules></security></rulebase>`));
    const { intermediateConfig } = parsePanosConfig(xml);
    const rules = intermediateConfig.security_policies.filter(policy => !policy._implicit);
    expect(rules.map(rule => rule.src_addresses)).toEqual([['007'], ['1e3']]);
  });
});

describe('PAN-OS parser — weekly schedules', () => {
  it('keeps a separate time window for each day', () => {
    const xml = wrapPanos(vsysXml('vsys1',
      `<schedule><entry name="work"><schedule-type><recurring><weekly>
         <monday><member>08:00-12:00</member></monday><friday><member>13:00-17:00</member></friday>
       </weekly></recurring></schedule-type></entry></schedule>`));
    const { intermediateConfig } = parsePanosConfig(xml);
    const commands = convertToSrxSetCommands(intermediateConfig, {}).commands;
    expect(commands).toContain('set schedulers scheduler work monday start-time 08:00 stop-time 12:00');
    expect(commands).toContain('set schedulers scheduler work friday start-time 13:00 stop-time 17:00');
  });
});
