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
