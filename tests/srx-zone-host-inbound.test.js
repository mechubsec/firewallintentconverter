import { describe, it, expect } from 'vitest';
import { parseSrxConfig } from '../src/parsers/srx-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';

const SRX = `set security zones security-zone trust interfaces ge-0/0/1.0 host-inbound-traffic system-services ssh
set security zones security-zone trust host-inbound-traffic system-services all
set security zones security-zone trust host-inbound-traffic system-services telnet except
set security zones security-zone trust host-inbound-traffic protocols ospf
set security zones security-zone untrust interfaces ge-0/0/0.0
`;

describe('SRX zone host-inbound-traffic', () => {
  const { intermediateConfig } = parseSrxConfig(SRX);
  const trust = intermediateConfig.zones.find(zone => zone.name === 'trust');

  it('parses zone-level and interface-level access', () => {
    expect(trust.host_inbound_traffic).toMatchObject({
      system_services: ['all'], system_services_except: ['telnet'], protocols: ['ospf'],
    });
    expect(trust.interface_host_inbound_traffic['ge-0/0/1.0'].system_services).toEqual(['ssh']);
  });

  it('round-trips into set output', () => {
    const { commands, warnings } = convertToSrxSetCommands(structuredClone(intermediateConfig));
    expect(commands).toContain('set security zones security-zone trust host-inbound-traffic system-services all');
    expect(commands).toContain('set security zones security-zone trust host-inbound-traffic system-services telnet except');
    expect(commands).toContain('set security zones security-zone trust host-inbound-traffic protocols ospf');
    expect(commands).toContain('set security zones security-zone trust interfaces ge-0/0/1.0 host-inbound-traffic system-services ssh');
    expect(warnings.some(w => /No host-inbound-traffic data/.test(w.message))).toBe(false);
  });

  it('round-trips into XML', () => {
    const { xml } = buildSrxXml(structuredClone(intermediateConfig));
    expect(xml).toMatch(/<system-services>\s*<name>telnet<\/name>\s*<except\/>\s*<\/system-services>/);
    expect(xml).toMatch(/<protocols>\s*<name>ospf<\/name>\s*<\/protocols>/);
    expect(xml).toMatch(/<name>ge-0\/0\/1\.0<\/name>\s*<host-inbound-traffic>\s*<system-services>\s*<name>ssh<\/name>/);
  });

  it('skips deactivated host-inbound statements', () => {
    const { intermediateConfig: config } = parseSrxConfig(`set security zones security-zone dmz interfaces ge-0/0/2.0 host-inbound-traffic system-services ssh
set security zones security-zone dmz host-inbound-traffic system-services ping
set security zones security-zone dmz host-inbound-traffic system-services telnet
deactivate security zones security-zone dmz host-inbound-traffic system-services telnet
deactivate security zones security-zone dmz interfaces ge-0/0/2.0 host-inbound-traffic
set security zones security-zone lab host-inbound-traffic system-services ssh
deactivate security zones security-zone lab host-inbound-traffic
`);
    const dmz = config.zones.find(zone => zone.name === 'dmz');
    const lab = config.zones.find(zone => zone.name === 'lab');
    expect(dmz.host_inbound_traffic.system_services).toEqual(['ping']);
    expect(dmz.interface_host_inbound_traffic).toEqual({});
    expect(lab.host_inbound_traffic.system_services).toEqual([]);
    const { commands } = convertToSrxSetCommands(structuredClone(config));
    expect(commands.filter(line => /telnet|ssh/.test(line))).toEqual([]);
  });

  it('expands bracket lists in set and hierarchical input', () => {
    const fromSet = parseSrxConfig(`set security zones security-zone trust host-inbound-traffic system-services [ ping ssh ]
set security zones security-zone trust interfaces ge-0/0/1.0
`).intermediateConfig.zones[0];
    expect(fromSet.host_inbound_traffic.system_services).toEqual(['ping', 'ssh']);
    const fromHierarchy = parseSrxConfig(`security {
    zones {
        security-zone trust {
            host-inbound-traffic {
                protocols [ bgp ospf ];
            }
            interfaces {
                ge-0/0/1.0;
            }
        }
    }
}`).intermediateConfig.zones[0];
    expect(fromHierarchy.host_inbound_traffic.protocols).toEqual(['bgp', 'ospf']);
  });

  it('treats a deactivated except as a plain entry', () => {
    const zone = parseSrxConfig(`set security zones security-zone trust host-inbound-traffic protocols all
set security zones security-zone trust host-inbound-traffic protocols bgp except
deactivate security zones security-zone trust host-inbound-traffic protocols bgp except
`).intermediateConfig.zones[0];
    expect(zone.host_inbound_traffic.protocols_except).toEqual([]);
  });

  it('ignores host-inbound under a deactivated zone or interface', () => {
    const { zones } = parseSrxConfig(`set security zones security-zone old host-inbound-traffic system-services ssh
set security zones security-zone old interfaces ge-0/0/3.0 host-inbound-traffic system-services telnet
deactivate security zones security-zone old
set security zones security-zone dmz interfaces ge-0/0/4.0 host-inbound-traffic system-services ssh
deactivate security zones security-zone dmz interfaces ge-0/0/4.0
`).intermediateConfig;
    const old = zones.find(zone => zone.name === 'old');
    const dmz = zones.find(zone => zone.name === 'dmz');
    expect(old.host_inbound_traffic.system_services).toEqual([]);
    expect(old.interface_host_inbound_traffic).toEqual({});
    expect(dmz.interface_host_inbound_traffic).toEqual({});
  });
});
