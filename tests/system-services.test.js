import { describe, it, expect } from 'vitest';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';
import { convertToSrxSetCommands, convertMergedToSrxSetCommands } from '../src/converters/srx-converter.js';
import { autoSplitRoutingContexts } from '../public/utils/auto-split.js';
import { buildSrxXml, buildMergedSrxXml } from '../src/converters/srx-xml-builder.js';

const forti = (allowaccess) => `config system interface
    edit "port1"
        set ip 203.0.113.2 255.255.255.248
        set allowaccess ${allowaccess}
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
`;
const convert = (config, context = null) => ({
  set: convertToSrxSetCommands(structuredClone(config), {}, context),
  xml: buildSrxXml(structuredClone(config), {}, context),
});
const serviceLines = commands => commands.filter(line => line.includes('system services'));
const zoneWith = (name, services) => ({
  name, interfaces: [], host_inbound_traffic: { system_services: services, protocols: [] },
});

describe('system services for converted management access', () => {
  it('enables the daemons for FortiGate allowaccess ssh/https/http/telnet in set and XML', () => {
    const { intermediateConfig } = parseFortigateConfig(forti('ping ssh https http telnet'));
    const { set, xml } = convert(intermediateConfig);
    expect(serviceLines(set.commands)).toEqual([
      'set system services ssh',
      'set system services web-management https system-generated-certificate',
      'set system services web-management http',
    ]);
    // telnet is clear-text and forbidden by output validation: warned, never emitted
    expect(set.warnings.filter(w => /telnet/.test(w.message))).toHaveLength(1);
    expect(xml.xml).not.toContain('<telnet/>');
    expect(xml.xml).toContain('<system>');
    expect(xml.xml).toMatch(/<services>\s*<ssh\/>\s*<web-management>\s*<https><system-generated-certificate\/><\/https>\s*<http\/>\s*<\/web-management>\s*<\/services>/);
  });

  it('emits no system services for ping-only access', () => {
    const { intermediateConfig } = parseFortigateConfig(forti('ping'));
    const { set, xml } = convert(intermediateConfig);
    expect(serviceLines(set.commands)).toEqual([]);
    expect(xml.xml).not.toContain('<services>');
  });

  it('keeps greenfield management_services and ignores zones then', () => {
    const config = {
      system_config: { hostname: 'fw1', management_services: { ssh: true, https: true, netconf: true } },
      zones: [zoneWith('trust', ['http'])],
    };
    const { set, xml } = convert(config);
    expect(serviceLines(set.commands)).toEqual([
      'set system services ssh',
      'set system services web-management https system-generated-certificate',
      'set system services netconf ssh',
    ]);
    expect(xml.xml).toContain('<netconf><ssh/></netconf>');
    expect(xml.xml).not.toContain('<http/>');
  });

  it('maps netconf, warns once for snmp and for all, and does not expand all', () => {
    const config = { zones: [zoneWith('a', ['netconf', 'snmp', 'all']), zoneWith('b', ['snmp'])] };
    const { set } = convert(config);
    expect(serviceLines(set.commands)).toEqual(['set system services netconf ssh']);
    expect(set.warnings.filter(w => /SNMP/.test(w.message))).toHaveLength(1);
    expect(set.warnings.filter(w => /system-services all/.test(w.message))).toHaveLength(1);
  });

  it('keeps system services at root for a logical-system target', () => {
    const { intermediateConfig } = parseFortigateConfig(forti('ssh https'));
    const { set, xml } = convert(intermediateConfig, { type: 'logical-system', name: 'LS1' });
    expect(serviceLines(set.commands)).toEqual([
      'set system services ssh',
      'set system services web-management https system-generated-certificate',
    ]);
    const rootSystem = xml.xml.indexOf('<system>');
    expect(rootSystem).toBeGreaterThan(-1);
    expect(rootSystem).toBeLessThan(xml.xml.indexOf('<logical-systems>'));
  });

  it('emits the union once for merged output', () => {
    const slot = (lsName, services) => ({ lsName, intermediateConfig: { zones: [zoneWith('z', services)] }, interfaceMappings: {} });
    const slots = [slot('LS1', ['ssh']), slot('LS2', ['ssh', 'https'])];
    const set = convertMergedToSrxSetCommands(structuredClone(slots), []);
    expect(serviceLines(set.commands)).toEqual([
      'set system services ssh',
      'set system services web-management https system-generated-certificate',
    ]);
    const { xml } = buildMergedSrxXml(structuredClone(slots), []);
    expect(xml.match(/<services>/g)).toHaveLength(1);
  });

  it('keeps dhcp-local-server inside the logical-system while ssh stays at root', () => {
    const config = {
      zones: [zoneWith('z', ['ssh'])],
      dhcp_config: [{ type: 'pool', name: 'Pool1', network: '10.0.0.0/24', interface: 'ge-0/0/1.0' }],
    };
    const { set, xml } = convert(config, { type: 'logical-system', name: 'LS1' });
    const lines = serviceLines(set.commands);
    expect(lines).toContain('set system services ssh');
    const dhcpLines = lines.filter(line => line.includes('dhcp-local-server') || line.includes('dhcp '));
    expect(dhcpLines.length).toBeGreaterThan(0);
    for (const line of dhcpLines) expect(line).toMatch(/^set logical-systems LS1 system services /);
    const contextStart = xml.xml.indexOf('<logical-systems>');
    expect(xml.xml.indexOf('<ssh/>')).toBeLessThan(contextStart);
    expect(xml.xml.lastIndexOf('<ssh/>')).toBeLessThan(contextStart);
  });

  it('carries custom FortiGate admin ports into set and XML, only when non-default', () => {
    const globalBlock = ports => `config system global\n${ports}\nend\n`;
    const custom = parseFortigateConfig(globalBlock('    set admin-ssh-port 2222\n    set admin-sport 8443\n    set admin-port 8080') + forti('ssh https http'));
    expect(custom.intermediateConfig.management_ports).toEqual({ ssh: '2222', https: '8443', http: '8080' });
    const { set, xml } = convert(custom.intermediateConfig);
    expect(serviceLines(set.commands)).toEqual([
      'set system services ssh',
      'set system services ssh port 2222',
      'set system services web-management https system-generated-certificate',
      'set system services web-management https port 8443',
      'set system services web-management http',
      'set system services web-management http port 8080',
    ]);
    expect(xml.xml).toContain('<ssh><port>2222</port></ssh>');
    expect(xml.xml).toContain('<https><port>8443</port><system-generated-certificate/></https>');
    expect(xml.xml).toContain('<http><port>8080</port></http>');

    const defaults = parseFortigateConfig(globalBlock('    set admin-ssh-port 22\n    set admin-sport 443') + forti('ssh https'));
    expect(serviceLines(convert(defaults.intermediateConfig).set.commands).join('\n')).not.toContain(' port ');
  });

  it('ignores out-of-range ports and ports of disabled daemons', () => {
    const config = { management_ports: { ssh: '70000', https: '8443' }, zones: [zoneWith('z', ['ssh'])] };
    const { set } = convert(config);
    expect(serviceLines(set.commands)).toEqual(['set system services ssh']);
    expect(set.warnings.filter(w => /Invalid ssh admin port/.test(w.message))).toHaveLength(1);
  });

  it('merged: a custom port only counts for slots that enable the daemon', () => {
    const slot = (lsName, services, ports) => ({
      lsName, intermediateConfig: { zones: [zoneWith('z', services)], management_ports: ports }, interfaceMappings: {},
    });
    // LS_A has a custom ssh port but no ssh access; LS_B uses the default port
    const noSsh = convertMergedToSrxSetCommands(structuredClone([slot('LS_A', ['https'], { ssh: '2222' }), slot('LS_B', ['ssh'], {})]), []);
    expect(serviceLines(noSsh.commands).join('\n')).not.toContain(' port ');
    // all enabling slots agree on a custom port
    const agree = convertMergedToSrxSetCommands(structuredClone([slot('LS_A', ['ssh'], { ssh: '2222' }), slot('LS_B', ['ssh'], { ssh: '2222' })]), []);
    expect(serviceLines(agree.commands)).toContain('set system services ssh port 2222');
    // enabling slots differ: the daemon is not enabled, warning names both
    const differ = convertMergedToSrxSetCommands(structuredClone([slot('LS_A', ['ssh'], { ssh: '2222' }), slot('LS_B', ['ssh'], {})]), []);
    expect(serviceLines(differ.commands)).toEqual([]);
    expect(differ.warnings.some(w => /LS_A: 2222, LS_B: 22/.test(w.message))).toBe(true);
  });

  it('ignores access entries of interfaces no longer in the zone', () => {
    const config = parseFortigateConfig(forti('ping')).intermediateConfig;
    const zone = config.zones.find(z => z.interface_host_inbound_traffic);
    zone.interface_host_inbound_traffic['port9'] = { system_services: ['ssh', 'https'], protocols: [] };
    expect(serviceLines(convert(config).set.commands)).toEqual([]);
  });

  it('derives no system services for an SRX source', () => {
    for (const vendor of ['srx', 'srx_healthcheck']) {
      const config = { metadata: { source_vendor: vendor }, zones: [zoneWith('trust', ['ssh', 'https'])] };
      const { set, xml } = convert(config);
      expect(serviceLines(set.commands)).toEqual([]);
      expect(xml.xml).not.toContain('<services>');
    }
  });

  it('carries management_ports into every auto-split slot so merged output keeps the custom port', () => {
    const config = {
      metadata: { source_vendor: 'fortigate' },
      management_ports: { ssh: '2222' },
      zones: [{ ...zoneWith('a', ['ssh']), interfaces: [] }, { ...zoneWith('b', ['ssh']), interfaces: [] }],
      routing_contexts: [{ type: 'vdom', name: 'v1', zones: ['a'] }, { type: 'vdom', name: 'v2', zones: ['b'] }],
    };
    const slots = autoSplitRoutingContexts(structuredClone(config));
    expect(slots).toHaveLength(2);
    for (const slot of slots) expect(slot.intermediateConfig.management_ports).toEqual({ ssh: '2222' });
    const merged = convertMergedToSrxSetCommands(slots, []);
    expect(serviceLines(merged.commands)).toContain('set system services ssh port 2222');
  });
});
