import { describe, it, expect } from 'vitest';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';

const FORTIGATE = `config system interface
    edit "port1"
        set ip 203.0.113.2 255.255.255.248
        set allowaccess https
    next
    edit "port2"
        set ip 192.168.10.1 255.255.255.0
        set allowaccess ping ssh fgfm
    next
    edit "port3"
        set ip 192.168.20.1 255.255.255.0
    next
end
config firewall policy
    edit 1
        set name "p1"
        set srcintf "port1" "port2" "port3"
        set dstintf "port1" "port2" "port3"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
`;

const convert = (config) => ({
  set: convertToSrxSetCommands(structuredClone(config)),
  xml: buildSrxXml(structuredClone(config)),
});
const hostLines = (commands) => commands.filter(line => line.includes('host-inbound-traffic'));

describe('zone host-inbound-traffic', () => {
  const { intermediateConfig, warnings: parseWarnings } = parseFortigateConfig(FORTIGATE);
  const { set, xml } = convert(intermediateConfig);

  it('emits per-interface access from allowaccess in set output', () => {
    expect(hostLines(set.commands)).toEqual([
      expect.stringMatching(/security-zone port1 interfaces \S+ host-inbound-traffic system-services https$/),
      expect.stringMatching(/security-zone port2 interfaces \S+ host-inbound-traffic system-services ping$/),
      expect.stringMatching(/security-zone port2 interfaces \S+ host-inbound-traffic system-services ssh$/),
    ]);
    expect(set.commands.join('\n')).not.toMatch(/security-zone \S+ host-inbound-traffic system-services ping/);
    expect(set.warnings.filter(w => /No host-inbound-traffic data/.test(w.message))).toHaveLength(0);
  });

  it('emits the same access in XML, inside the interface element', () => {
    expect(xml.xml).toMatch(/<interfaces>\s*<name>[^<]+<\/name>\s*<host-inbound-traffic>\s*<system-services>\s*<name>https<\/name>/);
    expect(xml.xml.match(/<system-services>/g)).toHaveLength(3);
    expect(xml.xml).not.toContain('fgfm');
  });

  it('warns once about allowaccess values with no SRX equivalent', () => {
    const fgfm = parseWarnings.filter(w => w.message.includes('fgfm'));
    expect(fgfm).toHaveLength(1);
    expect(fgfm[0].element).toBe('interfaces/port2');
  });

  it('emits nothing and warns once for zones without access data', () => {
    const bare = {
      zones: [{ name: 'a', interfaces: ['ge-0/0/0'] }, { name: 'b', interfaces: ['ge-0/0/1'] }],
    };
    const result = convert(bare);
    expect(hostLines(result.set.commands)).toEqual([]);
    expect(result.xml.xml).not.toContain('host-inbound-traffic');
    for (const warnings of [result.set.warnings, result.xml.warnings]) {
      const missing = warnings.filter(w => /No host-inbound-traffic data/.test(w.message));
      expect(missing).toHaveLength(1);
      expect(missing[0].message).toContain('a, b');
    }
  });

  it('drops unsafe names with a warning in both outputs', () => {
    const config = { zones: [{ name: 'z', interfaces: [], host_inbound_traffic: { system_services: ['ssh', 'bad name;'], protocols: [] } }] };
    const result = convert(config);
    expect(hostLines(result.set.commands)).toEqual(['set security zones security-zone z host-inbound-traffic system-services ssh']);
    expect(result.xml.xml).not.toContain('bad name');
    expect(result.set.warnings.some(w => /Invalid host-inbound/.test(w.message))).toBe(true);
  });

  it('emits greenfield zone host_inbound_traffic', () => {
    const config = {
      metadata: { source_vendor: 'greenfield' },
      zones: [{ name: 'trust', interfaces: ['ge-0/0/1.0'], host_inbound_traffic: { system_services: ['ssh', 'dhcp'], protocols: ['bgp'] } }],
      address_objects: [], address_groups: [], service_objects: [], service_groups: [], security_policies: [],
    };
    const { commands, warnings } = convertToSrxSetCommands(structuredClone(config));
    expect(commands).toContain('set security zones security-zone trust host-inbound-traffic system-services ssh');
    expect(commands).toContain('set security zones security-zone trust host-inbound-traffic system-services dhcp');
    expect(commands).toContain('set security zones security-zone trust host-inbound-traffic protocols bgp');
    expect(warnings.some(w => /No host-inbound-traffic data/.test(w.message))).toBe(false);
    expect(buildSrxXml(structuredClone(config)).xml).toMatch(/<protocols>\s*<name>bgp<\/name>/);
  });

  it('uses ip6-allowaccess on IPv6-only interfaces and warns when the families differ', () => {
    const { intermediateConfig, warnings } = parseFortigateConfig(`config system interface
    edit "v6only"
        config ipv6
            set ip6-address 2001:db8::1/64
            set ip6-allowaccess ping ssh
        end
    next
    edit "dual"
        set ip 192.0.2.1 255.255.255.0
        set allowaccess ping
        config ipv6
            set ip6-address 2001:db8:1::1/64
            set ip6-allowaccess ping https
        end
    next
end
config firewall policy
    edit 1
        set srcintf "v6only"
        set dstintf "dual"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
`);
    const access = Object.assign({}, ...intermediateConfig.zones.map(zone => zone.interface_host_inbound_traffic || {}));
    expect(access.v6only.system_services).toEqual(['ping', 'ssh']);
    expect(access.dual.system_services).toEqual(['ping']);
    expect(warnings.some(w => /dual: allowaccess \(ping\) and ip6-allowaccess \(ping https\) differ/.test(w.message))).toBe(true);
    expect(warnings.some(w => /allowaccess ssh is converted to host-inbound-traffic only/.test(w.message))).toBe(true);
  });

  it('treats DHCP links as IPv4, ignores ::/0, and warns about local-in policies', () => {
    const { intermediateConfig, warnings } = parseFortigateConfig(`config system interface
    edit "wan1"
        set mode dhcp
        set allowaccess ping
        config ipv6
            set ip6-address ::/0
            set ip6-allowaccess ping ssh https
        end
    next
    edit "lan"
        set ip 10.0.0.1 255.255.255.0
        set allowaccess ping ssh
    next
end
config firewall local-in-policy
    edit 1
        set intf "lan"
        set srcaddr "admin-net"
        set dstaddr "all"
        set action accept
        set service "SSH"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
`);
    const access = Object.assign({}, ...intermediateConfig.zones.map(zone => zone.interface_host_inbound_traffic || {}));
    expect(access.wan1.system_services).toEqual(['ping', 'dhcp']);
    expect(warnings.some(w => /wan1: allowaccess/.test(w.message))).toBe(false);
    expect(warnings.some(w => /local-in-policy restricts management access/.test(w.message))).toBe(true);
  });

  it('warns about allowaccess on interfaces outside every zone and policy', () => {
    const { warnings } = parseFortigateConfig(`config system interface
    edit "mgmt"
        set ip 192.0.2.10 255.255.255.0
        set allowaccess ping https ssh
    next
end
`);
    expect(warnings.some(w => /allowaccess on mgmt was not converted/.test(w.message))).toBe(true);
  });

  it('treats an empty greenfield host_inbound_traffic object as missing data', () => {
    const config = {
      metadata: { source_vendor: 'greenfield' },
      zones: [{ name: 'guest', interfaces: ['ge-0/0/2.0'], host_inbound_traffic: {} }],
      address_objects: [], address_groups: [], service_objects: [], service_groups: [], security_policies: [],
    };
    const { warnings } = convertToSrxSetCommands(structuredClone(config));
    expect(warnings.some(w => /No host-inbound-traffic data for zone\(s\): guest/.test(w.message))).toBe(true);
  });
});
