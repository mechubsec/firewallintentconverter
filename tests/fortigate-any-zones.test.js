import { describe, it, expect } from 'vitest';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

const INTERFACES = `config system interface
    edit "port1"
        set ip 203.0.113.2 255.255.255.248
    next
    edit "port2"
        set alias "lan"
        set ip 192.168.10.1 255.255.255.0
    next
    edit "port3"
        set ip 192.168.20.1 255.255.255.0
    next
    edit "port4"
    next
end
`;

const ANY_POLICY = `config firewall policy
    edit 1
        set name "any-to-wan"
        set srcintf "any"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
`;

const NAMED_POLICY = ANY_POLICY.replace('set srcintf "any"', 'set srcintf "port2"');

const ANY_CENTRAL_SNAT = `config firewall central-snat-map
    edit 1
        set srcintf "any"
        set dstintf "port1"
        set orig-addr "all"
        set dst-addr "all"
    next
end
`;

function convert(text) {
  const { intermediateConfig, warnings } = parseFortigateConfig(text);
  const commands = convertToSrxSetCommands(intermediateConfig, {}, null, {}).commands;
  const output = Array.isArray(commands) ? commands.join('\n') : String(commands);
  return { intermediateConfig, warnings, output };
}

const zoneNames = (config) => config.zones.map(zone => zone.name).sort();

describe('FortiGate "any" interface zoning (#125)', () => {
  it('zones every L3 interface when a policy uses srcintf any', () => {
    const { intermediateConfig, output } = convert(INTERFACES + ANY_POLICY);
    expect(zoneNames(intermediateConfig)).toEqual(['port1', 'port2', 'port3']);
    expect(output).toContain('set security zones security-zone port2 interfaces ge-0/0/1.0');
    expect(output).toContain('set security zones security-zone port3 interfaces ge-0/0/2.0');
    expect(output).not.toContain('security-zone port4');
  });

  it('zones every L3 interface when only a NAT rule uses any, and NAT matches them', () => {
    const { intermediateConfig, output } = convert(INTERFACES + ANY_CENTRAL_SNAT);
    expect(zoneNames(intermediateConfig)).toEqual(['port1', 'port2', 'port3']);
    expect(output).toContain('security-zone port3 interfaces ge-0/0/2.0');
    expect(output).toMatch(/nat source rule-set \S+ from zone port3/);
    expect(output).toMatch(/nat source rule-set \S+ from zone port2/);
  });

  it('generates intra-zone deny policies for the new zones', () => {
    const { output } = convert(INTERFACES + ANY_POLICY);
    expect(output).toMatch(/Implicit-Intra-zone-Deny-port3 match from-zone port3/);
  });

  it('does not duplicate interfaces already in an explicit zone', () => {
    const zoneConfig = `config system zone
    edit "lan"
        set interface "port2" "port3"
    next
end
`;
    const { intermediateConfig } = convert(INTERFACES + zoneConfig + ANY_POLICY);
    expect(zoneNames(intermediateConfig)).toEqual(['lan', 'port1']);
  });

  it('skips LAG member interfaces', () => {
    const lag = `config system interface
    edit "agg1"
        set type aggregate
        set member "port3"
        set ip 10.9.9.1 255.255.255.0
    next
end
`;
    const { intermediateConfig } = convert(INTERFACES + lag + ANY_POLICY);
    expect(zoneNames(intermediateConfig)).toEqual(['agg1', 'port1', 'port2']);
  });

  it('does not expand across multiple VDOMs and warns', () => {
    const vdomInterfaces = INTERFACES.replace('edit "port3"\n', 'edit "port3"\n        set vdom "other"\n');
    const { intermediateConfig, warnings } = convert(vdomInterfaces + ANY_POLICY);
    expect(zoneNames(intermediateConfig)).toEqual(['port1']);
    const warning = warnings.find(w => JSON.stringify(w).includes('multiple VDOMs'));
    expect(warning).toBeTruthy();
    expect(JSON.stringify(warning)).toContain('port2, port3');
  });

  it('leaves zones unchanged when nothing uses any', () => {
    const { intermediateConfig } = convert(INTERFACES + NAMED_POLICY);
    expect(zoneNames(intermediateConfig)).toEqual(['port1', 'port2']);
  });
  it('zones DHCP and PPPoE interfaces, which have no static address', () => {
    const text = INTERFACES.replace('    edit "port4"\n    next', '    edit "port4"\n        set mode dhcp\n    next\n    edit "port5"\n        set mode pppoe\n    next');
    const { intermediateConfig } = convert(text + ANY_POLICY);
    expect(zoneNames(intermediateConfig)).toEqual(['port1', 'port2', 'port3', 'port4', 'port5']);
  });

  it('skips management and FortiLink interfaces', () => {
    const text = INTERFACES.replace('    edit "port4"\n    next', '    edit "mgmt"\n        set ip 10.0.0.1 255.255.255.0\n        set dedicated-to management\n    next\n    edit "fortilink"\n        set ip 10.255.1.1 255.255.255.0\n        set fortilink enable\n    next');
    const { intermediateConfig } = convert(text + ANY_POLICY);
    expect(zoneNames(intermediateConfig)).toEqual(['port1', 'port2', 'port3']);
  });

  it('treats the FortiOS unset IPv6 address ::/0 as no address', () => {
    const text = INTERFACES.replace('    edit "port4"\n    next', '    edit "port4"\n        set ip 0.0.0.0 0.0.0.0\n        config ipv6\n            set ip6-address ::/0\n        end\n    next');
    const { intermediateConfig } = convert(text + ANY_POLICY);
    expect(zoneNames(intermediateConfig)).toEqual(['port1', 'port2', 'port3']);
  });
  it('skips administratively down interfaces', () => {
    const text = INTERFACES.replace('    edit "port4"\n    next', '    edit "port4"\n        set ip 192.168.40.1 255.255.255.0\n        set status down\n    next');
    const { intermediateConfig } = convert(text + ANY_POLICY);
    expect(zoneNames(intermediateConfig)).toEqual(['port1', 'port2', 'port3']);
  });
});
