import { describe, it, expect } from 'vitest';
import { parseHuaweiConfig } from '../src/parsers/huawei-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';

const CONFIG = `interface GigabitEthernet0/0/1
 ip address 192.168.1.1 255.255.255.0
 service-manage enable
 service-manage ping permit
 service-manage ssh permit
 service-manage https permit
 service-manage snmp permit
 service-manage snmp deny
 service-manage netconf permit
 service-manage ftp permit
#
interface GigabitEthernet0/0/2
 ip address 203.0.113.1 255.255.255.0
 service-manage enable
#
interface GigabitEthernet0/0/3
 ip address 172.16.0.1 255.255.255.0
 service-manage all permit
#
interface GigabitEthernet0/0/4
 ip address 10.0.0.1 255.255.255.0
#
firewall zone trust
 set priority 85
 add interface GigabitEthernet0/0/1
#
firewall zone untrust
 set priority 5
 add interface GigabitEthernet0/0/2
#
firewall zone dmz
 set priority 50
 add interface GigabitEthernet0/0/3
 add interface GigabitEthernet0/0/4
#
`;

describe('Huawei service-manage', () => {
  const { intermediateConfig, warnings } = parseHuaweiConfig(CONFIG);
  const set = convertToSrxSetCommands(structuredClone(intermediateConfig), {}, null, {});
  const xml = buildSrxXml(structuredClone(intermediateConfig));
  const hostLines = set.commands.filter(line => line.includes('host-inbound-traffic'));

  it('emits per-interface permitted services in set output', () => {
    expect(hostLines).toEqual([
      expect.stringMatching(/security-zone trust interfaces \S+ host-inbound-traffic system-services ping$/),
      expect.stringMatching(/security-zone trust interfaces \S+ host-inbound-traffic system-services ssh$/),
      expect.stringMatching(/security-zone trust interfaces \S+ host-inbound-traffic system-services https$/),
      expect.stringMatching(/security-zone trust interfaces \S+ host-inbound-traffic system-services netconf$/),
      ...['ping', 'ssh', 'https', 'http', 'telnet', 'snmp', 'netconf'].map(service =>
        expect.stringMatching(new RegExp(`security-zone dmz interfaces \\S+ host-inbound-traffic system-services ${service}$`))),
    ]);
    expect(hostLines.some(line => line.endsWith('system-services all'))).toBe(false);
  });

  it('emits the same in XML', () => {
    expect(xml.xml.match(/<system-services>/g)).toHaveLength(11);
    expect(xml.xml).toMatch(/<system-services>\s*<name>netconf<\/name>/);
  });

  it('leaves interfaces without service-manage lines without access data', () => {
    const dmz = intermediateConfig.zones.find(zone => zone.name === 'dmz');
    expect(Object.keys(dmz.interface_host_inbound_traffic)).toEqual(['GigabitEthernet0/0/3']);
    expect(intermediateConfig.zones.find(zone => zone.name === 'untrust').interface_host_inbound_traffic['GigabitEthernet0/0/2'])
      .toEqual({ system_services: [], protocols: [] });
  });

  it('warns about unmapped services', () => {
    expect(warnings.filter(w => w.message.includes('ftp'))).toHaveLength(1);
  });
});

describe('Huawei service-manage all', () => {
  it('expands all permit so a later deny removes an individual service', () => {
    const { intermediateConfig } = parseHuaweiConfig(`interface GigabitEthernet0/0/1
 ip address 192.168.1.1 255.255.255.0
 service-manage all permit
 service-manage ssh deny
#
firewall zone trust
 add interface GigabitEthernet0/0/1
#
`);
    const services = intermediateConfig.zones[0].interface_host_inbound_traffic['GigabitEthernet0/0/1'].system_services;
    expect(services).not.toContain('ssh');
    expect(services).toEqual(expect.arrayContaining(['ping', 'https', 'netconf']));
  });
});

describe('Huawei SNMP ACL', () => {
  const CONFIG_WITH = (extra) => `snmp-agent
${extra}
#
interface GigabitEthernet0/0/1
 ip address 192.168.1.1 255.255.255.0
 service-manage ping permit
 service-manage snmp permit
#
firewall zone trust
 add interface GigabitEthernet0/0/1
#
`;
  it('does not grant snmp when an snmp-agent line carries an ACL, and warns', () => {
    const { intermediateConfig, warnings } = parseHuaweiConfig(CONFIG_WITH('snmp-agent community read cipher abc acl 2000'));
    expect(intermediateConfig.zones[0].interface_host_inbound_traffic['GigabitEthernet0/0/1'].system_services).toEqual(['ping']);
    expect(warnings.some(w => /snmp is restricted by ACL 2000/.test(w.message))).toBe(true);
  });

  it('keeps snmp when no ACL is configured', () => {
    const { intermediateConfig } = parseHuaweiConfig(CONFIG_WITH('snmp-agent community read cipher abc'));
    expect(intermediateConfig.zones[0].interface_host_inbound_traffic['GigabitEthernet0/0/1'].system_services).toEqual(['ping', 'snmp']);
  });
});

describe('Huawei management ACLs', () => {
  const CONFIG_WITH = (extra) => `${extra}
#
interface GigabitEthernet0/0/1
 ip address 192.168.1.1 255.255.255.0
 service-manage ping permit
 service-manage ssh permit
 service-manage telnet permit
 service-manage https permit
#
firewall zone trust
 add interface GigabitEthernet0/0/1
#
`;
  const servicesOf = (extra) => {
    const { intermediateConfig, warnings } = parseHuaweiConfig(CONFIG_WITH(extra));
    return { services: intermediateConfig.zones[0].interface_host_inbound_traffic['GigabitEthernet0/0/1'].system_services, warnings };
  };

  it('drops ssh when ssh server acl is configured', () => {
    for (const line of ['ssh server acl 2000', 'ssh ipv6 server acl 2001']) {
      const { services, warnings } = servicesOf(line);
      expect(services).toEqual(['ping', 'telnet', 'https']);
      expect(warnings.filter(w => /ssh is restricted by ACL/.test(w.message))).toHaveLength(1);
    }
  });

  it('drops ssh and telnet when a vty block has acl inbound', () => {
    const { services, warnings } = servicesOf('user-interface vty 0 4\n acl 2000 inbound\n authentication-mode aaa');
    expect(services).toEqual(['ping', 'https']);
    expect(warnings.filter(w => /ACL 2000/.test(w.message))).toHaveLength(2);
  });

  it('keeps the services when no ACL is bound (control)', () => {
    expect(servicesOf('user-interface vty 0 4\n authentication-mode aaa').services).toEqual(['ping', 'ssh', 'telnet', 'https']);
  });
});
