import { describe, it, expect } from 'vitest';
import { parseCiscoAsaConfig } from '../src/parsers/cisco-asa-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';

const INTERFACES = `interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.0
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.1.1 255.255.255.0
!
interface GigabitEthernet0/2
 nameif dmz
 security-level 50
 ip address 172.16.0.1 255.255.255.0
!
`;

const run = (accessLines) => {
  const { intermediateConfig, warnings: parseWarnings } = parseCiscoAsaConfig(INTERFACES + accessLines);
  const set = convertToSrxSetCommands(structuredClone(intermediateConfig), {}, null, {});
  const xml = buildSrxXml(structuredClone(intermediateConfig));
  const hostLines = set.commands.filter(line => line.includes('host-inbound-traffic'));
  return { intermediateConfig, parseWarnings, set, xml, hostLines };
};

describe('Cisco ASA interface management access', () => {
  const { hostLines, xml, parseWarnings } = run(`ssh 0.0.0.0 0.0.0.0 inside
ssh 10.9.0.0 255.255.0.0 outside
telnet 192.168.1.0 255.255.255.0 inside
http server enable
http 192.168.1.0 255.255.255.0 inside
http 0 0 dmz
http 10.0.0.0 255.0.0.0 dmz
ssh 10.0.0.0 255.0.0.0 dmz
ssh 0 0 dmz
icmp deny any outside
icmp permit any echo inside
icmp permit 198.51.100.0 255.255.255.0 outside
ssh timeout 5
`);
  const linesFor = zone => hostLines.filter(line => line.includes(`security-zone ${zone} `)).map(line => line.split(' ').pop());

  it('emits ssh/telnet/https per interface from the nameif lines (set)', () => {
    expect(hostLines).toContainEqual(expect.stringMatching(/security-zone inside interfaces \S+ host-inbound-traffic system-services ssh$/));
    // inside: telnet and http are source-restricted only, so they are not granted
    expect(linesFor('inside')).toEqual(['ping', 'ssh']);
    // outside: ssh is source-restricted only, and icmp deny any precedes the restricted permit
    expect(linesFor('outside')).toEqual([]);
  });

  it('grants a service that has an any-source line plus restricted lines, and the default ICMP permit', () => {
    expect(linesFor('dmz')).toEqual(['ping', 'ssh', 'https']);
    expect(parseWarnings.some(w => w.element === 'interfaces/dmz')).toBe(false);
  });

  it('matches in XML', () => {
    expect(xml.xml.match(/<system-services>/g)).toHaveLength(5);
    expect(xml.xml).not.toContain('<name>telnet</name>');
  });

  it('warns that source-restricted services were not converted', () => {
    expect(parseWarnings.some(w => w.element === 'interfaces/outside' && /ssh on outside is restricted to 10\.9\.0\.0 255\.255\.0\.0.*not converted/.test(w.message))).toBe(true);
    expect(parseWarnings.some(w => w.element === 'interfaces/inside' && /telnet on inside is restricted to 192\.168\.1\.0/.test(w.message))).toBe(true);
  });
});

describe('Cisco ASA edge cases', () => {
  it('ignores http lines without http server enable and warns', () => {
    const { hostLines, parseWarnings } = run('http 0.0.0.0 0.0.0.0 inside\n');
    expect(hostLines.some(line => line.endsWith('https'))).toBe(false);
    expect(parseWarnings.some(w => /http server enable/.test(w.message))).toBe(true);
  });

  it('does not grant ping when icmp permits are source-restricted only', () => {
    const { hostLines, parseWarnings } = run('icmp permit 10.0.0.0 255.0.0.0 inside\n');
    expect(hostLines.some(line => line.includes('security-zone inside '))).toBe(false);
    expect(parseWarnings.some(w => w.element === 'interfaces/inside' && /ping/.test(w.message))).toBe(true);
  });

  it('fails closed when a restricted echo deny precedes the any-source permit', () => {
    const { hostLines, parseWarnings } = run('icmp deny host 198.51.100.10 echo outside\nicmp permit any echo outside\n');
    expect(hostLines.some(line => line.includes('security-zone outside '))).toBe(false);
    expect(parseWarnings.some(w => w.element === 'interfaces/outside' && /ping on outside is restricted to deny host 198\.51\.100\.10/.test(w.message))).toBe(true);
  });

  it('grants ping when a restricted deny follows the any-source permit', () => {
    const { hostLines } = run('icmp permit any echo outside\nicmp deny host 198.51.100.10 echo outside\n');
    expect(hostLines.filter(line => line.includes('security-zone outside ')).map(line => line.split(' ').pop())).toEqual(['ping']);
  });

  it('does not grant https for a custom ASDM port and warns', () => {
    const { hostLines, parseWarnings } = run('http server enable 8443\nhttp 0 0 inside\n');
    expect(hostLines.some(line => line.endsWith('https'))).toBe(false);
    expect(parseWarnings.some(w => /custom port 8443/.test(w.message))).toBe(true);
    expect(run('http server enable 443\nhttp 0 0 inside\n').hostLines.some(line => line.endsWith('https'))).toBe(true);
  });

  it('treats an all-zero address and mask in icmp as any source', () => {
    const { hostLines } = run('icmp permit 0.0.0.0 0.0.0.0 echo outside\n');
    expect(hostLines.filter(line => line.includes('security-zone outside ')).map(line => line.split(' ').pop())).toEqual(['ping']);
  });

  it('fails closed on a nameif with a control-plane access-group', () => {
    const { hostLines, parseWarnings, intermediateConfig } = run('ssh 0 0 outside\nssh 0 0 inside\naccess-group ADMIN-ONLY in interface outside control-plane\n');
    expect(hostLines.some(line => line.includes('security-zone outside '))).toBe(false);
    expect(hostLines).toContainEqual(expect.stringMatching(/security-zone inside interfaces \S+ host-inbound-traffic system-services ssh$/));
    expect(parseWarnings.some(w => w.element === 'interfaces/outside' && /Control-plane ACL ADMIN-ONLY/.test(w.message))).toBe(true);
    // the control-plane ACL must not also be applied as a transit policy
    expect(intermediateConfig.security_policies.some(policy => (policy.name || '').includes('ADMIN-ONLY'))).toBe(false);
  });

  it('grants no ping when icmp lines only cover non-echo types', () => {
    const { hostLines } = run('icmp permit any unreachable inside\n');
    expect(hostLines.some(line => line.includes('security-zone inside '))).toBe(false);
  });
});

describe('Cisco ASA dual-stack interfaces', () => {
  const DUAL = `interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.0
 ipv6 address 2001:db8::1/64
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.1.1 255.255.255.0
 ipv6 address 2001:db8:1::1/64
!
interface GigabitEthernet0/2
 nameif v6only
 security-level 50
 ipv6 address 2001:db8:2::1/64
!
`;
  const runDual = (accessLines) => {
    const { intermediateConfig, warnings } = parseCiscoAsaConfig(DUAL + accessLines);
    const { commands } = convertToSrxSetCommands(structuredClone(intermediateConfig), {}, null, {});
    const servicesFor = zone => commands.filter(line => line.includes(`security-zone ${zone} interfaces`) && line.includes('system-services')).map(line => line.split(' ').pop());
    return { warnings, servicesFor };
  };

  it('grants a service only when both families allow it from any source', () => {
    const { servicesFor } = runDual('ssh 0 0 inside\nssh ::/0 inside\nipv6 icmp permit any echo inside\nicmp permit any echo inside\n');
    expect(servicesFor('inside')).toEqual(['ping', 'ssh']);
  });

  it('does not grant a service allowed over one family only, and warns', () => {
    const { servicesFor, warnings } = runDual('ssh 0 0 outside\n');
    expect(servicesFor('outside')).toEqual(['ping']);
    expect(warnings.some(w => w.element === 'interfaces/outside' && /ssh on outside is allowed from any source over ipv4 only/.test(w.message))).toBe(true);
  });

  it('lets a single-family interface be decided by its own family, using ipv6 icmp lines', () => {
    const { servicesFor } = runDual('ssh ::/0 v6only\nipv6 icmp deny any v6only\nicmp permit any echo v6only\n');
    expect(servicesFor('v6only')).toEqual(['ssh']);
  });

  it('recognises ICMPv6 echo request as type 128, not 8', () => {
    const v6 = runDual('icmp permit any echo v6only\nipv6 icmp permit any 128 v6only\n');
    expect(v6.servicesFor('v6only')).toEqual(['ping']);
    const wrongType = runDual('ipv6 icmp permit any 8 v6only\n');
    expect(wrongType.servicesFor('v6only')).toEqual([]);
  });

  it('applies the ipv6 icmp list to the IPv6 family of a dual-stack interface', () => {
    const { servicesFor, warnings } = runDual('ipv6 icmp deny any outside\n');
    expect(servicesFor('outside')).toEqual([]);
    expect(warnings.some(w => /ping on outside is allowed from any source over ipv4 only/.test(w.message))).toBe(true);
  });
});
