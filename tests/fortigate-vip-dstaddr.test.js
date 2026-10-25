import { describe, it, expect } from 'vitest';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

const BASE = `config system interface
    edit "port1"
        set ip 203.0.113.2 255.255.255.248
    next
    edit "port2"
        set ip 192.168.10.1 255.255.255.0
    next
end
config firewall address
    edit "lan-net"
        set subnet 192.168.10.0 255.255.255.0
    next
end
config firewall service custom
    edit "HTTPS"
        set tcp-portrange 443
    next
end
config firewall vip
    edit "vip-web-01"
        set extip 203.0.113.3
        set extintf "port1"
        set mappedip "192.168.10.20"
    next
    edit "vip-web-02"
        set extip 203.0.113.4
        set extintf "port1"
        set mappedip "192.168.10.21"
    next
    edit "vip-unused"
        set extip 203.0.113.9
        set extintf "port1"
        set mappedip "192.168.10.99"
    next
end
config firewall vipgrp
    edit "vipgrp-web"
        set interface "port1"
        set member "vip-web-01" "vip-web-02"
    next
end
`;

const policy = (dstaddr) => `config firewall policy
    edit 1
        set name "web-inbound"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "lan-net"
        set dstaddr ${dstaddr}
        set action accept
        set service "HTTPS"
    next
end`;

function convert(dstaddr) {
  const { intermediateConfig } = parseFortigateConfig(BASE + policy(dstaddr));
  return convertToSrxSetCommands(intermediateConfig, {}, null, {}).commands;
}

const VIP_WEB_01 = '        set extip 203.0.113.3\n        set extintf "port1"\n        set mappedip "192.168.10.20"\n';
const withVipLines = (extraLines) => {
  if (!BASE.includes(VIP_WEB_01)) throw new Error('fixture drifted: vip-web-01 block not found');
  return BASE.replace(VIP_WEB_01, VIP_WEB_01 + extraLines);
};

const isDeactivated = (commands) => commands.some((line) => line.startsWith('deactivate') && line.includes('web-inbound'));

describe('FortiGate VIP used as policy dstaddr', () => {
  it('resolves the VIP to its mapped address and keeps the policy active', () => {
    const commands = convert('"vip-web-01"');
    expect(commands).toContain('set security address-book global address vip-web-01 192.168.10.20/32');
    expect(commands.some((line) => / match destination-address vip-web-01$/.test(line))).toBe(true);
    expect(isDeactivated(commands)).toBe(false);
    expect(commands.join('\n')).not.toContain(`undefined reference(s)`);
  });

  it('still matches the DNAT rule on the external address', () => {
    const commands = convert('"vip-web-01"');
    expect(commands.some((line) => / match destination-address 203\.0\.113\.3$/.test(line))).toBe(true);
  });

  it('skips DNAT for a VIP without extip instead of matching any destination', () => {
    const config = BASE.replace('        set extip 203.0.113.9\n', '') + policy('"vip-web-01"');
    const { intermediateConfig } = parseFortigateConfig(config);
    expect(intermediateConfig.nat_rules.some((rule) => rule.name === 'vip-unused')).toBe(false);
  });

  it('keeps the policy deactivated when the VIP produces no DNAT', () => {
    const noExtIp = BASE.replace('        set extip 203.0.113.3\n', '');
    const commands = convertToSrxSetCommands(parseFortigateConfig(noExtIp + policy('"vip-web-01"')).intermediateConfig, {}, null, {}).commands;
    expect(commands.join('\n')).not.toContain('address vip-web-01 ');
    expect(isDeactivated(commands)).toBe(true);
  });

  it('keeps the policy deactivated for an interface-address VIP (extip 0.0.0.0)', () => {
    const interfaceVip = BASE.replace('set extip 203.0.113.3', 'set extip 0.0.0.0');
    const { intermediateConfig } = parseFortigateConfig(interfaceVip + policy('"vip-web-01"'));
    const commands = convertToSrxSetCommands(intermediateConfig, {}, null, {}).commands;
    expect(intermediateConfig.nat_rules.some((rule) => rule.name === 'vip-web-01')).toBe(false);
    expect(isDeactivated(commands)).toBe(true);
  });

  it.each([
    ['a source filter', '        set src-filter "198.51.100.0/24"\n'],
    ['a non-static type', '        set type dns-translation\n'],
    ['a VIP service', '        set service "HTTPS"\n'],
    ['several mapped addresses', '        set mappedip "192.168.10.20" "192.168.10.22"\n'],
  ])('keeps the policy deactivated for a VIP with %s', (_label, extraLine) => {
    const commands = convertToSrxSetCommands(parseFortigateConfig(withVipLines(extraLine) + policy('"vip-web-01"')).intermediateConfig, {}, null, {}).commands;
    expect(commands.join('\n')).not.toContain('address vip-web-01 ');
    expect(isDeactivated(commands)).toBe(true);
  });

  it('does not resolve a VIP with a non-tcp/udp port forward', () => {
    // Checked at parse time: the converter already rejects an sctp DNAT match_protocol.
    const sctp = withVipLines('        set portforward enable\n        set protocol sctp\n        set extport 443\n        set mappedport 443\n');
    const { intermediateConfig } = parseFortigateConfig(sctp + policy('"vip-web-01"'));
    expect(intermediateConfig.address_objects.some((object) => object.name === 'vip-web-01')).toBe(false);
  });

  it('defaults a port-forward VIP without protocol to tcp', () => {
    const portForward = withVipLines('        set portforward enable\n        set extport 443\n        set mappedport 8443\n');
    const commands = convertToSrxSetCommands(parseFortigateConfig(portForward + policy('"vip-web-01"')).intermediateConfig, {}, null, {}).commands;
    expect(commands.some((line) => / rule vip-web-01 match protocol tcp$/.test(line))).toBe(true);
    expect(commands.some((line) => / rule vip-web-01 match destination-port 443$/.test(line))).toBe(true);
  });

  it('leaves a vipgrp with an unconvertible member unresolved', () => {
    const missingMember = BASE.replace('set member "vip-web-01" "vip-web-02"', 'set member "vip-web-01" "vip-missing"');
    const commands = convertToSrxSetCommands(parseFortigateConfig(missingMember + policy('"vipgrp-web"')).intermediateConfig, {}, null, {}).commands;
    expect(commands.some((line) => line.includes('address-set vipgrp-web'))).toBe(false);
    expect(isDeactivated(commands)).toBe(true);
  });

  it('adds no address-book entry for unreferenced VIPs', () => {
    const text = convert('"vip-web-01"').join('\n');
    expect(text).not.toContain('address vip-unused');
    expect(text).not.toContain('address vip-web-02 ');
  });

  it('resolves a vipgrp to an address-set of the member VIPs', () => {
    const commands = convert('"vipgrp-web"');
    expect(commands).toContain('set security address-book global address vip-web-01 192.168.10.20/32');
    expect(commands).toContain('set security address-book global address vip-web-02 192.168.10.21/32');
    expect(commands.some((line) => /address-set vipgrp-web address vip-web-02$/.test(line))).toBe(true);
    expect(isDeactivated(commands)).toBe(false);
  });
});
