import { describe, it, expect } from 'vitest';
import { parseSonicWallConfig } from '../src/parsers/sonicwall-parser.js';

const CONFIG = `address-object ipv4 "Web Servers" host 192.0.2.10 zone DMZ
address-object ipv4 "Bad Net" network 198.51.100.0 255.255.255.0 zone WAN
address-object ipv4 "Mgmt" host 192.0.2.99 zone LAN
address-group ipv4 "Outer"
  address-object ipv4 "Web Servers"
  address-group ipv4 "Inner"
  address-object ipv4 "Mgmt"
address-group ipv4 "Inner"
  address-object ipv4 "Bad Net"
access-rule ipv4 from WAN to DMZ action deny source "Bad Net" destination "Web Servers" service any
access-rule ipv4 from WAN to DMZ bogus
`;

const { intermediateConfig, warnings } = parseSonicWallConfig(CONFIG);

describe('SonicWall CLI access-rule and address-group parsing', () => {
  it('parses access rules whose source/destination names are quoted with spaces', () => {
    expect(intermediateConfig.security_policies).toHaveLength(1);
    const [policy] = intermediateConfig.security_policies;
    expect(policy.src_addresses).toEqual(['Bad Net']);
    expect(policy.dst_addresses).toEqual(['Web Servers']);
    expect(policy.action).toBe('deny');
  });

  it('warns on an access-rule line it cannot parse', () => {
    expect(warnings.some(item => item.message.includes('access-rule ipv4 from WAN to DMZ bogus'))).toBe(true);
  });

  it('keeps an indented address-group member inside its outer group', () => {
    const groups = Object.fromEntries(intermediateConfig.address_groups.map(group => [group.name, group.members]));
    expect(groups.Outer).toEqual(['Web Servers', 'Inner', 'Mgmt']);
    expect(groups.Inner).toEqual(['Bad Net']);
    expect(intermediateConfig.address_groups).toHaveLength(2);
  });
});
