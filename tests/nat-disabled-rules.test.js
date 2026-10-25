import { describe, it, expect } from 'vitest';
import { parsePanosConfig } from '../src/parsers/panos-parser.js';
import { parseCiscoAsaConfig } from '../src/parsers/cisco-asa-parser.js';
import { parseCheckPointConfig } from '../src/parsers/checkpoint-parser.js';

const panos = disabled => `<?xml version="1.0"?>
<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
  <zone>
    <entry name="trust"><network><layer3/></network></entry>
    <entry name="untrust"><network><layer3/></network></entry>
  </zone>
  <address>
    <entry name="srv"><ip-netmask>192.168.1.10/32</ip-netmask></entry>
    <entry name="srv-pub"><ip-netmask>203.0.113.10/32</ip-netmask></entry>
  </address>
  <rulebase><nat><rules>
    <entry name="srv-static">
      <from><member>trust</member></from>
      <to><member>untrust</member></to>
      <source><member>srv</member></source>
      <destination><member>any</member></destination>
      <source-translation><static-ip>
        <translated-address>srv-pub</translated-address>
        <bi-directional>yes</bi-directional>
      </static-ip></source-translation>
      <disabled>${disabled}</disabled>
    </entry>
    <entry name="hide">
      <from><member>trust</member></from>
      <to><member>untrust</member></to>
      <source><member>any</member></source>
      <destination><member>any</member></destination>
      <source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface></interface-address></dynamic-ip-and-port></source-translation>
      <disabled>${disabled}</disabled>
    </entry>
  </rules></nat></rulebase>
</entry></vsys></entry></devices></config>`;

const asa = suffix => `interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.0
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.1.1 255.255.255.0
!
object network WEB
 host 192.168.1.10
 nat (inside,outside) static 203.0.113.10${suffix}
object network WEB-PUB
 host 203.0.113.11
nat (inside,outside) source static WEB WEB-PUB${suffix}
`;

const checkPoint = enabled => JSON.stringify({
  'objects-dictionary': [
    { uid: 'h1', type: 'host', name: 'web-private', 'ipv4-address': '192.168.1.10' },
    { uid: 'h2', type: 'host', name: 'web-public', 'ipv4-address': '203.0.113.10' },
  ],
  rulebase: [],
  'nat-rulebase': {
    rulebase: [{
      type: 'nat-rule', name: 'web-static', method: 'static', enabled,
      'original-source': 'h1', 'original-destination': 'any', 'original-service': 'any',
      'translated-source': 'h2', 'translated-destination': 'any', 'translated-service': 'any',
    }],
  },
});

const disabledWarnings = warnings => warnings.filter(item => /is (disabled|inactive) — not converted/.test(item.message));

describe('disabled NAT rules are not converted as active', () => {
  it('PAN-OS disabled yes', () => {
    const off = parsePanosConfig(panos('yes'));
    expect(off.intermediateConfig.nat_rules).toHaveLength(0);
    expect(disabledWarnings(off.warnings)).toHaveLength(2);
    expect(parsePanosConfig(panos('no')).intermediateConfig.nat_rules).toHaveLength(2);
  });

  it('ASA inactive object NAT and twice NAT', () => {
    const off = parseCiscoAsaConfig(asa(' inactive'));
    expect(off.intermediateConfig.nat_rules).toHaveLength(0);
    expect(disabledWarnings(off.warnings)).toHaveLength(2);
    expect(parseCiscoAsaConfig(asa('')).intermediateConfig.nat_rules).toHaveLength(2);
  });

  it('Check Point enabled false', () => {
    const off = parseCheckPointConfig(checkPoint(false));
    expect(off.intermediateConfig.nat_rules).toHaveLength(0);
    expect(disabledWarnings(off.warnings)).toHaveLength(1);
    expect(parseCheckPointConfig(checkPoint(true)).intermediateConfig.nat_rules).toHaveLength(1);
  });
});

describe('ASA inactive is read only as an option', () => {
  it('an object NAT description mentioning inactive keeps the rule', () => {
    const text = asa(' description inactive migration');
    expect(parseCiscoAsaConfig(text).intermediateConfig.nat_rules.map(rule => rule.name)).toContain('Auto-NAT-WEB');
  });

  it('an address object named inactive keeps the twice NAT rule', () => {
    const text = asa('').replace('source static WEB WEB-PUB', 'source static inactive WEB-PUB')
      .replace('object network WEB-PUB', 'object network inactive\n host 192.168.1.20\nobject network WEB-PUB');
    const rules = parseCiscoAsaConfig(text).intermediateConfig.nat_rules;
    expect(rules.some(rule => rule.name.startsWith('Manual-NAT-'))).toBe(true);
  });
});
