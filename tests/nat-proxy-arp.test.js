import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';
import { parsePanosConfig } from '../src/parsers/panos-parser.js';
import { parseCiscoAsaConfig } from '../src/parsers/cisco-asa-parser.js';

const WAN = 'set security nat proxy-arp interface ge-0/0/0.0 address';

function fortigate({ pool = '', vip = '', interfaces = '' } = {}) {
  return `config system interface
    edit "port1"
        set ip 203.0.113.2 255.255.255.248
    next
    edit "port2"
        set ip 192.168.10.1 255.255.255.0
    next
${interfaces}end
config firewall address
    edit "lan-net"
        set subnet 192.168.10.0 255.255.255.0
    next
end
config firewall ippool
    edit "pool1"
        set startip 203.0.113.3
        set endip 203.0.113.4
${pool}    next
end
config firewall vip
    edit "web"
        set extip 203.0.113.5
        set mappedip "192.168.10.10"
        set extintf "port1"
${vip}    next
end
config firewall central-snat-map
    edit 1
        set srcintf "any"
        set dstintf "port1"
        set orig-addr "lan-net"
        set dst-addr "all"
        set nat-ippool "pool1"
    next
end
`;
}

const fortigateConfig = options => parseFortigateConfig(fortigate(options)).intermediateConfig;

function render(config) {
  const mappings = Object.fromEntries((config.interfaces || []).map((iface, index) => [iface.name, `ge-0/0/${index}`]));
  const set = convertToSrxSetCommands(structuredClone(config), mappings, null, {});
  const xml = buildSrxXml(structuredClone(config), mappings);
  const setLines = set.commands.filter(line => line.startsWith('set security nat proxy-arp'));
  const xmlBlock = (xml.xml.match(/<proxy-arp>[\s\S]*?<\/proxy-arp>/) || [''])[0];
  const warnings = [...set.warnings, ...xml.warnings].filter(item => /proxy ARP|proxied/.test(item.message || ''));
  return { setLines, xmlBlock, warnings };
}

const natConfig = (natRules, interfaces) => ({
  zones: [{ name: 'trust', interfaces: ['lan'] }, { name: 'untrust', interfaces: ['wan'] }],
  address_objects: [],
  interfaces: interfaces || [{ name: 'wan', ip: '203.0.113.2/29' }, { name: 'lan', ip: '192.168.10.1/24' }],
  nat_rules: natRules,
});
const dnat = (overrides = {}) => ({
  name: 'dnat', type: 'destination', src_zones: ['untrust'], dst_zones: ['trust'],
  src_addresses: ['any'], dst_addresses: ['203.0.113.5'], translated_dst: '192.168.10.10', ...overrides,
});
const snat = (overrides = {}) => ({
  name: 'snat', type: 'source', src_zones: ['trust'], dst_zones: ['untrust'],
  src_addresses: ['any'], dst_addresses: ['any'],
  translated_src: { type: 'dynamic-ip-pool', addresses: ['203.0.113.3-203.0.113.4'] }, ...overrides,
});

describe('NAT proxy ARP: issue repro', () => {
  it('emits the pool range and the VIP address on the connected interface', () => {
    const { setLines, xmlBlock, warnings } = render(fortigateConfig());
    expect(setLines).toEqual([
      `${WAN} 203.0.113.3/32 to 203.0.113.4/32`,
      `${WAN} 203.0.113.5/32`,
    ]);
    expect(xmlBlock).toContain('<name>ge-0/0/0.0</name>');
    expect(xmlBlock).toContain('<address><name>203.0.113.3/32</name><to><ipaddr>203.0.113.4/32</ipaddr></to></address>');
    expect(xmlBlock).toContain('<address><name>203.0.113.5/32</name></address>');
    expect(warnings).toEqual([]);
  });

  it('drops the pool when arp-reply is disabled on it', () => {
    const { setLines } = render(fortigateConfig({ pool: '        set arp-reply disable\n' }));
    expect(setLines).toEqual([`${WAN} 203.0.113.5/32`]);
  });

  it('drops the VIP when arp-reply is disabled on it', () => {
    const { setLines, xmlBlock } = render(fortigateConfig({ vip: '        set arp-reply disable\n' }));
    expect(setLines).toEqual([`${WAN} 203.0.113.3/32 to 203.0.113.4/32`]);
    expect(xmlBlock).not.toContain('203.0.113.5');
  });
});

describe('NAT proxy ARP: selection', () => {
  it('skips an address equal to the interface address', () => {
    const { setLines } = render(natConfig([dnat({ dst_addresses: ['203.0.113.2'] })]));
    expect(setLines).toEqual([]);
  });

  it('warns instead of proxying a pool range that includes the interface address', () => {
    const config = fortigateConfig({ pool: '        set startip 203.0.113.2\n' });
    const { setLines, warnings } = render(config);
    expect(setLines.some(line => line.includes('203.0.113.2/32 to'))).toBe(false);
    expect(warnings.some(item => /includes an interface's own address/.test(item.message))).toBe(true);
  });

  it('emits nothing for an address outside every connected subnet', () => {
    const { setLines, xmlBlock } = render(natConfig([dnat({ dst_addresses: ['198.51.100.5'] })]));
    expect(setLines).toEqual([]);
    expect(xmlBlock).toBe('');
  });

  it('warns and emits nothing when subnets overlap', () => {
    const interfaces = [{ name: 'wan', ip: '203.0.113.2/29' }, { name: 'wan2', ip: '203.0.113.1/24' }];
    const zones = [{ name: 'trust', interfaces: ['lan'] }, { name: 'untrust', interfaces: ['wan', 'wan2'] }];
    const { setLines, warnings } = render({ ...natConfig([dnat()], interfaces), zones });
    expect(setLines).toEqual([]);
    expect(warnings.length).toBeGreaterThan(0);
  });

  it('warns and emits nothing for a partly covered range', () => {
    const rule = snat({ translated_src: { type: 'dynamic-ip-pool', addresses: ['203.0.113.6-203.0.113.9'] } });
    const { setLines, warnings } = render(natConfig([rule]));
    expect(setLines).toEqual([]);
    expect(warnings.length).toBeGreaterThan(0);
  });

  it('warns about a range that encloses a whole connected subnet', () => {
    const rule = snat({ translated_src: { type: 'dynamic-ip-pool', addresses: ['203.0.112.250-203.0.113.9'] } });
    const { setLines, warnings } = render(natConfig([rule]));
    expect(setLines).toEqual([]);
    expect(warnings.some(item => /only partly inside/.test(item.message))).toBe(true);
  });

  it('does not proxy a wider prefix as a whole and warns', () => {
    const { setLines, warnings } = render(natConfig([dnat({ dst_addresses: ['203.0.113.0/30'] })]));
    expect(setLines).toEqual([]);
    expect(warnings.length).toBeGreaterThan(0);
  });

  it('emits one entry when several rules use the same address', () => {
    const { setLines } = render(natConfig([dnat({ name: 'a' }), dnat({ name: 'b' }), dnat({ name: 'c', dst_addresses: ['203.0.113.6'] })]));
    expect(setLines).toEqual([`${WAN} 203.0.113.5/32`, `${WAN} 203.0.113.6/32`]);
  });

  it('lets a skipped rule contribute nothing', () => {
    const { setLines } = render(natConfig([dnat({ translated_dst: 'nowhere' })]));
    expect(setLines).toEqual([]);
  });

  it('covers static source pools but not static NAT match destinations', () => {
    // A static rule's dst_addresses is the source rule's destination filter, possibly a real host.
    const rules = [
      { name: 'static', type: 'static', dst_addresses: ['203.0.113.6'], translated_src: { address: '192.168.10.11' } },
      snat({ translated_src: { type: 'static', address: '203.0.113.4' } }),
    ];
    expect(render(natConfig(rules)).setLines).toEqual([`${WAN} 203.0.113.4/32`]);
  });

  it('only proxies on an interface in the rule\'s own zones', () => {
    const zoned = rules => ({
      ...natConfig(rules),
      zones: [{ name: 'trust', interfaces: ['lan'] }, { name: 'untrust', interfaces: ['wan'] }],
    });
    // A trust-only hairpin DNAT never sees WAN traffic, so it must not claim a WAN address.
    expect(render(zoned([dnat({ src_zones: ['trust'] })])).setLines).toEqual([]);
    expect(render(zoned([dnat({ src_zones: ['untrust'] })])).setLines).toEqual([`${WAN} 203.0.113.5/32`]);
    // A pool's egress zone is its to-zone.
    expect(render(zoned([snat({ dst_zones: ['trust'] })])).setLines).toEqual([]);
    expect(render(zoned([snat()])).setLines).toEqual([`${WAN} 203.0.113.3/32 to 203.0.113.4/32`]);
  });

  it('warns instead of guessing when the rule\'s zone has no known interfaces', () => {
    const config = { ...natConfig([dnat()]), zones: [{ name: 'trust', interfaces: ['lan'] }, { name: 'untrust', interfaces: [] }] };
    const { setLines, warnings } = render(config);
    expect(setLines).toEqual([]);
    expect(warnings.some(item => /zone untrust has no known interfaces/.test(item.message))).toBe(true);
  });

  it('reads zone membership from interfaces when zones list none (SonicWall)', () => {
    const interfaces = [{ name: 'wan', zone: 'WAN', ip: '203.0.113.2/29' }, { name: 'lan', zone: 'LAN', ip: '192.168.10.1/24' }];
    const zones = [{ name: 'LAN', interfaces: [] }, { name: 'WAN', interfaces: [] }];
    const hairpin = { ...natConfig([dnat({ src_zones: ['LAN'] })], interfaces), zones };
    expect(render(hairpin).setLines).toEqual([]);
    const inbound = { ...natConfig([dnat({ src_zones: ['WAN'] })], interfaces), zones };
    expect(render(inbound).setLines).toEqual([`${WAN} 203.0.113.5/32`]);
  });

  it('recognises tunnel interfaces by name when the parser does not type them', () => {
    const interfaces = [{ name: 'wan', ip: '203.0.113.2/29' }, { name: 'Tunnel1', type: 'physical', ip: '10.10.10.1/24' }];
    const rules = [snat({ translated_src: { type: 'dynamic-ip-pool', addresses: ['10.10.10.10/32'] } })];
    expect(render(natConfig(rules, interfaces)).setLines).toEqual([]);
  });

  it('never picks a tunnel or loopback interface', () => {
    const interfaces = [{ name: 'wan', ip: '203.0.113.2/29' }, { name: 'tun', type: 'tunnel', ip: '10.10.10.1/24' }, { name: 'lo', type: 'loopback', ip: '10.20.20.1/24' }];
    const rules = [
      snat({ translated_src: { type: 'dynamic-ip-pool', addresses: ['10.10.10.10/32'] } }),
      dnat({ dst_addresses: ['10.20.20.5'] }),
    ];
    expect(render(natConfig(rules, interfaces)).setLines).toEqual([]);
  });

  it('does not proxy provider-interface or interface NAT', () => {
    const rules = [
      snat({ translated_src: { type: 'interface', interface: 'wan' } }),
      snat({ name: 'plain', translated_src: { type: 'interface' } }),
    ];
    expect(render(natConfig(rules)).setLines).toEqual([]);
  });
});

describe('NAT proxy ARP: other vendors', () => {
  // Their parsers hand over "A.B.C.D/len" interface addresses, as FortiGate does.
  it('reads the CIDR interface address from PAN-OS', () => {
    const config = parsePanosConfig(`<config><devices><entry name="localhost.localdomain"><network><interface><ethernet>
      <entry name="ethernet1/1"><layer3><ip><entry name="198.51.100.2/24"/></ip></layer3></entry>
    </ethernet></interface></network><vsys><entry name="vsys1"><zone/></entry></vsys></entry></devices></config>`).intermediateConfig;
    const rules = [dnat({ dst_addresses: ['198.51.100.9'] })];
    const zones = [{ name: 'untrust', interfaces: ['ethernet1/1'] }];
    const { setLines } = render({ ...natConfig(rules), interfaces: config.interfaces, zones });
    expect(setLines).toEqual(['set security nat proxy-arp interface ge-0/0/0.0 address 198.51.100.9/32']);
  });

  it('ignores an unset 0.0.0.0 interface address', () => {
    const config = fortigateConfig({ interfaces: '    edit "port3"\n        set ip 0.0.0.0 0.0.0.0\n    next\n' });
    const { setLines } = render(config);
    expect(setLines).toContain(`${WAN} 203.0.113.5/32`);
  });

  it('proxies an ASA range object used as a pool, and honours sysopt noproxyarp', () => {
    const asa = extra => parseCiscoAsaConfig(`interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.1.1 255.255.255.0
object network LAN
 subnet 192.168.1.0 255.255.255.0
object network PUBRANGE
 range 203.0.113.20 203.0.113.30
nat (inside,outside) source dynamic LAN PUBRANGE
${extra}`).intermediateConfig;
    const { setLines } = render(asa(''));
    expect(setLines).toEqual(['set security nat proxy-arp interface ge-0/0/0.0 address 203.0.113.20/32 to 203.0.113.30/32']);
    const set = convertToSrxSetCommands(asa(''), {}, null, {}).commands;
    expect(set.some(line => /source pool \S+ address 203\.0\.113\.20\/32 to 203\.0\.113\.30\/32$/.test(line))).toBe(true);
    expect(render(asa('sysopt noproxyarp outside\n')).setLines).toEqual([]);
  });

  it('honours ASA no-proxy-arp on a twice NAT pool', () => {
    const asa = option => parseCiscoAsaConfig(`interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.1.1 255.255.255.0
object network LAN
 subnet 192.168.1.0 255.255.255.0
object network PUB
 host 203.0.113.20
nat (inside,outside) source dynamic LAN PUB${option}
`).intermediateConfig;
    expect(render(asa('')).setLines).toEqual(['set security nat proxy-arp interface ge-0/0/0.0 address 203.0.113.20/32']);
    expect(render(asa(' no-proxy-arp')).setLines).toEqual([]);
  });

  it('reads the CIDR interface address from ASA', () => {
    const config = parseCiscoAsaConfig(`interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0
`).intermediateConfig;
    // ASA zone membership is on the interface (zone = nameif), as with SonicWall.
    const rules = [dnat({ src_zones: ['outside'], dst_addresses: ['203.0.113.10'] })];
    const { setLines, xmlBlock } = render({ ...natConfig(rules), interfaces: config.interfaces, zones: [] });
    expect(setLines).toEqual(['set security nat proxy-arp interface ge-0/0/0.0 address 203.0.113.10/32']);
    expect(xmlBlock).toContain('203.0.113.10/32');
  });
});
