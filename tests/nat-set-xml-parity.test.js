import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';
import { parsePanosConfig } from '../src/parsers/panos-parser.js';
import { parseCiscoAsaConfig } from '../src/parsers/cisco-asa-parser.js';
import { parseSrxConfig } from '../src/parsers/srx-parser.js';

// ---------------------------------------------------------------------------
// Normalizers: both outputs become { zones, source, destination, static, pools, comments }
// ---------------------------------------------------------------------------

const COMMENT_PREFIX = /^(NAT:|NAT pool|CAVEAT:|WARNING:)/;

function emptyShape() {
  return { source: [], destination: [], static: [], pools: {}, comments: [] };
}

function ruleSetOf(shape, type, name) {
  let ruleSet = shape[type].find(item => item.name === name);
  if (!ruleSet) {
    ruleSet = { name, from: [], to: [], rules: [] };
    shape[type].push(ruleSet);
  }
  return ruleSet;
}

function ruleOf(ruleSet, name) {
  let rule = ruleSet.rules.find(item => item.name === name);
  if (!rule) {
    rule = { name, source: [], destination: [], protocol: null, port: null, then: null, persistent: false };
    ruleSet.rules.push(rule);
  }
  return rule;
}

function addUnique(list, value) {
  if (!list.includes(value)) list.push(value);
}

function normalizeSet(commands) {
  const shape = emptyShape();
  let inNat = false;
  for (const line of commands) {
    if (line === '# NAT Rules') inNat = true;
    if (line.startsWith('# ')) {
      if (inNat && COMMENT_PREFIX.test(line.slice(2))) shape.comments.push(line.slice(2));
      continue;
    }
    let match = line.match(/^set security nat (source|destination) pool (\S+) address port (\S+)$/);
    if (match) {
      (shape.pools[match[2]] ||= { addresses: [], port: null }).port = match[3];
      continue;
    }
    match = line.match(/^set security nat (source|destination) pool (\S+) address (.+)$/);
    if (match) {
      addUnique((shape.pools[match[2]] ||= { addresses: [], port: null }).addresses, match[3]);
      continue;
    }
    match = line.match(/^set security nat (source|destination|static) rule-set (\S+) (from|to) zone (\S+)$/);
    if (match) {
      addUnique(ruleSetOf(shape, match[1], match[2])[match[3]], match[4]);
      continue;
    }
    match = line.match(/^set security nat (source|destination|static) rule-set (\S+) rule (\S+) (match|then) (.+)$/);
    if (!match) continue;
    const [, type, setName, ruleName, section] = match;
    let rest = match[5];
    const rule = ruleOf(ruleSetOf(shape, type, setName), ruleName);
    const persistentSuffix = ' persistent-nat permit target-host';
    if (section === 'then' && rest.endsWith(persistentSuffix)) {
      rule.persistent = true;
      rest = rest.slice(0, -persistentSuffix.length);
    }
    if (section === 'match') {
      const [field, value] = [rest.split(' ')[0], rest.split(' ').slice(1).join(' ')];
      if (field === 'protocol') rule.protocol = value;
      else if (field === 'destination-port') rule.port = value;
      else if (field.endsWith('-name')) rule[field.replace('-address-name', '')].push(`name:${value}`);
      else rule[field.replace('-address', '')].push(`prefix:${value}`);
    } else if (rest === 'source-nat interface') rule.then = 'interface';
    else if (rest === 'source-nat off') rule.then = 'off';
    else if (rest.startsWith('source-nat pool ')) rule.then = `pool:${rest.slice(16)}`;
    else if (rest.startsWith('destination-nat pool ')) rule.then = `dnat-pool:${rest.slice(21)}`;
    else if (rest.startsWith('static-nat prefix ')) rule.then = `static:${rest.slice(18)}`;
  }
  return shape;
}

// The builder's XML is well formed and line oriented; parse it into { tag, text, children }.
function parseXml(xml) {
  const root = { tag: '#root', text: '', children: [] };
  const stack = [root];
  for (const token of xml.match(/<!--[\s\S]*?-->|<[^>]+>|[^<]+/g) || []) {
    const top = stack[stack.length - 1];
    if (token.startsWith('<!--')) top.children.push({ tag: '#comment', text: token.slice(5, -4).trim(), children: [] });
    else if (token.startsWith('</')) stack.pop();
    else if (token.startsWith('<?')) continue;
    else if (token.startsWith('<')) {
      const node = { tag: token.replace(/^<|\/?>$/g, '').split(' ')[0], text: '', children: [] };
      top.children.push(node);
      if (!token.endsWith('/>')) stack.push(node);
    } else if (token.trim()) top.text += token.trim();
  }
  return root;
}

const child = (node, tag) => node.children.find(item => item.tag === tag);
const childrenOf = (node, tag) => node.children.filter(item => item.tag === tag);

function findNat(root) {
  const stack = [root];
  while (stack.length) {
    const node = stack.pop();
    if (node.tag === 'nat' && node.children.some(item => ['source', 'destination', 'static'].includes(item.tag))) return node;
    stack.push(...node.children);
  }
  return null;
}

function normalizeXml(xml) {
  const shape = emptyShape();
  const nat = findNat(parseXml(xml));
  if (!nat) return shape;
  for (const type of ['source', 'destination', 'static']) {
    const section = child(nat, type);
    // Comments left directly under <nat> belong to a section with nothing live to render.
    if (!section && type === 'static') {
      for (const node of nat.children) {
        if (node.tag === '#comment' && COMMENT_PREFIX.test(node.text)) shape.comments.push(node.text);
      }
    }
    if (!section) continue;
    for (const node of section.children) {
      if (node.tag === '#comment') {
        if (COMMENT_PREFIX.test(node.text)) shape.comments.push(node.text);
      } else if (node.tag === 'pool') {
        const pool = { addresses: [], port: null };
        for (const address of childrenOf(node, 'address')) {
          if (child(address, 'ipaddr')) {
            pool.addresses.push(child(address, 'ipaddr').text);
            if (child(address, 'port')) pool.port = child(address, 'port').text;
          } else {
            const to = child(address, 'to');
            pool.addresses.push(to ? `${child(address, 'name').text} to ${child(to, 'ipaddr').text}` : child(address, 'name').text);
          }
        }
        shape.pools[child(node, 'name').text] = pool;
      } else if (node.tag === 'rule-set') {
        const ruleSet = ruleSetOf(shape, type, child(node, 'name').text);
        ruleSet.from = (child(node, 'from')?.children || []).map(zone => zone.text);
        ruleSet.to = (child(node, 'to')?.children || []).map(zone => zone.text);
        for (const entry of node.children) {
          if (entry.tag === '#comment') {
            if (COMMENT_PREFIX.test(entry.text)) shape.comments.push(entry.text);
          } else if (entry.tag === 'rule') {
            normalizeXmlRule(ruleSet, entry, shape);
          }
        }
      }
    }
  }
  return shape;
}

function normalizeXmlRule(ruleSet, node, shape) {
  const rule = ruleOf(ruleSet, child(node, 'name').text);
  for (const entry of node.children) {
    if (entry.tag === '#comment' && COMMENT_PREFIX.test(entry.text)) shape.comments.push(entry.text);
  }
  const match = child(node, 'src-nat-rule-match') || child(node, 'dest-nat-rule-match') || child(node, 'static-nat-rule-match');
  for (const field of match?.children || []) {
    if (field.tag === 'protocol') rule.protocol = field.text;
    else if (field.tag === 'destination-port') {
      const high = child(field, 'to') && child(child(field, 'to'), 'high').text;
      rule.port = high ? `${child(field, 'name').text} to ${high}` : child(field, 'name').text;
    }
    else if (child(field, 'dst-addr')) rule.destination.push(`prefix:${child(field, 'dst-addr').text}`);
    else if (child(field, 'dst-addr-name')) rule.destination.push(`name:${child(field, 'dst-addr-name').text}`);
    else if (field.tag.endsWith('-address-name')) rule[field.tag.replace('-address-name', '')].push(`name:${field.text}`);
    else rule[field.tag.replace('-address', '')].push(`prefix:${field.text}`);
  }
  const then = child(node, 'then');
  const sourceNat = child(then, 'source-nat');
  if (sourceNat) {
    const target = child(sourceNat, 'interface') || child(sourceNat, 'pool');
    if (child(sourceNat, 'off')) rule.then = 'off';
    else rule.then = target.tag === 'interface' ? 'interface' : `pool:${child(target, 'pool-name').text}`;
    const persistent = target && child(target, 'persistent-nat');
    if (persistent) rule.persistent = Boolean(child(child(persistent, 'permit'), 'target-host'));
  }
  const destinationNat = child(then, 'destination-nat');
  if (destinationNat) rule.then = `dnat-pool:${child(child(destinationNat, 'pool'), 'pool-name').text}`;
  const staticNat = child(then, 'static-nat');
  if (staticNat) rule.then = `static:${child(child(staticNat, 'prefix'), 'addr-prefix').text}`;
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

const FORTIGATE_REPRO = `config system interface
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
config firewall ippool
    edit "pool1"
        set startip 203.0.113.3
        set endip 203.0.113.4
    next
end
config firewall vip
    edit "web"
        set extip 203.0.113.5
        set mappedip "192.168.10.10"
        set extintf "port1"
        set portforward enable
        set protocol tcp
        set extport 443
        set mappedport 8443
    next
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

const PANOS_NAT = `<?xml version="1.0"?>
<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1"><layer3><ip><entry name="198.51.100.2/24"/></ip></layer3></entry>
          </ethernet>
        </interface>
      </network>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="trust"><network><layer3/></network></entry>
            <entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
          </zone>
          <address>
            <entry name="lan"><ip-netmask>10.1.0.0/16</ip-netmask></entry>
          </address>
          <service>
            <entry name="svc-web"><protocol><tcp><port>8080</port></tcp></protocol></entry>
          </service>
          <rulebase>
            <nat>
              <rules>
                <entry name="hide-lan">
                  <from><member>trust</member></from>
                  <to><member>untrust</member></to>
                  <source><member>lan</member></source>
                  <destination><member>any</member></destination>
                  <service>svc-web</service>
                  <source-translation>
                    <dynamic-ip-and-port>
                      <interface-address><interface>ethernet1/1</interface></interface-address>
                    </dynamic-ip-and-port>
                  </source-translation>
                </entry>
              </rules>
            </nat>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>`;

const ASA_NAT = `interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.1.1 255.255.255.0
object network LAN
 subnet 192.168.1.0 255.255.255.0
 nat (inside,outside) dynamic interface
object network WEB
 host 192.168.1.10
 nat (inside,outside) static 203.0.113.10
`;

const SRX_NO_NAT = `set security zones security-zone trust interfaces ge-0/0/1.0
set security zones security-zone untrust interfaces ge-0/0/0.0
set security nat source rule-set rs1 from zone trust
set security nat source rule-set rs1 to zone untrust
set security nat source rule-set rs1 rule vpn-exempt match source-address 10.0.0.0/8
set security nat source rule-set rs1 rule vpn-exempt match destination-address 172.16.0.0/12
set security nat source rule-set rs1 rule vpn-exempt then source-nat off
set security nat source rule-set rs1 rule hide match source-address 10.0.0.0/8
set security nat source rule-set rs1 rule hide then source-nat interface
`;

const zone = name => ({ name, interfaces: [] });
const sourceRule = overrides => ({
  name: 'snat',
  type: 'source',
  src_zones: ['trust'],
  dst_zones: ['untrust'],
  src_addresses: ['any'],
  dst_addresses: ['any'],
  translated_src: { type: 'interface' },
  ...overrides,
});
const handBuilt = (natRules, extra = {}) => ({
  zones: [zone('trust'), zone('untrust')],
  address_objects: [
    { name: 'lan-net', type: 'ip-netmask', value: '192.168.10.0/24' },
    { name: 'web-host', type: 'ip-netmask', value: '192.168.10.10' },
    { name: 'site-fqdn', type: 'fqdn', value: 'example.com' },
  ],
  address_groups: [{ name: 'servers', members: ['lan-net', 'web-host'] }],
  nat_rules: natRules,
  ...extra,
});

const CASES = {
  'FortiGate central SNAT pool + VIP port forward (issue repro)': () => parseFortigateConfig(FORTIGATE_REPRO).intermediateConfig,
  'static NAT': () => handBuilt([{
    name: 'static-web', type: 'static', src_zones: [], dst_zones: [],
    dst_addresses: ['203.0.113.5'], translated_src: { address: '192.168.10.10' },
  }]),
  'static NAT through an address object': () => handBuilt([{
    name: 'static-obj', type: 'static', dst_addresses: ['203.0.113.5'], translated_src: { address: 'web-host' },
  }]),
  'address-group source match': () => handBuilt([sourceRule({ src_addresses: ['servers'] })]),
  'any zone expanded to every zone': () => ({
    ...handBuilt([sourceRule({ src_zones: ['any'], dst_zones: ['any'] })]),
    zones: [zone('trust'), zone('untrust'), zone('dmz')],
  }),
  'any destination zone with a named source zone': () => ({
    ...handBuilt([sourceRule({ dst_zones: ['any'] })]),
    zones: [zone('trust'), zone('untrust'), zone('dmz')],
  }),
  'rule with an unresolvable address is skipped': () => handBuilt([
    sourceRule({ name: 'ghost-rule', src_addresses: ['ghost'] }),
    sourceRule({ name: 'good-rule', src_addresses: ['lan-net'] }),
  ]),
  'FQDN-only match is skipped': () => handBuilt([sourceRule({ dst_addresses: ['site-fqdn'] })]),
  'partially resolvable match keeps the resolved addresses': () => handBuilt([
    sourceRule({ src_addresses: ['ghost', 'lan-net'] }),
  ]),
  'source pool that does not resolve falls back to interface NAT': () => handBuilt([
    sourceRule({ translated_src: { type: 'dynamic-ip-pool', addresses: ['gateway-name'] } }),
  ]),
  'static source translation that does not resolve falls back to interface NAT': () => handBuilt([
    sourceRule({ translated_src: { type: 'static', address: 'nowhere' } }),
  ]),
  'dynamic pool with a range and protocol/port match': () => handBuilt([
    sourceRule({
      translated_src: { type: 'dynamic-ip-pool', addresses: ['203.0.113.3-203.0.113.4', '203.0.113.9/32'] },
      match_protocol: 'tcp', match_port: '443', _uturn: true, caveat: 'review order',
    }),
  ]),
  'provider interface pool': () => handBuilt(
    [sourceRule({ translated_src: { type: 'interface', interface: 'ethernet1/1' } })],
    { interfaces: [{ name: 'ethernet1/1', ip: '198.51.100.2/24' }] },
  ),
  'interface NAT without a static IP': () => handBuilt(
    [sourceRule({ translated_src: { type: 'interface', interface: 'ethernet1/2' } })],
    { interfaces: [{ name: 'ethernet1/2' }] },
  ),
  'destination NAT with port and protocol': () => handBuilt([{
    name: 'dnat', type: 'destination', src_zones: ['untrust'], dst_zones: ['trust'],
    src_addresses: ['any'], dst_addresses: ['203.0.113.5'], translated_dst: '192.168.10.10',
    translated_port: '8443', match_port: '443', match_protocol: 'tcp',
  }]),
  'port ranges in source and destination NAT': () => handBuilt([
    sourceRule({ name: 'snat-range', match_protocol: 'tcp', match_port: '8000-8010' }),
    {
      name: 'dnat-range', type: 'destination', src_zones: ['untrust'], dst_zones: ['trust'],
      src_addresses: ['any'], dst_addresses: ['203.0.113.5'], translated_dst: '192.168.10.10',
      match_protocol: 'udp', match_port: '5000-5004',
    },
  ]),
  'persistent NAT on interface and pool': () => handBuilt([
    sourceRule({ name: 'uturn-if', _uturn: true }),
    sourceRule({
      name: 'uturn-pool', _uturn: true,
      translated_src: { type: 'dynamic-ip-pool', addresses: ['203.0.113.9/32'] },
    }),
  ]),
  'several destination addresses keep the first': () => handBuilt([
    {
      name: 'dnat-many', type: 'destination', src_zones: ['untrust'], dst_zones: ['trust'],
      src_addresses: ['any'], dst_addresses: ['203.0.113.5', '203.0.113.6'], translated_dst: '192.168.10.10',
    },
    {
      name: 'static-many', type: 'static', dst_addresses: ['203.0.113.7', '203.0.113.8'],
      translated_src: { address: '192.168.10.11' },
    },
  ]),
  'destination NAT whose translated address does not resolve is skipped': () => handBuilt([{
    name: 'dnat-bad', type: 'destination', src_zones: ['untrust'], dst_zones: ['trust'],
    src_addresses: ['any'], dst_addresses: ['203.0.113.5'], translated_dst: 'nowhere',
  }]),
  'source-and-destination rule': () => handBuilt([{
    name: 'both', type: 'source-and-destination', src_zones: ['untrust'], dst_zones: ['trust'],
    src_addresses: ['any'], dst_addresses: ['203.0.113.5'], translated_dst: '192.168.10.10',
    translated_src: { type: 'interface' },
  }]),
  'IPv6 any address': () => handBuilt([sourceRule({ src_addresses: undefined, dst_addresses: ['2001:db8::/64'] })]),
  'PAN-OS NAT': () => parsePanosConfig(PANOS_NAT).intermediateConfig,
  'Cisco ASA NAT': () => parseCiscoAsaConfig(ASA_NAT).intermediateConfig,
  'SRX source-nat off exemption before interface NAT': () => parseSrxConfig(SRX_NO_NAT).intermediateConfig,
  'no zones to expand any': () => ({ ...handBuilt([sourceRule({ src_zones: ['any'], dst_zones: ['any'] })]), zones: [] }),
};

// XML keeps unmapped source interface names, so map them explicitly for both outputs.
const render = config => {
  const mappings = Object.fromEntries((config.interfaces || []).map((iface, index) => [iface.name, `ge-0/0/${index}`]));
  const set = convertToSrxSetCommands(structuredClone(config), mappings, null, {});
  const xml = buildSrxXml(structuredClone(config), mappings);
  return { set, xml };
};

describe('NAT: set commands and XML render the same plan', () => {
  for (const [label, build] of Object.entries(CASES)) {
    it(label, () => {
      const config = build();
      const { set, xml } = render(config);
      const fromSet = normalizeSet(set.commands);
      const fromXml = normalizeXml(xml.xml);
      expect(fromXml).toEqual(fromSet);
    });
  }

  it('every case plans at least one rule-set or comment, so the comparison is not vacuous', () => {
    for (const [label, build] of Object.entries(CASES)) {
      const shape = normalizeSet(render(build()).set.commands);
      const planned = shape.source.length + shape.destination.length + shape.static.length + shape.comments.length;
      expect(planned, label).toBeGreaterThan(0);
    }
  });

  it('compares something: the repro produces rule-sets and pools on both sides', () => {
    const { set, xml } = render(CASES['FortiGate central SNAT pool + VIP port forward (issue repro)']());
    const shape = normalizeSet(set.commands);
    expect(shape.source[0].rules).toHaveLength(1);
    expect(shape.destination[0].rules).toHaveLength(1);
    expect(Object.keys(shape.pools)).toHaveLength(2);
    expect(normalizeXml(xml.xml)).toEqual(shape);
  });
});

describe('NAT XML: the issue symptoms', () => {
  const repro = () => {
    const { intermediateConfig } = parseFortigateConfig(FORTIGATE_REPRO);
    return buildSrxXml(intermediateConfig, {}).xml;
  };

  it('writes IP prefixes, not object names or mangled literals, into address elements', () => {
    const fullXml = repro();
    const xml = fullXml.slice(fullXml.indexOf("<nat>"));
    expect(xml).not.toMatch(/<(source|destination)-address>(lan-net|all|n-[^<]*)</);
    expect(xml).toContain('<source-address>192.168.10.0/24</source-address>');
    expect(xml).toContain('<destination-address><dst-addr>203.0.113.5</dst-addr></destination-address>');
    expect(xml).toContain('<destination-port><name>443</name></destination-port>');
    expect(xml).toContain('<address><ipaddr>192.168.10.10/32</ipaddr><port>8443</port></address>');
  });

  it('puts group names in the -name elements', () => {
    const { xml } = render(CASES['address-group source match']());
    expect(xml.xml).toContain('<source-address-name>servers</source-address-name>');
    expect(xml.xml).not.toContain('<source-address>servers</source-address>');
  });

  it('expands zone "any" to real zones', () => {
    const { xml } = render(CASES['any zone expanded to every zone']());
    const natXml = xml.xml.slice(xml.xml.indexOf('<nat>'));
    expect(natXml).not.toContain('<zone>any</zone>');
    expect(natXml).toContain('<from><zone>trust</zone><zone>untrust</zone><zone>dmz</zone></from>');
  });

  it('keeps the match protocol', () => {
    expect(repro()).toContain('<protocol>tcp</protocol>');
  });

  it('falls back to interface NAT with a comment when a pool does not resolve', () => {
    const { xml } = render(CASES['source pool that does not resolve falls back to interface NAT']());
    expect(xml.xml).toContain('<source-nat><interface/></source-nat>');
    expect(xml.xml).toContain('<!-- NAT pool address could not be resolved — using interface NAT -->');
  });

  it('skips a destination rule whose translated address does not resolve', () => {
    const { xml } = render(CASES['destination NAT whose translated address does not resolve is skipped']());
    expect(xml.xml).not.toContain('<name>dnat-bad</name>');
    expect(xml.xml).toContain('<!-- NAT: destination rule "dnat-bad" skipped');
  });

  it('renders the provider-interface pool', () => {
    const { xml } = render(CASES['provider interface pool']());
    expect(xml.xml).toContain('<address><name>198.51.100.2/32</name></address>');
  });

  it('resolves the static source pool and static-nat prefix', () => {
    const { xml } = render(CASES['static NAT through an address object']());
    expect(xml.xml).toContain('<addr-prefix>192.168.10.10</addr-prefix>');
  });
});

describe('NAT: Junos schema shapes', () => {
  it('nests persistent-nat under source-nat and uses the set keyword order', () => {
    const { set, xml } = render(CASES['persistent NAT on interface and pool']());
    expect(set.commands).toContain('set security nat source rule-set trust-to-untrust rule uturn-if then source-nat interface persistent-nat permit target-host');
    expect(set.commands.some(line => / then source-nat pool \S+ persistent-nat permit target-host$/.test(line))).toBe(true);
    expect(set.commands.some(line => / then persistent-nat /.test(line))).toBe(false);
    expect(xml.xml).toContain('<source-nat><interface><persistent-nat><permit><target-host/></permit></persistent-nat></interface></source-nat>');
    expect(xml.xml).toMatch(/<pool-name>[^<]+<\/pool-name><persistent-nat><permit><target-host\/><\/permit><\/persistent-nat><\/pool>/);
  });

  it('renders port ranges as "A to B" and <to><high>', () => {
    const { set, xml } = render(CASES['port ranges in source and destination NAT']());
    expect(set.commands.some(line => line.endsWith('rule snat-range match destination-port 8000 to 8010'))).toBe(true);
    expect(set.commands.some(line => line.endsWith('rule dnat-range match destination-port 5000 to 5004'))).toBe(true);
    expect(xml.xml).toContain('<destination-port><name>8000</name><to><high>8010</high></to></destination-port>');
    expect(xml.xml).toContain('<destination-port><name>5000</name><to><high>5004</high></to></destination-port>');
  });

  it('keeps one destination address and warns about the dropped ones', () => {
    const { set, xml } = render(CASES['several destination addresses keep the first']());
    for (const output of [set, xml]) {
      const messages = output.warnings.map(item => item.message);
      expect(messages.some(text => /dnat-many.*kept 203\.0\.113\.5, dropped 203\.0\.113\.6/.test(text))).toBe(true);
      expect(messages.some(text => /static-many.*kept 203\.0\.113\.7, dropped 203\.0\.113\.8/.test(text))).toBe(true);
    }
    expect(set.commands.filter(line => line.includes('rule dnat-many match destination-address'))).toHaveLength(1);
    expect(xml.xml).not.toContain('203.0.113.6');
  });
});

describe('NAT: a rule is never widened', () => {
  it('skips an unresolvable rule in both outputs and warns once per output', () => {
    const { set, xml } = render(CASES['rule with an unresolvable address is skipped']());
    expect(set.commands.some(line => line.includes('rule ghost-rule'))).toBe(false);
    expect(xml.xml).not.toContain('<name>ghost-rule</name>');
    expect(set.warnings.filter(item => /ghost-rule/.test(item.message))).toHaveLength(1);
    expect(xml.warnings.filter(item => /ghost-rule/.test(item.message))).toHaveLength(1);
  });
  it('keeps an SRX source-nat off exemption in both outputs', () => {
    const { set, xml } = render(parseSrxConfig(SRX_NO_NAT).intermediateConfig);
    expect(set.commands.some(line => /rule \S*vpn-exempt then source-nat off$/.test(line))).toBe(true);
    expect(set.commands.some(line => /rule \S*vpn-exempt then source-nat interface/.test(line))).toBe(false);
    expect(xml.xml).toContain('<source-nat><off/></source-nat>');
  });
});
