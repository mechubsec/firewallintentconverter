import { describe, it, expect } from 'vitest';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';

const CONFIG = `config system interface
    edit "port1"
        set alias "wan"
        set ip 203.0.113.2 255.255.255.248
    next
    edit "port2"
        set alias "lan"
        set ip 192.168.10.1 255.255.255.0
    next
end
config firewall address
    edit "lan-net"
        set subnet 192.168.10.0 255.255.255.0
    next
    edit "web-01"
        set subnet 192.168.10.20 255.255.255.255
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
end
config firewall policy
    edit 1
        set name "web-inbound"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "lan-net"
        set dstaddr "web-01"
        set action accept
        set service "HTTPS"
    next
end`;

function convert(mutate = (config) => config) {
  const config = mutate(parseFortigateConfig(CONFIG).intermediateConfig);
  return convertToSrxSetCommands(config, {}, null, {}).commands;
}

describe('FortiGate to SRX output', () => {
  it('keeps interface masks', () => {
    const commands = convert();
    expect(commands.some((line) => line.endsWith('family inet address 203.0.113.2/29'))).toBe(true);
    expect(commands.some((line) => line.endsWith('family inet address 192.168.10.1/24'))).toBe(true);
  });

  it('keeps address-object masks', () => {
    const commands = convert();
    expect(commands).toContain('set security address-book global address lan-net 192.168.10.0/24');
    expect(commands).toContain('set security address-book global address web-01 192.168.10.20/32');
  });

  it('never labels FortiGate output as PAN-OS or prints the internal implicit-rule tag', () => {
    const text = convert().join('\n');
    expect(text).not.toContain('PAN-OS');
    expect(text).not.toContain('added_by_fpic');
  });

  it('matches VIP destination NAT from the ingress zone only', () => {
    const fromZones = convert().filter((line) => /^set security nat destination rule-set \S+ from zone /.test(line));
    expect(fromZones).toHaveLength(1);
    expect(fromZones[0]).toMatch(/ from zone port1$/);
  });

  it('labels source tags by vendor', () => {
    const withTag = (vendor) => (config) => ({
      ...config,
      metadata: { ...config.metadata, source_vendor: vendor },
      security_policies: config.security_policies.map((policy) =>
        policy.name === 'web-inbound' ? { ...policy, tags: ['web'] } : policy),
    });
    expect(convert(withTag('panos')).join('\n')).toContain('[PAN-OS tags: web]');
    expect(convert(withTag('fortigate')).join('\n')).toContain('[Source tags: web]');
  });

  it('resolves a VIP external interface to its explicit zone', () => {
    const zoned = CONFIG.replace('config firewall address', `config system zone
    edit "WAN"
        set interface "port1"
    next
end
config firewall address`);
    const commands = convertToSrxSetCommands(parseFortigateConfig(zoned).intermediateConfig, {}, null, {}).commands;
    const fromZones = commands.filter((line) => /^set security nat destination rule-set \S+ from zone /.test(line));
    expect(fromZones).toHaveLength(1);
    expect(fromZones[0]).toMatch(/ from zone WAN$/);
    expect(commands.some((line) => /security zones security-zone port1\b/.test(line))).toBe(false);
  });

  it('keeps added_by_fpic on a real policy but hides it on implicit rules', () => {
    const tagged = (config) => ({
      ...config,
      security_policies: config.security_policies.map((policy) =>
        policy.name === 'web-inbound' ? { ...policy, tags: ['added_by_fpic'] } : policy),
    });
    const text = convert(tagged).join('\n');
    expect(text).toContain('added_by_fpic');
    expect(convert().join('\n')).not.toContain('added_by_fpic');
  });

  describe('VIP interface scope inside a zone', () => {
    const withZone = (members) => CONFIG.replace('config firewall address', `config system zone
    edit "WAN"
        set interface ${members.map((member) => `"${member}"`).join(' ')}
    next
end
config firewall address`);
    const parse = (text) => parseFortigateConfig(text).intermediateConfig;
    const run = (config) => convertToSrxSetCommands(config, {}, null, {});
    const isWidening = (warning) => JSON.stringify(warning).includes('limited to interface');
    const CAVEAT = '# CAVEAT: VIP vip-web-01 was limited to interface port1; this rule-set matches all of zone WAN — scope it with "from interface ge-0/0/0.0"';

    it('uses the zone as from-zone and flags a multi-member zone in set output', () => {
      const { commands, warnings } = run(parse(withZone(['port1', 'port3'])));
      expect(commands.filter((line) => line.includes('nat destination') && / from zone WAN$/.test(line))).toHaveLength(1);
      expect(commands).toContain(CAVEAT);
      expect(warnings.some(isWidening)).toBe(true);
    });

    it('returns the same warning from the XML builder', () => {
      const { warnings } = buildSrxXml(parse(withZone(['port1', 'port3'])));
      expect(warnings.some(isWidening)).toBe(true);
    });

    it('evaluates membership at conversion time, not parse time', () => {
      const config = parse(withZone(['port1']));
      expect(run(config).warnings.some(isWidening)).toBe(false);
      const zone = config.zones.find((candidate) => candidate.name === 'WAN');
      zone.interfaces = [...zone.interfaces, 'port3'];
      expect(run(config).warnings.some(isWidening)).toBe(true);
      expect(buildSrxXml(config).warnings.some(isWidening)).toBe(true);
    });

    const withMapping = { port1: 'ge-0/0/5', port3: 'ge-0/0/7' };
    const runMapped = (config) => convertToSrxSetCommands(config, withMapping, null, {});
    const twoVips = (secondInterface) => parse(withZone(['port1', 'port3', 'port4']).replace(
      'config firewall policy', `config firewall vip
    edit "vip-web-02"
        set extip 203.0.113.4
        set extintf "${secondInterface}"
        set mappedip "192.168.10.20"
    next
end
config firewall policy`));

    it('warns when the ingress interface was moved out of the from-zone', () => {
      const config = parse(withZone(['port1', 'port3']));
      config.zones.find((candidate) => candidate.name === 'WAN').interfaces = ['port3', 'port4'];
      const { commands, warnings } = run(config);
      expect(commands.some((line) => line.startsWith('# CAVEAT: ') && line.includes('not in zone WAN') && line.includes("matches that zone's interfaces instead"))).toBe(true);
      expect(warnings.some((warning) => JSON.stringify(warning).includes('not in zone WAN'))).toBe(true);
      expect(buildSrxXml(config).warnings.some((warning) => JSON.stringify(warning).includes('not in zone WAN'))).toBe(true);
    });

    it('warns when the zone was reduced to one member that is not the ingress interface', () => {
      const config = parse(withZone(['port1']));
      config.zones.find((candidate) => candidate.name === 'WAN').interfaces = ['port3'];
      expect(run(config).warnings.some((warning) => JSON.stringify(warning).includes('not in zone WAN'))).toBe(true);
    });

    it('suggests the mapped SRX interface name in set and XML', () => {
      const config = parse(withZone(['port1', 'port3']));
      const set = runMapped(config);
      expect(set.commands.some((line) => line.startsWith('# CAVEAT: ') && line.includes('"from interface ge-0/0/5.0"'))).toBe(true);
      expect(set.warnings.some((warning) => JSON.stringify(warning).includes('from interface ge-0/0/5.0'))).toBe(true);
      expect(set.commands.some((line) => line.includes('from interface port1'))).toBe(false);
      const xml = buildSrxXml(config, withMapping);
      expect(xml.warnings.some((warning) => JSON.stringify(warning).includes('from interface ge-0/0/5.0'))).toBe(true);
      expect(xml.warnings.some((warning) => JSON.stringify(warning).includes('from interface port1'))).toBe(false);
    });

    it('advises splitting the rule-set when VIPs in it widen from different interfaces', () => {
      const config = twoVips('port3');
      const set = runMapped(config);
      const caveats = set.commands.filter((line) => line.startsWith('# CAVEAT: '));
      expect(caveats).toHaveLength(1);
      expect(caveats[0]).toContain('split');
      expect(caveats[0]).toContain('vip-web-01');
      expect(caveats[0]).toContain('vip-web-02');
      expect(caveats[0]).toContain('ge-0/0/5.0');
      expect(caveats[0]).toContain('ge-0/0/7.0');
      expect(set.commands.some((line) => line.includes('scope it with'))).toBe(false);
      const widening = set.warnings.filter((warning) => /split/i.test(JSON.stringify(warning)));
      expect(widening).toHaveLength(1);
      expect(set.warnings.some((warning) => JSON.stringify(warning).includes('scope the rule-set with'))).toBe(false);
      const xmlWarnings = buildSrxXml(config, withMapping).warnings;
      expect(xmlWarnings.filter((warning) => /split/i.test(JSON.stringify(warning)))).toHaveLength(1);
      expect(xmlWarnings.some((warning) => JSON.stringify(warning).includes('Scope the rule-set with'))).toBe(false);
    });

    it('keeps per-interface advice when VIPs in a rule-set share the same interface', () => {
      const config = twoVips('port1');
      const set = runMapped(config);
      const caveats = set.commands.filter((line) => line.startsWith('# CAVEAT: '));
      expect(caveats).toHaveLength(2);
      expect(caveats.every((line) => line.includes('"from interface ge-0/0/5.0"'))).toBe(true);
      expect(buildSrxXml(config, withMapping).warnings.filter((warning) => JSON.stringify(warning).includes('from interface ge-0/0/5.0'))).toHaveLength(2);
    });

    it('stays silent for a single-member zone and for a zone-less interface', () => {
      for (const text of [withZone(['port1']), CONFIG]) {
        const { commands, warnings } = run(parse(text));
        expect(commands.some((line) => line.includes('scope it with'))).toBe(false);
        expect(warnings.some(isWidening)).toBe(false);
        expect(buildSrxXml(parse(text)).warnings.some(isWidening)).toBe(false);
      }
    });
  });
});
