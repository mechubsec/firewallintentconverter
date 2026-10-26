import { describe, it, expect } from 'vitest';
import { exportToTerraform } from '../public/utils/iac-export.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

function buildConfig(policies) {
  return {
    metadata: { source_vendor: 'fortigate' },
    zones: [{ name: 'lan', interfaces: [] }, { name: 'wan', interfaces: [] }],
    address_objects: [
      { name: 'bad-host', type: 'ip-netmask', value: '198.51.100.7/32' },
      { name: 'lan-net', type: 'ip-netmask', value: '192.168.10.0/24' },
    ],
    address_groups: [],
    service_objects: [],
    service_groups: [],
    applications: [],
    security_policies: policies.map((overrides) => ({
      action: 'deny',
      src_zones: ['lan'],
      dst_zones: ['wan'],
      src_addresses: ['bad-host'],
      dst_addresses: ['lan-net'],
      negate_source: false,
      negate_destination: false,
      applications: [],
      services: ['any'],
      disabled: false,
      ...overrides,
    })),
  };
}

const convert = (policies, policyStructure = 'zone-pair') => (
  convertToSrxSetCommands(buildConfig(policies), {}, null, { policyStructure }).commands
);

const POL = 'set security policies from-zone lan to-zone wan policy';
const rawConfigOf = (hcl) => hcl.match(/resource "junos_null_load_config" "additional" \{[\s\S]*?\n\}/)?.[0] ?? '';
const policyResources = (hcl) => hcl.match(/resource "junos_security_policy"/g) ?? [];

describe('exportToTerraform policies', () => {
  it('keeps negation from converter output in a structured block', () => {
    const hcl = exportToTerraform(convert([
      { name: 'deny-except-src', negate_source: true },
      { name: 'deny-except-dst', negate_destination: true },
    ]));
    expect(policyResources(hcl)).toHaveLength(1);
    const [sourcePolicy, destinationPolicy] = hcl.split('  policy {').slice(1);
    expect(sourcePolicy).toContain('match_source_address_excluded      = true');
    expect(sourcePolicy).not.toContain('match_destination_address_excluded');
    expect(sourcePolicy).toContain('then                      = "deny"');
    expect(destinationPolicy).toContain('match_destination_address_excluded = true');
    expect(destinationPolicy).not.toContain('match_source_address_excluded');
  });

  it('emits one resource per zone pair with policies in input order', () => {
    const hcl = exportToTerraform([
      `${POL} first match source-address a`,
      `${POL} first match destination-address b`,
      `${POL} first then permit`,
      `${POL} second match source-address a`,
      `${POL} second match destination-address b`,
      `${POL} second then deny`,
      'set security policies from-zone wan to-zone lan policy back match source-address any',
      'set security policies from-zone wan to-zone lan policy back match destination-address any',
      'set security policies from-zone wan to-zone lan policy back then permit',
    ]);
    expect(policyResources(hcl)).toHaveLength(2);
    expect(hcl.indexOf('name                      = "first"')).toBeLessThan(hcl.indexOf('name                      = "second"'));
    expect(hcl).toContain('resource "junos_security_policy" "lan_to_wan"');
    expect(hcl).toContain('resource "junos_security_policy" "wan_to_lan"');
    expect(hcl).not.toContain('junos_null_load_config');
  });

  it('suffixes zone-pair resource names that sanitize identically', () => {
    const hcl = exportToTerraform([
      'set security policies from-zone a-b to-zone c policy p then permit',
      'set security policies from-zone a_b to-zone c policy p then permit',
    ]);
    expect(hcl).toContain('"a_b_to_c"');
    expect(hcl).toContain('"a_b_to_c_2"');
  });

  it('exports a deactivated policy zone pair as raw lines in original order', () => {
    const commands = [
      'set system host-name fw1',
      ...convert([{ name: 'disabled-rule', disabled: true }, { name: 'ok-rule' }]),
    ].filter((cmd) => cmd.startsWith('set') || cmd.startsWith('deactivate'));
    const hcl = exportToTerraform(commands);
    expect(policyResources(hcl)).toHaveLength(0);
    expect(hcl).toContain('# Zone pair lan -> wan exported as raw set commands: contains deactivated policy');
    const raw = rawConfigOf(hcl);
    const policyLines = commands.filter((cmd) => cmd.includes('security policies'));
    expect(policyLines.some((cmd) => cmd.startsWith('deactivate'))).toBe(true);
    let cursor = raw.indexOf('set system host-name fw1');
    expect(cursor).toBeGreaterThan(-1);
    for (const line of policyLines) {
      const next = raw.indexOf(`"${line}"`, cursor);
      expect(next, line).toBeGreaterThan(-1);
      cursor = next;
    }
  });

  it.each([
    ['scheduler-name', `${POL} p scheduler-name business-hours`],
    ['source-identity', `${POL} p match source-identity "alice"`],
    ['unknown then', `${POL} p then permit tunnel ipsec-vpn x`],
  ])('falls back to raw for %s', (_label, extraLine) => {
    const hcl = exportToTerraform([
      `${POL} p match source-address a`,
      `${POL} p then permit`,
      extraLine,
    ]);
    expect(policyResources(hcl)).toHaveLength(0);
    expect(hcl).toContain('# Zone pair lan -> wan exported as raw set commands');
    const raw = rawConfigOf(hcl);
    expect(raw).toContain(JSON.stringify(extraLine)); // same escaping as HCL for these lines (no ${ or %{)
    expect(raw).toContain(`"${POL} p match source-address a"`);
  });

  it('maps count, log, description and application-services', () => {
    const hcl = exportToTerraform([
      `${POL} p description "Allow web"`,
      `${POL} p match source-address a`,
      `${POL} p match destination-address b`,
      `${POL} p match application junos-http`,
      `${POL} p then permit`,
      `${POL} p then log session-init`,
      `${POL} p then log session-close`,
      `${POL} p then count`,
      `${POL} p then permit application-services utm-policy utm1`,
      `${POL} p then permit application-services idp-policy idp1`,
      `${POL} p then permit application-services security-intelligence-policy si1`,
    ]);
    expect(hcl).toContain('description = "Allow web"');
    expect(hcl).toContain('log_init  = true');
    expect(hcl).toContain('log_close = true');
    expect(hcl).toContain('count     = true');
    expect(hcl).toContain('match_application         = ["junos-http"]');
    expect(hcl).toMatch(/permit_application_services \{\n\s+utm_policy = "utm1"\n\s+idp_policy = "idp1"\n\s+security_intelligence_policy = "si1"\n\s+\}/);
  });

  it('puts global-structure policies in the raw block', () => {
    const commands = convert([{ name: 'g1' }], 'global');
    const hcl = exportToTerraform(commands);
    expect(policyResources(hcl)).toHaveLength(0);
    expect(rawConfigOf(hcl)).toContain('set security policies global policy g1 then deny');
  });

  it('never emits nonexistent resources', () => {
    const hcl = exportToTerraform([
      'set security address-book global address h1 10.0.0.1/32',
      'set security zones security-zone lan interfaces ge-0/0/1.0',
      'set security zones security-zone lan host-inbound-traffic system-services ssh',
      'set system host-name fw1',
    ]);
    expect(hcl).not.toContain('junos_config');
    expect(hcl).not.toContain('junos_security_global_address_book');
    const raw = rawConfigOf(hcl);
    expect(hcl).toContain('network_address {\n    name = "h1"');
    expect(raw).toContain('"set security zones security-zone lan host-inbound-traffic system-services ssh"');
    expect(raw).toContain('action = "set"');
  });

  it('keeps a zone with non-interface lines entirely raw, in order', () => {
    const hcl = exportToTerraform([
      'set security zones security-zone lan interfaces ge-0/0/1.0',
      'set security zones security-zone lan host-inbound-traffic system-services ssh',
      'set security zones security-zone wan interfaces ge-0/0/0.0',
    ]);
    expect(hcl).not.toContain('resource "junos_security_zone" "lan"');
    expect(hcl).toContain('resource "junos_security_zone" "wan"');
    const raw = rawConfigOf(hcl);
    expect(raw.indexOf('security-zone lan interfaces ge-0/0/1.0'))
      .toBeLessThan(raw.indexOf('security-zone lan host-inbound-traffic'));
  });

  it('handles zone and policy names that collide with Object.prototype', () => {
    const hcl = exportToTerraform([
      'set security zones security-zone constructor interfaces ge-0/0/1.0',
      'set security policies from-zone constructor to-zone toString policy constructor match source-address any',
      'set security policies from-zone constructor to-zone toString policy constructor match destination-address any',
      'set security policies from-zone constructor to-zone toString policy constructor then deny',
    ]);
    expect(hcl).toContain('resource "junos_security_zone" "constructor"');
    expect(hcl).toContain('name                      = "constructor"');
    expect(hcl).toContain('then                      = "deny"');
  });

  it('does not let a policy without an action default to permit', () => {
    const hcl = exportToTerraform([
      `${POL} p match source-address any`,
      `${POL} p match destination-address any`,
      `${POL} p match application any`,
    ]);
    expect(policyResources(hcl)).toHaveLength(0);
    expect(hcl).not.toContain('then                      = "permit"');
    expect(rawConfigOf(hcl)).toContain(`${POL} p match application any`);
  });

  it('escapes HCL interpolation in descriptions and raw lines', () => {
    const hcl = exportToTerraform([
      `${POL} p description "\${file(\\"/etc/passwd\\")} %{if true}x%{endif}"`,
      `${POL} p then permit`,
      'set system login message "${file(\\"/etc/shadow\\")}"',
    ]);
    expect(hcl).toContain('description = "$${file(\\"/etc/passwd\\")} %%{if true}x%%{endif}"');
    expect(hcl).toContain('"set system login message \\"$${file(');
    expect(hcl).not.toMatch(/[^$]\$\{file/);
  });

  it('orders raw block after zones and policies after the raw block', () => {
    const hcl = exportToTerraform([
      'set security zones security-zone lan interfaces ge-0/0/1.0',
      'set system host-name fw1',
      `${POL} p then permit`,
    ]);
    const raw = rawConfigOf(hcl);
    expect(raw).toContain('depends_on = [junos_security_zone.lan]');
    const policyBlock = hcl.slice(hcl.indexOf('resource "junos_security_policy"'));
    expect(policyBlock).toContain('depends_on = [junos_security_zone.lan, junos_null_load_config.additional]');
  });
});

describe('exportToTerraform address book', () => {
  const bookConfig = () => {
    const config = buildConfig([{ name: 'p', src_addresses: ['host1'], dst_addresses: ['lan-net'] }]);
    config.address_objects = [
      { name: 'host1', type: 'ip-netmask', value: '198.51.100.7/32' },
      { name: 'lan-net', type: 'ip-netmask', value: '192.168.10.0/24', description: 'say "hi" ${file("/etc/passwd")}' },
      { name: 'pool', type: 'range', value: '10.0.0.1-10.0.0.9' },
      { name: 'web', type: 'fqdn', value: 'example.com', fqdn_ip_version: 'v4' },
    ];
    config.address_groups = [
      { name: 'inner', members: ['host1', 'pool'] },
      { name: 'outer', members: ['inner', 'lan-net', 'web'], description: 'all of it' },
    ];
    return config;
  };
  const bookCommands = () => (
    convertToSrxSetCommands(bookConfig(), {}, null, { policyStructure: 'zone-pair' }).commands
  );
  const bookResourceOf = (hcl) => hcl.match(/resource "junos_security_address_book" "global" \{[\s\S]*?\n\}/)?.[0] ?? '';

  it('maps host, network, range, FQDN and address-set lines to one resource', () => {
    const hcl = exportToTerraform(bookCommands());
    const book = bookResourceOf(hcl);
    expect(hcl.match(/resource "junos_security_address_book"/g)).toHaveLength(1);
    expect(book).toContain('name = "global"');
    expect(book).toMatch(/network_address \{\n    name = "host1"\n    value = "198.51.100.7\/32"\n  \}/);
    expect(book).toMatch(/range_address \{\n    name = "pool"\n    from = "10.0.0.1"\n    to = "10.0.0.9"\n  \}/);
    expect(book).toMatch(/dns_name \{\n    name = "web"\n    value = "example.com"\n    ipv4_only = true\n  \}/);
    expect(book).toMatch(/address_set \{\n    name = "outer"\n    address = \["lan-net", "web"\]\n    address_set = \["inner"\]\n    description = "all of it"\n  \}/);
    expect(book).toContain('address = ["host1", "pool"]');
    expect(hcl).not.toContain('junos_security_global_address_book');
  });

  it('escapes quotes and template sequences in descriptions', () => {
    const book = bookResourceOf(exportToTerraform(bookCommands()));
    expect(book).toContain('description = "say \\"hi\\" $${file(\\"/etc/passwd\\")}"');
  });

  it('maps prefixless hosts with /32 and /128', () => {
    const hcl = exportToTerraform([
      'set security address-book global address h4 192.168.10.10',
      'set security address-book global address h6 2001:db8::10',
    ]);
    expect(bookResourceOf(hcl)).toContain('name = "h4"\n    value = "192.168.10.10/32"');
    expect(bookResourceOf(hcl)).toContain('name = "h6"\n    value = "2001:db8::10/128"');
    expect(rawConfigOf(hcl)).toBe('');
  });

  it('maps wildcard-address lines', () => {
    const hcl = exportToTerraform(['set security address-book global address w wildcard-address 192.0.2.0/255.255.0.255']);
    expect(bookResourceOf(hcl)).toContain('wildcard_address {\n    name = "w"\n    value = "192.0.2.0/255.255.0.255"');
    expect(rawConfigOf(hcl)).toBe('');
  });

  it('makes policies and the raw block depend on the address book', () => {
    const hcl = exportToTerraform([...bookCommands(), 'set system host-name fw1']);
    expect(rawConfigOf(hcl)).toContain('depends_on = [junos_security_zone.lan, junos_security_zone.wan, junos_security_address_book.global]');
    const policyBlock = hcl.slice(hcl.indexOf('resource "junos_security_policy"'));
    expect(policyBlock).toContain('junos_security_address_book.global');
  });

  it('keeps every address-book line either mapped or raw', () => {
    const commands = [
      ...bookCommands(),
      'set security address-book global address odd 192.0.2.1/32 extra',
      'set security address-book branch address b 192.0.2.5/32',
      'set security address-book branch attach zone lan',
    ];
    const hcl = exportToTerraform(commands);
    const raw = rawConfigOf(hcl);
    // an unmapped global line keeps the whole global book raw, with a note
    expect(hcl).not.toContain('junos_security_address_book');
    expect(hcl).toContain('# Global address book exported as raw set commands');
    for (const cmd of commands.filter(line => line.startsWith('set security address-book'))) {
      expect(raw).toContain(cmd.replace(/[\\"]/g, '\\$&').replace('${', () => '$${'));
    }
  });

  it('structures the global book while zone-scoped books stay raw', () => {
    const scoped = ['set security address-book branch address b 192.0.2.5/32', 'set security address-book branch attach zone lan'];
    const hcl = exportToTerraform([...bookCommands(), ...scoped]);
    expect(bookResourceOf(hcl)).toContain('network_address');
    for (const cmd of scoped) expect(rawConfigOf(hcl)).toContain(cmd);
    expect(rawConfigOf(hcl)).not.toContain('address-book global');
  });

  it('keeps a deactivated global book raw', () => {
    const hcl = exportToTerraform([
      'set security address-book global address a 192.0.2.1/32',
      'deactivate security address-book global address a',
    ]);
    expect(bookResourceOf(hcl)).toBe('');
    expect(rawConfigOf(hcl)).toContain('deactivate security address-book global address a');
  });

  it('keeps the book raw when raw lines (global policies) reference it', () => {
    const commands = convertToSrxSetCommands(bookConfig(), {}, null, {}).commands;
    const hcl = exportToTerraform(commands);
    expect(hcl).not.toContain('resource "junos_security_address_book"');
    expect(hcl).toMatch(/# Global address book exported as raw set commands: referenced by raw command/);
    expect(rawConfigOf(hcl)).toContain('set security address-book global address host1');
  });

  it('emits no address book resource when there are no address-book lines', () => {
    expect(exportToTerraform(['set system host-name fw1'])).not.toContain('junos_security_address_book');
  });
});
