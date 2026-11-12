/** SRX parser: address-excluded negation and deactivated policies (issue #123). */
import { describe, it, expect } from 'vitest';
import { parseSrxConfig } from '../src/parsers/srx-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

const policyLines = (path, name, extra = []) => [
  `set security policies ${path} policy ${name} match source-address bad-host`,
  `set security policies ${path} policy ${name} match destination-address any`,
  `set security policies ${path} policy ${name} match application any`,
  `set security policies ${path} policy ${name} then permit`,
  ...extra,
];
const ZP = 'from-zone trust to-zone untrust';
const byName = (text) => Object.fromEntries(
  parseSrxConfig(text).intermediateConfig.security_policies.map(p => [p.name, p]));

describe('SRX parser: address-excluded', () => {
  it('reads source/destination excluded for zone and global policies', () => {
    const text = [
      ...policyLines(ZP, 'src-neg', [`set security policies ${ZP} policy src-neg match source-address-excluded`]),
      ...policyLines(ZP, 'dst-neg', [`set security policies ${ZP} policy dst-neg match destination-address-excluded`]),
      ...policyLines('global', 'g-neg', ['set security policies global policy g-neg match source-address-excluded']),
      ...policyLines(ZP, 'plain'),
    ].join('\n');
    const p = byName(text);
    expect([p['src-neg'].negate_source, p['src-neg'].negate_destination]).toEqual([true, false]);
    expect([p['dst-neg'].negate_source, p['dst-neg'].negate_destination]).toEqual([false, true]);
    expect(p['g-neg'].negate_source).toBe(true);
    expect([p.plain.negate_source, p.plain.negate_destination]).toEqual([false, false]);
  });

  it('ignores a deactivated excluded flag (set and hierarchical)', () => {
    const setText = [
      ...policyLines(ZP, 'off-neg', [
        `set security policies ${ZP} policy off-neg match source-address-excluded`,
        `deactivate security policies ${ZP} policy off-neg match source-address-excluded`,
      ]),
    ].join('\n');
    expect(byName(setText)['off-neg']).toMatchObject({ negate_source: false, disabled: false });

    const hierarchical = `security {
    policies {
        from-zone trust to-zone untrust {
            policy off-neg {
                match {
                    source-address any;
                    destination-address bad-host;
                    inactive: destination-address-excluded;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
    }
}`;
    expect(byName(hierarchical)['off-neg']).toMatchObject({ negate_destination: false, disabled: false });
  });
});

describe('SRX parser: deactivated policies', () => {
  it('marks only the deactivated policy disabled', () => {
    const text = [
      ...policyLines(ZP, 'P'), ...policyLines(ZP, 'Q'), ...policyLines('global', 'G'), ...policyLines('global', 'H'),
      `deactivate security policies ${ZP} policy P`,
      'deactivate security policies global policy G',
    ].join('\n');
    const p = byName(text);
    expect([p.P.disabled, p.Q.disabled, p.G.disabled, p.H.disabled]).toEqual([true, false, true, false]);
  });

  it('reads hierarchical source-address-excluded and inactive: policy', () => {
    const text = `security {
    policies {
        from-zone trust to-zone untrust {
            inactive: policy P {
                match {
                    source-address bad-host;
                    source-address-excluded;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
            policy Q {
                match {
                    source-address bad-host;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
    }
}`;
    const p = byName(text);
    expect(p.P).toMatchObject({ disabled: true, negate_source: true });
    expect(p.Q).toMatchObject({ disabled: false, negate_source: false });
  });

  it('applies in logical-systems', () => {
    const base = 'set logical-systems ls1 security policies from-zone trust to-zone untrust policy P';
    const text = [
      `${base} match source-address bad-host`, `${base} match source-address-excluded`,
      `${base} match destination-address any`, `${base} match application any`, `${base} then permit`,
      `deactivate logical-systems ls1 security policies from-zone trust to-zone untrust policy P`,
    ].join('\n');
    expect(byName(text).P).toMatchObject({ negate_source: true, disabled: true });
  });

  it('does not crash or invent names for deactivated non-policy statements', () => {
    const text = [
      'set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24',
      'set security zones security-zone trust interfaces ge-0/0/1.0',
      'set security zones security-zone trust interfaces ge-0/0/2.0',
      'set security nat source rule-set X from zone trust',
      'set security nat source rule-set X to zone untrust',
      'set security nat source rule-set X rule Y match source-address 10.0.0.0/8',
      'set security nat source rule-set X rule Y then source-nat interface',
      'deactivate interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24',
      'deactivate security zones security-zone trust interfaces ge-0/0/1.0',
      'deactivate security nat source rule-set X rule Y',
    ].join('\n');
    const { intermediateConfig: cfg } = parseSrxConfig(text);
    const trust = cfg.zones.find(z => z.name === 'trust');
    expect([...trust.interfaces].sort()).toEqual(['ge-0/0/1.0', 'ge-0/0/2.0']);
    // A deactivated NAT rule must not come back active, so it is dropped.
    expect(cfg.nat_rules).toEqual([]);
    expect(JSON.stringify(cfg)).not.toContain('_deactivated');
  });
});

describe('SRX round trip', () => {
  const config = {
    metadata: { source_vendor: 'fortigate' },
    zones: [{ name: 'trust', interfaces: [] }, { name: 'untrust', interfaces: [] }],
    address_objects: [
      { name: 'bad-host', type: 'ip-netmask', value: '198.51.100.7/32' },
      { name: 'lan-net', type: 'ip-netmask', value: '192.168.10.0/24' },
    ],
    address_groups: [], service_objects: [], service_groups: [], applications: [],
    security_policies: [
      { name: 'deny-except', action: 'deny', src_zones: ['trust'], dst_zones: ['untrust'],
        src_addresses: ['bad-host'], dst_addresses: ['lan-net'], negate_source: true,
        negate_destination: false, applications: [], services: ['any'], disabled: false },
      { name: 'off-permit', action: 'permit', src_zones: ['trust'], dst_zones: ['untrust'],
        src_addresses: ['lan-net'], dst_addresses: ['bad-host'], negate_source: false,
        negate_destination: true, applications: [], services: ['any'], disabled: true },
    ],
  };

  for (const policyStructure of ['global', 'zone-pair']) {
    it(`survives ${policyStructure} output`, () => {
      // Unfiltered output: its `#` banners must not tip the parser into hierarchical mode
      const text = convertToSrxSetCommands(config, {}, null, { policyStructure }).commands.join('\n');
      const p = byName(text);
      expect(p['deny-except']).toMatchObject({ negate_source: true, negate_destination: false, disabled: false });
      expect(p['off-permit']).toMatchObject({ negate_source: false, negate_destination: true, disabled: true });
    });
  }
});

describe('SRX parser: config order, prototype safety, NAT and address-books', () => {
  const zones = ['set security zones security-zone trust', 'set security zones security-zone untrust'];
  const base = 'set security policies from-zone trust to-zone untrust policy';
  const policyBody = (name, action) => [
    `${base} ${name} match source-address any`,
    `${base} ${name} match destination-address any`,
    `${base} ${name} match application any`,
    `${base} ${name} then ${action}`,
  ];

  it('keeps config order for numeric policy names', () => {
    const config = [...zones, ...policyBody('10', 'deny'), ...policyBody('2', 'permit'), ...policyBody('blockit', 'deny')].join('\n');
    const { security_policies: policies } = parseSrxConfig(config).intermediateConfig;
    expect(policies.map(policy => policy.name).slice(0, 3)).toEqual(['10', '2', 'blockit']);
  });

  it('keeps config order for numeric NAT rules', () => {
    const rule = (name) => [
      `set security nat source rule-set sn rule ${name} match source-address 192.0.2.0/24`,
      `set security nat source rule-set sn rule ${name} then source-nat interface`,
    ];
    const config = [...zones, ...rule('10'), ...rule('2'), ...rule('x')].join('\n');
    const { nat_rules: natRules } = parseSrxConfig(config).intermediateConfig;
    expect(natRules.map(natRule => natRule.name)).toEqual(['sn/10', 'sn/2', 'sn/x']);
  });

  it('does not pollute Object.prototype from a __proto__ policy name', () => {
    parseSrxConfig([
      `${base.replace('trust to-zone untrust', 'a to-zone b')} __proto__ match source-address evil`,
      `${base.replace('trust to-zone untrust', 'a to-zone b')} __proto__ then permit`,
    ].join('\n'));
    expect(({}).match).toBeUndefined();
    expect(({}).then).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, 'match')).toBe(false);
  });

  it('does not convert a deactivated NAT rule', () => {
    const config = [
      ...zones,
      'set security nat source rule-set sn from zone trust',
      'set security nat source rule-set sn to zone untrust',
      'set security nat source rule-set sn rule off match source-address 192.0.2.0/24',
      'set security nat source rule-set sn rule off then source-nat interface',
      'deactivate security nat source rule-set sn rule off',
    ].join('\n');
    const { intermediateConfig, warnings } = parseSrxConfig(config);
    expect(intermediateConfig.nat_rules).toEqual([]);
    expect(warnings.some(warning => /disabled/.test(warning.message))).toBe(true);
  });

  it('resolves the destination pool address and port of a destination NAT rule', () => {
    const config = [
      ...zones,
      'set security nat destination pool web address 198.51.100.10/32 port 8080',
      'set security nat destination rule-set dn from zone untrust',
      'set security nat destination rule-set dn rule r1 match destination-address 192.0.2.50/32',
      'set security nat destination rule-set dn rule r1 match destination-port 443',
      'set security nat destination rule-set dn rule r1 then destination-nat pool web',
    ].join('\n');
    const [natRule] = parseSrxConfig(config).intermediateConfig.nat_rules;
    expect(natRule.translated_dst).toBe('198.51.100.10/32');
    expect(natRule.translated_port).toBe('8080');
    expect(natRule.match_port).toBe('443');
  });

  it('reads named and zone-attached address-books', () => {
    const config = [
      ...zones,
      'set security address-book book1 address bk1 198.51.100.0/24',
      'set security address-book book1 attach zone untrust',
      'set security zones security-zone trust address-book address za 203.0.113.0/24',
    ].join('\n');
    const names = parseSrxConfig(config).intermediateConfig.address_objects.map(address => address.name);
    expect(names).toEqual(expect.arrayContaining(['bk1', 'za']));
  });
});
