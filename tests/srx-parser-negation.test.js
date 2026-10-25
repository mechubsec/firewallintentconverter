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
    expect(cfg.nat_rules.map(r => r.name)).toEqual(['X/Y']);
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
