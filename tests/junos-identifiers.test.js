import { describe, expect, it } from 'vitest';

import {
  JUNOS_IDENTIFIER_MAPPING_VERSION,
  JunosIdentifierPlanningError,
  createJunosIdentifierPlan,
  planJunosIdentifiers,
  planMergedJunosIdentifiers,
  validateIdentifierMappings,
} from '../src/security/junos-identifiers.js';
import {
  sanitizeJunosName as sanitizeForTest,
  setMapVendorApp,
} from '../src/parsers/parser-utils.js';
import {
  loadAppMappings,
  mapVendorApp,
} from '../src/utils/app-mappings.js';
import {
  JUNOS_IDENTIFIER_CATALOG,
  collectJunosIdentifierSymbols,
  collectMergedJunosIdentifierSymbols,
} from '../src/security/junos-identifier-catalog.js';
import { JunosSerializationError } from '../src/security/junos-serialization.js';

function fullConfig() {
  return {
    zones: [{ name: 'trust zone' }, { name: 'untrust zone' }],
    address_objects: [{ name: 'web host', value: '192.0.2.10' }],
    address_groups: [{ name: 'web group', members: ['web host'] }],
    service_objects: [{ name: 'custom web', protocol: 'tcp', port_range: '8080,8443' }],
    service_groups: [{ name: 'web services', members: ['custom web'] }],
    applications: [{ name: 'custom app', protocol: 'tcp', port: '9000,9001' }],
    application_groups: [{ name: 'app bundle', members: ['custom app'] }],
    schedules: [{ name: 'business hours', days: ['mon'], start: '09:00', end: '17:00' }],
    security_policies: [{
      name: 'allow web',
      src_zones: ['trust zone'],
      dst_zones: ['untrust zone'],
      src_addresses: ['web group'],
      dst_addresses: ['web host'],
      applications: ['junos-https'],
      services: ['web services'],
      schedule: 'business hours',
      action: 'allow',
      security_profiles: {
        virus: 'virus profile',
        spyware: 'spyware profile',
      },
    }],
    nat_rules: [
      {
        name: 'source web', type: 'source',
        src_zones: ['trust zone'], dst_zones: ['untrust zone'],
        src_addresses: ['web host'], dst_addresses: ['any'],
        translated_src: { type: 'dynamic-ip-pool', addresses: ['web host'] },
      },
      {
        name: 'destination web', type: 'destination',
        src_zones: ['untrust zone'], dst_zones: ['trust zone'],
        dst_addresses: ['web host'], translated_dst: { address: '192.0.2.10' },
      },
      {
        name: 'static web', type: 'static',
        src_zones: ['untrust zone'], dst_zones: ['trust zone'],
        dst_addresses: ['web host'], translated_src: { address: '192.0.2.10' },
      },
    ],
    static_routes: [{ destination: '0.0.0.0/0', next_hop: '192.0.2.1', vrf: 'blue vrf' }],
    bgp_config: [{
      instance: 'blue vrf',
      peer_groups: [{
        name: 'edge peers',
        neighbors: [{ address: '192.0.2.2', import_policy: 'IMPORT EDGE', export_policy: 'EXPORT EDGE' }],
      }],
      networks: [{ prefix: '192.0.2.0/24', policy: 'EXPORT EDGE' }],
      redistribute: [{ protocol: 'static' }],
    }],
    ospf_config: [{ instance: 'blue vrf', redistribute: [{ protocol: 'static' }] }],
    ospf3_config: [{ instance: 'blue vrf', redistribute: [{ protocol: 'direct' }] }],
    evpn_config: [{ instance: 'evpn vrf', vlans: [{ name: 'tenant vlan', vlan_id: 100, vni: 10100 }] }],
    vxlan_config: [{ instance: 'evpn vrf', name: 'overlay', vnis: [{ vni: 10200, vlan_id: 200 }] }],
    screen_config: [{ name: 'edge screen', zone: 'untrust zone', tcp: { land_attack: true } }],
    vpn_tunnels: [{
      name: 'branch vpn',
      ike_proposal: { name: 'ike proposal' },
      ike_gateway: { name: 'ike gateway', address: '198.51.100.10' },
      ipsec_proposal: { name: 'ipsec proposal' },
    }],
    external_lists: [{ name: 'bad hosts', isBlockList: true, listType: 'ip' }],
    decryption_rules: [
      { name: 'decrypt outbound', action: 'decrypt', decryption_type: 'ssl-forward-proxy', decryption_profile: 'corp tls' },
      { name: 'decrypt inbound', action: 'decrypt', decryption_type: 'ssl-inbound-inspection', decryption_profile: 'server tls' },
    ],
    bridge_domains: [{ name: 'bridge tenant', vlan_id: 300 }],
    l2_interfaces: [{ name: 'ge-0/0/1.0', bridge_domain: 'bridge tenant' }],
    vwire_pairs: [{ name: 'transparent pair', interface1: 'ge-0/0/2', interface2: 'ge-0/0/3' }],
    pbf_rules: [{
      name: 'prefer isp', action: 'forward', next_hop_value: '203.0.113.1',
      src_addresses: ['web host'], dst_addresses: ['any'],
    }],
    dhcp_config: [{
      type: 'server', name: 'branch pool', network: '10.0.0.0/24',
      pools: ['10.0.0.10-10.0.0.20'], ranges: [{ name: 'printers', low: '10.0.0.30', high: '10.0.0.40' }],
    }],
    qos_config: [
      { type: 'scheduler', name: 'voice scheduler' },
      { type: 'shaping-profile', name: 'branch qos', classes: [{ name: 'voice class' }] },
      { type: 'interface-cos', interface: 'ge-0/0/0', scheduler_map: 'branch qos' },
      { type: 'classifier', name: 'dscp edge' },
    ],
    flow_monitoring_config: {
      instance_name: 'branch flow',
      collectors: [{ address: '192.0.2.50', protocol: 'ipfix' }],
      templates: [{ name: 'branch template' }],
    },
    aaa_config: [{ type: 'profile', name: 'admin access', authentication_order: ['radius'] }],
    snmp_config: [
      { type: 'community', name: 'monitor community' },
      { type: 'trap-group', name: 'noc traps', targets: ['192.0.2.60'] },
      { type: 'v3-user', name: 'monitor user' },
    ],
  };
}

const definition = (sourceName, definitionPath, overrides = {}) => ({
  catalogKey: 'address-book',
  context: 'root/address-book:global',
  namespace: 'address-book-entry',
  kind: 'address',
  sourceName,
  definitionPath,
  generated: false,
  role: null,
  stableParentKey: null,
  ...overrides,
});

const reference = (sourceName, referencePath, overrides = {}) => ({
  catalogKey: 'address-book',
  context: 'root/address-book:global',
  namespace: 'address-book-entry',
  compatibleKinds: ['address', 'address-set'],
  sourceName,
  referencePath,
  literals: [],
  ...overrides,
});

const validEntry = (overrides = {}) => ({
  context: 'root/address-book:global',
  namespace: 'address-book-entry',
  kind: 'address',
  sourceName: 'Web Server',
  outputName: 'Web-Server',
  definitionPath: 'address_objects[0].name',
  referencePaths: ['security_policies[0].src_addresses[0]'],
  resolution: 'unchanged',
  ...overrides,
});

const mapping = (...entries) => ({
  version: JUNOS_IDENTIFIER_MAPPING_VERSION,
  entries,
});

function capturePlanningError(callback) {
  try {
    callback();
  } catch (error) {
    expect(error).toBeInstanceOf(JunosIdentifierPlanningError);
    return error;
  }
  throw new Error('Expected JunosIdentifierPlanningError');
}

describe('Junos identifier allocation', () => {
  it.each([
    ['absent', {}],
    ['null', { type: null }],
    ['non-string', { type: 42 }],
    ['unknown', { type: 'evil' }],
  ])('rejects a direct target context with an %s type', (_label, typeFields) => {
    const error = capturePlanningError(() => planJunosIdentifiers({}, {
      targetContext: { ...typeFields, name: 'tenant-a' },
    }));

    expect(error).toMatchObject({
      code: 'missing_catalog_coverage',
      definitionPaths: ['targetContext.type'],
      reason: 'target context type must be none, logical-system, or tenant',
    });
  });

  it('applies target type and name validation to embedded config context', () => {
    const typeError = capturePlanningError(() => planJunosIdentifiers({
      target_context: { type: 'invalid', name: 'tenant-a' },
    }));
    expect(typeError).toMatchObject({
      definitionPaths: ['targetContext.type'],
      reason: 'target context type must be none, logical-system, or tenant',
    });

    const nameError = capturePlanningError(() => planJunosIdentifiers({
      target_context: { type: 'tenant', name: '' },
    }));
    expect(nameError).toMatchObject({
      definitionPaths: ['targetContext.name'],
      reason: 'active target context requires a non-blank string name',
    });
  });

  it.each([
    ['absent', {}],
    ['null', { name: null }],
    ['non-string', { name: 42 }],
    ['blank', { name: '   ' }],
  ])('rejects an active direct target context with an %s name', (_label, nameFields) => {
    const error = capturePlanningError(() => planJunosIdentifiers({}, {
      targetContext: { type: 'logical-system', ...nameFields },
    }));

    expect(error).toMatchObject({
      code: 'missing_catalog_coverage',
      definitionPaths: ['targetContext.name'],
      reason: 'active target context requires a non-blank string name',
    });
  });

  it.each([
    ['absent', {}],
    ['null', { lsName: null }],
    ['non-string', { lsName: 42 }],
    ['blank', { lsName: '   ' }],
  ])('rejects a merged logical-system slot with an %s name', (_label, nameFields) => {
    const error = capturePlanningError(() => planMergedJunosIdentifiers([{
      ...nameFields,
      intermediateConfig: {},
      interfaceMappings: {},
    }]));

    expect(error).toMatchObject({
      code: 'missing_catalog_coverage',
      definitionPaths: ['configSlots[0].lsName'],
      reason: 'active target context requires a non-blank string name',
    });
  });

  it.each([
    ['Web Server', 'Web@Server'],
    ['Web  Server', 'Web--Server'],
    ['!!!', '???'],
    ['1 edge', 'n-1-edge'],
    [`${'a'.repeat(63)}x`, `${'a'.repeat(63)}y`],
  ])('renames both definitions for %s and %s', (left, right) => {
    const plan = createJunosIdentifierPlan({
      definitions: [definition(left, 'defs[0]'), definition(right, 'defs[1]')],
      references: [],
    });

    expect(plan.nameForDefinition('defs[0]')).not.toBe(plan.nameForDefinition('defs[1]'));
    expect(plan.mapping.entries.every(entry => entry.resolution === 'collision-renamed'))
      .toBe(true);
    expect(plan.collisionCount).toBe(2);
    expect(plan.warnings).toHaveLength(2);
    expect(plan.warnings[0]).toMatchObject({
      type: 'warning',
      category: 'identifier',
      subType: 'identifier_collision',
      suggestion: 'Review the identifier mapping before deployment.',
    });
  });

  it('preserves case-only and other non-colliding names', () => {
    const plan = createJunosIdentifierPlan({
      definitions: [definition('Web', 'defs[0]'), definition('web', 'defs[1]')],
      references: [],
    });

    expect(plan.nameForDefinition('defs[0]')).toBe('Web');
    expect(plan.nameForDefinition('defs[1]')).toBe('web');
    expect(plan.mapping.entries.map(entry => entry.resolution)).toEqual([
      'unchanged',
      'unchanged',
    ]);
  });

  it('is stable when definitions and references are reordered', () => {
    const definitions = [
      definition('Web Server', 'defs.web-space'),
      definition('Web@Server', 'defs.web-at'),
      definition('Database', 'defs.database'),
    ];
    const references = [
      reference('Web Server', 'refs.web-space'),
      reference('Web@Server', 'refs.web-at'),
      reference('Outside Name', 'refs.external'),
    ];

    const forward = createJunosIdentifierPlan({ definitions, references });
    const reversed = createJunosIdentifierPlan({
      definitions: [...definitions].reverse(),
      references: [...references].reverse(),
    });

    expect(reversed.mapping).toEqual(forward.mapping);
    expect(reversed.warnings).toEqual(forward.warnings);
    for (const path of definitions.map(item => item.definitionPath)) {
      expect(reversed.nameForDefinition(path)).toBe(forward.nameForDefinition(path));
    }
    for (const path of references.map(item => item.referencePath)) {
      expect(reversed.nameForReference(path)).toBe(forward.nameForReference(path));
    }
  });

  it('keeps a singleton unchanged when it matches a first collision candidate', () => {
    const colliding = [
      definition('Web Server', 'defs.web-space'),
      definition('Web@Server', 'defs.web-at'),
    ];
    const firstPlan = createJunosIdentifierPlan({ definitions: colliding, references: [] });
    const firstCandidate = firstPlan.nameForDefinition('defs.web-space');

    const plan = createJunosIdentifierPlan({
      definitions: [...colliding, definition(firstCandidate, 'defs.singleton')],
      references: [],
    });

    expect(plan.nameForDefinition('defs.singleton')).toBe(firstCandidate);
    expect(plan.nameForDefinition('defs.web-space')).not.toBe(firstCandidate);
    expect(plan.nameForDefinition('defs.web-at')).not.toBe(firstCandidate);
  });

  it('rejects exact duplicate semantic definitions', () => {
    const error = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [
        definition('Web Server', 'defs[0]'),
        definition('Web Server', 'defs[1]'),
      ],
      references: [],
    }));

    expect(error).toMatchObject({
      code: 'duplicate_definition',
      namespace: 'address-book-entry',
      context: 'root/address-book:global',
      sourceName: 'Web Server',
      definitionPaths: ['defs[0]', 'defs[1]'],
    });
  });

  it('rejects duplicate generated stable identities before allocation', () => {
    let hashCalls = 0;
    const generated = {
      kind: 'source-nat-pool',
      generated: true,
      role: 'source-nat-pool',
      stableParentKey: 'source-rule:Web Rule',
    };

    const error = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [
        definition('Web Pool', 'nat.rules[0]', generated),
        definition('Web@Pool', 'nat.rules[1]', generated),
      ],
      references: [],
    }, {
      hash64: () => {
        hashCalls += 1;
        return 0n;
      },
    }));

    expect(error).toMatchObject({
      code: 'duplicate_definition',
      namespace: 'address-book-entry',
      context: 'root/address-book:global',
      definitionPaths: [
        'nat.rules[0]#generated:source-nat-pool',
        'nat.rules[1]#generated:source-nat-pool',
      ],
    });
    expect(hashCalls).toBe(0);
  });

  it('rejects exact source duplicates for generated definitions before allocation', () => {
    let hashCalls = 0;
    const generated = {
      kind: 'source-nat-pool',
      generated: true,
      role: 'source-nat-pool',
    };

    const error = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [
        definition('Web Pool', 'nat.rules[0]', {
          ...generated,
          stableParentKey: 'source-rule:Web Rule',
        }),
        definition('Web Pool', 'nat.rules[1]', {
          ...generated,
          stableParentKey: 'source-rule:Other Rule',
        }),
      ],
      references: [],
    }, {
      hash64: () => {
        hashCalls += 1;
        return 0n;
      },
    }));

    expect(error).toMatchObject({
      code: 'duplicate_definition',
      namespace: 'address-book-entry',
      context: 'root/address-book:global',
      sourceName: 'Web Pool',
      definitionPaths: [
        'nat.rules[0]#generated:source-nat-pool',
        'nat.rules[1]#generated:source-nat-pool',
      ],
    });
    expect(hashCalls).toBe(0);
  });

  it('rejects a reference that can bind to both an address and address set', () => {
    const error = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [
        definition('Shared', 'addresses[0]'),
        definition('Shared', 'address_sets[0]', { kind: 'address-set' }),
      ],
      references: [reference('Shared', 'policies[0].src_addresses[0]')],
    }));

    expect(error).toMatchObject({
      code: 'ambiguous_reference',
      namespace: 'address-book-entry',
      sourceName: 'Shared',
      definitionPaths: ['address_sets[0]', 'addresses[0]'],
      referencePaths: ['policies[0].src_addresses[0]'],
    });
  });

  it('reserves an unresolved external reference without binding by normalized spelling', () => {
    const plan = createJunosIdentifierPlan({
      definitions: [definition('Web Server', 'defs[0]')],
      references: [reference('Web@Server', 'refs[0]')],
    });

    expect(plan.nameForDefinition('defs[0]')).toBe('Web-Server');
    expect(plan.nameForReference('refs[0]')).not.toBe('Web-Server');
    expect(plan.mapping.entries).toContainEqual(expect.objectContaining({
      sourceName: 'Web@Server',
      definitionPath: null,
      referencePaths: ['refs[0]'],
      resolution: 'unresolved-collision-renamed',
    }));
    expect(plan.collisionCount).toBe(0);
  });

  it('returns explicit literals without adding mapping entries', () => {
    const plan = createJunosIdentifierPlan({
      definitions: [],
      references: [reference('any', 'refs.any', { literals: ['any'] })],
    });

    expect(plan.nameForReference('refs.any')).toBe('any');
    expect(plan.mapping.entries).toEqual([]);
  });

  it('validates and reserves explicit literal output names', () => {
    const invalid = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [],
      references: [reference('mapped app', 'refs.invalid', {
        literalOutputName: 'bad name;set system root-authentication',
      })],
    }));

    expect(invalid).toMatchObject({
      code: 'missing_catalog_coverage',
      reason: 'invalid literal output name metadata',
    });

    const invalidLiteral = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [],
      references: [reference('bad name;set system services ssh', 'refs.literal', {
        literals: ['bad name;set system services ssh'],
      })],
    }));

    expect(invalidLiteral).toMatchObject({
      code: 'missing_catalog_coverage',
      reason: 'invalid literal metadata',
    });

    const plan = createJunosIdentifierPlan({
      definitions: [definition('junos-https', 'defs.literal-collision')],
      references: [reference('HTTPS', 'refs.https', {
        literalOutputName: 'junos-https',
      })],
    });

    expect(plan.nameForReference('refs.https')).toBe('junos-https');
    expect(plan.nameForDefinition('defs.literal-collision')).not.toBe('junos-https');
    expect(plan.mapping.entries[0].resolution).toBe('collision-renamed');
  });

  it('catalogs generated names by owner and role with auditable paths', () => {
    const plan = createJunosIdentifierPlan({
      definitions: [definition('Web Pool', 'nat.rules[0]', {
        kind: 'source-nat-pool',
        generated: true,
        role: 'source-nat-pool',
        stableParentKey: 'source-rule:Web Rule',
      })],
      references: [],
    });

    expect(plan.nameForGenerated('nat.rules[0]', 'source-nat-pool')).toBe('Web-Pool');
    expect(plan.mapping.entries).toEqual([expect.objectContaining({
      definitionPath: 'nat.rules[0]#generated:source-nat-pool',
      resolution: 'generated',
    })]);
  });

  it('fails closed for every missing lookup type', () => {
    const plan = createJunosIdentifierPlan({ definitions: [], references: [] });

    for (const lookup of [
      () => plan.nameForDefinition('missing.definition'),
      () => plan.nameForReference('missing.reference'),
      () => plan.nameForGenerated('missing.owner', 'missing-role'),
    ]) {
      expect(capturePlanningError(lookup)).toMatchObject({
        code: 'missing_catalog_coverage',
      });
    }
  });

  it('retries all candidates involved in a one-round injected hash conflict', () => {
    const calls = [];
    const hash64 = input => {
      calls.push(input);
      const retry = input.split('\0').at(-1);
      if (retry === '0') return 0n;
      return input.includes('Web Server') ? 1n : 2n;
    };

    const plan = createJunosIdentifierPlan({
      definitions: [
        definition('Web Server', 'defs[0]'),
        definition('Web@Server', 'defs[1]'),
      ],
      references: [],
    }, { hash64 });

    expect(plan.nameForDefinition('defs[0]')).not.toBe(plan.nameForDefinition('defs[1]'));
    expect(calls.some(input => input.endsWith('\0' + '1'))).toBe(true);
  });

  it('throws allocation_failed after 32 complete conflict rounds', () => {
    let calls = 0;
    const error = capturePlanningError(() => createJunosIdentifierPlan({
      definitions: [
        definition('Web Server', 'defs[0]'),
        definition('Web@Server', 'defs[1]'),
      ],
      references: [],
    }, {
      hash64: () => {
        calls += 1;
        return 0n;
      },
    }));

    expect(error).toMatchObject({
      code: 'allocation_failed',
      namespace: 'address-book-entry',
      context: 'root/address-book:global',
    });
    expect(calls).toBe(64);
  });
});

describe('Junos identifier mapping validation', () => {
  it('returns a deeply frozen defensive copy', () => {
    const original = mapping(validEntry());
    const validated = validateIdentifierMappings(original);

    expect(validated).toEqual(original);
    expect(validated).not.toBe(original);
    expect(validated.entries[0]).not.toBe(original.entries[0]);
    expect(Object.isFrozen(validated)).toBe(true);
    expect(Object.isFrozen(validated.entries)).toBe(true);
    expect(Object.isFrozen(validated.entries[0])).toBe(true);
    expect(Object.isFrozen(validated.entries[0].referencePaths)).toBe(true);

    original.entries[0].sourceName = 'Changed';
    original.entries[0].referencePaths.push('security_policies[1].src_addresses[0]');
    expect(validated.entries[0].sourceName).toBe('Web Server');
    expect(validated.entries[0].referencePaths).toEqual([
      'security_policies[0].src_addresses[0]',
    ]);
  });

  it.each([
    ['unknown version', { version: 2, entries: [] }],
    ['unknown mapping field', { version: 1, entries: [], artifact: 'secret' }],
    ['unknown entry field', mapping(validEntry({ artifact: 'secret' }))],
    ['unknown resolution', mapping(validEntry({ resolution: 'renamed' }))],
    ['unsafe scalar', mapping(validEntry({ sourceName: 'Web\nServer' }))],
    ['invalid output name', mapping(validEntry({ outputName: '1-invalid' }))],
    ['null definition path', mapping(validEntry({ definitionPath: null }))],
    ['unresolved definition path', mapping(validEntry({
      definitionPath: 'defs[0]',
      resolution: 'unresolved-reference',
    }))],
    ['unsorted reference paths', mapping(validEntry({
      referencePaths: ['refs[1]', 'refs[0]'],
    }))],
    ['duplicate reference paths', mapping(validEntry({
      referencePaths: ['refs[0]', 'refs[0]'],
    }))],
    ['unchanged output mismatch', mapping(validEntry({ outputName: 'Other' }))],
    ['normalized base on explicit entry', mapping(validEntry({
      outputName: 'arbitrary-name',
      normalizedBase: 'arbitrary-name',
    }))],
    ['collision output unchanged', mapping(validEntry({
      outputName: 'Web-Server',
      resolution: 'collision-renamed',
    }))],
  ])('rejects %s', (_label, invalidMapping) => {
    const error = capturePlanningError(() => validateIdentifierMappings(invalidMapping));
    expect(error).toMatchObject({ code: 'invalid_identifier_mapping' });
    expect(error.message).not.toContain('secret');
  });

  it('rejects duplicate semantic definitions', () => {
    const error = capturePlanningError(() => validateIdentifierMappings(mapping(
      validEntry({ definitionPath: 'defs[0]', referencePaths: [] }),
      validEntry({ definitionPath: 'defs[1]', referencePaths: [] }),
    )));

    expect(error.code).toBe('invalid_identifier_mapping');
  });

  it('rejects duplicate output names across kinds and unresolved entries', () => {
    const error = capturePlanningError(() => validateIdentifierMappings(mapping(
      validEntry({ definitionPath: 'defs[0]', referencePaths: [] }),
      validEntry({
        kind: 'address-set',
        sourceName: 'Web-Server',
        definitionPath: null,
        referencePaths: ['refs[0]'],
        resolution: 'unresolved-reference',
      }),
    )));

    expect(error.code).toBe('invalid_identifier_mapping');
  });
});

describe('Junos identifier catalog', () => {
  it('catalogs every converter namespace with exact auditable paths and contexts', () => {
    const symbols = collectJunosIdentifierSymbols(fullConfig(), {
      targetContext: { type: 'logical-system', name: 'branch a' },
    });
    const paths = new Set([
      ...symbols.definitions.map(item => item.definitionPath),
      ...symbols.references.map(item => item.referencePath),
    ]);

    expect([...paths]).toEqual(expect.arrayContaining([
      'targetContext.name',
      'zones[0].name',
      'address_objects[0].name',
      'address_groups[0].members[0]',
      'service_objects[0].name',
      'service_groups[0].members[0]',
      'applications[0].name',
      'application_groups[0].members[0]',
      'schedules[0].name',
      'security_policies[0].name',
      'security_policies[0].dst_addresses[0]',
      'nat_rules[0].name',
      'static_routes[0].vrf',
      'bgp_config[0].peer_groups[0].name',
      'screen_config[0].name',
      'vpn_tunnels[0].name',
      'external_lists[0].name',
      'decryption_rules[0].decryption_profile',
      'bridge_domains[0].name',
      'l2_interfaces[0].bridge_domain',
      'pbf_rules[0].name',
      'dhcp_config[0].name',
      'qos_config[0].name',
      'flow_monitoring_config.instance_name',
      'aaa_config[0].name',
      'snmp_config[0].name',
    ]));

    const address = symbols.definitions.find(item => item.definitionPath === 'address_objects[0].name');
    const addressSet = symbols.definitions.find(item => item.definitionPath === 'address_groups[0].name');
    expect(address).toMatchObject({ namespace: 'address-book-entry', kind: 'address' });
    expect(addressSet).toMatchObject({ namespace: 'address-book-entry', kind: 'address-set' });
    expect(addressSet.context).toBe(address.context);

    const policy = symbols.definitions.find(item => item.definitionPath === 'security_policies[0].name');
    expect(policy).toMatchObject({
      namespace: 'security-policy',
      context: expect.stringContaining('zone-pair:["trust zone","untrust zone"]'),
    });

    const bgpGroup = symbols.definitions.find(item => item.definitionPath === 'bgp_config[0].peer_groups[0].name');
    expect(bgpGroup).toMatchObject({
      namespace: 'bgp-group',
      context: expect.stringContaining('routing-instance:blue vrf'),
    });

    expect(symbols.definitions).not.toContainEqual(expect.objectContaining({ sourceName: 'junos-https' }));
    expect(symbols.references).toContainEqual(expect.objectContaining({
      referencePath: 'security_policies[0].applications[0]',
      sourceName: 'junos-https',
      literals: expect.arrayContaining(['junos-https']),
    }));
  });

  it('catalogs current generated preferred names with owner paths and stable roles', () => {
    const symbols = collectJunosIdentifierSymbols(fullConfig(), {
      targetContext: { type: 'logical-system', name: 'branch a' },
    });

    expect(symbols.definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({
        sourceName: 'pool-source web',
        definitionPath: 'nat_rules[0]',
        generated: true,
        role: 'source-nat-pool',
        stableParentKey: expect.stringContaining('source web'),
      }),
      expect.objectContaining({
        sourceName: 'dnat-pool-destination web',
        definitionPath: 'nat_rules[1]',
        role: 'destination-nat-pool',
      }),
      expect.objectContaining({
        sourceName: 'ike-pol-branch vpn',
        definitionPath: 'vpn_tunnels[0]',
        role: 'ike-policy',
      }),
      expect.objectContaining({
        sourceName: 'ipsec-pol-branch vpn',
        definitionPath: 'vpn_tunnels[0]',
        role: 'ipsec-policy',
      }),
      expect.objectContaining({
        sourceName: 'PBF-prefer isp',
        definitionPath: 'pbf_rules[0]',
        role: 'pbf-routing-instance',
      }),
      expect.objectContaining({
        sourceName: 'corp tls',
        definitionPath: 'decryption_rules[0]',
        role: 'ssl-forward-profile',
      }),
      expect.objectContaining({
        sourceName: 'server tls',
        definitionPath: 'decryption_rules[1]',
        role: 'ssl-inbound-profile',
      }),
      expect.objectContaining({
        sourceName: 'ike proposal',
        definitionPath: 'vpn_tunnels[0].ike_proposal.name',
        generated: false,
      }),
      expect.objectContaining({
        sourceName: 'ike gateway',
        definitionPath: 'vpn_tunnels[0].ike_gateway.name',
        generated: false,
      }),
      expect.objectContaining({
        sourceName: 'ipsec proposal',
        definitionPath: 'vpn_tunnels[0].ipsec_proposal.name',
        generated: false,
      }),
    ]));

    const plan = planJunosIdentifiers(fullConfig(), {
      targetContext: { type: 'logical-system', name: 'branch a' },
    });
    expect(plan.nameForReference('service_groups[0].members[0]'))
      .toBe(plan.nameForGenerated('service_objects[0]', 'service-multi-port-set'));
    expect(plan.nameForReference('application_groups[0].members[0]'))
      .toBe(plan.nameForGenerated('applications[0]', 'application-multi-port-set'));
  });

  it('deduplicates shared NAT rule sets and catalogs PBF filter children', () => {
    const config = fullConfig();
    config.nat_rules.push({
      name: 'source api', type: 'source',
      src_zones: ['trust zone'], dst_zones: ['untrust zone'],
      translated_src: { type: 'interface' },
    });
    config.pbf_rules.push({
      name: 'prefer api', action: 'forward', next_hop_value: '203.0.113.1',
    });

    const symbols = collectJunosIdentifierSymbols(config);
    const sourceRuleSets = symbols.definitions.filter(item => (
      item.role?.startsWith('source-nat-rule-set')
      && item.sourceName === 'trust zone-to-untrust zone'
    ));
    expect(sourceRuleSets).toHaveLength(1);
    expect(symbols.definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({ sourceName: 'PBF-FILTER', role: 'pbf-filter' }),
      expect.objectContaining({ sourceName: 'default', role: 'pbf-default-term' }),
      expect.objectContaining({ sourceName: 'dscp edge', namespace: 'cos-scheduler-map' }),
    ]));
    expect(symbols.references).toContainEqual(expect.objectContaining({
      referencePath: 'pbf_rules[0].next_hop_value#routing-instance',
      sourceName: 'PBF-prefer api',
    }));
    expect(() => planJunosIdentifiers(config)).not.toThrow();
  });

  it('catalogs classifier-style QoS entries in their emitted scheduler-map namespaces', () => {
    const config = {
      qos_config: [
        { type: 'classifier', name: 'Branch Map', classes: [{ name: 'Voice Class' }] },
        { type: 'shaping-profile', name: 'Branch@Map', classes: [{ name: 'Voice@Class' }] },
      ],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const plan = planJunosIdentifiers(config);

    expect(symbols.definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({
        definitionPath: 'qos_config[0].name',
        namespace: 'cos-scheduler-map',
      }),
      expect.objectContaining({
        definitionPath: 'qos_config[0].classes[0].name',
        namespace: 'cos-scheduler',
      }),
      expect.objectContaining({
        definitionPath: 'qos_config[0].classes[0].name#forwarding-class',
        namespace: 'forwarding-class',
      }),
    ]));
    expect(new Set(plan.mapping.entries
      .filter(entry => entry.namespace === 'cos-scheduler-map')
      .map(entry => entry.outputName)).size).toBe(2);
  });

  it('catalogs the generated BGP fallback group in the emitted group namespace', () => {
    const config = {
      bgp_config: [
        { networks: [{ policy: 'EXPORT-FALLBACK' }] },
        { peer_groups: [{ name: 'BGP@PEERS', neighbors: [] }] },
      ],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const plan = planJunosIdentifiers(config);

    expect(symbols.definitions).toContainEqual(expect.objectContaining({
      definitionPath: 'bgp_config[0]',
      namespace: 'bgp-group',
      sourceName: 'BGP-PEERS',
      generated: true,
      role: 'default-bgp-group',
    }));
    expect(new Set(plan.mapping.entries
      .filter(entry => entry.namespace === 'bgp-group')
      .map(entry => entry.outputName)).size).toBe(2);
  });

  it('gives each static NAT from-zone its own rule set', () => {
    const config = {
      zones: [{ name: 'outside a' }, { name: 'outside b' }, { name: 'inside' }],
      nat_rules: [
        { name: 'static a', type: 'static', src_zones: ['outside a'], dst_zones: ['inside'] },
        { name: 'static b', type: 'static', src_zones: ['outside b'], dst_zones: ['inside'] },
      ],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const ruleSets = symbols.definitions.filter(item => item.role?.startsWith('static-nat-rule-set'));
    const rules = symbols.definitions.filter(item => item.kind === 'static-nat-rule');

    expect(ruleSets.map(item => item.sourceName).sort()).toEqual(['STATIC-NAT-outside a', 'STATIC-NAT-outside b']);
    expect(new Set(rules.map(item => item.context)).size).toBe(2);
    expect(() => planJunosIdentifiers(config)).not.toThrow();
  });

  it('catalogs every source and destination NAT Cartesian zone pair', () => {
    const config = {
      zones: ['s1', 's2', 'd1', 'd2'].map(name => ({ name })),
      nat_rules: [{
        name: 'both rule',
        type: 'source-and-destination',
        src_zones: ['s1', 's2'],
        dst_zones: ['d1', 'd2'],
        translated_src: { type: 'dynamic-ip-pool', addresses: ['192.0.2.1'] },
        translated_dst: { address: '198.51.100.1' },
      }, {
        name: 'static rule',
        type: 'static',
        src_zones: ['s1', 's2'],
        dst_zones: ['d1', 'd2'],
      }],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const generatedRuleSets = type => symbols.definitions.filter(item => (
      item.role?.startsWith(`${type}-nat-rule-set`)
    ));
    const rules = type => symbols.definitions.filter(item => item.kind === `${type}-nat-rule`);

    expect(generatedRuleSets('source').map(item => item.sourceName).sort()).toEqual([
      's1-to-d1', 's1-to-d2', 's2-to-d1', 's2-to-d2',
    ]);
    expect(generatedRuleSets('destination').map(item => item.sourceName).sort()).toEqual([
      's1-to-d1', 's1-to-d2', 's2-to-d1', 's2-to-d2',
    ]);
    expect(rules('source')).toHaveLength(4);
    expect(rules('destination')).toHaveLength(4);
    expect(generatedRuleSets('static')).toHaveLength(2);
    expect(rules('static')).toHaveLength(2);
    expect(() => planJunosIdentifiers(config)).not.toThrow();
  });

  it('scopes every any-zone policy to the shared global policy namespace', () => {
    const config = {
      security_policies: [
        { name: 'same global', src_zones: ['any'], dst_zones: ['dmz'] },
        { name: 'same global', src_zones: ['trust'], dst_zones: ['any'] },
      ],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const policies = symbols.definitions.filter(item => item.kind === 'security-policy');

    expect(new Set(policies.map(item => item.context)).size).toBe(1);
    expect(capturePlanningError(() => planJunosIdentifiers(config)).code)
      .toBe('duplicate_definition');

    expect(() => planJunosIdentifiers({
      security_policies: [{
        name: 'one global', src_zones: ['any'], dst_zones: ['dmz', 'outside'],
      }],
    })).not.toThrow();
  });

  it('rejects repeated explicit VPN definitions but deduplicates SSL profiles', () => {
    const config = {
      vpn_tunnels: [
        {
          name: 'vpn one',
          ike_proposal: { name: 'shared ike' },
          ike_gateway: { name: 'shared gateway' },
          ipsec_proposal: { name: 'shared ipsec' },
        },
        {
          name: 'vpn two',
          ike_proposal: { name: 'shared ike' },
          ike_gateway: { name: 'shared gateway' },
          ipsec_proposal: { name: 'shared ipsec' },
        },
      ],
      decryption_rules: [
        { action: 'decrypt', decryption_type: 'ssl-forward-proxy', decryption_profile: 'shared tls' },
        { action: 'decrypt', decryption_type: 'ssl-forward-proxy', decryption_profile: 'shared tls' },
      ],
    };
    const symbols = collectJunosIdentifierSymbols(config);

    expect(symbols.definitions.filter(item => item.sourceName === 'shared ike')).toHaveLength(2);
    expect(symbols.definitions.filter(item => item.sourceName === 'shared tls')).toHaveLength(1);
    expect(capturePlanningError(() => planJunosIdentifiers(config)).code)
      .toBe('duplicate_definition');
  });

  it.each([
    ['forward then inbound', ['ssl-forward-proxy', 'ssl-inbound-inspection']],
    ['inbound then forward', ['ssl-inbound-inspection', 'ssl-forward-proxy']],
  ])('rejects ambiguous SSL policy profile references with %s ordering', (_label, modes) => {
    const config = {
      security_policies: [{
        name: 'decrypt policy',
        action: 'allow',
        _srx_decrypt: true,
        _srx_decrypt_profile: 'Shared TLS',
      }],
      decryption_rules: modes.map((decryptionType, index) => ({
        name: `decrypt-${index + 1}`,
        action: 'decrypt',
        decryption_type: decryptionType,
        decryption_profile: 'Shared TLS',
      })),
    };

    expect(capturePlanningError(() => planJunosIdentifiers(config))).toMatchObject({
      code: 'ambiguous_reference',
      namespace: 'ssl-proxy-profile',
      sourceName: 'Shared TLS',
      referencePaths: ['security_policies[0]._srx_decrypt_profile'],
    });
  });

  it('keeps VPN generated source identity distinct before allocation', () => {
    const plan = planJunosIdentifiers({
      vpn_tunnels: [{ name: 'A B' }, { name: 'A-B' }],
    });
    const policies = plan.mapping.entries.filter(item => item.namespace === 'ike-policy');

    expect(policies.map(item => item.sourceName).sort()).toEqual([
      'ike-pol-A B', 'ike-pol-A-B',
    ]);
    expect(new Set(policies.map(item => item.outputName)).size).toBe(2);
    expect(policies.every(item => item.resolution === 'generated-collision-renamed')).toBe(true);
  });

  it('models predefined service and vendor application aliases without definitions', () => {
    const config = {
      metadata: { source_vendor: 'fortigate' },
      service_objects: [{ name: 'Secure Web', protocol: 'tcp', port_range: '443' }],
      service_groups: [{ name: 'scalar services', members: ['Secure Web'] }],
      security_policies: [{
        name: 'mapped apps',
        applications: ['HTTPS'],
        services: ['Secure Web'],
      }],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const plan = planJunosIdentifiers(config);

    expect(symbols.definitions).not.toContainEqual(expect.objectContaining({
      sourceName: 'Secure Web',
    }));
    expect(symbols.references).toEqual(expect.arrayContaining([
      expect.objectContaining({
        sourceName: 'HTTPS',
        literalOutputName: 'junos-https',
      }),
      expect.objectContaining({
        sourceName: 'Secure Web',
        literalOutputName: 'junos-https',
      }),
    ]));
    expect(plan.nameForReference('security_policies[0].applications[0]'))
      .toBe('junos-https');
    expect(plan.nameForReference('security_policies[0].services[0]'))
      .toBe('junos-https');
  });

  it('expands application groups and binds generated custom and unmapped names', async () => {
    await loadAppMappings();
    setMapVendorApp(mapVendorApp);
    const config = {
      metadata: { source_vendor: 'panos' },
      application_groups: [{
        name: 'cloud bundle',
        members: ['HTTPS', 'unknown customer app'],
      }],
      security_policies: [{
        name: 'cloud policy',
        applications: ['cloud bundle', 'adobe-cloud'],
      }],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const plan = planJunosIdentifiers(config);

    expect(symbols.definitions).not.toContainEqual(expect.objectContaining({
      sourceName: 'cloud bundle',
    }));
    expect(symbols.definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({
        sourceName: 'unknown customer app',
        preferredOutputName: 'unknown-customer-app-UNMAPPED',
        role: 'unmapped-application',
      }),
      expect.objectContaining({
        sourceName: 'adobe-cloud',
        role: 'custom-application',
      }),
    ]));
    expect(plan.nameForReference('application_groups[0].members[0]'))
      .toBe('junos-https');
    expect(plan.nameForReference('application_groups[0].members[1]'))
      .toBe('unknown-customer-app-UNMAPPED');
    expect(plan.nameForReference('security_policies[0].applications[1]'))
      .toBe('adobe-cloud');
  });

  it('retains raw identities for colliding generated unmapped applications', () => {
    const config = {
      metadata: { source_vendor: 'fortigate' },
      security_policies: [{
        name: 'unmapped collisions',
        applications: ['foo bar', 'foo@bar'],
      }],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const plan = planJunosIdentifiers(config);
    const generated = symbols.definitions.filter(item => item.role === 'unmapped-application');

    expect(generated.map(item => item.sourceName).sort()).toEqual(['foo bar', 'foo@bar']);
    expect(generated.map(item => item.preferredOutputName))
      .toEqual(['foo-bar-UNMAPPED', 'foo-bar-UNMAPPED']);
    expect(plan.nameForReference('security_policies[0].applications[0]'))
      .not.toBe(plan.nameForReference('security_policies[0].applications[1]'));
    expect(plan.mapping.entries
      .filter(item => item.sourceName === 'foo bar' || item.sourceName === 'foo@bar')
      .every(item => item.resolution === 'generated-collision-renamed')).toBe(true);
  });

  it('narrows nested address and service group reference kinds', () => {
    const symbols = collectJunosIdentifierSymbols({
      address_objects: [{ name: 'host' }],
      address_groups: [
        { name: 'address child', members: ['host'] },
        { name: 'address parent', members: ['address child'] },
      ],
      service_objects: [{ name: 'custom service', protocol: 'tcp', port_range: '8080' }],
      service_groups: [
        { name: 'service child', members: ['custom service'] },
        { name: 'service parent', members: ['service child'] },
      ],
    });
    const referenceAt = path => symbols.references.find(item => item.referencePath === path);

    expect(referenceAt('address_groups[0].members[0]').compatibleKinds).toEqual(['address']);
    expect(referenceAt('address_groups[1].members[0]').compatibleKinds).toEqual(['address-set']);
    expect(referenceAt('service_groups[0].members[0]').compatibleKinds).toEqual(['application']);
    expect(referenceAt('service_groups[1].members[0]').compatibleKinds).toEqual(['application-set']);
  });

  it('uses Set passthrough names for SRX applications and unresolved services', () => {
    const config = {
      metadata: { source_vendor: 'srx' },
      service_objects: [{ name: 'missing port', protocol: 'tcp', port_range: '' }],
      security_policies: [{
        name: 'passthrough',
        applications: ['existing custom'],
        services: ['missing service'],
      }],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const plan = planJunosIdentifiers(config);

    expect(symbols.definitions).not.toContainEqual(expect.objectContaining({
      definitionPath: 'service_objects[0].name',
    }));
    expect(symbols.definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({ sourceName: 'existing custom', role: 'passthrough-application' }),
      expect.objectContaining({ sourceName: 'missing service', role: 'unresolved-service-application' }),
    ]));
    expect(plan.nameForReference('security_policies[0].applications[0]'))
      .toBe('existing-custom');
    expect(plan.nameForReference('security_policies[0].services[0]'))
      .toBe('missing-service');
  });

  it('assigns shared UTM and IDP generated names by semantic combination', () => {
    const policies = [
      { name: 'one', security_profiles: { virus: 'z av', spyware: 'strict spyware', 'application-control': 'edge apps' } },
      { name: 'two', security_profiles: { virus: 'a av', vulnerability: 'alert vuln' } },
      { name: 'three', security_profiles: { virus: 'z av', spyware: 'strict spyware', 'application-control': 'edge apps' } },
    ];
    const config = {
      security_policies: policies,
      security_profile_definitions: {
        'application-control:edge apps': { categories: { risky: 'block' } },
        'spyware:strict spyware': { severityActions: { critical: 'block' } },
      },
    };
    const forward = collectJunosIdentifierSymbols(config);
    const reversed = collectJunosIdentifierSymbols({
      ...config,
      security_policies: [policies[1], policies[0], policies[2]],
    });
    const generatedPolicies = symbols => new Map(symbols.definitions
      .filter(item => ['utm-policy', 'idp-policy'].includes(item.role))
      .map(item => [item.stableParentKey, item.sourceName]));

    expect(generatedPolicies(reversed)).toEqual(generatedPolicies(forward));
    expect(forward.references).toEqual(expect.arrayContaining([
      expect.objectContaining({ referencePath: 'security_policies[2]#utm-policy' }),
      expect.objectContaining({ referencePath: 'security_policies[2]#idp-policy' }),
      expect.objectContaining({
        referencePath: 'security_policies[0].security_profiles.virus',
        sourceName: 'z av',
        bindingSourceName: 'z av',
      }),
      expect.objectContaining({
        referencePath: 'security_policies[0].security_profiles.application-control',
        sourceName: 'edge apps',
        bindingSourceName: 'edge apps',
      }),
    ]));
    expect(forward.definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({ namespace: 'application-firewall-rule', sourceName: 'appfw-r1' }),
      expect.objectContaining({ namespace: 'idp-rule', sourceName: 'spyware-critical-r1' }),
    ]));
  });

  it('preserves fallback zone field paths for policies and NAT', () => {
    const symbols = collectJunosIdentifierSymbols({
      security_policies: [{ name: 'fallback policy', source_zones: ['inside'], destination_zones: ['outside'] }],
      nat_rules: [{ name: 'fallback nat', type: 'source', source_zones: ['inside'], destination_zones: ['outside'] }],
    });
    const paths = symbols.references.map(item => item.referencePath);

    expect(paths).toEqual(expect.arrayContaining([
      'security_policies[0].source_zones[0]',
      'security_policies[0].destination_zones[0]',
      'nat_rules[0].source_zones[0]',
      'nat_rules[0].destination_zones[0]',
    ]));
  });

  it('catalogs emitter-compatible generic policy and VPN generated names', () => {
    const symbols = collectJunosIdentifierSymbols({
      security_policies: [{
        name: 'Rule-1', action: 'allow', src_zones: ['Trust Zone'],
        dst_zones: ['DMZ'], applications: ['junos-https'],
      }],
      vpn_tunnels: [{ name: '9 branch' }],
    });

    expect(symbols.definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({
        sourceName: 'name:Rule-1',
        preferredOutputName: 'permit-trust-zone-to-dmz-https',
        definitionPath: 'security_policies[0]',
        role: 'security-policy:["Trust Zone","DMZ"]',
        stableParentKey: 'security-policy:name:Rule-1',
      }),
      expect.objectContaining({
        sourceName: 'ike-pol-9 branch',
        definitionPath: 'vpn_tunnels[0]',
        role: 'ike-policy',
      }),
    ]));
  });

  it('keeps PBF shared-next-hop identity stable when rules are reordered', () => {
    const rules = [
      { name: 'z route', action: 'forward', next_hop_value: '192.0.2.1' },
      { name: 'a route', action: 'forward', next_hop_value: '192.0.2.1' },
    ];
    const generated = symbols => symbols.definitions.find(item => item.role === 'pbf-routing-instance');
    const forward = generated(collectJunosIdentifierSymbols({ pbf_rules: rules }));
    const reversed = generated(collectJunosIdentifierSymbols({ pbf_rules: [...rules].reverse() }));

    expect(forward.sourceName).toBe('PBF-a route');
    expect(reversed.sourceName).toBe(forward.sourceName);
    expect(reversed.stableParentKey).toBe(forward.stableParentKey);
  });

  it('uses emitter profile truncation and canonical SecIntel rule ordering', () => {
    const longProfile = `${'profile'.repeat(6)} tail`;
    const externalLists = [
      { name: 'z feed', isBlockList: true },
      { name: 'a feed', isBlockList: true },
    ];
    const collect = lists => collectJunosIdentifierSymbols({
      security_policies: [{ name: 'profile policy', security_profiles: { virus: longProfile } }],
      external_lists: lists,
    });
    const forward = collect(externalLists);
    const reversed = collect([...externalLists].reverse());
    const antiVirus = forward.definitions.find(item => item.kind === 'anti-virus-profile');
    const secIntel = symbols => new Map(symbols.definitions
      .filter(item => item.role === 'security-intelligence-rule')
      .map(item => [item.stableParentKey, item.sourceName]));

    expect(antiVirus.sourceName).toBe(longProfile);
    expect(antiVirus.preferredOutputName)
      .toBe(`custom-av-${sanitizeForTest(longProfile).slice(0, 24)}`);
    expect(forward.references).toContainEqual(expect.objectContaining({
      referencePath: 'security_policies[0].security_profiles.virus',
      bindingSourceName: antiVirus.sourceName,
    }));
    expect(secIntel(reversed)).toEqual(secIntel(forward));
    expect(secIntel(forward).get('external-list:a feed')).toBe('secIntel-rule-1');
  });

  it('catalogs emitted DNS-security filtering rules and references', () => {
    const config = {
      security_policies: [{
        name: 'dns policy',
        security_profiles: { 'dns-security': 'Strict DNS' },
      }],
      security_profile_definitions: {
        'dns-security:Strict DNS': { blockedDomains: ['bad.example'] },
      },
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const plan = planJunosIdentifiers(config);

    expect(symbols.definitions).toContainEqual(expect.objectContaining({
      namespace: 'dns-filtering-rule',
      kind: 'dns-filtering-rule',
      sourceName: 'Strict DNS',
      definitionPath: 'security_policies[0]',
      role: 'security-feature:dns-filtering-rule',
    }));
    expect(symbols.references).toContainEqual(expect.objectContaining({
      namespace: 'dns-filtering-rule',
      sourceName: 'Strict DNS',
      referencePath: 'security_policies[0].security_profiles.dns-security',
    }));
    expect(plan.nameForReference('security_policies[0].security_profiles.dns-security'))
      .toBe(plan.nameForGenerated('security_policies[0]', 'security-feature:dns-filtering-rule'));
  });

  it('preserves periods only for explicit multi-port preferred names', () => {
    const plan = planJunosIdentifiers({
      service_objects: [{ name: 'Foo.Bar', protocol: 'tcp', port_range: '8080,8081' }],
      applications: [{ name: 'Baz.Qux', protocol: 'udp', port: '9000,9001' }],
      security_policies: [{ name: 'custom', applications: ['unknown.app'] }],
    });

    expect(plan.nameForGenerated('service_objects[0]', 'service-multi-port-set'))
      .toBe('Foo.Bar-set');
    expect(plan.nameForGenerated('service_objects[0]', 'service-port:8080'))
      .toBe('Foo.Bar-8080');
    expect(plan.nameForGenerated('applications[0]', 'application-multi-port-set'))
      .toBe('Baz.Qux-set');
    expect(plan.nameForGenerated('applications[0]', 'application-port:9000'))
      .toBe('Baz.Qux-9000');
    expect(plan.nameForReference('security_policies[0].applications[0]'))
      .toBe('unknown-app-UNMAPPED');
  });

  it('plans missing NAT zones as stable generated definitions bound to references', () => {
    const rules = [
      {
        name: 'Branch One', type: 'source',
        src_zones: ['Branch Zone'], dst_zones: ['outside'],
      },
      {
        name: 'Branch Two', type: 'source',
        src_zones: ['Branch@Zone'], dst_zones: ['outside'],
      },
    ];
    const configFor = natRules => ({
      zones: [{ name: 'outside' }],
      nat_rules: natRules,
    });
    const forwardSymbols = collectJunosIdentifierSymbols(configFor(rules));
    const forward = planJunosIdentifiers(configFor(rules));
    const reversed = planJunosIdentifiers(configFor([...rules].reverse()));
    const generated = forwardSymbols.definitions.filter(item => (
      item.namespace === 'zone' && item.role?.startsWith('nat-missing-zone:')
    ));
    const outputs = plan => new Map(plan.mapping.entries
      .filter(entry => entry.namespace === 'zone' && entry.sourceName.startsWith('Branch'))
      .map(entry => [entry.sourceName, entry.outputName]));

    expect(generated).toEqual(expect.arrayContaining([
      expect.objectContaining({
        sourceName: 'Branch Zone',
        definitionPath: 'nat_rules',
        role: 'nat-missing-zone:Branch Zone',
        stableParentKey: 'nat-missing-zone:Branch Zone',
      }),
      expect.objectContaining({
        sourceName: 'Branch@Zone',
        definitionPath: 'nat_rules',
        role: 'nat-missing-zone:Branch@Zone',
        stableParentKey: 'nat-missing-zone:Branch@Zone',
      }),
    ]));
    expect(outputs(reversed)).toEqual(outputs(forward));
    expect(new Set(outputs(forward).values()).size).toBe(2);
    for (const entry of forward.mapping.entries.filter(item => (
      item.namespace === 'zone' && item.sourceName.startsWith('Branch')
    ))) {
      expect(entry.definitionPath).toContain('#generated:nat-missing-zone:');
      expect(entry.referencePaths).toHaveLength(1);
      expect(forward.nameForReference(entry.referencePaths[0])).toBe(entry.outputName);
      expect(forward.nameForGenerated('nat_rules', `nat-missing-zone:${entry.sourceName}`))
        .toBe(entry.outputName);
    }
  });

  it('keeps VPN traffic-selector identities stable when proxy IDs are reordered', () => {
    const selectors = [
      { local: '10.2.0.0/16', remote: '172.16.2.0/24' },
      { local: '10.1.0.0/16', remote: '172.16.1.0/24' },
    ];
    const configFor = proxyId => ({
      vpn_tunnels: [{ name: 'Branch VPN', proxy_id: proxyId }],
    });
    const forward = planJunosIdentifiers(configFor(selectors));
    const reversed = planJunosIdentifiers(configFor([...selectors].reverse()));

    expect(forward.nameForGenerated('vpn_tunnels[0].proxy_id[0]', 'vpn-traffic-selector'))
      .toBe(reversed.nameForGenerated('vpn_tunnels[0].proxy_id[1]', 'vpn-traffic-selector'));
    expect(forward.nameForGenerated('vpn_tunnels[0].proxy_id[1]', 'vpn-traffic-selector'))
      .toBe(reversed.nameForGenerated('vpn_tunnels[0].proxy_id[0]', 'vpn-traffic-selector'));
    expect(forward.nameForReference('vpn_tunnels[0].proxy_id[0]#traffic-selector'))
      .toBe(forward.nameForGenerated('vpn_tunnels[0].proxy_id[0]', 'vpn-traffic-selector'));
  });

  it('catalogs absent identifier fields as generated owner-scoped fallbacks', () => {
    const symbols = collectJunosIdentifierSymbols({
      screen_config: [{ zone: 'outside' }],
      vpn_tunnels: [{}],
      dhcp_config: [{
        type: 'server', network: '10.0.0.0/24',
        ranges: [{ low: '10.0.0.10', high: '10.0.0.20' }],
      }],
      flow_monitoring_config: { collectors: [{ address: '192.0.2.1' }] },
      qos_config: [{ type: 'shaping-profile', name: 'map', classes: [{}] }],
    });

    expect(symbols.definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({ sourceName: 'default-screen', definitionPath: 'screen_config[0]', generated: true, role: 'default-screen-profile' }),
      expect.objectContaining({ sourceName: 'vpn-1', definitionPath: 'vpn_tunnels[0]', generated: true, role: 'ipsec-vpn' }),
      expect.objectContaining({ sourceName: 'dhcp-pool', definitionPath: 'dhcp_config[0]', generated: true, role: 'dhcp-pool' }),
      expect.objectContaining({ sourceName: 'range1', definitionPath: 'dhcp_config[0].ranges[0]', generated: true, role: 'dhcp-named-range' }),
      expect.objectContaining({ sourceName: 'FLOW-SAMPLE', definitionPath: 'flow_monitoring_config', generated: true, role: 'sampling-instance' }),
      expect.objectContaining({ sourceName: 'default', definitionPath: 'qos_config[0].classes[0]', generated: true, role: 'qos-default-scheduler' }),
      expect.objectContaining({ sourceName: 'default', definitionPath: 'qos_config[0].classes[0]', generated: true, role: 'qos-default-forwarding-class' }),
    ]));
  });

  it('keeps generated comma-port, DHCP, and flow identities stable under reordering', () => {
    const config = {
      service_objects: [{ name: 'ports', protocol: 'tcp', port_range: '9001,9000' }],
      dhcp_config: [{
        type: 'server', name: 'pool', network: '10.0.0.0/24',
        pools: ['10.0.0.30-10.0.0.40', '10.0.0.10-10.0.0.20'],
      }],
      flow_monitoring_config: {
        collectors: [{ address: '192.0.2.2' }, { address: '192.0.2.1' }],
      },
    };
    const reordered = {
      ...config,
      service_objects: [{ ...config.service_objects[0], port_range: '9000,9001' }],
      dhcp_config: [{ ...config.dhcp_config[0], pools: [...config.dhcp_config[0].pools].reverse() }],
      flow_monitoring_config: {
        collectors: [...config.flow_monitoring_config.collectors].reverse(),
      },
    };
    const identities = symbols => new Map(symbols.definitions
      .filter(item => item.generated && [
        'service-port:9000', 'service-port:9001', 'dhcp-pool-range',
        'collector-flow-template',
      ].includes(item.role))
      .map(item => [`${item.stableParentKey}\0${item.role}`, item.sourceName]));

    expect(identities(collectJunosIdentifierSymbols(reordered)))
      .toEqual(identities(collectJunosIdentifierSymbols(config)));
  });

  it('always treats default and master routing instances as built-in literals', () => {
    const config = {
      static_routes: [{ destination: '192.0.2.0/24', vrf: 'default' }],
      bgp_config: [{ instance: 'master' }],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const plan = planJunosIdentifiers(config);

    expect(symbols.definitions).not.toContainEqual(expect.objectContaining({
      namespace: 'routing-instance',
      sourceName: 'default',
    }));
    expect(symbols.definitions).not.toContainEqual(expect.objectContaining({
      namespace: 'routing-instance',
      sourceName: 'master',
    }));
    expect(plan.nameForReference('static_routes[0].vrf')).toBe('default');
    expect(plan.nameForReference('bgp_config[0].instance')).toBe('master');
  });

  it('keeps raw security-profile identities when emitter bases collide', () => {
    const config = {
      security_policies: [
        { name: 'profile one', security_profiles: { virus: 'foo bar' } },
        { name: 'profile two', security_profiles: { virus: 'foo@bar' } },
      ],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const plan = planJunosIdentifiers(config);
    const profiles = symbols.definitions.filter(item => (
      item.namespace === 'utm-anti-virus-profile'
    ));

    expect(profiles.map(item => item.sourceName).sort()).toEqual(['foo bar', 'foo@bar']);
    expect(profiles.map(item => item.preferredOutputName))
      .toEqual(['custom-av-foo-bar', 'custom-av-foo-bar']);
    expect(plan.nameForReference('security_policies[0].security_profiles.virus'))
      .not.toBe(plan.nameForReference('security_policies[1].security_profiles.virus'));
    expect(plan.mapping.entries.filter(item => (
      item.namespace === 'utm-anti-virus-profile'
    )).every(item => item.resolution === 'generated-collision-renamed')).toBe(true);
  });

  it('canonicalizes equivalent UTM feature owners across profile types and policy order', () => {
    const policies = [
      { name: 'wildfire owner', security_profiles: { 'wildfire-analysis': 'Shared AV' } },
      { name: 'virus owner', security_profiles: { virus: 'Shared AV' } },
      { name: 'collision', security_profiles: { virus: 'Shared@AV' } },
    ];
    const configFor = securityPolicies => ({ security_policies: securityPolicies });
    const forwardSymbols = collectJunosIdentifierSymbols(configFor(policies));
    const reverseSymbols = collectJunosIdentifierSymbols(configFor([...policies].reverse()));
    const featureIdentity = symbols => symbols.definitions
      .filter(item => item.namespace === 'utm-anti-virus-profile')
      .map(item => ({
        sourceName: item.sourceName,
        role: item.role,
        stableParentKey: item.stableParentKey,
      }))
      .sort((left, right) => left.sourceName.localeCompare(right.sourceName));
    const outputBySource = plan => new Map(plan.mapping.entries
      .filter(item => item.namespace === 'utm-anti-virus-profile')
      .map(item => [item.sourceName, item.outputName]));

    expect(featureIdentity(reverseSymbols)).toEqual(featureIdentity(forwardSymbols));
    expect(outputBySource(planJunosIdentifiers(configFor([...policies].reverse()))))
      .toEqual(outputBySource(planJunosIdentifiers(configFor(policies))));
  });

  it('uses any-zone definitions and synthetic references for explicit empty zone arrays', () => {
    const config = {
      security_policies: [{
        name: 'empty policy', src_zones: [], dst_zones: [],
      }],
      nat_rules: [{
        name: 'empty nat', type: 'source', src_zones: [], dst_zones: [],
      }],
    };
    const symbols = collectJunosIdentifierSymbols(config);

    expect(symbols.definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({
        kind: 'security-policy', context: 'root/global-policy', sourceName: 'empty policy',
      }),
      expect.objectContaining({
        kind: 'source-nat-rule-set', sourceName: 'any-to-any',
      }),
      expect.objectContaining({
        kind: 'source-nat-rule', sourceName: 'empty nat',
        context: 'root/nat:source/rule-set:["any","any"]',
      }),
    ]));
    expect(symbols.references).toEqual(expect.arrayContaining([
      expect.objectContaining({ sourceName: 'any', referencePath: 'security_policies[0]#effective-source-zone' }),
      expect.objectContaining({ sourceName: 'any', referencePath: 'security_policies[0]#effective-destination-zone' }),
      expect.objectContaining({ sourceName: 'any', referencePath: 'nat_rules[0]#effective-source-zone' }),
      expect.objectContaining({ sourceName: 'any', referencePath: 'nat_rules[0]#effective-destination-zone' }),
    ]));
    expect(() => planJunosIdentifiers(config)).not.toThrow();
  });

  it('preserves semantic suffixes within 63-character application identifiers', () => {
    const longUnknown = 'u'.repeat(63);
    const longCustom = 'c'.repeat(63);
    const config = {
      metadata: { source_vendor: 'fortigate' },
      applications: [{ name: longCustom, protocol: 'tcp', port: '80,443' }],
      security_policies: [{
        name: 'long apps', applications: [longUnknown, longCustom],
      }],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const plan = planJunosIdentifiers(config);
    const preferred = symbols.definitions
      .filter(item => item.preferredOutputName)
      .map(item => item.preferredOutputName);

    expect(preferred).toEqual(expect.arrayContaining([
      expect.stringMatching(/-UNMAPPED$/),
      expect.stringMatching(/-set$/),
      expect.stringMatching(/-80$/),
      expect.stringMatching(/-443$/),
    ]));
    expect(preferred.every(name => name.length <= 63)).toBe(true);
    expect(() => plan.nameForReference('security_policies[0].applications[0]')).not.toThrow();
    expect(() => plan.nameForReference('security_policies[0].applications[1]')).not.toThrow();
  });

  it('reserves catalog literals even when no reference uses them', () => {
    const config = {
      applications: [{ name: 'junos-https', protocol: 'tcp', port: '9443' }],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const plan = planJunosIdentifiers(config);

    expect(symbols.reservations).toContainEqual(expect.objectContaining({
      context: 'root/applications',
      namespace: 'application-entry',
      outputName: 'junos-https',
    }));
    expect(plan.nameForDefinition('applications[0].name')).not.toBe('junos-https');
  });

  it('passes SRX application identities through before vendor mapping', () => {
    const config = {
      metadata: { source_vendor: 'srx' },
      security_policies: [{ name: 'passthrough HTTP', applications: ['HTTP'] }],
    };
    const symbols = collectJunosIdentifierSymbols(config);
    const plan = planJunosIdentifiers(config);

    expect(symbols.definitions).toContainEqual(expect.objectContaining({
      sourceName: 'HTTP', role: 'passthrough-application',
    }));
    expect(symbols.references).toContainEqual(expect.objectContaining({
      sourceName: 'HTTP', bindingSourceName: 'HTTP',
    }));
    expect(plan.nameForReference('security_policies[0].applications[0]')).toBe('HTTP');
  });

  it('catalogs only emitted DHCP pool ranges before canonical numbering', () => {
    const symbols = collectJunosIdentifierSymbols({
      dhcp_config: [{
        type: 'server', name: 'filtered', network: '10.0.0.0/24',
        pools: ['not-a-range-', 'invalid', '', '10.0.0.10-10.0.0.20'],
      }],
    });
    const ranges = symbols.definitions.filter(item => item.role === 'dhcp-pool-range');

    expect(ranges).toEqual([
      expect.objectContaining({
        sourceName: 'range1',
        definitionPath: 'dhcp_config[0].pools[3]',
        stableParentKey: 'dhcp-pool:filtered:range:10.0.0.10-10.0.0.20',
      }),
    ]);
  });

  it('collects merged logical-system slots and cross-link references', () => {
    const slots = [
      { lsName: 'branch a', intermediateConfig: { zones: [{ name: 'transit zone' }] }, interfaceMappings: {} },
      { lsName: 'branch b', intermediateConfig: { zones: [{ name: 'transit zone' }] }, interfaceMappings: {} },
    ];
    const links = [{ ls1: 'branch a', ls2: 'branch b', sharedZone: 'transit zone' }];
    const symbols = collectMergedJunosIdentifierSymbols(slots, links);
    const plan = planMergedJunosIdentifiers(slots, links);

    expect(symbols.definitions).toEqual(expect.arrayContaining([
      expect.objectContaining({ definitionPath: 'configSlots[0].lsName', sourceName: 'branch a' }),
      expect.objectContaining({ definitionPath: 'configSlots[1].lsName', sourceName: 'branch b' }),
      expect.objectContaining({ definitionPath: 'configSlots[0].intermediateConfig.zones[0].name' }),
    ]));
    expect(symbols.definitions.some(definition => definition.role?.startsWith('cross-link-zone-')))
      .toBe(false);
    expect(symbols.references).toEqual(expect.arrayContaining([
      expect.objectContaining({ referencePath: 'crossLsLinks[0].ls1', sourceName: 'branch a' }),
      expect.objectContaining({ referencePath: 'crossLsLinks[0].ls2', sourceName: 'branch b' }),
      expect.objectContaining({ referencePath: 'crossLsLinks[0].sharedZone#ls1', sourceName: 'transit zone' }),
      expect.objectContaining({ referencePath: 'crossLsLinks[0].sharedZone#ls2', sourceName: 'transit zone' }),
    ]));
    expect(plan.nameForReference('crossLsLinks[0].sharedZone#ls1'))
      .toBe(plan.nameForDefinition('configSlots[0].intermediateConfig.zones[0].name'));
    expect(plan.nameForReference('crossLsLinks[0].sharedZone#ls2'))
      .toBe(plan.nameForDefinition('configSlots[1].intermediateConfig.zones[0].name'));
  });

  it('generates a cross-link zone only on a missing side and binds both references', () => {
    const slots = [
      { lsName: 'branch a', intermediateConfig: { zones: [{ name: 'transit zone' }] } },
      { lsName: 'branch b', intermediateConfig: { zones: [] } },
    ];
    const links = [{ ls1: 'branch a', ls2: 'branch b', sharedZone: 'transit zone' }];
    const symbols = collectMergedJunosIdentifierSymbols(slots, links);
    const plan = planMergedJunosIdentifiers(slots, links);
    const generated = symbols.definitions.filter(definition => (
      definition.role?.startsWith('cross-link-zone-')
    ));

    expect(generated).toEqual([
      expect.objectContaining({
        context: 'logical-system:branch b',
        definitionPath: 'crossLsLinks[0].sharedZone#ls2',
        role: 'cross-link-zone-ls2',
      }),
    ]);
    expect(plan.nameForReference('crossLsLinks[0].sharedZone#ls1'))
      .toBe(plan.nameForDefinition('configSlots[0].intermediateConfig.zones[0].name'));
    expect(plan.nameForReference('crossLsLinks[0].sharedZone#ls2'))
      .toBe(plan.nameForGenerated('crossLsLinks[0].sharedZone#ls2', 'cross-link-zone-ls2'));
  });

  it('generates and binds cross-link zones when absent on both sides', () => {
    const slots = [
      { lsName: 'branch a', intermediateConfig: { zones: [] } },
      { lsName: 'branch b', intermediateConfig: { zones: [] } },
    ];
    const links = [{ ls1: 'branch a', ls2: 'branch b', sharedZone: 'transit zone' }];
    const symbols = collectMergedJunosIdentifierSymbols(slots, links);
    const plan = planMergedJunosIdentifiers(slots, links);
    const generated = symbols.definitions.filter(definition => (
      definition.role?.startsWith('cross-link-zone-')
    ));

    expect(generated).toHaveLength(2);
    expect(plan.nameForReference('crossLsLinks[0].sharedZone#ls1'))
      .toBe(plan.nameForGenerated('crossLsLinks[0].sharedZone#ls1', 'cross-link-zone-ls1'));
    expect(plan.nameForReference('crossLsLinks[0].sharedZone#ls2'))
      .toBe(plan.nameForGenerated('crossLsLinks[0].sharedZone#ls2', 'cross-link-zone-ls2'));
  });

  it('selects a stable generated cross-link owner when links are reordered', () => {
    const slots = [
      { lsName: 'branch a', intermediateConfig: { zones: [] } },
      { lsName: 'branch b', intermediateConfig: { zones: [] } },
      { lsName: 'branch c', intermediateConfig: { zones: [] } },
    ];
    const links = [
      { ls1: 'branch a', ls2: 'branch b', sharedZone: 'transit zone' },
      { ls1: 'branch c', ls2: 'branch a', sharedZone: 'transit zone' },
    ];
    const generatedForBranchA = inputLinks => collectMergedJunosIdentifierSymbols(
      slots,
      inputLinks,
    ).definitions.find(definition => (
      definition.context === 'logical-system:branch a'
      && definition.sourceName === 'transit zone'
      && definition.generated
    ));
    const forward = generatedForBranchA(links);
    const reordered = generatedForBranchA([...links].reverse());

    expect({ role: reordered.role, stableParentKey: reordered.stableParentKey }).toEqual({
      role: forward.role,
      stableParentKey: forward.stableParentKey,
    });
  });

  it('keeps cross-link zone collision groups local to each logical system', () => {
    const slots = [
      {
        lsName: 'branch a',
        intermediateConfig: { zones: [{ name: 'Shared Zone' }, { name: 'Shared@Zone' }] },
      },
      {
        lsName: 'branch b',
        intermediateConfig: { zones: [{ name: 'Shared@Zone' }] },
      },
    ];
    const links = [{ ls1: 'branch a', ls2: 'branch b', sharedZone: 'Shared Zone' }];
    const plan = planMergedJunosIdentifiers(slots, links);

    expect(plan.nameForReference('crossLsLinks[0].sharedZone#ls1'))
      .not.toBe(plan.nameForReference('crossLsLinks[0].sharedZone#ls2'));
  });

  it('rejects non-concrete cross-link zone literals at the exact source path', () => {
    const slots = [
      { lsName: 'branch a', intermediateConfig: { zones: [] } },
      { lsName: 'branch b', intermediateConfig: { zones: [] } },
    ];
    const links = [{ ls1: 'branch a', ls2: 'branch b', sharedZone: 'any' }];

    expect(() => planMergedJunosIdentifiers(slots, links)).toThrow(expect.objectContaining({
      name: 'JunosSerializationError',
      fieldPath: 'crossLsLinks[0].sharedZone',
      valueKind: 'zone',
    }));
    expect(() => planMergedJunosIdentifiers(slots, links)).toThrow(JunosSerializationError);
  });

  it('reuses NAT-generated missing zones for cross-link side references', () => {
    const intermediateConfig = {
      zones: [{ name: 'outside' }],
      nat_rules: [{
        name: 'Transit NAT',
        type: 'source',
        src_zones: ['Transit Zone'],
        dst_zones: ['outside'],
      }],
    };
    const slots = [
      { lsName: 'branch a', intermediateConfig },
      { lsName: 'branch b', intermediateConfig },
    ];
    const links = [{ ls1: 'branch a', ls2: 'branch b', sharedZone: 'Transit Zone' }];
    const plan = planMergedJunosIdentifiers(slots, links);
    const zones = plan.mapping.entries.filter(entry => (
      entry.namespace === 'zone' && entry.sourceName === 'Transit Zone'
    ));

    expect(zones).toHaveLength(2);
    for (const [slotIndex, side] of ['ls1', 'ls2'].entries()) {
      const zone = zones.find(entry => entry.context === `logical-system:${slots[slotIndex].lsName}`);
      expect(zone.definitionPath).toContain('#generated:nat-missing-zone:Transit Zone');
      expect(zone.referencePaths).toEqual([
        `configSlots[${slotIndex}].intermediateConfig.nat_rules[0].src_zones[0]`,
        `crossLsLinks[0].sharedZone#${side}`,
      ]);
      expect(plan.nameForReference(`crossLsLinks[0].sharedZone#${side}`)).toBe(zone.outputName);
    }
  });

  it.each([
    [
      'unknown',
      [
        { lsName: 'branch a', intermediateConfig: {} },
        { lsName: 'branch b', intermediateConfig: {} },
      ],
      [{ ls1: 'missing', ls2: 'branch b', sharedZone: 'transit' }],
    ],
    [
      'ambiguous',
      [
        { lsName: 'branch a', intermediateConfig: {} },
        { lsName: 'branch a', intermediateConfig: {} },
      ],
      [{ ls1: 'branch a', ls2: 'branch a', sharedZone: 'transit' }],
    ],
  ])('fails closed for %s cross-link logical-system endpoints', (_label, slots, links) => {
    expect(() => planMergedJunosIdentifiers(slots, links)).toThrow();
  });

  it('exposes frozen catalog keys and deterministic public planning wrappers', () => {
    expect(Object.isFrozen(JUNOS_IDENTIFIER_CATALOG)).toBe(true);
    expect(JUNOS_IDENTIFIER_CATALOG).toMatchObject({
      TARGET_CONTEXT: 'target-context',
      ADDRESS_BOOK: 'address-book',
      POLICY: 'security-policy',
      FLOW: 'flow-monitoring',
    });

    const config = fullConfig();
    const options = { targetContext: { type: 'logical-system', name: 'branch a' } };
    const forward = planJunosIdentifiers(config, options);
    const reordered = planJunosIdentifiers({
      ...config,
      zones: [...config.zones].reverse(),
      address_objects: [...config.address_objects].reverse(),
    }, options);
    expect(reordered.mapping.entries.map(({ definitionPath, ...entry }) => entry))
      .toEqual(forward.mapping.entries.map(({ definitionPath, ...entry }) => entry));

    const merged = planMergedJunosIdentifiers([
      { lsName: 'branch a', intermediateConfig: { zones: [{ name: 'inside' }] } },
    ]);
    expect(merged.nameForDefinition('configSlots[0].lsName')).toBe('branch-a');
  });
});
