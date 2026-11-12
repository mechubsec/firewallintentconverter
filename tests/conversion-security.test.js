import fs from 'node:fs';

import { describe, expect, it } from 'vitest';

import { convertConfig, mergeConvert } from '../public/utils/engine.js';
import { JunosIdentifierPlanningError } from '../src/security/junos-identifiers.js';
import { JunosSerializationError } from '../src/security/junos-serialization.js';

const storage = new Map();
globalThis.localStorage = {
  getItem: key => storage.get(key) ?? null,
  setItem: (key, value) => storage.set(key, String(value)),
  removeItem: key => storage.delete(key),
};

const { formatJunosSerializationError, getExportPolicies } = await import('../public/hooks/useConversion.js');

function collisionConfig() {
  return {
    metadata: { source_vendor: 'panos' },
    zones: [
      { name: 'trust', interfaces: [] },
      { name: 'untrust', interfaces: [] },
    ],
    address_objects: [
      { name: 'Web Server', type: 'host', value: '192.0.2.10/32' },
      { name: 'Web@Server', type: 'host', value: '192.0.2.11/32' },
    ],
    address_groups: [{
      name: 'Web Farm',
      members: ['Web Server', 'Web@Server'],
    }],
    service_objects: [],
    service_groups: [],
    applications: [],
    application_groups: [],
    schedules: [],
    security_policies: [
      {
        name: 'Allow Web One',
        src_zones: ['trust'],
        dst_zones: ['untrust'],
        src_addresses: ['any'],
        dst_addresses: ['Web Server'],
        applications: ['junos-https'],
        services: [],
        action: 'allow',
      },
      {
        name: 'Allow Web Two',
        src_zones: ['trust'],
        dst_zones: ['untrust'],
        src_addresses: ['any'],
        dst_addresses: ['Web@Server'],
        applications: ['junos-https'],
        services: [],
        action: 'allow',
      },
    ],
    nat_rules: [],
    interfaces: [],
  };
}

function mergeSlot(lsName, intermediateConfig) {
  return { lsName, intermediateConfig, interfaceMappings: {} };
}

describe('conversion fail-closed behavior', () => {
  it('formats a typed error with its safe path and reason', () => {
    const error = new JunosSerializationError(
      'metadata.siteName',
      'scalar',
      'control characters are not allowed',
    );

    expect(formatJunosSerializationError(error, 'Conversion')).toBe(
      'Conversion blocked: metadata.siteName — control characters are not allowed',
    );
  });

  it('does not reflect a rejected value in typed error output', () => {
    const rejectedValue = 'attacker\nset system services telnet';
    const error = new JunosSerializationError(
      'metadata.siteName',
      'scalar',
      'control characters are not allowed',
    );

    expect(formatJunosSerializationError(error, 'Conversion'))
      .not.toContain(rejectedValue);
  });

  it('formats identifier planning errors without configuration content', () => {
    const error = new JunosIdentifierPlanningError('ambiguous_reference', {
      namespace: 'address-book-entry',
      context: 'root/address-book:global',
      sourceName: 'Web Server',
      referencePaths: ['security_policies[0].dst_addresses[0]'],
      reason: 'reference matches more than one definition',
    });
    const message = formatJunosSerializationError(error, 'Conversion');

    expect(message).toContain('Conversion blocked');
    expect(message).toContain('ambiguous_reference');
    expect(message).not.toContain('Web Server');
    expect(message).not.toContain('address-book-entry');
    expect(message).not.toContain('set security');
  });

  it('does not reflect context-only identifier planning metadata', () => {
    const secretContext = 'logical-system:Secret Branch/zone:Private Servers';
    const error = new JunosIdentifierPlanningError('allocation_failed', {
      namespace: 'security-policy',
      context: secretContext,
      sourceName: 'Secret Allow Rule',
      reason: 'could not allocate a unique Junos identifier',
    });
    const message = formatJunosSerializationError(error, 'Conversion');

    expect(message).toContain('Conversion blocked');
    expect(message).toContain('allocation_failed');
    expect(message).toContain('could not allocate a unique Junos identifier');
    expect(message).not.toContain(secretContext);
    expect(message).not.toContain('Secret Branch');
    expect(message).not.toContain('Private Servers');
    expect(message).not.toContain('Secret Allow Rule');
    expect(message).not.toContain('security-policy');
  });

  it('strips source-derived synthetic suffixes from definition paths', () => {
    const error = new JunosIdentifierPlanningError('allocation_failed', {
      definitionPaths: [
        'security_policies[0].name#zone-pair:CUSTOMER-SECRET-SRC->CUSTOMER-SECRET-DST',
      ],
      reason: 'could not allocate a unique Junos identifier',
    });

    expect(formatJunosSerializationError(error, 'Conversion')).toBe(
      'Conversion blocked: allocation_failed at security_policies[0].name — could not allocate a unique Junos identifier',
    );
  });

  it('omits non-structural reference paths with source-derived keys', () => {
    const unsafePath = 'address_objects.CUSTOMER-SECRET:DMZ.name';
    const error = new JunosIdentifierPlanningError('ambiguous_reference', {
      referencePaths: [unsafePath],
      reason: 'reference matches more than one definition',
    });
    const message = formatJunosSerializationError(error, 'Conversion');

    expect(message).toBe(
      'Conversion blocked: ambiguous_reference — reference matches more than one definition',
    );
    expect(message).not.toContain(unsafePath);
    expect(message).not.toContain('CUSTOMER-SECRET');
  });

  it('blocks unsafe data through both public engine paths', async () => {
    await expect(convertConfig(
      { metadata: { siteName: 'x\nset system services telnet' } },
      'set',
    )).rejects.toMatchObject({ fieldPath: 'metadata.siteName' });

    await expect(mergeConvert(
      [{ lsName: 'x\nset system services telnet', intermediateConfig: {} }],
      [],
      'xml',
    )).rejects.toHaveProperty('name', 'JunosSerializationError');
  });

  it('gates acceptance on the translated policies that are exported', () => {
    const translated = [{ name: 't', _review_status: 'pending' }];
    const source = { security_policies: [{ name: 's', _review_status: 'accepted' }] };
    expect(getExportPolicies(translated, source)).toBe(translated);
    expect(getExportPolicies(null, source)).toBe(source.security_policies);
  });

  it('clears stale output before work and in both error handlers', () => {
    const source = fs.readFileSync(
      new URL('../public/hooks/useConversion.js', import.meta.url),
      'utf8',
    );
    const clearCalls = source.match(/conversionDispatch\(\{ type: 'CLEAR_OUTPUT' \}\)/g) || [];

    expect(clearCalls).toHaveLength(5);
    expect(source).toContain("formatJunosSerializationError(err, 'Conversion')");
    expect(source).toContain("formatJunosSerializationError(err, 'Merge conversion')");
  });

  it('keeps completed-artifact validation at the public engine boundary', () => {
    const source = fs.readFileSync(
      new URL('../public/utils/engine.js', import.meta.url),
      'utf8',
    );

    expect(source).toContain('validateSetOutput(output.commands)');
    expect(source).toContain('validateXmlOutput(output.xml)');
  });

  it('returns canonical discriminated output through both public engine paths', async () => {
    const intermediate = {
      metadata: {},
      zones: [],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      security_policies: [],
      nat_rules: [],
      interfaces: [],
    };

    const setResult = await convertConfig(intermediate, 'set');
    const configSlots = [
      { lsName: 'site-a', intermediateConfig: intermediate, interfaceMappings: {} },
    ];
    const mergedSetResult = await mergeConvert(configSlots, [], 'set');
    const xmlResult = await mergeConvert(configSlots, [], 'xml');

    expect(setResult.output.format).toBe('set');
    expect(setResult.output.commands.length).toBeGreaterThan(0);
    expect(mergedSetResult.output.format).toBe('set');
    expect(mergedSetResult.output.commands.length).toBeGreaterThan(0);
    expect(mergedSetResult.output.commands.every(
      command => typeof command === 'string' && command.trim().length > 0,
    )).toBe(true);
    expect(xmlResult.output.format).toBe('xml');
    expect(xmlResult.output.xml).toContain('<configuration>');
  });

  it('returns mappings and collision metadata through public engines', async () => {
    const single = await convertConfig(collisionConfig(), 'set');
    const merged = await mergeConvert([mergeSlot('Branch', collisionConfig())], [], 'xml');

    for (const result of [single, merged]) {
      expect(result.output.identifierMappings.version).toBe(1);
      expect(result.output.summary.identifier_collisions_resolved).toBeGreaterThan(0);
      expect(result.output.warnings.some(
        warning => warning.subType === 'identifier_collision',
      )).toBe(true);
    }
  });
});
