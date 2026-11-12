import { describe, it, expect } from 'vitest';
import { parseCheckPointConfig } from '../src/parsers/checkpoint-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

const dictionary = (extra = []) => [
  { uid: 'any', type: 'CpmiAnyObject', name: 'Any' },
  { uid: 'acc', type: 'RulebaseAction', name: 'Accept' },
  { uid: 'drp', type: 'RulebaseAction', name: 'Drop' },
  { uid: 'inn', type: 'RulebaseAction', name: 'Inner Layer' },
  { uid: 'netA', type: 'network', name: 'netA', subnet4: '192.0.2.0', 'mask-length4': 24 },
  { uid: 'netB', type: 'network', name: 'netB', subnet4: '198.51.100.0', 'mask-length4': 24 },
  { uid: 'hC', type: 'host', name: 'hostC', 'ipv4-address': '203.0.113.5' },
  ...extra,
];
const rule = (overrides) => ({
  type: 'access-rule', source: ['any'], destination: ['any'], service: ['any'], enabled: true, ...overrides,
});
const parse = (rulebase, extra) => parseCheckPointConfig(JSON.stringify({
  rulebase, 'objects-dictionary': dictionary(extra), total: rulebase.length,
})).intermediateConfig.security_policies;

describe('Check Point inline layers', () => {
  const layer = (rules) => ({ uid: 'lay', type: 'access-layer', name: 'inline1', rulebase: rules });

  it('ANDs the parent match into children and does not emit the parent as allow', () => {
    const policies = parse([
      rule({ uid: 'p', name: 'parent', source: ['netA'], action: 'inn', 'inline-layer': 'lay' }),
    ], [layer([rule({ uid: 'c', name: 'child', destination: ['hC'], action: 'acc' })])]);
    expect(policies.map(p => p.name)).toEqual(['child']);
    expect(policies[0].src_addresses).toEqual(['netA']);
    expect(policies[0].dst_addresses).toEqual(['hostC']);
    expect(policies[0].disabled).toBe(false);
  });

  it('fails closed when parent and child sources conflict', () => {
    const { intermediateConfig, warnings } = parseCheckPointConfig(JSON.stringify({
      rulebase: [rule({ uid: 'p', name: 'parent', source: ['netA'], action: 'inn', 'inline-layer': 'lay' })],
      'objects-dictionary': dictionary([layer([rule({ uid: 'c', name: 'child', source: ['netB'], action: 'acc' })])]),
      total: 1,
    }));
    expect(intermediateConfig.security_policies[0].disabled).toBe(true);
    expect(warnings.some(w => /inline layer/i.test(w.message))).toBe(true);
  });

  it('denies an unresolved action instead of allowing', () => {
    const policies = parse([rule({ uid: 'u', name: 'u', source: ['netA'], action: 'zzz-unknown' })]);
    expect(policies[0].action).toBe('deny');
  });
});

describe('Check Point mask-length4 of 0', () => {
  it('converts a 0.0.0.0/0 network instead of aborting', () => {
    const { intermediateConfig } = parseCheckPointConfig(JSON.stringify({
      rulebase: [rule({ uid: 'r', name: 'r', source: ['everything'], action: 'acc' })],
      'objects-dictionary': dictionary([
        { uid: 'everything', type: 'network', name: 'everything', subnet4: '0.0.0.0', 'mask-length4': 0 },
      ]),
      total: 1,
    }));
    const addr = intermediateConfig.address_objects.find(a => a.name === 'everything');
    expect(addr.value).toBe('0.0.0.0/0');
    expect(() => convertToSrxSetCommands(intermediateConfig)).not.toThrow();
  });
});
