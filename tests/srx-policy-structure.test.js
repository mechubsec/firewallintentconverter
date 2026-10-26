import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

/** A config exercising multi-zone, apps, logging, deny — for structure tests. */
export const MULTIZONE_CONFIG = {
  zones: [
    { name: 'trust', interfaces: [] }, { name: 'dmz', interfaces: [] },
    { name: 'untrust', interfaces: [] }, { name: 'partner', interfaces: [] },
  ],
  address_objects: [
    { name: 'web', type: 'ip-netmask', value: '10.0.0.10/32' },
  ],
  service_objects: [],
  security_policies: [
    {
      name: 'allow-web', _rule_index: 0, action: 'allow',
      src_zones: ['trust', 'dmz'], dst_zones: ['untrust', 'partner'],
      src_addresses: ['web'], dst_addresses: ['any'],
      applications: ['junos-https'], services: [], log_end: true,
    },
    {
      name: 'deny-all', _rule_index: 1, action: 'deny',
      src_zones: ['trust'], dst_zones: ['untrust'],
      src_addresses: ['any'], dst_addresses: ['any'],
      applications: ['any'], services: [],
    },
  ],
  nat_rules: [],
};

/** Extract only the policy set-lines from converter output text. */
export function policyLines(out) {
  const text = Array.isArray(out.commands) ? out.commands.join('\n') : String(out);
  return text.split('\n').filter(l => l.includes('security policies') || l.startsWith('deactivate security policies'));
}

describe('policy body extraction is behavior-preserving (zone-pair)', () => {
  it('zone-pair output contains the expected per-pair policy lines', () => {
    const out = convertToSrxSetCommands(MULTIZONE_CONFIG, {}, null, { policyStructure: 'zone-pair' });
    const lines = policyLines(out).join('\n');
    // allow-web spans 2x2 zone pairs in zone-pair mode
    expect(lines).toContain('set security policies from-zone trust to-zone untrust policy allow-web then permit');
    expect(lines).toContain('set security policies from-zone dmz to-zone partner policy allow-web then permit');
    // logging carried through the shared body
    expect(lines).toContain('set security policies from-zone trust to-zone untrust policy allow-web then log session-close');
  });
});

describe('global policy structure (default)', () => {
  it('emits one consolidated global rule per policy with match from/to zones', () => {
    const out = convertToSrxSetCommands(MULTIZONE_CONFIG, {}, null, { policyStructure: 'global' });
    const lines = policyLines(out);
    const joined = lines.join('\n');
    // allow-web is ONE global policy, not four zone-pair entries
    expect(joined).toContain('set security policies global policy allow-web match from-zone trust');
    expect(joined).toContain('set security policies global policy allow-web match from-zone dmz');
    expect(joined).toContain('set security policies global policy allow-web match to-zone untrust');
    expect(joined).toContain('set security policies global policy allow-web match to-zone partner');
    expect(joined).toContain('set security policies global policy allow-web then permit');
    // No zone-pair container lines in global mode
    expect(joined).not.toMatch(/from-zone \S+ to-zone \S+ policy/);
    // default-policy present for global
    const allText = Array.isArray(out.commands) ? out.commands.join('\n') : String(out);
    expect(allText).toContain('set security policies default-policy deny-all');
  });

  it('preserves source rule order in the single global list', () => {
    const out = convertToSrxSetCommands(MULTIZONE_CONFIG, {}, null, { policyStructure: 'global' });
    const joined = policyLines(out).join('\n');
    expect(joined.indexOf('policy allow-web')).toBeLessThan(joined.indexOf('policy deny-all'));
  });

  it('defaults to global when no policyStructure option is given', () => {
    const withOpt = convertToSrxSetCommands(MULTIZONE_CONFIG, {}, null, { policyStructure: 'global' });
    const noOpt = convertToSrxSetCommands(MULTIZONE_CONFIG, {}, null);
    expect(policyLines(noOpt)).toEqual(policyLines(withOpt));
  });
});
