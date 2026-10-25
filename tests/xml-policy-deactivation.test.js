/**
 * The XML output must deactivate a policy for every reason the set output
 * does: disabled, unmapped application, undefined reference, negation.
 */
import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';

const base = {
  action: 'allow', src_zones: ['lan'], dst_zones: ['wan'], src_addresses: ['lan-net'], dst_addresses: ['any'],
  negate_source: false, negate_destination: false, applications: [], services: ['any'], disabled: false,
};

function buildConfig(policies) {
  return {
    metadata: { source_vendor: 'fortigate' },
    zones: [{ name: 'lan', interfaces: [] }, { name: 'wan', interfaces: [] }, { name: 'dmz', interfaces: [] }],
    address_objects: [{ name: 'lan-net', type: 'ip-netmask', value: '192.168.10.0/24' }],
    address_groups: [], service_objects: [], service_groups: [], applications: [],
    security_policies: policies,
  };
}

const setDeactivated = config => new Set(
  [...convertToSrxSetCommands(structuredClone(config), {}, null, {}).commands.join('\n')
    .matchAll(/^deactivate .*policy (\S+)/gm)].map(match => match[1]),
);

/** @returns {{name: string, inactive: boolean}[]} one entry per emitted policy copy */
function xmlPolicies(config) {
  const { xml } = buildSrxXml(structuredClone(config));
  return [...xml.matchAll(/<policy( inactive="inactive")?>\s*<name>([^<]+)<\/name>/g)]
    .map(match => ({ name: match[2], inactive: !!match[1] }));
}

describe('XML policy deactivation parity with set output', () => {
  const config = buildConfig([
    { ...base, name: 'ok-policy' },
    { ...base, name: 'off-policy', disabled: true },
    { ...base, name: 'undef-ref', dst_addresses: ['ghost-host'] },
    { ...base, name: 'unmapped-app', services: [], applications: ['totally-made-up-app-xyz'] },
    { ...base, name: 'neg-any', src_addresses: ['any'], negate_source: true },
  ]);
  const expected = new Set(['off-policy', 'undef-ref', 'unmapped-app', 'neg-any']);

  it('deactivates the same policies in both outputs', () => {
    const xmlInactive = new Set(xmlPolicies(config).filter(policy => policy.inactive).map(policy => policy.name));
    expect(setDeactivated(config)).toEqual(expected);
    expect(xmlInactive).toEqual(expected);
  });

  it('keeps ok-policy active', () => {
    expect(xmlPolicies(config).find(policy => policy.name === 'ok-policy').inactive).toBe(false);
  });

  it('deactivates a policy whose application group has an unmapped member', () => {
    const groupConfig = buildConfig([{ ...base, name: 'grp-app', services: [], applications: ['grp'] }]);
    groupConfig.application_groups = [{ name: 'grp', members: ['totally-made-up-app-xyz', 'junos-https'] }];
    expect(setDeactivated(groupConfig)).toEqual(new Set(['grp-app']));
    expect(xmlPolicies(groupConfig).every(policy => policy.inactive)).toBe(true);
  });

  it('names the undefined reference in a CAVEAT comment', () => {
    const { xml } = buildSrxXml(structuredClone(config));
    expect(xml).toMatch(/CAVEAT: policy deactivated — undefined reference\(s\): address "ghost-host"/);
  });
});

describe('XML deactivation across emitted copies', () => {
  it('deactivates every zone-pair copy of a disabled policy', () => {
    const copies = xmlPolicies(buildConfig([{ ...base, name: 'multi', disabled: true, dst_zones: ['wan', 'dmz'] }]));
    expect(copies).toHaveLength(2);
    expect(copies.every(policy => policy.inactive)).toBe(true);
  });

  it('deactivates a disabled global policy', () => {
    const copies = xmlPolicies(buildConfig([{ ...base, name: 'glob', disabled: true, src_zones: [], dst_zones: [] }]));
    expect(copies.length).toBeGreaterThan(0);
    expect(copies.every(policy => policy.inactive)).toBe(true);
  });
});
