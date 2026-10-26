import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';
import { MULTIZONE_CONFIG } from './srx-policy-structure.test.js';

/** Config shaped like parser output: zone-pair rules plus the parsers' any/any catch-all deny. */
const withCatchAll = sourceVendor => ({
  ...MULTIZONE_CONFIG,
  metadata: { source_vendor: sourceVendor },
  security_policies: [
    ...MULTIZONE_CONFIG.security_policies,
    {
      name: 'Implicit-Default-Deny', _rule_index: 2, action: 'deny', _implicit: true,
      src_zones: ['any'], dst_zones: ['any'], src_addresses: ['any'], dst_addresses: ['any'],
      applications: ['any'], services: [],
    },
  ],
});

const setText = out => out.commands.join('\n');
const xmlText = out => out.xml;

describe('default-policy fails closed', () => {
  for (const vendor of ['fortigate', 'panos']) {
    it(`${vendor}: global structure emits deny-all, never permit-all (set and XML)`, () => {
      const config = withCatchAll(vendor);
      const set = setText(convertToSrxSetCommands(config, {}, null, { policyStructure: 'global' }));
      expect(set).toContain('set security policies default-policy deny-all');
      expect(set).not.toContain('permit-all');

      const xml = xmlText(buildSrxXml(config, {}, null, {}));
      expect(xml).toMatch(/<default-policy>\s*<deny-all\/>\s*<\/default-policy>/);
      expect(xml).not.toContain('permit-all');
    });
  }

  it('zone structure without any-zone policies emits no default-policy in set or XML', () => {
    const set = setText(convertToSrxSetCommands(MULTIZONE_CONFIG, {}, null, { policyStructure: 'zone-pair' }));
    expect(set).not.toContain('default-policy');
    const xml = xmlText(buildSrxXml(MULTIZONE_CONFIG, {}, null, {}));
    expect(xml).not.toContain('default-policy');
  });
});
