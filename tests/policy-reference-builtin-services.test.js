/**
 * Vendor built-in services the converter maps to Junos predefined
 * applications must not count as undefined policy references (#127).
 */
import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';
import { findPolicyReferenceIssues } from '../src/security/policy-reference-integrity.js';

function buildConfig(services) {
  return {
    metadata: { source_vendor: 'fortigate' },
    zones: [{ name: 'lan', interfaces: [] }, { name: 'wan', interfaces: [] }],
    address_objects: [
      { name: 'lan-net', type: 'ip-netmask', value: '192.168.10.0/24' },
      { name: 'srv', type: 'ip-netmask', value: '203.0.113.5/32' },
    ],
    address_groups: [], service_objects: [], service_groups: [], applications: [],
    security_policies: [{
      name: 'p1', action: 'allow', src_zones: ['lan'], dst_zones: ['wan'],
      src_addresses: ['lan-net'], dst_addresses: ['srv'], negate_source: false,
      negate_destination: false, applications: [], services, disabled: false,
    }],
  };
}

const setOutput = config => convertToSrxSetCommands(structuredClone(config), {}, null, {}).commands.join('\n');
const xmlOutput = config => buildSrxXml(structuredClone(config)).xml;

describe('built-in services in policy reference integrity', () => {
  it('keeps a policy with HTTPS and DNS active in set and XML output', () => {
    const config = buildConfig(['HTTPS', 'DNS']);
    expect(findPolicyReferenceIssues(config).size).toBe(0);
    const set = setOutput(config);
    expect(set).not.toMatch(/^deactivate /m);
    expect(set).toContain('junos-https');
    expect(set).toContain('junos-dns-udp');
    const xml = xmlOutput(config);
    expect(xml).not.toContain('inactive="inactive"');
    expect(xml).toContain('junos-https');
    expect(xml).toContain('junos-dns-udp');
  });

  it('treats ALL as any', () => {
    const config = buildConfig(['ALL']);
    expect(findPolicyReferenceIssues(config).size).toBe(0);
    expect(setOutput(config)).not.toMatch(/^deactivate /m);
    expect(xmlOutput(config)).not.toContain('inactive="inactive"');
  });

  it('maps GRE to junos-gre (IP protocol 47), never junos-udp-any', () => {
    const config = buildConfig(['GRE']);
    expect(findPolicyReferenceIssues(config).size).toBe(0);
    const set = setOutput(config);
    expect(set).not.toMatch(/^deactivate /m);
    expect(set).toContain('match application junos-gre');
    expect(set).not.toContain('junos-udp-any');
    expect(xmlOutput(config)).toContain('junos-gre');
  });

  it('still deactivates an unknown service name', () => {
    const config = buildConfig(['NOT-A-REAL-SVC']);
    expect(findPolicyReferenceIssues(config).get(0).services).toEqual(['NOT-A-REAL-SVC']);
    expect(setOutput(config)).toMatch(/^deactivate .*policy p1/m);
    expect(xmlOutput(config)).toContain('inactive="inactive"');
  });
});
