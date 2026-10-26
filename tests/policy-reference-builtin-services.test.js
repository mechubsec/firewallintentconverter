/**
 * Vendor built-in services the converter maps to Junos predefined
 * applications must not count as undefined policy references (#127).
 */
import { describe, it, expect, vi } from 'vitest';
import { invalidateOverridesCache } from '../src/utils/app-mappings.js';
import { parseCiscoAsaConfig } from '../src/parsers/cisco-asa-parser.js';
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

  it('does not treat another vendor name (PAN-OS web-browsing) as a FortiGate built-in (#152)', () => {
    const config = buildConfig(['web-browsing']);
    expect(findPolicyReferenceIssues(config).get(0).services).toEqual(['web-browsing']);
    const set = setOutput(config);
    expect(set).toMatch(/^deactivate .*policy p1/m);
    expect(set).not.toContain('match application junos-http');
    expect(xmlOutput(config)).toContain('inactive="inactive"');
  });

  it('still maps the PAN-OS web-browsing application', () => {
    const config = buildConfig([]);
    config.metadata.source_vendor = 'panos';
    config.security_policies[0].applications = ['web-browsing'];
    expect(setOutput(config)).toContain('match application junos-http');
  });

  it('gives the same answer cold and after the vendor mappings are loaded', async () => {
    vi.resetModules();
    const integrity = await import('../src/security/policy-reference-integrity.js');
    const config = buildConfig(['IPsec-NAT-T', 'web-browsing']);
    const cold = integrity.findPolicyReferenceIssues(config).get(0).services;
    const appMappings = await import('../src/utils/app-mappings.js');
    const parserUtils = await import('../src/parsers/parser-utils.js');
    await appMappings.loadAppMappings();
    parserUtils.setMapVendorApp(appMappings.mapVendorApp);
    expect(integrity.findPolicyReferenceIssues(config).get(0).services).toEqual(cold);
  });

  it('keeps FortiGate predefined services from the bundled mappings active, cold', () => {
    const config = buildConfig(['IPsec-NAT-T', 'RTSP', 'CIFS']);
    expect(findPolicyReferenceIssues(config).size).toBe(0);
    const set = setOutput(config);
    expect(set).not.toMatch(/^deactivate /m);
    for (const app of ['junos-ike-nat', 'junos-rtsp', 'junos-smb']) expect(set).toContain(app);
  });

  it('deactivates a service group (and its policy) with an undefined member', () => {
    const config = buildConfig(['grp']);
    config.service_groups = [{ name: 'grp', members: ['web-browsing', 'HTTPS'] }];
    expect(findPolicyReferenceIssues(config).get(0).services).toEqual(['grp']);
    const set = setOutput(config);
    expect(set).toMatch(/^deactivate applications application-set grp$/m);
    expect(set).toMatch(/^deactivate .*policy p1/m);
    expect(xmlOutput(config)).toContain('<application-set inactive="inactive">');
  });

  it('deactivates a policy that matches a bad service group via applications, and warns in XML', () => {
    const config = buildConfig([]);
    config.security_policies[0].applications = ['grp'];
    config.service_groups = [{ name: 'grp', members: ['web-browsing'] }];
    expect(findPolicyReferenceIssues(config).get(0).services).toEqual(['grp']);
    expect(setOutput(config)).toMatch(/^deactivate .*policy p1/m);
    const { xml, warnings } = buildSrxXml(structuredClone(config));
    expect(xml).toContain('inactive="inactive"');
    expect(warnings.some((w) => /grp/.test(w.message || w.element || JSON.stringify(w)) && /application-set deactivated/.test(JSON.stringify(w)))).toBe(true);
  });

  it('counts a member defined in config.applications as resolved', () => {
    const config = buildConfig(['grp']);
    config.applications = [{ name: 'custom-app', protocol: 'tcp', port: '8443' }];
    config.service_groups = [{ name: 'grp', members: ['custom-app', 'HTTPS'] }];
    expect(findPolicyReferenceIssues(config).size).toBe(0);
    expect(setOutput(config)).not.toMatch(/^deactivate /m);
  });

  it('resolves a wide shared-child group DAG quickly', () => {
    const config = buildConfig(['g40']);
    config.service_groups = [{ name: 'g0', members: ['HTTPS'] }];
    for (let level = 1; level <= 40; level += 1) {
      config.service_groups.push({ name: `g${level}`, members: [`g${level - 1}`, `g${level - 1}`, 'HTTP'] });
    }
    const start = Date.now();
    expect(findPolicyReferenceIssues(config).size).toBe(0);
    expect(Date.now() - start).toBeLessThan(500);
  });

  describe('user mapping overrides', () => {
    const withOverrides = (overrides, run) => {
      vi.stubGlobal('localStorage', { getItem: () => JSON.stringify(overrides) });
      invalidateOverridesCache();
      try { run(); } finally {
        vi.unstubAllGlobals();
        invalidateOverridesCache();
      }
    };

    it('treats a user-mapped FortiGate service as a built-in', () => {
      withOverrides({ fortigate: { 'my-web': { junosApp: 'junos-https' } } }, () => {
        const config = buildConfig(['MY-WEB']);
        expect(findPolicyReferenceIssues(config).size).toBe(0);
        const set = setOutput(config);
        expect(set).not.toMatch(/^deactivate /m);
        expect(set).toContain('junos-https');
      });
    });

    it('honours a tombstone on a bundled FortiGate service', () => {
      withOverrides({ fortigate: { 'ipsec-nat-t': { _deleted: true } } }, () => {
        const config = buildConfig(['IPsec-NAT-T']);
        expect(findPolicyReferenceIssues(config).get(0).services).toEqual(['IPsec-NAT-T']);
        expect(setOutput(config)).toMatch(/^deactivate .*policy p1/m);
      });
    });
  });

  it('keeps a service group of built-ins active', () => {
    const config = buildConfig(['grp']);
    config.service_groups = [{ name: 'grp', members: ['HTTP', 'HTTPS'] }];
    expect(findPolicyReferenceIssues(config).size).toBe(0);
    expect(setOutput(config)).not.toMatch(/^deactivate /m);
    expect(xmlOutput(config)).not.toContain('inactive="inactive"');
  });

  it('keeps ASA ACEs with bare icmp/icmp6/ip keywords active', () => {
    const { intermediateConfig } = parseCiscoAsaConfig(`interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.0
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.1.1 255.255.255.0
!
access-list IN extended permit icmp any any
access-list IN extended permit icmp6 any any
access-list IN extended permit ip any any
access-list IN extended permit tcp any any eq www
access-list IN extended permit udp any any eq domain
access-group IN in interface outside
`);
    const set = convertToSrxSetCommands(structuredClone(intermediateConfig), {}, null, {}).commands.join('\n');
    expect(set).not.toMatch(/^deactivate .*policy/m);
    expect(set).toContain('junos-icmp-all');
  });
});
