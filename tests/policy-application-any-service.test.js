/**
 * "application any" beside a specific service must not widen the policy to
 * any port: PAN-OS/AWS/Azure/GCP rules carry applications: ['any'] plus the
 * services that actually restrict the match. Set and XML output must agree.
 */
import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';
import { parsePanosConfig } from '../src/parsers/panos-parser.js';
import { parseGcpFirewallRules } from '../src/parsers/gcp-fw-parser.js';

const basePolicy = {
  name: 'pol', action: 'allow', src_zones: ['lan'], dst_zones: ['wan'], src_addresses: ['any'], dst_addresses: ['any'],
  negate_source: false, negate_destination: false, applications: ['any'], services: ['any'], disabled: false,
};

function buildConfig(policy) {
  return {
    metadata: { source_vendor: 'paloalto' },
    zones: [{ name: 'lan', interfaces: [] }, { name: 'wan', interfaces: [] }],
    address_objects: [], address_groups: [], service_objects: [], service_groups: [], applications: [],
    security_policies: [{ ...basePolicy, ...policy }],
  };
}

/** @returns {string[]} application match values from the set output for the named policy */
function setApps(config, name = 'pol') {
  const prefix = ` policy ${name} match application `;
  return convertToSrxSetCommands(structuredClone(config), {}, null, {}).commands
    .filter(line => line.includes(prefix)).map(line => line.split(prefix)[1]);
}

/** @returns {string[]} application elements from the XML output for the named policy */
function xmlApps(config, name = 'pol') {
  const { xml } = buildSrxXml(structuredClone(config));
  const block = xml.match(new RegExp(`<policy[^>]*>\\s*<name>${name}</name>[\\s\\S]*?</policy>`));
  return [...block[0].matchAll(/<application>([^<]+)<\/application>/g)].map(match => match[1]);
}

function expectBoth(config, expected, name) {
  expect(setApps(config, name)).toEqual(expected);
  expect(xmlApps(config, name)).toEqual(expected);
}

describe('application any with specific services', () => {
  it('keeps only the service when application is any', () => {
    expectBoth(buildConfig({ services: ['tcp-22'] }), ['tcp-22']);
  });

  it('keeps multiple services and drops any', () => {
    expectBoth(buildConfig({ services: ['tcp-22', 'tcp-443'] }), ['tcp-22', 'tcp-443']);
  });

  it('PAN-OS application any + service-https is not any', () => {
    const xml = `<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<zone><entry name="trust"><network><layer3/></network></entry><entry name="untrust"><network><layer3/></network></entry></zone>
<rulebase><security><rules><entry name="web"><from><member>trust</member></from><to><member>untrust</member></to>
<source><member>any</member></source><destination><member>any</member></destination>
<application><member>any</member></application><service><member>service-https</member></service><action>allow</action></entry></rules></security></rulebase>
</entry></vsys></entry></devices></config>`;
    const config = parsePanosConfig(xml).intermediateConfig;
    const apps = setApps(config, 'web');
    // PAN-OS predefined service-https resolves to junos-https (#152).
    expect(apps).toEqual(['junos-https']);
    expect(apps).not.toContain('any');
    expect(xmlApps(config, 'web')).toEqual(['junos-https']);
  });

  it('GCP allow rule becomes its service only', () => {
    const config = parseGcpFirewallRules(JSON.stringify([{
      name: 'allow-ssh', network: 'projects/p/global/networks/vpc1', direction: 'INGRESS', priority: 1000,
      sourceRanges: ['10.0.0.0/8'], allowed: [{ IPProtocol: 'tcp', ports: ['22'] }],
    }])).intermediateConfig;
    expect(config.security_policies[0].applications).toEqual(['any']);
    expectBoth(config, ['tcp-22'], 'allow-ssh');
  });
});

describe('controls: behaviour that must not change', () => {
  it('application any + service any stays any', () => {
    expectBoth(buildConfig({ services: ['any'] }), ['any']);
  });

  it('application any + application-default stays any', () => {
    expectBoth(buildConfig({ services: ['application-default'] }), ['any']);
  });

  it('application any + service-set keyword stays any', () => {
    expectBoth(buildConfig({ services: ['service-set'] }), ['any']);
  });

  it('specific application + application-default is unchanged', () => {
    expectBoth(buildConfig({ applications: ['ssh'], services: ['application-default'] }), ['junos-ssh']);
  });

  it('specific application + specific service still emits both (unchanged)', () => {
    expectBoth(buildConfig({ applications: ['ssh'], services: ['tcp-2222'] }), ['junos-ssh', 'tcp-2222']);
  });
});
