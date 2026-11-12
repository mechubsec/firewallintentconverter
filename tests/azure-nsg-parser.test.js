import { describe, it, expect } from 'vitest';
import { parseAzureNsg } from '../src/parsers/azure-nsg-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

const rule = (name, props) => ({
  name,
  properties: {
    priority: 100, direction: 'Inbound', access: 'Allow', protocol: 'Tcp',
    sourceAddressPrefix: '*', sourcePortRange: '*',
    destinationAddressPrefix: '*', destinationPortRange: '443', ...props,
  },
});
const parse = (nsgs) => parseAzureNsg(JSON.stringify(nsgs)).intermediateConfig;
const policyOf = (config, name) => config.security_policies.find(policy => policy.name === name);

describe('Azure NSG parser', () => {
  it('disables rules that use unresolvable service tags instead of mapping them to 0.0.0.0/0', () => {
    const config = parse({ name: 'n', securityRules: [
      rule('vnet', { protocol: '*', sourceAddressPrefix: 'VirtualNetwork', destinationAddressPrefix: 'VirtualNetwork', destinationPortRange: '*' }),
      rule('storage', { destinationAddressPrefix: 'Storage' }),
      rule('internet', { sourceAddressPrefix: 'Internet' }),
    ] });
    expect(policyOf(config, 'vnet').disabled).toBe(true);
    expect(policyOf(config, 'storage').disabled).toBe(true);
    expect(policyOf(config, 'internet')).toMatchObject({ disabled: false, src_addresses: ['any'] });
    expect(config.address_objects).toEqual([]);
    expect(config.warnings.some(warning => /VirtualNetwork/.test(warning.message))).toBe(true);
  });

  it('keeps the protocol when the port is a wildcard and the port when the protocol is', () => {
    const config = parse({ name: 'n', securityRules: [
      rule('tcp-all', { destinationPortRange: '*' }),
      rule('any-443', { protocol: '*' }),
    ] });
    expect(policyOf(config, 'tcp-all').services).toEqual(['tcp/1-65535']);
    expect(policyOf(config, 'any-443').services).toEqual(['tcp/443', 'udp/443']);
  });

  it('honours source prefix on outbound rules and a single source port', () => {
    const config = parse({ name: 'n', securityRules: [
      rule('out', { direction: 'Outbound', access: 'Deny', sourceAddressPrefix: '192.0.2.10', sourcePortRange: '1024' }),
    ] });
    const policy = policyOf(config, 'out');
    expect(policy.src_addresses).toEqual(['addr-192.0.2.10']);
    expect(config.service_objects[0]).toMatchObject({ protocol: 'tcp', port: '443', source_port: '1024' });
  });

  it('uses /128 for IPv6 hosts', () => {
    const config = parse({ name: 'n', securityRules: [rule('v6', { sourceAddressPrefix: '2001:db8::1' })] });
    expect(config.address_objects[0].value).toBe('2001:db8::1/128');
  });

  it('keeps one zone and unique policy names per NSG', () => {
    const defaults = [rule('AllowInternetOutBound', { priority: 65001, direction: 'Outbound', destinationAddressPrefix: 'Internet' })];
    const config = parse([
      { name: 'a', securityRules: [], defaultSecurityRules: defaults },
      { name: 'b', securityRules: [], defaultSecurityRules: defaults },
    ]);
    expect(config.zones.map(zone => zone.name)).toEqual(['nsg-a', 'nsg-b']);
    expect(config.security_policies.map(policy => policy.src_zones[0]).sort()).toEqual(['nsg-a', 'nsg-b']);
    expect(() => convertToSrxSetCommands(config)).not.toThrow();
  });
});
