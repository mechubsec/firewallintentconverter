import { describe, it, expect } from 'vitest';
import { parseAwsSecurityGroups } from '../src/parsers/aws-sg-parser.js';
import { parseAzureNsg } from '../src/parsers/azure-nsg-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

describe('cloud parsers emit schema action values', () => {
  it('AWS security group allow converts to then permit', () => {
    const { intermediateConfig } = parseAwsSecurityGroups(JSON.stringify({
      SecurityGroups: [{
        GroupId: 'sg-1', GroupName: 'web', VpcId: 'vpc-1',
        IpPermissions: [{ IpProtocol: 'tcp', FromPort: 443, ToPort: 443, IpRanges: [{ CidrIp: '10.0.0.0/8' }] }],
        IpPermissionsEgress: [],
      }],
    }));
    expect(intermediateConfig.security_policies[0].action).toBe('allow');
    const { commands } = convertToSrxSetCommands(intermediateConfig);
    const thenLines = commands.filter(line => / then (permit|deny|reject)$/.test(line));
    expect(thenLines.some(line => line.endsWith(' then permit'))).toBe(true);
    expect(thenLines.some(line => line.endsWith(' then deny'))).toBe(false);
    expect(commands.some(line => / match application tcp-443$/.test(line))).toBe(true);
  });

  it('Azure NSG allow converts to then permit and deny stays deny', () => {
    const rule = (name, access, priority) => ({
      name,
      properties: {
        priority, direction: 'Inbound', access, protocol: 'Tcp',
        sourceAddressPrefix: '10.0.0.0/8', sourcePortRange: '*',
        destinationAddressPrefix: '*', destinationPortRange: '443',
      },
    });
    const { intermediateConfig } = parseAzureNsg(JSON.stringify({
      name: 'nsg1',
      properties: { securityRules: [rule('allow-https', 'Allow', 100), rule('deny-https', 'Deny', 200)] },
    }));
    const actions = Object.fromEntries(intermediateConfig.security_policies.map(p => [p.name, p.action]));
    expect(actions['allow-https']).toBe('allow');
    expect(actions['deny-https']).toBe('deny');
    const { commands } = convertToSrxSetCommands(intermediateConfig);
    expect(commands).toContain('set security policies global policy allow-https then permit');
    expect(commands).toContain('set security policies global policy deny-https then deny');
    expect(commands).toContain('set security policies global policy allow-https match application tcp-443');
  });
});
