import { describe, it, expect } from 'vitest';
import { parseAwsSecurityGroups } from '../src/parsers/aws-sg-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

const convert = (permissions) => {
  const { intermediateConfig } = parseAwsSecurityGroups(JSON.stringify({
    SecurityGroups: [{ GroupId: 'sg-1', GroupName: 'web', VpcId: 'vpc-1', IpPermissions: permissions, IpPermissionsEgress: [] }],
  }));
  return { intermediateConfig, commands: convertToSrxSetCommands(intermediateConfig).commands };
};
const perm = (extra) => ({ IpRanges: [{ CidrIp: '192.0.2.0/24' }], ...extra });

describe('AWS security group parser', () => {
  it('gives each permission a unique policy name', () => {
    const { intermediateConfig } = convert([
      perm({ IpProtocol: 'tcp', FromPort: 80, ToPort: 80 }),
      perm({ IpProtocol: 'tcp', FromPort: 443, ToPort: 443 }),
    ]);
    const names = intermediateConfig.security_policies.map(policy => policy.name);
    expect(new Set(names).size).toBe(2);
  });

  it('maps ICMP FromPort/ToPort to icmp type/code instead of a port', () => {
    const { intermediateConfig, commands } = convert([
      perm({ IpProtocol: 'icmp', FromPort: 8, ToPort: -1 }),
      perm({ IpProtocol: 'icmp', FromPort: -1, ToPort: -1 }),
      perm({ IpProtocol: 'icmp', FromPort: 3, ToPort: 1 }),
    ]);
    const icmpServices = intermediateConfig.service_objects.filter(svc => svc.protocol === 'icmp');
    expect(icmpServices.map(svc => svc.port)).toEqual(['', '', '']);
    expect(icmpServices.find(svc => svc.icmp_type === '8')).toBeDefined();
    expect(icmpServices.find(svc => svc.icmp_code === '1')).toMatchObject({ icmp_type: '3' });
    expect(commands).toContain('set applications application icmp-8 icmp-type 8');
  });
});
