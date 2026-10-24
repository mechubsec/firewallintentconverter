import { describe, it, expect } from 'vitest';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

const buildConfig = (serviceBlock, serviceName) => `config system interface
    edit "port1"
        set alias "wan"
        set ip 203.0.113.2 255.255.255.248
    next
    edit "port2"
        set alias "lan"
        set ip 192.168.10.1 255.255.255.0
    next
end
config firewall address
    edit "all"
        set subnet 0.0.0.0 0.0.0.0
    next
end
config firewall service custom
${serviceBlock}
end
config firewall policy
    edit 1
        set name "svc-policy"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "${serviceName}"
    next
end`;

function convert(serviceBlock, serviceName) {
  const { intermediateConfig } = parseFortigateConfig(buildConfig(serviceBlock, serviceName));
  return {
    config: intermediateConfig,
    commands: convertToSrxSetCommands(intermediateConfig, {}, null, {}).commands,
  };
}

describe('FortiGate multi-protocol custom services', () => {
  it('resolves a tcp+udp service to an application-set', () => {
    const { config, commands } = convert(
      '    edit "DNS"\n        set tcp-portrange 53\n        set udp-portrange 53\n    next', 'DNS');
    const text = commands.join('\n');

    expect(config.service_groups.find((group) => group.name === 'DNS').members).toEqual(['DNS_tcp', 'DNS_udp']);
    expect(text).toContain('inactive (undefined reference): 0');
    expect(commands.filter((line) => /^deactivate .*policies/.test(line))).toEqual([]);
    // The converter maps tcp/53 and udp/53 onto Junos predefined apps.
    expect(commands).toContain('set applications application-set DNS application junos-dns-tcp');
    expect(commands).toContain('set applications application-set DNS application junos-dns-udp');
    expect(commands.some((line) => / match application DNS$/.test(line))).toBe(true);
  });

  it('keeps tcp+sctp names distinct', () => {
    const { config, commands } = convert(
      '    edit "MULTI"\n        set tcp-portrange 80\n        set sctp-portrange 80\n    next', 'MULTI');
    const names = config.service_objects.map((service) => service.name);

    expect(names).toEqual(['MULTI_tcp', 'MULTI_sctp']);
    expect(config.service_groups.find((group) => group.name === 'MULTI').members).toEqual(names);
    expect(commands.join('\n')).toContain('inactive (undefined reference): 0');
  });

  it('leaves single-protocol services unchanged', () => {
    const { config } = convert('    edit "WEB"\n        set tcp-portrange 80\n    next', 'WEB');
    expect(config.service_objects.map((service) => service.name)).toEqual(['WEB']);
    expect(config.service_groups).toEqual([]);
  });
});
