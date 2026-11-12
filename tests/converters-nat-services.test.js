import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';

const baseConfig = (extra = {}) => ({
  zones: [{ name: 'trust', interfaces: [] }, { name: 'untrust', interfaces: [] }],
  address_objects: [],
  ...extra,
});
const render = config => ({
  set: convertToSrxSetCommands(structuredClone(config), {}, null, {}),
  xml: buildSrxXml(structuredClone(config), {}).xml,
});

describe('destination NAT keeps its source restriction', () => {
  const dnat = overrides => baseConfig({
    address_objects: [
      { name: 'h', type: 'subnet', value: '192.0.2.0/24' },
      { name: 'pub', type: 'host', value: '198.51.100.5' },
    ],
    nat_rules: [{
      name: 'dnat', type: 'destination', src_zones: ['untrust'], dst_zones: ['trust'],
      src_addresses: ['h'], dst_addresses: ['pub'], match_protocol: 'tcp', match_port: '443',
      translated_dst: { address: '198.51.100.10' }, ...overrides,
    }],
  });

  it('emits match source-address in set and XML', () => {
    const { set, xml } = render(dnat());
    expect(set.commands.some(line => /nat destination rule-set \S+ rule dnat match source-address 192\.0\.2\.0\/24$/.test(line))).toBe(true);
    expect(xml).toContain('<source-address>192.0.2.0/24</source-address>');
  });

  it('skips the rule when no source address resolves', () => {
    const { set, xml } = render(dnat({ src_addresses: ['ghost'] }));
    expect(set.commands.some(line => line.includes('rule dnat match'))).toBe(false);
    expect(xml).not.toContain('<name>dnat</name>');
  });

  it('adds no source match when the source is any', () => {
    const { set, xml } = render(dnat({ src_addresses: ['any'] }));
    expect(set.commands.some(line => line.includes('rule dnat match source-address'))).toBe(false);
    expect(xml).not.toContain('<source-address>');
  });
});

describe('address-book prefixes with host bits set', () => {
  const config = type => baseConfig({ address_objects: [{ name: 'blk', type, value: '198.51.100.9/27' }] });

  it('masks a subnet to its network address in set and XML, with a warning', () => {
    const { set, xml } = render(config('subnet'));
    expect(set.commands).toContain('set security address-book global address blk 198.51.100.0/27');
    expect(xml).toContain('<ip-prefix>198.51.100.0/27</ip-prefix>');
    expect(set.warnings.some(warning => warning.element === 'address/blk')).toBe(true);
  });

  it('keeps the host-with-mask to /32 in both outputs', () => {
    const { set, xml } = render(config('host'));
    expect(set.commands).toContain('set security address-book global address blk 198.51.100.9/32');
    expect(xml).toContain('<ip-prefix>198.51.100.9/32</ip-prefix>');
  });
});

describe('XML address-book types', () => {
  it.each([['ip-netmask', 'value'], ['ip-prefix', 'value'], ['network', 'network']])('emits a prefix for %s', (type, field) => {
    const { set, xml } = render(baseConfig({ address_objects: [{ name: 'lan', type, [field]: '192.0.2.0/24' }] }));
    expect(set.commands).toContain('set security address-book global address lan 192.0.2.0/24');
    expect(xml).toContain('<ip-prefix>192.0.2.0/24</ip-prefix>');
  });

  it('does not throw on a range with no value', () => {
    const { set, xml } = render(baseConfig({ address_objects: [{ name: 'rng', type: 'range' }] }));
    expect(set.commands.some(line => line.includes('address rng range-address'))).toBe(false);
    expect(xml).not.toContain('<range-address>');
  });
});

describe('service source-port', () => {
  const services = overrides => baseConfig({ service_objects: [{ name: 'svc', protocol: 'tcp', port_range: '9000', ...overrides }] });

  it('emits source-port on a single application in set and XML', () => {
    const { set, xml } = render(services({ source_port: '1000' }));
    expect(set.commands).toContain('set applications application svc source-port 1000');
    expect(xml).toContain('<source-port>1000</source-port>');
  });

  it('puts source-port on each sub-application, never on the application-set', () => {
    const { set, xml } = render(services({ port_range: '8080,8443', source_port: '1024-65535' }));
    const sourcePortLines = set.commands.filter(line => line.includes(' source-port '));
    expect(sourcePortLines).toHaveLength(2);
    expect(sourcePortLines.every(line => line.startsWith('set applications application ') && !line.includes('-set '))).toBe(true);
    expect(xml.match(/<source-port>1024-65535<\/source-port>/g)).toHaveLength(2);
  });
});
