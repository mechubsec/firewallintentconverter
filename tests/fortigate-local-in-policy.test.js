import { describe, it, expect } from 'vitest';
import { parseFortigateConfig } from '../src/parsers/fortigate-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

const INTERFACES = `config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.248
        set allowaccess ping https ssh
    next
    edit "lan"
        set ip 192.168.10.1 255.255.255.0
        set allowaccess ping https ssh
    next
end
config firewall policy
    edit 1
        set srcintf "wan1" "lan"
        set dstintf "wan1" "lan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
`;

const localIn = (...entries) => `config firewall local-in-policy
${entries.join('\n')}
end
`;
const entry = (id, fields) => `    edit ${id}
${Object.entries(fields).map(([key, value]) => `        set ${key} ${value}`).join('\n')}
    next`;

const accessOf = (intermediateConfig) =>
  Object.assign({}, ...intermediateConfig.zones.map(zone => zone.interface_host_inbound_traffic || {}));
const localInWarnings = warnings => warnings.filter(w => /local-in-policy/.test(w.message));

describe('FortiGate local-in-policy fails closed', () => {
  it('removes HTTPS/SSH from wan1 when accept-trusted + deny-all restrict them', () => {
    const { intermediateConfig, warnings } = parseFortigateConfig(INTERFACES + localIn(
      entry(1, { intf: '"wan1"', srcaddr: '"trusted"', dstaddr: '"all"', action: 'accept', service: '"HTTPS" "SSH"' }),
      entry(2, { intf: '"wan1"', srcaddr: '"all"', dstaddr: '"all"', service: '"HTTPS" "SSH"' }),
    ));
    const access = accessOf(intermediateConfig);
    expect(access.wan1.system_services).toEqual(['ping']);
    expect(access.lan.system_services).toEqual(['ping', 'https', 'ssh']);
    const wanWarnings = localInWarnings(warnings).filter(w => /wan1/.test(w.message));
    expect(wanWarnings).toHaveLength(1);
    expect(wanWarnings[0].message).toMatch(/local-in-policy 2 restricts https, ssh on interface wan1/);
    expect(wanWarnings[0].message).not.toMatch(/\b1,/);
    // lan still allows them, so the daemons stay enabled
    const { commands } = convertToSrxSetCommands(structuredClone(intermediateConfig));
    expect(commands).toContain('set system services ssh');
  });

  it('leaves access unchanged for accept-only entries', () => {
    const { intermediateConfig, warnings } = parseFortigateConfig(INTERFACES + localIn(
      entry(1, { intf: '"wan1"', srcaddr: '"trusted"', dstaddr: '"all"', action: 'accept', service: '"HTTPS"' }),
    ));
    expect(accessOf(intermediateConfig).wan1.system_services).toEqual(['ping', 'https', 'ssh']);
    expect(localInWarnings(warnings)).toHaveLength(0);
  });

  it('applies an `intf any` deny to every interface and drops the daemons', () => {
    const { intermediateConfig, warnings } = parseFortigateConfig(INTERFACES + localIn(
      entry(5, { intf: '"any"', srcaddr: '"all"', dstaddr: '"all"', action: 'deny', service: '"ALL"' }),
    ));
    const access = accessOf(intermediateConfig);
    expect(access.wan1.system_services).toEqual([]);
    expect(access.lan.system_services).toEqual([]);
    expect(localInWarnings(warnings)).toHaveLength(2);
    const { commands } = convertToSrxSetCommands(structuredClone(intermediateConfig));
    expect(commands.filter(line => line.includes('system services'))).toEqual([]);
  });

  it('ignores disabled entries and warns about unknown service names', () => {
    const { intermediateConfig, warnings } = parseFortigateConfig(INTERFACES + localIn(
      entry(1, { intf: '"wan1"', srcaddr: '"all"', dstaddr: '"all"', service: '"SSH"', status: 'disable' }),
      entry(2, { intf: '"wan1"', srcaddr: '"all"', dstaddr: '"all"', service: '"MY-CUSTOM"' }),
    ));
    expect(accessOf(intermediateConfig).wan1.system_services).toEqual(['ping', 'https', 'ssh']);
    expect(localInWarnings(warnings).filter(w => /MY-CUSTOM/.test(w.message))).toHaveLength(1);
  });

  it('reads local-in-policy6 too', () => {
    const { intermediateConfig } = parseFortigateConfig(INTERFACES + `config firewall local-in-policy6
${entry(3, { intf: '"lan"', srcaddr: '"all"', dstaddr: '"all"', service: '"HTTPS"' })}
end
`);
    expect(accessOf(intermediateConfig).lan.system_services).toEqual(['ping', 'ssh']);
  });

  it('does not remove a service shadowed by an earlier accept-all entry', () => {
    const { intermediateConfig, warnings } = parseFortigateConfig(INTERFACES + localIn(
      entry(1, { intf: '"wan1"', srcaddr: '"all"', dstaddr: '"all"', action: 'accept', service: '"SSH"' }),
      entry(2, { intf: '"wan1"', srcaddr: '"all"', dstaddr: '"all"', service: '"HTTPS" "SSH"' }),
    ));
    expect(accessOf(intermediateConfig).wan1.system_services).toEqual(['ping', 'ssh']);
    expect(localInWarnings(warnings).filter(w => /wan1/.test(w.message))[0].message).toMatch(/restricts https on/);
  });

  it('does not treat a source-restricted earlier accept as shadowing', () => {
    const { intermediateConfig } = parseFortigateConfig(INTERFACES + localIn(
      entry(1, { intf: '"wan1"', srcaddr: '"trusted"', dstaddr: '"all"', action: 'accept', service: '"SSH"' }),
      entry(2, { intf: '"wan1"', srcaddr: '"all"', dstaddr: '"all"', service: '"SSH"' }),
    ));
    expect(accessOf(intermediateConfig).wan1.system_services).toEqual(['ping', 'https']);
  });

  it('does not let a scheduled or negated earlier accept shadow a later deny', () => {
    const base = { intf: '"wan1"', srcaddr: '"all"', dstaddr: '"all"', action: 'accept', service: '"SSH"' };
    const deny = entry(2, { intf: '"wan1"', srcaddr: '"all"', dstaddr: '"all"', service: '"SSH"' });
    for (const extra of [{ 'internet-service-src': 'enable' }, { 'virtual-patch': 'enable' }, { schedule: '"workhours"' }, { 'srcaddr-negate': 'enable' }, { 'service-negate': 'enable' }]) {
      const { intermediateConfig } = parseFortigateConfig(INTERFACES + localIn(entry(1, { ...base, ...extra }), deny));
      expect(accessOf(intermediateConfig).wan1.system_services).toEqual(['ping', 'https']);
    }
    const always = parseFortigateConfig(INTERFACES + localIn(entry(1, { ...base, schedule: '"always"' }), deny));
    expect(accessOf(always.intermediateConfig).wan1.system_services).toEqual(['ping', 'https', 'ssh']);
  });

  it('treats `... disable` defaults from full-config exports as neutral', () => {
    const { intermediateConfig } = parseFortigateConfig(INTERFACES + localIn(
      entry(1, {
        intf: '"wan1"', srcaddr: '"all"', dstaddr: '"all"', action: 'accept', service: '"SSH"',
        'internet-service-src': 'disable', 'virtual-patch': 'disable', 'srcaddr-negate': 'disable', schedule: '"always"',
      }),
      entry(2, { intf: '"wan1"', srcaddr: '"all"', dstaddr: '"all"', service: '"SSH"' }),
    ));
    expect(accessOf(intermediateConfig).wan1.system_services).toEqual(['ping', 'https', 'ssh']);
  });

  it('complements a service-negate deny and fails closed on address-negate denies', () => {
    const negated = parseFortigateConfig(INTERFACES + localIn(
      entry(1, { intf: '"wan1"', srcaddr: '"all"', dstaddr: '"all"', service: '"SSH"', 'service-negate': 'enable' }),
    ));
    // denies everything except SSH: ping and https go, ssh stays
    expect(accessOf(negated.intermediateConfig).wan1.system_services).toEqual(['ssh']);
    const addressNegate = parseFortigateConfig(INTERFACES + localIn(
      entry(1, { intf: '"wan1"', srcaddr: '"trusted"', 'srcaddr-negate': 'enable', dstaddr: '"all"', service: '"SSH"' }),
    ));
    expect(accessOf(addressNegate.intermediateConfig).wan1.system_services).toEqual(['ping', 'https']);
  });
});
