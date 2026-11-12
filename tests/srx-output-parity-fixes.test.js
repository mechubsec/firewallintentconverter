import { describe, it, expect } from 'vitest';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';

const baseConfig = (overrides = {}) => ({
  zones: [{ name: 'trust', interfaces: [] }, { name: 'untrust', interfaces: [] }],
  address_objects: [], address_groups: [], service_objects: [], nat_rules: [],
  security_policies: [],
  ...overrides,
});
const policy = (overrides = {}) => ({
  name: 'p1', action: 'allow', src_zones: ['trust'], dst_zones: ['untrust'],
  src_addresses: ['any'], dst_addresses: ['any'], applications: ['any'], services: [],
  ...overrides,
});
const setLines = (config, options = {}) => convertToSrxSetCommands(config, {}, null, options).commands.join('\n');
const xmlOf = (config, mappings = {}) => buildSrxXml(config, mappings, null, {}).xml;

describe('policy with one "any" zone keeps its other zone match', () => {
  const config = baseConfig({ security_policies: [policy({ dst_zones: ['any'] })] });

  it('XML global policy carries from-zone', () => {
    const xml = xmlOf(config);
    const globalBlock = xml.slice(xml.indexOf('<global>'), xml.indexOf('</global>'));
    expect(globalBlock).toContain('<from-zone>trust</from-zone>');
    expect(globalBlock).not.toContain('<to-zone>');
  });

  it('XML merges several source zones into one global policy', () => {
    const multi = baseConfig({ security_policies: [policy({ src_zones: ['trust', 'untrust'], dst_zones: ['any'] })] });
    const xml = xmlOf(multi);
    expect(xml).toContain('<from-zone>trust</from-zone>');
    expect(xml).toContain('<from-zone>untrust</from-zone>');
  });

  it('set zone-pair mode carries from-zone', () => {
    const out = setLines(config, { policyStructure: 'zone-pair' });
    expect(out).toContain('set security policies global policy p1 match from-zone trust');
  });
});

describe('XML tagged sub-interfaces match set output', () => {
  const config = baseConfig({
    interfaces: [
      { name: 'eth1.10', parent: 'eth1', vlan: 10, ip: '192.0.2.1/24' },
      { name: 'eth1.20', parent: 'eth1', vlan: 20, ip: '198.51.100.1/24' },
    ],
  });
  it('emits flexible-vlan-tagging and vlan-id', () => {
    const mappings = { eth1: 'ge-0/0/1' };
    const set = convertToSrxSetCommands(config, mappings, null, {}).commands.join('\n');
    expect(set).toContain('set interfaces ge-0/0/1 flexible-vlan-tagging');
    const xml = xmlOf(config, mappings);
    expect(xml.match(/<flexible-vlan-tagging\/>/g)).toHaveLength(1);
    expect(xml).toContain('<vlan-id>10</vlan-id>');
    expect(xml).toContain('<vlan-id>20</vlan-id>');
  });
});

describe('action mapping is shared by set and XML', () => {
  it.each([
    ['reject', 'reject'], ['reset-client', 'reject'], ['discard', 'deny'],
  ])('%s -> %s', (action, junosAction) => {
    const config = baseConfig({ security_policies: [policy({ action })] });
    expect(setLines(config)).toContain(`policy p1 then ${junosAction}`);
    expect(xmlOf(config)).toContain(`<${junosAction}/>`);
  });
});

describe('unemittable schedule', () => {
  const config = baseConfig({
    schedules: [{ name: 'daily-sched', type: 'recurring', days: [], start: '08:00', end: '17:00' }],
    security_policies: [policy({ schedule: 'daily-sched' })],
  });
  it('set: policy is deactivated and no scheduler-name references the missing scheduler', () => {
    const out = setLines(config);
    expect(out).not.toContain('scheduler-name daily-sched');
    expect(out).toContain('deactivate security policies global policy p1');
  });
  it('XML: policy is inactive, no empty scheduler, no scheduler-name', () => {
    const xml = xmlOf(config);
    expect(xml).not.toContain('scheduler-name');
    expect(xml).not.toMatch(/<scheduler>\s*<name>daily-sched/);
    expect(xml).toMatch(/<policy inactive="inactive">\s*<name>p1/);
  });
});
