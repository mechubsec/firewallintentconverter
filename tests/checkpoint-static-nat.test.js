import { describe, it, expect } from 'vitest';
import { parseCheckPointConfig } from '../src/parsers/checkpoint-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';
import { buildSrxXml } from '../src/converters/srx-xml-builder.js';

const outboundRow = (overrides = {}) => ({
  type: 'nat-rule', name: 'web-out', method: 'static', 'auto-generated': true,
  'original-source': 'h1', 'original-destination': 'any', 'original-service': 'any',
  'translated-source': 'h2', 'translated-destination': 'any', 'translated-service': 'any',
  ...overrides,
});
const inboundRow = (overrides = {}) => ({
  type: 'nat-rule', name: 'web-in', method: 'static', 'auto-generated': true,
  'original-source': 'any', 'original-destination': 'h2', 'original-service': 'any',
  'translated-source': 'any', 'translated-destination': 'h1', 'translated-service': 'any',
  ...overrides,
});

const checkPointConfig = (rows) => JSON.stringify({
  'objects-dictionary': [
    { uid: 'h1', type: 'host', name: 'web-private', 'ipv4-address': '192.168.1.10' },
    { uid: 'h2', type: 'host', name: 'web-public', 'ipv4-address': '203.0.113.10' },
    { uid: 'h3', type: 'host', name: 'other-private', 'ipv4-address': '192.168.1.11' },
    { uid: 'partner', type: 'network', name: 'partner', subnet4: '198.51.100.0', 'mask-length4': '24' },
    { uid: 'inrange', type: 'host', name: 'in-range', 'ipv4-address': '203.0.113.50' },
    { uid: 'lowhost', type: 'host', name: 'low-host', 'ipv4-address': '10.0.0.1' },
    { uid: 'pubrange', type: 'address-range', name: 'pub-range', 'ipv4-address-first': '203.0.113.1', 'ipv4-address-last': '203.0.113.100' },
    { uid: 'h1net', type: 'network', name: 'h1-net', subnet4: '192.168.1.10', 'mask-length4': '32' },
    { uid: 'pubnet', type: 'network', name: 'pubnet', subnet4: '203.0.113.0', 'mask-length4': '24' },
    { uid: 'lan', type: 'network', name: 'lan', subnet4: '192.168.0.0', 'mask-length4': 16 },
    { uid: 'orig', type: 'CpmiOriginal', name: 'Original' },
    { uid: 'anyobj', type: 'CpmiAnyObject', name: 'Any' },
    { uid: 'svc443', type: 'service-tcp', name: 'https', port: '443' },
  ],
  rulebase: [],
  'nat-rulebase': { rulebase: rows },
});

const convert = (rows) => {
  const { intermediateConfig, warnings } = parseCheckPointConfig(checkPointConfig(rows));
  const result = convertToSrxSetCommands(structuredClone(intermediateConfig), {}, null, {});
  const xml = buildSrxXml(structuredClone(intermediateConfig), {}).xml;
  return { intermediateConfig, commands: result.commands, xml, warnings: [...warnings, ...result.warnings] };
};
const natLines = (commands) => commands.filter((line) => line.startsWith('set security nat'));

describe('Check Point static NAT', () => {
  it('an automatic outbound + inbound pair becomes one bidirectional static rule', () => {
    const { intermediateConfig, commands, xml } = convert([outboundRow(), inboundRow()]);
    expect(intermediateConfig.nat_rules).toHaveLength(1);
    const lines = natLines(commands);
    expect(lines.filter((line) => / rule \S+ match destination-address 203\.0\.113\.10\/32$/.test(line))).toHaveLength(1);
    expect(lines.some((line) => line.endsWith('then static-nat prefix 192.168.1.10/32'))).toBe(true);
    expect(lines.some((line) => line.includes('source pool') || line.includes('destination pool'))).toBe(false);
    expect(xml).toContain('<static-nat>');
    expect(xml).toContain('203.0.113.10/32');
  });

  it('pairs regardless of row order', () => {
    const { intermediateConfig } = convert([inboundRow(), outboundRow()]);
    expect(intermediateConfig.nat_rules).toHaveLength(1);
    expect(intermediateConfig.nat_rules[0].translated_src.one_way).toBeUndefined();
  });

  it('a lone outbound row is one-way source NAT with port no-translation', () => {
    const { intermediateConfig, commands, xml } = convert([outboundRow()]);
    expect(intermediateConfig.nat_rules).toHaveLength(1);
    expect(intermediateConfig.nat_rules[0].type).toBe('source');
    const lines = natLines(commands);
    expect(lines.some((line) => /source pool \S+ port no-translation$/.test(line))).toBe(true);
    expect(lines.some((line) => line.includes('set security nat static'))).toBe(false);
    expect(xml).toContain('<port><no-translation/></port>');
  });

  it('a lone inbound row is one-way destination NAT', () => {
    const { intermediateConfig, commands, xml } = convert([inboundRow()]);
    expect(intermediateConfig.nat_rules[0].type).toBe('destination');
    const lines = natLines(commands);
    expect(lines.some((line) => /destination pool \S+ address 192\.168\.1\.10\/32$/.test(line))).toBe(true);
    expect(lines.some((line) => line.includes('set security nat static'))).toBe(false);
    expect(xml).toContain('192.168.1.10/32');
  });

  it('a mismatched pair converts each row one-way', () => {
    const { intermediateConfig, commands } = convert([outboundRow(), inboundRow({ 'translated-destination': 'h3' })]);
    expect(intermediateConfig.nat_rules.map((rule) => rule.type)).toEqual(['source', 'destination']);
    expect(natLines(commands).some((line) => line.includes('set security nat static'))).toBe(false);
  });

  it('a disabled row is still skipped and does not pair', () => {
    const { intermediateConfig, warnings } = convert([outboundRow(), inboundRow({ enabled: false })]);
    expect(intermediateConfig.nat_rules.map((rule) => rule.type)).toEqual(['source']);
    expect(warnings.some((item) => item.message.includes('disabled'))).toBe(true);
  });

  it('a hide NAT row is unaffected', () => {
    const { intermediateConfig } = convert([outboundRow({ method: 'hide' })]);
    expect(intermediateConfig.nat_rules[0].translated_src.type).toBe('dynamic-ip-pool');
  });

  it('a lone inbound row limited to a source or service is skipped, and never pairs', () => {
    for (const limit of [{ 'original-source': 'h3' }, { 'original-service': 'https' }]) {
      const { intermediateConfig, warnings } = convert([outboundRow(), inboundRow(limit)]);
      expect(intermediateConfig.nat_rules.map((rule) => rule.type)).toEqual(['source']);
      expect(warnings.some((item) => item.element === 'nat/destination/web-in')).toBe(true);
    }
  });

  it('pairs thousands of rows quickly and in config order', () => {
    const rows = [];
    const objects = [];
    for (let index = 0; index < 3000; index++) {
      objects.push({ uid: `p${index}`, type: 'host', name: `priv${index}`, 'ipv4-address': `10.${index >> 8}.${index & 255}.1` });
      objects.push({ uid: `q${index}`, type: 'host', name: `pub${index}`, 'ipv4-address': `20.${index >> 8}.${index & 255}.1` });
      rows.push(outboundRow({ name: `out${index}`, 'original-source': `p${index}`, 'translated-source': `q${index}` }));
      rows.push(inboundRow({ name: `in${index}`, 'original-destination': `q${index}`, 'translated-destination': `p${index}` }));
    }
    const { intermediateConfig } = parseCheckPointConfig(JSON.stringify({ 'objects-dictionary': objects, rulebase: [], 'nat-rulebase': { rulebase: rows } }));
    expect(intermediateConfig.nat_rules).toHaveLength(3000);
    expect(intermediateConfig.nat_rules[0].name).toBe('out0');
  });

  it('treats the built-in Original object as an untouched cell', () => {
    const rows = [
      outboundRow({ 'translated-destination': 'orig', 'translated-service': 'orig' }),
      inboundRow({ 'translated-source': 'orig', 'translated-service': 'orig' }),
    ];
    const { intermediateConfig, commands } = convert(rows);
    expect(intermediateConfig.nat_rules).toHaveLength(1);
    expect(natLines(commands).some((line) => line.endsWith('then static-nat prefix 192.168.1.10/32'))).toBe(true);
  });

  it('skips static rows that translate the service, and never pairs them', () => {
    const { intermediateConfig, warnings } = convert([outboundRow(), inboundRow({ 'translated-service': 'svc443' })]);
    expect(intermediateConfig.nat_rules.map((rule) => rule.type)).toEqual(['source']);
    expect(warnings.some((item) => item.element === 'nat/static/web-in' && item.message.includes('service/port'))).toBe(true);
  });

  it('keeps one-way rules when an earlier rule could match the public address first', () => {
    const hideAll = { type: 'nat-rule', name: 'hide-all', method: 'hide', 'original-source': 'any', 'original-destination': 'any', 'original-service': 'any', 'translated-source': 'h2', 'translated-destination': 'orig', 'translated-service': 'orig' };
    const sameObject = { ...hideAll, name: 'to-public', 'original-destination': 'h2' };
    for (const earlier of [hideAll, sameObject]) {
      const { intermediateConfig, warnings } = convert([earlier, outboundRow(), inboundRow()]);
      // The outbound half converts one-way; the inbound half is not emitted as DNAT, which would run before source NAT.
      expect(intermediateConfig.nat_rules.map((rule) => rule.type)).toEqual(['source', 'source']);
      expect(warnings.some((item) => item.element === 'nat/destination/web-in' && item.message.includes(`"${earlier.name}"`))).toBe(true);
    }
  });

  it('keeps a pair one-way when an earlier rule could match its private host', () => {
    const earlierSource = { type: 'nat-rule', name: 'p-to-other', method: 'hide', 'original-source': 'h1', 'original-destination': 'h3', 'original-service': 'any', 'translated-source': 'h2', 'translated-destination': 'orig', 'translated-service': 'orig' };
    const { intermediateConfig } = convert([earlierSource, outboundRow(), inboundRow()]);
    expect(intermediateConfig.nat_rules.map((rule) => rule.type)).toEqual(['source', 'source', 'destination']);
    expect(intermediateConfig.nat_rules.some((rule) => rule.translated_src?.type === 'static' && !rule.translated_src.one_way)).toBe(false);
  });

  it('counts skipped rows as earlier rules for later pairs', () => {
    const portForward = inboundRow({ name: 'port-forward', 'translated-service': 'svc443' });
    const { intermediateConfig, warnings } = convert([portForward, outboundRow(), inboundRow()]);
    expect(intermediateConfig.nat_rules.map((rule) => rule.type)).toEqual(['source']);
    expect(warnings.some((item) => item.element === 'nat/destination/web-in' && item.message.includes('"port-forward"'))).toBe(true);
  });

  it('warns once per pair when a later destination NAT rule could also translate its private host', () => {
    const laterDnat = (name) => inboundRow({ name, 'original-destination': 'h3', 'translated-destination': 'h2' });
    const { intermediateConfig, warnings } = convert([outboundRow(), inboundRow(), laterDnat('later-a'), laterDnat('later-b')]);
    expect(intermediateConfig.nat_rules).toHaveLength(3);
    const overlap = warnings.filter((item) => item.message.includes('also destination-translated'));
    expect(overlap).toHaveLength(1);
    expect(overlap[0].element).toBe('nat/static/web-out');
    expect(overlap[0].message).toContain('"later-a"');
  });

  it('pairs inbound rows listed entirely before the outbound rows in linear time', () => {
    const pairs = 9000;
    const objects = [];
    const inbound = [];
    const outbound = [];
    for (let index = 0; index < pairs; index++) {
      objects.push({ uid: `p${index}`, type: 'host', name: `priv${index}`, 'ipv4-address': `10.${index >> 8}.${index & 255}.1` });
      objects.push({ uid: `q${index}`, type: 'host', name: `pub${index}`, 'ipv4-address': `20.${index >> 8}.${index & 255}.1` });
      inbound.push(inboundRow({ name: `in${index}`, 'original-destination': `q${index}`, 'translated-destination': `p${index}` }));
      outbound.push(outboundRow({ name: `out${index}`, 'original-source': `p${index}`, 'translated-source': `q${index}` }));
    }
    const { intermediateConfig } = parseCheckPointConfig(JSON.stringify({ 'objects-dictionary': objects, rulebase: [], 'nat-rulebase': { rulebase: [...inbound, ...outbound] } }));
    expect(intermediateConfig.nat_rules).toHaveLength(pairs);
  });

  it('collapses the pair when an earlier rule matches a different destination', () => {
    const unrelated = { type: 'nat-rule', name: 'to-other', method: 'hide', 'original-source': 'h3', 'original-destination': 'h3', 'original-service': 'any', 'translated-source': 'h2', 'translated-destination': 'orig', 'translated-service': 'orig' };
    const { intermediateConfig } = convert([unrelated, outboundRow(), inboundRow()]);
    expect(intermediateConfig.nat_rules).toHaveLength(2);
    expect(intermediateConfig.nat_rules[1].translated_src.one_way).toBeUndefined();
  });

  it('converts back-to-back automatic pairs without one blocking the next', () => {
    const objects = [];
    const rows = [];
    for (let index = 1; index <= 3; index++) {
      objects.push({ uid: `p${index}`, type: 'host', name: `priv${index}`, 'ipv4-address': `192.168.1.${index}` });
      objects.push({ uid: `q${index}`, type: 'host', name: `pub${index}`, 'ipv4-address': `203.0.113.${index}` });
      rows.push(outboundRow({ name: `out${index}`, 'original-source': `p${index}`, 'translated-source': `q${index}` }));
      rows.push(inboundRow({ name: `in${index}`, 'original-destination': `q${index}`, 'translated-destination': `p${index}` }));
    }
    const { intermediateConfig, warnings } = parseCheckPointConfig(JSON.stringify({ 'objects-dictionary': objects, rulebase: [], 'nat-rulebase': { rulebase: rows } }));
    expect(intermediateConfig.nat_rules).toHaveLength(3);
    expect(intermediateConfig.nat_rules.every((rule) => rule.translated_src.type === 'static' && !rule.translated_src.one_way)).toBe(true);
    expect(warnings.some((item) => item.element.startsWith('nat/destination/'))).toBe(false);
  });

  it('a leading hide rule for the internal network keeps later pairs one-way but still emits the inbound DNAT', () => {
    const hideLan = { type: 'nat-rule', name: 'hide-lan', method: 'hide', 'original-source': 'lan', 'original-destination': 'any', 'original-service': 'any', 'translated-source': 'h2', 'translated-destination': 'orig', 'translated-service': 'orig' };
    const { intermediateConfig } = convert([hideLan, outboundRow(), inboundRow()]);
    expect(intermediateConfig.nat_rules.map((rule) => rule.type)).toEqual(['source', 'source', 'destination']);
  });

  it('an earlier rule with a specific source blocks the public side only when it names the destination', () => {
    const base = { type: 'nat-rule', method: 'hide', 'original-source': 'h3', 'original-service': 'any', 'translated-source': 'h2', 'translated-destination': 'orig', 'translated-service': 'orig' };
    const namesPublic = { ...base, name: 'h3-to-public', 'original-destination': 'pubnet' };
    const hairpinOnly = { ...base, name: 'h3-to-any', 'original-destination': 'any' };
    const blocked = convert([namesPublic, outboundRow(), inboundRow()]);
    expect(blocked.intermediateConfig.nat_rules.map((rule) => rule.type)).toEqual(['source', 'source']);
    expect(blocked.warnings.some((item) => item.element === 'nat/destination/web-in' && item.message.includes('"h3-to-public"'))).toBe(true);
    const allowed = convert([hairpinOnly, outboundRow(), inboundRow()]);
    expect(allowed.intermediateConfig.nat_rules).toHaveLength(2);
    expect(allowed.intermediateConfig.nat_rules[1].translated_src.one_way).toBeUndefined();
  });

  it('a lone inbound subnet mapping is skipped, since a destination pool loses host offsets', () => {
    const { intermediateConfig, warnings } = convert([inboundRow({ 'original-destination': 'pubnet', 'translated-destination': 'lan' })]);
    expect(intermediateConfig.nat_rules).toHaveLength(0);
    expect(warnings.some((item) => item.element === 'nat/destination/web-in' && item.message.includes('host-to-host'))).toBe(true);
  });

  it('a lone outbound row with a specific destination keeps it as the source rule destination match', () => {
    const { intermediateConfig, commands } = convert([outboundRow({ 'original-destination': 'h3' })]);
    expect(intermediateConfig.nat_rules[0]).toMatchObject({ type: 'source', dst_addresses: ['other-private'] });
    expect(natLines(commands).some((line) => line.endsWith('match destination-address 192.168.1.11/32'))).toBe(true);
  });

  it('checks thousands of earlier rules and pairs without rescanning ranges', () => {
    const objects = [];
    const rows = [];
    const count = 3000;
    for (let index = 0; index < count; index++) {
      objects.push({ uid: `s${index}`, type: 'host', name: `src${index}`, 'ipv4-address': `10.1.${index >> 8}.${index & 255}` });
      objects.push({ uid: `d${index}`, type: 'network', name: `dst${index}`, subnet4: `10.2.${index >> 4}.${(index & 15) * 16}`, 'mask-length4': '28' });
      rows.push({ type: 'nat-rule', name: `pre${index}`, method: 'hide', 'original-source': `s${index}`, 'original-destination': `d${index}`, 'original-service': 'any', 'translated-source': `s${index}`, 'translated-destination': 'orig', 'translated-service': 'orig' });
    }
    for (let index = 0; index < count; index++) {
      objects.push({ uid: `p${index}`, type: 'host', name: `priv${index}`, 'ipv4-address': `192.168.${index >> 8}.${index & 255}` });
      objects.push({ uid: `q${index}`, type: 'host', name: `pub${index}`, 'ipv4-address': `20.${index >> 8}.${index & 255}.1` });
      rows.push(outboundRow({ name: `out${index}`, 'original-source': `p${index}`, 'translated-source': `q${index}` }));
      rows.push(inboundRow({ name: `in${index}`, 'original-destination': `q${index}`, 'translated-destination': `p${index}` }));
    }
    const { intermediateConfig } = parseCheckPointConfig(JSON.stringify({ 'objects-dictionary': objects, rulebase: [], 'nat-rulebase': { rulebase: rows } }));
    expect(intermediateConfig.nat_rules).toHaveLength(count * 2);
    expect(intermediateConfig.nat_rules.filter((rule) => rule.type === 'static')).toHaveLength(count);
  });

  const hideRule = (name, source, destination = 'any') => ({
    type: 'nat-rule', name, method: 'hide', 'original-source': source, 'original-destination': destination,
    'original-service': 'any', 'translated-source': 'h2', 'translated-destination': 'orig', 'translated-service': 'orig',
  });

  it('warns once per pair about an earlier external-source rule with destination any, without blocking', () => {
    const { intermediateConfig, warnings } = convert([hideRule('partner-hide', 'partner'), outboundRow(), inboundRow()]);
    expect(intermediateConfig.nat_rules.filter((rule) => rule.type === 'static')).toHaveLength(1);
    const notices = warnings.filter((item) => item.message.includes('takes precedence on Check Point'));
    expect(notices).toHaveLength(1);
    expect(notices[0].message).toContain('"partner-hide"');
    expect(notices[0].message).toContain('web-public');
  });

  it('does not warn when the earlier source is another pair or an internal network', () => {
    const objects = [];
    const rows = [];
    for (let index = 1; index <= 2; index++) {
      objects.push({ uid: `p${index}`, type: 'host', name: `priv${index}`, 'ipv4-address': `192.168.1.${index}` });
      objects.push({ uid: `q${index}`, type: 'host', name: `pub${index}`, 'ipv4-address': `203.0.113.${index}` });
      rows.push(outboundRow({ name: `out${index}`, 'original-source': `p${index}`, 'translated-source': `q${index}` }));
      rows.push(inboundRow({ name: `in${index}`, 'original-destination': `q${index}`, 'translated-destination': `p${index}` }));
    }
    const { warnings } = parseCheckPointConfig(JSON.stringify({ 'objects-dictionary': objects, rulebase: [], 'nat-rulebase': { rulebase: rows } }));
    expect(warnings.some((item) => item.message.includes('takes precedence on Check Point'))).toBe(false);
    const internal = convert([hideRule('lan-hide', 'lan'), outboundRow(), inboundRow()]);
    expect(internal.warnings.some((item) => item.message.includes('takes precedence on Check Point'))).toBe(false);
  });

  it('uses the earliest overlapping rule when the public object is an address range', () => {
    const named = { ...hideRule('names-public', 'h3', 'in-range') };
    const lowLater = hideRule('low-later', 'h3', 'low-host');
    const { intermediateConfig, warnings } = convert([named, outboundRow({ 'translated-source': 'pubrange' }), inboundRow({ 'original-destination': 'pubrange' }), lowLater]);
    expect(intermediateConfig.nat_rules.some((rule) => rule.type === 'static')).toBe(false);
    expect(warnings.some((item) => item.element === 'nat/destination/web-in' && item.message.includes('"names-public"'))).toBe(true);
  });

  it('converts a lone inbound host-to-host row built from /32 network objects', () => {
    const { intermediateConfig } = convert([inboundRow({ 'translated-destination': 'h1net' })]);
    expect(intermediateConfig.nat_rules[0].type).toBe('destination');
  });
});
