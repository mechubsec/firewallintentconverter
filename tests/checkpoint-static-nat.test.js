import { describe, it, expect } from 'vitest';
import { parseCheckPointConfig } from '../src/parsers/checkpoint-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

const checkPointConfig = (destination = 'any') => JSON.stringify({
  'objects-dictionary': [
    { uid: 'h1', type: 'host', name: 'web-private', 'ipv4-address': '192.168.1.10' },
    { uid: 'h2', type: 'host', name: 'web-public', 'ipv4-address': '203.0.113.10' },
  ],
  rulebase: [],
  'nat-rulebase': {
    rulebase: [{
      type: 'nat-rule',
      name: 'web-static',
      method: 'static',
      'original-source': 'h1',
      'original-destination': destination,
      'original-service': 'any',
      'translated-source': 'h2',
      'translated-destination': 'any',
      'translated-service': 'any',
    }],
  },
});

describe('Check Point static NAT', () => {
  // A manual Check Point NAT row is one-way; Junos static NAT would add inbound translation.
  it('a method static row is not turned into bidirectional Junos static NAT', () => {
    const { intermediateConfig, warnings } = parseCheckPointConfig(checkPointConfig());
    const result = convertToSrxSetCommands(structuredClone(intermediateConfig), {}, null, {});
    expect(result.commands.some((line) => line.startsWith('set security nat static'))).toBe(false);
    expect([...warnings, ...result.warnings].some((item) => item.element.startsWith('nat/static/'))).toBe(true);
  });
});
