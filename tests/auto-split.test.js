import { describe, expect, it } from 'vitest';

import { autoSplitRoutingContexts } from '../public/utils/auto-split.js';

const baseConfig = () => ({
  metadata: { source_vendor: 'fortigate' },
  zones: [{ name: 'a', interfaces: [] }, { name: 'b', interfaces: [] }, { name: 'c', interfaces: [] }],
  routing_contexts: [{ type: 'vdom', name: 'v1', zones: ['a'] }, { type: 'vdom', name: 'v2', zones: ['b'] }],
});

describe('autoSplitRoutingContexts', () => {
  it('keeps slot names unique when contexts sanitize identically', () => {
    const config = baseConfig();
    config.routing_contexts = [{ type: 'vdom', name: 'a b', zones: ['a'] }, { type: 'vdom', name: 'a-b', zones: ['b'] }];
    const slots = autoSplitRoutingContexts(config);
    expect(new Set(slots.map(slot => slot.lsName)).size).toBe(2);
  });

  it('warns about dropped policies and policies/routes copied into several slots', () => {
    const config = baseConfig();
    config.security_policies = [
      { name: 'any-rule', src_zones: ['any'], dst_zones: ['any'] },
      { name: 'orphan', src_zones: ['c'], dst_zones: ['c'] },
      { name: 'own', src_zones: ['a'], dst_zones: ['a'] },
    ];
    config.static_routes = [{ destination: '0.0.0.0/0' }];
    const [slot] = autoSplitRoutingContexts(config);
    const messages = slot.warnings.map(warning => warning.message).join('\n');
    expect(messages).toContain('dropped: orphan');
    expect(messages).toContain('any-rule');
    expect(messages).toContain('0.0.0.0/0');
    expect(messages).not.toContain('own');
  });
});

describe('detectVendor', () => {
  it('detects Check Point JSON when objects-dictionary follows a long rulebase', async () => {
    const { detectVendor } = await import('../src/parsers/parser-utils.js');
    const rulebase = Array.from({ length: 200 }, (_, i) => ({ name: `rule-${i}`, type: 'access-rule' }));
    const text = JSON.stringify({ rulebase, 'objects-dictionary': [] });
    expect(text.indexOf('objects-dictionary')).toBeGreaterThan(2000);
    expect(detectVendor(text).vendor).toBe('checkpoint');
  });
});
