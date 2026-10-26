/**
 * Address negation (negate_source / negate_destination) must be part of every
 * shadow, redundancy, merge and any-address comparison (#124).
 */

import { describe, it, expect } from 'vitest';
import { detectShadowedRules } from '../src/analysis/shadow-detector.js';
import { AnalysisEngine } from '../src/analysis/config-analyzer.js';

let ruleIndex = 0;
function rule(name, overrides = {}) {
  return {
    _rule_index: ++ruleIndex, name, action: 'allow',
    src_zones: ['trust'], dst_zones: ['untrust'],
    src_addresses: ['any'], dst_addresses: ['any'],
    applications: [], services: ['tcp-443'],
    ...overrides,
  };
}

function analyze(policies) {
  const warnings = [];
  const counts = detectShadowedRules(policies, warnings);
  return { counts, warnings };
}

describe('shadow detector respects address negation', () => {
  it('control: identical non-negated rules are still shadowed', () => {
    const { counts } = analyze([
      rule('a', { src_addresses: ['net-a'] }),
      rule('b', { src_addresses: ['net-a'] }),
    ]);
    expect(counts.shadowedCount).toBe(1);
  });

  it('control: a non-negated subset is still redundant', () => {
    const { counts } = analyze([
      rule('broad', { src_addresses: ['net-a', 'net-b'] }),
      rule('narrow', { src_addresses: ['net-a'] }),
    ]);
    expect(counts.redundantCount).toBe(1);
  });

  it('negated vs non-negated same list is not shadowed or redundant', () => {
    const { counts } = analyze([
      rule('not-a', { src_addresses: ['net-a'], negate_source: true }),
      rule('is-a', { src_addresses: ['net-a'] }),
    ]);
    expect(counts.shadowedCount).toBe(0);
    expect(counts.redundantCount).toBe(0);
  });

  it('negated destination mismatch is not shadowed', () => {
    const { counts } = analyze([
      rule('a', { dst_addresses: ['srv'] }),
      rule('b', { dst_addresses: ['srv'], negate_destination: true }),
    ]);
    expect(counts.shadowedCount).toBe(0);
  });

  it('negated any is not treated as any', () => {
    const { counts } = analyze([
      rule('not-any', { src_addresses: ['any'], negate_source: true, services: ['any'] }),
      rule('specific', { src_addresses: ['net-a'], services: ['tcp-443'] }),
    ]);
    expect(counts.shadowedCount).toBe(0);
    expect(counts.redundantCount).toBe(0);
  });

  it('negated vs non-negated pair is not suggested for merge', () => {
    const { counts } = analyze([
      rule('a', { src_addresses: ['net-a'] }),
      rule('b', { src_addresses: ['net-b'], negate_source: true }),
    ]);
    expect(counts.mergeableCount).toBe(0);
  });

  it('control: differing non-negated sources are still mergeable', () => {
    const { counts } = analyze([
      rule('a', { src_addresses: ['net-a'] }),
      rule('b', { src_addresses: ['net-b'] }),
    ]);
    expect(counts.mergeableCount).toBe(1);
  });

  it('both-negated pairs are only comparable on exact equality', () => {
    const same = analyze([
      rule('a', { src_addresses: ['net-a'], negate_source: true }),
      rule('b', { src_addresses: ['net-a'], negate_source: true }),
    ]);
    expect(same.counts.shadowedCount).toBe(1);

    // not-{a,b} is narrower than not-{a}; a naive subset test would flag it
    const different = analyze([
      rule('not-a', { src_addresses: ['net-a'], negate_source: true }),
      rule('not-a-b', { src_addresses: ['net-a', 'net-b'], negate_source: true }),
    ]);
    expect(different.counts.redundantCount).toBe(0);
    expect(different.counts.shadowedCount).toBe(0);
  });
});

describe('config analyzer respects address negation', () => {
  const config = (policies) => ({
    security_policies: policies,
    address_objects: [], address_groups: [], service_objects: [], service_groups: [], nat_rules: [],
  });

  it('negated any source is not overly permissive', () => {
    const finding = AnalysisEngine._permissivePolicies(config([
      rule('neg', { negate_source: true, services: ['any'] }),
      rule('open'),
    ]));
    expect(finding.count).toBe(1);
    expect(finding.items[0].label).toContain('open');
  });

  it('negated-any rule does not shadow a later rule', () => {
    const earlier = rule('neg', { negate_source: true, services: ['any'] });
    const later = rule('later', { src_addresses: ['net-a'] });
    expect(AnalysisEngine._shadows(earlier, later)).toBe(false);
    expect(AnalysisEngine._shadows({ ...earlier, negate_source: false }, later)).toBe(true);
  });

  it('negated duplicate is not a redundant rule; true duplicate still is', () => {
    const base = { src_addresses: ['net-a'] };
    expect(AnalysisEngine._redundantRules(config([
      rule('a', base), rule('b', { ...base, negate_source: true }),
    ])).count).toBe(0);
    expect(AnalysisEngine._redundantRules(config([
      rule('a', base), rule('b', base),
    ])).count).toBe(1);
  });

  it('negated any does not count as a deny-all tail rule', () => {
    const denyAll = { action: 'deny', log_end: true, services: ['any'] };
    expect(AnalysisEngine._noDenyAll(config([rule('d', denyAll)])).count).toBe(0);
    expect(AnalysisEngine._noDenyAll(config([rule('d', { ...denyAll, negate_source: true })])).count).toBe(1);
  });
});

describe('consolidation skips negated rules', () => {
  const trio = (negateLast) => [
    rule('c1', { src_addresses: ['net-a'], dst_addresses: ['srv-1'] }),
    rule('c2', { src_addresses: ['net-a'], dst_addresses: ['srv-2'] }),
    rule('c3', { src_addresses: ['net-a'], dst_addresses: ['srv-3'], negate_destination: negateLast }),
  ];

  it('control: three same-source rules are consolidation candidates', () => {
    expect(analyze(trio(false)).counts.consolidateCount).toBe(1);
  });

  it('a negated destination keeps the group below the threshold', () => {
    expect(analyze(trio(true)).counts.consolidateCount).toBe(0);
  });
});
