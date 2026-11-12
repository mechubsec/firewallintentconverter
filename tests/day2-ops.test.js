/**
 * Tests for Day 2 Operations pure functions extracted from useDay2Ops hook.
 *
 * Run with: node tests/day2-ops.test.js
 */

// ---------------------------------------------------------------------------
// Minimal localStorage stub
// ---------------------------------------------------------------------------
const _store = {};
global.localStorage = {
  getItem: (k) => _store[k] || null,
  setItem: (k, v) => { _store[k] = v; },
  removeItem: (k) => { delete _store[k]; },
};

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------
import {
  computeSummaryPure,
  annotateConfigPure,
  disableNeverHitRulesPure,
  tightenPermissiveRulesPure,
} from '../public/hooks/useDay2Ops.js';

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------
let passed = 0;
let failed = 0;
let currentTest = '';

function assert(condition, msg) {
  const label = currentTest ? `${currentTest}: ${msg}` : msg;
  if (condition) {
    passed++;
  } else {
    failed++;
    console.error(`  FAIL: ${label}`);
  }
}

function test(name, fn) {
  currentTest = name;
  try {
    fn();
  } catch (err) {
    failed++;
    console.error(`  FAIL: ${name} — threw: ${err.message}`);
  }
  currentTest = '';
}

// ---------------------------------------------------------------------------
// computeSummaryPure
// ---------------------------------------------------------------------------

console.log('\n--- computeSummaryPure ---');

test('empty array → all zeros', () => {
  const result = computeSummaryPure([]);
  assert(result.total === 0, 'total === 0');
  assert(result.annotated === 0, 'annotated === 0');
  assert(result.active === 0, 'active === 0');
  assert(result.neverHit === 0, 'neverHit === 0');
  assert(result.activePercent === 0, 'activePercent === 0');
  assert(result.totalSessions === 0, 'totalSessions === 0');
  assert(Array.isArray(result.topApps), 'topApps is array');
  assert(result.topApps.length === 0, 'topApps is empty');
});

test('null/undefined → all zeros', () => {
  const resultNull = computeSummaryPure(null);
  assert(resultNull.total === 0, 'null total === 0');
  const resultUndef = computeSummaryPure(undefined);
  assert(resultUndef.total === 0, 'undefined total === 0');
});

test('mix of annotated and unannotated policies', () => {
  const policies = [
    { name: 'p1', _hit_count: 5, _session_count: 10 },
    { name: 'p2', _hit_count: 0, _session_count: 0 },
    { name: 'p3' }, // unannotated
    { name: 'p4', _hit_count: 3, _session_count: 2 },
  ];
  const result = computeSummaryPure(policies);
  assert(result.total === 4, 'total === 4');
  assert(result.annotated === 3, 'annotated === 3 (p1, p2, p4)');
  assert(result.active === 2, 'active === 2 (p1, p4)');
  assert(result.neverHit === 1, 'neverHit === 1 (p2 only)');
  assert(result.totalSessions === 12, 'totalSessions === 12');
});

test('all policies with _hit_count > 0 → activePercent = 100', () => {
  const policies = [
    { name: 'p1', _hit_count: 1 },
    { name: 'p2', _hit_count: 10 },
    { name: 'p3', _hit_count: 100 },
  ];
  const result = computeSummaryPure(policies);
  assert(result.activePercent === 100, 'activePercent === 100');
  assert(result.neverHit === 0, 'neverHit === 0');
});

test('some with _hit_count = 0 → correct neverHit, excluding disabled', () => {
  const policies = [
    { name: 'p1', _hit_count: 0 },           // never hit
    { name: 'p2', _hit_count: 0, disabled: true }, // disabled — excluded from neverHit
    { name: 'p3', _hit_count: 0 },            // never hit
    { name: 'p4', _hit_count: 5 },
  ];
  const result = computeSummaryPure(policies);
  assert(result.neverHit === 2, 'neverHit === 2 (p1, p3 — p2 disabled excluded)');
});

test('topApps sorted by sessions descending', () => {
  const appSessions = [
    { application: 'junos-http', sessions: 50 },
    { application: 'junos-https', sessions: 200 },
    { application: 'junos-dns', sessions: 10 },
  ];
  const result = computeSummaryPure([], appSessions);
  assert(result.topApps[0].application === 'junos-https', 'first topApp is junos-https');
  assert(result.topApps[1].application === 'junos-http', 'second topApp is junos-http');
  assert(result.topApps[2].application === 'junos-dns', 'third topApp is junos-dns');
});

test('topApps capped at 10', () => {
  const appSessions = Array.from({ length: 15 }, (_, i) => ({
    application: `app-${i}`,
    sessions: i,
  }));
  const result = computeSummaryPure([], appSessions);
  assert(result.topApps.length === 10, 'topApps.length === 10');
});

// ---------------------------------------------------------------------------
// annotateConfigPure
// ---------------------------------------------------------------------------

console.log('\n--- annotateConfigPure ---');

const MOCK_STATS = {
  policies: [
    { name: 'allow-web', hit_count: 100, session_count: 50, byte_count: 9000 },
    { name: 'allow-dns', hit_count: 0, session_count: 0, byte_count: 0 },
  ],
  app_sessions: [
    { application: 'junos-https', sessions: 200 },
    { application: 'junos-http', sessions: 50 },
    { application: 'junos-dns', sessions: 10 },
  ],
};

test('exact name match annotates policy correctly', () => {
  const configPolicies = [
    { name: 'allow-web', applications: ['junos-https', 'junos-http'] },
  ];
  const { annotatedPolicies, matchCount } = annotateConfigPure(configPolicies, MOCK_STATS);
  const pol = annotatedPolicies[0];
  assert(matchCount === 1, 'matchCount === 1');
  assert(pol._hit_count === 100, '_hit_count === 100');
  assert(pol._session_count === 50, '_session_count === 50');
  assert(pol._byte_count === 9000, '_byte_count === 9000');
  assert(typeof pol._stats_timestamp === 'string', '_stats_timestamp is string');
});

test('unmatched policy gets no annotation', () => {
  const configPolicies = [
    { name: 'allow-web', applications: ['junos-https'] },
    { name: 'deny-all', applications: ['any'] },  // not in stats
  ];
  const { annotatedPolicies } = annotateConfigPure(configPolicies, MOCK_STATS);
  const unmatched = annotatedPolicies.find(p => p.name === 'deny-all');
  assert(unmatched._hit_count === undefined, 'unmatched has no _hit_count');
  assert(unmatched._matched_apps === undefined, 'unmatched has no _matched_apps');
});

test('low match rate (< 50%) detectable via matchRate', () => {
  const configPolicies = [
    { name: 'allow-web', applications: [] },
    { name: 'policy-x', applications: [] },
    { name: 'policy-y', applications: [] },
  ];
  const { matchRate, matchCount } = annotateConfigPure(configPolicies, MOCK_STATS);
  assert(matchCount === 1, 'matchCount === 1');
  assert(matchRate < 0.5, 'matchRate < 0.5');
});

test('_matched_apps = intersection of policy.applications and app_sessions', () => {
  const configPolicies = [
    { name: 'allow-web', applications: ['junos-https', 'junos-dns', 'junos-ftp'] },
  ];
  const { annotatedPolicies } = annotateConfigPure(configPolicies, MOCK_STATS);
  const pol = annotatedPolicies[0];
  assert(pol._matched_apps.includes('junos-https'), '_matched_apps has junos-https');
  assert(pol._matched_apps.includes('junos-dns'), '_matched_apps has junos-dns');
  assert(!pol._matched_apps.includes('junos-ftp'), '_matched_apps excludes junos-ftp (no sessions)');
  assert(pol._matched_apps.length === 2, '_matched_apps.length === 2');
});

test('policy with applications: ["any"] — "any" not in app_sessions → empty _matched_apps', () => {
  const configPolicies = [
    { name: 'allow-web', applications: ['any'] },
  ];
  const { annotatedPolicies } = annotateConfigPure(configPolicies, MOCK_STATS);
  const pol = annotatedPolicies[0];
  assert(Array.isArray(pol._matched_apps), '_matched_apps is array');
  assert(pol._matched_apps.length === 0, '_matched_apps is empty (any is not a session key)');
});

test('policy with no matching apps → empty _matched_apps', () => {
  const configPolicies = [
    { name: 'allow-web', applications: ['junos-ftp', 'junos-smtp'] },
  ];
  const { annotatedPolicies } = annotateConfigPure(configPolicies, MOCK_STATS);
  const pol = annotatedPolicies[0];
  assert(pol._matched_apps.length === 0, '_matched_apps empty when no sessions match');
});

test('null/missing config → returns empty array', () => {
  const { annotatedPolicies } = annotateConfigPure(null, MOCK_STATS);
  assert(Array.isArray(annotatedPolicies), 'returns array');
  assert(annotatedPolicies.length === 0, 'returns empty array');
});

// ---------------------------------------------------------------------------
// disableNeverHitRulesPure
// ---------------------------------------------------------------------------

console.log('\n--- disableNeverHitRulesPure ---');

test('policies with _hit_count === 0 get disabled: true', () => {
  const policies = [
    { name: 'p1', _hit_count: 0 },
    { name: 'p2', _hit_count: 5 },
    { name: 'p3', _hit_count: 0 },
  ];
  const result = disableNeverHitRulesPure(policies);
  assert(result[0].disabled === true, 'p1 disabled');
  assert(result[2].disabled === true, 'p3 disabled');
});

test('policies with _hit_count > 0 are unchanged', () => {
  const policies = [
    { name: 'p1', _hit_count: 5 },
  ];
  const result = disableNeverHitRulesPure(policies);
  assert(!result[0].disabled, 'p1 not disabled');
});

test('already-disabled policies are unchanged', () => {
  const policies = [
    { name: 'p1', _hit_count: 0, disabled: true },
  ];
  const result = disableNeverHitRulesPure(policies);
  // Should remain disabled but not be double-touched
  assert(result[0].disabled === true, 'still disabled');
  // Original object should be same reference (not re-spread)
  assert(result[0] === policies[0], 'same reference — not mutated unnecessarily');
});

test('unannotated policies (no _hit_count) are unchanged', () => {
  const policies = [
    { name: 'p1' }, // no _hit_count
  ];
  const result = disableNeverHitRulesPure(policies);
  assert(!result[0].disabled, 'unannotated policy not disabled');
});

// ---------------------------------------------------------------------------
// tightenPermissiveRulesPure
// ---------------------------------------------------------------------------

console.log('\n--- tightenPermissiveRulesPure ---');

test('policy with "any" + _matched_apps → applications replaced', () => {
  const policies = [
    { name: 'p1', applications: ['any'], _matched_apps: ['junos-https', 'junos-dns'] },
  ];
  const result = tightenPermissiveRulesPure(policies);
  assert(!result[0].applications.includes('any'), '"any" removed');
  assert(result[0].applications.includes('junos-https'), 'junos-https added');
  assert(result[0].applications.includes('junos-dns'), 'junos-dns added');
  assert(result[0].applications.length === 2, 'applications.length === 2');
});

test('policy without "any" is unchanged', () => {
  const policies = [
    { name: 'p1', applications: ['junos-https'], _matched_apps: ['junos-https'] },
  ];
  const result = tightenPermissiveRulesPure(policies);
  assert(result[0] === policies[0], 'same reference — not modified');
});

test('policy with "any" but no _matched_apps is unchanged', () => {
  const policies = [
    { name: 'p1', applications: ['any'], _matched_apps: [] },
  ];
  const result = tightenPermissiveRulesPure(policies);
  assert(result[0].applications.includes('any'), '"any" preserved when no matched apps');
});

test('policy with "any" but missing _matched_apps is unchanged', () => {
  const policies = [
    { name: 'p1', applications: ['any'] },
  ];
  const result = tightenPermissiveRulesPure(policies);
  assert(result[0].applications.includes('any'), '"any" preserved when _matched_apps missing');
});

test('mixed policies — only eligible ones are tightened', () => {
  const policies = [
    { name: 'p1', applications: ['any'], _matched_apps: ['junos-https'] },
    { name: 'p2', applications: ['any'], _matched_apps: [] },
    { name: 'p3', applications: ['junos-dns'], _matched_apps: ['junos-dns'] },
  ];
  const result = tightenPermissiveRulesPure(policies);
  assert(!result[0].applications.includes('any'), 'p1 tightened');
  assert(result[1].applications.includes('any'), 'p2 unchanged');
  assert(result[2].applications.includes('junos-dns'), 'p3 unchanged');
});

test('same policy name in different zone pairs keeps separate hit counts', () => {
  const stats = { policies: [
    { name: 'allow-web', from_zone: 'trust', to_zone: 'dmz', hit_count: 5000 },
    { name: 'allow-web', from_zone: 'guest', to_zone: 'untrust', hit_count: 0 },
  ] };
  const configPolicies = [
    { name: 'allow-web', src_zones: ['trust'], dst_zones: ['dmz'] },
    { name: 'allow-web', src_zones: ['guest'], dst_zones: ['untrust'] },
  ];
  const { annotatedPolicies } = annotateConfigPure(configPolicies, stats);
  assert(annotatedPolicies[0]._hit_count === 5000, 'trust->dmz keeps 5000 hits');
  assert(annotatedPolicies[1]._hit_count === 0, 'guest->untrust has 0 hits');
  const disabled = disableNeverHitRulesPure(annotatedPolicies);
  assert(!disabled[0].disabled && disabled[1].disabled, 'only the never-hit rule is disabled');
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log(`\n✔ ${passed} passed  ${failed > 0 ? `✘ ${failed} failed` : '0 failed'}\n`);
if (failed > 0) process.exit(1);
