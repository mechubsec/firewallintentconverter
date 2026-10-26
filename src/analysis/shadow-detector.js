/**
 * Rule Analysis Engine
 * ========================
 *
 * Detects rule issues and optimization opportunities within zone-pair groups.
 * SRX processes security policies top-down, first-match wins within each
 * zone-pair. Zone-based policies take precedence over global policies.
 * Implicit deny-all is last.
 *
 * Detection categories:
 *   SHADOWS (warning):
 *     1. Full shadow: earlier rule matches any/any/any
 *     2. Exact match: identical src, dst, and service criteria
 *     3. Any-superset: earlier rule uses "any" where later has specifics
 *     4. Disabled shadow: disabled rule that WOULD shadow if enabled
 *
 *   REORDER (warning):
 *     5. Deny-after-broad-permit: specific deny placed after broader permit
 *
 *   OPTIMIZATION (info):
 *     6. Redundant: later permit is subset of earlier permit
 *     7. Mergeable: adjacent rules differ in exactly one dimension
 *     8. Consolidation: 3+ rules with same services could be combined
 */

import { createWarning } from '../parsers/parser-utils.js';

// ---------------------------------------------------------------------------
// Main Entry Point
// ---------------------------------------------------------------------------

/**
 * Analyzes security policies for shadows, ordering issues, and optimization
 * opportunities within zone-pair groups.
 *
 * @param {Array} policies - security_policies from intermediate config
 * @param {Array} warnings - mutable array to push warnings into
 * @returns {{ shadowedCount, reorderCount, redundantCount, mergeableCount, consolidateCount }}
 */
export function detectShadowedRules(policies, warnings) {
  if (!policies || policies.length === 0) {
    return { shadowedCount: 0, reorderCount: 0, redundantCount: 0, mergeableCount: 0, consolidateCount: 0 };
  }

  // Group by zone pair (mirrors SRX converter logic)
  const zonePairs = buildZonePairs(policies);

  // Run all detectors
  const shadowedCount = detectShadows(zonePairs, warnings);
  const reorderCount = detectReorderIssues(zonePairs, warnings);
  const redundantCount = detectRedundantRules(zonePairs, warnings);
  const mergeableCount = detectMergeableRules(zonePairs, warnings);
  const consolidateCount = detectConsolidationOpportunities(zonePairs, warnings);

  return { shadowedCount, reorderCount, redundantCount, mergeableCount, consolidateCount };
}

// ---------------------------------------------------------------------------
// Zone-Pair Grouping
// ---------------------------------------------------------------------------

function buildZonePairs(policies) {
  const zonePairs = {};
  for (const policy of policies) {
    const srcZones = policy.src_zones.length > 0 ? policy.src_zones : ['any'];
    const dstZones = policy.dst_zones.length > 0 ? policy.dst_zones : ['any'];

    for (const src of srcZones) {
      for (const dst of dstZones) {
        const key = `${src} -> ${dst}`;
        if (!zonePairs[key]) zonePairs[key] = [];
        zonePairs[key].push(policy);
      }
    }
  }
  return zonePairs;
}

// ---------------------------------------------------------------------------
// 1. Shadow Detection (existing, refactored)
// ---------------------------------------------------------------------------

function detectShadows(zonePairs, warnings) {
  let count = 0;

  for (const [zonePair, rules] of Object.entries(zonePairs)) {
    for (let i = 1; i < rules.length; i++) {
      const laterRule = rules[i];
      if (laterRule._implicit) continue;

      for (let j = 0; j < i; j++) {
        const earlierRule = rules[j];

        const shadowType = checkShadow(earlierRule, laterRule);
        if (!shadowType) continue;

        const isEarlierDisabled = earlierRule.disabled;
        const disabledNote = isEarlierDisabled ? ' (currently disabled)' : '';

        warnings.push(createWarning(
          'warning',
          `policy/${laterRule.name}`,
          `Rule "${laterRule.name}" (#${laterRule._rule_index}) is ${shadowType} by earlier rule "${earlierRule.name}" (#${earlierRule._rule_index})${disabledNote} in zone-pair [${zonePair}]`,
          isEarlierDisabled
            ? 'The earlier rule is disabled — if enabled, it would shadow this rule'
            : 'The later rule will never match traffic — consider reordering or removing it'
        ));

        count++;
        break;
      }
    }
  }

  return count;
}

function checkShadow(earlier, later) {
  const earlierUsers = earlier.source_users || [];
  const laterUsers = later.source_users || [];

  if (isAnyMatch(earlier)) {
    // If earlier has no identity restriction but later does, later is more specific — not shadowed
    if (earlierUsers.length === 0 && laterUsers.length > 0) return null;
    return 'fully shadowed (any/any/any match-all)';
  }
  if (srcMatch(earlier, later) && dstMatch(earlier, later) &&
      (earlierUsers.length === 0 || arraysMatchUnordered(earlierUsers, laterUsers)) &&
      servicesMatch(earlier, later)) {
    return 'exactly shadowed (identical match criteria)';
  }
  if (isSupersetByAny(earlier, later) &&
      (earlierUsers.length === 0 || arraysMatchUnordered(earlierUsers, laterUsers))) {
    return 'shadowed (earlier rule uses broader match criteria)';
  }
  return null;
}

// ---------------------------------------------------------------------------
// 2. Reorder Detection — deny after broader permit
// ---------------------------------------------------------------------------

/**
 * Detects deny rules placed after a broader permit that covers the same traffic.
 * Since SRX is first-match, the deny will never fire.
 */
function detectReorderIssues(zonePairs, warnings) {
  let count = 0;

  for (const [zonePair, rules] of Object.entries(zonePairs)) {
    const activeRules = rules.filter(r => !r._implicit && !r.disabled);

    for (let i = 0; i < activeRules.length; i++) {
      const laterRule = activeRules[i];
      if (laterRule.action === 'allow') continue; // only check deny/reject rules

      for (let j = 0; j < i; j++) {
        const earlierRule = activeRules[j];
        if (earlierRule.action !== 'allow') continue;

        // Check if the later deny is a subset of the earlier permit
        if (isSubset(laterRule, earlierRule) && !isSubset(earlierRule, laterRule)) {
          warnings.push(createWarning(
            'warning',
            `optimization/reorder/${laterRule.name}`,
            `Deny rule "${laterRule.name}" (#${laterRule._rule_index}) is after broader permit "${earlierRule.name}" (#${earlierRule._rule_index}) — deny will never match in [${zonePair}]`,
            'Move the deny rule above the broader permit rule so it takes effect'
          ));
          count++;
          break;
        }
      }
    }
  }

  return count;
}

// ---------------------------------------------------------------------------
// 3. Redundant Rule Detection
// ---------------------------------------------------------------------------

/**
 * Detects later permit rules that are subsets of an earlier permit rule.
 * The later rule will never independently match new traffic.
 */
function detectRedundantRules(zonePairs, warnings) {
  let count = 0;

  for (const [zonePair, rules] of Object.entries(zonePairs)) {
    for (let i = 1; i < rules.length; i++) {
      const laterRule = rules[i];
      if (laterRule._implicit || laterRule.disabled || laterRule.action !== 'allow') continue;

      for (let j = 0; j < i; j++) {
        const earlierRule = rules[j];
        if (earlierRule.disabled || earlierRule.action !== 'allow') continue;

        // Skip if it's an exact match (already caught by shadow detector)
        if (srcMatch(earlierRule, laterRule) && dstMatch(earlierRule, laterRule) &&
            servicesMatch(earlierRule, laterRule)) {
          break; // already reported as shadow
        }

        if (isSubset(laterRule, earlierRule)) {
          warnings.push(createWarning(
            'info',
            `optimization/redundant/${laterRule.name}`,
            `Rule "${laterRule.name}" (#${laterRule._rule_index}) is redundant — all its traffic is already permitted by "${earlierRule.name}" (#${earlierRule._rule_index}) in [${zonePair}]`,
            'Consider removing this rule to simplify the policy'
          ));
          count++;
          break;
        }
      }
    }
  }

  return count;
}

// ---------------------------------------------------------------------------
// 4. Mergeable Rule Detection
// ---------------------------------------------------------------------------

/**
 * Detects adjacent rules in the same zone-pair with the same action that
 * differ in exactly one dimension (src addresses, dst addresses, or services).
 * These can be merged into a single rule.
 */
function detectMergeableRules(zonePairs, warnings) {
  let count = 0;

  for (const [zonePair, rules] of Object.entries(zonePairs)) {
    const activeRules = rules.filter(r => !r._implicit && !r.disabled);

    for (let i = 0; i < activeRules.length - 1; i++) {
      const ruleA = activeRules[i];
      const ruleB = activeRules[i + 1];

      if (ruleA.action !== ruleB.action) continue;
      // Unioning negated lists is wrong (not-X + not-Y is not not-(X+Y)), so never suggest it.
      if (hasNegation(ruleA) || hasNegation(ruleB)) continue;

      const sameSrc = srcMatch(ruleA, ruleB);
      const sameDst = dstMatch(ruleA, ruleB);
      const sameSvc = servicesMatch(ruleA, ruleB);

      let mergeField = null;
      if (sameSrc && sameDst && !sameSvc) mergeField = 'services/applications';
      else if (sameSrc && !sameDst && sameSvc) mergeField = 'destination addresses';
      else if (!sameSrc && sameDst && sameSvc) mergeField = 'source addresses';

      if (mergeField) {
        warnings.push(createWarning(
          'info',
          `optimization/merge/${ruleA.name}+${ruleB.name}`,
          `Rules "${ruleA.name}" and "${ruleB.name}" can be merged — identical except ${mergeField} in [${zonePair}]`,
          `Combine ${mergeField} into a single rule for a cleaner policy`
        ));
        count++;
      }
    }
  }

  return count;
}

// ---------------------------------------------------------------------------
// 5. Consolidation Opportunities
// ---------------------------------------------------------------------------

/**
 * Detects 3+ rules with identical services and source addresses (or
 * identical services and destination addresses) that could be consolidated
 * into a single rule using an address group.
 */
function detectConsolidationOpportunities(zonePairs, warnings) {
  let count = 0;

  for (const [zonePair, rules] of Object.entries(zonePairs)) {
    const activePermits = rules.filter(r => !r._implicit && !r.disabled && r.action === 'allow');
    if (activePermits.length < 3) continue;

    // Group by normalized service + source addresses
    const bySvcAndSrc = {};
    // Group by normalized service + destination addresses
    const bySvcAndDst = {};

    for (const rule of activePermits) {
      const svcKey = getAllServices(rule).sort().join('|');
      if (svcKey === 'any') continue; // skip any/any rules
      if (hasNegation(rule)) continue; // a merged list can't express "except X"

      const srcKey = [...(rule.src_addresses || ['any'])].sort().join('|');
      const dstKey = [...(rule.dst_addresses || ['any'])].sort().join('|');

      const srcGroupKey = `svc:${svcKey}|src:${srcKey}`;
      if (!bySvcAndSrc[srcGroupKey]) bySvcAndSrc[srcGroupKey] = [];
      bySvcAndSrc[srcGroupKey].push(rule);

      const dstGroupKey = `svc:${svcKey}|dst:${dstKey}`;
      if (!bySvcAndDst[dstGroupKey]) bySvcAndDst[dstGroupKey] = [];
      bySvcAndDst[dstGroupKey].push(rule);
    }

    // Check same-service + same-source → consolidate destinations
    for (const [, group] of Object.entries(bySvcAndSrc)) {
      if (group.length < 3) continue;
      const ruleNames = group.map(r => `"${r.name}"`).join(', ');
      warnings.push(createWarning(
        'info',
        `optimization/consolidate/${group[0].name}`,
        `${group.length} rules with same services and source could be consolidated in [${zonePair}]: ${ruleNames}`,
        'Merge destination addresses into a single rule or address group'
      ));
      count++;
    }

    // Check same-service + same-destination → consolidate sources
    for (const [, group] of Object.entries(bySvcAndDst)) {
      if (group.length < 3) continue;
      // Avoid duplicate if already flagged in the src group
      const srcAlreadyFlagged = Object.values(bySvcAndSrc).some(g =>
        g.length >= 3 && g.every(r => group.includes(r)));
      if (srcAlreadyFlagged) continue;

      const ruleNames = group.map(r => `"${r.name}"`).join(', ');
      warnings.push(createWarning(
        'info',
        `optimization/consolidate/${group[0].name}`,
        `${group.length} rules with same services and destination could be consolidated in [${zonePair}]: ${ruleNames}`,
        'Merge source addresses into a single rule or address group'
      ));
      count++;
    }
  }

  return count;
}

// ---------------------------------------------------------------------------
// Shared Helpers
// ---------------------------------------------------------------------------

function isAnyMatch(rule) {
  return isAnyAddresses(rule.src_addresses, rule.negate_source) &&
         isAnyAddresses(rule.dst_addresses, rule.negate_destination) &&
         isAnyService(rule);
}

// A negated side ("everything except X") is never "any", even when its list is.
function isAnyAddresses(addrs, negated) {
  if (negated) return false;
  if (!addrs || addrs.length === 0) return true;
  return addrs.length === 1 && (addrs[0] === 'any' || addrs[0] === 'all');
}

function isAnyService(rule) {
  const apps = rule.applications || [];
  const svcs = rule.services || [];
  if (apps.length === 1 && apps[0] === 'any') return true;
  if (svcs.length === 1 && (svcs[0] === 'any' || svcs[0] === 'ALL')) return true;
  if (apps.length === 0 && svcs.length === 0) return true;
  return false;
}

function arraysMatchUnordered(a, b) {
  if (!a || !b) return (!a || a.length === 0) && (!b || b.length === 0);
  if (a.length !== b.length) return false;
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  return sortedA.every((v, i) => v === sortedB[i]);
}

// Address sides are only comparable when their negation flags match.
function srcMatch(ruleA, ruleB) {
  return !ruleA.negate_source === !ruleB.negate_source &&
    arraysMatchUnordered(ruleA.src_addresses, ruleB.src_addresses);
}

function dstMatch(ruleA, ruleB) {
  return !ruleA.negate_destination === !ruleB.negate_destination &&
    arraysMatchUnordered(ruleA.dst_addresses, ruleB.dst_addresses);
}

function hasNegation(rule) {
  return Boolean(rule.negate_source || rule.negate_destination);
}

function getAllServices(rule) {
  return [...(rule.applications || []), ...(rule.services || [])]
    .filter(s => s !== 'application-default');
}

function servicesMatch(earlier, later) {
  if (isAnyService(earlier)) return true;
  const earlierAll = getAllServices(earlier);
  const laterAll = getAllServices(later);
  return arraysMatchUnordered(earlierAll, laterAll);
}

function isSupersetByAny(earlier, later) {
  const earlierSrcAny = isAnyAddresses(earlier.src_addresses, earlier.negate_source);
  const earlierDstAny = isAnyAddresses(earlier.dst_addresses, earlier.negate_destination);

  if (!earlierSrcAny && !earlierDstAny) return false;
  if (earlierSrcAny && earlierDstAny) return false;

  if (earlierSrcAny && !earlierDstAny) {
    if (!dstMatch(earlier, later)) return false;
  } else if (!earlierSrcAny && earlierDstAny) {
    if (!srcMatch(earlier, later)) return false;
  }

  return servicesMatch(earlier, later);
}

/**
 * Checks if ruleA's match criteria is a subset of ruleB's.
 * ruleA is a subset of ruleB if every packet matching ruleA also matches ruleB.
 */
function isSubset(ruleA, ruleB) {
  const srcOk = isAnyAddresses(ruleB.src_addresses, ruleB.negate_source) ||
    addressesSubset(ruleA.src_addresses, ruleA.negate_source, ruleB.src_addresses, ruleB.negate_source);
  if (!srcOk) return false;

  const dstOk = isAnyAddresses(ruleB.dst_addresses, ruleB.negate_destination) ||
    addressesSubset(ruleA.dst_addresses, ruleA.negate_destination, ruleB.dst_addresses, ruleB.negate_destination);
  if (!dstOk) return false;

  return isAnyService(ruleB) || servicesSubset(ruleA, ruleB);
}

// Mismatched negation is never a subset; both-negated is only trusted on exact equality.
function addressesSubset(subset, subsetNegated, superset, supersetNegated) {
  if (subsetNegated || supersetNegated) {
    return Boolean(subsetNegated) === Boolean(supersetNegated) && arraysMatchUnordered(subset, superset);
  }
  return arraysSubset(subset, superset);
}

function arraysSubset(subset, superset) {
  if (!subset || subset.length === 0) return true;
  if (!superset) return false;
  const superSet = new Set(superset);
  return subset.every(item => superSet.has(item));
}

function servicesSubset(ruleA, ruleB) {
  const aAll = getAllServices(ruleA);
  const bAll = getAllServices(ruleB);
  if (aAll.length === 0) return true;
  const bSet = new Set(bAll);
  return aAll.every(s => bSet.has(s));
}
