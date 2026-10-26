/**
 * SRX Output Validator
 * ======================
 * Agent: SRX-Expert
 *
 * Validates the generated SRX configuration for common issues before export.
 * Checks for:
 *   - Duplicate object names
 *   - Missing address references in policies
 *   - Invalid zone references
 *   - Empty policies (no match criteria)
 *   - Naming convention violations
 *
 * Phase 1: Basic validation checks.
 * Phase 2+: Deep validation including cross-reference integrity and
 *           platform-specific constraints (branch vs high-end SRX).
 */

import { createWarning } from '../parsers/parser-utils.js';

/**
 * Validates the intermediate config and the generated SRX output.
 *
 * @param {Object} intermediateConfig - The parsed intermediate JSON
 * @param {Object} output - The generated SRX output (commands or xml)
 * @returns {{ valid: boolean, errors: Object[], warnings: Object[] }}
 */
export function validateSrxOutput(intermediateConfig, output) {
  const errors = [];
  const warnings = [];

  // Check for duplicate object names
  checkDuplicateNames(intermediateConfig, errors);

  // Check for unresolved references in policies
  checkUnresolvedReferences(intermediateConfig, warnings);

  // Check for empty or overly broad policies
  checkPolicyQuality(intermediateConfig, warnings);

  // Check naming conventions
  checkNamingConventions(intermediateConfig, warnings);

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Checks for duplicate names within each object category.
 * Junos will reject configs with duplicate names.
 */
function checkDuplicateNames(config, errors) {
  const categories = [
    { items: config.address_objects, label: 'address' },
    { items: config.address_groups, label: 'address-group' },
    { items: config.service_objects, label: 'service' },
    { items: config.security_policies, label: 'security-policy' },
    { items: config.nat_rules, label: 'nat-rule' },
  ];

  for (const { items, label } of categories) {
    if (!items) continue;
    const seen = new Set();
    for (const item of items) {
      if (seen.has(item.name)) {
        errors.push(createWarning('unsupported', `${label}/${item.name}`,
          `Duplicate ${label} name "${item.name}" — Junos requires unique names within each category`,
          `Rename one of the duplicate "${item.name}" objects`));
      }
      seen.add(item.name);
    }
  }
}

/**
 * Checks that addresses referenced in security policies actually exist
 * in the address book.
 */
function checkUnresolvedReferences(config, warnings) {
  const addressNames = new Set([
    ...(config.address_objects || []).map(a => a.name),
    ...(config.address_groups || []).map(g => g.name),
    'any', // Built-in
  ]);

  const zoneNames = new Set([
    ...(config.zones || []).map(z => z.name),
    'any', // Built-in
  ]);

  for (const policy of (config.security_policies || [])) {
    // Check source addresses
    for (const addr of (policy.src_addresses || [])) {
      if (!addressNames.has(addr)) {
        warnings.push(createWarning('warning', `policy/${policy.name}`,
          `Source address "${addr}" referenced in policy "${policy.name}" not found in address book`,
          'Ensure the address object is defined or add it manually'));
      }
    }
    // Check destination addresses
    for (const addr of (policy.dst_addresses || [])) {
      if (!addressNames.has(addr)) {
        warnings.push(createWarning('warning', `policy/${policy.name}`,
          `Destination address "${addr}" referenced in policy "${policy.name}" not found in address book`,
          'Ensure the address object is defined or add it manually'));
      }
    }
    // Check zones
    for (const zone of (policy.src_zones || [])) {
      if (!zoneNames.has(zone)) {
        warnings.push(createWarning('warning', `policy/${policy.name}`,
          `Source zone "${zone}" referenced in policy "${policy.name}" not found in zone list`,
          'Verify zone names match between source and SRX config'));
      }
    }
    for (const zone of (policy.dst_zones || [])) {
      if (!zoneNames.has(zone)) {
        warnings.push(createWarning('warning', `policy/${policy.name}`,
          `Destination zone "${zone}" referenced in policy "${policy.name}" not found in zone list`,
          'Verify zone names match between source and SRX config'));
      }
    }
  }
}

/**
 * Flags overly broad or empty policies that might indicate config errors.
 */
function checkPolicyQuality(config, warnings) {
  for (const policy of (config.security_policies || [])) {
    if (policy._implicit) continue; // source-platform default, not a user rule
    // Flag permit-any rules
    const allAnySrc = (policy.src_addresses || []).length === 0 ||
      (policy.src_addresses.length === 1 && policy.src_addresses[0] === 'any');
    const allAnyDst = (policy.dst_addresses || []).length === 0 ||
      (policy.dst_addresses.length === 1 && policy.dst_addresses[0] === 'any');
    const allAnyApp = (policy.applications || []).length === 0 ||
      (policy.applications.length === 1 && policy.applications[0] === 'any');

    if (allAnySrc && allAnyDst && allAnyApp && policy.action === 'allow') {
      warnings.push(createWarning('warning', `policy/${policy.name}`,
        `Policy "${policy.name}" permits ANY source, ANY destination, ANY application — this is a very permissive rule`,
        'Review this rule for security implications'));
    }
  }
}

/**
 * Checks for names that might cause issues in Junos.
 */
function checkNamingConventions(config, warnings) {
  const maxLength = 63;
  const allItems = [
    ...(config.address_objects || []),
    ...(config.address_groups || []),
    ...(config.service_objects || []),
    ...(config.security_policies || []),
    ...(config.nat_rules || []),
    ...(config.zones || []),
  ];

  for (const item of allItems) {
    if (!item.name) continue;
    if (item.name.length > maxLength) {
      warnings.push(createWarning('warning', `name/${item.name}`,
        `Name "${item.name}" exceeds Junos ${maxLength}-character limit — will be truncated`,
        'Consider using a shorter name'));
    }
    if (/\s/.test(item.name)) {
      warnings.push(createWarning('warning', `name/${item.name}`,
        `Name "${item.name}" contains spaces — will be replaced with hyphens in SRX output`,
        'Review the sanitized name in the output'));
    }
  }
}
