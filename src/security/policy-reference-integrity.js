/**
 * Policy Reference Integrity Detection
 * =======================================
 *
 * Finds security policies that reference undefined address or service objects.
 * A referenced name is undefined when it is none of:
 *   - 'any' (universal wildcard)
 *   - a literal address (IPv4/IPv6, prefix, or range) for address fields
 *   - a literal service ('application-default', proto/port shape, or bare port) for service fields
 *   - a defined name in address_objects ∪ address_groups (for addresses)
 *   - a defined name in service_objects ∪ service_groups (for services)
 *   - a vendor built-in the converter maps to a Junos predefined application
 *     (mapServiceToJunos: the source vendor's own catalog, as the identifier catalog does)
 *
 * Applications are intentionally NOT checked here (covered by issue #33).
 */

import { JUNOS_PREDEFINED_APPS, mapServiceToJunos } from '../parsers/parser-utils.js';

/**
 * Detects whether a string looks like a literal IP address, prefix, or range.
 * Accepts IPv4 and IPv6 forms:
 *   - Plain address: 192.0.2.1, 2001:db8::1
 *   - Prefix: 192.0.2.0/24, 2001:db8::/32
 *   - Range: 192.0.2.1-192.0.2.10
 *
 * @param {string} value - The address value to test
 * @returns {boolean} True if the value looks like a literal address
 */
function isLiteralAddress(value) {
  if (!value || typeof value !== 'string') return false;

  // Fix 2: IPv4 address requires full dotted-quad (not "10" or "1.2.3")
  const ipv4AddrPattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;

  // Fix 2: IPv4 range is two full dotted-quads joined by a dash
  const ipv4RangePattern = /^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$/;

  // Fix 3: IPv6 requires at least one colon (not bare hex like "abcd" or "fe80")
  const ipv6Pattern = /^[0-9a-fA-F:]+:[0-9a-fA-F:]*(-[0-9a-fA-F:]+:[0-9a-fA-F:]*)?(\/\d+)?$/;

  return ipv4AddrPattern.test(value) || ipv4RangePattern.test(value) || ipv6Pattern.test(value);
}

/**
 * Detects whether a string looks like a literal service specification.
 * Accepts:
 *   - 'application-default'
 *   - proto/port: tcp/443, udp/53
 *   - bare port number: 8080
 *
 * @param {string} value - The service value to test
 * @returns {boolean} True if the value looks like a literal service
 */
function isLiteralService(value) {
  if (!value || typeof value !== 'string') return false;

  // application-default
  if (value === 'application-default') return true;

  // proto/port or bare port number
  const protoPortPattern = /^(tcp|udp|icmp)\/\d+$/i;
  const barePortPattern = /^\d+$/;

  return protoPortPattern.test(value) || barePortPattern.test(value);
}

/**
 * Finds service groups with a member that resolves to nothing (not a defined
 * service/group, literal, or built-in of the source vendor), directly or via a
 * nested group. Such a group cannot be emitted as a valid application-set.
 *
 * @param {Object} config - Intermediate JSON config
 * @returns {Set<string>} Names of service groups with an unresolved member
 */
export function findUnresolvedServiceGroups(config) {
  const sourceVendor = config.metadata?.source_vendor || '';
  const groups = new Map((config.service_groups || []).map((group) => [group.name, group]));
  const definedNames = new Set((config.service_objects || []).map((obj) => obj.name));
  // Same emission rule as the identifier catalog: an application needs protocol+port (or a port list)
  for (const app of config.applications || []) {
    if (app.name && (String(app.port || '').includes(',') || (app.protocol && app.port))) definedNames.add(app.name);
  }
  const outcomes = new Map(); // group name -> true/false once decided; false while in progress (cycle guard)

  const hasUnresolvedMember = (group) => {
    if (outcomes.has(group.name)) return outcomes.get(group.name);
    outcomes.set(group.name, false);
    const bad = (group.members || []).some((member) => {
      if (!member || typeof member !== 'string' || member === 'any' || member === 'service-set') return false;
      if (groups.has(member)) return hasUnresolvedMember(groups.get(member));
      if (definedNames.has(member) || isLiteralService(member)) return false;
      const mapped = mapServiceToJunos(member, sourceVendor);
      return !(mapped === 'any' || JUNOS_PREDEFINED_APPS.has(mapped));
    });
    outcomes.set(group.name, bad);
    return bad;
  };
  for (const group of groups.values()) hasUnresolvedMember(group);
  return new Set([...outcomes].filter(([, bad]) => bad).map(([name]) => name));
}

/**
 * Finds security policies with undefined address or service references.
 * Returns a map of policy index → { addresses: string[], services: string[] }
 * containing ONLY policies that have at least one undefined reference.
 *
 * @param {Object} config - Intermediate JSON config
 * @returns {Map<number, {addresses: string[], services: string[]}>} Map of offending policy indices
 */
export function findPolicyReferenceIssues(config) {
  const issues = new Map();

  // Build defined name sets once
  const addressNames = new Set();
  for (const obj of config.address_objects || []) {
    if (obj.name) addressNames.add(obj.name);
  }
  for (const grp of config.address_groups || []) {
    if (grp.name) addressNames.add(grp.name);
  }

  const serviceNames = new Set();
  for (const obj of config.service_objects || []) {
    if (obj.name) serviceNames.add(obj.name);
  }
  for (const grp of config.service_groups || []) {
    if (grp.name) serviceNames.add(grp.name);
  }

  const sourceVendor = config.metadata?.source_vendor || '';
  const unresolvedGroups = findUnresolvedServiceGroups(config);
  const policies = config.security_policies || [];
  for (let i = 0; i < policies.length; i++) {
    const policy = policies[i];

    // Skip implicit policies
    if (policy._implicit) continue;

    const undefinedAddresses = [];
    const undefinedServices = [];

    // Check address references (src_addresses, dst_addresses)
    const srcAddresses = policy.src_addresses || [];
    const dstAddresses = policy.dst_addresses || [];
    const allAddresses = [...srcAddresses, ...dstAddresses];

    for (const addr of allAddresses) {
      if (!addr || typeof addr !== 'string') continue;

      // Defined if: 'any', literal IP, or in addressNames
      if (addr === 'any') continue;
      if (isLiteralAddress(addr)) continue;
      if (addressNames.has(addr)) continue;

      // Undefined reference — add if not already tracked
      if (!undefinedAddresses.includes(addr)) {
        undefinedAddresses.push(addr);
      }
    }

    // Check service references (services)
    const services = policy.services || [];
    for (const svc of services) {
      if (!svc || typeof svc !== 'string') continue;

      // Fix 4: Check defined service names BEFORE literal check so a defined
      // numeric-named service (e.g., service_objects: [{name: '8080', ...}]) is
      // treated as a defined reference, not a literal.
      if (svc === 'any') continue;
      if (serviceNames.has(svc) && !unresolvedGroups.has(svc)) continue;
      if (isLiteralService(svc)) continue;
      // Only a known predefined target counts: app-mappings.json can yield names
      // (e.g. junos-gre) that may not exist on the device.
      const mapped = mapServiceToJunos(svc, sourceVendor);
      if (mapped === 'any' || JUNOS_PREDEFINED_APPS.has(mapped)) continue;

      // Undefined reference — add if not already tracked
      if (!undefinedServices.includes(svc)) {
        undefinedServices.push(svc);
      }
    }

    // Applications are not checked (#33), except a reference to a service group
    // that is emitted deactivated: `match application <group>` would be invalid.
    for (const app of policy.applications || []) {
      if (unresolvedGroups.has(app) && !undefinedServices.includes(app)) undefinedServices.push(app);
    }

    // Include policy in map only if it has at least one undefined reference
    if (undefinedAddresses.length > 0 || undefinedServices.length > 0) {
      issues.set(i, {
        addresses: undefinedAddresses,
        services: undefinedServices,
      });
    }
  }

  return issues;
}

/**
 * Lists why a policy's negated source/destination match cannot be emitted
 * faithfully. Junos `*-address-excluded` negates the whole listed set, so the
 * list must be emitted exactly: a wildcard in it (negation then matches
 * nothing) or an entry dropped as an EDL block-list address (the exclusion
 * would shrink) changes the meaning, and the policy must be deactivated.
 *
 * @param {Object} policy - Intermediate security policy
 * @returns {string[]} Human-readable reasons; empty when negation is representable or absent
 */
export function findNegationIssues(policy) {
  const reasons = [];
  const droppedAddresses = new Set(policy._secIntelAddresses || []);
  for (const [negated, field, label] of [
    [policy.negate_source, 'src_addresses', 'source'],
    [policy.negate_destination, 'dst_addresses', 'destination'],
  ]) {
    if (!negated) continue;
    const addresses = policy[field] || [];
    if (addresses.length === 0 || addresses.some((addr) => addr === 'any' || addr === 'all')) {
      reasons.push(`negated ${label} matches nothing (list is or contains any)`);
    }
    if (addresses.some((addr) => droppedAddresses.has(addr))) {
      reasons.push(`negated ${label} list contains block-list addresses that are emitted as SecIntel feeds`);
    }
  }
  return reasons;
}
