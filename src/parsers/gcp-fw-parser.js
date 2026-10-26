/**
 * GCP VPC Firewall Rules Parser
 * ================================
 *
 * Parses GCP Firewall Rules JSON (from `gcloud compute firewall-rules list --format=json`)
 * into the vendor-neutral intermediate JSON schema.
 *
 * Handles:
 *   - INGRESS and EGRESS direction rules
 *   - allowed / denied arrays with IPProtocol and ports
 *   - sourceRanges, destinationRanges
 *   - sourceTags, targetTags, sourceServiceAccounts, targetServiceAccounts
 *   - priority-based ordering
 *   - disabled rules
 *   - Network → zone mapping
 *
 * Cloud-to-firewall concept mapping:
 *   network     → zone
 *   targetTags  → address-group
 *   allowed[]   → permit policy with service objects
 *   denied[]    → deny policy with service objects
 */

import { createWarning } from './parser-utils.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Safely parse JSON with prototype-pollution guard.
 * @param {string} text
 * @returns {Object}
 */
function safeParse(text) {
  return JSON.parse(text, (key, value) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return undefined;
    }
    return value;
  });
}

/**
 * Extract a short network name from the full GCP network URL.
 * e.g. "projects/my-proj/global/networks/my-vpc" → "my-vpc"
 *
 * @param {string} networkUrl
 * @returns {string}
 */
function extractNetworkName(networkUrl) {
  if (!networkUrl) return 'default';
  const parts = networkUrl.split('/');
  return parts[parts.length - 1] || 'default';
}

/**
 * Normalize GCP protocol value.
 * @param {string} proto
 * @returns {string}
 */
function normalizeProtocol(proto) {
  if (!proto || proto === 'all') return 'any';
  const lower = proto.toLowerCase();
  const numMap = { '6': 'tcp', '17': 'udp', '1': 'icmp', '58': 'icmpv6' };
  return numMap[lower] || lower;
}

/**
 * Build service objects from a GCP allowed/denied entry.
 * Each entry has { IPProtocol, ports? } where ports is an array like ["80", "443", "8080-8090"].
 *
 * @param {Object} entry - GCP allowed/denied entry
 * @param {Object[]} serviceObjects - accumulator
 * @param {Set} serviceObjectSet - dedup set
 * @returns {string[]} - array of service names
 */
function buildServicesFromEntry(entry, serviceObjects, serviceObjectSet) {
  const protocol = normalizeProtocol(entry.IPProtocol);

  if (protocol === 'any') return ['any'];

  const ports = entry.ports;
  if (!ports || !Array.isArray(ports) || ports.length === 0) {
    // Protocol with no port restriction (e.g. ICMP, ESP, or all ports for TCP/UDP)
    const svcName = protocol;
    if (!serviceObjectSet.has(svcName)) {
      serviceObjectSet.add(svcName);
      serviceObjects.push({
        name: svcName,
        protocol,
        port: '',
        source_port: '',
      });
    }
    return [svcName];
  }

  const serviceNames = [];
  for (const portSpec of ports) {
    const svcName = `${protocol}/${portSpec}`;
    if (!serviceObjectSet.has(svcName)) {
      serviceObjectSet.add(svcName);
      serviceObjects.push({
        name: svcName,
        protocol,
        port: String(portSpec),
        source_port: '',
      });
    }
    serviceNames.push(svcName);
  }

  return serviceNames;
}

/**
 * Resolve a CIDR to an address object, creating it if needed.
 *
 * @param {string} cidr
 * @param {string} zoneName
 * @param {Object[]} addressObjects
 * @param {Set} addressObjectSet
 * @returns {string}
 */
function resolveAddress(cidr, zoneName, addressObjects, addressObjectSet) {
  if (!cidr || cidr === '0.0.0.0/0' || cidr === '::/0') return 'any';

  const addrName = `addr-${cidr.replace(/[/:]/g, '_')}`;
  if (!addressObjectSet.has(addrName)) {
    addressObjectSet.add(addrName);
    addressObjects.push({
      name: addrName,
      type: 'ip-netmask',
      value: cidr,
      zone: zoneName,
    });
  }
  return addrName;
}

// ---------------------------------------------------------------------------
// Main Parser Entry Point
// ---------------------------------------------------------------------------

/**
 * Parses GCP VPC Firewall Rules JSON into the intermediate config schema.
 *
 * @param {string} configText - Raw JSON from `gcloud compute firewall-rules list --format=json`
 * @returns {{ intermediateConfig: Object, warnings: Object[], parseStats: Object }}
 */
export function parseGcpFirewallRules(configText) {
  const warnings = [];

  let parsed;
  try {
    parsed = safeParse(configText);
  } catch (err) {
    warnings.push(createWarning('error', 'input', `Failed to parse JSON: ${err.message}`, 'Ensure input is valid JSON from "gcloud compute firewall-rules list --format=json"'));
    return buildEmptyResult(warnings);
  }

  // Accept a bare array or { items: [...] } wrapper
  let rules = [];
  if (Array.isArray(parsed)) {
    rules = parsed;
  } else if (parsed && Array.isArray(parsed.items)) {
    rules = parsed.items;
  } else if (parsed && typeof parsed === 'object' && parsed.name) {
    // Single rule object
    rules = [parsed];
  } else {
    warnings.push(createWarning('error', 'input', 'Input is not a JSON array of firewall rules', 'Input should be a JSON array from "gcloud compute firewall-rules list --format=json"'));
    return buildEmptyResult(warnings);
  }

  if (rules.length === 0) {
    warnings.push(createWarning('warning', 'input', 'Firewall rules array is empty', 'Verify the gcloud output contains firewall rules'));
  }

  // Sort by priority (lower = higher precedence, default 1000)
  rules.sort((a, b) => {
    const prioA = Number(a.priority) || 1000;
    const prioB = Number(b.priority) || 1000;
    return prioA - prioB;
  });

  const zones = [];
  const zoneSet = new Set();
  const addressObjects = [];
  const addressObjectSet = new Set();
  const addressGroups = [];
  const addressGroupSet = new Set();
  const serviceObjects = [];
  const serviceObjectSet = new Set();
  const securityPolicies = [];
  // Networks with an enabled explicit egress deny rule (drives the inter-network warning).
  const egressDenyNetworks = new Set();

  for (let idx = 0; idx < rules.length; idx++) {
    const rule = rules[idx];
    if (!rule || typeof rule !== 'object') continue;

    const ruleName = rule.name || `gcp-rule-${idx}`;
    const networkName = extractNetworkName(rule.network);
    const zoneName = `net-${networkName}`;
    const direction = (rule.direction || 'INGRESS').toUpperCase();
    const priority = Number(rule.priority) || 1000;
    const isDisabled = rule.disabled === true;
    const description = rule.description || '';

    // --- Zone from network ---
    if (!zoneSet.has(zoneName)) {
      zoneSet.add(zoneName);
      zones.push({ name: zoneName, interfaces: [] });
    }

    // --- Address groups from targetTags ---
    const targetTags = Array.isArray(rule.targetTags) ? rule.targetTags : [];
    for (const tag of targetTags) {
      const groupName = `tag-${tag}`;
      if (!addressGroupSet.has(groupName)) {
        addressGroupSet.add(groupName);
        addressGroups.push({
          name: groupName,
          members: [],
          zone: zoneName,
        });
        warnings.push(createWarning('info', `tag/${tag}`,
          `GCP target tag "${tag}" mapped to address-group — populate with actual instance IPs after conversion`,
          'Use "gcloud compute instances list --filter=tags.items=TAG" to find tagged instances'));
      }
    }

    // Address groups from sourceTags
    const sourceTags = Array.isArray(rule.sourceTags) ? rule.sourceTags : [];
    for (const tag of sourceTags) {
      const groupName = `tag-${tag}`;
      if (!addressGroupSet.has(groupName)) {
        addressGroupSet.add(groupName);
        addressGroups.push({
          name: groupName,
          members: [],
          zone: zoneName,
        });
        warnings.push(createWarning('info', `tag/${tag}`,
          `GCP source tag "${tag}" mapped to address-group — populate with actual instance IPs after conversion`,
          'Use "gcloud compute instances list --filter=tags.items=TAG" to find tagged instances'));
      }
    }

    // Service account based groups
    const targetServiceAccounts = Array.isArray(rule.targetServiceAccounts) ? rule.targetServiceAccounts : [];
    for (const sa of targetServiceAccounts) {
      const saShort = sa.split('@')[0] || sa;
      const groupName = `sa-${saShort}`;
      if (!addressGroupSet.has(groupName)) {
        addressGroupSet.add(groupName);
        addressGroups.push({
          name: groupName,
          members: [],
          zone: zoneName,
        });
        warnings.push(createWarning('info', `service-account/${saShort}`,
          `GCP service account "${sa}" mapped to address-group placeholder`,
          'Populate with actual instance IPs using the service account'));
      }
    }

    // --- Resolve source/destination ranges ---
    const isIngress = direction === 'INGRESS';
    const sourceRanges = Array.isArray(rule.sourceRanges) ? rule.sourceRanges : [];
    const destinationRanges = Array.isArray(rule.destinationRanges) ? rule.destinationRanges : [];

    const srcAddresses = [];
    const dstAddresses = [];

    if (isIngress) {
      // Ingress: sourceRanges are sources, destination is the network/tags
      if (sourceRanges.length > 0) {
        for (const cidr of sourceRanges) {
          srcAddresses.push(resolveAddress(cidr, zoneName, addressObjects, addressObjectSet));
        }
      } else if (sourceTags.length > 0) {
        for (const tag of sourceTags) {
          srcAddresses.push(`tag-${tag}`);
        }
      } else {
        srcAddresses.push('any');
      }

      if (targetTags.length > 0) {
        for (const tag of targetTags) {
          dstAddresses.push(`tag-${tag}`);
        }
      } else if (targetServiceAccounts.length > 0) {
        for (const sa of targetServiceAccounts) {
          const saShort = sa.split('@')[0] || sa;
          dstAddresses.push(`sa-${saShort}`);
        }
      } else {
        dstAddresses.push('any');
      }
    } else {
      // Egress: destinationRanges are destinations, source is the network/tags
      if (targetTags.length > 0) {
        for (const tag of targetTags) {
          srcAddresses.push(`tag-${tag}`);
        }
      } else if (targetServiceAccounts.length > 0) {
        for (const sa of targetServiceAccounts) {
          const saShort = sa.split('@')[0] || sa;
          srcAddresses.push(`sa-${saShort}`);
        }
      } else {
        srcAddresses.push('any');
      }

      if (destinationRanges.length > 0) {
        for (const cidr of destinationRanges) {
          dstAddresses.push(resolveAddress(cidr, zoneName, addressObjects, addressObjectSet));
        }
      } else {
        dstAddresses.push('any');
      }
    }

    // --- Process allowed and denied entries ---
    const allowedEntries = Array.isArray(rule.allowed) ? rule.allowed : [];
    const deniedEntries = Array.isArray(rule.denied) ? rule.denied : [];

    // Build policies for allowed entries
    for (let aIdx = 0; aIdx < allowedEntries.length; aIdx++) {
      const entry = allowedEntries[aIdx];
      const serviceNames = buildServicesFromEntry(entry, serviceObjects, serviceObjectSet);
      const policyName = allowedEntries.length > 1
        ? `${ruleName}-allow-${aIdx}`
        : ruleName;

      securityPolicies.push({
        name: policyName,
        src_zones: isIngress ? ['any'] : [zoneName],
        dst_zones: isIngress ? [zoneName] : ['any'],
        src_addresses: srcAddresses.length > 0 ? srcAddresses : ['any'],
        dst_addresses: dstAddresses.length > 0 ? dstAddresses : ['any'],
        services: serviceNames,
        applications: ['any'],
        action: 'allow',
        _gcp_order: { phase: isIngress ? 1 : 2, priority, deny: false },
        logging: rule.logConfig ? (rule.logConfig.enable === true) : false,
        disabled: isDisabled,
        description: description || `GCP firewall rule (priority ${priority}, ${direction})`,
        tags: [`gcp-network:${networkName}`, `priority:${priority}`, ...targetTags.map(t => `target-tag:${t}`)],
        source_users: ['any'],
        _rule_index: securityPolicies.length,
      });
    }

    if (!isIngress && !isDisabled && deniedEntries.length > 0) egressDenyNetworks.add(networkName);

    // Build policies for denied entries
    for (let dIdx = 0; dIdx < deniedEntries.length; dIdx++) {
      const entry = deniedEntries[dIdx];
      const serviceNames = buildServicesFromEntry(entry, serviceObjects, serviceObjectSet);
      const policyName = deniedEntries.length > 1
        ? `${ruleName}-deny-${dIdx}`
        : ruleName;

      securityPolicies.push({
        name: policyName,
        src_zones: isIngress ? ['any'] : [zoneName],
        dst_zones: isIngress ? [zoneName] : ['any'],
        src_addresses: srcAddresses.length > 0 ? srcAddresses : ['any'],
        dst_addresses: dstAddresses.length > 0 ? dstAddresses : ['any'],
        services: serviceNames,
        applications: ['any'],
        action: 'deny',
        _gcp_order: { phase: isIngress ? 1 : 2, priority, deny: true },
        logging: rule.logConfig ? (rule.logConfig.enable === true) : false,
        disabled: isDisabled,
        description: description || `GCP firewall rule (priority ${priority}, ${direction})`,
        tags: [`gcp-network:${networkName}`, `priority:${priority}`, ...targetTags.map(t => `target-tag:${t}`)],
        source_users: ['any'],
        _rule_index: securityPolicies.length,
      });
    }

    // Warn if rule has neither allowed nor denied
    if (allowedEntries.length === 0 && deniedEntries.length === 0) {
      warnings.push(createWarning('warning', `rule/${ruleName}`,
        'Rule has no "allowed" or "denied" entries — skipped',
        'Verify the rule definition in GCP'));
    }
  }

  // GCP implied rules (priority 65535, below every explicit rule): allow egress, deny ingress.
  // Final order is set by the comparator below.
  const impliedBase = zoneName => ({
    src_addresses: ['any'],
    dst_addresses: ['any'],
    services: ['any'],
    applications: ['any'],
    logging: false,
    disabled: false,
    tags: [`gcp-network:${zoneName.slice('net-'.length)}`, 'priority:65535'],
    source_users: ['any'],
    _implicit: true,
  });
  for (const zoneName of zoneSet) {
    securityPolicies.push({
      ...impliedBase(zoneName),
      name: `Implicit: GCP deny ingress (${zoneName.slice('net-'.length)})`,
      src_zones: ['any'],
      dst_zones: [zoneName],
      action: 'deny',
      _gcp_order: { phase: 1, priority: 65535, deny: true },
      description: 'GCP implied deny ingress rule (priority 65535)',
      _rule_index: securityPolicies.length,
    });
  }
  for (const zoneName of zoneSet) {
    securityPolicies.push({
      ...impliedBase(zoneName),
      name: `Implicit: GCP allow egress (${zoneName.slice('net-'.length)})`,
      src_zones: [zoneName],
      dst_zones: ['any'],
      action: 'allow',
      _gcp_order: { phase: 2, priority: 65535, deny: false },
      description: 'GCP implied allow egress rule (priority 65535)',
      _rule_index: securityPolicies.length,
    });
  }

  // GCP needs both the source's egress and the destination's ingress check to pass, but the SRX
  // stops at the first match. Phases, each sorted by priority then deny before allow (GCP's
  // same-priority tie-break; the sort is stable, so explicit precedes implied on ties):
  //   1: ingress policies, ending in a catch-all deny per imported zone, so every flow into an
  //      imported zone is decided here;
  //   2: egress policies, reached only by flows to non-imported destinations (exact order).
  securityPolicies.sort((a, b) => (
    a._gcp_order.phase - b._gcp_order.phase
    || a._gcp_order.priority - b._gcp_order.priority
    || Number(b._gcp_order.deny) - Number(a._gcp_order.deny)
  ));
  securityPolicies.forEach((policy, index) => {
    policy._rule_index = index;
    delete policy._gcp_order;
  });

  if (egressDenyNetworks.size > 0) {
    warnings.push(createWarning('warning', 'networks',
      `Egress deny rules in network(s) ${[...egressDenyNetworks].join(', ')} are enforced only for traffic leaving to non-imported destinations; for traffic between or within the imported networks the destination network's ingress rules decide (GCP also applies the source's egress denies)`,
      'Add explicit inter-network deny policies if that traffic crosses the SRX'));
  }

  const intermediateConfig = {
    zones,
    address_objects: addressObjects,
    address_groups: addressGroups,
    service_objects: serviceObjects,
    service_groups: [],
    security_policies: securityPolicies,
    nat_rules: [],
    applications: [],
    application_groups: [],
    schedules: [],
    security_profile_objects: [],
    security_profile_definitions: [],
    external_lists: [],
    vpn_tunnels: [],
    ha_config: null,
    screen_config: [],
    syslog_config: [],
    snmp_config: [],
    aaa_config: [],
    dhcp_config: [],
    qos_config: [],
    flow_monitoring_config: {
      collectors: [],
      sampling: { input_rate: 1000, run_length: 0, interfaces: [] },
      templates: [],
    },
    interfaces: [],
    lag_interfaces: [],
    routing_contexts: [],
    static_routes: [],
    bgp_config: [],
    ospf_config: [],
    ospf3_config: [],
    evpn_config: [],
    vxlan_config: [],
    pbf_rules: [],
    decryption_rules: [],
    target_context: null,
    transparent_mode: false,
    bridge_domains: [],
    l2_interfaces: [],
    vwire_pairs: [],
    metadata: {
      source_vendor: 'gcp_fw',
      source_version: '',
      export_date: new Date().toISOString(),
      rule_count: securityPolicies.length,
      nat_rule_count: 0,
      object_count: addressObjects.length + serviceObjects.length,
      zone_count: zones.length,
      interface_count: 0,
      network_count: zoneSet.size,
      tag_group_count: addressGroups.length,
    },
    warnings,
  };

  return {
    intermediateConfig,
    warnings,
    parseStats: intermediateConfig.metadata,
  };
}

// ---------------------------------------------------------------------------
// Empty result builder
// ---------------------------------------------------------------------------

/**
 * @param {Object[]} warnings
 * @returns {{ intermediateConfig: Object, warnings: Object[], parseStats: Object }}
 */
function buildEmptyResult(warnings) {
  const intermediateConfig = {
    zones: [],
    address_objects: [],
    address_groups: [],
    service_objects: [],
    service_groups: [],
    security_policies: [],
    nat_rules: [],
    applications: [],
    application_groups: [],
    schedules: [],
    security_profile_objects: [],
    security_profile_definitions: [],
    external_lists: [],
    vpn_tunnels: [],
    ha_config: null,
    screen_config: [],
    syslog_config: [],
    snmp_config: [],
    aaa_config: [],
    dhcp_config: [],
    qos_config: [],
    flow_monitoring_config: {
      collectors: [],
      sampling: { input_rate: 1000, run_length: 0, interfaces: [] },
      templates: [],
    },
    interfaces: [],
    lag_interfaces: [],
    routing_contexts: [],
    static_routes: [],
    bgp_config: [],
    ospf_config: [],
    ospf3_config: [],
    evpn_config: [],
    vxlan_config: [],
    pbf_rules: [],
    decryption_rules: [],
    target_context: null,
    transparent_mode: false,
    bridge_domains: [],
    l2_interfaces: [],
    vwire_pairs: [],
    metadata: {
      source_vendor: 'gcp_fw',
      source_version: '',
      export_date: new Date().toISOString(),
      rule_count: 0,
      nat_rule_count: 0,
      object_count: 0,
      zone_count: 0,
      interface_count: 0,
      network_count: 0,
      tag_group_count: 0,
    },
    warnings,
  };
  return { intermediateConfig, warnings, parseStats: intermediateConfig.metadata };
}
