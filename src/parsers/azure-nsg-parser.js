/**
 * Azure Network Security Group (NSG) Parser
 * ============================================
 *
 * Parses Azure NSG JSON (from `az network nsg show` or ARM templates)
 * into the vendor-neutral intermediate JSON schema.
 *
 * Handles:
 *   - securityRules array (direct or nested in ARM properties)
 *   - defaultSecurityRules (built-in Azure rules)
 *   - Priority-based ordering
 *   - Inbound/Outbound direction mapping
 *   - Allow/Deny action mapping
 *   - Wildcard ports ("*"), port ranges, comma-separated ports
 *   - Service tags (VirtualNetwork, AzureLoadBalancer, Internet, etc.)
 *
 * Cloud-to-firewall concept mapping:
 *   NSG name            → zone
 *   securityRule         → security policy (ordered by priority)
 *   sourceAddressPrefix  → address object
 *   destinationPortRange → service object
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
 * Normalize Azure protocol value to lowercase standard name.
 * @param {string} proto
 * @returns {string}
 */
function normalizeProtocol(proto) {
  if (!proto || proto === '*') return 'any';
  const lower = proto.toLowerCase();
  const map = { tcp: 'tcp', udp: 'udp', icmp: 'icmp', ah: 'ah', esp: 'esp' };
  return map[lower] || lower;
}

/**
 * Expand Azure port notation into an array of port strings.
 * Handles: "*", "80", "80-443", "80,443,8080-8090"
 * Also handles sourcePortRanges / destinationPortRanges arrays.
 *
 * @param {string|string[]} portRange - Single port spec or array
 * @param {string|string[]} portRanges - Additional port ranges array
 * @returns {string[]}
 */
function expandPorts(portRange, portRanges) {
  const results = [];

  const addPort = (val) => {
    if (!val || val === '*') {
      results.push('any');
      return;
    }
    // Could be comma-separated
    const parts = String(val).split(',').map(p => p.trim()).filter(Boolean);
    for (const part of parts) {
      results.push(part);
    }
  };

  if (portRange !== undefined && portRange !== null) {
    addPort(portRange);
  }

  if (Array.isArray(portRanges)) {
    for (const pr of portRanges) {
      addPort(pr);
    }
  }

  return results.length > 0 ? results : ['any'];
}

const IPV4_PATTERN = /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/;

/**
 * Resolve an Azure address prefix to an address object name, creating the
 * object if it does not already exist. "*" and "Internet" mean any. Service
 * tags (VirtualNetwork, Storage, ...) cannot be resolved from an NSG export, so
 * they are recorded in unresolvedTags and the caller must not enable the rule.
 *
 * @param {string} prefix - e.g. "10.0.0.0/24", "2001:db8::1", "*", "VirtualNetwork"
 * @param {string} zoneName
 * @param {Object[]} addressObjects
 * @param {Set} addressObjectSet
 * @param {string[]} unresolvedTags - collects unresolvable service tags
 * @returns {string} - address object name or "any"
 */
function resolveAddress(prefix, zoneName, addressObjects, addressObjectSet, unresolvedTags) {
  if (!prefix || prefix === '*' || prefix === 'Internet') return 'any';

  const isIpv6 = prefix.includes(':');
  if (!isIpv6 && !IPV4_PATTERN.test(prefix)) {  // njsscan-ignore: regex_dos
    unresolvedTags.push(prefix);
    return 'any';
  }

  const addrName = `addr-${prefix.replace(/[/:]/g, '_')}`;
  if (!addressObjectSet.has(addrName)) {
    addressObjectSet.add(addrName);
    addressObjects.push({
      name: addrName,
      type: 'ip-netmask',
      value: prefix.includes('/') ? prefix : `${prefix}/${isIpv6 ? 128 : 32}`,
      zone: zoneName,
    });
  }
  return addrName;
}

/**
 * Resolve multiple address prefixes (prefix + prefixes array).
 * @param {string} prefix
 * @param {string[]} prefixes
 * @param {string} zoneName
 * @param {Object[]} addressObjects
 * @param {Set} addressObjectSet
 * @param {string[]} unresolvedTags
 * @returns {string[]}
 */
function resolveAddresses(prefix, prefixes, zoneName, addressObjects, addressObjectSet, unresolvedTags) {
  const results = [];

  if (prefix) {
    results.push(resolveAddress(prefix, zoneName, addressObjects, addressObjectSet, unresolvedTags));
  }

  if (Array.isArray(prefixes)) {
    for (const p of prefixes) {
      results.push(resolveAddress(p, zoneName, addressObjects, addressObjectSet, unresolvedTags));
    }
  }

  return results.length > 0 ? results : ['any'];
}

const FULL_PORT_RANGE = '1-65535';

/**
 * Build (and register) the service objects for one rule. A protocol with "*" ports
 * covers every port of that protocol only; protocol "*" with a port covers tcp and udp.
 *
 * @param {string} protocol - normalized protocol
 * @param {string[]} dstPorts - expanded destination ports ("any" for wildcard)
 * @param {string[]} srcPorts - expanded source ports ("any" for wildcard)
 * @param {Object[]} serviceObjects
 * @param {Set} serviceObjectSet
 * @param {string[]} issues - collects reasons the rule cannot be translated
 * @returns {string[]} service names
 */
function buildServices(protocol, dstPorts, srcPorts, serviceObjects, serviceObjectSet, issues) {
  const sourcePort = srcPorts[0] === 'any' ? '' : srcPorts[0];
  if (srcPorts.length > 1) issues.push('multiple source port ranges are not supported');

  const anyDestination = dstPorts.every(portSpec => portSpec === 'any');
  if (protocol === 'any' && anyDestination && !sourcePort) return ['any'];

  const protocols = protocol === 'any' ? ['tcp', 'udp'] : [protocol];
  const names = [];
  for (const proto of protocols) {
    if (!['tcp', 'udp', 'icmp'].includes(proto)) {
      issues.push(`protocol "${proto}" has no service mapping`);
      continue;
    }
    const portSpecs = proto === 'icmp' ? [''] : dstPorts.map(portSpec => (portSpec === 'any' ? FULL_PORT_RANGE : portSpec));
    for (const port of portSpecs) {
      const svcName = proto === 'icmp' ? 'icmp' : `${proto}/${sourcePort ? `${sourcePort}:` : ''}${port}`;
      if (!serviceObjectSet.has(svcName)) {
        serviceObjectSet.add(svcName);
        serviceObjects.push({ name: svcName, protocol: proto, port, source_port: proto === 'icmp' ? '' : sourcePort });
      }
      names.push(svcName);
    }
  }
  return [...new Set(names)];
}

// ---------------------------------------------------------------------------
// Main Parser Entry Point
// ---------------------------------------------------------------------------

/**
 * Parses Azure NSG JSON into the intermediate config schema.
 *
 * @param {string} configText - Raw JSON from `az network nsg show` or ARM template
 * @returns {{ intermediateConfig: Object, warnings: Object[], parseStats: Object }}
 */
export function parseAzureNsg(configText) {
  const warnings = [];

  let parsed;
  try {
    parsed = safeParse(configText);
  } catch (err) {
    warnings.push(createWarning('error', 'input', `Failed to parse JSON: ${err.message}`, 'Ensure input is valid JSON from "az network nsg show" or ARM template'));
    return buildEmptyResult(warnings);
  }

  // Locate the security rules — multiple possible structures
  const nsgs = [];
  if (Array.isArray(parsed)) {
    for (const nsg of parsed) {
      if (nsg && typeof nsg === 'object') nsgs.push({ name: nsg.name || 'azure-nsg', ...extractRulesFromNsg(nsg) });
    }
  } else if (parsed && typeof parsed === 'object') {
    // Direct NSG object or ARM template
    nsgs.push({ name: parsed.name || 'azure-nsg', ...extractRulesFromNsg(parsed) });
  }

  if (nsgs.every(nsg => nsg.securityRules.length === 0 && nsg.defaultRules.length === 0)) {
    warnings.push(createWarning('warning', 'input', 'No security rules found in input', 'Ensure input contains "securityRules" or is a valid ARM template with NSG resources'));
  }

  // Merge and sort all rules by priority, each tagged with its NSG and zone
  const prefixNames = nsgs.length > 1;
  const allRules = nsgs.flatMap(nsg => [...nsg.securityRules, ...nsg.defaultRules]
    .map(rule => ({ rule, nsgName: nsg.name, zoneName: `nsg-${nsg.name}` })));
  allRules.sort((a, b) => getPriority(a.rule) - getPriority(b.rule));

  const nsgName = nsgs.length > 0 ? nsgs[nsgs.length - 1].name : 'azure-nsg';
  const zones = [...new Set(nsgs.map(nsg => `nsg-${nsg.name}`))].map(name => ({ name, interfaces: [] }));

  const addressObjects = [];
  const addressObjectSet = new Set();
  const serviceObjects = [];
  const serviceObjectSet = new Set();
  const securityPolicies = [];

  for (let idx = 0; idx < allRules.length; idx++) {
    const { rule, nsgName: ruleNsgName, zoneName } = allRules[idx];
    const props = rule.properties || rule;
    const baseName = rule.name || props.name || `rule-${idx}`;
    const ruleName = prefixNames ? `${ruleNsgName}-${baseName}` : baseName;
    const priority = getPriority(rule);
    const direction = (props.direction || 'Inbound').toLowerCase();
    const access = (props.access || 'Allow').toLowerCase();
    const protocol = normalizeProtocol(props.protocol);

    const unresolvedTags = [];
    const srcAddresses = resolveAddresses(
      props.sourceAddressPrefix,
      props.sourceAddressPrefixes,
      zoneName, addressObjects, addressObjectSet, unresolvedTags
    );

    // Resolve destination addresses
    const dstAddresses = resolveAddresses(
      props.destinationAddressPrefix,
      props.destinationAddressPrefixes,
      zoneName, addressObjects, addressObjectSet, unresolvedTags
    );

    const issues = unresolvedTags.map(tag => `service tag "${tag}" cannot be resolved from an NSG export`);
    const uniqueServices = buildServices(
      protocol,
      expandPorts(props.destinationPortRange, props.destinationPortRanges),
      expandPorts(props.sourcePortRange, props.sourcePortRanges),
      serviceObjects, serviceObjectSet, issues
    );

    // Fail closed: a rule we cannot translate faithfully is disabled, never widened
    const disabled = issues.length > 0;
    if (disabled) {
      warnings.push(createWarning('warning', `policy/${ruleName}`,
        `Rule "${ruleName}" disabled: ${issues.join('; ')}`,
        'Replace the service tag with its CIDR ranges (e.g. the VNet address space), then enable the rule'));
    }

    const isInbound = direction === 'inbound';
    const action = access === 'allow' ? 'allow' : 'deny';

    securityPolicies.push({
      name: ruleName,
      src_zones: isInbound ? ['any'] : [zoneName],
      dst_zones: isInbound ? [zoneName] : ['any'],
      src_addresses: srcAddresses,
      dst_addresses: dstAddresses,
      services: uniqueServices.length > 0 ? uniqueServices : ['any'], // empty only when disabled
      applications: ['any'],
      action,
      logging: true,
      disabled,
      description: props.description || `Azure NSG rule (priority ${priority}, ${direction})`,
      tags: [`azure-nsg:${ruleNsgName}`, `priority:${priority}`],
      source_users: ['any'],
      _rule_index: idx,
    });
  }

  const intermediateConfig = {
    zones,
    address_objects: addressObjects,
    address_groups: [],
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
      source_vendor: 'azure_nsg',
      source_version: '',
      export_date: new Date().toISOString(),
      rule_count: securityPolicies.length,
      nat_rule_count: 0,
      object_count: addressObjects.length + serviceObjects.length,
      zone_count: zones.length,
      interface_count: 0,
      nsg_name: nsgName,
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
// Rule extraction helpers
// ---------------------------------------------------------------------------

/**
 * Extract security rules from an NSG object, handling multiple JSON shapes:
 * - Direct: { securityRules: [...], defaultSecurityRules: [...] }
 * - ARM nested: { properties: { securityRules: [...] } }
 * - ARM template resources array
 *
 * @param {Object} nsg
 * @returns {{ securityRules: Object[], defaultRules: Object[] }}
 */
function extractRulesFromNsg(nsg) {
  let securityRules = [];
  let defaultRules = [];

  // Direct format from `az network nsg show`
  if (Array.isArray(nsg.securityRules)) {
    securityRules = nsg.securityRules;
  }
  if (Array.isArray(nsg.defaultSecurityRules)) {
    defaultRules = nsg.defaultSecurityRules;
  }

  // ARM template nested in properties
  if (nsg.properties) {
    if (Array.isArray(nsg.properties.securityRules)) {
      securityRules = nsg.properties.securityRules;
    }
    if (Array.isArray(nsg.properties.defaultSecurityRules)) {
      defaultRules = nsg.properties.defaultSecurityRules;
    }
  }

  // ARM template with resources array (e.g. full ARM deployment)
  if (Array.isArray(nsg.resources)) {
    for (const resource of nsg.resources) {
      if (resource.type === 'Microsoft.Network/networkSecurityGroups') {
        const nested = extractRulesFromNsg(resource);
        securityRules.push(...nested.securityRules);
        defaultRules.push(...nested.defaultRules);
      }
      // Inline security rule resources
      if (resource.type === 'Microsoft.Network/networkSecurityGroups/securityRules') {
        securityRules.push(resource);
      }
    }
  }

  return { securityRules, defaultRules };
}

/**
 * Get the priority value from a rule, handling nested properties.
 * @param {Object} rule
 * @returns {number}
 */
function getPriority(rule) {
  const props = rule.properties || rule;
  const raw = props.priority;
  const val = Number(raw);
  return Number.isFinite(val) ? val : 65000;
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
      source_vendor: 'azure_nsg',
      source_version: '',
      export_date: new Date().toISOString(),
      rule_count: 0,
      nat_rule_count: 0,
      object_count: 0,
      zone_count: 0,
      interface_count: 0,
      nsg_name: '',
    },
    warnings,
  };
  return { intermediateConfig, warnings, parseStats: intermediateConfig.metadata };
}
