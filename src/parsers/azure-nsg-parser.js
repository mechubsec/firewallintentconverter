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

/**
 * Azure service tags that map to well-known address concepts.
 */
const SERVICE_TAG_MAP = {
  '*': 'any',
  'Internet': 'any',
  'VirtualNetwork': 'VirtualNetwork',
  'AzureLoadBalancer': 'AzureLoadBalancer',
};

/**
 * Resolve an Azure address prefix to an address object name, creating the
 * object if it does not already exist.
 *
 * @param {string} prefix - e.g. "10.0.0.0/24", "*", "VirtualNetwork"
 * @param {string} zoneName
 * @param {Object[]} addressObjects
 * @param {Set} addressObjectSet
 * @param {Object[]} warnings
 * @returns {string} - address object name or "any"
 */
function resolveAddress(prefix, zoneName, addressObjects, addressObjectSet, warnings) {
  if (!prefix || prefix === '*') return 'any';

  // Check service tags
  const tagName = SERVICE_TAG_MAP[prefix];
  if (tagName === 'any') return 'any';

  if (tagName) {
    const objName = `azure-tag-${prefix}`;
    if (!addressObjectSet.has(objName)) {
      addressObjectSet.add(objName);
      addressObjects.push({
        name: objName,
        type: 'ip-netmask',
        value: '0.0.0.0/0',
        zone: zoneName,
      });
      warnings.push(createWarning('info', `address/${objName}`,
        `Azure service tag "${prefix}" mapped as placeholder 0.0.0.0/0`,
        'Replace with actual CIDR ranges for the Azure service tag'));
    }
    return objName;
  }

  // CIDR or IP address
  const addrName = `addr-${prefix.replace(/[/:]/g, '_')}`;
  if (!addressObjectSet.has(addrName)) {
    addressObjectSet.add(addrName);
    const isCidr = prefix.includes('/') || prefix.includes(':');
    addressObjects.push({
      name: addrName,
      type: isCidr ? 'ip-netmask' : 'ip-netmask',
      value: prefix.includes('/') ? prefix : `${prefix}/32`,
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
 * @param {Object[]} warnings
 * @returns {string[]}
 */
function resolveAddresses(prefix, prefixes, zoneName, addressObjects, addressObjectSet, warnings) {
  const results = [];

  if (prefix) {
    results.push(resolveAddress(prefix, zoneName, addressObjects, addressObjectSet, warnings));
  }

  if (Array.isArray(prefixes)) {
    for (const p of prefixes) {
      results.push(resolveAddress(p, zoneName, addressObjects, addressObjectSet, warnings));
    }
  }

  return results.length > 0 ? results : ['any'];
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
  let securityRules = [];
  let defaultRules = [];
  let nsgName = 'azure-nsg';

  if (Array.isArray(parsed)) {
    // Array of NSGs — take all rules from all NSGs
    for (const nsg of parsed) {
      const rules = extractRulesFromNsg(nsg);
      securityRules.push(...rules.securityRules);
      defaultRules.push(...rules.defaultRules);
      if (nsg.name) nsgName = nsg.name;
    }
  } else if (parsed && typeof parsed === 'object') {
    // Direct NSG object or ARM template
    const rules = extractRulesFromNsg(parsed);
    securityRules = rules.securityRules;
    defaultRules = rules.defaultRules;
    if (parsed.name) nsgName = parsed.name;
  }

  if (securityRules.length === 0 && defaultRules.length === 0) {
    warnings.push(createWarning('warning', 'input', 'No security rules found in input', 'Ensure input contains "securityRules" or is a valid ARM template with NSG resources'));
  }

  // Merge and sort all rules by priority
  const allRules = [...securityRules, ...defaultRules];
  allRules.sort((a, b) => {
    const prioA = getPriority(a);
    const prioB = getPriority(b);
    return prioA - prioB;
  });

  const zoneName = `nsg-${nsgName}`;
  const zones = [{ name: zoneName, interfaces: [] }];

  const addressObjects = [];
  const addressObjectSet = new Set();
  const serviceObjects = [];
  const serviceObjectSet = new Set();
  const securityPolicies = [];

  for (let idx = 0; idx < allRules.length; idx++) {
    const rule = allRules[idx];
    const props = rule.properties || rule;
    const ruleName = rule.name || props.name || `rule-${idx}`;
    const priority = getPriority(rule);
    const direction = (props.direction || 'Inbound').toLowerCase();
    const access = (props.access || 'Allow').toLowerCase();
    const protocol = normalizeProtocol(props.protocol);

    // Resolve source addresses
    const srcAddresses = resolveAddresses(
      props.sourceAddressPrefix,
      props.sourceAddressPrefixes,
      zoneName, addressObjects, addressObjectSet, warnings
    );

    // Resolve destination addresses
    const dstAddresses = resolveAddresses(
      props.destinationAddressPrefix,
      props.destinationAddressPrefixes,
      zoneName, addressObjects, addressObjectSet, warnings
    );

    // Build service objects from destination ports
    const dstPorts = expandPorts(props.destinationPortRange, props.destinationPortRanges);
    const serviceNames = [];

    for (const portSpec of dstPorts) {
      if (portSpec === 'any' || protocol === 'any') {
        serviceNames.push('any');
        continue;
      }
      const svcName = `${protocol}/${portSpec}`;
      if (!serviceObjectSet.has(svcName)) {
        serviceObjectSet.add(svcName);
        serviceObjects.push({
          name: svcName,
          protocol,
          port: portSpec,
          source_port: '',
        });
      }
      serviceNames.push(svcName);
    }

    const uniqueServices = [...new Set(serviceNames)];

    const isInbound = direction === 'inbound';
    const action = access === 'allow' ? 'allow' : 'deny';

    securityPolicies.push({
      name: ruleName,
      src_zones: isInbound ? ['any'] : [zoneName],
      dst_zones: isInbound ? [zoneName] : ['any'],
      src_addresses: isInbound ? srcAddresses : ['any'],
      dst_addresses: isInbound ? dstAddresses : dstAddresses,
      services: uniqueServices.length > 0 ? uniqueServices : ['any'],
      applications: ['any'],
      action,
      logging: true,
      disabled: false,
      description: props.description || `Azure NSG rule (priority ${priority}, ${direction})`,
      tags: [`azure-nsg:${nsgName}`, `priority:${priority}`],
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
