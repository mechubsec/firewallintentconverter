/**
 * AWS Security Group Parser
 * ==========================
 *
 * Parses AWS Security Group JSON (from `aws ec2 describe-security-groups`)
 * into the vendor-neutral intermediate JSON schema.
 *
 * Handles:
 *   - SecurityGroups with GroupId, GroupName, VpcId
 *   - IpPermissions (inbound) and IpPermissionsEgress (outbound)
 *   - IpRanges, Ipv6Ranges, PrefixListIds, UserIdGroupPairs
 *   - Protocol / port mapping to service objects
 *
 * Cloud-to-firewall concept mapping:
 *   VpcId        → zone
 *   GroupName    → address-group
 *   IpPermission → security policy rule
 */

import { createWarning } from './parser-utils.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Safely parse JSON with prototype-pollution guard.
 * @param {string} text - Raw JSON string
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
 * Build a human-readable service name from protocol/port info.
 * @param {string} protocol
 * @param {number|undefined} fromPort
 * @param {number|undefined} toPort
 * @returns {string}
 */
function buildServiceName(protocol, fromPort, toPort) {
  if (protocol === '-1' || protocol === 'all') return 'any';
  const proto = protocol.toLowerCase();
  if (fromPort === undefined || fromPort === null) return proto;
  if (fromPort === toPort) return `${proto}/${fromPort}`;
  return `${proto}/${fromPort}-${toPort}`;
}

/**
 * Map AWS protocol number string to name.
 * @param {string} proto
 * @returns {string}
 */
function normalizeProtocol(proto) {
  if (proto === '-1' || proto === 'all') return 'any';
  const numMap = { '6': 'tcp', '17': 'udp', '1': 'icmp', '58': 'icmpv6' };
  return numMap[proto] || proto.toLowerCase();
}

// ---------------------------------------------------------------------------
// Main Parser Entry Point
// ---------------------------------------------------------------------------

/**
 * Parses AWS Security Group JSON into the intermediate config schema.
 *
 * @param {string} configText - Raw JSON from `aws ec2 describe-security-groups`
 * @returns {{ intermediateConfig: Object, warnings: Object[], parseStats: Object }}
 */
export function parseAwsSecurityGroups(configText) {
  const warnings = [];

  let parsed;
  try {
    parsed = safeParse(configText);
  } catch (err) {
    warnings.push(createWarning('error', 'input', `Failed to parse JSON: ${err.message}`, 'Ensure input is valid JSON from "aws ec2 describe-security-groups"'));
    return buildEmptyResult(warnings);
  }

  // Accept either { SecurityGroups: [...] } or a bare array
  let securityGroups = [];
  if (Array.isArray(parsed)) {
    securityGroups = parsed;
  } else if (parsed && Array.isArray(parsed.SecurityGroups)) {
    securityGroups = parsed.SecurityGroups;
  } else {
    warnings.push(createWarning('error', 'input', 'No SecurityGroups array found in input', 'Input should contain a "SecurityGroups" key or be a JSON array of SG objects'));
    return buildEmptyResult(warnings);
  }

  if (securityGroups.length === 0) {
    warnings.push(createWarning('warning', 'input', 'SecurityGroups array is empty', 'Verify the AWS CLI output contains security groups'));
  }

  const zones = [];
  const zoneSet = new Set();
  const addressObjects = [];
  const addressObjectSet = new Set();
  const addressGroups = [];
  const serviceObjects = [];
  const serviceObjectSet = new Set();
  const securityPolicies = [];
  let ruleIndex = 0;

  for (const sg of securityGroups) {
    if (!sg || typeof sg !== 'object') continue;

    const groupId = sg.GroupId || 'unknown-sg';
    const groupName = sg.GroupName || groupId;
    const vpcId = sg.VpcId || 'default-vpc';
    const description = sg.Description || '';

    // --- Zone from VpcId ---
    const zoneName = `vpc-${vpcId}`;
    if (!zoneSet.has(zoneName)) {
      zoneSet.add(zoneName);
      zones.push({ name: zoneName, interfaces: [] });
    }

    // --- Address group from SG ---
    const sgMembers = [];

    // Collect CIDR-based address objects from inbound rules for SG membership
    const allPermissions = [
      ...(Array.isArray(sg.IpPermissions) ? sg.IpPermissions : []),
      ...(Array.isArray(sg.IpPermissionsEgress) ? sg.IpPermissionsEgress : []),
    ];

    // Build address group for this SG
    const groupMemberCidrs = new Set();
    for (const perm of allPermissions) {
      for (const range of (perm.IpRanges || [])) {
        if (range.CidrIp) groupMemberCidrs.add(range.CidrIp);
      }
      for (const range of (perm.Ipv6Ranges || [])) {
        if (range.CidrIpv6) groupMemberCidrs.add(range.CidrIpv6);
      }
    }

    for (const cidr of groupMemberCidrs) {
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
      sgMembers.push(addrName);
    }

    addressGroups.push({
      name: `sg-${groupName}`,
      members: sgMembers,
      zone: zoneName,
    });

    // --- Inbound rules → policies ---
    const inboundPerms = Array.isArray(sg.IpPermissions) ? sg.IpPermissions : [];
    for (const perm of inboundPerms) {
      const rules = buildRulesFromPermission(perm, {
        direction: 'inbound',
        sgName: groupName,
        groupId,
        zoneName,
        description,
        ruleIndex,
        warnings,
        addressObjects,
        addressObjectSet,
        serviceObjects,
        serviceObjectSet,
      });
      for (const rule of rules) {
        rule._rule_index = ruleIndex++;
        securityPolicies.push(rule);
      }
    }

    // --- Outbound rules → policies ---
    const outboundPerms = Array.isArray(sg.IpPermissionsEgress) ? sg.IpPermissionsEgress : [];
    for (const perm of outboundPerms) {
      const rules = buildRulesFromPermission(perm, {
        direction: 'outbound',
        sgName: groupName,
        groupId,
        zoneName,
        description,
        ruleIndex,
        warnings,
        addressObjects,
        addressObjectSet,
        serviceObjects,
        serviceObjectSet,
      });
      for (const rule of rules) {
        rule._rule_index = ruleIndex++;
        securityPolicies.push(rule);
      }
    }

    // Warn on referenced SG pairs (cross-SG references)
    for (const perm of allPermissions) {
      for (const pair of (perm.UserIdGroupPairs || [])) {
        const refId = pair.GroupId || 'unknown';
        warnings.push(createWarning('info', `sg/${groupId}`,
          `Rule references security group "${refId}" — mapped as address-group placeholder`,
          'Verify the referenced SG is included in the input'));
      }
    }
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
      source_vendor: 'aws_sg',
      source_version: '',
      export_date: new Date().toISOString(),
      rule_count: securityPolicies.length,
      nat_rule_count: 0,
      object_count: addressObjects.length + serviceObjects.length,
      zone_count: zones.length,
      interface_count: 0,
      security_group_count: securityGroups.length,
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
// Rule Builder
// ---------------------------------------------------------------------------

/**
 * Converts a single IpPermission entry into one or more security policy objects.
 *
 * @param {Object} perm - AWS IpPermission object
 * @param {Object} ctx  - Context with direction, sgName, zoneName, etc.
 * @returns {Object[]}  - Array of policy rule objects
 */
function buildRulesFromPermission(perm, ctx) {
  const {
    direction, sgName, groupId, zoneName, description,
    warnings, addressObjects, addressObjectSet, serviceObjects, serviceObjectSet,
  } = ctx;

  const rules = [];
  const protocol = normalizeProtocol(perm.IpProtocol || '-1');
  const fromPort = perm.FromPort;
  const toPort = perm.ToPort;

  // Build or reuse service object
  const serviceName = buildServiceName(protocol, fromPort, toPort);
  if (serviceName !== 'any' && !serviceObjectSet.has(serviceName)) {
    serviceObjectSet.add(serviceName);
    const portStr = (fromPort !== undefined && fromPort !== null)
      ? (fromPort === toPort ? String(fromPort) : `${fromPort}-${toPort}`)
      : '';
    serviceObjects.push({
      name: serviceName,
      protocol,
      port: portStr,
      source_port: '',
    });
  }

  // Collect source/destination CIDRs
  const cidrs = [];
  for (const range of (perm.IpRanges || [])) {
    if (range.CidrIp) cidrs.push({ cidr: range.CidrIp, desc: range.Description || '' });
  }
  for (const range of (perm.Ipv6Ranges || [])) {
    if (range.CidrIpv6) cidrs.push({ cidr: range.CidrIpv6, desc: range.Description || '' });
  }

  // Cross-SG references become address-group references
  for (const pair of (perm.UserIdGroupPairs || [])) {
    const refGroupId = pair.GroupId || 'unknown';
    cidrs.push({ cidr: null, sgRef: refGroupId, desc: pair.Description || '' });
  }

  // PrefixListIds
  for (const pl of (perm.PrefixListIds || [])) {
    if (pl.PrefixListId) {
      cidrs.push({ cidr: null, prefixList: pl.PrefixListId, desc: pl.Description || '' });
    }
  }

  // If no sources/dests found, use "any"
  if (cidrs.length === 0) {
    cidrs.push({ cidr: '0.0.0.0/0', desc: '' });
  }

  for (const entry of cidrs) {
    let addressRef = 'any';

    if (entry.cidr) {
      if (entry.cidr === '0.0.0.0/0' || entry.cidr === '::/0') {
        addressRef = 'any';
      } else {
        addressRef = `addr-${entry.cidr.replace(/[/:]/g, '_')}`;
        if (!addressObjectSet.has(addressRef)) {
          addressObjectSet.add(addressRef);
          addressObjects.push({
            name: addressRef,
            type: 'ip-netmask',
            value: entry.cidr,
            zone: zoneName,
          });
        }
      }
    } else if (entry.sgRef) {
      // Reference to another SG — use address-group naming convention
      addressRef = `sg-ref-${entry.sgRef}`;
      if (!addressObjectSet.has(addressRef)) {
        addressObjectSet.add(addressRef);
        addressObjects.push({
          name: addressRef,
          type: 'ip-netmask',
          value: '0.0.0.0/0',
          zone: zoneName,
        });
        warnings.push(createWarning('warning', `sg/${groupId}`,
          `SG reference "${entry.sgRef}" mapped as placeholder 0.0.0.0/0 — resolve after conversion`,
          'Replace with actual CIDR ranges of the referenced security group'));
      }
    } else if (entry.prefixList) {
      addressRef = `prefix-${entry.prefixList}`;
      if (!addressObjectSet.has(addressRef)) {
        addressObjectSet.add(addressRef);
        addressObjects.push({
          name: addressRef,
          type: 'ip-netmask',
          value: '0.0.0.0/0',
          zone: zoneName,
        });
        warnings.push(createWarning('warning', `sg/${groupId}`,
          `Prefix list "${entry.prefixList}" mapped as placeholder — resolve actual CIDRs after conversion`,
          'Use "aws ec2 get-managed-prefix-list-entries" to retrieve actual CIDRs'));
      }
    }

    const isInbound = direction === 'inbound';
    const ruleName = `${sgName}-${direction}-${protocol}-${rules.length}`;

    rules.push({
      name: ruleName,
      src_zones: isInbound ? ['any'] : [zoneName],
      dst_zones: isInbound ? [zoneName] : ['any'],
      src_addresses: isInbound ? [addressRef] : ['any'],
      dst_addresses: isInbound ? ['any'] : [addressRef],
      services: [serviceName],
      applications: ['any'],
      action: 'allow',
      logging: true,
      disabled: false,
      description: description || `${direction} rule from SG ${sgName} (${groupId})`,
      tags: [`aws-sg:${groupId}`],
      source_users: ['any'],
      _rule_index: 0,
    });
  }

  return rules;
}

// ---------------------------------------------------------------------------
// Empty result builder for error cases
// ---------------------------------------------------------------------------

/**
 * Returns a valid but empty intermediate config for error-exit scenarios.
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
      source_vendor: 'aws_sg',
      source_version: '',
      export_date: new Date().toISOString(),
      rule_count: 0,
      nat_rule_count: 0,
      object_count: 0,
      zone_count: 0,
      interface_count: 0,
      security_group_count: 0,
    },
    warnings,
  };
  return { intermediateConfig, warnings, parseStats: intermediateConfig.metadata };
}
