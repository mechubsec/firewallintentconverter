/**
 * SRX XML Configuration Builder
 * ================================
 * Agent: SRX-Expert
 *
 * Converts the vendor-neutral intermediate JSON schema into Junos XML
 * configuration format, suitable for "load merge" or "load replace" on SRX.
 *
 * Phase 1: Basic XML structure with security zones, address book, and policies.
 * Phase 2+: Full XML with NAT, routing, VPN, UTM.
 */

import { sanitizeJunosName, mapAppToJunos, mapProfileToSrx, createWarning, isPredefEquivalent } from '../parsers/parser-utils.js';
import {
  setEnum,
  setInteger,
  setToken,
  xmlAttribute,
  xmlComment,
  xmlElementName,
  xmlText,
} from '../security/junos-serialization.js';
import { findNegationIssues, findPolicyReferenceIssues } from '../security/policy-reference-integrity.js';
import { validateJunosInput } from '../security/junos-input-validation.js';
import { encodeJunosZonePair } from '../security/junos-identifier-identity.js';
import {
  planJunosIdentifiers,
  planMergedJunosIdentifiers,
} from '../security/junos-identifiers.js';
import { canonicalizeJunosSecurityFeatures } from '../security/junos-identifier-catalog.js';
import { validateXmlOutput } from '../security/junos-output-validation.js';
import { versionStamp } from '../version.js';
import { hostInboundEntries, warnZonesWithoutHostInbound } from './srx-host-inbound.js';
import { planNat } from './nat-plan.js';

/**
 * Builds a Junos XML configuration from the intermediate config.
 *
 * @param {Object} config - Intermediate JSON config
 * @param {Object} [interfaceMappings] - User-defined PAN-OS → SRX interface mappings
 * @returns {{ xml: string, warnings: Object[] }}
 */
export function buildSrxXml(config, interfaceMappings = {}, targetContext = null, options = {}) {
  validateJunosInput(config);
  validateJunosInput(interfaceMappings, 'interfaceMappings');
  for (const [sourceName, mappedName] of Object.entries(interfaceMappings)) {
    setToken(mappedName, `interfaceMappings.${sourceName}`, /^[A-Za-z0-9_.:/-]+$/);
  }
  if (targetContext) validateJunosInput(targetContext, 'targetContext');
  const effectiveTargetContext = targetContext || config.target_context || null;
  if (effectiveTargetContext?.type !== undefined) {
    setEnum(effectiveTargetContext.type, ['none', 'logical-system', 'tenant'], 'targetContext.type');
  }

  const identifiers = options.identifierPlan || planJunosIdentifiers(config, { targetContext });
  const identifierPath = localPath => `${options.pathPrefix || ''}${localPath}`;
  const targetContextPath = options.targetContextPath || 'targetContext.name';
  const identifierNames = {
    path: identifierPath,
    mapping: identifiers.mapping,
    definition: localPath => identifiers.nameForDefinition(identifierPath(localPath)),
    reference: localPath => identifiers.nameForReference(identifierPath(localPath)),
    generated: (localPath, role) => identifiers.nameForGenerated(identifierPath(localPath), role),
    generatedEntries: localPath => identifiers.mapping.entries.filter(entry => (
      entry.definitionPath?.startsWith(`${identifierPath(localPath)}#generated:`)
    )),
  };
  const warnings = [...identifiers.warnings];
  const summary = {
    identifier_collisions_resolved: identifiers.collisionCount,
  };
  const lines = [];
  xmlCustomfwicApps.clear();
  xmlUnmappedApps.clear();
  xmlPredefServiceMap.clear();
  prepareXmlApplicationGroupApplications(config.application_groups, identifierNames);

  // Detect source vendor for 1:1 passthrough (SRX→SRX needs no app mapping)
  const sourceVendor = config.metadata?.source_vendor || '';

  // Compute UTM/IDP/SecIntel assignment maps (mirrors srx-converter logic)
  const { utmPolicyMap, utmProfiles } = computeUtmMap(config, identifierNames, warnings);
  const { idpPolicyMap } = computeIdpMap(config.security_policies, identifierNames);
  const blockLists = (config.external_lists || [])
    .map((list, index) => ({ list, index }))
    .filter(({ list }) => list.isBlockList)
    .sort((left, right) => String(left.list.name).localeCompare(String(right.list.name)));
  const secIntelEnabled = blockLists.length > 0;
  const secIntelPolicyName = secIntelEnabled
    ? identifierNames.generated(`external_lists[${blockLists[0].index}]`, 'security-intelligence-policy')
    : null;

  // Determine context wrapping
  const ctx = effectiveTargetContext;
  const useContext = ctx && ctx.type && ctx.type !== 'none' && ctx.name;
  const indent = useContext ? '    ' : '  ';

  const omitWrapper = options.omitConfigurationWrapper || false;

  if (!omitWrapper) {
    lines.push('<?xml version="1.0" encoding="UTF-8"?>');
    lines.push('<configuration>');
    // Version stamp — inside <configuration> so validateXmlOutput accepts it
    // (content outside the root is rejected).
    lines.push(xmlComment(versionStamp(options.llmModel), 'version'));

    // Site identification header (for SDC/Mist integration)
    const siteN = config.metadata?.siteName;
    const siteG = config.metadata?.siteGroup;
    if (siteN || siteG) {
      let siteComment = 'Site Identification:';
      if (siteN) siteComment += ` Site: ${siteN}`;
      if (siteG) siteComment += ` | Site Group: ${siteG}`;
      lines.push(xmlComment(siteComment, 'metadata.siteName'));
    }
  }

  // Open logical-system or tenant wrapper
  if (useContext) {
    const ctxTag = xmlElementName(
      ctx.type === 'logical-system' ? 'logical-systems' : 'tenants',
      ['logical-systems', 'tenants'],
      'targetContext.type',
    );
    lines.push(ctxTag === 'logical-systems' ? '  <logical-systems>' : '  <tenants>');
    lines.push(`    <name>${xmlText(identifiers.nameForDefinition(targetContextPath), targetContextPath)}</name>`);
  }

  // System configuration (Day-0)
  buildSystemConfigXml(config.system_config, lines, indent);

  // Interface addresses (IPv4 + IPv6)
  buildInterfaceAddressesXml(config.interfaces, lines, interfaceMappings, indent);

  // Security section
  lines.push(`${indent}<security>`);

  // Zones
  buildZonesXml(config.zones, lines, interfaceMappings, identifierNames, warnings);

  // Address book
  buildAddressBookXml(config.address_objects, config.address_groups, lines, identifierNames);

  // UTM
  buildUtmXml(utmProfiles, lines, identifierNames);

  // Policies
  buildPoliciesXml(config.security_policies, lines, warnings, { utmPolicyMap, idpPolicyMap, secIntelEnabled, secIntelPolicyName }, config.application_groups, sourceVendor, config._rule_groups, identifierNames, findPolicyReferenceIssues(config));

  // NAT
  buildNatXml(config, lines, warnings, identifierNames, interfaceMappings);

  // IDP
  buildIdpXml(config, lines, identifierNames);

  lines.push(`${indent}</security>`);

  // Routing (static routes, BGP, OSPF)
  buildRoutingXml(config, lines, identifierNames);

  // Chassis Cluster / HA
  buildHaXml(config.ha_config, lines);

  // Security Screens
  buildScreenXml(config.screen_config, lines, identifierNames);

  // VPN / IPsec
  buildVpnXml(config.vpn_tunnels, lines, identifierNames);

  // Syslog
  buildSyslogXml(config.syslog_config, lines);

  // SNMP
  buildSnmpXml(config.snmp_config, lines, identifierNames);

  // AAA
  buildAaaXml(config.aaa_config, lines, identifierNames);

  // DHCP
  buildDhcpXml(config.dhcp_config, lines, identifierNames);

  // QoS / CoS
  buildQosXml(config.qos_config, lines, identifierNames);

  // L2 / Bridge Domains / Virtual-Wire
  buildL2Xml(config, lines, interfaceMappings, identifierNames);

  // Policy-Based Forwarding (filter-based forwarding)
  buildPbfXml(config.pbf_rules, lines, interfaceMappings, identifierNames);

  // SSL Proxy / PKI
  buildSslProxyXml(config, lines, identifierNames);

  // Flow Monitoring (Inline Jflow)
  buildFlowMonitoringXml(config.flow_monitoring_config, lines, identifierNames);

  // Applications (includes Customfwic placeholders for unmapped apps)
  buildApplicationsXml(config.service_objects, config.applications, config.service_groups, lines, xmlCustomfwicApps, identifierNames);

  // Schedulers
  buildSchedulersXml(config.schedules, lines, identifierNames);

  // Services (SecIntel)
  if (secIntelEnabled) {
    buildSecIntelXml(config.external_lists || [], lines, identifierNames);
  }

  // User Identification (JIMS) — when policies use source-identity
  buildUserIdentificationXml(config.security_policies, lines);

  // Unsupported feature notices
  lines.push('<!--');
  lines.push('  NOT CONVERTED — Manual Configuration Required');
  if (!config.aaa_config || config.aaa_config.length === 0) {
    lines.push('  AAA / Authentication (RADIUS, TACACS+, LDAP) — no AAA config detected in source.');
    lines.push('  If needed, configure manually: system authentication-order, access profile, etc.');
  }
  lines.push('-->');

  // Close context wrapper
  if (useContext) {
    const ctxTag = xmlElementName(
      ctx.type === 'logical-system' ? 'logical-systems' : 'tenants',
      ['logical-systems', 'tenants'],
      'targetContext.type',
    );
    lines.push(ctxTag === 'logical-systems' ? '  </logical-systems>' : '  </tenants>');
  }

  if (!omitWrapper) {
    lines.push('</configuration>');
  }

  const xml = lines.join('\n');
  if (!omitWrapper) validateXmlOutput(xml);
  return { xml, warnings, summary, identifierMappings: identifiers.mapping };
}

// ---------------------------------------------------------------------------
// Zone XML Builder
// ---------------------------------------------------------------------------

/**
 * Maps a source interface to the name emitted on a security-zone `interfaces`
 * line: user mapping if present (unit .0 appended), else the name as-is.
 */
function mapZoneInterfaceName(iface, interfaceMappings = {}) {
  if (interfaceMappings[iface]) {
    return interfaceMappings[iface].includes('.') ? interfaceMappings[iface] : `${interfaceMappings[iface]}.0`;
  }
  const base = iface.split('.')[0];
  if (interfaceMappings[base]) {
    const unit = iface.includes('.') ? iface.split('.')[1] : '0';
    return `${interfaceMappings[base].split('.')[0]}.${unit}`;
  }
  return iface;
}

function hostInboundXml(access, element, warnings, pad) {
  const { services, protocols } = hostInboundEntries(access, element, warnings);
  if (services.length === 0 && protocols.length === 0) return [];
  const entry = (tag, { name, except }) => [
    `${pad}  <${tag}>`,
    `${pad}    <name>${xmlText(name)}</name>`,
    ...(except ? [`${pad}    <except/>`] : []),
    `${pad}  </${tag}>`,
  ];
  return [
    `${pad}<host-inbound-traffic>`,
    ...services.flatMap(item => entry('system-services', item)),
    ...protocols.flatMap(item => entry('protocols', item)),
    `${pad}</host-inbound-traffic>`,
  ];
}

function buildZonesXml(zones, lines, interfaceMappings = {}, identifierNames, warnings = []) {
  if (!zones || zones.length === 0) return;

  lines.push('    <zones>');
  for (let zoneIndex = 0; zoneIndex < zones.length; zoneIndex += 1) {
    const zone = zones[zoneIndex];
    const path = `zones[${zoneIndex}].name`;
    const name = identifierNames.definition(path);
    lines.push(`      <security-zone>`);
    lines.push(`        <name>${xmlText(name)}</name>`);
    if (zone.description) {
      lines.push(`        <description>${xmlText(zone.description)}</description>`);
    }
    lines.push(...hostInboundXml(zone.host_inbound_traffic, `zones/${name}`, warnings, '        '));
    for (const iface of zone.interfaces || []) {
      const srxIface = mapZoneInterfaceName(iface, interfaceMappings);
      lines.push(`        <interfaces>`);
      lines.push(`          <name>${xmlText(srxIface)}</name>`);
      lines.push(...hostInboundXml(zone.interface_host_inbound_traffic?.[iface], `zones/${name}/${srxIface}`, warnings, '          '));
      lines.push(`        </interfaces>`);
    }
    lines.push(`      </security-zone>`);
  }
  warnZonesWithoutHostInbound(zones, warnings);
  lines.push('    </zones>');
}

// ---------------------------------------------------------------------------
// Address Book XML Builder
// ---------------------------------------------------------------------------

function buildAddressBookXml(addressObjects, addressGroups, lines, identifierNames) {
  if ((!addressObjects || addressObjects.length === 0) &&
      (!addressGroups || addressGroups.length === 0)) return;

  lines.push('    <address-book>');
  lines.push('      <name>global</name>');

  // Address entries
  for (let objectIndex = 0; objectIndex < (addressObjects || []).length; objectIndex += 1) {
    const obj = addressObjects[objectIndex];
    const name = identifierNames.definition(`address_objects[${objectIndex}].name`);
    lines.push('      <address>');
    lines.push(`        <name>${xmlText(name)}</name>`);

    switch (obj.type) {
      case 'host':
      case 'subnet':
        lines.push(`        <ip-prefix>${xmlText(obj.value)}</ip-prefix>`);
        break;
      case 'fqdn': {
        const fqdnValue = (obj.value && obj.value.startsWith('*.')) ? obj.value.slice(2) : obj.value;
        lines.push(`        <dns-name>`);
        lines.push(`          <name>${xmlText(fqdnValue)}</name>`);
        if (obj.fqdn_ip_version === 'v4') {
          lines.push(`          <ipv4-only/>`);
        } else if (obj.fqdn_ip_version === 'v6') {
          lines.push(`          <ipv6-only/>`);
        }
        lines.push(`        </dns-name>`);
        break;
      }
      case 'range':
        lines.push(`        <range-address>`);
        lines.push(`          <name>${xmlText(name)}</name>`);
        const [low, high] = obj.value.split('-').map(s => s.trim());
        lines.push(`          <low>${xmlText(low)}</low>`);
        lines.push(`          <high>${xmlText(high)}</high>`);
        lines.push(`        </range-address>`);
        break;
      case 'geography':
      case 'dynamic':
      case 'wildcard':
        lines.push(`        ${xmlComment(`UNSUPPORTED: ${obj.type} address "${obj.name}" (${obj.value})`, 'address_objects')}`);
        continue;
    }

    if (obj.description) {
      lines.push(`        <description>${xmlText(obj.description)}</description>`);
    }

    lines.push('      </address>');
  }

  // Address sets (groups)
  const addrGroupNameSet = new Set((addressGroups || []).map(g => g.name));
  for (let groupIndex = 0; groupIndex < (addressGroups || []).length; groupIndex += 1) {
    const group = addressGroups[groupIndex];
    const groupName = identifierNames.definition(`address_groups[${groupIndex}].name`);
    if (group._dynamic) {
      lines.push(`      ${xmlComment(`UNSUPPORTED: Dynamic address group "${group.name}" — SRX does not support tag-based dynamic groups`, 'address_groups')}`);
      continue;
    }
    lines.push('      <address-set>');
    lines.push(`        <name>${xmlText(groupName)}</name>`);
    for (let memberIndex = 0; memberIndex < group.members.length; memberIndex += 1) {
      const member = group.members[memberIndex];
      const memberName = identifierNames.reference(`address_groups[${groupIndex}].members[${memberIndex}]`);
      if (addrGroupNameSet.has(member)) {
        lines.push('        <address-set>');
        lines.push(`          <name>${xmlText(memberName)}</name>`);
        lines.push('        </address-set>');
      } else {
        lines.push('        <address>');
        lines.push(`          <name>${xmlText(memberName)}</name>`);
        lines.push('        </address>');
      }
    }
    lines.push('      </address-set>');
  }

  lines.push('    </address-book>');
}

// ---------------------------------------------------------------------------
// User Identification (JIMS) XML Builder
// ---------------------------------------------------------------------------

function buildUserIdentificationXml(policies, lines) {
  if (!policies || policies.length === 0) return;
  const identityPolicies = policies.filter(p => p.source_users && p.source_users.length > 0);
  if (identityPolicies.length === 0) return;

  lines.push('  <services>');
  lines.push('    <user-identification>');
  lines.push('      <identity-management>');
  lines.push('        <connection>');
  lines.push('          <connect-method>https</connect-method>');
  lines.push('          <port>1443</port>');
  lines.push('          <!-- Configure JIMS server address and credentials -->');
  lines.push('        </connection>');
  lines.push('      </identity-management>');
  lines.push('    </user-identification>');
  lines.push('  </services>');
}

// ---------------------------------------------------------------------------
// Security Policies XML Builder
// ---------------------------------------------------------------------------

function generatedPolicyRole(fromZone, toZone) {
  return `security-policy:${encodeJunosZonePair(fromZone, toZone)}`;
}

function orderedZoneEntries(zones) {
  return zones
    .map((zone, index) => ({ zone, index }))
    .sort((left, right) => (
      String(left.zone).localeCompare(String(right.zone)) || left.index - right.index
    ));
}

function buildPoliciesXml(policies, lines, warnings, profileMaps = {}, appGroups = [], sourceVendor = '', ruleGroups = [], identifierNames, policyReferenceIssues = new Map()) {
  if (!policies || policies.length === 0) return;

  const {
    utmPolicyMap = {}, idpPolicyMap = {}, secIntelEnabled = false, secIntelPolicyName = null,
  } = profileMaps;

  // Build rule-index→group map for group comment insertion
  const groupByIndex = {};
  if (ruleGroups && ruleGroups.length > 0) {
    for (const g of ruleGroups) {
      for (const idx of (g.rule_indices || [])) {
        groupByIndex[idx] = g.group_name;
      }
    }
  }

  // Group policies by zone pair
  const zonePairs = new Map();
  for (let policyIndex = 0; policyIndex < policies.length; policyIndex += 1) {
    const policy = policies[policyIndex];
    for (let addressIndex = 0; addressIndex < policy.src_addresses.length; addressIndex += 1) {
      identifierNames.reference(`security_policies[${policyIndex}].src_addresses[${addressIndex}]`);
    }
    for (let addressIndex = 0; addressIndex < policy.dst_addresses.length; addressIndex += 1) {
      identifierNames.reference(`security_policies[${policyIndex}].dst_addresses[${addressIndex}]`);
    }
    const srcZones = policy.src_zones.length > 0 ? policy.src_zones : ['any'];
    const dstZones = policy.dst_zones.length > 0 ? policy.dst_zones : ['any'];
    const sourceEntries = orderedZoneEntries(srcZones);
    const destinationEntries = orderedZoneEntries(dstZones);
    let definitionIndex = 0;
    const definedPairs = new Set();
    for (let sourceOrdinal = 0; sourceOrdinal < sourceEntries.length; sourceOrdinal += 1) {
      const { zone: src, index: sourceIndex } = sourceEntries[sourceOrdinal];
      identifierNames.reference(policy.src_zones.length > 0
        ? `security_policies[${policyIndex}].src_zones[${sourceIndex}]`
        : `security_policies[${policyIndex}]#effective-source-zone`);
      for (const { zone: dst, index: destinationIndex } of destinationEntries) {
        if (sourceOrdinal === 0) {
          identifierNames.reference(policy.dst_zones.length > 0
            ? `security_policies[${policyIndex}].dst_zones[${destinationIndex}]`
            : `security_policies[${policyIndex}]#effective-destination-zone`);
        }
        const isGlobal = src === 'any' || dst === 'any';
        const contextKey = isGlobal ? 'global' : encodeJunosZonePair(src, dst);
        if (!zonePairs.has(contextKey)) {
          zonePairs.set(contextKey, { from: src, to: dst, isGlobal, policies: [] });
        }
        if (definedPairs.has(contextKey)) continue;
        definedPairs.add(contextKey);
        definitionIndex += 1;
        const occurrence = definitionIndex;
        const genericName = !policy.name
          // njsscan regex_dos: false positive. Alternation is four distinct literals and is not nested under a quantifier - nothing to backtrack.
          || /^(rule|policy|permit|deny)[-_]?\d+$/i.test(policy.name)  // njsscan-ignore: regex_dos
          || /^\d+$/.test(policy.name);
        const outputName = genericName
          ? identifierNames.generated(
            `security_policies[${policyIndex}]`,
            generatedPolicyRole(src, dst),
          )
          : identifierNames.definition(occurrence === 1
            ? `security_policies[${policyIndex}].name`
            : `security_policies[${policyIndex}].name#zone-pair:${encodeJunosZonePair(src, dst)}`);
        zonePairs.get(contextKey).policies.push({
          policy, policyIndex, sourceIndex, destinationIndex, outputName,
        });
      }
    }
  }

  lines.push('    <policies>');

  for (const pair of zonePairs.values()) {
    const first = pair.policies[0];
    const sourcePath = first.policy.src_zones.length > 0
      ? `security_policies[${first.policyIndex}].src_zones[${first.sourceIndex}]`
      : `security_policies[${first.policyIndex}]#effective-source-zone`;
    const destinationPath = first.policy.dst_zones.length > 0
      ? `security_policies[${first.policyIndex}].dst_zones[${first.destinationIndex}]`
      : `security_policies[${first.policyIndex}]#effective-destination-zone`;
    lines.push(pair.isGlobal ? '      <global>' : '      <policy>');
    if (!pair.isGlobal) {
      lines.push(`        <from-zone-name>${xmlText(identifierNames.reference(sourcePath))}</from-zone-name>`);
      lines.push(`        <to-zone-name>${xmlText(identifierNames.reference(destinationPath))}</to-zone-name>`);
    }

    let currentGroup = null;
    for (const item of pair.policies) {
      const { policy, policyIndex: pIdx, outputName: name } = item;
      // Emit XML comment for group boundaries
      const ruleGroup = groupByIndex[pIdx] || policy._group || null;
      if (ruleGroup && ruleGroup !== currentGroup) {
        lines.push(`        ${xmlComment(`===== Group: ${ruleGroup} =====`, `security_policies[${pIdx}]._group`)}`);
        currentGroup = ruleGroup;
      }
      // Clean EDL addresses from match criteria
      const secIntelAddrs = new Set(policy._secIntelAddresses || []);
      let srcAddrs = policy.src_addresses
        .map((value, index) => ({ value, index }))
        .filter(({ value }) => !secIntelAddrs.has(value));
      let dstAddrs = policy.dst_addresses
        .map((value, index) => ({ value, index }))
        .filter(({ value }) => !secIntelAddrs.has(value));
      if (srcAddrs.length === 0 && policy.src_addresses.length > 0) srcAddrs = [{ value: 'any', index: null }];
      if (dstAddrs.length === 0 && policy.dst_addresses.length > 0) dstAddrs = [{ value: 'any', index: null }];

      const apps = resolveApps(policy.applications, policy.services, warnings, policy.name, appGroups, sourceVendor, pIdx, identifierNames);
      const hasUnmappedApp = apps.some(app => xmlUnmappedApps.has(app));
      const referenceIssue = policyReferenceIssues.get(pIdx);

      // Junos XML marks a deactivated statement with inactive="inactive"
      const negationIssues = findNegationIssues(policy);
      if (negationIssues.length > 0) {
        lines.push(`        ${xmlComment(`CAVEAT: policy deactivated — negated address match not representable: ${negationIssues.join('; ')}`, `security_policies[${pIdx}]`)}`);
        warnings.push(createWarning(
          'warning',
          `security_policies[${pIdx}]`,
          `Policy ${policy.name || pIdx} deactivated: ${negationIssues.join('; ')}`,
          'Rewrite the negated address match by hand before enabling this policy.',
        ));
      }
      if (referenceIssue) {
        const undefinedItems = [
          ...(referenceIssue.addresses || []).map(addr => `address "${addr}"`),
          ...(referenceIssue.services || []).map(svc => `service "${svc}"`),
        ];
        lines.push(`        ${xmlComment(`CAVEAT: policy deactivated — undefined reference(s): ${undefinedItems.join(', ')}`, `security_policies[${pIdx}]`)}`);
        warnings.push(createWarning(
          'warning',
          `security_policies[${pIdx}]`,
          `Policy ${policy.name || pIdx} has undefined reference(s): ${undefinedItems.join(', ')}`,
          'Define the missing objects before enabling this policy.',
        ));
      }
      const deactivate = policy.disabled || hasUnmappedApp || !!referenceIssue || negationIssues.length > 0;
      lines.push(deactivate ? '        <policy inactive="inactive">' : '        <policy>');
      lines.push(`          <name>${xmlText(name)}</name>`);
      if (policy.description) {
        lines.push(`          <description>${xmlText(policy.description, `security_policies[${pIdx}].description`)}</description>`);
      }

      // Match
      lines.push('          <match>');
      for (const { index: addressIndex } of (srcAddrs.length > 0 ? srcAddrs : [{ value: 'any', index: null }])) {
        const output = addressIndex === null ? 'any' : identifierNames.reference(`security_policies[${pIdx}].src_addresses[${addressIndex}]`);
        lines.push(`            <source-address>${xmlText(output)}</source-address>`);
      }
      if (policy.negate_source) lines.push('            <source-address-excluded/>');
      for (const { index: addressIndex } of (dstAddrs.length > 0 ? dstAddrs : [{ value: 'any', index: null }])) {
        const output = addressIndex === null ? 'any' : identifierNames.reference(`security_policies[${pIdx}].dst_addresses[${addressIndex}]`);
        lines.push(`            <destination-address>${xmlText(output)}</destination-address>`);
      }
      if (policy.negate_destination) lines.push('            <destination-address-excluded/>');

      for (const app of apps) {
        lines.push(`            <application>${xmlText(app)}</application>`);
      }
      if (policy.source_users && policy.source_users.length > 0) {
        for (const identity of policy.source_users) {
          // identifier-catalog: non-symbol security-policy source-identity element value
          lines.push(`            <source-identity>${xmlText(sanitizeJunosName(identity))}</source-identity>`);
        }
      }
      lines.push('          </match>');

      // Then
      lines.push('          <then>');
      const action = xmlElementName(
        policy.action === 'allow' ? 'permit' : (policy.action === 'drop' || policy.action === 'deny' ? 'deny' : 'reject'),
        ['permit', 'deny', 'reject'],
        `security_policies[${pIdx}].action`,
      );
      const actionElement = { permit: '<permit/>', deny: '<deny/>', reject: '<reject/>' }[action];
      lines.push(`            ${actionElement}`);
      if (policy.log_start || policy.log_end) {
        lines.push('            <log>');
        if (policy.log_start) lines.push('              <session-init/>');
        if (policy.log_end) lines.push('              <session-close/>');
        lines.push('            </log>');
      }
      if (policy._srx_log_count !== false) {
        lines.push('            <count/>');
      }

      // Application services (UTM / IDP / SecIntel)
      const hasUtm = !!utmPolicyMap[pIdx];
      const hasIdp = !!idpPolicyMap[pIdx];
      const hasProfileGroup = policy.profile_group && Object.keys(policy.security_profiles || {}).length === 0;
      const hasSecIntel = secIntelEnabled && policy.action === 'allow' &&
        policy.dst_zones.some(z => z.toLowerCase() === 'untrust');

      const hasSslProxy = policy._srx_decrypt && policy.action === 'allow';

      if (hasUtm || hasIdp || hasSecIntel || hasProfileGroup || hasSslProxy) {
        lines.push('            <application-services>');
        if (hasUtm) {
          lines.push(`              <utm-policy>${xmlText(utmPolicyMap[pIdx])}</utm-policy>`);
        } else if (hasProfileGroup) {
          lines.push(`              <utm-policy>${xmlText(identifierNames.reference(`security_policies[${pIdx}]#utm-policy`))}</utm-policy>`);
        }
        if (hasIdp) {
          lines.push(`              <idp-policy>${xmlText(idpPolicyMap[pIdx])}</idp-policy>`);
        }
        if (hasSecIntel) {
          lines.push(`              <security-intelligence-policy>${xmlText(secIntelPolicyName)}</security-intelligence-policy>`);
        }
        if (hasSslProxy) {
          const sslProfile = identifierNames.reference(policy._srx_decrypt_profile
            ? `security_policies[${pIdx}]._srx_decrypt_profile`
            : `security_policies[${pIdx}]#ssl-proxy-profile`);
          lines.push('              <ssl-proxy>');
          lines.push(`                <profile-name>${xmlText(sslProfile)}</profile-name>`);
          lines.push('              </ssl-proxy>');
        }
        lines.push('            </application-services>');
      }

      lines.push('          </then>');

      // Scheduler
      if (policy.schedule) {
        lines.push(`          <scheduler-name>${xmlText(identifierNames.reference(`security_policies[${pIdx}].schedule`))}</scheduler-name>`);
      }

      lines.push('        </policy>');
    }

    lines.push(pair.isGlobal ? '      </global>' : '      </policy>');
  }

  // Fail closed when a global catch-all is removed or the config is merged onto a permit-all device; matches the set output.
  if ([...zonePairs.values()].some(pair => pair.isGlobal)) {
    lines.push('      <default-policy>');
    lines.push('        <deny-all/>');
    lines.push('      </default-policy>');
  }

  lines.push('    </policies>');
}

// ---------------------------------------------------------------------------
// NAT XML Builder (renders the plan shared with the set converter)
// ---------------------------------------------------------------------------

function buildNatXml(config, lines, warnings, identifierNames, interfaceMappings = {}) {
  const plan = planNat({
    natRules: config.nat_rules,
    addressObjects: config.address_objects,
    addressGroups: config.address_groups,
    zones: config.zones,
    interfaces: config.interfaces,
    // XML keeps source interface names unless mapped, so NAT names them the same way.
    mapInterface: name => mapZoneInterfaceName(name, interfaceMappings),
    naming: identifierNames,
  });
  if (!plan) return;
  warnings.push(...plan.warnings);

  const comments = (indent, texts) => {
    for (const text of texts) lines.push(`${indent}${xmlComment(text, 'nat_rules')}`);
  };
  const zoneElements = (tag, zoneNames) => (
    `<${tag}>${zoneNames.map(zone => `<zone>${xmlText(zone)}</zone>`).join('')}</${tag}>`
  );
  const matchElements = (indent, element, entries) => {
    for (const entry of entries) {
      const tag = entry.kind === 'address-name' ? `${element}-name` : element;
      lines.push(`${indent}<${tag}>${xmlText(entry.value)}</${tag}>`);
    }
  };
  // destination-port is a list keyed by name.
  const portElement = (indent, port) => (
    `${indent}<destination-port><name>${xmlText(port.name)}</name>${port.high ? `<to><high>${xmlText(port.high)}</high></to>` : ''}</destination-port>`
  );
  // DNAT and static rules take a destination-address container holding one dst-addr.
  const dstAddrElements = (indent, entries) => {
    for (const entry of entries) {
      lines.push(`${indent}<destination-address><dst-addr>${xmlText(entry.value)}</dst-addr></destination-address>`);
    }
  };
  const ruleSetHeader = (indent, ruleSet) => {
    lines.push(`${indent}<rule-set>`);
    lines.push(`${indent}  <name>${xmlText(ruleSet.name)}</name>`);
    if (ruleSet.fromZones.length > 0) lines.push(`${indent}  ${zoneElements('from', ruleSet.fromZones)}`);
    if (ruleSet.toZones.length > 0) lines.push(`${indent}  ${zoneElements('to', ruleSet.toZones)}`);
  };
  const poolsOf = ruleSets => {
    const pools = new Map();
    for (const ruleSet of ruleSets) {
      for (const rule of ruleSet.rules) {
        if (!rule.skipped && rule.then?.pool) pools.set(rule.then.pool.name, rule.then.pool);
      }
    }
    return [...pools.values()];
  };

  if (plan.missingZones.length > 0) {
    lines.push('    <zones>');
    for (const zoneName of plan.missingZones) {
      lines.push(`      <security-zone><name>${xmlText(zoneName)}</name></security-zone>`);
    }
    lines.push('    </zones>');
  }

  lines.push('    <nat>');

  if (plan.source) {
    lines.push('      <source>');
    for (const ruleSet of plan.source) {
      if (ruleSet.skipped) {
        comments('        ', ruleSet.comments);
        continue;
      }
      ruleSetHeader('        ', ruleSet);
      for (const rule of ruleSet.rules) {
        comments('          ', rule.comments);
        if (rule.skipped) continue;
        lines.push('          <rule>');
        lines.push(`            <name>${xmlText(rule.name)}</name>`);
        lines.push('            <src-nat-rule-match>');
        matchElements('              ', 'source-address', rule.match.source);
        matchElements('              ', 'destination-address', rule.match.destination);
        if (rule.match.protocol) lines.push(`              <protocol>${xmlText(rule.match.protocol)}</protocol>`);
        if (rule.match.destinationPort) lines.push(portElement('              ', rule.match.destinationPort));
        lines.push('            </src-nat-rule-match>');
        comments('            ', rule.thenComments);
        lines.push('            <then>');
        const persistent = rule.persistent ? '<persistent-nat><permit><target-host/></permit></persistent-nat>' : '';
        if (rule.then.kind === 'pool') {
          lines.push(`              <source-nat><pool><pool-name>${xmlText(rule.then.pool.name)}</pool-name>${persistent}</pool></source-nat>`);
        } else if (rule.then.kind === 'off') {
          lines.push('              <source-nat><off/></source-nat>');
        } else {
          lines.push(persistent ? `              <source-nat><interface>${persistent}</interface></source-nat>` : '              <source-nat><interface/></source-nat>');
        }
        lines.push('            </then>');
        lines.push('          </rule>');
      }
      lines.push('        </rule-set>');
    }
    for (const pool of poolsOf(plan.source)) {
      lines.push('        <pool>');
      lines.push(`          <name>${xmlText(pool.name)}</name>`);
      for (const address of pool.addresses) {
        lines.push(address.to
          ? `          <address><name>${xmlText(address.prefix)}</name><to><ipaddr>${xmlText(address.to)}</ipaddr></to></address>`
          : `          <address><name>${xmlText(address.prefix)}</name></address>`);
      }
      if (pool.hostAddressBase) lines.push(`          <host-address-base>${xmlText(pool.hostAddressBase)}</host-address-base>`);
      if (pool.noPortTranslation) lines.push('          <port><no-translation/></port>');
      lines.push('        </pool>');
    }
    lines.push('      </source>');
  }

  if (plan.destination) {
    lines.push('      <destination>');
    for (const ruleSet of plan.destination) {
      if (ruleSet.skipped) {
        comments('        ', ruleSet.comments);
        continue;
      }
      ruleSetHeader('        ', ruleSet);
      comments('          ', ruleSet.comments);
      for (const rule of ruleSet.rules) {
        comments('          ', rule.comments);
        if (rule.skipped) continue;
        lines.push('          <rule>');
        lines.push(`            <name>${xmlText(rule.name)}</name>`);
        lines.push('            <dest-nat-rule-match>');
        dstAddrElements('              ', rule.match.destination);
        if (rule.match.destinationPort) lines.push(portElement('              ', rule.match.destinationPort));
        if (rule.match.protocol) lines.push(`              <protocol>${xmlText(rule.match.protocol)}</protocol>`);
        lines.push('            </dest-nat-rule-match>');
        lines.push('            <then>');
        if (rule.then) {
          lines.push(`              <destination-nat><pool><pool-name>${xmlText(rule.then.pool.name)}</pool-name></pool></destination-nat>`);
        }
        lines.push('            </then>');
        lines.push('          </rule>');
      }
      lines.push('        </rule-set>');
    }
    for (const pool of poolsOf(plan.destination)) {
      lines.push('        <pool>');
      lines.push(`          <name>${xmlText(pool.name)}</name>`);
      lines.push(`          <address><ipaddr>${xmlText(pool.prefix)}</ipaddr>${pool.port ? `<port>${xmlText(String(pool.port))}</port>` : ''}</address>`);
      lines.push('        </pool>');
    }
    lines.push('      </destination>');
  }

  // A rule-set with no emitted rule is not valid Junos, so it keeps only its comments.
  const emittedStatic = (plan.static || []).filter(ruleSet => !ruleSet.skipped && ruleSet.rules.some(rule => !rule.skipped));
  for (const ruleSet of (plan.static || []).filter(item => !emittedStatic.includes(item))) {
    comments('      ', ruleSet.comments);
    for (const rule of ruleSet.rules) comments('      ', rule.comments);
  }
  if (emittedStatic.length > 0) {
    lines.push('      <static>');
    for (const ruleSet of emittedStatic) {
      ruleSetHeader('        ', ruleSet);
      for (const rule of ruleSet.rules) {
        comments('          ', rule.comments);
        if (rule.skipped) continue;
        lines.push('          <rule>');
        lines.push(`            <name>${xmlText(rule.name)}</name>`);
        lines.push('            <static-nat-rule-match>');
        dstAddrElements('              ', rule.match.destination);
        lines.push('            </static-nat-rule-match>');
        lines.push('            <then>');
        if (rule.then) {
          lines.push('              <static-nat>');
          lines.push(`                <prefix><addr-prefix>${xmlText(rule.then.prefix)}</addr-prefix></prefix>`);
          lines.push('              </static-nat>');
        }
        lines.push('            </then>');
        lines.push('          </rule>');
      }
      lines.push('        </rule-set>');
    }
    lines.push('      </static>');
  }

  if (plan.proxyArp.length > 0) {
    lines.push('      <proxy-arp>');
    for (const interfaceName of new Set(plan.proxyArp.map(entry => entry.interface))) {
      lines.push('        <interface>');
      lines.push(`          <name>${xmlText(interfaceName)}</name>`);
      for (const entry of plan.proxyArp.filter(item => item.interface === interfaceName)) {
        lines.push(entry.to
          ? `          <address><name>${xmlText(entry.address)}</name><to><ipaddr>${xmlText(entry.to)}</ipaddr></to></address>`
          : `          <address><name>${xmlText(entry.address)}</name></address>`);
      }
      lines.push('        </interface>');
    }
    lines.push('      </proxy-arp>');
  }

  lines.push('    </nat>');
}

// ---------------------------------------------------------------------------
// Applications XML Builder
// ---------------------------------------------------------------------------

function buildApplicationsXml(serviceObjects, applications, serviceGroups, lines, customfwicMap, identifierNames) {
  const allApps = [
    ...(serviceObjects || []).map((app, index) => ({ app, index, root: 'service_objects', kind: 'service', portField: 'port_range' })),
    ...(applications || []).map((app, index) => ({ app, index, root: 'applications', kind: 'application', portField: 'port' })),
  ];
  const groups = serviceGroups || [];
  const hasCustomfwic = customfwicMap && customfwicMap.size > 0;
  if (allApps.length === 0 && groups.length === 0 && !hasCustomfwic) return;

  lines.push('  <applications>');

  for (const descriptor of allApps) {
    const { app, index, root, kind, portField } = descriptor;
    const protocol = app.protocol || 'tcp';
    const port = app.port_range || app.port || '';

    // Check if this service maps to a predefined Junos application — skip if so
    const predefApp = isPredefEquivalent(app.name, protocol, port);
    if (predefApp) {
      xmlPredefServiceMap.set(app.name, predefApp);
      lines.push(`    ${xmlComment(`Skipped: "${app.name}" (${protocol}/${port}) → predefined ${predefApp}`, 'service_objects')}`);
      continue;
    }

    const ownerPath = `${root}[${index}]`;
    if (port.includes(',')) {
      const setName = identifierNames.generated(ownerPath, `${kind}-multi-port-set`);
      const parts = [...new Set(port.split(',').map(part => part.trim()))].sort();
      for (const part of parts) {
        const childName = identifierNames.generated(ownerPath, `${kind}-port:${part}`);
        lines.push('    <application>');
        lines.push(`      <name>${xmlText(childName)}</name>`);
        lines.push(`      <protocol>${xmlText(protocol)}</protocol>`);
        lines.push(`      <destination-port>${xmlText(part)}</destination-port>`);
        lines.push('    </application>');
      }
      lines.push('    <application-set>');
      lines.push(`      <name>${xmlText(setName)}</name>`);
      for (const part of parts) {
        const childName = identifierNames.generated(ownerPath, `${kind}-port:${part}`);
        lines.push(`      <application><name>${xmlText(childName)}</name></application>`);
      }
      lines.push('    </application-set>');
      identifierNames.reference(`${ownerPath}.name`);
      continue;
    }

    const emitsWithoutPort = root === 'service_objects'
      && (['icmp', 'icmp6'].includes(protocol) || (protocol === 'ip' && app.protocol_number));
    if ((root === 'applications' && (!app.protocol || !port)) || (!port && !emitsWithoutPort)) {
      continue;
    }

    const name = identifierNames.definition(`${ownerPath}.name`);

    if (protocol === 'icmp' || protocol === 'icmp6') {
      lines.push('    <application>');
      lines.push(`      <name>${xmlText(name)}</name>`);
      lines.push(`      <protocol>${xmlText(protocol)}</protocol>`);
      if (app.icmp_type) {
        lines.push(`      <icmp-type>${xmlText(app.icmp_type)}</icmp-type>`);
      }
      if (app.icmp_code) {
        lines.push(`      <icmp-code>${xmlText(app.icmp_code)}</icmp-code>`);
      }
      if (app.description) {
        lines.push(`      <description>${xmlText(app.description)}</description>`);
      }
      lines.push('    </application>');
    } else if (protocol === 'ip' && app.protocol_number) {
      lines.push('    <application>');
      lines.push(`      <name>${xmlText(name)}</name>`);
      lines.push(`      <protocol>${xmlText(app.protocol_number)}</protocol>`);
      if (app.description) {
        lines.push(`      <description>${xmlText(app.description)}</description>`);
      }
      lines.push('    </application>');
    } else {
      if (!port) continue;
      lines.push('    <application>');
      lines.push(`      <name>${xmlText(name)}</name>`);
      lines.push(`      <protocol>${xmlText(protocol)}</protocol>`);
      lines.push(`      <destination-port>${xmlText(port)}</destination-port>`);
      if (app.description) {
        lines.push(`      <description>${xmlText(app.description)}</description>`);
      }
      lines.push('    </application>');
    }
  }

  // Application sets (service groups)
  const svcGroupNameSet = new Set(groups.map(g => g.name));
  for (let groupIndex = 0; groupIndex < groups.length; groupIndex += 1) {
    const group = groups[groupIndex];
    const groupName = identifierNames.definition(`service_groups[${groupIndex}].name`);
    lines.push('    <application-set>');
    lines.push(`      <name>${xmlText(groupName)}</name>`);
    for (let memberIndex = 0; memberIndex < group.members.length; memberIndex += 1) {
      const member = group.members[memberIndex];
      const memberName = identifierNames.reference(`service_groups[${groupIndex}].members[${memberIndex}]`);
      if (svcGroupNameSet.has(member)) {
        lines.push('      <application-set>');
        lines.push(`        <name>${xmlText(memberName)}</name>`);
        lines.push('      </application-set>');
      } else {
        lines.push('      <application>');
        lines.push(`        <name>${xmlText(memberName)}</name>`);
        lines.push('      </application>');
      }
    }
    lines.push('    </application-set>');
  }

  // Placeholder Customfwic applications for unmapped apps
  if (hasCustomfwic) {
    lines.push('    <!-- Placeholder applications (Customfwic) - REQUIRES MANUAL CONFIGURATION -->');
    for (const [customName, details] of customfwicMap) {
      if (details.kind === 'application-set') continue;
      lines.push('    <application>');
      lines.push(`      <name>${xmlText(customName)}</name>`);
      lines.push('      <protocol>tcp</protocol>');
      lines.push('      <destination-port>0</destination-port>');
      lines.push(`      <description>Placeholder for ${xmlText(details.originalName)} - REQUIRES MANUAL CONFIGURATION</description>`);
      lines.push('    </application>');
    }
    for (const [customName, details] of customfwicMap) {
      if (details.kind !== 'application-set') continue;
      lines.push('    <application-set>');
      lines.push(`      <name>${xmlText(customName)}</name>`);
      for (const [childName, childDetails] of customfwicMap) {
        if (childDetails.kind === 'application' && childDetails.originalName === details.originalName) {
          lines.push(`      <application><name>${xmlText(childName)}</name></application>`);
        }
      }
      lines.push('    </application-set>');
    }
  }

  lines.push('  </applications>');
}

// ---------------------------------------------------------------------------
// Schedulers XML Builder
// ---------------------------------------------------------------------------

const XML_SCHEDULE_DAYS = {
  sun: 'sunday', mon: 'monday', tue: 'tuesday', wed: 'wednesday',
  thu: 'thursday', fri: 'friday', sat: 'saturday',
  sunday: 'sunday', monday: 'monday', tuesday: 'tuesday', wednesday: 'wednesday',
  thursday: 'thursday', friday: 'friday', saturday: 'saturday',
};

function buildSchedulersXml(schedules, lines, identifierNames) {
  if (!schedules || schedules.length === 0) return;

  lines.push('  <schedulers>');

  for (let scheduleIndex = 0; scheduleIndex < schedules.length; scheduleIndex += 1) {
    const sched = schedules[scheduleIndex];
    const name = identifierNames.definition(`schedules[${scheduleIndex}].name`);
    lines.push('    <scheduler>');
    lines.push(`      <name>${xmlText(name)}</name>`);

    if (sched.type === 'recurring' && sched.days && sched.days.length > 0) {
      for (let dayIndex = 0; dayIndex < sched.days.length; dayIndex += 1) {
        const day = sched.days[dayIndex];
        const dayTag = xmlElementName(
          XML_SCHEDULE_DAYS[day.toLowerCase()],
          Object.values(XML_SCHEDULE_DAYS),
          `schedules.days[${dayIndex}]`,
        );
        const dayElements = {
          sunday: ['<sunday>', '</sunday>'], monday: ['<monday>', '</monday>'],
          tuesday: ['<tuesday>', '</tuesday>'], wednesday: ['<wednesday>', '</wednesday>'],
          thursday: ['<thursday>', '</thursday>'], friday: ['<friday>', '</friday>'],
          saturday: ['<saturday>', '</saturday>'],
        }[dayTag];
        lines.push(`      ${dayElements[0]}`);
        if (sched.start) lines.push(`        <start-time>${xmlText(sched.start)}</start-time>`);
        if (sched.end) lines.push(`        <stop-time>${xmlText(sched.end)}</stop-time>`);
        lines.push(`      ${dayElements[1]}`);
      }
    } else if (sched.type === 'onetime') {
      if (sched.start) lines.push(`      <start-date>${xmlText(sched.start)}</start-date>`);
      if (sched.end) lines.push(`      <stop-date>${xmlText(sched.end)}</stop-date>`);
    }

    lines.push('    </scheduler>');
  }

  lines.push('  </schedulers>');
}

// ---------------------------------------------------------------------------
// UTM XML Builder
// ---------------------------------------------------------------------------

function computeUtmMap(config, identifierNames, warnings) {
  const policies = config.security_policies || [];
  const utmPolicyMap = {};
  const utmProfiles = [];
  if (policies.length === 0) return { utmPolicyMap, utmProfiles };

  const utmTypes = ['virus', 'wildfire-analysis', 'url-filtering', 'file-blocking', 'email-filter',
    'application-control', 'dlp', 'dns-security', 'decryption', 'waf', 'casb', 'voip'];
  const comboMap = new Map();
  const securityFeatures = canonicalizeJunosSecurityFeatures(config);
  const featureUseLookup = new Map();
  for (const feature of securityFeatures) {
    for (const use of feature.uses) {
      featureUseLookup.set(`${use.policyIndex}\0${use.type}`, feature);
    }
  }

  for (let policyIndex = 0; policyIndex < policies.length; policyIndex += 1) {
    const policy = policies[policyIndex];
    const sp = policy.security_profiles || {};
    const utmP = {};
    for (const t of utmTypes) {
      if (sp[t]) utmP[t] = sp[t];
    }
    if (Object.keys(utmP).length === 0) continue;

    const key = JSON.stringify(utmP);
    if (!comboMap.has(key)) {
      comboMap.set(key, { profiles: utmP, policyIndexes: [] });
    }
    comboMap.get(key).policyIndexes.push(policyIndex);
  }

  const orderedCombos = [...comboMap.entries()].sort(([left], [right]) => left.localeCompare(right));
  for (const [, combo] of orderedCombos) {
    const ownerIndex = combo.policyIndexes[0];
    const policyName = identifierNames.generated(`security_policies[${ownerIndex}]`, 'utm-policy');
    const profiles = {};
    for (const [type, value] of Object.entries(combo.profiles)) {
      const feature = featureUseLookup.get(`${ownerIndex}\0${type}`);
      const mapped = mapProfileToSrx(type, value);
      if (mapped.srxFeature === 'unsupported' && type === 'file-blocking') {
        warnings.push(createWarning(
          'unsupported',
          `profile/${type}/${value}`,
          `File-blocking profile "${value}" is not supported in Junos SRX conversion`,
          'SRX does not have an equivalent file-blocking feature — review UTM content-filtering or ICAP for similar functionality',
        ));
      }
      profiles[type] = {
        mapped,
        feature,
        outputName: feature
          ? identifierNames.generated(`security_policies[${feature.ownerIndex}]`, feature.role)
          : mapped.srxProfile,
      };
      if (feature) {
        for (const policyIndex of combo.policyIndexes) {
          identifierNames.reference(`security_policies[${policyIndex}].security_profiles.${type}`);
        }
      }
    }
    utmProfiles.push({ policyName, profiles });
    for (const policyIndex of combo.policyIndexes) {
      utmPolicyMap[policyIndex] = identifierNames.reference(`security_policies[${policyIndex}]#utm-policy`);
    }
  }

  const defaults = policies
    .map((policy, policyIndex) => ({ policy, policyIndex }))
    .filter(({ policy }) => policy.profile_group && Object.keys(policy.security_profiles || {}).length === 0);
  if (defaults.length > 0) {
    const owner = [...defaults].sort((left, right) => (
      String(left.policy.name || '').localeCompare(String(right.policy.name || ''))
    ))[0];
    const policyName = identifierNames.generated(`security_policies[${owner.policyIndex}]`, 'default-utm-policy');
    utmProfiles.push({ policyName, profiles: {} });
    for (const { policyIndex } of defaults) {
      utmPolicyMap[policyIndex] = identifierNames.reference(`security_policies[${policyIndex}]#utm-policy`);
    }
  }
  return { utmPolicyMap, utmProfiles };
}

function computeIdpMap(policies, identifierNames) {
  const idpPolicyMap = {};
  const idpProfiles = [];
  if (!policies) return { idpPolicyMap, idpProfiles };

  const idpTypes = ['spyware', 'vulnerability'];
  const comboMap = new Map();
  for (let policyIndex = 0; policyIndex < policies.length; policyIndex += 1) {
    const policy = policies[policyIndex];
    const sp = policy.security_profiles || {};
    const hasIdp = idpTypes.some(t => sp[t]);
    if (!hasIdp) continue;

    const idpP = {};
    for (const t of idpTypes) {
      if (sp[t]) idpP[t] = sp[t];
    }
    const key = JSON.stringify(idpP);
    if (!comboMap.has(key)) {
      comboMap.set(key, { profiles: idpP, policyIndexes: [] });
    }
    comboMap.get(key).policyIndexes.push(policyIndex);
  }
  const orderedCombos = [...comboMap.entries()].sort(([left], [right]) => left.localeCompare(right));
  for (const [, combo] of orderedCombos) {
    const ownerIndex = combo.policyIndexes[0];
    const policyName = identifierNames.generated(`security_policies[${ownerIndex}]`, 'idp-policy');
    idpProfiles.push({ ...combo, ownerIndex, policyName });
    for (const policyIndex of combo.policyIndexes) {
      idpPolicyMap[policyIndex] = identifierNames.reference(`security_policies[${policyIndex}]#idp-policy`);
    }
  }
  return { idpPolicyMap, idpProfiles };
}

function buildUtmXml(utmProfiles, lines, identifierNames) {
  if (!utmProfiles || utmProfiles.length === 0) return;

  lines.push('    <utm>');

  // Feature profiles
  const emitted = new Set();
  lines.push('      <!-- NOTE: Generated profiles use recommended defaults — review and customize -->');
  lines.push('      <feature-profile>');
  for (const combo of utmProfiles) {
    for (const profile of Object.values(combo.profiles)) {
      const { mapped, outputName } = profile;
      if (mapped.srxFeature !== 'utm' || emitted.has(outputName)) continue;
      emitted.add(outputName);

      if (mapped.srxType === 'anti-virus') {
        lines.push('        <anti-virus>');
        lines.push(`          <profile>`);
        lines.push(`            <name>${xmlText(outputName)}</name>`);
        lines.push('            <fallback-options><default>log-and-permit</default><content-size>log-and-permit</content-size></fallback-options>');
        lines.push('            <scan-options><content-size-limit>20000</content-size-limit><timeout>180</timeout></scan-options>');
        lines.push('          </profile>');
        lines.push('        </anti-virus>');
      } else if (mapped.srxType === 'web-filtering') {
        lines.push('        <web-filtering>');
        lines.push(`          <profile>`);
        lines.push(`            <name>${xmlText(outputName)}</name>`);
        lines.push('            <type>juniper-enhanced</type>');
        lines.push('            <default>block</default>');
        lines.push('          </profile>');
        lines.push('        </web-filtering>');
      } else if (mapped.srxType === 'content-filtering') {
        lines.push('        <content-filtering>');
        lines.push(`          <profile>`);
        lines.push(`            <name>${xmlText(outputName)}</name>`);
        lines.push('          </profile>');
        lines.push('        </content-filtering>');
      } else if (mapped.srxType === 'anti-spam') {
        lines.push('        <anti-spam>');
        lines.push(`          <profile>`);
        lines.push(`            <name>${xmlText(outputName)}</name>`);
        lines.push('          </profile>');
        lines.push('        </anti-spam>');
      } else if (mapped.srxType === 'dns-security') {
        lines.push('        <dns-filtering>');
        lines.push(`          <rule><name>${xmlText(outputName)}</name></rule>`);
        lines.push('        </dns-filtering>');
      }
    }
  }
  lines.push('      </feature-profile>');

  const emittedAppFw = new Set();
  for (const combo of utmProfiles) {
    for (const profile of Object.values(combo.profiles)) {
      const { mapped, outputName, feature } = profile;
      if (mapped.srxFeature !== 'appfw' || !feature || emittedAppFw.has(outputName)) continue;
      emittedAppFw.add(outputName);
      lines.push('      <application-firewall>');
      lines.push('        <rule-sets>');
      lines.push(`          <name>${xmlText(outputName)}</name>`);
      for (let ruleIndex = 0; ruleIndex < feature.applicationFirewallRules.length; ruleIndex += 1) {
        const [category] = feature.applicationFirewallRules[ruleIndex];
        const ruleName = identifierNames.generated(
          `security_policies[${feature.ownerIndex}]`,
          `application-firewall-rule-${ruleIndex + 1}`,
        );
        lines.push('          <rule>');
        lines.push(`            <name>${xmlText(ruleName)}</name>`);
        lines.push(`            <match><dynamic-application-group>junos:${xmlText(category)}</dynamic-application-group></match>`);
        lines.push('            <then><deny/></then>');
        lines.push('          </rule>');
      }
      lines.push('        </rule-sets>');
      lines.push('      </application-firewall>');
    }
  }

  // UTM policies
  for (const combo of utmProfiles) {
    lines.push(`      <utm-policy name="${xmlAttribute(combo.policyName, 'utm.policyName')}">`);
    for (const profile of Object.values(combo.profiles)) {
      const { mapped, outputName } = profile;
      if (mapped.srxFeature !== 'utm') continue;
      if (mapped.srxType === 'anti-virus') {
        lines.push(`        <anti-virus><http-profile>${xmlText(outputName)}</http-profile></anti-virus>`);
      } else if (mapped.srxType === 'web-filtering') {
        lines.push(`        <web-filtering><http-profile>${xmlText(outputName)}</http-profile></web-filtering>`);
      } else if (mapped.srxType === 'content-filtering') {
        lines.push(`        <content-filtering><rule-set>${xmlText(outputName)}</rule-set></content-filtering>`);
      } else if (mapped.srxType === 'anti-spam') {
        lines.push(`        <anti-spam><smtp-profile>${xmlText(outputName)}</smtp-profile></anti-spam>`);
      }
    }
    lines.push('      </utm-policy>');
  }

  lines.push('    </utm>');
}

// ---------------------------------------------------------------------------
// IDP XML Builder
// ---------------------------------------------------------------------------

function buildIdpXml(config, lines, identifierNames) {
  const policies = config.security_policies || [];
  if (policies.length === 0) return;

  const idpTypes = ['spyware', 'vulnerability'];
  const comboMap = new Map();
  for (let policyIndex = 0; policyIndex < policies.length; policyIndex += 1) {
    const policy = policies[policyIndex];
    const sp = policy.security_profiles || {};
    const hasIdp = idpTypes.some(t => sp[t]);
    if (!hasIdp) continue;

    const idpP = {};
    for (const t of idpTypes) {
      if (sp[t]) idpP[t] = sp[t];
    }
    const key = JSON.stringify(idpP);
    if (!comboMap.has(key)) {
      comboMap.set(key, { profiles: idpP, policyIndexes: [] });
    }
    comboMap.get(key).policyIndexes.push(policyIndex);
  }

  if (comboMap.size === 0) return;

  lines.push('    <idp>');

  const orderedCombos = [...comboMap.entries()].sort(([left], [right]) => left.localeCompare(right));
  for (const [, combo] of orderedCombos) {
    const ownerIndex = combo.policyIndexes[0];
    const policyName = identifierNames.generated(`security_policies[${ownerIndex}]`, 'idp-policy');
    lines.push(`      <idp-policy>`);
    lines.push(`        <name>${xmlText(policyName)}</name>`);
    lines.push('        <rulebase-ips>');

    let ruleIdx = 0;
    for (const [pType, pValue] of Object.entries(combo.profiles)) {
      const definition = config.security_profile_definitions?.[`${pType}:${pValue}`];
      const severityActions = definition?.severityActions || {};
      const severities = ['critical', 'high', 'medium', 'low', 'info']
        .filter(severity => severityActions[severity]);
      const ruleParts = severities.length > 0 ? severities : [null];
      for (const severity of ruleParts) {
        ruleIdx += 1;
        const ruleName = identifierNames.generated(
          `security_policies[${ownerIndex}]`,
          `idp-rule-${ruleIdx}`,
        );
        const sourceAction = severity ? severityActions[severity] : null;
        const actionMap = {
          'reset-both': 'drop-connection', 'reset-client': 'drop-connection',
          'reset-server': 'drop-connection', drop: 'drop-packet', block: 'drop-connection',
          'block-all': 'drop-connection', alert: 'no-action', monitor: 'no-action',
          pass: 'no-action', default: 'recommended',
        };
        const nameLower = pValue.toLowerCase();
        const idpAction = sourceAction
          ? (actionMap[sourceAction] || 'recommended')
          : nameLower.includes('strict') || nameLower.includes('critical')
            ? 'drop-connection'
            : nameLower.includes('alert') || nameLower.includes('monitor')
              ? 'no-action' : 'recommended';
        const attackGroup = severity
          ? `${severity.charAt(0).toUpperCase()}${severity.slice(1)} - Recommended`
          : 'Recommended';

        lines.push('          <rule>');
        lines.push(`            <name>${xmlText(ruleName)}</name>`);
        lines.push('            <match>');
        lines.push('              <attacks>');
        lines.push(`                <predefined-attack-groups>${xmlText(attackGroup)}</predefined-attack-groups>`);
        lines.push('              </attacks>');
        lines.push('            </match>');
        lines.push('            <then>');
        const actionTag = xmlElementName(
          idpAction,
          ['recommended', 'drop-connection', 'drop-packet', 'no-action'],
          'security_profiles.idp.action',
        );
        const actionElement = {
          recommended: '<recommended/>',
          'drop-connection': '<drop-connection/>',
          'drop-packet': '<drop-packet/>',
          'no-action': '<no-action/>',
        }[actionTag];
        lines.push(`              <action>${actionElement}</action>`);
        lines.push('              <notification><log-attacks/></notification>');
        lines.push('            </then>');
        lines.push('          </rule>');
      }
    }

    lines.push('        </rulebase-ips>');
    lines.push('      </idp-policy>');
  }

  lines.push('    </idp>');
}

// ---------------------------------------------------------------------------
// SecIntel XML Builder
// ---------------------------------------------------------------------------

function buildSecIntelXml(externalLists, lines, identifierNames) {
  const blockLists = externalLists
    .map((list, index) => ({ list, index }))
    .filter(({ list }) => list.isBlockList)
    .sort((left, right) => String(left.list.name).localeCompare(String(right.list.name)));
  if (!blockLists || blockLists.length === 0) return;
  const ownerIndex = blockLists[0].index;
  const profileName = identifierNames.generated(`external_lists[${ownerIndex}]`, 'security-intelligence-profile');
  const policyName = identifierNames.generated(`external_lists[${ownerIndex}]`, 'security-intelligence-policy');

  lines.push('  <services>');
  lines.push('    <security-intelligence>');

  lines.push('      <profile>');
  lines.push(`        <name>${xmlText(profileName)}</name>`);
  lines.push('        <category>BlockList</category>');
  blockLists.forEach(({ index }) => {
    const ruleName = identifierNames.generated(`external_lists[${index}].name`, 'security-intelligence-rule');
    lines.push(`        <rule>`);
    lines.push(`          <name>${xmlText(ruleName)}</name>`);
    lines.push('          <match><threat-level>10</threat-level></match>');
    lines.push('          <then><action>block close</action><log/></then>');
    lines.push('        </rule>');
  });
  lines.push('      </profile>');

  lines.push('      <policy>');
  lines.push(`        <name>${xmlText(policyName)}</name>`);
  lines.push(`        <profile>${xmlText(profileName)}</profile>`);
  lines.push('      </policy>');

  lines.push('    </security-intelligence>');
  lines.push('  </services>');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Tracks unmapped apps for placeholder XML generation */
const xmlCustomfwicApps = new Map();

/** Names of generated placeholder apps with no Junos equivalent (policies using them are deactivated) */
const xmlUnmappedApps = new Set();

/** Tracks service objects that map to predefined Junos apps (XML path) */
const xmlPredefServiceMap = new Map();

function prepareXmlApplicationGroupApplications(groups, identifierNames) {
  for (let groupIndex = 0; groupIndex < (groups || []).length; groupIndex += 1) {
    const group = groups[groupIndex];
    for (let memberIndex = 0; memberIndex < (group.members || []).length; memberIndex += 1) {
      const member = group.members[memberIndex];
      if (member === 'service-set') continue;
      const path = `application_groups[${groupIndex}].members[${memberIndex}]`;
      identifierNames.reference(path);
      for (const entry of identifierNames.generatedEntries(path)) {
        const role = entry.definitionPath.slice(entry.definitionPath.lastIndexOf('#generated:') + 11);
        const generatedName = identifierNames.generated(path, role);
        xmlCustomfwicApps.set(generatedName, { originalName: member, kind: entry.kind });
        if (role === 'unmapped-application') xmlUnmappedApps.add(generatedName);
      }
    }
  }
}

function resolveApps(applications, services, warnings, policyName, appGroups = [], sourceVendor = '', policyIndex, identifierNames) {
  const resolved = [];
  const isSrxSource = sourceVendor === 'srx' || sourceVendor === 'greenfield' || sourceVendor === 'srx_healthcheck';

  // Helper to map a single app name to Junos (with Customfwic fallback)
  const mapSingleApp = (appName, path) => {
    if (appName === 'service-set') return;
    const outputName = identifierNames.reference(path);
    resolved.push(outputName);
    const junos = mapAppToJunos(appName, sourceVendor);
    for (const entry of identifierNames.generatedEntries(path)) {
      const role = entry.definitionPath.slice(entry.definitionPath.lastIndexOf('#generated:') + 11);
      const generatedName = identifierNames.generated(path, role);
      xmlCustomfwicApps.set(generatedName, { originalName: appName, kind: entry.kind });
      if (role === 'unmapped-application') xmlUnmappedApps.add(outputName);
    }
    if (!junos && !isSrxSource) {
      if (warnings) {
        warnings.push(createWarning(
          'warning',
          `policy/${policyName}`,
          `Application "${appName}" has no predefined Junos equivalent — using placeholder "${outputName}"`,
          'Create a custom application on the SRX with the correct protocol/port definition for this application'
        ));
      }
    }
  };

  if (applications && applications.length > 0) {
    for (let appIndex = 0; appIndex < applications.length; appIndex += 1) {
      const app = applications[appIndex];
      if (app === 'any') {
        resolved.push(identifierNames.reference(`security_policies[${policyIndex}].applications[${appIndex}]`));
        continue;
      }
      if (app === 'service-set') continue;

      // Check if this is an application group reference — expand to members
      const group = appGroups.find(g => g.name === app);
      if (group && group.members.length > 0) {
        for (let memberIndex = 0; memberIndex < group.members.length; memberIndex += 1) {
          mapSingleApp(
            group.members[memberIndex],
            `security_policies[${policyIndex}].applications[${appIndex}]#member:${memberIndex}`,
          );
        }
        continue;
      }

      mapSingleApp(app, `security_policies[${policyIndex}].applications[${appIndex}]`);
    }
  }
  if (services && services.length > 0) {
    for (let serviceIndex = 0; serviceIndex < services.length; serviceIndex += 1) {
      const svc = services[serviceIndex];
      if (svc === 'application-default' || svc === 'any' || svc === 'service-set') continue;
      resolved.push(identifierNames.reference(`security_policies[${policyIndex}].services[${serviceIndex}]`));
    }
  }
  if (resolved.includes('any')) return ['any'];
  if (resolved.length === 0) resolved.push('any');
  return [...new Set(resolved)];
}

// ---------------------------------------------------------------------------
// Static Routes XML Builder
// ---------------------------------------------------------------------------

function routingInstanceDefinitionPath(config, sourceName) {
  if (sourceName === 'default' || sourceName === 'master') return null;
  for (let index = 0; index < (config.static_routes || []).length; index += 1) {
    const route = config.static_routes[index];
    if (route.vrf === sourceName) return `static_routes[${index}].vrf`;
    if (route.next_hop_type === 'next-vr' && route.next_hop === sourceName) return `static_routes[${index}].next_hop`;
  }
  for (const field of ['bgp_config', 'ospf_config', 'ospf3_config', 'evpn_config', 'vxlan_config']) {
    for (let index = 0; index < (config[field] || []).length; index += 1) {
      if (config[field][index].instance === sourceName) return `${field}[${index}].instance`;
    }
  }
  return null;
}

function routingInstanceUseName(config, sourceName, localPath, identifierNames) {
  const definitionPath = routingInstanceDefinitionPath(config, sourceName);
  return definitionPath === localPath
    ? identifierNames.definition(localPath)
    : identifierNames.reference(localPath);
}

function buildAdditionalBgpBodyXml(bgp, bgpIndex, lines, indent, identifierNames) {
  for (let groupIndex = 0; groupIndex < (bgp.peer_groups || []).length; groupIndex += 1) {
    const group = bgp.peer_groups[groupIndex];
    lines.push(`${indent}<group>`);
    lines.push(`${indent}  <name>${xmlText(identifierNames.definition(`bgp_config[${bgpIndex}].peer_groups[${groupIndex}].name`))}</name>`);
    lines.push(`${indent}  <type>${xmlText(group.type || 'external')}</type>`);
    for (let neighborIndex = 0; neighborIndex < (group.neighbors || []).length; neighborIndex += 1) {
      const neighbor = group.neighbors[neighborIndex];
      lines.push(`${indent}  <neighbor>`);
      lines.push(`${indent}    <name>${xmlText(neighbor.address)}</name>`);
      if (neighbor.peer_as) lines.push(`${indent}    <peer-as>${neighbor.peer_as}</peer-as>`);
      if (neighbor.import_policy) {
        lines.push(`${indent}    <import>${xmlText(identifierNames.reference(`bgp_config[${bgpIndex}].peer_groups[${groupIndex}].neighbors[${neighborIndex}].import_policy`))}</import>`);
      }
      if (neighbor.export_policy) {
        lines.push(`${indent}    <export>${xmlText(identifierNames.reference(`bgp_config[${bgpIndex}].peer_groups[${groupIndex}].neighbors[${neighborIndex}].export_policy`))}</export>`);
      }
      lines.push(`${indent}  </neighbor>`);
    }
    if (groupIndex === 0) {
      for (let networkIndex = 0; networkIndex < (bgp.networks || []).length; networkIndex += 1) {
        if (bgp.networks[networkIndex].policy) {
          lines.push(`${indent}  <export>${xmlText(identifierNames.reference(`bgp_config[${bgpIndex}].networks[${networkIndex}].policy`))}</export>`);
        }
      }
    }
    lines.push(`${indent}</group>`);
  }
  const needsDefaultGroup = (bgp.networks || []).some(network => network.policy)
    && !bgp.peer_groups?.[0]?.name;
  if (needsDefaultGroup) {
    const groupName = identifierNames.generated(`bgp_config[${bgpIndex}]`, 'default-bgp-group');
    identifierNames.reference(`bgp_config[${bgpIndex}]#default-bgp-group`);
    lines.push(`${indent}<group>`);
    lines.push(`${indent}  <name>${xmlText(groupName)}</name>`);
    for (let networkIndex = 0; networkIndex < (bgp.networks || []).length; networkIndex += 1) {
      if (bgp.networks[networkIndex].policy) {
        lines.push(`${indent}  <export>${xmlText(identifierNames.reference(`bgp_config[${bgpIndex}].networks[${networkIndex}].policy`))}</export>`);
      }
    }
    lines.push(`${indent}</group>`);
  }
  for (let redistIndex = 0; redistIndex < (bgp.redistribute || []).length; redistIndex += 1) {
    const policyName = identifierNames.generated(
      `bgp_config[${bgpIndex}].redistribute[${redistIndex}]`,
      'bgp-redistribution-policy',
    );
    lines.push(`${indent}<export>${xmlText(policyName)}</export>`);
  }
}

function buildOspfRecordXml(ospf, ospfIndex, field, lines, indent, identifierNames) {
  const protocol = field === 'ospf3_config' ? 'ospf3' : 'ospf';
  const role = protocol === 'ospf3'
    ? 'ospf3-redistribution-policy'
    : 'ospf-redistribution-policy';
  lines.push(`${indent}<${protocol}>`);
  if (ospf.reference_bandwidth) {
    lines.push(`${indent}  <reference-bandwidth>${xmlText(String(ospf.reference_bandwidth))}</reference-bandwidth>`);
  }
  for (const area of ospf.areas || []) {
    lines.push(`${indent}  <area>`);
    lines.push(`${indent}    <name>${xmlText(area.area_id)}</name>`);
    if (area.area_type === 'stub' || area.area_type === 'totally-stub') {
      lines.push(`${indent}    <stub>`);
      if (area.area_type === 'totally-stub') lines.push(`${indent}      <no-summaries/>`);
      lines.push(`${indent}    </stub>`);
    } else if (area.area_type === 'nssa' || area.area_type === 'totally-nssa') {
      lines.push(`${indent}    <nssa>`);
      if (area.area_type === 'totally-nssa') lines.push(`${indent}      <no-summaries/>`);
      lines.push(`${indent}    </nssa>`);
    }
    for (const iface of area.interfaces || []) {
      lines.push(`${indent}    <interface>`);
      lines.push(`${indent}      <name>${xmlText(iface.name)}</name>`);
      if (iface.cost != null) lines.push(`${indent}      <metric>${iface.cost}</metric>`);
      if (iface.hello_interval != null) lines.push(`${indent}      <hello-interval>${iface.hello_interval}</hello-interval>`);
      if (iface.dead_interval != null) lines.push(`${indent}      <dead-interval>${iface.dead_interval}</dead-interval>`);
      if (iface.passive) lines.push(`${indent}      <passive/>`);
      if (iface.network_type) lines.push(`${indent}      <interface-type>${xmlText(iface.network_type)}</interface-type>`);
      if (protocol === 'ospf3' && iface.instance_id != null) {
        lines.push(`${indent}      <instance-id>${iface.instance_id}</instance-id>`);
      }
      if (protocol === 'ospf' && iface.authentication) {
        lines.push(`${indent}      <authentication>`);
        if (iface.authentication.type === 'md5') {
          lines.push(`${indent}        <md5>`);
          lines.push(`${indent}          <name>${iface.authentication.key_id || 1}</name>`);
          lines.push(`${indent}          <key>${xmlText(iface.authentication.key || '')}</key>`);
          lines.push(`${indent}        </md5>`);
        } else if (iface.authentication.type === 'simple') {
          lines.push(`${indent}        <simple-password>${xmlText(iface.authentication.key || '')}</simple-password>`);
        }
        lines.push(`${indent}      </authentication>`);
      }
      lines.push(`${indent}    </interface>`);
    }
    lines.push(`${indent}  </area>`);
  }
  for (let redistIndex = 0; redistIndex < (ospf.redistribute || []).length; redistIndex += 1) {
    const policyName = identifierNames.generated(
      `${field}[${ospfIndex}].redistribute[${redistIndex}]`, role,
    );
    lines.push(`${indent}  <export>${xmlText(policyName)}</export>`);
  }
  lines.push(`${indent}</${protocol}>`);
}

function buildRoutingXml(config, lines, identifierNames) {
  const routes = config.static_routes || [];
  const bgpConfigs = config.bgp_config || [];
  const ospfConfigs = config.ospf_config || [];
  const ospf3Configs = config.ospf3_config || [];
  const evpnConfigs = config.evpn_config || [];
  const vxlanConfigs = config.vxlan_config || [];

  for (let routeIndex = 0; routeIndex < routes.length; routeIndex += 1) {
    const route = routes[routeIndex];
    if (route.vrf) {
      routingInstanceUseName(config, route.vrf, `static_routes[${routeIndex}].vrf`, identifierNames);
    }
    if (route.next_hop_type === 'next-vr' && route.next_hop) {
      routingInstanceUseName(config, route.next_hop, `static_routes[${routeIndex}].next_hop`, identifierNames);
    }
  }
  for (const field of ['bgp_config', 'ospf_config', 'ospf3_config', 'evpn_config', 'vxlan_config']) {
    for (let configIndex = 0; configIndex < (config[field] || []).length; configIndex += 1) {
      const item = config[field][configIndex];
      if (item.instance) {
        routingInstanceUseName(config, item.instance, `${field}[${configIndex}].instance`, identifierNames);
      }
    }
  }

  const globalRoutes = routes.filter(r => !r.vrf || ['default', 'master'].includes(r.vrf));
  const vrfGroups = {};
  for (const r of routes.filter(r => r.vrf && !['default', 'master'].includes(r.vrf))) {
    if (!vrfGroups[r.vrf]) vrfGroups[r.vrf] = [];
    vrfGroups[r.vrf].push(r);
  }

  // Find global BGP/OSPF/OSPFv3/EVPN (instance === '')
  const globalBgp = bgpConfigs.find(b => !b.instance);
  const globalBgpIndex = bgpConfigs.indexOf(globalBgp);
  const globalOspfs = ospfConfigs.filter(o => !o.instance);
  const globalOspf3s = ospf3Configs.filter(o => !o.instance);
  const globalOspf = globalOspfs[0];
  const globalEvpn = evpnConfigs.find(e => !e.instance);

  const hasGlobalRoutingOpts = globalRoutes.length > 0 || globalBgp;
  const hasGlobalProtocols = globalBgp || globalOspfs.length > 0 || globalOspf3s.length > 0 || globalEvpn;

  // Global routing-options (static routes + BGP AS/router-id)
  if (hasGlobalRoutingOpts) {
    lines.push('  <routing-options>');

    // Autonomous system and router-id from BGP
    if (globalBgp) {
      if (globalBgp.local_as) {
        lines.push('    <autonomous-system>');
        lines.push(`      <as-number>${globalBgp.local_as}</as-number>`);
        lines.push('    </autonomous-system>');
      }
      if (globalBgp.router_id) {
        lines.push(`    <router-id>${xmlText(globalBgp.router_id)}</router-id>`);
      }
    } else if (globalOspf?.router_id) {
      lines.push(`    <router-id>${xmlText(globalOspf.router_id)}</router-id>`);
    }

    // Static routes
    if (globalRoutes.length > 0) {
      lines.push('    <static>');
      for (const route of globalRoutes) {
        const routeIndex = routes.indexOf(route);
        lines.push('      <route>');
        lines.push(`        <name>${xmlText(route.destination)}</name>`);
        if (route.next_hop_type === 'discard') {
          lines.push('        <discard/>');
        } else if (route.next_hop_type === 'next-vr' && route.next_hop) {
          const instance = routingInstanceUseName(
            config, route.next_hop, `static_routes[${routeIndex}].next_hop`, identifierNames,
          );
          lines.push(`        <next-table>${xmlText(instance)}.inet.0</next-table>`);
        } else if (route.next_hop) {
          lines.push(`        <next-hop>${xmlText(route.next_hop)}</next-hop>`);
        }
        if (route.metric && route.metric !== 10) {
          lines.push(`        <metric>${route.metric}</metric>`);
        }
        lines.push('      </route>');
      }
      lines.push('    </static>');
    }

    lines.push('  </routing-options>');
  }

  // Global protocols (BGP + OSPF)
  if (hasGlobalProtocols) {
    lines.push('  <protocols>');

    // BGP
    if (globalBgp) {
      lines.push('    <bgp>');
      for (let groupIndex = 0; groupIndex < (globalBgp.peer_groups || []).length; groupIndex += 1) {
        const group = globalBgp.peer_groups[groupIndex];
        lines.push('      <group>');
        lines.push(`        <name>${xmlText(identifierNames.definition(`bgp_config[${globalBgpIndex}].peer_groups[${groupIndex}].name`))}</name>`);
        lines.push(`        <type>${xmlText(group.type || 'external')}</type>`);
        for (let neighborIndex = 0; neighborIndex < (group.neighbors || []).length; neighborIndex += 1) {
          const neighbor = group.neighbors[neighborIndex];
          lines.push('        <neighbor>');
          lines.push(`          <name>${xmlText(neighbor.address)}</name>`);
          if (neighbor.peer_as) {
            lines.push(`          <peer-as>${neighbor.peer_as}</peer-as>`);
          }
          if (neighbor.description) {
            lines.push(`          <description>${xmlText(neighbor.description)}</description>`);
          }
          if (neighbor.local_address) {
            lines.push(`          <local-address>${xmlText(neighbor.local_address)}</local-address>`);
          }
          if (neighbor.import_policy) {
            lines.push(`          <import>${xmlText(identifierNames.reference(`bgp_config[${globalBgpIndex}].peer_groups[${groupIndex}].neighbors[${neighborIndex}].import_policy`))}</import>`);
          }
          if (neighbor.export_policy) {
            lines.push(`          <export>${xmlText(identifierNames.reference(`bgp_config[${globalBgpIndex}].peer_groups[${groupIndex}].neighbors[${neighborIndex}].export_policy`))}</export>`);
          }
          if (neighbor.authentication_key) {
            lines.push(`          <authentication-key>${xmlText(neighbor.authentication_key)}</authentication-key>`);
          }
          lines.push('        </neighbor>');
        }
        if (groupIndex === 0) {
          for (let networkIndex = 0; networkIndex < (globalBgp.networks || []).length; networkIndex += 1) {
            if (globalBgp.networks[networkIndex].policy) {
              lines.push(`        <export>${xmlText(identifierNames.reference(`bgp_config[${globalBgpIndex}].networks[${networkIndex}].policy`))}</export>`);
            }
          }
        }
        lines.push('      </group>');
      }
      const needsDefaultGroup = (globalBgp.networks || []).some(network => network.policy)
        && !globalBgp.peer_groups?.[0]?.name;
      if (needsDefaultGroup) {
        const groupName = identifierNames.generated(`bgp_config[${globalBgpIndex}]`, 'default-bgp-group');
        lines.push('      <group>');
        lines.push(`        <name>${xmlText(groupName)}</name>`);
        for (let networkIndex = 0; networkIndex < (globalBgp.networks || []).length; networkIndex += 1) {
          const network = globalBgp.networks[networkIndex];
          if (network.policy) {
            lines.push(`        <export>${xmlText(identifierNames.reference(`bgp_config[${globalBgpIndex}].networks[${networkIndex}].policy`))}</export>`);
          }
        }
        lines.push('      </group>');
        identifierNames.reference(`bgp_config[${globalBgpIndex}]#default-bgp-group`);
      }
      lines.push('    </bgp>');
    }

    for (const ospf of globalOspfs) {
      buildOspfRecordXml(
        ospf, ospfConfigs.indexOf(ospf), 'ospf_config', lines, '    ', identifierNames,
      );
    }
    for (const ospf3 of globalOspf3s) {
      buildOspfRecordXml(
        ospf3, ospf3Configs.indexOf(ospf3), 'ospf3_config', lines, '    ', identifierNames,
      );
    }

    // EVPN
    if (globalEvpn) {
      lines.push('    <evpn>');
      lines.push(`      <encapsulation>${xmlText(globalEvpn.encapsulation || 'vxlan')}</encapsulation>`);
      if (globalEvpn.multicast_mode) {
        lines.push(`      <multicast-mode>${xmlText(globalEvpn.multicast_mode)}</multicast-mode>`);
      }
      if (globalEvpn.extended_vni_list && globalEvpn.extended_vni_list.length > 0) {
        for (const vni of globalEvpn.extended_vni_list) {
          lines.push(`      <extended-vni-list>${vni}</extended-vni-list>`);
        }
      }
      lines.push('    </evpn>');
    }

    lines.push('  </protocols>');
  }

  // Switch-options (for EVPN/VxLAN — vtep-source-interface, route-distinguisher, vrf-target)
  if (globalEvpn && globalEvpn.route_distinguisher) {
    lines.push('  <switch-options>');
    lines.push(`    <vtep-source-interface>${xmlText(globalEvpn.vtep_source_interface || 'lo0.0')}</vtep-source-interface>`);
    lines.push(`    <route-distinguisher>`);
    lines.push(`      <rd-type>${xmlText(globalEvpn.route_distinguisher)}</rd-type>`);
    lines.push(`    </route-distinguisher>`);
    if (globalEvpn.vrf_target) {
      lines.push(`    <vrf-target>`);
      lines.push(`      <community>${xmlText(globalEvpn.vrf_target)}</community>`);
      lines.push(`    </vrf-target>`);
    }
    lines.push('  </switch-options>');
  }

  // VLANs (for EVPN VxLAN VNI mappings)
  const allVlans = [
    ...evpnConfigs.flatMap((evpn, evpnIndex) => (
      (evpn.vlans || []).map((vlan, vlanIndex) => ({ vlan, evpnIndex, vlanIndex, source: 'evpn' }))
    )),
    ...vxlanConfigs.flatMap((vxlan, vxlanIndex) => (
      (vxlan.vnis || []).map((vlan, vlanIndex) => ({ vlan, vxlanIndex, vlanIndex, source: 'vxlan' }))
        .filter(({ vlan }) => vlan.vlan_id)
    )),
  ];
  if (allVlans.length > 0) {
    lines.push('  <vlans>');
    for (const { vlan, evpnIndex, vxlanIndex, vlanIndex, source } of allVlans) {
      const vlanName = source === 'evpn'
        ? identifierNames.definition(`evpn_config[${evpnIndex}].vlans[${vlanIndex}].name`)
        : identifierNames.generated(`vxlan_config[${vxlanIndex}].vnis[${vlanIndex}]`, 'vxlan-vlan');
      lines.push(`    <vlan>`);
      lines.push(`      <name>${xmlText(vlanName)}</name>`);
      lines.push(`      <vlan-id>${vlan.vlan_id}</vlan-id>`);
      lines.push('      <vxlan>');
      lines.push(`        <vni>${vlan.vni}</vni>`);
      if (vlan.ingress_node_replication) {
        lines.push('        <ingress-node-replication/>');
      }
      lines.push('      </vxlan>');
      lines.push('    </vlan>');
    }
    lines.push('  </vlans>');
  }

  // Routing instances (VRFs — static routes + per-instance BGP/OSPF/OSPFv3/EVPN)
  const instBgpMap = {};
  const instOspfMap = {};
  const instOspf3Map = {};
  const instEvpnMap = {};
  for (const b of bgpConfigs.filter(b => b.instance)) instBgpMap[b.instance] = b;
  for (const o of ospfConfigs.filter(o => o.instance)) {
    if (!instOspfMap[o.instance]) instOspfMap[o.instance] = [];
    instOspfMap[o.instance].push(o);
  }
  for (const o of ospf3Configs.filter(o => o.instance)) {
    if (!instOspf3Map[o.instance]) instOspf3Map[o.instance] = [];
    instOspf3Map[o.instance].push(o);
  }
  for (const e of evpnConfigs.filter(e => e.instance)) instEvpnMap[e.instance] = e;

  const allInstNames = new Set([
    ...Object.keys(vrfGroups),
    ...Object.keys(instBgpMap),
    ...Object.keys(instOspfMap),
    ...Object.keys(instOspf3Map),
    ...Object.keys(instEvpnMap),
  ]);
  allInstNames.delete('default');
  allInstNames.delete('master');

  if (allInstNames.size > 0) {
    lines.push('  <routing-instances>');
    for (const instName of allInstNames) {
      const definitionPath = routingInstanceDefinitionPath(config, instName);
      const name = identifierNames.definition(definitionPath);
      const instRoutes = vrfGroups[instName] || [];
      const instBgp = instBgpMap[instName];
      const instOspfs = instOspfMap[instName] || [];
      const instOspf3s = instOspf3Map[instName] || [];
      const instOspf = instOspfs[0];
      const instEvpn = instEvpnMap[instName];

      lines.push('    <instance>');
      lines.push(`      <name>${xmlText(name)}</name>`);
      const instType = instEvpn?.instance_type || 'virtual-router';
      lines.push(`      <instance-type>${xmlText(instType)}</instance-type>`);

      // Routing-options (static + BGP AS/router-id)
      if (instRoutes.length > 0 || instBgp) {
        lines.push('      <routing-options>');
        if (instBgp?.local_as) {
          lines.push('        <autonomous-system>');
          lines.push(`          <as-number>${instBgp.local_as}</as-number>`);
          lines.push('        </autonomous-system>');
        }
        if (instBgp?.router_id || instOspf?.router_id) {
          lines.push(`        <router-id>${xmlText(instBgp?.router_id || instOspf?.router_id)}</router-id>`);
        }
        if (instRoutes.length > 0) {
          lines.push('        <static>');
          for (const route of instRoutes) {
            lines.push('          <route>');
            lines.push(`            <name>${xmlText(route.destination)}</name>`);
            if (route.next_hop_type === 'discard') {
              lines.push('            <discard/>');
            } else if (route.next_hop) {
              lines.push(`            <next-hop>${xmlText(route.next_hop)}</next-hop>`);
            }
            lines.push('          </route>');
          }
          lines.push('        </static>');
        }
        lines.push('      </routing-options>');
      }

      // Protocols (BGP + OSPF + OSPFv3 + EVPN)
      if (instBgp || instOspfs.length > 0 || instOspf3s.length > 0 || instEvpn) {
        lines.push('      <protocols>');
        if (instBgp) {
          lines.push('        <bgp>');
          const bgpIndex = bgpConfigs.indexOf(instBgp);
          for (let groupIndex = 0; groupIndex < (instBgp.peer_groups || []).length; groupIndex += 1) {
            const group = instBgp.peer_groups[groupIndex];
            lines.push('          <group>');
            lines.push(`            <name>${xmlText(identifierNames.definition(`bgp_config[${bgpIndex}].peer_groups[${groupIndex}].name`))}</name>`);
            lines.push(`            <type>${xmlText(group.type || 'external')}</type>`);
            for (let neighborIndex = 0; neighborIndex < (group.neighbors || []).length; neighborIndex += 1) {
              const neighbor = group.neighbors[neighborIndex];
              lines.push('            <neighbor>');
              lines.push(`              <name>${xmlText(neighbor.address)}</name>`);
              if (neighbor.peer_as) lines.push(`              <peer-as>${neighbor.peer_as}</peer-as>`);
              if (neighbor.description) lines.push(`              <description>${xmlText(neighbor.description)}</description>`);
              if (neighbor.import_policy) {
                lines.push(`              <import>${xmlText(identifierNames.reference(`bgp_config[${bgpIndex}].peer_groups[${groupIndex}].neighbors[${neighborIndex}].import_policy`))}</import>`);
              }
              if (neighbor.export_policy) {
                lines.push(`              <export>${xmlText(identifierNames.reference(`bgp_config[${bgpIndex}].peer_groups[${groupIndex}].neighbors[${neighborIndex}].export_policy`))}</export>`);
              }
              lines.push('            </neighbor>');
            }
            if (groupIndex === 0) {
              for (let networkIndex = 0; networkIndex < (instBgp.networks || []).length; networkIndex += 1) {
                if (instBgp.networks[networkIndex].policy) {
                  lines.push(`            <export>${xmlText(identifierNames.reference(`bgp_config[${bgpIndex}].networks[${networkIndex}].policy`))}</export>`);
                }
              }
            }
            lines.push('          </group>');
          }
          const needsDefaultGroup = (instBgp.networks || []).some(network => network.policy)
            && !instBgp.peer_groups?.[0]?.name;
          if (needsDefaultGroup) {
            const groupName = identifierNames.generated(`bgp_config[${bgpIndex}]`, 'default-bgp-group');
            identifierNames.reference(`bgp_config[${bgpIndex}]#default-bgp-group`);
            lines.push('          <group>');
            lines.push(`            <name>${xmlText(groupName)}</name>`);
            for (let networkIndex = 0; networkIndex < (instBgp.networks || []).length; networkIndex += 1) {
              if (instBgp.networks[networkIndex].policy) {
                lines.push(`            <export>${xmlText(identifierNames.reference(`bgp_config[${bgpIndex}].networks[${networkIndex}].policy`))}</export>`);
              }
            }
            lines.push('          </group>');
          }
          for (let redistIndex = 0; redistIndex < (instBgp.redistribute || []).length; redistIndex += 1) {
            const policyName = identifierNames.generated(
              `bgp_config[${bgpIndex}].redistribute[${redistIndex}]`,
              'bgp-redistribution-policy',
            );
            lines.push(`          <export>${xmlText(policyName)}</export>`);
          }
          lines.push('        </bgp>');
        }
        for (let extraIndex = 0; extraIndex < bgpConfigs.length; extraIndex += 1) {
          const extraBgp = bgpConfigs[extraIndex];
          if (extraBgp === instBgp || extraBgp.instance !== instName) continue;
          lines.push('        <bgp>');
          buildAdditionalBgpBodyXml(extraBgp, extraIndex, lines, '          ', identifierNames);
          lines.push('        </bgp>');
        }
        for (const ospf of instOspfs) {
          buildOspfRecordXml(
            ospf, ospfConfigs.indexOf(ospf), 'ospf_config', lines, '        ', identifierNames,
          );
        }
        for (const ospf3 of instOspf3s) {
          buildOspfRecordXml(
            ospf3, ospf3Configs.indexOf(ospf3), 'ospf3_config', lines, '        ', identifierNames,
          );
        }
        if (instEvpn) {
          lines.push('        <evpn>');
          lines.push(`          <encapsulation>${xmlText(instEvpn.encapsulation || 'vxlan')}</encapsulation>`);
          if (instEvpn.multicast_mode) {
            lines.push(`          <multicast-mode>${xmlText(instEvpn.multicast_mode)}</multicast-mode>`);
          }
          lines.push('        </evpn>');
        }
        lines.push('      </protocols>');
      }

      const instancePolicies = [];
      for (const [field, role] of [
        ['bgp_config', 'bgp-redistribution-policy'],
        ['ospf_config', 'ospf-redistribution-policy'],
        ['ospf3_config', 'ospf3-redistribution-policy'],
      ]) {
        for (let itemIndex = 0; itemIndex < (config[field] || []).length; itemIndex += 1) {
          const item = config[field][itemIndex];
          if (item.instance !== instName) continue;
          for (let redistIndex = 0; redistIndex < (item.redistribute || []).length; redistIndex += 1) {
            instancePolicies.push(identifierNames.generated(
              `${field}[${itemIndex}].redistribute[${redistIndex}]`, role,
            ));
          }
        }
      }
      if (instancePolicies.length > 0) {
        lines.push('      <policy-options>');
        for (const policyName of instancePolicies) {
          lines.push(`        <policy-statement><name>${xmlText(policyName)}</name><then><accept/></then></policy-statement>`);
        }
        lines.push('      </policy-options>');
      }

      lines.push('    </instance>');
    }
    lines.push('  </routing-instances>');
  }

  const additionalGlobalBgp = [];
  for (let bgpIndex = 0; bgpIndex < bgpConfigs.length; bgpIndex += 1) {
    const bgp = bgpConfigs[bgpIndex];
    if (bgp === globalBgp || bgp.instance) continue;
    additionalGlobalBgp.push({ bgp, bgpIndex });
  }
  if (additionalGlobalBgp.length > 0) {
    lines.push('  <protocols><bgp>');
    for (const { bgp, bgpIndex } of additionalGlobalBgp) {
      buildAdditionalBgpBodyXml(bgp, bgpIndex, lines, '    ', identifierNames);
    }
    lines.push('  </bgp></protocols>');
  }

  const redistributionPolicies = [];
  for (let bgpIndex = 0; bgpIndex < bgpConfigs.length; bgpIndex += 1) {
    if (bgpConfigs[bgpIndex].instance) continue;
    for (let redistIndex = 0; redistIndex < (bgpConfigs[bgpIndex].redistribute || []).length; redistIndex += 1) {
      redistributionPolicies.push(identifierNames.generated(
        `bgp_config[${bgpIndex}].redistribute[${redistIndex}]`,
        'bgp-redistribution-policy',
      ));
    }
  }
  for (const [field, role] of [['ospf_config', 'ospf-redistribution-policy'], ['ospf3_config', 'ospf3-redistribution-policy']]) {
    for (let configIndex = 0; configIndex < (config[field] || []).length; configIndex += 1) {
      if (config[field][configIndex].instance) continue;
      for (let redistIndex = 0; redistIndex < (config[field][configIndex].redistribute || []).length; redistIndex += 1) {
        redistributionPolicies.push(identifierNames.generated(
          `${field}[${configIndex}].redistribute[${redistIndex}]`, role,
        ));
      }
    }
  }
  if (redistributionPolicies.length > 0) {
    lines.push('  <policy-options>');
    for (const policyName of redistributionPolicies) {
      lines.push(`    <policy-statement><name>${xmlText(policyName)}</name><then><accept/></then></policy-statement>`);
    }
    lines.push('  </policy-options>');
  }
}

function buildVpnXml(tunnels, lines, identifierNames) {
  if (!tunnels || tunnels.length === 0) return;

  // IKE section
  lines.push('  <security>');
  lines.push('    <ike>');

  const emittedProposals = new Set();
  for (let vpnIndex = 0; vpnIndex < tunnels.length; vpnIndex += 1) {
    const vpn = tunnels[vpnIndex];
    const ownerPath = `vpn_tunnels[${vpnIndex}]`;
    const ikeProposalName = vpn.ike_proposal?.name
      ? identifierNames.definition(`${ownerPath}.ike_proposal.name`)
      : identifierNames.generated(ownerPath, 'ike-proposal');
    const ikeProposal = vpn.ike_proposal || {};
    // IKE proposal
    if (!emittedProposals.has(ikeProposalName)) {
      emittedProposals.add(ikeProposalName);
      lines.push('      <proposal>');
      lines.push(`        <name>${xmlText(ikeProposalName)}</name>`);
      lines.push(`        <authentication-method>${ikeProposal.auth_method || 'pre-shared-keys'}</authentication-method>`);
      lines.push(`        <dh-group>${ikeProposal.dh_group || 'group14'}</dh-group>`);
      lines.push(`        <encryption-algorithm>${ikeProposal.encryption || 'aes-256-cbc'}</encryption-algorithm>`);
      lines.push(`        <authentication-algorithm>${ikeProposal.authentication || 'sha-256'}</authentication-algorithm>`);
      if (ikeProposal.lifetime) lines.push(`        <lifetime-seconds>${ikeProposal.lifetime}</lifetime-seconds>`);
      lines.push('      </proposal>');
    }

    // IKE gateway
    const gwName = vpn.ike_gateway?.name
      ? identifierNames.definition(`${ownerPath}.ike_gateway.name`)
      : identifierNames.generated(ownerPath, 'ike-gateway');
    const ikePolicyName = identifierNames.generated(ownerPath, 'ike-policy');
    const ikeProposalReference = identifierNames.reference(`${ownerPath}.ike_proposal.name`);
    lines.push('      <policy>');
    lines.push(`        <name>${xmlText(ikePolicyName)}</name>`);
    lines.push(`        <proposals>${xmlText(ikeProposalReference)}</proposals>`);
    lines.push('      </policy>');
    lines.push('      <gateway>');
    lines.push(`        <name>${xmlText(gwName)}</name>`);
    if (vpn.ike_gateway?.address) lines.push(`        <address>${vpn.ike_gateway.address}</address>`);
    lines.push(`        <ike-policy>${xmlText(identifierNames.reference(`${ownerPath}.name#ike-policy`))}</ike-policy>`);
    if (vpn.ike_gateway?.ike_version === 'v2') lines.push('        <version>v2-only</version>');
    lines.push('      </gateway>');
  }
  lines.push('    </ike>');

  // IPsec section
  lines.push('    <ipsec>');
  const emittedIpsec = new Set();
  for (let vpnIndex = 0; vpnIndex < tunnels.length; vpnIndex += 1) {
    const vpn = tunnels[vpnIndex];
    const ownerPath = `vpn_tunnels[${vpnIndex}]`;
    const ipsecProposalName = vpn.ipsec_proposal?.name
      ? identifierNames.definition(`${ownerPath}.ipsec_proposal.name`)
      : identifierNames.generated(ownerPath, 'ipsec-proposal');
    const ipsecProposal = vpn.ipsec_proposal || {};
    if (!emittedIpsec.has(ipsecProposalName)) {
      emittedIpsec.add(ipsecProposalName);
      lines.push('      <proposal>');
      lines.push(`        <name>${xmlText(ipsecProposalName)}</name>`);
      lines.push(`        <protocol>${ipsecProposal.protocol || 'esp'}</protocol>`);
      lines.push(`        <encryption-algorithm>${ipsecProposal.encryption || 'aes-256-cbc'}</encryption-algorithm>`);
      lines.push(`        <authentication-algorithm>${ipsecProposal.authentication || 'hmac-sha-256-128'}</authentication-algorithm>`);
      if (ipsecProposal.lifetime) lines.push(`        <lifetime-seconds>${ipsecProposal.lifetime}</lifetime-seconds>`);
      lines.push('      </proposal>');
    }

    const ipsecPolicyName = identifierNames.generated(ownerPath, 'ipsec-policy');
    lines.push('      <policy>');
    lines.push(`        <name>${xmlText(ipsecPolicyName)}</name>`);
    lines.push(`        <proposals>${xmlText(identifierNames.reference(`${ownerPath}.ipsec_proposal.name`))}</proposals>`);
    lines.push('      </policy>');

    // VPN definition
    const vpnName = vpn.name
      ? identifierNames.definition(`${ownerPath}.name`)
      : identifierNames.generated(ownerPath, 'ipsec-vpn');
    lines.push('      <vpn>');
    lines.push(`        <name>${xmlText(vpnName)}</name>`);
    lines.push(`        <ike><gateway>${xmlText(identifierNames.reference(`${ownerPath}.ike_gateway.name`))}</gateway></ike>`);
    lines.push(`        <ipsec-policy>${xmlText(identifierNames.reference(`${ownerPath}.name#ipsec-policy`))}</ipsec-policy>`);
    if (vpn.tunnel_interface) {
      const bindIf = vpn.tunnel_interface.startsWith('st0') ? vpn.tunnel_interface : 'st0.0';
      lines.push(`        <bind-interface>${bindIf}</bind-interface>`);
    }
    if (vpn.proxy_id && vpn.proxy_id.length > 0) {
      for (let i = 0; i < vpn.proxy_id.length; i++) {
        const selectorPath = `${ownerPath}.proxy_id[${i}]`;
        const selectorName = identifierNames.generated(selectorPath, 'vpn-traffic-selector');
        identifierNames.reference(`${selectorPath}#traffic-selector`);
        lines.push(`        <traffic-selector><name>${xmlText(selectorName)}</name>`);
        if (vpn.proxy_id[i].local) lines.push(`          <local-ip>${vpn.proxy_id[i].local}</local-ip>`);
        if (vpn.proxy_id[i].remote) lines.push(`          <remote-ip>${vpn.proxy_id[i].remote}</remote-ip>`);
        lines.push('        </traffic-selector>');
      }
    }
    lines.push('      </vpn>');
  }
  lines.push('    </ipsec>');
  lines.push('  </security>');
}

function buildScreenXml(screens, lines, identifierNames) {
  if (!screens || screens.length === 0) return;

  // Screen definitions go inside <security><screen>
  lines.push('  <security>');
  lines.push('    <screen>');

  const zoneAssignments = [];
  for (let screenIndex = 0; screenIndex < screens.length; screenIndex += 1) {
    const screen = screens[screenIndex];
    const name = screen.name
      ? identifierNames.definition(`screen_config[${screenIndex}].name`)
      : identifierNames.generated(`screen_config[${screenIndex}]`, 'default-screen-profile');
    if (screen.zone) {
      zoneAssignments.push({
        profileName: name,
        zoneName: identifierNames.reference(`screen_config[${screenIndex}].zone`),
      });
    }
    lines.push('      <ids-option>');
    lines.push(`        <name>${xmlText(name)}</name>`);

    // ICMP
    if (screen.icmp && (screen.icmp.ping_death || screen.icmp.flood_threshold)) {
      lines.push('        <icmp>');
      if (screen.icmp.ping_death) lines.push('          <ping-death/>');
      if (screen.icmp.flood_threshold) lines.push(`          <flood><threshold>${screen.icmp.flood_threshold}</threshold></flood>`);
      lines.push('        </icmp>');
    }

    // TCP
    if (screen.tcp) {
      const hasTcp = screen.tcp.syn_flood_threshold || screen.tcp.land_attack || screen.tcp.winnuke || screen.tcp.tcp_no_flag;
      if (hasTcp) {
        lines.push('        <tcp>');
        if (screen.tcp.syn_flood_threshold) {
          lines.push('          <syn-flood>');
          const alarmVal = screen.tcp.syn_flood_alarm_threshold || Math.round(screen.tcp.syn_flood_threshold * 5) || 1024;
          lines.push(`            <alarm-threshold>${alarmVal}</alarm-threshold>`);
          lines.push(`            <attack-threshold>${screen.tcp.syn_flood_threshold}</attack-threshold>`);
          if (screen.tcp.syn_flood_timeout) lines.push(`            <timeout>${screen.tcp.syn_flood_timeout}</timeout>`);
          lines.push('          </syn-flood>');
        }
        if (screen.tcp.land_attack) lines.push('          <land/>');
        if (screen.tcp.winnuke) lines.push('          <winnuke/>');
        if (screen.tcp.tcp_no_flag) lines.push('          <tcp-no-flag/>');
        lines.push('        </tcp>');
      }
    }

    // UDP
    if (screen.udp && screen.udp.flood_threshold) {
      lines.push('        <udp>');
      lines.push(`          <flood><threshold>${screen.udp.flood_threshold}</threshold></flood>`);
      lines.push('        </udp>');
    }

    // IP
    if (screen.ip) {
      const hasIp = screen.ip.spoofing || screen.ip.source_route || screen.ip.tear_drop;
      if (hasIp) {
        lines.push('        <ip>');
        if (screen.ip.spoofing) lines.push('          <spoofing/>');
        if (screen.ip.source_route) lines.push('          <source-route-option/>');
        if (screen.ip.tear_drop) lines.push('          <tear-drop/>');
        lines.push('        </ip>');
      }
    }

    // Session limits
    if (screen.limit_session) {
      if (screen.limit_session.source_based || screen.limit_session.destination_based) {
        lines.push('        <limit-session>');
        if (screen.limit_session.source_based) lines.push(`          <source-ip-based>${screen.limit_session.source_based}</source-ip-based>`);
        if (screen.limit_session.destination_based) lines.push(`          <destination-ip-based>${screen.limit_session.destination_based}</destination-ip-based>`);
        lines.push('        </limit-session>');
      }
    }

    lines.push('      </ids-option>');
  }

  lines.push('    </screen>');
  if (zoneAssignments.length > 0) {
    lines.push('    <zones>');
    for (const assignment of zoneAssignments) {
      lines.push('      <security-zone>');
      lines.push(`        <name>${xmlText(assignment.zoneName)}</name>`);
      lines.push(`        <screen>${xmlText(assignment.profileName)}</screen>`);
      lines.push('      </security-zone>');
    }
    lines.push('    </zones>');
  }
  lines.push('  </security>');
}

function buildHaXml(haConfig, lines) {
  if (!haConfig || !haConfig.enabled) return;

  if (haConfig.ha_type === 'mnha') {
    buildMnhaXml(haConfig, lines);
    return;
  }

  const clusterId = haConfig.group_id || 1;
  const pri = haConfig.priority || 200;
  const secPri = pri > 100 ? 100 : pri - 1;

  lines.push('  <chassis>');
  lines.push('    <cluster>');
  lines.push(`      <cluster-id>${clusterId}</cluster-id>`);

  // Redundancy group 0
  lines.push('      <redundancy-group>');
  lines.push('        <name>0</name>');
  lines.push(`        <node><name>0</name><priority>${pri}</priority></node>`);
  lines.push(`        <node><name>1</name><priority>${secPri}</priority></node>`);
  if (haConfig.preempt) lines.push('        <preempt/>');
  lines.push('      </redundancy-group>');

  // Redundancy group 1
  lines.push('      <redundancy-group>');
  lines.push('        <name>1</name>');
  lines.push(`        <node><name>0</name><priority>${pri}</priority></node>`);
  lines.push(`        <node><name>1</name><priority>${secPri}</priority></node>`);
  if (haConfig.preempt) lines.push('        <preempt/>');
  lines.push('      </redundancy-group>');

  lines.push('      <heartbeat-interval>1000</heartbeat-interval>');
  lines.push('      <heartbeat-threshold>3</heartbeat-threshold>');
  lines.push('    </cluster>');
  lines.push('  </chassis>');

  // Fabric interfaces
  for (const iface of (haConfig.ha_interfaces || [])) {
    const name = (iface.name || '').toLowerCase();
    if ((name === 'fab0' || name === 'fab1') && iface.interface) {
      lines.push('  <interfaces>');
      lines.push(`    <interface><name>${name}</name>`);
      lines.push(`      <fabric-options><member-interfaces><name>${xmlText(iface.interface)}</name></member-interfaces></fabric-options>`);
      lines.push('    </interface>');
      lines.push('  </interfaces>');
    }
  }

  lines.push(`  ${xmlComment(`Source HA: ${haConfig.description || haConfig.mode}`, 'ha_config.description')}`);
  lines.push('  <!-- NOTE: Review chassis cluster config for target hardware -->');
}

function buildMnhaXml(haConfig, lines) {
  const localId = haConfig.local_id || 1;
  const peerId = haConfig.peer_id || 2;

  lines.push('  <chassis>');
  lines.push('    <high-availability>');

  // Local node
  lines.push('      <local-id>');
  lines.push(`        <id>${localId}</id>`);
  if (haConfig.local_ip) {
    lines.push(`        <local-ip>${xmlText(haConfig.local_ip)}</local-ip>`);
  }
  lines.push('      </local-id>');

  // Peer node
  lines.push('      <peer-id>');
  lines.push(`        <id>${peerId}</id>`);
  if (haConfig.peer_ip) {
    lines.push(`        <peer-ip>${xmlText(haConfig.peer_ip)}</peer-ip>`);
  }
  if (haConfig.icl_interface) {
    lines.push(`        <interface>${xmlText(haConfig.icl_interface)}</interface>`);
  }
  if (haConfig.vpn_profile) {
    lines.push(`        <vpn-profile>${xmlText(haConfig.vpn_profile)}</vpn-profile>`);
  }
  lines.push('        <liveness-detection>');
  lines.push(`          <minimum-interval>${haConfig.liveness_interval || 400}</minimum-interval>`);
  lines.push(`          <multiplier>${haConfig.liveness_multiplier || 5}</multiplier>`);
  lines.push('        </liveness-detection>');
  lines.push('      </peer-id>');

  // SRG0
  lines.push('      <services-redundancy-group>');
  lines.push('        <name>0</name>');
  lines.push(`        <peer-id>${peerId}</peer-id>`);
  lines.push('      </services-redundancy-group>');

  // SRG1
  lines.push('      <services-redundancy-group>');
  lines.push('        <name>1</name>');
  lines.push(`        <deployment-type>${xmlText(haConfig.deployment_type || 'routing')}</deployment-type>`);
  lines.push(`        <peer-id>${peerId}</peer-id>`);
  lines.push(`        <activeness-priority>${haConfig.activeness_priority || 200}</activeness-priority>`);
  if (haConfig.preemption) {
    lines.push('        <preemption/>');
  }
  // Interface monitoring
  if (haConfig.monitoring) {
    for (const lg of (haConfig.monitoring.link_groups || [])) {
      if (lg.enabled && lg.interfaces) {
        for (const iface of lg.interfaces) {
          lines.push(`        <interface-monitor><name>${xmlText(iface)}</name><weight>255</weight></interface-monitor>`);
        }
      }
    }
  }
  lines.push('      </services-redundancy-group>');

  lines.push('    </high-availability>');
  lines.push('  </chassis>');
  lines.push(`  ${xmlComment(`MNHA: ${haConfig.description || haConfig.mode || 'active-passive'}`, 'ha_config.description')}`);
  lines.push('  <!-- NOTE: Review MNHA config — verify ICL, VPN profile, and SRG settings -->');
}

// ---------------------------------------------------------------------------
// Syslog XML Builder
// ---------------------------------------------------------------------------

function buildSyslogXml(syslogConfig, lines) {
  if (!syslogConfig || syslogConfig.length === 0) return;

  lines.push('  <system>');
  lines.push('    <syslog>');

  for (const srv of syslogConfig) {
    if (!srv.server || srv.transport === 'file') continue;

    lines.push('      <host>');
    lines.push(`        <name>${xmlText(srv.server)}</name>`);
    lines.push('        <any><any/></any>');

    if (srv.port && srv.port !== 514) {
      lines.push(`        <port>${srv.port}</port>`);
    }

    if (srv.transport === 'tcp' || srv.transport === 'tls') {
      lines.push('        <transport><protocol>tcp</protocol></transport>');
    }

    if (srv.source_address) {
      lines.push(`        <source-address>${xmlText(srv.source_address)}</source-address>`);
    }

    if (srv.structured_data) {
      lines.push('        <structured-data/>');
    }

    lines.push('      </host>');
  }

  lines.push('    </syslog>');
  lines.push('  </system>');
}


// ---------------------------------------------------------------------------
// SNMP XML Builder
// ---------------------------------------------------------------------------

const SNMP_CATEGORY_NAMES = [
  'authentication', 'chassis', 'configuration', 'link', 'remote-operations',
  'routing', 'rmon-alarm', 'services', 'startup',
];

function buildSnmpXml(snmpConfig, lines, identifierNames) {
  if (!snmpConfig || snmpConfig.length === 0) return;

  lines.push('  <snmp>');

  // Contact / location from first entry
  const contactEntry = snmpConfig.find(e => e.contact);
  const locationEntry = snmpConfig.find(e => e.location);
  if (contactEntry?.contact) {
    lines.push(`    <contact>${xmlText(contactEntry.contact)}</contact>`);
  }
  if (locationEntry?.location) {
    lines.push(`    <location>${xmlText(locationEntry.location)}</location>`);
  }

  for (let entryIndex = 0; entryIndex < snmpConfig.length; entryIndex += 1) {
    const entry = snmpConfig[entryIndex];
    if (entry.type === 'community') {
      lines.push('    <community>');
      lines.push(`      <name>${xmlText(identifierNames.definition(`snmp_config[${entryIndex}].name`))}</name>`);
      const auth = entry.authorization === 'read-write' ? 'read-write' : 'read-only';
      lines.push(`      <authorization>${auth}</authorization>`);
      if (entry.clients && entry.clients.length > 0) {
        lines.push('      <clients>');
        for (const client of entry.clients) {
          lines.push(`        <name>${xmlText(client)}</name>`);
        }
        lines.push('      </clients>');
      }
      lines.push('    </community>');
    }

    if (entry.type === 'trap-group') {
      lines.push('    <trap-group>');
      lines.push(`      <name>${xmlText(identifierNames.definition(`snmp_config[${entryIndex}].name`))}</name>`);
      if (entry.version) {
        lines.push(`      <version>${xmlText(entry.version)}</version>`);
      }
      for (const target of (entry.targets || [])) {
        lines.push(`      <targets><name>${xmlText(target)}</name></targets>`);
      }
      for (const cat of (entry.categories || [])) {
        const category = xmlElementName(cat, SNMP_CATEGORY_NAMES, 'snmp_config.categories');
        const categoryElement = {
          authentication: '<authentication/>', chassis: '<chassis/>',
          configuration: '<configuration/>', link: '<link/>',
          'remote-operations': '<remote-operations/>', routing: '<routing/>',
          'rmon-alarm': '<rmon-alarm/>', services: '<services/>', startup: '<startup/>',
        }[category];
        lines.push(`      <categories>${categoryElement}</categories>`);
      }
      lines.push('    </trap-group>');
    }

    if (entry.type === 'v3-user') {
      const VALID_AUTH = ['md5', 'sha'];
      const VALID_PRIV = ['des', 'aes128'];
      lines.push('    <v3>');
      lines.push('      <usm>');
      lines.push('        <local-engine>');
      lines.push('          <user>');
      lines.push(`            <name>${xmlText(identifierNames.definition(`snmp_config[${entryIndex}].name`))}</name>`);
      if (entry.auth_protocol && entry.auth_protocol !== 'none' && VALID_AUTH.includes(entry.auth_protocol)) {
        lines.push(`            <authentication-${entry.auth_protocol}/>`);
      }
      if (entry.privacy_protocol && entry.privacy_protocol !== 'none' && VALID_PRIV.includes(entry.privacy_protocol)) {
        lines.push(`            <privacy-${entry.privacy_protocol}/>`);
      }
      lines.push('          </user>');
      lines.push('        </local-engine>');
      lines.push('      </usm>');
      lines.push('    </v3>');
    }
  }

  lines.push('  </snmp>');
}


// ---------------------------------------------------------------------------
// AAA XML Builder
// ---------------------------------------------------------------------------

function buildAaaXml(aaaConfig, lines, identifierNames) {
  if (!aaaConfig || aaaConfig.length === 0) return;

  const radiusServers = aaaConfig.filter(e => e.type === 'radius' && e.server);
  const tacplusServers = aaaConfig.filter(e => e.type === 'tacplus' && e.server);
  const profiles = aaaConfig.filter(e => e.type === 'profile');
  const authOrders = aaaConfig.filter(e => e.type === 'auth-order');

  if (radiusServers.length > 0 || tacplusServers.length > 0 || authOrders.length > 0) {
    lines.push('  <system>');

    for (const srv of radiusServers) {
      lines.push('    <radius-server>');
      lines.push(`      <name>${xmlText(srv.server)}</name>`);
      lines.push(`      <port>${srv.port || 1812}</port>`);
      if (srv.secret) {
        lines.push(`      <secret>${xmlText(srv.secret)}</secret>`);
      }
      if (srv.timeout) {
        lines.push(`      <timeout>${srv.timeout}</timeout>`);
      }
      if (srv.source_address) {
        lines.push(`      <source-address>${xmlText(srv.source_address)}</source-address>`);
      }
      lines.push('    </radius-server>');
    }

    for (const srv of tacplusServers) {
      lines.push('    <tacplus-server>');
      lines.push(`      <name>${xmlText(srv.server)}</name>`);
      lines.push(`      <port>${srv.port || 49}</port>`);
      if (srv.secret) {
        lines.push(`      <secret>${xmlText(srv.secret)}</secret>`);
      }
      if (srv.timeout) {
        lines.push(`      <timeout>${srv.timeout}</timeout>`);
      }
      if (srv.single_connection) {
        lines.push('      <single-connection/>');
      }
      lines.push('    </tacplus-server>');
    }

    for (const ao of authOrders) {
      if (ao.authentication_order) {
        for (const method of ao.authentication_order) {
          lines.push(`    <authentication-order>${xmlText(method)}</authentication-order>`);
        }
      }
    }

    lines.push('  </system>');
  }

  if (profiles.length > 0) {
    lines.push('  <access>');
    for (const profile of profiles) {
      const profileIndex = aaaConfig.indexOf(profile);
      lines.push('    <profile>');
      lines.push(`      <name>${xmlText(identifierNames.definition(`aaa_config[${profileIndex}].name`))}</name>`);
      if (profile.authentication_order) {
        for (const method of profile.authentication_order) {
          lines.push(`      <authentication-order>${xmlText(method)}</authentication-order>`);
        }
      }
      lines.push('    </profile>');
    }
    lines.push('  </access>');
  }
}


// ---------------------------------------------------------------------------
// DHCP XML Builder
// ---------------------------------------------------------------------------

function buildDhcpXml(dhcpConfig, lines, identifierNames) {
  if (!dhcpConfig || dhcpConfig.length === 0) return;

  let hasRelay = false;
  let hasPool = false;

  for (const cfg of dhcpConfig) {
    if (cfg.type === 'relay') hasRelay = true;
    if (cfg.type === 'server' || cfg.type === 'pool') hasPool = true;
  }

  // DHCP Relay: forwarding-options
  if (hasRelay) {
    lines.push('  <forwarding-options>');
    lines.push('    <helpers>');
    lines.push('      <bootp>');
    for (const cfg of dhcpConfig) {
      if (cfg.type !== 'relay') continue;
      const iface = cfg.interface || 'ge-0/0/0.0';
      lines.push(`        <interface><name>${xmlText(iface)}</name>`);
      for (const srv of (cfg.servers || [])) {
        lines.push(`          <server>${xmlText(srv)}</server>`);
      }
      lines.push('        </interface>');
    }
    lines.push('      </bootp>');
    lines.push('    </helpers>');
    lines.push('  </forwarding-options>');
  }

  // DHCP Server: access address-assignment pool
  if (hasPool) {
    lines.push('  <access>');
    lines.push('    <address-assignment>');
    for (let configIndex = 0; configIndex < dhcpConfig.length; configIndex += 1) {
      const cfg = dhcpConfig[configIndex];
      if (cfg.type !== 'server' && cfg.type !== 'pool') continue;
      const poolName = cfg.name
        ? identifierNames.definition(`dhcp_config[${configIndex}].name`)
        : identifierNames.generated(`dhcp_config[${configIndex}]`, 'dhcp-pool');
      lines.push(`      <pool><name>${xmlText(poolName)}</name>`);
      lines.push('        <family><inet>');

      if (cfg.network) {
        lines.push(`          <network>${xmlText(cfg.network)}</network>`);
      }

      if (cfg.ranges) {
        for (let rangeIndex = 0; rangeIndex < cfg.ranges.length; rangeIndex += 1) {
          const range = cfg.ranges[rangeIndex];
          const rangeName = range.name
            ? identifierNames.definition(`dhcp_config[${configIndex}].ranges[${rangeIndex}].name`)
            : identifierNames.generated(`dhcp_config[${configIndex}].ranges[${rangeIndex}]`, 'dhcp-named-range');
          lines.push(`          <range><name>${xmlText(rangeName)}</name>`);
          if (range.low) lines.push(`            <low>${range.low}</low>`);
          if (range.high) lines.push(`            <high>${range.high}</high>`);
          lines.push('          </range>');
        }
      }

      if (cfg.pools) {
        for (let i = 0; i < cfg.pools.length; i++) {
          const pool = cfg.pools[i];
          if (pool.includes('-')) {
            const [low, high] = pool.split('-');
            const rangeName = identifierNames.generated(`dhcp_config[${configIndex}].pools[${i}]`, 'dhcp-pool-range');
            lines.push(`          <range><name>${xmlText(rangeName)}</name><low>${low}</low><high>${high}</high></range>`);
          }
        }
      }

      const gw = cfg.gateway || cfg.router;
      const dns = cfg.dns_servers || [];
      if (gw || dns.length > 0) {
        lines.push('          <dhcp-attributes>');
        if (gw) lines.push(`            <router>${xmlText(gw)}</router>`);
        for (const d of dns) {
          lines.push(`            <name-server>${xmlText(d)}</name-server>`);
        }
        lines.push('          </dhcp-attributes>');
      }

      lines.push('        </inet></family>');
      lines.push('      </pool>');
    }
    lines.push('    </address-assignment>');
    lines.push('  </access>');
  }
}


// ---------------------------------------------------------------------------
// QoS / CoS XML Builder
// ---------------------------------------------------------------------------

function buildQosXml(qosConfig, lines, identifierNames) {
  if (!qosConfig || qosConfig.length === 0) return;

  lines.push('  <class-of-service>');

  for (let qosIndex = 0; qosIndex < qosConfig.length; qosIndex += 1) {
    const qos = qosConfig[qosIndex];
    const qosPath = `qos_config[${qosIndex}]`;
    if (qos.type === 'scheduler') {
      lines.push('    <schedulers>');
      lines.push(`      <name>${xmlText(identifierNames.definition(`${qosPath}.name`))}</name>`);
      if (qos.transmit_rate) lines.push(`      <transmit-rate>${xmlText(qos.transmit_rate)}</transmit-rate>`);
      if (qos.buffer_size) lines.push(`      <buffer-size>${xmlText(qos.buffer_size)}</buffer-size>`);
      if (qos.priority) lines.push(`      <priority>${xmlText(qos.priority)}</priority>`);
      lines.push('    </schedulers>');
    } else if (qos.type === 'interface-cos') {
      lines.push('    <interfaces>');
      lines.push(`      <interface><name>${xmlText(qos.interface)}</name>`);
      if (qos.scheduler_map) lines.push(`        <scheduler-map>${xmlText(identifierNames.reference(`${qosPath}.scheduler_map`))}</scheduler-map>`);
      if (qos.shaping_rate) lines.push(`        <shaping-rate>${xmlText(qos.shaping_rate)}</shaping-rate>`);
      lines.push('      </interface>');
      lines.push('    </interfaces>');
    } else {
      // Generic scheduler-map from PAN-OS/FortiGate/Cisco
      const classes = qos.classes || [];
      if (classes.length > 0) {
        lines.push('    <scheduler-maps>');
        lines.push(`      <name>${xmlText(identifierNames.definition(`${qosPath}.name`))}</name>`);
        for (let classIndex = 0; classIndex < classes.length; classIndex += 1) {
          const cls = classes[classIndex];
          const classPath = `${qosPath}.classes[${classIndex}]`;
          const schedulerName = cls.name
            ? identifierNames.definition(`${classPath}.name`)
            : identifierNames.generated(classPath, 'qos-default-scheduler');
          const forwardingClass = cls.name
            ? identifierNames.definition(`${classPath}.name#forwarding-class`)
            : identifierNames.generated(classPath, 'qos-default-forwarding-class');
          lines.push(`      <forwarding-class><class-name>${xmlText(forwardingClass)}</class-name>`);
          lines.push(`        <scheduler>${xmlText(schedulerName)}</scheduler>`);
          lines.push('      </forwarding-class>');
        }
        lines.push('    </scheduler-maps>');

        // Emit scheduler definitions for each class
        for (let classIndex = 0; classIndex < classes.length; classIndex += 1) {
          const cls = classes[classIndex];
          const classPath = `${qosPath}.classes[${classIndex}]`;
          const clsName = cls.name
            ? identifierNames.definition(`${classPath}.name`)
            : identifierNames.generated(classPath, 'qos-default-scheduler');
          lines.push('    <schedulers>');
          lines.push(`      <name>${xmlText(clsName)}</name>`);
          if (cls.guaranteed_bandwidth || cls.maximum_bandwidth || cls.police_rate) {
            lines.push(`      <transmit-rate>${cls.police_rate || cls.maximum_bandwidth || cls.guaranteed_bandwidth}</transmit-rate>`);
          }
          if (cls.priority === true || cls.priority === 'high') {
            lines.push('      <priority>high</priority>');
          }
          lines.push('    </schedulers>');
        }
      }
    }
  }

  lines.push('  </class-of-service>');
}


// ---------------------------------------------------------------------------
// L2 / Bridge Domains / Virtual-Wire
// ---------------------------------------------------------------------------

function buildL2Xml(config, lines, interfaceMappings = {}, identifierNames) {
  const bridgeDomains = config.bridge_domains || [];
  const l2Interfaces = config.l2_interfaces || [];
  const vwirePairs = config.vwire_pairs || [];

  if (bridgeDomains.length === 0 && l2Interfaces.length === 0 && vwirePairs.length === 0) return;

  lines.push('  <!-- L2 / Bridge Domains -->');
  lines.push('  <bridge-domains>');

  // Explicit bridge domains
  for (let bridgeIndex = 0; bridgeIndex < bridgeDomains.length; bridgeIndex += 1) {
    const bd = bridgeDomains[bridgeIndex];
    const bdName = identifierNames.definition(`bridge_domains[${bridgeIndex}].name`);
    lines.push('    <domain>');
    lines.push(`      <name>${xmlText(bdName)}</name>`);
    lines.push('      <domain-type>bridge</domain-type>');
    if (bd.vlan_id) lines.push(`      <vlan-id>${xmlText(String(bd.vlan_id))}</vlan-id>`);
    if (bd.irb_interface) lines.push(`      <routing-interface>${xmlText(bd.irb_interface)}</routing-interface>`);
    lines.push('    </domain>');
  }

  // Virtual-wire bridge domains
  for (let vwireIndex = 0; vwireIndex < vwirePairs.length; vwireIndex += 1) {
    const vw = vwirePairs[vwireIndex];
    const bdName = identifierNames.generated(`vwire_pairs[${vwireIndex}]`, 'vwire-bridge-domain');
    lines.push('    <domain>');
    lines.push(`      <name>${xmlText(bdName)}</name>`);
    lines.push('      <domain-type>bridge</domain-type>');
    if (vw.tag_allowed && vw.tag_allowed.length === 1 && vw.tag_allowed[0] !== '0') {
      lines.push(`      <vlan-id>${xmlText(String(vw.tag_allowed[0]))}</vlan-id>`);
    }
    if (vw.tag_allowed && vw.tag_allowed.length > 1) {
      lines.push(`      <vlan-id-list>${xmlText(vw.tag_allowed.join(' '))}</vlan-id-list>`);
    }
    lines.push('    </domain>');
  }

  lines.push('  </bridge-domains>');

  // Interface family bridge assignments for resolved vwire interfaces
  const bridgeInterfaces = [];
  for (let vwireIndex = 0; vwireIndex < vwirePairs.length; vwireIndex += 1) {
    const vw = vwirePairs[vwireIndex];
    const bdName = identifierNames.generated(`vwire_pairs[${vwireIndex}]`, 'vwire-bridge-domain');
    for (const srcIf of [vw.interface1, vw.interface2]) {
      let srxName = srcIf;
      if (interfaceMappings[srcIf]) {
        srxName = interfaceMappings[srcIf];
        if (!srxName.includes('.')) srxName += '.0';
      } else {
        const base = srcIf.split('.')[0];
        if (interfaceMappings[base]) {
          srxName = `${interfaceMappings[base].split('.')[0]}.0`;
        }
      }
      // Only emit if actually mapped (not the original name)
      const origNorm = srcIf.includes('.') ? srcIf : `${srcIf}.0`;
      if (srxName !== origNorm) {
        bridgeInterfaces.push({ srxName, bdName, vlanList: vw.tag_allowed });
      }
    }
  }
  for (let interfaceIndex = 0; interfaceIndex < l2Interfaces.length; interfaceIndex += 1) {
    const l2if = l2Interfaces[interfaceIndex];
    const parts = l2if.name.match(/^(.+?)\.(\d+)$/);
    const srxName = parts ? l2if.name : `${l2if.name}.0`;
    bridgeInterfaces.push({
      srxName,
      bdName: l2if.bridge_domain
        ? identifierNames.reference(`l2_interfaces[${interfaceIndex}].bridge_domain`)
        : null,
    });
  }

  if (bridgeInterfaces.length > 0) {
    lines.push('  <!-- L2 Interface Assignments -->');
    lines.push('  <interfaces>');
    for (const bi of bridgeInterfaces) {
      const [baseName, unitNum = '0'] = bi.srxName.split('.');
      lines.push('    <interface>');
      lines.push(`      <name>${xmlText(baseName)}</name>`);
      lines.push('      <unit>');
      lines.push(`        <name>${xmlText(unitNum)}</name>`);
      lines.push('        <family>');
      lines.push('          <bridge>');
      if (bi.vlanList && bi.vlanList.length > 1) {
        lines.push('            <interface-mode>trunk</interface-mode>');
        lines.push(`            <vlan-id-list>${xmlText(bi.vlanList.join(' '))}</vlan-id-list>`);
      } else if (bi.bdName) {
        lines.push(`            <bridge-domain-name>${xmlText(bi.bdName)}</bridge-domain-name>`);
      }
      lines.push('          </bridge>');
      lines.push('        </family>');
      lines.push('      </unit>');
      lines.push('    </interface>');
    }
    lines.push('  </interfaces>');
  }
}


// ---------------------------------------------------------------------------
// Policy-Based Forwarding (Filter-Based Forwarding)
// ---------------------------------------------------------------------------

function buildPbfXml(pbfRules, lines, interfaceMappings = {}, identifierNames) {
  if (!pbfRules || pbfRules.length === 0) return;

  const activeRules = pbfRules.filter(r => !r.disabled);
  if (activeRules.length === 0) return;
  const isIpOrPrefixLiteral = value => (
    /^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,3})?$/.test(value)
    || (value.includes(':') && /^[0-9A-Fa-f:.]+(?:\/\d{1,3})?$/.test(value))
  );

  // Collect routing instances (type forwarding)
  const instances = new Map();
  for (const rule of activeRules) {
    if (rule.action === 'forward' && rule.next_hop_value) {
      if (!instances.has(rule.next_hop_value)) {
        const candidates = activeRules
          .map((candidate, index) => ({ candidate, index: pbfRules.indexOf(candidate) }))
          .filter(({ candidate }) => candidate.action === 'forward' && candidate.next_hop_value === rule.next_hop_value)
          .sort((left, right) => String(left.candidate.name).localeCompare(String(right.candidate.name)));
        const ownerIndex = candidates[0].index;
        instances.set(rule.next_hop_value, identifierNames.generated(`pbf_rules[${ownerIndex}]`, 'pbf-routing-instance'));
      }
    }
  }

  // Emit routing-instances for PBF
  if (instances.size > 0) {
    lines.push('  <!-- PBF Routing Instances -->');
    lines.push('  <routing-instances>');
    for (const [nextHop, instName] of instances) {
      const defaultRoute = nextHop.includes(':') ? '::/0' : '0.0.0.0/0';
      lines.push('    <instance>');
      lines.push(`      <name>${xmlText(instName)}</name>`);
      lines.push('      <instance-type>forwarding</instance-type>');
      lines.push('      <routing-options>');
      lines.push('        <static>');
      lines.push('          <route>');
      lines.push(`            <name>${xmlText(defaultRoute)}</name>`);
      lines.push(`            <next-hop>${xmlText(nextHop)}</next-hop>`);
      lines.push('          </route>');
      lines.push('        </static>');
      lines.push('      </routing-options>');
      lines.push('    </instance>');
    }
    lines.push('  </routing-instances>');
  }

  // Emit firewall filter
  lines.push('  <!-- PBF Firewall Filter -->');
  lines.push('  <firewall>');
  lines.push('    <filter>');
  lines.push(`      <name>${xmlText(identifierNames.generated('pbf_rules', 'pbf-filter'))}</name>`);

  for (const rule of activeRules) {
    const ruleIndex = pbfRules.indexOf(rule);
    const termName = identifierNames.definition(`pbf_rules[${ruleIndex}].name`);
    lines.push('      <term>');
    lines.push(`        <name>${xmlText(termName)}</name>`);

    // from clause
    const hasSrc = (rule.src_addresses || []).some(a => a !== 'any');
    const hasDst = (rule.dst_addresses || []).some(a => a !== 'any');
    if (hasSrc || hasDst) {
      lines.push('        <from>');
      for (let addressIndex = 0; addressIndex < (rule.src_addresses || []).length; addressIndex += 1) {
        const src = rule.src_addresses[addressIndex];
        if (src === 'any') continue;
        const output = isIpOrPrefixLiteral(src)
          ? src : identifierNames.reference(`pbf_rules[${ruleIndex}].src_addresses[${addressIndex}]`);
        lines.push(`          <source-address>${xmlText(output)}</source-address>`);
      }
      for (let addressIndex = 0; addressIndex < (rule.dst_addresses || []).length; addressIndex += 1) {
        const dst = rule.dst_addresses[addressIndex];
        if (dst === 'any') continue;
        const output = isIpOrPrefixLiteral(dst)
          ? dst : identifierNames.reference(`pbf_rules[${ruleIndex}].dst_addresses[${addressIndex}]`);
        lines.push(`          <destination-address>${xmlText(output)}</destination-address>`);
      }
      lines.push('        </from>');
    }

    // then clause
    lines.push('        <then>');
    if (rule.action === 'forward' && rule.next_hop_value) {
      identifierNames.reference(`pbf_rules[${ruleIndex}].next_hop_value#routing-instance`);
      const instName = instances.get(rule.next_hop_value);
      lines.push(`          <routing-instance>${xmlText(instName)}</routing-instance>`);
    } else if (rule.action === 'discard') {
      lines.push('          <discard/>');
    } else {
      lines.push('          <accept/>');
    }
    lines.push('        </then>');
    lines.push('      </term>');
  }

  // Default accept term
  lines.push('      <term>');
  lines.push(`        <name>${xmlText(identifierNames.generated('pbf_rules', 'pbf-default-term'))}</name>`);
  lines.push('        <then><accept/></then>');
  lines.push('      </term>');
  lines.push('    </filter>');
  lines.push('  </firewall>');
}


// ---------------------------------------------------------------------------
// SSL Proxy / PKI XML
// ---------------------------------------------------------------------------

/**
 * Builds SSL proxy profile and PKI ca-profile XML from decryption rules.
 */
function buildSslProxyXml(config, lines, identifierNames) {
  const decryptionRules = config.decryption_rules || [];
  const fallbackDecryptPolicies = (config.security_policies || [])
    .map((policy, index) => ({ policy, index }))
    .filter(({ policy }) => policy._srx_decrypt && policy.action === 'allow' && !policy._srx_decrypt_profile);
  const hasDecryptRules = decryptionRules.some(r => (
    !r.disabled && ['decrypt', 'decrypt-and-forward'].includes(r.action)
  ));

  if (!hasDecryptRules && fallbackDecryptPolicies.length === 0) return;

  // Collect profiles
  const fwdProxyProfiles = new Set();
  const inboundProfiles = new Map();
  let caProfileName = null;

  const sharedProfiles = new Map();
  for (let ruleIndex = 0; ruleIndex < decryptionRules.length; ruleIndex += 1) {
    const rule = decryptionRules[ruleIndex];
    if (rule.disabled) continue;
    if (rule.action === 'decrypt' || rule.action === 'decrypt-and-forward') {
      if (rule.decryption_type === 'ssl-forward-proxy') {
        const key = `forward:${rule.decryption_profile || 'ssl-fwd-proxy'}`;
        if (!sharedProfiles.has(key)) {
          sharedProfiles.set(key, identifierNames.generated(`decryption_rules[${ruleIndex}]`, 'ssl-forward-profile'));
        }
        if (rule.decryption_profile) identifierNames.reference(`decryption_rules[${ruleIndex}].decryption_profile`);
        fwdProxyProfiles.add(sharedProfiles.get(key));
      } else if (rule.decryption_type === 'ssl-inbound-inspection') {
        const key = `inbound:${rule.decryption_profile || 'ssl-inbound-proxy'}`;
        if (!sharedProfiles.has(key)) {
          sharedProfiles.set(key, identifierNames.generated(`decryption_rules[${ruleIndex}]`, 'ssl-inbound-profile'));
        }
        if (rule.decryption_profile) identifierNames.reference(`decryption_rules[${ruleIndex}].decryption_profile`);
        const pName = sharedProfiles.get(key);
        inboundProfiles.set(pName, rule.ssl_certificate || 'SERVER-CERT');
      } else if (rule.decryption_type !== 'ssh-proxy') {
        const key = 'forward:ssl-fwd-proxy';
        if (!sharedProfiles.has(key)) {
          sharedProfiles.set(key, identifierNames.generated(`decryption_rules[${ruleIndex}]`, 'ssl-forward-profile'));
        }
        fwdProxyProfiles.add(sharedProfiles.get(key));
      }
    }
  }

  if (fwdProxyProfiles.size === 0 && fallbackDecryptPolicies.length > 0) {
    const owner = [...fallbackDecryptPolicies].sort((left, right) => (
      String(left.policy.name || '').localeCompare(String(right.policy.name || ''))
    ))[0];
    fwdProxyProfiles.add(identifierNames.generated(`security_policies[${owner.index}]`, 'ssl-forward-profile'));
  }

  if (fwdProxyProfiles.size === 0 && inboundProfiles.size === 0) return;

  // PKI ca-profile (inside <security>)
  if (fwdProxyProfiles.size > 0) {
    const pkiOwners = [];
    for (let ruleIndex = 0; ruleIndex < decryptionRules.length; ruleIndex += 1) {
      const rule = decryptionRules[ruleIndex];
      if (!rule.disabled && ['decrypt', 'decrypt-and-forward'].includes(rule.action)
          && rule.decryption_type !== 'ssl-inbound-inspection' && rule.decryption_type !== 'ssh-proxy') {
        pkiOwners.push({ path: `decryption_rules[${ruleIndex}]`, key: `rule:${rule.name || ''}` });
      }
    }
    for (const { policy, index } of fallbackDecryptPolicies) {
      pkiOwners.push({ path: `security_policies[${index}]`, key: `policy:${policy.name || ''}` });
    }
    const pkiOwner = [...pkiOwners].sort((left, right) => left.key.localeCompare(right.key))[0];
    const caProfile = identifierNames.generated(pkiOwner.path, 'ssl-pki-ca-profile');
    caProfileName = caProfile;
    const caIdentity = identifierNames.generated(pkiOwner.path, 'ssl-pki-ca-identity');
    lines.push('  <!-- PKI CA Profile for SSL Forward Proxy -->');
    lines.push('  <security>');
    lines.push('    <pki>');
    lines.push('      <ca-profile>');
    lines.push(`        <name>${xmlText(caProfile)}</name>`);
    lines.push(`        <ca-identity>${xmlText(caIdentity)}</ca-identity>`);
    lines.push('      </ca-profile>');
    lines.push('    </pki>');
    lines.push('  </security>');
  }

  // Services SSL proxy profiles
  lines.push('  <!-- SSL Proxy Profiles -->');
  lines.push('  <services>');
  lines.push('    <ssl>');
  lines.push('      <proxy>');

  for (const profileName of fwdProxyProfiles) {
    lines.push('        <profile>');
    lines.push(`          <name>${xmlText(profileName)}</name>`);
    lines.push(`          <root-ca>${xmlText(caProfileName)}</root-ca>`);
    lines.push('          <protocol-version>tls12-and-above</protocol-version>');
    lines.push('          <actions>');
    lines.push('            <log/>');
    lines.push('            <crl-disable/>');
    lines.push('          </actions>');
    lines.push('        </profile>');
  }

  for (const [profileName, certName] of inboundProfiles) {
    lines.push('        <profile>');
    lines.push(`          <name>${xmlText(profileName)}</name>`);
    lines.push(`          <server-certificate>${xmlText(certName)}</server-certificate>`);
    lines.push('          <protocol-version>tls12-and-above</protocol-version>');
    lines.push('          <actions>');
    lines.push('            <log/>');
    lines.push('          </actions>');
    lines.push('        </profile>');
  }

  lines.push('      </proxy>');
  lines.push('    </ssl>');
  lines.push('  </services>');
}


// ---------------------------------------------------------------------------
// Flow Monitoring XML (Inline Jflow)
// ---------------------------------------------------------------------------

/**
 * Builds SRX inline-jflow XML configuration from flow monitoring config.
 */
function buildFlowMonitoringXml(flowConfig, lines, identifierNames) {
  if (!flowConfig || !flowConfig.collectors || flowConfig.collectors.length === 0) return;

  const instanceName = flowConfig.instance_name
    ? identifierNames.definition('flow_monitoring_config.instance_name')
    : identifierNames.generated('flow_monitoring_config', 'sampling-instance');
  const sampling = flowConfig.sampling || {};
  const rate = sampling.input_rate || 1000;
  const templates = flowConfig.templates || [];

  // forwarding-options > sampling
  lines.push('  <!-- Flow Monitoring (Inline Jflow) -->');
  lines.push('  <forwarding-options>');
  lines.push('    <sampling>');
  lines.push('      <instance>');
  lines.push(`        <name>${xmlText(instanceName)}</name>`);
  lines.push('        <input>');
  lines.push(`          <rate>${rate}</rate>`);
  lines.push('        </input>');
  lines.push('        <family>');
  lines.push('          <inet>');
  lines.push('            <output>');

  for (let i = 0; i < flowConfig.collectors.length; i++) {
    const collector = flowConfig.collectors[i];
    const tplName = identifierNames.reference(`flow_monitoring_config.collectors[${i}]#template`);
    const isIpfix = !collector.protocol || collector.protocol === 'ipfix' || collector.protocol === 'netflow-v10';

    lines.push('              <flow-server>');
    lines.push(`                <name>${xmlText(collector.address)}</name>`);
    lines.push(`                <port>${collector.port || 2055}</port>`);
    if (isIpfix) {
      lines.push('                <version-ipfix>');
      lines.push(`                  <template>${xmlText(tplName)}</template>`);
      lines.push('                </version-ipfix>');
    } else {
      lines.push('                <version9>');
      lines.push(`                  <template>${xmlText(tplName)}</template>`);
      lines.push('                </version9>');
    }
    lines.push('              </flow-server>');
  }

  // Inline jflow source address
  const srcAddr = flowConfig.collectors.find(c => c.source_address)?.source_address;
  if (srcAddr) {
    lines.push('              <inline-jflow>');
    lines.push(`                <source-address>${xmlText(srcAddr)}</source-address>`);
    lines.push('              </inline-jflow>');
  }

  lines.push('            </output>');
  lines.push('          </inet>');
  lines.push('        </family>');
  lines.push('      </instance>');
  lines.push('    </sampling>');
  lines.push('  </forwarding-options>');

  // services > flow-monitoring templates
  if (templates.length > 0 || flowConfig.collectors.length > templates.length) {
    lines.push('  <services>');
    lines.push('    <flow-monitoring>');

    for (let templateIndex = 0; templateIndex < templates.length; templateIndex += 1) {
      const tpl = templates[templateIndex];
      const tplName = identifierNames.definition(`flow_monitoring_config.templates[${templateIndex}].name`);
      lines.push('      <version-ipfix>');
      lines.push('        <template>');
      lines.push(`          <name>${xmlText(tplName)}</name>`);
      lines.push(`          <flow-active-timeout>${tpl.active_timeout || 60}</flow-active-timeout>`);
      lines.push('          <template-refresh-rate>');
      lines.push(`            <packets>${tpl.refresh_rate || 1000}</packets>`);
      lines.push('          </template-refresh-rate>');
      if (tpl.flow_type === 'ipv6') {
        lines.push('          <ipv6-template/>');
      }
      lines.push('        </template>');
      lines.push('      </version-ipfix>');
    }

    const emittedFallbacks = new Set();
    for (let collectorIndex = 0; collectorIndex < flowConfig.collectors.length; collectorIndex += 1) {
      if (templates[collectorIndex]) continue;
      const collector = flowConfig.collectors[collectorIndex];
      const key = JSON.stringify([
        collector.address || '', collector.port || 2055, collector.protocol || 'ipfix',
        collector.source_address || '',
      ]);
      if (emittedFallbacks.has(key)) continue;
      emittedFallbacks.add(key);
      const tplName = identifierNames.generated(
        `flow_monitoring_config.collectors[${collectorIndex}]`,
        'collector-flow-template',
      );
      lines.push('      <version-ipfix>');
      lines.push('        <template>');
      lines.push(`          <name>${xmlText(tplName)}</name>`);
      lines.push('          <flow-active-timeout>60</flow-active-timeout>');
      lines.push('          <template-refresh-rate><packets>1000</packets></template-refresh-rate>');
      lines.push('        </template>');
      lines.push('      </version-ipfix>');
    }

    lines.push('    </flow-monitoring>');
    lines.push('  </services>');
  }
}


// ---------------------------------------------------------------------------
// System Configuration (Day-0)
// ---------------------------------------------------------------------------

function buildInterfaceAddressesXml(interfaces, lines, interfaceMappings = {}, indent = '  ') {
  if (!interfaces || interfaces.length === 0) return;

  const withAddrs = interfaces.filter(i => i.ip || i.ipv6);
  if (withAddrs.length === 0) return;

  lines.push(`${indent}<!-- Interface Addresses -->`);
  lines.push(`${indent}<interfaces>`);

  for (const iface of withAddrs) {
    // Map source interface name to SRX name
    let srxName = iface.name || '';
    if (interfaceMappings[srxName]) {
      srxName = interfaceMappings[srxName];
      if (!srxName.includes('.')) srxName += '.0';
    } else {
      const base = srxName.split('.')[0];
      const unit = srxName.includes('.') ? srxName.split('.')[1] : null;
      if (interfaceMappings[base]) {
        srxName = `${interfaceMappings[base].split('.')[0]}.${unit || '0'}`;
      }
    }

    const [baseName, unitNum = '0'] = srxName.split('.');
    lines.push(`${indent}  <interface>`);
    lines.push(`${indent}    <name>${xmlText(baseName)}</name>`);
    lines.push(`${indent}    <unit>`);
    lines.push(`${indent}      <name>${xmlText(unitNum)}</name>`);
    if (iface.description) {
      lines.push(`${indent}      <description>${xmlText(iface.description)}</description>`);
    }
    if (iface.ip) {
      lines.push(`${indent}      <family>`);
      lines.push(`${indent}        <inet>`);
      lines.push(`${indent}          <address><name>${xmlText(iface.ip)}</name></address>`);
      lines.push(`${indent}        </inet>`);
      if (iface.ipv6) {
        lines.push(`${indent}        <inet6>`);
        lines.push(`${indent}          <address><name>${xmlText(iface.ipv6)}</name></address>`);
        lines.push(`${indent}        </inet6>`);
      }
      lines.push(`${indent}      </family>`);
    } else if (iface.ipv6) {
      lines.push(`${indent}      <family>`);
      lines.push(`${indent}        <inet6>`);
      lines.push(`${indent}          <address><name>${xmlText(iface.ipv6)}</name></address>`);
      lines.push(`${indent}        </inet6>`);
      lines.push(`${indent}      </family>`);
    }
    lines.push(`${indent}    </unit>`);
    lines.push(`${indent}  </interface>`);
  }

  lines.push(`${indent}</interfaces>`);
}

function buildSystemConfigXml(systemConfig, lines, indent = '  ') {
  if (!systemConfig) return;

  const hasContent = systemConfig.hostname || systemConfig.domain_name ||
    (systemConfig.dns_servers && systemConfig.dns_servers.length > 0) ||
    (systemConfig.ntp_servers && systemConfig.ntp_servers.length > 0) ||
    systemConfig.timezone || systemConfig.login_banner;

  if (!hasContent) return;

  lines.push(`${indent}<!-- System Configuration (Day-0) -->`);
  lines.push(`${indent}<system>`);

  if (systemConfig.hostname) {
    lines.push(`${indent}  <host-name>${xmlText(systemConfig.hostname)}</host-name>`);
  }
  if (systemConfig.domain_name) {
    lines.push(`${indent}  <domain-name>${xmlText(systemConfig.domain_name)}</domain-name>`);
  }
  for (const dns of (systemConfig.dns_servers || [])) {
    lines.push(`${indent}  <name-server><name>${xmlText(dns)}</name></name-server>`);
  }
  if (systemConfig.timezone) {
    lines.push(`${indent}  <time-zone>${xmlText(systemConfig.timezone)}</time-zone>`);
  }
  if (systemConfig.login_banner) {
    lines.push(`${indent}  <login>`);
    lines.push(`${indent}    <message>${xmlText(systemConfig.login_banner)}</message>`);
    lines.push(`${indent}  </login>`);
  }

  const mgmt = systemConfig.management_services || {};
  if (mgmt.ssh || mgmt.https || mgmt.netconf) {
    lines.push(`${indent}  <services>`);
    if (mgmt.ssh) lines.push(`${indent}    <ssh/>`);
    if (mgmt.https) {
      lines.push(`${indent}    <web-management>`);
      lines.push(`${indent}      <https><system-generated-certificate/></https>`);
      lines.push(`${indent}    </web-management>`);
    }
    if (mgmt.netconf) {
      lines.push(`${indent}    <netconf><ssh/></netconf>`);
    }
    lines.push(`${indent}  </services>`);
  }

  if (systemConfig.ntp_servers && systemConfig.ntp_servers.length > 0) {
    lines.push(`${indent}  <ntp>`);
    for (const ntp of systemConfig.ntp_servers) {
      lines.push(`${indent}    <server><name>${xmlText(ntp)}</name></server>`);
    }
    lines.push(`${indent}  </ntp>`);
  }

  lines.push(`${indent}</system>`);
}

// ---------------------------------------------------------------------------
// Multi-Firewall Merge XML Builder
// ---------------------------------------------------------------------------

/**
 * Builds a merged Junos XML configuration from multiple config slots,
 * each wrapped in a logical-system section.
 *
 * @param {Array<{lsName: string, intermediateConfig: Object, interfaceMappings: Object}>} configSlots
 * @param {Array<{ls1: string, ls2: string, sharedZone: string, lt1Unit: number, lt2Unit: number}>} crossLsLinks
 * @param {Object} globalConfig - Chassis-level config
 * @returns {{ xml: string, warnings: Object[], summary: Object, identifierMappings: Object }}
 */
export function buildMergedSrxXml(configSlots, crossLsLinks = [], globalConfig = {}) {
  if (!Array.isArray(configSlots) || !Array.isArray(crossLsLinks)) {
    throw new TypeError('configSlots and crossLsLinks must be arrays');
  }
  validateJunosInput(globalConfig, 'globalConfig');
  configSlots.forEach((slot, index) => {
    validateJunosInput({ lsName: slot.lsName }, `configSlots[${index}]`);
    validateJunosInput(slot.intermediateConfig, `configSlots[${index}].intermediateConfig`);
    validateJunosInput(slot.interfaceMappings || {}, `configSlots[${index}].interfaceMappings`);
  });
  validateJunosInput({ crossLsLinks }, 'merge');
  crossLsLinks.forEach((link, index) => {
    setInteger(link.lt1Unit, { min: 0, max: 16385 }, `crossLsLinks[${index}].lt1Unit`);
    setInteger(link.lt2Unit, { min: 0, max: 16385 }, `crossLsLinks[${index}].lt2Unit`);
  });

  const identifiers = planMergedJunosIdentifiers(configSlots, crossLsLinks, globalConfig);
  const globalIdentifierPath = localPath => `globalConfig.${localPath}`;
  const globalIdentifierNames = {
    path: globalIdentifierPath,
    mapping: identifiers.mapping,
    definition: localPath => identifiers.nameForDefinition(globalIdentifierPath(localPath)),
    reference: localPath => identifiers.nameForReference(globalIdentifierPath(localPath)),
    generated: (localPath, role) => (
      identifiers.nameForGenerated(globalIdentifierPath(localPath), role)
    ),
    generatedEntries: localPath => identifiers.mapping.entries.filter(entry => (
      entry.definitionPath?.startsWith(`${globalIdentifierPath(localPath)}#generated:`)
    )),
  };
  const allLines = [];
  const allWarnings = [...identifiers.warnings];
  const perLsSummaries = [];

  allLines.push('<?xml version="1.0" encoding="UTF-8"?>');
  allLines.push('<configuration>');
  allLines.push(xmlComment(versionStamp(globalConfig?.llmModel), 'version'));
  allLines.push(xmlComment(
    `Multi-Firewall Merge: ${configSlots.map(s => s.lsName).join(', ')}`,
    'configSlots',
  ));

  buildHaXml(globalConfig.ha_config, allLines);
  buildSyslogXml(globalConfig.syslog_config, allLines);
  buildSnmpXml(globalConfig.snmp_config, allLines, globalIdentifierNames);
  buildAaaXml(globalConfig.aaa_config, allLines, globalIdentifierNames);

  // Per-LS sections
  for (let slotIndex = 0; slotIndex < configSlots.length; slotIndex += 1) {
    const slot = configSlots[slotIndex];
    const safeLsName = identifiers.nameForDefinition(`configSlots[${slotIndex}].lsName`);
    const ctx = { type: 'logical-system', name: slot.lsName };
    const result = buildSrxXml(
      slot.intermediateConfig,
      slot.interfaceMappings || {},
      ctx,
      {
        omitConfigurationWrapper: true,
        identifierPlan: identifiers,
        pathPrefix: `configSlots[${slotIndex}].intermediateConfig.`,
        targetContextPath: `configSlots[${slotIndex}].lsName`,
      },
    );
    allLines.push('');
    allLines.push(`  ${xmlComment(`Logical-System: ${slot.lsName}`, `configSlots[${slotIndex}].lsName`)}`);
    allLines.push(result.xml);
    allWarnings.push(...result.warnings.slice(identifiers.warnings.length)
      .map(w => ({ ...w, _ls: safeLsName })));
    perLsSummaries.push({ lsName: safeLsName, summary: result.summary });
  }

  // Cross-LS lt- tunnel interfaces
  if (crossLsLinks.length > 0) {
    allLines.push('');
    allLines.push('  <!-- Cross-Logical-System Tunnel Interfaces (lt-) -->');
    for (let linkIndex = 0; linkIndex < crossLsLinks.length; linkIndex += 1) {
      const link = crossLsLinks[linkIndex];
      const ls1 = xmlText(
        identifiers.nameForReference(`crossLsLinks[${linkIndex}].ls1`),
        `crossLsLinks[${linkIndex}].ls1`,
      );
      const ls2 = xmlText(
        identifiers.nameForReference(`crossLsLinks[${linkIndex}].ls2`),
        `crossLsLinks[${linkIndex}].ls2`,
      );
      const zone1 = xmlText(
        identifiers.nameForReference(`crossLsLinks[${linkIndex}].sharedZone#ls1`),
        `crossLsLinks[${linkIndex}].sharedZone#ls1`,
      );
      const zone2 = xmlText(
        identifiers.nameForReference(`crossLsLinks[${linkIndex}].sharedZone#ls2`),
        `crossLsLinks[${linkIndex}].sharedZone#ls2`,
      );
      const u1 = setInteger(link.lt1Unit, { min: 0, max: 16385 }, `crossLsLinks[${linkIndex}].lt1Unit`);
      const u2 = setInteger(link.lt2Unit, { min: 0, max: 16385 }, `crossLsLinks[${linkIndex}].lt2Unit`);

      // Side A lt- interface in LS1
      allLines.push(`  <logical-systems>`);
      allLines.push(`    <name>${ls1}</name>`);
      allLines.push(`    <interfaces>`);
      allLines.push(`      <interface>`);
      allLines.push(`        <name>lt-0/0/0</name>`);
      allLines.push(`        <unit>`);
      allLines.push(`          <name>${u1}</name>`);
      allLines.push(`          <encapsulation>ethernet</encapsulation>`);
      allLines.push(`          <peer-unit>${u2}</peer-unit>`);
      allLines.push(`          <family><inet/></family>`);
      allLines.push(`        </unit>`);
      allLines.push(`      </interface>`);
      allLines.push(`    </interfaces>`);
      allLines.push(`    <security>`);
      allLines.push(`      <zones>`);
      allLines.push(`        <security-zone>`);
      allLines.push(`          <name>${zone1}</name>`);
      allLines.push(`          <interfaces>`);
      allLines.push(`            <name>lt-0/0/0.${u1}</name>`);
      allLines.push(`          </interfaces>`);
      allLines.push(`        </security-zone>`);
      allLines.push(`      </zones>`);
      allLines.push(`    </security>`);
      allLines.push(`  </logical-systems>`);

      // Side B lt- interface in LS2
      allLines.push(`  <logical-systems>`);
      allLines.push(`    <name>${ls2}</name>`);
      allLines.push(`    <interfaces>`);
      allLines.push(`      <interface>`);
      allLines.push(`        <name>lt-0/0/0</name>`);
      allLines.push(`        <unit>`);
      allLines.push(`          <name>${u2}</name>`);
      allLines.push(`          <encapsulation>ethernet</encapsulation>`);
      allLines.push(`          <peer-unit>${u1}</peer-unit>`);
      allLines.push(`          <family><inet/></family>`);
      allLines.push(`        </unit>`);
      allLines.push(`      </interface>`);
      allLines.push(`    </interfaces>`);
      allLines.push(`    <security>`);
      allLines.push(`      <zones>`);
      allLines.push(`        <security-zone>`);
      allLines.push(`          <name>${zone2}</name>`);
      allLines.push(`          <interfaces>`);
      allLines.push(`            <name>lt-0/0/0.${u2}</name>`);
      allLines.push(`          </interfaces>`);
      allLines.push(`        </security-zone>`);
      allLines.push(`      </zones>`);
      allLines.push(`    </security>`);
      allLines.push(`  </logical-systems>`);
    }
  }

  allLines.push('</configuration>');

  const summary = {
    logical_systems: configSlots.length,
    cross_ls_links: crossLsLinks.length,
    per_ls: perLsSummaries,
    total_warnings: allWarnings.length,
    identifier_collisions_resolved: identifiers.collisionCount,
  };

  const xml = allLines.join('\n');
  validateXmlOutput(xml);
  return {
    xml,
    warnings: allWarnings,
    summary,
    identifierMappings: identifiers.mapping,
  };
}
