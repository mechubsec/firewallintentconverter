/**
 * SRX Set-Command Converter
 * ===========================
 * Agent: SRX-Expert
 *
 * Converts the vendor-neutral intermediate JSON schema into Juniper SRX
 * set commands (Junos CLI format).
 *
 * Output follows Junos hierarchy:
 *   - security zones
 *   - security address-book global
 *   - applications
 *   - security policies from-zone X to-zone Y policy Z
 *   - security nat source/destination
 *   - deactivate statements for disabled rules
 *
 * Each generated command is tagged with a conversion status
 * (clean / warning / unsupported) for the warnings panel.
 */

import { sanitizeJunosName, mapAppToJunos, mapProfileToSrx, createWarning, isPredefEquivalent, planIngressScopeAdvice, JUNOS_PREDEFINED_APPS } from '../parsers/parser-utils.js';
import { getJunosEmission } from '../utils/app-mappings.js';
import {
  setAddressOrPrefix,
  setComment,
  setEnum,
  setInteger,
  setQuoted,
  setToken,
} from '../security/junos-serialization.js';
import { validateJunosInput } from '../security/junos-input-validation.js';
import { versionStamp } from '../version.js';
import { encodeJunosZonePair } from '../security/junos-identifier-identity.js';
import {
  planJunosIdentifiers,
  planMergedJunosIdentifiers,
} from '../security/junos-identifiers.js';
import { canonicalizeJunosSecurityFeatures } from '../security/junos-identifier-catalog.js';
import { validateSetOutput } from '../security/junos-output-validation.js';
import { findPolicyReferenceIssues, findNegationIssues } from '../security/policy-reference-integrity.js';

/**
 * Returns the correct ANY address for NAT rules based on whether the rule
 * contains IPv6 addresses. Uses '::/0' for IPv6, '0.0.0.0/0' for IPv4.
 */
function natAnyAddress(rule) {
  const allAddrs = [
    ...(rule.src_addresses || []),
    ...(rule.dst_addresses || []),
    ...(rule.translated_src?.addresses || []),
    ...(rule.translated_src?.address ? [rule.translated_src.address] : []),
    ...(rule.translated_dst?.address ? [rule.translated_dst.address] : []),
  ];
  return allAddrs.some(a => a && typeof a === 'string' && a.includes(':')) ? '::/0' : '0.0.0.0/0';
}

function serializeSetComments(commands) {
  for (let index = 0; index < commands.length; index += 1) {
    if (commands[index].startsWith('# ')) {
      commands[index] = setComment(commands[index].slice(2), `output.comments[${index}]`);
    }
  }
}

// ---------------------------------------------------------------------------
// Main Converter Entry Point
// ---------------------------------------------------------------------------

// Internal marker every parser puts on the implicit rules it synthesises;
// the rules carry their own descriptions, so it is never printed.
const INTERNAL_IMPLICIT_RULE_TAG = 'added_by_fpic';

/**
 * Converts an intermediate config to SRX set commands.
 *
 * @param {Object} config - Intermediate JSON config from the parser
 * @param {Object} [interfaceMappings] - User-defined PAN-OS → SRX interface mappings
 * @param {Object|null} [targetContext] - Optional logical-system or tenant wrapper
 * @param {Object} [options] - Internal identifier-plan/path options for composed conversion
 * @returns {{ commands: string[], warnings: Object[], summary: Object, identifierMappings: Object }}
 */
export function convertToSrxSetCommands(config, interfaceMappings = {}, targetContext = null, options = {}) {
  validateJunosInput(config);
  validateJunosInput(interfaceMappings, 'interfaceMappings');
  for (const [sourceName, mappedName] of Object.entries(interfaceMappings)) {
    setToken(mappedName, `interfaceMappings.${sourceName}`, /^[A-Za-z0-9_.:/-]+$/);
  }
  if (targetContext) {
    validateJunosInput(targetContext, 'targetContext');
  }
  const effectiveTargetContext = targetContext || config.target_context || null;
  if (effectiveTargetContext?.type !== undefined) {
    setEnum(effectiveTargetContext.type, ['none', 'logical-system', 'tenant'], 'targetContext.type');
  }

  const identifiers = options.identifierPlan || planJunosIdentifiers(config, { targetContext });
  const identifierPath = localPath => `${options.pathPrefix || ''}${localPath}`;
  const targetContextPath = options.targetContextPath || 'targetContext.name';
  const commands = [];
  commands.push(setComment(versionStamp(options.llmModel), 'version'));
  const warnings = [...identifiers.warnings];
  const summary = {
    identifier_collisions_resolved: identifiers.collisionCount,
    zones_converted: 0,
    addresses_converted: 0,
    address_groups_converted: 0,
    services_converted: 0,
    policies_converted: 0,
    nat_rules_converted: 0,
    static_routes_converted: 0,
    bgp_groups_converted: 0,
    bgp_neighbors_converted: 0,
    ospf_areas_converted: 0,
    ospf_interfaces_converted: 0,
    lag_interfaces_converted: 0,
    total_warnings: 0,
    unsupported_items: 0,
    total_source_policies: 0,
    policies_deactivated_undefined_ref: 0,
  };

  // Detect policies with undefined address/service references
  const policyReferenceIssues = findPolicyReferenceIssues(config);
  summary.total_source_policies = (config.security_policies || []).filter(p => !p._implicit).length;

  // Site identification header (for SDC/Mist integration)
  const siteN = config.metadata?.siteName;
  const siteG = config.metadata?.siteGroup;
  if (siteN || siteG) {
    commands.push('# =============================================');
    commands.push('# Site Identification');
    commands.push('# =============================================');
    if (siteN) commands.push(setComment(`Site: ${siteN}`, 'metadata.siteName'));
    if (siteG) commands.push(setComment(`Site Group: ${siteG}`, 'metadata.siteGroup'));
    commands.push('');
  }

  // Clear trackers from any previous conversion (module-level state)
  unmappedApps.clear();
  concreteCustomApps.clear();
  predefServiceMap.clear();
  commaPortSetMap.clear();
  unresolvedServiceApps.clear();

  // Generate commands in Junos hierarchy order
  convertSystemConfig(config.system_config, commands, warnings, summary);
  convertZones(config.zones, commands, warnings, summary, interfaceMappings, identifiers, identifierPath);
  convertInterfaceAddresses(config.interfaces, commands, warnings, summary, interfaceMappings);
  convertRemoteAccessPlaceholders(config.interfaces, commands, interfaceMappings, config.global_protect);
  ensureZoneInterfaceFamilies(config.zones, config.interfaces, commands, interfaceMappings);
  convertLagInterfaces(config.lag_interfaces, commands, warnings, summary, interfaceMappings);
  convertAddressObjects(config.address_objects, commands, warnings, summary, identifiers, identifierPath);
  // Detect source vendor for 1:1 passthrough (SRX→SRX needs no app mapping)
  const sourceVendor = config.metadata?.source_vendor || '';

  convertAddressGroups(config.address_groups, commands, warnings, summary, identifiers, identifierPath);
  convertServiceObjects(config.service_objects, commands, warnings, summary, identifiers, identifierPath);
  convertServiceGroups(config.service_groups, commands, warnings, summary, sourceVendor, identifiers, identifierPath);
  convertApplications(config.applications, commands, warnings, summary, identifiers, identifierPath);

  // UTM / IDP / SecIntel — must run before security policies to build assignment maps
  const profileDefs = config.security_profile_definitions || {};
  const { utmCommands, utmPolicyMap } = convertUtmPolicies(config.security_policies, warnings, profileDefs, identifiers, identifierPath);
  const { idpCommands, idpPolicyMap } = convertIdpPolicies(config.security_policies, warnings, profileDefs, identifiers, identifierPath);
  const { secIntelCommands, secIntelEnabled, secIntelPolicyName } = convertSecIntel(config.external_lists, config.security_policies, warnings, identifiers, identifierPath);

  commands.push(...utmCommands);
  commands.push(...idpCommands);
  commands.push(...secIntelCommands);

  convertSchedules(config.schedules, commands, warnings, identifiers, identifierPath);
  prepareApplicationGroupApplications(
    config.application_groups,
    warnings,
    sourceVendor,
    identifiers,
    identifierPath,
  );

  // Run policy conversion into a temp buffer to populate unmappedApps/concreteCustomApps,
  // then emit application definitions BEFORE emitting the policy commands.
  // This ensures all custom applications are defined before policies reference them.
  const policyCommands = [];
  const policyStructure = options.policyStructure === 'zone-pair' ? 'zone-pair' : 'global';
  convertSecurityPolicies(config.security_policies, policyCommands, warnings, summary, { utmPolicyMap, idpPolicyMap, secIntelEnabled, secIntelPolicyName }, config.application_groups, sourceVendor, config._rule_groups, identifiers, identifierPath, policyStructure, policyReferenceIssues);

  // Tier 2 emission: concrete custom applications (known ports from canonical data)
  if (concreteCustomApps.size > 0) {
    commands.push('# =============================================');
    commands.push('# Custom Applications (auto-generated from app-mappings canonical data)');
    commands.push('# =============================================');
    for (const [customName, info] of concreteCustomApps) {
      const { protocol, ports, originalName, canonical, subNames } = info;
      if (ports.length === 1) {
        commands.push(`set applications application ${customName} protocol ${protocol}`);
        commands.push(`set applications application ${customName} destination-port ${ports[0]}`);
        commands.push(`set applications application ${customName} description ${setQuoted(`${originalName} (canonical: ${canonical})`, 'applications.generated.description')}`);
      } else {
        // Multi-port: customName becomes an application-set composed of per-port sub-apps
        commands.push(`# ${originalName} (canonical: ${canonical})`);
        for (const port of ports) {
          const subName = subNames.get(String(port));
          commands.push(`set applications application ${subName} protocol ${protocol}`);
          commands.push(`set applications application ${subName} destination-port ${port}`);
        }
        for (const port of ports) {
          const subName = subNames.get(String(port));
          commands.push(`set applications application-set ${customName} application ${subName}`);
        }
      }
    }
    commands.push('');
  }

  // Existing Fix 4 logic: emit definitions for service references with inferable name patterns
  if (unresolvedServiceApps.size > 0) {
    const definedApps = new Set();
    for (const cmd of commands) {
      const appMatch = cmd.match(/^set applications application (\S+)/);
      if (appMatch) definedApps.add(appMatch[1]);
      const appSetMatch = cmd.match(/^set applications application-set (\S+)/);
      if (appSetMatch) definedApps.add(appSetMatch[1]);
    }
    const inferable = [];
    const uninferable = [];
    for (const [safeName, originalName] of unresolvedServiceApps) {
      if (definedApps.has(safeName)) continue;
      if (JUNOS_PREDEFINED_APPS.has(safeName)) continue;
      const m = safeName.match(/^(tcp|udp|sctp)-(\d[\d-]*)$/i);
      if (m) inferable.push({ safeName, originalName, proto: m[1].toLowerCase(), port: m[2] });
      else uninferable.push({ safeName, originalName });
    }
    if (inferable.length > 0) {
      commands.push('# =============================================');
      commands.push('# Auto-inferred Application Definitions (from name pattern)');
      commands.push('# =============================================');
      for (const { safeName, proto, port } of inferable) {
        commands.push(`set applications application ${safeName} protocol ${proto}`);
        commands.push(`set applications application ${safeName} destination-port ${port}`);
      }
      commands.push('');
    }
    for (const { safeName, originalName } of uninferable) {
      unmappedApps.set(safeName, originalName);
    }
  }

  // Tier 3 emission: single INTERVIEW REQUIRED block
  if (unmappedApps.size > 0) {
    commands.push('# =============================================================');
    commands.push('# INTERVIEW REQUIRED: Unmapped Applications');
    commands.push('# -----------------------------------------------------------');
    commands.push('# The following applications were referenced in the source');
    commands.push('# configuration but could not be mapped to a known Junos');
    commands.push('# predefined application or canonical mapping entry.');
    commands.push('#');
    commands.push('# For each entry below, replace the placeholder with the real');
    commands.push('# protocol and destination-port(s), or map it to an existing');
    commands.push('# Junos predefined application in your policies.');
    commands.push('#');
    commands.push('# NOTE: These application definitions AND all policies referencing');
    commands.push('# them are DEACTIVATED pending a real protocol/port definition,');
    commands.push('# then reactivation.');
    commands.push('# =============================================================');
    for (const [placeholderName, originalName] of unmappedApps) {
      commands.push(`# INTERVIEW: "${originalName}" — placeholder "${placeholderName}" emitted below with sentinel values.`);
      commands.push(`set applications application ${placeholderName} protocol tcp`);
      commands.push(`set applications application ${placeholderName} destination-port 1`);
      commands.push(`set applications application ${placeholderName} description ${setQuoted(`INTERVIEW REQUIRED: ${originalName}`, 'applications.unmapped.description')}`);
      commands.push(`deactivate applications application ${placeholderName}`);
    }
    commands.push('# =============================================================');
    commands.push('');
  }

  commands.push(...policyCommands);

  // Fix 1: When global policies exist, Junos requires a default-policy statement
  const hasGlobalPolicy = policyCommands.some(cmd => cmd.includes('security policies global policy'));
  if (hasGlobalPolicy) {
    commands.push('set security policies default-policy permit-all');
  }

  convertNatRules(
    config.nat_rules,
    commands,
    warnings,
    summary,
    config.address_objects,
    config.address_groups,
    config.zones,
    identifiers,
    identifierPath,
    config.interfaces,
    interfaceMappings,
  );
  const routingInstances = new Set();
  convertStaticRoutes(config.static_routes, commands, warnings, summary, interfaceMappings, identifiers, identifierPath, routingInstances);
  convertBgpConfig(config.bgp_config, commands, warnings, summary, identifiers, identifierPath, routingInstances);
  convertOspfConfig(config.ospf_config, commands, warnings, summary, interfaceMappings, identifiers, identifierPath, routingInstances);
  convertOspf3Config(config.ospf3_config, commands, warnings, summary, interfaceMappings, identifiers, identifierPath, routingInstances);
  convertEvpnConfig(config.evpn_config, commands, warnings, summary, interfaceMappings, identifiers, identifierPath, routingInstances);
  convertVxlanConfig(config.vxlan_config, commands, warnings, summary, interfaceMappings, identifiers, identifierPath, routingInstances);
  convertHaConfig(config.ha_config, commands, warnings, summary, interfaceMappings, options.deploymentMode);
  convertScreenConfig(config.screen_config, commands, warnings, summary, identifiers, identifierPath);
  convertVpnTunnels(config.vpn_tunnels, commands, warnings, summary, interfaceMappings, identifiers, identifierPath);
  convertSyslogConfig(config.syslog_config, commands, warnings, summary);
  convertSnmpConfig(config.snmp_config, commands, warnings, summary, identifiers, identifierPath);
  convertAaaConfig(config.aaa_config, commands, warnings, summary, identifiers, identifierPath);
  convertDhcpConfig(config.dhcp_config, commands, warnings, summary, interfaceMappings, identifiers, identifierPath);
  convertQosConfig(config.qos_config, commands, warnings, summary, interfaceMappings, identifiers, identifierPath);
  convertL2Config(config, commands, warnings, summary, interfaceMappings, identifiers, identifierPath);
  convertPbfConfig(config.pbf_rules, commands, warnings, summary, interfaceMappings, config.address_objects, identifiers, identifierPath);
  convertSslProxyConfig(config, commands, warnings, summary, identifiers, identifierPath);
  convertFlowMonitoringConfig(config.flow_monitoring_config, commands, warnings, summary, interfaceMappings, identifiers, identifierPath);
  convertUserIdentification(config.security_policies, commands, warnings);

  // Unsupported feature notices (only if AAA was not auto-converted)
  if (!config.aaa_config || config.aaa_config.length === 0) {
    commands.push('# =============================================');
    commands.push('# NOT CONVERTED — Manual Configuration Required');
    commands.push('# =============================================');
    commands.push('# AAA / Authentication (RADIUS, TACACS+, LDAP) — no AAA config detected in source');
    commands.push('# If needed, configure manually: set system authentication-order, set access profile, etc.');
    commands.push('');
  }

  summary.total_warnings = warnings.length;

  // Logical-system / tenant wrapping
  const ctx = effectiveTargetContext;
  if (ctx && ctx.type && ctx.type !== 'none' && ctx.name) {
    const ctxName = identifiers.nameForDefinition(targetContextPath);
    const prefix = ctx.type === 'logical-system'
      ? `logical-systems ${ctxName}`
      : `tenants ${ctxName}`;

    for (let i = 0; i < commands.length; i++) {
      const cmd = commands[i];
      if (cmd.startsWith('set ')) {
        commands[i] = `set ${prefix} ${cmd.slice(4)}`;
      } else if (cmd.startsWith('deactivate ')) {
        commands[i] = `deactivate ${prefix} ${cmd.slice(11)}`;
      }
    }
  }

  serializeSetComments(commands);
  validateSetOutput(commands);
  return { commands, warnings, summary, identifierMappings: identifiers.mapping };
}

// ---------------------------------------------------------------------------
// System Configuration Converter (Day-0)
// ---------------------------------------------------------------------------

function convertSystemConfig(systemConfig, commands, warnings, summary) {
  if (!systemConfig) return;

  const hasContent = systemConfig.hostname || systemConfig.domain_name ||
    (systemConfig.dns_servers && systemConfig.dns_servers.length > 0) ||
    (systemConfig.ntp_servers && systemConfig.ntp_servers.length > 0) ||
    systemConfig.timezone || systemConfig.login_banner;

  if (!hasContent) return;

  commands.push('# =============================================');
  commands.push('# System Configuration (Day-0)');
  commands.push('# =============================================');

  if (systemConfig.hostname) {
    const hostname = setToken(
      systemConfig.hostname,
      'system_config.hostname',
      /^(?=.{1,255}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/,
    );
    commands.push(`set system host-name ${hostname}`);
  }
  if (systemConfig.domain_name) {
    commands.push(`set system domain-name ${systemConfig.domain_name}`);
  }
  for (const dns of (systemConfig.dns_servers || [])) {
    commands.push(`set system name-server ${dns}`);
  }
  for (const ntp of (systemConfig.ntp_servers || [])) {
    commands.push(`set system ntp server ${ntp}`);
  }
  if (systemConfig.timezone) {
    commands.push(`set system time-zone ${systemConfig.timezone}`);
  }
  if (systemConfig.login_banner) {
    commands.push(`set system login message ${setQuoted(systemConfig.login_banner, 'system_config.login_banner')}`);
  }

  const mgmt = systemConfig.management_services || {};
  if (mgmt.ssh) {
    commands.push('set system services ssh');
  }
  if (mgmt.https) {
    commands.push('set system services web-management https system-generated-certificate');
  }
  if (mgmt.netconf) {
    commands.push('set system services netconf ssh');
  }

  commands.push('');
  summary.system_config_converted = 1;
}

// ---------------------------------------------------------------------------
// Zone Converter
// ---------------------------------------------------------------------------

function convertZones(zones, commands, warnings, summary, interfaceMappings = {}, identifiers, identifierPath) {
  if (!zones || zones.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Security Zones');
  commands.push('# =============================================');

  // Track which interfaces are already assigned to a zone (Junos: one zone per interface)
  const assignedInterfaces = new Map(); // srxIface → zoneName

  for (let zoneIndex = 0; zoneIndex < zones.length; zoneIndex += 1) {
    const zone = zones[zoneIndex];
    const zoneName = identifiers.nameForDefinition(identifierPath(`zones[${zoneIndex}].name`));
    commands.push(`set security zones security-zone ${zoneName}`);

    // Add interfaces to zone
    for (const iface of zone.interfaces || []) {
      // Map PAN-OS interface names to SRX convention if needed
      const srxIface = mapInterfaceName(iface, interfaceMappings);
      // Skip if this interface is already assigned to another zone (first assignment wins)
      if (assignedInterfaces.has(srxIface)) {
        const existingZone = assignedInterfaces.get(srxIface);
        warnings.push(createWarning('warning', `zones/${zoneName}`,
          `Interface ${srxIface} already assigned to zone "${existingZone}" — skipped in zone "${zoneName}"`,
          'Junos allows an interface in only one security zone. Verify zone assignments.'));
        commands.push(`# WARNING: ${srxIface} skipped — already in zone ${existingZone}`);
        continue;
      }
      assignedInterfaces.set(srxIface, zoneName);
      commands.push(`set security zones security-zone ${zoneName} interfaces ${srxIface}`);
    }

    // Allow host-inbound traffic defaults (common SRX requirement)
    commands.push(`set security zones security-zone ${zoneName} host-inbound-traffic system-services ping`);

    if (zone.description) {
      commands.push(`set security zones security-zone ${zoneName} description ${setQuoted(zone.description, 'zones.description')}`);
    }

    summary.zones_converted++;
  }

  commands.push('');
}

/**
 * Maps PAN-OS interface naming (ethernet1/1, ethernet1/1.100) to
 * SRX interface naming (ge-0/0/0, ge-0/0/0.100).
 *
 * This is a best-effort mapping — real deployments will need the user to
 * confirm interface assignments, which is handled in the interview phase.
 */
function mapInterfaceName(panosIface, interfaceMappings = {}) {
  // Check user-defined mappings first
  if (interfaceMappings[panosIface]) {
    const srx = interfaceMappings[panosIface];
    // Append .0 unit if not already specified
    return srx.includes('.') ? srx : `${srx}.0`;
  }

  // Strip VLAN unit for lookup, then re-add
  const base = panosIface.split('.')[0];
  const unit = panosIface.includes('.') ? panosIface.split('.')[1] : null;
  if (interfaceMappings[base]) {
    const srx = interfaceMappings[base];
    const srxBase = srx.split('.')[0];
    return `${srxBase}.${unit || '0'}`;
  }

  // Fallback: auto-map vendor interface naming to SRX ge-/xe- naming

  // PAN-OS: ethernet1/2 → ge-0/0/1.0  (slot-1, port-1)
  const panos = panosIface.match(/^ethernet(\d+)\/(\d+)(\.(\d+))?$/i);
  if (panos) {
    const slot = parseInt(panos[1]) - 1;
    const port = parseInt(panos[2]) - 1;
    const u = panos[4] || '0';
    return `ge-0/${slot}/${port}.${u}`;
  }

  // FortiGate: port1 → ge-0/0/0.0  (N-1)
  const forti = panosIface.match(/^port(\d+)(\.(\d+))?$/i);
  if (forti) {
    const port = parseInt(forti[1]) - 1;
    const u = forti[3] || '0';
    return `ge-0/0/${port}.${u}`;
  }

  // Check Point Gaia: eth0 → ge-0/0/0.0, bond0 passes through
  const cpEth = panosIface.match(/^eth(\d+)(\.(\d+))?$/i);
  if (cpEth) {
    const port = parseInt(cpEth[1]);
    const u = cpEth[3] || '0';
    return `ge-0/0/${port}.${u}`;
  }

  // SonicWall: X0 → ge-0/0/0.0
  const swX = panosIface.match(/^X(\d+)(\.(\d+))?$/i);
  if (swX) {
    const port = parseInt(swX[1]);
    const u = swX[3] || '0';
    return `ge-0/0/${port}.${u}`;
  }

  // Huawei: GigabitEthernet0/0/1 → ge-0/0/1.0
  const hwGe = panosIface.match(/^GigabitEthernet(\d+)\/(\d+)\/(\d+)(\.(\d+))?$/i);
  if (hwGe) {
    const slot = parseInt(hwGe[2]);
    const port = parseInt(hwGe[3]);
    const u = hwGe[5] || '0';
    return `ge-0/${slot}/${port}.${u}`;
  }

  // Huawei: XGigabitEthernet0/0/0 → xe-0/0/0.0
  const hwXe = panosIface.match(/^XGigabitEthernet(\d+)\/(\d+)\/(\d+)(\.(\d+))?$/i);
  if (hwXe) {
    const slot = parseInt(hwXe[2]);
    const port = parseInt(hwXe[3]);
    const u = hwXe[5] || '0';
    return `xe-0/${slot}/${port}.${u}`;
  }

  // Cisco ASA/IOS: GigabitEthernet1/1 (2-segment) → ge-0/0/0.0
  const ciscoGe2 = panosIface.match(/^GigabitEthernet(\d+)\/(\d+)(\.(\d+))?$/i);
  if (ciscoGe2) {
    const slot = parseInt(ciscoGe2[1]);
    const port = parseInt(ciscoGe2[2]);
    const u = ciscoGe2[4] || '0';
    return `ge-0/${slot}/${port}.${u}`;
  }

  // Cisco: TenGigabitEthernet1/1 → xe-0/1/1.0
  const ciscoXe = panosIface.match(/^TenGigabitEthernet(\d+)\/(\d+)(\.(\d+))?$/i);
  if (ciscoXe) {
    const slot = parseInt(ciscoXe[1]);
    const port = parseInt(ciscoXe[2]);
    const u = ciscoXe[4] || '0';
    return `xe-0/${slot}/${port}.${u}`;
  }

  // FortiGate named interfaces: internal/dmz/wan → ge-0/0/N.0
  const fortiNamed = panosIface.match(/^(internal|dmz|wan|lan)(\d*)(\.(\d+))?$/i);
  if (fortiNamed) {
    const nameMap = { internal: 1, dmz: 2, wan: 3, lan: 4 };
    const basePort = nameMap[fortiNamed[1].toLowerCase()] || 0;
    const idx = fortiNamed[2] ? parseInt(fortiNamed[2]) : 0;
    const u = fortiNamed[4] || '0';
    return `ge-0/0/${basePort + idx}.${u}`;
  }

  // Cisco: Tunnel interfaces → st0.N
  const tunnelMatch = panosIface.match(/^tunnel(\d+)(\.(\d+))?$/i);
  if (tunnelMatch) {
    const u = tunnelMatch[1] || '0';
    return `st0.${u}`;
  }

  // Bug 1 fix: Map vendor "loopback" interfaces to SRX lo0 naming.
  // Vendor configs use "loopback.X" but SRX expects "lo0.X". Without this,
  // the zone references an undefined interface-range 'loopback.X'.
  const loMatch = panosIface.match(/^loopback(\.(\d+))?$/i);
  if (loMatch) {
    const u = loMatch[2] || '0';
    return `lo0.${u}`;
  }

  // If it doesn't match any known format, return as-is
  return panosIface;
}

/**
 * Checks if an interface name is a valid SRX interface (not a leftover vendor name).
 * Valid SRX interfaces: ge-/xe-/et-/lo0/st0/irb/ae/fxp/em/reth/vlan/me
 */
function isValidSrxInterface(ifName) {
  if (!ifName) return false;
  return /^(ge-|xe-|et-|lo0|st0|irb|ae\d|fxp|em\d|reth|vlan|me\d)/i.test(ifName);
}

// ---------------------------------------------------------------------------
// Interface Address Converter (IPv4 + IPv6)
// ---------------------------------------------------------------------------

/**
 * True when `value` is a Junos-serializable literal IPv4/IPv6 address or prefix.
 * @param {string} value - candidate address (already trimmed)
 * @returns {boolean}
 */
function isEmittableAddress(value) {
  try {
    setAddressOrPrefix(value, 'probe');
    return true;
  } catch {
    return false;
  }
}

/**
 * Emit one interface family address, skipping non-literal PAN-OS values
 * (named object refs, scoped link-locals like `fe80::1%eth0`, EUI-64 suffixes,
 * `dhcpv6`, etc.) with a caveat + warning instead of hard-blocking conversion.
 * @param {string[]} commands - output command list (mutated)
 * @param {object[]} warnings - warnings list (mutated)
 * @param {string} base - SRX physical interface (e.g. ge-0/0/1)
 * @param {string} unit - unit number
 * @param {string} ifKey - `${base}.${unit}` for messages
 * @param {'inet'|'inet6'} family - address family to emit
 * @param {string} rawValue - the source address value
 * @returns {void}
 */
function emitInterfaceAddress(commands, warnings, base, unit, ifKey, family, rawValue) {
  if (!rawValue) return;
  const value = String(rawValue).trim();
  const label = family === 'inet6' ? 'IPv6' : 'IPv4';
  if (isEmittableAddress(value)) {
    commands.push(`set interfaces ${base} unit ${unit} family ${family} address ${value}`);
    return;
  }
  // Do NOT reflect rawValue into the command stream — a malformed value may be
  // an injection payload (e.g. "192.0.2.1/24 set system services telnet"). The
  // raw value goes only into the warning (UI data, not executable output).
  commands.push(`# CAVEAT: interface ${ifKey} ${label} address omitted — source value is not a literal IP/prefix; assign it manually`);
  warnings.push(createWarning('warning', `interfaces/${ifKey}`,
    `Interface ${ifKey} ${label} address "${rawValue}" is not a literal IP/prefix (named ref, scoped, EUI-64, or dhcp keyword) — address skipped`,
    `Assign the interface ${label} address manually on the SRX`));
}

function convertInterfaceAddresses(interfaces, commands, warnings, summary, interfaceMappings = {}) {
  if (!interfaces || interfaces.length === 0) return;

  const hasAddresses = interfaces.some(i => i.ip || i.ipv6);
  if (!hasAddresses) return;

  commands.push('# =============================================');
  commands.push('# Interface Addresses');
  commands.push('# =============================================');

  // --- VLAN tagging pre-pass ---
  // Group by SRX physical base to detect tagged sub-units (802.1Q).
  const vlanByBase = new Map();       // base -> Map(unit -> tag)
  const baseHasNativeIp = new Map();  // base -> true when a unit-0 iface has an IP and no tag
  for (const iface of interfaces) {
    if (!iface.ip && !iface.ipv6) continue;
    const [base, unit = '0'] = mapInterfaceName(iface.name || '', interfaceMappings).split('.');
    const tag = iface.vlan ? String(iface.vlan) : '';
    if (tag) {
      if (!vlanByBase.has(base)) vlanByBase.set(base, new Map());
      vlanByBase.get(base).set(unit, tag);
    } else if (unit === '0') {
      baseHasNativeIp.set(base, true);
    }
  }
  for (const [base, unitTags] of vlanByBase) {
    commands.push(`set interfaces ${base} flexible-vlan-tagging`);
    if (baseHasNativeIp.get(base)) {
      const usedTags = new Set([...unitTags.values()].map(Number));
      let nativeVlan = 1;
      while (usedTags.has(nativeVlan) && nativeVlan < 4094) nativeVlan += 1;
      commands.push(`set interfaces ${base} native-vlan-id ${nativeVlan}`);
      commands.push(`# NOTE: native-vlan-id ${nativeVlan} inferred for the untagged parent IP on ${base} — verify against your VLAN plan`);
      warnings.push(createWarning('warning', `interfaces/${base}`,
        `native-vlan-id ${nativeVlan} was inferred for the untagged parent IP on ${base}`,
        'PAN-OS does not specify a native VLAN — confirm this id fits your VLAN plan'));
    }
  }

  const configuredInterfaces = new Set();
  for (const iface of interfaces) {
    if (!iface.ip && !iface.ipv6) continue;

    const srxName = mapInterfaceName(iface.name || '', interfaceMappings);
    const [base, unit = '0'] = srxName.split('.');
    const ifKey = `${base}.${unit}`;

    // Skip if this interface was already configured (multiple vendor interfaces mapped to same SRX interface)
    if (configuredInterfaces.has(ifKey)) {
      warnings.push(createWarning('warning', `interfaces/${ifKey}`,
        `Interface ${ifKey} already configured (mapped from ${iface.name}) — skipping duplicate`,
        'Check interface mappings for conflicts'));
      continue;
    }
    configuredInterfaces.add(ifKey);

    if (iface.vlan) {
      commands.push(`set interfaces ${base} unit ${unit} vlan-id ${String(iface.vlan)}`);
    }

    emitInterfaceAddress(commands, warnings, base, unit, ifKey, 'inet', iface.ip);
    emitInterfaceAddress(commands, warnings, base, unit, ifKey, 'inet6', iface.ipv6);
    if (iface.description) {
      commands.push(`set interfaces ${base} unit ${unit} description ${setQuoted(iface.description, 'interfaces.description')}`);
    }
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// Remote Access (SSL-VPN) Placeholder
// ---------------------------------------------------------------------------

/**
 * Emit an honest caveat for SSL-VPN / remote-access tunnels (e.g. PAN-OS
 * GlobalProtect). The st0 unit itself is already ensured elsewhere; here we
 * only document that the remote-access VPN was NOT auto-converted. No IKE,
 * IPsec, or access configuration is generated.
 *
 * @param {Array} interfaces - intermediateConfig.interfaces
 * @param {Array<string>} commands - output command accumulator
 * @param {object} interfaceMappings - PAN-OS→SRX interface map
 * @param {{gateways: Array<{name: string, tunnel_interface: string}>}} globalProtect
 */
function convertRemoteAccessPlaceholders(interfaces, commands, interfaceMappings = {}, globalProtect = { gateways: [] }) {
  const raInterfaces = (interfaces || []).filter(i => i.remote_access_role === 'ssl-vpn');
  if (raInterfaces.length === 0) return;

  const gatewayByTunnel = new Map(
    (globalProtect?.gateways || []).map(g => [g.tunnel_interface, g.name]),
  );

  commands.push('# =============================================');
  commands.push('# SSL-VPN / Remote Access — NOT CONVERTED');
  commands.push('# =============================================');
  for (const iface of raInterfaces) {
    const mapped = mapInterfaceName(iface.name || '', interfaceMappings);
    const gateway = gatewayByTunnel.get(iface.name);
    const gwLabel = gateway ? ` (GlobalProtect '${gateway}')` : '';
    commands.push(`# ${iface.name} -> ${mapped}: SSL-VPN${gwLabel} — remote-access VPN not auto-converted;`);
    commands.push('#   rebuild as Juniper Secure Connect / IPsec dial-up (re-implement MFA via RADIUS).');
  }
  commands.push('');
}

// ---------------------------------------------------------------------------
// Ensure Zone-Referenced Interfaces Have Family Config
// ---------------------------------------------------------------------------

/**
 * Checks all interfaces referenced in security zones and ensures each has at
 * least a `set interfaces {base} unit {unit} family inet` command. Interfaces
 * already configured via convertInterfaceAddresses are skipped.
 *
 * @param {Object[]} zones - Parsed zone objects
 * @param {Object[]} interfaces - Parsed interface objects (may be empty)
 * @param {string[]} commands - Output commands array
 * @param {Object} interfaceMappings - User-defined interface mappings
 */
function ensureZoneInterfaceFamilies(zones, interfaces, commands, interfaceMappings = {}) {
  if (!zones || zones.length === 0) return;

  // Collect all interfaces that already have a `set interfaces ... family inet` command
  const configuredRe = /^set interfaces (\S+) unit (\S+) family inet/;
  const configured = new Set();
  for (const cmd of commands) {
    const m = cmd.match(configuredRe);
    if (m) configured.add(`${m[1]}.${m[2]}`);
  }

  const added = [];
  for (const zone of zones) {
    for (const iface of zone.interfaces || []) {
      const srxIface = mapInterfaceName(iface, interfaceMappings);
      const [base, unit = '0'] = srxIface.split('.');
      const key = `${base}.${unit}`;
      if (!configured.has(key)) {
        commands.push(`set interfaces ${base} unit ${unit} family inet`);
        configured.add(key);
        added.push(srxIface);
      }
    }
  }

  if (added.length > 0) {
    // Insert a blank line after the added interface family commands
    commands.push('');
  }
}

// ---------------------------------------------------------------------------
// LAG / Aggregate Ethernet Converter
// ---------------------------------------------------------------------------

/**
 * Generates SRX ae (aggregate ethernet) interface configuration from parsed
 * LAG data in the intermediate config.
 *
 * Output:
 *   set chassis aggregated-devices ethernet device-count {N}
 *   set interfaces ae{N} aggregated-ether-options lacp {active|passive}
 *   set interfaces ae{N} description "{description}"
 *   set interfaces {member} ether-options 802.3ad ae{N}
 *
 * @param {Object[]} lagInterfaces - Array of lag_interfaces from intermediate config
 * @param {string[]} commands - Output commands array
 * @param {Object[]} warnings - Warnings array
 * @param {Object} summary - Summary counters
 * @param {Object} interfaceMappings - User-defined interface mappings
 */
function convertLagInterfaces(lagInterfaces, commands, warnings, summary, interfaceMappings = {}) {
  if (!lagInterfaces || lagInterfaces.length === 0) return;

  commands.push('# =============================================');
  commands.push('# LAG / Aggregate Ethernet Interfaces');
  commands.push('# =============================================');

  // Device count must accommodate the highest ae index
  let maxAeIndex = 0;
  for (const lag of lagInterfaces) {
    const aeMatch = lag.name.match(/^ae(\d+)$/);
    if (aeMatch) {
      const idx = parseInt(aeMatch[1], 10);
      if (idx >= maxAeIndex) maxAeIndex = idx + 1;
    }
  }

  commands.push(`set chassis aggregated-devices ethernet device-count ${maxAeIndex}`);

  for (const lag of lagInterfaces) {
    const aeName = lag.name;

    // LACP mode
    if (lag.lacp_mode === 'active' || lag.lacp_mode === 'passive') {
      commands.push(`set interfaces ${aeName} aggregated-ether-options lacp ${lag.lacp_mode}`);
    }

    // LACP system priority
    if (lag.lacp_priority) {
      commands.push(`set interfaces ${aeName} aggregated-ether-options lacp system-priority ${lag.lacp_priority}`);
    }

    // Description
    if (lag.description) {
      commands.push(`set interfaces ${aeName} description ${setQuoted(lag.description, 'lag_interfaces.description')}`);
    }

    // Member interface bindings
    for (const member of lag.members) {
      // Apply interface mapping if available
      const mappedMember = mapInterfaceName(member, interfaceMappings);
      const memberBase = mappedMember.split('.')[0];
      commands.push(`set interfaces ${memberBase} ether-options 802.3ad ${aeName}`);
    }

    summary.lag_interfaces_converted++;

    // Source name annotation for traceability
    if (lag.source_name && lag.source_name !== aeName) {
      commands.push(`# Source: ${lag.source_name} (${lag.source_members.join(', ')})`);
    }
  }

  commands.push('');

  warnings.push(createWarning('info', 'lag',
    `Converted ${lagInterfaces.length} LAG interface(s) to SRX ae configuration`,
    'Verify ae interface settings and member port assignments'));
}

// ---------------------------------------------------------------------------
// Address Object Converter
// ---------------------------------------------------------------------------

function convertAddressObjects(objects, commands, warnings, summary, identifiers, identifierPath) {
  if (!objects || objects.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Address Book (Global)');
  commands.push('# =============================================');

  for (let objectIndex = 0; objectIndex < objects.length; objectIndex += 1) {
    const obj = objects[objectIndex];
    const name = identifiers.nameForDefinition(identifierPath(`address_objects[${objectIndex}].name`));

    // Fix 6: Check all field variants for IP value (SonicWall uses subnet/network/address)
    const addrValue = obj.value || obj.ip || obj.network || obj.subnet || obj.address;

    switch (obj.type) {
      case 'host':
      case 'subnet':
      case 'network':
      case 'ip-netmask':
      case 'ip-prefix':
        if (!addrValue) {
          commands.push(`# WARNING: Address "${obj.name}" has no IP value — skipping`);
          warnings.push(createWarning('warning', `address/${name}`,
            `Address "${obj.name}" (type: ${obj.type}) has no IP/subnet value — skipped`,
            'Add an IP address or subnet to this address object'));
          continue;
        }
        {
          // Validate IP/mask: if host bits are set (e.g., 198.51.100.9/27), Junos rejects it.
          // Fix: for host addresses with non-/32 mask, use /32 (it's a host, not a network).
          let fixedAddr = addrValue;
          const cidrMatch = addrValue.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
          if (cidrMatch) {
            const [, ip, maskStr] = cidrMatch;
            const mask = parseInt(maskStr);
            if (mask < 32) {
              // Check if host bits are set
              const ipNum = ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct), 0) >>> 0;
              const netMask = mask === 0 ? 0 : (0xFFFFFFFF << (32 - mask)) >>> 0;
              if ((ipNum & ~netMask) !== 0) {
                // Host bits set — use /32 for address-book entry
                fixedAddr = `${ip}/32`;
              }
            }
          }
          commands.push(`set security address-book global address ${name} ${fixedAddr}`);
        }
        break;
      case 'range':
        if (!addrValue) {
          commands.push(`# WARNING: Range address "${obj.name}" has no range value — skipping`);
          warnings.push(createWarning('warning', `address/${name}`,
            `Range address "${obj.name}" has no range value — skipped`,
            'Add a range value (e.g., "10.0.0.1-10.0.0.10") to this address object'));
          continue;
        }
        // SRX supports range-address
        commands.push(`set security address-book global address ${name} range-address ${addrValue.replace('-', ' to ')}`);
        break;
      case 'fqdn': {
        const fqdnValue = addrValue;
        // Wildcard FQDNs (e.g., *.example.com) are not supported by SRX dns-name
        const isWildcard = fqdnValue && fqdnValue.startsWith('*.');
        if (isWildcard) {
          commands.push(`# WARNING: Wildcard FQDN "${obj.name}" (${fqdnValue}) — SRX does not support wildcard dns-name`);
          commands.push(`# Convert to specific FQDN, address feed, or address set`);
          commands.push(`set security address-book global address ${name} dns-name ${fqdnValue.slice(2)}`);
          warnings.push(createWarning('warning', `address/${name}`,
            `Wildcard FQDN "${obj.name}" (${fqdnValue}) stripped to "${fqdnValue.slice(2)}" — SRX dns-name does not support wildcards`,
            'Replace with specific FQDN or use custom address feed'));
        } else {
          let dnsCmd = `set security address-book global address ${name} dns-name ${fqdnValue}`;
          // Append ipv4-only / ipv6-only if source specified IP version
          if (obj.fqdn_ip_version === 'v4') {
            dnsCmd += ' ipv4-only';
          } else if (obj.fqdn_ip_version === 'v6') {
            dnsCmd += ' ipv6-only';
          }
          commands.push(dnsCmd);
        }
        break;
      }
      case 'wildcard':
        // No SRX equivalent — add as comment
        commands.push(`# UNSUPPORTED: Wildcard address "${obj.name}" (${addrValue}) — convert manually`);
        warnings.push(createWarning('unsupported', `address/${name}`,
          `Wildcard address "${obj.name}" cannot be converted to SRX format`,
          'Replace with subnet or range address'));
        summary.unsupported_items++;
        continue; // Skip the description line
      case 'geography':
        commands.push(`# UNSUPPORTED: Geography address "${obj.name}" (country: ${addrValue}) — SRX requires Security Intelligence feeds for geo-IP`);
        warnings.push(createWarning('unsupported', `address/${name}`,
          `Geography address "${obj.name}" (${addrValue}) has no direct SRX equivalent`,
          'Replace with static IP ranges or configure SRX Security Intelligence geo-IP feeds'));
        summary.unsupported_items++;
        continue;
      case 'dynamic':
        commands.push(`# UNSUPPORTED: Dynamic/SDN address "${obj.name}" (${addrValue}) — SRX requires manual configuration`);
        warnings.push(createWarning('unsupported', `address/${name}`,
          `Dynamic/SDN address "${obj.name}" (${addrValue}) has no direct SRX equivalent`,
          'Replace with static addresses or use SRX Security Intelligence feeds'));
        summary.unsupported_items++;
        continue;
      default:
        commands.push(`# WARNING: Unknown address type "${obj.type}" for "${obj.name}"`);
        break;
    }

    if (obj.description) {
      commands.push(`set security address-book global address ${name} description ${setQuoted(obj.description, 'address_objects.description')}`);
    }

    summary.addresses_converted++;
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// Address Group Converter
// ---------------------------------------------------------------------------

function convertAddressGroups(groups, commands, warnings, summary, identifiers, identifierPath) {
  if (!groups || groups.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Address Sets (Groups)');
  commands.push('# =============================================');

  const groupNameSet = new Set(groups.map(g => g.name));

  for (let groupIndex = 0; groupIndex < groups.length; groupIndex += 1) {
    const group = groups[groupIndex];
    const groupName = identifiers.nameForDefinition(identifierPath(`address_groups[${groupIndex}].name`));
    if (group._dynamic) {
      commands.push(`# UNSUPPORTED: Dynamic address group "${group.name}" — SRX does not support tag-based dynamic groups`);
      commands.push(`# Define members statically or use SRX address-book with feed servers`);
      continue;
    }

    for (let memberIndex = 0; memberIndex < group.members.length; memberIndex += 1) {
      const member = group.members[memberIndex];
      const memberName = identifiers.nameForReference(
        identifierPath(`address_groups[${groupIndex}].members[${memberIndex}]`),
      );
      if (groupNameSet.has(member)) {
        commands.push(`set security address-book global address-set ${groupName} address-set ${memberName}`);
      } else {
        commands.push(`set security address-book global address-set ${groupName} address ${memberName}`);
      }
    }

    if (group.description) {
      commands.push(`set security address-book global address-set ${groupName} description ${setQuoted(group.description, 'address_groups.description')}`);
    }

    summary.address_groups_converted++;
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// Service Object Converter → SRX Applications
// ---------------------------------------------------------------------------

function convertServiceObjects(services, commands, warnings, summary, identifiers, identifierPath) {
  if (!services || services.length === 0) return;

  predefServiceMap.clear();

  commands.push('# =============================================');
  commands.push('# Applications (from Service Objects)');
  commands.push('# =============================================');

  for (let serviceIndex = 0; serviceIndex < services.length; serviceIndex += 1) {
    const svc = services[serviceIndex];
    const protocol = svc.protocol || 'tcp';
    const port = svc.port_range || '';

    // Check if this service maps to a predefined Junos application
    const predefApp = isPredefEquivalent(svc.name, protocol, port);
    if (predefApp) {
      predefServiceMap.set(svc.name, predefApp);
      commands.push(`# Skipped: "${svc.name}" (${protocol}/${port}) → predefined ${predefApp}`);
      summary.services_converted++;
      continue;
    }

    if (!port && !['icmp', 'icmp6'].includes(protocol)
        && !(protocol === 'ip' && svc.protocol_number)) {
      commands.push(`# WARNING: Service "${svc.name}" has no port defined — skipping`);
      warnings.push(createWarning('warning', `service/${svc.name}`,
        `Service "${svc.name}" has no port range defined`,
        'Define the port range for this service'));
      continue;
    }

    const ownerPath = identifierPath(`service_objects[${serviceIndex}]`);
    const multiPort = port.includes(',');
    const name = multiPort
      ? identifiers.nameForGenerated(ownerPath, 'service-multi-port-set')
      : identifiers.nameForDefinition(identifierPath(`service_objects[${serviceIndex}].name`));

    if (protocol === 'icmp' || protocol === 'icmp6') {
      // ICMP services use icmp-type/icmp-code instead of destination-port
      commands.push(`set applications application ${name} protocol ${protocol}`);
      if (svc.icmp_type) {
        commands.push(`set applications application ${name} icmp-type ${svc.icmp_type}`);
      }
      if (svc.icmp_code) {
        commands.push(`set applications application ${name} icmp-code ${svc.icmp_code}`);
      }
    } else if (protocol === 'ip' && svc.protocol_number) {
      // IP protocol by number
      commands.push(`set applications application ${name} protocol ${svc.protocol_number}`);
    } else {
      // TCP/UDP/SCTP — require port
      // Bug 2 fix: Junos destination-port does not accept comma-separated discrete
      // ports (e.g., "443,8443"). Split into individual applications and wrap in an
      // application-set so policies can reference the set by the original name.
      if (port.includes(',')) {
        const setName = name;
        commaPortSetMap.set(svc.name, setName);
        const portParts = [...new Set(port.split(',').map(p => p.trim()))].sort();
        for (const part of portParts) {
          const subName = identifiers.nameForGenerated(ownerPath, `service-port:${part}`);
          commands.push(`set applications application ${subName} protocol ${protocol}`);
          commands.push(`set applications application ${subName} destination-port ${part}`);
        }
        for (const part of portParts) {
          const subName = identifiers.nameForGenerated(ownerPath, `service-port:${part}`);
          commands.push(`set applications application-set ${setName} application ${subName}`);
        }
      } else {
        commands.push(`set applications application ${name} protocol ${protocol}`);
        commands.push(`set applications application ${name} destination-port ${port}`);
      }

      if (svc.source_port) {
        commands.push(`set applications application ${name} source-port ${svc.source_port}`);
      }
    }

    if (svc.description) {
      const hierarchy = multiPort ? 'application-set' : 'application';
      commands.push(`set applications ${hierarchy} ${name} description ${setQuoted(svc.description, 'service_objects.description')}`);
    }

    summary.services_converted++;
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// Service Group Converter → SRX Application Sets
// ---------------------------------------------------------------------------

function convertServiceGroups(groups, commands, warnings, summary, sourceVendor = '', identifiers, identifierPath) {
  if (!groups || groups.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Application Sets (from Service Groups)');
  commands.push('# =============================================');

  const groupNameSet = new Set(groups.map(g => g.name));

  for (let groupIndex = 0; groupIndex < groups.length; groupIndex += 1) {
    const group = groups[groupIndex];
    const groupName = identifiers.nameForDefinition(identifierPath(`service_groups[${groupIndex}].name`));

    for (let memberIndex = 0; memberIndex < group.members.length; memberIndex += 1) {
      const member = group.members[memberIndex];
      const memberName = identifiers.nameForReference(
        identifierPath(`service_groups[${groupIndex}].members[${memberIndex}]`),
      );
      if (groupNameSet.has(member)) {
        commands.push(`set applications application-set ${groupName} application-set ${memberName}`);
      } else {
        commands.push(`set applications application-set ${groupName} application ${memberName}`);
      }
    }

    summary.services_converted++;
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// Custom Application Converter
// ---------------------------------------------------------------------------

function convertApplications(apps, commands, warnings, summary, identifiers, identifierPath) {
  if (!apps || apps.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Custom Applications');
  commands.push('# =============================================');

  for (let applicationIndex = 0; applicationIndex < apps.length; applicationIndex += 1) {
    const app = apps[applicationIndex];
    if (!app.protocol || !app.port) {
      commands.push(`# INTERVIEW REQUIRED: Custom application "${app.name}" needs protocol/port definition`);
      continue;
    }

    const ownerPath = identifierPath(`applications[${applicationIndex}]`);
    const multiPort = app.port.includes(',');
    const name = multiPort
      ? identifiers.nameForGenerated(ownerPath, 'application-multi-port-set')
      : identifiers.nameForDefinition(identifierPath(`applications[${applicationIndex}].name`));

    // Bug 2 fix: handle comma-separated discrete ports in custom apps too
    if (app.port.includes(',')) {
      const setName = name;
      commaPortSetMap.set(app.name, setName);
      const portParts = [...new Set(app.port.split(',').map(p => p.trim()))].sort();
      for (const part of portParts) {
        const subName = identifiers.nameForGenerated(ownerPath, `application-port:${part}`);
        commands.push(`set applications application ${subName} protocol ${app.protocol}`);
        commands.push(`set applications application ${subName} destination-port ${part}`);
      }
      for (const part of portParts) {
        const subName = identifiers.nameForGenerated(ownerPath, `application-port:${part}`);
        commands.push(`set applications application-set ${setName} application ${subName}`);
      }
    } else {
      commands.push(`set applications application ${name} protocol ${app.protocol}`);
      commands.push(`set applications application ${name} destination-port ${app.port}`);
    }

    if (app.description) {
      const hierarchy = multiPort ? 'application-set' : 'application';
      commands.push(`set applications ${hierarchy} ${name} description ${setQuoted(app.description, 'applications.description')}`);
    }
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// UTM Policy Converter
// ---------------------------------------------------------------------------

/**
 * Scans all security policies for UTM-relevant profiles (virus, wildfire,
 * url-filtering, file-blocking) and generates SRX UTM feature profiles
 * and utm-policy definitions.
 *
 * Returns { utmCommands, utmPolicyMap } where utmPolicyMap maps
 * rule name → utm-policy name for attachment in convertSecurityPolicies.
 */
function convertUtmPolicies(policies, warnings, profileDefs = {}, identifiers, identifierPath) {
  const utmCommands = [];
  const utmPolicyMap = {};
  if (!policies || policies.length === 0) return { utmCommands, utmPolicyMap };

  const utmTypes = ['virus', 'wildfire-analysis', 'url-filtering', 'file-blocking', 'email-filter',
    'application-control', 'dlp', 'dns-security', 'decryption', 'waf', 'casb', 'voip'];
  const securityFeatures = canonicalizeJunosSecurityFeatures({
    security_policies: policies,
    security_profile_definitions: profileDefs,
  });
  const featureUseLookup = new Map();
  for (const feature of securityFeatures) {
    for (const use of feature.uses) {
      featureUseLookup.set(`${use.policyIndex}\0${use.type}`, feature);
    }
  }

  // Collect unique UTM profile combinations per rule
  const comboMap = new Map(); // serialized combo → { profiles, policyName, rules[] }
  const defaultUtmPolicies = [];
  for (let policyIndex = 0; policyIndex < policies.length; policyIndex += 1) {
    const policy = policies[policyIndex];
    const sp = policy.security_profiles || {};
    if (policy.profile_group && Object.keys(sp).length === 0) {
      defaultUtmPolicies.push({ policy, policyIndex });
    }
    const utmProfiles = {};
    for (const t of utmTypes) {
      if (sp[t]) utmProfiles[t] = sp[t];
    }
    if (Object.keys(utmProfiles).length === 0) continue;

    const key = JSON.stringify(utmProfiles);
    if (!comboMap.has(key)) {
      comboMap.set(key, { profiles: utmProfiles, policyIndexes: [] });
    }
    comboMap.get(key).policyIndexes.push(policyIndex);
  }

  if (comboMap.size === 0 && defaultUtmPolicies.length === 0) return { utmCommands, utmPolicyMap };

  utmCommands.push('# =============================================');

  if (defaultUtmPolicies.length > 0) {
    const owner = [...defaultUtmPolicies].sort((left, right) => (
      String(left.policy.name || '').localeCompare(String(right.policy.name || ''))
    ))[0];
    const defaultUtmName = identifiers.nameForGenerated(
      identifierPath(`security_policies[${owner.policyIndex}]`),
      'default-utm-policy',
    );
    utmCommands.push(`# Default UTM policy for source profile groups without individual profile detail`);
    utmCommands.push(`set security utm utm-policy ${defaultUtmName}`);
    for (const { policyIndex } of defaultUtmPolicies) {
      utmPolicyMap[policyIndex] = defaultUtmName;
      identifiers.nameForReference(
        identifierPath(`security_policies[${policyIndex}]#utm-policy`),
      );
    }
  }
  utmCommands.push('# UTM Feature Profiles & Policies');
  utmCommands.push('# NOTE: Generated profiles use recommended defaults — review and customize for your environment');
  utmCommands.push('# =============================================');

  // Collect all unique feature profiles
  const emittedProfiles = new Set();

  const orderedCombos = [...comboMap.entries()].sort(([left], [right]) => left.localeCompare(right));
  for (const [, combo] of orderedCombos) {
    const ownerIndex = combo.policyIndexes[0];
    const pName = identifiers.nameForGenerated(
      identifierPath(`security_policies[${ownerIndex}]`),
      'utm-policy',
    );
    for (const policyIndex of combo.policyIndexes) utmPolicyMap[policyIndex] = pName;

    for (const [pType, pValue] of Object.entries(combo.profiles)) {
      const mapped = mapProfileToSrx(pType, pValue);
      const defKey = `${pType}:${pValue}`;
      const profileDef = profileDefs[defKey];
      const feature = featureUseLookup.get(`${combo.policyIndexes[0]}\0${pType}`);
      let profileName = mapped.srxProfile;
      if (feature) {
        profileName = identifiers.nameForGenerated(
          identifierPath(`security_policies[${feature.ownerIndex}]`),
          feature.role,
        );
        for (const policyIndex of combo.policyIndexes) {
          identifiers.nameForReference(
            identifierPath(`security_policies[${policyIndex}].security_profiles.${pType}`),
          );
        }
      }

      // AppFW: generate actual rule-set if we have category data
      if (mapped.srxFeature === 'appfw') {
        if (profileDef && profileDef.categories && Object.keys(profileDef.categories).length > 0) {
          const rsName = profileName;
          utmCommands.push(`# Application Firewall rule-set from application-control "${pValue}"`);
          let ruleNum = 0;
          const blockedCategories = Object.entries(profileDef.categories)
            .filter(([, action]) => action === 'block' || action === 'block-all' || action === 'reset')
            .sort(([left], [right]) => left.localeCompare(right));
          for (const [category] of blockedCategories) {
            ruleNum++;
            const ruleName = identifiers.nameForGenerated(
              identifierPath(`security_policies[${feature.ownerIndex}]`),
              `application-firewall-rule-${ruleNum}`,
            );
            // identifier-catalog: non-symbol application-firewall dynamic-application-group match value
            utmCommands.push(`set security application-firewall rule-sets ${rsName} rule ${ruleName} match dynamic-application-group junos:${sanitizeJunosName(category)}`);
            utmCommands.push(`set security application-firewall rule-sets ${rsName} rule ${ruleName} then deny`);
          }
          if (ruleNum > 0) {
            utmCommands.push(`set security application-firewall rule-sets ${rsName} default-rule permit`);
          } else {
            utmCommands.push(`# No blocked categories found in "${pValue}" — configure AppFW manually if needed`);
          }
        } else {
          utmCommands.push(`# NOTE: application-control "${pValue}" — configure SRX AppFW rule-set manually`);
        }
        continue;
      }
      if (mapped.srxFeature === 'none') {
        utmCommands.push(`# NOTE: DLP profile "${pValue}" — SRX DLP requires ICAP integration`);
        warnings.push(createWarning('unsupported', `profile/dlp/${pValue}`,
          `DLP profile "${pValue}" requires ICAP integration on SRX`,
          'Configure an ICAP server and redirect profile for DLP inspection'));
        continue;
      }

      if (mapped.srxFeature === 'ssl-proxy') {
        // SSL Proxy profiles are now generated by convertSslProxyConfig()
        continue;
      }
      if (mapped.srxFeature === 'unsupported') {
        utmCommands.push(`# NOTE: file-blocking profile "${pValue}" — not supported in SRX conversion`);
        warnings.push(createWarning('unsupported', `profile/${pType}/${pValue}`,
          `File-blocking profile "${pValue}" is not supported in Junos SRX conversion`,
          'SRX does not have an equivalent file-blocking feature — review UTM content-filtering or ICAP for similar functionality'));
        continue;
      }
      if (mapped.srxFeature === 'unknown') {
        warnings.push(createWarning('unsupported', `profile/${pType}/${pValue}`,
          `${pType} profile "${pValue}" has no SRX equivalent`,
          `Review SRX capabilities for ${pType} and configure manually`));
        utmCommands.push(`# UNSUPPORTED: ${pType} profile "${pValue}" — no direct SRX equivalent`);
        continue;
      }

      if (mapped.srxFeature !== 'utm') continue;

      // Emit feature profile definition once (uses source-derived params when available)
      if (!emittedProfiles.has(profileName)) {
        emittedProfiles.add(profileName);
        if (mapped.srxType === 'anti-virus') {
          const sizeLimit = (profileDef && profileDef.scanMode === 'full') ? 40000 : 20000;
          utmCommands.push(`set security utm feature-profile anti-virus profile ${profileName} fallback-options default log-and-permit`);
          utmCommands.push(`set security utm feature-profile anti-virus profile ${profileName} fallback-options content-size log-and-permit`);
          // content-size-limit and timeout are not valid under AV profile in modern Junos — skip
        } else if (mapped.srxType === 'web-filtering') {
          // Fix 3: Junos requires the web-filtering type to be set before
          // defining profiles, and the utm-policy http-profile name must match
          // the profile name defined under juniper-enhanced exactly.
          utmCommands.push(`set security utm feature-profile web-filtering type juniper-enhanced`);
          if (profileDef && profileDef.blockCategories && profileDef.blockCategories.length > 0) {
            utmCommands.push(`# Block categories from source: ${profileDef.blockCategories.join(', ')}`);
            utmCommands.push(`set security utm feature-profile web-filtering juniper-enhanced profile ${profileName} default block`);
          } else {
            utmCommands.push(`set security utm feature-profile web-filtering juniper-enhanced profile ${profileName} default log-and-permit`);
          }
        } else if (mapped.srxType === 'content-filtering') {
          if (profileDef && profileDef.blockedExtensions && profileDef.blockedExtensions.length > 0) {
            for (const ext of profileDef.blockedExtensions) {
              // identifier-catalog: non-symbol content-filtering block-extension match value
              utmCommands.push(`set security utm feature-profile content-filtering profile ${profileName} block-extension ${sanitizeJunosName(ext)}`);
            }
          } else {
            utmCommands.push(`set security utm feature-profile content-filtering profile ${profileName} permit-command file-extension exe`);
            utmCommands.push(`set security utm feature-profile content-filtering profile ${profileName} permit-command file-extension zip`);
          }
        } else if (mapped.srxType === 'dns-security') {
          utmCommands.push(`# DNS Security from "${pValue}" — requires ATP Cloud license`);
          if (profileDef && profileDef.blockedDomains && profileDef.blockedDomains.length > 0) {
            for (const domain of profileDef.blockedDomains) {
              utmCommands.push(`set services dns-filtering dns-filtering-rule ${profileName} match-name ${domain}`);
              utmCommands.push(`set services dns-filtering dns-filtering-rule ${profileName} then action block`);
            }
          }
          utmCommands.push(`set services dns-filtering default-action allow`);
        } else if (mapped.srxType === 'anti-spam') {
          utmCommands.push(`set security utm feature-profile anti-spam profile ${profileName} sbl-default-server`);
        } else {
          utmCommands.push(`set security utm feature-profile ${mapped.srxType} profile ${profileName}`);
        }
      }

      // Attach to utm-policy
      if (mapped.srxType === 'anti-virus') {
        utmCommands.push(`set security utm utm-policy ${pName} anti-virus http-profile ${profileName}`);
        utmCommands.push(`set security utm utm-policy ${pName} anti-virus smtp-profile ${profileName}`);
      } else if (mapped.srxType === 'web-filtering') {
        utmCommands.push(`set security utm utm-policy ${pName} web-filtering http-profile ${profileName}`);
      } else if (mapped.srxType === 'content-filtering') {
        utmCommands.push(`set security utm utm-policy ${pName} content-filtering rule-set ${profileName}`);
      } else if (mapped.srxType === 'anti-spam') {
        utmCommands.push(`set security utm utm-policy ${pName} anti-spam smtp-profile ${profileName}`);
      }
    }
  }

  utmCommands.push('');
  return { utmCommands, utmPolicyMap };
}

// ---------------------------------------------------------------------------
// IDP Policy Converter
// ---------------------------------------------------------------------------

/**
 * Scans policies for IDP-relevant profiles (spyware, vulnerability) and
 * generates SRX IDP policy definitions.
 */
function convertIdpPolicies(policies, warnings, profileDefs = {}, identifiers, identifierPath) {
  const idpCommands = [];
  const idpPolicyMap = {};
  if (!policies || policies.length === 0) return { idpCommands, idpPolicyMap };

  const idpTypes = ['spyware', 'vulnerability'];
  const comboMap = new Map();

  for (let sourcePolicyIndex = 0; sourcePolicyIndex < policies.length; sourcePolicyIndex += 1) {
    const policy = policies[sourcePolicyIndex];
    const sp = policy.security_profiles || {};
    const hasIdp = idpTypes.some(t => sp[t]);
    if (!hasIdp) continue;

    const idpProfiles = {};
    for (const t of idpTypes) {
      if (sp[t]) idpProfiles[t] = sp[t];
    }

    const key = JSON.stringify(idpProfiles);
    if (!comboMap.has(key)) {
      comboMap.set(key, { profiles: idpProfiles, policyIndexes: [] });
    }
    comboMap.get(key).policyIndexes.push(sourcePolicyIndex);
  }

  if (comboMap.size === 0) return { idpCommands, idpPolicyMap };

  idpCommands.push('# =============================================');
  idpCommands.push('# IDP Policies');
  idpCommands.push('# NOTE: Actions derived from source profile name heuristics — review for your environment');
  idpCommands.push('# =============================================');

  const idpActionMap = {
    'reset-both': 'drop-connection', 'reset-client': 'drop-connection',
    'reset-server': 'drop-connection', 'drop': 'drop-packet',
    'block': 'drop-connection', 'block-all': 'drop-connection',
    'alert': 'no-action', 'monitor': 'no-action',
    'pass': 'no-action', 'default': 'recommended',
  };

  const orderedCombos = [...comboMap.entries()].sort(([left], [right]) => left.localeCompare(right));
  for (const [, combo] of orderedCombos) {
    const ownerIndex = combo.policyIndexes[0];
    const pName = identifiers.nameForGenerated(
      identifierPath(`security_policies[${ownerIndex}]`),
      'idp-policy',
    );
    for (const sourcePolicyIndex of combo.policyIndexes) {
      idpPolicyMap[sourcePolicyIndex] = pName;
    }
    let ruleIdx = 0;

    for (const [pType, pValue] of Object.entries(combo.profiles)) {
      const defKey = `${pType}:${pValue}`;
      const profileDef = profileDefs[defKey];

      if (profileDef && profileDef.severityActions && Object.keys(profileDef.severityActions).length > 0) {
        // Generate severity-specific IDP rules from source profile data
        const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
        for (const severity of severityOrder) {
          const sourceAction = profileDef.severityActions[severity];
          if (!sourceAction) continue;

          ruleIdx++;
          const ruleName = identifiers.nameForGenerated(
            identifierPath(`security_policies[${ownerIndex}]`),
            `idp-rule-${ruleIdx}`,
          );
          const base = `security idp idp-policy ${pName} rulebase-ips rule ${ruleName}`;
          const idpAction = idpActionMap[sourceAction] || 'recommended';
          const attackGroup = severity.charAt(0).toUpperCase() + severity.slice(1);

          idpCommands.push(`set ${base} match attacks predefined-attack-groups ${setQuoted(`${attackGroup} - Recommended`, 'security_profiles.idp.attack_group')}`);
          idpCommands.push(`set ${base} then action ${idpAction}`);
          idpCommands.push(`set ${base} then notification log-attacks`);
          idpCommands.push(`# Mapped from ${pType} "${pValue}" severity ${severity} (${sourceAction}) → SRX ${idpAction}`);
        }
      } else {
        // Fallback: name-based heuristics when no profile definitions available
        ruleIdx++;
        const ruleName = identifiers.nameForGenerated(
          identifierPath(`security_policies[${ownerIndex}]`),
          `idp-rule-${ruleIdx}`,
        );
        const base = `security idp idp-policy ${pName} rulebase-ips rule ${ruleName}`;

        const nameLower = pValue.toLowerCase();
        let idpAction = 'recommended';
        if (nameLower.includes('strict') || nameLower.includes('critical')) {
          idpAction = 'drop-connection';
        } else if (nameLower.includes('alert') || nameLower.includes('monitor')) {
          idpAction = 'no-action';
        }

        idpCommands.push(`set ${base} match attacks predefined-attack-groups "Recommended"`);
        idpCommands.push(`set ${base} then action ${idpAction}`);
        idpCommands.push(`set ${base} then notification log-attacks`);
        idpCommands.push(`# IDP rule mapped from ${pType} profile "${pValue}" → action: ${idpAction}`);
      }
    }
  }

  idpCommands.push('');
  return { idpCommands, idpPolicyMap };
}

// ---------------------------------------------------------------------------
// Security Intelligence (SecIntel) Converter
// ---------------------------------------------------------------------------

/**
 * Generates SRX Security Intelligence configuration from detected EDL block lists.
 */
function convertSecIntel(externalLists, policies, warnings, identifiers, identifierPath) {
  const secIntelCommands = [];
  let secIntelEnabled = false;
  let secIntelPolicyName = 'secIntel-policy';
  if (!externalLists || externalLists.length === 0) return { secIntelCommands, secIntelEnabled, secIntelPolicyName };

  const blockLists = externalLists
    .map((list, index) => ({ list, index }))
    .filter(({ list }) => list.isBlockList)
    .sort((left, right) => String(left.list.name).localeCompare(String(right.list.name)));
  if (blockLists.length === 0) return { secIntelCommands, secIntelEnabled, secIntelPolicyName };

  secIntelEnabled = true;

  secIntelCommands.push('# =============================================');
  secIntelCommands.push('# Security Intelligence (SecIntel)');
  secIntelCommands.push('# =============================================');

  // Create a SecIntel profile with rules for each block list
  const firstOwnerPath = identifierPath(`external_lists[${blockLists[0].index}]`);
  const profileName = identifiers.nameForGenerated(
    firstOwnerPath,
    'security-intelligence-profile',
  );
  secIntelPolicyName = identifiers.nameForGenerated(
    firstOwnerPath,
    'security-intelligence-policy',
  );
  let ruleIdx = 0;

  for (const { list: bl, index: blockListIndex } of blockLists) {
    ruleIdx++;
    const ruleName = identifiers.nameForGenerated(
      identifierPath(`external_lists[${blockListIndex}].name`),
      'security-intelligence-rule',
    );

    secIntelCommands.push(`# EDL: "${bl.name}" (${bl.isPredefined ? 'predefined' : 'custom'}, type: ${bl.listType})`);
    secIntelCommands.push(`set services security-intelligence profile ${profileName} category BlockList`);
    secIntelCommands.push(`set services security-intelligence profile ${profileName} rule ${ruleName} match threat-level 10`);
    secIntelCommands.push(`set services security-intelligence profile ${profileName} rule ${ruleName} then action block close`);
    secIntelCommands.push(`set services security-intelligence profile ${profileName} rule ${ruleName} then log`);
  }

  secIntelCommands.push(`set services security-intelligence policy ${secIntelPolicyName} ${profileName}`);

  warnings.push(createWarning(
    'warning',
    'security-intelligence',
    `${blockLists.length} EDL block list(s) mapped to SRX SecIntel: [${blockLists.map(({ list }) => list.name).join(', ')}]`,
    'Verify SRX platform supports Security Intelligence and configure feed servers'
  ));

  secIntelCommands.push('');
  return { secIntelCommands, secIntelEnabled, secIntelPolicyName };
}

// ---------------------------------------------------------------------------
// Schedule Converter → SRX Schedulers
// ---------------------------------------------------------------------------

const DAY_NAME_MAP = {
  sun: 'sunday', mon: 'monday', tue: 'tuesday', wed: 'wednesday',
  thu: 'thursday', fri: 'friday', sat: 'saturday',
  sunday: 'sunday', monday: 'monday', tuesday: 'tuesday', wednesday: 'wednesday',
  thursday: 'thursday', friday: 'friday', saturday: 'saturday',
};

function convertSchedules(schedules, commands, warnings, identifiers, identifierPath) {
  if (!schedules || schedules.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Schedulers');
  commands.push('# =============================================');

  for (let scheduleIndex = 0; scheduleIndex < schedules.length; scheduleIndex += 1) {
    const sched = schedules[scheduleIndex];
    const name = identifiers.nameForDefinition(identifierPath(`schedules[${scheduleIndex}].name`));
    if (sched.type === 'recurring' && sched.days && sched.days.length > 0) {
      for (const day of sched.days) {
        const junosDay = DAY_NAME_MAP[day.toLowerCase()] || day.toLowerCase();
        commands.push(`set schedulers scheduler ${name} ${junosDay} start-time ${sched.start} stop-time ${sched.end}`);
      }
    } else if (sched.type === 'onetime') {
      commands.push(`set schedulers scheduler ${name} start-date ${setQuoted(sched.start, 'schedules.start')} stop-date ${setQuoted(sched.end, 'schedules.end')}`);
    } else {
      commands.push(`# WARNING: Schedule "${sched.name}" has unknown type "${sched.type}" — skipping`);
    }
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// User Identification (JIMS) — emitted when policies use source_users
// ---------------------------------------------------------------------------

function convertUserIdentification(policies, commands, warnings) {
  if (!policies || policies.length === 0) return;
  const identityPolicies = policies.filter(p => p.source_users && p.source_users.length > 0);
  if (identityPolicies.length === 0) return;

  commands.push('# =============================================');
  commands.push('# User Identification (JIMS Integration)');
  commands.push('# =============================================');
  commands.push('# NOTE: JIMS/User-ID requires manual configuration with server-specific details.');
  commands.push('# Configure identity-management connection after JIMS server is set up:');
  commands.push('# set services user-identification identity-management connection connect-method https');
  commands.push('# set services user-identification identity-management connection port 1443');
  commands.push('# set services user-identification identity-management connection primary address <JIMS_SERVER_IP>');
  commands.push('# set services user-identification identity-management connection primary client-id <CLIENT_ID>');
  commands.push('# set services user-identification identity-management connection primary client-secret <SECRET>');
  commands.push('');

  // Document all unique identity references
  const allIdentities = new Set();
  for (const p of identityPolicies) {
    for (const id of p.source_users) allIdentities.add(id);
  }
  commands.push(`# Identity references used in ${identityPolicies.length} policies:`);
  for (const id of allIdentities) {
    commands.push(`#   - ${id}`);
  }
  commands.push('');

  warnings.push(createWarning(
    'interview_required',
    'services/user-identification',
    `${identityPolicies.length} policies use identity-based match (source_users) — JIMS server configuration required`,
    'Configure JIMS server IP, client-id, and client-secret. Ensure AD user/group names match the source firewall identities.'
  ));
}

// ---------------------------------------------------------------------------
// Security Policy Converter
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

/**
 * Emit the match/action body for one security policy (everything after the
 * `security policies ... policy <name>` prefix line). Shared by both the
 * zone-pair and global emission paths so their behavior cannot drift.
 *
 * @param {string[]} commands - output accumulator
 * @param {string} policyPath - e.g. `security policies global policy P` or
 *   `security policies from-zone X to-zone Y policy P`
 * @param {string} policyName - resolved policy identifier
 * @param {object} ctx - see plan Task 1 Interfaces block
 */
function emitPolicyBody(commands, policyPath, policyName, ctx) {
  const {
    policy, pIdx, srcAddrs, dstAddrs, dstZones, appGroups, sourceVendor,
    utmPolicyMap, idpPolicyMap, secIntelEnabled, secIntelPolicyName,
    identifiers, identifierPath, warnings, deactivateCommands, deactivateCaveats,
    policyReferenceIssues, unmappedAppPolicyIndices,
  } = ctx;

  // Description (include source tags as comments)
  let fullDescription = policy.description || '';
  const sourceTags = (policy.tags || []).filter((tag) => !(policy._implicit && tag === INTERNAL_IMPLICIT_RULE_TAG));
  if (sourceTags.length > 0) {
    const tagLabel = !sourceVendor || sourceVendor === 'panos' ? 'PAN-OS tags' : 'Source tags';
    const tagNote = `[${tagLabel}: ${sourceTags.join(', ')}]`;
    fullDescription = fullDescription ? `${fullDescription} ${tagNote}` : tagNote;
  }
  if (fullDescription) {
    commands.push(`set ${policyPath} description ${setQuoted(fullDescription, `security_policies[${pIdx}].description`)}`);
  }

  const effectiveSrcAddrs = srcAddrs.length > 0 ? srcAddrs : [{ value: 'any', index: null }];
  for (const { index: addressIndex } of effectiveSrcAddrs) {
    const addressName = addressIndex === null
      ? 'any'
      : identifiers.nameForReference(identifierPath(`security_policies[${pIdx}].src_addresses[${addressIndex}]`));
    commands.push(`set ${policyPath} match source-address ${addressName}`);
  }
  if (policy.negate_source) commands.push(`set ${policyPath} match source-address-excluded`);

  const effectiveDstAddrs = dstAddrs.length > 0 ? dstAddrs : [{ value: 'any', index: null }];
  for (const { index: addressIndex } of effectiveDstAddrs) {
    const addressName = addressIndex === null
      ? 'any'
      : identifiers.nameForReference(identifierPath(`security_policies[${pIdx}].dst_addresses[${addressIndex}]`));
    commands.push(`set ${policyPath} match destination-address ${addressName}`);
  }
  if (policy.negate_destination) commands.push(`set ${policyPath} match destination-address-excluded`);

  let apps = resolveApplications(policy.applications, policy.services, warnings, policyName, appGroups, sourceVendor, pIdx, identifiers, identifierPath);
  if (apps.includes('any')) apps = ['any'];
  const hasUnmappedApp = apps.some(a => unmappedApps.has(a));

  // Fix 1: Track this policy index if it has an unmapped app
  if (hasUnmappedApp && unmappedAppPolicyIndices) {
    unmappedAppPolicyIndices.add(pIdx);
  }

  for (const app of apps) {
    commands.push(`set ${policyPath} match application ${app}`);
  }

  if (policy.source_users && policy.source_users.length > 0) {
    for (const identity of policy.source_users) {
      // identifier-catalog: non-symbol security-policy source-identity match value
      commands.push(`set ${policyPath} match source-identity ${setQuoted(sanitizeJunosName(identity), `security_policies[${pIdx}].source_users`)}`);
    }
  }

  const srxAction = mapAction(policy.action);
  commands.push(`set ${policyPath} then ${srxAction}`);

  if (policy.log_start) commands.push(`set ${policyPath} then log session-init`);
  if (policy.log_end) commands.push(`set ${policyPath} then log session-close`);
  if (policy._srx_log_count !== false) commands.push(`set ${policyPath} then count`);

  if (utmPolicyMap[pIdx]) {
    const utmPolicyName = identifiers.nameForReference(identifierPath(`security_policies[${pIdx}]#utm-policy`));
    commands.push(`set ${policyPath} then permit application-services utm-policy ${utmPolicyName}`);
  }
  if (idpPolicyMap[pIdx]) {
    const idpPolicyName = identifiers.nameForReference(identifierPath(`security_policies[${pIdx}]#idp-policy`));
    commands.push(`set ${policyPath} then permit application-services idp-policy ${idpPolicyName}`);
  }
  if (secIntelEnabled && policy.action === 'allow' && dstZones.some(z => z.toLowerCase() === 'untrust')) {
    commands.push(`set ${policyPath} then permit application-services security-intelligence-policy ${secIntelPolicyName}`);
  }

  if (policy._srx_decrypt && policy.action === 'allow') {
    const sslProfile = identifiers.nameForReference(identifierPath(
      policy._srx_decrypt_profile
        ? `security_policies[${pIdx}]._srx_decrypt_profile`
        : `security_policies[${pIdx}]#ssl-proxy-profile`,
    ));
    commands.push(`# NOTE: SSL proxy skipped — profile "${sslProfile}" requires manual PKI setup before enabling`);
    commands.push(`# set ${policyPath} then permit application-services ssl-proxy profile-name ${sslProfile}`);
  }

  if (policy.schedule) {
    const scheduleName = identifiers.nameForReference(identifierPath(`security_policies[${pIdx}].schedule`));
    commands.push(`set ${policyPath} scheduler-name ${scheduleName}`);
  }

  // Check for undefined references (addresses or services)
  const hasUndefinedRef = policyReferenceIssues && policyReferenceIssues.has(pIdx);

  const negationIssues = findNegationIssues(policy);

  if (policy.disabled || hasUnmappedApp || hasUndefinedRef || negationIssues.length > 0) {
    if (negationIssues.length > 0) {
      deactivateCaveats.push(`# CAVEAT: policy deactivated — negated address match not representable: ${negationIssues.join('; ')}`);
      warnings.push(createWarning(
        'warning',
        `security_policies[${pIdx}]`,
        `Policy ${policy.name || pIdx} deactivated: ${negationIssues.join('; ')}`,
        'Rewrite the negated address match by hand before enabling this policy.',
      ));
    }
    if (hasUndefinedRef) {
      // Emit caveat comment naming the undefined reference(s)
      const issue = policyReferenceIssues.get(pIdx);
      const undefinedItems = [];
      if (issue.addresses && issue.addresses.length > 0) {
        for (const addr of issue.addresses) {
          undefinedItems.push(`address "${addr}"`);
        }
      }
      if (issue.services && issue.services.length > 0) {
        for (const svc of issue.services) {
          undefinedItems.push(`service "${svc}"`);
        }
      }
      const caveatMsg = `# CAVEAT: policy deactivated — undefined reference(s): ${undefinedItems.join(', ')}`;
      deactivateCaveats.push(caveatMsg);

      // Create a warning for the report
      warnings.push(createWarning(
        `Policy ${policy.name || pIdx} has undefined reference(s): ${undefinedItems.join(', ')}`,
        `security_policies[${pIdx}]`,
        `Policy references undefined objects: ${undefinedItems.join(', ')}`,
      ));
    }
    deactivateCommands.push(`deactivate ${policyPath}`);
  }
}

function convertSecurityPolicies(policies, commands, warnings, summary, profileMaps = {}, appGroups = [], sourceVendor = '', ruleGroups = [], identifiers, identifierPath, policyStructure = 'global', policyReferenceIssues = new Map()) {
  if (!policies || policies.length === 0) return;

  const {
    utmPolicyMap = {}, idpPolicyMap = {}, secIntelEnabled = false,
    secIntelPolicyName = 'secIntel-policy',
  } = profileMaps;

  commands.push('# =============================================');
  commands.push('# Security Policies');
  commands.push('# =============================================');

  // Build rule-index→group map for group comment insertion
  const groupByIndex = {};
  if (ruleGroups && ruleGroups.length > 0) {
    for (const g of ruleGroups) {
      for (const idx of (g.rule_indices || [])) {
        groupByIndex[idx] = g.group_name;
      }
    }
  }
  let currentGroup = null;

  // Collect deactivate commands for disabled rules (applied at the end)
  const deactivateCommands = [];
  const deactivateCaveats = [];

  // Fix 1: Track policies with unmapped applications for fidelity manifest
  const unmappedAppPolicyIndices = new Set();

  for (let pIdx = 0; pIdx < policies.length; pIdx++) {
    const policy = policies[pIdx];

    // Emit group comment when entering a new group (JUNOS preserves /* */ comments)
    const ruleGroup = groupByIndex[pIdx] || policy._group || null;
    if (ruleGroup && ruleGroup !== currentGroup) {
      commands.push('');
      commands.push(setComment(`===== Group: ${ruleGroup} =====`, `ruleGroups[${pIdx}]`));
      currentGroup = ruleGroup;
    }

    if (policy._implicit) {
      commands.push(`# --- Implicit Rule: ${policy.name} ---`);
    }

    // Clean up EDL block list addresses from match criteria
    const secIntelAddrs = new Set(policy._secIntelAddresses || []);
    let srcAddrs = policy.src_addresses
      .map((value, index) => ({ value, index }))
      .filter(({ value }) => !secIntelAddrs.has(value));
    let dstAddrs = policy.dst_addresses
      .map((value, index) => ({ value, index }))
      .filter(({ value }) => !secIntelAddrs.has(value));
    if (srcAddrs.length === 0 && policy.src_addresses.length > 0) srcAddrs = [{ value: 'any', index: null }];
    if (dstAddrs.length === 0 && policy.dst_addresses.length > 0) dstAddrs = [{ value: 'any', index: null }];

    // SRX policies are organized by from-zone/to-zone pair.
    const sourceZoneField = policy.src_zones !== undefined ? 'src_zones' : 'source_zones';
    const destinationZoneField = policy.dst_zones !== undefined ? 'dst_zones' : 'destination_zones';
    const srcZones = policy[sourceZoneField]?.length > 0 ? policy[sourceZoneField] : ['any'];
    const dstZones = policy[destinationZoneField]?.length > 0 ? policy[destinationZoneField] : ['any'];
    const sourceEntries = orderedZoneEntries(srcZones);
    const destinationEntries = orderedZoneEntries(dstZones);

    if (policyStructure === 'zone-pair') {
      // ---- existing zone-pair emission (unchanged) ----
      let definitionIndex = 0;
      const policyNamesByContext = new Map();
      for (const { zone: srcZone, index: sourceIndex } of sourceEntries) {
        const sourcePath = policy[sourceZoneField]?.length > 0
          ? `security_policies[${pIdx}].${sourceZoneField}[${sourceIndex}]`
          : `security_policies[${pIdx}]#effective-source-zone`;
        const fromZone = identifiers.nameForReference(identifierPath(sourcePath));
        for (const { zone: dstZone, index: destinationIndex } of destinationEntries) {
          const destinationPath = policy[destinationZoneField]?.length > 0
            ? `security_policies[${pIdx}].${destinationZoneField}[${destinationIndex}]`
            : `security_policies[${pIdx}]#effective-destination-zone`;
          const toZone = identifiers.nameForReference(identifierPath(destinationPath));
          // Fix 9: Use global policy when EITHER zone is 'any' (not just both)
          const isGlobal = fromZone === 'any' || toZone === 'any';
          const policyContext = isGlobal ? 'global' : encodeJunosZonePair(srcZone, dstZone);
          let policyName;
          if (policyNamesByContext.has(policyContext)) {
            policyName = policyNamesByContext.get(policyContext);
          } else {
            definitionIndex += 1;
            const genericName = !policy.name
              // njsscan regex_dos: false positive. Alternation is four distinct literals and is not nested under a quantifier - nothing to backtrack.
              || /^(rule|policy|permit|deny)[-_]?\d+$/i.test(policy.name)  // njsscan-ignore: regex_dos
              || /^\d+$/.test(policy.name);
            policyName = genericName
              ? identifiers.nameForGenerated(
                identifierPath(`security_policies[${pIdx}]`),
                generatedPolicyRole(srcZone, dstZone),
              )
              : identifiers.nameForDefinition(identifierPath(
                definitionIndex === 1
                  ? `security_policies[${pIdx}].name`
                  : `security_policies[${pIdx}].name#zone-pair:${encodeJunosZonePair(srcZone, dstZone)}`,
              ));
            policyNamesByContext.set(policyContext, policyName);
          }
          const policyPath = isGlobal
            ? `security policies global policy ${policyName}`
            : `security policies from-zone ${fromZone} to-zone ${toZone} policy ${policyName}`;

          emitPolicyBody(commands, policyPath, policyName, {
            policy, pIdx, srcAddrs, dstAddrs, dstZones, appGroups, sourceVendor,
            utmPolicyMap, idpPolicyMap, secIntelEnabled, secIntelPolicyName,
            identifiers, identifierPath, warnings, deactivateCommands, deactivateCaveats,
            policyReferenceIssues, unmappedAppPolicyIndices,
          });
        }
      }
    } else {
      // ---- global emission: one consolidated rule per policy ----
      const genericName = !policy.name
        || /^(rule|policy|permit|deny)[-_]?\d+$/i.test(policy.name)
        || /^\d+$/.test(policy.name);
      const firstSrc = sourceEntries[0]?.zone ?? 'any';
      const firstDst = destinationEntries[0]?.zone ?? 'any';
      const policyName = genericName
        ? identifiers.nameForGenerated(identifierPath(`security_policies[${pIdx}]`), generatedPolicyRole(firstSrc, firstDst))
        : identifiers.nameForDefinition(identifierPath(`security_policies[${pIdx}].name`));
      const policyPath = `security policies global policy ${policyName}`;

      for (const { zone: srcZone, index: sourceIndex } of sourceEntries) {
        const sourcePath = policy[sourceZoneField]?.length > 0
          ? `security_policies[${pIdx}].${sourceZoneField}[${sourceIndex}]`
          : `security_policies[${pIdx}]#effective-source-zone`;
        const fromZone = identifiers.nameForReference(identifierPath(sourcePath));
        commands.push(`set ${policyPath} match from-zone ${fromZone}`);
      }
      for (const { zone: dstZone, index: destinationIndex } of destinationEntries) {
        const destinationPath = policy[destinationZoneField]?.length > 0
          ? `security_policies[${pIdx}].${destinationZoneField}[${destinationIndex}]`
          : `security_policies[${pIdx}]#effective-destination-zone`;
        const toZone = identifiers.nameForReference(identifierPath(destinationPath));
        commands.push(`set ${policyPath} match to-zone ${toZone}`);
      }

      emitPolicyBody(commands, policyPath, policyName, {
        policy, pIdx, srcAddrs, dstAddrs, dstZones, appGroups, sourceVendor,
        utmPolicyMap, idpPolicyMap, secIntelEnabled, secIntelPolicyName,
        identifiers, identifierPath, warnings, deactivateCommands, deactivateCaveats,
        policyReferenceIssues, unmappedAppPolicyIndices,
      });
    }

    summary.policies_converted++;
  }

  // Append deactivate commands and caveats at the end
  if (deactivateCommands.length > 0) {
    commands.push('');
    if (deactivateCaveats.length > 0) {
      commands.push(...deactivateCaveats);
    }
    commands.push('# Deactivated rules (disabled in source, or see caveats above)');
    commands.push(...deactivateCommands);
  }

  // Fix 1: Compute full disposition breakdown for fidelity manifest
  const disabledIndices = new Set();
  const undefinedRefIndices = new Set(policyReferenceIssues.keys());

  for (let i = 0; i < policies.length; i++) {
    if (policies[i]._implicit) continue;
    if (policies[i].disabled) disabledIndices.add(i);
  }

  const negationIndices = new Set();
  policies.forEach((policy, index) => {
    if (!policy._implicit && findNegationIssues(policy).length > 0) negationIndices.add(index);
  });

  // Compute inactive union: a policy in multiple categories counts once
  const inactiveUnion = new Set([
    ...disabledIndices,
    ...undefinedRefIndices,
    ...unmappedAppPolicyIndices,
    ...negationIndices,
  ]);

  const activeCount = summary.total_source_policies - inactiveUnion.size;

  // Update summary counters
  summary.policies_deactivated_undefined_ref = undefinedRefIndices.size;

  // Emit fidelity manifest if there are non-implicit policies
  if (summary.total_source_policies > 0) {
    commands.push('');
    commands.push('# =============================================');
    commands.push('# Conversion Fidelity Manifest');
    commands.push('# =============================================');
    commands.push(`# Source security policies: ${summary.total_source_policies}`);
    commands.push(`#   active (converted): ${activeCount}`);
    commands.push(`#   inactive (disabled in source): ${disabledIndices.size}`);
    commands.push(`#   inactive (unmapped application): ${unmappedAppPolicyIndices.size}`);
    commands.push(`#   inactive (undefined reference): ${undefinedRefIndices.size}`);
    commands.push(`#   inactive (negated address not representable): ${negationIndices.size}`);

    // Emit detail lines for undefined references if any
    if (policyReferenceIssues.size > 0) {
      commands.push('# Undefined references (rule -> missing object):');
      for (const [pIdx, issue] of policyReferenceIssues) {
        const policy = policies[pIdx];
        const policyName = policy.name || `policy-${pIdx}`;
        const items = [];
        for (const addr of issue.addresses || []) {
          items.push(`address "${addr}"`);
        }
        for (const svc of issue.services || []) {
          items.push(`service "${svc}"`);
        }
        commands.push(`#   - ${policyName}: ${items.join(', ')}`);
      }
    }
  }

  commands.push('');
}

/**
 * Tracks unmapped applications — the name is unknown to our mapping data
 * AND does not match any JUNOS_PREDEFINED_APPS entry. These produce the
 * INTERVIEW REQUIRED block and a policy reference to <name>-UNMAPPED.
 * Map of unmappedName → originalName.
 */
const unmappedApps = new Map();

/**
 * Tracks applications with concrete protocol/port info sourced from
 * app-mappings.json canonical entries that have no `junos` predefined.
 * Emitted as real `set applications application ...` definitions.
 * Map of customName → { protocol, ports: string[], originalName, canonical }.
 */
const concreteCustomApps = new Map();

/**
 * Fix 4: Tracks service names referenced in policies that were not defined
 * by convertServiceObjects (e.g., "tcp-9090"). These need application
 * definitions emitted before policies.
 * Map of sanitizedName → originalServiceName.
 */
const unresolvedServiceApps = new Map();

/**
 * Tracks services/apps with comma-separated ports that were split into
 * individual applications and wrapped in an application-set with a -set suffix.
 * Map of originalName → setName (e.g., "tcp-443-8443" → "tcp-443-8443-set").
 * Built during convertServiceObjects()/convertApplications(), consumed by resolveApplications().
 */
const commaPortSetMap = new Map();

/**
 * Tracks service objects that are equivalent to predefined Junos applications.
 * Map of serviceName → junosPredefinedName (e.g., "SSH" → "junos-ssh").
 * Built during convertServiceObjects(), consumed by resolveApplications().
 */
const predefServiceMap = new Map();

function generatedRole(entry) {
  const marker = '#generated:';
  const markerIndex = entry?.definitionPath?.lastIndexOf(marker) ?? -1;
  return markerIndex < 0 ? null : entry.definitionPath.slice(markerIndex + marker.length);
}

function generatedOwnerPath(entry) {
  const marker = '#generated:';
  const markerIndex = entry?.definitionPath?.lastIndexOf(marker) ?? -1;
  return markerIndex < 0 ? null : entry.definitionPath.slice(0, markerIndex);
}

function planApplicationUse(appName, referencePath, warnings, warningElement, sourceVendor, identifiers) {
  const plannedName = identifiers.nameForReference(referencePath);
  const mappingEntry = identifiers.mapping.entries.find(entry => (
    entry.referencePaths.includes(referencePath)
  ));
  if (!mappingEntry) return plannedName;
  if (!mappingEntry.resolution.startsWith('generated')) return plannedName;

  const role = generatedRole(mappingEntry);
  const ownerPath = generatedOwnerPath(mappingEntry);
  if (['service-multi-port-set', 'application-multi-port-set'].includes(role)) {
    return plannedName;
  }
  if (role === 'passthrough-application') {
    unresolvedServiceApps.set(plannedName, appName);
    return plannedName;
  }
  if (role === 'unmapped-application') {
    unmappedApps.set(plannedName, appName);
    warnings.push(createWarning(
      'warning',
      warningElement,
      `Application "${appName}" has no known Junos equivalent — listed in INTERVIEW REQUIRED block`,
      'Provide the correct protocol/port(s) for this application and replace the <name>-UNMAPPED placeholder.',
    ));
    return plannedName;
  }
  if (!['custom-application', 'custom-application-set'].includes(role) || !ownerPath) {
    return plannedName;
  }

  const emission = getJunosEmission(appName, sourceVendor);
  if (emission?.kind === 'custom') {
    concreteCustomApps.set(plannedName, {
      protocol: emission.protocol,
      ports: emission.ports,
      originalName: appName,
      canonical: emission.canonical,
      subNames: new Map(emission.ports.map(port => [
        String(port),
        emission.ports.length > 1
          ? identifiers.nameForGenerated(ownerPath, `custom-application-port:${port}`)
          : plannedName,
      ])),
    });
    return plannedName;
  }
  return plannedName;
}

function prepareApplicationGroupApplications(groups, warnings, sourceVendor, identifiers, identifierPath) {
  for (let groupIndex = 0; groupIndex < (groups || []).length; groupIndex += 1) {
    const group = groups[groupIndex];
    for (let memberIndex = 0; memberIndex < (group.members || []).length; memberIndex += 1) {
      const member = group.members[memberIndex];
      if (member === 'service-set') continue;
      planApplicationUse(
        member,
        identifierPath(`application_groups[${groupIndex}].members[${memberIndex}]`),
        warnings,
        `application-group/${group.name}`,
        sourceVendor,
        identifiers,
      );
    }
  }
}

/**
 * Resolves application/service fields from any vendor to SRX application names.
 *
 * For SRX→SRX conversions, applications pass through 1:1 (already Junos names).
 * For other vendors, applications are mapped via mapAppToJunos().
 * Unmapped applications get a "-UNMAPPED" suffix and a warning is generated
 * pointing users to the INTERVIEW REQUIRED block for manual completion.
 *
 * SRX only has "application" in policy match — we unify both fields.
 */
function resolveApplications(applications, services, warnings, policyName, appGroups = [], sourceVendor = '', policyIndex, identifiers, identifierPath) {
  const resolved = [];

  // Helper to map a single app name to Junos using three-tier emission logic
  const mapSingleApp = (appName, localReferencePath) => {
    const referencePath = identifierPath(localReferencePath);
    resolved.push(planApplicationUse(
      appName,
      referencePath,
      warnings,
      `policy/${policyName}`,
      sourceVendor,
      identifiers,
    ));
  };

  // Map applications to Junos equivalents
  if (applications && applications.length > 0) {
    for (let appIndex = 0; appIndex < applications.length; appIndex += 1) {
      const app = applications[appIndex];
      if (app === 'any') {
        resolved.push(identifiers.nameForReference(
          identifierPath(`security_policies[${policyIndex}].applications[${appIndex}]`),
        ));
        continue;
      }

      // Skip vendor keywords that aren't real application names
      if (app === 'service-set') continue;

      // Check if this is an application group reference — expand to members
      const group = appGroups.find(g => g.name === app);
      if (group && group.members.length > 0) {
        for (let memberIndex = 0; memberIndex < group.members.length; memberIndex += 1) {
          if (group.members[memberIndex] === 'service-set') continue;
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

  // Handle explicit service references (not "application-default")
  if (services && services.length > 0) {
    for (let serviceIndex = 0; serviceIndex < services.length; serviceIndex += 1) {
      const svc = services[serviceIndex];
      if (svc === 'application-default' || svc === 'any') continue;
      // Bug 10 fix: Filter Huawei "service-set" keyword from services too.
      // This is a Huawei config keyword meaning "use the service objects", not an app name.
      if (svc === 'service-set') continue;
      const referencePath = identifierPath(`security_policies[${policyIndex}].services[${serviceIndex}]`);
      const serviceName = identifiers.nameForReference(referencePath);
      resolved.push(serviceName);
      const mappingEntry = identifiers.mapping.entries.find(entry => (
        entry.referencePaths.includes(referencePath)
      ));
      if (mappingEntry?.resolution.startsWith('generated')
          || mappingEntry?.resolution.startsWith('unresolved')) {
        unresolvedServiceApps.set(serviceName, svc);
      }
    }
  }

  // If nothing resolved, use "any"
  if (resolved.length === 0) {
    resolved.push('any');
  }

  return [...new Set(resolved)]; // Deduplicate
}

/**
 * Maps PAN-OS action to SRX policy action.
 *
 * PAN-OS actions: allow, deny, drop, reset-client, reset-server, reset-both
 * SRX actions: permit, deny, reject
 */
function mapAction(panosAction) {
  switch (panosAction) {
    case 'allow':
      return 'permit';
    case 'deny':
      return 'deny';
    case 'drop':
      return 'deny';
    case 'reset-client':
    case 'reset-server':
    case 'reset-both':
      return 'reject';
    default:
      return 'deny';
  }
}

// ---------------------------------------------------------------------------
// NAT Rule Converter
// ---------------------------------------------------------------------------

/**
 * Resolves a NAT match address to a raw IP/subnet. Junos NAT match commands
 * require literal IPs, not address-book object names.
 * @param {string} addr - Address string (IP, subnet, or object name)
 * @param {Object} addrLookup - Map of address-object names to IP values
 * @param {string[]} warnings - Collector for warning messages
 * @returns {string|null} Resolved IP/subnet, or null if unresolvable
 */
function resolveNatAddress(addr, addrLookup, warnings) {
  if (!addr || addr === 'any') return null;
  // Already an IP or subnet (contains a dot and looks numeric)
  // njsscan regex_dos: false positive. Adjacent tokens are disjoint (\d excludes the literal dot and slash), so neither pattern backtracks.
  if (/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(addr) || /^[0-9a-fA-F:]+\/\d+$/.test(addr)) {  // njsscan-ignore: regex_dos
    return addr;
  }
  const resolved = addrLookup[addr];
  if (!resolved) {
    warnings.push(createWarning('nat', `NAT match address "${addr}" is not a known address object — skipped`));
    return null;
  }
  // Skip FQDN / dns-name values (not usable in NAT match)
  if (!/^\d+\.\d+\.\d+\.\d+/.test(resolved) && !/^[0-9a-fA-F:]+/.test(resolved)) {
    warnings.push(createWarning('nat', `NAT match address "${addr}" resolves to FQDN "${resolved}" — skipped (Junos NAT requires IP)`));
    return null;
  }
  return resolved;
}

function effectiveNatTypes(rule) {
  return rule.type === 'source-and-destination'
    ? ['source', 'destination']
    : [rule.type || 'source'];
}

function convertNatRules(
  natRules,
  commands,
  warnings,
  summary,
  addressObjects,
  addressGroups,
  configuredZones,
  identifiers,
  identifierPath,
  interfaces,
  interfaceMappings,
) {
  if (!natRules || natRules.length === 0) return;

  // Build lookup map: address-object name → IP/subnet value
  const addrLookup = {};
  const rawAddressNames = new Map();
  for (let objectIndex = 0; objectIndex < (addressObjects || []).length; objectIndex += 1) {
    const obj = addressObjects[objectIndex];
    const plannedName = identifiers.nameForDefinition(identifierPath(`address_objects[${objectIndex}].name`));
    rawAddressNames.set(obj.name, plannedName);
    if (obj.value) addrLookup[plannedName] = obj.value;
    else if (obj.ip) addrLookup[plannedName] = obj.ip;
    else if (obj.network) addrLookup[plannedName] = obj.network;
    else if (obj.subnet) addrLookup[plannedName] = obj.subnet;
    else if (obj.address) addrLookup[plannedName] = obj.address;
  }

  // Build set of address-group names for NAT match name-refs
  const groupNames = new Set((addressGroups || []).map(g => g.name));

  // Helper: Extract provider interface's host IP as a /32 or /128 for provider source NAT pools
  const providerInterfaceIp = (panIfaceName) => {
    if (!panIfaceName) return null;
    const iface = (interfaces || []).find(i => i.name === panIfaceName && (i.ip || i.ipv6));
    const raw = iface ? (iface.ip || iface.ipv6) : '';
    if (!raw) return null;
    const host = String(raw).split('/')[0];
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return `${host}/32`;
    if (host.includes(':')) return `${host}/128`;
    return null;
  };

  const natRuleIndex = new Map(natRules.map((rule, index) => [rule, index]));
  const sourceZonesFor = natSourceZones;
  const destinationZonesFor = natDestinationZones;
  const typesFor = effectiveNatTypes;
  const zoneReference = (ruleIndex, rule, direction, zone) => {
    const field = direction === 'source'
      ? natSourceZoneField(rule) : natDestinationZoneField(rule);
    const values = direction === 'source' ? sourceZonesFor(rule) : destinationZonesFor(rule);
    const index = values.indexOf(zone);
    const localPath = rule[field]?.length > 0
      ? `nat_rules[${ruleIndex}].${field}[${index}]`
      : `nat_rules[${ruleIndex}]#effective-${direction}-zone`;
    return identifiers.nameForReference(identifierPath(localPath));
  };
  const ruleSetInfo = (type, fromZone, toZone) => {
    const ownerIndex = natRules.findIndex(rule => (
      typesFor(rule).includes(type)
      && sourceZonesFor(rule).includes(fromZone)
      && destinationZonesFor(rule).includes(toZone)
    ));
    const role = type === 'static'
      ? 'static-nat-rule-set'
      : `${type}-nat-rule-set:${encodeJunosZonePair(fromZone, toZone)}`;
    return {
      ownerIndex,
      name: identifiers.nameForGenerated(identifierPath(`nat_rules[${ownerIndex}]`), role),
    };
  };
  const ruleNameFor = (ruleIndex, rule, type, fromZone, toZone) => {
    let occurrence = 0;
    for (const candidateType of typesFor(rule)) {
      const pairs = candidateType === 'static'
        ? [['STATIC-NAT', '*']]
        : sourceZonesFor(rule).flatMap(source => (
          destinationZonesFor(rule).map(destination => [source, destination])
        ));
      for (const [candidateFrom, candidateTo] of pairs) {
        occurrence += 1;
        if (candidateType === type && candidateFrom === fromZone && candidateTo === toZone) {
          const suffix = occurrence === 1
            ? '' : `#${type}:${encodeJunosZonePair(fromZone, toZone)}`;
          return identifiers.nameForDefinition(
            identifierPath(`nat_rules[${ruleIndex}].name${suffix}`),
          );
        }
      }
    }
    return identifiers.nameForDefinition(identifierPath(`nat_rules[${ruleIndex}].name`));
  };
  const matchAddress = (ruleIndex, field, addressIndex, rawAddress) => {
    const plannedName = identifiers.nameForReference(
      identifierPath(`nat_rules[${ruleIndex}].${field}[${addressIndex}]`),
    );
    const value = /^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(rawAddress)
      || /^[0-9a-fA-F:]+\/\d+$/.test(rawAddress)
      ? rawAddress : plannedName;
    return resolveNatAddress(value, addrLookup, warnings);
  };
  const translatedAddress = rawAddress => {
    const plannedName = rawAddressNames.get(rawAddress);
    return resolveNatAddress(plannedName || rawAddress, addrLookup, warnings);
  };
  // A "start-end" source pool range (FortiGate ippool) is Junos "A/32 to B/32".
  // Source pools only: a match address takes a prefix, and a destination pool
  // range would leave a range VIP's rule with nothing to match.
  const sourcePoolAddress = rawAddress => {
    // njsscan regex_dos: false positive. \d excludes the literal dot and hyphen, so no token backtracks.
    const range = String(rawAddress || '').match(/^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/);  // njsscan-ignore: regex_dos
    return range ? `${range[1]}/32 to ${range[2]}/32` : translatedAddress(rawAddress);
  };

  commands.push('# =============================================');
  commands.push('# NAT Rules');
  commands.push('# =============================================');

  const configuredZoneNames = new Set((configuredZones || []).map(zone => zone.name));
  const missingZoneNames = new Set();
  for (const rule of natRules) {
    for (const zone of [...sourceZonesFor(rule), ...destinationZonesFor(rule)]) {
      if (zone !== 'any' && !configuredZoneNames.has(zone)) missingZoneNames.add(zone);
    }
  }
  const missingZoneOutputs = new Map([...missingZoneNames].sort().map(sourceName => [
    sourceName,
    identifiers.nameForGenerated(
      identifierPath('nat_rules'),
      natMissingZoneRole(sourceName),
    ),
  ]));

  // Bug 8 fix: Ensure all zones referenced in NAT rules are defined.
  // Collect already-defined zones from prior commands, then create any missing ones.
  const definedZones = new Set();
  for (const cmd of commands) {
    const zoneMatch = cmd.match(/^set security zones security-zone (\S+)/);
    if (zoneMatch) definedZones.add(zoneMatch[1]);
  }
  for (const zoneName of missingZoneOutputs.values()) {
    if (!definedZones.has(zoneName)) {
      commands.push(`set security zones security-zone ${zoneName}`);
      definedZones.add(zoneName);
    }
  }
  for (let ruleIndex = 0; ruleIndex < natRules.length; ruleIndex += 1) {
    const rule = natRules[ruleIndex];
    for (const [direction, zones] of [
      ['source', sourceZonesFor(rule)],
      ['destination', destinationZonesFor(rule)],
    ]) {
      for (const zone of zones) {
        zoneReference(ruleIndex, rule, direction, zone);
      }
    }
  }

  // Group NAT rules by type for SRX rule-set organization
  const sourceNatRules = natRules.filter(rule => effectiveNatTypes(rule).includes('source'));
  const destNatRules = natRules.filter(rule => effectiveNatTypes(rule).includes('destination'));
  const staticNatRules = natRules.filter(rule => effectiveNatTypes(rule).includes('static'));

  // --- Source NAT ---
  if (sourceNatRules.length > 0) {
    // Group by zone pair for SRX rule-sets
    const ruleSetGroups = groupByZonePair(sourceNatRules);

    for (const { fromZone, toZone, rules } of ruleSetGroups) {
      // Fix 5: NAT rule-sets cannot use 'any' as zone — replace with actual zones
      const { name: ruleSetName } = ruleSetInfo('source', fromZone, toZone);
      const ruleSetPath = `security nat source rule-set ${ruleSetName}`;
      const zoneRule = rules[0];
      const zoneRuleIndex = natRuleIndex.get(zoneRule);
      if (fromZone === 'any' || toZone === 'any') {
        const actualZones = [...definedZones].filter(z => z !== 'any');
        if (actualZones.length === 0) {
          commands.push(`# WARNING: NAT rule-set ${fromZone}-to-${toZone} skipped — no defined zones to replace 'any'`);
          warnings.push(createWarning('warning', `nat/source/${fromZone}-to-${toZone}`,
            `NAT rule-set from ${fromZone} to ${toZone} skipped — 'any' is not valid and no zones defined`,
            'Define security zones before NAT rules'));
          continue;
        }
        const resolvedFromZones = fromZone === 'any'
          ? actualZones : [zoneReference(zoneRuleIndex, zoneRule, 'source', fromZone)];
        const resolvedToZones = toZone === 'any'
          ? actualZones : [zoneReference(zoneRuleIndex, zoneRule, 'destination', toZone)];
        for (const fz of resolvedFromZones) {
          commands.push(`set ${ruleSetPath} from zone ${fz}`);
        }
        for (const tz of resolvedToZones) {
          commands.push(`set ${ruleSetPath} to zone ${tz}`);
        }
      } else {
        commands.push(`set ${ruleSetPath} from zone ${zoneReference(zoneRuleIndex, zoneRule, 'source', fromZone)}`);
        commands.push(`set ${ruleSetPath} to zone ${zoneReference(zoneRuleIndex, zoneRule, 'destination', toZone)}`);
      }

      for (const rule of rules) {
        // Single-lined so a hostile policy name cannot start a new command line.
        if (rule.caveat) commands.push(`# CAVEAT: ${String(rule.caveat).replace(/[\r\n]+/g, ' ')}`);
        const ruleIndex = natRuleIndex.get(rule);
        const ruleName = ruleNameFor(ruleIndex, rule, 'source', fromZone, toZone);
        const rulePath = `${ruleSetPath} rule ${ruleName}`;

        // Match criteria
        const anyAddr = natAnyAddress(rule);
        const hasSourceAddresses = Array.isArray(rule.src_addresses);
        const sourceAddresses = hasSourceAddresses ? rule.src_addresses : [anyAddr];
        for (let addressIndex = 0; addressIndex < sourceAddresses.length; addressIndex += 1) {
          const addr = sourceAddresses[addressIndex];
          if (addr === 'any') {
            if (hasSourceAddresses) {
              identifiers.nameForReference(
                identifierPath(`nat_rules[${ruleIndex}].src_addresses[${addressIndex}]`),
              );
            }
            commands.push(`set ${rulePath} match source-address ${anyAddr}`);
          } else {
            // Check if addr is a literal IP/prefix
            const isLiteral = /^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(addr) || /^[0-9a-fA-F:]+\/\d+$/.test(addr);
            if (isLiteral) {
              commands.push(`set ${rulePath} match source-address ${addr}`);
            } else if (groupNames.has(addr)) {
              // Address group → emit name-ref
              const groupNameRef = identifiers.nameForReference(
                identifierPath(`nat_rules[${ruleIndex}].src_addresses[${addressIndex}]`),
              );
              commands.push(`set ${rulePath} match source-address-name ${groupNameRef}`);
            } else {
              // Address object or unknown → resolve to IP
              const resolved = hasSourceAddresses
                ? matchAddress(ruleIndex, 'src_addresses', addressIndex, addr)
                : addr;
              if (resolved) {
                commands.push(`set ${rulePath} match source-address ${resolved}`);
              }
            }
          }
        }
        const hasDestinationAddresses = Array.isArray(rule.dst_addresses);
        const destinationAddresses = hasDestinationAddresses ? rule.dst_addresses : [anyAddr];
        for (let addressIndex = 0; addressIndex < destinationAddresses.length; addressIndex += 1) {
          const addr = destinationAddresses[addressIndex];
          if (addr === 'any') {
            if (hasDestinationAddresses) {
              identifiers.nameForReference(
                identifierPath(`nat_rules[${ruleIndex}].dst_addresses[${addressIndex}]`),
              );
            }
            commands.push(`set ${rulePath} match destination-address ${anyAddr}`);
          } else {
            // Check if addr is a literal IP/prefix
            const isLiteral = /^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(addr) || /^[0-9a-fA-F:]+\/\d+$/.test(addr);
            if (isLiteral) {
              commands.push(`set ${rulePath} match destination-address ${addr}`);
            } else if (groupNames.has(addr)) {
              // Address group → emit name-ref
              const groupNameRef = identifiers.nameForReference(
                identifierPath(`nat_rules[${ruleIndex}].dst_addresses[${addressIndex}]`),
              );
              commands.push(`set ${rulePath} match destination-address-name ${groupNameRef}`);
            } else {
              // Address object or unknown → resolve to IP
              const resolved = hasDestinationAddresses
                ? matchAddress(ruleIndex, 'dst_addresses', addressIndex, addr)
                : addr;
              if (resolved) {
                commands.push(`set ${rulePath} match destination-address ${resolved}`);
              }
            }
          }
        }

        // Protocol and port matching (from service)
        if (rule.match_protocol) {
          const proto = String(rule.match_protocol).toLowerCase();
          if (proto === 'tcp' || proto === 'udp') {
            commands.push(`set ${rulePath} match protocol ${proto}`);
          }
        }
        if (rule.match_port) {
          commands.push(`set ${rulePath} match destination-port ${rule.match_port}`);
        }

        // Translation action
        if (rule.translated_src) {
          if (rule.translated_src.type === 'interface') {
            const panIf = rule.translated_src.interface || '';
            const providerIp = providerInterfaceIp(panIf);
            if (providerIp) {
              const srxIf = mapInterfaceName(panIf, interfaceMappings);
              const providerPool = identifiers.nameForGenerated(identifierPath(`nat_rules[${ruleIndex}]`), 'provider-source-nat-pool');
              commands.push(`# NAT: source translated to provider interface ${srxIf} (${providerIp})`);
              commands.push(`set security nat source pool ${providerPool} address ${providerIp}`);
              commands.push(`set ${rulePath} then source-nat pool ${providerPool}`);
            } else {
              if (panIf) {
                const srxIf = mapInterfaceName(panIf, interfaceMappings);
                commands.push(`# NAT: source translated to interface ${srxIf} — no static IP found; using egress interface NAT (verify routing sends this traffic out ${srxIf})`);
              }
              commands.push(`set ${rulePath} then source-nat interface`);
            }
          } else if (rule.translated_src.type === 'dynamic-ip-pool') {
            // Create a source NAT pool
            const poolName = identifiers.nameForGenerated(
              identifierPath(`nat_rules[${ruleIndex}]`),
              'source-nat-pool',
            );
            let allResolved = true;
            const poolCmds = [];
            for (const addr of rule.translated_src.addresses) {
              const resolvedPoolAddr = sourcePoolAddress(addr);
              if (resolvedPoolAddr) {
                poolCmds.push(`set security nat source pool ${poolName} address ${resolvedPoolAddr}`);
              } else {
                allResolved = false;
              }
            }
            if (allResolved && poolCmds.length > 0) {
              commands.push(...poolCmds);
              commands.push(`set ${rulePath} then source-nat pool ${poolName}`);
            } else {
              // Can't resolve pool addresses (e.g., Check Point hide NAT using gateway name)
              // Fall back to interface NAT
              commands.push(`# NAT pool address could not be resolved — using interface NAT`);
              commands.push(`set ${rulePath} then source-nat interface`);
            }
          } else if (rule.translated_src.type === 'static') {
            const staticPoolName = identifiers.nameForGenerated(
              identifierPath(`nat_rules[${ruleIndex}]`),
              'static-source-nat-pool',
            );
            // NAT pool address must be an IP, not a named object — resolve it
            const resolvedStaticAddr = translatedAddress(rule.translated_src.address);
            if (resolvedStaticAddr) {
              // Fix 3: Normalize bare IPs (both IPv4 and IPv6) with prefix
              const withPrefix = (ip) => {
                if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return `${ip}/32`;
                if (ip.includes(':') && !ip.includes('/')) return `${ip}/128`;
                return ip;
              };
              const staticAddr = withPrefix(resolvedStaticAddr);
              commands.push(`set security nat source pool ${staticPoolName} address ${staticAddr}`);
              commands.push(`set ${rulePath} then source-nat pool ${staticPoolName}`);
            } else {
              commands.push(`# NAT: translated source "${rule.translated_src.address}" is not a resolvable IP/prefix — using interface NAT`);
              warnings.push(createWarning('nat', `Source NAT translated address "${rule.translated_src.address}" could not be resolved to an IP/prefix — fell back to interface NAT`));
              commands.push(`set ${rulePath} then source-nat interface`);
            }
          } else {
            // Unknown translation type — default to interface NAT (e.g., Check Point hide NAT)
            commands.push(`set ${rulePath} then source-nat interface`);
          }
        } else {
          // No translated_src specified — default to interface NAT (hide/masquerade)
          commands.push(`set ${rulePath} then source-nat interface`);
        }

        // U-turn/hairpin NAT: add persistent-nat for return traffic
        if (rule._uturn) {
          commands.push(`set ${rulePath} then persistent-nat permit target-host`);
        }

        summary.nat_rules_converted++;
      }
    }
  }

  // --- Destination NAT ---
  if (destNatRules.length > 0) {
    const ruleSetGroups = groupByZonePair(destNatRules);

    for (const { fromZone, toZone, rules } of ruleSetGroups) {
      const { name: ruleSetName } = ruleSetInfo('destination', fromZone, toZone);
      const ruleSetPath = `security nat destination rule-set ${ruleSetName}`;
      const zoneRule = rules[0];
      const zoneRuleIndex = natRuleIndex.get(zoneRule);

      // Fix 5: NAT rule-sets cannot use 'any' as zone — replace with actual zones
      if (fromZone === 'any') {
        const actualZones = [...definedZones].filter(z => z !== 'any');
        if (actualZones.length === 0) {
          commands.push(`# WARNING: Destination NAT rule-set ${fromZone}-to-${toZone} skipped — no defined zones`);
          warnings.push(createWarning('warning', `nat/destination/${fromZone}-to-${toZone}`,
            `Destination NAT rule-set from ${fromZone} skipped — 'any' is not valid and no zones defined`,
            'Define security zones before NAT rules'));
          continue;
        }
        for (const fz of actualZones) {
          commands.push(`set ${ruleSetPath} from zone ${fz}`);
        }
      } else {
        commands.push(`set ${ruleSetPath} from zone ${zoneReference(zoneRuleIndex, zoneRule, 'source', fromZone)}`);
      }

      // Names are single-lined so a hostile value cannot start a new command line.
      const oneLine = (value) => String(value).replace(/[\r\n]+/g, ' ');
      for (const advice of planIngressScopeAdvice(rules, configuredZones, (name) => mapInterfaceName(name, interfaceMappings))) {
        commands.push(`# CAVEAT: ${oneLine(advice.caveat)}`);
        const adviceTarget = advice.grouped
          ? ruleSetName
          : ruleNameFor(natRuleIndex.get(advice.rules[0]), advice.rules[0], 'destination', fromZone, toZone);
        warnings.push(createWarning('warning', `nat/destination/${adviceTarget}`, advice.message, advice.suggestion));
      }

      for (const rule of rules) {
        const ruleIndex = natRuleIndex.get(rule);
        const ruleName = ruleNameFor(ruleIndex, rule, 'destination', fromZone, toZone);
        const rulePath = `${ruleSetPath} rule ${ruleName}`;

        // Fix 1: Pre-validate translated destination address BEFORE emitting any match lines
        let resolvedDstAddr = null;
        if (rule.translated_dst) {
          const rawDst = typeof rule.translated_dst === 'string' ? rule.translated_dst : rule.translated_dst.address || '';
          if (rawDst) {
            resolvedDstAddr = translatedAddress(rawDst);
            if (!resolvedDstAddr) {
              commands.push(`# NAT: destination rule "${ruleName}" skipped — translated destination "${rawDst}" is not a resolvable IP/prefix`);
              warnings.push(createWarning('nat', `Destination NAT rule "${ruleName}" skipped — translated address "${rawDst}" could not be resolved to an IP/prefix`));
              continue; // skip the whole rule: no match, no then
            }
          }
        }

        // Match
        const dnatAny = natAnyAddress(rule);
        const hasDestinationAddresses = Array.isArray(rule.dst_addresses);
        const destinationAddresses = hasDestinationAddresses ? rule.dst_addresses : [dnatAny];
        for (let addressIndex = 0; addressIndex < destinationAddresses.length; addressIndex += 1) {
          const addr = destinationAddresses[addressIndex];
          if (addr === 'any') {
            if (hasDestinationAddresses) {
              identifiers.nameForReference(
                identifierPath(`nat_rules[${ruleIndex}].dst_addresses[${addressIndex}]`),
              );
            }
            commands.push(`set ${rulePath} match destination-address ${dnatAny}`);
          } else {
            const resolved = hasDestinationAddresses
              ? matchAddress(ruleIndex, 'dst_addresses', addressIndex, addr)
              : addr;
            if (resolved) {
              commands.push(`set ${rulePath} match destination-address ${resolved}`);
            }
          }
        }
        // Port-forward matching (FortiGate VIP extport)
        if (rule.match_port) {
          commands.push(`set ${rulePath} match destination-port ${rule.match_port}`);
        }
        if (rule.match_protocol) {
          const proto = rule.match_protocol.toLowerCase();
          if (proto === 'tcp' || proto === 'udp') {
            commands.push(`set ${rulePath} match protocol ${proto}`);
          }
        }

        // Translation — reuse resolvedDstAddr (already validated above)
        if (resolvedDstAddr) {
          // Fix 3: Normalize bare IPv6 addresses to /128
          const withPrefix = (ip) => {
            if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return `${ip}/32`;
            if (ip.includes(':') && !ip.includes('/')) return `${ip}/128`;
            return ip;
          };
          const dstAddr = withPrefix(resolvedDstAddr);
          const poolName = identifiers.nameForGenerated(
            identifierPath(`nat_rules[${ruleIndex}]`),
            'destination-nat-pool',
          );
          commands.push(`set security nat destination pool ${poolName} address ${dstAddr}`);
          if (rule.translated_port) {
            commands.push(`set security nat destination pool ${poolName} address port ${rule.translated_port}`);
          }
          commands.push(`set ${rulePath} then destination-nat pool ${poolName}`);
        }

        summary.nat_rules_converted++;
      }
    }
  }

  // --- Static NAT ---
  if (staticNatRules.length > 0) {
    commands.push('# Static NAT Rules');
    for (const rule of staticNatRules) {
      const ruleIndex = natRuleIndex.get(rule);
      const ruleSetName = identifiers.nameForGenerated(
        identifierPath(`nat_rules[${natRuleIndex.get(staticNatRules[0])}]`),
        'static-nat-rule-set',
      );
      const ruleName = ruleNameFor(ruleIndex, rule, 'static', 'STATIC-NAT', '*');
      const ruleSetPath = `security nat static rule-set ${ruleSetName} rule ${ruleName}`;

      for (let addressIndex = 0; addressIndex < (rule.dst_addresses || []).length; addressIndex += 1) {
        const addr = rule.dst_addresses[addressIndex];
        if (addr !== 'any') {
          const resolved = matchAddress(ruleIndex, 'dst_addresses', addressIndex, addr);
          if (resolved) {
            commands.push(`set ${ruleSetPath} match destination-address ${resolved}`);
          }
        } else {
          identifiers.nameForReference(
            identifierPath(`nat_rules[${ruleIndex}].dst_addresses[${addressIndex}]`),
          );
        }
      }

      if (rule.translated_src && rule.translated_src.address) {
        commands.push(`set ${ruleSetPath} then static-nat prefix ${rule.translated_src.address}`);
      }

      summary.nat_rules_converted++;
    }
  }

  commands.push('');
}

function plannedRoutingInstanceName(sourceName, path, identifiers, routingInstances) {
  if (sourceName === 'default' || sourceName === 'master' || routingInstances.has(sourceName)) {
    return identifiers.nameForReference(path);
  }
  routingInstances.add(sourceName);
  return identifiers.nameForDefinition(path);
}

function convertStaticRoutes(routes, commands, warnings, summary, interfaceMappings = {}, identifiers, identifierPath, routingInstances) {
  if (!routes || routes.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Static Routes');
  commands.push('# =============================================');

  // Track destinations that already have a next-hop to avoid duplicate default routes
  // (Junos allows only one default route action per destination in the same routing table)
  const routesWithNextHop = new Set();     // key: "vrf|dest" or "|dest"
  const routesWithAction = new Set();      // any action emitted for this dest
  const routeIdentifierNames = routes.map((route, routeIndex) => ({
    instanceName: route.vrf
      ? plannedRoutingInstanceName(
        route.vrf,
        identifierPath(`static_routes[${routeIndex}].vrf`),
        identifiers,
        routingInstances,
      )
      : null,
    nextTableName: route.next_hop_type === 'next-vr' && route.next_hop
      ? plannedRoutingInstanceName(
        route.next_hop,
        identifierPath(`static_routes[${routeIndex}].next_hop`),
        identifiers,
        routingInstances,
      )
      : null,
  }));

  // First pass: identify all destinations that have a concrete next-hop
  for (let routeIndex = 0; routeIndex < routes.length; routeIndex += 1) {
    const route = routes[routeIndex];
    if (!route.destination) continue;
    const dest = route.destination.trim();
    const rawNextHop = route.next_hop ? route.next_hop.trim().replace(/[^\w.:/-]/g, '') : '';
    const nextHop = route.next_hop_type === 'next-vr'
      ? rawNextHop : mapInterfaceName(rawNextHop, interfaceMappings);
    const key = `${route.vrf || ''}|${dest}`;
    if (nextHop && route.next_hop_type !== 'next-vr' && route.next_hop_type !== 'discard') {
      routesWithNextHop.add(key);
    }
  }

  // Group ip-address-type routes by vrf|destination for qualified-next-hop processing
  const ipAddressRouteGroups = new Map();
  const processedGroups = new Set();

  for (let routeIndex = 0; routeIndex < routes.length; routeIndex += 1) {
    const route = routes[routeIndex];
    if (!route.destination) continue;
    const dest = route.destination.trim();
    const rawNextHop = route.next_hop ? route.next_hop.trim().replace(/[^\w.:/-]/g, '') : '';
    const nextHop = route.next_hop_type === 'next-vr'
      ? rawNextHop : mapInterfaceName(rawNextHop, interfaceMappings);

    // Only group ip-address routes (not discard/next-vr/none) that have a mapped next-hop
    if (nextHop && route.next_hop_type !== 'next-vr' && route.next_hop_type !== 'discard' && route.next_hop_type !== 'none') {
      const key = `${route.vrf || ''}|${dest}`;
      if (!ipAddressRouteGroups.has(key)) {
        ipAddressRouteGroups.set(key, []);
      }
      ipAddressRouteGroups.get(key).push({ route, routeIndex, nextHop });
    }
  }

  for (let routeIndex = 0; routeIndex < routes.length; routeIndex += 1) {
    const route = routes[routeIndex];
    if (!route.destination) continue;

    const dest = route.destination.trim();
    const rawNextHop = route.next_hop ? route.next_hop.trim().replace(/[^\w.:/-]/g, '') : '';
    const nextHop = route.next_hop_type === 'next-vr'
      ? rawNextHop : mapInterfaceName(rawNextHop, interfaceMappings);
    const key = `${route.vrf || ''}|${dest}`;

    const { instanceName, nextTableName } = routeIdentifierNames[routeIndex];

    // Determine the command prefix (VRF or global)
    const prefix = route.vrf
      ? `set routing-instances ${instanceName} routing-options static route ${dest}`
      : `set routing-options static route ${dest}`;

    // Check if this route is part of an ip-address group that needs qualified-next-hop processing
    const group = ipAddressRouteGroups.get(key);
    const isGroupedIpRoute = !!group && group.length > 1 && group.some(member => member.routeIndex === routeIndex);

    if (group && group.length > 1 && !processedGroups.has(key)) {
      // Process the entire group at once
      processedGroups.add(key);

      // Sort by metric ascending (default to 10 if not set)
      const sortedGroup = [...group].sort((a, b) => {
        const metricA = a.route.metric || 10;
        const metricB = b.route.metric || 10;
        return metricA - metricB;
      });

      const minMetric = sortedGroup[0].route.metric || 10;

      // Emit primary next-hops (all routes with minMetric)
      for (const { route: r, nextHop: nh } of sortedGroup) {
        const metric = r.metric || 10;
        if (metric === minMetric) {
          commands.push(`${prefix} next-hop ${nh}`);
          routesWithAction.add(key);
        }
      }

      // Emit route-level preference only if minMetric !== 10
      if (minMetric !== 10) {
        const pref = Math.max(1, Math.min(4294967295, minMetric));
        commands.push(`${prefix} preference ${pref}`);
      }

      // Emit qualified-next-hop for backups (all routes with metric > minMetric)
      for (const { route: r, nextHop: nh } of sortedGroup) {
        const metric = r.metric || 10;
        if (metric > minMetric) {
          const pref = Math.max(1, Math.min(4294967295, metric));
          commands.push(`${prefix} qualified-next-hop ${nh} preference ${pref}`);
        }
      }

      // Count every route in this group once (later members hit the skip branch).
      summary.static_routes_converted += sortedGroup.length;
    } else if (isGroupedIpRoute) {
      // This ip-address route was already emitted with its group — skip, do not count
      // (counted in branch 1)
    } else {
      // Single route, or discard/next-vr route (not part of any ip group) — normal per-route logic
      if (route.vrf) {
        // Routing instance
        if (route.next_hop_type === 'discard') {
          if (!routesWithAction.has(key)) {
            commands.push(`set routing-instances ${instanceName} routing-options static route ${dest} discard`);
            routesWithAction.add(key);
          }
        } else if (route.next_hop_type === 'next-vr' && nextHop) {
          // Skip next-table if this destination already has a concrete next-hop
          if (!routesWithNextHop.has(key)) {
            commands.push(`set routing-instances ${instanceName} routing-options static route ${dest} next-table ${nextTableName}.inet.0`);
            routesWithAction.add(key);
          }
        } else if (nextHop) {
          commands.push(`set routing-instances ${instanceName} routing-options static route ${dest} next-hop ${nextHop}`);
          routesWithAction.add(key);
        }
        if (nextHop && route.next_hop_type !== 'discard' && route.next_hop_type !== 'next-vr' && route.metric && route.metric !== 10) {
          const pref = Math.max(1, Math.min(4294967295, route.metric));
          commands.push(`set routing-instances ${instanceName} routing-options static route ${dest} preference ${pref}`);
        }
      } else {
        // Global routing-options
        if (route.next_hop_type === 'discard') {
          if (!routesWithAction.has(key)) {
            commands.push(`set routing-options static route ${dest} discard`);
            routesWithAction.add(key);
          }
        } else if (route.next_hop_type === 'next-vr' && nextHop) {
          // Skip next-table if this destination already has a concrete next-hop
          if (!routesWithNextHop.has(key)) {
            commands.push(`set routing-options static route ${dest} next-table ${nextTableName}.inet.0`);
            routesWithAction.add(key);
          }
        } else if (nextHop) {
          commands.push(`set routing-options static route ${dest} next-hop ${nextHop}`);
          routesWithAction.add(key);
        }
        if (nextHop && route.next_hop_type !== 'discard' && route.next_hop_type !== 'next-vr' && route.metric && route.metric !== 10) {
          const pref = Math.max(1, Math.min(4294967295, route.metric));
          commands.push(`set routing-options static route ${dest} preference ${pref}`);
        }
      }

      summary.static_routes_converted++;
    }
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// BGP Configuration
// ---------------------------------------------------------------------------

function convertBgpConfig(bgpConfig, commands, warnings, summary, identifiers, identifierPath, routingInstances) {
  if (!bgpConfig || bgpConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# BGP Configuration');
  commands.push('# =============================================');

  const defaultBgpGroups = new Map();
  for (let bgpIndex = 0; bgpIndex < bgpConfig.length; bgpIndex += 1) {
    const bgp = bgpConfig[bgpIndex];
    const instanceName = bgp.instance
      ? plannedRoutingInstanceName(
        bgp.instance,
        identifierPath(`bgp_config[${bgpIndex}].instance`),
        identifiers,
        routingInstances,
      )
      : null;
    const prefix = bgp.instance
      ? `set routing-instances ${instanceName} `
      : 'set ';
    const defaultGroupKey = bgp.instance || 'default';
    const needsDefaultGroup = (bgp.networks || []).some(network => network.policy)
      && !bgp.peer_groups?.[0]?.name;
    let defaultGroupName = null;
    if (needsDefaultGroup) {
      if (!defaultBgpGroups.has(defaultGroupKey)) {
        defaultBgpGroups.set(defaultGroupKey, identifiers.nameForGenerated(
          identifierPath(`bgp_config[${bgpIndex}]`),
          'default-bgp-group',
        ));
      }
      defaultGroupName = identifiers.nameForReference(
        identifierPath(`bgp_config[${bgpIndex}]#default-bgp-group`),
      );
    }

    // Autonomous system and router-id
    if (bgp.local_as) {
      commands.push(`${prefix}routing-options autonomous-system ${bgp.local_as}`);
    }
    if (bgp.router_id) {
      commands.push(`${prefix}routing-options router-id ${bgp.router_id}`);
    }

    // Peer groups and neighbors
    for (let groupIndex = 0; groupIndex < (bgp.peer_groups || []).length; groupIndex += 1) {
      const group = bgp.peer_groups[groupIndex];
      const gName = identifiers.nameForDefinition(
        identifierPath(`bgp_config[${bgpIndex}].peer_groups[${groupIndex}].name`),
      );
      commands.push(`${prefix}protocols bgp group ${gName} type ${group.type || 'external'}`);

      for (let neighborIndex = 0; neighborIndex < (group.neighbors || []).length; neighborIndex += 1) {
        const neighbor = group.neighbors[neighborIndex];
        const nBase = `${prefix}protocols bgp group ${gName} neighbor ${neighbor.address}`;
        if (neighbor.peer_as) {
          commands.push(`${nBase} peer-as ${neighbor.peer_as}`);
        }
        if (neighbor.description) {
          commands.push(`${nBase} description ${setQuoted(neighbor.description, 'bgp_config.neighbors.description')}`);
        }
        if (neighbor.local_address) {
          commands.push(`${nBase} local-address ${neighbor.local_address}`);
        }
        if (neighbor.import_policy) {
          const importPolicy = identifiers.nameForReference(identifierPath(
            `bgp_config[${bgpIndex}].peer_groups[${groupIndex}].neighbors[${neighborIndex}].import_policy`,
          ));
          commands.push(`${nBase} import ${importPolicy}`);
        }
        if (neighbor.export_policy) {
          const exportPolicy = identifiers.nameForReference(identifierPath(
            `bgp_config[${bgpIndex}].peer_groups[${groupIndex}].neighbors[${neighborIndex}].export_policy`,
          ));
          commands.push(`${nBase} export ${exportPolicy}`);
        }
        if (neighbor.authentication_key) {
          commands.push(`${nBase} authentication-key ${setQuoted(neighbor.authentication_key, 'bgp_config.neighbors.authentication_key')}`);
        }
        if (neighbor.enabled === false) {
          warnings.push(createWarning(
            'info',
            `BGP neighbor ${neighbor.address} in group ${gName} is disabled — deactivate command not generated (requires manual config)`,
            neighbor.address,
            'bgp_neighbor_disabled'
          ));
        }
        summary.bgp_neighbors_converted = (summary.bgp_neighbors_converted || 0) + 1;
      }
      summary.bgp_groups_converted = (summary.bgp_groups_converted || 0) + 1;
    }

    // Network advertisements via policy-options
    if (bgp.networks && bgp.networks.length > 0) {
      for (let networkIndex = 0; networkIndex < bgp.networks.length; networkIndex += 1) {
        const net = bgp.networks[networkIndex];
        if (net.policy) {
          // Reference existing policy
          const groupName = bgp.peer_groups?.[0]?.name
            ? identifiers.nameForDefinition(identifierPath(`bgp_config[${bgpIndex}].peer_groups[0].name`))
            : defaultGroupName;
          const exportPolicy = identifiers.nameForReference(
            identifierPath(`bgp_config[${bgpIndex}].networks[${networkIndex}].policy`),
          );
          commands.push(`${prefix}protocols bgp group ${groupName} export ${exportPolicy}`);
        }
      }
    }

    // Redistribution via policy-options
    for (let redistIndex = 0; redistIndex < (bgp.redistribute || []).length; redistIndex += 1) {
      const redist = bgp.redistribute[redistIndex];
      const stmtName = identifiers.nameForGenerated(
        identifierPath(`bgp_config[${bgpIndex}].redistribute[${redistIndex}]`),
        'bgp-redistribution-policy',
      );
      commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 from protocol ${redist.protocol}`);
      commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 then accept`);
      if (redist.policy) {
        commands.push(`# Source policy reference: ${redist.policy}`);
      }
    }
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// OSPF Configuration
// ---------------------------------------------------------------------------

function convertOspfConfig(ospfConfig, commands, warnings, summary, interfaceMappings = {}, identifiers, identifierPath, routingInstances) {
  if (!ospfConfig || ospfConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# OSPF Configuration');
  commands.push('# =============================================');

  for (let ospfIndex = 0; ospfIndex < ospfConfig.length; ospfIndex += 1) {
    const ospf = ospfConfig[ospfIndex];
    const instanceName = ospf.instance
      ? plannedRoutingInstanceName(
        ospf.instance,
        identifierPath(`ospf_config[${ospfIndex}].instance`),
        identifiers,
        routingInstances,
      )
      : null;
    const prefix = ospf.instance
      ? `set routing-instances ${instanceName} `
      : 'set ';

    // Router-id (may overlap with BGP — SRX uses routing-options router-id for both)
    if (ospf.router_id) {
      commands.push(`${prefix}routing-options router-id ${ospf.router_id}`);
    }

    // Reference bandwidth
    if (ospf.reference_bandwidth) {
      commands.push(`${prefix}protocols ospf reference-bandwidth ${ospf.reference_bandwidth}`);
    }

    // Areas
    for (const area of ospf.areas || []) {
      const areaId = area.area_id;

      // Fix 7: Check if area has any valid SRX interfaces after mapping — skip if empty
      const mappedInterfaces = (area.interfaces || []).filter(iface => {
        const mapped = mapInterfaceName(iface.name, interfaceMappings);
        return isValidSrxInterface(mapped);
      });
      if (mappedInterfaces.length === 0) {
        commands.push(`# WARNING: OSPF area ${areaId} skipped — no interfaces configured`);
        warnings.push(createWarning('warning', `ospf/area/${areaId}`,
          `OSPF area ${areaId} has no interfaces after mapping — skipped to avoid commit error`,
          'Add interfaces to this OSPF area or remove it'));
        continue;
      }

      // Area type
      if (area.area_type === 'stub') {
        commands.push(`${prefix}protocols ospf area ${areaId} stub`);
      } else if (area.area_type === 'totally-stub') {
        commands.push(`${prefix}protocols ospf area ${areaId} stub no-summaries`);
      } else if (area.area_type === 'nssa') {
        commands.push(`${prefix}protocols ospf area ${areaId} nssa`);
      } else if (area.area_type === 'totally-nssa') {
        commands.push(`${prefix}protocols ospf area ${areaId} nssa no-summaries`);
      }

      // Interfaces
      for (const iface of area.interfaces || []) {
        const mappedIfName = mapInterfaceName(iface.name, interfaceMappings);
        if (!isValidSrxInterface(mappedIfName)) continue;
        const ifBase = `${prefix}protocols ospf area ${areaId} interface ${mappedIfName}`;
        commands.push(ifBase);

        if (iface.cost != null) {
          commands.push(`${ifBase} metric ${iface.cost}`);
        }
        if (iface.hello_interval != null) {
          commands.push(`${ifBase} hello-interval ${iface.hello_interval}`);
        }
        if (iface.dead_interval != null) {
          commands.push(`${ifBase} dead-interval ${iface.dead_interval}`);
        }
        if (iface.passive) {
          commands.push(`${ifBase} passive`);
        }
        if (iface.network_type) {
          commands.push(`${ifBase} interface-type ${iface.network_type}`);
        }

        // Authentication
        if (iface.authentication) {
          if (iface.authentication.type === 'md5') {
            const keyId = iface.authentication.key_id || 1;
            commands.push(`${ifBase} authentication md5 ${keyId} key ${setQuoted(iface.authentication.key || '', 'ospf_config.areas.interfaces.authentication.key')}`);
          } else if (iface.authentication.type === 'simple') {
            commands.push(`${ifBase} authentication simple-password ${setQuoted(iface.authentication.key || '', 'ospf_config.areas.interfaces.authentication.key')}`);
          }
        }

        summary.ospf_interfaces_converted = (summary.ospf_interfaces_converted || 0) + 1;
      }

      // Network statements (from Cisco/Huawei — converted to interface references with warning)
      for (const net of area.networks || []) {
        warnings.push(createWarning(
          'info',
          `OSPF network statement ${net.prefix} in area ${areaId} — SRX uses per-interface OSPF config. Add the appropriate interface to area ${areaId} manually.`,
          net.prefix,
          'ospf_network_to_interface'
        ));
      }

      summary.ospf_areas_converted = (summary.ospf_areas_converted || 0) + 1;
    }

    // Redistribution via export policy
    for (let redistIndex = 0; redistIndex < (ospf.redistribute || []).length; redistIndex += 1) {
      const redist = ospf.redistribute[redistIndex];
      const stmtName = identifiers.nameForGenerated(
        identifierPath(`ospf_config[${ospfIndex}].redistribute[${redistIndex}]`),
        'ospf-redistribution-policy',
      );
      commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 from protocol ${redist.protocol}`);
      if (redist.metric_type) {
        commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 then external type ${redist.metric_type}`);
      }
      commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 then accept`);
      commands.push(`${prefix}protocols ospf export ${stmtName}`);
    }
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// OSPFv3 Configuration
// ---------------------------------------------------------------------------

function convertOspf3Config(ospf3Config, commands, warnings, summary, interfaceMappings = {}, identifiers, identifierPath, routingInstances) {
  if (!ospf3Config || ospf3Config.length === 0) return;

  commands.push('# =============================================');
  commands.push('# OSPFv3 (IPv6 OSPF) Configuration');
  commands.push('# =============================================');

  for (let ospfIndex = 0; ospfIndex < ospf3Config.length; ospfIndex += 1) {
    const ospf = ospf3Config[ospfIndex];
    const instanceName = ospf.instance
      ? plannedRoutingInstanceName(
        ospf.instance,
        identifierPath(`ospf3_config[${ospfIndex}].instance`),
        identifiers,
        routingInstances,
      )
      : null;
    const prefix = ospf.instance
      ? `set routing-instances ${instanceName} `
      : 'set ';

    if (ospf.router_id) {
      commands.push(`${prefix}routing-options router-id ${ospf.router_id}`);
    }

    if (ospf.reference_bandwidth) {
      commands.push(`${prefix}protocols ospf3 reference-bandwidth ${ospf.reference_bandwidth}`);
    }

    for (const area of ospf.areas || []) {
      const areaId = area.area_id;

      // Fix 7: Skip OSPFv3 areas with no valid SRX interfaces after mapping
      const mappedIf3s = (area.interfaces || []).filter(iface => {
        const mapped = mapInterfaceName(iface.name, interfaceMappings);
        return isValidSrxInterface(mapped);
      });
      if (mappedIf3s.length === 0) {
        commands.push(`# WARNING: OSPFv3 area ${areaId} skipped — no interfaces configured`);
        warnings.push(createWarning('warning', `ospf3/area/${areaId}`,
          `OSPFv3 area ${areaId} has no interfaces after mapping — skipped to avoid commit error`,
          'Add interfaces to this OSPFv3 area or remove it'));
        continue;
      }

      if (area.area_type === 'stub') {
        commands.push(`${prefix}protocols ospf3 area ${areaId} stub`);
      } else if (area.area_type === 'totally-stub') {
        commands.push(`${prefix}protocols ospf3 area ${areaId} stub no-summaries`);
      } else if (area.area_type === 'nssa') {
        commands.push(`${prefix}protocols ospf3 area ${areaId} nssa`);
      } else if (area.area_type === 'totally-nssa') {
        commands.push(`${prefix}protocols ospf3 area ${areaId} nssa no-summaries`);
      }

      for (const iface of area.interfaces || []) {
        const mappedIf3Name = mapInterfaceName(iface.name, interfaceMappings);
        if (!isValidSrxInterface(mappedIf3Name)) continue;
        const ifBase = `${prefix}protocols ospf3 area ${areaId} interface ${mappedIf3Name}`;
        commands.push(ifBase);

        if (iface.cost != null) {
          commands.push(`${ifBase} metric ${iface.cost}`);
        }
        if (iface.hello_interval != null) {
          commands.push(`${ifBase} hello-interval ${iface.hello_interval}`);
        }
        if (iface.dead_interval != null) {
          commands.push(`${ifBase} dead-interval ${iface.dead_interval}`);
        }
        if (iface.passive) {
          commands.push(`${ifBase} passive`);
        }
        if (iface.network_type) {
          commands.push(`${ifBase} interface-type ${iface.network_type}`);
        }
        if (iface.instance_id != null) {
          commands.push(`${ifBase} instance-id ${iface.instance_id}`);
        }

        summary.ospf3_interfaces_converted = (summary.ospf3_interfaces_converted || 0) + 1;
      }

      for (const net of area.networks || []) {
        warnings.push(createWarning(
          'info',
          `OSPFv3 network statement ${net.prefix} in area ${areaId} — SRX uses per-interface OSPFv3 config. Add the appropriate interface to area ${areaId} manually.`,
          net.prefix,
          'ospf3_network_to_interface'
        ));
      }

      summary.ospf3_areas_converted = (summary.ospf3_areas_converted || 0) + 1;
    }

    for (let redistIndex = 0; redistIndex < (ospf.redistribute || []).length; redistIndex += 1) {
      const redist = ospf.redistribute[redistIndex];
      const stmtName = identifiers.nameForGenerated(
        identifierPath(`ospf3_config[${ospfIndex}].redistribute[${redistIndex}]`),
        'ospf3-redistribution-policy',
      );
      commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 from protocol ${redist.protocol}`);
      if (redist.metric_type) {
        commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 then external type ${redist.metric_type}`);
      }
      commands.push(`${prefix}policy-options policy-statement ${stmtName} term 1 then accept`);
      commands.push(`${prefix}protocols ospf3 export ${stmtName}`);
    }
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// EVPN Configuration
// ---------------------------------------------------------------------------

function convertEvpnConfig(evpnConfig, commands, warnings, summary, interfaceMappings = {}, identifiers, identifierPath, routingInstances) {
  if (!evpnConfig || evpnConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# EVPN / VxLAN Fabric Configuration');
  commands.push('# =============================================');

  for (let evpnIndex = 0; evpnIndex < evpnConfig.length; evpnIndex += 1) {
    const evpn = evpnConfig[evpnIndex];
    const instanceName = evpn.instance
      ? plannedRoutingInstanceName(
        evpn.instance,
        identifierPath(`evpn_config[${evpnIndex}].instance`),
        identifiers,
        routingInstances,
      )
      : null;
    const prefix = evpn.instance
      ? `set routing-instances ${instanceName} `
      : 'set ';

    // Instance type for routing-instances (mac-vrf, virtual-switch)
    if (evpn.instance && evpn.instance_type) {
      commands.push(`${prefix}instance-type ${evpn.instance_type}`);
    }

    // EVPN protocol settings
    commands.push(`${prefix}protocols evpn encapsulation ${evpn.encapsulation || 'vxlan'}`);

    if (evpn.multicast_mode) {
      commands.push(`${prefix}protocols evpn multicast-mode ${evpn.multicast_mode}`);
    }

    if (evpn.extended_vni_list && evpn.extended_vni_list.length > 0) {
      for (const vni of evpn.extended_vni_list) {
        commands.push(`${prefix}protocols evpn extended-vni-list ${vni}`);
      }
    }

    // Switch-options (global or per-instance)
    if (evpn.route_distinguisher) {
      const swPrefix = evpn.instance ? prefix : 'set ';
      const vtepSource = mapInterfaceName(
        evpn.vtep_source_interface || 'lo0.0',
        interfaceMappings,
      );
      commands.push(`${swPrefix}switch-options vtep-source-interface ${vtepSource}`);
      commands.push(`${swPrefix}switch-options route-distinguisher ${evpn.route_distinguisher}`);
    }

    if (evpn.vrf_target) {
      const swPrefix = evpn.instance ? prefix : 'set ';
      commands.push(`${swPrefix}switch-options vrf-target ${evpn.vrf_target}`);
    }

    // Route targets (explicit import/export)
    for (const rt of evpn.route_targets || []) {
      if (rt.direction === 'import' || rt.direction === 'both') {
        commands.push(`${prefix}vrf-import ${rt.target}`);
      }
      if (rt.direction === 'export' || rt.direction === 'both') {
        commands.push(`${prefix}vrf-export ${rt.target}`);
      }
    }

    // VLANs with VxLAN VNI mappings
    for (let vlanIndex = 0; vlanIndex < (evpn.vlans || []).length; vlanIndex += 1) {
      const vlan = evpn.vlans[vlanIndex];
      const vlanName = identifiers.nameForDefinition(
        identifierPath(`evpn_config[${evpnIndex}].vlans[${vlanIndex}].name`),
      );
      commands.push(`set vlans ${vlanName} vlan-id ${vlan.vlan_id}`);
      commands.push(`set vlans ${vlanName} vxlan vni ${vlan.vni}`);
      if (vlan.ingress_node_replication) {
        commands.push(`set vlans ${vlanName} vxlan ingress-node-replication`);
      }
      summary.evpn_vlans_converted = (summary.evpn_vlans_converted || 0) + 1;
    }

    summary.evpn_instances_converted = (summary.evpn_instances_converted || 0) + 1;
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// VxLAN Configuration (standalone, non-EVPN)
// ---------------------------------------------------------------------------

function convertVxlanConfig(vxlanConfig, commands, warnings, summary, interfaceMappings = {}, identifiers, identifierPath, routingInstances) {
  if (!vxlanConfig || vxlanConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# VxLAN Tunnel Configuration');
  commands.push('# =============================================');
  commands.push('# Note: SRX typically uses EVPN for VxLAN. These are standalone VxLAN tunnels.');

  for (let tunnelIndex = 0; tunnelIndex < vxlanConfig.length; tunnelIndex += 1) {
    const tunnel = vxlanConfig[tunnelIndex];
    const instanceName = tunnel.instance
      ? plannedRoutingInstanceName(
        tunnel.instance,
        identifierPath(`vxlan_config[${tunnelIndex}].instance`),
        identifiers,
        routingInstances,
      )
      : null;
    const prefix = tunnel.instance
      ? `set routing-instances ${instanceName} `
      : 'set ';

    // VTEP source interface
    if (tunnel.vtep_source_interface || tunnel.source_interface) {
      const vtepSource = mapInterfaceName(
        tunnel.vtep_source_interface || tunnel.source_interface,
        interfaceMappings,
      );
      commands.push(`${prefix}switch-options vtep-source-interface ${vtepSource}`);
    }

    // VNI entries
    for (let vniIndex = 0; vniIndex < (tunnel.vnis || []).length; vniIndex += 1) {
      const vni = tunnel.vnis[vniIndex];
      const vniId = vni.vni;
      const vlanName = vni.vlan_id
        ? identifiers.nameForGenerated(
          identifierPath(`vxlan_config[${tunnelIndex}].vnis[${vniIndex}]`),
          'vxlan-vlan',
        )
        : null;
      commands.push(`# VxLAN VNI ${vniId}${tunnel.name ? ` (source: ${tunnel.name})` : ''}`);

      if (vni.vlan_id) {
        commands.push(`set vlans ${vlanName} vlan-id ${vni.vlan_id}`);
        commands.push(`set vlans ${vlanName} vxlan vni ${vniId}`);
      }

      if (vni.ingress_replication) {
        if (vlanName) commands.push(`set vlans ${vlanName} vxlan ingress-node-replication`);
      }

      // Static remote VTEPs (flood list)
      for (const vtep of vni.remote_vteps || []) {
        warnings.push(createWarning(
          'info',
          `VxLAN VNI ${vniId} has static remote VTEP ${vtep}. SRX EVPN uses BGP for VTEP discovery — consider migrating to EVPN.`,
          tunnel.name || `VNI-${vniId}`,
          'vxlan_static_vtep'
        ));
      }
    }

    // UDP port
    if (tunnel.udp_port && tunnel.udp_port !== 4789) {
      warnings.push(createWarning(
        'info',
        `VxLAN tunnel ${tunnel.name || ''} uses non-standard UDP port ${tunnel.udp_port} (default: 4789). SRX uses standard port 4789.`,
        tunnel.name || 'vxlan',
        'vxlan_nonstandard_port'
      ));
    }

    summary.vxlan_tunnels_converted = (summary.vxlan_tunnels_converted || 0) + 1;
  }

  commands.push('');
}

/**
 * Converts HA configuration to SRX chassis cluster or MNHA set commands.
 */
/**
 * Converts HA configuration to SRX commands based on explicit deployment mode or auto-detection.
 * @param {Object} haConfig - HA configuration from source
 * @param {Array<string>} commands - Output command array
 * @param {Array<Object>} warnings - Warnings array
 * @param {Object} summary - Summary object
 * @param {Object} interfaceMappings - Interface mapping object
 * @param {string} deploymentMode - Explicit deployment mode: 'standalone', 'chassis-cluster', 'mnha', or undefined (auto)
 */
function convertHaConfig(haConfig, commands, warnings, summary, interfaceMappings = {}, deploymentMode) {
  // Explicit deployment mode dispatch
  if (deploymentMode) {
    if (deploymentMode === 'standalone') {
      commands.push('# Target: standalone — no HA/chassis-cluster/MNHA config emitted.');
      commands.push('');
      return;
    }

    if (deploymentMode === 'mnha') {
      // MNHA mode — use haConfig fields or defaults
      convertMnhaConfig(haConfig || {}, commands, warnings, summary, interfaceMappings);
      return;
    }

    if (deploymentMode === 'chassis-cluster') {
      // Chassis cluster mode — emit even if haConfig is missing/disabled
      const effectiveHaConfig = haConfig || {};
      convertChassisClusterConfig(effectiveHaConfig, commands, warnings, summary, interfaceMappings);
      return;
    }
  }

  // Auto mode (legacy behavior) — only emit HA if enabled
  if (!haConfig || !haConfig.enabled) return;

  // Auto mode ha_type dispatch
  if (haConfig.ha_type === 'mnha') {
    convertMnhaConfig(haConfig, commands, warnings, summary, interfaceMappings);
    return;
  }

  // Auto mode default: chassis cluster
  convertChassisClusterConfig(haConfig, commands, warnings, summary, interfaceMappings);
}

/**
 * Converts chassis cluster configuration to SRX set commands.
 * Extracted from convertHaConfig for reuse in explicit deployment mode.
 */
function convertChassisClusterConfig(haConfig, commands, warnings, summary, interfaceMappings = {}) {
  commands.push('# =============================================');
  commands.push('# Chassis Cluster / HA Configuration');
  commands.push('# =============================================');
  commands.push(`# Source HA: ${haConfig.description || haConfig.mode || 'chassis-cluster'}`);

  const clusterId = haConfig.group_id || 1;

  // Chassis cluster setup
  commands.push(`set chassis cluster cluster-id ${clusterId}`);

  // Redundancy group 0 (control plane) — always needed
  commands.push(`set chassis cluster redundancy-group 0 node 0 priority ${haConfig.priority || 200}`);
  const secondaryPrio = (haConfig.priority || 200) > 100 ? 100 : (haConfig.priority || 200) - 1;
  commands.push(`set chassis cluster redundancy-group 0 node 1 priority ${secondaryPrio}`);

  // Redundancy group 1 (data plane) — mirrors RG0 priorities
  commands.push(`set chassis cluster redundancy-group 1 node 0 priority ${haConfig.priority || 200}`);
  commands.push(`set chassis cluster redundancy-group 1 node 1 priority ${secondaryPrio}`);

  if (haConfig.preempt) {
    commands.push('set chassis cluster redundancy-group 0 preempt');
    commands.push('set chassis cluster redundancy-group 1 preempt');
  }

  // Heartbeat interval
  commands.push('set chassis cluster heartbeat-interval 1000');
  commands.push('set chassis cluster heartbeat-threshold 3');

  // HA interfaces — map to SRX fabric and control links
  if (haConfig.ha_interfaces) {
    for (const iface of haConfig.ha_interfaces) {
    const name = (iface.name || '').toLowerCase();
    if (name === 'fab0' || name === 'fab1' || name.includes('fabric')) {
      if (iface.interface) {
        const memberInterface = mapInterfaceName(iface.interface, interfaceMappings);
        commands.push(`set interfaces ${name.startsWith('fab') ? name : 'fab0'} fabric-options member-interfaces ${memberInterface}`);
      }
    } else if (name.includes('ha1') || name.includes('heartbeat') || name.includes('failover') || name.includes('control')) {
      // Map to SRX control-link (fxp1) — add as comment since fxp1 is implicit
      commands.push(`# Source HA control link: ${iface.name} on ${iface.interface || 'N/A'} (${iface.ip || 'no IP'})`);
    } else if (name.includes('ha2') || name.includes('state') || name.includes('stateful')) {
      commands.push(`# Source HA data link: ${iface.name} on ${iface.interface || 'N/A'} (${iface.ip || 'no IP'})`);
    } else if (iface.interface) {
      commands.push(`# Source HA interface: ${iface.name} on ${iface.interface} (${iface.ip || 'no IP'})`);
    }
    }
  }

  // Monitoring
  if (haConfig.monitoring) {
    for (const lg of (haConfig.monitoring.link_groups || [])) {
      if (lg.interfaces && lg.interfaces.length > 0) {
        commands.push(`# Source link monitoring group "${lg.name}": ${lg.interfaces.join(', ')}`);
      }
    }
  }

  commands.push('# NOTE: Review chassis cluster config — verify fabric interfaces, reth interfaces,');
  commands.push('# and redundancy-group assignments match your target SRX hardware topology');

  warnings.push(createWarning('ha', 'HA converted to chassis cluster — verify fabric/reth mappings for target hardware', 'info'));
  summary.ha_converted = 1;
  commands.push('');
}

/**
 * Builds the list of MNHA peers from haConfig for 2-, 3-, or 4-node topologies.
 * For 2-node: uses legacy peer_id/peer_ip fields or additional_peers[0].
 * For 3/4-node: uses additional_peers array for all peers beyond the first.
 * @param {Object} haConfig - HA configuration object
 * @param {number} nodeCount - Total node count (2, 3, or 4)
 * @returns {Array<Object>} Array of peer objects with peer_id, peer_ip, icl_interface, vpn_profile, etc.
 */
function buildMnhaPeerList(haConfig, nodeCount) {
  const peers = [];
  const additionalPeers = haConfig.additional_peers || [];

  // First peer — always from top-level fields (backward compatible with 2-node)
  // ICL interface fallback: haConfig.icl_interface or first ha_interface (for PAN-OS sources)
  const iclInterfaceFallback = haConfig.icl_interface ||
    (haConfig.ha_interfaces && haConfig.ha_interfaces[0] ? haConfig.ha_interfaces[0].interface : '');

  peers.push({
    peer_id: haConfig.peer_id || 2,
    peer_ip: haConfig.peer_ip || '',
    icl_interface: iclInterfaceFallback,
    vpn_profile: haConfig.vpn_profile || '',
    liveness_interval: haConfig.liveness_interval || 400,
    liveness_multiplier: haConfig.liveness_multiplier || 5,
    deployment_type: haConfig.deployment_type || 'routing',
    activeness_priority: haConfig.activeness_priority || 200,
    preemption: haConfig.preemption,
  });

  // Additional peers for 3-node and 4-node
  for (let i = 0; i < nodeCount - 2; i++) {
    const extra = additionalPeers[i] || {};
    peers.push({
      peer_id: extra.peer_id || (3 + i),
      peer_ip: extra.peer_ip || '',
      icl_interface: extra.icl_interface || '',
      vpn_profile: extra.vpn_profile || '',
      liveness_interval: extra.liveness_interval || haConfig.liveness_interval || 400,
      liveness_multiplier: extra.liveness_multiplier || haConfig.liveness_multiplier || 5,
      deployment_type: extra.deployment_type || haConfig.deployment_type || 'routing',
      activeness_priority: extra.activeness_priority || Math.max(100, (haConfig.activeness_priority || 200) - (50 * (i + 1))),
      preemption: extra.preemption ?? haConfig.preemption,
    });
  }

  return peers;
}

/**
 * Converts MNHA (Multinode High Availability) configuration to SRX set commands.
 * Uses `set chassis high-availability` instead of `set chassis cluster`.
 * Supports 2-node, 3-node, and 4-node MNHA topologies.
 * Emits skill-correct MNHA config per srx-mnha skill (flat model, activeness-probe, SRG monitoring, ICL zone).
 */
function convertMnhaConfig(haConfig, commands, warnings, summary, interfaceMappings = {}) {
  const nodeCount = haConfig.node_count || 2;
  commands.push('# =============================================');
  commands.push(`# Multinode High Availability (MNHA) — ${nodeCount}-Node Configuration`);
  commands.push('# =============================================');
  commands.push(`# ${haConfig.description || 'MNHA ' + (haConfig.mode || 'active-passive')}`);

  const localId = haConfig.local_id || 1;
  const prefix = 'set chassis high-availability';

  // Local node
  commands.push(`${prefix} local-id ${localId}`);
  if (haConfig.local_ip) {
    commands.push(`${prefix} local-id local-ip ${haConfig.local_ip}`);
  }

  // Build list of all peers (supports 2-, 3-, and 4-node topologies)
  const peers = buildMnhaPeerList(haConfig, nodeCount);
  const iclInterfaces = []; // Track ICL interfaces for security zone

  // SRG1 (data plane) — SRG-level attributes emitted ONCE (not per peer).
  const deployType = haConfig.deployment_type || 'routing';
  commands.push(`${prefix} services-redundancy-group 1 deployment-type ${deployType}`);
  commands.push(`${prefix} services-redundancy-group 1 activeness-priority ${haConfig.activeness_priority || 200}`);
  if (haConfig.preemption) {
    commands.push(`${prefix} services-redundancy-group 1 preemption`);
  }

  for (const peer of peers) {
    // Peer node identity
    if (peer.peer_ip) {
      commands.push(`${prefix} peer-id ${peer.peer_id} peer-ip ${peer.peer_ip}`);
    }
    if (peer.icl_interface) {
      const iclInterface = mapInterfaceName(peer.icl_interface, interfaceMappings);
      commands.push(`${prefix} peer-id ${peer.peer_id} interface ${iclInterface}`);
      // Track for ICL security zone
      if (!iclInterfaces.includes(iclInterface)) {
        iclInterfaces.push(iclInterface);
      }
    }
    if (peer.vpn_profile) {
      commands.push(`# CAVEAT: ICL encryption references vpn-profile "${peer.vpn_profile}" — define this IKE/IPsec profile, or remove the line to run the ICL unencrypted.`);
      commands.push(`${prefix} peer-id ${peer.peer_id} vpn-profile ${peer.vpn_profile}`);
    }

    // Liveness detection per peer
    const livenessInterval = peer.liveness_interval || haConfig.liveness_interval || 400;
    const livenessMultiplier = peer.liveness_multiplier || haConfig.liveness_multiplier || 5;
    commands.push(`${prefix} peer-id ${peer.peer_id} liveness-detection minimum-interval ${livenessInterval}`);
    commands.push(`${prefix} peer-id ${peer.peer_id} liveness-detection multiplier ${livenessMultiplier}`);

    // SRG0 (control plane) — associate each peer
    commands.push(`${prefix} services-redundancy-group 0 peer-id ${peer.peer_id}`);

    // SRG1 (data plane) — associate each peer
    commands.push(`${prefix} services-redundancy-group 1 peer-id ${peer.peer_id}`);
  }

  // Mandatory activeness-probe for deployment-type routing (emitted once, SRG-level).
  if (deployType === 'routing') {
    const probeDest = haConfig.activeness_probe_dest || '192.0.2.1';
    const probeSrc = haConfig.activeness_probe_src || '192.0.2.2';
    commands.push(`${prefix} services-redundancy-group 1 activeness-probe dest-ip ${probeDest} src-ip ${probeSrc}`);

    if (!haConfig.activeness_probe_dest || !haConfig.activeness_probe_src) {
      commands.push('# CAVEAT: activeness-probe uses placeholder IPs — set to a REAL reachable data-segment address (not the ICL); mandatory for deployment-type routing.');
      warnings.push(createWarning('ha', 'MNHA activeness-probe uses placeholder IPs (192.0.2.x) — replace with real reachable data-segment addresses before commit', 'warning'));
    }
  }

  // SRG interface monitoring via monitor-object (not chassis-cluster interface-monitor)
  const monitoredInterfaces = new Set();
  if (haConfig.monitoring) {
    for (const lg of (haConfig.monitoring.link_groups || [])) {
      if (lg.enabled && lg.interfaces && lg.interfaces.length > 0) {
        for (const iface of lg.interfaces) {
          const monitorIfl = mapInterfaceName(iface, interfaceMappings);
          // Extract IFD (physical interface) for monitoring — strip .unit
          const monitorIfd = monitorIfl.split('.')[0];
          if (!monitoredInterfaces.has(monitorIfd)) {
            monitoredInterfaces.add(monitorIfd);
            // Sanitize interface name for monitor-object name (replace slashes with dashes)
            const monObjName = `mon-${monitorIfd.replace(/\//g, '-')}`;
            commands.push(`${prefix} services-redundancy-group 1 monitor monitor-object ${monObjName} interface interface-name ${monitorIfd} weight 100`);
            commands.push(`${prefix} services-redundancy-group 1 monitor monitor-object ${monObjName} interface threshold 100`);
            commands.push(`${prefix} services-redundancy-group 1 monitor monitor-object ${monObjName} object-threshold 100`);
            commands.push(`${prefix} services-redundancy-group 1 monitor srg-threshold 100`);
          }
        }
      }
    }
    if (monitoredInterfaces.size > 0) {
      commands.push('# CAVEAT: chassis-cluster interface-monitor weights were NOT ported 1:1 — SRG monitoring redesigned; re-validate failover.');
    }
  }

  // ICL security zone (required for HA link services)
  for (const iclIface of iclInterfaces) {
    // Add .0 unit if not already present
    const iclIfl = iclIface.includes('.') ? iclIface : `${iclIface}.0`;
    commands.push(`set security zones security-zone ICL interfaces ${iclIfl}`);
  }
  if (iclInterfaces.length > 0) {
    commands.push('set security zones security-zone ICL host-inbound-traffic system-services high-availability');
  }

  // MNHA caveats
  commands.push('# CAVEAT: flat MNHA config model targets Junos <= 24.x; Junos 26.x requires the GRID model (grid-id/local-domain-id/peer-domain-id) + reboot — verify against the target release.');
  commands.push('# CAVEAT: enabling chassis high-availability is reboot-gated (may need two cycles) to activate.');
  commands.push('# CAVEAT: this is NODE-LOCAL config for one node; the peer node mirrors it with swapped local/peer IDs + IPs and a lower activeness-priority. MNHA does not auto-sync full config.');

  if (nodeCount > 2) {
    commands.push(`# NOTE: ${nodeCount}-node MNHA requires full mesh ICL connectivity between all nodes.`);
    commands.push('# Ensure each node has dedicated ICL interfaces to every other peer.');
  }
  commands.push('# NOTE: Review MNHA config — verify ICL interface, VPN profile, and virtual-IP');
  commands.push('# assignments match your target SRX4700 topology');

  warnings.push(createWarning('ha', 'MNHA output is a node-local scaffold — review activeness-probe, ICL, monitoring, and peer-node mirror per the srx-mnha guidance.', 'info'));
  summary.ha_converted = 1;
  summary.mnha_node_count = nodeCount;
  commands.push('');
}

/**
 * Converts screen/DDoS protection configuration to SRX screen ids-option set commands.
 */
function convertScreenConfig(screens, commands, warnings, summary, identifiers, identifierPath) {
  if (!screens || screens.length === 0) return;

  // Junos screen value limits (parameter → max allowed value)
  const screenLimits = {
    syn_flood_timeout: 50,          // 1..50
    syn_flood_threshold: 1000000,   // 1..1000000
    syn_flood_alarm_threshold: 1000000,
    flood_threshold: 1000000,       // icmp/udp flood
    source_based: 128000,           // limit-session
    destination_based: 128000,
  };

  /** @param {number} val @param {string} key */
  const clampScreen = (val, key) => {
    const max = screenLimits[key];
    if (max && val > max) return max;
    return val;
  };

  commands.push('# =============================================');
  commands.push('# Security Screen (IDS Options)');
  commands.push('# =============================================');

  for (let screenIndex = 0; screenIndex < screens.length; screenIndex += 1) {
    const screen = screens[screenIndex];
    const ownerPath = identifierPath(`screen_config[${screenIndex}]`);
    const name = screen.name
      ? identifiers.nameForDefinition(`${ownerPath}.name`)
      : identifiers.nameForGenerated(ownerPath, 'default-screen-profile');
    const prefix = `set security screen ids-option ${name}`;

    // ICMP protections
    if (screen.icmp) {
      if (screen.icmp.ping_death) commands.push(`${prefix} icmp ping-death`);
      if (screen.icmp.fragment) commands.push(`${prefix} icmp fragment`);
      if (screen.icmp.flood_threshold) commands.push(`${prefix} icmp flood threshold ${clampScreen(screen.icmp.flood_threshold, 'flood_threshold')}`);
    }

    // TCP protections
    if (screen.tcp) {
      if (screen.tcp.syn_flood_threshold) {
        const attackVal = clampScreen(screen.tcp.syn_flood_threshold, 'syn_flood_threshold');
        commands.push(`${prefix} tcp syn-flood attack-threshold ${attackVal}`);
        if (screen.tcp.syn_flood_alarm_threshold) {
          const alarmVal = clampScreen(screen.tcp.syn_flood_alarm_threshold, 'syn_flood_alarm_threshold');
          commands.push(`${prefix} tcp syn-flood alarm-threshold ${alarmVal}`);
        }
      }
      if (screen.tcp.syn_flood_timeout) commands.push(`${prefix} tcp syn-flood timeout ${clampScreen(screen.tcp.syn_flood_timeout, 'syn_flood_timeout')}`);
      if (screen.tcp.land_attack) commands.push(`${prefix} tcp land`);
      if (screen.tcp.winnuke) commands.push(`${prefix} tcp winnuke`);
      if (screen.tcp.tcp_no_flag) commands.push(`${prefix} tcp tcp-no-flag`);
    }

    // UDP protections
    if (screen.udp && screen.udp.flood_threshold) {
      commands.push(`${prefix} udp flood threshold ${clampScreen(screen.udp.flood_threshold, 'flood_threshold')}`);
    }

    // IP protections
    if (screen.ip) {
      if (screen.ip.spoofing) commands.push(`${prefix} ip spoofing`);
      if (screen.ip.source_route) commands.push(`${prefix} ip source-route-option`);
      if (screen.ip.tear_drop) commands.push(`${prefix} ip tear-drop`);
      if (screen.ip.record_route) commands.push(`${prefix} ip record-route-option`);
      if (screen.ip.timestamp) commands.push(`${prefix} ip timestamp-option`);
    }

    // Session limits
    if (screen.limit_session) {
      if (screen.limit_session.source_based) commands.push(`${prefix} limit-session source-ip-based ${clampScreen(screen.limit_session.source_based, 'source_based')}`);
      if (screen.limit_session.destination_based) commands.push(`${prefix} limit-session destination-ip-based ${clampScreen(screen.limit_session.destination_based, 'destination_based')}`);
    }

    // Apply screen to zone if known
    if (screen.zone) {
      const zoneName = identifiers.nameForReference(`${ownerPath}.zone`);
      commands.push(`set security zones security-zone ${zoneName} screen ${name}`);
    } else {
      commands.push(`# NOTE: screen profile "${name}" is not attached to any zone — attach it to the intended zone.`);
      warnings.push(createWarning('warning', `screen/${name}`,
        `Screen profile "${name}" is defined but not attached to a security zone`,
        'Bind it with: set security zones security-zone <zone> screen <name>'));
    }

    summary.screens_converted = (summary.screens_converted || 0) + 1;
  }

  commands.push('');
}

/**
 * Converts VPN/IPsec tunnel configuration to SRX set commands.
 */
/**
 * Maps common authentication algorithm names to valid Junos IKE/IPsec identifiers.
 * IKE proposals use bare names (sha-256), IPsec proposals use HMAC variants (hmac-sha-256-128).
 * @param {string} algo - The source authentication algorithm name
 * @param {'ike'|'ipsec'} context - Whether this is for an IKE or IPsec proposal
 * @returns {string} Valid Junos authentication-algorithm value
 */
function mapAuthAlgorithm(algo, context = 'ipsec') {
  const ikeMap = {
    'sha256': 'sha-256',
    'sha-256': 'sha-256',
    'sha1': 'sha1',
    'sha-1': 'sha1',
    'sha384': 'sha-384',
    'sha-384': 'sha-384',
    'sha512': 'sha-512',
    'sha-512': 'sha-512',
    'md5': 'md5',
    'hmac-sha-256-128': 'sha-256',
    'hmac-sha1-96': 'sha1',
    'hmac-md5-96': 'md5',
  };
  const ipsecMap = {
    'sha256': 'hmac-sha-256-128',
    'sha-256': 'hmac-sha-256-128',
    'sha1': 'hmac-sha1-96',
    'sha-1': 'hmac-sha1-96',
    'sha384': 'hmac-sha-384',
    'sha-384': 'hmac-sha-384',
    'sha512': 'hmac-sha-512',
    'sha-512': 'hmac-sha-512',
    'md5': 'hmac-md5-96',
  };
  const map = context === 'ike' ? ikeMap : ipsecMap;
  return map[algo.toLowerCase()] || algo;
}

function convertVpnTunnels(tunnels, commands, warnings, summary, interfaceMappings = {}, identifiers, identifierPath) {
  if (!tunnels || tunnels.length === 0) return;

  commands.push('# =============================================');
  commands.push('# VPN / IPsec Configuration');
  commands.push('# =============================================');

  const emittedProposals = new Set();
  const emittedPolicies = new Set();
  const emittedGateways = new Set();
  // Bug 6/11 fix: Track emitted st0 interfaces to avoid duplicates
  const emittedTunnelInterfaces = new Set();

  // Bug 6/11 fix: Emit all required st0 tunnel interfaces BEFORE IPsec references.
  // vSRX commit check fails if bind-interface references an unconfigured st0 unit.
  for (const vpn of tunnels) {
    if (vpn.tunnel_interface) {
      const mappedTunnel = mapInterfaceName(vpn.tunnel_interface, interfaceMappings);
      const bindIf = mappedTunnel.startsWith('st0') ? mappedTunnel : 'st0.0';
      if (!emittedTunnelInterfaces.has(bindIf)) {
        emittedTunnelInterfaces.add(bindIf);
        const [stBase, stUnit = '0'] = bindIf.split('.');
        commands.push(`set interfaces ${stBase} unit ${stUnit} family inet`);
      }
    }
  }

  for (let vpnIndex = 0; vpnIndex < tunnels.length; vpnIndex += 1) {
    const vpn = tunnels[vpnIndex];
    const ownerPath = identifierPath(`vpn_tunnels[${vpnIndex}]`);
    const vpnName = vpn.name
      ? identifiers.nameForDefinition(`${ownerPath}.name`)
      : identifiers.nameForGenerated(ownerPath, 'ipsec-vpn');

    // Bug 7 fix: Determine the external interface for IKE gateway.
    // If the source vendor interface can't be mapped to a valid SRX interface,
    // skip the entire VPN config with a warning instead of emitting invalid config.
    let resolvedExtIf = null;
    if (vpn.ike_gateway?.external_interface) {
      const candidateIf = mapInterfaceName(
        vpn.ike_gateway.external_interface,
        interfaceMappings,
      );
      // Check if it's already a valid SRX interface name (e.g., ge-0/0/0.0)
      if (/^(ge|xe|et|ae|lo|irb|st|reth)-?\d/.test(candidateIf)) {
        resolvedExtIf = candidateIf.includes('.') ? candidateIf : `${candidateIf}.0`;
      }
    }
    if (!resolvedExtIf && vpn.ike_gateway?.local_address) {
      // local_address might be an IP, not an interface — use fallback
      const la = vpn.ike_gateway.local_address;
      const mappedLocal = mapInterfaceName(la, interfaceMappings);
      if (/^(ge|xe|et|ae|lo|irb|reth)-?\d/.test(mappedLocal)) {
        resolvedExtIf = mappedLocal.includes('.') ? mappedLocal : `${mappedLocal}.0`;
      }
      // If local_address is an IP address, we can't derive the interface — use ge-0/0/0.0 as default
      if (!resolvedExtIf && /^\d+\.\d+\.\d+\.\d+/.test(la)) {
        resolvedExtIf = 'ge-0/0/0.0';
        warnings.push(createWarning('warning', `vpn/${vpnName}`,
          `IKE gateway local-address "${la}" is an IP — using ge-0/0/0.0 as external-interface`,
          'Verify the correct external interface for this VPN tunnel'));
      }
    }
    if (!resolvedExtIf) {
      // No valid external interface found — skip VPN with warning
      warnings.push(createWarning('warning', `vpn/${vpnName}`,
        `VPN "${vpn.name}" skipped — external interface could not be determined from source config`,
        'Manually configure IKE gateway external-interface'));
      commands.push(`# WARNING: VPN "${vpn.name}" skipped — IKE gateway external-interface not resolvable`);
      continue;
    }

    // IKE Proposal
    const ikeProposal = vpn.ike_proposal || {};
    const propName = ikeProposal.name
      ? identifiers.nameForDefinition(`${ownerPath}.ike_proposal.name`)
      : identifiers.nameForGenerated(ownerPath, 'ike-proposal');
    if (!emittedProposals.has(`ike:${propName}`)) {
      emittedProposals.add(`ike:${propName}`);
      commands.push(`set security ike proposal ${propName} authentication-method ${ikeProposal.auth_method || 'pre-shared-keys'}`);
      commands.push(`set security ike proposal ${propName} dh-group ${ikeProposal.dh_group || 'group14'}`);
      commands.push(`set security ike proposal ${propName} encryption-algorithm ${ikeProposal.encryption || 'aes-256-cbc'}`);
      commands.push(`set security ike proposal ${propName} authentication-algorithm ${mapAuthAlgorithm(ikeProposal.authentication || 'sha-256', 'ike')}`);
      if (ikeProposal.lifetime) {
        commands.push(`set security ike proposal ${propName} lifetime-seconds ${ikeProposal.lifetime}`);
      }
    }

    // IKE Policy
    const polName = identifiers.nameForGenerated(ownerPath, 'ike-policy');
    if (!emittedPolicies.has(polName)) {
      emittedPolicies.add(polName);
      const propRef = identifiers.nameForReference(`${ownerPath}.ike_proposal.name`);
      commands.push(`set security ike policy ${polName} proposals ${propRef}`);
      commands.push(`set security ike policy ${polName} pre-shared-key ascii-text "CHANGE-ME"`);
    }

    // IKE Gateway
    const gwName = vpn.ike_gateway?.name
      ? identifiers.nameForDefinition(`${ownerPath}.ike_gateway.name`)
      : identifiers.nameForGenerated(ownerPath, 'ike-gateway');
    if (!emittedGateways.has(gwName)) {
      emittedGateways.add(gwName);
      if (vpn.ike_gateway?.address) {
        commands.push(`set security ike gateway ${gwName} address ${vpn.ike_gateway.address}`);
      }
      const policyRef = identifiers.nameForReference(`${ownerPath}.name#ike-policy`);
      commands.push(`set security ike gateway ${gwName} ike-policy ${policyRef}`);
      // Bug 7 fix: Use resolved external interface instead of raw vendor interface name
      commands.push(`set security ike gateway ${gwName} external-interface ${resolvedExtIf}`);
      if (vpn.ike_gateway?.ike_version === 'v2') {
        commands.push(`set security ike gateway ${gwName} version v2-only`);
      }
    }

    // IPsec Proposal
    const ipsecProposal = vpn.ipsec_proposal || {};
    const ipropName = ipsecProposal.name
      ? identifiers.nameForDefinition(`${ownerPath}.ipsec_proposal.name`)
      : identifiers.nameForGenerated(ownerPath, 'ipsec-proposal');
    if (!emittedProposals.has(`ipsec:${ipropName}`)) {
      emittedProposals.add(`ipsec:${ipropName}`);
      commands.push(`set security ipsec proposal ${ipropName} protocol ${ipsecProposal.protocol || 'esp'}`);
      commands.push(`set security ipsec proposal ${ipropName} encryption-algorithm ${ipsecProposal.encryption || 'aes-256-cbc'}`);
      commands.push(`set security ipsec proposal ${ipropName} authentication-algorithm ${mapAuthAlgorithm(ipsecProposal.authentication || 'hmac-sha-256-128')}`);
      if (ipsecProposal.lifetime) {
        commands.push(`set security ipsec proposal ${ipropName} lifetime-seconds ${ipsecProposal.lifetime}`);
      }
    }

    // IPsec Policy
    const ipsecPolName = identifiers.nameForGenerated(ownerPath, 'ipsec-policy');
    const ipropRef = identifiers.nameForReference(`${ownerPath}.ipsec_proposal.name`);
    commands.push(`set security ipsec policy ${ipsecPolName} proposals ${ipropRef}`);
    if (vpn.ipsec_proposal?.pfs_group) {
      commands.push(`set security ipsec policy ${ipsecPolName} perfect-forward-secrecy keys ${vpn.ipsec_proposal.pfs_group}`);
    }

    // IPsec VPN
    const gatewayRef = identifiers.nameForReference(`${ownerPath}.ike_gateway.name`);
    const ipsecPolicyRef = identifiers.nameForReference(`${ownerPath}.name#ipsec-policy`);
    commands.push(`set security ipsec vpn ${vpnName} ike gateway ${gatewayRef}`);
    commands.push(`set security ipsec vpn ${vpnName} ike ipsec-policy ${ipsecPolicyRef}`);
    if (vpn.tunnel_interface) {
      const mappedTunnel = mapInterfaceName(vpn.tunnel_interface, interfaceMappings);
      const bindIf = mappedTunnel.startsWith('st0') ? mappedTunnel : 'st0.0';
      commands.push(`set security ipsec vpn ${vpnName} bind-interface ${bindIf}`);
    }

    // Traffic selectors / Proxy IDs
    if (vpn.proxy_id && vpn.proxy_id.length > 0) {
      for (let i = 0; i < vpn.proxy_id.length; i++) {
        const pid = vpn.proxy_id[i];
        const selectorPath = `${ownerPath}.proxy_id[${i}]`;
        identifiers.nameForGenerated(selectorPath, 'vpn-traffic-selector');
        const tsName = identifiers.nameForReference(`${selectorPath}#traffic-selector`);
        if (pid.local) commands.push(`set security ipsec vpn ${vpnName} traffic-selector ${tsName} local-ip ${pid.local}`);
        if (pid.remote) commands.push(`set security ipsec vpn ${vpnName} traffic-selector ${tsName} remote-ip ${pid.remote}`);
      }
    }

    summary.vpn_tunnels_converted = (summary.vpn_tunnels_converted || 0) + 1;
  }

  commands.push('');
}

// ---------------------------------------------------------------------------
// Syslog Configuration Converter
// ---------------------------------------------------------------------------

function convertSyslogConfig(syslogConfig, commands, warnings, summary) {
  if (!syslogConfig || syslogConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Syslog / Logging Configuration');
  commands.push('# =============================================');

  for (const srv of syslogConfig) {
    if (!srv.server || srv.transport === 'file') continue;

    const host = srv.server;
    commands.push(`set system syslog host ${host} any any`);

    if (srv.port && srv.port !== 514) {
      commands.push(`set system syslog host ${host} port ${srv.port}`);
    }

    if (srv.transport === 'tcp' || srv.transport === 'tls') {
      commands.push(`set system syslog host ${host} transport protocol tcp`);
    }

    if (srv.source_address) {
      commands.push(`set system syslog host ${host} source-address ${srv.source_address}`);
    }

    if (srv.structured_data) {
      commands.push(`set system syslog host ${host} structured-data`);
    }

    // Facility-specific entries
    if (srv.facilities && srv.facilities.length > 0) {
      for (const fac of srv.facilities) {
        commands.push(`set system syslog host ${host} ${fac.facility} ${fac.level}`);
      }
    }

    summary.syslog_servers_converted = (summary.syslog_servers_converted || 0) + 1;
  }

  commands.push('');
}


// ---------------------------------------------------------------------------
// AAA Configuration Converter
// ---------------------------------------------------------------------------

function convertAaaConfig(aaaConfig, commands, warnings, summary, identifiers, identifierPath) {
  if (!aaaConfig || aaaConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# AAA / Authentication Configuration');
  commands.push('# =============================================');

  let radiusCount = 0;
  let tacplusCount = 0;
  let profileCount = 0;

  for (let entryIndex = 0; entryIndex < aaaConfig.length; entryIndex += 1) {
    const entry = aaaConfig[entryIndex];
    if (entry.type === 'radius') {
      if (!entry.server) continue;
      commands.push(`set system radius-server ${entry.server} port ${entry.port || 1812}`);
      if (entry.secret) {
        // njsscan node_secret: false positive. Junos CLI keyword in *generated* config, not a stored credential; value is sanitized by setQuoted().
        commands.push(`set system radius-server ${entry.server} secret ${setQuoted(entry.secret, 'aaa_config.radius.secret')}`);  // njsscan-ignore: node_secret
      } else {
        commands.push(`# set system radius-server ${entry.server} secret "<SHARED-SECRET>" /* requires manual configuration */`);
      }
      if (entry.timeout) {
        commands.push(`set system radius-server ${entry.server} timeout ${entry.timeout}`);
      }
      if (entry.retry) {
        commands.push(`set system radius-server ${entry.server} retry ${entry.retry}`);
      }
      if (entry.source_address) {
        commands.push(`set system radius-server ${entry.server} source-address ${entry.source_address}`);
      }
      radiusCount++;
    }

    if (entry.type === 'tacplus') {
      if (!entry.server) continue;
      commands.push(`set system tacplus-server ${entry.server} port ${entry.port || 49}`);
      if (entry.secret) {
        // njsscan node_secret: false positive. Junos CLI keyword in *generated* config, not a stored credential; value is sanitized by setQuoted().
        commands.push(`set system tacplus-server ${entry.server} secret ${setQuoted(entry.secret, 'aaa_config.tacacs.secret')}`);  // njsscan-ignore: node_secret
      } else {
        commands.push(`# set system tacplus-server ${entry.server} secret "<SHARED-SECRET>" /* requires manual configuration */`);
      }
      if (entry.timeout) {
        commands.push(`set system tacplus-server ${entry.server} timeout ${entry.timeout}`);
      }
      if (entry.single_connection) {
        commands.push(`set system tacplus-server ${entry.server} single-connection`);
      }
      if (entry.source_address) {
        commands.push(`set system tacplus-server ${entry.server} source-address ${entry.source_address}`);
      }
      tacplusCount++;
    }

    if (entry.type === 'ldap') {
      // SRX uses LDAP via access profile, emit as comments for manual configuration
      commands.push(`# LDAP server: ${entry.server}:${entry.port || 389} (base-dn: ${entry.base_dn || 'N/A'})`);
      commands.push(`# Configure via: set access profile <name> ldap-server ${entry.server}`);
    }

    if (entry.type === 'profile') {
      const profileName = identifiers.nameForDefinition(
        identifierPath(`aaa_config[${entryIndex}].name`),
      );
      if (entry.authentication_order && entry.authentication_order.length > 0) {
        for (const method of entry.authentication_order) {
          const normalized = method.toLowerCase().includes('tacacs') ? 'tacplus' :
                            method.toLowerCase().includes('radius') ? 'radius' :
                            method.toLowerCase().includes('ldap') ? 'ldap' :
                            method.toLowerCase() === 'password' ? 'password' : method;
          commands.push(`set access profile ${profileName} authentication-order ${normalized}`);
        }
      }
      profileCount++;
    }

    if (entry.type === 'auth-order') {
      if (entry.authentication_order && entry.authentication_order.length > 0) {
        for (const method of entry.authentication_order) {
          commands.push(`set system authentication-order ${method}`);
        }
      }
    }
  }

  // Add note about shared secrets
  if (radiusCount > 0 || tacplusCount > 0) {
    commands.push('# NOTE: Shared secrets are sanitized. Verify and replace before deployment.');
  }

  summary.aaa_radius_servers_converted = radiusCount;
  summary.aaa_tacplus_servers_converted = tacplusCount;
  summary.aaa_profiles_converted = profileCount;

  commands.push('');
}


// ---------------------------------------------------------------------------
// SNMP Configuration Converter
// ---------------------------------------------------------------------------

function convertSnmpConfig(snmpConfig, commands, warnings, summary, identifiers, identifierPath) {
  if (!snmpConfig || snmpConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# SNMP Configuration');
  commands.push('# =============================================');

  let communityCount = 0;
  let trapGroupCount = 0;

  // Emit contact/location from first entry that has them
  const contactEntry = snmpConfig.find(e => e.contact);
  const locationEntry = snmpConfig.find(e => e.location);
  if (contactEntry?.contact) {
    commands.push(`set snmp contact ${setQuoted(contactEntry.contact, 'snmp_config.contact')}`);
  }
  if (locationEntry?.location) {
    commands.push(`set snmp location ${setQuoted(locationEntry.location, 'snmp_config.location')}`);
  }

  for (let entryIndex = 0; entryIndex < snmpConfig.length; entryIndex += 1) {
    const entry = snmpConfig[entryIndex];
    const plannedName = ['community', 'trap-group', 'v3-user'].includes(entry.type)
      ? identifiers.nameForDefinition(identifierPath(`snmp_config[${entryIndex}].name`))
      : null;
    if (entry.type === 'community') {
      const auth = entry.authorization === 'read-write' ? 'read-write' : 'read-only';
      commands.push(`set snmp community ${plannedName} authorization ${auth}`);

      // Restrict to specific clients if configured
      if (entry.clients && entry.clients.length > 0) {
        for (const client of entry.clients) {
          commands.push(`set snmp community ${plannedName} clients ${client}`);
        }
      }
      communityCount++;
    }

    if (entry.type === 'trap-group') {
      const groupName = plannedName;
      if (entry.version) {
        commands.push(`set snmp trap-group ${groupName} version ${entry.version}`);
      }
      for (const target of (entry.targets || [])) {
        commands.push(`set snmp trap-group ${groupName} targets ${target}`);
      }
      for (const cat of (entry.categories || [])) {
        commands.push(`set snmp trap-group ${groupName} categories ${cat}`);
      }
      trapGroupCount++;
    }

    if (entry.type === 'v3-user') {
      const VALID_AUTH = ['md5', 'sha'];
      const VALID_PRIV = ['des', 'aes128'];
      const userName = plannedName;
      commands.push(`set snmp v3 usm local-engine user ${userName}`);
      if (entry.auth_protocol && entry.auth_protocol !== 'none' && VALID_AUTH.includes(entry.auth_protocol)) {
        commands.push(`set snmp v3 usm local-engine user ${userName} authentication-${entry.auth_protocol}`);
      }
      if (entry.privacy_protocol && entry.privacy_protocol !== 'none' && VALID_PRIV.includes(entry.privacy_protocol)) {
        commands.push(`set snmp v3 usm local-engine user ${userName} privacy-${entry.privacy_protocol}`);
      }
    }
  }

  summary.snmp_communities_converted = communityCount;
  summary.snmp_trap_groups_converted = trapGroupCount;

  commands.push('');
}


// ---------------------------------------------------------------------------
// DHCP Configuration Converter
// ---------------------------------------------------------------------------

function convertDhcpConfig(dhcpConfig, commands, warnings, summary, interfaceMappings = {}, identifiers, identifierPath) {
  if (!dhcpConfig || dhcpConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# DHCP Configuration');
  commands.push('# =============================================');

  for (let configIndex = 0; configIndex < dhcpConfig.length; configIndex += 1) {
    const cfg = dhcpConfig[configIndex];
    if (cfg.type === 'relay') {
      // DHCP Relay: set forwarding-options helpers bootp interface <if> server <ip>
      const iface = mapInterfaceName(cfg.interface || 'ge-0/0/0.0', interfaceMappings);
      const servers = cfg.servers || [];
      for (const srv of servers) {
        commands.push(`set forwarding-options helpers bootp interface ${iface} server ${srv}`);
      }
      summary.dhcp_configs_converted = (summary.dhcp_configs_converted || 0) + 1;
    } else if (cfg.type === 'server' || cfg.type === 'pool') {
      // DHCP Server pool
      const ownerPath = identifierPath(`dhcp_config[${configIndex}]`);
      const poolName = cfg.name
        ? identifiers.nameForDefinition(`${ownerPath}.name`)
        : identifiers.nameForGenerated(ownerPath, 'dhcp-pool');

      // Fix 1: DHCP pool requires a network statement — skip pool entirely if missing
      const dhcpNetwork = cfg.network || cfg.subnet;
      if (!dhcpNetwork) {
        commands.push(`# WARNING: DHCP pool "${cfg.name || poolName}" skipped — no network/subnet defined (mandatory for SRX)`);
        warnings.push(createWarning('warning', `dhcp/${poolName}`,
          `DHCP pool "${cfg.name || poolName}" has no network statement — skipped`,
          'Add a network statement (e.g., 192.168.1.0/24) to the DHCP pool configuration'));
        continue;
      }

      // Emit network statement first (mandatory)
      commands.push(`set access address-assignment pool ${poolName} family inet network ${dhcpNetwork}`);

      if (cfg.pools) {
        const emittedRanges = cfg.pools
          .map((pool, rangeIndex) => ({ pool, rangeIndex }))
          .filter(({ pool }) => (
            typeof pool === 'string'
            && pool.split('-').length === 2
            && pool.split('-').every(part => part.trim().length > 0)
          ))
          .sort((left, right) => String(left.pool).localeCompare(String(right.pool)));
        for (const { pool, rangeIndex } of emittedRanges) {
          if (pool.includes('-')) {
            const [low, high] = pool.split('-');
            const rangeName = identifiers.nameForGenerated(
              identifierPath(`dhcp_config[${configIndex}].pools[${rangeIndex}]`),
              'dhcp-pool-range',
            );
            commands.push(`set access address-assignment pool ${poolName} family inet range ${rangeName} low ${low}`);
            commands.push(`set access address-assignment pool ${poolName} family inet range ${rangeName} high ${high}`);
          }
        }
      }

      if (cfg.ranges) {
        for (let rangeIndex = 0; rangeIndex < cfg.ranges.length; rangeIndex += 1) {
          const range = cfg.ranges[rangeIndex];
          const rangePath = identifierPath(`dhcp_config[${configIndex}].ranges[${rangeIndex}]`);
          const rName = range.name
            ? identifiers.nameForDefinition(`${rangePath}.name`)
            : identifiers.nameForGenerated(rangePath, 'dhcp-named-range');
          if (range.low) commands.push(`set access address-assignment pool ${poolName} family inet range ${rName} low ${range.low}`);
          if (range.high) commands.push(`set access address-assignment pool ${poolName} family inet range ${rName} high ${range.high}`);
        }
      }

      if (cfg.gateway || cfg.router) {
        commands.push(`set access address-assignment pool ${poolName} family inet dhcp-attributes router ${cfg.gateway || cfg.router}`);
      }

      const dnsServers = cfg.dns_servers || [];
      for (const dns of dnsServers) {
        commands.push(`set access address-assignment pool ${poolName} family inet dhcp-attributes name-server ${dns}`);
      }

      if (cfg.lease_time && cfg.lease_time !== 86400) {
        commands.push(`set access address-assignment pool ${poolName} family inet dhcp-attributes maximum-lease-time ${cfg.lease_time}`);
      }

      if (cfg.interfaces || cfg.interface) {
        const ifList = cfg.interfaces || [cfg.interface];
        for (const iface of ifList.filter(Boolean)) {
          const mappedInterface = mapInterfaceName(iface, interfaceMappings);
          commands.push(`set system services dhcp-local-server group ${poolName} interface ${mappedInterface}`);
        }
      }

      summary.dhcp_configs_converted = (summary.dhcp_configs_converted || 0) + 1;
    }
  }

  commands.push('');
}


// ---------------------------------------------------------------------------
// QoS / CoS Configuration Converter
// ---------------------------------------------------------------------------

function convertQosConfig(qosConfig, commands, warnings, summary, interfaceMappings = {}, identifiers, identifierPath) {
  if (!qosConfig || qosConfig.length === 0) return;

  commands.push('# =============================================');
  commands.push('# QoS / Class-of-Service Configuration');
  commands.push('# =============================================');

  for (let qosIndex = 0; qosIndex < qosConfig.length; qosIndex += 1) {
    const qos = qosConfig[qosIndex];
    const qosPath = identifierPath(`qos_config[${qosIndex}]`);
    if (qos.type === 'scheduler') {
      // SRX CoS scheduler
      const name = identifiers.nameForDefinition(`${qosPath}.name`);
      if (qos.transmit_rate) commands.push(`set class-of-service schedulers ${name} transmit-rate ${qos.transmit_rate}`);
      if (qos.buffer_size) commands.push(`set class-of-service schedulers ${name} buffer-size ${qos.buffer_size}`);
      if (qos.priority) commands.push(`set class-of-service schedulers ${name} priority ${qos.priority}`);
      summary.qos_configs_converted = (summary.qos_configs_converted || 0) + 1;
    } else if (qos.type === 'interface-cos') {
      // Interface CoS binding
      const ifName = mapInterfaceName(qos.interface || 'ge-0/0/0', interfaceMappings);
      if (qos.scheduler_map) {
        const schedulerMap = identifiers.nameForReference(`${qosPath}.scheduler_map`);
        commands.push(`set class-of-service interfaces ${ifName} scheduler-map ${schedulerMap}`);
      }
      if (qos.shaping_rate) commands.push(`set class-of-service interfaces ${ifName} shaping-rate ${qos.shaping_rate}`);
      summary.qos_configs_converted = (summary.qos_configs_converted || 0) + 1;
    } else if (qos.type === 'shaping-profile' || qos.type === 'policy-map') {
      // Generic QoS from FortiGate/Cisco — map to CoS scheduler-map
      const name = identifiers.nameForDefinition(`${qosPath}.name`);
      const classes = qos.classes || [];
      if (classes.length > 0) {
        commands.push(`set class-of-service scheduler-maps ${name}`);
        for (let classIndex = 0; classIndex < classes.length; classIndex += 1) {
          const cls = classes[classIndex];
          const classPath = `${qosPath}.classes[${classIndex}]`;
          const clsName = cls.name
            ? identifiers.nameForDefinition(`${classPath}.name`)
            : identifiers.nameForGenerated(classPath, 'qos-default-scheduler');
          const forwardingClass = cls.name
            ? identifiers.nameForDefinition(`${classPath}.name#forwarding-class`)
            : identifiers.nameForGenerated(classPath, 'qos-default-forwarding-class');
          if (cls.guaranteed_bandwidth) {
            commands.push(`set class-of-service schedulers ${clsName} transmit-rate percent ${cls.guaranteed_bandwidth}`);
          }
          if (cls.maximum_bandwidth) {
            commands.push(`set class-of-service schedulers ${clsName} transmit-rate percent ${cls.maximum_bandwidth} exact`);
          }
          if (cls.priority === true || cls.priority === 'high') {
            commands.push(`set class-of-service schedulers ${clsName} priority high`);
          }
          if (cls.police_rate) {
            commands.push(`set class-of-service schedulers ${clsName} transmit-rate ${cls.police_rate}`);
          }
          commands.push(`set class-of-service scheduler-maps ${name} forwarding-class ${forwardingClass} scheduler ${clsName}`);
        }
      }
      if (qos.interface) {
        const ifName = mapInterfaceName(qos.interface, interfaceMappings);
        commands.push(`set class-of-service interfaces ${ifName} scheduler-map ${name}`);
      }
      summary.qos_configs_converted = (summary.qos_configs_converted || 0) + 1;
    } else {
      // Max bandwidth style (PAN-OS)
      const name = identifiers.nameForDefinition(`${qosPath}.name`);
      if (qos.max_bandwidth) {
        commands.push(`# QoS profile "${qos.name}" — max-bandwidth: ${qos.max_bandwidth}`);
        commands.push(`set class-of-service scheduler-maps ${name}`);
      }
      const classes = qos.classes || [];
      for (let classIndex = 0; classIndex < classes.length; classIndex += 1) {
        const cls = classes[classIndex];
        const classPath = `${qosPath}.classes[${classIndex}]`;
        const clsName = cls.name
          ? identifiers.nameForDefinition(`${classPath}.name`)
          : identifiers.nameForGenerated(classPath, 'qos-default-scheduler');
        const forwardingClass = cls.name
          ? identifiers.nameForDefinition(`${classPath}.name#forwarding-class`)
          : identifiers.nameForGenerated(classPath, 'qos-default-forwarding-class');
        if (cls.guaranteed_bandwidth) {
          commands.push(`set class-of-service schedulers ${clsName} transmit-rate ${cls.guaranteed_bandwidth}`);
        }
        if (cls.maximum_bandwidth) {
          commands.push(`set class-of-service schedulers ${clsName} transmit-rate ${cls.maximum_bandwidth}`);
        }
        if (cls.priority) {
          commands.push(`set class-of-service schedulers ${clsName} priority ${cls.priority}`);
        }
        commands.push(`set class-of-service scheduler-maps ${name} forwarding-class ${forwardingClass} scheduler ${clsName}`);
      }
      summary.qos_configs_converted = (summary.qos_configs_converted || 0) + 1;
    }
  }

  commands.push('');
}


// ---------------------------------------------------------------------------
// L2 / Bridge Domain / Virtual-Wire Configuration
// ---------------------------------------------------------------------------

/**
 * Generates SRX bridge-domain and L2 interface (family bridge) commands.
 *
 * Maps:
 *   - bridge_domains → set bridge-domains <name> domain-type bridge, vlan-id, routing-interface
 *   - l2_interfaces → set interfaces <base> unit <n> family bridge [bridge-domain-name] [vlan-id]
 *   - vwire_pairs → bridge-domain mapping with TODO comments (SRX has no direct vwire equivalent)
 */
function convertL2Config(config, commands, warnings, summary, interfaceMappings = {}, identifiers, identifierPath) {
  const bridgeDomains = config.bridge_domains || [];
  const l2Interfaces = config.l2_interfaces || [];
  const vwirePairs = config.vwire_pairs || [];
  const transparentMode = config.transparent_mode || false;

  if (bridgeDomains.length === 0 && l2Interfaces.length === 0 && vwirePairs.length === 0 && !transparentMode) {
    return;
  }

  commands.push('# =============================================');
  commands.push('# L2 / Bridge Domain Configuration');
  commands.push('# =============================================');

  if (transparentMode) {
    commands.push('# Source firewall was in transparent/L2 mode');
    commands.push('# SRX equivalent: bridge-domains with family bridge interfaces');
    commands.push('');
  }

  // Bridge domains
  for (let bridgeIndex = 0; bridgeIndex < bridgeDomains.length; bridgeIndex += 1) {
    const bd = bridgeDomains[bridgeIndex];
    const bdName = identifiers.nameForDefinition(
      identifierPath(`bridge_domains[${bridgeIndex}].name`),
    );
    commands.push(`set bridge-domains ${bdName} domain-type bridge`);
    if (bd.vlan_id) {
      commands.push(`set bridge-domains ${bdName} vlan-id ${bd.vlan_id}`);
    }
    if (bd.irb_interface) {
      const routingInterface = mapInterfaceName(bd.irb_interface, interfaceMappings);
      commands.push(`set bridge-domains ${bdName} routing-interface ${routingInterface}`);
    }
    summary.bridge_domains_converted = (summary.bridge_domains_converted || 0) + 1;
  }

  if (bridgeDomains.length > 0) commands.push('');

  // L2 interfaces — set family bridge
  for (let interfaceIndex = 0; interfaceIndex < l2Interfaces.length; interfaceIndex += 1) {
    const l2if = l2Interfaces[interfaceIndex];
    const mappedName = mapInterfaceName(l2if.name, interfaceMappings);
    const parts = mappedName.match(/^(.+?)\.(\d+)$/);
    if (parts) {
      const [, base, unit] = parts;
      commands.push(`set interfaces ${base} unit ${unit} family bridge`);
      if (l2if.bridge_domain) {
        const bridgeDomain = identifiers.nameForReference(
          identifierPath(`l2_interfaces[${interfaceIndex}].bridge_domain`),
        );
        commands.push(`set interfaces ${base} unit ${unit} family bridge bridge-domain-name ${bridgeDomain}`);
      }
      if (l2if.vlan) {
        commands.push(`set interfaces ${base} unit ${unit} vlan-id ${l2if.vlan}`);
      }
    } else {
      // No unit specified — default to unit 0
      const base = mappedName;
      commands.push(`set interfaces ${base} unit 0 family bridge`);
      if (l2if.bridge_domain) {
        const bridgeDomain = identifiers.nameForReference(
          identifierPath(`l2_interfaces[${interfaceIndex}].bridge_domain`),
        );
        commands.push(`set interfaces ${base} unit 0 family bridge bridge-domain-name ${bridgeDomain}`);
      }
    }
    summary.l2_interfaces_converted = (summary.l2_interfaces_converted || 0) + 1;
  }

  if (l2Interfaces.length > 0) commands.push('');

  // Virtual-wire pairs — SRX has no direct equivalent; map to bridge-domain
  for (let vwireIndex = 0; vwireIndex < vwirePairs.length; vwireIndex += 1) {
    const vw = vwirePairs[vwireIndex];
    const bdName = identifiers.nameForGenerated(
      identifierPath(`vwire_pairs[${vwireIndex}]`),
      'vwire-bridge-domain',
    );
    commands.push(`# Virtual-wire pair "${vw.name}": ${vw.interface1} <-> ${vw.interface2}`);
    commands.push(`set bridge-domains ${bdName} domain-type bridge`);

    // Resolve mapped SRX interfaces
    const srxIf1 = mapInterfaceName(vw.interface1, interfaceMappings);
    const srxIf2 = mapInterfaceName(vw.interface2, interfaceMappings);
    const resolved1 = srxIf1 !== (vw.interface1.includes('.') ? vw.interface1 : `${vw.interface1}.0`);
    const resolved2 = srxIf2 !== (vw.interface2.includes('.') ? vw.interface2 : `${vw.interface2}.0`);

    if (vw.tag_allowed && vw.tag_allowed.length > 1) {
      // Multiple VLANs — trunk mode
      commands.push(`set bridge-domains ${bdName} vlan-id-list ${vw.tag_allowed.join(' ')}`);
      if (resolved1) {
        const [base1, unit1] = srxIf1.split('.');
        commands.push(`set interfaces ${base1} unit ${unit1 || 0} family bridge interface-mode trunk`);
        commands.push(`set interfaces ${base1} unit ${unit1 || 0} family bridge vlan-id-list ${vw.tag_allowed.join(' ')}`);
      }
      if (resolved2) {
        const [base2, unit2] = srxIf2.split('.');
        commands.push(`set interfaces ${base2} unit ${unit2 || 0} family bridge interface-mode trunk`);
        commands.push(`set interfaces ${base2} unit ${unit2 || 0} family bridge vlan-id-list ${vw.tag_allowed.join(' ')}`);
      }
    } else {
      // Single or no VLAN — access mode with bridge-domain-name
      if (vw.tag_allowed && vw.tag_allowed.length === 1 && vw.tag_allowed[0] !== '0') {
        commands.push(`set bridge-domains ${bdName} vlan-id ${vw.tag_allowed[0]}`);
      }
      if (resolved1) {
        const [base1, unit1] = srxIf1.split('.');
        commands.push(`set interfaces ${base1} unit ${unit1 || 0} family bridge bridge-domain-name ${bdName}`);
      }
      if (resolved2) {
        const [base2, unit2] = srxIf2.split('.');
        commands.push(`set interfaces ${base2} unit ${unit2 || 0} family bridge bridge-domain-name ${bdName}`);
      }
    }

    if (resolved1 && resolved2) {
      warnings.push(createWarning(
        'info', `l2/vwire/${vw.name}`,
        `Virtual-wire pair "${vw.name}" mapped to bridge-domain ${bdName} with interfaces ${srxIf1} and ${srxIf2}`,
        'Verify bridge-domain configuration after deployment'
      ));
    } else {
      const unresolved = [];
      if (!resolved1) unresolved.push(vw.interface1);
      if (!resolved2) unresolved.push(vw.interface2);
      commands.push(`# NOTE: Could not resolve interface(s): ${unresolved.join(', ')} — map them in Interface Mapper`);
      warnings.push(createWarning(
        'warning', `l2/vwire/${vw.name}`,
        `Virtual-wire pair "${vw.name}": interface(s) ${unresolved.join(', ')} not mapped — assign in Interface Mapper`,
        'Open Interface Mapper and assign SRX ports for the unmapped interfaces'
      ));
    }
    commands.push('');

    summary.vwire_pairs_converted = (summary.vwire_pairs_converted || 0) + 1;
  }

  commands.push('');
}


// ---------------------------------------------------------------------------
// Policy-Based Forwarding → Filter-Based Forwarding
// ---------------------------------------------------------------------------

function isIpOrPrefixLiteral(value) {
  if (typeof value !== 'string') return false;
  return /^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,3})?$/.test(value)
    || (value.includes(':') && /^[0-9A-Fa-f:.]+(?:\/\d{1,3})?$/.test(value));
}

function pbfAddressFamily(value) {
  return String(value).includes(':') ? 'inet6' : 'inet';
}

/**
 * Converts PBF rules to SRX filter-based forwarding configuration.
 *
 * For each PBF "forward" rule with a next-hop:
 *   1. Creates a routing-instance of type forwarding with a default route to the next-hop
 *   2. Creates a firewall filter term matching the rule's criteria
 *   3. Binds the filter to the from-interface(s)
 *
 * Discard rules → firewall filter term with "then discard"
 * No-PBF rules → firewall filter term with "then accept" (default routing)
 */
function convertPbfConfig(pbfRules, commands, warnings, summary, interfaceMappings = {}, addressObjects = [], identifiers, identifierPath) {
  if (!pbfRules || pbfRules.length === 0) return;
  if (!pbfRules.some(rule => !rule.disabled)) return;

  // Build lookup map from address object names to their IP values
  const addrLookup = new Map();
  for (let objectIndex = 0; objectIndex < (addressObjects || []).length; objectIndex += 1) {
    const obj = addressObjects[objectIndex];
    const addrVal = obj.value || obj.ip || obj.network || obj.subnet || obj.address;
    if (obj.name && addrVal && ['host', 'subnet', 'network', 'ip-netmask', 'ip-prefix'].includes(obj.type)) {
      addrLookup.set(obj.name, addrVal);
      addrLookup.set(
        identifiers.nameForDefinition(identifierPath(`address_objects[${objectIndex}].name`)),
        addrVal,
      );
    }
  }

  commands.push('# =============================================');
  commands.push('# Policy-Based Forwarding (Filter-Based Forwarding)');
  commands.push('# =============================================');

  // 1. Collect unique forwarding routing-instances per next-hop
  const candidatesByNextHop = new Map();
  for (let ruleIndex = 0; ruleIndex < pbfRules.length; ruleIndex += 1) {
    const rule = pbfRules[ruleIndex];
    if (rule.disabled || rule.action !== 'forward' || !rule.next_hop_value) continue;
    const candidates = candidatesByNextHop.get(rule.next_hop_value) || [];
    candidates.push({ rule, ruleIndex });
    candidatesByNextHop.set(rule.next_hop_value, candidates);
  }
  const instances = new Map(); // next-hop → planned instance name
  for (const [nextHop, candidates] of candidatesByNextHop) {
    const canonical = [...candidates].sort((left, right) => (
      String(left.rule.name).localeCompare(String(right.rule.name))
    ))[0];
    instances.set(nextHop, identifiers.nameForGenerated(
      identifierPath(`pbf_rules[${canonical.ruleIndex}]`),
      'pbf-routing-instance',
    ));
  }

  // Emit routing instances
  for (const [nextHop, instName] of instances) {
    commands.push(`set routing-instances ${instName} instance-type forwarding`);
    // Determine IPv4 vs IPv6 default route
    const defaultRoute = nextHop.includes(':') ? '::/0' : '0.0.0.0/0';
    commands.push(`set routing-instances ${instName} routing-options static route ${defaultRoute} next-hop ${nextHop}`);
  }
  if (instances.size > 0) commands.push('');

  // 2. Build firewall filter terms
  const filterName = identifiers.nameForGenerated(identifierPath('pbf_rules'), 'pbf-filter');
  const filterInterfaces = new Map();
  const usedFamilies = new Set();
  let termCount = 0;

  for (let ruleIndex = 0; ruleIndex < pbfRules.length; ruleIndex += 1) {
    const rule = pbfRules[ruleIndex];
    if (rule.disabled) continue;
    const termName = identifiers.nameForDefinition(
      identifierPath(`pbf_rules[${ruleIndex}].name`),
    );
    const matchedValues = [
      ...(rule.src_addresses || []),
      ...(rule.dst_addresses || []),
    ].filter(value => value !== 'any').map(value => (
      isIpOrPrefixLiteral(value) ? value : addrLookup.get(value)
    )).filter(Boolean);
    const familyValues = [...matchedValues];
    if (
      rule.action === 'forward'
      && rule.next_hop_value
      && isIpOrPrefixLiteral(rule.next_hop_value)
    ) {
      familyValues.push(rule.next_hop_value);
    }
    const family = familyValues.length > 0 ? pbfAddressFamily(familyValues[0]) : 'inet';
    usedFamilies.add(family);
    const termBase = `set firewall family ${family} filter ${filterName} term ${termName}`;

    // Match: source addresses (resolve named objects to IP values for firewall filters)
    for (let addressIndex = 0; addressIndex < (rule.src_addresses || []).length; addressIndex += 1) {
      const src = rule.src_addresses[addressIndex];
      if (src === 'any') continue;
      if (isIpOrPrefixLiteral(src)) {
        commands.push(`${termBase} from source-address ${src}`);
      } else {
        const plannedAddress = identifiers.nameForReference(
          identifierPath(`pbf_rules[${ruleIndex}].src_addresses[${addressIndex}]`),
        );
        if (addrLookup.has(src)) {
          commands.push(`${termBase} from source-address ${addrLookup.get(src)}`);
        } else if (addrLookup.has(plannedAddress)) {
          commands.push(`${termBase} from source-address ${addrLookup.get(plannedAddress)}`);
        } else {
          commands.push(`# WARNING: skipping source-address "${src}" — named object not resolvable to IP for firewall filter`);
          warnings.push(createWarning('warning', `pbf/${rule.name}`,
            `PBF filter term "${rule.name}" references named address "${src}" which could not be resolved to an IP`,
            'Firewall filters require raw IP addresses — add the address manually'));
        }
      }
    }
    // Match: destination addresses (resolve named objects to IP values for firewall filters)
    for (let addressIndex = 0; addressIndex < (rule.dst_addresses || []).length; addressIndex += 1) {
      const dst = rule.dst_addresses[addressIndex];
      if (dst === 'any') continue;
      if (isIpOrPrefixLiteral(dst)) {
        commands.push(`${termBase} from destination-address ${dst}`);
      } else {
        const plannedAddress = identifiers.nameForReference(
          identifierPath(`pbf_rules[${ruleIndex}].dst_addresses[${addressIndex}]`),
        );
        if (addrLookup.has(dst)) {
          commands.push(`${termBase} from destination-address ${addrLookup.get(dst)}`);
        } else if (addrLookup.has(plannedAddress)) {
          commands.push(`${termBase} from destination-address ${addrLookup.get(plannedAddress)}`);
        } else {
          commands.push(`# WARNING: skipping destination-address "${dst}" — named object not resolvable to IP for firewall filter`);
          warnings.push(createWarning('warning', `pbf/${rule.name}`,
            `PBF filter term "${rule.name}" references named address "${dst}" which could not be resolved to an IP`,
            'Firewall filters require raw IP addresses — add the address manually'));
        }
      }
    }
    // Match: applications/services (map to protocol/port if possible)
    for (const svc of (rule.services || []).filter(s => s !== 'any' && s !== 'application-default')) {
      const m = svc.match(/^(tcp|udp)\/(\d+)(?:-(\d+))?$/i);
      if (m) {
        commands.push(`${termBase} from protocol ${m[1].toLowerCase()}`);
        commands.push(`${termBase} from destination-port ${m[3] ? `${m[2]}-${m[3]}` : m[2]}`);
      }
    }

    // Action
    if (rule.action === 'forward' && rule.next_hop_value) {
      const instName = identifiers.nameForReference(
        identifierPath(`pbf_rules[${ruleIndex}].next_hop_value#routing-instance`),
      );
      commands.push(`${termBase} then routing-instance ${instName}`);
    } else if (rule.action === 'discard') {
      commands.push(`${termBase} then discard`);
    } else {
      // no-pbf or forward-to-vsys → accept (use default routing)
      commands.push(`${termBase} then accept`);
    }

    // Track from-interfaces for filter binding
    if (rule.from_type === 'interface') {
      for (const iface of (rule.from_value || [])) {
        const srxIface = mapInterfaceName(iface, interfaceMappings);
        const interfaces = filterInterfaces.get(family) || new Set();
        interfaces.add(srxIface);
        filterInterfaces.set(family, interfaces);
      }
    }

    // Forward-to-vsys → warning (no direct SRX equivalent)
    if (rule.action === 'forward-to-vsys') {
      warnings.push(createWarning(
        'warning', `pbf/${rule.name}`,
        `PBF rule "${rule.name}" forwards to vsys "${rule.forward_vsys}" — SRX cross-logical-system routing requires manual lt- interface config`,
        'Configure lt- tunnel interfaces between logical-systems for cross-LS forwarding'
      ));
    }

    termCount++;
  }

  // Default accept term (allow unmatched traffic to use default routing)
  if (termCount > 0) {
    const defaultTerm = identifiers.nameForGenerated(
      identifierPath('pbf_rules'),
      'pbf-default-term',
    );
    for (const family of usedFamilies) {
      commands.push(`set firewall family ${family} filter ${filterName} term ${defaultTerm} then accept`);
    }
    commands.push('');
  }

  // 3. Bind filter to from-interfaces
  for (const [family, interfaces] of filterInterfaces) {
    for (const iface of interfaces) {
      const [base, unit = '0'] = iface.split('.');
      commands.push(`set interfaces ${base} unit ${unit} family ${family} filter input ${filterName}`);
    }
  }

  if (filterInterfaces.size > 0) commands.push('');

  summary.pbf_rules_converted = termCount;
  summary.pbf_routing_instances = instances.size;
}


// ---------------------------------------------------------------------------
// SSL Proxy / PKI Configuration
// ---------------------------------------------------------------------------

/**
 * Generates SRX SSL proxy profiles and PKI configuration from decryption rules.
 *
 * For ssl-forward-proxy rules → root-ca based profile
 * For ssl-inbound-inspection → server-certificate based profile
 * Also generates PKI ca-profile placeholders and no-decrypt exclusion notes.
 */
function convertSslProxyConfig(config, commands, warnings, summary, identifiers, identifierPath) {
  const decryptionRules = config.decryption_rules || [];
  const fallbackDecryptPolicies = (config.security_policies || [])
    .map((policy, index) => ({ policy, index }))
    .filter(({ policy }) => (
      policy._srx_decrypt && policy.action === 'allow' && !policy._srx_decrypt_profile
    ));
  const hasDecryptPolicies = fallbackDecryptPolicies.length > 0;
  const hasDecryptRules = decryptionRules.some(r => (
    !r.disabled && ['decrypt', 'decrypt-and-forward'].includes(r.action)
  ));

  if (decryptionRules.length === 0 && !hasDecryptPolicies) return;

  if (!hasDecryptRules && !hasDecryptPolicies) {
    // Only no-decrypt rules — no SSL proxy needed, just note it
    commands.push('# =============================================');
    commands.push('# SSL/TLS Decryption — All rules are no-decrypt');
    commands.push('# No SSL Proxy configuration required');
    commands.push('# =============================================');
    commands.push('');
    return;
  }

  commands.push('# =============================================');
  commands.push('# SSL Proxy / PKI Configuration');
  commands.push('# =============================================');

  // Collect unique profiles by decryption type
  const fwdProxyProfiles = new Set();
  const inboundProfiles = new Map(); // profile-name → certificate
  const profileDefinitions = new Map(); // source identity → planned definition name
  const noDecryptNames = [];

  for (let ruleIndex = 0; ruleIndex < decryptionRules.length; ruleIndex += 1) {
    const rule = decryptionRules[ruleIndex];
    if (rule.disabled) continue;

    if (rule.action === 'decrypt' || rule.action === 'decrypt-and-forward') {
      if (rule.decryption_type === 'ssl-forward-proxy') {
        const sourceName = rule.decryption_profile
          ? `ssl-fwd-${rule.decryption_profile}`
          : 'ssl-fwd-proxy';
        if (!profileDefinitions.has(sourceName)) {
          profileDefinitions.set(sourceName, identifiers.nameForGenerated(
            identifierPath(`decryption_rules[${ruleIndex}]`),
            'ssl-forward-profile',
          ));
        }
        const profileName = rule.decryption_profile
          ? identifiers.nameForReference(
            identifierPath(`decryption_rules[${ruleIndex}].decryption_profile`),
          )
          : profileDefinitions.get(sourceName);
        fwdProxyProfiles.add(profileName);
      } else if (rule.decryption_type === 'ssl-inbound-inspection') {
        const sourceName = rule.decryption_profile
          ? `ssl-inbound-${rule.decryption_profile}`
          : 'ssl-inbound-proxy';
        if (!profileDefinitions.has(sourceName)) {
          profileDefinitions.set(sourceName, identifiers.nameForGenerated(
            identifierPath(`decryption_rules[${ruleIndex}]`),
            'ssl-inbound-profile',
          ));
        }
        const profileName = rule.decryption_profile
          ? identifiers.nameForReference(
            identifierPath(`decryption_rules[${ruleIndex}].decryption_profile`),
          )
          : profileDefinitions.get(sourceName);
        inboundProfiles.set(profileName, rule.ssl_certificate || 'SERVER-CERT');
      } else if (rule.decryption_type === 'ssh-proxy') {
        // SSH proxy → SRX doesn't have direct equivalent
        warnings.push(createWarning(
          'unsupported', `decrypt/${rule.name}`,
          `SSH proxy decryption rule "${rule.name}" has no direct SRX equivalent`,
          'SRX does not support SSH traffic decryption — configure SSH-based controls at the application layer'
        ));
      } else {
        // Generic decrypt — use forward proxy as default
        const sourceName = 'ssl-fwd-proxy';
        if (!profileDefinitions.has(sourceName)) {
          profileDefinitions.set(sourceName, identifiers.nameForGenerated(
            identifierPath(`decryption_rules[${ruleIndex}]`),
            'ssl-forward-profile',
          ));
        }
        fwdProxyProfiles.add(profileDefinitions.get(sourceName));
      }
    } else if (rule.action === 'no-decrypt') {
      noDecryptNames.push(rule.name);
    }
  }

  if (hasDecryptPolicies) {
    const hasRuleFallbackProfile = decryptionRules.some(rule => (
      !rule.disabled
      && ['decrypt', 'decrypt-and-forward'].includes(rule.action)
      && rule.decryption_type !== 'ssl-inbound-inspection'
      && rule.decryption_type !== 'ssh-proxy'
      && (
        rule.decryption_type !== 'ssl-forward-proxy'
        || !rule.decryption_profile
        || rule.decryption_profile === 'ssl-fwd-proxy'
      )
    ));
    if (!hasRuleFallbackProfile) {
      const owner = [...fallbackDecryptPolicies].sort((left, right) => (
        String(left.policy.name || '').localeCompare(String(right.policy.name || ''))
      ))[0];
      identifiers.nameForGenerated(
        identifierPath(`security_policies[${owner.index}]`),
        'ssl-forward-profile',
      );
    }
    for (const { index } of fallbackDecryptPolicies) {
      fwdProxyProfiles.add(identifiers.nameForReference(
        identifierPath(`security_policies[${index}]#ssl-proxy-profile`),
      ));
    }
  }

  // 1. PKI CA profile placeholder (needed for forward proxy)
  if (fwdProxyProfiles.size > 0) {
    const pkiOwners = decryptionRules
      .map((rule, index) => ({ rule, path: `decryption_rules[${index}]`, key: `rule:${rule.name || ''}` }))
      .filter(({ rule }) => (
        !rule.disabled
        && ['decrypt', 'decrypt-and-forward'].includes(rule.action)
        && rule.decryption_type !== 'ssl-inbound-inspection'
        && rule.decryption_type !== 'ssh-proxy'
      ));
    (config.security_policies || []).forEach((policy, index) => {
      if (policy._srx_decrypt && policy.action === 'allow' && !policy._srx_decrypt_profile) {
        pkiOwners.push({ path: `security_policies[${index}]`, key: `policy:${policy.name || ''}` });
      }
    });
    const pkiOwner = pkiOwners.sort((left, right) => left.key.localeCompare(right.key))[0];
    const pkiOwnerPath = identifierPath(pkiOwner.path);
    const caProfileName = identifiers.nameForGenerated(pkiOwnerPath, 'ssl-pki-ca-profile');
    const caIdentityName = identifiers.nameForGenerated(pkiOwnerPath, 'ssl-pki-ca-identity');
    commands.push('');
    commands.push('# PKI Configuration — CA profile for SSL forward proxy');
    commands.push(`set security pki ca-profile ${caProfileName} ca-identity ${caIdentityName}`);
    commands.push('# NOTE: Import the CA certificate after commit:');
    commands.push(`#   request security pki ca-certificate load ca-profile ${caProfileName} filename /var/tmp/ca-cert.pem`);
    commands.push('# NOTE: Generate key pair for signing:');
    commands.push(`#   request security pki generate-key-pair certificate-id ${caIdentityName} size 2048`);
    commands.push(`#   request security pki local-certificate generate-self-signed certificate-id ${caIdentityName} \\`);
    commands.push(`#     subject "CN=${caIdentityName},OU=Security,O=Organization" domain-name example.com`);
    commands.push('');
  }

  // 2. PKI local-certificate placeholder (for inbound inspection)
  if (inboundProfiles.size > 0) {
    for (const [, certName] of inboundProfiles) {
      commands.push(`# NOTE: Import server certificate for inbound SSL inspection:`);
      commands.push(`#   request security pki local-certificate load certificate-id ${certName} filename /var/tmp/${certName}.pem key /var/tmp/${certName}-key.pem`);
    }
    commands.push('');
  }

  // 3. SSL Forward Proxy profiles — skipped (requires manual PKI setup)
  if (fwdProxyProfiles.size > 0) {
    commands.push('# SSL forward-proxy profiles require manual configuration:');
    for (const profileName of fwdProxyProfiles) {
      commands.push(`#   set services ssl proxy profile ${profileName} root-ca <CA_PROFILE>`);
    }
    commands.push('# SSL proxy requires PKI certificates that cannot be auto-generated.');
    commands.push('# See: https://www.juniper.net/documentation/us/en/software/junos/ssl-proxy/');
  }

  // 4. SSL Inbound Inspection profiles — skipped (requires manual PKI setup)
  if (inboundProfiles.size > 0) {
    commands.push('# SSL inbound-inspection profiles require manual configuration:');
    for (const [profileName, certName] of inboundProfiles) {
      commands.push(`#   set services ssl proxy profile ${profileName} server-certificate ${certName}`);
    }
  }

  if (fwdProxyProfiles.size > 0 || inboundProfiles.size > 0) commands.push('');

  // 5. No-decrypt exclusion notes
  if (noDecryptNames.length > 0) {
    commands.push('# No-decrypt exclusions (traffic explicitly excluded from SSL inspection):');
    for (const name of noDecryptNames) {
      commands.push(`#   - ${name}`);
    }
    commands.push('# NOTE: Implement no-decrypt via SRX security policy exemptions (match-then-bypass)');
    commands.push('# or SSL proxy whitelist entries for specific domains/addresses');
    commands.push('');
  }

  // Summary
  summary.ssl_proxy_profiles = fwdProxyProfiles.size + inboundProfiles.size;
  summary.ssl_fwd_proxy_count = fwdProxyProfiles.size;
  summary.ssl_inbound_count = inboundProfiles.size;
  summary.ssl_no_decrypt_count = noDecryptNames.length;

  warnings.push(createWarning(
    'info', 'ssl-proxy/config',
    `Generated ${fwdProxyProfiles.size} SSL forward-proxy and ${inboundProfiles.size} inbound-inspection profiles`,
    'Import CA certificate and server certificates before committing. Test with a small policy scope first.'
  ));
}


// ---------------------------------------------------------------------------
// Flow Monitoring / Inline-Jflow Configuration
// ---------------------------------------------------------------------------

/**
 * Generates SRX inline-jflow configuration from flow monitoring config.
 *
 * Produces:
 *   set forwarding-options sampling instance <name> input rate <rate>
 *   set forwarding-options sampling instance <name> family inet output flow-server <addr> port <port>
 *   set forwarding-options sampling instance <name> family inet output flow-server <addr> version-ipfix template <tpl>
 *   set forwarding-options sampling instance <name> family inet output inline-jflow source-address <src>
 *   set services flow-monitoring version-ipfix template <tpl> flow-active-timeout <sec>
 *   set services flow-monitoring version-ipfix template <tpl> template-refresh-rate packets <num>
 *   set interfaces <iface> unit 0 family inet sampling input
 */
function flowCollectorKeyForSet(collector) {
  return JSON.stringify([
    collector.address || '',
    collector.port || 2055,
    collector.protocol || 'ipfix',
    collector.source_address || '',
  ]);
}

function canonicalFlowTemplateNamesForSet(collectors) {
  const keys = [...new Set((collectors || []).map(flowCollectorKeyForSet))].sort();
  return new Map(keys.map((key, index) => [key, `flow-tpl-${index + 1}`]));
}

function convertFlowMonitoringConfig(flowConfig, commands, warnings, summary, interfaceMappings = {}, identifiers, identifierPath) {
  if (!flowConfig || !flowConfig.collectors || flowConfig.collectors.length === 0) return;

  commands.push('# =============================================');
  commands.push('# Flow Monitoring (Inline Jflow)');
  commands.push('# =============================================');

  const instanceName = flowConfig.instance_name
    ? identifiers.nameForDefinition(identifierPath('flow_monitoring_config.instance_name'))
    : identifiers.nameForGenerated(identifierPath('flow_monitoring_config'), 'sampling-instance');
  const sampling = flowConfig.sampling || {};
  const rate = sampling.input_rate || 1000;
  const runLength = sampling.run_length || 0;

  // Sampling instance input
  commands.push(`set forwarding-options sampling instance ${instanceName} input rate ${rate}`);
  if (runLength > 0) {
    commands.push(`set forwarding-options sampling instance ${instanceName} input run-length ${runLength}`);
  }

  // Flow servers and templates
  const templates = flowConfig.templates || [];
  const fallbackTemplateNames = canonicalFlowTemplateNamesForSet(flowConfig.collectors);
  const fallbackDefinitions = new Map();

  for (let collectorIndex = 0; collectorIndex < flowConfig.collectors.length; collectorIndex += 1) {
    const collector = flowConfig.collectors[collectorIndex];
    const addr = collector.address;
    const port = collector.port || 2055;
    const protocol = (collector.protocol || 'ipfix').toLowerCase();
    const isIpfix = protocol === 'ipfix' || protocol === 'netflow-v10';
    const versionKey = isIpfix ? 'version-ipfix' : 'version9';

    // Get matching template or create default
    const collectorKey = flowCollectorKeyForSet(collector);
    const explicitTemplate = templates[collectorIndex];
    const tpl = explicitTemplate || {
      name: fallbackTemplateNames.get(collectorKey),
      flow_type: 'ipv4',
      active_timeout: 60,
      refresh_rate: 1000,
    };
    if (!explicitTemplate && !fallbackDefinitions.has(collectorKey)) {
      fallbackDefinitions.set(collectorKey, {
        template: tpl,
        outputName: identifiers.nameForGenerated(
          identifierPath(`flow_monitoring_config.collectors[${collectorIndex}]`),
          'collector-flow-template',
        ),
      });
    }
    const tplName = identifiers.nameForReference(
      identifierPath(`flow_monitoring_config.collectors[${collectorIndex}]#template`),
    );

    commands.push(`set forwarding-options sampling instance ${instanceName} family inet output flow-server ${addr} port ${port}`);
    commands.push(`set forwarding-options sampling instance ${instanceName} family inet output flow-server ${addr} ${versionKey} template ${tplName}`);

    // IPv6 family if specified
    if (tpl.flow_type === 'ipv6') {
      commands.push(`set forwarding-options sampling instance ${instanceName} family inet6 output flow-server ${addr} port ${port}`);
      commands.push(`set forwarding-options sampling instance ${instanceName} family inet6 output flow-server ${addr} ${versionKey} template ${tplName}`);
    }

    // Inline jflow source address
    if (collector.source_address) {
      commands.push(`set forwarding-options sampling instance ${instanceName} family inet output inline-jflow source-address ${collector.source_address}`);
    }

  }

  commands.push('');

  // Template definitions
  const templateDefinitions = templates.map((template, templateIndex) => ({
    template,
    outputName: identifiers.nameForDefinition(
      identifierPath(`flow_monitoring_config.templates[${templateIndex}].name`),
    ),
  }));
  templateDefinitions.push(...fallbackDefinitions.values());
  for (const { template: tpl, outputName: tplName } of templateDefinitions) {
    const isIpfix = true; // Default to IPFIX for SRX
    const versionKey = isIpfix ? 'version-ipfix' : 'version9';

    commands.push(`set services flow-monitoring ${versionKey} template ${tplName} flow-active-timeout ${tpl.active_timeout || 60}`);
    commands.push(`set services flow-monitoring ${versionKey} template ${tplName} template-refresh-rate packets ${tpl.refresh_rate || 1000}`);

    if (tpl.flow_type === 'ipv6') {
      commands.push(`set services flow-monitoring ${versionKey} template ${tplName} ipv6-template`);
    }
  }

  commands.push('');

  // Interface sampling bindings
  const samplingInterfaces = sampling.interfaces || [];
  for (const iface of samplingInterfaces) {
    const srxIface = mapInterfaceName(iface, interfaceMappings);
    const [base, unit = '0'] = srxIface.split('.');
    commands.push(`set interfaces ${base} unit ${unit} family inet sampling input`);
  }

  if (samplingInterfaces.length > 0) commands.push('');

  summary.flow_collectors = flowConfig.collectors.length;
  summary.flow_templates = templateDefinitions.length;

  warnings.push(createWarning('info', 'flow-monitoring/config',
    `Generated inline-jflow config with ${flowConfig.collectors.length} collector(s) and ${templateDefinitions.length} template(s)`,
    'Verify flow-server addresses and template parameters after deployment'));
}


/**
 * Groups NAT rules by source-zone → destination-zone pair.
 * SRX organizes NAT rules into rule-sets per zone pair.
 */
function natSourceZoneField(rule) {
  return rule.src_zones !== undefined ? 'src_zones' : 'source_zones';
}

function natDestinationZoneField(rule) {
  return rule.dst_zones !== undefined ? 'dst_zones' : 'destination_zones';
}

function natSourceZones(rule) {
  const zones = rule.src_zones ?? rule.source_zones;
  return Array.isArray(zones) && zones.length > 0 ? zones : ['any'];
}

function natDestinationZones(rule) {
  const zones = rule.dst_zones ?? rule.destination_zones;
  return Array.isArray(zones) && zones.length > 0 ? zones : ['any'];
}

function natMissingZoneRole(sourceName) {
  return `nat-missing-zone:${sourceName}`;
}

function groupByZonePair(rules) {
  const groups = [];
  for (const rule of rules) {
    const fromZones = natSourceZones(rule);
    const toZones = natDestinationZones(rule);

    for (const fromZone of fromZones) {
      for (const toZone of toZones) {
        let group = groups.find(item => (
          item.fromZone === fromZone && item.toZone === toZone
        ));
        if (!group) {
          group = { fromZone, toZone, rules: [] };
          groups.push(group);
        }
        group.rules.push(rule);
      }
    }
  }
  return groups;
}

// ---------------------------------------------------------------------------
// Multi-Firewall Merge Converter
// ---------------------------------------------------------------------------

/**
 * Converts multiple intermediate configs into a merged SRX output
 * with per-logical-system sections and shared chassis-level config.
 *
 * @param {Array<{lsName: string, intermediateConfig: Object, interfaceMappings: Object}>} configSlots
 * @param {Array<{ls1: string, ls2: string, sharedZone: string, lt1Unit: number, lt2Unit: number}>} crossLsLinks
 * @param {Object} globalConfig - Chassis-level config (HA, syslog)
 * @returns {{ commands: string[], warnings: Object[], summary: Object, identifierMappings: Object }}
 */
export function convertMergedToSrxSetCommands(configSlots, crossLsLinks = [], globalConfig = {}) {
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
  const allCommands = [];
  allCommands.push(setComment(versionStamp(globalConfig?.llmModel), 'version'));
  const allWarnings = [...identifiers.warnings];
  const perLsSummaries = [];

  // 1. Global chassis-level config (not inside any LS)
  allCommands.push('# =============================================');
  allCommands.push('# Multi-Firewall Merge — Chassis-Level Config');
  allCommands.push('# =============================================');
  allCommands.push(setComment(
    `Logical-systems: ${configSlots.map(s => s.lsName).join(', ')}`,
    'configSlots',
  ));
  allCommands.push('');

  // HA config at chassis level
  if (globalConfig.ha_config && globalConfig.ha_config.enabled) {
    const haCommands = [];
    const haWarnings = [];
    const haSummary = {};
    convertHaConfig(globalConfig.ha_config, haCommands, haWarnings, haSummary);
    allCommands.push(...haCommands);
    allWarnings.push(...haWarnings);
    allCommands.push('');
  }

  // Syslog at chassis level
  if (globalConfig.syslog_config && globalConfig.syslog_config.length > 0) {
    const sysCommands = [];
    convertSyslogConfig(globalConfig.syslog_config, sysCommands, allWarnings, {});
    allCommands.push(...sysCommands);
    allCommands.push('');
  }

  // SNMP at chassis level
  if (globalConfig.snmp_config && globalConfig.snmp_config.length > 0) {
    const snmpCommands = [];
    convertSnmpConfig(
      globalConfig.snmp_config,
      snmpCommands,
      allWarnings,
      {},
      identifiers,
      globalIdentifierPath,
    );
    allCommands.push(...snmpCommands);
    allCommands.push('');
  }

  // AAA at chassis level
  if (globalConfig.aaa_config && globalConfig.aaa_config.length > 0) {
    const aaaCommands = [];
    convertAaaConfig(
      globalConfig.aaa_config,
      aaaCommands,
      allWarnings,
      {},
      identifiers,
      globalIdentifierPath,
    );
    allCommands.push(...aaaCommands);
    allCommands.push('');
  }

  // 2. Per-LS sections
  for (let slotIndex = 0; slotIndex < configSlots.length; slotIndex += 1) {
    const slot = configSlots[slotIndex];
    const { lsName, intermediateConfig: config, interfaceMappings = {} } = slot;
    const safeLsName = identifiers.nameForDefinition(`configSlots[${slotIndex}].lsName`);

    allCommands.push('# =============================================');
    allCommands.push(setComment(`Logical-System: ${lsName}`, `configSlots[${slotIndex}].lsName`));
    allCommands.push('# =============================================');

    // Use existing converter with targetContext set to logical-system
    const targetContext = { type: 'logical-system', name: lsName };
    const result = convertToSrxSetCommands(config, interfaceMappings, targetContext, {
      identifierPlan: identifiers,
      pathPrefix: `configSlots[${slotIndex}].intermediateConfig.`,
      targetContextPath: `configSlots[${slotIndex}].lsName`,
    });

    allCommands.push(...result.commands);
    allWarnings.push(...result.warnings.slice(identifiers.warnings.length)
      .map(w => ({ ...w, _ls: safeLsName })));
    perLsSummaries.push({ lsName: safeLsName, summary: result.summary });
    allCommands.push('');
  }

  // 3. Cross-LS lt- tunnel interfaces
  if (crossLsLinks.length > 0) {
    allCommands.push('# =============================================');
    allCommands.push('# Cross-Logical-System Tunnel Interfaces (lt-)');
    allCommands.push('# =============================================');
    allCommands.push('# Auto-detected from shared zone names across logical-systems');
    allCommands.push('');

    for (let linkIndex = 0; linkIndex < crossLsLinks.length; linkIndex += 1) {
      const link = crossLsLinks[linkIndex];
      const ls1 = identifiers.nameForReference(`crossLsLinks[${linkIndex}].ls1`);
      const ls2 = identifiers.nameForReference(`crossLsLinks[${linkIndex}].ls2`);
      const u1 = setInteger(link.lt1Unit, { min: 0, max: 16385 }, `crossLsLinks[${linkIndex}].lt1Unit`);
      const u2 = setInteger(link.lt2Unit, { min: 0, max: 16385 }, `crossLsLinks[${linkIndex}].lt2Unit`);
      const zone1 = identifiers.nameForReference(`crossLsLinks[${linkIndex}].sharedZone#ls1`);
      const zone2 = identifiers.nameForReference(`crossLsLinks[${linkIndex}].sharedZone#ls2`);

      allCommands.push(setComment(
        `${link.ls1} <-> ${link.ls2} via zone "${link.sharedZone}"`,
        `crossLsLinks[${linkIndex}]`,
      ));

      // Side A
      allCommands.push(`set logical-systems ${ls1} interfaces lt-0/0/0 unit ${u1} encapsulation ethernet`);
      allCommands.push(`set logical-systems ${ls1} interfaces lt-0/0/0 unit ${u1} peer-unit ${u2}`);
      allCommands.push(`set logical-systems ${ls1} interfaces lt-0/0/0 unit ${u1} family inet`);
      allCommands.push(`set logical-systems ${ls1} security zones security-zone ${zone1} interfaces lt-0/0/0.${u1}`);

      // Side B
      allCommands.push(`set logical-systems ${ls2} interfaces lt-0/0/0 unit ${u2} encapsulation ethernet`);
      allCommands.push(`set logical-systems ${ls2} interfaces lt-0/0/0 unit ${u2} peer-unit ${u1}`);
      allCommands.push(`set logical-systems ${ls2} interfaces lt-0/0/0 unit ${u2} family inet`);
      allCommands.push(`set logical-systems ${ls2} security zones security-zone ${zone2} interfaces lt-0/0/0.${u2}`);

      allCommands.push('');
    }
  }

  // 4. Merged summary
  const mergedSummary = {
    logical_systems: configSlots.length,
    cross_ls_links: crossLsLinks.length,
    per_ls: perLsSummaries,
    total_policies: perLsSummaries.reduce((sum, ls) => sum + (ls.summary.policies_converted || 0), 0),
    total_warnings: allWarnings.length,
    identifier_collisions_resolved: identifiers.collisionCount,
  };

  serializeSetComments(allCommands);
  validateSetOutput(allCommands);
  return {
    commands: allCommands,
    warnings: allWarnings,
    summary: mergedSummary,
    identifierMappings: identifiers.mapping,
  };
}
