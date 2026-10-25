/**
 * Junos SRX Configuration Parser
 * ================================
 *
 * Parses Junos SRX configurations (set commands and hierarchical format)
 * into the vendor-neutral intermediate JSON schema.
 *
 * Handles:
 *   - Security zones and interfaces
 *   - Address objects (global address-book)
 *   - Address sets (groups)
 *   - Service/application references
 *   - Security policies (with match criteria, actions, logging)
 *   - NAT rules (source, destination, static)
 *   - Security profiles (UTM, IDP)
 *
 * Supports both:
 *   - "set" commands format (show configuration | display set)
 *   - Hierarchical curly-brace format (show configuration)
 */

import { createWarning, detectIpVersion } from './parser-utils.js';

// ---------------------------------------------------------------------------
// Main Parser Entry Point
// ---------------------------------------------------------------------------

/**
 * Parses a Junos SRX configuration into the intermediate JSON schema.
 *
 * @param {string} configText - Raw Junos configuration text (set or hierarchical)
 * @returns {{ intermediateConfig: Object, warnings: Object[], parseStats: Object }}
 */
export function parseSrxConfig(configText) {
  const warnings = [];

  // Normalize to set commands if hierarchical format detected
  const setCommands = normalizeToSetCommands(configText);

  // Parse set commands into a tree structure
  const tree = buildConfigTree(setCommands);

  // Detect logical-systems and tenants
  const lsNode = tree['logical-systems'] || {};
  const tenantNode = tree['tenants'] || {};
  const lsNames = Object.keys(lsNode).filter(k => !k.startsWith('_'));
  const tenantNames = Object.keys(tenantNode).filter(k => !k.startsWith('_'));
  const hasContexts = lsNames.length > 0 || tenantNames.length > 0;

  if (hasContexts) {
    return parseMultiContextSrx(tree, setCommands, lsNode, lsNames, tenantNode, tenantNames, warnings);
  }

  // Single flat config (existing path)
  return parseFlatSrx(tree, setCommands, warnings);
}

/**
 * Parses a flat (no logical-systems/tenants) SRX config.
 */
function parseFlatSrx(tree, setCommands, warnings) {
  // Extract each config section
  const zones = parseZones(tree, warnings);
  const addressObjects = parseAddressObjects(tree, warnings);
  const addressGroups = parseAddressGroups(tree, warnings);
  const serviceObjects = parseServiceObjects(tree, warnings);
  const serviceGroups = parseServiceGroups(tree, warnings);
  const securityPolicies = parseSecurityPolicies(tree, warnings);
  const natRules = parseNatRules(tree, warnings);
  const applications = parseApplications(tree, warnings);
  const schedules = parseSchedulers(setCommands, warnings);
  const { staticRoutes, routingContexts } = parseSrxStaticRoutes(tree, warnings);
  const bgpConfig = parseSrxBgpConfig(tree, warnings);
  const ospfConfig = parseSrxOspfConfig(tree, warnings);
  const ospf3Config = parseSrxOspf3Config(tree, warnings);
  const evpnConfig = parseSrxEvpnConfig(tree, warnings);
  const vxlanConfig = parseSrxVxlanConfig(tree, warnings);
  const haConfig = parseSrxHaConfig(tree, warnings);
  const screenConfig = parseSrxScreenConfig(tree, zones, warnings);

  // Extract version info if available
  const version = extractVersion(tree);

  // Append SRX implicit default deny
  securityPolicies.push({
    name: 'Implicit: Default Deny',
    src_zones: ['any'],
    dst_zones: ['any'],
    src_addresses: ['any'],
    dst_addresses: ['any'],
    negate_source: false,
    negate_destination: false,
    applications: ['any'],
    services: ['any'],
    action: 'deny',
    log_start: false,
    log_end: false,
    profile_group: '',
    security_profiles: {},
    description: 'SRX default: implicit deny for unmatched traffic',
    tags: ['added_by_fpic'],
    disabled: false,
    _rule_index: securityPolicies.length + 1,
    _implicit: true,
    source_users: [],
  });

  // Parse VPN/IPsec tunnel configuration
  const vpnTunnels = parseSrxVpnConfig(tree, warnings);

  // Parse syslog, SNMP, AAA, DHCP, QoS
  const syslogConfig = parseSrxSyslogConfig(tree, warnings);
  const snmpConfig = parseSrxSnmpConfig(tree, warnings);
  const aaaConfig = parseSrxAaaConfig(tree, warnings);
  const dhcpConfig = parseSrxDhcpConfig(tree, warnings);
  const qosConfig = parseSrxQosConfig(tree, warnings);

  // Parse interface configurations
  const interfaces = parseSrxInterfaces(tree, zones, warnings);

  // Parse LAG / ae interfaces
  const lagInterfaces = parseSrxLagInterfaces(tree, warnings);

  // Parse L2 / bridge-domain configuration
  const bridgeDomains = parseSrxBridgeDomains(tree, warnings);
  const l2Interfaces = detectSrxL2Interfaces(tree, interfaces, warnings);

  // Parse SSL Proxy profiles (round-trip) — must run after policies
  const decryptionRules = parseSrxSslProxy(tree, securityPolicies, warnings);

  // Parse PBF / Firewall filter (round-trip)
  const pbfRules = parseSrxPbfRules(tree, warnings);

  // Parse flow monitoring (round-trip)
  const flowMonitoringConfig = parseSrxFlowMonitoring(tree, warnings);

  const intermediateConfig = {
    zones,
    address_objects: addressObjects,
    address_groups: addressGroups,
    service_objects: serviceObjects,
    service_groups: serviceGroups,
    security_policies: securityPolicies,
    nat_rules: natRules,
    applications,
    application_groups: [],
    schedules,
    security_profile_objects: [],
    external_lists: [],
    vpn_tunnels: vpnTunnels,
    ha_config: haConfig,
    screen_config: screenConfig,
    syslog_config: syslogConfig,
    snmp_config: snmpConfig,
    aaa_config: aaaConfig,
    dhcp_config: dhcpConfig,
    qos_config: qosConfig,
    interfaces,
    lag_interfaces: lagInterfaces,
    routing_contexts: routingContexts,
    static_routes: staticRoutes,
    bgp_config: bgpConfig,
    ospf_config: ospfConfig,
    ospf3_config: ospf3Config,
    evpn_config: evpnConfig,
    vxlan_config: vxlanConfig,
    pbf_rules: pbfRules,
    decryption_rules: decryptionRules,
    flow_monitoring_config: flowMonitoringConfig,
    target_context: null,
    transparent_mode: bridgeDomains.length > 0,
    bridge_domains: bridgeDomains,
    l2_interfaces: l2Interfaces,
    vwire_pairs: [],
    metadata: {
      source_vendor: 'srx',
      source_version: version,
      export_date: new Date().toISOString(),
      rule_count: securityPolicies.length,
      nat_rule_count: natRules.length,
      object_count: addressObjects.length + addressGroups.length + serviceObjects.length + serviceGroups.length,
      zone_count: zones.length,
      interface_count: interfaces.length,
      vpn_tunnel_count: vpnTunnels.length,
      syslog_server_count: syslogConfig.length,
      snmp_config_count: snmpConfig.length,
      aaa_config_count: aaaConfig.length,
      dhcp_config_count: dhcpConfig.length,
      qos_profile_count: qosConfig.length,
      routing_context_count: routingContexts.length,
      static_route_count: staticRoutes.length,
      bgp_instance_count: bgpConfig.length,
      ospf_instance_count: ospfConfig.length,
      ospf3_instance_count: ospf3Config.length,
      evpn_instance_count: evpnConfig.length,
      vxlan_tunnel_count: vxlanConfig.length,
      ha_enabled: !!(haConfig && haConfig.enabled),
      multi_vsys: false,
    },
  };

  return {
    intermediateConfig,
    warnings,
    parseStats: intermediateConfig.metadata,
  };
}

/**
 * Parses an SRX config containing logical-systems and/or tenants.
 * Each context is parsed independently and merged into flat arrays
 * with _logical_system tags (same pattern as PAN-OS multi-vsys).
 */
function parseMultiContextSrx(tree, setCommands, lsNode, lsNames, tenantNode, tenantNames, warnings) {
  const allZones = [];
  const allAddressObjects = [];
  const allAddressGroups = [];
  const allServiceObjects = [];
  const allServiceGroups = [];
  const allPolicies = [];
  const allNatRules = [];
  const allApplications = [];
  const allSchedules = [];
  const allStaticRoutes = [];
  const allBgpConfig = [];
  const allOspfConfig = [];
  const allOspf3Config = [];
  const allEvpnConfig = [];
  const allVxlanConfig = [];
  const allVpnTunnels = [];
  const allScreenConfig = [];
  const allSyslogConfig = [];
  const allSnmpConfig = [];
  const allAaaConfig = [];
  const allDhcpConfig = [];
  const allQosConfig = [];
  const allInterfaces = [];
  const allBridgeDomains = [];
  const allL2Interfaces = [];
  const allDecryptionRules = [];
  const allPbfRules = [];
  const routingContexts = [];
  let haConfig = { enabled: false };
  let ruleIndex = 0;

  const version = extractVersion(tree);

  // Also parse global/chassis-level config that exists outside any LS
  const globalHa = parseSrxHaConfig(tree, warnings);
  if (globalHa && globalHa.enabled) haConfig = globalHa;
  const globalSyslog = parseSrxSyslogConfig(tree, warnings);
  if (globalSyslog.length) allSyslogConfig.push(...globalSyslog);
  const globalSnmp = parseSrxSnmpConfig(tree, warnings);
  if (globalSnmp.length) allSnmpConfig.push(...globalSnmp);
  const globalAaa = parseSrxAaaConfig(tree, warnings);
  if (globalAaa.length) allAaaConfig.push(...globalAaa);

  // Parse each logical-system
  for (const lsName of lsNames) {
    const subTree = lsNode[lsName];
    const ctxLabel = `logical-system ${lsName}`;

    // Filter set commands for this LS to handle scheduler parsing
    const lsPrefix = `set logical-systems ${lsName} `;
    const lsSetCmds = setCommands
      .filter(cmd => cmd.startsWith(lsPrefix))
      .map(cmd => 'set ' + cmd.substring(lsPrefix.length));

    const parsed = parseContextSubTree(subTree, lsSetCmds, ctxLabel, lsName, warnings);
    // Tag all items
    parsed.policies.forEach(p => { p._logical_system = lsName; p._rule_index = ++ruleIndex; });
    parsed.natRules.forEach(r => { r._logical_system = lsName; });

    allZones.push(...parsed.zones);
    allAddressObjects.push(...parsed.addressObjects);
    allAddressGroups.push(...parsed.addressGroups);
    allServiceObjects.push(...parsed.serviceObjects);
    allServiceGroups.push(...parsed.serviceGroups);
    allPolicies.push(...parsed.policies);
    allNatRules.push(...parsed.natRules);
    allApplications.push(...parsed.applications);
    allSchedules.push(...parsed.schedules);
    allStaticRoutes.push(...parsed.staticRoutes);
    allBgpConfig.push(...parsed.bgpConfig);
    allOspfConfig.push(...parsed.ospfConfig);
    allOspf3Config.push(...parsed.ospf3Config);
    allEvpnConfig.push(...parsed.evpnConfig);
    allVxlanConfig.push(...parsed.vxlanConfig);
    allVpnTunnels.push(...parsed.vpnTunnels);
    allScreenConfig.push(...parsed.screenConfig);
    allSyslogConfig.push(...parsed.syslogConfig);
    allSnmpConfig.push(...(parsed.snmpConfig || []));
    allAaaConfig.push(...(parsed.aaaConfig || []));
    allDhcpConfig.push(...parsed.dhcpConfig);
    allQosConfig.push(...parsed.qosConfig);
    allInterfaces.push(...parsed.interfaces);
    allBridgeDomains.push(...parsed.bridgeDomains);
    allL2Interfaces.push(...parsed.l2Interfaces);
    allDecryptionRules.push(...(parsed.decryptionRules || []));
    allPbfRules.push(...(parsed.pbfRules || []));

    routingContexts.push({
      name: lsName,
      type: 'logical-system',
      virtual_routers: [],
      zones: parsed.zones.map(z => z.name),
    });
  }

  // Parse each tenant
  for (const tName of tenantNames) {
    const subTree = tenantNode[tName];
    const ctxLabel = `tenant ${tName}`;

    const tPrefix = `set tenants ${tName} `;
    const tSetCmds = setCommands
      .filter(cmd => cmd.startsWith(tPrefix))
      .map(cmd => 'set ' + cmd.substring(tPrefix.length));

    const parsed = parseContextSubTree(subTree, tSetCmds, ctxLabel, tName, warnings);
    parsed.policies.forEach(p => { p._logical_system = tName; p._rule_index = ++ruleIndex; });
    parsed.natRules.forEach(r => { r._logical_system = tName; });

    allZones.push(...parsed.zones);
    allAddressObjects.push(...parsed.addressObjects);
    allAddressGroups.push(...parsed.addressGroups);
    allServiceObjects.push(...parsed.serviceObjects);
    allServiceGroups.push(...parsed.serviceGroups);
    allPolicies.push(...parsed.policies);
    allNatRules.push(...parsed.natRules);
    allApplications.push(...parsed.applications);
    allSchedules.push(...parsed.schedules);
    allStaticRoutes.push(...parsed.staticRoutes);
    allBgpConfig.push(...parsed.bgpConfig);
    allOspfConfig.push(...parsed.ospfConfig);
    allOspf3Config.push(...parsed.ospf3Config);
    allEvpnConfig.push(...parsed.evpnConfig);
    allVxlanConfig.push(...parsed.vxlanConfig);
    allVpnTunnels.push(...parsed.vpnTunnels);
    allScreenConfig.push(...parsed.screenConfig);
    allSyslogConfig.push(...parsed.syslogConfig);
    allSnmpConfig.push(...(parsed.snmpConfig || []));
    allAaaConfig.push(...(parsed.aaaConfig || []));
    allDhcpConfig.push(...parsed.dhcpConfig);
    allQosConfig.push(...parsed.qosConfig);
    allInterfaces.push(...parsed.interfaces);
    allBridgeDomains.push(...parsed.bridgeDomains);
    allL2Interfaces.push(...parsed.l2Interfaces);
    allDecryptionRules.push(...(parsed.decryptionRules || []));
    allPbfRules.push(...(parsed.pbfRules || []));

    routingContexts.push({
      name: tName,
      type: 'tenant',
      virtual_routers: [],
      zones: parsed.zones.map(z => z.name),
    });
  }

  // Add implicit default deny per context
  for (const ctx of routingContexts) {
    allPolicies.push({
      name: `Implicit: Default Deny (${ctx.name})`,
      src_zones: ['any'],
      dst_zones: ['any'],
      src_addresses: ['any'],
      dst_addresses: ['any'],
      negate_source: false,
      negate_destination: false,
      applications: ['any'],
      services: ['any'],
      action: 'deny',
      log_start: false,
      log_end: false,
      profile_group: '',
      security_profiles: {},
      description: `SRX default: implicit deny for ${ctx.name}`,
      tags: ['added_by_fpic'],
      disabled: false,
      _rule_index: ++ruleIndex,
      _implicit: true,
      _logical_system: ctx.name,
      source_users: [],
    });
  }

  const totalContexts = lsNames.length + tenantNames.length;
  warnings.push(createWarning(
    'info',
    `SRX config contains ${totalContexts} context(s): ${[...lsNames.map(n => `LS:${n}`), ...tenantNames.map(n => `tenant:${n}`)].join(', ')}`,
    'logical-systems',
    'multi_context_detected'
  ));

  const intermediateConfig = {
    zones: allZones,
    address_objects: allAddressObjects,
    address_groups: allAddressGroups,
    service_objects: allServiceObjects,
    service_groups: allServiceGroups,
    security_policies: allPolicies,
    nat_rules: allNatRules,
    applications: allApplications,
    application_groups: [],
    schedules: allSchedules,
    security_profile_objects: [],
    external_lists: [],
    vpn_tunnels: allVpnTunnels,
    ha_config: haConfig,
    screen_config: allScreenConfig,
    syslog_config: allSyslogConfig,
    snmp_config: allSnmpConfig,
    aaa_config: allAaaConfig,
    dhcp_config: allDhcpConfig,
    qos_config: allQosConfig,
    interfaces: allInterfaces,
    lag_interfaces: parseSrxLagInterfaces(tree, []),
    routing_contexts: routingContexts,
    static_routes: allStaticRoutes,
    bgp_config: allBgpConfig,
    ospf_config: allOspfConfig,
    ospf3_config: allOspf3Config,
    evpn_config: allEvpnConfig,
    vxlan_config: allVxlanConfig,
    pbf_rules: allPbfRules,
    decryption_rules: allDecryptionRules,
    flow_monitoring_config: { collectors: [], sampling: { input_rate: 1000, run_length: 0, interfaces: [] }, templates: [] },
    target_context: null,
    transparent_mode: allBridgeDomains.length > 0,
    bridge_domains: allBridgeDomains,
    l2_interfaces: allL2Interfaces,
    vwire_pairs: [],
    metadata: {
      source_vendor: 'srx',
      source_version: version,
      export_date: new Date().toISOString(),
      rule_count: allPolicies.length,
      nat_rule_count: allNatRules.length,
      object_count: allAddressObjects.length + allAddressGroups.length + allServiceObjects.length + allServiceGroups.length,
      zone_count: allZones.length,
      interface_count: allInterfaces.length,
      vpn_tunnel_count: allVpnTunnels.length,
      syslog_server_count: allSyslogConfig.length,
      snmp_config_count: allSnmpConfig.length,
      aaa_config_count: allAaaConfig.length,
      dhcp_config_count: allDhcpConfig.length,
      qos_profile_count: allQosConfig.length,
      routing_context_count: routingContexts.length,
      static_route_count: allStaticRoutes.length,
      bgp_instance_count: allBgpConfig.length,
      ospf_instance_count: allOspfConfig.length,
      ospf3_instance_count: allOspf3Config.length,
      evpn_instance_count: allEvpnConfig.length,
      vxlan_tunnel_count: allVxlanConfig.length,
      ha_enabled: !!(haConfig && haConfig.enabled),
      multi_vsys: true,
    },
  };

  return {
    intermediateConfig,
    warnings,
    parseStats: intermediateConfig.metadata,
  };
}

/**
 * Parses a single logical-system or tenant sub-tree using all existing parse functions.
 */
function parseContextSubTree(subTree, setCommands, ctxLabel, ctxName, warnings) {
  const zones = parseZones(subTree, warnings);
  const addressObjects = parseAddressObjects(subTree, warnings);
  const addressGroups = parseAddressGroups(subTree, warnings);
  const serviceObjects = parseServiceObjects(subTree, warnings);
  const serviceGroups = parseServiceGroups(subTree, warnings);
  const policies = parseSecurityPolicies(subTree, warnings);
  const natRules = parseNatRules(subTree, warnings);
  const applications = parseApplications(subTree, warnings);
  const schedules = parseSchedulers(setCommands, warnings);
  const { staticRoutes } = parseSrxStaticRoutes(subTree, warnings);
  const bgpConfig = parseSrxBgpConfig(subTree, warnings);
  const ospfConfig = parseSrxOspfConfig(subTree, warnings);
  const ospf3Config = parseSrxOspf3Config(subTree, warnings);
  const evpnConfig = parseSrxEvpnConfig(subTree, warnings);
  const vxlanConfig = parseSrxVxlanConfig(subTree, warnings);
  const vpnTunnels = parseSrxVpnConfig(subTree, warnings);
  const screenConfig = parseSrxScreenConfig(subTree, zones, warnings);
  const syslogConfig = parseSrxSyslogConfig(subTree, warnings);
  const snmpConfig = parseSrxSnmpConfig(subTree, warnings);
  const aaaConfig = parseSrxAaaConfig(subTree, warnings);
  const dhcpConfig = parseSrxDhcpConfig(subTree, warnings);
  const qosConfig = parseSrxQosConfig(subTree, warnings);
  const interfaces = parseSrxInterfaces(subTree, zones, warnings);
  const bridgeDomains = parseSrxBridgeDomains(subTree, warnings);
  const l2Interfaces = detectSrxL2Interfaces(subTree, interfaces, warnings);
  const decryptionRules = parseSrxSslProxy(subTree, policies, warnings);
  const pbfRules = parseSrxPbfRules(subTree, warnings);

  return {
    zones, addressObjects, addressGroups, serviceObjects, serviceGroups,
    policies, natRules, applications, schedules, staticRoutes,
    bgpConfig, ospfConfig, ospf3Config, evpnConfig, vxlanConfig,
    vpnTunnels, screenConfig, syslogConfig, snmpConfig, aaaConfig, dhcpConfig, qosConfig,
    interfaces, bridgeDomains, l2Interfaces, decryptionRules, pbfRules,
  };
}

// ---------------------------------------------------------------------------
// Normalize hierarchical config to set commands
// ---------------------------------------------------------------------------

/**
 * Converts hierarchical Junos config to set commands.
 * If already in set format, returns lines as-is.
 */
function normalizeToSetCommands(configText) {
  const lines = configText.split('\n').map(l => l.trimEnd());

  // Check if already set commands
  const setLines = lines.filter(l => /^(set|deactivate) /.test(l.trim()));
  // Comment lines don't count: converter output carries many `#` banners
  const contentLines = lines.filter(l => l.trim().length > 0 && !l.trim().startsWith('#'));
  if (setLines.length > contentLines.length * 0.5) {
    // Mostly set commands — use them directly
    return setLines.map(l => l.trim());
  }

  // Convert hierarchical to set commands
  return hierarchicalToSet(lines);
}

/**
 * Converts hierarchical curly-brace Junos config to flat set commands.
 */
function hierarchicalToSet(lines) {
  const setCommands = [];
  const pathStack = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();

    // Skip empty lines, comments, annotations
    if (!line || line.startsWith('#') || line.startsWith('/*') || line.startsWith('*')) continue;

    // Handle closing brace
    if (line === '}') {
      pathStack.pop();
      continue;
    }

    // Handle "inactive:" prefix
    const inactiveMatch = line.match(/^inactive:\s*(.+)$/);
    const activeLine = inactiveMatch ? inactiveMatch[1].trim() : line;
    const deactivatePrefix = inactiveMatch ? 'deactivate ' : 'set ';

    // Handle opening brace: "keyword {" or "keyword value {"
    if (activeLine.endsWith('{')) {
      const path = activeLine.slice(0, -1).trim();
      pathStack.push(path);
      if (inactiveMatch) setCommands.push(`deactivate ${pathStack.join(' ')}`);
      continue;
    }

    // Handle leaf value ending with ";"
    if (activeLine.endsWith(';')) {
      const value = activeLine.slice(0, -1).trim();
      const fullPath = [...pathStack, value].join(' ');
      setCommands.push(`${deactivatePrefix}${fullPath}`);
      continue;
    }

    // Handle bracket lists: [value1 value2 value3];
    const bracketMatch = activeLine.match(/^(.+?)\s+\[([^\]]+)\];?$/);
    if (bracketMatch) {
      const prefix = bracketMatch[1].trim();
      const values = bracketMatch[2].trim().split(/\s+/);
      for (const val of values) {
        const fullPath = [...pathStack, prefix, val].join(' ');
        setCommands.push(`set ${fullPath}`);
      }
      continue;
    }
  }

  return setCommands;
}

// ---------------------------------------------------------------------------
// Build config tree from set commands
// ---------------------------------------------------------------------------

/**
 * Builds a nested object tree from flat set commands.
 * Each path segment becomes a key, leaf values are stored as arrays.
 */
function buildConfigTree(setCommands) {
  const tree = {};

  for (const cmd of setCommands) {
    // Remove "set " or "deactivate " prefix
    let path;
    let isDeactivate = false;
    if (cmd.startsWith('set ')) {
      path = cmd.substring(4);
    } else if (cmd.startsWith('deactivate ')) {
      path = cmd.substring(11);
      isDeactivate = true;
    } else {
      continue;
    }

    // Tokenize respecting quoted strings
    const tokens = tokenize(path);
    if (tokens.length === 0) continue;

    // Navigate/create tree nodes
    let node = tree;
    for (let i = 0; i < tokens.length - 1; i++) {
      const token = tokens[i];
      if (!node[token]) node[token] = {};
      if (typeof node[token] === 'string') {
        // Convert leaf to branch
        node[token] = { _value: node[token] };
      } else if (node[token] === true) {
        // A flag statement (e.g. `set ... security-zone trust`) that later gains children
        node[token] = {};
      }
      node = node[token];
    }

    // Set leaf value
    const lastToken = tokens[tokens.length - 1];
    if (node[lastToken] === undefined) {
      node[lastToken] = true; // flag-style value
    }
    // Mark the deactivated statement itself (a flag leaf becomes an object)
    if (isDeactivate) {
      if (typeof node[lastToken] !== 'object') {
        node[lastToken] = node[lastToken] === true ? {} : { _value: node[lastToken] };
      }
      node[lastToken]._deactivated = true;
    }
  }

  return tree;
}

/**
 * Tokenizes a Junos set command path, respecting quoted strings.
 */
function tokenize(path) {
  const tokens = [];
  let current = '';
  let inQuote = false;
  let quoteChar = '';

  for (let i = 0; i < path.length; i++) {
    const ch = path[i];

    if (inQuote) {
      if (ch === quoteChar) {
        inQuote = false;
        // Don't include quote chars in token
      } else {
        current += ch;
      }
    } else if (ch === '"' || ch === "'") {
      inQuote = true;
      quoteChar = ch;
    } else if (ch === ' ') {
      if (current) {
        tokens.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }
  if (current) tokens.push(current);
  return tokens;
}

// ---------------------------------------------------------------------------
// Zone Parser
// ---------------------------------------------------------------------------

function parseZones(tree, warnings) {
  const zonesNode = tree?.security?.zones?.['security-zone'];
  if (!zonesNode) return [];

  const zones = [];
  for (const [zoneName, zoneData] of Object.entries(zonesNode)) {
    if (zoneName.startsWith('_')) continue;

    const interfaces = [];
    if (zoneData?.interfaces) {
      for (const ifName of Object.keys(zoneData.interfaces)) {
        if (!ifName.startsWith('_')) {
          interfaces.push(ifName);
        }
      }
    }

    const description = extractStringValue(zoneData?.description) || '';

    zones.push({
      name: zoneName,
      description,
      interfaces,
    });
  }

  return zones;
}

// ---------------------------------------------------------------------------
// Address Object Parser (global address-book)
// ---------------------------------------------------------------------------

function parseAddressObjects(tree, warnings) {
  const addrBook = tree?.security?.['address-book']?.global;
  if (!addrBook) return [];

  const objects = [];
  const addressNode = addrBook.address;
  if (!addressNode) return [];

  for (const [name, data] of Object.entries(addressNode)) {
    if (name.startsWith('_')) continue;

    let type = 'unknown';
    let value = '';

    if (data && typeof data === 'object') {
      // IP prefix
      const ipPrefix = findKeyValue(data);
      if (ipPrefix) {
        value = ipPrefix;
        if (value.endsWith('/32')) {
          type = 'host';
        } else if (value.includes('/')) {
          type = 'subnet';
        }
      }

      // dns-name
      if (data['dns-name']) {
        type = 'fqdn';
        value = extractStringValue(data['dns-name']) || Object.keys(data['dns-name'])[0] || '';
      }

      // range-address
      if (data['range-address']) {
        type = 'range';
        const rangeKeys = Object.keys(data['range-address']).filter(k => !k.startsWith('_'));
        if (rangeKeys.length > 0) {
          const rangeName = rangeKeys[0];
          const rangeData = data['range-address'][rangeName];
          const lower = rangeName;
          const upper = rangeData?.to ? Object.keys(rangeData.to).filter(k => !k.startsWith('_'))[0] || '' : '';
          value = upper ? `${lower}-${upper}` : lower;
        }
      }

      // Wildcard-address
      if (data['wildcard-address']) {
        type = 'wildcard';
        const wcKeys = Object.keys(data['wildcard-address']).filter(k => !k.startsWith('_'));
        value = wcKeys[0] || '';
      }

      // Simple IP/subnet as direct key
      if (type === 'unknown') {
        const keys = Object.keys(data).filter(k => !k.startsWith('_') && k !== 'description');
        for (const k of keys) {
          if (k.match(/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/)) {
            value = k;
            type = k.endsWith('/32') ? 'host' : 'subnet';
            break;
          }
        }
      }
    } else if (typeof data === 'string') {
      value = data;
      type = value.includes('/') ? (value.endsWith('/32') ? 'host' : 'subnet') : 'host';
    }

    const description = (data && typeof data === 'object') ?
      (extractStringValue(data.description) || '') : '';

    objects.push({ name, type, value, description, tags: [] });
  }

  // Auto-tag ip_version on all address objects
  for (const obj of objects) {
    obj.ip_version = detectIpVersion(obj.value);
  }

  return objects;
}

// ---------------------------------------------------------------------------
// Address Group Parser (address-set in global address-book)
// ---------------------------------------------------------------------------

function parseAddressGroups(tree, warnings) {
  const addrBook = tree?.security?.['address-book']?.global;
  if (!addrBook) return [];

  const groups = [];
  const setNode = addrBook['address-set'];
  if (!setNode) return [];

  for (const [name, data] of Object.entries(setNode)) {
    if (name.startsWith('_')) continue;

    const members = [];
    if (data?.address) {
      for (const memberName of Object.keys(data.address)) {
        if (!memberName.startsWith('_')) {
          members.push(memberName);
        }
      }
    }
    if (data?.['address-set']) {
      for (const subSetName of Object.keys(data['address-set'])) {
        if (!subSetName.startsWith('_')) {
          members.push(subSetName);
        }
      }
    }

    const description = (data && typeof data === 'object') ?
      (extractStringValue(data.description) || '') : '';

    groups.push({ name, members, description, tags: [] });
  }

  return groups;
}

// ---------------------------------------------------------------------------
// Service Object Parser
// ---------------------------------------------------------------------------

function parseServiceObjects(tree, warnings) {
  const appNode = tree?.applications?.application;
  if (!appNode) return [];

  const services = [];
  for (const [name, data] of Object.entries(appNode)) {
    if (name.startsWith('_') || !data || typeof data !== 'object') continue;

    let protocol = '';
    let portRange = '';
    let sourcePort = '';

    if (data.protocol) {
      protocol = extractStringValue(data.protocol) || Object.keys(data.protocol).filter(k => !k.startsWith('_'))[0] || '';
    }

    if (data['destination-port']) {
      portRange = extractStringValue(data['destination-port']) || Object.keys(data['destination-port']).filter(k => !k.startsWith('_'))[0] || '';
    }

    if (data['source-port']) {
      sourcePort = extractStringValue(data['source-port']) || Object.keys(data['source-port']).filter(k => !k.startsWith('_'))[0] || '';
    }

    if (protocol || portRange) {
      services.push({
        name,
        protocol,
        port_range: portRange,
        source_port: sourcePort,
        description: extractStringValue(data.description) || '',
      });
    }
  }

  return services;
}

// ---------------------------------------------------------------------------
// Service Group Parser (application-set)
// ---------------------------------------------------------------------------

function parseServiceGroups(tree, warnings) {
  const setNode = tree?.applications?.['application-set'];
  if (!setNode) return [];

  const groups = [];
  for (const [name, data] of Object.entries(setNode)) {
    if (name.startsWith('_') || !data || typeof data !== 'object') continue;

    const members = [];
    if (data.application) {
      for (const memberName of Object.keys(data.application)) {
        if (!memberName.startsWith('_')) {
          members.push(memberName);
        }
      }
    }

    groups.push({
      name,
      members,
      description: extractStringValue(data.description) || '',
    });
  }

  return groups;
}

// ---------------------------------------------------------------------------
// Application Parser
// ---------------------------------------------------------------------------

function parseApplications(tree, warnings) {
  const appNode = tree?.applications?.application;
  if (!appNode) return [];

  const apps = [];
  for (const [name, data] of Object.entries(appNode)) {
    if (name.startsWith('_') || !data || typeof data !== 'object') continue;

    let protocol = '';
    let port = '';

    if (data.protocol) {
      protocol = extractStringValue(data.protocol) || Object.keys(data.protocol).filter(k => !k.startsWith('_'))[0] || '';
    }
    if (data['destination-port']) {
      port = extractStringValue(data['destination-port']) || Object.keys(data['destination-port']).filter(k => !k.startsWith('_'))[0] || '';
    }

    apps.push({
      name,
      protocol,
      port,
      description: extractStringValue(data.description) || '',
    });
  }

  return apps;
}

// ---------------------------------------------------------------------------
// Security Policies Parser
// ---------------------------------------------------------------------------

function parseSecurityPolicies(tree, warnings) {
  const policiesNode = tree?.security?.policies;
  if (!policiesNode) return [];

  const policies = [];
  let ruleIndex = 0;

  // Junos policies are organized as:
  // security policies from-zone <src> to-zone <dst> policy <name> ...
  for (const [key, value] of Object.entries(policiesNode)) {
    if (!key.startsWith('from-zone') && key !== 'global') continue;

    if (key === 'global') {
      // Global policies
      const policyNode = value?.policy;
      if (policyNode) {
        for (const [policyName, policyData] of Object.entries(policyNode)) {
          if (policyName.startsWith('_')) continue;
          ruleIndex++;
          policies.push(parseSinglePolicy(policyName, policyData, ['any'], ['any'], ruleIndex, warnings));
        }
      }
      continue;
    }

    // Parse "from-zone <src> to-zone <dst>"
    // The key format in tree could be nested: tree.security.policies["from-zone"]["<src>"]["to-zone"]["<dst>"]
    // Or it could be a single compound key depending on tokenization
    // Let's handle both cases

    if (key === 'from-zone') {
      // Nested format: security.policies.from-zone.<srcZone>.to-zone.<dstZone>.policy.<name>
      for (const [srcZone, srcData] of Object.entries(value)) {
        if (srcZone.startsWith('_') || !srcData || typeof srcData !== 'object') continue;
        const toZoneNode = srcData['to-zone'];
        if (!toZoneNode) continue;

        for (const [dstZone, dstData] of Object.entries(toZoneNode)) {
          if (dstZone.startsWith('_') || !dstData || typeof dstData !== 'object') continue;
          const policyNode = dstData.policy;
          if (!policyNode) continue;

          for (const [policyName, policyData] of Object.entries(policyNode)) {
            if (policyName.startsWith('_')) continue;
            ruleIndex++;
            policies.push(parseSinglePolicy(policyName, policyData, [srcZone], [dstZone], ruleIndex, warnings));
          }
        }
      }
    }
  }

  return policies;
}

/**
 * Parse a single security policy entry.
 */
function parseSinglePolicy(name, data, srcZones, dstZones, ruleIndex, warnings) {
  if (!data || typeof data !== 'object') {
    data = {};
  }

  const matchNode = data.match || {};

  // Source addresses
  const srcAddresses = collectKeys(matchNode['source-address']);
  // Destination addresses
  const dstAddresses = collectKeys(matchNode['destination-address']);
  // Applications
  const applications = collectKeys(matchNode.application);
  // Source identity (user/group references via JIMS)
  const sourceIdentity = collectKeys(matchNode['source-identity']);

  // Action
  let action = 'deny';
  const thenNode = data.then || {};
  if (thenNode.permit !== undefined) action = 'permit';
  else if (thenNode.deny !== undefined) action = 'deny';
  else if (thenNode.reject !== undefined) action = 'reject';

  // Logging
  let logStart = false;
  let logEnd = false;
  if (thenNode.log) {
    if (thenNode.log['session-init'] !== undefined) logStart = true;
    if (thenNode.log['session-close'] !== undefined) logEnd = true;
  }

  // Count: if thenNode.count exists, note it
  const hasCount = thenNode.count !== undefined;

  // Disabled
  const disabled = data._deactivated === true;

  // Description
  const description = extractStringValue(data.description) || '';

  // Security profiles from then → permit → application-services
  const security_profiles = {};
  let profileGroup = '';
  const appServices = thenNode.permit?.['application-services'] || thenNode['application-services'] || {};

  if (appServices['utm-policy']) {
    const utmPolicyName = extractStringValue(appServices['utm-policy']) ||
      Object.keys(appServices['utm-policy']).filter(k => !k.startsWith('_'))[0] || 'default';
    security_profiles['url-filtering'] = utmPolicyName;
    security_profiles['virus'] = utmPolicyName;
  }
  if (appServices['idp-policy']) {
    const idpPolicyName = extractStringValue(appServices['idp-policy']) ||
      Object.keys(appServices['idp-policy']).filter(k => !k.startsWith('_'))[0] || 'default';
    security_profiles['spyware'] = idpPolicyName;
    security_profiles['vulnerability'] = idpPolicyName;
  }

  // SSL Proxy profile detection
  let sslProxyProfile = '';
  if (appServices['ssl-proxy']) {
    const sslNode = appServices['ssl-proxy'];
    if (typeof sslNode === 'object' && sslNode['profile-name']) {
      sslProxyProfile = extractStringValue(sslNode['profile-name']);
    } else {
      sslProxyProfile = extractStringValue(sslNode);
    }
    if (sslProxyProfile) {
      security_profiles['decryption'] = sslProxyProfile;
    }
  }

  // Map SRX action to intermediate (PAN-OS-compatible) action
  const actionMap = { permit: 'allow', deny: 'deny', reject: 'reset-both' };
  const intermediateAction = actionMap[action] || action;

  // Scheduler
  const schedulerName = extractStringValue(data['scheduler-name']) || '';

  return {
    name,
    src_zones: srcZones,
    dst_zones: dstZones,
    src_addresses: srcAddresses.length > 0 ? srcAddresses : ['any'],
    dst_addresses: dstAddresses.length > 0 ? dstAddresses : ['any'],
    negate_source: isActiveStatement(matchNode['source-address-excluded']),
    negate_destination: isActiveStatement(matchNode['destination-address-excluded']),
    applications: applications.length > 0 ? applications : ['any'],
    services: ['application-default'],
    action: intermediateAction,
    log_start: logStart,
    log_end: logEnd,
    profile_group: profileGroup,
    security_profiles,
    description,
    tags: [],
    disabled,
    schedule: schedulerName,
    source_users: sourceIdentity.filter(id => id !== 'any'),
    _rule_index: ruleIndex,
    ...(sslProxyProfile ? { _srx_ssl_proxy_profile: sslProxyProfile } : {}),
  };
}

// ---------------------------------------------------------------------------
// NAT Rules Parser
// ---------------------------------------------------------------------------

function parseNatRules(tree, warnings) {
  const natNode = tree?.security?.nat;
  if (!natNode) return [];

  const rules = [];
  let ruleIndex = 0;

  // Source NAT
  if (natNode.source) {
    const ruleSets = natNode.source['rule-set'];
    if (ruleSets) {
      for (const [rsName, rsData] of Object.entries(ruleSets)) {
        if (rsName.startsWith('_') || !rsData || typeof rsData !== 'object') continue;

        const srcZones = collectKeys(rsData.from?.zone);
        const dstZones = collectKeys(rsData.to?.zone);

        const ruleNode = rsData.rule;
        if (!ruleNode) continue;

        for (const [ruleName, ruleData] of Object.entries(ruleNode)) {
          if (ruleName.startsWith('_') || !ruleData || typeof ruleData !== 'object') continue;
          ruleIndex++;

          const matchNode = ruleData.match || {};
          const srcAddrs = collectKeys(matchNode['source-address']);
          const dstAddrs = collectKeys(matchNode['destination-address']);

          let translatedSrc = null;
          const thenNode = ruleData.then || {};

          if (thenNode['source-nat']) {
            const snat = thenNode['source-nat'];
            if (snat.interface !== undefined) {
              translatedSrc = { type: 'interface', interface: '' };
            } else if (snat.pool) {
              const poolName = extractStringValue(snat.pool) ||
                Object.keys(snat.pool).filter(k => !k.startsWith('_'))[0] || '';
              translatedSrc = { type: 'dynamic-ip-pool', addresses: [poolName] };
            } else if (snat.off !== undefined) {
              translatedSrc = { type: 'no-nat' };
            }
          }

          rules.push({
            name: `${rsName}/${ruleName}`,
            type: 'source',
            src_zones: srcZones,
            dst_zones: dstZones,
            src_addresses: srcAddrs.length > 0 ? srcAddrs : ['any'],
            dst_addresses: dstAddrs.length > 0 ? dstAddrs : ['any'],
            translated_src: translatedSrc,
            translated_dst: null,
            translated_port: null,
            description: extractStringValue(ruleData.description) || '',
            _rule_index: ruleIndex,
          });
        }
      }
    }
  }

  // Destination NAT
  if (natNode.destination) {
    const ruleSets = natNode.destination['rule-set'];
    if (ruleSets) {
      for (const [rsName, rsData] of Object.entries(ruleSets)) {
        if (rsName.startsWith('_') || !rsData || typeof rsData !== 'object') continue;

        const srcZones = collectKeys(rsData.from?.zone);
        const dstZones = collectKeys(rsData.to?.zone);

        const ruleNode = rsData.rule;
        if (!ruleNode) continue;

        for (const [ruleName, ruleData] of Object.entries(ruleNode)) {
          if (ruleName.startsWith('_') || !ruleData || typeof ruleData !== 'object') continue;
          ruleIndex++;

          const matchNode = ruleData.match || {};
          const srcAddrs = collectKeys(matchNode['source-address']);
          const dstAddrs = collectKeys(matchNode['destination-address']);
          const dstPort = extractStringValue(matchNode['destination-port']) ||
            Object.keys(matchNode['destination-port'] || {}).filter(k => !k.startsWith('_'))[0] || null;

          let translatedDst = null;
          let translatedPort = null;
          const thenNode = ruleData.then || {};

          if (thenNode['destination-nat']) {
            const dnat = thenNode['destination-nat'];
            if (dnat.pool) {
              const poolNode = dnat.pool;
              const poolName = extractStringValue(poolNode) ||
                Object.keys(poolNode).filter(k => !k.startsWith('_'))[0] || '';
              translatedDst = poolName;
            }
          }

          rules.push({
            name: `${rsName}/${ruleName}`,
            type: 'destination',
            src_zones: srcZones,
            dst_zones: dstZones,
            src_addresses: srcAddrs.length > 0 ? srcAddrs : ['any'],
            dst_addresses: dstAddrs.length > 0 ? dstAddrs : ['any'],
            translated_src: null,
            translated_dst: translatedDst,
            translated_port: translatedPort,
            description: extractStringValue(ruleData.description) || '',
            _rule_index: ruleIndex,
          });
        }
      }
    }
  }

  // Static NAT
  if (natNode.static) {
    const ruleSets = natNode.static['rule-set'];
    if (ruleSets) {
      for (const [rsName, rsData] of Object.entries(ruleSets)) {
        if (rsName.startsWith('_') || !rsData || typeof rsData !== 'object') continue;

        const srcZones = collectKeys(rsData.from?.zone);
        const dstZones = collectKeys(rsData.to?.zone);

        const ruleNode = rsData.rule;
        if (!ruleNode) continue;

        for (const [ruleName, ruleData] of Object.entries(ruleNode)) {
          if (ruleName.startsWith('_') || !ruleData || typeof ruleData !== 'object') continue;
          ruleIndex++;

          const matchNode = ruleData.match || {};
          const dstAddrs = collectKeys(matchNode['destination-address']);

          let translatedSrc = null;
          const thenNode = ruleData.then || {};
          if (thenNode['static-nat']) {
            const staticNat = thenNode['static-nat'];
            if (staticNat.prefix) {
              const prefixKeys = Object.keys(staticNat.prefix).filter(k => !k.startsWith('_'));
              translatedSrc = { type: 'static', address: prefixKeys[0] || '' };
            }
          }

          rules.push({
            name: `${rsName}/${ruleName}`,
            type: 'static',
            src_zones: srcZones,
            dst_zones: dstZones,
            src_addresses: ['any'],
            dst_addresses: dstAddrs.length > 0 ? dstAddrs : ['any'],
            translated_src: translatedSrc,
            translated_dst: null,
            translated_port: null,
            description: extractStringValue(ruleData.description) || '',
            _rule_index: ruleIndex,
          });
        }
      }
    }
  }

  return rules;
}

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Scheduler Parser
// ---------------------------------------------------------------------------

/**
 * Parses SRX schedulers directly from set commands.
 *
 * Junos syntax:
 *   set schedulers scheduler <name> <day> start-time <HH:MM:SS> stop-time <HH:MM:SS>
 *   set schedulers scheduler <name> start-date "<datetime>" stop-date "<datetime>"
 *
 * Parses from raw commands instead of the config tree because the tree
 * nests `start-time <val> stop-time <val>` as a deep path, making extraction fragile.
 */
function parseSchedulers(setCommands, warnings) {
  const schedMap = {}; // name → { type, days: Set, start, end }

  const dayNames = new Set([
    'sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday',
    'daily', 'weekdays', 'weekend',
  ]);

  for (const cmd of setCommands) {
    if (!cmd.startsWith('set schedulers scheduler ')) continue;
    const rest = cmd.substring(24); // after "set schedulers scheduler "
    const tokens = tokenize(rest);
    if (tokens.length < 2) continue;

    const name = tokens[0];
    if (!schedMap[name]) {
      schedMap[name] = { type: 'unknown', days: new Set(), start: '', end: '' };
    }
    const sched = schedMap[name];

    // Check for one-time schedule
    if (tokens[1] === 'start-date' && tokens.length >= 3) {
      sched.type = 'onetime';
      sched.start = tokens[2];
      continue;
    }
    if (tokens[1] === 'stop-date' && tokens.length >= 3) {
      sched.type = 'onetime';
      sched.end = tokens[2];
      continue;
    }

    // Recurring schedule: <name> <day> start-time <val> stop-time <val>
    if (dayNames.has(tokens[1].toLowerCase())) {
      sched.type = 'recurring';
      sched.days.add(tokens[1].toLowerCase());

      // Extract start-time and stop-time from remaining tokens
      for (let i = 2; i < tokens.length - 1; i++) {
        if (tokens[i] === 'start-time') sched.start = tokens[i + 1];
        if (tokens[i] === 'stop-time') sched.end = tokens[i + 1];
      }
    }
  }

  const dayShortMap = { monday: 'Mon', tuesday: 'Tue', wednesday: 'Wed', thursday: 'Thu', friday: 'Fri', saturday: 'Sat', sunday: 'Sun', daily: 'Daily', weekdays: 'Weekdays', weekend: 'Weekend' };
  return Object.entries(schedMap).map(([name, s]) => ({
    name,
    type: s.type === 'unknown' ? 'recurring' : s.type,
    days: [...s.days].map(d => dayShortMap[d.toLowerCase()] || d),
    start: s.start,
    end: s.end,
  }));
}

/**
 * Extracts a string value from a tree node.
 * The value could be stored as a key (when tree was built from set commands).
 */
function extractStringValue(node) {
  if (!node) return '';
  if (typeof node === 'string') return node;
  if (typeof node === 'boolean') return '';
  if (typeof node === 'object') {
    if (node._value) return node._value;
    const keys = Object.keys(node).filter(k => !k.startsWith('_'));
    // If single key and its value is true, the key IS the value
    if (keys.length === 1 && node[keys[0]] === true) return keys[0];
    return keys[0] || '';
  }
  return String(node);
}

/**
 * Collects all non-underscore keys from a node (used for member lists).
 */
/** True when a statement is present and not deactivated (`deactivate` / `inactive:`). */
function isActiveStatement(node) {
  return node !== undefined && !node?._deactivated;
}

function collectKeys(node) {
  if (!node) return [];
  if (typeof node !== 'object') return [String(node)];
  return Object.keys(node).filter(k => !k.startsWith('_'));
}

/**
 * Find a value that looks like an IP address or subnet from object keys.
 */
function findKeyValue(data) {
  if (!data || typeof data !== 'object') return null;
  const keys = Object.keys(data).filter(k => !k.startsWith('_') && k !== 'description');
  for (const k of keys) {
    if (k.match(/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/)) return k;
    // IPv6
    if (k.includes(':') && k.match(/^[0-9a-fA-F:\/]+$/)) return k;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Static Route Parser
// ---------------------------------------------------------------------------

function parseSrxStaticRoutes(tree, warnings) {
  const staticRoutes = [];
  const routingContexts = [];

  // Global routing-options
  const globalRoutes = tree?.['routing-options']?.static?.route;
  if (globalRoutes && typeof globalRoutes === 'object') {
    for (const [dest, data] of Object.entries(globalRoutes)) {
      if (dest.startsWith('_')) continue;
      staticRoutes.push(buildSrxRoute(dest, data, '', ''));
    }
  }

  // Build default routing context
  routingContexts.push({
    name: 'default',
    type: 'default',
    virtual_routers: [],
    zones: [],
  });

  // Routing instances (VRFs)
  const instances = tree?.['routing-instances'];
  if (instances && typeof instances === 'object') {
    for (const [instName, instData] of Object.entries(instances)) {
      if (instName.startsWith('_') || typeof instData !== 'object') continue;

      const instRoutes = instData?.['routing-options']?.static?.route;
      if (instRoutes && typeof instRoutes === 'object') {
        for (const [dest, data] of Object.entries(instRoutes)) {
          if (dest.startsWith('_')) continue;
          staticRoutes.push(buildSrxRoute(dest, data, instName, instName));
        }
      }

      routingContexts.push({
        name: instName,
        type: 'default',
        virtual_routers: [{
          name: instName,
          interfaces: [],
          static_routes: instRoutes ? Object.entries(instRoutes)
            .filter(([k]) => !k.startsWith('_'))
            .map(([d, v]) => buildSrxRoute(d, v, instName, instName)) : [],
        }],
        zones: [],
      });
    }
  }

  return { staticRoutes, routingContexts };
}

function buildSrxRoute(dest, data, vrf, routingContext) {
  let nextHop = '';
  let nextHopType = 'ip-address';

  if (typeof data === 'string') {
    nextHop = data;
  } else if (typeof data === 'object') {
    if (data['next-hop']) {
      nextHop = extractStringValue(data['next-hop']);
    } else if (data.discard !== undefined) {
      nextHopType = 'discard';
    } else if (data.reject !== undefined) {
      nextHopType = 'discard';
    }
  }

  return {
    name: dest,
    destination: dest,
    next_hop: nextHop,
    next_hop_type: nextHopType,
    interface: '',
    metric: typeof data === 'object' && data.metric ? parseInt(extractStringValue(data.metric)) || 10 : 10,
    admin_distance: null,
    description: '',
    vrf,
    routing_context: routingContext,
  };
}

// ---------------------------------------------------------------------------
// BGP Configuration
// ---------------------------------------------------------------------------

/**
 * Parses BGP configuration from the SRX config tree.
 * Handles global `protocols bgp` and per-routing-instance BGP.
 */
function parseSrxBgpConfig(tree, warnings) {
  const bgpConfigs = [];

  // Global BGP
  const globalBgp = parseBgpFromSubTree(tree, '', warnings);
  if (globalBgp) bgpConfigs.push(globalBgp);

  // Per-routing-instance BGP
  const instances = tree?.['routing-instances'];
  if (instances && typeof instances === 'object') {
    for (const [instName, instData] of Object.entries(instances)) {
      if (instName.startsWith('_') || typeof instData !== 'object') continue;
      const instBgp = parseBgpFromSubTree(instData, instName, warnings);
      if (instBgp) bgpConfigs.push(instBgp);
    }
  }

  return bgpConfigs;
}

function parseBgpFromSubTree(tree, instance, warnings) {
  const bgpNode = tree?.protocols?.bgp;
  if (!bgpNode || typeof bgpNode !== 'object') return null;

  // Get AS number and router-id from routing-options
  const routingOpts = tree?.['routing-options'];
  const localAs = routingOpts?.['autonomous-system']
    ? parseInt(extractStringValue(routingOpts['autonomous-system'])) || null
    : null;
  const routerId = routingOpts?.['router-id']
    ? extractStringValue(routingOpts['router-id'])
    : '';

  // Parse peer groups
  const peerGroups = [];
  const groupNode = bgpNode.group;
  if (groupNode && typeof groupNode === 'object') {
    for (const [groupName, groupData] of Object.entries(groupNode)) {
      if (groupName.startsWith('_') || typeof groupData !== 'object') continue;
      peerGroups.push(parseBgpGroup(groupName, groupData));
    }
  }

  // Parse networks from policy-options (BGP network advertisements)
  const networks = [];
  const policyOpts = tree?.['policy-options']?.['policy-statement'];
  if (policyOpts && typeof policyOpts === 'object') {
    for (const [stmtName, stmtData] of Object.entries(policyOpts)) {
      if (stmtName.startsWith('_') || typeof stmtData !== 'object') continue;
      // Look for route-filter terms that indicate BGP network advertisements
      const terms = stmtData.term;
      if (terms && typeof terms === 'object') {
        for (const [termName, termData] of Object.entries(terms)) {
          if (termName.startsWith('_') || typeof termData !== 'object') continue;
          const rf = termData?.from?.['route-filter'];
          if (rf && typeof rf === 'object') {
            for (const [prefix, rfData] of Object.entries(rf)) {
              if (prefix.startsWith('_')) continue;
              networks.push({ prefix, policy: stmtName });
            }
          }
        }
      }
    }
  }

  // Parse redistribution from export policies
  const redistribute = [];
  const exportPolicies = bgpNode.export;
  if (exportPolicies) {
    // Export policies reference policy-statements; check for redistribution patterns
    const exportList = typeof exportPolicies === 'string' ? [exportPolicies] :
      (Array.isArray(exportPolicies) ? exportPolicies : Object.keys(exportPolicies).filter(k => !k.startsWith('_')));
    for (const policyName of exportList) {
      if (policyOpts?.[policyName]) {
        const stmt = policyOpts[policyName];
        const terms = stmt?.term;
        if (terms && typeof terms === 'object') {
          for (const [tName, tData] of Object.entries(terms)) {
            if (tName.startsWith('_') || typeof tData !== 'object') continue;
            const proto = tData?.from?.protocol;
            if (proto) {
              const protoName = extractStringValue(proto);
              if (protoName && !redistribute.find(r => r.protocol === protoName)) {
                redistribute.push({ protocol: protoName, policy: policyName });
              }
            }
          }
        }
      }
    }
  }

  if (peerGroups.length === 0 && !localAs) return null;

  return {
    instance,
    local_as: localAs,
    router_id: routerId,
    peer_groups: peerGroups,
    networks,
    redistribute,
  };
}

function parseBgpGroup(groupName, groupData) {
  const typeVal = extractStringValue(groupData.type) || '';
  const neighbors = [];

  const neighborNode = groupData.neighbor;
  if (neighborNode && typeof neighborNode === 'object') {
    for (const [addr, nData] of Object.entries(neighborNode)) {
      if (addr.startsWith('_')) continue;
      const nObj = typeof nData === 'object' ? nData : {};
      neighbors.push({
        address: addr,
        peer_as: nObj['peer-as'] ? parseInt(extractStringValue(nObj['peer-as'])) || null : null,
        description: nObj.description ? extractStringValue(nObj.description) : '',
        update_source: '',
        local_address: nObj['local-address'] ? extractStringValue(nObj['local-address']) : '',
        import_policy: nObj.import ? extractStringValue(nObj.import) : '',
        export_policy: nObj.export ? extractStringValue(nObj.export) : '',
        authentication_key: nObj['authentication-key'] ? extractStringValue(nObj['authentication-key']) : '',
        enabled: true,
      });
    }
  }

  return {
    name: groupName,
    type: typeVal === 'external' ? 'external' : typeVal === 'internal' ? 'internal' : typeVal || 'external',
    neighbors,
  };
}

// ---------------------------------------------------------------------------
// OSPF Configuration
// ---------------------------------------------------------------------------

/**
 * Parses OSPFv2 configuration from the SRX config tree.
 * Handles global `protocols ospf` and per-routing-instance OSPF.
 */
function parseSrxOspfConfig(tree, warnings) {
  const ospfConfigs = [];

  // Global OSPF
  const globalOspf = parseOspfFromSubTree(tree, '', warnings);
  if (globalOspf) ospfConfigs.push(globalOspf);

  // Per-routing-instance OSPF
  const instances = tree?.['routing-instances'];
  if (instances && typeof instances === 'object') {
    for (const [instName, instData] of Object.entries(instances)) {
      if (instName.startsWith('_') || typeof instData !== 'object') continue;
      const instOspf = parseOspfFromSubTree(instData, instName, warnings);
      if (instOspf) ospfConfigs.push(instOspf);
    }
  }

  return ospfConfigs;
}

function parseOspfFromSubTree(tree, instance, warnings) {
  const ospfNode = tree?.protocols?.ospf;
  if (!ospfNode || typeof ospfNode !== 'object') return null;

  // Get router-id from routing-options
  const routingOpts = tree?.['routing-options'];
  const routerId = routingOpts?.['router-id']
    ? extractStringValue(routingOpts['router-id'])
    : '';

  const refBw = ospfNode['reference-bandwidth']
    ? extractStringValue(ospfNode['reference-bandwidth'])
    : null;

  // Parse areas
  const areas = [];
  const areaNode = ospfNode.area;
  if (areaNode && typeof areaNode === 'object') {
    for (const [areaId, areaData] of Object.entries(areaNode)) {
      if (areaId.startsWith('_') || typeof areaData !== 'object') continue;
      areas.push(parseOspfArea(areaId, areaData));
    }
  }

  // Parse redistribution from export policies
  const redistribute = [];
  const exportPolicy = ospfNode.export;
  if (exportPolicy) {
    const policyOpts = tree?.['policy-options']?.['policy-statement'];
    const exportList = typeof exportPolicy === 'string' ? [exportPolicy] :
      (Array.isArray(exportPolicy) ? exportPolicy : Object.keys(exportPolicy).filter(k => !k.startsWith('_')));
    for (const policyName of exportList) {
      if (policyOpts?.[policyName]) {
        const stmt = policyOpts[policyName];
        const terms = stmt?.term;
        if (terms && typeof terms === 'object') {
          for (const [tName, tData] of Object.entries(terms)) {
            if (tName.startsWith('_') || typeof tData !== 'object') continue;
            const proto = tData?.from?.protocol;
            if (proto) {
              const protoName = extractStringValue(proto);
              if (protoName && !redistribute.find(r => r.protocol === protoName)) {
                const metricType = tData?.then?.['external']?.type
                  ? extractStringValue(tData.then.external.type) : null;
                redistribute.push({ protocol: protoName, policy: policyName, metric_type: metricType });
              }
            }
          }
        }
      }
    }
  }

  if (areas.length === 0) return null;

  return {
    instance,
    router_id: routerId,
    reference_bandwidth: refBw,
    areas,
    redistribute,
  };
}

function parseOspfArea(areaId, areaData) {
  // Determine area type
  let areaType = 'normal';
  if (areaData.stub !== undefined) {
    areaType = areaData.stub?.['no-summaries'] !== undefined ? 'totally-stub' : 'stub';
  } else if (areaData.nssa !== undefined) {
    areaType = areaData.nssa?.['no-summaries'] !== undefined ? 'totally-nssa' : 'nssa';
  }

  // Parse interfaces
  const interfaces = [];
  const ifaceNode = areaData.interface;
  if (ifaceNode && typeof ifaceNode === 'object') {
    for (const [ifName, ifData] of Object.entries(ifaceNode)) {
      if (ifName.startsWith('_')) continue;
      const ifObj = typeof ifData === 'object' ? ifData : {};
      interfaces.push({
        name: ifName,
        cost: ifObj.metric ? parseInt(extractStringValue(ifObj.metric)) || null : null,
        hello_interval: ifObj['hello-interval'] ? parseInt(extractStringValue(ifObj['hello-interval'])) || null : null,
        dead_interval: ifObj['dead-interval'] ? parseInt(extractStringValue(ifObj['dead-interval'])) || null : null,
        authentication: parseOspfAuth(ifObj),
        passive: ifObj.passive !== undefined,
        network_type: ifObj['interface-type'] ? extractStringValue(ifObj['interface-type']) : null,
      });
    }
  }

  return {
    area_id: areaId,
    area_type: areaType,
    interfaces,
    networks: [],
  };
}

function parseOspfAuth(ifData) {
  const authNode = ifData?.authentication;
  if (!authNode || typeof authNode !== 'object') return null;
  if (authNode.md5) {
    // md5 keys are under authentication > md5 > <key-id> > key
    const md5Node = authNode.md5;
    if (typeof md5Node === 'object') {
      for (const [keyId, keyData] of Object.entries(md5Node)) {
        if (keyId.startsWith('_')) continue;
        const key = typeof keyData === 'object' && keyData.key
          ? extractStringValue(keyData.key) : '';
        return { type: 'md5', key_id: parseInt(keyId) || 1, key };
      }
    }
    return { type: 'md5', key_id: 1, key: '' };
  }
  if (authNode['simple-password']) {
    return { type: 'simple', key: extractStringValue(authNode['simple-password']) };
  }
  return null;
}

// ---------------------------------------------------------------------------
// OSPFv3 (IPv6 OSPF) Configuration
// ---------------------------------------------------------------------------

/**
 * Parses OSPFv3 configuration from the SRX config tree.
 * SRX uses `set protocols ospf3` as a separate stanza from `set protocols ospf`.
 */
function parseSrxOspf3Config(tree, warnings) {
  const ospf3Configs = [];

  // Global OSPFv3
  const globalOspf3 = parseOspf3FromSubTree(tree, '', warnings);
  if (globalOspf3) ospf3Configs.push(globalOspf3);

  // Per-routing-instance OSPFv3
  const instances = tree?.['routing-instances'];
  if (instances && typeof instances === 'object') {
    for (const [instName, instData] of Object.entries(instances)) {
      if (instName.startsWith('_') || typeof instData !== 'object') continue;
      const instOspf3 = parseOspf3FromSubTree(instData, instName, warnings);
      if (instOspf3) ospf3Configs.push(instOspf3);
    }
  }

  return ospf3Configs;
}

function parseOspf3FromSubTree(tree, instance, warnings) {
  const ospf3Node = tree?.protocols?.ospf3;
  if (!ospf3Node || typeof ospf3Node !== 'object') return null;

  const routingOpts = tree?.['routing-options'];
  const routerId = routingOpts?.['router-id']
    ? extractStringValue(routingOpts['router-id'])
    : '';

  const refBw = ospf3Node['reference-bandwidth']
    ? extractStringValue(ospf3Node['reference-bandwidth'])
    : null;

  // Parse areas
  const areas = [];
  const areaNode = ospf3Node.area;
  if (areaNode && typeof areaNode === 'object') {
    for (const [areaId, areaData] of Object.entries(areaNode)) {
      if (areaId.startsWith('_') || typeof areaData !== 'object') continue;
      areas.push(parseOspf3Area(areaId, areaData));
    }
  }

  // Parse redistribution from export policies
  const redistribute = [];
  const exportPolicy = ospf3Node.export;
  if (exportPolicy) {
    const policyOpts = tree?.['policy-options']?.['policy-statement'];
    const exportList = typeof exportPolicy === 'string' ? [exportPolicy] :
      (Array.isArray(exportPolicy) ? exportPolicy : Object.keys(exportPolicy).filter(k => !k.startsWith('_')));
    for (const policyName of exportList) {
      if (policyOpts?.[policyName]) {
        const stmt = policyOpts[policyName];
        const terms = stmt?.term;
        if (terms && typeof terms === 'object') {
          for (const [tName, tData] of Object.entries(terms)) {
            if (tName.startsWith('_') || typeof tData !== 'object') continue;
            const proto = tData?.from?.protocol;
            if (proto) {
              const protoName = extractStringValue(proto);
              if (protoName && !redistribute.find(r => r.protocol === protoName)) {
                const metricType = tData?.then?.['external']?.type
                  ? extractStringValue(tData.then.external.type) : null;
                redistribute.push({ protocol: protoName, policy: policyName, metric_type: metricType });
              }
            }
          }
        }
      }
    }
  }

  if (areas.length === 0) return null;

  return {
    instance,
    router_id: routerId,
    reference_bandwidth: refBw,
    areas,
    redistribute,
  };
}

function parseOspf3Area(areaId, areaData) {
  let areaType = 'normal';
  if (areaData.stub !== undefined) {
    areaType = areaData.stub?.['no-summaries'] !== undefined ? 'totally-stub' : 'stub';
  } else if (areaData.nssa !== undefined) {
    areaType = areaData.nssa?.['no-summaries'] !== undefined ? 'totally-nssa' : 'nssa';
  }

  const interfaces = [];
  const ifaceNode = areaData.interface;
  if (ifaceNode && typeof ifaceNode === 'object') {
    for (const [ifName, ifData] of Object.entries(ifaceNode)) {
      if (ifName.startsWith('_')) continue;
      const ifObj = typeof ifData === 'object' ? ifData : {};
      interfaces.push({
        name: ifName,
        cost: ifObj.metric ? parseInt(extractStringValue(ifObj.metric)) || null : null,
        hello_interval: ifObj['hello-interval'] ? parseInt(extractStringValue(ifObj['hello-interval'])) || null : null,
        dead_interval: ifObj['dead-interval'] ? parseInt(extractStringValue(ifObj['dead-interval'])) || null : null,
        passive: ifObj.passive !== undefined,
        network_type: ifObj['interface-type'] ? extractStringValue(ifObj['interface-type']) : null,
        instance_id: ifObj['instance-id'] ? parseInt(extractStringValue(ifObj['instance-id'])) || null : null,
      });
    }
  }

  return { area_id: areaId, area_type: areaType, interfaces, networks: [] };
}

// ---------------------------------------------------------------------------
// EVPN Configuration
// ---------------------------------------------------------------------------

/**
 * Parses EVPN configuration from the SRX config tree.
 * Reads: protocols > evpn, switch-options, vlans, routing-instances (mac-vrf).
 */
function parseSrxEvpnConfig(tree, warnings) {
  const evpnConfigs = [];

  // Global EVPN
  const globalEvpn = parseEvpnFromSubTree(tree, '', warnings);
  if (globalEvpn) evpnConfigs.push(globalEvpn);

  // Per-routing-instance EVPN (mac-vrf)
  const instances = tree?.['routing-instances'];
  if (instances && typeof instances === 'object') {
    for (const [instName, instData] of Object.entries(instances)) {
      if (instName.startsWith('_') || typeof instData !== 'object') continue;
      const instEvpn = parseEvpnFromSubTree(instData, instName, warnings);
      if (instEvpn) evpnConfigs.push(instEvpn);
    }
  }

  return evpnConfigs;
}

function parseEvpnFromSubTree(tree, instance, warnings) {
  const evpnNode = tree?.protocols?.evpn;
  const switchOpts = tree?.['switch-options'];
  const vlansNode = tree?.vlans;

  // Need at least evpn protocol or switch-options with vtep
  if (!evpnNode && !switchOpts) return null;
  if (!evpnNode) return null;

  const encap = evpnNode.encapsulation
    ? extractStringValue(evpnNode.encapsulation) : 'vxlan';
  const mcastMode = evpnNode['multicast-mode']
    ? extractStringValue(evpnNode['multicast-mode']) : null;

  // Extended VNI list
  const extVniList = [];
  const extVniNode = evpnNode['extended-vni-list'];
  if (extVniNode) {
    const vniStr = extractStringValue(extVniNode);
    if (vniStr) {
      // Can be space-separated or single value
      vniStr.split(/\s+/).forEach(v => {
        const n = parseInt(v);
        if (n) extVniList.push(n);
      });
    }
  }

  // Instance type from routing-instance
  const instType = tree?.['instance-type']
    ? extractStringValue(tree['instance-type']) : '';

  // Switch-options: route-distinguisher, vrf-target, vtep-source-interface
  const rd = switchOpts?.['route-distinguisher']
    ? extractStringValue(switchOpts['route-distinguisher']) : '';
  const vrfTarget = switchOpts?.['vrf-target']
    ? extractStringValue(switchOpts['vrf-target']) : null;

  // Parse route-targets from vrf-target or explicit vrf-import/vrf-export
  const routeTargets = [];
  if (vrfTarget) {
    routeTargets.push({ target: vrfTarget, direction: 'both' });
  }

  // Parse VLANs with VxLAN VNI mappings
  const vlans = [];
  if (vlansNode && typeof vlansNode === 'object') {
    for (const [vlanName, vlanData] of Object.entries(vlansNode)) {
      if (vlanName.startsWith('_') || typeof vlanData !== 'object') continue;
      const vxlanNode = vlanData.vxlan;
      if (!vxlanNode) continue;
      const vlanId = vlanData['vlan-id'] ? parseInt(extractStringValue(vlanData['vlan-id'])) || 0 : 0;
      const vni = vxlanNode.vni ? parseInt(extractStringValue(vxlanNode.vni)) || 0 : 0;
      if (vni) {
        vlans.push({
          name: vlanName,
          vlan_id: vlanId,
          vni,
          ingress_node_replication: vxlanNode['ingress-node-replication'] !== undefined,
        });
      }
    }
  }

  if (vlans.length === 0 && extVniList.length === 0) return null;

  return {
    instance,
    instance_type: instType || 'mac-vrf',
    encapsulation: encap,
    multicast_mode: mcastMode,
    extended_vni_list: extVniList,
    route_distinguisher: rd,
    route_targets: routeTargets,
    vrf_target: vrfTarget,
    vlans,
  };
}

// ---------------------------------------------------------------------------
// VxLAN Configuration
// ---------------------------------------------------------------------------

/**
 * Parses standalone VxLAN tunnel configuration from the SRX config tree.
 * Reads: switch-options > vtep-source-interface, interfaces > vtep.
 */
function parseSrxVxlanConfig(tree, warnings) {
  const vxlanConfigs = [];

  const switchOpts = tree?.['switch-options'];
  const vtepSource = switchOpts?.['vtep-source-interface']
    ? extractStringValue(switchOpts['vtep-source-interface']) : '';

  // Check for VTEP interface config
  const vtepIf = tree?.interfaces?.vtep;
  if (!vtepIf && !vtepSource) return vxlanConfigs;

  // Collect VNIs from vlans that have vxlan config
  const vnis = [];
  const vlansNode = tree?.vlans;
  if (vlansNode && typeof vlansNode === 'object') {
    for (const [vlanName, vlanData] of Object.entries(vlansNode)) {
      if (vlanName.startsWith('_') || typeof vlanData !== 'object') continue;
      const vxlanNode = vlanData.vxlan;
      if (!vxlanNode) continue;
      const vni = vxlanNode.vni ? parseInt(extractStringValue(vxlanNode.vni)) || 0 : 0;
      const vlanId = vlanData['vlan-id'] ? parseInt(extractStringValue(vlanData['vlan-id'])) || 0 : 0;
      if (vni) {
        vnis.push({
          vni,
          vlan_id: vlanId || null,
          mcast_group: null,
          ingress_replication: vxlanNode['ingress-node-replication'] !== undefined,
          remote_vteps: [],
        });
      }
    }
  }

  if (vtepSource || vnis.length > 0) {
    vxlanConfigs.push({
      name: 'vtep',
      instance: '',
      vtep_source_interface: vtepSource,
      vnis,
      udp_port: 4789,
      source_interface: vtepSource,
    });
  }

  return vxlanConfigs;
}

// ---------------------------------------------------------------------------
// HA (Chassis Cluster) Configuration
// ---------------------------------------------------------------------------
// Screen / DDoS Protection Parser
// ---------------------------------------------------------------------------

/**
 * Parses SRX screen (ids-option) config into the screen_config schema.
 * Screens at: security > screen > ids-option > <screen-name>
 * Zone assignment: security > zones > security-zone > <zone-name> > screen
 */
function parseSrxScreenConfig(tree, zones, warnings) {
  const screenConfigs = [];

  const idsOptions = tree?.security?.screen?.['ids-option'];
  if (!idsOptions || typeof idsOptions !== 'object') return screenConfigs;

  // Build map of zone → screen name from zone config
  const zoneToScreen = {};
  const zonesNode = tree?.security?.zones?.['security-zone'];
  if (zonesNode && typeof zonesNode === 'object') {
    for (const [zoneName, zoneData] of Object.entries(zonesNode)) {
      if (typeof zoneData !== 'object' || zoneName.startsWith('_')) continue;
      if (zoneData.screen) {
        const screenName = extractStringValue(zoneData.screen);
        if (screenName) {
          zoneToScreen[screenName] = zoneName;
        }
      }
    }
  }

  for (const [screenName, screenData] of Object.entries(idsOptions)) {
    if (typeof screenData !== 'object' || screenName.startsWith('_')) continue;

    const icmpNode = screenData.icmp || {};
    const tcpNode = screenData.tcp || {};
    const udpNode = screenData.udp || {};
    const ipNode = screenData.ip || {};
    const limitNode = screenData['limit-session'] || {};

    const screen = {
      name: screenName,
      zone: zoneToScreen[screenName] || '',
      icmp: {
        flood_threshold: parseInt(extractStringValue(icmpNode['flood']?.threshold)) || null,
        ping_death: !!(icmpNode['ping-death'] === true || icmpNode['ping-death'] === 'true'),
        fragment: !!(icmpNode['fragment'] === true || icmpNode['fragment'] === 'true'),
      },
      tcp: {
        syn_flood_threshold: null,
        syn_flood_timeout: null,
        land_attack: !!(tcpNode['land'] === true || tcpNode['land'] === 'true'),
        winnuke: !!(tcpNode['winnuke'] === true || tcpNode['winnuke'] === 'true'),
        tcp_no_flag: !!(tcpNode['tcp-no-flag'] === true || tcpNode['tcp-no-flag'] === 'true'),
      },
      udp: {
        flood_threshold: parseInt(extractStringValue(udpNode['flood']?.threshold)) || null,
      },
      ip: {
        spoofing: !!(ipNode['spoofing'] === true || ipNode['spoofing'] === 'true'),
        source_route: !!(ipNode['source-route-option'] === true || ipNode['source-route-option'] === 'true'),
        tear_drop: !!(ipNode['tear-drop'] === true || ipNode['tear-drop'] === 'true'),
        record_route: !!(ipNode['record-route-option'] === true || ipNode['record-route-option'] === 'true'),
        timestamp: !!(ipNode['timestamp-option'] === true || ipNode['timestamp-option'] === 'true'),
      },
      limit_session: {
        source_based: parseInt(extractStringValue(limitNode['source-ip-based'])) || null,
        destination_based: parseInt(extractStringValue(limitNode['destination-ip-based'])) || null,
      },
      description: '',
    };

    // Parse SYN flood sub-tree
    const synFlood = tcpNode['syn-flood'];
    if (synFlood && typeof synFlood === 'object') {
      screen.tcp.syn_flood_threshold =
        parseInt(extractStringValue(synFlood['attack-threshold'])) ||
        parseInt(extractStringValue(synFlood['alarm-threshold'])) ||
        null;
      screen.tcp.syn_flood_timeout =
        parseInt(extractStringValue(synFlood['timeout'])) || null;
    }

    // Parse ICMP ip-sweep threshold (maps to icmp flood_threshold if not already set)
    const ipSweep = icmpNode['ip-sweep'];
    if (ipSweep && typeof ipSweep === 'object' && !screen.icmp.flood_threshold) {
      screen.icmp.flood_threshold = parseInt(extractStringValue(ipSweep.threshold)) || null;
    }

    screenConfigs.push(screen);
  }

  if (screenConfigs.length > 0) {
    warnings.push(createWarning('info', 'screen-config',
      `Parsed ${screenConfigs.length} screen ids-option profile(s)`,
      'Review screen/DDoS settings in the generated config'));
  }

  return screenConfigs;
}


// ---------------------------------------------------------------------------

function parseSrxHaConfig(tree, warnings) {
  const chassis = tree['chassis'];
  if (!chassis) return null;
  const cluster = chassis['cluster'];
  if (!cluster) return null;

  const clusterId = parseInt(extractStringValue(cluster['cluster-id'])) || 1;

  // Redundancy groups
  const haInterfaces = [];
  const rg = cluster['redundancy-group'];
  let primaryPriority = 200;
  if (rg && typeof rg === 'object') {
    for (const [rgId, rgData] of Object.entries(rg)) {
      if (typeof rgData !== 'object') continue;
      const node = rgData['node'];
      if (node && typeof node === 'object') {
        for (const [nodeId, nodeData] of Object.entries(node)) {
          if (typeof nodeData !== 'object') continue;
          const prio = parseInt(extractStringValue(nodeData['priority']));
          if (nodeId === '0' && rgId === '0' && prio) primaryPriority = prio;
        }
      }
    }
  }

  // Fabric interfaces
  const interfaces = tree['interfaces'] || {};
  for (const ifName of ['fab0', 'fab1']) {
    const fab = interfaces[ifName];
    if (fab && typeof fab === 'object') {
      const opts = fab['fabric-options'] || {};
      const members = opts['member-interfaces'];
      haInterfaces.push({
        name: ifName,
        ip: '',
        netmask: '',
        interface: members ? (typeof members === 'string' ? members : Object.keys(members)[0] || '') : '',
      });
    }
  }

  // Control link (fxp0 for management, fxp1 for control)
  for (const ifName of ['fxp0', 'fxp1']) {
    const fxp = interfaces[ifName];
    if (fxp && typeof fxp === 'object') {
      haInterfaces.push({
        name: ifName,
        ip: '',
        netmask: '',
        interface: ifName,
      });
    }
  }

  return {
    enabled: true,
    mode: 'cluster',
    group_id: clusterId,
    priority: primaryPriority,
    preempt: false,
    peer_ip: '',
    ha_interfaces: haInterfaces,
    monitoring: { link_groups: [], path_groups: [] },
    description: `SRX chassis cluster id ${clusterId}`,
  };
}

/**
 * Extract Junos version from tree.
 */

// ---------------------------------------------------------------------------
// VPN / IPsec Tunnel Parser
// ---------------------------------------------------------------------------

/**
 * Parses Junos SRX VPN/IPsec configuration from the config tree.
 * IKE: tree.security.ike (proposals, policies, gateways)
 * IPsec: tree.security.ipsec (proposals, policies, vpns)
 */
function parseSrxVpnConfig(tree, warnings) {
  const vpnTunnels = [];
  const ikeNode = tree && tree.security ? tree.security.ike : null;
  const ipsecNode = tree && tree.security ? tree.security.ipsec : null;

  // ---- IKE proposals ----
  const ikeProposals = {};
  if (ikeNode && ikeNode.proposal) {
    for (const [name, data] of Object.entries(ikeNode.proposal)) {
      if (name.startsWith('_') || typeof data !== 'object') continue;
      ikeProposals[name] = {
        name,
        auth_method: extractStringValue(data['authentication-method']) || 'pre-shared-keys',
        dh_group: extractStringValue(data['dh-group']) || 'group14',
        encryption: extractStringValue(data['encryption-algorithm']) || 'aes-256-cbc',
        authentication: extractStringValue(data['authentication-algorithm']) || 'sha-256',
        lifetime: parseInt(extractStringValue(data['lifetime-seconds']), 10) || 28800,
      };
    }
  }

  // ---- IKE policies ----
  const ikePolicies = {};
  if (ikeNode && ikeNode.policy) {
    for (const [name, data] of Object.entries(ikeNode.policy)) {
      if (name.startsWith('_') || typeof data !== 'object') continue;
      const proposalRefs = collectKeys(data.proposals);
      const hasPsk = data['pre-shared-key'];
      if (hasPsk) {
        warnings.push(createWarning(
          'info', 'ike-policy/' + name,
          'IKE policy ' + name + ' pre-shared key sanitized',
          'Pre-shared keys are never included in parsed output'
        ));
      }
      ikePolicies[name] = {
        name,
        mode: extractStringValue(data.mode) || 'main',
        proposals: proposalRefs,
      };
    }
  }


  // ---- IKE gateways ----
  const ikeGateways = {};
  if (ikeNode && ikeNode.gateway) {
    for (const [name, data] of Object.entries(ikeNode.gateway)) {
      if (name.startsWith('_') || typeof data !== 'object') continue;
      const address = extractStringValue(data.address);
      const extInterface = extractStringValue(data['external-interface']);
      const ikePolicyRef = extractStringValue(data['ike-policy']);
      const policy = ikePolicies[ikePolicyRef];
      const ikeVersion = data.version ? extractStringValue(data.version) : 'v2';

      ikeGateways[name] = {
        name, address,
        local_address: extInterface,
        pre_shared_key: 'SANITIZED',
        ike_version: ikeVersion.startsWith('v') ? ikeVersion : 'v' + ikeVersion,
        proposal: ikePolicyRef,
        _proposalRefs: policy ? policy.proposals : [],
      };
    }
  }

  // ---- IPsec proposals ----
  const ipsecProposals = {};
  if (ipsecNode && ipsecNode.proposal) {
    for (const [name, data] of Object.entries(ipsecNode.proposal)) {
      if (name.startsWith('_') || typeof data !== 'object') continue;
      ipsecProposals[name] = {
        name,
        protocol: extractStringValue(data.protocol) || 'esp',
        encryption: extractStringValue(data['encryption-algorithm']) || 'aes-256-cbc',
        authentication: extractStringValue(data['authentication-algorithm']) || 'hmac-sha-256-128',
        lifetime: parseInt(extractStringValue(data['lifetime-seconds']), 10) || 3600,
        pfs_group: 'group14',
      };
    }
  }

  // ---- IPsec policies ----
  const ipsecPolicies = {};
  if (ipsecNode && ipsecNode.policy) {
    for (const [name, data] of Object.entries(ipsecNode.policy)) {
      if (name.startsWith('_') || typeof data !== 'object') continue;
      const pfsNode = data['perfect-forward-secrecy'];
      const pfs = pfsNode ? pfsNode.keys : null;
      const proposalRefs = collectKeys(data.proposals);
      ipsecPolicies[name] = {
        name,
        pfs_group: pfs ? extractStringValue(pfs) : 'group14',
        proposals: proposalRefs,
      };
    }
  }


  // ---- IPsec VPNs ----
  if (ipsecNode && ipsecNode.vpn) {
    for (const [name, data] of Object.entries(ipsecNode.vpn)) {
      if (name.startsWith('_') || typeof data !== 'object') continue;

      const bindInterface = extractStringValue(data['bind-interface']);
      const ikeData = data.ike || {};
      const gwRef = extractStringValue(ikeData.gateway);
      const ipsecPolicyRef = extractStringValue(ikeData['ipsec-policy']);

      // Traffic selectors
      const proxyIds = [];
      const tsNode = data['traffic-selector'];
      if (tsNode && typeof tsNode === 'object') {
        for (const [tsName, tsData] of Object.entries(tsNode)) {
          if (tsName.startsWith('_') || typeof tsData !== 'object') continue;
          proxyIds.push({
            local: extractStringValue(tsData['local-ip']) || '',
            remote: extractStringValue(tsData['remote-ip']) || '',
            protocol: 'any',
          });
        }
      }

      // Resolve gateway
      const gw = ikeGateways[gwRef] || {
        name: gwRef, address: '', local_address: '',
        pre_shared_key: 'SANITIZED', ike_version: 'v2', proposal: '', _proposalRefs: [],
      };

      // Resolve IKE proposal
      const firstIkeProposalName = gw._proposalRefs && gw._proposalRefs[0] ? gw._proposalRefs[0] : '';
      const ikeProposal = ikeProposals[firstIkeProposalName] || {
        name: firstIkeProposalName || 'default',
        auth_method: 'pre-shared-keys', dh_group: 'group14',
        encryption: 'aes-256-cbc', authentication: 'sha-256', lifetime: 28800,
      };

      // Resolve IPsec proposal
      const ipsecPolicy = ipsecPolicies[ipsecPolicyRef];
      const firstIpsecProposalName = ipsecPolicy && ipsecPolicy.proposals[0] ? ipsecPolicy.proposals[0] : '';
      const ipsecProposal = ipsecProposals[firstIpsecProposalName] || {
        name: firstIpsecProposalName || 'default', protocol: 'esp',
        encryption: 'aes-256-cbc', authentication: 'hmac-sha-256-128',
        lifetime: 3600, pfs_group: 'group14',
      };
      if (ipsecPolicy && ipsecPolicy.pfs_group) {
        ipsecProposal.pfs_group = ipsecPolicy.pfs_group;
      }

      vpnTunnels.push({
        name,
        ike_gateway: {
          name: gw.name, address: gw.address, local_address: gw.local_address,
          pre_shared_key: 'SANITIZED', ike_version: gw.ike_version, proposal: gw.proposal,
        },
        ike_proposal: ikeProposal,
        ipsec_proposal: ipsecProposal,
        proxy_id: proxyIds,
        tunnel_interface: bindInterface,
        description: '',
      });
    }
  }

  if (vpnTunnels.length > 0) {
    warnings.push(createWarning(
      'info', 'vpn',
      'Parsed ' + vpnTunnels.length + ' VPN/IPsec tunnel(s)',
      'VPN tunnel configuration detected and included in intermediate output'
    ));
  }

  return vpnTunnels;
}


function extractVersion(tree) {
  // version statement
  if (tree.version) {
    return extractStringValue(tree.version);
  }
  // system host-name can help identify
  if (tree.system?.['host-name']) {
    return 'unknown (host: ' + extractStringValue(tree.system['host-name']) + ')';
  }
  return 'unknown';
}


// ---------------------------------------------------------------------------
// Syslog Configuration Parser
// ---------------------------------------------------------------------------

function parseSrxSyslogConfig(tree, warnings) {
  const servers = [];
  const syslog = tree.system?.syslog;
  if (!syslog) return servers;

  // SRX: set system syslog host <ip> <facility> <level>
  const hosts = syslog.host;
  if (hosts && typeof hosts === 'object') {
    for (const [hostAddr, hostConfig] of Object.entries(hosts)) {
      if (typeof hostConfig !== 'object') continue;
      const rawTransport = hostConfig['transport']?.protocol;
      const transport = typeof rawTransport === 'object' ? Object.keys(rawTransport)[0] || 'udp' : rawTransport || 'udp';
      const rawPort = hostConfig.port;
      const port = parseInt(typeof rawPort === 'object' ? Object.keys(rawPort)[0] || '514' : rawPort || (hostConfig['transport']?.['tls-profile'] ? '6514' : '514'), 10);

      // Parse facility/severity pairs
      const facilities = [];
      for (const [key, val] of Object.entries(hostConfig)) {
        if (['transport', 'port', 'source-address', 'structured-data'].includes(key)) continue;
        if (typeof val === 'string') {
          facilities.push({ facility: key, level: val });
        } else if (typeof val === 'object') {
          facilities.push({ facility: key, level: Object.keys(val)[0] || 'any' });
        }
      }

      servers.push({
        name: `syslog-${hostAddr}`,
        server: hostAddr,
        port,
        transport,
        facilities,
        source_address: hostConfig['source-address'] || '',
        structured_data: !!hostConfig['structured-data'],
      });
    }
  }

  // SRX: set system syslog file <name> <facility> <level>
  const files = syslog.file;
  if (files && typeof files === 'object') {
    for (const [fileName, fileConfig] of Object.entries(files)) {
      if (typeof fileConfig !== 'object') continue;
      const facilities = [];
      for (const [key, val] of Object.entries(fileConfig)) {
        if (['archive', 'match', 'structured-data'].includes(key)) continue;
        if (typeof val === 'string') {
          facilities.push({ facility: key, level: val });
        }
      }
      servers.push({
        name: `file-${fileName}`,
        server: `file:${fileName}`,
        port: 0,
        transport: 'file',
        facilities,
      });
    }
  }

  if (servers.length > 0) {
    warnings.push(createWarning('info', 'syslog', `Parsed ${servers.length} syslog destination(s)`, 'Syslog configuration detected'));
  }
  return servers;
}


// ---------------------------------------------------------------------------
// SNMP Configuration Parser
// ---------------------------------------------------------------------------

/**
 * Parses SRX SNMP configuration from the hierarchical tree.
 * Extracts communities, trap groups, trap targets, contact/location, and v3 config.
 */
function parseSrxSnmpConfig(tree, warnings) {
  const entries = [];
  const snmp = tree.system?.snmp;
  if (!snmp) return entries;

  const contact = extractStringValue(snmp.contact) || '';
  const location = extractStringValue(snmp.location) || '';
  const engineId = extractStringValue(snmp['engine-id']) || '';

  // Parse communities: set system snmp community <name> authorization <ro|rw>
  const communities = snmp.community;
  if (communities && typeof communities === 'object') {
    for (const [name, cfg] of Object.entries(communities)) {
      const auth = typeof cfg === 'object'
        ? extractStringValue(cfg.authorization) || 'read-only'
        : 'read-only';
      const clients = [];
      if (typeof cfg === 'object' && cfg.clients) {
        for (const client of Object.keys(cfg.clients)) {
          if (client !== 'restrict') clients.push(client);
        }
      }
      entries.push({
        type: 'community',
        name,
        authorization: auth,
        clients,
        contact,
        location,
      });
    }
  }

  // Parse trap groups: set system snmp trap-group <name> targets <ip>
  const trapGroups = snmp['trap-group'];
  if (trapGroups && typeof trapGroups === 'object') {
    for (const [groupName, groupCfg] of Object.entries(trapGroups)) {
      if (typeof groupCfg !== 'object') continue;
      const targets = [];
      if (groupCfg.targets) {
        if (typeof groupCfg.targets === 'string') {
          targets.push(groupCfg.targets);
        } else if (typeof groupCfg.targets === 'object') {
          targets.push(...Object.keys(groupCfg.targets));
        }
      }
      const categories = [];
      if (groupCfg.categories && typeof groupCfg.categories === 'object') {
        categories.push(...Object.keys(groupCfg.categories));
      }
      const version = extractStringValue(groupCfg.version) || 'v2';
      entries.push({
        type: 'trap-group',
        name: groupName,
        targets,
        categories,
        version,
      });
    }
  }

  // Parse v3 USM users if present
  const v3 = snmp.v3;
  if (v3 && typeof v3 === 'object') {
    const usm = v3.usm?.['local-engine']?.user;
    if (usm && typeof usm === 'object') {
      for (const [userName, userCfg] of Object.entries(usm)) {
        if (typeof userCfg !== 'object') continue;
        const authProto = userCfg['authentication-sha'] ? 'sha' :
                          userCfg['authentication-md5'] ? 'md5' : 'none';
        const privProto = userCfg['privacy-aes128'] ? 'aes128' :
                          userCfg['privacy-des'] ? 'des' : 'none';
        entries.push({
          type: 'v3-user',
          name: userName,
          auth_protocol: authProto,
          privacy_protocol: privProto,
          contact,
          location,
        });
      }
    }
  }

  if (entries.length > 0) {
    warnings.push(createWarning('info', 'snmp', `Parsed ${entries.length} SNMP configuration item(s)`, 'SNMP configuration detected'));
  }
  return entries;
}


// ---------------------------------------------------------------------------
// AAA Configuration Parser
// ---------------------------------------------------------------------------

/**
 * Parses SRX AAA configuration from the hierarchical tree.
 * Extracts RADIUS servers, TACACS+ servers, LDAP servers, and access profiles.
 */
function parseSrxAaaConfig(tree, warnings) {
  const entries = [];
  const access = tree.system?.access;
  if (!access && !tree.access) return entries;

  const accessNode = access || tree.access || {};

  // Parse RADIUS servers: set system radius-server <ip>
  // (can also be under access)
  const radiusServers = tree.system?.['radius-server'] || accessNode['radius-server'];
  if (radiusServers && typeof radiusServers === 'object') {
    for (const [ip, cfg] of Object.entries(radiusServers)) {
      if (typeof cfg !== 'object') continue;
      entries.push({
        type: 'radius',
        name: `radius-${ip}`,
        server: ip,
        port: parseInt(extractStringValue(cfg.port) || '1812', 10),
        secret: extractStringValue(cfg.secret) || '',
        timeout: parseInt(extractStringValue(cfg.timeout) || '5', 10),
        retry: parseInt(extractStringValue(cfg['retry-count'] || cfg.retry) || '3', 10),
        source_address: extractStringValue(cfg['source-address']) || '',
      });
    }
  }

  // Parse TACACS+ servers: set system tacplus-server <ip>
  const tacplusServers = tree.system?.['tacplus-server'] || accessNode['tacplus-server'];
  if (tacplusServers && typeof tacplusServers === 'object') {
    for (const [ip, cfg] of Object.entries(tacplusServers)) {
      if (typeof cfg !== 'object') continue;
      entries.push({
        type: 'tacplus',
        name: `tacplus-${ip}`,
        server: ip,
        port: parseInt(extractStringValue(cfg.port) || '49', 10),
        secret: extractStringValue(cfg.secret) || '',
        timeout: parseInt(extractStringValue(cfg.timeout) || '5', 10),
        single_connection: !!cfg['single-connection'],
        source_address: extractStringValue(cfg['source-address']) || '',
      });
    }
  }

  // Parse access profiles: set access profile <name>
  const profiles = accessNode.profile;
  if (profiles && typeof profiles === 'object') {
    for (const [profileName, profileCfg] of Object.entries(profiles)) {
      if (typeof profileCfg !== 'object') continue;
      const authOrder = [];
      if (profileCfg['authentication-order']) {
        const order = profileCfg['authentication-order'];
        if (typeof order === 'string') authOrder.push(order);
        else if (typeof order === 'object') authOrder.push(...Object.keys(order));
      }
      entries.push({
        type: 'profile',
        name: profileName,
        authentication_order: authOrder,
      });
    }
  }

  // Parse authentication-order: set system authentication-order
  const authOrder = tree.system?.['authentication-order'];
  if (authOrder) {
    const order = typeof authOrder === 'string' ? [authOrder] :
                  typeof authOrder === 'object' ? Object.keys(authOrder) : [];
    if (order.length > 0) {
      entries.push({
        type: 'auth-order',
        name: 'system-auth-order',
        authentication_order: order,
      });
    }
  }

  if (entries.length > 0) {
    warnings.push(createWarning('info', 'aaa', `Parsed ${entries.length} AAA configuration item(s)`, 'AAA configuration detected'));
  }
  return entries;
}


// ---------------------------------------------------------------------------
// DHCP Configuration Parser
// ---------------------------------------------------------------------------

function parseSrxDhcpConfig(tree, warnings) {
  const dhcpConfigs = [];

  // SRX: set system services dhcp-local-server group <name> interface <if>
  const dhcpLocal = tree.system?.services?.['dhcp-local-server'];
  if (dhcpLocal) {
    const groups = dhcpLocal.group;
    if (groups && typeof groups === 'object') {
      for (const [groupName, groupConfig] of Object.entries(groups)) {
        if (typeof groupConfig !== 'object') continue;
        const ifaces = [];
        const ifSection = groupConfig.interface;
        if (ifSection) {
          if (typeof ifSection === 'string') ifaces.push(ifSection);
          else if (typeof ifSection === 'object') ifaces.push(...Object.keys(ifSection));
        }
        dhcpConfigs.push({
          type: 'server',
          group: groupName,
          interfaces: ifaces,
        });
      }
    }
  }

  // SRX: set forwarding-options helpers bootp interface <if> server <ip>
  const bootp = tree['forwarding-options']?.helpers?.bootp;
  if (bootp) {
    const ifSection = bootp.interface;
    if (ifSection && typeof ifSection === 'object') {
      for (const [ifName, ifConfig] of Object.entries(ifSection)) {
        if (typeof ifConfig !== 'object') continue;
        const relayServers = [];
        const serverSection = ifConfig.server;
        if (typeof serverSection === 'string') relayServers.push(serverSection);
        else if (typeof serverSection === 'object') relayServers.push(...Object.keys(serverSection));

        dhcpConfigs.push({
          type: 'relay',
          interface: ifName,
          servers: relayServers,
        });
      }
    }
  }

  // SRX: set access address-assignment pool <name> family inet range <range> low/high
  const pools = tree.access?.['address-assignment']?.pool;
  if (pools && typeof pools === 'object') {
    for (const [poolName, poolConfig] of Object.entries(pools)) {
      if (typeof poolConfig !== 'object') continue;
      const network = poolConfig.family?.inet?.network || '';
      const ranges = [];
      const rangeSection = poolConfig.family?.inet?.range;
      if (rangeSection && typeof rangeSection === 'object') {
        for (const [rangeName, rangeConfig] of Object.entries(rangeSection)) {
          if (typeof rangeConfig !== 'object') continue;
          ranges.push({ name: rangeName, low: rangeConfig.low || '', high: rangeConfig.high || '' });
        }
      }
      const dns = [];
      const dnsSection = poolConfig.family?.inet?.['dhcp-attributes']?.['name-server'];
      if (dnsSection) {
        if (typeof dnsSection === 'string') dns.push(dnsSection);
        else if (typeof dnsSection === 'object') dns.push(...Object.keys(dnsSection));
      }
      const router = poolConfig.family?.inet?.['dhcp-attributes']?.router || '';

      dhcpConfigs.push({
        type: 'pool',
        name: poolName,
        network,
        ranges,
        dns_servers: dns,
        router,
      });
    }
  }

  if (dhcpConfigs.length > 0) {
    warnings.push(createWarning('info', 'dhcp', `Parsed ${dhcpConfigs.length} DHCP config(s)`, 'DHCP configuration detected'));
  }
  return dhcpConfigs;
}


// ---------------------------------------------------------------------------
// QoS / CoS Configuration Parser
// ---------------------------------------------------------------------------

function parseSrxQosConfig(tree, warnings) {
  const qosProfiles = [];

  // SRX: set class-of-service ...
  const cos = tree['class-of-service'];
  if (!cos) return qosProfiles;

  // Forwarding classes
  const fwdClasses = cos['forwarding-classes'];
  const classMap = {};
  if (fwdClasses) {
    const classSection = fwdClasses.class || fwdClasses['queue'];
    if (classSection && typeof classSection === 'object') {
      for (const [name, config] of Object.entries(classSection)) {
        classMap[name] = {
          name,
          queue: typeof config === 'object' ? (config['queue-num'] || '') : config,
          priority: typeof config === 'object' ? (config.priority || '') : '',
        };
      }
    }
  }

  // Schedulers
  const schedulers = cos.schedulers;
  if (schedulers && typeof schedulers === 'object') {
    for (const [name, config] of Object.entries(schedulers)) {
      if (typeof config !== 'object') continue;
      qosProfiles.push({
        name,
        type: 'scheduler',
        transmit_rate: extractStringValue(config['transmit-rate']),
        buffer_size: extractStringValue(config['buffer-size']),
        priority: extractStringValue(config.priority),
        drop_profile: extractStringValue(config['drop-profile-map']?.['loss-priority']?.['any']?.protocol?.any),
      });
    }
  }

  // Interfaces with CoS
  const interfaces = cos.interfaces;
  if (interfaces && typeof interfaces === 'object') {
    for (const [ifName, ifConfig] of Object.entries(interfaces)) {
      if (typeof ifConfig !== 'object') continue;
      qosProfiles.push({
        name: `cos-${ifName}`,
        type: 'interface-cos',
        interface: ifName,
        scheduler_map: extractStringValue(ifConfig['scheduler-map']),
        shaping_rate: extractStringValue(ifConfig['shaping-rate']),
      });
    }
  }

  if (qosProfiles.length > 0) {
    warnings.push(createWarning('info', 'qos', `Parsed ${qosProfiles.length} CoS/QoS config(s)`, 'Class-of-service configuration detected'));
  }
  return qosProfiles;
}


// ---------------------------------------------------------------------------
// Bridge Domain Parser (L2 Support)
// ---------------------------------------------------------------------------

/**
 * Parses SRX bridge-domain configuration.
 * Junos: set bridge-domains <name> domain-type bridge
 *        set bridge-domains <name> vlan-id <id>
 *        set bridge-domains <name> routing-interface irb.<unit>
 */
function parseSrxBridgeDomains(tree, warnings) {
  const bdNode = tree?.['bridge-domains'];
  if (!bdNode || typeof bdNode !== 'object') return [];

  const bridgeDomains = [];
  for (const [bdName, bdData] of Object.entries(bdNode)) {
    if (bdName.startsWith('_') || typeof bdData !== 'object') continue;

    const vlanId = extractStringValue(bdData['vlan-id']) || '';
    const routingIf = extractStringValue(bdData['routing-interface']) || '';

    // Collect interfaces assigned to this bridge domain
    const bdInterfaces = [];

    bridgeDomains.push({
      name: bdName,
      vlan_id: vlanId,
      interfaces: bdInterfaces,
      irb_interface: routingIf,
    });
  }

  if (bridgeDomains.length > 0) {
    warnings.push(createWarning(
      'info', 'l2/bridge-domains',
      `Parsed ${bridgeDomains.length} bridge domain(s) from SRX config`,
      'Bridge domain configuration will be preserved in conversion'
    ));
  }

  return bridgeDomains;
}

/**
 * Detects L2 interfaces from SRX config.
 * An interface is L2 if its unit has "family bridge" configured.
 * Also detects bridge-domain assignments on interface units.
 */
function detectSrxL2Interfaces(tree, interfaces, warnings) {
  const l2Interfaces = [];
  const ifacesNode = tree?.interfaces;
  if (!ifacesNode || typeof ifacesNode !== 'object') return l2Interfaces;

  for (const [ifName, ifData] of Object.entries(ifacesNode)) {
    if (ifName.startsWith('_') || typeof ifData !== 'object') continue;
    const unitNode = ifData?.unit;
    if (!unitNode || typeof unitNode !== 'object') continue;

    for (const [unitNum, unitData] of Object.entries(unitNode)) {
      if (unitNum.startsWith('_') || typeof unitData !== 'object') continue;

      // Check for family bridge
      const hasBridge = unitData?.family?.bridge !== undefined;
      if (!hasBridge) continue;

      const fullName = `${ifName}.${unitNum}`;
      const vlanId = extractStringValue(unitData?.['vlan-id']) || '';
      const bridgeDomainName = extractStringValue(unitData?.['bridge-domain-name']) ||
        (unitData?.family?.bridge?.['bridge-domain-name'] ? extractStringValue(unitData.family.bridge['bridge-domain-name']) : '');

      l2Interfaces.push({
        name: fullName,
        mode: vlanId ? 'trunk' : 'access',
        vlan: vlanId,
        bridge_domain: bridgeDomainName,
      });
    }
  }

  if (l2Interfaces.length > 0) {
    warnings.push(createWarning(
      'info', 'l2/interfaces',
      `Detected ${l2Interfaces.length} L2 interface(s) with family bridge`,
      'L2 interfaces will be preserved in the generated config'
    ));
  }

  return l2Interfaces;
}

// ---------------------------------------------------------------------------
// Interface Configuration Parser
// ---------------------------------------------------------------------------

function parseSrxInterfaces(tree, zones, warnings) {
  const ifacesNode = tree?.interfaces || {};

  // Build zone lookup: interface name → zone name
  const ifToZone = {};
  for (const z of zones) {
    for (const ifName of (z.interfaces || [])) {
      ifToZone[ifName] = z.name;
    }
  }

  // Detect interface type from name
  const getType = (name) => {
    if (/^lo\d/.test(name)) return 'loopback';
    if (/^st\d/.test(name)) return 'tunnel';
    if (/^reth\d/.test(name)) return 'redundant';
    if (/^ae\d/.test(name)) return 'aggregate';
    if (/^irb/.test(name)) return 'irb';
    if (/^fab\d/.test(name)) return 'fabric';
    if (/^fxp\d/.test(name)) return 'management';
    return 'physical';
  };

  const interfaces = [];
  const seenNames = new Set();

  // Walk explicit interface definitions from tree.interfaces
  for (const [ifName, ifData] of Object.entries(ifacesNode)) {
    if (ifName.startsWith('_') || typeof ifData !== 'object') continue;

    // Skip fabric interfaces (handled by HA)
    if (/^fab\d/.test(ifName)) continue;

    const unitNode = ifData?.unit;
    if (unitNode && typeof unitNode === 'object') {
      // Walk logical units
      for (const [unitNum, unitData] of Object.entries(unitNode)) {
        if (unitNum.startsWith('_') || typeof unitData !== 'object') continue;

        const fullName = `${ifName}.${unitNum}`;
        const desc = extractStringValue(unitData?.description) || extractStringValue(ifData?.description) || '';
        const vlanId = extractStringValue(unitData?.['vlan-id']) || '';

        // Extract IPv4 addresses
        const inetAddr = unitData?.family?.inet?.address;
        let ip = '';
        if (inetAddr && typeof inetAddr === 'object') {
          const addrKeys = Object.keys(inetAddr).filter(k => !k.startsWith('_'));
          if (addrKeys.length > 0) ip = addrKeys[0]; // First address (CIDR format)
        }

        // Extract IPv6 addresses
        const inet6Addr = unitData?.family?.inet6?.address;
        let ipv6 = '';
        if (inet6Addr && typeof inet6Addr === 'object') {
          const addr6Keys = Object.keys(inet6Addr).filter(k => !k.startsWith('_'));
          if (addr6Keys.length > 0) ipv6 = addr6Keys[0];
        }

        seenNames.add(fullName);
        interfaces.push({
          name: fullName,
          ip: ip,
          ipv6: ipv6,
          zone: ifToZone[fullName] || '',
          vlan: vlanId,
          type: getType(ifName),
          description: desc,
          status: 'up',
          speed: '',
        });
      }
    } else {
      // Interface with no units (e.g., fxp0) — still include
      const desc = extractStringValue(ifData?.description) || '';
      seenNames.add(ifName);
      interfaces.push({
        name: ifName,
        ip: '',
        ipv6: '',
        zone: ifToZone[ifName] || '',
        vlan: '',
        type: getType(ifName),
        description: desc,
        status: 'up',
        speed: '',
      });
    }
  }

  // Also create entries for interfaces referenced in zones but not in tree.interfaces
  for (const [ifName, zoneName] of Object.entries(ifToZone)) {
    if (seenNames.has(ifName)) continue;
    const baseName = ifName.split('.')[0];
    seenNames.add(ifName);
    interfaces.push({
      name: ifName,
      ip: '',
      ipv6: '',
      zone: zoneName,
      vlan: '',
      type: getType(baseName),
      description: '',
      status: 'up',
      speed: '',
    });
  }

  if (interfaces.length > 0) {
    warnings.push(createWarning('info', 'interfaces', `Parsed ${interfaces.length} interface(s)`, 'Interface configuration detected'));
  }
  return interfaces;
}


// ---------------------------------------------------------------------------
// SSL Proxy / PKI Round-Trip Parser
// ---------------------------------------------------------------------------

/**
 * Parses SRX SSL proxy profiles and PKI ca-profiles from set commands.
 *
 * Source config:
 *   set services ssl proxy profile <name> root-ca <ca>
 *   set services ssl proxy profile <name> server-certificate <cert>
 *   set services ssl proxy profile <name> protocol-version <ver>
 *   set security pki ca-profile <name> ca-identity <id>
 *
 * Also scans security policies for ssl-proxy profile-name attachments
 * and sets _srx_decrypt on matching policies.
 */
function parseSrxSslProxy(tree, securityPolicies, warnings) {
  const rules = [];
  let ruleIndex = 0;

  // Parse SSL proxy profiles from tree
  const sslNode = tree.services?.ssl?.proxy?.profile;
  if (!sslNode || typeof sslNode !== 'object') return rules;

  const profiles = {};
  for (const [profileName, profileData] of Object.entries(sslNode)) {
    if (typeof profileData !== 'object') continue;
    const rootCa = extractStringValue(profileData['root-ca']);
    const serverCert = extractStringValue(profileData['server-certificate']);
    const protocolVersion = extractStringValue(profileData['protocol-version']);
    const isInbound = !!serverCert && !rootCa;

    profiles[profileName] = {
      name: profileName,
      root_ca: rootCa,
      server_certificate: serverCert,
      protocol_version: protocolVersion,
      is_inbound: isInbound,
    };
  }

  if (Object.keys(profiles).length === 0) return rules;

  // Scan security policies for ssl-proxy attachments and create synthetic decryption rules
  for (const policy of securityPolicies) {
    // Check if policy has _srx_ssl_proxy_profile set during policy parsing
    // (set by parseSinglePolicy when ssl-proxy profile-name is encountered)
    if (policy._srx_ssl_proxy_profile) {
      const profileName = policy._srx_ssl_proxy_profile;
      const profileDef = profiles[profileName];
      const isInbound = profileDef?.is_inbound || false;

      policy._srx_decrypt = true;
      policy._srx_decrypt_profile = profileName;

      ruleIndex++;
      rules.push({
        name: `${policy.name}-ssl`,
        src_zones: policy.src_zones || [],
        dst_zones: policy.dst_zones || [],
        src_addresses: policy.src_addresses || [],
        dst_addresses: policy.dst_addresses || [],
        src_users: [],
        negate_source: policy.negate_source || false,
        negate_destination: policy.negate_destination || false,
        services: policy.services || [],
        url_categories: [],
        action: 'decrypt',
        decryption_type: isInbound ? 'ssl-inbound-inspection' : 'ssl-forward-proxy',
        ssl_certificate: profileDef?.server_certificate || '',
        decryption_profile: profileName,
        log_success: false,
        log_fail: false,
        log_setting: '',
        description: `Round-trip from SRX ssl-proxy profile "${profileName}" on policy "${policy.name}"`,
        tags: [],
        disabled: policy.disabled || false,
        _rule_index: ruleIndex,
        _source_policy: policy.name,
      });
    }
  }

  if (rules.length > 0) {
    warnings.push(createWarning('info', 'ssl-proxy',
      `Parsed ${Object.keys(profiles).length} SSL proxy profile(s) and ${rules.length} decryption rule(s)`,
      'SSL proxy configuration detected for round-trip'));
  }

  return rules;
}


// ---------------------------------------------------------------------------
// PBF / Firewall Filter Round-Trip Parser
// ---------------------------------------------------------------------------

/**
 * Parses SRX firewall filter terms into PBF rules for round-trip conversion.
 *
 * Source config:
 *   set firewall filter <name> term <term> from source-address <addr>
 *   set firewall filter <name> term <term> from destination-address <addr>
 *   set firewall filter <name> term <term> then routing-instance <inst>
 *   set firewall filter <name> term <term> then discard
 *   set firewall filter <name> term <term> then accept
 */
function parseSrxPbfRules(tree, warnings) {
  const rules = [];
  const filterNode = tree.firewall?.filter;
  if (!filterNode || typeof filterNode !== 'object') return rules;

  let ruleIndex = 0;

  for (const [filterName, filterData] of Object.entries(filterNode)) {
    if (typeof filterData !== 'object' || !filterData.term) continue;

    for (const [termName, termData] of Object.entries(filterData.term)) {
      if (typeof termData !== 'object') continue;
      if (termName === 'default') continue; // skip default accept term

      const fromClause = termData.from || {};
      const thenClause = termData.then || {};

      const srcAddrs = collectKeys(fromClause['source-address']);
      const dstAddrs = collectKeys(fromClause['destination-address']);

      // Determine action from then clause
      let action = 'forward';
      let nextHop = '';
      let routingInstance = '';

      if (thenClause.discard === true || thenClause.discard !== undefined) {
        action = 'discard';
      } else if (thenClause.accept === true || thenClause.accept !== undefined) {
        action = 'no-pbf';
      } else if (thenClause['routing-instance']) {
        action = 'forward';
        routingInstance = extractStringValue(thenClause['routing-instance']);

        // Try to resolve next-hop from the routing-instance config
        const instData = tree['routing-instances']?.[routingInstance];
        if (instData?.['routing-options']?.static?.route) {
          const routes = instData['routing-options'].static.route;
          for (const [, rData] of Object.entries(routes)) {
            if (typeof rData === 'object' && rData['next-hop']) {
              nextHop = extractStringValue(rData['next-hop']);
              break;
            }
          }
        }
      }

      ruleIndex++;
      rules.push({
        name: termName,
        src_zones: [],
        dst_zones: [],
        src_addresses: srcAddrs.length > 0 ? srcAddrs : ['any'],
        dst_addresses: dstAddrs.length > 0 ? dstAddrs : ['any'],
        services: ['any'],
        action,
        next_hop_type: nextHop ? 'ip-address' : '',
        next_hop_value: nextHop,
        egress_interface: '',
        from_type: 'zone',
        from_value: [],
        forward_vsys: '',
        enforce_symmetric_return: false,
        disabled: false,
        description: `Round-trip from SRX filter "${filterName}" term "${termName}"`,
        _rule_index: ruleIndex,
        _source_filter: filterName,
        _routing_instance: routingInstance,
      });
    }
  }

  if (rules.length > 0) {
    warnings.push(createWarning('info', 'pbf',
      `Parsed ${rules.length} firewall filter term(s) as PBF rules`,
      'Firewall filter-based forwarding detected for round-trip'));
  }

  return rules;
}


// ---------------------------------------------------------------------------
// Flow Monitoring Round-Trip Parser
// ---------------------------------------------------------------------------

/**
 * Parses SRX flow monitoring configuration for round-trip.
 *
 * Source config:
 *   set forwarding-options sampling instance <name> input rate <rate>
 *   set forwarding-options sampling instance <name> family inet output flow-server <addr> port <port>
 *   set forwarding-options sampling instance <name> family inet output inline-jflow source-address <src>
 *   set services flow-monitoring version-ipfix template <name> flow-active-timeout <sec>
 *   set services flow-monitoring version-ipfix template <name> template-refresh-rate packets <num>
 */
function parseSrxFlowMonitoring(tree, warnings) {
  const result = { collectors: [], sampling: { input_rate: 1000, run_length: 0, interfaces: [] }, templates: [] };

  // Parse forwarding-options > sampling
  const samplingNode = tree['forwarding-options']?.sampling;
  if (!samplingNode) return result;

  // Can be instance-based or flat
  const instances = samplingNode.instance || { _default: samplingNode };

  for (const [instName, instData] of Object.entries(instances)) {
    if (typeof instData !== 'object') continue;

    // Input rate
    const inputNode = instData.input || {};
    if (inputNode.rate) {
      result.sampling.input_rate = parseInt(extractStringValue(inputNode.rate)) || 1000;
    }
    if (inputNode['run-length']) {
      result.sampling.run_length = parseInt(extractStringValue(inputNode['run-length'])) || 0;
    }

    // Family inet output
    const inetOutput = instData.family?.inet?.output || {};

    // Flow servers
    const flowServer = inetOutput['flow-server'];
    if (flowServer && typeof flowServer === 'object') {
      for (const [addr, serverData] of Object.entries(flowServer)) {
        if (addr.startsWith('_') || typeof serverData !== 'object') continue;
        const port = parseInt(extractStringValue(serverData.port)) || 2055;
        const versionIpfix = serverData['version-ipfix'];
        const version9 = serverData['version9'];
        const protocol = versionIpfix ? 'ipfix' : version9 ? 'netflow-v9' : 'ipfix';

        // Extract template name from version-ipfix > template
        let templateName = '';
        if (versionIpfix && typeof versionIpfix === 'object' && versionIpfix.template) {
          templateName = extractStringValue(versionIpfix.template);
        }

        result.collectors.push({
          address: addr,
          port,
          protocol,
          source_address: '',
          _template: templateName,
        });
      }
    }

    // Inline jflow source address
    const inlineJflow = inetOutput['inline-jflow'];
    if (inlineJflow && typeof inlineJflow === 'object') {
      const srcAddr = extractStringValue(inlineJflow['source-address']);
      if (srcAddr) {
        for (const c of result.collectors) c.source_address = srcAddr;
      }
    }
  }

  // Parse services > flow-monitoring templates
  const flowMon = tree.services?.['flow-monitoring'];
  if (flowMon) {
    const ipfixNode = flowMon['version-ipfix'] || flowMon['version9'] || {};
    const templateNode = ipfixNode.template;
    if (templateNode && typeof templateNode === 'object') {
      for (const [tplName, tplData] of Object.entries(templateNode)) {
        if (tplName.startsWith('_') || typeof tplData !== 'object') continue;
        result.templates.push({
          name: tplName,
          flow_type: tplData['ipv6-template'] ? 'ipv6' : 'ipv4',
          active_timeout: parseInt(extractStringValue(tplData['flow-active-timeout'])) || 60,
          refresh_rate: parseInt(extractStringValue(tplData['template-refresh-rate']?.packets)) || 1000,
        });
      }
    }
  }

  if (result.collectors.length > 0) {
    warnings.push(createWarning('info', 'flow-monitoring',
      `Parsed ${result.collectors.length} flow collector(s) and ${result.templates.length} template(s)`,
      'SRX flow monitoring configuration detected for round-trip'));
  }

  return result;
}


// ---------------------------------------------------------------------------
// LAG / ae Interface Parser
// ---------------------------------------------------------------------------

/**
 * Parses SRX aggregate ethernet (ae) interfaces and their member assignments.
 *
 * SRX config patterns:
 *   set interfaces ae0 aggregated-ether-options lacp active
 *   set interfaces ae0 description "LAG to switch"
 *   set interfaces ge-0/0/0 ether-options 802.3ad ae0
 *   set chassis aggregated-devices ethernet device-count 4
 *
 * @param {Object} tree - Parsed set-command tree
 * @param {Object[]} warnings - Warnings array
 * @returns {Object[]} Array of lag_interfaces in intermediate schema format
 */
function parseSrxLagInterfaces(tree, warnings) {
  const lagInterfaces = [];
  const ifacesNode = tree?.interfaces || {};

  // Collect ae interfaces
  const aeInterfaces = {};
  for (const [ifName, ifData] of Object.entries(ifacesNode)) {
    if (!ifName.startsWith('ae') || typeof ifData !== 'object') continue;

    const aeOpts = ifData['aggregated-ether-options'] || {};
    const lacpNode = aeOpts.lacp || {};

    let lacpMode = 'static';
    if (lacpNode.active !== undefined) lacpMode = 'active';
    else if (lacpNode.passive !== undefined) lacpMode = 'passive';

    const lacpPriority = lacpNode['system-priority']
      ? parseInt(extractStringValue(lacpNode['system-priority']), 10) || null
      : null;

    const description = extractStringValue(ifData?.description) || '';

    aeInterfaces[ifName] = {
      name: ifName,
      source_name: ifName,
      members: [],
      source_members: [],
      lacp_mode: lacpMode,
      lacp_priority: lacpPriority,
      description,
    };
  }

  if (Object.keys(aeInterfaces).length === 0) return lagInterfaces;

  // Find member assignments: ge-0/0/0 ether-options 802.3ad ae0
  for (const [ifName, ifData] of Object.entries(ifacesNode)) {
    if (ifName.startsWith('ae') || typeof ifData !== 'object') continue;

    const etherOpts = ifData['ether-options'] || {};
    const adRef = etherOpts['802.3ad'];
    if (!adRef || typeof adRef !== 'object') continue;

    // The ae interface name is a key under 802.3ad
    const aeKeys = Object.keys(adRef).filter(k => k.startsWith('ae'));
    for (const aeKey of aeKeys) {
      if (aeInterfaces[aeKey]) {
        aeInterfaces[aeKey].members.push(ifName);
        aeInterfaces[aeKey].source_members.push(ifName);
      }
    }
  }

  for (const ae of Object.values(aeInterfaces)) {
    lagInterfaces.push(ae);
  }

  if (lagInterfaces.length > 0) {
    warnings.push(createWarning('info', 'lag',
      `Parsed ${lagInterfaces.length} ae (LAG) interface(s) with ${lagInterfaces.reduce((s, l) => s + l.members.length, 0)} member(s)`,
      'SRX ae interfaces detected for round-trip'));
  }

  return lagInterfaces;
}
