/**
 * SonicWall SonicOS 7 Configuration Parser
 * =========================================
 *
 * Parses SonicWall SonicOS 7 firewall configurations into the vendor-neutral
 * intermediate JSON schema.
 *
 * Handles two input formats:
 *   - REST API JSON (combined /api/sonicos/* endpoint exports)
 *   - CLI text (`show current-config` output) as a fallback
 *
 * SonicWall is zone-based (like SRX), which makes zone mapping straightforward.
 *
 * Supported config elements:
 *   - Zones (trusted, untrusted, public, custom)
 *   - Interfaces (X0, X1, etc. with IP assignment)
 *   - Address objects (host, network, range, FQDN, MAC)
 *   - Address groups
 *   - Service objects (protocol + port range)
 *   - Service groups
 *   - Access rules (security policies)
 *   - NAT policies (source, destination, and combined)
 *   - Route policies (static routes)
 */

import { createWarning, mapAppToJunos, safeJsonParse, detectIpVersion } from './parser-utils.js';


// ---------------------------------------------------------------------------
// Built-in SonicWall Objects
// ---------------------------------------------------------------------------

/**
 * SonicWall predefined objects that appear in rules but not in object exports.
 * Value of null means the object will resolve to an interface IP/subnet at
 * runtime; 'any' means it maps directly to the intermediate 'any' keyword.
 */
const SONICWALL_BUILTINS = {
  'Any': 'any',
  'X0 IP': null,
  'X0 Subnet': null,
  'X1 IP': null,
  'X1 Subnet': null,
  'X2 IP': null,
  'X2 Subnet': null,
  'X3 IP': null,
  'X3 Subnet': null,
  'WAN Primary IP': null,
  'Firewalled Subnets': null,
};


// ---------------------------------------------------------------------------
// Main Parser Entry Point
// ---------------------------------------------------------------------------

/**
 * Parses a SonicWall SonicOS configuration into the intermediate JSON schema.
 *
 * @param {string} configText - Raw SonicWall configuration (JSON or CLI text)
 * @returns {{ intermediateConfig: Object, warnings: Object[], parseStats: Object }}
 */
export function parseSonicWallConfig(configText) {
  const warnings = [];
  const trimmed = configText.trim();

  // Auto-detect JSON vs CLI format
  if (trimmed.startsWith('{')) {
    return parseJsonFormat(trimmed, warnings);
  }
  return parseCliFormat(trimmed, warnings);
}


// ---------------------------------------------------------------------------
// JSON Format Parser
// ---------------------------------------------------------------------------

function parseJsonFormat(text, warnings) {
  let config;
  try {
    config = safeJsonParse(text);
  } catch (e) {
    warnings.push(createWarning('warning', 'parse', `JSON parse error: ${e.message}`, 'Verify the JSON export is complete and well-formed'));
    return buildEmptyResult(warnings);
  }

  // Parse each section
  const zones = parseJsonZones(config, warnings);
  const interfaces = parseJsonInterfaces(config, warnings);
  const addressObjects = parseJsonAddressObjects(config, warnings);
  const addressGroups = parseJsonAddressGroups(config, warnings);
  const serviceObjects = parseJsonServiceObjects(config, warnings);
  const serviceGroups = parseJsonServiceGroups(config, warnings);
  const securityPolicies = parseJsonAccessRules(config, warnings);
  const natRules = parseJsonNatPolicies(config, warnings);
  const staticRoutes = parseJsonRoutePolicies(config, warnings);

  // Normalize interfaces to standard schema
  const normalizedInterfaces = interfaces.map(iface => ({
    name: iface.name,
    ip: iface.ip,
    zone: iface.zone,
    vlan: iface.vlan || '',
    type: iface.vlan ? 'vlan' : 'physical',
    description: iface.comment || '',
    status: iface.enabled ? 'up' : 'shutdown',
    speed: '',
  }));

  // Parse LAG / aggregate interfaces from JSON
  const lagInterfaces = parseSonicwallLagInterfaces(config, warnings);

  // Detect version if present
  const version = config.firmware_version || config.version || '';

  const intermediateConfig = {
    zones,
    address_objects: addressObjects,
    address_groups: addressGroups,
    service_objects: serviceObjects,
    service_groups: serviceGroups,
    security_policies: securityPolicies,
    nat_rules: natRules,
    applications: [],
    application_groups: [],
    schedules: [],
    security_profile_objects: [],
    external_lists: [],
    vpn_tunnels: [],
    ha_config: null,
    screen_config: [],
    syslog_config: [],
    snmp_config: [],
    aaa_config: [],
    dhcp_config: [],
    qos_config: [],
    flow_monitoring_config: { collectors: [], sampling: { input_rate: 1000, run_length: 0, interfaces: [] }, templates: [] },
    interfaces: normalizedInterfaces,
    lag_interfaces: lagInterfaces,
    routing_contexts: [{ name: 'default', type: 'default', virtual_routers: [], zones: [] }],
    static_routes: staticRoutes,
    bgp_config: [],
    ospf_config: [],
    ospf3_config: [],
    evpn_config: [],
    vxlan_config: [],
    target_context: null,
    transparent_mode: false,
    bridge_domains: [],
    l2_interfaces: [],
    vwire_pairs: [],
    _sonicwall: {
      builtinObjects: Object.keys(SONICWALL_BUILTINS),
    },
    metadata: {
      source_vendor: 'sonicwall',
      source_version: version,
      export_date: new Date().toISOString(),
      rule_count: securityPolicies.length,
      nat_rule_count: natRules.length,
      object_count: addressObjects.length + serviceObjects.length,
      zone_count: zones.length,
      interface_count: normalizedInterfaces.length,
      vpn_tunnel_count: 0,
      syslog_server_count: 0,
      dhcp_config_count: 0,
      qos_profile_count: 0,
      routing_context_count: 1,
      static_route_count: staticRoutes.length,
      ha_enabled: false,
      multi_vsys: false,
    },
  };

  return {
    intermediateConfig,
    warnings,
    parseStats: intermediateConfig.metadata,
  };
}


// ---------------------------------------------------------------------------
// JSON Section Parsers
// ---------------------------------------------------------------------------

/**
 * Parses zones from SonicWall JSON export.
 * Maps SonicWall security_type to intermediate zone types:
 *   trusted   -> trust
 *   untrusted -> untrust
 *   public    -> dmz
 *   others    -> kept as-is
 */
function parseJsonZones(config, warnings) {
  const zones = [];
  const rawZones = config.zones || [];

  for (const z of rawZones) {
    const name = z.name || '';
    if (!name) continue;

    const secType = (z.security_type || '').toLowerCase();
    let mappedType = secType;
    if (secType === 'trusted') mappedType = 'trust';
    else if (secType === 'untrusted') mappedType = 'untrust';
    else if (secType === 'public') mappedType = 'dmz';

    zones.push({
      name,
      description: `SonicWall zone (${secType || 'custom'})`,
      interfaces: [],
      _sonicwall: {
        securityType: secType,
        uuid: z.uuid || '',
      },
    });
  }

  return zones;
}

/**
 * Parses interfaces from SonicWall JSON export.
 * Handles the nested ip_assignment.mode.static structure.
 */
function parseJsonInterfaces(config, warnings) {
  const interfaces = [];
  const rawInterfaces = safeArray(config.interfaces?.ipv4);

  // Build IPv6 lookup from config.interfaces.ipv6 if present
  const ipv6Map = {};
  const rawIpv6 = safeArray(config.interfaces?.ipv6);
  for (const iface6 of rawIpv6) {
    const name = iface6.name || '';
    if (!name) continue;
    const staticCfg = iface6.ip_assignment?.mode?.static;
    if (staticCfg) {
      const addr6 = staticCfg.ip || '';
      const prefix = staticCfg.prefix_length || staticCfg.prefix || '';
      if (addr6) {
        ipv6Map[name] = prefix ? `${addr6}/${prefix}` : addr6;
      }
    }
  }

  for (const iface of rawInterfaces) {
    const name = iface.name || '';
    if (!name) continue;

    let ip = '';
    const staticConfig = iface.ip_assignment?.mode?.static;
    if (staticConfig) {
      const addr = staticConfig.ip || '';
      const mask = staticConfig.netmask || '255.255.255.255';
      if (addr) {
        ip = `${addr}/${swMaskToCidr(mask)}`;
      }
    }

    // Determine zone from interface config
    const zone = iface.zone || '';

    interfaces.push({
      name,
      ip,
      ipv6: ipv6Map[name] || '',
      zone,
      enabled: iface.enabled !== false,
      comment: iface.comment || iface.description || '',
      vlan: iface.vlan || '',
    });

    // Associate interface with its zone
    // (Done in a post-processing step below if zones were already parsed)
  }

  return interfaces;
}

/**
 * Parses address objects from SonicWall JSON export.
 * Handles ipv4 (host, network, range) and fqdn subtypes.
 * MAC address objects are skipped with a warning.
 */
function parseJsonAddressObjects(config, warnings) {
  const objects = [];
  const addrObjs = config.address_objects || {};

  // IPv4 address objects
  const ipv4Objs = safeArray(addrObjs.ipv4);
  for (const obj of ipv4Objs) {
    const name = obj.name || '';
    if (!name) continue;

    if (obj.host && obj.host.ip) {
      objects.push({
        name,
        type: 'host',
        value: `${obj.host.ip}/32`,
        description: obj.description || '',
        tags: [],
      });
    } else if (obj.network && obj.network.ip) {
      const cidr = swMaskToCidr(obj.network.mask || '255.255.255.255');
      objects.push({
        name,
        type: 'network',
        value: `${obj.network.ip}/${cidr}`,
        description: obj.description || '',
        tags: [],
      });
    } else if (obj.range && obj.range.begin) {
      objects.push({
        name,
        type: 'range',
        value: `${obj.range.begin}-${obj.range.end || obj.range.begin}`,
        description: obj.description || '',
        tags: [],
      });
    }
  }

  // IPv6 address objects (if present)
  const ipv6Objs = safeArray(addrObjs.ipv6);
  for (const obj of ipv6Objs) {
    const name = obj.name || '';
    if (!name) continue;

    if (obj.host && obj.host.ip) {
      objects.push({
        name,
        type: 'host',
        value: `${obj.host.ip}/128`,
        description: obj.description || '',
        tags: [],
      });
    } else if (obj.network && obj.network.ip) {
      const prefix = obj.network.prefix || '128';
      objects.push({
        name,
        type: 'network',
        value: `${obj.network.ip}/${prefix}`,
        description: obj.description || '',
        tags: [],
      });
    }
  }

  // FQDN address objects
  const fqdnObjs = safeArray(addrObjs.fqdn);
  for (const obj of fqdnObjs) {
    const name = obj.name || '';
    if (!name) continue;

    const domain = obj.domain || '';
    if (domain) {
      objects.push({
        name,
        type: 'fqdn',
        value: domain,
        description: obj.description || '',
        tags: [],
      });
      warnings.push(createWarning(
        'info',
        `address/${name}`,
        `FQDN address "${name}" (${domain}) requires SRX dns-name support (SRX 12.1+)`,
        'Verify SRX version supports dns-name, or replace with static IP'
      ));
    }
  }

  // MAC address objects - skip with warning
  const macObjs = safeArray(addrObjs.mac);
  for (const obj of macObjs) {
    const name = obj.name || '';
    if (!name) continue;

    warnings.push(createWarning(
      'warning',
      `address/${name}`,
      `MAC address object "${name}" (${obj.mac_address || ''}) skipped - SRX does not support MAC-based address objects`,
      'Replace with IP-based address object or remove rules referencing this object'
    ));
  }

  // Auto-tag ip_version on all address objects
  for (const obj of objects) {
    obj.ip_version = detectIpVersion(obj.value);
  }

  return objects;
}

/**
 * Parses address groups from SonicWall JSON export.
 * Resolves member references from address_object and nested address_group arrays.
 */
function parseJsonAddressGroups(config, warnings) {
  const groups = [];
  const addrGroups = config.address_groups || {};

  const ipv4Groups = safeArray(addrGroups.ipv4);
  for (const grp of ipv4Groups) {
    const name = grp.name || '';
    if (!name) continue;

    const members = [];

    // Address object members
    const addrObjMembers = grp.address_object?.ipv4 || grp.address_object || [];
    const addrObjArray = safeArray(addrObjMembers);
    for (const m of addrObjArray) {
      if (typeof m === 'string') {
        members.push(m);
      } else if (m && m.name) {
        members.push(m.name);
      }
    }

    // Nested address group members
    const addrGrpMembers = grp.address_group?.ipv4 || grp.address_group || [];
    const addrGrpArray = safeArray(addrGrpMembers);
    for (const m of addrGrpArray) {
      if (typeof m === 'string') {
        members.push(m);
      } else if (m && m.name) {
        members.push(m.name);
      }
    }

    groups.push({
      name,
      members,
      description: grp.description || '',
      tags: [],
    });
  }

  // IPv6 groups (if present)
  const ipv6Groups = safeArray(addrGroups.ipv6);
  for (const grp of ipv6Groups) {
    const name = grp.name || '';
    if (!name) continue;

    const members = [];
    const memberArr = safeArray(grp.address_object?.ipv6 || grp.address_object || []);
    for (const m of memberArr) {
      if (typeof m === 'string') members.push(m);
      else if (m && m.name) members.push(m.name);
    }

    groups.push({
      name,
      members,
      description: grp.description || '',
      tags: [],
    });
  }

  return groups;
}

/**
 * Parses service objects from SonicWall JSON export.
 * Maps protocol + port_range to intermediate format.
 */
function parseJsonServiceObjects(config, warnings) {
  const services = [];
  const rawServices = safeArray(config.service_objects);

  for (const svc of rawServices) {
    const name = svc.name || '';
    if (!name) continue;

    let protocol = '';
    if (svc.protocol) {
      if (svc.protocol.tcp) protocol = 'tcp';
      else if (svc.protocol.udp) protocol = 'udp';
      else if (svc.protocol.icmp) protocol = 'icmp';
      else if (typeof svc.protocol === 'string') protocol = svc.protocol.toLowerCase();
    }

    let portRange = 'any';
    if (svc.port_range) {
      const begin = svc.port_range.begin;
      const end = svc.port_range.end;
      if (begin !== undefined && end !== undefined) {
        portRange = begin === end ? String(begin) : `${begin}-${end}`;
      } else if (begin !== undefined) {
        portRange = String(begin);
      }
    }

    services.push({
      name,
      protocol: protocol || 'tcp',
      port_range: portRange,
      source_port: '',
      description: svc.description || '',
    });
  }

  return services;
}

/**
 * Parses service groups from SonicWall JSON export.
 */
function parseJsonServiceGroups(config, warnings) {
  const groups = [];
  const rawGroups = safeArray(config.service_groups);

  for (const grp of rawGroups) {
    const name = grp.name || '';
    if (!name) continue;

    const members = [];
    const svcMembers = safeArray(grp.service_object);
    for (const m of svcMembers) {
      if (typeof m === 'string') {
        members.push(m);
      } else if (m && m.name) {
        members.push(m.name);
      }
    }

    groups.push({
      name,
      members,
      description: grp.description || '',
    });
  }

  return groups;
}

/**
 * Parses access rules (security policies) from SonicWall JSON export.
 * Handles source/destination address resolution, service mapping,
 * action translation, and sorting by priority.
 */
function parseJsonAccessRules(config, warnings) {
  const policies = [];
  const accessRules = config.access_rules || {};
  let ruleIndex = 1;

  const ipv4Rules = safeArray(accessRules.ipv4);
  const ipv6Rules = safeArray(accessRules.ipv6);
  const allRules = [...ipv4Rules, ...ipv6Rules];

  // Sort by priority if available
  allRules.sort((a, b) => {
    const pA = a.priority?.manual ?? a.priority?.auto ?? 9999;
    const pB = b.priority?.manual ?? b.priority?.auto ?? 9999;
    return pA - pB;
  });

  for (const rule of allRules) {
    const ruleName = rule.name || rule.comment || `Rule-${ruleIndex}`;
    const uuid = rule.uuid || '';

    // Zones
    const fromZone = rule.from || '';
    const toZone = rule.to || '';

    // Source addresses
    const srcAddrs = resolveAddress(rule.source?.address);
    const dstAddrs = resolveAddress(rule.destination?.address);

    // Services
    const serviceNames = resolveService(rule.service);

    // Action mapping
    let action = 'deny';
    const rawAction = (rule.action || '').toLowerCase();
    if (rawAction === 'allow' || rawAction === 'permit') {
      action = 'allow';
    } else if (rawAction === 'deny' || rawAction === 'discard' || rawAction === 'drop') {
      action = 'deny';
    }

    // Logging
    const logEnabled = rule.logging === true || rule.logging === 'enable' || rule.logging === 'enabled';

    // Schedule
    let scheduleName = '';
    if (rule.schedule && !rule.schedule.always_on) {
      scheduleName = rule.schedule.name || rule.schedule || '';
      if (typeof scheduleName !== 'string') scheduleName = '';
    }

    // Comment / description
    const comment = rule.comment || rule.description || '';

    // Priority
    const priority = rule.priority?.manual ?? rule.priority?.auto ?? null;

    // Enabled state
    const enabled = rule.enabled !== false;

    // DPI
    const dpiEnabled = rule.dpi === true;

    // Connection limit
    const connectionLimitEnabled = rule.connection_limit?.enabled === true;

    // User/group identity references
    const srcUsers = [];
    const userRef = rule.source?.user;
    const groupRef = rule.source?.group;
    if (userRef && userRef !== 'all' && userRef !== 'All') srcUsers.push(typeof userRef === 'string' ? userRef : String(userRef));
    if (groupRef && groupRef !== 'all' && groupRef !== 'All') srcUsers.push(`group:${typeof groupRef === 'string' ? groupRef : String(groupRef)}`);

    const policy = {
      name: ruleName,
      src_zones: fromZone ? [fromZone] : [],
      dst_zones: toZone ? [toZone] : [],
      src_addresses: srcAddrs,
      dst_addresses: dstAddrs,
      negate_source: false,
      negate_destination: false,
      applications: [],
      services: serviceNames,
      action,
      log_start: false,
      log_end: logEnabled,
      profile_group: '',
      security_profiles: {},
      description: comment,
      tags: [],
      disabled: !enabled,
      schedule: scheduleName,
      source_users: srcUsers,
      _rule_index: ruleIndex++,
      _sonicwall: {
        uuid,
        priority,
        connectionLimit: connectionLimitEnabled,
        dpi: dpiEnabled,
        schedule: scheduleName,
      },
    };

    if (policy.source_users.length > 0) {
      warnings.push(createWarning(
        'warning',
        `security-rule/${policy.name}`,
        `Rule "${policy.name}" uses identity [${policy.source_users.join(', ')}] — SRX requires JIMS for user identification`,
        'Configure SRX user-identification with JIMS and verify user/group names match Active Directory'
      ));
    }

    policies.push(policy);
  }

  return policies;
}

/**
 * Parses NAT policies from SonicWall JSON export.
 * Handles source NAT (masquerade/pool), destination NAT, and combined cases.
 */
function parseJsonNatPolicies(config, warnings) {
  const natRules = [];
  const natPolicies = config.nat_policies || {};
  let ruleIndex = 1;

  const ipv4Rules = safeArray(natPolicies.ipv4);
  const ipv6Rules = safeArray(natPolicies.ipv6);
  const allRules = [...ipv4Rules, ...ipv6Rules];

  for (const rule of allRules) {
    const name = rule.name || rule.comment || `NAT-${ruleIndex}`;
    const uuid = rule.uuid || '';
    const enabled = rule.enabled !== false;

    if (!enabled) {
      ruleIndex++;
      continue;
    }

    // Determine inbound/outbound zones
    const srcZone = rule.inbound || '';
    const dstZone = rule.outbound || '';

    // Original source/destination addresses
    const origSrc = resolveNatAddress(rule.original_source);
    const origDst = resolveNatAddress(rule.original_destination);

    // Translated source/destination
    const xlatedSrc = resolveNatAddress(rule.translated_source);
    const xlatedDst = resolveNatAddress(rule.translated_destination);

    // Determine if source or destination (or both) are being translated
    const srcTranslated = !isOriginal(rule.translated_source);
    const dstTranslated = !isOriginal(rule.translated_destination);

    // Determine NAT type
    let natType = 'source';
    if (srcTranslated && dstTranslated) natType = 'source-and-destination';
    else if (!srcTranslated && dstTranslated) natType = 'destination';
    else if (srcTranslated && !dstTranslated) natType = 'source';
    else {
      // Neither translated - skip this rule, it's a no-op
      ruleIndex++;
      continue;
    }

    // Build translated_src
    let translated_src = null;
    if (srcTranslated) {
      const xlatedName = xlatedSrc;
      // Check if translating to an interface IP (e.g., "X1 IP")
      if (typeof xlatedName === 'string' && xlatedName.match(/^X\d+\s+IP$/i)) {
        translated_src = { type: 'interface', addresses: [] };
      } else {
        translated_src = { type: 'dynamic-ip-pool', addresses: [xlatedName] };
      }
    }

    // Build translated_dst
    let translated_dst = null;
    if (dstTranslated) {
      translated_dst = xlatedDst;
    }

    // Translated service/port
    let translated_port = null;
    if (rule.translated_service && !isOriginal(rule.translated_service)) {
      const xlatedSvc = resolveNatAddress(rule.translated_service);
      if (xlatedSvc && xlatedSvc !== 'any') {
        translated_port = xlatedSvc;
      }
    }

    natRules.push({
      name,
      type: natType,
      src_zones: srcZone ? [srcZone] : [],
      dst_zones: dstZone ? [dstZone] : [],
      src_addresses: [origSrc],
      dst_addresses: [origDst],
      translated_src,
      translated_dst,
      translated_port,
      description: rule.comment || `SonicWall NAT policy: ${name}`,
      _rule_index: ruleIndex++,
    });
  }

  return natRules;
}

/**
 * Parses route policies (static routes) from SonicWall JSON export.
 */
function parseJsonRoutePolicies(config, warnings) {
  const routes = [];
  const routePolicies = config.route_policies || {};
  const ipv4Routes = safeArray(routePolicies.ipv4);

  for (const route of ipv4Routes) {
    const dest = route.destination?.name || route.destination || '0.0.0.0';
    const mask = route.mask?.name || route.mask || '0.0.0.0';
    const gateway = route.gateway || '';
    const iface = route.interface || '';
    const metric = route.metric || 1;

    const cidr = swMaskToCidr(mask);
    const destination = `${dest}/${cidr}`;

    routes.push({
      name: `${iface || 'route'}-${routes.length + 1}`,
      destination,
      next_hop: gateway,
      next_hop_type: 'ip-address',
      interface: iface,
      metric,
      admin_distance: metric,
      description: route.comment || '',
      vrf: '',
      routing_context: '',
    });
  }

  return routes;
}


// ---------------------------------------------------------------------------
// CLI Format Parser (fallback)
// ---------------------------------------------------------------------------

function parseCliFormat(text, warnings) {
  const lines = text.split('\n').map(l => l.trimEnd());

  const addressObjects = parseCliAddressObjects(lines, warnings);
  const addressGroups = parseCliAddressGroups(lines, warnings);
  const serviceObjects = parseCliServiceObjects(lines, warnings);
  const securityPolicies = parseCliAccessRules(lines, warnings);
  const natRules = parseCliNatPolicies(lines, warnings);
  const zones = inferCliZones(securityPolicies, addressObjects);

  const intermediateConfig = {
    zones,
    address_objects: addressObjects,
    address_groups: addressGroups,
    service_objects: serviceObjects,
    service_groups: [],
    security_policies: securityPolicies,
    nat_rules: natRules,
    applications: [],
    application_groups: [],
    schedules: [],
    security_profile_objects: [],
    external_lists: [],
    vpn_tunnels: [],
    ha_config: null,
    screen_config: [],
    syslog_config: [],
    snmp_config: [],
    aaa_config: [],
    dhcp_config: [],
    qos_config: [],
    interfaces: [],
    lag_interfaces: [],
    routing_contexts: [{ name: 'default', type: 'default', virtual_routers: [], zones: [] }],
    static_routes: [],
    bgp_config: [],
    ospf_config: [],
    ospf3_config: [],
    evpn_config: [],
    vxlan_config: [],
    target_context: null,
    transparent_mode: false,
    bridge_domains: [],
    l2_interfaces: [],
    vwire_pairs: [],
    _sonicwall: {
      builtinObjects: Object.keys(SONICWALL_BUILTINS),
    },
    metadata: {
      source_vendor: 'sonicwall',
      source_version: '',
      export_date: new Date().toISOString(),
      rule_count: securityPolicies.length,
      nat_rule_count: natRules.length,
      object_count: addressObjects.length + serviceObjects.length,
      zone_count: zones.length,
      interface_count: 0,
      vpn_tunnel_count: 0,
      syslog_server_count: 0,
      dhcp_config_count: 0,
      qos_profile_count: 0,
      routing_context_count: 1,
      static_route_count: 0,
      ha_enabled: false,
      multi_vsys: false,
    },
  };

  warnings.push(createWarning(
    'info',
    'parse/format',
    'Parsed SonicWall CLI text format (limited fidelity compared to REST API JSON export)',
    'For complete parsing, export configuration via SonicOS REST API in JSON format'
  ));

  return {
    intermediateConfig,
    warnings,
    parseStats: intermediateConfig.metadata,
  };
}


// ---------------------------------------------------------------------------
// CLI Section Parsers
// ---------------------------------------------------------------------------

/**
 * Parses address-object lines from CLI text.
 * Format: address-object ipv4 "<name>" host|network|range ... zone <zone>
 */
function parseCliAddressObjects(lines, warnings) {
  const objects = [];

  for (const line of lines) {
    const trimmed = line.trim();

    // address-object ipv4 "WebServer1" host 10.0.1.10 zone LAN
    const hostMatch = trimmed.match(
      /^address-object\s+ipv4\s+"([^"]+)"\s+host\s+(\S+)(?:\s+zone\s+(\S+))?/i
    );
    if (hostMatch) {
      objects.push({
        name: hostMatch[1],
        type: 'host',
        value: `${hostMatch[2]}/32`,
        description: '',
        tags: [],
      });
      continue;
    }

    // address-object ipv4 "DMZ-Net" network 172.16.0.0 255.255.255.0 zone DMZ
    const netMatch = trimmed.match(
      /^address-object\s+ipv4\s+"([^"]+)"\s+network\s+(\S+)\s+(\S+)(?:\s+zone\s+(\S+))?/i
    );
    if (netMatch) {
      const cidr = swMaskToCidr(netMatch[3]);
      objects.push({
        name: netMatch[1],
        type: 'network',
        value: `${netMatch[2]}/${cidr}`,
        description: '',
        tags: [],
      });
      continue;
    }

    // address-object ipv4 "ExtServer" range 203.0.113.50 203.0.113.60 zone WAN
    const rangeMatch = trimmed.match(
      /^address-object\s+ipv4\s+"([^"]+)"\s+range\s+(\S+)\s+(\S+)(?:\s+zone\s+(\S+))?/i
    );
    if (rangeMatch) {
      objects.push({
        name: rangeMatch[1],
        type: 'range',
        value: `${rangeMatch[2]}-${rangeMatch[3]}`,
        description: '',
        tags: [],
      });
      continue;
    }

    // address-object fqdn "google-dns" domain dns.google.com zone WAN
    const fqdnMatch = trimmed.match(
      /^address-object\s+fqdn\s+"([^"]+)"\s+domain\s+(\S+)(?:\s+zone\s+(\S+))?/i
    );
    if (fqdnMatch) {
      objects.push({
        name: fqdnMatch[1],
        type: 'fqdn',
        value: fqdnMatch[2],
        description: '',
        tags: [],
      });
      warnings.push(createWarning(
        'info',
        `address/${fqdnMatch[1]}`,
        `FQDN address "${fqdnMatch[1]}" (${fqdnMatch[2]}) requires SRX dns-name support (SRX 12.1+)`,
        'Verify SRX version supports dns-name, or replace with static IP'
      ));
      continue;
    }
  }

  // Auto-tag ip_version on all address objects
  for (const obj of objects) {
    obj.ip_version = detectIpVersion(obj.value);
  }

  return objects;
}

/**
 * Parses address-group blocks from CLI text.
 * Format:
 *   address-group ipv4 "WebServers"
 *     address-object ipv4 "WebServer1"
 */
function parseCliAddressGroups(lines, warnings) {
  const groups = [];
  let currentGroup = null;

  for (const line of lines) {
    const trimmed = line.trim();

    // Start of a new group (only at top level; an indented line is a nested member)
    const grpMatch = trimmed.match(/^address-group\s+ipv4\s+"([^"]+)"/i);
    const isIndented = line.startsWith(' ') || line.startsWith('\t');
    if (grpMatch && !(currentGroup && isIndented)) {
      if (currentGroup) groups.push(currentGroup);
      currentGroup = { name: grpMatch[1], members: [], description: '', tags: [] };
      continue;
    }

    // Member of current group (indented line)
    if (currentGroup && (line.startsWith(' ') || line.startsWith('\t'))) {
      const memberMatch = trimmed.match(/^address-object\s+ipv4\s+"([^"]+)"/i);
      if (memberMatch) {
        currentGroup.members.push(memberMatch[1]);
        continue;
      }
      const grpMemberMatch = trimmed.match(/^address-group\s+ipv4\s+"([^"]+)"/i);
      if (grpMemberMatch) {
        currentGroup.members.push(grpMemberMatch[1]);
        continue;
      }
    } else if (currentGroup && !line.startsWith(' ') && !line.startsWith('\t') && trimmed) {
      // End of indented block
      groups.push(currentGroup);
      currentGroup = null;
    }
  }

  if (currentGroup) groups.push(currentGroup);
  return groups;
}

/**
 * Parses service-object lines from CLI text.
 * Format: service-object "<name>" protocol <proto> <start> <end>
 */
function parseCliServiceObjects(lines, warnings) {
  const services = [];

  for (const line of lines) {
    const trimmed = line.trim();

    const svcMatch = trimmed.match(
      /^service-object\s+"([^"]+)"\s+protocol\s+(\S+)\s+(\d+)\s+(\d+)/i
    );
    if (svcMatch) {
      const begin = parseInt(svcMatch[3], 10);
      const end = parseInt(svcMatch[4], 10);
      services.push({
        name: svcMatch[1],
        protocol: svcMatch[2].toLowerCase(),
        port_range: begin === end ? String(begin) : `${begin}-${end}`,
        source_port: '',
        description: '',
      });
    }
  }

  return services;
}

/**
 * Parses access-rule lines from CLI text.
 * Format: access-rule ipv4 from <zone> to <zone> action <action> source <src> destination <dst> service <svc>
 */
function parseCliAccessRules(lines, warnings) {
  const policies = [];
  let ruleIndex = 1;

  for (const line of lines) {
    const trimmed = line.trim();

    const ruleMatch = trimmed.match(
      /^access-rule\s+ipv4\s+from\s+(\S+)\s+to\s+(\S+)\s+action\s+(\S+)\s+source\s+("[^"]+"|\S+)\s+destination\s+("[^"]+"|\S+)\s+service\s+(.+)/i
    );
    if (!ruleMatch) {
      if (/^access-rule\s/i.test(trimmed)) {
        warnings.push(createWarning('warning', 'access-rule', `Could not parse access-rule line: ${trimmed}`,
          'Review this rule by hand; it was not converted'));
      }
      continue;
    }
    const fromZone = ruleMatch[1];
    const toZone = ruleMatch[2];
    let action = ruleMatch[3].toLowerCase();
    const src = ruleMatch[4];
    const dst = ruleMatch[5];
    const svc = ruleMatch[6].trim();

    if (action === 'discard' || action === 'drop') action = 'deny';
    if (action === 'permit') action = 'allow';

    // Resolve 'any' keyword
    const srcAddrs = src.toLowerCase() === 'any' ? ['any'] : [unquote(src)];
    const dstAddrs = dst.toLowerCase() === 'any' ? ['any'] : [unquote(dst)];
    const serviceNames = svc.toLowerCase() === 'any' ? ['any'] : [unquote(svc)];

    policies.push({
      name: `Rule-${ruleIndex}`,
      src_zones: [fromZone],
      dst_zones: [toZone],
      src_addresses: srcAddrs,
      dst_addresses: dstAddrs,
      negate_source: false,
      negate_destination: false,
      applications: [],
      services: serviceNames,
      action,
      log_start: false,
      log_end: false,
      profile_group: '',
      security_profiles: {},
      description: '',
      tags: [],
      disabled: false,
      schedule: '',
      source_users: [],
      _rule_index: ruleIndex++,
      _sonicwall: {
        uuid: '',
        priority: null,
        connectionLimit: false,
        dpi: false,
        schedule: '',
      },
    });
  }

  return policies;
}

/**
 * Parses nat-policy lines from CLI text.
 * Format: nat-policy ipv4 original-source <src> translated-source "<xlated>" inbound <in> outbound <out>
 */
function parseCliNatPolicies(lines, warnings) {
  const natRules = [];
  let ruleIndex = 1;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('nat-policy ')) continue;

    // Extract key-value pairs from the line
    const origSrcMatch = trimmed.match(/original-source\s+(?:"([^"]+)"|(\S+))/i);
    const xlatedSrcMatch = trimmed.match(/translated-source\s+(?:"([^"]+)"|(\S+))/i);
    const origDstMatch = trimmed.match(/original-destination\s+(?:"([^"]+)"|(\S+))/i);
    const xlatedDstMatch = trimmed.match(/translated-destination\s+(?:"([^"]+)"|(\S+))/i);
    const inboundMatch = trimmed.match(/inbound\s+(\S+)/i);
    const outboundMatch = trimmed.match(/outbound\s+(\S+)/i);

    const origSrc = origSrcMatch ? (origSrcMatch[1] || origSrcMatch[2] || 'any') : 'any';
    const xlatedSrc = xlatedSrcMatch ? (xlatedSrcMatch[1] || xlatedSrcMatch[2] || origSrc) : origSrc;
    const origDst = origDstMatch ? (origDstMatch[1] || origDstMatch[2] || 'any') : 'any';
    const xlatedDst = xlatedDstMatch ? (xlatedDstMatch[1] || xlatedDstMatch[2] || origDst) : origDst;
    const srcZone = inboundMatch ? inboundMatch[1] : '';
    const dstZone = outboundMatch ? outboundMatch[1] : '';

    const srcTranslated = origSrc.toLowerCase() !== xlatedSrc.toLowerCase();
    const dstTranslated = origDst.toLowerCase() !== xlatedDst.toLowerCase();

    if (!srcTranslated && !dstTranslated) {
      ruleIndex++;
      continue;
    }

    let natType = 'source';
    if (srcTranslated && dstTranslated) natType = 'source-and-destination';
    else if (!srcTranslated && dstTranslated) natType = 'destination';

    let translated_src = null;
    if (srcTranslated) {
      if (xlatedSrc.match(/^X\d+\s+IP$/i)) {
        translated_src = { type: 'interface', addresses: [] };
      } else {
        translated_src = { type: 'dynamic-ip-pool', addresses: [xlatedSrc] };
      }
    }

    natRules.push({
      name: `NAT-${ruleIndex}`,
      type: natType,
      src_zones: srcZone ? [srcZone] : [],
      dst_zones: dstZone ? [dstZone] : [],
      src_addresses: [origSrc.toLowerCase() === 'any' ? 'any' : origSrc],
      dst_addresses: [origDst.toLowerCase() === 'any' ? 'any' : origDst],
      translated_src,
      translated_dst: dstTranslated ? xlatedDst : null,
      translated_port: null,
      description: `SonicWall CLI NAT rule ${ruleIndex}`,
      _rule_index: ruleIndex++,
    });
  }

  return natRules;
}

/**
 * Infers zones from policy references when parsing CLI format.
 * CLI text may not have explicit zone definitions, so we gather
 * zone names from access rules and address objects.
 */
function inferCliZones(policies, addressObjects) {
  const zoneNames = new Set();

  for (const p of policies) {
    for (const z of p.src_zones) if (z) zoneNames.add(z);
    for (const z of p.dst_zones) if (z) zoneNames.add(z);
  }

  return Array.from(zoneNames).map(name => ({
    name,
    description: `Inferred zone from CLI config`,
    interfaces: [],
  }));
}


// ---------------------------------------------------------------------------
// Address / Service Resolution Helpers
// ---------------------------------------------------------------------------

/**
 * Resolves a SonicWall address field to an array of address names.
 * Handles { any: true }, { name: "objName" }, { group: "grpName" },
 * and arrays of those.
 */
function resolveAddress(addrField) {
  if (!addrField) return ['any'];

  if (addrField.any === true || addrField.any === 'true') return ['any'];

  if (addrField.name) {
    const name = addrField.name;
    // Check if it's a built-in that maps to 'any'
    if (SONICWALL_BUILTINS[name] === 'any') return ['any'];
    return [name];
  }

  if (addrField.group) return [addrField.group];

  // Array of address entries
  if (Array.isArray(addrField)) {
    const result = [];
    for (const item of addrField) {
      if (typeof item === 'string') {
        result.push(item === 'Any' ? 'any' : item);
      } else if (item?.name) {
        if (SONICWALL_BUILTINS[item.name] === 'any') result.push('any');
        else result.push(item.name);
      } else if (item?.group) {
        result.push(item.group);
      }
    }
    return result.length > 0 ? result : ['any'];
  }

  // Fallback: if it's a plain string
  if (typeof addrField === 'string') {
    if (addrField.toLowerCase() === 'any' || addrField === 'Any') return ['any'];
    return [addrField];
  }

  return ['any'];
}

/**
 * Resolves a SonicWall service field to an array of service names.
 * Handles { any: true }, { name: "svcName" }, and arrays.
 */
function resolveService(svcField) {
  if (!svcField) return ['any'];

  if (svcField.any === true || svcField.any === 'true') return ['any'];

  if (svcField.name) {
    const name = svcField.name;
    // Try mapping well-known service names
    const mapped = mapAppToJunos(name);
    return [mapped || name];
  }

  if (svcField.group) return [svcField.group];

  // Array of service entries
  if (Array.isArray(svcField)) {
    const result = [];
    for (const item of svcField) {
      if (typeof item === 'string') {
        const mapped = mapAppToJunos(item);
        result.push(mapped || item);
      } else if (item?.name) {
        const mapped = mapAppToJunos(item.name);
        result.push(mapped || item.name);
      } else if (item?.group) {
        result.push(item.group);
      }
    }
    return result.length > 0 ? result : ['any'];
  }

  if (typeof svcField === 'string') {
    if (svcField.toLowerCase() === 'any') return ['any'];
    const mapped = mapAppToJunos(svcField);
    return [mapped || svcField];
  }

  return ['any'];
}

/**
 * Resolves a NAT address field to a single address name string.
 * Handles { any: true }, { name: "..." }, { original: true }, or plain string.
 */
function resolveNatAddress(field) {
  if (!field) return 'any';
  if (field.any === true || field.any === 'true') return 'any';
  if (field.original === true || field.original === 'true') return 'original';
  if (field.name) return field.name;
  if (typeof field === 'string') return field;
  return 'any';
}

/**
 * Checks if a NAT field indicates "original" (no translation).
 */
function isOriginal(field) {
  if (!field) return true;
  if (field.original === true || field.original === 'true') return true;
  if (typeof field === 'string' && field.toLowerCase() === 'original') return true;
  return false;
}


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Converts a SonicWall subnet mask (dotted or CIDR) to CIDR prefix length.
 *
 * @param {string} mask - Subnet mask in dotted notation (255.255.255.0) or CIDR (24)
 * @returns {string} - CIDR prefix length as string
 */
function swMaskToCidr(mask) {
  if (!mask) return '32';
  if (/^\d+$/.test(mask) && parseInt(mask) <= 32) return mask;
  const parts = mask.split('.');
  if (parts.length !== 4) return '32';
  let cidr = 0;
  for (const p of parts) cidr += (parseInt(p) >>> 0).toString(2).split('1').length - 1;
  return String(cidr);
}

/**
 * Ensures a value is always an array.
 * Handles undefined, null, single values, and existing arrays.
 */
function safeArray(value) {
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) return value;
  return [value];
}

/**
 * Removes surrounding double quotes from a string.
 */
function unquote(s) {
  if (!s) return s;
  if (s.startsWith('"') && s.endsWith('"')) return s.slice(1, -1);
  return s;
}

/**
 * Builds an empty result for error cases.
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
    external_lists: [],
    vpn_tunnels: [],
    ha_config: null,
    screen_config: [],
    syslog_config: [],
    snmp_config: [],
    aaa_config: [],
    dhcp_config: [],
    qos_config: [],
    interfaces: [],
    lag_interfaces: [],
    routing_contexts: [{ name: 'default', type: 'default', virtual_routers: [], zones: [] }],
    static_routes: [],
    bgp_config: [],
    ospf_config: [],
    ospf3_config: [],
    evpn_config: [],
    vxlan_config: [],
    target_context: null,
    transparent_mode: false,
    bridge_domains: [],
    l2_interfaces: [],
    vwire_pairs: [],
    _sonicwall: {
      builtinObjects: Object.keys(SONICWALL_BUILTINS),
    },
    metadata: {
      source_vendor: 'sonicwall',
      source_version: '',
      export_date: new Date().toISOString(),
      rule_count: 0,
      nat_rule_count: 0,
      object_count: 0,
      zone_count: 0,
      interface_count: 0,
      vpn_tunnel_count: 0,
      syslog_server_count: 0,
      dhcp_config_count: 0,
      qos_profile_count: 0,
      routing_context_count: 1,
      static_route_count: 0,
      ha_enabled: false,
      multi_vsys: false,
    },
  };

  return {
    intermediateConfig,
    warnings,
    parseStats: intermediateConfig.metadata,
  };
}


// ---------------------------------------------------------------------------
// LAG / Aggregate Interface Parser
// ---------------------------------------------------------------------------

/**
 * Parses SonicWall LAG/aggregate interfaces from REST API JSON config.
 *
 * SonicWall JSON may contain LAG configuration in interface objects:
 *   { "interfaces": { "ipv4": [ { "name": "X0", "lag": { ... } } ] } }
 *   or under a "lag" / "port_aggregation" / "link_aggregation" section.
 *
 * @param {Object} config - Parsed SonicWall JSON config
 * @param {Object[]} warnings - Warnings array
 * @returns {Object[]} Array of lag_interfaces in intermediate schema format
 */
function parseSonicwallLagInterfaces(config, warnings) {
  const lagInterfaces = [];

  // Strategy 1: Check for explicit LAG / link_aggregation section
  const lagSection = config.lag || config.link_aggregation || config.port_aggregation || {};
  const lagEntries = Array.isArray(lagSection) ? lagSection : (lagSection.entries || lagSection.groups || []);

  let aeIndex = 0;
  for (const entry of lagEntries) {
    if (!entry || typeof entry !== 'object') continue;

    const sourceName = entry.name || entry.id || `LAG${aeIndex}`;
    const members = Array.isArray(entry.members || entry.interfaces)
      ? (entry.members || entry.interfaces).map(m => typeof m === 'object' ? (m.name || m.interface || '') : String(m)).filter(Boolean)
      : [];

    const lacpMode = entry.lacp_mode || entry.mode || (entry.lacp ? 'active' : 'static');
    const description = entry.description || entry.comment || '';

    lagInterfaces.push({
      name: `ae${aeIndex}`,
      source_name: sourceName,
      members,
      source_members: [...members],
      lacp_mode: lacpMode,
      lacp_priority: null,
      description,
    });
    aeIndex++;
  }

  // Strategy 2: Check interface objects for lag/aggregate type
  const ifaceSections = config.interfaces || {};
  const allIfaces = [
    ...(Array.isArray(ifaceSections.ipv4) ? ifaceSections.ipv4 : []),
    ...(Array.isArray(ifaceSections.ipv6) ? ifaceSections.ipv6 : []),
    ...(Array.isArray(ifaceSections) ? ifaceSections : []),
  ];

  for (const iface of allIfaces) {
    if (!iface || typeof iface !== 'object') continue;
    if (!iface.lag && !iface.aggregate && iface.type !== 'lag' && iface.type !== 'aggregate') continue;

    // Avoid duplicates from strategy 1
    const sourceName = iface.name || '';
    if (lagInterfaces.some(l => l.source_name === sourceName)) continue;

    const lagData = iface.lag || iface.aggregate || {};
    const members = Array.isArray(lagData.members || lagData.interfaces)
      ? (lagData.members || lagData.interfaces).map(m => typeof m === 'object' ? (m.name || '') : String(m)).filter(Boolean)
      : [];

    lagInterfaces.push({
      name: `ae${aeIndex}`,
      source_name: sourceName,
      members,
      source_members: [...members],
      lacp_mode: lagData.lacp_mode || lagData.mode || 'static',
      lacp_priority: null,
      description: iface.comment || iface.description || '',
    });
    aeIndex++;
  }

  if (lagInterfaces.length > 0) {
    warnings.push(createWarning('info', 'lag',
      `Parsed ${lagInterfaces.length} LAG/aggregate interface(s) with ${lagInterfaces.reduce((s, l) => s + l.members.length, 0)} member(s)`,
      'LAG interfaces will be converted to SRX ae interfaces'));
  }

  return lagInterfaces;
}
