/**
 * PAN-OS XML Configuration Parser
 * =================================
 * Agent: PANOS-Expert
 *
 * Parses PAN-OS running-config XML exports (both device-level and Panorama)
 * into the vendor-neutral intermediate JSON schema.
 *
 * Handles:
 *   - Security zones and interfaces
 *   - Address objects (IP, FQDN, range, wildcard)
 *   - Address groups (static and dynamic)
 *   - Service objects (TCP/UDP with port ranges)
 *   - Service groups
 *   - Security rules (with all match criteria, actions, logging)
 *   - NAT rules (source, destination, static)
 *   - Custom applications
 *   - Basic VPN/IKE gateway detection
 *
 * Designed for configs up to 10,000+ rules — avoids unnecessary object
 * copies and uses direct property access where possible.
 */

import { XMLParser } from 'fast-xml-parser';
import {
  ensureArray,
  extractMembers,
  extractEntries,
  getNestedValue,
  createWarning,
  detectVendor,
  detectIpVersion,
  buildStaticNatFields,
} from './parser-utils.js';

// ---------------------------------------------------------------------------
// XML Parser Configuration
// ---------------------------------------------------------------------------

const xmlParserOptions = {
  ignoreAttributes: false,       // PAN-OS uses name="..." on <entry> elements
  attributeNamePrefix: '@_',     // Access attributes as @_name, @_uuid, etc.
  allowBooleanAttributes: true,
  parseTagValue: true,
  trimValues: true,
  // Security: disable entity processing to prevent XXE and entity expansion DoS
  processEntities: false,
  // Force 'entry' and 'member' to always be arrays even when there's only one child.
  // These are the only PAN-OS elements that appear as repeated siblings.
  // Container nodes like <zone>, <address>, <rulebase> are singletons and must NOT
  // be forced to arrays — doing so breaks navigation (e.g., vsys.zone becomes [obj]
  // instead of obj).
  isArray: (name) => {
    return name === 'entry' || name === 'member';
  },
};

// ---------------------------------------------------------------------------
// Main Parser Entry Point
// ---------------------------------------------------------------------------

/**
 * Parses a complete PAN-OS XML configuration into the intermediate JSON schema.
 *
 * @param {string} configText - Raw PAN-OS XML configuration text
 * @returns {{ intermediateConfig: Object, warnings: Object[], parseStats: Object }}
 */
export function parsePanosConfig(configText) {
  // Detect vendor to confirm this is PAN-OS
  const detection = detectVendor(configText);
  if (detection.vendor !== 'panos' && detection.vendor !== 'unknown') {
    throw new Error(`Detected vendor "${detection.vendor}" — this parser only supports PAN-OS XML configs`);
  }

  const parser = new XMLParser(xmlParserOptions);
  let parsed;
  try {
    parsed = parser.parse(configText);
  } catch (err) {
    throw new Error(`Failed to parse XML: ${err.message}`);
  }

  const warnings = [];

  // Navigate to the vsys config. PAN-OS XML structure:
  // <config> → <devices> → <entry> → <vsys> → <entry name="vsys1">
  const config = parsed.config;
  if (!config) {
    throw new Error('Invalid PAN-OS config: missing <config> root element');
  }

  // Extract PAN-OS version from config attributes
  const panosVersion = config['@_version'] || 'unknown';

  // Find the vsys entry — handle both device-level and Panorama exports
  const vsysList = findVsysEntries(config);
  if (vsysList.length === 0) {
    throw new Error('No vsys found in configuration. Ensure this is a valid PAN-OS device config or Panorama export.');
  }

  // Parse all vsys entries — merge objects from each vsys
  const multiVsys = vsysList.length > 1;
  const allZones = [];
  const allAddressObjects = [];
  const allAddressGroups = [];
  const allServiceObjects = [];
  const allServiceGroups = [];
  const allApplications = [];
  const allApplicationGroups = [];
  const allSecurityPolicies = [];
  const allNatRules = [];
  const allExternalLists = [];
  const allSchedules = [];
  const allSecurityProfileObjects = [];
  const allSecurityProfileDefinitions = {};
  const allDecryptionRules = [];
  const allPbfRules = [];
  const allBgpConfig = [];
  const allOspfConfig = [];
  const allOspf3Config = [];
  const routingContexts = [];

  // Parse HA configuration (device-level, not per-vsys)
  const haConfig = parseHaConfig(config, warnings);

  for (const vsys of vsysList) {
    const vsysName = vsys['@_name'] || 'vsys1';

    // Parse each config section
    const zones = parseZones(vsys, warnings);
    const addressObjects = parseAddressObjects(vsys, warnings);
    const addressGroups = parseAddressGroups(vsys, warnings);
    const serviceObjects = parseServiceObjects(vsys, warnings);
    const serviceGroups = parseServiceGroups(vsys, warnings);
    const applications = parseApplications(vsys, warnings);
    const applicationGroups = parseApplicationGroups(vsys, warnings);
    const securityPolicies = parseSecurityRules(vsys, warnings);
    const natRules = parseNatRules(vsys, warnings, serviceObjects);
    const externalLists = parseExternalLists(vsys, warnings);
    const schedules = parseScheduleObjects(vsys);

    // Resolve profile group references
    const profileGroupDefs = parseProfileGroupDefinitions(vsys);
    for (const policy of securityPolicies) {
      if (policy.profile_group && Object.keys(policy.security_profiles).length === 0) {
        const groupDef = profileGroupDefs[policy.profile_group];
        if (groupDef) {
          policy.security_profiles = { ...groupDef };
        }
      }
    }

    // Flag SecIntel rules
    flagSecIntelRules(securityPolicies, externalLists, warnings);

    // Tag policies with vsys name when multi-vsys
    if (multiVsys) {
      for (const policy of securityPolicies) {
        policy._vsys = vsysName;
      }
      for (const rule of natRules) {
        rule._vsys = vsysName;
      }
    }

    // Build security profile objects + definitions
    allSecurityProfileObjects.push(...buildSecurityProfileObjects(securityPolicies));
    const profileDefs = parseSecurityProfileDefinitions(vsys, warnings);
    Object.assign(allSecurityProfileDefinitions, profileDefs);

    // Append implicit rules for this vsys
    let implicitIndex = securityPolicies.length + 1;
    for (const zone of zones) {
      securityPolicies.push({
        name: `Implicit: Intra-zone Allow (${zone.name})`,
        src_zones: [zone.name],
        dst_zones: [zone.name],
        src_addresses: ['any'],
        dst_addresses: ['any'],
        negate_source: false,
        negate_destination: false,
        applications: ['any'],
        services: ['any'],
        action: 'allow',
        log_start: false,
        log_end: false,
        profile_group: '',
        security_profiles: {},
        description: 'PAN-OS default: traffic within the same zone is allowed',
        tags: ['added_by_fpic'],
        disabled: false,
        _rule_index: implicitIndex++,
        _implicit: true,
        ...(multiVsys ? { _vsys: vsysName } : {}),
      });
    }
    securityPolicies.push({
      name: 'Implicit: Interzone Default Deny',
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
      description: 'PAN-OS default: traffic between different zones is denied',
      tags: ['added_by_fpic'],
      disabled: false,
      _rule_index: implicitIndex++,
      _implicit: true,
      ...(multiVsys ? { _vsys: vsysName } : {}),
    });

    // Build routing context for this vsys (includes BGP/OSPF extraction)
    const vrResult = parseVirtualRouters(config, warnings);
    const virtualRouters = vrResult.virtualRouters || vrResult;
    const vrBgpConfigs = vrResult.bgpConfigs || [];
    const vrOspfConfigs = vrResult.ospfConfigs || [];
    const vrOspf3Configs = vrResult.ospf3Configs || [];
    allBgpConfig.push(...vrBgpConfigs);
    allOspfConfig.push(...vrOspfConfigs);
    allOspf3Config.push(...vrOspf3Configs);
    routingContexts.push({
      name: vsysName,
      type: 'vsys',
      virtual_routers: Array.isArray(virtualRouters) ? virtualRouters : [],
      zones: zones.map(z => z.name),
    });

    // Merge into aggregated arrays
    allZones.push(...zones);
    allAddressObjects.push(...addressObjects);
    allAddressGroups.push(...addressGroups);
    allServiceObjects.push(...serviceObjects);
    allServiceGroups.push(...serviceGroups);
    allApplications.push(...applications);
    allApplicationGroups.push(...applicationGroups);
    allSecurityPolicies.push(...securityPolicies);
    allNatRules.push(...natRules);
    allExternalLists.push(...externalLists);
    allSchedules.push(...schedules);

    // Parse decryption and PBF rulebases
    const decryptionRules = parseDecryptionRules(vsys, warnings);
    const pbfRules = parsePbfRules(vsys, warnings);
    allDecryptionRules.push(...decryptionRules);
    allPbfRules.push(...pbfRules);
  }

  // Flatten static routes from all virtual routers
  const staticRoutes = [];
  for (const ctx of routingContexts) {
    for (const vr of ctx.virtual_routers) {
      for (const route of vr.static_routes) {
        staticRoutes.push({ ...route, routing_context: ctx.name });
      }
    }
  }

  // Parse screen/DDoS protection profiles (device-level, not per-vsys)
  const screenConfig = parseScreenConfig(config, allZones, warnings);

  // Parse VPN/IPsec tunnel configuration (device-level, not per-vsys)
  const vpnTunnels = parseVpnConfig(config, warnings);

  // Parse syslog server configuration
  const syslogConfig = parseSyslogConfig(config, warnings);

  // Parse DHCP relay/server configuration
  const dhcpConfig = parseDhcpConfig(config, warnings);

  // Parse QoS/traffic shaping configuration
  const qosConfig = parseQosConfig(config, warnings);

  // Parse interface configurations
  const interfaces = parseInterfaceConfig(config, allZones, warnings);
  const lagInterfaces = parsePanosLagInterfaces(config, warnings);
  const vwirePairs = parseVwirePairs(config, warnings);
  const hasL2 = allZones.some(z => z.zone_type === 'layer2' || z.zone_type === 'virtual-wire');

  // Detect GlobalProtect (SSL-VPN) and mark the tunnel interfaces it binds.
  const globalProtect = parseGlobalProtect(config, warnings);
  const sslVpnTunnels = new Set(globalProtect.gateways.map(g => g.tunnel_interface));
  for (const iface of interfaces) {
    if (sslVpnTunnels.has(iface.name)) iface.remote_access_role = 'ssl-vpn';
  }

  // Re-index all policies across vsys for consistent ordering
  for (let i = 0; i < allSecurityPolicies.length; i++) {
    allSecurityPolicies[i]._rule_index = i + 1;
  }

  const intermediateConfig = {
    zones: allZones,
    address_objects: allAddressObjects,
    address_groups: allAddressGroups,
    service_objects: allServiceObjects,
    service_groups: allServiceGroups,
    security_policies: allSecurityPolicies,
    nat_rules: allNatRules,
    decryption_rules: allDecryptionRules,
    pbf_rules: allPbfRules,
    applications: allApplications,
    application_groups: allApplicationGroups,
    schedules: allSchedules,
    security_profile_objects: allSecurityProfileObjects,
    security_profile_definitions: allSecurityProfileDefinitions,
    external_lists: allExternalLists,
    vpn_tunnels: vpnTunnels,
    global_protect: globalProtect,
    ha_config: haConfig,
    screen_config: screenConfig,
    syslog_config: syslogConfig,
    snmp_config: parsePanosSnmpConfig(config, warnings),
    aaa_config: parsePanosAaaConfig(config, warnings),
    dhcp_config: dhcpConfig,
    qos_config: qosConfig,
    flow_monitoring_config: parseNetflowConfig(config, warnings),
    interfaces,
    lag_interfaces: lagInterfaces,
    transparent_mode: hasL2,
    bridge_domains: [],
    l2_interfaces: [],
    vwire_pairs: vwirePairs,
    routing_contexts: routingContexts,
    static_routes: staticRoutes,
    bgp_config: allBgpConfig,
    ospf_config: allOspfConfig,
    ospf3_config: allOspf3Config,
    evpn_config: [],
    vxlan_config: [],
    target_context: null,
    metadata: {
      source_vendor: 'panos',
      source_version: panosVersion,
      export_date: new Date().toISOString(),
      rule_count: allSecurityPolicies.length,
      nat_rule_count: allNatRules.length,
      decryption_rule_count: allDecryptionRules.length,
      pbf_rule_count: allPbfRules.length,
      object_count: allAddressObjects.length + allAddressGroups.length + allServiceObjects.length + allServiceGroups.length,
      zone_count: allZones.length,
      interface_count: interfaces.length,
      routing_context_count: routingContexts.length,
      static_route_count: staticRoutes.length,
      bgp_instance_count: allBgpConfig.length,
      ospf_instance_count: allOspfConfig.length,
      ospf3_instance_count: allOspf3Config.length,
      evpn_instance_count: 0,
      vxlan_tunnel_count: 0,
      vpn_tunnel_count: vpnTunnels.length,
      syslog_server_count: syslogConfig.length,
      dhcp_config_count: dhcpConfig.length,
      qos_profile_count: qosConfig.length,
      ha_enabled: !!(haConfig && haConfig.enabled),
      multi_vsys: multiVsys,
    },
  };

  return {
    intermediateConfig,
    warnings,
    parseStats: intermediateConfig.metadata,
  };
}

// ---------------------------------------------------------------------------
// HA Configuration
// ---------------------------------------------------------------------------

function parseHaConfig(config, warnings) {
  const devices = getNestedValue(config, 'devices');
  if (!devices) return null;
  const deviceEntries = extractEntries(devices);
  for (const device of deviceEntries) {
    const ha = getNestedValue(device, 'deviceconfig.high-availability');
    if (!ha) continue;

    const enabled = ha.enabled === 'yes' || ha.enabled === true;
    if (!enabled) return { enabled: false, mode: 'standalone', group_id: 0, priority: 128, preempt: false, peer_ip: '', ha_interfaces: [], monitoring: { link_groups: [], path_groups: [] }, description: 'HA disabled' };

    const group = ha.group || {};
    const groupId = parseInt(group['group-id']) || 1;
    const peerIp = group['peer-ip'] || '';

    // Determine mode
    let mode = 'active-passive';
    const modeNode = group.mode || {};
    if (modeNode['active-active']) mode = 'active-active';
    else if (modeNode['active-passive']) mode = 'active-passive';

    // Election options
    const election = group['election-option'] || {};
    const priority = parseInt(election['device-priority']) || 128;
    const preempt = election.preemptive === 'yes' || election.preemptive === true;

    // HA interfaces
    const haInterfaces = [];
    const haIface = ha.interface || {};
    for (const linkName of ['ha1', 'ha1-backup', 'ha2', 'ha2-backup', 'ha3']) {
      const link = haIface[linkName];
      if (!link) continue;
      const ipAddr = link['ip-address'] || '';
      const port = link.port || '';
      haInterfaces.push({
        name: linkName.toUpperCase(),
        ip: ipAddr.split('/')[0],
        netmask: ipAddr.includes('/') ? ipAddr.split('/')[1] : '',
        interface: port,
      });
    }

    // Link monitoring
    const monitoring = { link_groups: [], path_groups: [] };
    const linkMonitor = getNestedValue(ha, 'group.monitoring.link-monitoring.link-group');
    if (linkMonitor) {
      const groups = extractEntries(linkMonitor);
      for (const g of groups) {
        monitoring.link_groups.push({
          name: g['@_name'] || 'default',
          enabled: g.enabled !== 'no',
          interfaces: extractMembers(g.interface || g),
        });
      }
    }
    const pathMonitor = getNestedValue(ha, 'group.monitoring.path-monitoring.path-group');
    if (pathMonitor) {
      const groups = extractEntries(pathMonitor);
      for (const g of groups) {
        monitoring.path_groups.push({
          name: g['@_name'] || 'default',
          enabled: g.enabled !== 'no',
        });
      }
    }

    return {
      enabled,
      mode,
      group_id: groupId,
      priority,
      preempt,
      peer_ip: peerIp,
      ha_interfaces: haInterfaces,
      monitoring,
      description: `PAN-OS HA ${mode} group ${groupId}`,
    };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Screen / DDoS Protection Parser
// ---------------------------------------------------------------------------

/**
 * Parses PAN-OS zone protection profiles into the screen_config schema.
 * Profiles are at: config > devices > entry > network > profiles > zone-protection-profile > entry
 * Zone assignment: each zone entry may have <zone-protection-profile>profileName</zone-protection-profile>
 */
function parseScreenConfig(config, zones, warnings) {
  const screenConfigs = [];

  // Navigate to zone-protection-profile entries
  const devices = getNestedValue(config, 'devices');
  if (!devices) return screenConfigs;

  const deviceEntries = extractEntries(devices);
  let profileEntries = [];
  for (const device of deviceEntries) {
    const profiles = getNestedValue(device, 'network.profiles.zone-protection-profile');
    if (profiles) {
      profileEntries = extractEntries(profiles);
      break;
    }
  }

  if (profileEntries.length === 0) return screenConfigs;

  // Build a map from profile name to zone name (from parsed zones)
  const profileToZone = {};
  for (const device of deviceEntries) {
    const vsys = getNestedValue(device, 'vsys');
    if (!vsys) continue;
    const vsysEntries = extractEntries(vsys);
    for (const vs of vsysEntries) {
      const zoneContainer = vs.zone;
      if (!zoneContainer) continue;
      const zoneEntries = extractEntries(zoneContainer);
      for (const zEntry of zoneEntries) {
        const zoneName = zEntry['@_name'] || '';
        const zpp = getNestedValue(zEntry, 'network.zone-protection-profile');
        if (zpp && typeof zpp === 'string') {
          profileToZone[zpp] = zoneName;
        }
      }
    }
  }

  for (const entry of profileEntries) {
    const name = entry['@_name'] || 'unnamed-screen';
    const flood = entry.flood || {};

    // TCP SYN flood
    const tcpSyn = flood['tcp-syn'] || {};
    const tcpSynEnabled = getNestedValue(tcpSyn, 'enable') === 'yes';
    const activateRate = tcpSynEnabled ? (parseInt(getNestedValue(tcpSyn, 'red.activate-rate')) || null) : null;
    const alarmRate = tcpSynEnabled ? (parseInt(getNestedValue(tcpSyn, 'red.alarm-rate')) || null) : null;

    // ICMP flood
    const icmpFlood = flood.icmp || {};
    const icmpEnabled = getNestedValue(icmpFlood, 'enable') === 'yes';
    const icmpRate = icmpEnabled
      ? parseInt(getNestedValue(icmpFlood, 'red.alarm-rate') || getNestedValue(icmpFlood, 'red.activate-rate')) || null
      : null;

    // UDP flood
    const udpFlood = flood.udp || {};
    const udpEnabled = getNestedValue(udpFlood, 'enable') === 'yes';
    const udpRate = udpEnabled
      ? parseInt(getNestedValue(udpFlood, 'red.alarm-rate') || getNestedValue(udpFlood, 'red.activate-rate')) || null
      : null;

    // Reconnaissance (scan)
    const scan = entry.scan || {};

    // IP-related protections (under reconnaissaince or protocol-protection)
    const protocolProtection = entry['protocol-protection'] || {};

    const screen = {
      name,
      zone: profileToZone[name] || '',
      icmp: {
        flood_threshold: icmpRate,
        ping_death: false,
        fragment: false,
      },
      tcp: {
        syn_flood_threshold: activateRate ?? alarmRate,
        syn_flood_alarm_threshold: alarmRate ?? activateRate,
        syn_flood_timeout: null,
        land_attack: false,
        winnuke: false,
        tcp_no_flag: false,
      },
      udp: {
        flood_threshold: udpRate,
      },
      ip: {
        spoofing: false,
        source_route: false,
        tear_drop: false,
        record_route: false,
        timestamp: false,
      },
      limit_session: {
        source_based: null,
        destination_based: null,
      },
      description: '',
    };

    // Check for additional protections in the profile
    const disallowed = entry['disallowed-addresses'] || {};
    const ipDrop = entry['ip-drop'] || {};

    if (ipDrop['spoofed-ip-address'] || getNestedValue(ipDrop, 'spoofed-ip-address.enable') === 'yes') {
      screen.ip.spoofing = true;
    }
    if (ipDrop['strict-source-routing'] || ipDrop['loose-source-routing']) {
      screen.ip.source_route = true;
    }

    screenConfigs.push(screen);
  }

  if (screenConfigs.length > 0) {
    warnings.push(createWarning("info", "screen-config",
      `Parsed ${screenConfigs.length} zone protection profile(s)`,
      "Review screen/DDoS settings in the generated config"));
  }

  return screenConfigs;
}


// ---------------------------------------------------------------------------
// VSys Finder
// ---------------------------------------------------------------------------

/**
 * Locates all vsys entries in the config, handling both device-level
 * configs and Panorama device group structures.
 */
function findVsysEntries(config) {
  // Standard device config: config → devices → entry → vsys → entry
  const devices = getNestedValue(config, 'devices');
  if (devices) {
    const deviceEntries = extractEntries(devices);
    for (const device of deviceEntries) {
      const vsys = getNestedValue(device, 'vsys');
      if (vsys) {
        return extractEntries(vsys);
      }
    }
  }

  // Panorama shared config: config → shared (treat as single virtual vsys)
  const shared = getNestedValue(config, 'shared');
  if (shared) {
    return [shared];
  }

  // Direct vsys at config level (some export formats)
  const directVsys = getNestedValue(config, 'vsys');
  if (directVsys) {
    return extractEntries(directVsys);
  }

  return [];
}

// ---------------------------------------------------------------------------
// Virtual Router + Static Route Parser
// ---------------------------------------------------------------------------

/**
 * Parses PAN-OS virtual routers and their static routes.
 * VRs live at: config > devices > entry > network > virtual-router > entry
 */
function parseVirtualRouters(config, warnings) {
  const devices = getNestedValue(config, 'devices');
  if (!devices) return [];

  const bgpConfigs = [];
  const ospfConfigs = [];
  const ospf3Configs = [];

  const deviceEntries = extractEntries(devices);
  for (const device of deviceEntries) {
    const vrContainer = getNestedValue(device, 'network.virtual-router');
    if (!vrContainer) continue;

    const vrEntries = extractEntries(vrContainer);
    const virtualRouters = vrEntries.map(vr => {
      const name = vr['@_name'] || 'default';
      const interfaces = extractMembers(vr.interface || vr);
      const staticRoutes = parseVrStaticRoutes(vr);

      // Parse BGP and OSPF from this virtual-router
      const bgp = parseVrBgpConfig(vr, name);
      if (bgp) bgpConfigs.push(bgp);
      const ospf = parseVrOspfConfig(vr, name);
      if (ospf) ospfConfigs.push(ospf);
      const ospf3 = parseVrOspf3Config(vr, name);
      if (ospf3) ospf3Configs.push(ospf3);

      return { name, interfaces, static_routes: staticRoutes };
    });
    return { virtualRouters, bgpConfigs, ospfConfigs, ospf3Configs };
  }

  return { virtualRouters: [], bgpConfigs: [], ospfConfigs: [], ospf3Configs: [] };
}

function parseVrStaticRoutes(vrEntry) {
  const routeContainer = getNestedValue(vrEntry, 'routing-table.ip.static-route');
  if (!routeContainer) return [];

  const entries = extractEntries(routeContainer);
  return entries.map(entry => {
    const name = entry['@_name'] || '';
    const destination = entry.destination || '';

    // Next-hop can be: nexthop > ip-address, nexthop > next-vr, or nexthop > discard
    const nexthop = entry.nexthop || {};
    let nextHop = '';
    let nextHopType = 'ip-address';

    if (typeof nexthop === 'string') {
      nextHop = nexthop;
    } else if (nexthop['ip-address']) {
      nextHop = String(nexthop['ip-address']);
    } else if (nexthop['next-vr']) {
      nextHop = String(nexthop['next-vr']);
      nextHopType = 'next-vr';
    } else if (nexthop.discard !== undefined || nexthop.discard === '') {
      nextHopType = 'discard';
    } else if (nexthop.none !== undefined) {
      nextHopType = 'none';
    }

    const iface = entry.interface ? String(entry.interface) : '';
    const metric = parseInt(entry.metric) || 10;

    return {
      name,
      destination,
      next_hop: nextHop,
      next_hop_type: nextHopType,
      interface: iface,
      metric,
      admin_distance: null,
      description: '',
      vrf: '',
    };
  });
}

/**
 * Parses BGP configuration from a PAN-OS virtual-router entry.
 * Path: virtual-router > entry > protocol > bgp
 */
function parseVrBgpConfig(vrEntry, vrName) {
  const bgpNode = getNestedValue(vrEntry, 'protocol.bgp');
  if (!bgpNode) return null;

  const enabled = bgpNode.enable === 'yes' || bgpNode.enable === true;
  if (!enabled && !bgpNode['local-as']) return null;

  const localAs = bgpNode['local-as'] ? parseInt(String(bgpNode['local-as'])) || null : null;
  const routerId = bgpNode['router-id'] ? String(bgpNode['router-id']) : '';

  // Parse peer groups
  const peerGroups = [];
  const pgContainer = getNestedValue(bgpNode, 'peer-group');
  if (pgContainer) {
    const pgEntries = extractEntries(pgContainer);
    for (const pg of pgEntries) {
      const groupName = pg['@_name'] || 'default';
      const pgType = pg.type ? (pg.type.ebgp !== undefined ? 'external' :
        pg.type.ibgp !== undefined ? 'internal' : 'external') : 'external';

      const neighbors = [];
      const peerContainer = getNestedValue(pg, 'peer');
      if (peerContainer) {
        const peerEntries = extractEntries(peerContainer);
        for (const peer of peerEntries) {
          const addr = peer['@_name'] || '';
          neighbors.push({
            address: addr,
            peer_as: peer['peer-as'] ? parseInt(String(peer['peer-as'])) || null : null,
            description: '',
            update_source: peer['local-address']?.interface ? String(peer['local-address'].interface) : '',
            local_address: peer['local-address']?.ip ? String(peer['local-address'].ip) : '',
            import_policy: '',
            export_policy: '',
            authentication_key: '',
            enabled: peer.enable !== 'no',
          });
        }
      }
      peerGroups.push({ name: groupName, type: pgType, neighbors });
    }
  }

  // Parse redistribution profiles
  const redistribute = [];
  const redistContainer = getNestedValue(bgpNode, 'redist-rules');
  if (redistContainer) {
    const redistEntries = extractEntries(redistContainer);
    for (const entry of redistEntries) {
      const proto = entry['@_name'] || '';
      if (proto) {
        redistribute.push({ protocol: proto.replace('ip-', ''), policy: '' });
      }
    }
  }

  return {
    instance: vrName === 'default' ? '' : vrName,
    local_as: localAs,
    router_id: routerId,
    peer_groups: peerGroups,
    networks: [],
    redistribute,
  };
}

/**
 * Parses OSPF configuration from a PAN-OS virtual-router entry.
 * Path: virtual-router > entry > protocol > ospf
 */
function parseVrOspfConfig(vrEntry, vrName) {
  const ospfNode = getNestedValue(vrEntry, 'protocol.ospf');
  if (!ospfNode) return null;

  const enabled = ospfNode.enable === 'yes' || ospfNode.enable === true;
  if (!enabled) return null;

  const routerId = ospfNode['router-id'] ? String(ospfNode['router-id']) : '';

  // Parse areas
  const areas = [];
  const areaContainer = getNestedValue(ospfNode, 'area');
  if (areaContainer) {
    const areaEntries = extractEntries(areaContainer);
    for (const area of areaEntries) {
      const areaId = area['@_name'] || '0.0.0.0';

      // Determine area type
      let areaType = 'normal';
      if (area.type) {
        if (area.type.stub !== undefined) {
          areaType = area.type.stub?.['no-summary'] !== undefined ? 'totally-stub' : 'stub';
        } else if (area.type.nssa !== undefined) {
          areaType = area.type.nssa?.['no-summary'] !== undefined ? 'totally-nssa' : 'nssa';
        }
      }

      // Parse interface references
      const interfaces = [];
      const ifContainer = getNestedValue(area, 'interface');
      if (ifContainer) {
        const ifEntries = extractEntries(ifContainer);
        for (const iface of ifEntries) {
          const ifName = iface['@_name'] || '';
          interfaces.push({
            name: ifName,
            cost: iface.metric ? parseInt(String(iface.metric)) || null : null,
            hello_interval: iface['hello-interval'] ? parseInt(String(iface['hello-interval'])) || null : null,
            dead_interval: iface['dead-counts'] ? parseInt(String(iface['dead-counts'])) || null : null,
            authentication: null,
            passive: iface.passive === 'yes' || iface.passive === true,
            network_type: iface['link-type'] ? String(iface['link-type']) : null,
          });
        }
      }

      areas.push({ area_id: areaId, area_type: areaType, interfaces, networks: [] });
    }
  }

  if (areas.length === 0) return null;

  // Parse redistribution
  const redistribute = [];
  const redistContainer = getNestedValue(ospfNode, 'export-rules');
  if (redistContainer) {
    const redistEntries = extractEntries(redistContainer);
    for (const entry of redistEntries) {
      const proto = entry['@_name'] || '';
      if (proto) redistribute.push({ protocol: proto, policy: '', metric_type: null });
    }
  }

  return {
    instance: vrName === 'default' ? '' : vrName,
    router_id: routerId,
    reference_bandwidth: null,
    areas,
    redistribute,
  };
}

/**
 * Parses OSPFv3 configuration from a PAN-OS virtual-router entry.
 * Path: virtual-router > entry > protocol > ospfv3
 */
function parseVrOspf3Config(vrEntry, vrName) {
  const ospf3Node = getNestedValue(vrEntry, 'protocol.ospfv3');
  if (!ospf3Node) return null;

  const enabled = ospf3Node.enable === 'yes' || ospf3Node.enable === true;
  if (!enabled) return null;

  const routerId = ospf3Node['router-id'] ? String(ospf3Node['router-id']) : '';

  const areas = [];
  const areaContainer = getNestedValue(ospf3Node, 'area');
  if (areaContainer) {
    const areaEntries = extractEntries(areaContainer);
    for (const area of areaEntries) {
      const areaId = area['@_name'] || '0.0.0.0';

      let areaType = 'normal';
      if (area.type) {
        if (area.type.stub !== undefined) {
          areaType = area.type.stub?.['no-summary'] !== undefined ? 'totally-stub' : 'stub';
        } else if (area.type.nssa !== undefined) {
          areaType = area.type.nssa?.['no-summary'] !== undefined ? 'totally-nssa' : 'nssa';
        }
      }

      const interfaces = [];
      const ifContainer = getNestedValue(area, 'interface');
      if (ifContainer) {
        const ifEntries = extractEntries(ifContainer);
        for (const iface of ifEntries) {
          const ifName = iface['@_name'] || '';
          interfaces.push({
            name: ifName,
            cost: iface.metric ? parseInt(String(iface.metric)) || null : null,
            hello_interval: iface['hello-interval'] ? parseInt(String(iface['hello-interval'])) || null : null,
            dead_interval: iface['dead-counts'] ? parseInt(String(iface['dead-counts'])) || null : null,
            passive: iface.passive === 'yes' || iface.passive === true,
            network_type: iface['link-type'] ? String(iface['link-type']) : null,
            instance_id: iface['instance-id'] ? parseInt(String(iface['instance-id'])) || null : null,
          });
        }
      }

      areas.push({ area_id: areaId, area_type: areaType, interfaces, networks: [] });
    }
  }

  if (areas.length === 0) return null;

  const redistribute = [];
  const redistContainer = getNestedValue(ospf3Node, 'export-rules');
  if (redistContainer) {
    const redistEntries = extractEntries(redistContainer);
    for (const entry of redistEntries) {
      const proto = entry['@_name'] || '';
      if (proto) redistribute.push({ protocol: proto, policy: '', metric_type: null });
    }
  }

  return {
    instance: vrName === 'default' ? '' : vrName,
    router_id: routerId,
    reference_bandwidth: null,
    areas,
    redistribute,
  };
}

// ---------------------------------------------------------------------------
// Zone Parser
// ---------------------------------------------------------------------------

function parseZones(vsys, warnings) {
  const zoneContainer = vsys.zone;
  if (!zoneContainer) return [];

  const entries = extractEntries(zoneContainer);
  return entries.map((entry) => {
    const name = entry['@_name'] || 'unnamed-zone';
    const interfaces = [];

    // Detect zone type from which network sub-key is populated
    let zoneType = 'layer3';

    const l3Members = getNestedValue(entry, 'network.layer3');
    if (l3Members) {
      interfaces.push(...extractMembers(l3Members));
      zoneType = 'layer3';
    }

    const l2Members = getNestedValue(entry, 'network.layer2');
    if (l2Members) {
      interfaces.push(...extractMembers(l2Members));
      zoneType = 'layer2';
    }

    const vwMembers = getNestedValue(entry, 'network.virtual-wire');
    if (vwMembers) {
      interfaces.push(...extractMembers(vwMembers));
      zoneType = 'virtual-wire';
    }

    const tapMembers = getNestedValue(entry, 'network.tap');
    if (tapMembers) {
      interfaces.push(...extractMembers(tapMembers));
      zoneType = 'tap';
    }

    return {
      name,
      description: entry.description || '',
      interfaces,
      zone_type: zoneType,
    };
  });
}

// ---------------------------------------------------------------------------
// Address Object Parser
// ---------------------------------------------------------------------------

function parseAddressObjects(vsys, warnings) {
  const addressContainer = vsys.address;
  if (!addressContainer) return [];

  const entries = extractEntries(addressContainer);
  const objects = entries.map((entry) => {
    const name = entry['@_name'] || 'unnamed-address';
    const tags = extractMembers(entry.tag);
    let type = 'unknown';
    let value = '';

    if (entry['ip-netmask']) {
      type = entry['ip-netmask'].includes('/32') ? 'host' : 'subnet';
      value = entry['ip-netmask'];
    } else if (entry['ip-range']) {
      type = 'range';
      value = entry['ip-range'];
    } else if (entry.fqdn) {
      type = 'fqdn';
      value = entry.fqdn;
      warnings.push(createWarning(
        'warning',
        `address/${name}`,
        `FQDN address "${name}" → SRX dns-name requires SRX 12.1+ and DNS resolution at commit time`,
        'Verify SRX version supports dns-name, or replace with static IP'
      ));
    } else if (entry['ip-wildcard']) {
      type = 'wildcard';
      value = entry['ip-wildcard'];
      warnings.push(createWarning(
        'unsupported',
        `address/${name}`,
        `Wildcard mask address "${name}" has no direct SRX equivalent`,
        'Convert to a subnet or address range manually'
      ));
    }

    return { name, type, value, description: entry.description || '', tags };
  });

  // Auto-tag ip_version on all address objects
  for (const obj of objects) {
    obj.ip_version = detectIpVersion(obj.value);
  }

  return objects;
}

// ---------------------------------------------------------------------------
// Address Group Parser
// ---------------------------------------------------------------------------

function parseAddressGroups(vsys, warnings) {
  const groupContainer = vsys['address-group'];
  if (!groupContainer) return [];

  const entries = extractEntries(groupContainer);
  return entries.map((entry) => {
    const name = entry['@_name'] || 'unnamed-group';
    const tags = extractMembers(entry.tag);
    let members = [];

    // Static group: has <static><member>...</member></static>
    const staticNode = entry.static;
    if (staticNode) {
      // static might be an array from isArray config; take first element if so
      const staticObj = Array.isArray(staticNode) ? staticNode[0] : staticNode;
      members = extractMembers(staticObj);
    }

    // Dynamic group: has <dynamic><filter>...</filter></dynamic>
    if (entry.dynamic) {
      warnings.push(createWarning(
        'unsupported',
        `address-group/${name}`,
        `Dynamic address group "${name}" uses tag-based matching — SRX does not support dynamic address groups natively`,
        'Define the group members statically, or use SRX address-book with feed servers'
      ));
      return {
        name,
        members: [],
        description: entry.description || '',
        tags,
        _dynamic: true,
      };
    }

    return {
      name,
      members,
      description: entry.description || '',
      tags,
    };
  });
}

// ---------------------------------------------------------------------------
// Service Object Parser
// ---------------------------------------------------------------------------

function parseServiceObjects(vsys, warnings) {
  const serviceContainer = vsys.service;
  if (!serviceContainer) return [];

  const entries = extractEntries(serviceContainer);
  return entries.map((entry) => {
    const name = entry['@_name'] || 'unnamed-service';
    let protocol = 'tcp';
    let portRange = '';
    let sourcePort = '';

    const proto = entry.protocol;
    if (proto) {
      if (proto.tcp) {
        protocol = 'tcp';
        portRange = proto.tcp.port ? String(proto.tcp.port) : '';
        sourcePort = proto.tcp['source-port'] ? String(proto.tcp['source-port']) : '';
      } else if (proto.udp) {
        protocol = 'udp';
        portRange = proto.udp.port ? String(proto.udp.port) : '';
        sourcePort = proto.udp['source-port'] ? String(proto.udp['source-port']) : '';
      } else if (proto.sctp) {
        protocol = 'sctp';
        portRange = proto.sctp.port ? String(proto.sctp.port) : '';
        warnings.push(createWarning(
          'warning',
          `service/${name}`,
          `SCTP service "${name}" — SRX SCTP support varies by platform and version`,
          'Verify SRX platform supports SCTP'
        ));
      } else if (proto.icmp) {
        protocol = 'icmp';
      } else if (proto.icmp6) {
        protocol = 'icmp6';
      }
    }

    const result = {
      name,
      protocol,
      port_range: portRange,
      source_port: sourcePort,
      description: entry.description || '',
    };

    // ICMP services don't have ports
    if (protocol === 'icmp' || protocol === 'icmp6') {
      result.icmp_type = '';
      result.icmp_code = '';
    }

    return result;
  });
}

// ---------------------------------------------------------------------------
// Service Group Parser
// ---------------------------------------------------------------------------

function parseServiceGroups(vsys, warnings) {
  const groupContainer = vsys['service-group'];
  if (!groupContainer) return [];

  const entries = extractEntries(groupContainer);
  return entries.map((entry) => {
    const name = entry['@_name'] || 'unnamed-service-group';
    const members = extractMembers(entry.members || entry);

    return {
      name,
      members,
      description: entry.description || '',
    };
  });
}

// ---------------------------------------------------------------------------
// Application Parser
// ---------------------------------------------------------------------------

function parseApplications(vsys, warnings) {
  const appContainer = vsys.application;
  if (!appContainer) return [];

  const entries = extractEntries(appContainer);
  return entries.map((entry) => {
    const name = entry['@_name'] || 'unnamed-app';

    // Extract protocol/port from default settings if available
    let protocol = '';
    let port = '';

    const defaults = entry.default;
    if (defaults) {
      const portList = getNestedValue(defaults, 'port');
      if (portList) {
        // PAN-OS format: "tcp/80,443" or "udp/53"
        const portMembers = extractMembers(portList);
        if (portMembers.length > 0) {
          const firstPort = portMembers[0];
          const match = firstPort.match(/^(tcp|udp)\/([\d,-]+)$/i);
          if (match) {
            protocol = match[1].toLowerCase();
            port = match[2];
          }
        }
      }
    }

    if (!protocol && !port) {
      warnings.push(createWarning(
        'interview_required',
        `application/${name}`,
        `Custom application "${name}" has no default port defined — SRX needs explicit protocol/port`,
        'Specify the protocol and port(s) this application uses'
      ));
    }

    return {
      name,
      protocol,
      port,
      description: entry.description || '',
    };
  });
}

// ---------------------------------------------------------------------------
// Application Group Parser
// ---------------------------------------------------------------------------

function parseApplicationGroups(vsys, warnings) {
  const groupContainer = vsys['application-group'];
  if (!groupContainer) return [];

  const entries = extractEntries(groupContainer);
  return entries.map((entry) => {
    const name = entry['@_name'] || 'unnamed-app-group';
    let members = [];

    // PAN-OS uses <members><member>...</member></members>
    const membersNode = entry.members;
    if (membersNode) {
      const membersObj = Array.isArray(membersNode) ? membersNode[0] : membersNode;
      members = extractMembers(membersObj);
    }

    return {
      name,
      members,
      description: entry.description || '',
    };
  });
}

// ---------------------------------------------------------------------------
// Security Rules Parser
// ---------------------------------------------------------------------------

function parseSecurityRules(vsys, warnings) {
  // Rules live under rulebase → security → rules → entry
  const rulebase = vsys.rulebase;
  if (!rulebase) return [];

  const securityNode = rulebase.security;
  if (!securityNode) return [];

  const rulesNode = securityNode.rules;
  if (!rulesNode) return [];

  // rulesNode itself might be an array (from isArray config)
  const rulesContainer = Array.isArray(rulesNode) ? rulesNode[0] : rulesNode;
  const ruleEntries = extractEntries(rulesContainer);

  return ruleEntries.map((entry, index) => {
    const name = entry['@_name'] || `rule-${index + 1}`;
    const srcZones = extractMembers(entry.from);
    const dstZones = extractMembers(entry.to);
    const srcAddresses = extractMembers(entry.source);
    const dstAddresses = extractMembers(entry.destination);
    const applications = extractMembers(entry.application);
    const services = extractMembers(entry.service);
    const sourceUsers = extractMembers(entry['source-user']);
    const filteredUsers = sourceUsers.length === 1 && sourceUsers[0] === 'any' ? [] : sourceUsers;
    const action = parseAction(entry.action);
    const disabled = entry.disabled === 'yes' || entry.disabled === true;
    const description = entry.description || '';
    const tags = extractMembers(entry.tag);

    // Negate flags
    const negateSource = entry['negate-source'] === 'yes' || entry['negate-source'] === true;
    const negateDest = entry['negate-destination'] === 'yes' || entry['negate-destination'] === true;

    // Logging
    const logStart = entry['log-start'] === 'yes' || entry['log-start'] === true;
    const logEnd = entry['log-end'] === 'yes' || entry['log-end'] === true || entry['log-end'] === undefined;

    // Security profile group (AV, IPS, URL filtering, etc.)
    let profileGroup = '';
    const security_profiles = {};
    if (entry['profile-setting']) {
      const group = getNestedValue(entry, 'profile-setting.group');
      if (group) {
        const groupMembers = extractMembers(group);
        profileGroup = groupMembers[0] || '';
        warnings.push(createWarning(
          'interview_required',
          `security-rule/${name}`,
          `Rule "${name}" uses security profile group "${profileGroup}" — will apply default UTM+IDP if no individual profiles specified`,
          'Expand the profile group into individual profiles for more precise SRX mapping'
        ));
      }

      // Extract individual security profiles
      const profiles = getNestedValue(entry, 'profile-setting.profiles');
      if (profiles) {
        const profileTypes = ['virus', 'spyware', 'vulnerability', 'url-filtering', 'file-blocking', 'wildfire-analysis'];
        for (const pType of profileTypes) {
          if (profiles[pType]) {
            const members = extractMembers(profiles[pType]);
            if (members.length > 0) {
              security_profiles[pType] = members[0]; // PAN-OS uses single profile per type
            }
          }
        }
        if (Object.keys(security_profiles).length > 0) {
          const profileList = Object.entries(security_profiles).map(([k, v]) => `${k}:${v}`).join(', ');
          warnings.push(createWarning(
            'warning',
            `security-rule/${name}`,
            `Rule "${name}" has individual security profiles [${profileList}] — will map to SRX UTM/IDP`,
            'Verify the generated UTM and IDP policies match your security requirements'
          ));
        }
      }
    }

    // Flag any/any zone combinations
    if (srcZones.includes('any') && dstZones.includes('any')) {
      warnings.push(createWarning(
        'warning',
        `security-rule/${name}`,
        `Rule "${name}" matches any source AND any destination zone — this is very broad`,
        'Confirm this rule should apply to all zone pairs on the SRX'
      ));
    }

    // Flag disabled rules
    if (disabled) {
      warnings.push(createWarning(
        'warning',
        `security-rule/${name}`,
        `Rule "${name}" is disabled — will be converted using "deactivate" in SRX`,
        'Choose whether to include disabled rules or skip them entirely'
      ));
    }

    // Flag tag usage
    if (tags.length > 0) {
      warnings.push(createWarning(
        'warning',
        `security-rule/${name}`,
        `Rule "${name}" has tags [${tags.join(', ')}] — SRX does not support tag-based policy matching`,
        'Tags will be added to the rule description as comments'
      ));
    }

    // Flag negate usage
    if (negateSource) {
      warnings.push(createWarning(
        'warning',
        `security-rule/${name}`,
        `Rule "${name}" negates source addresses — SRX uses "source-address ... except" or "source-exclude-list"`,
        'Verify the SRX policy correctly excludes the specified source addresses'
      ));
    }
    if (negateDest) {
      warnings.push(createWarning(
        'warning',
        `security-rule/${name}`,
        `Rule "${name}" negates destination addresses — SRX uses "destination-address ... except" or "destination-exclude-list"`,
        'Verify the SRX policy correctly excludes the specified destination addresses'
      ));
    }

    // Flag User-ID source-user usage
    if (filteredUsers.length > 0) {
      warnings.push(createWarning(
        'warning',
        `security-rule/${name}`,
        `Rule "${name}" uses User-ID source users [${filteredUsers.join(', ')}] — SRX requires JIMS integration for user identification`,
        'Configure SRX user-identification with JIMS and verify user/group names match Active Directory'
      ));
    }

    return {
      name,
      src_zones: srcZones,
      dst_zones: dstZones,
      src_addresses: srcAddresses,
      dst_addresses: dstAddresses,
      negate_source: negateSource,
      negate_destination: negateDest,
      applications,
      services,
      action,
      log_start: logStart,
      log_end: logEnd,
      profile_group: profileGroup,
      security_profiles,
      description,
      tags,
      disabled,
      schedule: entry.schedule ? String(entry.schedule) : '',
      source_users: filteredUsers,
      _rule_index: index + 1,
    };
  });
}

/**
 * Parses the PAN-OS action field, which can be a string or an object.
 * PAN-OS uses: allow, deny, drop, reset-client, reset-server, reset-both
 */
function parseAction(actionField) {
  if (!actionField) return 'deny';
  if (typeof actionField === 'string') return actionField;
  // Object form: { allow: null } or { deny: null } or { drop: null }
  if (typeof actionField === 'object') {
    const keys = Object.keys(actionField);
    return keys[0] || 'deny';
  }
  return 'deny';
}

// ---------------------------------------------------------------------------
// Security Profile Definition Extractor
// ---------------------------------------------------------------------------

/**
 * Parses actual PAN-OS security profile definitions (not just references from rules).
 * Extracts severity→action mappings, blocked categories, file extensions, etc.
 * Returns an object keyed by "type:name" for lookup by the converter.
 */
function parseSecurityProfileDefinitions(vsys, warnings) {
  const defs = {};
  const profilesContainer = vsys.profiles || vsys['profile-setting']?.profiles || {};

  // Vulnerability protection profiles → severity→action
  const vulnEntries = extractEntries(profilesContainer.vulnerability || {});
  for (const entry of vulnEntries) {
    const name = entry['@_name'] || '';
    const severityActions = {};
    const rules = extractEntries(entry.rules || {});
    for (const rule of rules) {
      const severities = extractMembers(rule.severity || {});
      const action = rule.action ? Object.keys(rule.action)[0] : 'default';
      for (const sev of severities) {
        severityActions[sev] = action;
      }
    }
    if (name) defs[`vulnerability:${name}`] = { type: 'vulnerability', name, severityActions };
  }

  // Anti-spyware profiles → severity→action
  const spyEntries = extractEntries(profilesContainer.spyware || {});
  for (const entry of spyEntries) {
    const name = entry['@_name'] || '';
    const severityActions = {};
    const rules = extractEntries(entry.rules || {});
    for (const rule of rules) {
      const severities = extractMembers(rule.severity || {});
      const action = rule.action ? Object.keys(rule.action)[0] : 'default';
      for (const sev of severities) {
        severityActions[sev] = action;
      }
    }
    if (name) defs[`spyware:${name}`] = { type: 'spyware', name, severityActions };
  }

  // URL filtering profiles → block/allow categories
  const urlEntries = extractEntries(profilesContainer['url-filtering'] || {});
  for (const entry of urlEntries) {
    const name = entry['@_name'] || '';
    const blockCategories = extractMembers(entry.block || {});
    const allowCategories = extractMembers(entry.allow || {});
    const alertCategories = extractMembers(entry.alert || {});
    if (name) defs[`url-filtering:${name}`] = { type: 'url-filtering', name, blockCategories, allowCategories, alertCategories };
  }

  // File blocking profiles → blocked file extensions
  const fbEntries = extractEntries(profilesContainer['file-blocking'] || {});
  for (const entry of fbEntries) {
    const name = entry['@_name'] || '';
    const blockedExtensions = [];
    const rules = extractEntries(entry.rules || {});
    for (const rule of rules) {
      const action = rule.action || 'alert';
      if (action === 'block' || action === 'block-continue') {
        const fileTypes = extractMembers(rule['file-type'] || {});
        blockedExtensions.push(...fileTypes);
      }
    }
    if (name) defs[`file-blocking:${name}`] = { type: 'file-blocking', name, blockedExtensions };
  }

  // Antivirus profiles → scan mode
  const avEntries = extractEntries(profilesContainer.virus || {});
  for (const entry of avEntries) {
    const name = entry['@_name'] || '';
    const decoders = Object.keys(entry.decoder || {});
    if (name) defs[`virus:${name}`] = { type: 'virus', name, decoders };
  }

  return defs;
}

// ---------------------------------------------------------------------------
// Security Profile Object Builder
// ---------------------------------------------------------------------------

/**
 * Builds security_profile_objects from all rules' security_profiles and profile_groups.
 *
 * For individual profiles (e.g. virus: 'default'), creates one object per unique
 * type+name pair.
 *
 * For profile groups (e.g. profile_group: 'strict-security'), expands to all 6
 * standard profile types using the group name, since PAN-OS config doesn't
 * include group definitions inline.
 */
function buildSecurityProfileObjects(policies) {
  const seen = new Map(); // key → object
  const allProfileTypes = ['virus', 'spyware', 'vulnerability', 'url-filtering', 'file-blocking', 'wildfire-analysis'];

  const featureLabels = {
    'virus':              { srxFeature: 'utm', srxType: 'anti-virus',        label: 'Antivirus' },
    'wildfire-analysis':  { srxFeature: 'utm', srxType: 'anti-virus',        label: 'WildFire Analysis' },
    'url-filtering':      { srxFeature: 'utm', srxType: 'web-filtering',     label: 'URL Filtering' },
    'file-blocking':      { srxFeature: 'utm', srxType: 'content-filtering', label: 'File Blocking' },
    'spyware':            { srxFeature: 'idp', srxType: 'idp-policy',        label: 'Anti-Spyware' },
    'vulnerability':      { srxFeature: 'idp', srxType: 'idp-policy',        label: 'Vulnerability Protection' },
  };

  for (const policy of policies) {
    // Individual profiles
    const sp = policy.security_profiles || {};
    for (const [pType, pName] of Object.entries(sp)) {
      const key = `${pType}::${pName}`;
      if (!seen.has(key)) {
        const info = featureLabels[pType] || { srxFeature: 'unknown', srxType: pType, label: pType };
        seen.set(key, {
          name: `${pType}-${pName}`.replace(/\s+/g, '-'),
          profile_type: pType,
          profile_type_label: info.label,
          profile_name: pName,
          srx_feature: info.srxFeature,
          srx_type: info.srxType,
          source: 'individual',
          attached_rules: [policy.name],
        });
      } else {
        const obj = seen.get(key);
        if (!obj.attached_rules.includes(policy.name)) {
          obj.attached_rules.push(policy.name);
        }
      }
    }

    // Profile group — expand to all 6 types
    if (policy.profile_group && Object.keys(sp).length === 0) {
      const groupName = policy.profile_group;
      for (const pType of allProfileTypes) {
        const key = `group:${groupName}::${pType}`;
        if (!seen.has(key)) {
          const info = featureLabels[pType];
          seen.set(key, {
            name: `${groupName}-${pType}`.replace(/\s+/g, '-'),
            profile_type: pType,
            profile_type_label: info.label,
            profile_name: groupName,
            srx_feature: info.srxFeature,
            srx_type: info.srxType,
            source: `group:${groupName}`,
            attached_rules: [policy.name],
          });
        } else {
          const obj = seen.get(key);
          if (!obj.attached_rules.includes(policy.name)) {
            obj.attached_rules.push(policy.name);
          }
        }
      }
    }
  }

  return [...seen.values()];
}

// ---------------------------------------------------------------------------
// Profile Group Definitions Parser
// ---------------------------------------------------------------------------

/**
 * Parses the <profile-group> section from PAN-OS config.
 * Returns a map of group name → { virus: 'default', spyware: 'strict', ... }
 */
function parseProfileGroupDefinitions(vsys) {
  const pgContainer = vsys['profile-group'];
  if (!pgContainer) return {};

  const entries = extractEntries(pgContainer);
  const groups = {};
  const profileTypes = ['virus', 'spyware', 'vulnerability', 'url-filtering', 'file-blocking', 'wildfire-analysis'];

  for (const entry of entries) {
    const name = entry['@_name'];
    if (!name) continue;

    const profiles = {};
    for (const pType of profileTypes) {
      if (entry[pType]) {
        const members = extractMembers(entry[pType]);
        if (members.length > 0) {
          profiles[pType] = members[0];
        }
      }
    }

    if (Object.keys(profiles).length > 0) {
      groups[name] = profiles;
    }
  }

  return groups;
}

// ---------------------------------------------------------------------------
// External Dynamic Lists (EDL) Parser
// ---------------------------------------------------------------------------

/**
 * Parses PAN-OS schedule objects.
 * PAN-OS schedules can be recurring (weekly/daily) or non-recurring (one-time).
 */
function parseScheduleObjects(vsys) {
  const scheduleContainer = vsys.schedule;
  if (!scheduleContainer) return [];

  const entries = extractEntries(scheduleContainer);
  return entries.map(entry => {
    const name = entry['@_name'] || 'unnamed-schedule';
    const schedType = entry['schedule-type'];
    if (!schedType) return { name, type: 'unknown', days: [], start: '', end: '' };

    if (schedType.recurring) {
      const weekly = schedType.recurring.weekly;
      if (weekly) {
        const dayNames = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
        const days = [];
        let start = '', end = '';
        for (const day of dayNames) {
          if (weekly[day]) {
            days.push(day.charAt(0).toUpperCase() + day.slice(1, 3));
            // Time ranges are in "HH:MM-HH:MM" format
            const timeStr = Array.isArray(weekly[day]) ? weekly[day][0] : String(weekly[day]);
            if (timeStr && timeStr.includes('-')) {
              const [s, e] = timeStr.split('-');
              start = start || s;
              end = e;
            }
          }
        }
        return { name, type: 'recurring', days, start, end };
      }
      // Daily schedule
      const daily = schedType.recurring.daily;
      if (daily) {
        const timeStr = Array.isArray(daily) ? daily[0] : String(daily);
        let start = '', end = '';
        if (timeStr && timeStr.includes('-')) {
          [start, end] = timeStr.split('-');
        }
        return { name, type: 'recurring', days: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], start, end };
      }
    }

    if (schedType['non-recurring']) {
      const nr = schedType['non-recurring'];
      const timeRange = Array.isArray(nr) ? nr[0] : String(nr);
      let start = '', end = '';
      if (timeRange && timeRange.includes('/')) {
        [start, end] = timeRange.split('/');
      }
      return { name, type: 'onetime', start, end };
    }

    return { name, type: 'unknown', days: [], start: '', end: '' };
  });
}

/**
 * Parses PAN-OS External Dynamic Lists (EDLs) from the device config.
 * Detects predefined Palo Alto threat feeds and custom block lists.
 */
function parseExternalLists(vsys, warnings) {
  const edls = [];
  const externalList = getNestedValue(vsys, 'external-list.entry');
  if (!externalList) return edls;

  const entries = ensureArray(externalList);
  for (const entry of entries) {
    const name = entry['@_name'] || entry.name || 'unnamed-edl';
    const typeNode = entry.type || {};

    let isPredefined = false;
    let url = '';
    let listType = 'ip';

    if (typeNode['predefined-ip']) {
      isPredefined = true;
      url = typeNode['predefined-ip'].url || name;
      listType = 'ip';
    } else if (typeNode['predefined-url']) {
      isPredefined = true;
      url = typeNode['predefined-url'].url || name;
      listType = 'url';
    } else if (typeNode.ip) {
      url = typeNode.ip.url || '';
      listType = 'ip';
    } else if (typeNode.domain) {
      url = typeNode.domain.url || '';
      listType = 'domain';
    } else if (typeNode.url) {
      url = typeNode.url.url || '';
      listType = 'url';
    }

    // Heuristic: is this a threat/block list?
    const blockListPatterns = [
      'bulletproof', 'highrisk', 'high-risk', 'known-ip', 'malicious',
      'tor-exit', 'c2', 'command-and-control', 'botnet', 'ransomware',
      'threat', 'block', 'deny', 'blacklist', 'blocklist',
    ];
    const isBlockList = isPredefined || blockListPatterns.some(p =>
      name.toLowerCase().includes(p) || url.toLowerCase().includes(p)
    );

    if (isBlockList) {
      warnings.push(createWarning(
        'warning',
        `external-list/${name}`,
        `EDL "${name}" detected as threat block list — will map to SRX Security Intelligence (SecIntel)`,
        'Verify the SRX platform supports Security Intelligence feeds'
      ));
    }

    edls.push({ name, url, listType, isPredefined, isBlockList });
  }
  return edls;
}

/**
 * Scans security rules for references to EDL block list addresses.
 * Adds `_secIntelAddresses` to rules that reference detected block lists.
 */
function flagSecIntelRules(policies, externalLists, warnings) {
  if (!externalLists || externalLists.length === 0) return;

  const blockListNames = new Set(
    externalLists.filter(e => e.isBlockList).map(e => e.name)
  );
  if (blockListNames.size === 0) return;

  for (const policy of policies) {
    const secIntelAddrs = [];
    for (const addr of [...policy.src_addresses, ...policy.dst_addresses]) {
      if (blockListNames.has(addr)) {
        secIntelAddrs.push(addr);
      }
    }
    if (secIntelAddrs.length > 0) {
      policy._secIntelAddresses = secIntelAddrs;
      warnings.push(createWarning(
        'warning',
        `security-rule/${policy.name}`,
        `Rule "${policy.name}" references threat feed(s) [${secIntelAddrs.join(', ')}] — will map to SRX SecIntel`,
        'EDL addresses will be removed from rule match criteria and replaced with SecIntel policy attachment'
      ));
    }
  }
}

// ---------------------------------------------------------------------------
// NAT Rules Parser
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// VPN / IPsec Tunnel Parser
// ---------------------------------------------------------------------------

/**
 * Parses PAN-OS IKE/IPsec VPN configuration.
 * IKE crypto/IPsec profiles, gateways, tunnels under devices > entry > network
 */
function parseVpnConfig(config, warnings) {
  const vpnTunnels = [];
  const devices = getNestedValue(config, 'devices');
  if (!devices) return vpnTunnels;

  const deviceEntries = extractEntries(devices);
  for (const device of deviceEntries) {
    // ---- IKE crypto profiles ----
    const ikeCryptoProfiles = {};
    const ikeCryptoContainer = getNestedValue(device, 'network.ike.crypto-profile.ike-crypto-profiles');
    if (ikeCryptoContainer) {
      for (const entry of extractEntries(ikeCryptoContainer)) {
        const name = entry['@_name'] || '';
        if (!name) continue;
        const encryption = extractMembers(entry.encryption).join(',') || 'aes-256-cbc';
        const hash = extractMembers(entry.hash).join(',') || 'sha256';
        const dhGroup = extractMembers(entry['dh-group']).join(',') || 'group14';
        let lifetime = 28800;
        if (entry.lifetime) {
          if (entry.lifetime.hours) lifetime = parseInt(entry.lifetime.hours, 10) * 3600;
          else if (entry.lifetime.seconds) lifetime = parseInt(entry.lifetime.seconds, 10);
          else if (entry.lifetime.minutes) lifetime = parseInt(entry.lifetime.minutes, 10) * 60;
          else if (entry.lifetime.days) lifetime = parseInt(entry.lifetime.days, 10) * 86400;
        }
        ikeCryptoProfiles[name] = {
          name,
          auth_method: 'pre-shared-keys',
          dh_group: dhGroup,
          encryption,
          authentication: hash,
          lifetime: lifetime || 28800,
        };
      }
    }

    // ---- IPsec crypto profiles ----
    const ipsecCryptoProfiles = {};
    const ipsecCryptoContainer = getNestedValue(device, 'network.ike.crypto-profile.ipsec-crypto-profiles');
    if (ipsecCryptoContainer) {
      for (const entry of extractEntries(ipsecCryptoContainer)) {
        const name = entry['@_name'] || '';
        if (!name) continue;
        const esp = entry.esp || {};
        const encryption = extractMembers(esp.encryption).join(',') || 'aes-256-cbc';
        const authentication = extractMembers(esp.authentication).join(',') || 'sha256';
        const dhGroup = typeof entry['dh-group'] === 'string' ? entry['dh-group'] : extractMembers(entry['dh-group']).join(',') || 'group14';
        let lifetime = 3600;
        if (entry.lifetime) {
          if (entry.lifetime.hours) lifetime = parseInt(entry.lifetime.hours, 10) * 3600;
          else if (entry.lifetime.seconds) lifetime = parseInt(entry.lifetime.seconds, 10);
          else if (entry.lifetime.minutes) lifetime = parseInt(entry.lifetime.minutes, 10) * 60;
          else if (entry.lifetime.days) lifetime = parseInt(entry.lifetime.days, 10) * 86400;
        }
        ipsecCryptoProfiles[name] = {
          name,
          protocol: 'esp',
          encryption,
          authentication,
          lifetime: lifetime || 3600,
          pfs_group: dhGroup,
        };
      }
    }

    // ---- IKE gateways ----
    const ikeGateways = {};
    const gwContainer = getNestedValue(device, 'network.ike.gateway');
    if (gwContainer) {
      for (const entry of extractEntries(gwContainer)) {
        const name = entry['@_name'] || '';
        if (!name) continue;

        let peerAddress = '';
        const peerAddr = entry['peer-address'];
        if (peerAddr) {
          if (typeof peerAddr === 'string') peerAddress = peerAddr;
          else if (peerAddr.ip) peerAddress = String(peerAddr.ip);
          else if (peerAddr.fqdn) peerAddress = String(peerAddr.fqdn);
          else if (peerAddr.dynamic) peerAddress = 'dynamic';
        }

        let localAddress = '';
        const localAddr = entry['local-address'];
        if (localAddr) {
          if (typeof localAddr === 'string') localAddress = localAddr;
          else if (localAddr.interface) localAddress = String(localAddr.interface);
          else if (localAddr.ip) localAddress = String(localAddr.ip);
        }

        let ikeVersion = 'v2';
        const protocol = entry.protocol;
        if (protocol) {
          if (protocol.ikev1) ikeVersion = 'v1';
          else if (protocol.ikev2) ikeVersion = 'v2';
        }

        let ikeProposal = '';
        // Check protocol-common for crypto profile reference
        const protocolCommon = entry['protocol-common'];
        if (protocolCommon && protocolCommon['ike-crypto-profile']) {
          ikeProposal = String(protocolCommon['ike-crypto-profile']);
        }
        // Also check protocol > ikev2/ikev1 for crypto profile reference
        if (!ikeProposal && protocol) {
          if (protocol.ikev2 && protocol.ikev2['ike-crypto-profile']) {
            ikeProposal = String(protocol.ikev2['ike-crypto-profile']);
          } else if (protocol.ikev1 && protocol.ikev1['ike-crypto-profile']) {
            ikeProposal = String(protocol.ikev1['ike-crypto-profile']);
          }
        }
        const auth = entry.authentication;
        if (auth && auth['pre-shared-key']) {
          warnings.push(createWarning(
            'info',
            'ike-gateway/' + name,
            'IKE gateway ' + name + ' pre-shared key sanitized',
            'Pre-shared keys are never included in parsed output'
          ));
        }

        ikeGateways[name] = {
          name,
          address: peerAddress,
          local_address: localAddress,
          pre_shared_key: 'SANITIZED',
          ike_version: ikeVersion,
          proposal: ikeProposal,
        };
      }
    }

    // ---- IPsec tunnels ----
    const ipsecContainer = getNestedValue(device, 'network.tunnel.ipsec');
    if (ipsecContainer) {
      for (const entry of extractEntries(ipsecContainer)) {
        const name = entry['@_name'] || '';
        if (!name) continue;

        const tunnelInterface = entry['tunnel-interface'] ? String(entry['tunnel-interface']) : '';
        const autoKey = entry['auto-key'] || {};

        let gwName = '';
        const ikeGwRef = autoKey['ike-gateway'];
        if (ikeGwRef) {
          const gwEntries = extractEntries(ikeGwRef);
          if (gwEntries.length > 0) gwName = gwEntries[0]['@_name'] || '';
        }

        let ipsecProposalName = '';
        if (autoKey['ipsec-crypto-profile']) {
          ipsecProposalName = String(autoKey['ipsec-crypto-profile']);
        }

        const proxyIds = [];
        const proxyIdContainer = autoKey['proxy-id'];
        if (proxyIdContainer) {
          for (const pid of extractEntries(proxyIdContainer)) {
            proxyIds.push({
              local: pid.local ? String(pid.local) : '',
              remote: pid.remote ? String(pid.remote) : '',
              protocol: pid.protocol ? String(pid.protocol) : 'any',
            });
          }
        }

        const gw = ikeGateways[gwName] || {
          name: gwName, address: '', local_address: '',
          pre_shared_key: 'SANITIZED', ike_version: 'v2', proposal: '',
        };

        const ikeProposal = ikeCryptoProfiles[gw.proposal] || {
          name: gw.proposal || 'default', auth_method: 'pre-shared-keys',
          dh_group: 'group14', encryption: 'aes-256-cbc',
          authentication: 'sha256', lifetime: 28800,
        };

        const ipsecProposal = ipsecCryptoProfiles[ipsecProposalName] || {
          name: ipsecProposalName || 'default', protocol: 'esp',
          encryption: 'aes-256-cbc', authentication: 'sha256',
          lifetime: 3600, pfs_group: 'group14',
        };

        vpnTunnels.push({
          name,
          ike_gateway: gw,
          ike_proposal: ikeProposal,
          ipsec_proposal: ipsecProposal,
          proxy_id: proxyIds,
          tunnel_interface: tunnelInterface,
          description: '',
        });
      }
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
function parseNatRules(vsys, warnings, serviceObjects) {
  const rulebase = vsys.rulebase;
  if (!rulebase) return [];

  const natNode = rulebase.nat;
  if (!natNode) return [];

  const rulesNode = natNode.rules;
  if (!rulesNode) return [];

  const rulesContainer = Array.isArray(rulesNode) ? rulesNode[0] : rulesNode;
  const ruleEntries = extractEntries(rulesContainer);

  // Build service lookup: name → {protocol, port_range}
  const serviceLookup = {};
  for (const svc of serviceObjects || []) {
    if (svc.name && svc.protocol && svc.port_range) {
      serviceLookup[svc.name] = { protocol: svc.protocol, port: svc.port_range };
    }
  }

  return ruleEntries.map((entry, index) => {
    const name = entry['@_name'] || `nat-rule-${index + 1}`;
    const srcZones = extractMembers(entry.from);
    const dstZones = extractMembers(entry.to);
    const srcAddresses = extractMembers(entry.source);
    const dstAddresses = extractMembers(entry.destination);
    const description = entry.description || '';

    let type = 'unknown';
    let translatedSrc = null;
    let translatedDst = null;
    let translatedPort = null;
    let staticBidirectional = false;
    let matchProtocol = null;
    let matchPort = null;

    // Service match (protocol/port)
    // The XML parser turns a numeric name such as <service>443</service> into a number.
    const serviceName = entry.service == null ? '' : String(entry.service).trim();
    if (serviceName && serviceName !== 'any' && serviceName !== 'application-default') {
      const svc = serviceLookup[serviceName];
      if (svc) {
        matchProtocol = svc.protocol;
        matchPort = svc.port;
      }
    }

    // Source NAT
    if (entry['source-translation']) {
      type = 'source';
      const srcTrans = entry['source-translation'];

      if (srcTrans['dynamic-ip-and-port']) {
        const dip = srcTrans['dynamic-ip-and-port'];
        if (dip['interface-address']) {
          translatedSrc = { type: 'interface', interface: dip['interface-address'].interface || '' };
        } else if (dip['translated-address']) {
          const translatedAddrs = extractMembers(dip['translated-address']);
          translatedSrc = { type: 'dynamic-ip-pool', addresses: translatedAddrs };
          warnings.push(createWarning(
            'interview_required',
            `nat-rule/${name}`,
            `NAT rule "${name}" uses dynamic IP pool — SRX requires an explicit source NAT pool definition`,
            'Specify the IP range for the SRX source NAT pool'
          ));
        }
      } else if (srcTrans['static-ip']) {
        type = 'static';
        staticBidirectional = String(srcTrans['static-ip']['bi-directional']).trim() === 'yes';
        translatedSrc = {
          type: 'static',
          address: srcTrans['static-ip']['translated-address'] || '',
        };
      }
    }

    // Destination NAT
    if (entry['destination-translation']) {
      type = type === 'source' ? 'source-and-destination' : 'destination';
      const dstTrans = entry['destination-translation'];
      translatedDst = dstTrans['translated-address'] || '';
      translatedPort = dstTrans['translated-port'] ? String(dstTrans['translated-port']) : null;
    }

    let staticFields = null;
    if (type === 'static') {
      staticFields = buildStaticNatFields({
        name,
        privateAddresses: srcAddresses,
        publicAddresses: [translatedSrc.address],
        destinationFilter: dstAddresses,
        insideZones: srcZones,
        outsideZones: dstZones,
        bidirectional: staticBidirectional,
        services: serviceName === 'application-default' ? [] : [serviceName],
        warnings,
      });
      if (!staticFields) return null;
    }

    // Detect U-turn/hairpin NAT: source zones == destination zones with combo NAT
    const isUturn = type === 'source-and-destination' &&
      srcZones.length > 0 && dstZones.length > 0 &&
      srcZones.length === dstZones.length &&
      srcZones.every(z => dstZones.includes(z));

    if (isUturn) {
      warnings.push(createWarning(
        'warning',
        `nat-rule/${name}`,
        `NAT rule "${name}" is a U-turn/hairpin NAT (same source and destination zones)`,
        'SRX will need persistent-nat permit on this rule for return traffic'
      ));
    }

    return {
      name,
      type,
      src_zones: srcZones,
      dst_zones: dstZones,
      src_addresses: srcAddresses,
      dst_addresses: dstAddresses,
      translated_src: translatedSrc,
      ...staticFields,
      translated_dst: translatedDst,
      translated_port: translatedPort,
      match_protocol: matchProtocol || undefined,
      match_port: matchPort || undefined,
      description,
      _rule_index: index + 1,
      _uturn: isUturn || undefined,
    };
  }).filter(Boolean);
}


// ---------------------------------------------------------------------------
// GlobalProtect Parser
// ---------------------------------------------------------------------------

/**
 * Parse GlobalProtect gateways and the tunnel interface each one binds.
 * GlobalProtect is SSL-VPN; it has no automatic SRX equivalent, so we only
 * record it for the UI/report and to stamp the tunnel interface.
 *
 * @param {object} config - Parsed PAN-OS XML config root.
 * @param {Array} warnings - Warning accumulator (unused today; reserved).
 * @returns {{ gateways: Array<{ name: string, tunnel_interface: string }> }}
 */
function parseGlobalProtect(config, warnings) {
  const gateways = [];
  const devices = getNestedValue(config, 'devices');
  if (!devices) return { gateways };

  for (const device of extractEntries(devices)) {
    const vsysNode = getNestedValue(device, 'vsys');
    if (!vsysNode) continue;
    for (const vsys of extractEntries(vsysNode)) {
      const gwContainer = getNestedValue(vsys, 'global-protect.global-protect-gateway');
      if (!gwContainer) continue;
      for (const entry of extractEntries(gwContainer)) {
        const name = entry['@_name'] || '';
        const tunnelInterface = typeof entry['tunnel-interface'] === 'string'
          ? entry['tunnel-interface'].trim()
          : '';
        if (!name || !tunnelInterface) continue;
        gateways.push({ name, tunnel_interface: tunnelInterface });
      }
    }
  }
  return { gateways };
}


// ---------------------------------------------------------------------------
// Decryption Rules Parser
// ---------------------------------------------------------------------------

/**
 * Parses PAN-OS SSL/TLS decryption rules.
 * Located at: vsys > rulebase > decryption > rules > entry
 */
function parseDecryptionRules(vsys, warnings) {
  const rulebase = vsys.rulebase;
  if (!rulebase) return [];

  const decryptNode = rulebase.decryption;
  if (!decryptNode) return [];

  const rulesNode = decryptNode.rules;
  if (!rulesNode) return [];

  const rulesContainer = Array.isArray(rulesNode) ? rulesNode[0] : rulesNode;
  const ruleEntries = extractEntries(rulesContainer);

  return ruleEntries.map((entry, index) => {
    const name = entry['@_name'] || `decrypt-rule-${index + 1}`;
    const srcZones = extractMembers(entry.from);
    const dstZones = extractMembers(entry.to);
    const srcAddresses = extractMembers(entry.source);
    const dstAddresses = extractMembers(entry.destination);
    const srcUsers = extractMembers(entry['source-user']);
    const services = extractMembers(entry.service);
    const urlCategories = extractMembers(entry.category);
    const description = entry.description || '';
    const disabled = entry.disabled === 'yes' || entry.disabled === true;
    const tags = extractMembers(entry.tag);
    const negateSource = entry['negate-source'] === 'yes' || entry['negate-source'] === true;
    const negateDest = entry['negate-destination'] === 'yes' || entry['negate-destination'] === true;

    // Action: decrypt, no-decrypt, decrypt-and-forward (PAN-OS 8.1+)
    const action = typeof entry.action === 'string' ? entry.action : 'no-decrypt';

    // Decryption type: ssl-forward-proxy, ssh-proxy, ssl-inbound-inspection
    let decryptionType = '';
    let sslCertificate = '';
    if (entry.type) {
      for (const dtype of ['ssl-forward-proxy', 'ssh-proxy', 'ssl-inbound-inspection']) {
        if (entry.type[dtype] !== undefined) {
          decryptionType = dtype;
          // ssl-inbound-inspection has a certificate reference
          if (dtype === 'ssl-inbound-inspection' && typeof entry.type[dtype] === 'object') {
            sslCertificate = entry.type[dtype]['ssl-certificate'] || '';
          }
          break;
        }
      }
    }

    // Decryption profile reference
    const decryptionProfile = entry.profile || '';

    // Log settings (PAN-OS 10.0+)
    const logSuccess = entry['log-success'] === 'yes' || entry['log-success'] === true;
    const logFail = entry['log-fail'] === 'yes' || entry['log-fail'] === true;
    const logSetting = entry['log-setting'] || '';

    return {
      name,
      src_zones: srcZones,
      dst_zones: dstZones,
      src_addresses: srcAddresses,
      dst_addresses: dstAddresses,
      src_users: srcUsers,
      negate_source: negateSource,
      negate_destination: negateDest,
      services,
      url_categories: urlCategories,
      action,
      decryption_type: decryptionType,
      ssl_certificate: sslCertificate,
      decryption_profile: decryptionProfile,
      log_success: logSuccess,
      log_fail: logFail,
      log_setting: logSetting,
      description,
      tags,
      disabled,
      _rule_index: index + 1,
    };
  });
}

// ---------------------------------------------------------------------------
// Policy-Based Forwarding (PBF) Rules Parser
// ---------------------------------------------------------------------------

/**
 * Parses PAN-OS policy-based forwarding rules.
 * Located at: vsys > rulebase > pbf > rules > entry
 */
function parsePbfRules(vsys, warnings) {
  const rulebase = vsys.rulebase;
  if (!rulebase) return [];

  const pbfNode = rulebase.pbf;
  if (!pbfNode) return [];

  const rulesNode = pbfNode.rules;
  if (!rulesNode) return [];

  const rulesContainer = Array.isArray(rulesNode) ? rulesNode[0] : rulesNode;
  const ruleEntries = extractEntries(rulesContainer);

  return ruleEntries.map((entry, index) => {
    const name = entry['@_name'] || `pbf-rule-${index + 1}`;
    const description = entry.description || '';
    const disabled = entry.disabled === 'yes' || entry.disabled === true;
    const tags = extractMembers(entry.tag);
    const schedule = entry.schedule ? String(entry.schedule) : '';

    // Source: from zone or interface
    let fromType = 'zone';
    let fromValue = [];
    if (entry.from) {
      if (entry.from.zone) {
        fromType = 'zone';
        fromValue = extractMembers(entry.from.zone);
      } else if (entry.from.interface) {
        fromType = 'interface';
        fromValue = extractMembers(entry.from.interface);
      } else {
        // Fallback: treat child members as zones
        fromValue = extractMembers(entry.from);
      }
    }

    const srcAddresses = extractMembers(entry.source);
    const dstAddresses = extractMembers(entry.destination);
    const srcUsers = extractMembers(entry['source-user']);
    const applications = extractMembers(entry.application);
    const services = extractMembers(entry.service);
    const negateSource = entry['negate-source'] === 'yes' || entry['negate-source'] === true;
    const negateDest = entry['negate-destination'] === 'yes' || entry['negate-destination'] === true;

    // Action: forward, forward-to-vsys, discard, no-pbf
    let action = 'forward';
    let egressInterface = '';
    let nextHopType = '';
    let nextHopValue = '';
    let forwardVsys = '';
    let monitorProfile = '';
    let monitorIp = '';
    let monitorDisable = false;

    if (entry.action) {
      if (entry.action.forward) {
        action = 'forward';
        const fwd = entry.action.forward;
        egressInterface = fwd['egress-interface'] || '';
        if (fwd.nexthop) {
          if (fwd.nexthop['ip-address']) {
            nextHopType = 'ip-address';
            nextHopValue = String(fwd.nexthop['ip-address']);
          } else if (fwd.nexthop.fqdn) {
            nextHopType = 'fqdn';
            nextHopValue = String(fwd.nexthop.fqdn);
          }
        }
        if (fwd.monitor) {
          monitorProfile = fwd.monitor.profile || '';
          monitorIp = fwd.monitor['ip-address'] || '';
          monitorDisable = fwd.monitor['disable-if-unreachable'] === 'yes' || fwd.monitor['disable-if-unreachable'] === true;
        }
      } else if (entry.action['forward-to-vsys']) {
        action = 'forward-to-vsys';
        const fvs = entry.action['forward-to-vsys'];
        forwardVsys = typeof fvs === 'string' ? fvs : (fvs.vsys || '');
      } else if (entry.action.discard !== undefined) {
        action = 'discard';
      } else if (entry.action['no-pbf'] !== undefined) {
        action = 'no-pbf';
      }
    }

    // Symmetric return
    let symmetricReturn = false;
    let symmetricReturnAddresses = [];
    if (entry['enforce-symmetric-return']) {
      symmetricReturn = entry['enforce-symmetric-return'].enabled === 'yes' || entry['enforce-symmetric-return'].enabled === true;
      if (entry['enforce-symmetric-return']['nexthop-address-list']) {
        symmetricReturnAddresses = extractEntries(entry['enforce-symmetric-return']['nexthop-address-list']).map(e => e['@_name'] || '').filter(Boolean);
      }
    }

    return {
      name,
      from_type: fromType,
      from_value: fromValue,
      src_addresses: srcAddresses,
      dst_addresses: dstAddresses,
      src_users: srcUsers,
      negate_source: negateSource,
      negate_destination: negateDest,
      applications,
      services,
      action,
      egress_interface: egressInterface,
      next_hop_type: nextHopType,
      next_hop_value: nextHopValue,
      forward_vsys: forwardVsys,
      monitor_profile: monitorProfile,
      monitor_ip: monitorIp,
      monitor_disable_if_unreachable: monitorDisable,
      symmetric_return: symmetricReturn,
      symmetric_return_addresses: symmetricReturnAddresses,
      description,
      tags,
      disabled,
      schedule,
      _rule_index: index + 1,
    };
  });
}

// ---------------------------------------------------------------------------
// Syslog Configuration Parser
// ---------------------------------------------------------------------------

/**
 * Parses PAN-OS syslog server profile configuration.
 * Located at: devices > entry > deviceconfig > system > syslog
 */
function parseSyslogConfig(config, warnings) {
  const servers = [];
  const devices = getNestedValue(config, 'devices');
  if (!devices) return servers;

  const entries = Array.isArray(devices.entry) ? devices.entry : devices.entry ? [devices.entry] : [];
  for (const device of entries) {
    // PAN-OS syslog: deviceconfig > system > syslog > server-profile > entry
    const syslogSection = getNestedValue(device, 'deviceconfig.system.syslog');
    if (!syslogSection) continue;

    const profiles = syslogSection['server-profile'];
    if (!profiles) continue;

    const profileEntries = Array.isArray(profiles.entry) ? profiles.entry : profiles.entry ? [profiles.entry] : [];
    for (const profile of profileEntries) {
      const profileName = profile['@_name'] || profile.name || 'default';
      const serverSection = profile.server;
      if (!serverSection) continue;

      const serverEntries = Array.isArray(serverSection.entry) ? serverSection.entry : serverSection.entry ? [serverSection.entry] : [];
      for (const srv of serverEntries) {
        servers.push({
          name: srv['@_name'] || srv.name || profileName,
          server: srv.server || srv['@_name'] || '',
          port: parseInt(srv.port || '514', 10),
          transport: srv.transport || 'udp',
          facility: srv.facility || 'LOG_USER',
          profile: profileName,
        });
      }
    }
  }

  if (servers.length > 0) {
    warnings.push(createWarning('info', 'syslog', `Parsed ${servers.length} syslog server(s)`, 'Syslog server configuration detected'));
  }
  return servers;
}


// ---------------------------------------------------------------------------
// DHCP Configuration Parser
// ---------------------------------------------------------------------------

/**
 * Parses PAN-OS DHCP server/relay configuration.
 * Located at: devices > entry > network > dhcp
 */
function parseDhcpConfig(config, warnings) {
  const dhcpConfigs = [];
  const devices = getNestedValue(config, 'devices');
  if (!devices) return dhcpConfigs;

  const entries = Array.isArray(devices.entry) ? devices.entry : devices.entry ? [devices.entry] : [];
  for (const device of entries) {
    const dhcpSection = getNestedValue(device, 'network.dhcp');
    if (!dhcpSection) continue;

    // DHCP Server
    const serverSection = dhcpSection.interface;
    if (serverSection) {
      const ifEntries = Array.isArray(serverSection.entry) ? serverSection.entry : serverSection.entry ? [serverSection.entry] : [];
      for (const iface of ifEntries) {
        const ifName = iface['@_name'] || '';
        const serverConfig = iface.server;
        if (!serverConfig) continue;

        const ipPool = serverConfig['ip-pool'];
        const pools = [];
        if (ipPool) {
          const members = Array.isArray(ipPool.member) ? ipPool.member : ipPool.member ? [ipPool.member] : [];
          pools.push(...members);
        }

        const gateway = serverConfig.option?.gateway || '';
        const dns1 = serverConfig.option?.['dns-server']?.primary || '';
        const dns2 = serverConfig.option?.['dns-server']?.secondary || '';

        dhcpConfigs.push({
          type: 'server',
          interface: ifName,
          pools,
          gateway,
          dns_servers: [dns1, dns2].filter(Boolean),
          lease_time: parseInt(serverConfig.option?.lease?.timeout || '86400', 10),
        });
      }
    }

    // DHCP Relay
    const relaySection = dhcpSection.relay;
    if (relaySection) {
      const relayEntries = Array.isArray(relaySection.entry) ? relaySection.entry : relaySection.entry ? [relaySection.entry] : [];
      for (const relay of relayEntries) {
        const ifName = relay['@_name'] || '';
        const relayServers = relay.server?.['ip-address'];
        const serverList = Array.isArray(relayServers) ? relayServers : relayServers ? [relayServers] : [];
        if (relay.server) {
          const members = Array.isArray(relay.server.member) ? relay.server.member : relay.server.member ? [relay.server.member] : [];
          if (members.length > 0) serverList.push(...members);
        }
        dhcpConfigs.push({
          type: 'relay',
          interface: ifName,
          servers: serverList,
        });
      }
    }
  }

  if (dhcpConfigs.length > 0) {
    warnings.push(createWarning('info', 'dhcp', `Parsed ${dhcpConfigs.length} DHCP config(s)`, 'DHCP server/relay configuration detected'));
  }
  return dhcpConfigs;
}


// ---------------------------------------------------------------------------
// QoS Configuration Parser
// ---------------------------------------------------------------------------

/**
 * Parses PAN-OS QoS profile configuration.
 * Located at: devices > entry > network > qos > profile
 */
function parseQosConfig(config, warnings) {
  const qosProfiles = [];
  const devices = getNestedValue(config, 'devices');
  if (!devices) return qosProfiles;

  const entries = Array.isArray(devices.entry) ? devices.entry : devices.entry ? [devices.entry] : [];
  for (const device of entries) {
    const qosSection = getNestedValue(device, 'network.qos.profile');
    if (!qosSection) continue;

    const profileEntries = Array.isArray(qosSection.entry) ? qosSection.entry : qosSection.entry ? [qosSection.entry] : [];
    for (const profile of profileEntries) {
      const name = profile['@_name'] || profile.name || 'default';
      const classes = [];

      // Parse class bandwidth allocations
      const classSection = profile.class;
      if (classSection) {
        const classEntries = Array.isArray(classSection.entry) ? classSection.entry : classSection.entry ? [classSection.entry] : [];
        for (const cls of classEntries) {
          classes.push({
            name: cls['@_name'] || '',
            priority: cls.priority || 'medium',
            guaranteed_bandwidth: parseInt(cls['guaranteed-bandwidth'] || '0', 10),
            maximum_bandwidth: parseInt(cls['maximum-bandwidth'] || '0', 10),
          });
        }
      }

      qosProfiles.push({
        name,
        max_bandwidth: parseInt(profile['aggregate-bandwidth']?.['egress-max'] || '0', 10),
        classes,
      });
    }
  }

  if (qosProfiles.length > 0) {
    warnings.push(createWarning('info', 'qos', `Parsed ${qosProfiles.length} QoS profile(s)`, 'QoS configuration detected'));
  }
  return qosProfiles;
}


// ---------------------------------------------------------------------------
// Interface Configuration Parser
// ---------------------------------------------------------------------------

function parseInterfaceConfig(config, zones, warnings) {
  const interfaces = [];

  // Build zone lookup: interface name → zone name
  const ifToZone = {};
  for (const z of zones) {
    for (const ifName of (z.interfaces || [])) {
      ifToZone[ifName] = z.name;
    }
  }

  const devices = getNestedValue(config, 'devices');
  if (!devices) return interfaces;

  // PAN-OS interface types: ethernet, loopback, tunnel, aggregate-ethernet, vlan
  const typeMap = {
    ethernet: 'physical',
    loopback: 'loopback',
    tunnel: 'tunnel',
    'aggregate-ethernet': 'aggregate',
    vlan: 'vlan',
  };

  // Iterate over device entries
  for (const device of extractEntries(devices)) {
    const network = getNestedValue(device, 'network.interface');
    if (!network) continue;

    for (const [ifType, container] of Object.entries(network)) {
      if (!container || typeof container !== 'object') continue;
      const typeName = typeMap[ifType] || ifType;
      const entries = extractEntries(container);

      for (const entry of entries) {
        const ifName = entry['@_name'] || '';
        if (!ifName) continue;

        // L3 sub-interfaces
        const l3 = getNestedValue(entry, 'layer3');
        if (l3) {
          // Get IP from top-level layer3 (for interfaces without sub-interfaces)
          const topIps = getNestedValue(l3, 'ip');
          if (topIps) {
            const ipEntries = extractEntries(topIps);
            const ip = ipEntries.length > 0 ? (ipEntries[0]['@_name'] || '') : '';
            const ipv6Node = getNestedValue(l3, 'ipv6.address');
            const ipv6 = ipv6Node ? (extractEntries(ipv6Node)[0]?.['@_name'] || '') : '';
            interfaces.push({
              name: ifName,
              ip,
              ipv6,
              zone: ifToZone[ifName] || '',
              vlan: '',
              type: typeName,
              description: entry.comment || '',
              status: entry['link-state'] === 'down' ? 'shutdown' : 'up',
              speed: '',
            });
          }

          // Sub-interfaces (units)
          const units = getNestedValue(l3, 'units');
          if (units) {
            const unitEntries = extractEntries(units);
            for (const unit of unitEntries) {
              const unitName = unit['@_name'] || '';
              const fullName = unitName || ifName;
              const unitIps = getNestedValue(unit, 'ip');
              const ip = unitIps ? (extractEntries(unitIps)[0]?.['@_name'] || '') : '';
              const unitIpv6 = getNestedValue(unit, 'ipv6.address');
              const ipv6 = unitIpv6 ? (extractEntries(unitIpv6)[0]?.['@_name'] || '') : '';
              const tag = unit.tag || '';
              interfaces.push({
                name: fullName,
                ip,
                ipv6,
                zone: ifToZone[fullName] || '',
                vlan: String(tag),
                type: typeName,
                description: unit.comment || entry.comment || '',
                status: 'up',
                speed: '',
              });
            }
          }

          // If no IPs and no units found, still include the interface
          if (!topIps && !units) {
            interfaces.push({
              name: ifName,
              ip: '',
              ipv6: '',
              zone: ifToZone[ifName] || '',
              vlan: '',
              type: typeName,
              description: entry.comment || '',
              status: entry['link-state'] === 'down' ? 'shutdown' : 'up',
              speed: '',
            });
          }
        } else {
          // Non-L3 interface or loopback/tunnel
          const ipEntries = getNestedValue(entry, 'ip');
          const ip = ipEntries ? (extractEntries(ipEntries)[0]?.['@_name'] || '') : '';
          interfaces.push({
            name: ifName,
            ip,
            ipv6: '',
            zone: ifToZone[ifName] || '',
            vlan: '',
            type: typeName,
            description: entry.comment || '',
            status: entry['link-state'] === 'down' ? 'shutdown' : 'up',
            speed: '',
          });
        }
      }
    }
  }

  if (interfaces.length > 0) {
    warnings.push(createWarning('info', 'interfaces', `Parsed ${interfaces.length} interface(s)`, 'Interface configuration detected'));
  }
  return interfaces;
}

/**
 * Parses PAN-OS virtual-wire pair definitions.
 * Located at: devices > entry > network > virtual-wire > entry
 */
function parseVwirePairs(config, warnings) {
  const pairs = [];
  const devices = getNestedValue(config, 'devices');
  if (!devices) return pairs;

  const deviceEntries = extractEntries(devices);
  for (const device of deviceEntries) {
    const vwContainer = getNestedValue(device, 'network.virtual-wire');
    if (!vwContainer) continue;

    const entries = extractEntries(vwContainer);
    for (const entry of entries) {
      const name = entry['@_name'] || '';
      if (!name) continue;
      const interface1 = typeof entry.interface1 === 'string' ? entry.interface1 : '';
      const interface2 = typeof entry.interface2 === 'string' ? entry.interface2 : '';
      // tag-allowed can be a plain string ("100-200") or member list
      const tagRaw = entry['tag-allowed'];
      const tagAllowed = typeof tagRaw === 'string' ? tagRaw.split(',').map(s => s.trim()).filter(Boolean)
        : extractMembers(tagRaw || {});

      pairs.push({ name, interface1, interface2, tag_allowed: tagAllowed });

      warnings.push(createWarning('warning', `vwire/${name}`,
        `Virtual-wire pair "${name}" (${interface1} <-> ${interface2}) — SRX does not support virtual-wire mode`,
        'Map to SRX L2 transparent mode with bridge-domain, or redesign as L3'));
    }
  }

  return pairs;
}


// ---------------------------------------------------------------------------
// NetFlow / IP Flow Export Parser
// ---------------------------------------------------------------------------

/**
 * Parses PAN-OS NetFlow (IP Flow Export) configuration.
 * Located at: deviceconfig > setting > ctd > ip-flow-export
 * Also checks: network > interface > ethernet > ... > netflow-profile
 */
function parseNetflowConfig(config, warnings) {
  const result = { collectors: [], sampling: { input_rate: 1000, run_length: 0, interfaces: [] }, templates: [] };

  // Check deviceconfig > setting for flow export
  const deviceConfig = config.deviceconfig || config['device-config'] || {};
  const setting = deviceConfig.setting || {};
  const ctd = setting.ctd || {};
  const flowExport = ctd['ip-flow-export'] || {};

  if (!flowExport || Object.keys(flowExport).length === 0) return result;

  // Parse collectors (can be nested under "server" or direct entries)
  const servers = flowExport.server || flowExport;
  if (servers && typeof servers === 'object') {
    const entries = extractEntries(servers);
    for (const entry of entries) {
      const name = entry['@_name'] || '';
      const host = entry.host || entry.server || name;
      const port = parseInt(entry.port) || 2055;
      const templateRefresh = parseInt(entry['template-refresh-rate']) || 600;

      if (host) {
        result.collectors.push({
          address: host,
          port,
          protocol: 'netflow-v9',
          source_address: entry['source-address'] || '',
        });
        result.templates.push({
          name: sanitizeName(name || `tpl-${host}`),
          flow_type: 'ipv4',
          active_timeout: parseInt(entry['active-timeout']) || 60,
          refresh_rate: templateRefresh,
        });
      }
    }
  }

  // Parse sampling rate
  if (flowExport['active-timeout']) {
    result.sampling.input_rate = parseInt(flowExport['active-timeout']) || 1000;
  }

  if (result.collectors.length > 0) {
    warnings.push(createWarning('info', 'netflow',
      `Parsed ${result.collectors.length} NetFlow collector(s)`,
      'NetFlow IP flow export configuration detected'));
  }

  return result;
}

function sanitizeName(name) {
  return name.replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 63);
}

// ---------------------------------------------------------------------------
// LAG / Aggregate-Ethernet Interface Parser
// ---------------------------------------------------------------------------

/**
 * Parses PAN-OS aggregate-ethernet interfaces and their member assignments.
 *
 * PAN-OS XML structure:
 *   <network><interface><aggregate-ethernet><entry name="ae1">
 *     <lacp><enable>yes</enable><mode>active</mode></lacp>
 *   </entry></aggregate-ethernet></network>
 *
 * Members reference their parent via:
 *   <ethernet><entry name="ethernet1/1"><aggregate-group>ae1</aggregate-group></entry>
 *
 * @param {Object} config - Parsed PAN-OS XML config root
 * @param {Object[]} warnings - Warnings array to append to
 * @returns {Object[]} Array of lag_interfaces in intermediate schema format
 */
function parsePanosLagInterfaces(config, warnings) {
  const lagInterfaces = [];
  const network = getNestedValue(config, 'devices.entry.network.interface');
  if (!network) return lagInterfaces;

  // Collect aggregate-ethernet entries
  const aeContainer = network['aggregate-ethernet'];
  if (!aeContainer) return lagInterfaces;

  const aeEntries = extractEntries(aeContainer);
  if (aeEntries.length === 0) return lagInterfaces;

  // Build member map: ae name → [ethernet names]
  const memberMap = {};
  const ethernetContainer = network['ethernet'];
  if (ethernetContainer) {
    const ethEntries = extractEntries(ethernetContainer);
    for (const eth of ethEntries) {
      const ethName = eth['@_name'] || '';
      const aggGroup = eth['aggregate-group'] || '';
      if (aggGroup && ethName) {
        if (!memberMap[aggGroup]) memberMap[aggGroup] = [];
        memberMap[aggGroup].push(ethName);
      }
    }
  }

  for (const entry of aeEntries) {
    const aeName = entry['@_name'] || '';
    if (!aeName) continue;

    // Parse LACP settings
    const lacpNode = getNestedValue(entry, 'lacp');
    let lacpMode = 'static';
    if (lacpNode) {
      const enabled = lacpNode.enable === 'yes' || lacpNode.enable === true;
      if (enabled) {
        lacpMode = lacpNode.mode || 'active';
      }
    }

    const lacpPriority = lacpNode?.['system-priority']
      ? parseInt(lacpNode['system-priority'], 10) || null
      : null;

    const sourceMembers = memberMap[aeName] || [];
    // Normalize PAN-OS ae name to SRX ae format (ae1 → ae0, keep as-is if already ae-prefixed)
    const srxName = aeName.startsWith('ae') ? aeName : `ae${aeName}`;
    // Normalize member names: PAN-OS ethernet1/1 → ge-0/0/0 style
    const srxMembers = sourceMembers.map(m => normalizePanosIfaceToSrx(m));

    const description = entry.comment || '';

    lagInterfaces.push({
      name: srxName,
      source_name: aeName,
      members: srxMembers,
      source_members: sourceMembers,
      lacp_mode: lacpMode,
      lacp_priority: lacpPriority,
      description,
    });
  }

  if (lagInterfaces.length > 0) {
    warnings.push(createWarning('info', 'lag',
      `Parsed ${lagInterfaces.length} aggregate-ethernet (LAG) interface(s) with ${lagInterfaces.reduce((s, l) => s + l.members.length, 0)} member(s)`,
      'LAG interfaces will be converted to SRX ae interfaces'));
  }

  return lagInterfaces;
}

/**
 * Normalizes a PAN-OS physical interface name to SRX naming convention.
 * e.g., ethernet1/1 → ge-0/0/0, ethernet1/2 → ge-0/0/1
 *
 * @param {string} panosName - PAN-OS interface name
 * @returns {string} SRX-normalized interface name
 */
function normalizePanosIfaceToSrx(panosName) {
  const m = panosName.match(/^ethernet(\d+)\/(\d+)$/i);
  if (m) {
    const slot = parseInt(m[1], 10) - 1;
    const port = parseInt(m[2], 10) - 1;
    return `ge-0/${slot}/${port}`;
  }
  return panosName;
}


// ---------------------------------------------------------------------------
// SNMP Configuration Parser (PAN-OS)
// ---------------------------------------------------------------------------

/**
 * Parses PAN-OS SNMP configuration from XML config.
 * PAN-OS path: deviceconfig > system > snmp-setting
 */
function parsePanosSnmpConfig(config, warnings) {
  const entries = [];
  const devices = getNestedValue(config, 'devices');
  if (!devices) return entries;

  const deviceEntries = Array.isArray(devices.entry) ? devices.entry : devices.entry ? [devices.entry] : [];
  for (const device of deviceEntries) {
    const snmpSection = getNestedValue(device, 'deviceconfig.system.snmp-setting');
    if (!snmpSection) continue;

    // SNMPv2c communities: snmp-setting > access-setting > version > v2c
    const v2c = getNestedValue(snmpSection, 'access-setting.version.v2c');
    if (v2c) {
      const communityEntries = Array.isArray(v2c.entry) ? v2c.entry : v2c.entry ? [v2c.entry] : [];
      for (const ce of communityEntries) {
        const name = ce['@_name'] || ce.name || 'public';
        entries.push({
          type: 'community',
          name,
          authorization: 'read-only',
          clients: [],
          contact: getNestedValue(snmpSection, 'contact') || '',
          location: getNestedValue(snmpSection, 'location') || '',
        });
      }
    }

    // SNMPv3 users: snmp-setting > access-setting > version > v3
    const v3 = getNestedValue(snmpSection, 'access-setting.version.v3');
    if (v3) {
      const userEntries = Array.isArray(v3.entry) ? v3.entry : v3.entry ? [v3.entry] : [];
      for (const ue of userEntries) {
        const name = ue['@_name'] || ue.name || '';
        const authProto = ue['auth-profile'] ? 'sha' : 'none';
        const privProto = ue['priv-profile'] ? 'aes128' : 'none';
        entries.push({
          type: 'v3-user',
          name,
          auth_protocol: authProto,
          privacy_protocol: privProto,
          contact: getNestedValue(snmpSection, 'contact') || '',
          location: getNestedValue(snmpSection, 'location') || '',
        });
      }
    }

    // Trap destinations: snmp-setting > snmp-system > trap-dest
    const trapDest = getNestedValue(snmpSection, 'snmp-system.trap-dest');
    if (trapDest) {
      const trapEntries = Array.isArray(trapDest.entry) ? trapDest.entry : trapDest.entry ? [trapDest.entry] : [];
      for (const te of trapEntries) {
        const name = te['@_name'] || te.name || '';
        entries.push({
          type: 'trap-group',
          name: `trap-${name}`,
          targets: [name],
          categories: [],
          version: te.version || 'v2c',
        });
      }
    }
  }

  if (entries.length > 0) {
    warnings.push(createWarning('info', 'snmp', `Parsed ${entries.length} SNMP configuration item(s)`, 'PAN-OS SNMP configuration detected'));
  }
  return entries;
}


// ---------------------------------------------------------------------------
// AAA Configuration Parser (PAN-OS)
// ---------------------------------------------------------------------------

/**
 * Parses PAN-OS AAA configuration.
 * PAN-OS path: shared > server-profile > radius / tacplus / ldap
 */
function parsePanosAaaConfig(config, warnings) {
  const entries = [];
  const devices = getNestedValue(config, 'devices');
  if (!devices) return entries;

  const deviceEntries = Array.isArray(devices.entry) ? devices.entry : devices.entry ? [devices.entry] : [];
  for (const device of deviceEntries) {
    // RADIUS server profiles: shared > server-profile > radius
    const radiusProfiles = getNestedValue(device, 'vsys.entry.server-profile.radius') ||
                           getNestedValue(device, 'shared.server-profile.radius');
    if (radiusProfiles) {
      const profileEntries = Array.isArray(radiusProfiles.entry) ? radiusProfiles.entry : radiusProfiles.entry ? [radiusProfiles.entry] : [];
      for (const profile of profileEntries) {
        const profileName = profile['@_name'] || profile.name || '';
        const servers = profile.server;
        const serverEntries = servers ? (Array.isArray(servers.entry) ? servers.entry : servers.entry ? [servers.entry] : []) : [];
        for (const srv of serverEntries) {
          entries.push({
            type: 'radius',
            name: `${profileName}-${srv['@_name'] || srv.name || ''}`,
            server: srv['ip-address'] || '',
            port: parseInt(srv.port || '1812', 10),
            secret: srv.secret || '',
            timeout: parseInt(srv.timeout || '3', 10),
            retry: parseInt(srv.retry || '3', 10),
            source_address: '',
          });
        }
      }
    }

    // TACACS+ server profiles
    const tacplusProfiles = getNestedValue(device, 'vsys.entry.server-profile.tacplus') ||
                            getNestedValue(device, 'shared.server-profile.tacplus');
    if (tacplusProfiles) {
      const profileEntries = Array.isArray(tacplusProfiles.entry) ? tacplusProfiles.entry : tacplusProfiles.entry ? [tacplusProfiles.entry] : [];
      for (const profile of profileEntries) {
        const profileName = profile['@_name'] || profile.name || '';
        const servers = profile.server;
        const serverEntries = servers ? (Array.isArray(servers.entry) ? servers.entry : servers.entry ? [servers.entry] : []) : [];
        for (const srv of serverEntries) {
          entries.push({
            type: 'tacplus',
            name: `${profileName}-${srv['@_name'] || srv.name || ''}`,
            server: srv.address || '',
            port: parseInt(srv.port || '49', 10),
            secret: srv.secret || '',
            timeout: parseInt(srv.timeout || '3', 10),
            single_connection: false,
            source_address: '',
          });
        }
      }
    }

    // LDAP server profiles
    const ldapProfiles = getNestedValue(device, 'vsys.entry.server-profile.ldap') ||
                         getNestedValue(device, 'shared.server-profile.ldap');
    if (ldapProfiles) {
      const profileEntries = Array.isArray(ldapProfiles.entry) ? ldapProfiles.entry : ldapProfiles.entry ? [ldapProfiles.entry] : [];
      for (const profile of profileEntries) {
        const profileName = profile['@_name'] || profile.name || '';
        const servers = profile.server;
        const serverEntries = servers ? (Array.isArray(servers.entry) ? servers.entry : servers.entry ? [servers.entry] : []) : [];
        for (const srv of serverEntries) {
          entries.push({
            type: 'ldap',
            name: `${profileName}-${srv['@_name'] || srv.name || ''}`,
            server: srv.address || '',
            port: parseInt(srv.port || '389', 10),
            base_dn: profile['base-dn'] || '',
            bind_dn: profile['bind-dn'] || '',
            ssl: profile.ssl === 'yes',
          });
        }
      }
    }

    // Authentication profile
    const authProfiles = getNestedValue(device, 'vsys.entry.authentication-profile') ||
                         getNestedValue(device, 'shared.authentication-profile');
    if (authProfiles) {
      const apEntries = Array.isArray(authProfiles.entry) ? authProfiles.entry : authProfiles.entry ? [authProfiles.entry] : [];
      for (const ap of apEntries) {
        const name = ap['@_name'] || ap.name || '';
        const method = ap.method ? Object.keys(ap.method)[0] || '' : '';
        entries.push({
          type: 'profile',
          name,
          authentication_order: method ? [method] : [],
        });
      }
    }
  }

  if (entries.length > 0) {
    warnings.push(createWarning('info', 'aaa', `Parsed ${entries.length} AAA configuration item(s)`, 'PAN-OS AAA configuration detected'));
  }
  return entries;
}
