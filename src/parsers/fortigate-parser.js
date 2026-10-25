/**
 * FortiGate / FortiOS Configuration Parser
 * ==========================================
 *
 * Parses FortiOS configurations (config/edit/set/next/end block format)
 * into the vendor-neutral intermediate JSON schema.
 *
 * Handles:
 *   - System zones and interfaces
 *   - Address objects (ipmask, iprange, fqdn, wildcard, geography, wildcard-fqdn)
 *   - Address groups
 *   - Service objects (custom) and service groups
 *   - Firewall policies (with UTM profiles, NAT, schedule, logging)
 *   - VIP objects (destination NAT)
 *   - IP pools (source NAT)
 *   - Central SNAT maps
 *
 * FortiOS config format:
 *   config <section>
 *       edit <id-or-name>
 *           set <key> <value...>
 *       next
 *   end
 */

import { createWarning, detectIpVersion } from './parser-utils.js';

// ---------------------------------------------------------------------------
// Main Parser Entry Point
// ---------------------------------------------------------------------------

/**
 * Parses a FortiOS configuration into the intermediate JSON schema.
 *
 * @param {string} configText - Raw FortiOS configuration text
 * @returns {{ intermediateConfig: Object, warnings: Object[], parseStats: Object }}
 */
export function parseFortigateConfig(configText) {
  const warnings = [];

  // Parse config text into a structured tree
  const tree = buildConfigTree(configText);

  // Extract each config section
  const zones = parseZones(tree, warnings);
  const interfaces = parseInterfaces(tree, warnings);
  const addressObjects = parseAddressObjects(tree, warnings);
  const addressGroups = parseAddressGroups(tree, warnings);
  const splitServiceGroups = [];
  const serviceObjects = parseServiceObjects(tree, warnings, splitServiceGroups);
  const serviceGroups = [...parseServiceGroups(tree, warnings), ...splitServiceGroups];
  const securityPolicies = parseSecurityPolicies(tree, warnings);
  const natRules = parseNatRules(tree, warnings);
  const vipObjects = parseVipObjects(tree, warnings);
  synthesizeVipAddresses(tree, securityPolicies, addressObjects, addressGroups);
  const schedules = parseSchedules(tree, warnings);
  const profileGroups = parseProfileGroups(tree, warnings);
  const securityProfileDefinitions = parseSecurityProfileDefinitions(tree, warnings);
  const transparentMode = detectTransparentMode(tree);
  const { l2Interfaces, bridgeDomains: l2BridgeDomains, vwirePairs: fortiVwirePairs } = transparentMode
    ? parseSwitchInterfaces(tree, warnings)
    : { l2Interfaces: [], bridgeDomains: [], vwirePairs: [] };
  const staticRoutes = parseStaticRoutes(tree, warnings);
  const bgpConfig = parseFortiBgpConfig(tree, warnings);
  const ospfConfig = parseFortiOspfConfig(tree, warnings);
  const ospf3Config = parseFortiOspf6Config(tree, warnings);
  const vxlanConfig = parseFortiVxlanConfig(tree, warnings);
  const haConfig = parseHaConfig(tree, warnings);
  const screenConfig = parseScreenConfig(tree, warnings);
  const pbfRules = parseFortiPolicyRouting(tree, warnings);

  // Promote schedules to intermediate format (normalize day names to short form)
  const dayShortMap = { monday: 'Mon', tuesday: 'Tue', wednesday: 'Wed', thursday: 'Thu', friday: 'Fri', saturday: 'Sat', sunday: 'Sun' };
  const intermediateSchedules = Object.values(schedules).map(s => ({
    name: s.name,
    type: s.type,
    days: (s.day || []).map(d => dayShortMap[d.toLowerCase()] || d),
    start: s.start || '',
    end: s.end || '',
  }));

  // Expand profile group references into individual profiles on policies
  for (const policy of securityPolicies) {
    if (policy.profile_group && Object.keys(policy.security_profiles).length === 0) {
      const groupDef = profileGroups[policy.profile_group];
      if (groupDef) {
        if (groupDef['av-profile']) policy.security_profiles.virus = groupDef['av-profile'];
        if (groupDef['webfilter-profile']) policy.security_profiles['url-filtering'] = groupDef['webfilter-profile'];
        if (groupDef['ips-sensor']) policy.security_profiles.vulnerability = groupDef['ips-sensor'];
        if (groupDef['application-list']) policy.security_profiles['application-control'] = groupDef['application-list'];
        if (groupDef['dnsfilter-profile']) policy.security_profiles['dns-security'] = groupDef['dnsfilter-profile'];
        if (groupDef['emailfilter-profile']) policy.security_profiles['email-filter'] = groupDef['emailfilter-profile'];
        if (groupDef['dlp-profile']) policy.security_profiles.dlp = groupDef['dlp-profile'];
        if (groupDef['ssl-ssh-profile']) policy.security_profiles.decryption = groupDef['ssl-ssh-profile'];
      } else {
        warnings.push(createWarning('warning', `policy/${policy.name}`,
          `Profile group "${policy.profile_group}" referenced but not found in config`,
          'Define the profile group or assign individual profiles'));
      }
    }
  }

  // Parse LAG / aggregate interfaces
  const lagInterfaces = parseFortigateLagInterfaces(tree, interfaces, warnings);

  // Merge zone and interface data — FortiGate can use interfaces directly as zones
  const lagMemberNames = new Set(lagInterfaces.flatMap(lag => lag.source_members));
  const mergedZones = mergeZonesAndInterfaces(zones, interfaces, securityPolicies, natRules, lagMemberNames, warnings);

  // Normalize interfaces to standard schema
  const ifToZone = {};
  for (const z of mergedZones) {
    for (const ifName of (z.interfaces || [])) ifToZone[ifName] = z.name;
  }
  const normalizedInterfaces = interfaces.map(iface => {
    // Convert "10.1.1.1 255.255.255.0" to CIDR "10.1.1.1/24"
    let ip = '';
    if (iface.ip) {
      const parts = iface.ip.trim().split(/\s+/);
      if (parts.length === 2) {
        const cidr = maskToCidr(parts[1]);
        ip = `${parts[0]}/${cidr}`;
      } else {
        ip = parts[0]; // Already CIDR or just IP
      }
    }
    return {
      name: iface.name,
      ip,
      zone: ifToZone[iface.name] || iface.zone || '',
      vlan: '',
      type: iface.type || 'physical',
      description: iface.alias || '',
      status: 'up',
      speed: '',
    };
  });

  // Detect VDOM context
  const routingContexts = detectVdomContext(tree, mergedZones, interfaces);

  // Tag policies with VDOM if interfaces have vdom info
  const ifVdomMap = {};
  for (const iface of interfaces) {
    if (iface.vdom && iface.vdom !== 'root') ifVdomMap[iface.name] = iface.vdom;
  }
  if (Object.keys(ifVdomMap).length > 0) {
    for (const policy of securityPolicies) {
      const srcIf = (policy.src_zones || [])[0];
      if (srcIf && ifVdomMap[srcIf]) {
        if (!policy._fortigate) policy._fortigate = {};
        policy._fortigate.vdom = ifVdomMap[srcIf];
      }
    }
  }

  // Detect FortiOS version from config
  const version = extractVersion(tree);

  // Append FortiGate implicit rules
  let implicitIndex = securityPolicies.length + 1;
  const implicitFortigateBase = { policyid: 0, schedule: 'always', nat: false, utm_status: false, inspection_mode: 'flow', profile_type: '', users: [], groups: [], uuid: '' };
  for (const zone of mergedZones) {
    const intrazoneAction = zone._intrazone || 'deny';
    securityPolicies.push({
      name: `Implicit: Intra-zone ${intrazoneAction === 'allow' ? 'Allow' : 'Deny'} (${zone.name})`,
      src_zones: [zone.name],
      dst_zones: [zone.name],
      src_addresses: ['all'],
      dst_addresses: ['all'],
      negate_source: false,
      negate_destination: false,
      applications: [],
      services: ['ALL'],
      action: intrazoneAction === 'allow' ? 'allow' : 'deny',
      log_start: false,
      log_end: false,
      profile_group: '',
      security_profiles: {},
      description: `FortiGate intrazone-traffic default: ${intrazoneAction}`,
      tags: ['added_by_fpic'],
      disabled: false,
      source_users: [],
      _rule_index: implicitIndex++,
      _implicit: true,
      _fortigate: { ...implicitFortigateBase },
    });
  }
  securityPolicies.push({
    name: 'Implicit: Default Deny',
    src_zones: ['any'],
    dst_zones: ['any'],
    src_addresses: ['all'],
    dst_addresses: ['all'],
    negate_source: false,
    negate_destination: false,
    applications: [],
    services: ['ALL'],
    action: 'deny',
    log_start: false,
    log_end: false,
    profile_group: '',
    security_profiles: {},
    description: 'FortiGate default: implicit deny at end of policy list',
    tags: ['added_by_fpic'],
    disabled: false,
    source_users: [],
    _rule_index: implicitIndex++,
    _implicit: true,
    _fortigate: { ...implicitFortigateBase },
  });

  // Parse VPN/IPsec tunnel configuration
  const vpnTunnels = parseVpnConfig(tree, warnings);

  // Parse syslog, DHCP, QoS
  const syslogConfig = parseFortiSyslogConfig(tree, warnings);
  const dhcpConfig = parseFortiDhcpConfig(tree, warnings);
  const qosConfig = parseFortiQosConfig(tree, warnings);

  // Synthesize decryption_rules from ssl-ssh-profile references (must run after profile group expansion)
  const decryptionRules = parseFortiSslProfiles(tree, securityPolicies, warnings);

  // Parse NetFlow/sFlow configuration
  const flowMonitoringConfig = parseFortiNetflow(tree, warnings);

  const intermediateConfig = {
    zones: mergedZones,
    address_objects: addressObjects,
    address_groups: addressGroups,
    service_objects: serviceObjects,
    service_groups: serviceGroups,
    security_policies: securityPolicies,
    nat_rules: natRules,
    applications: [],
    application_groups: [],
    schedules: intermediateSchedules,
    security_profile_objects: buildProfileObjects(securityPolicies, profileGroups),
    security_profile_definitions: securityProfileDefinitions,
    external_lists: [],
    vpn_tunnels: vpnTunnels,
    ha_config: haConfig,
    screen_config: screenConfig,
    syslog_config: syslogConfig,
    snmp_config: parseFortigateSnmpConfig(tree, warnings),
    aaa_config: parseFortigateAaaConfig(tree, warnings),
    dhcp_config: dhcpConfig,
    qos_config: qosConfig,
    interfaces: normalizedInterfaces,
    lag_interfaces: lagInterfaces,
    transparent_mode: transparentMode,
    bridge_domains: l2BridgeDomains,
    l2_interfaces: l2Interfaces,
    vwire_pairs: fortiVwirePairs,
    routing_contexts: routingContexts,
    static_routes: staticRoutes,
    bgp_config: bgpConfig,
    ospf_config: ospfConfig,
    ospf3_config: ospf3Config,
    evpn_config: [],
    vxlan_config: vxlanConfig,
    pbf_rules: pbfRules,
    decryption_rules: decryptionRules,
    flow_monitoring_config: flowMonitoringConfig,
    target_context: null,
    // FortiGate-specific extras (for the FortiGate view)
    _fortigate: {
      vips: vipObjects,
      schedules,
      profileGroups,
    },
    metadata: {
      source_vendor: 'fortigate',
      source_version: version,
      export_date: new Date().toISOString(),
      rule_count: securityPolicies.length,
      nat_rule_count: natRules.length,
      object_count: addressObjects.length + serviceObjects.length,
      zone_count: mergedZones.length,
      interface_count: normalizedInterfaces.length,
      vpn_tunnel_count: vpnTunnels.length,
      syslog_server_count: syslogConfig.length,
      dhcp_config_count: dhcpConfig.length,
      qos_profile_count: qosConfig.length,
      routing_context_count: routingContexts.length,
      static_route_count: staticRoutes.length,
      bgp_instance_count: bgpConfig.length,
      ospf_instance_count: ospfConfig.length,
      ospf3_instance_count: ospf3Config.length,
      evpn_instance_count: 0,
      vxlan_tunnel_count: vxlanConfig.length,
      ha_enabled: !!(haConfig && haConfig.enabled),
      multi_vsys: routingContexts.length > 1,
    },
  };

  return {
    intermediateConfig,
    warnings,
    parseStats: intermediateConfig.metadata,
  };
}


// ---------------------------------------------------------------------------
// Policy-Based Routing (config router policy)
// ---------------------------------------------------------------------------

function parseFortiPolicyRouting(tree, warnings) {
  const section = tree['router policy'] || {};
  const rules = [];
  for (const [id, entry] of entriesInConfigOrder(section)) {
    if (typeof entry !== 'object') continue;
    const inputDevice = getString(entry['input-device']) || '';
    const srcRaw = getString(entry.src) || '';
    const dstRaw = getString(entry.dst) || '';
    const gateway = getString(entry.gateway) || '';
    const outputDevice = getString(entry['output-device']) || '';
    const protocol = getString(entry.protocol) || '';
    const startPort = getString(entry['start-port']) || '';
    const endPort = getString(entry['end-port']) || '';

    if (!gateway && !outputDevice) continue;

    // Convert src/dst from "IP MASK" to CIDR
    const toCidr = (raw) => {
      if (!raw || raw === '0.0.0.0 0.0.0.0') return 'any';
      const parts = raw.split(/\s+/);
      if (parts.length === 2) {
        const mask = parts[1];
        const bits = mask.split('.').reduce((a, o) => a + (parseInt(o, 10) >>> 0).toString(2).replace(/0/g, '').length, 0);
        return `${parts[0]}/${bits}`;
      }
      return raw;
    };

    const srcAddr = toCidr(srcRaw);
    const dstAddr = toCidr(dstRaw);

    const services = [];
    if (protocol && startPort) {
      const proto = protocol === '6' ? 'tcp' : protocol === '17' ? 'udp' : protocol;
      services.push(endPort && endPort !== startPort ? `${proto}/${startPort}-${endPort}` : `${proto}/${startPort}`);
    }

    rules.push({
      name: `pbf-${id}`,
      from_type: inputDevice ? 'interface' : 'zone',
      from_value: inputDevice ? [inputDevice] : [],
      src_addresses: srcAddr !== 'any' ? [srcAddr] : ['any'],
      dst_addresses: dstAddr !== 'any' ? [dstAddr] : ['any'],
      src_users: [],
      negate_source: false,
      negate_destination: false,
      applications: [],
      services,
      action: 'forward',
      egress_interface: outputDevice,
      next_hop_type: 'ip-address',
      next_hop_value: gateway,
      forward_vsys: '',
      monitor_profile: '',
      monitor_ip: '',
      monitor_disable_if_unreachable: false,
      symmetric_return: false,
      symmetric_return_addresses: [],
      description: '',
      tags: [],
      disabled: false,
      schedule: '',
      _rule_index: rules.length + 1,
    });
  }
  return rules;
}


// ---------------------------------------------------------------------------
// Static Route Parser
// ---------------------------------------------------------------------------

function parseStaticRoutes(tree, warnings) {
  const routeSection = tree['router static'];
  if (!routeSection) return [];

  const routes = [];
  for (const [id, entry] of Object.entries(routeSection)) {
    if (typeof entry !== 'object' || entry === null) continue;

    const dstVal = entry['dst'];
    const gateway = getString(entry['gateway']) || '';
    const device = getString(entry['device']) || '';
    const distance = parseInt(getString(entry['distance'])) || 10;
    const comment = getString(entry['comment']) || getString(entry['comments']) || '';
    const isBlackhole = getString(entry['blackhole']) === 'enable';

    // FortiGate dst is "ip mask" — stored as array ['ip','mask'] or string "ip mask"
    let destination = '0.0.0.0/0';
    if (Array.isArray(dstVal) && dstVal.length >= 2) {
      destination = `${dstVal[0]}/${maskToCidr(dstVal[1])}`;
    } else if (typeof dstVal === 'string') {
      const parts = dstVal.split(/\s+/);
      if (parts.length === 2) {
        destination = `${parts[0]}/${maskToCidr(parts[1])}`;
      } else {
        destination = dstVal;
      }
    }

    routes.push({
      name: id,
      destination,
      next_hop: gateway,
      next_hop_type: isBlackhole ? 'discard' : (gateway ? 'ip-address' : 'none'),
      interface: device,
      metric: distance,
      admin_distance: distance,
      description: comment,
      vrf: '',
      routing_context: '',
    });
  }

  return routes;
}

// ---------------------------------------------------------------------------
// BGP Configuration
// ---------------------------------------------------------------------------

function parseFortiBgpConfig(tree, warnings) {
  const bgpSection = tree['router bgp'];
  if (!bgpSection || typeof bgpSection !== 'object') return [];

  const localAs = parseInt(getString(bgpSection['as'])) || null;
  const routerId = getString(bgpSection['router-id']) || '';

  if (!localAs) return [];

  // Parse neighbors
  const peerGroups = [];
  const defaultGroup = { name: 'PEERS', type: 'external', neighbors: [] };

  const neighborSection = bgpSection['neighbor'];
  if (neighborSection && typeof neighborSection === 'object') {
    for (const [id, entry] of Object.entries(neighborSection)) {
      if (typeof entry !== 'object' || entry === null) continue;
      const addr = getString(entry['remote-ip']) || id;
      const peerAs = parseInt(getString(entry['remote-as'])) || null;
      const groupType = peerAs && peerAs === localAs ? 'internal' : 'external';
      defaultGroup.type = groupType;
      defaultGroup.neighbors.push({
        address: addr.split('/')[0], // remove CIDR if present
        peer_as: peerAs,
        description: getString(entry['description']) || '',
        update_source: getString(entry['update-source']) || '',
        local_address: '',
        import_policy: getString(entry['route-map-in']) || '',
        export_policy: getString(entry['route-map-out']) || '',
        authentication_key: '',
        enabled: getString(entry['shutdown']) !== 'enable',
      });
    }
  }

  if (defaultGroup.neighbors.length > 0) peerGroups.push(defaultGroup);

  // Parse networks
  const networks = [];
  const networkSection = bgpSection['network'];
  if (networkSection && typeof networkSection === 'object') {
    for (const [id, entry] of Object.entries(networkSection)) {
      if (typeof entry !== 'object' || entry === null) continue;
      const prefix = getString(entry['prefix']);
      if (prefix) {
        // FortiGate prefix format: "ip mask" or CIDR
        const parts = prefix.split(/\s+/);
        const formatted = parts.length === 2 ? `${parts[0]}/${maskToCidr(parts[1])}` : prefix;
        networks.push({ prefix: formatted, policy: '' });
      }
    }
  }

  // Parse redistribution — handles both nested and flattened key formats
  const redistribute = [];
  const redistSection = bgpSection['redistribute'];
  if (redistSection && typeof redistSection === 'object') {
    for (const [proto, entry] of Object.entries(redistSection)) {
      if (typeof entry !== 'object' || entry === null) continue;
      if (getString(entry['status']) === 'enable') {
        redistribute.push({ protocol: proto, policy: getString(entry['route-map']) || '' });
      }
    }
  }
  // Flattened keys: 'redistribute "static"', 'redistribute "connected"', etc.
  for (const key of Object.keys(bgpSection)) {
    const redistMatch = key.match(/^redistribute\s+"?(\w+)"?$/);
    if (redistMatch) {
      const entry = bgpSection[key];
      if (typeof entry === 'object' && entry !== null && getString(entry['status']) === 'enable') {
        redistribute.push({ protocol: redistMatch[1], policy: getString(entry['route-map']) || '' });
      }
    }
  }

  return [{
    instance: '',
    local_as: localAs,
    router_id: routerId,
    peer_groups: peerGroups,
    networks,
    redistribute,
  }];
}

// ---------------------------------------------------------------------------
// OSPF Configuration
// ---------------------------------------------------------------------------

function parseFortiOspfConfig(tree, warnings) {
  const ospfSection = tree['router ospf'];
  if (!ospfSection || typeof ospfSection !== 'object') return [];

  const routerId = getString(ospfSection['router-id']) || '';

  // Parse areas
  const areas = [];
  const areaSection = ospfSection['area'];
  if (areaSection && typeof areaSection === 'object') {
    for (const [id, entry] of Object.entries(areaSection)) {
      if (typeof entry !== 'object' || entry === null) continue;
      const areaId = getString(entry['id']) || id;
      let areaType = 'normal';
      const typeVal = getString(entry['type']);
      if (typeVal === 'stub') areaType = getString(entry['no-summary']) === 'enable' ? 'totally-stub' : 'stub';
      else if (typeVal === 'nssa') areaType = getString(entry['no-summary']) === 'enable' ? 'totally-nssa' : 'nssa';
      areas.push({ area_id: areaId, area_type: areaType, interfaces: [], networks: [] });
    }
  }

  // Parse OSPF interfaces (FortiGate links interfaces to areas separately)
  const ospfIfSection = ospfSection['ospf-interface'];
  if (ospfIfSection && typeof ospfIfSection === 'object') {
    for (const [id, entry] of Object.entries(ospfIfSection)) {
      if (typeof entry !== 'object' || entry === null) continue;
      const ifName = getString(entry['interface']) || id;
      const areaRef = getString(entry['area']) || '0.0.0.0';
      const iface = {
        name: ifName,
        cost: entry['cost'] ? parseInt(getString(entry['cost'])) || null : null,
        hello_interval: entry['hello-interval'] ? parseInt(getString(entry['hello-interval'])) || null : null,
        dead_interval: entry['dead-interval'] ? parseInt(getString(entry['dead-interval'])) || null : null,
        authentication: null,
        passive: false,
        network_type: getString(entry['network-type']) || null,
      };

      // Authentication
      const authType = getString(entry['authentication']);
      if (authType === 'md5') {
        iface.authentication = { type: 'md5', key_id: 1, key: getString(entry['md5-key']) || '' };
      } else if (authType === 'text') {
        iface.authentication = { type: 'simple', key: getString(entry['authentication-key']) || '' };
      }

      // Find or create the matching area
      let area = areas.find(a => a.area_id === areaRef);
      if (!area) {
        area = { area_id: areaRef, area_type: 'normal', interfaces: [], networks: [] };
        areas.push(area);
      }
      area.interfaces.push(iface);
    }
  }

  // Parse passive interfaces
  const passiveSection = ospfSection['passive-interface'];
  if (passiveSection && typeof passiveSection === 'object') {
    for (const [id, entry] of Object.entries(passiveSection)) {
      if (typeof entry !== 'object' || entry === null) continue;
      const ifName = getString(entry['name']) || id;
      // Mark matching interfaces as passive
      for (const area of areas) {
        for (const iface of area.interfaces) {
          if (iface.name === ifName) iface.passive = true;
        }
      }
    }
  }

  if (areas.length === 0) return [];

  // Parse redistribution — handles both nested "redistribute" > "<proto>" and
  // flattened 'redistribute "<proto>"' keys from FortiGate config format
  const redistribute = [];
  const redistSection = ospfSection['redistribute'];
  if (redistSection && typeof redistSection === 'object') {
    for (const [proto, entry] of Object.entries(redistSection)) {
      if (typeof entry !== 'object' || entry === null) continue;
      if (getString(entry['status']) === 'enable') {
        const metricType = getString(entry['metric-type']);
        redistribute.push({ protocol: proto, policy: getString(entry['route-map']) || '', metric_type: metricType || null });
      }
    }
  }
  // Flattened keys: 'redistribute "static"', 'redistribute "connected"', etc.
  for (const key of Object.keys(ospfSection)) {
    const redistMatch = key.match(/^redistribute\s+"?(\w+)"?$/);
    if (redistMatch) {
      const entry = ospfSection[key];
      if (typeof entry === 'object' && entry !== null && getString(entry['status']) === 'enable') {
        const proto = redistMatch[1];
        const metricType = getString(entry['metric-type']);
        redistribute.push({ protocol: proto, policy: getString(entry['route-map']) || '', metric_type: metricType || null });
      }
    }
  }

  return [{
    instance: '',
    router_id: routerId,
    reference_bandwidth: null,
    areas,
    redistribute,
  }];
}

// ---------------------------------------------------------------------------
// OSPFv3 (IPv6 OSPF) Configuration
// ---------------------------------------------------------------------------

function parseFortiOspf6Config(tree, warnings) {
  const ospf6Section = tree['router ospf6'];
  if (!ospf6Section || typeof ospf6Section !== 'object') return [];

  const routerId = getString(ospf6Section['router-id']) || '';

  // Parse areas
  const areas = [];
  const areaSection = ospf6Section['area'];
  if (areaSection && typeof areaSection === 'object') {
    for (const [id, entry] of Object.entries(areaSection)) {
      if (typeof entry !== 'object' || entry === null) continue;
      const areaId = getString(entry['id']) || id;
      let areaType = 'normal';
      const typeVal = getString(entry['type']);
      if (typeVal === 'stub') areaType = getString(entry['no-summary']) === 'enable' ? 'totally-stub' : 'stub';
      else if (typeVal === 'nssa') areaType = getString(entry['no-summary']) === 'enable' ? 'totally-nssa' : 'nssa';
      areas.push({ area_id: areaId, area_type: areaType, interfaces: [], networks: [] });
    }
  }

  // Parse OSPFv3 interfaces
  const ospfIfSection = ospf6Section['ospf6-interface'];
  if (ospfIfSection && typeof ospfIfSection === 'object') {
    for (const [id, entry] of Object.entries(ospfIfSection)) {
      if (typeof entry !== 'object' || entry === null) continue;
      const ifName = getString(entry['interface']) || id;
      const areaRef = getString(entry['area-id']) || '0.0.0.0';
      const iface = {
        name: ifName,
        cost: entry['cost'] ? parseInt(getString(entry['cost'])) || null : null,
        hello_interval: entry['hello-interval'] ? parseInt(getString(entry['hello-interval'])) || null : null,
        dead_interval: entry['dead-interval'] ? parseInt(getString(entry['dead-interval'])) || null : null,
        passive: false,
        network_type: getString(entry['network-type']) || null,
        instance_id: entry['instance-id'] ? parseInt(getString(entry['instance-id'])) || null : null,
      };

      let area = areas.find(a => a.area_id === areaRef);
      if (!area) {
        area = { area_id: areaRef, area_type: 'normal', interfaces: [], networks: [] };
        areas.push(area);
      }
      area.interfaces.push(iface);
    }
  }

  // Parse passive interfaces
  const passiveSection = ospf6Section['passive-interface'];
  if (passiveSection && typeof passiveSection === 'object') {
    for (const [id, entry] of Object.entries(passiveSection)) {
      if (typeof entry !== 'object' || entry === null) continue;
      const ifName = getString(entry['name']) || id;
      for (const area of areas) {
        for (const iface of area.interfaces) {
          if (iface.name === ifName) iface.passive = true;
        }
      }
    }
  }

  if (areas.length === 0) return [];

  // Parse redistribution
  const redistribute = [];
  const redistSection = ospf6Section['redistribute'];
  if (redistSection && typeof redistSection === 'object') {
    for (const [proto, entry] of Object.entries(redistSection)) {
      if (typeof entry !== 'object' || entry === null) continue;
      if (getString(entry['status']) === 'enable') {
        redistribute.push({ protocol: proto, policy: getString(entry['routemap']) || '', metric_type: null });
      }
    }
  }
  // Flattened keys: 'redistribute "static"', etc.
  for (const key of Object.keys(ospf6Section)) {
    const redistMatch = key.match(/^redistribute\s+"?(\w+)"?$/);
    if (redistMatch) {
      const entry = ospf6Section[key];
      if (typeof entry === 'object' && entry !== null && getString(entry['status']) === 'enable') {
        const proto = redistMatch[1];
        redistribute.push({ protocol: proto, policy: getString(entry['routemap']) || '', metric_type: null });
      }
    }
  }

  return [{
    instance: '',
    router_id: routerId,
    reference_bandwidth: null,
    areas,
    redistribute,
  }];
}

// ---------------------------------------------------------------------------
// VxLAN Configuration
// ---------------------------------------------------------------------------

function parseFortiVxlanConfig(tree, warnings) {
  const vxlanSection = tree['system vxlan'];
  if (!vxlanSection || typeof vxlanSection !== 'object') return [];

  const tunnels = [];
  for (const [name, entry] of Object.entries(vxlanSection)) {
    if (typeof entry !== 'object' || entry === null) continue;

    const vni = entry['vni'] ? parseInt(getString(entry['vni'])) || null : null;
    const iface = getString(entry['interface']) || '';
    const dstport = entry['dstport'] ? parseInt(getString(entry['dstport'])) || 4789 : 4789;

    // Remote IPs
    const remoteVteps = [];
    const remoteIpSection = entry['remote-ip'];
    if (remoteIpSection && typeof remoteIpSection === 'object') {
      for (const [, ripEntry] of Object.entries(remoteIpSection)) {
        if (typeof ripEntry === 'object' && ripEntry !== null) {
          const ip = getString(ripEntry['ip']) || '';
          if (ip) remoteVteps.push(ip);
        }
      }
    }

    // Multicast group
    const mcastGroup = getString(entry['multicast-ttl']) ? null : null;

    if (vni) {
      tunnels.push({
        name: getString(entry['name']) || name,
        instance: '',
        vtep_source_interface: iface,
        vnis: [{
          vni,
          vlan_id: null,
          mcast_group: mcastGroup,
          ingress_replication: remoteVteps.length > 0,
          remote_vteps: remoteVteps,
        }],
        udp_port: dstport,
        source_interface: iface,
      });
    }
  }

  return tunnels;
}

// ---------------------------------------------------------------------------
// VDOM Context Detection
// ---------------------------------------------------------------------------

function detectVdomContext(tree, zones, interfaces) {
  const routingContexts = [];

  // Check for explicit VDOM config
  const vdomSection = tree['vdom'];
  if (vdomSection && typeof vdomSection === 'object') {
    for (const [vdomName, vdomData] of Object.entries(vdomSection)) {
      if (typeof vdomData !== 'object') continue;
      routingContexts.push({
        name: vdomName,
        type: 'vdom',
        virtual_routers: [],
        zones: zones.filter(z => {
          // Match zones to VDOM via interface vdom field
          const matchIf = interfaces.find(i => i.name === z.name);
          return matchIf && matchIf.vdom === vdomName;
        }).map(z => z.name),
      });
    }
  }

  // If no explicit VDOMs detected, create a single default context
  if (routingContexts.length === 0) {
    // Check if interfaces have different vdom values
    const vdoms = new Set();
    for (const iface of interfaces) {
      if (iface.vdom) vdoms.add(iface.vdom);
    }

    if (vdoms.size > 1) {
      for (const vdomName of vdoms) {
        routingContexts.push({
          name: vdomName,
          type: 'vdom',
          virtual_routers: [],
          zones: zones.filter(z => {
            const matchIf = interfaces.find(i => i.name === z.name);
            return matchIf && matchIf.vdom === vdomName;
          }).map(z => z.name),
        });
      }
    } else {
      routingContexts.push({
        name: vdoms.size === 1 ? [...vdoms][0] : 'default',
        type: 'default',
        virtual_routers: [],
        zones: zones.map(z => z.name),
      });
    }
  }

  return routingContexts;
}

// ---------------------------------------------------------------------------
// HA Configuration
// ---------------------------------------------------------------------------

function parseHaConfig(tree, warnings) {
  const haSection = tree['system ha'];
  if (!haSection) return null;

  const modeMap = { 'standalone': 'standalone', 'a-p': 'active-passive', 'a-a': 'active-active' };
  const modeStr = getString(haSection['mode']) || 'standalone';
  const mode = modeMap[modeStr] || modeStr;
  if (mode === 'standalone') return { enabled: false, mode: 'standalone', group_id: 0, priority: 128, preempt: false, peer_ip: '', ha_interfaces: [], monitoring: { link_groups: [], path_groups: [] }, description: 'HA standalone' };

  const groupId = parseInt(getString(haSection['group-id'])) || 0;
  const groupName = getString(haSection['group-name']) || '';
  const priority = parseInt(getString(haSection['priority'])) || 128;
  const preempt = getString(haSection['override']) === 'enable';
  const password = ''; // sanitized

  // Heartbeat device
  const haInterfaces = [];
  const hbdev = haSection['hbdev'];
  if (hbdev) {
    // hbdev can be "port5" 50 or array
    const hbParts = Array.isArray(hbdev) ? hbdev : [hbdev];
    for (let i = 0; i < hbParts.length; i += 2) {
      const ifName = typeof hbParts[i] === 'string' ? hbParts[i].replace(/"/g, '') : String(hbParts[i]);
      haInterfaces.push({
        name: 'heartbeat',
        ip: '',
        netmask: '',
        interface: ifName,
      });
    }
  }

  // HA management interface
  const haMgmtIf = haSection['ha-mgmt-interfaces'];
  if (haMgmtIf && typeof haMgmtIf === 'object') {
    for (const [id, entry] of Object.entries(haMgmtIf)) {
      if (typeof entry !== 'object') continue;
      haInterfaces.push({
        name: 'management',
        ip: getString(entry['gateway']) || '',
        netmask: '',
        interface: getString(entry['interface']) || '',
      });
    }
  }

  // Link monitoring
  const monitoring = { link_groups: [], path_groups: [] };
  const monitor = haSection['monitor'];
  if (monitor) {
    const monParts = Array.isArray(monitor) ? monitor : [monitor];
    monitoring.link_groups.push({
      name: 'default',
      enabled: true,
      interfaces: monParts.map(m => typeof m === 'string' ? m.replace(/"/g, '') : String(m)),
    });
  }

  return {
    enabled: true,
    mode,
    group_id: groupId,
    priority,
    preempt,
    peer_ip: '',
    ha_interfaces: haInterfaces,
    monitoring,
    description: `FortiGate HA ${mode}${groupName ? ` (${groupName})` : ''} group ${groupId}`,
  };
}

// ---------------------------------------------------------------------------
// Config Tree Builder
// ---------------------------------------------------------------------------
// Screen / DDoS Protection Parser
// ---------------------------------------------------------------------------

/**
 * Parses FortiGate DoS policy and anomaly settings into the screen_config schema.
 * DoS policies: config firewall DoS-policy
 * Anomaly settings: config firewall anomaly
 */
function parseScreenConfig(tree, warnings) {
  const screenConfigs = [];

  // Parse "firewall DoS-policy" entries
  const dosSection = tree['firewall DoS-policy'];
  if (dosSection && typeof dosSection === 'object') {
    for (const [id, entry] of Object.entries(dosSection)) {
      if (typeof entry !== 'object') continue;

      const iface = getString(entry.interface) || '';
      const name = `dos-policy-${id}`;

      const screen = {
        name,
        zone: iface,
        icmp: {
          flood_threshold: null,
          ping_death: false,
          fragment: false,
        },
        tcp: {
          syn_flood_threshold: null,
          syn_flood_timeout: null,
          land_attack: false,
          winnuke: false,
          tcp_no_flag: false,
        },
        udp: {
          flood_threshold: null,
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
        description: `DoS policy ${id} on interface ${iface}`,
      };

      // Parse anomaly sub-entries within the DoS policy
      const anomaly = entry.anomaly;
      if (anomaly && typeof anomaly === 'object') {
        for (const [anomalyName, anomalyData] of Object.entries(anomaly)) {
          if (typeof anomalyData !== 'object') continue;
          const status = getString(anomalyData.status);
          if (status !== 'enable') continue;
          const threshold = parseInt(getString(anomalyData.threshold)) || null;

          switch (anomalyName) {
            case 'tcp_syn_flood':
              screen.tcp.syn_flood_threshold = threshold;
              break;
            case 'udp_flood':
              screen.udp.flood_threshold = threshold;
              break;
            case 'icmp_flood':
              screen.icmp.flood_threshold = threshold;
              break;
            case 'icmp_sweep':
            case 'icmp_fragment':
              screen.icmp.fragment = true;
              break;
            case 'tcp_land':
              screen.tcp.land_attack = true;
              break;
            case 'tcp_winnuke':
              screen.tcp.winnuke = true;
              break;
            case 'tcp_no_flag':
              screen.tcp.tcp_no_flag = true;
              break;
            case 'ip_spoofing':
              screen.ip.spoofing = true;
              break;
            case 'ip_source_route':
              screen.ip.source_route = true;
              break;
          }
        }
      }

      screenConfigs.push(screen);
    }
  }

  // Parse standalone "firewall anomaly" entries (global anomaly protection)
  const anomalySection = tree['firewall anomaly'];
  if (anomalySection && typeof anomalySection === 'object') {
    const globalScreen = {
      name: 'global-anomaly',
      zone: '',
      icmp: {
        flood_threshold: null,
        ping_death: false,
        fragment: false,
      },
      tcp: {
        syn_flood_threshold: null,
        syn_flood_timeout: null,
        land_attack: false,
        winnuke: false,
        tcp_no_flag: false,
      },
      udp: {
        flood_threshold: null,
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
      description: 'FortiGate global anomaly protection settings',
    };

    let hasAny = false;
    for (const [anomalyName, anomalyData] of Object.entries(anomalySection)) {
      if (typeof anomalyData !== 'object') continue;
      const status = getString(anomalyData.status);
      if (status !== 'enable') continue;
      hasAny = true;
      const threshold = parseInt(getString(anomalyData.threshold)) || null;

      switch (anomalyName) {
        case 'tcp_syn_flood':
          globalScreen.tcp.syn_flood_threshold = threshold;
          break;
        case 'udp_flood':
          globalScreen.udp.flood_threshold = threshold;
          break;
        case 'icmp_flood':
          globalScreen.icmp.flood_threshold = threshold;
          break;
        case 'tcp_land':
          globalScreen.tcp.land_attack = true;
          break;
        case 'tcp_winnuke':
          globalScreen.tcp.winnuke = true;
          break;
        case 'tcp_no_flag':
          globalScreen.tcp.tcp_no_flag = true;
          break;
        case 'ip_spoofing':
          globalScreen.ip.spoofing = true;
          break;
        case 'ip_source_route':
          globalScreen.ip.source_route = true;
          break;
      }
    }

    if (hasAny) {
      screenConfigs.push(globalScreen);
    }
  }

  if (screenConfigs.length > 0) {
    warnings.push(createWarning('info', 'screen-config',
      `Parsed ${screenConfigs.length} DoS/anomaly protection profile(s)`,
      'Review screen/DDoS settings in the generated config'));
  }

  return screenConfigs;
}


// ---------------------------------------------------------------------------

// Per-section first-seen order of `edit` ids; object keys alone iterate integer ids numerically.
const EDIT_ORDER = Symbol('editOrder');

/** Returns a section's [id, entry] pairs in config order (FortiOS evaluates top-down, not by ID). */
function entriesInConfigOrder(section) {
  return (section[EDIT_ORDER] || Object.keys(section)).map((id) => [id, section[id]]);
}

/**
 * Parses FortiOS config text into a nested tree structure.
 *
 * FortiOS uses:
 *   config <path>        → opens a config section
 *       edit <id>         → opens a named entry
 *           set <k> <v>   → sets a key-value
 *           unset <k>     → clears a key
 *           config <sub>  → nested config block
 *       next              → closes current edit block
 *   end                   → closes current config block
 *
 * Result structure:
 *   { 'firewall policy': { '1': { name: 'Allow-Web', srcintf: ['port1'], ... }, ... } }
 */
function buildConfigTree(configText) {
  const lines = configText.split('\n');
  const root = {};
  const stack = []; // stack of { node, type: 'config'|'edit' }
  let current = root;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;

    if (line.startsWith('config ')) {
      const sectionName = line.slice(7).trim();
      if (!current[sectionName]) {
        current[sectionName] = {};
      }
      stack.push({ node: current, type: 'config' });
      current = current[sectionName];

    } else if (line.startsWith('edit ')) {
      const rawId = line.slice(5).trim();
      const entryId = unquote(rawId);
      if (!current[entryId]) {
        current[entryId] = {};
        (current[EDIT_ORDER] ||= []).push(entryId);
      }
      stack.push({ node: current, type: 'edit' });
      current = current[entryId];

    } else if (line === 'next') {
      // Close edit block — pop back to parent config
      if (stack.length > 0) {
        const frame = stack.pop();
        current = frame.node;
      }

    } else if (line === 'end') {
      // Close config block — pop back to parent
      if (stack.length > 0) {
        const frame = stack.pop();
        current = frame.node;
      }

    } else if (line.startsWith('set ')) {
      const parts = tokenize(line.slice(4));
      if (parts.length >= 2) {
        const key = parts[0];
        const values = parts.slice(1).map(unquote);
        // Single value → string; multiple values → array
        current[key] = values.length === 1 ? values[0] : values;
      } else if (parts.length === 1) {
        current[parts[0]] = 'enable';
      }

    } else if (line.startsWith('unset ')) {
      const key = line.slice(6).trim();
      delete current[key];
    }
  }

  return root;
}


// ---------------------------------------------------------------------------
// Tokenizer (respects quoted strings)
// ---------------------------------------------------------------------------

function tokenize(input) {
  const tokens = [];
  let i = 0;
  while (i < input.length) {
    // Skip whitespace
    while (i < input.length && /\s/.test(input[i])) i++;
    if (i >= input.length) break;

    if (input[i] === '"') {
      // Quoted string
      i++; // skip opening quote
      let token = '';
      while (i < input.length && input[i] !== '"') {
        if (input[i] === '\\' && i + 1 < input.length) {
          token += input[i + 1];
          i += 2;
        } else {
          token += input[i];
          i++;
        }
      }
      i++; // skip closing quote
      tokens.push(token);
    } else {
      // Unquoted token
      let token = '';
      while (i < input.length && !/\s/.test(input[i])) {
        token += input[i];
        i++;
      }
      tokens.push(token);
    }
  }
  return tokens;
}

function unquote(s) {
  if (typeof s !== 'string') return s;
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
    return s.slice(1, -1);
  }
  return s;
}

function ensureArray(val) {
  if (val === undefined || val === null) return [];
  return Array.isArray(val) ? val : [val];
}

function getString(val) {
  if (Array.isArray(val)) return val[0] || '';
  return val || '';
}

/**
 * Returns a FortiOS "address mask" value as CIDR. FortiOS tokenises
 * `set ip 10.0.0.1 255.255.255.0` into an array, which getString would cut
 * to its first token and lose the mask. Single-token values pass through.
 */
function ipMaskToCidr(val) {
  const parts = Array.isArray(val) ? val : String(val || '').trim().split(/\s+/).filter(Boolean);
  if (parts.length === 2) return `${parts[0]}/${maskToCidr(parts[1])}`;
  return parts[0] || '';
}

// ---------------------------------------------------------------------------
// Section Parsers
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// VPN / IPsec Tunnel Parser
// ---------------------------------------------------------------------------

/**
 * Parses FortiGate VPN/IPsec configuration from the config tree.
 * Phase1: tree['vpn ipsec phase1-interface']
 * Phase2: tree['vpn ipsec phase2-interface']
 */
function parseVpnConfig(tree, warnings) {
  const vpnTunnels = [];
  const phase1Section = tree['vpn ipsec phase1-interface'] || {};
  const phase2Section = tree['vpn ipsec phase2-interface'] || {};

  // Parse phase1 (IKE) entries into a lookup map
  const phase1Map = {};
  for (const [name, entry] of Object.entries(phase1Section)) {
    if (typeof entry !== 'object' || !entry) continue;
    const ikeVersion = getString(entry['ike-version']) === '1' ? 'v1' : 'v2';
    const remoteGw = getString(entry['remote-gw']);
    const iface = getString(entry['interface']);
    const proposal = getString(entry['proposal']);

    if (entry['psksecret']) {
      warnings.push(createWarning(
        'info', 'vpn-phase1/' + name,
        'VPN phase1 ' + name + ' pre-shared key sanitized',
        'Pre-shared keys are never included in parsed output'
      ));
    }

    const proposalParts = parseFortiProposal(proposal);

    phase1Map[name] = {
      name, remoteGw, iface, ikeVersion, proposal,
      encryption: proposalParts.encryption,
      authentication: proposalParts.authentication,
      dhGroup: getString(entry['dhgrp']) || '14',
      keylife: parseInt(getString(entry['keylife']), 10) || 28800,
    };
  }

  // Parse phase2 (IPsec) entries and link to phase1
  for (const [name, entry] of Object.entries(phase2Section)) {
    if (typeof entry !== 'object' || !entry) continue;
    const phase1name = getString(entry['phase1name']);
    const p1 = phase1Map[phase1name];
    if (!p1) {
      warnings.push(createWarning(
        'warning', 'vpn-phase2/' + name,
        'VPN phase2 ' + name + ' references unknown phase1 ' + phase1name,
        'Phase1 definition not found in config'
      ));
    }

    const p2proposal = getString(entry['proposal']);
    const p2parts = parseFortiProposal(p2proposal);
    const pfsEnabled = getString(entry['pfs']) === 'enable';
    const dhgrp = getString(entry['dhgrp']);
    const keylifeseconds = parseInt(getString(entry['keylifeseconds']), 10) || 3600;

    const proxyIds = [];
    const srcSubnetRaw = entry['src-subnet'];
    const dstSubnetRaw = entry['dst-subnet'];
    const srcSubnet = Array.isArray(srcSubnetRaw) ? srcSubnetRaw.join(" ") : getString(srcSubnetRaw);
    const dstSubnet = Array.isArray(dstSubnetRaw) ? dstSubnetRaw.join(" ") : getString(dstSubnetRaw);
    if (srcSubnet || dstSubnet) {
      proxyIds.push({
        local: fortiSubnetToCidr(srcSubnet),
        remote: fortiSubnetToCidr(dstSubnet),
        protocol: getString(entry['protocol']) || 'any',
      });
    }

    const dhGroupStr = pfsEnabled && dhgrp ? 'group' + dhgrp : 'group14';

    vpnTunnels.push({
      name,
      ike_gateway: {
        name: phase1name,
        address: p1 ? p1.remoteGw : '',
        local_address: p1 ? p1.iface : '',
        pre_shared_key: 'SANITIZED',
        ike_version: p1 ? p1.ikeVersion : 'v2',
        proposal: p1 ? p1.proposal : '',
      },
      ike_proposal: {
        name: p1 ? p1.proposal : 'default',
        auth_method: 'pre-shared-keys',
        dh_group: p1 ? 'group' + p1.dhGroup : 'group14',
        encryption: p1 ? p1.encryption : 'aes-256-cbc',
        authentication: p1 ? p1.authentication : 'sha256',
        lifetime: p1 ? p1.keylife : 28800,
      },
      ipsec_proposal: {
        name: p2proposal || 'default',
        protocol: 'esp',
        encryption: p2parts.encryption,
        authentication: p2parts.authentication,
        lifetime: keylifeseconds,
        pfs_group: dhGroupStr,
      },
      proxy_id: proxyIds,
      tunnel_interface: phase1name,
      description: '',
    });
  }

  // Phase1 entries without matching phase2 -> stub tunnels
  const usedPhase1 = new Set(vpnTunnels.map(t => t.ike_gateway.name));
  for (const [name, p1] of Object.entries(phase1Map)) {
    if (usedPhase1.has(name)) continue;
    vpnTunnels.push({
      name: name + '-tunnel',
      ike_gateway: {
        name, address: p1.remoteGw, local_address: p1.iface,
        pre_shared_key: 'SANITIZED', ike_version: p1.ikeVersion, proposal: p1.proposal,
      },
      ike_proposal: {
        name: p1.proposal, auth_method: 'pre-shared-keys',
        dh_group: 'group' + p1.dhGroup, encryption: p1.encryption,
        authentication: p1.authentication, lifetime: p1.keylife,
      },
      ipsec_proposal: {
        name: 'default', protocol: 'esp', encryption: 'aes-256-cbc',
        authentication: 'sha256', lifetime: 3600, pfs_group: 'group14',
      },
      proxy_id: [],
      tunnel_interface: name,
      description: 'Phase1 only (no matching phase2 found)',
    });
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

/** Parses FortiGate proposal strings like 'aes256-sha256'. */
function parseFortiProposal(proposal) {
  if (!proposal) return { encryption: 'aes-256-cbc', authentication: 'sha256' };
  const first = proposal.split(/\s+/)[0] || proposal;
  const encMap = {
    'aes128': 'aes-128-cbc', 'aes192': 'aes-192-cbc',
    'aes256': 'aes-256-cbc', '3des': '3des-cbc', 'des': 'des-cbc',
    'aes128gcm': 'aes-128-gcm', 'aes256gcm': 'aes-256-gcm',
  };
  const hashMap = {
    'sha256': 'sha256', 'sha384': 'sha384', 'sha512': 'sha512',
    'sha1': 'sha1', 'md5': 'md5',
  };
  const parts = first.split('-');
  const enc = parts[0] || '';
  const hash = parts.slice(1).join('-') || '';
  return {
    encryption: encMap[enc] || enc || 'aes-256-cbc',
    authentication: hashMap[hash] || hash || 'sha256',
  };
}

/** Converts FortiGate subnet notation (e.g. '10.0.0.0 255.0.0.0') to CIDR. */
function fortiSubnetToCidr(subnetStr) {
  if (!subnetStr) return '';
  const parts = subnetStr.trim().split(/\s+/);
  if (parts.length === 2) {
    const mask = parts[1];
    const bits = mask.split('.').reduce((acc, octet) => {
      return acc + (parseInt(octet, 10) >>> 0).toString(2).replace(/0/g, '').length;
    }, 0);
    return parts[0] + '/' + bits;
  }
  return subnetStr;
}


function extractVersion(tree) {
  const global = tree['system global'] || {};
  // Sometimes version is at top-level as a comment: #config-version=...
  // For tree-based approach, check if there's a version key
  return global['version'] || global['fgt-version'] || '';
}

// --- Zones ---
function parseZones(tree, warnings) {
  const zonesSection = tree['system zone'] || {};
  const zones = [];

  for (const [name, entry] of Object.entries(zonesSection)) {
    if (typeof entry !== 'object') continue;
    zones.push({
      name,
      description: getString(entry['description']) || '',
      interfaces: ensureArray(entry['interface']),
      _intrazone: getString(entry['intrazone-traffic']) || 'deny',
    });
  }
  return zones;
}

// --- Interfaces ---
function parseInterfaces(tree, warnings) {
  const ifaceSection = tree['system interface'] || {};
  const interfaces = [];

  for (const [name, entry] of Object.entries(ifaceSection)) {
    if (typeof entry !== 'object') continue;
    // Extract IPv6 address from FortiGate ipv6 block
    const ipv6Block = entry['ipv6'];
    const ipv6 = (ipv6Block && typeof ipv6Block === 'object')
      ? getString(ipv6Block['ip6-address']) || ''
      : '';
    interfaces.push({
      name,
      alias: getString(entry['alias']) || '',
      ip: ipMaskToCidr(entry['ip']),
      ipv6,
      type: getString(entry['type']) || 'physical',
      vdom: getString(entry['vdom']) || 'root',
      mode: getString(entry['mode']) || 'static',
      dedicated_to: getString(entry['dedicated-to']) || '',
      fortilink: getString(entry['fortilink']) === 'enable',
      status: getString(entry['status']) || 'up',
      zone: '', // will be filled by zone data
    });
  }
  return interfaces;
}

// --- Merge zones and interfaces ---
function mergeZonesAndInterfaces(zones, interfaces, policies, natRules = [], lagMemberNames = new Set(), warnings = []) {
  // Build a map of interface-name → zone
  const ifaceToZone = {};
  for (const zone of zones) {
    for (const iface of zone.interfaces) {
      ifaceToZone[iface] = zone.name;
    }
  }

  // Collect all interfaces referenced in policies
  const usedInterfaces = new Set();
  for (const policy of policies) {
    policy.src_zones.forEach(z => usedInterfaces.add(z));
    policy.dst_zones.forEach(z => usedInterfaces.add(z));
  }

  // For interfaces used in policies that aren't part of a zone, create implicit zones
  const zoneMap = {};
  for (const zone of zones) {
    zoneMap[zone.name] = zone;
  }

  for (const ifaceName of usedInterfaces) {
    if (ifaceName === 'any') continue;
    if (!zoneMap[ifaceName] && !ifaceToZone[ifaceName]) {
      // Interface used directly as zone — create a zone for it
      const iface = interfaces.find(i => i.name === ifaceName);
      zoneMap[ifaceName] = {
        name: ifaceName,
        description: iface?.alias || '',
        interfaces: [ifaceName],
      };
    }
  }

  zoneAllL3InterfacesForAny({ zoneMap, ifaceToZone, interfaces, policies, natRules, lagMemberNames, warnings });

  return Object.values(zoneMap);
}

// "any" as srcintf/dstintf covers every interface, but an unzoned interface
// drops all transit traffic on the SRX, so zone each L3 interface that has none.
function zoneAllL3InterfacesForAny({ zoneMap, ifaceToZone, interfaces, policies, natRules, lagMemberNames, warnings }) {
  const isAny = (rule) => [...rule.src_zones, ...rule.dst_zones].includes('any');
  // A VIP with extintf "any" (or none) has no src zone: it listens on every interface.
  const vipMatchesAny = (rule) => rule.type === 'destination' && rule.src_zones.length === 0;
  if (!policies.some(isAny) && !natRules.some(rule => isAny(rule) || vipMatchesAny(rule))) return;

  const isZoned = (iface) => zoneMap[iface.name] || ifaceToZone[iface.name];
  // DHCP/PPPoE interfaces are L3 without a static address; 0.0.0.0 and ::/0 are FortiOS "unset".
  const isL3 = (iface) => ['dhcp', 'pppoe'].includes(iface.mode)
    || (iface.ip && !iface.ip.startsWith('0.0.0.0'))
    || (iface.ipv6 && !/^::(\/0)?$/.test(iface.ipv6));
  // Management and FortiLink ports carry no policy traffic; a down port carries none at all.
  const isControlLink = (iface) => iface.dedicated_to === 'management' || iface.fortilink;
  const isDown = (iface) => iface.status === 'down';
  const unzoned = interfaces.filter(iface => !isZoned(iface) && isL3(iface) && !isControlLink(iface)
    && !isDown(iface) && iface.type !== 'tunnel' && !lagMemberNames.has(iface.name));
  if (unzoned.length === 0) return;

  // "any" is per-VDOM in FortiOS; with several VDOMs here we can't tell which one it means.
  if (new Set(interfaces.map(iface => iface.vdom)).size > 1) {
    warnings.push(createWarning('warning', 'zones',
      `A policy or NAT rule uses interface "any" but interfaces span multiple VDOMs; left unzoned: ${unzoned.map(i => i.name).join(', ')}`,
      'Assign these interfaces to zones manually'));
    return;
  }

  for (const iface of unzoned) {
    zoneMap[iface.name] = { name: iface.name, description: iface.alias || '', interfaces: [iface.name] };
  }
}


// --- Address Objects ---
function parseAddressObjects(tree, warnings) {
  const addrSection = tree['firewall address'] || {};
  const objects = [];

  for (const [name, entry] of Object.entries(addrSection)) {
    if (typeof entry !== 'object') continue;
    const addrType = getString(entry['type']) || 'ipmask';
    let type = 'subnet';
    let value = '';

    switch (addrType) {
      case 'ipmask': {
        const subnet = ensureArray(entry['subnet']).join(' ');
        if (subnet) {
          // FortiOS uses "10.1.1.0 255.255.255.0" format
          const parts = subnet.split(/\s+/);
          if (parts.length === 2) {
            value = `${parts[0]}/${maskToCidr(parts[1])}`;
          } else {
            value = subnet;
          }
          type = value.endsWith('/32') ? 'host' : 'subnet';
        }
        break;
      }
      case 'iprange':
        type = 'range';
        value = `${getString(entry['start-ip'])}-${getString(entry['end-ip'])}`;
        break;
      case 'fqdn':
        type = 'fqdn';
        value = getString(entry['fqdn']) || '';
        warnings.push(createWarning(
          'info',
          `address:${name}`,
          `FQDN address "${name}" → SRX dns-name requires SRX 12.1+ and DNS resolution at commit time`,
          'Verify SRX version supports dns-name, or replace with static IP'
        ));
        break;
      case 'wildcard':
        type = 'wildcard';
        value = getString(entry['wildcard']) || '';
        break;
      case 'wildcard-fqdn':
        type = 'fqdn';
        value = getString(entry['wildcard-fqdn']) || '';
        warnings.push(createWarning(
          'warning',
          `address:${name}`,
          `Wildcard FQDN "${name}" (${value}) — SRX dns-name does not support wildcards`,
          'Replace with specific FQDN or use custom feed / address set'
        ));
        break;
      case 'geography':
        type = 'geography';
        value = getString(entry['country']) || '';
        warnings.push(createWarning('unsupported', `address:${name}`, `Geography address "${name}" (country: ${value}) — SRX does not support geo-IP address objects natively`, 'Replace with static IP ranges or use SRX Security Intelligence feeds'));
        break;
      case 'dynamic':
        type = 'dynamic';
        value = getString(entry['sdn']) || 'unknown';
        warnings.push(createWarning('unsupported', `address:${name}`, `Dynamic/SDN address "${name}" (${value}) — SRX does not support SDN-based address objects natively`, 'Replace with static addresses or use SRX Security Intelligence feeds'));
        break;
      default:
        warnings.push(createWarning('warning', `address:${name}`, `Unknown address type: ${addrType}`, 'Review manually'));
        value = 'unknown';
    }

    objects.push({
      name,
      type,
      value,
      description: getString(entry['comment']) || getString(entry['comments']) || '',
      tags: ensureArray(entry['tags'] || entry['tag']),
    });
  }

  // Auto-tag ip_version on all address objects
  for (const obj of objects) {
    obj.ip_version = detectIpVersion(obj.value);
  }

  return objects;
}


// --- Address Groups ---
function parseAddressGroups(tree, warnings) {
  const groupSection = tree['firewall addrgrp'] || {};
  const groups = [];

  for (const [name, entry] of Object.entries(groupSection)) {
    if (typeof entry !== 'object') continue;
    groups.push({
      name,
      members: ensureArray(entry['member']),
      description: getString(entry['comment']) || getString(entry['comments']) || '',
      tags: ensureArray(entry['tags'] || entry['tag']),
    });
  }

  return groups;
}


// --- Service Objects ---
// Multi-protocol services are split per protocol; a group under the original
// name (pushed to splitGroups) keeps policy references resolvable.
function parseServiceObjects(tree, warnings, splitGroups = []) {
  const svcSection = tree['firewall service custom'] || {};
  const services = [];
  // Generated split names must not shadow a service or group the config already defines.
  const takenNames = new Set([...Object.keys(svcSection), ...Object.keys(tree['firewall service group'] || {})]);
  const uniqueName = (baseName) => {
    let candidate = baseName;
    for (let suffix = 2; takenNames.has(candidate); suffix += 1) candidate = `${baseName}_${suffix}`;
    takenNames.add(candidate);
    return candidate;
  };

  for (const [name, entry] of Object.entries(svcSection)) {
    if (typeof entry !== 'object') continue;
    const protocol = getString(entry['protocol']) || 'TCP/UDP/SCTP';

    if (protocol === 'ICMP' || protocol === 'ICMP6') {
      services.push({
        name,
        protocol: protocol.toLowerCase(),
        port_range: '',
        source_port: '',
        icmp_type: getString(entry['icmptype']) || '',
        icmp_code: getString(entry['icmpcode']) || '',
        description: getString(entry['comment']) || '',
      });
    } else if (protocol === 'IP') {
      services.push({
        name,
        protocol: 'ip',
        port_range: '',
        source_port: '',
        protocol_number: getString(entry['protocol-number']) || '',
        description: getString(entry['comment']) || '',
      });
    } else {
      // TCP/UDP/SCTP
      // "set tcp-portrange 80 443" lists several ranges; each becomes its own service.
      const rangesByProtocol = {
        tcp: ensureArray(entry['tcp-portrange']),
        udp: ensureArray(entry['udp-portrange']),
        sctp: ensureArray(entry['sctp-portrange']),
      };
      const portParts = Object.entries(rangesByProtocol)
        .flatMap(([proto, ranges]) => ranges.map((range, index) => ({
          proto,
          range,
          baseName: ranges.length > 1 ? `${name}_${proto}_${index + 1}` : `${name}_${proto}`,
        })));
      const isSplit = portParts.length > 1;
      const description = getString(entry['comment']) || '';

      const members = [];
      for (const { proto, range, baseName } of portParts) {
        const serviceName = isSplit ? uniqueName(baseName) : name;
        members.push(serviceName);
        services.push({
          name: serviceName,
          protocol: proto,
          port_range: normalizePortRange(range),
          source_port: '',
          description,
        });
      }
      if (isSplit) {
        splitGroups.push({ name, members, description });
      }
      // If no ports specified, it's a protocol-level match
      if (portParts.length === 0) {
        services.push({
          name,
          protocol: 'tcp',
          port_range: '1-65535',
          source_port: '',
          description: getString(entry['comment']) || '',
        });
      }
    }
  }

  return services;
}


// --- Service Groups ---
function parseServiceGroups(tree, warnings) {
  const groupSection = tree['firewall service group'] || {};
  const groups = [];

  for (const [name, entry] of Object.entries(groupSection)) {
    if (typeof entry !== 'object') continue;
    groups.push({
      name,
      members: ensureArray(entry['member']),
      description: getString(entry['comment']) || '',
    });
  }

  return groups;
}


// --- Security Policies ---
function parseSecurityPolicies(tree, warnings) {
  const policySection = tree['firewall policy'] || {};
  const policies = [];
  let ruleIndex = 1;

  const entries = entriesInConfigOrder(policySection)
    .filter(([, v]) => typeof v === 'object');

  for (const [id, entry] of entries) {
    const action = mapAction(getString(entry['action']));
    const disabled = getString(entry['status']) === 'disable';

    // Security profiles
    const securityProfiles = {};
    const profileType = getString(entry['profile-type']);
    if (profileType === 'group' && entry['profile-group']) {
      // Profile group reference — will be resolved later
    }
    if (entry['av-profile']) securityProfiles.virus = getString(entry['av-profile']);
    if (entry['webfilter-profile']) securityProfiles['url-filtering'] = getString(entry['webfilter-profile']);
    if (entry['ips-sensor']) securityProfiles.vulnerability = getString(entry['ips-sensor']);
    if (entry['application-list']) securityProfiles['application-control'] = getString(entry['application-list']);
    if (entry['dnsfilter-profile']) securityProfiles['dns-security'] = getString(entry['dnsfilter-profile']);
    if (entry['emailfilter-profile']) securityProfiles['email-filter'] = getString(entry['emailfilter-profile']);
    if (entry['dlp-profile']) securityProfiles['dlp'] = getString(entry['dlp-profile']);
    if (entry['ssl-ssh-profile']) securityProfiles.decryption = getString(entry['ssl-ssh-profile']);
    if (entry['waf-profile']) securityProfiles.waf = getString(entry['waf-profile']);
    if (entry['casb-profile']) securityProfiles.casb = getString(entry['casb-profile']);
    if (entry['voip-profile']) securityProfiles.voip = getString(entry['voip-profile']);

    const logTraffic = getString(entry['logtraffic']) || 'utm';

    // Schedule
    const schedule = getString(entry['schedule']) || 'always';

    // NAT in policy
    const natEnabled = getString(entry['nat']) === 'enable';

    const policy = {
      name: getString(entry['name']) || `Policy_${id}`,
      src_zones: ensureArray(entry['srcintf']),
      dst_zones: ensureArray(entry['dstintf']),
      src_addresses: ensureArray(entry['srcaddr']),
      dst_addresses: ensureArray(entry['dstaddr']),
      negate_source: getString(entry['srcaddr-negate']) === 'enable',
      negate_destination: getString(entry['dstaddr-negate']) === 'enable',
      applications: ensureArray(entry['application-list'] ? entry['application-list'] : undefined),
      services: ensureArray(entry['service']),
      action,
      log_start: logTraffic === 'all' || getString(entry['logtraffic-start']) === 'enable',
      log_end: logTraffic === 'all' || logTraffic === 'utm',
      profile_group: profileType === 'group' ? getString(entry['profile-group']) : '',
      security_profiles: securityProfiles,
      description: getString(entry['comments']) || getString(entry['comment']) || '',
      tags: ensureArray(entry['label']),
      disabled,
      schedule: schedule === 'always' ? '' : schedule,
      source_users: [
        ...ensureArray(entry['users']).filter(u => u && u !== 'all'),
        ...ensureArray(entry['groups']).map(g => `group:${g}`),
      ].filter(Boolean),
      _rule_index: ruleIndex++,
      // FortiGate-specific fields for the FortiGate view
      _fortigate: {
        policyid: parseInt(id, 10) || id,
        schedule,
        nat: natEnabled,
        utm_status: getString(entry['utm-status']) === 'enable',
        inspection_mode: getString(entry['inspection-mode']) || 'flow',
        profile_type: profileType || 'single',
        users: ensureArray(entry['users']),
        groups: ensureArray(entry['groups']),
        uuid: getString(entry['uuid']) || '',
      },
    };

    if (policy.source_users.length > 0) {
      warnings.push(createWarning(
        'warning',
        `security-rule/${policy.name}`,
        `Policy "${policy.name}" uses FSSO identity [${policy.source_users.join(', ')}] — SRX requires JIMS for user identification`,
        'Configure SRX user-identification with JIMS and ensure FortiGate FSSO groups map to AD groups'
      ));
    }

    policies.push(policy);
  }

  return policies;
}


// --- NAT Rules (VIP + IP Pool + Central SNAT) ---
function parseNatRules(tree, warnings) {
  const natRules = [];
  const ifaceToZone = {};
  const zoneMemberCount = {};
  for (const zone of parseZones(tree, warnings)) {
    zoneMemberCount[zone.name] = zone.interfaces.length;
    for (const iface of zone.interfaces) ifaceToZone[iface] = zone.name;
  }
  let ruleIndex = 1;
  const zoneOf = (iface) => ifaceToZone[iface] || iface;
  // A zone stands for an interface only when it is the zone's sole member; otherwise
  // the zone-scoped rule-set would also translate traffic on the sibling interfaces.
  const sharedZoneOf = (iface) => (ifaceToZone[iface] && zoneMemberCount[ifaceToZone[iface]] > 1 ? ifaceToZone[iface] : null);

  // IP pools become SRX source pools only where a rule names them; an
  // unknown or absent pool means egress-interface NAT.
  const ippoolSection = tree['firewall ippool'] || {};
  const warnedPools = new Set();
  const poolTranslation = (poolNames) => {
    const pools = poolNames.filter((poolName) => typeof ippoolSection[poolName] === 'object');
    for (const poolName of poolNames) {
      if (pools.includes(poolName) || warnedPools.has(poolName)) continue;
      warnedPools.add(poolName);
      warnings.push(createWarning('warning', `nat/ippool/${poolName}`,
        `IP pool "${poolName}" is not defined — source NAT falls back to the egress interface address`,
        'Define the pool or correct the pool name, then review the SRX source NAT translation'));
    }
    // Only the default overload pool maps to a Junos PAT pool; make other modes loud.
    for (const poolName of pools) {
      const poolType = getString(ippoolSection[poolName]['type']) || 'overload';
      if (poolType === 'overload' || warnedPools.has(poolName)) continue;
      warnedPools.add(poolName);
      warnings.push(createWarning('warning', `nat/ippool/${poolName}`,
        `IP pool "${poolName}" is type ${poolType} but is converted as a default Junos PAT pool`,
        'Recreate the pool behaviour manually (static NAT for one-to-one; port allocation options for fixed-port-range or port-block-allocation)'));
    }
    const ranges = pools
      .map((poolName) => `${getString(ippoolSection[poolName]['startip'])}-${getString(ippoolSection[poolName]['endip'])}`);
    return ranges.length > 0 ? { type: 'dynamic-ip-pool', addresses: ranges } : { type: 'interface' };
  };

  // FortiGate's built-in "all" is any address.
  const natAddresses = (value) => ensureArray(value).map((address) => (address === 'all' ? 'any' : address));

  // Central SNAT map
  const csnatSection = tree['firewall central-snat-map'] || {};
  for (const [id, entry] of entriesInConfigOrder(csnatSection)) {
    if (typeof entry !== 'object') continue;
    const ruleName = getString(entry['comments']) || `Central-SNAT-${id}`;
    const sharedIface = [...ensureArray(entry['srcintf']), ...ensureArray(entry['dstintf'])].find(sharedZoneOf);
    if (sharedIface) {
      warnings.push(createWarning('warning', `nat/${ruleName}`,
        `Central SNAT "${ruleName}" matches interface "${sharedIface}", one of several members of zone "${sharedZoneOf(sharedIface)}" — not converted`,
        `Build it manually as a rule-set scoped "from interface"/"to interface" ${sharedIface}`));
      continue;
    }
    natRules.push({
      name: ruleName,
      type: 'source',
      src_zones: ensureArray(entry['srcintf']).map(zoneOf),
      dst_zones: ensureArray(entry['dstintf']).map(zoneOf),
      src_addresses: natAddresses(entry['orig-addr']),
      dst_addresses: natAddresses(entry['dst-addr']),
      translated_src: poolTranslation(ensureArray(entry['nat-ippool'])),
      translated_dst: null,
      translated_port: getString(entry['nat-port']) || null,
      description: getString(entry['comments']) || '',
      _rule_index: ruleIndex++,
    });
  }

  // Policy-level "set nat enable": outbound source NAT, unless central NAT mode
  // makes FortiOS ignore it. Disabled policies match no traffic, so they must
  // not translate any.
  const centralNat = getString((tree['system settings'] || {})['central-nat']) === 'enable';
  const acceptPolicies = centralNat ? [] : entriesInConfigOrder(tree['firewall policy'] || {})
    .filter(([, entry]) => typeof entry === 'object'
      && getString(entry['status']) !== 'disable'
      && mapAction(getString(entry['action'])) === 'allow')
    .map(([id, entry]) => {
      const nat = getString(entry['nat']) === 'enable';
      const translation = nat
        ? poolTranslation(getString(entry['ippool']) === 'enable' ? ensureArray(entry['poolname']) : [])
        : null;
      return {
        id,
        entry,
        name: getString(entry['name']) || `Policy-${id}`,
        srcZones: ensureArray(entry['srcintf']).map(zoneOf),
        dstZones: ensureArray(entry['dstintf']).map(zoneOf),
        translation,
        translationKey: JSON.stringify(translation),
      };
    });
  // "any" expands to every zone at emission, so it overlaps every zone here.
  const zonesOverlap = (zones, otherZones) => zones.includes('any') || otherZones.includes('any')
    || zones.some((zone) => otherZones.includes(zone));
  const sharesZonePair = (policy, other) => zonesOverlap(policy.srcZones, other.srcZones)
    && zonesOverlap(policy.dstZones, other.dstZones);
  // Conflicts depend only on a policy's zones and translation, so scan once per distinct combination.
  // shortcut: still quadratic if nearly every policy has its own zone set; upgrade to per-zone-pair counts if that shows up.
  const conflictCache = new Map();
  const conflictsOf = (policy) => {
    const cacheKey = JSON.stringify([policy.srcZones, policy.dstZones, policy.translationKey]);
    if (!conflictCache.has(cacheKey)) {
      conflictCache.set(cacheKey, acceptPolicies.filter((other) => other.translationKey !== policy.translationKey
        && sharesZonePair(policy, other)));
    }
    return conflictCache.get(cacheKey);
  };
  for (const policy of acceptPolicies) {
    if (!policy.translation) continue;
    // SRX source NAT cannot match a negated list; the plain list would NAT exactly the excluded traffic.
    if (getString(policy.entry['srcaddr-negate']) === 'enable' || getString(policy.entry['dstaddr-negate']) === 'enable') {
      warnings.push(createWarning('warning', `nat/${policy.name}`,
        `Policy "${policy.name}" enables NAT on a negated address — source NAT not converted`,
        'Build it manually: a "source-nat off" rule for the excluded addresses above the translating rule'));
      continue;
    }
    if (getString(policy.entry['fixedport']) === 'enable') {
      warnings.push(createWarning('warning', `nat/${policy.name}`,
        `Policy "${policy.name}" uses fixed-port NAT, but the SRX source NAT rule translates source ports`,
        'Use a source pool with "port no-translation" if the source port must be preserved'));
    }
    // shortcut: SRX source NAT matches neither policy order nor service, so a zone pair
    // whose policies translate differently is flagged, not converted; upgrade to ordered
    // per-policy rules with "source-nat off" and service matches.
    const conflicting = conflictsOf(policy);
    // Name a few conflicts, not all: a large mixed rulebase would repeat thousands per warning.
    const conflictNames = conflicting.slice(0, 3).map((other) => `"${other.name}"`).join(', ')
      + (conflicting.length > 3 ? ` and ${conflicting.length - 3} more` : '');
    const caveat = conflicting.length > 0
      ? `source NAT for policy "${policy.name}" ignores policy order and service, but ${conflictNames} in the same zone pair translate differently — review rule order and add "source-nat off" rules where needed`
      : null;
    if (caveat) {
      warnings.push(createWarning('warning', `nat/${policy.name}`, caveat,
        'Order the SRX source NAT rules to match FortiGate policy precedence, adding "then source-nat off" for traffic FortiGate leaves untranslated'));
    }
    natRules.push({
      name: policy.name,
      type: 'source',
      src_zones: policy.srcZones,
      dst_zones: policy.dstZones,
      src_addresses: natAddresses(policy.entry['srcaddr']),
      dst_addresses: natAddresses(policy.entry['dstaddr']),
      translated_src: policy.translation,
      translated_dst: null,
      translated_port: null,
      description: `Policy ${policy.id} source NAT`,
      ...(caveat ? { caveat } : {}),
      _rule_index: ruleIndex++,
    });
  }

  // VIP-based DNAT
  const vipSection = tree['firewall vip'] || {};
  for (const [name, entry] of Object.entries(vipSection)) {
    if (typeof entry !== 'object') continue;
    const extIp = getString(entry['extip']) || '';
    // Without an external IP there is nothing to match; 'any' would DNAT the whole zone.
    // extip 0.0.0.0 means "the extintf's own address", which a static match cannot express.
    if (!extIp || extIp === '0.0.0.0') {
      warnings.push(createWarning('warning', `nat/${name}`,
        `VIP "${name}" has no static extip — destination NAT not converted`,
        'Add the external IP to the SRX destination NAT rule manually'));
      continue;
    }
    const mappedIp = getString(entry['mappedip']);
    const mappedIpArr = ensureArray(entry['mappedip']);
    const portForward = getString(entry['portforward']) === 'enable';
    const extPort = getString(entry['extport']) || '';
    const mappedPort = getString(entry['mappedport']) || '';
    const vipProtocol = getString(entry['protocol']) || '';
    // The VIP's external interface is where the traffic arrives: it is the
    // rule-set's from-zone, not a destination zone.
    const extIntf = getString(entry['extintf']);
    // An interface that belongs to an explicit zone is matched by that zone.
    const extZone = extIntf ? (ifaceToZone[extIntf] || extIntf) : '';
    natRules.push({
      name,
      type: 'destination',
      src_zones: extZone && extZone !== 'any' ? [extZone] : [],
      dst_zones: [],
      // Original ingress interface; src_zones is its zone, so the converter can
      // flag a VIP that the zone-scoped SRX rule-set matches more widely.
      ingress_interface: extIntf && extIntf !== 'any' ? extIntf : null,
      src_addresses: ['any'],
      dst_addresses: [extIp],
      translated_src: null,
      translated_dst: mappedIpArr[0] || mappedIp || '',
      translated_port: portForward ? mappedPort : null,
      match_port: portForward ? extPort : null,
      // FortiOS applies protocol only to port forwarding, and defaults it to tcp.
      match_protocol: portForward ? (vipProtocol || 'tcp') : null,
      description: getString(entry['comment']) || getString(entry['comments']) || '',
      _rule_index: ruleIndex++,
    });
  }

  return natRules;
}


/**
 * A FortiGate policy may name a VIP (or VIP group) as its dstaddr. SRX matches
 * policy after destination NAT, so the VIP stands for its mapped address.
 * Adds an address object per referenced VIP, plus an address group per
 * referenced vipgrp. Never overwrites an existing object or group.
 */
function synthesizeVipAddresses(tree, securityPolicies, addressObjects, addressGroups) {
  const vipSection = tree['firewall vip'] || {};
  const vipGroupSection = tree['firewall vipgrp'] || {};
  const knownNames = new Set([...addressObjects, ...addressGroups].map(entry => entry.name));

  // The generated DNAT rule models only a plain static-nat VIP: one static
  // extip, one mapped address, optional tcp/udp port forward. Leave any other
  // VIP unresolved so its policy stays deactivated instead of permitting
  // traffic the conversion does not translate as the FortiGate would.
  const unmodeledVipFields = ['src-filter', 'srcintf-filter', 'service'];
  const mappedAddressOf = (vipName) => {
    const vipEntry = vipSection[vipName];
    if (typeof vipEntry !== 'object') return null;
    if ((getString(vipEntry['type']) || 'static-nat') !== 'static-nat') return null;
    if (unmodeledVipFields.some((field) => vipEntry[field])) return null;
    if (getString(vipEntry['portforward']) === 'enable') {
      const protocol = getString(vipEntry['protocol']) || 'tcp';
      if (protocol !== 'tcp' && protocol !== 'udp') return null;
      // The DNAT rule maps one port to one port; range and m-to-n forwarding are not modeled.
      const extPort = getString(vipEntry['extport']) || '';
      const mappedPort = getString(vipEntry['mappedport']) || extPort;
      if (extPort.includes('-') || mappedPort.includes('-') || getString(vipEntry['portmapping-type']) === 'm-to-n') return null;
      // SRX matches policy after DNAT, so a translated port no longer matches the policy's service.
      if (mappedPort !== extPort) return null;
    }
    const extIp = getString(vipEntry['extip']) || '';
    const mappedIps = ensureArray(vipEntry['mappedip']);
    const mappedIp = mappedIps.length === 1 ? mappedIps[0] : '';
    if (!extIp || extIp === '0.0.0.0' || !mappedIp || extIp.includes('-') || mappedIp.includes('-')) return null;
    return mappedIp.includes('/') ? mappedIp : `${mappedIp}/32`;
  };

  const addVipAddress = (vipName, value) => {
    if (knownNames.has(vipName)) return;
    knownNames.add(vipName);
    addressObjects.push({
      name: vipName,
      type: value.endsWith('/32') ? 'host' : 'subnet',
      value,
      description: `VIP ${vipName} mapped (post-DNAT) address`,
      tags: [],
      ip_version: detectIpVersion(value),
    });
  };

  const referencedNames = new Set(securityPolicies.flatMap(policy => policy.dst_addresses));
  for (const referencedName of referencedNames) {
    if (knownNames.has(referencedName)) continue;
    const groupEntry = vipGroupSection[referencedName];
    if (typeof groupEntry !== 'object') {
      const value = mappedAddressOf(referencedName);
      if (value) addVipAddress(referencedName, value);
      continue;
    }
    const members = ensureArray(groupEntry['member']);
    const memberValues = members.map(mappedAddressOf);
    // One unconvertible member would leave the address-set naming a missing address.
    if (members.length === 0 || memberValues.some(value => !value)) continue;
    members.forEach((member, index) => addVipAddress(member, memberValues[index]));
    knownNames.add(referencedName);
    addressGroups.push({
      name: referencedName,
      members,
      description: getString(groupEntry['comment']) || getString(groupEntry['comments']) || '',
      tags: [],
    });
  }
}


// --- VIP Objects (for FortiGate view) ---
function parseVipObjects(tree, warnings) {
  const vipSection = tree['firewall vip'] || {};
  const vips = [];

  for (const [name, entry] of Object.entries(vipSection)) {
    if (typeof entry !== 'object') continue;
    vips.push({
      name,
      extip: getString(entry['extip']),
      mappedip: ensureArray(entry['mappedip']),
      extintf: getString(entry['extintf']) || 'any',
      portforward: getString(entry['portforward']) === 'enable',
      extport: getString(entry['extport']) || '',
      mappedport: getString(entry['mappedport']) || '',
      type: getString(entry['type']) || 'static-nat',
      comment: getString(entry['comment']) || getString(entry['comments']) || '',
    });
  }

  return vips;
}


// --- Schedules ---
function parseSchedules(tree, warnings) {
  const schedules = {};
  const recurring = tree['firewall schedule recurring'] || {};
  const onetime = tree['firewall schedule onetime'] || {};

  for (const [name, entry] of Object.entries(recurring)) {
    if (typeof entry !== 'object') continue;
    schedules[name] = {
      name,
      type: 'recurring',
      day: ensureArray(entry['day']),
      start: getString(entry['start']) || '00:00',
      end: getString(entry['end']) || '23:59',
    };
  }

  for (const [name, entry] of Object.entries(onetime)) {
    if (typeof entry !== 'object') continue;
    schedules[name] = {
      name,
      type: 'onetime',
      start: getString(entry['start']) || '',
      end: getString(entry['end']) || '',
    };
  }

  return schedules;
}


// --- Profile Groups ---
function detectTransparentMode(tree) {
  const global = tree['system global'] || {};
  const settings = tree['system settings'] || {};
  const opmode = getString(global['opmode']) || getString(settings['opmode']) || 'nat';
  return opmode.toLowerCase() === 'transparent';
}

/**
 * Parse L2 interface information from virtual-switch config and forward-domain assignments
 */
function parseSwitchInterfaces(tree, warnings) {
  const l2Interfaces = [];
  const bridgeDomains = [];
  const vwirePairs = [];

  // Parse system virtual-switch for L2 port groups
  const vsSection = tree['system virtual-switch'] || {};
  for (const [vsName, vsEntry] of Object.entries(vsSection)) {
    if (typeof vsEntry !== 'object') continue;
    const ports = [];
    const portSection = vsEntry.port || {};
    for (const [portName] of Object.entries(portSection)) {
      if (typeof portName === 'string' && portName.startsWith('port')) {
        ports.push(portName);
      }
    }
    if (ports.length > 0) {
      bridgeDomains.push({
        name: vsName,
        vlan_id: null,
        interfaces: ports,
        irb_interface: null,
      });
      for (const port of ports) {
        l2Interfaces.push({
          name: port,
          mode: 'access',
          vlan: null,
          bridge_domain: vsName,
        });
      }
      // 2-port virtual-switch → synthetic vwire pair (SRX bridge-domain auto-mapping)
      if (ports.length === 2) {
        vwirePairs.push({
          name: vsName,
          interface1: ports[0],
          interface2: ports[1],
          tag_allowed: [],
        });
      }
    }
  }

  // Track which ports are already assigned to virtual-switch bridge domains
  const vsPortSet = new Set(l2Interfaces.map(l => l.name));

  // Also check interfaces for forward-domain assignments (transparent mode L2 grouping)
  const ifSection = tree['system interface'] || {};
  const forwardDomainGroups = {};
  for (const [ifName, ifEntry] of Object.entries(ifSection)) {
    if (typeof ifEntry !== 'object') continue;
    const fd = getString(ifEntry['forward-domain']);
    if (fd) {
      if (!forwardDomainGroups[fd]) forwardDomainGroups[fd] = [];
      forwardDomainGroups[fd].push(ifName);
      // Only add if not already in l2Interfaces from virtual-switch
      if (!l2Interfaces.find(l => l.name === ifName)) {
        l2Interfaces.push({
          name: ifName,
          mode: 'access',
          vlan: null,
          bridge_domain: `forward-domain-${fd}`,
        });
      }
    }
  }

  // Create bridge domains for forward-domain groups not already covered by virtual-switch
  for (const [fdId, members] of Object.entries(forwardDomainGroups)) {
    // Skip if all members are already assigned to a virtual-switch bridge domain
    const uncoveredMembers = members.filter(m => !vsPortSet.has(m));
    if (uncoveredMembers.length === 0) continue;
    const bdName = `forward-domain-${fdId}`;
    if (!bridgeDomains.find(bd => bd.name === bdName)) {
      bridgeDomains.push({
        name: bdName,
        vlan_id: null,
        interfaces: uncoveredMembers,
        irb_interface: null,
      });
    }
  }

  return { l2Interfaces, bridgeDomains, vwirePairs };
}

function parseProfileGroups(tree, warnings) {
  const groupSection = tree['firewall profile-group'] || {};
  const groups = {};

  for (const [name, entry] of Object.entries(groupSection)) {
    if (typeof entry !== 'object') continue;
    groups[name] = {
      name,
      'av-profile': getString(entry['av-profile']) || '',
      'webfilter-profile': getString(entry['webfilter-profile']) || '',
      'ips-sensor': getString(entry['ips-sensor']) || '',
      'application-list': getString(entry['application-list']) || '',
      'dnsfilter-profile': getString(entry['dnsfilter-profile']) || '',
      'emailfilter-profile': getString(entry['emailfilter-profile']) || '',
      'dlp-profile': getString(entry['dlp-profile']) || '',
      'ssl-ssh-profile': getString(entry['ssl-ssh-profile']) || '',
    };
  }

  return groups;
}


// --- Extract security profile definitions from FortiGate config ---
function parseSecurityProfileDefinitions(tree, warnings) {
  const defs = {};

  // IPS sensor → severity/action mappings
  const ipsSection = tree['ips sensor'] || {};
  for (const [name, entry] of Object.entries(ipsSection)) {
    if (typeof entry !== 'object') continue;
    const severityActions = {};
    const entries = entry.entries || {};
    for (const [, ipsEntry] of Object.entries(entries)) {
      if (typeof ipsEntry !== 'object') continue;
      const action = getString(ipsEntry.action) || 'default';
      const severities = ensureArray(ipsEntry.severity);
      for (const sev of severities) {
        if (sev) severityActions[sev] = action;
      }
    }
    defs[`vulnerability:${name}`] = { type: 'vulnerability', name, severityActions };
  }

  // Application control list → category/action mappings
  const appSection = tree['application list'] || {};
  for (const [name, entry] of Object.entries(appSection)) {
    if (typeof entry !== 'object') continue;
    const categories = {};
    const entries = entry.entries || {};
    for (const [, appEntry] of Object.entries(entries)) {
      if (typeof appEntry !== 'object') continue;
      const category = getString(appEntry.category) || 'unknown';
      const action = getString(appEntry.action) || 'pass';
      categories[category] = action;
    }
    defs[`application-control:${name}`] = { type: 'application-control', name, categories };
  }

  // Webfilter profile → block/allow categories
  const wfSection = tree['webfilter profile'] || {};
  for (const [name, entry] of Object.entries(wfSection)) {
    if (typeof entry !== 'object') continue;
    const blockCategories = [];
    const allowCategories = [];
    const ftgdFilter = entry['ftgd-wf'] || {};
    const filters = ftgdFilter.filters || {};
    for (const [, filter] of Object.entries(filters)) {
      if (typeof filter !== 'object') continue;
      const action = getString(filter.action) || 'warning';
      const catId = getString(filter.id) || getString(filter.category) || '';
      if (catId) {
        if (action === 'block') blockCategories.push(catId);
        else if (action === 'allow') allowCategories.push(catId);
      }
    }
    defs[`url-filtering:${name}`] = { type: 'url-filtering', name, blockCategories, allowCategories };
  }

  // DNS filter profile → blocked domains
  const dnsSection = tree['dnsfilter profile'] || {};
  for (const [name, entry] of Object.entries(dnsSection)) {
    if (typeof entry !== 'object') continue;
    const blockedDomains = [];
    const domainFilter = entry['domain-filter'] || {};
    const dfEntries = domainFilter.entries || {};
    for (const [, df] of Object.entries(dfEntries)) {
      if (typeof df === 'object' && getString(df.action) === 'block') {
        const domain = getString(df.domain);
        if (domain) blockedDomains.push(domain);
      }
    }
    defs[`dns-security:${name}`] = { type: 'dns-security', name, blockedDomains };
  }

  // Antivirus profile
  const avSection = tree['antivirus profile'] || {};
  for (const [name, entry] of Object.entries(avSection)) {
    if (typeof entry !== 'object') continue;
    const scanMode = getString(entry['scan-mode']) || 'default';
    defs[`virus:${name}`] = { type: 'virus', name, scanMode };
  }

  return defs;
}


// ---------------------------------------------------------------------------
// SSL/SSH Inspection Profile Parser
// ---------------------------------------------------------------------------

/**
 * Parses FortiGate `firewall ssl-ssh-profile` definitions and synthesizes
 * decryption_rules from security policies that reference deep-inspection profiles.
 *
 * FortiGate model: profiles define inspection mode (deep/certificate); policies reference them.
 * PAN-OS model: explicit decryption rulebase with per-rule decrypt/no-decrypt actions.
 * We bridge the gap by creating synthetic decryption_rules entries.
 */
function parseFortiSslProfiles(tree, securityPolicies, warnings) {
  const profileSection = tree['firewall ssl-ssh-profile'] || {};
  const profiles = {};

  for (const [name, entry] of Object.entries(profileSection)) {
    if (typeof entry !== 'object') continue;

    // Determine inspection mode from https section
    const httpsBlock = entry.https || {};
    const httpsMode = getString(httpsBlock['inspection-mode']) || getString(httpsBlock.status) || '';
    const isDeep = httpsMode === 'deep-inspection' || name.toLowerCase().includes('deep-inspection');
    const certMode = getString(httpsBlock['server-cert-mode']) || '';
    const caCert = getString(entry['server-cert']) || getString(entry['caname']) || '';

    profiles[name] = {
      name,
      is_deep_inspection: isDeep,
      cert_mode: certMode,
      ca_cert: caCert,
      ssl_exempt: entry['ssl-exempt'] ? Object.keys(entry['ssl-exempt']) : [],
    };
  }

  // Synthesize decryption_rules from policies referencing ssl-ssh-profiles
  const decryptionRules = [];
  let ruleIndex = 0;

  for (const policy of securityPolicies) {
    const sslProfileName = policy.security_profiles?.decryption;
    if (!sslProfileName) continue;

    const profileDef = profiles[sslProfileName];
    const isDecrypt = profileDef ? profileDef.is_deep_inspection : sslProfileName.toLowerCase().includes('deep');
    const action = isDecrypt ? 'decrypt' : 'no-decrypt';

    ruleIndex++;
    decryptionRules.push({
      name: `${policy.name}-ssl`,
      src_zones: policy.src_zones || [],
      dst_zones: policy.dst_zones || [],
      src_addresses: policy.src_addresses || [],
      dst_addresses: policy.dst_addresses || [],
      src_users: [],
      negate_source: false,
      negate_destination: false,
      services: policy.services || [],
      url_categories: [],
      action,
      decryption_type: isDecrypt ? 'ssl-forward-proxy' : '',
      ssl_certificate: profileDef?.ca_cert || '',
      decryption_profile: sslProfileName,
      log_success: false,
      log_fail: false,
      log_setting: '',
      description: `Synthesized from FortiGate policy "${policy.name}" with ssl-ssh-profile "${sslProfileName}"`,
      tags: [],
      disabled: policy.disabled || false,
      _rule_index: ruleIndex,
      _source_policy: policy.name,
    });

    // Flag the security policy for SSL proxy attachment
    if (isDecrypt && policy.action === 'allow') {
      policy._srx_decrypt = true;
    }
  }

  if (decryptionRules.length > 0) {
    warnings.push({
      severity: 'info',
      id: 'fortigate/ssl-profiles',
      message: `Synthesized ${decryptionRules.length} decryption rules from FortiGate ssl-ssh-profile references`,
      recommendation: 'Review the SSL B&I tab to verify decryption scope matches your intent',
    });
  }

  return decryptionRules;
}


// --- Build security profile objects list ---
function buildProfileObjects(policies, profileGroups) {
  const profileSet = new Map();

  for (const policy of policies) {
    const profiles = policy.security_profiles || {};
    for (const [type, name] of Object.entries(profiles)) {
      if (!name) continue;
      const key = `${type}:${name}`;
      if (!profileSet.has(key)) {
        profileSet.set(key, {
          name,
          profile_type: type,
          profile_type_label: getProfileLabel(type),
          profile_name: name,
          srx_feature: mapProfileToSrxFeature(type),
          srx_type: mapProfileToSrxType(type),
          source: policy.profile_group ? `group:${policy.profile_group}` : 'individual',
          attached_rules: [],
        });
      }
      profileSet.get(key).attached_rules.push(policy.name);
    }
  }

  return Array.from(profileSet.values());
}


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mapAction(fortiAction) {
  switch ((fortiAction || '').toLowerCase()) {
    case 'accept': return 'allow';
    case 'deny': return 'deny';
    case 'ipsec': return 'allow'; // IPsec tunnel action
    case 'learn': return 'allow';
    default: return 'allow';
  }
}

function maskToCidr(mask) {
  if (!mask) return '32';
  // Handle CIDR format already (e.g. "24")
  if (/^\d+$/.test(mask) && parseInt(mask) <= 32) return mask;
  // Convert dotted-decimal mask to CIDR
  const parts = mask.split('.');
  if (parts.length !== 4) return '32';
  let cidr = 0;
  for (const part of parts) {
    const n = parseInt(part, 10);
    cidr += (n >>> 0).toString(2).split('1').length - 1;
  }
  return String(cidr);
}

function normalizePortRange(portStr) {
  // FortiOS port ranges: "80" or "443" or "8080-8090" or "80 443 8080-8090"
  // May include source port: "80:1024-65535" (dst:src)
  if (!portStr) return '';
  return portStr.split(/\s+/).map(p => {
    // Strip source port portion (after colon)
    const colonIdx = p.indexOf(':');
    return colonIdx >= 0 ? p.slice(0, colonIdx) : p;
  }).join(',');
}

function getProfileLabel(profileType) {
  const labels = {
    virus: 'Antivirus',
    'url-filtering': 'Web Filter',
    vulnerability: 'IPS',
    'application-control': 'App Control',
    'dns-security': 'DNS Filter',
    'email-filter': 'Email Filter',
    'dlp': 'DLP',
    decryption: 'SSL Inspection',
    waf: 'WAF',
    casb: 'CASB',
    voip: 'VoIP',
  };
  return labels[profileType] || profileType;
}

function mapProfileToSrxFeature(profileType) {
  const map = {
    virus: 'utm',
    'url-filtering': 'utm',
    vulnerability: 'idp',
    'application-control': 'appfw',
    'dns-security': 'utm',
    'email-filter': 'utm',
    'dlp': 'none',
    decryption: 'ssl-proxy',
    waf: 'utm',
  };
  return map[profileType] || 'utm';
}

function mapProfileToSrxType(profileType) {
  const map = {
    virus: 'utm-policy',
    'url-filtering': 'utm-policy',
    vulnerability: 'idp-policy',
    'application-control': 'application-firewall',
    'dns-security': 'utm-policy',
    'email-filter': 'anti-spam',
    'dlp': 'dlp',
    decryption: 'ssl-proxy',
  };
  return map[profileType] || 'utm-policy';
}


// ---------------------------------------------------------------------------
// Syslog Configuration Parser
// ---------------------------------------------------------------------------

function parseFortiSyslogConfig(tree, warnings) {
  const servers = [];
  // FortiGate: config log syslogd setting / config log syslogd2 setting, etc.
  for (const key of Object.keys(tree)) {
    if (!key.startsWith('log syslogd')) continue;
    const section = tree[key];
    if (!section) continue;

    const server = section.server || '';
    if (!server) continue;

    servers.push({
      name: key.replace('log ', '').replace(' setting', ''),
      server,
      port: parseInt(section.port || '514', 10),
      transport: section.mode === 'reliable' ? 'tcp' : 'udp',
      facility: section.facility || 'local7',
      profile: key,
      source_ip: section['source-ip'] || '',
    });
  }

  if (servers.length > 0) {
    warnings.push(createWarning('info', 'syslog', `Parsed ${servers.length} syslog server(s)`, 'Syslog server configuration detected'));
  }
  return servers;
}


// ---------------------------------------------------------------------------
// DHCP Configuration Parser
// ---------------------------------------------------------------------------

function parseFortiDhcpConfig(tree, warnings) {
  const dhcpConfigs = [];
  // FortiGate: config system dhcp server
  const dhcpServer = tree['system dhcp server'];
  if (dhcpServer) {
    for (const [id, entry] of Object.entries(dhcpServer)) {
      if (!entry || typeof entry !== 'object') continue;
      const iface = entry.interface || '';
      const pools = [];
      // ip-range sub-entries
      const ipRange = entry['ip-range'];
      if (ipRange && typeof ipRange === 'object') {
        for (const [, range] of Object.entries(ipRange)) {
          if (range && range['start-ip'] && range['end-ip']) {
            pools.push(`${range['start-ip']}-${range['end-ip']}`);
          }
        }
      }

      const dns1 = entry['dns-server1'] || '';
      const dns2 = entry['dns-server2'] || '';
      const gateway = entry['default-gateway'] || '';
      const netmask = entry.netmask || '';

      dhcpConfigs.push({
        type: 'server',
        interface: iface,
        pools,
        gateway,
        netmask,
        dns_servers: [dns1, dns2].filter(Boolean),
        lease_time: parseInt(entry['lease-time'] || '86400', 10),
        domain: entry.domain || '',
      });
    }
  }

  // FortiGate: config system dhcp6 server (IPv6 — just detect)
  // FortiGate doesn't have explicit DHCP relay in config (it uses helper addresses on interfaces)

  if (dhcpConfigs.length > 0) {
    warnings.push(createWarning('info', 'dhcp', `Parsed ${dhcpConfigs.length} DHCP server config(s)`, 'DHCP server configuration detected'));
  }
  return dhcpConfigs;
}


// ---------------------------------------------------------------------------
// QoS / Traffic Shaping Configuration Parser
// ---------------------------------------------------------------------------

function parseFortiQosConfig(tree, warnings) {
  const qosProfiles = [];
  // FortiGate: config firewall shaping-profile
  const shapingProfile = tree['firewall shaping-profile'];
  if (shapingProfile) {
    for (const [name, entry] of Object.entries(shapingProfile)) {
      if (!entry || typeof entry !== 'object') continue;
      const classes = [];
      const shapingEntries = entry['shaping-entries'];
      if (shapingEntries && typeof shapingEntries === 'object') {
        for (const [, se] of Object.entries(shapingEntries)) {
          if (se && typeof se === 'object') {
            classes.push({
              name: se['class-id'] || '',
              priority: se.priority || 'medium',
              guaranteed_bandwidth: parseInt(se['guaranteed-bandwidth-percentage'] || '0', 10),
              maximum_bandwidth: parseInt(se['maximum-bandwidth-percentage'] || '0', 10),
            });
          }
        }
      }
      qosProfiles.push({
        name,
        type: 'shaping-profile',
        classes,
      });
    }
  }

  // FortiGate: config firewall shaping-policy
  const shapingPolicy = tree['firewall shaping-policy'];
  if (shapingPolicy) {
    for (const [id, entry] of Object.entries(shapingPolicy)) {
      if (!entry || typeof entry !== 'object') continue;
      qosProfiles.push({
        name: entry.name || `shaping-policy-${id}`,
        type: 'shaping-policy',
        traffic_shaper: entry['traffic-shaper'] || '',
        traffic_shaper_reverse: entry['traffic-shaper-reverse'] || '',
        per_ip_shaper: entry['per-ip-shaper'] || '',
        srcintf: entry.srcintf || '',
        dstintf: entry.dstintf || '',
      });
    }
  }

  if (qosProfiles.length > 0) {
    warnings.push(createWarning('info', 'qos', `Parsed ${qosProfiles.length} QoS/shaping config(s)`, 'Traffic shaping configuration detected'));
  }
  return qosProfiles;
}


// ---------------------------------------------------------------------------
// NetFlow / sFlow Configuration Parser
// ---------------------------------------------------------------------------

/**
 * Parses FortiGate NetFlow and sFlow configuration.
 *
 * Sources:
 *   config system netflow — global NetFlow collector
 *   config system sflow — global sFlow collector
 *   Per-interface: set netflow-sampler both/tx/rx
 */
function parseFortiNetflow(tree, warnings) {
  const result = { collectors: [], sampling: { input_rate: 1000, run_length: 0, interfaces: [] }, templates: [] };

  // Global NetFlow: config system netflow
  const netflowSection = tree['system netflow'] || {};
  const nfCollector = getString(netflowSection['collector-ip'] || netflowSection.server || '');
  const nfPort = parseInt(getString(netflowSection['collector-port'] || netflowSection.port || '')) || 2055;
  const nfSourceIp = getString(netflowSection['source-ip'] || '');
  const nfActiveTimeout = parseInt(getString(netflowSection['active-flow-timeout'] || '')) || 60;

  if (nfCollector) {
    result.collectors.push({
      address: nfCollector,
      port: nfPort,
      protocol: 'netflow-v9',
      source_address: nfSourceIp,
    });
    result.templates.push({
      name: 'forti-netflow',
      flow_type: 'ipv4',
      active_timeout: nfActiveTimeout,
      refresh_rate: 600,
    });
  }

  // Global sFlow: config system sflow
  const sflowSection = tree['system sflow'] || {};
  const sfCollector = getString(sflowSection['collector-ip'] || sflowSection.server || '');
  const sfPort = parseInt(getString(sflowSection['collector-port'] || sflowSection.port || '')) || 6343;
  const sfSourceIp = getString(sflowSection['source-ip'] || '');

  if (sfCollector) {
    result.collectors.push({
      address: sfCollector,
      port: sfPort,
      protocol: 'sflow',
      source_address: sfSourceIp,
    });
  }

  // Per-interface sampling detection
  const ifSection = tree['system interface'] || {};
  for (const [ifName, ifEntry] of Object.entries(ifSection)) {
    if (typeof ifEntry !== 'object') continue;
    const sampler = getString(ifEntry['netflow-sampler'] || ifEntry['sflow-sampler'] || '');
    if (sampler && sampler !== 'disable') {
      result.sampling.interfaces.push(ifName);
    }
  }

  if (result.collectors.length > 0) {
    warnings.push(createWarning('info', 'netflow',
      `Parsed ${result.collectors.length} flow collector(s)` +
      (result.sampling.interfaces.length > 0 ? ` with ${result.sampling.interfaces.length} sampled interface(s)` : ''),
      'NetFlow/sFlow configuration detected'));
  }

  return result;
}


// ---------------------------------------------------------------------------
// LAG / Aggregate Interface Parser
// ---------------------------------------------------------------------------

/**
 * Parses FortiGate aggregate/redundant interfaces and their members.
 *
 * FortiOS config format:
 *   config system interface
 *       edit "agg1"
 *           set type aggregate
 *           set member "port1" "port2"
 *           set lacp-mode active
 *       next
 *   end
 *
 * @param {Object} tree - Parsed FortiOS config tree
 * @param {Object[]} interfaces - Already-parsed interface list
 * @param {Object[]} warnings - Warnings array
 * @returns {Object[]} Array of lag_interfaces in intermediate schema format
 */
function parseFortigateLagInterfaces(tree, interfaces, warnings) {
  const lagInterfaces = [];
  const ifaceSection = tree['system interface'] || {};

  let aeIndex = 0;

  for (const [name, entry] of Object.entries(ifaceSection)) {
    if (typeof entry !== 'object') continue;

    const ifType = getString(entry['type']) || '';
    if (ifType !== 'aggregate' && ifType !== 'redundant') continue;

    // Parse member interfaces
    const memberRaw = entry['member'];
    let sourceMembers = [];
    if (typeof memberRaw === 'string') {
      sourceMembers = memberRaw.split(/\s+/).map(m => m.replace(/^"|"$/g, '')).filter(Boolean);
    } else if (Array.isArray(memberRaw)) {
      sourceMembers = memberRaw.map(m => String(m).replace(/^"|"$/g, '')).filter(Boolean);
    }

    // Parse LACP mode
    const lacpModeRaw = getString(entry['lacp-mode']) || '';
    let lacpMode = 'static';
    if (lacpModeRaw === 'active') lacpMode = 'active';
    else if (lacpModeRaw === 'passive') lacpMode = 'passive';
    else if (ifType === 'redundant') lacpMode = 'static';

    const description = getString(entry['alias']) || '';
    const srxName = `ae${aeIndex}`;
    aeIndex++;

    lagInterfaces.push({
      name: srxName,
      source_name: name,
      members: sourceMembers.map(m => m), // FortiGate member names are preserved as-is for mapping
      source_members: sourceMembers,
      lacp_mode: lacpMode,
      lacp_priority: null,
      description,
    });
  }

  if (lagInterfaces.length > 0) {
    warnings.push(createWarning('info', 'lag',
      `Parsed ${lagInterfaces.length} aggregate/redundant interface(s) with ${lagInterfaces.reduce((s, l) => s + l.members.length, 0)} member(s)`,
      'LAG interfaces will be converted to SRX ae interfaces'));
  }

  return lagInterfaces;
}


// ---------------------------------------------------------------------------
// SNMP Configuration Parser (FortiGate)
// ---------------------------------------------------------------------------

/**
 * Parses FortiGate SNMP configuration from config tree.
 * FortiGate: config system snmp sysinfo / config system snmp community
 */
function parseFortigateSnmpConfig(tree, warnings) {
  const entries = [];

  // System SNMP info: config system snmp sysinfo
  const sysinfo = tree['system snmp sysinfo'] || {};
  const contact = sysinfo['contact-info'] || '';
  const location = sysinfo.location || '';

  // Communities: config system snmp community
  const communitySection = tree['system snmp community'];
  if (communitySection && communitySection._entries) {
    for (const entry of communitySection._entries) {
      const name = entry.name || '';
      entries.push({
        type: 'community',
        name,
        authorization: entry['query-v2c-status'] === 'disable' ? 'none' : 'read-only',
        clients: [],
        contact,
        location,
      });

      // Trap hosts within community
      if (entry._sub && entry._sub.hosts && entry._sub.hosts._entries) {
        for (const host of entry._sub.hosts._entries) {
          const ip = host.ip || host['ha-direct'] || '';
          if (ip) {
            entries.push({
              type: 'trap-group',
              name: `trap-${name}-${ip}`,
              targets: [ip.split(/\s/)[0]],
              categories: [],
              version: entry['query-v2c-status'] !== 'disable' ? 'v2c' : 'v1',
            });
          }
        }
      }
    }
  }

  // Flat key approach: some FortiGate configs have flat set lines
  for (const key of Object.keys(tree)) {
    if (key === 'system snmp community') {
      const sec = tree[key];
      if (sec && !sec._entries) {
        // Simple community string stored as value
        const communityName = sec.name || sec.community || '';
        if (communityName) {
          entries.push({
            type: 'community',
            name: communityName,
            authorization: 'read-only',
            clients: [],
            contact,
            location,
          });
        }
      }
    }
  }

  if (entries.length > 0) {
    warnings.push(createWarning('info', 'snmp', `Parsed ${entries.length} SNMP configuration item(s)`, 'FortiGate SNMP configuration detected'));
  }
  return entries;
}


// ---------------------------------------------------------------------------
// AAA Configuration Parser (FortiGate)
// ---------------------------------------------------------------------------

/**
 * Parses FortiGate AAA configuration from config tree.
 * FortiGate: config user radius / config user tacacs+ / config user ldap
 */
function parseFortigateAaaConfig(tree, warnings) {
  const entries = [];

  // RADIUS servers: config user radius
  const radiusSection = tree['user radius'];
  if (radiusSection && radiusSection._entries) {
    for (const entry of radiusSection._entries) {
      entries.push({
        type: 'radius',
        name: entry.name || '',
        server: entry.server || '',
        port: parseInt(entry['radius-port'] || '1812', 10),
        secret: entry.secret || '',
        timeout: parseInt(entry.timeout || '5', 10),
        retry: 3,
        source_address: entry['source-ip'] || '',
      });
    }
  }

  // TACACS+ servers: config user tacacs+
  const tacplusSection = tree['user tacacs+'];
  if (tacplusSection && tacplusSection._entries) {
    for (const entry of tacplusSection._entries) {
      entries.push({
        type: 'tacplus',
        name: entry.name || '',
        server: entry.server || '',
        port: parseInt(entry.port || '49', 10),
        secret: entry.key || '',
        timeout: parseInt(entry.timeout || '5', 10),
        single_connection: false,
        source_address: entry['source-ip'] || '',
      });
    }
  }

  // LDAP servers: config user ldap
  const ldapSection = tree['user ldap'];
  if (ldapSection && ldapSection._entries) {
    for (const entry of ldapSection._entries) {
      entries.push({
        type: 'ldap',
        name: entry.name || '',
        server: entry.server || '',
        port: parseInt(entry.port || '389', 10),
        base_dn: entry.dn || '',
        bind_dn: entry.username || '',
        ssl: entry.secure === 'ldaps',
      });
    }
  }

  // Flat key fallback for simpler configs
  for (const key of Object.keys(tree)) {
    if (key === 'user radius' && tree[key] && !tree[key]._entries) {
      const sec = tree[key];
      if (sec.server) {
        entries.push({
          type: 'radius',
          name: sec.name || 'radius-1',
          server: sec.server,
          port: parseInt(sec['radius-port'] || '1812', 10),
          secret: sec.secret || '',
          timeout: parseInt(sec.timeout || '5', 10),
          retry: 3,
          source_address: '',
        });
      }
    }
  }

  if (entries.length > 0) {
    warnings.push(createWarning('info', 'aaa', `Parsed ${entries.length} AAA configuration item(s)`, 'FortiGate AAA configuration detected'));
  }
  return entries;
}
