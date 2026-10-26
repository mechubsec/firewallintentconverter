/**
 * Check Point R80+/R81+ Configuration Parser
 * ============================================
 *
 * Parses Check Point firewall configurations (from mgmt_cli JSON exports /
 * ShowPolicyPackage tool) into the vendor-neutral intermediate JSON schema.
 *
 * Handles:
 *   - objects-dictionary → UID resolution (hosts, networks, ranges, services, groups)
 *   - access-rule rulebase with nested access-section / inline-layer flattening
 *   - NAT rulebase (hide/static NAT)
 *   - Gateway topology → zone derivation
 *   - Gaia clish text (interfaces + static routes) appended after JSON
 *   - group-with-exclusion objects
 *   - Service objects: tcp, udp, icmp, icmp6, other, groups
 *   - DNS-domain (FQDN) objects
 *   - Address ranges
 *
 * Input formats:
 *   1. Single mgmt_cli show-access-rulebase JSON response
 *   2. ShowPolicyPackage combined JSON (multiple sections)
 *   3. JSON + Gaia clish text separated by "--- GAIA CLISH ---"
 */

import { createWarning, safeJsonParse, detectIpVersion, buildStaticNatFields } from './parser-utils.js';

// ---------------------------------------------------------------------------
// Main Parser Entry Point
// ---------------------------------------------------------------------------

/**
 * Parses a Check Point configuration into the intermediate JSON schema.
 *
 * @param {string} configText - Raw Check Point config (JSON, or JSON + Gaia clish text)
 * @returns {{ intermediateConfig: Object, warnings: Object[], parseStats: Object }}
 */
export function parseCheckPointConfig(configText) {
  const warnings = [];

  // 1. Split JSON and optional Gaia clish text
  const { jsonText, gaiaText } = splitJsonAndGaia(configText, warnings);

  // 2. Parse JSON
  let configJson;
  try {
    configJson = safeJsonParse(jsonText);
  } catch (e) {
    throw new Error(`Invalid Check Point configuration: not valid JSON — ${e.message}`);
  }

  // 3. Build UID → object map from objects-dictionary arrays
  const uidMap = buildUidMap(configJson, warnings);

  // 4. Extract version and gateway info
  const version = extractVersion(configJson);
  const gatewayName = extractGatewayName(configJson);

  // 5. Parse objects by type
  const addressObjects = parseAddressObjects(uidMap, warnings);
  const addressGroups = parseAddressGroups(uidMap, warnings);
  const serviceObjects = parseServiceObjects(uidMap, warnings);
  const serviceGroups = parseServiceGroups(uidMap, warnings);

  // 6. Flatten and parse rulebase → security policies
  const { policies: securityPolicies, layerCount } = parseRulebase(configJson, uidMap, warnings);

  // 7. Parse NAT rulebase
  const natRules = parseNatRulebase(configJson, uidMap, warnings);

  // 8. Derive zones from gateway topology
  const zones = deriveZones(configJson, uidMap, warnings);

  // 9. Parse Gaia clish text for interfaces and static routes
  const { interfaces: gaiaInterfaces, staticRoutes: gaiaRoutes } = parseGaiaClish(gaiaText, warnings);

  // 10. Normalize interfaces
  const normalizedInterfaces = gaiaInterfaces.map(iface => ({
    name: iface.name,
    ip: iface.ip,
    zone: iface.zone || '',
    vlan: iface.vlan || '',
    type: iface.vlan ? 'vlan' : 'physical',
    description: iface.description || '',
    status: iface.status || 'up',
    speed: '',
  }));

  // 10a. Parse LAG / bonding group interfaces
  const lagInterfaces = parseCheckpointLagInterfaces(gaiaText, warnings);

  // 11. Build intermediate config
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
    static_routes: gaiaRoutes,
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
    _checkpoint: {
      uidMap: null, // don't include the full map, too large
      layerCount: layerCount,
      gatewayName: gatewayName || '',
    },
    metadata: {
      source_vendor: 'checkpoint',
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
      static_route_count: gaiaRoutes.length,
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
// JSON / Gaia Clish Splitter
// ---------------------------------------------------------------------------

/**
 * Splits input text into a JSON portion and an optional Gaia clish text portion.
 * Supports explicit "--- GAIA CLISH ---" markers, or auto-detects where JSON ends.
 */
function splitJsonAndGaia(configText, warnings) {
  const trimmed = configText.trim();

  // Check for explicit marker
  const markerIndex = trimmed.indexOf('--- GAIA CLISH ---');
  if (markerIndex !== -1) {
    return {
      jsonText: trimmed.substring(0, markerIndex).trim(),
      gaiaText: trimmed.substring(markerIndex + '--- GAIA CLISH ---'.length).trim(),
    };
  }

  // Try parsing as pure JSON first
  try {
    JSON.parse(trimmed);
    return { jsonText: trimmed, gaiaText: '' };
  } catch (_e) {
    // Not pure JSON — find where JSON ends
  }

  // Find end of JSON object/array by tracking brace/bracket depth
  const jsonEnd = findJsonEnd(trimmed);
  if (jsonEnd > 0) {
    const jsonPart = trimmed.substring(0, jsonEnd).trim();
    const rest = trimmed.substring(jsonEnd).trim();

    // Verify the JSON part is valid
    try {
      JSON.parse(jsonPart);
      if (rest) {
        warnings.push(createWarning('info', 'format',
          'Detected Gaia clish text appended after JSON block',
          'Interface and route data extracted from clish commands'));
      }
      return { jsonText: jsonPart, gaiaText: rest };
    } catch (_e2) {
      // Fall through — can't parse
    }
  }

  // Last resort: return as-is and let JSON.parse fail with a useful error
  return { jsonText: trimmed, gaiaText: '' };
}

/**
 * Finds the index just past the end of the first complete JSON object or array.
 * Tracks brace/bracket nesting, respects strings.
 */
function findJsonEnd(text) {
  let depth = 0;
  let inString = false;
  let escape = false;
  let started = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];

    if (escape) {
      escape = false;
      continue;
    }

    if (ch === '\\' && inString) {
      escape = true;
      continue;
    }

    if (ch === '"' && !escape) {
      inString = !inString;
      continue;
    }

    if (inString) continue;

    if (ch === '{' || ch === '[') {
      depth++;
      started = true;
    } else if (ch === '}' || ch === ']') {
      depth--;
      if (depth === 0 && started) {
        return i + 1;
      }
    }
  }

  return -1;
}


// ---------------------------------------------------------------------------
// UID Map Builder
// ---------------------------------------------------------------------------

/**
 * Builds a UID → object lookup map from all objects-dictionary arrays
 * found anywhere in the config JSON.
 */
function buildUidMap(configJson, warnings) {
  const uidMap = new Map();

  // Collect objects-dictionary arrays from various locations
  const dictionaries = [];

  if (Array.isArray(configJson['objects-dictionary'])) {
    dictionaries.push(configJson['objects-dictionary']);
  }

  // ShowPolicyPackage format may have "objects" at top level
  if (Array.isArray(configJson['objects'])) {
    dictionaries.push(configJson['objects']);
  }

  // May be nested in access-layers or other sub-structures
  if (Array.isArray(configJson['access-layers'])) {
    for (const layer of configJson['access-layers']) {
      if (Array.isArray(layer['objects-dictionary'])) {
        dictionaries.push(layer['objects-dictionary']);
      }
    }
  }

  // NAT rulebase may have its own objects-dictionary
  if (configJson['nat-rulebase'] && Array.isArray(configJson['nat-rulebase']['objects-dictionary'])) {
    dictionaries.push(configJson['nat-rulebase']['objects-dictionary']);
  }

  // Rulebase entries may embed objects-dictionary
  if (Array.isArray(configJson['rulebase'])) {
    collectNestedDictionaries(configJson['rulebase'], dictionaries);
  }

  // Populate the map
  let duplicateCount = 0;
  for (const dict of dictionaries) {
    for (const obj of dict) {
      if (!obj || !obj.uid) continue;
      if (uidMap.has(obj.uid)) {
        duplicateCount++;
      }
      uidMap.set(obj.uid, obj);
    }
  }

  if (duplicateCount > 0) {
    warnings.push(createWarning('info', 'uid-map',
      `${duplicateCount} duplicate UID(s) encountered in objects-dictionary — last definition wins`,
      'This is normal when multiple layers share objects'));
  }

  // Register well-known special UIDs by scanning for known names/types
  registerSpecialObjects(uidMap);

  const objectCount = uidMap.size;
  if (objectCount === 0) {
    warnings.push(createWarning('warning', 'objects-dictionary',
      'No objects-dictionary found in the configuration — UID resolution will use raw UIDs',
      'Ensure the export includes objects-dictionary (mgmt_cli --show-all or SmartConsole export)'));
  }

  return uidMap;
}

/**
 * Recursively collects objects-dictionary arrays from nested structures.
 */
function collectNestedDictionaries(arr, dictionaries) {
  if (!Array.isArray(arr)) return;
  for (const item of arr) {
    if (!item) continue;
    if (Array.isArray(item['objects-dictionary'])) {
      dictionaries.push(item['objects-dictionary']);
    }
    if (Array.isArray(item['rulebase'])) {
      collectNestedDictionaries(item['rulebase'], dictionaries);
    }
  }
}

/**
 * Registers well-known Check Point objects (Any, Accept, Drop, etc.) in the UID map
 * so they can be resolved by UID when referenced in rules.
 */
function registerSpecialObjects(uidMap) {
  for (const [uid, obj] of uidMap.entries()) {
    if (!obj || !obj.name) continue;
    const name = obj.name;
    const type = obj.type || '';

    // Tag special objects for easy identification during resolution
    if (name === 'Any' || type === 'CpmiAnyObject') {
      obj._special = 'any';
    } else if (name === 'All_Internet') {
      obj._special = 'any';
    }

    // Action objects
    if (name === 'Accept' || name === 'Inner Layer') {
      obj._action = 'allow';
    } else if (name === 'Drop') {
      obj._action = 'deny';
    } else if (name === 'Reject') {
      obj._action = 'deny';
    }

    // Track type objects
    if (name === 'Log' || name === 'Alert') {
      obj._track = true;
    } else if (name === 'None') {
      obj._track = false;
    }
  }
}


// ---------------------------------------------------------------------------
// UID Resolution Helpers
// ---------------------------------------------------------------------------

/**
 * Resolves a UID (string or { uid: "..." } object) to the corresponding object
 * from the UID map. Returns the object or null.
 */
function resolveUid(uidOrObj, uidMap) {
  if (!uidOrObj) return null;
  const uid = typeof uidOrObj === 'string' ? uidOrObj : (uidOrObj.uid || null);
  if (!uid) return null;
  return uidMap.get(uid) || null;
}

/**
 * True when a NAT cell is the built-in "Original" object (type CpmiOriginal), i.e. not translated.
 */
function isOriginalObject(uidOrObj, uidMap) {
  const obj = resolveUid(uidOrObj, uidMap);
  if (obj) return obj.type === 'CpmiOriginal' || obj.name === 'Original';
  return extractUidString(uidOrObj) === 'Original';
}

/**
 * Returns the source name used when referencing an object. Check Point stores
 * DNS-domain definitions with a leading dot that is not part of the emitted
 * definition name, so references must apply the same semantic transformation.
 */
function formatObjectReferenceName(obj, fallback = '') {
  const name = obj?.name || fallback;
  return obj?.type === 'dns-domain' ? name.replace(/^\./, '') : name;
}

/**
 * Resolves a UID to its object name, or the raw UID if unresolved.
 */
function resolveUidToName(uidOrObj, uidMap, warnings, context) {
  const obj = resolveUid(uidOrObj, uidMap);
  if (obj) {
    if (obj._special === 'any') return 'any';
    return formatObjectReferenceName(obj, extractUidString(uidOrObj));
  }
  const raw = extractUidString(uidOrObj);
  if (raw && raw !== 'any') {
    warnings.push(createWarning('warning', context || 'uid-resolve',
      `Could not resolve UID "${raw}" — using UID as name`,
      'Ensure objects-dictionary includes all referenced objects'));
  }
  return raw || 'any';
}

/**
 * Extracts the UID string from either a plain string or { uid: "..." } object.
 */
function extractUidString(uidOrObj) {
  if (!uidOrObj) return '';
  if (typeof uidOrObj === 'string') return uidOrObj;
  return uidOrObj.uid || '';
}

/**
 * Resolves an array of UIDs (strings or objects) to an array of names.
 * Filters out 'any' duplicates and collapses to ['any'] if all are 'any'.
 */
function resolveUidArray(uidArray, uidMap, warnings, context) {
  if (!uidArray || !Array.isArray(uidArray) || uidArray.length === 0) return ['any'];

  const names = [];
  for (const uidOrObj of uidArray) {
    const name = resolveUidToName(uidOrObj, uidMap, warnings, context);
    if (name) names.push(name);
  }

  if (names.length === 0) return ['any'];

  // If all resolved to 'any', collapse
  const nonAny = names.filter(n => n !== 'any');
  if (nonAny.length === 0) return ['any'];

  return nonAny.length > 0 ? nonAny : ['any'];
}

/**
 * Resolves a UID to an action string ('allow' or 'deny').
 */
function resolveAction(uidOrObj, uidMap) {
  const obj = resolveUid(uidOrObj, uidMap);
  if (obj) {
    if (obj._action) return obj._action;
    const name = (obj.name || '').toLowerCase();
    if (name === 'accept' || name === 'inner layer') return 'allow';
    if (name === 'drop' || name === 'reject') return 'deny';
  }
  // Check if the UID itself is a known action name
  const raw = extractUidString(uidOrObj);
  const rawLower = (raw || '').toLowerCase();
  if (rawLower === 'accept' || rawLower.includes('accept')) return 'allow';
  if (rawLower === 'drop' || rawLower === 'reject' || rawLower.includes('drop')) return 'deny';
  return 'allow';
}

/**
 * Resolves the track/log setting from a rule's track field.
 * Returns true if logging is enabled (Log or Alert), false otherwise.
 */
function resolveTrack(trackField, uidMap) {
  if (!trackField) return false;

  // track may be { type: { uid: "..." } } or { type: "uid-string" }
  // or directly a UID string
  let trackTypeRef = trackField;
  if (trackField.type) {
    trackTypeRef = trackField.type;
  }

  const obj = resolveUid(trackTypeRef, uidMap);
  if (obj) {
    if (obj._track === true) return true;
    if (obj._track === false) return false;
    const name = (obj.name || '').toLowerCase();
    if (name === 'log' || name === 'alert' || name === 'full log' || name === 'extended log') return true;
    if (name === 'none') return false;
  }

  // Check raw string
  const raw = extractUidString(trackTypeRef);
  const rawLower = (raw || '').toLowerCase();
  if (rawLower === 'log' || rawLower === 'alert') return true;
  if (rawLower === 'none') return false;

  return false;
}

/**
 * Resolves service UIDs to service name strings (protocol/port or name).
 */
function resolveServiceArray(uidArray, uidMap, warnings) {
  if (!uidArray || !Array.isArray(uidArray) || uidArray.length === 0) return ['any'];

  const names = [];
  for (const uidOrObj of uidArray) {
    const obj = resolveUid(uidOrObj, uidMap);
    if (obj) {
      if (obj._special === 'any') {
        names.push('any');
        continue;
      }
      const svcName = formatServiceName(obj);
      if (svcName) names.push(svcName);
    } else {
      const raw = extractUidString(uidOrObj);
      if (raw) names.push(raw);
    }
  }

  if (names.length === 0) return ['any'];
  const nonAny = names.filter(n => n !== 'any');
  if (nonAny.length === 0) return ['any'];
  return nonAny;
}

/**
 * Formats a service object into a name or protocol/port string.
 */
function formatServiceName(obj) {
  if (!obj) return 'any';
  const type = obj.type || '';
  const name = obj.name || '';

  // Any service
  if (name === 'Any' || type === 'CpmiAnyObject') return 'any';

  // For service objects, prefer the object name (will be resolved by service objects)
  if (type.startsWith('service-')) return name;
  if (type === 'group' || type === 'service-group') return name;

  return name || 'any';
}


// ---------------------------------------------------------------------------
// Version / Gateway Extraction
// ---------------------------------------------------------------------------

function extractVersion(configJson) {
  // Check various locations for version info
  if (configJson['api-server-version']) return configJson['api-server-version'];
  if (configJson['current-session'] && configJson['current-session']['api-server-version']) {
    return configJson['current-session']['api-server-version'];
  }
  // Check in gateways
  if (Array.isArray(configJson['gateways'])) {
    for (const gw of configJson['gateways']) {
      if (gw['version']) return gw['version'];
      if (gw['os-name']) return gw['os-name'];
    }
  }
  return '';
}

function extractGatewayName(configJson) {
  if (configJson['name']) return configJson['name'];
  if (Array.isArray(configJson['gateways']) && configJson['gateways'].length > 0) {
    return configJson['gateways'][0].name || '';
  }
  if (configJson['gateway'] && configJson['gateway'].name) {
    return configJson['gateway'].name;
  }
  return '';
}


// ---------------------------------------------------------------------------
// Address Object Parser
// ---------------------------------------------------------------------------

function parseAddressObjects(uidMap, warnings) {
  const addressObjects = [];

  for (const [_uid, obj] of uidMap) {
    if (!obj || !obj.type) continue;
    const type = obj.type;
    const name = obj.name || '';

    // Skip special/any objects
    if (obj._special === 'any') continue;
    if (!name || name === 'Any' || name === 'All_Internet') continue;

    if (type === 'host') {
      const ip = obj['ipv4-address'] || obj['ipv6-address'] || '';
      if (!ip) continue;
      addressObjects.push({
        name,
        type: 'host',
        value: ip.includes(':') ? ip : `${ip}/32`,
        description: obj.comments || '',
        tags: obj.tags ? resolveTagNames(obj.tags, uidMap) : [],
      });
    } else if (type === 'network') {
      const subnet = obj['subnet4'] || obj['subnet6'] || '';
      const maskLen = obj['mask-length4'] || obj['mask-length6'] || obj['mask-length'] || '';
      if (!subnet) continue;
      addressObjects.push({
        name,
        type: 'subnet',
        value: `${subnet}/${maskLen}`,
        description: obj.comments || '',
        tags: obj.tags ? resolveTagNames(obj.tags, uidMap) : [],
      });
    } else if (type === 'address-range') {
      const first = obj['ipv4-address-first'] || obj['ipv6-address-first'] || '';
      const last = obj['ipv4-address-last'] || obj['ipv6-address-last'] || '';
      if (!first || !last) continue;
      addressObjects.push({
        name,
        type: 'range',
        value: `${first}-${last}`,
        description: obj.comments || '',
        tags: obj.tags ? resolveTagNames(obj.tags, uidMap) : [],
      });
    } else if (type === 'dns-domain') {
      // DNS domain names in Check Point start with "." (e.g. ".example.com")
      const domain = name.startsWith('.') ? name.substring(1) : name;
      addressObjects.push({
        name: name.replace(/^\./, ''),
        type: 'fqdn',
        value: domain,
        description: obj.comments || '',
        tags: obj.tags ? resolveTagNames(obj.tags, uidMap) : [],
      });
      warnings.push(createWarning('info', `address/${name}`,
        `FQDN/dns-domain "${name}" → SRX dns-name requires SRX 12.1+ and DNS resolution at commit time`,
        'Verify SRX version supports dns-name, or replace with static IP'));
    }
  }

  // Auto-tag ip_version on all address objects
  for (const obj of addressObjects) {
    obj.ip_version = detectIpVersion(obj.value);
  }

  return addressObjects;
}

/**
 * Resolves tag UIDs or objects to tag name strings.
 */
function resolveTagNames(tags, uidMap) {
  if (!tags || !Array.isArray(tags)) return [];
  return tags.map(t => {
    if (typeof t === 'string') {
      const obj = uidMap.get(t);
      return obj ? (obj.name || t) : t;
    }
    if (t && t.name) return t.name;
    if (t && t.uid) {
      const obj = uidMap.get(t.uid);
      return obj ? (obj.name || t.uid) : t.uid;
    }
    return '';
  }).filter(Boolean);
}


// ---------------------------------------------------------------------------
// Address Group Parser
// ---------------------------------------------------------------------------

function parseAddressGroups(uidMap, warnings) {
  const addressGroups = [];

  for (const [_uid, obj] of uidMap) {
    if (!obj || !obj.type) continue;
    const type = obj.type;
    const name = obj.name || '';

    if (type === 'group' && Array.isArray(obj.members)) {
      // Standard group — resolve member UIDs to names
      const members = obj.members.map(m => {
        const memberObj = resolveUid(m, uidMap);
        if (memberObj) {
          if (memberObj._special === 'any') return 'any';
          return formatObjectReferenceName(memberObj, extractUidString(m));
        }
        return extractUidString(m);
      }).filter(Boolean);

      // Only include if it looks like a network/address group (not service group)
      // Heuristic: check first resolved member's type
      const firstMemberUid = obj.members[0];
      const firstMember = resolveUid(firstMemberUid, uidMap);
      if (firstMember && isServiceType(firstMember.type)) continue;

      addressGroups.push({
        name,
        members,
        description: obj.comments || '',
        tags: obj.tags ? resolveTagNames(obj.tags, uidMap) : [],
      });
    } else if (type === 'group-with-exclusion') {
      // Use the "include" group, warn about excluded members
      const includeRef = obj.include || obj['include'];
      const exceptRef = obj.except || obj['except'];

      const includeObj = resolveUid(includeRef, uidMap);
      let members = [];
      if (includeObj && Array.isArray(includeObj.members)) {
        members = includeObj.members.map(m => {
          const memberObj = resolveUid(m, uidMap);
          return memberObj
            ? formatObjectReferenceName(memberObj, extractUidString(m))
            : extractUidString(m);
        }).filter(Boolean);
      } else if (includeObj) {
        members = [formatObjectReferenceName(includeObj, extractUidString(includeRef))];
      }

      const exceptName = exceptRef
        ? (resolveUid(exceptRef, uidMap)?.name || extractUidString(exceptRef))
        : 'unknown';

      addressGroups.push({
        name,
        members,
        description: obj.comments || `Exclusion group (excludes: ${exceptName})`,
        tags: obj.tags ? resolveTagNames(obj.tags, uidMap) : [],
      });

      warnings.push(createWarning('warning', `address-group/${name}`,
        `Group-with-exclusion "${name}" — exclusion of "${exceptName}" cannot be represented in SRX address-book`,
        'Manually remove excluded addresses from the group, or use address-set with negate in policy'));
    }
  }

  return addressGroups;
}

/**
 * Checks whether a Check Point object type is a service type.
 */
function isServiceType(type) {
  if (!type) return false;
  return type.startsWith('service-') || type === 'service-group';
}


// ---------------------------------------------------------------------------
// Service Object Parser
// ---------------------------------------------------------------------------

function parseServiceObjects(uidMap, warnings) {
  const serviceObjects = [];

  for (const [_uid, obj] of uidMap) {
    if (!obj || !obj.type) continue;
    const type = obj.type;
    const name = obj.name || '';

    // Skip special/any
    if (obj._special === 'any') continue;
    if (!name || name === 'Any') continue;

    if (type === 'service-tcp') {
      serviceObjects.push({
        name,
        protocol: 'tcp',
        port_range: normalizePort(obj.port),
        source_port: normalizePort(obj['source-port']) || '',
        description: obj.comments || '',
      });
    } else if (type === 'service-udp') {
      serviceObjects.push({
        name,
        protocol: 'udp',
        port_range: normalizePort(obj.port),
        source_port: normalizePort(obj['source-port']) || '',
        description: obj.comments || '',
      });
    } else if (type === 'service-icmp' || type === 'service-icmp6') {
      const proto = type === 'service-icmp' ? 'icmp' : 'icmp6';
      const icmpType = obj['icmp-type'] !== undefined ? String(obj['icmp-type']) : '';
      const icmpCode = obj['icmp-code'] !== undefined ? String(obj['icmp-code']) : '';
      let portRange = 'any';
      if (icmpType) {
        portRange = icmpCode ? `${icmpType}/${icmpCode}` : icmpType;
      }
      serviceObjects.push({
        name,
        protocol: proto,
        port_range: portRange,
        source_port: '',
        description: obj.comments || '',
      });
    } else if (type === 'service-other') {
      // Map IP protocol number
      const ipProto = obj['ip-protocol'] !== undefined ? String(obj['ip-protocol']) : '';
      const protoName = mapIpProtocolNumber(ipProto);
      serviceObjects.push({
        name,
        protocol: protoName,
        port_range: 'any',
        source_port: '',
        description: obj.comments || '',
      });
    }
  }

  return serviceObjects;
}

/**
 * Normalizes a Check Point port field.
 * Can be a string like "80", "8000-8100", ">1024", or a number.
 * Returns the string as-is (pass-through) or "any" for empty/missing.
 */
function normalizePort(port) {
  if (port === undefined || port === null || port === '') return 'any';
  return String(port);
}

/**
 * Maps an IP protocol number to a name.
 */
function mapIpProtocolNumber(protoNum) {
  const map = {
    '1': 'icmp', '6': 'tcp', '17': 'udp', '47': 'gre',
    '50': 'esp', '51': 'ah', '89': 'ospf', '132': 'sctp',
  };
  return map[String(protoNum)] || `ip-proto-${protoNum}`;
}


// ---------------------------------------------------------------------------
// Service Group Parser
// ---------------------------------------------------------------------------

function parseServiceGroups(uidMap, warnings) {
  const serviceGroups = [];

  for (const [_uid, obj] of uidMap) {
    if (!obj || !obj.type) continue;

    // Check Point uses both "service-group" and "group" types for service groups.
    // For "group" type, we need to verify members are services.
    if (obj.type === 'service-group' ||
        (obj.type === 'group' && Array.isArray(obj.members) && isServiceGroup(obj, uidMap))) {
      const name = obj.name || '';
      if (!name || name === 'Any') continue;

      const members = (obj.members || []).map(m => {
        const memberObj = resolveUid(m, uidMap);
        if (memberObj) {
          return memberObj.name || extractUidString(m);
        }
        return extractUidString(m);
      }).filter(Boolean);

      serviceGroups.push({
        name,
        members,
        description: obj.comments || '',
      });
    }
  }

  return serviceGroups;
}

/**
 * Heuristic check: is this "group" actually a service group?
 * Checks the type of the first resolvable member.
 */
function isServiceGroup(obj, uidMap) {
  if (!Array.isArray(obj.members) || obj.members.length === 0) return false;
  for (const m of obj.members) {
    const member = resolveUid(m, uidMap);
    if (member && member.type) {
      return isServiceType(member.type);
    }
  }
  return false;
}


// ---------------------------------------------------------------------------
// Rulebase Parser
// ---------------------------------------------------------------------------

/**
 * Parses the access rulebase from the config JSON.
 * Handles flattening of access-sections and inline layers.
 *
 * @returns {{ policies: Object[], layerCount: number }}
 */
function parseRulebase(configJson, uidMap, warnings) {
  const policies = [];
  let ruleIndex = 1;
  let layerCount = 0;

  // Collect all rulebases to process
  const rulebases = [];

  // Format 1: top-level "rulebase" array
  if (Array.isArray(configJson['rulebase'])) {
    rulebases.push({ rules: configJson['rulebase'], layerName: 'default' });
    layerCount++;
  }

  // Format 2: nested in "access-layers"
  if (Array.isArray(configJson['access-layers'])) {
    for (const layer of configJson['access-layers']) {
      if (Array.isArray(layer['rulebase'])) {
        const layerName = layer.name || layer.uid || `layer-${layerCount + 1}`;
        rulebases.push({ rules: layer['rulebase'], layerName });
        layerCount++;
      }
    }
  }

  // Format: top-level may be the rulebase response directly
  if (rulebases.length === 0 && configJson['total'] !== undefined && Array.isArray(configJson['rulebase'])) {
    rulebases.push({ rules: configJson['rulebase'], layerName: 'default' });
    layerCount = 1;
  }

  // Process each rulebase
  for (const { rules, layerName } of rulebases) {
    const flatRules = flattenRulebase(rules, uidMap, layerName, '', warnings);
    for (const rule of flatRules) {
      const policy = buildPolicyFromRule(rule, uidMap, ruleIndex, layerName, warnings);
      if (policy) {
        policies.push(policy);
        ruleIndex++;
      }
    }
  }

  if (policies.length === 0 && layerCount === 0) {
    warnings.push(createWarning('warning', 'rulebase',
      'No access rulebase found in configuration',
      'Ensure the export includes the access policy rulebase (show-access-rulebase)'));
  }

  return { policies, layerCount: layerCount || 1 };
}

/**
 * Recursively flattens a rulebase, expanding access-section containers
 * and inline-layer references.
 *
 * @returns {Object[]} - Flat array of access-rule objects
 */
function flattenRulebase(rules, uidMap, layerName, sectionName, warnings) {
  const flat = [];

  for (const item of rules) {
    if (!item) continue;
    const type = item.type || '';

    if (type === 'access-section') {
      // Section container — recurse into nested rulebase
      const nestedName = item.name || sectionName;
      if (Array.isArray(item.rulebase)) {
        const nested = flattenRulebase(item.rulebase, uidMap, layerName, nestedName, warnings);
        flat.push(...nested);
      }
    } else if (type === 'access-rule') {
      // Attach section name for metadata
      item._sectionName = sectionName;
      item._layerName = layerName;
      flat.push(item);

      // Check for inline-layer and recurse if found
      if (item['inline-layer']) {
        const inlineLayerRef = item['inline-layer'];
        const inlineObj = resolveUid(inlineLayerRef, uidMap);
        if (inlineObj && Array.isArray(inlineObj.rulebase)) {
          const inlineFlat = flattenRulebase(inlineObj.rulebase, uidMap, inlineObj.name || layerName, sectionName, warnings);
          flat.push(...inlineFlat);
        }
      }
    } else if (type === 'place-holder') {
      // Skip placeholder rules
    } else {
      // Unknown type — might be a section or rule variant
      if (Array.isArray(item.rulebase)) {
        const nested = flattenRulebase(item.rulebase, uidMap, layerName, item.name || sectionName, warnings);
        flat.push(...nested);
      }
    }
  }

  return flat;
}

/**
 * Builds a security policy from a flattened access-rule.
 */
function buildPolicyFromRule(rule, uidMap, ruleIndex, layerName, warnings) {
  if (!rule) return null;

  const ruleUid = rule.uid || '';
  const ruleName = rule.name || `Rule-${ruleIndex}`;
  const ruleNumber = rule['rule-number'] || rule['position'] || ruleIndex;
  const enabled = rule.enabled !== false; // default to enabled
  const comments = rule.comments || rule.comment || '';
  const sectionName = rule._sectionName || '';

  // Separate identity references (access-role) from address objects in source
  const srcIdentities = [];
  const srcAddrUids = [];
  if (Array.isArray(rule.source)) {
    for (const uidOrObj of rule.source) {
      const obj = resolveUid(uidOrObj, uidMap);
      if (obj && obj.type === 'access-role') {
        const roleName = obj.name || extractUidString(uidOrObj);
        srcIdentities.push(roleName);
      } else {
        srcAddrUids.push(uidOrObj);
      }
    }
  }
  if (srcIdentities.length > 0) {
    warnings.push(createWarning(
      'warning',
      `rule/${ruleName}/source-identity`,
      `Rule "${ruleName}" uses Access Role [${srcIdentities.join(', ')}] — SRX source-identity supports user/group only, network/machine conditions are lost`,
      'Create separate address-based match conditions for the network/machine parts of the Access Role'
    ));
  }

  // Resolve source and destination addresses
  const srcAddrs = srcAddrUids.length > 0 ? resolveUidArray(srcAddrUids, uidMap, warnings, `rule/${ruleName}/source`) : resolveUidArray(rule.source, uidMap, warnings, `rule/${ruleName}/source`);
  const dstAddrs = resolveUidArray(rule.destination, uidMap, warnings, `rule/${ruleName}/destination`);

  // Resolve services
  const serviceNames = resolveServiceArray(rule.service, uidMap, warnings);

  // Resolve action
  const action = resolveAction(rule.action, uidMap);

  // Resolve track/log
  const logEnabled = resolveTrack(rule.track, uidMap);

  // Resolve install-on
  const installOnNames = resolveInstallOn(rule['install-on'], uidMap);

  // Negation flags
  const negateSource = rule['source-negate'] === true;
  const negateDest = rule['destination-negate'] === true;

  // Derive zones (Check Point doesn't have traditional zones — use defaults)
  // Zone derivation is done at the config level, not per-rule
  const srcZones = [];
  const dstZones = [];

  return {
    name: ruleName,
    src_zones: srcZones,
    dst_zones: dstZones,
    src_addresses: srcAddrs,
    dst_addresses: dstAddrs,
    negate_source: negateSource,
    negate_destination: negateDest,
    applications: [],  // Check Point doesn't have app-id in traditional rules
    services: serviceNames,
    action,
    log_start: false,
    log_end: logEnabled,
    profile_group: '',
    security_profiles: {},
    description: comments,
    tags: [],
    disabled: !enabled,
    schedule: '',
    source_users: srcIdentities,
    _rule_index: ruleIndex,
    _checkpoint: {
      uid: ruleUid,
      layer: layerName,
      ruleNumber,
      installOn: installOnNames,
      section: sectionName,
    },
  };
}

/**
 * Resolves install-on UIDs to object names.
 */
function resolveInstallOn(installOn, uidMap) {
  if (!installOn || !Array.isArray(installOn)) return [];
  return installOn.map(uidOrObj => {
    const obj = resolveUid(uidOrObj, uidMap);
    if (obj) {
      if (obj._special === 'any' || obj.name === 'Policy Targets') return 'all';
      return obj.name || extractUidString(uidOrObj);
    }
    return extractUidString(uidOrObj);
  }).filter(Boolean);
}


// ---------------------------------------------------------------------------
// NAT Rulebase Parser
// ---------------------------------------------------------------------------

function parseNatRulebase(configJson, uidMap, warnings) {
  const natRules = [];
  let ruleIndex = 1;

  // Look for NAT rulebase in various locations
  const natRulebases = [];

  if (configJson['nat-rulebase']) {
    const natRb = configJson['nat-rulebase'];
    if (Array.isArray(natRb.rulebase)) {
      natRulebases.push(natRb.rulebase);
    } else if (Array.isArray(natRb)) {
      natRulebases.push(natRb);
    }
  }
  if (Array.isArray(configJson['nat-rules'])) {
    natRulebases.push(configJson['nat-rules']);
  }

  for (const rulebase of natRulebases) {
    const built = [];
    const flatRules = flattenNatRulebase(rulebase);
    for (const rule of flatRules) {
      const natRule = buildNatRule(rule, uidMap, ruleIndex, warnings);
      if (natRule) {
        built.push(natRule);
        ruleIndex++;
      }
    }
    natRules.push(...resolveDirectionalStaticNat(built, warnings, uidMap));
  }

  if (natRules.length > 0) {
    warnings.push(createWarning('info', 'nat',
      `Parsed ${natRules.length} NAT rule(s) from Check Point config`,
      'Review NAT translations for SRX source/destination NAT compatibility'));
  }

  return natRules;
}

/**
 * Flattens NAT rulebase (may have nested sections like access rulebase).
 */
function flattenNatRulebase(rules) {
  if (!Array.isArray(rules)) return [];
  const flat = [];
  for (const item of rules) {
    if (!item) continue;
    if (item.type === 'nat-section' && Array.isArray(item.rulebase)) {
      flat.push(...flattenNatRulebase(item.rulebase));
    } else if (item.type === 'nat-rule') {
      flat.push(item);
    } else if (Array.isArray(item.rulebase)) {
      flat.push(...flattenNatRulebase(item.rulebase));
    } else {
      // Treat as a nat-rule if it has source/destination fields
      if (item['original-source'] || item['original-destination']) {
        flat.push(item);
      }
    }
  }
  return flat;
}

/**
 * Returns the IPv4 [first, last] range of a host or network object, or null when it can't be read
 * as one (groups, ranges, IPv6), so callers treat the object as possibly overlapping anything.
 */
function ipv4RangeOf(obj) {
  const toInt = (address) => {
    const octets = String(address).split('.').map(Number);
    if (octets.length !== 4 || octets.some((octet) => !(octet >= 0 && octet <= 255))) return null;
    return octets.reduce((total, octet) => total * 256 + octet, 0);
  };
  if (obj?.['ipv4-address']) {
    const address = toInt(obj['ipv4-address']);
    return address === null ? null : [address, address];
  }
  const base = obj?.subnet4 ? toInt(obj.subnet4) : null;
  const length = Number(obj?.['mask-length4']);
  if (base === null || !(length >= 0 && length <= 32)) return null;
  const size = 2 ** (32 - length);
  const first = Math.floor(base / size) * size;
  return [first, first + size - 1];
}

/**
 * Converts directional Check Point static rows. An outbound row (translates the source) and an inbound
 * row (translates the destination) over the same objects collapse into one bidirectional Junos static
 * rule; a lone row converts one-way (source pool without port translation, or destination NAT), so a
 * single row never opens a translation direction the source did not have.
 *
 * Check Point is one first-match list; Junos runs static, destination, then source NAT in stages, so
 * a single forward sweep keeps the earlier rules that stay in force and:
 * - keeps a pair one-way when an earlier rule could match its private host (source side) or public
 *   address (destination side), and skips the inbound half when the latter would let a Junos
 *   destination rule steal traffic Check Point gives to the earlier rule;
 * - warns, once per pair, when a later destination-NAT rule could also translate a claimed host.
 * Rows that translate the service/port are skipped: Junos static NAT cannot translate ports.
 *
 * shortcut: rules between the two rows of a pair that are themselves undecided pair rows are not
 * counted as blockers; upgrade if interleaved auto-NAT pairs show up.
 */
function resolveDirectionalStaticNat(rules, warnings, uidMap) {
  const isUnchanged = (value, original) => !value || value === 'any' || value === original;
  const isUnscoped = (meta) => (!meta.origSvc || meta.origSvc === 'any') && isUnchanged(meta.transSvc, meta.origSvc);
  const rangeByName = new Map();
  for (const [uid, obj] of uidMap) {
    if (obj?.name) rangeByName.set(formatObjectReferenceName(obj, uid), ipv4RangeOf(obj));
  }
  const rangesOverlap = (left, right) => left[0] <= right[1] && left[1] >= right[0];
  const singleAddressNames = new Set();
  for (const [uid, obj] of uidMap) {
    if (!obj?.name) continue;
    const isSingleNetwork = Number(obj['mask-length4']) === 32 || Number(obj['mask-length6']) === 128;
    if (obj['ipv4-address'] || obj['ipv6-address'] || (obj.type === 'network' && isSingleNetwork)) {
      singleAddressNames.add(formatObjectReferenceName(obj, uid));
    }
  }

  // Index inbound rows by the (public, private) objects an outbound row must mirror; first in config order wins.
  const inboundByMirror = new Map();
  for (const rule of rules) {
    const meta = rule._static;
    if (meta?.direction !== 'inbound' || !isUnscoped(meta) || meta.origSrc !== 'any') continue;
    const key = `${meta.origDst}|${meta.transDst}`;
    if (!inboundByMirror.has(key)) inboundByMirror.set(key, []);
    inboundByMirror.get(key).push(rule);
  }
  const partnerOf = new Map();
  for (const rule of rules) {
    const meta = rule._static;
    if (meta?.direction !== 'outbound' || !isUnscoped(meta) || meta.origDst !== 'any') continue;
    const inbound = inboundByMirror.get(`${meta.transSrc}|${meta.origSrc}`)?.shift();
    if (!inbound) continue;
    partnerOf.set(rule, inbound);
    partnerOf.set(inbound, rule);
  }
  const positionOf = new Map(rules.map((rule, position) => [rule, position]));

  // Earlier rules still in force, per side, with the position they sit at. Resolvable addresses live in
  // a sorted list of disjoint intervals (merged on insert, keeping the earliest position and rule), so
  // an overlap check is a binary search.
  // shortcut: a merged interval answers with its earliest member's position, so a decision made before
  // a later row can over-block; that only keeps a pair one-way. Upgrade if that bites.
  const newFacet = () => ({ any: null, unknown: null, intervals: [], earliest: null });
  const facets = { destination: newFacet(), source: newFacet() };
  const firstIntervalEnding = (intervals, first) => {
    let low = 0;
    let high = intervals.length;
    while (low < high) {
      const middle = (low + high) >> 1;
      if (intervals[middle].last < first) low = middle + 1;
      else high = middle;
    }
    return low;
  };
  const addToFacet = (facet, name, at, rule) => {
    const entry = { at, rule: rule.name };
    if (name === 'any') {
      facet.any ??= entry;
      return;
    }
    const range = rangeByName.get(name);
    if (!range) {
      facet.unknown ??= entry;
      return;
    }
    const { intervals } = facet;
    if (!facet.earliest || at < facet.earliest.at) facet.earliest = entry;
    const start = firstIntervalEnding(intervals, range[0]);
    let end = start;
    let merged = { first: range[0], last: range[1], ...entry };
    while (end < intervals.length && intervals[end].first <= merged.last) {
      const other = intervals[end];
      merged = {
        first: Math.min(merged.first, other.first),
        last: Math.max(merged.last, other.last),
        ...(other.at < merged.at ? { at: other.at, rule: other.rule } : { at: merged.at, rule: merged.rule }),
      };
      end++;
    }
    intervals.splice(start, end - start, merged);
  };
  // Earliest generic rule with a specific source and destination "any": it wins for that source's traffic
  // to a public address on Check Point, while a collapsed static rule translates it on the SRX.
  let hairpinRule = null;
  const addBlocker = (rule, at) => {
    const sourceName = rule.src_addresses?.[0] ?? 'any';
    const destinationName = rule.dst_addresses?.[0] ?? 'any';
    addToFacet(facets.source, sourceName, at, rule);
    // Inbound traffic comes from arbitrary sources. A rule limited to a known host or network that matches
    // destination "any" only affects hairpin traffic from that source (residual difference: on the SRX the
    // static rule translates that hairpin traffic instead); one that names the destination is a real rule about it.
    if (sourceName === 'any' || !rangeByName.get(sourceName) || destinationName !== 'any') {
      addToFacet(facets.destination, destinationName, at, rule);
    }
  };
  /** Returns the name of an earlier rule (before position `before`) that could match `name`, else null. */
  const findBlocker = (facet, name, before) => {
    if (facet.any && facet.any.at < before) return facet.any.rule;
    if (facet.unknown && facet.unknown.at < before) return facet.unknown.rule;
    const { intervals } = facet;
    if (intervals.length === 0) return null;
    const range = rangeByName.get(name);
    // An address range or group could overlap any interval, so the earliest rule decides.
    if (!range) return facet.earliest.at < before ? facet.earliest.rule : null;
    const index = firstIntervalEnding(intervals, range[0]);
    const hit = intervals[index];
    return hit && hit.first <= range[1] && hit.at < before ? hit.rule : null;
  };

  // Hosts a collapsed pair or one-way outbound row claims; a later destination NAT rule may also hit them.
  let claimed = [];
  const claimHost = (name, privateName) => claimed.push({ name, privateName });
  const warnLaterDestinationNat = (rule) => {
    if (claimed.length === 0) return;
    const sourceName = rule.src_addresses?.[0] ?? 'any';
    const sourceRange = rangeByName.get(sourceName);
    const remaining = [];
    for (const entry of claimed) {
      const hostRange = rangeByName.get(entry.privateName);
      const overlaps = sourceName === 'any' || sourceName === entry.privateName || !sourceRange || !hostRange
        || rangesOverlap(sourceRange, hostRange);
      if (!overlaps) {
        remaining.push(entry);
        continue;
      }
      warnings.push(createWarning('warning', `nat/static/${entry.name}`,
        `Traffic from ${entry.privateName} to ${rule.dst_addresses?.[0] ?? 'any'} is also destination-translated on the SRX by rule "${rule.name}", which Check Point evaluates after "${entry.name}"`,
        'Review the destination NAT rule; on Check Point the earlier rule wins, on the SRX both apply'));
    }
    claimed = remaining;
  };

  const skipped = (rule, element, message, suggestion) => {
    warnings.push(createWarning('warning', `${element}/${rule.name}`, message, suggestion));
  };
  const oneWayOutbound = (rule, meta) => {
    const staticFields = buildStaticNatFields({
      name: rule.name,
      privateAddresses: [meta.origSrc],
      publicAddresses: [meta.transSrc],
      destinationFilter: [meta.origDst],
      insideZones: [],
      outsideZones: [],
      bidirectional: false,
      services: [meta.origSvc],
      warnings,
    });
    if (!staticFields) return null;
    claimHost(rule.name, meta.origSrc);
    return { ...rule, translated_src: null, ...staticFields };
  };
  const inboundDestination = (rule, meta, earlierRule) => {
    if (earlierRule) {
      skipped(rule, 'nat/destination',
        `Destination NAT rule "${rule.name}" skipped — earlier rule "${earlierRule}" could match ${meta.origDst} first on Check Point, but Junos runs destination NAT before source NAT and would translate that traffic here`,
        'Build the destination NAT rule manually after checking rule order');
      return null;
    }
    // The destination NAT plan carries no source match, and a service name is not a port, so it would widen.
    if (meta.origSrc !== 'any' || !isUnscoped(meta)) {
      skipped(rule, 'nat/destination',
        `Destination NAT rule "${rule.name}" skipped — it is limited to a specific source or service, which would be lost in the SRX destination rule`,
        'Build the destination NAT rule manually with match source-address / destination-port');
      return null;
    }
    // A destination pool maps every address to one, so a subnet or range mapping would lose its host offsets.
    if (!singleAddressNames.has(meta.origDst) || !singleAddressNames.has(meta.transDst)) {
      skipped(rule, 'nat/destination',
        `Destination NAT rule "${rule.name}" skipped — it maps ${meta.origDst} to ${meta.transDst}, and only host-to-host mappings convert to an SRX destination pool`,
        'Build the destination NAT rule manually');
      return null;
    }
    const destinationRule = { ...rule, type: 'destination' };
    warnLaterDestinationNat(destinationRule);
    return destinationRule;
  };

  const converted = [];
  const pending = new Map(); // first-seen row of an undecided pair -> its output slot
  for (const rule of rules) {
    const position = positionOf.get(rule);
    const meta = rule._static;
    delete rule._static;
    if (!meta) {
      const ruleSource = rule.src_addresses?.[0] ?? 'any';
      if (!hairpinRule && ruleSource !== 'any' && rangeByName.get(ruleSource) && (rule.dst_addresses?.[0] ?? 'any') === 'any') {
        hairpinRule = { name: rule.name, source: ruleSource, at: position };
      }
      if (rule.translated_dst) warnLaterDestinationNat(rule);
      addBlocker(rule, position);
      converted.push(rule);
      continue;
    }
    if (!isUnchanged(meta.transSvc, meta.origSvc)) {
      skipped(rule, 'nat/static',
        `Static NAT rule "${rule.name}" skipped — it translates the service/port, which Junos static NAT cannot do`,
        'Build a destination NAT rule manually for port translation');
      addBlocker(rule, position);
      continue;
    }

    const partner = partnerOf.get(rule);
    if (partner && !pending.has(partner)) {
      // Decide when the second row is reached; keep the first row's output slot until then.
      pending.set(rule, { slot: converted.length, meta });
      converted.push(null);
      continue;
    }
    if (partner) {
      const first = pending.get(partner);
      pending.delete(partner);
      const outbound = meta.direction === 'outbound' ? rule : partner;
      const inbound = outbound === rule ? partner : rule;
      const outboundMeta = outbound === rule ? meta : first.meta;
      const inboundMeta = outbound === rule ? first.meta : meta;
      const outboundPosition = positionOf.get(outbound);
      const inboundPosition = positionOf.get(inbound);
      const privateBlocker = findBlocker(facets.source, outboundMeta.origSrc, outboundPosition);
      const publicBlocker = findBlocker(facets.destination, outboundMeta.transSrc, inboundPosition);
      if (!privateBlocker && !publicBlocker) {
        const staticFields = buildStaticNatFields({
          name: outbound.name,
          privateAddresses: [outboundMeta.origSrc],
          publicAddresses: [outboundMeta.transSrc],
          destinationFilter: [outboundMeta.origDst],
          insideZones: [],
          outsideZones: [],
          bidirectional: true,
          services: [outboundMeta.origSvc],
          warnings,
        });
        if (staticFields) {
          converted[first.slot] = { ...outbound, translated_src: null, ...staticFields };
          claimHost(outbound.name, outboundMeta.origSrc);
          if (hairpinRule && hairpinRule.at < inboundPosition) {
            warnings.push(createWarning('warning', `nat/static/${outbound.name}`,
              `Earlier NAT rule "${hairpinRule.name}" (source ${hairpinRule.source}, destination any) takes precedence on Check Point for traffic from ${hairpinRule.source} to ${outboundMeta.transSrc}; on the SRX static NAT translates it`,
              'Review the static NAT rule; security policy still controls access'));
          }
        }
        continue;
      }
      // Demoted: each half converts one-way, and both stay in force for later pairs.
      const outboundOutput = oneWayOutbound(outbound, outboundMeta);
      const inboundOutput = inboundDestination(inbound, inboundMeta, publicBlocker);
      addBlocker(outbound, outboundPosition);
      addBlocker(inbound, inboundPosition);
      const firstIsOutbound = outbound === partner;
      converted[first.slot] = firstIsOutbound ? outboundOutput : inboundOutput;
      converted.push(firstIsOutbound ? inboundOutput : outboundOutput);
      continue;
    }

    if (meta.direction === 'inbound') {
      const output = inboundDestination(rule, meta, null);
      addBlocker(rule, position);
      converted.push(output);
      continue;
    }
    const output = oneWayOutbound(rule, meta);
    addBlocker(rule, position);
    converted.push(output);
  }
  return converted.filter(Boolean);
}

/**
 * Builds a NAT rule from a Check Point nat-rule object.
 */
function buildNatRule(rule, uidMap, ruleIndex, warnings) {
  if (!rule) return null;
  // Converting a disabled rule would make it active on the SRX.
  if (rule.enabled === false) {
    const name = rule.name || `NAT-${ruleIndex}`;
    warnings.push(createWarning('warning', `nat/${name}`,
      `NAT rule "${name}" is disabled — not converted`,
      'Add it to the SRX by hand, deactivated, if you want to keep it'));
    return null;
  }

  const origSrc = resolveUidToName(rule['original-source'], uidMap, warnings, 'nat/orig-src');
  const origDst = resolveUidToName(rule['original-destination'], uidMap, warnings, 'nat/orig-dst');
  const origSvc = resolveUidToName(rule['original-service'], uidMap, warnings, 'nat/orig-svc');
  // R80/R81 exports mark an untouched translated cell with the built-in "Original" object.
  const resolveTranslated = (cell, original, context) => (
    isOriginalObject(cell, uidMap) ? original : resolveUidToName(cell, uidMap, warnings, context)
  );
  const transSrc = resolveTranslated(rule['translated-source'], origSrc, 'nat/trans-src');
  const transDst = resolveTranslated(rule['translated-destination'], origDst, 'nat/trans-dst');
  const transSvc = resolveTranslated(rule['translated-service'], origSvc, 'nat/trans-svc');

  // Determine NAT type from method field
  const method = (rule.method || '').toLowerCase();
  let type = 'source';
  if (method === 'static') {
    type = 'static';
  } else if (method === 'hide') {
    type = 'source';
  }
  // If translated-destination differs from original, it's destination NAT
  if (transDst !== origDst && transDst !== 'any' && origDst !== transDst) {
    if (type === 'source' && method !== 'hide') {
      type = 'destination';
    }
  }

  // Build translated_src
  let translated_src = null;
  if (transSrc && transSrc !== 'any' && transSrc !== origSrc) {
    if (method === 'static') {
      translated_src = { type: 'static', address: transSrc, addresses: [transSrc] };
    } else {
      translated_src = { type: 'dynamic-ip-pool', addresses: [transSrc] };
    }
  }

  // A static row translates one direction only; resolveDirectionalStaticNat pairs or converts it.
  const isChanged = (translated, original) => translated && translated !== 'any' && translated !== original;
  const translatesSource = isChanged(transSrc, origSrc);
  const translatesDestination = isChanged(transDst, origDst);
  let staticDirection = null;
  if (method === 'static' && translatesSource !== translatesDestination) {
    staticDirection = translatesSource ? 'outbound' : 'inbound';
  }

  return {
    name: rule.name || `NAT-${ruleIndex}`,
    type,
    ...(staticDirection ? { _static: { direction: staticDirection, origSrc, origDst, transSrc, transDst, origSvc, transSvc } } : {}),
    src_zones: [],
    dst_zones: [],
    src_addresses: [origSrc],
    dst_addresses: [origDst],
    translated_src,
    translated_dst: (transDst && transDst !== 'any' && transDst !== origDst)
      ? transDst : null,
    translated_port: (transSvc && transSvc !== 'any' && transSvc !== origSvc)
      ? transSvc : null,
    description: rule.comments || `NAT rule ${ruleIndex}`,
    _rule_index: ruleIndex,
  };
}


// ---------------------------------------------------------------------------
// Zone Derivation
// ---------------------------------------------------------------------------

/**
 * Derives zones from gateway topology data.
 *
 * Check Point doesn't have traditional firewall zones. We derive them from:
 * 1. Object topology (external/internal markers)
 * 2. Specific zone names set on objects
 * 3. Gateway interface topology
 *
 * Falls back to a default "checkpoint" zone if no topology data is available.
 */
function deriveZones(configJson, uidMap, warnings) {
  const zones = [];
  const zoneMap = {}; // zoneName → { interfaces: [], description }

  // Check for gateway topology data
  const gateways = configJson['gateways'] || [];
  if (Array.isArray(gateways)) {
    for (const gw of gateways) {
      if (!gw) continue;

      // Check interfaces within gateway
      const interfaces = gw.interfaces || gw['topology'] || [];
      if (Array.isArray(interfaces)) {
        for (const iface of interfaces) {
          if (!iface) continue;

          const ifaceName = iface.name || '';
          let zoneName = '';

          // Check for specific zone set on the object
          if (iface['specific-zone']) {
            const zoneObj = resolveUid(iface['specific-zone'], uidMap);
            zoneName = zoneObj ? zoneObj.name : extractUidString(iface['specific-zone']);
          } else if (iface['topology']) {
            const topo = (typeof iface['topology'] === 'string')
              ? iface['topology']
              : (iface['topology'].name || '');

            if (topo.toLowerCase() === 'external') {
              zoneName = 'untrust';
            } else if (topo.toLowerCase() === 'internal') {
              zoneName = 'trust';
            } else {
              zoneName = topo || 'checkpoint';
            }
          }

          if (zoneName) {
            if (!zoneMap[zoneName]) {
              zoneMap[zoneName] = { interfaces: [], description: '' };
            }
            if (ifaceName) {
              zoneMap[zoneName].interfaces.push(ifaceName);
            }
          }
        }
      }
    }
  }

  // Scan UID map for gateway objects and topology data
  for (const [_uid, obj] of uidMap) {
    if (!obj) continue;

    // Simple gateway objects have interfaces with topology info
    if ((obj.type === 'simple-gateway' || obj.type === 'CpmiGatewayPlain' || obj.type === 'checkpoint-host') && obj.interfaces) {
      const gwIfaces = Array.isArray(obj.interfaces) ? obj.interfaces : [];
      for (const iface of gwIfaces) {
        if (!iface) continue;
        const ifaceName = iface.name || '';
        let zoneName = '';

        if (iface['topology']) {
          const topo = iface['topology'];
          // Handle nested leads-to structure: { "leads-to": { "name": "ZoneName" } }
          if (topo['leads-to']) {
            const leadsTo = topo['leads-to'];
            zoneName = typeof leadsTo === 'string' ? leadsTo : (leadsTo.name || '');
          } else {
            zoneName = typeof topo === 'string' ? topo : (topo.name || '');
          }

          // Normalize common zone names
          if (zoneName.toLowerCase().includes('external') || zoneName.toLowerCase().includes('outside')) {
            zoneName = 'untrust';
          } else if (zoneName.toLowerCase().includes('internal') || zoneName.toLowerCase().includes('inside')) {
            zoneName = 'trust';
          } else {
            zoneName = zoneName || 'checkpoint';
          }
        }

        if (zoneName) {
          if (!zoneMap[zoneName]) {
            zoneMap[zoneName] = { interfaces: [], description: '' };
          }
          if (ifaceName && !zoneMap[zoneName].interfaces.includes(ifaceName)) {
            zoneMap[zoneName].interfaces.push(ifaceName);
          }
        }
      }
    }

    // Non-gateway objects with direct topology property
    if (obj['topology'] && obj.name && !obj.interfaces) {
      const topo = typeof obj['topology'] === 'string' ? obj['topology'] : (obj['topology'].name || '');
      let zoneName = '';
      if (topo.toLowerCase() === 'external') zoneName = 'untrust';
      else if (topo.toLowerCase() === 'internal') zoneName = 'trust';

      if (zoneName && !zoneMap[zoneName]) {
        zoneMap[zoneName] = { interfaces: [], description: `Derived from topology: ${topo}` };
      }
    }
  }

  // Convert zoneMap to zones array
  for (const [name, data] of Object.entries(zoneMap)) {
    zones.push({
      name,
      description: data.description || `Check Point topology zone: ${name}`,
      interfaces: data.interfaces,
    });
  }

  // If no zones were derived, create a default zone
  if (zones.length === 0) {
    zones.push({
      name: 'checkpoint',
      description: 'Default zone — Check Point does not use traditional zones',
      interfaces: [],
    });
    warnings.push(createWarning('info', 'zones',
      'No topology or zone data found — created default "checkpoint" zone',
      'Assign zones manually in the Zone Editor based on your network topology'));
  }

  return zones;
}


// ---------------------------------------------------------------------------
// Gaia Clish Text Parser
// ---------------------------------------------------------------------------

/**
 * Parses Gaia clish text for interface and static route definitions.
 *
 * Expected formats:
 *   set interface eth0 ipv4-address 10.0.0.1 mask-length 24
 *   set interface eth0 state on
 *   set interface eth0 comments "LAN interface"
 *   set static-route 0.0.0.0/0 nexthop gateway address 10.0.0.254 on
 *   set static-route 10.1.0.0/16 nexthop gateway address 10.0.0.1 on
 */
function parseGaiaClish(gaiaText, warnings) {
  const interfaces = [];
  const staticRoutes = [];

  if (!gaiaText || !gaiaText.trim()) {
    return { interfaces, staticRoutes };
  }

  const lines = gaiaText.split('\n').map(l => l.trim()).filter(l => l);
  const ifaceMap = {}; // ifaceName → { ip, maskLen, state, comments, vlan }

  for (const line of lines) {
    // Interface commands
    const ifaceMatch = line.match(
      /^set\s+interface\s+(\S+)\s+ipv4-address\s+(\S+)\s+mask-length\s+(\d+)/
    );
    if (ifaceMatch) {
      const [, name, ip, maskLen] = ifaceMatch;
      if (!ifaceMap[name]) ifaceMap[name] = { name, ip: '', ipv6: '', zone: '', vlan: '', description: '', status: 'up' };
      ifaceMap[name].ip = `${ip}/${maskLen}`;
      continue;
    }

    // IPv6 address: set interface <name> ipv6-address <addr> mask-length <len>
    const iface6Match = line.match(
      /^set\s+interface\s+(\S+)\s+ipv6-address\s+(\S+)\s+mask-length\s+(\d+)/
    );
    if (iface6Match) {
      const [, name, ip6, maskLen] = iface6Match;
      if (!ifaceMap[name]) ifaceMap[name] = { name, ip: '', ipv6: '', zone: '', vlan: '', description: '', status: 'up' };
      ifaceMap[name].ipv6 = `${ip6}/${maskLen}`;
      continue;
    }

    const stateMatch = line.match(/^set\s+interface\s+(\S+)\s+state\s+(on|off)/);
    if (stateMatch) {
      const [, name, state] = stateMatch;
      if (!ifaceMap[name]) ifaceMap[name] = { name, ip: '', ipv6: '', zone: '', vlan: '', description: '', status: 'up' };
      ifaceMap[name].status = state === 'on' ? 'up' : 'shutdown';
      continue;
    }

    const commentMatch = line.match(/^set\s+interface\s+(\S+)\s+comments?\s+"?([^"]*)"?/);
    if (commentMatch) {
      const [, name, comment] = commentMatch;
      if (!ifaceMap[name]) ifaceMap[name] = { name, ip: '', ipv6: '', zone: '', vlan: '', description: '', status: 'up' };
      ifaceMap[name].description = comment;
      continue;
    }

    // VLAN interface
    const vlanMatch = line.match(/^set\s+interface\s+(\S+)\.(\d+)\s+/);
    if (vlanMatch) {
      const fullName = `${vlanMatch[1]}.${vlanMatch[2]}`;
      if (!ifaceMap[fullName]) ifaceMap[fullName] = { name: fullName, ip: '', ipv6: '', zone: '', vlan: vlanMatch[2], description: '', status: 'up' };
      // Re-parse for IP if present
      const vlanIpMatch = line.match(
        /^set\s+interface\s+\S+\s+ipv4-address\s+(\S+)\s+mask-length\s+(\d+)/
      );
      if (vlanIpMatch) {
        ifaceMap[fullName].ip = `${vlanIpMatch[1]}/${vlanIpMatch[2]}`;
      }
      continue;
    }

    // Static routes: set static-route <prefix/len> nexthop gateway address <gw> on
    const routeMatch = line.match(
      /^set\s+static-route\s+(\S+)\s+nexthop\s+gateway\s+address\s+(\S+)\s+(on|off)/
    );
    if (routeMatch) {
      const [, destination, gateway, state] = routeMatch;
      if (state === 'on') {
        staticRoutes.push({
          name: `gaia-route-${staticRoutes.length + 1}`,
          destination,
          next_hop: gateway,
          next_hop_type: 'ip-address',
          interface: '',
          metric: 0,
          admin_distance: 0,
          description: '',
          vrf: '',
          routing_context: '',
        });
      }
      continue;
    }

    // Static routes with interface: set static-route <prefix/len> nexthop gateway logical <iface> on
    const routeIfMatch = line.match(
      /^set\s+static-route\s+(\S+)\s+nexthop\s+gateway\s+logical\s+(\S+)\s+(on|off)/
    );
    if (routeIfMatch) {
      const [, destination, iface, state] = routeIfMatch;
      if (state === 'on') {
        staticRoutes.push({
          name: `gaia-route-${staticRoutes.length + 1}`,
          destination,
          next_hop: '',
          next_hop_type: 'interface',
          interface: iface,
          metric: 0,
          admin_distance: 0,
          description: '',
          vrf: '',
          routing_context: '',
        });
      }
      continue;
    }
  }

  // Convert ifaceMap to array (only interfaces with IP addresses)
  for (const [name, iface] of Object.entries(ifaceMap)) {
    if (iface.ip || iface.ipv6) {
      interfaces.push(iface);
    }
  }

  if (interfaces.length > 0 || staticRoutes.length > 0) {
    warnings.push(createWarning('info', 'gaia-clish',
      `Parsed ${interfaces.length} interface(s) and ${staticRoutes.length} static route(s) from Gaia clish text`,
      'Interface and routing data extracted from Gaia clish configuration'));
  }

  return { interfaces, staticRoutes };
}


// ---------------------------------------------------------------------------
// LAG / Bonding Group Interface Parser
// ---------------------------------------------------------------------------

/**
 * Parses Check Point Gaia bonding group (LAG) interfaces.
 *
 * Gaia clish config patterns:
 *   add bonding group 1
 *   set bonding group 1 interface eth1
 *   set bonding group 1 interface eth2
 *   set bonding group 1 mode 8023AD
 *   set bonding group 1 lacp-rate slow
 *
 * @param {string} gaiaText - Gaia clish configuration text
 * @param {Object[]} warnings - Warnings array
 * @returns {Object[]} Array of lag_interfaces in intermediate schema format
 */
function parseCheckpointLagInterfaces(gaiaText, warnings) {
  const lagInterfaces = [];
  if (!gaiaText) return lagInterfaces;

  const bondGroups = {};
  const lines = gaiaText.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();

    // add bonding group {N}
    const addMatch = trimmed.match(/^add\s+bonding\s+group\s+(\d+)/i);
    if (addMatch) {
      const groupNum = addMatch[1];
      if (!bondGroups[groupNum]) {
        bondGroups[groupNum] = { members: [], mode: 'active', description: '' };
      }
      continue;
    }

    // set bonding group {N} interface {member}
    const ifMatch = trimmed.match(/^set\s+bonding\s+group\s+(\d+)\s+interface\s+(\S+)/i);
    if (ifMatch) {
      const groupNum = ifMatch[1];
      const member = ifMatch[2];
      if (!bondGroups[groupNum]) {
        bondGroups[groupNum] = { members: [], mode: 'active', description: '' };
      }
      bondGroups[groupNum].members.push(member);
      continue;
    }

    // set bonding group {N} mode {mode}
    const modeMatch = trimmed.match(/^set\s+bonding\s+group\s+(\d+)\s+mode\s+(\S+)/i);
    if (modeMatch) {
      const groupNum = modeMatch[1];
      const mode = modeMatch[2].toLowerCase();
      if (!bondGroups[groupNum]) {
        bondGroups[groupNum] = { members: [], mode: 'active', description: '' };
      }
      if (mode === '8023ad' || mode === 'lacp') {
        bondGroups[groupNum].mode = 'active';
      } else if (mode === 'round-robin' || mode === 'xor' || mode === 'activebackup') {
        bondGroups[groupNum].mode = 'static';
      }
    }
  }

  let aeIndex = 0;
  for (const [groupNum, group] of Object.entries(bondGroups)) {
    lagInterfaces.push({
      name: `ae${aeIndex}`,
      source_name: `bond${groupNum}`,
      members: group.members,
      source_members: [...group.members],
      lacp_mode: group.mode,
      lacp_priority: null,
      description: group.description,
    });
    aeIndex++;
  }

  if (lagInterfaces.length > 0) {
    warnings.push(createWarning('info', 'lag',
      `Parsed ${lagInterfaces.length} bonding group (LAG) interface(s) with ${lagInterfaces.reduce((s, l) => s + l.members.length, 0)} member(s)`,
      'Bonding group interfaces will be converted to SRX ae interfaces'));
  }

  return lagInterfaces;
}
