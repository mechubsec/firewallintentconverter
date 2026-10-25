/**
 * Huawei USG (VRP / USG6000E series) Configuration Parser
 * ========================================================
 *
 * Parses Huawei USG firewall configurations (VRP CLI from
 * `display current-configuration`) into the vendor-neutral
 * intermediate JSON schema.
 *
 * Handles:
 *   - sysname (hostname)
 *   - firewall zone definitions (priority, interfaces)
 *   - Interface definitions (GigabitEthernet, XGigabitEthernet, Eth-Trunk, Vlanif)
 *   - ip address-set (type object) — host, network, range, FQDN
 *   - ip address-set (type group) — nested group references
 *   - ip service-set (type object) — protocol/port definitions
 *   - ip service-set (type group) — nested group references
 *   - security-policy rules (new-style zone-based policies)
 *   - nat-policy rules (source NAT)
 *   - nat address-group (NAT pools with PAT/no-PAT)
 *   - nat server (destination NAT / static mapping)
 *   - ip route-static (static routes)
 *   - HA detection (hrp enable / hrp standby-device)
 *   - Basic VPN/IPsec detection (ike / ipsec proposals and peers)
 *   - time-range schedules
 *
 * The config is section-delimited by `#` with indented sub-commands.
 */

import { createWarning, mapAppToJunos, sanitizeJunosName, detectIpVersion } from './parser-utils.js';

// ---------------------------------------------------------------------------
// Predefined Huawei Service Mapping
// ---------------------------------------------------------------------------

const HUAWEI_PREDEFINED_SERVICES = {
  'http':     { protocol: 'tcp', port: '80' },
  'https':    { protocol: 'tcp', port: '443' },
  'dns':      { protocol: 'udp', port: '53' },
  'ftp':      { protocol: 'tcp', port: '21' },
  'ssh':      { protocol: 'tcp', port: '22' },
  'telnet':   { protocol: 'tcp', port: '23' },
  'smtp':     { protocol: 'tcp', port: '25' },
  'pop3':     { protocol: 'tcp', port: '110' },
  'imap':     { protocol: 'tcp', port: '143' },
  'snmp':     { protocol: 'udp', port: '161' },
  'ntp':      { protocol: 'udp', port: '123' },
  'ping':     { protocol: 'icmp', port: '' },
  'tracert':  { protocol: 'icmp', port: '' },
  'tftp':     { protocol: 'udp', port: '69' },
  'syslog':   { protocol: 'udp', port: '514' },
  'ldap':     { protocol: 'tcp', port: '389' },
  'radius':   { protocol: 'udp', port: '1812' },
  'dhcp':     { protocol: 'udp', port: '67' },
  'snmptrap': { protocol: 'udp', port: '162' },
  'bgp':      { protocol: 'tcp', port: '179' },
  'ospf':     { protocol: 'ip',  port: '89' },
  'sip':      { protocol: 'udp', port: '5060' },
  'h323':     { protocol: 'tcp', port: '1720' },
  'rdp':      { protocol: 'tcp', port: '3389' },
  'mysql':    { protocol: 'tcp', port: '3306' },
  'mssql':    { protocol: 'tcp', port: '1433' },
};


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Converts a Huawei mask value (dotted notation or CIDR integer) to a CIDR
 * prefix length string.
 */
function huaweiMaskToCidr(mask) {
  if (!mask) return '32';
  // Already a CIDR prefix length (e.g. "24", "32")
  if (/^\d+$/.test(mask) && parseInt(mask, 10) <= 128) return mask;
  // Dotted-decimal mask — count the 1-bits
  const parts = mask.split('.');
  if (parts.length !== 4) return '32';
  let cidr = 0;
  for (const p of parts) {
    cidr += (parseInt(p, 10) >>> 0).toString(2).split('1').length - 1;
  }
  return String(cidr);
}

/**
 * Returns true when a service name matches a Huawei predefined service.
 */
function isHuaweiPredefinedService(name) {
  return name === 'any' || HUAWEI_PREDEFINED_SERVICES.hasOwnProperty(name.toLowerCase());
}


// ---------------------------------------------------------------------------
// Section Splitter
// ---------------------------------------------------------------------------

/**
 * Splits the raw config text on `#` delimiters and returns an array of
 * sections.  Each section is an object { header, lines } where `header` is
 * the first non-empty trimmed line and `lines` is an array of the remaining
 * trimmed lines (preserving order).
 */
function splitSections(configText) {
  const rawSections = configText.split(/^#\s*$/m);
  const sections = [];

  for (const raw of rawSections) {
    const lines = raw.split('\n').map(l => l.trimEnd());
    // Find the first non-empty line — that is the section header
    let header = '';
    const body = [];
    let foundHeader = false;

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (trimmed === 'return') continue; // skip trailing `return`
      if (trimmed.startsWith('undo ')) continue; // skip negation lines

      if (!foundHeader) {
        header = trimmed;
        foundHeader = true;
      } else {
        body.push(trimmed);
      }
    }

    if (header) {
      sections.push({ header, lines: body });
    }
  }

  return sections;
}


// ---------------------------------------------------------------------------
// Zone Parser
// ---------------------------------------------------------------------------

function parseZones(sections, warnings) {
  const zones = [];

  for (const sec of sections) {
    const match = sec.header.match(/^firewall\s+zone\s+(\S+)/i);
    if (!match) continue;

    const zoneName = match[1];
    let priority = 0;
    const interfaces = [];

    // Derive type from name
    let type = 'custom';
    const lower = zoneName.toLowerCase();
    if (lower === 'trust') type = 'trust';
    else if (lower === 'untrust') type = 'untrust';
    else if (lower === 'dmz') type = 'dmz';
    else if (lower === 'local') type = 'local';

    for (const line of sec.lines) {
      const priMatch = line.match(/^set\s+priority\s+(\d+)/i);
      if (priMatch) {
        priority = parseInt(priMatch[1], 10);
        continue;
      }
      const ifMatch = line.match(/^add\s+interface\s+(\S+)/i);
      if (ifMatch) {
        interfaces.push(ifMatch[1]);
        continue;
      }
    }

    zones.push({
      name: zoneName,
      description: `Huawei zone "${zoneName}" (priority ${priority})`,
      interfaces,
      _huawei: { priority, type },
    });
  }

  return zones;
}


// ---------------------------------------------------------------------------
// Interface Parser
// ---------------------------------------------------------------------------

function parseInterfaces(sections, warnings) {
  const interfaces = [];

  for (const sec of sections) {
    const match = sec.header.match(/^interface\s+(\S+)/i);
    if (!match) continue;

    const ifaceName = match[1];
    let ip = '';
    let ipv6 = '';
    let description = '';
    let shutdown = false;
    let vlan = '';

    // Detect Vlanif type
    const vlanMatch = ifaceName.match(/Vlanif(\d+)/i);
    if (vlanMatch) {
      vlan = vlanMatch[1];
    }

    for (const line of sec.lines) {
      const ipMatch = line.match(/^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)/i);
      if (ipMatch) {
        const cidr = huaweiMaskToCidr(ipMatch[2]);
        ip = `${ipMatch[1]}/${cidr}`;
        continue;
      }
      const ipv6Match = line.match(/^ipv6\s+address\s+(\S+)/i);
      if (ipv6Match) {
        ipv6 = ipv6Match[1];
        continue;
      }
      const aliasMatch = line.match(/^alias\s+"([^"]+)"/i);
      if (aliasMatch) {
        description = aliasMatch[1];
        continue;
      }
      const descMatch = line.match(/^description\s+(.+)/i);
      if (descMatch) {
        description = descMatch[1].trim();
        continue;
      }
      if (line.trim().toLowerCase() === 'shutdown') {
        shutdown = true;
        continue;
      }
    }

    interfaces.push({
      name: ifaceName,
      ip,
      ipv6,
      description,
      shutdown,
      vlan,
    });
  }

  return interfaces;
}


// ---------------------------------------------------------------------------
// Address-Set (Object) Parser
// ---------------------------------------------------------------------------

function parseAddressSets(sections, warnings) {
  const addressObjects = [];
  const addressGroups = [];

  for (const sec of sections) {
    // ip address-set <name> type object
    const objMatch = sec.header.match(/^ip\s+address-set\s+(\S+)\s+type\s+object/i);
    if (objMatch) {
      const name = objMatch[1];
      const entries = [];

      for (const line of sec.lines) {
        // address <n> <ip> mask <bits>  — host or network
        const maskMatch = line.match(/^address\s+\d+\s+(\d+\.\d+\.\d+\.\d+)\s+mask\s+(\S+)/i);
        if (maskMatch) {
          const ip = maskMatch[1];
          const cidr = huaweiMaskToCidr(maskMatch[2]);
          if (cidr === '32') {
            entries.push({ type: 'host', value: `${ip}/32` });
          } else {
            entries.push({ type: 'subnet', value: `${ip}/${cidr}` });
          }
          continue;
        }

        // address <n> <ip> <dotted-mask>  — network with dotted mask (no "mask" keyword)
        const dottedMatch = line.match(/^address\s+\d+\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i);
        if (dottedMatch) {
          const ip = dottedMatch[1];
          const cidr = huaweiMaskToCidr(dottedMatch[2]);
          if (cidr === '32') {
            entries.push({ type: 'host', value: `${ip}/32` });
          } else {
            entries.push({ type: 'subnet', value: `${ip}/${cidr}` });
          }
          continue;
        }

        // address <n> range <start> <end>
        const rangeMatch = line.match(/^address\s+\d+\s+range\s+(\S+)\s+(\S+)/i);
        if (rangeMatch) {
          entries.push({ type: 'range', value: `${rangeMatch[1]}-${rangeMatch[2]}` });
          continue;
        }

        // address <n> fqdn <domain>
        const fqdnMatch = line.match(/^address\s+\d+\s+fqdn\s+(\S+)/i);
        if (fqdnMatch) {
          entries.push({ type: 'fqdn', value: fqdnMatch[1] });
          warnings.push(createWarning(
            'info',
            `address/${name}`,
            `FQDN address "${name}" (${fqdnMatch[1]}) — SRX dns-name requires SRX 12.1+ and DNS resolution at commit time`,
            'Verify SRX version supports dns-name, or replace with static IP'
          ));
          continue;
        }
      }

      // If the address-set has a single entry, expose it directly
      if (entries.length === 1) {
        addressObjects.push({
          name,
          type: entries[0].type,
          value: entries[0].value,
          description: '',
          tags: [],
        });
      } else if (entries.length > 1) {
        // Multiple entries in a single address-set: create individual objects
        // plus a group that references them
        const memberNames = [];
        for (let i = 0; i < entries.length; i++) {
          const entryName = `${name}_${i}`;
          memberNames.push(entryName);
          addressObjects.push({
            name: entryName,
            type: entries[i].type,
            value: entries[i].value,
            description: `Auto-expanded from address-set ${name}`,
            tags: [],
          });
        }
        addressGroups.push({
          name,
          members: memberNames,
          description: `Huawei address-set (object) with ${entries.length} entries`,
          tags: [],
        });
      }

      continue;
    }

    // ip address-set <name> type group
    const grpMatch = sec.header.match(/^ip\s+address-set\s+(\S+)\s+type\s+group/i);
    if (grpMatch) {
      const name = grpMatch[1];
      const members = [];

      for (const line of sec.lines) {
        const memMatch = line.match(/^address\s+address-set\s+(\S+)/i);
        if (memMatch) {
          members.push(memMatch[1]);
          continue;
        }
      }

      addressGroups.push({
        name,
        members,
        description: '',
        tags: [],
      });

      continue;
    }
  }

  // Auto-tag ip_version on all address objects
  for (const obj of addressObjects) {
    obj.ip_version = detectIpVersion(obj.value);
  }

  return { addressObjects, addressGroups };
}


// ---------------------------------------------------------------------------
// Service-Set Parser
// ---------------------------------------------------------------------------

function parseServiceSets(sections, warnings) {
  const serviceObjects = [];
  const serviceGroups = [];

  for (const sec of sections) {
    // ip service-set <name> type object
    const objMatch = sec.header.match(/^ip\s+service-set\s+(\S+)\s+type\s+object/i);
    if (objMatch) {
      const name = objMatch[1];
      const entries = [];

      for (const line of sec.lines) {
        // service <n> protocol <proto> destination-port <start> to <end>
        const rangeMatch = line.match(
          /^service\s+\d+\s+protocol\s+(\S+)\s+(?:source-port\s+\S+\s+)?destination-port\s+(\d+)\s+to\s+(\d+)/i
        );
        if (rangeMatch) {
          entries.push({
            protocol: rangeMatch[1].toLowerCase(),
            port: `${rangeMatch[2]}-${rangeMatch[3]}`,
            srcPort: '',
          });
          continue;
        }

        // service <n> protocol <proto> [source-port <sp>] destination-port <port>
        const singleMatch = line.match(
          /^service\s+\d+\s+protocol\s+(\S+)\s+(?:source-port\s+(\S+)\s+)?destination-port\s+(\d+)/i
        );
        if (singleMatch) {
          entries.push({
            protocol: singleMatch[1].toLowerCase(),
            port: singleMatch[3],
            srcPort: singleMatch[2] || '',
          });
          continue;
        }

        // service <n> protocol icmp
        const icmpMatch = line.match(/^service\s+\d+\s+protocol\s+icmp/i);
        if (icmpMatch) {
          entries.push({ protocol: 'icmp', port: '', srcPort: '' });
          continue;
        }

        // service <n> protocol <number> — raw IP protocol number
        const protoNumMatch = line.match(/^service\s+\d+\s+protocol\s+(\d+)/i);
        if (protoNumMatch) {
          entries.push({ protocol: protoNumMatch[1], port: '', srcPort: '' });
          continue;
        }
      }

      if (entries.length === 1) {
        serviceObjects.push({
          name,
          protocol: entries[0].protocol,
          port_range: entries[0].port || 'any',
          source_port: entries[0].srcPort,
          description: '',
        });
      } else if (entries.length > 1) {
        // Multiple protocol/port entries — create individual service objects
        // and a service group referencing them
        const memberNames = [];
        for (let i = 0; i < entries.length; i++) {
          const entryName = `${name}_${i}`;
          memberNames.push(entryName);
          serviceObjects.push({
            name: entryName,
            protocol: entries[i].protocol,
            port_range: entries[i].port || 'any',
            source_port: entries[i].srcPort,
            description: `Auto-expanded from service-set ${name}`,
          });
        }
        serviceGroups.push({
          name,
          members: memberNames,
          description: `Huawei service-set (object) with ${entries.length} entries`,
          _protocol: '',
        });
      }

      continue;
    }

    // ip service-set <name> type group
    const grpMatch = sec.header.match(/^ip\s+service-set\s+(\S+)\s+type\s+group/i);
    if (grpMatch) {
      const name = grpMatch[1];
      const members = [];

      for (const line of sec.lines) {
        const memMatch = line.match(/^service\s+service-set\s+(\S+)/i);
        if (memMatch) {
          members.push(memMatch[1]);
          continue;
        }
      }

      serviceGroups.push({
        name,
        members,
        description: '',
        _protocol: '',
      });

      continue;
    }
  }

  return { serviceObjects, serviceGroups };
}


// ---------------------------------------------------------------------------
// Security Policy Parser
// ---------------------------------------------------------------------------

/**
 * Parses the `security-policy` section which contains nested `rule name <x>`
 * blocks.  Returns an array of security policy objects in intermediate form.
 */
function parseSecurityPolicies(sections, warnings) {
  const policies = [];
  let ruleIndex = 1;

  for (const sec of sections) {
    if (sec.header !== 'security-policy') continue;

    // Collect all lines and split into individual rules
    const rules = splitNestedRules(sec.lines);

    for (const rule of rules) {
      const policy = buildSecurityPolicy(rule.name, rule.lines, ruleIndex++, warnings);
      if (policy) {
        policies.push(policy);
      }
    }
  }

  // Check for old-style interzone policies
  for (const sec of sections) {
    if (/^(policy\s+)?interzone\b/i.test(sec.header)) {
      warnings.push(createWarning(
        'warning',
        'security-policy/interzone',
        'Detected old-style interzone policy format — only new-style security-policy rules are fully parsed',
        'Migrate the Huawei config to new-style security-policy rules for complete conversion'
      ));
      break;
    }
  }

  // Append implicit default deny
  policies.push({
    name: 'Implicit: Default Deny',
    src_zones: ['any'],
    dst_zones: ['any'],
    src_addresses: ['any'],
    dst_addresses: ['any'],
    negate_source: false,
    negate_destination: false,
    applications: [],
    services: ['any'],
    action: 'deny',
    log_start: false,
    log_end: false,
    profile_group: '',
    security_profiles: {},
    description: 'Huawei USG implicit deny at end of security-policy',
    tags: ['added_by_fpic'],
    disabled: false,
    schedule: '',
    source_users: [],
    _rule_index: ruleIndex++,
    _implicit: true,
    _huawei: {
      priority: 0,
      counting: false,
      longLink: false,
    },
  });

  return policies;
}

/**
 * Splits a flat list of lines from the security-policy section into
 * individual rule blocks.
 *
 * Each rule starts with `rule name <name>` and continues until the next
 * `rule name` line or end of input.
 */
function splitNestedRules(lines) {
  const rules = [];
  let current = null;

  for (const line of lines) {
    const ruleStart = line.match(/^rule\s+name\s+(\S+)/i);
    if (ruleStart) {
      if (current) rules.push(current);
      current = { name: ruleStart[1], lines: [] };
    } else if (current) {
      current.lines.push(line);
    }
  }
  if (current) rules.push(current);

  return rules;
}

/**
 * Builds a single security policy object from the lines inside a rule block.
 */
function buildSecurityPolicy(ruleName, lines, ruleIndex, warnings) {
  const srcZones = [];
  const dstZones = [];
  const srcAddrs = [];
  const dstAddrs = [];
  const services = [];
  const applications = [];
  const profileRefs = {};
  const srcUsers = [];
  let action = 'deny';
  let disabled = false;
  let description = '';
  let schedule = '';
  let logStart = false;
  let logEnd = false;
  let counting = false;
  let longLink = false;

  for (const line of lines) {
    const trimmed = line.trim();

    // Source / destination zones (can appear multiple times)
    const srcZoneMatch = trimmed.match(/^source-zone\s+(\S+)/i);
    if (srcZoneMatch) {
      srcZones.push(srcZoneMatch[1]);
      continue;
    }
    const dstZoneMatch = trimmed.match(/^destination-zone\s+(\S+)/i);
    if (dstZoneMatch) {
      dstZones.push(dstZoneMatch[1]);
      continue;
    }

    // Source addresses
    const srcAddrSet = trimmed.match(/^source-address\s+address-set\s+(\S+)/i);
    if (srcAddrSet) {
      srcAddrs.push(srcAddrSet[1]);
      continue;
    }
    const srcAddrInline = trimmed.match(/^source-address\s+(\d+\.\d+\.\d+\.\d+)\s+mask\s+(\S+)/i);
    if (srcAddrInline) {
      const cidr = huaweiMaskToCidr(srcAddrInline[2]);
      srcAddrs.push(`${srcAddrInline[1]}/${cidr}`);
      continue;
    }
    if (/^source-address\s+any$/i.test(trimmed)) {
      // 'any' will be handled below — only add if nothing else is present
      continue;
    }

    // Destination addresses
    const dstAddrSet = trimmed.match(/^destination-address\s+address-set\s+(\S+)/i);
    if (dstAddrSet) {
      dstAddrs.push(dstAddrSet[1]);
      continue;
    }
    const dstAddrInline = trimmed.match(/^destination-address\s+(\d+\.\d+\.\d+\.\d+)\s+mask\s+(\S+)/i);
    if (dstAddrInline) {
      const cidr = huaweiMaskToCidr(dstAddrInline[2]);
      dstAddrs.push(`${dstAddrInline[1]}/${cidr}`);
      continue;
    }
    if (/^destination-address\s+any$/i.test(trimmed)) {
      continue;
    }

    // Services (predefined or service-set reference; can appear multiple times)
    const svcMatch = trimmed.match(/^service\s+(\S+)/i);
    if (svcMatch) {
      const svcName = svcMatch[1];
      if (svcName.toLowerCase() !== 'any') {
        services.push(svcName);
      }
      continue;
    }

    // Applications
    const appMatch = trimmed.match(/^application\s+(\S+)/i);
    if (appMatch) {
      const appName = appMatch[1];
      if (appName.toLowerCase() !== 'any') {
        applications.push(appName);
      }
      continue;
    }

    // Source user identity
    const srcUserMatch = trimmed.match(/^source-user\s+(\S+)/i);
    if (srcUserMatch) {
      srcUsers.push(srcUserMatch[1]);
      continue;
    }
    const srcUserGroupMatch = trimmed.match(/^source-user-group\s+(\S+)/i);
    if (srcUserGroupMatch) {
      srcUsers.push(`group:${srcUserGroupMatch[1]}`);
      continue;
    }

    // Action
    if (/^action\s+permit$/i.test(trimmed)) {
      action = 'allow';
      continue;
    }
    if (/^action\s+deny$/i.test(trimmed)) {
      action = 'deny';
      continue;
    }

    // Disabled
    if (/^disable$/i.test(trimmed)) {
      disabled = true;
      continue;
    }

    // Time-range / schedule
    const trMatch = trimmed.match(/^time-range\s+(\S+)/i);
    if (trMatch) {
      schedule = trMatch[1];
      continue;
    }

    // Description
    const descMatch = trimmed.match(/^description\s+(.+)/i);
    if (descMatch) {
      description = descMatch[1].trim();
      continue;
    }
    const longDescMatch = trimmed.match(/^long-description\s+(.+)/i);
    if (longDescMatch) {
      description = longDescMatch[1].trim();
      continue;
    }

    // Security profiles
    const profMatch = trimmed.match(/^profile\s+(\S+)\s+(\S+)/i);
    if (profMatch) {
      profileRefs[profMatch[1]] = profMatch[2];
      continue;
    }

    // Logging
    if (/^log\s+enable$/i.test(trimmed)) {
      logEnd = true;
      continue;
    }

    // Counting
    if (/^counting$/i.test(trimmed)) {
      counting = true;
      continue;
    }

    // Long-link enable
    if (/^long-link\s+enable$/i.test(trimmed)) {
      longLink = true;
      continue;
    }
  }

  // Default to 'any' if no explicit addresses were collected
  if (srcAddrs.length === 0) srcAddrs.push('any');
  if (dstAddrs.length === 0) dstAddrs.push('any');
  if (services.length === 0) services.push('any');

  return {
    name: ruleName,
    src_zones: srcZones.length > 0 ? srcZones : ['any'],
    dst_zones: dstZones.length > 0 ? dstZones : ['any'],
    src_addresses: srcAddrs,
    dst_addresses: dstAddrs,
    negate_source: false,
    negate_destination: false,
    applications,
    services,
    action,
    log_start: logStart,
    log_end: logEnd,
    profile_group: '',
    security_profiles: profileRefs,
    description,
    tags: [],
    disabled,
    schedule,
    source_users: srcUsers,
    _rule_index: ruleIndex,
    _huawei: {
      priority: 0,
      counting,
      longLink,
    },
  };
}


// ---------------------------------------------------------------------------
// NAT Policy Parser (Source NAT)
// ---------------------------------------------------------------------------

function parseNatPolicies(sections, warnings) {
  const natRules = [];
  let ruleIndex = 1;

  for (const sec of sections) {
    if (sec.header !== 'nat-policy') continue;

    const rules = splitNestedRules(sec.lines);
    for (const rule of rules) {
      const natRule = buildNatPolicyRule(rule.name, rule.lines, ruleIndex++, warnings);
      if (natRule) {
        natRules.push(natRule);
      }
    }
  }

  return natRules;
}

function buildNatPolicyRule(ruleName, lines, ruleIndex, warnings) {
  const srcZones = [];
  const dstZones = [];
  const srcAddrs = [];
  const dstAddrs = [];
  let translatedSrc = null;
  let description = '';
  const unparsedClauses = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const srcZoneMatch = trimmed.match(/^source-zone\s+(\S+)/i);
    if (srcZoneMatch) { srcZones.push(srcZoneMatch[1]); continue; }

    const dstZoneMatch = trimmed.match(/^destination-zone\s+(\S+)/i);
    if (dstZoneMatch) { dstZones.push(dstZoneMatch[1]); continue; }

    const srcAddrSet = trimmed.match(/^source-address\s+address-set\s+(\S+)/i);
    if (srcAddrSet) { srcAddrs.push(srcAddrSet[1]); continue; }
    if (/^source-address\s+any$/i.test(trimmed)) continue;

    const dstAddrSet = trimmed.match(/^destination-address\s+address-set\s+(\S+)/i);
    if (dstAddrSet) { dstAddrs.push(dstAddrSet[1]); continue; }
    if (/^destination-address\s+any$/i.test(trimmed)) continue;

    // <ip> mask <mask|length> or <ip> <length>; a bare dotted value after the IP is a wildcard, left unparsed.
    const inlineAddr = trimmed.match(/^(source|destination)-address\s+(\d+\.\d+\.\d+\.\d+)\s+(?:mask\s+(\S+)|(\d+))$/i);
    if (inlineAddr) {
      const prefix = `${inlineAddr[2]}/${huaweiMaskToCidr(inlineAddr[3] || inlineAddr[4])}`;
      (inlineAddr[1].toLowerCase() === 'source' ? srcAddrs : dstAddrs).push(prefix);
      continue;
    }

    // action source-nat address-group <name>
    const snatPoolMatch = trimmed.match(/^action\s+source-nat\s+address-group\s+(\S+)/i);
    if (snatPoolMatch) {
      translatedSrc = { type: 'dynamic-ip-pool', addresses: [snatPoolMatch[1]] };
      continue;
    }

    // action source-nat easy-ip
    if (/^action\s+source-nat\s+easy-ip$/i.test(trimmed)) {
      translatedSrc = { type: 'interface', addresses: [] };
      continue;
    }

    // action no-nat
    if (/^action\s+no-nat$/i.test(trimmed)) {
      translatedSrc = { type: 'no-nat' };
      continue;
    }

    const descMatch = trimmed.match(/^description\s+(.+)/i);
    if (descMatch) { description = descMatch[1].trim(); continue; }
    if (/^service\s+any$/i.test(trimmed)) continue;

    unparsedClauses.push(trimmed);
  }

  // An exemption with a clause we can't read would widen to the whole zone pair; drop it instead.
  if (translatedSrc?.type === 'no-nat' && unparsedClauses.length > 0) {
    warnings.push(createWarning('warning', `nat/source/${ruleName}`,
      `NAT rule "${ruleName}" (action no-nat) skipped — unsupported match clause: ${unparsedClauses.join('; ')}`,
      'Build this NAT exemption manually, ahead of the source NAT rule it exempts traffic from'));
    return null;
  }

  if (srcAddrs.length === 0) srcAddrs.push('any');
  if (dstAddrs.length === 0) dstAddrs.push('any');

  return {
    name: ruleName,
    type: 'source',
    src_zones: srcZones.length > 0 ? srcZones : ['any'],
    dst_zones: dstZones.length > 0 ? dstZones : ['any'],
    src_addresses: srcAddrs,
    dst_addresses: dstAddrs,
    translated_src: translatedSrc,
    translated_dst: null,
    translated_port: null,
    description: description || `Source NAT rule: ${ruleName}`,
    _rule_index: ruleIndex,
  };
}


// ---------------------------------------------------------------------------
// NAT Address-Group Parser (NAT Pools)
// ---------------------------------------------------------------------------

function parseNatAddressGroups(sections, warnings) {
  const pools = [];

  for (const sec of sections) {
    const match = sec.header.match(/^nat\s+address-group\s+(\S+)\s+(\d+)/i);
    if (!match) continue;

    const name = match[1];
    const id = match[2];
    let mode = 'pat';
    const ipRanges = [];

    for (const line of sec.lines) {
      if (/^mode\s+pat$/i.test(line.trim())) { mode = 'pat'; continue; }
      if (/^mode\s+no-pat$/i.test(line.trim())) { mode = 'no-pat'; continue; }
      const secMatch = line.match(/^section\s+\d+\s+(\S+)\s+(\S+)/i);
      if (secMatch) {
        ipRanges.push(`${secMatch[1]}-${secMatch[2]}`);
        continue;
      }
    }

    pools.push({ name, id, mode, ipRanges });
  }

  return pools;
}


// ---------------------------------------------------------------------------
// NAT Server (Destination NAT) Parser
// ---------------------------------------------------------------------------

function parseNatServers(sections, allLines, warnings) {
  const dnatRules = [];
  let ruleIndex = 1000; // offset to avoid collision with nat-policy indices

  // nat server lines can appear at the top level (not inside a section header)
  // We search through all raw lines for them.
  for (const line of allLines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('nat server ')) continue;

    // nat server <name> zone <zone> global <pub-ip> [pub-port] inside <priv-ip> [priv-port]
    // nat server <name> zone <zone> global <pub-ip> inside <priv-ip>
    const match = trimmed.match(
      /^nat\s+server\s+(\S+)\s+zone\s+(\S+)\s+global\s+(\S+)\s+(?:(\d+)\s+)?inside\s+(\S+)(?:\s+(\d+))?/i
    );
    if (match) {
      const [, name, zone, globalIp, globalPort, insideIp, insidePort] = match;

      dnatRules.push({
        name: `DNAT-${name}`,
        type: 'destination',
        src_zones: ['any'],
        dst_zones: [zone],
        src_addresses: ['any'],
        dst_addresses: [globalIp],
        translated_src: null,
        translated_dst: insideIp,
        translated_port: insidePort || globalPort || null,
        description: `Destination NAT: ${name} (${globalIp}${globalPort ? ':' + globalPort : ''} → ${insideIp}${insidePort ? ':' + insidePort : ''})`,
        _rule_index: ruleIndex++,
      });
    }
  }

  return dnatRules;
}


// ---------------------------------------------------------------------------
// Static Route Parser
// ---------------------------------------------------------------------------

function parseStaticRoutes(allLines, warnings) {
  const routes = [];

  for (const line of allLines) {
    const trimmed = line.trim();
    // ip route-static <dest> <mask> <nexthop>
    const match = trimmed.match(
      /^ip\s+route-static\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)/i
    );
    if (!match) continue;

    const [, dest, mask, nextHop] = match;
    const cidr = huaweiMaskToCidr(mask);

    routes.push({
      name: `static-route-${routes.length + 1}`,
      destination: `${dest}/${cidr}`,
      next_hop: nextHop,
      next_hop_type: 'ip-address',
      interface: '',
      metric: 60,
      admin_distance: 60,
      description: '',
      vrf: '',
      routing_context: '',
    });
  }

  return routes;
}


// ---------------------------------------------------------------------------
// BGP Configuration
// ---------------------------------------------------------------------------

function parseHuaweiBgpConfig(sections, warnings) {
  const bgpConfigs = [];

  for (const sec of sections) {
    const match = sec.header.match(/^bgp\s+(\d+)/i);
    if (!match) continue;

    const localAs = parseInt(match[1]) || null;
    let routerId = '';
    const neighbors = [];
    const networks = [];
    const redistribute = [];
    let inAddrFamily = false;

    for (const line of sec.lines) {
      const trimmed = line.trim();

      if (/^ipv4-family\s+unicast/i.test(trimmed) || /^address-family\s+ipv4\s+unicast/i.test(trimmed)) {
        inAddrFamily = true;
        continue;
      }
      if (inAddrFamily && trimmed === '#') {
        inAddrFamily = false;
        continue;
      }

      if (trimmed.startsWith('router-id ')) {
        routerId = trimmed.slice(10).trim();
      } else if (trimmed.startsWith('peer ')) {
        const tokens = trimmed.split(/\s+/);
        const peerAddr = tokens[1];
        if (tokens[2] === 'as-number') {
          const existing = neighbors.find(n => n.address === peerAddr);
          if (existing) {
            existing.peer_as = parseInt(tokens[3]) || null;
          } else {
            neighbors.push({
              address: peerAddr,
              peer_as: parseInt(tokens[3]) || null,
              description: '',
              update_source: '',
              local_address: '',
              import_policy: '',
              export_policy: '',
              authentication_key: '',
              enabled: true,
            });
          }
        } else if (tokens[2] === 'description') {
          const existing = neighbors.find(n => n.address === peerAddr);
          if (existing) existing.description = tokens.slice(3).join(' ');
        } else if (tokens[2] === 'route-policy') {
          const existing = neighbors.find(n => n.address === peerAddr);
          if (existing) {
            const direction = tokens[4]; // import or export
            if (direction === 'import') existing.import_policy = tokens[3];
            else if (direction === 'export') existing.export_policy = tokens[3];
          }
        } else if (tokens[2] === 'enable' && inAddrFamily) {
          // Peer activation in address-family — mark as enabled
          const existing = neighbors.find(n => n.address === peerAddr);
          if (existing) existing.enabled = true;
        }
      } else if (trimmed.startsWith('network ') && inAddrFamily) {
        const tokens = trimmed.split(/\s+/);
        const prefix = tokens[1];
        const mask = tokens[2];
        if (prefix && mask) {
          const cidr = huaweiMaskToCidr(mask);
          networks.push({ prefix: `${prefix}/${cidr}`, policy: '' });
        } else if (prefix) {
          networks.push({ prefix, policy: '' });
        }
      } else if (trimmed.startsWith('import-route ') && inAddrFamily) {
        const tokens = trimmed.split(/\s+/);
        redistribute.push({ protocol: tokens[1], policy: '' });
      }
    }

    if (localAs) {
      bgpConfigs.push({
        instance: '',
        local_as: localAs,
        router_id: routerId,
        peer_groups: neighbors.length > 0 ? [{ name: 'PEERS', type: 'external', neighbors }] : [],
        networks,
        redistribute,
      });
    }
  }

  return bgpConfigs;
}

// ---------------------------------------------------------------------------
// OSPF Configuration
// ---------------------------------------------------------------------------

function parseHuaweiOspfConfig(sections, warnings) {
  const ospfConfigs = [];

  for (const sec of sections) {
    const match = sec.header.match(/^ospf\s+(\d+)/i);
    if (!match) continue;

    const processId = parseInt(match[1]) || 0;
    // Router-id can appear on the header line: "ospf 1 router-id 10.1.1.254"
    const headerRidMatch = sec.header.match(/router-id\s+(\S+)/i);
    let routerId = headerRidMatch ? headerRidMatch[1] : '';
    const areaMap = {};
    const redistribute = [];
    let currentArea = null;

    for (const line of sec.lines) {
      const trimmed = line.trim();

      if (trimmed.startsWith('router-id ')) {
        routerId = trimmed.slice(10).trim();
      } else if (/^area\s+(\S+)/.test(trimmed)) {
        const areaMatch = trimmed.match(/^area\s+(\S+)/);
        currentArea = areaMatch[1];
        if (!areaMap[currentArea]) {
          areaMap[currentArea] = { area_id: currentArea, area_type: 'normal', interfaces: [], networks: [] };
        }
        // Check for stub/nssa in same line
        if (/\bstub\b/.test(trimmed)) {
          areaMap[currentArea].area_type = /\bno-summary\b/.test(trimmed) ? 'totally-stub' : 'stub';
        } else if (/\bnssa\b/.test(trimmed)) {
          areaMap[currentArea].area_type = /\bno-summary\b/.test(trimmed) ? 'totally-nssa' : 'nssa';
        }
      } else if (trimmed === 'stub' && currentArea) {
        areaMap[currentArea].area_type = 'stub';
      } else if (trimmed === 'stub no-summary' && currentArea) {
        areaMap[currentArea].area_type = 'totally-stub';
      } else if (trimmed === 'nssa' && currentArea) {
        areaMap[currentArea].area_type = 'nssa';
      } else if (trimmed === 'nssa no-summary' && currentArea) {
        areaMap[currentArea].area_type = 'totally-nssa';
      } else if (trimmed.startsWith('network ') && currentArea) {
        const tokens = trimmed.split(/\s+/);
        // network <prefix> <wildcard>
        if (tokens.length >= 3) {
          const prefix = tokens[1];
          const wildcard = tokens[2];
          const cidr = huaweiWildcardToCidr(wildcard);
          areaMap[currentArea].networks.push({ prefix: `${prefix}/${cidr}` });
        }
      } else if (trimmed.startsWith('import-route ')) {
        const tokens = trimmed.split(/\s+/);
        redistribute.push({ protocol: tokens[1], policy: '', metric_type: null });
      }
    }

    if (Object.keys(areaMap).length > 0) {
      ospfConfigs.push({
        instance: '',
        router_id: routerId,
        reference_bandwidth: null,
        areas: Object.values(areaMap),
        redistribute,
      });
    }
  }

  return ospfConfigs;
}

function huaweiWildcardToCidr(wildcard) {
  if (!wildcard) return 32;
  const parts = wildcard.split('.');
  if (parts.length !== 4) return 32;
  let bits = 0;
  for (const part of parts) {
    let val = parseInt(part);
    while (val > 0) { bits++; val = val >> 1; }
  }
  return 32 - bits;
}

// ---------------------------------------------------------------------------
// OSPFv3 (IPv6 OSPF) Configuration
// ---------------------------------------------------------------------------

function parseHuaweiOspf3Config(sections, warnings) {
  const ospf3Configs = [];

  for (const sec of sections) {
    const match = sec.header.match(/^ospfv3\s+(\d+)/i);
    if (!match) continue;

    const processId = parseInt(match[1]) || 0;
    const headerRidMatch = sec.header.match(/router-id\s+(\S+)/i);
    let routerId = headerRidMatch ? headerRidMatch[1] : '';
    const areaMap = {};
    const redistribute = [];
    let currentArea = null;

    for (const line of sec.lines) {
      const trimmed = line.trim();

      if (trimmed.startsWith('router-id ')) {
        routerId = trimmed.slice(10).trim();
      } else if (/^area\s+(\S+)/.test(trimmed)) {
        const areaMatch = trimmed.match(/^area\s+(\S+)/);
        currentArea = areaMatch[1];
        if (!areaMap[currentArea]) {
          areaMap[currentArea] = { area_id: currentArea, area_type: 'normal', interfaces: [], networks: [] };
        }
        if (/\bstub\b/.test(trimmed)) {
          areaMap[currentArea].area_type = /\bno-summary\b/.test(trimmed) ? 'totally-stub' : 'stub';
        } else if (/\bnssa\b/.test(trimmed)) {
          areaMap[currentArea].area_type = /\bno-summary\b/.test(trimmed) ? 'totally-nssa' : 'nssa';
        }
      } else if (trimmed === 'stub' && currentArea) {
        areaMap[currentArea].area_type = 'stub';
      } else if (trimmed === 'stub no-summary' && currentArea) {
        areaMap[currentArea].area_type = 'totally-stub';
      } else if (trimmed === 'nssa' && currentArea) {
        areaMap[currentArea].area_type = 'nssa';
      } else if (trimmed === 'nssa no-summary' && currentArea) {
        areaMap[currentArea].area_type = 'totally-nssa';
      } else if (trimmed.startsWith('import-route ')) {
        const tokens = trimmed.split(/\s+/);
        redistribute.push({ protocol: tokens[1], policy: '', metric_type: null });
      }
    }

    if (Object.keys(areaMap).length > 0) {
      ospf3Configs.push({
        instance: '',
        router_id: routerId,
        reference_bandwidth: null,
        areas: Object.values(areaMap),
        redistribute,
      });
    }
  }

  return ospf3Configs;
}

// ---------------------------------------------------------------------------
// Time-Range / Schedule Parser
// ---------------------------------------------------------------------------

function parseTimeRanges(sections, warnings) {
  const schedules = [];

  for (const sec of sections) {
    const match = sec.header.match(/^time-range\s+(\S+)/i);
    if (!match) continue;

    const name = match[1];
    let type = 'unknown';
    let start = '';
    let end = '';
    const days = [];

    for (const line of sec.lines) {
      const trimmed = line.trim();

      // absolute-range <start-time> <start-date> to <end-time> <end-date>
      if (trimmed.startsWith('absolute-range')) {
        type = 'onetime';
        const abMatch = trimmed.match(/absolute-range\s+(.+?)\s+to\s+(.+)/i);
        if (abMatch) {
          start = abMatch[1].trim();
          end = abMatch[2].trim();
        }
        continue;
      }

      // period-range <start-time> to <end-time> <day-of-week>...
      if (trimmed.startsWith('period-range')) {
        type = 'recurring';
        const perMatch = trimmed.match(/period-range\s+(\S+)\s+to\s+(\S+)\s+(.*)/i);
        if (perMatch) {
          start = perMatch[1].trim();
          end = perMatch[2].trim();
          const dayTokens = perMatch[3].trim().split(/\s+/);
          const dayShortMap = {
            monday: 'Mon', tuesday: 'Tue', wednesday: 'Wed',
            thursday: 'Thu', friday: 'Fri', saturday: 'Sat', sunday: 'Sun',
            'working-day': 'Mon,Tue,Wed,Thu,Fri',
            'off-day': 'Sat,Sun',
          };
          for (const tok of dayTokens) {
            const mapped = dayShortMap[tok.toLowerCase()];
            if (mapped) {
              days.push(...mapped.split(','));
            }
          }
        }
        continue;
      }
    }

    schedules.push({ name, type, days, start, end });
  }

  return schedules;
}


// ---------------------------------------------------------------------------
// HA Detection
// ---------------------------------------------------------------------------

function parseHaConfig(allLines, warnings) {
  let hrpEnabled = false;
  let standbyDevice = false;
  let groupId = 0;
  let priority = 100;

  for (const line of allLines) {
    const trimmed = line.trim();

    if (trimmed === 'hrp enable') {
      hrpEnabled = true;
      continue;
    }
    if (/^hrp\s+standby-device$/i.test(trimmed)) {
      standbyDevice = true;
      continue;
    }
    const grpMatch = trimmed.match(/^hrp\s+mirror\s+session\s+enable/i);
    if (grpMatch) {
      // mirror session indicates HA sync
      continue;
    }
    const priMatch = trimmed.match(/^hrp\s+priority\s+(\d+)/i);
    if (priMatch) {
      priority = parseInt(priMatch[1], 10);
      continue;
    }
  }

  if (!hrpEnabled) return null;

  if (standbyDevice) {
    warnings.push(createWarning(
      'info', 'ha/hrp',
      'This device is the HRP standby device',
      'Ensure you are converting the primary device configuration'
    ));
  }

  return {
    enabled: true,
    mode: 'active-passive',
    group_id: groupId,
    priority: standbyDevice ? 200 : priority,
    preempt: false,
    peer_ip: '',
    ha_interfaces: [],
    monitoring: { link_groups: [], path_groups: [] },
    description: `Huawei HRP HA (${standbyDevice ? 'standby' : 'primary'})`,
  };
}


// ---------------------------------------------------------------------------
// VPN / IPsec Parser (basic detection)
// ---------------------------------------------------------------------------

function parseVpnConfig(sections, warnings) {
  const vpnTunnels = [];

  // Gather IKE proposals
  const ikeProposals = {};
  for (const sec of sections) {
    const match = sec.header.match(/^ike\s+proposal\s+(\S+)/i);
    if (!match) continue;
    const name = match[1];
    const proposal = {
      name,
      encryption: 'aes-256-cbc',
      authentication: 'sha256',
      dhGroup: 'group14',
      lifetime: 86400,
    };
    for (const line of sec.lines) {
      const encMatch = line.match(/^encryption-algorithm\s+(\S+)/i);
      if (encMatch) proposal.encryption = encMatch[1];
      const authMatch = line.match(/^authentication-algorithm\s+(\S+)/i);
      if (authMatch) proposal.authentication = authMatch[1];
      const dhMatch = line.match(/^dh\s+group(\d+)/i);
      if (dhMatch) proposal.dhGroup = `group${dhMatch[1]}`;
      const lifeMatch = line.match(/^sa\s+duration\s+(\d+)/i);
      if (lifeMatch) proposal.lifetime = parseInt(lifeMatch[1], 10);
    }
    ikeProposals[name] = proposal;
  }

  // Gather IKE peers
  const ikePeers = {};
  for (const sec of sections) {
    const match = sec.header.match(/^ike\s+peer\s+(\S+)/i);
    if (!match) continue;
    const name = match[1];
    const peer = { name, remoteAddress: '', localAddress: '', ikeVersion: 'v2', proposalName: '' };
    for (const line of sec.lines) {
      const remMatch = line.match(/^remote-address\s+(\S+)/i);
      if (remMatch) peer.remoteAddress = remMatch[1];
      const locMatch = line.match(/^local-address\s+(\S+)/i);
      if (locMatch) peer.localAddress = locMatch[1];
      const verMatch = line.match(/^ike-version\s+(\S+)/i);
      if (verMatch) peer.ikeVersion = verMatch[1] === '1' ? 'v1' : 'v2';
      const propMatch = line.match(/^ike-proposal\s+(\S+)/i);
      if (propMatch) peer.proposalName = propMatch[1];
      if (/pre-shared-key/i.test(line)) {
        warnings.push(createWarning(
          'info', `vpn/ike-peer/${name}`,
          `IKE peer "${name}" pre-shared key sanitized`,
          'Pre-shared keys are never included in parsed output'
        ));
      }
    }
    ikePeers[name] = peer;
  }

  // Gather IPsec proposals
  const ipsecProposals = {};
  for (const sec of sections) {
    const match = sec.header.match(/^ipsec\s+proposal\s+(\S+)/i);
    if (!match) continue;
    const name = match[1];
    const proposal = { name, encryption: 'aes-256-cbc', authentication: 'sha-256', encapsulation: 'esp' };
    for (const line of sec.lines) {
      const encMatch = line.match(/^esp\s+encryption-algorithm\s+(\S+)/i);
      if (encMatch) proposal.encryption = encMatch[1];
      const authMatch = line.match(/^esp\s+authentication-algorithm\s+(\S+)/i);
      if (authMatch) proposal.authentication = authMatch[1];
      if (/^encapsulation-mode\s+tunnel/i.test(line.trim())) proposal.encapsulation = 'esp';
    }
    ipsecProposals[name] = proposal;
  }

  // Gather IPsec policies
  for (const sec of sections) {
    const match = sec.header.match(/^ipsec\s+policy\s+(\S+)\s+(\d+)\s+isakmp/i);
    if (!match) continue;
    const policyName = match[1];
    const seqNum = match[2];
    let ikePeerName = '';
    let ipsecProposalName = '';
    let pfs = 'group14';

    for (const line of sec.lines) {
      const peerMatch = line.match(/^ike-peer\s+(\S+)/i);
      if (peerMatch) ikePeerName = peerMatch[1];
      const propMatch = line.match(/^proposal\s+(\S+)/i);
      if (propMatch) ipsecProposalName = propMatch[1];
      const pfsMatch = line.match(/^pfs\s+(\S+)/i);
      if (pfsMatch) pfs = pfsMatch[1];
    }

    const peer = ikePeers[ikePeerName] || { name: ikePeerName, remoteAddress: '', localAddress: '', ikeVersion: 'v2', proposalName: '' };
    const ikeProp = ikeProposals[peer.proposalName] || ikeProposals[Object.keys(ikeProposals)[0]] || {
      name: 'default', encryption: 'aes-256-cbc', authentication: 'sha256', dhGroup: 'group14', lifetime: 86400,
    };
    const ipsecProp = ipsecProposals[ipsecProposalName] || {
      name: ipsecProposalName || 'default', encryption: 'aes-256-cbc', authentication: 'sha-256', encapsulation: 'esp',
    };

    vpnTunnels.push({
      name: `${policyName}-${seqNum}`,
      ike_gateway: {
        name: peer.name,
        address: peer.remoteAddress,
        local_address: peer.localAddress,
        pre_shared_key: 'SANITIZED',
        ike_version: peer.ikeVersion,
        proposal: ikeProp.name,
      },
      ike_proposal: {
        name: ikeProp.name,
        auth_method: 'pre-shared-keys',
        dh_group: ikeProp.dhGroup,
        encryption: ikeProp.encryption,
        authentication: ikeProp.authentication,
        lifetime: ikeProp.lifetime,
      },
      ipsec_proposal: {
        name: ipsecProp.name,
        protocol: ipsecProp.encapsulation,
        encryption: ipsecProp.encryption,
        authentication: ipsecProp.authentication,
        lifetime: 3600,
        pfs_group: pfs,
      },
      proxy_id: [],
      tunnel_interface: '',
      description: `IPsec policy ${policyName} seq ${seqNum}`,
      _huawei: { ikePeer: ikePeerName, ipsecProposal: ipsecProposalName },
    });
  }

  if (vpnTunnels.length > 0) {
    warnings.push(createWarning(
      'info', 'vpn',
      `Parsed ${vpnTunnels.length} VPN/IPsec tunnel(s)`,
      'VPN tunnel configuration detected and included in intermediate output'
    ));
  }

  return vpnTunnels;
}


// ---------------------------------------------------------------------------
// Security Profile Definition Parser
// ---------------------------------------------------------------------------

function parseSecurityProfiles(sections, warnings) {
  const profiles = [];

  // Huawei uses `profile type <name>` within security-policy rules.
  // Standalone profile definitions are under `profile <type>` sections.
  for (const sec of sections) {
    // profile <type> name <name>   (varies by firmware version)
    const profMatch = sec.header.match(/^profile\s+(\S+)\s+name\s+(\S+)/i);
    if (profMatch) {
      profiles.push({
        type: profMatch[1],
        name: profMatch[2],
        settings: sec.lines.map(l => l.trim()),
      });
    }
  }

  return profiles;
}


// ---------------------------------------------------------------------------
// Version Detection
// ---------------------------------------------------------------------------

function extractVersion(allLines) {
  for (const line of allLines) {
    const trimmed = line.trim();
    // Software Version V300R001C20SPC600 or similar
    const verMatch = trimmed.match(/Software\s+Version\s+(\S+)/i);
    if (verMatch) return verMatch[1];
    // sysname-based version is sometimes in a comment
    const verMatch2 = trimmed.match(/^!\s*Software\s+Version\s+(\S+)/i);
    if (verMatch2) return verMatch2[1];
  }
  return '';
}


// ---------------------------------------------------------------------------
// Main Parser Entry Point
// ---------------------------------------------------------------------------

/**
 * Parses a Huawei USG (VRP) configuration into the intermediate JSON schema.
 *
 * @param {string} configText - Raw Huawei USG configuration text
 * @returns {{ intermediateConfig: Object, warnings: Object[], parseStats: Object }}
 */
export function parseHuaweiConfig(configText) {
  const warnings = [];
  const allLines = configText.split('\n').map(l => l.trimEnd());

  // Split on `#` into sections
  const sections = splitSections(configText);

  // Extract hostname
  let hostname = '';
  for (const sec of sections) {
    const sysMatch = sec.header.match(/^sysname\s+(\S+)/i);
    if (sysMatch) {
      hostname = sysMatch[1];
      break;
    }
  }

  // Parse all sections
  const zones = parseZones(sections, warnings);
  const rawInterfaces = parseInterfaces(sections, warnings);
  const { addressObjects, addressGroups } = parseAddressSets(sections, warnings);
  const { serviceObjects, serviceGroups } = parseServiceSets(sections, warnings);
  const securityPolicies = parseSecurityPolicies(sections, warnings);
  const natPolicyRules = parseNatPolicies(sections, warnings);
  const natAddressGroups = parseNatAddressGroups(sections, warnings);
  const dnatRules = parseNatServers(sections, allLines, warnings);
  const natRules = [...natPolicyRules, ...dnatRules];
  const staticRoutes = parseStaticRoutes(allLines, warnings);
  const bgpConfig = parseHuaweiBgpConfig(sections, warnings);
  const ospfConfig = parseHuaweiOspfConfig(sections, warnings);
  const ospf3Config = parseHuaweiOspf3Config(sections, warnings);
  const schedules = parseTimeRanges(sections, warnings);
  const securityProfiles = parseSecurityProfiles(sections, warnings);
  const vpnTunnels = parseVpnConfig(sections, warnings);
  const haConfig = parseHaConfig(allLines, warnings);
  const version = extractVersion(allLines);

  // Build zone-to-interface mapping for interface normalization
  const zoneByIface = {};
  for (const z of zones) {
    for (const ifName of z.interfaces) {
      zoneByIface[ifName] = z.name;
    }
  }

  // Normalize interfaces to standard schema
  const normalizedInterfaces = rawInterfaces.map(iface => ({
    name: iface.name,
    ip: iface.ip,
    zone: zoneByIface[iface.name] || '',
    vlan: iface.vlan,
    type: iface.vlan ? 'vlan' : 'physical',
    description: iface.description,
    status: iface.shutdown ? 'shutdown' : 'up',
    speed: '',
  }));

  // Store NAT address group info on warnings for converter reference
  if (natAddressGroups.length > 0) {
    warnings.push(createWarning(
      'info', 'nat/address-group',
      `Parsed ${natAddressGroups.length} NAT address-group pool(s): ${natAddressGroups.map(p => p.name).join(', ')}`,
      'NAT pools will be used for source NAT translation'
    ));
  }

  // Parse LAG / Eth-Trunk interfaces
  const lagInterfaces = parseHuaweiLagInterfaces(sections, warnings);

  // Summary warning
  warnings.push(createWarning(
    'info', 'parse-summary',
    `Huawei USG config parsed: ${securityPolicies.length} policy rule(s), ${natRules.length} NAT rule(s), ` +
    `${addressObjects.length} address object(s), ${serviceObjects.length} service object(s), ` +
    `${zones.length} zone(s), ${normalizedInterfaces.length} interface(s)`,
    'Review parsed output before conversion'
  ));

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
    schedules,
    security_profile_objects: securityProfiles,
    external_lists: [],
    vpn_tunnels: vpnTunnels,
    ha_config: haConfig,
    screen_config: [],
    syslog_config: [],
    snmp_config: parseHuaweiSnmpConfig(allLines, warnings),
    aaa_config: parseHuaweiAaaConfig(allLines, sections, warnings),
    dhcp_config: [],
    qos_config: [],
    flow_monitoring_config: parseHuaweiNetstream(sections, allLines, warnings),
    interfaces: normalizedInterfaces,
    lag_interfaces: lagInterfaces,
    routing_contexts: [{ name: 'default', type: 'default', virtual_routers: [], zones: [] }],
    static_routes: staticRoutes,
    bgp_config: bgpConfig,
    ospf_config: ospfConfig,
    ospf3_config: ospf3Config,
    evpn_config: [],
    vxlan_config: [],
    target_context: null,
    transparent_mode: false,
    bridge_domains: [],
    l2_interfaces: [],
    vwire_pairs: [],
    pbf_rules: [],
    _huawei: {
      sysname: hostname,
      zoneCount: zones.length,
      natAddressGroups,
    },
    metadata: {
      source_vendor: 'huawei_usg',
      source_version: version,
      export_date: new Date().toISOString(),
      rule_count: securityPolicies.length,
      nat_rule_count: natRules.length,
      object_count: addressObjects.length + serviceObjects.length,
      zone_count: zones.length,
      interface_count: normalizedInterfaces.length,
      vpn_tunnel_count: vpnTunnels.length,
      syslog_server_count: 0,
      dhcp_config_count: 0,
      qos_profile_count: 0,
      routing_context_count: 1,
      static_route_count: staticRoutes.length,
      bgp_instance_count: bgpConfig.length,
      ospf_instance_count: ospfConfig.length,
      ospf3_instance_count: ospf3Config.length,
      evpn_instance_count: 0,
      vxlan_tunnel_count: 0,
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


// ---------------------------------------------------------------------------
// NetStream / Flow Export Configuration Parser
// ---------------------------------------------------------------------------

/**
 * Parses Huawei USG ip netstream configuration.
 *
 * Sources:
 *   ip netstream export host <address> <port>
 *   ip netstream export source <address>
 *   ip netstream export version <version>
 *   ip netstream sampler fix-packets <rate>
 *   Per-interface: ip netstream inbound / ip netstream outbound
 */
function parseHuaweiNetstream(sections, allLines, warnings) {
  const result = { collectors: [], sampling: { input_rate: 1000, run_length: 0, interfaces: [] }, templates: [] };

  let sourceAddr = '';
  let version = 'netflow-v9';
  let samplingRate = 1000;

  for (const line of allLines) {
    const trimmed = line.trim();

    // ip netstream export host <address> <port>
    const hostMatch = trimmed.match(/^ip\s+netstream\s+export\s+host\s+(\S+)\s+(\d+)/i);
    if (hostMatch) {
      result.collectors.push({
        address: hostMatch[1],
        port: parseInt(hostMatch[2]) || 2055,
        protocol: version,
        source_address: '',
      });
      continue;
    }

    // ip netstream export source <address>
    const srcMatch = trimmed.match(/^ip\s+netstream\s+export\s+source\s+(\S+)/i);
    if (srcMatch) {
      sourceAddr = srcMatch[1];
      continue;
    }

    // ip netstream export version <9|10|ipfix>
    const verMatch = trimmed.match(/^ip\s+netstream\s+export\s+version\s+(\S+)/i);
    if (verMatch) {
      const v = verMatch[1];
      version = v === '10' || v.toLowerCase() === 'ipfix' ? 'ipfix' : `netflow-v${v}`;
      continue;
    }

    // ip netstream sampler fix-packets <rate>
    const samplerMatch = trimmed.match(/^ip\s+netstream\s+sampler\s+fix-packets\s+(\d+)/i);
    if (samplerMatch) {
      samplingRate = parseInt(samplerMatch[1]) || 1000;
      continue;
    }

    // Per-interface netstream detection
    const ifNetstream = trimmed.match(/^ip\s+netstream\s+(inbound|outbound)/i);
    if (ifNetstream) {
      // We're inside an interface section — the interface name comes from context
      // Just note that sampling is configured
    }
  }

  // Apply source address to all collectors
  if (sourceAddr) {
    for (const c of result.collectors) c.source_address = sourceAddr;
  }

  // Update collector protocol based on version
  for (const c of result.collectors) c.protocol = version;

  result.sampling.input_rate = samplingRate;

  if (result.collectors.length > 0) {
    result.templates.push({
      name: 'huawei-netstream',
      flow_type: 'ipv4',
      active_timeout: 60,
      refresh_rate: 600,
    });

    warnings.push(createWarning('info', 'netflow',
      `Parsed ${result.collectors.length} NetStream export host(s)`,
      'Huawei NetStream configuration detected'));
  }

  return result;
}


// ---------------------------------------------------------------------------
// LAG / Eth-Trunk Interface Parser
// ---------------------------------------------------------------------------

/**
 * Parses Huawei USG Eth-Trunk (LAG) interfaces and their member assignments.
 *
 * Huawei config patterns:
 *   interface Eth-Trunk0
 *     description LAG to switch
 *     mode lacp-static
 *     trunkport GigabitEthernet0/0/1
 *     trunkport GigabitEthernet0/0/2
 *   #
 *
 * Alternative member assignment:
 *   interface GigabitEthernet0/0/1
 *     eth-trunk 0
 *   #
 *
 * @param {Object[]} sections - Parsed config sections
 * @param {Object[]} warnings - Warnings array
 * @returns {Object[]} Array of lag_interfaces in intermediate schema format
 */
function parseHuaweiLagInterfaces(sections, warnings) {
  const lagInterfaces = [];
  const trunkData = {};
  const memberFromIface = {};

  for (const section of sections) {
    if (!section.header) continue;
    const lines = section.lines || [];

    // Match Eth-Trunk interface sections
    const trunkMatch = section.header.match(/^interface\s+Eth-Trunk(\d+)/i);
    if (trunkMatch) {
      const trunkNum = trunkMatch[1];
      const trunk = {
        source_name: `Eth-Trunk${trunkNum}`,
        description: '',
        members: [],
        lacp_mode: 'static',
      };

      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('description ')) {
          trunk.description = trimmed.slice(12).trim();
        } else if (trimmed.startsWith('mode lacp-static')) {
          trunk.lacp_mode = 'active';
        } else if (trimmed.startsWith('mode manual')) {
          trunk.lacp_mode = 'static';
        } else if (trimmed.startsWith('trunkport ')) {
          const member = trimmed.slice(10).trim().split(/\s+/)[0];
          if (member) trunk.members.push(member);
        }
      }

      trunkData[trunkNum] = trunk;
      continue;
    }

    // Check for eth-trunk assignment on physical interfaces
    const ifMatch = section.header.match(/^interface\s+(\S+)/i);
    if (ifMatch) {
      const ifName = ifMatch[1];
      for (const line of lines) {
        const etMatch = line.trim().match(/^eth-trunk\s+(\d+)/i);
        if (etMatch) {
          const trunkNum = etMatch[1];
          if (!memberFromIface[trunkNum]) memberFromIface[trunkNum] = [];
          memberFromIface[trunkNum].push(ifName);
        }
      }
    }
  }

  // Merge member assignments from physical interface sections
  for (const [trunkNum, members] of Object.entries(memberFromIface)) {
    if (!trunkData[trunkNum]) {
      trunkData[trunkNum] = {
        source_name: `Eth-Trunk${trunkNum}`,
        description: '',
        members: [],
        lacp_mode: 'static',
      };
    }
    for (const m of members) {
      if (!trunkData[trunkNum].members.includes(m)) {
        trunkData[trunkNum].members.push(m);
      }
    }
  }

  let aeIndex = 0;
  for (const [trunkNum, trunk] of Object.entries(trunkData)) {
    lagInterfaces.push({
      name: `ae${aeIndex}`,
      source_name: trunk.source_name,
      members: trunk.members,
      source_members: [...trunk.members],
      lacp_mode: trunk.lacp_mode,
      lacp_priority: null,
      description: trunk.description,
    });
    aeIndex++;
  }

  if (lagInterfaces.length > 0) {
    warnings.push(createWarning('info', 'lag',
      `Parsed ${lagInterfaces.length} Eth-Trunk (LAG) interface(s) with ${lagInterfaces.reduce((s, l) => s + l.members.length, 0)} member(s)`,
      'Eth-Trunk interfaces will be converted to SRX ae interfaces'));
  }

  return lagInterfaces;
}


// ---------------------------------------------------------------------------
// SNMP Configuration Parser (Huawei USG)
// ---------------------------------------------------------------------------

/**
 * Parses Huawei USG SNMP configuration from CLI lines.
 * Huawei: snmp-agent community, snmp-agent target-host, snmp-agent sys-info, etc.
 */
function parseHuaweiSnmpConfig(allLines, warnings) {
  const entries = [];
  let contact = '';
  let location = '';
  const communities = new Map();
  const trapHosts = [];

  for (const line of allLines) {
    const trimmed = line.trim();

    // snmp-agent community read <string> / snmp-agent community write <string>
    const commMatch = trimmed.match(/^snmp-agent\s+community\s+(read|write)\s+(\S+)/);
    if (commMatch) {
      communities.set(commMatch[2], commMatch[1] === 'write' ? 'read-write' : 'read-only');
      continue;
    }

    // snmp-agent target-host trap address udp-domain <ip> [udp-port <port>] params securityname <str>
    const targetMatch = trimmed.match(/^snmp-agent\s+target-host\s+trap\s+address\s+udp-domain\s+(\S+)/);
    if (targetMatch) {
      const portMatch = trimmed.match(/udp-port\s+(\d+)/);
      const secMatch = trimmed.match(/securityname\s+(\S+)/);
      trapHosts.push({
        ip: targetMatch[1],
        port: portMatch ? parseInt(portMatch[1], 10) : 162,
        community: secMatch ? secMatch[1] : '',
      });
      continue;
    }

    // snmp-agent sys-info contact <string>
    const contactMatch = trimmed.match(/^snmp-agent\s+sys-info\s+contact\s+(.+)$/);
    if (contactMatch) {
      contact = contactMatch[1];
      continue;
    }

    // snmp-agent sys-info location <string>
    const locationMatch = trimmed.match(/^snmp-agent\s+sys-info\s+location\s+(.+)$/);
    if (locationMatch) {
      location = locationMatch[1];
      continue;
    }
  }

  for (const [name, auth] of communities) {
    entries.push({
      type: 'community',
      name,
      authorization: auth,
      clients: [],
      contact,
      location,
    });
  }

  if (trapHosts.length > 0) {
    entries.push({
      type: 'trap-group',
      name: 'trap-default',
      targets: trapHosts.map(th => th.ip),
      categories: [],
      version: 'v2c',
    });
  }

    if (entries.length > 0) {
    warnings.push(createWarning('info', 'snmp', `Parsed ${entries.length} SNMP configuration item(s)`, 'Huawei SNMP configuration detected'));
  }
  return entries;
}


// ---------------------------------------------------------------------------
// AAA Configuration Parser (Huawei USG)
// ---------------------------------------------------------------------------

/**
 * Parses Huawei USG AAA configuration from CLI lines and sections.
 * Huawei: radius-server template, hwtacacs-server template, aaa
 */
function parseHuaweiAaaConfig(allLines, sections, warnings) {
  const entries = [];

  // Parse radius-server template sections
  for (const sec of sections) {
    const radiusMatch = sec.header.match(/^radius-server\s+template\s+(\S+)/i);
    if (radiusMatch) {
      const templateName = radiusMatch[1];
      let server = '';
      let port = 1812;
      let secret = '';

      for (const line of sec.lines) {
        const trimmed = line.trim();
        const authMatch = trimmed.match(/radius-server\s+authentication\s+(\S+)\s+(\d+)/);
        if (authMatch) { server = authMatch[1]; port = parseInt(authMatch[2], 10); }
        const keyMatch = trimmed.match(/radius-server\s+shared-key\s+(?:cipher\s+)?(\S+)/);
        if (keyMatch) secret = keyMatch[1];
      }

      if (server) {
        entries.push({
          type: 'radius',
          name: templateName,
          server,
          port,
          secret,
          timeout: 5,
          retry: 3,
          source_address: '',
        });
      }
    }

    // hwtacacs-server template
    const tacMatch = sec.header.match(/^hwtacacs-server\s+template\s+(\S+)/i);
    if (tacMatch) {
      const templateName = tacMatch[1];
      let server = '';
      let port = 49;
      let secret = '';

      for (const line of sec.lines) {
        const trimmed = line.trim();
        const authMatch = trimmed.match(/hwtacacs-server\s+authentication\s+(\S+)(?:\s+(\d+))?/);
        if (authMatch) { server = authMatch[1]; if (authMatch[2]) port = parseInt(authMatch[2], 10); }
        const keyMatch = trimmed.match(/hwtacacs-server\s+shared-key\s+(?:cipher\s+)?(\S+)/);
        if (keyMatch) secret = keyMatch[1];
      }

      if (server) {
        entries.push({
          type: 'tacplus',
          name: templateName,
          server,
          port,
          secret,
          timeout: 5,
          single_connection: false,
          source_address: '',
        });
      }
    }

    // aaa section with authentication-scheme, domain, etc.
    if (sec.header.match(/^aaa\s*$/i)) {
      for (const line of sec.lines) {
        const trimmed = line.trim();
        const schemeMatch = trimmed.match(/authentication-scheme\s+(\S+)/);
        if (schemeMatch) {
          entries.push({
            type: 'profile',
            name: schemeMatch[1],
            authentication_order: ['radius'],
          });
        }
      }
    }
  }

  if (entries.length > 0) {
    warnings.push(createWarning('info', 'aaa', `Parsed ${entries.length} AAA configuration item(s)`, 'Huawei AAA configuration detected'));
  }
  return entries;
}
