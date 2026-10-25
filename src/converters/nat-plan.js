/**
 * NAT plan
 * ========
 * Resolves the intermediate NAT rules into the decisions both SRX emitters
 * render: rule-sets, rules (match, translation), pools, comments and warnings.
 * The set-command converter and the XML builder only format this plan, so
 * they cannot drift apart.
 */

import { createWarning, planIngressScopeAdvice } from '../parsers/parser-utils.js';
import { encodeJunosZonePair } from '../security/junos-identifier-identity.js';

const IPV4_ADDRESS = /^\d+\.\d+\.\d+\.\d+(\/\d+)?$/;

/** True for a full or "::"-compressed IPv6 address, so names like "dead:beef" are not literals. */
function isIpv6Address(text) {
  const halves = text.split('::');
  if (halves.length > 2) return false;
  const groups = halves.flatMap(half => (half ? half.split(':') : []));
  if (!groups.every(group => /^[0-9a-fA-F]{1,4}$/.test(group))) return false;
  return halves.length === 2 ? groups.length < 8 : groups.length === 8;
}

function isLiteralAddress(addr) {
  if (IPV4_ADDRESS.test(addr)) return true;
  const [address, prefixLength, ...rest] = String(addr).split('/');
  return rest.length === 0 && (prefixLength === undefined || /^\d{1,3}$/.test(prefixLength)) && isIpv6Address(address);
}

/** Returns '::/0' for rules touching IPv6 addresses, else '0.0.0.0/0'. */
function natAnyAddress(rule) {
  const allAddrs = [
    ...(rule.src_addresses || []),
    ...(rule.dst_addresses || []),
    ...(rule.translated_src?.addresses || []),
    ...(rule.translated_src?.address ? [rule.translated_src.address] : []),
    ...(rule.translated_dst?.address ? [rule.translated_dst.address] : []),
    ...(typeof rule.translated_dst === 'string' ? [rule.translated_dst] : []),
  ];
  return allAddrs.some(a => a && typeof a === 'string' && a.includes(':')) ? '::/0' : '0.0.0.0/0';
}

function effectiveNatTypes(rule) {
  return rule.type === 'source-and-destination'
    ? ['source', 'destination']
    : [rule.type || 'source'];
}

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

/** Groups NAT rules by source-zone to destination-zone pair (one SRX rule-set each). */
function groupByZonePair(rules) {
  const groups = [];
  for (const rule of rules) {
    for (const fromZone of natSourceZones(rule)) {
      for (const toZone of natDestinationZones(rule)) {
        let group = groups.find(item => item.fromZone === fromZone && item.toZone === toZone);
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

function withPrefix(ip) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return `${ip}/32`;
  if (ip.includes(':') && !ip.includes('/')) return `${ip}/128`;
  return ip;
}

const oneLine = value => String(value).replace(/[\r\n]+/g, ' ');

/**
 * Builds the NAT plan both emitters render.
 *
 * Plan shape (resolved decisions only, no output syntax):
 * - missingZones: generated names of NAT zones absent from config.zones
 * - source / destination / static: rule-set arrays, or null when no rule has that type
 * - rule-set: { type, name, fromZones, toZones, comments, skipped, rules }
 * - rule: { name, comments, skipped, match: { source, destination, protocol, destinationPort },
 *           then, persistent }; match entries are { kind: 'prefix' | 'address-name', value };
 *           destinationPort is { name, high? } ("high" for a start-end range);
 *           destination and static rules keep one destination entry (Junos takes one)
 * - then: { kind: 'interface' } | { kind: 'off' } | { kind: 'pool', pool: { name, addresses: [{ prefix, to? }] } }
 *       | { kind: 'destination-pool', pool: { name, prefix, port } } | { kind: 'static-prefix', prefix }
 * - comments are plain text; the emitters add their own comment syntax
 * - warnings: warning objects for the caller's warning list
 *
 * @param {Object} input
 * @param {Object[]} input.natRules - Intermediate NAT rules
 * @param {Object[]} [input.addressObjects]
 * @param {Object[]} [input.addressGroups]
 * @param {Object[]} [input.zones] - config.zones
 * @param {Object[]} [input.interfaces] - config.interfaces
 * @param {function(string): string} input.mapInterface - Source -> SRX interface name
 * @param {{reference: function(string): string, definition: function(string): string,
 *   generated: function(string, string): string}} input.naming - Identifier names for a
 *   config-local path (e.g. `nat_rules[0].name`)
 * @returns {Object|null} The plan, or null when there are no NAT rules
 */
export function planNat({
  natRules,
  addressObjects,
  addressGroups,
  zones,
  interfaces,
  mapInterface,
  naming,
}) {
  if (!natRules || natRules.length === 0) return null;
  const warnings = [];

  // Address-object name -> IP/subnet value, keyed by the emitted object name.
  const addrLookup = {};
  const rawAddressNames = new Map();
  for (let objectIndex = 0; objectIndex < (addressObjects || []).length; objectIndex += 1) {
    const obj = addressObjects[objectIndex];
    const plannedName = naming.definition(`address_objects[${objectIndex}].name`);
    rawAddressNames.set(obj.name, plannedName);
    const value = obj.value || obj.ip || obj.network || obj.subnet || obj.address;
    if (value) addrLookup[plannedName] = value;
  }
  const groupNames = new Set((addressGroups || []).map(group => group.name));

  // Junos NAT match/pool addresses must be IPs, not address-book names.
  const resolveNatAddress = addr => {
    if (!addr || addr === 'any') return null;
    if (isLiteralAddress(addr)) return addr;
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
  };
  const matchAddress = (ruleIndex, field, addressIndex, rawAddress) => {
    const plannedName = naming.reference(`nat_rules[${ruleIndex}].${field}[${addressIndex}]`);
    // A defined object wins over a name that merely looks like an address.
    const literal = isLiteralAddress(rawAddress) && !rawAddressNames.has(rawAddress);
    return resolveNatAddress(literal ? rawAddress : plannedName);
  };
  const translatedAddress = rawAddress => (
    resolveNatAddress(rawAddressNames.get(rawAddress) || rawAddress)
  );
  // A "start-end" source pool range (FortiGate ippool) is Junos "A/32 to B/32".
  const sourcePoolAddress = rawAddress => {
    // njsscan regex_dos: false positive. \d excludes the literal dot and hyphen, so no token backtracks.
    const range = String(rawAddress || '').match(/^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/);  // njsscan-ignore: regex_dos
    if (range) return { prefix: `${range[1]}/32`, to: `${range[2]}/32` };
    const resolved = translatedAddress(rawAddress);
    return resolved ? { prefix: withPrefix(resolved) } : null;
  };
  const providerInterfaceIp = interfaceName => {
    if (!interfaceName) return null;
    const iface = (interfaces || []).find(item => item.name === interfaceName && (item.ip || item.ipv6));
    const host = String((iface && (iface.ip || iface.ipv6)) || '').split('/')[0];
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return `${host}/32`;
    if (host.includes(':')) return `${host}/128`;
    return null;
  };

  const natRuleIndex = new Map(natRules.map((rule, index) => [rule, index]));
  const zoneReference = (ruleIndex, rule, direction, zone) => {
    const field = direction === 'source' ? natSourceZoneField(rule) : natDestinationZoneField(rule);
    const values = direction === 'source' ? natSourceZones(rule) : natDestinationZones(rule);
    const localPath = rule[field]?.length > 0
      ? `nat_rules[${ruleIndex}].${field}[${values.indexOf(zone)}]`
      : `nat_rules[${ruleIndex}]#effective-${direction}-zone`;
    return naming.reference(localPath);
  };
  const ruleSetName = (type, fromZone, toZone) => {
    const ownerIndex = natRules.findIndex(rule => (
      effectiveNatTypes(rule).includes(type)
      && natSourceZones(rule).includes(fromZone)
      && natDestinationZones(rule).includes(toZone)
    ));
    const role = type === 'static'
      ? 'static-nat-rule-set'
      : `${type}-nat-rule-set:${encodeJunosZonePair(fromZone, toZone)}`;
    return naming.generated(`nat_rules[${ownerIndex}]`, role);
  };
  const ruleNameFor = (ruleIndex, rule, type, fromZone, toZone) => {
    let occurrence = 0;
    for (const candidateType of effectiveNatTypes(rule)) {
      const pairs = candidateType === 'static'
        ? [['STATIC-NAT', '*']]
        : natSourceZones(rule).flatMap(source => (
          natDestinationZones(rule).map(destination => [source, destination])
        ));
      for (const [candidateFrom, candidateTo] of pairs) {
        occurrence += 1;
        if (candidateType === type && candidateFrom === fromZone && candidateTo === toZone) {
          const suffix = occurrence === 1
            ? '' : `#${type}:${encodeJunosZonePair(fromZone, toZone)}`;
          return naming.definition(`nat_rules[${ruleIndex}].name${suffix}`);
        }
      }
    }
    return naming.definition(`nat_rules[${ruleIndex}].name`);
  };

  // "any" expands to the zones the config defines plus the ones NAT adds.
  const configuredZoneNames = new Set((zones || []).map(zone => zone.name));
  const definedZones = new Set(
    (zones || []).map((_, zoneIndex) => naming.definition(`zones[${zoneIndex}].name`)),
  );
  const missingZoneNames = new Set();
  for (const rule of natRules) {
    for (const zone of [...natSourceZones(rule), ...natDestinationZones(rule)]) {
      if (zone !== 'any' && !configuredZoneNames.has(zone)) missingZoneNames.add(zone);
    }
  }
  const missingZones = [];
  for (const sourceName of [...missingZoneNames].sort()) {
    const outputName = naming.generated('nat_rules', natMissingZoneRole(sourceName));
    if (definedZones.has(outputName)) continue;
    definedZones.add(outputName);
    missingZones.push(outputName);
  }
  const actualZones = [...definedZones].filter(zone => zone !== 'any');

  // Reference every NAT zone and address once so unused-name tracking sees them.
  for (let ruleIndex = 0; ruleIndex < natRules.length; ruleIndex += 1) {
    const rule = natRules[ruleIndex];
    for (const zone of natSourceZones(rule)) zoneReference(ruleIndex, rule, 'source', zone);
    for (const zone of natDestinationZones(rule)) zoneReference(ruleIndex, rule, 'destination', zone);
  }

  /**
   * Plans one match field. A field that listed addresses but resolved none
   * must not become "match anything", so it reports `unresolved`.
   */
  const planMatchField = (ruleIndex, rule, field, { anyAddress, allowGroups, keepAny }) => {
    const addresses = rule[field];
    if (!Array.isArray(addresses)) return { entries: keepAny ? [{ kind: 'prefix', value: anyAddress }] : [], unresolved: false };
    const entries = [];
    let succeeded = 0;
    for (let addressIndex = 0; addressIndex < addresses.length; addressIndex += 1) {
      const addr = addresses[addressIndex];
      const referencePath = `nat_rules[${ruleIndex}].${field}[${addressIndex}]`;
      if (addr === 'any') {
        naming.reference(referencePath);
        succeeded += 1;
        if (keepAny) entries.push({ kind: 'prefix', value: anyAddress });
      } else if (allowGroups && groupNames.has(addr)) {
        entries.push({ kind: 'address-name', value: naming.reference(referencePath) });
        succeeded += 1;
      } else {
        const resolved = matchAddress(ruleIndex, field, addressIndex, addr);
        if (!resolved) continue;
        entries.push({ kind: 'prefix', value: resolved });
        succeeded += 1;
      }
    }
    return { entries, unresolved: addresses.length > 0 && succeeded === 0 };
  };
  const skipUnresolved = (type, ruleName, field, rule) => {
    const label = field === 'src_addresses' ? 'source' : 'destination';
    const listed = oneLine(rule[field].join(', '));
    warnings.push(createWarning(
      'warning',
      `nat/${type}/${ruleName}`,
      `NAT rule "${ruleName}" skipped — none of its ${label} addresses (${listed}) resolve to an IP/prefix, so it would match all ${label} addresses`,
      'Define the address as an IP/prefix object, then add the NAT rule manually',
    ));
    return `NAT: ${type} rule "${ruleName}" skipped — none of its ${label} addresses (${listed}) resolve to an IP/prefix`;
  };
  const planProtocol = rule => {
    const proto = rule.match_protocol ? String(rule.match_protocol).toLowerCase() : '';
    return proto === 'tcp' || proto === 'udp' ? proto : null;
  };
  // A match port is one port or a "start-end" range; other forms are kept as written.
  const planPort = rule => {
    if (!rule.match_port) return null;
    const port = String(rule.match_port);
    // njsscan regex_dos: false positive. \d excludes the hyphen, so no token backtracks.
    const range = port.match(/^(\d+)-(\d+)$/);  // njsscan-ignore: regex_dos
    return range ? { name: range[1], high: range[2] } : { name: port };
  };
  // Junos takes one destination address per DNAT/static rule; later ones would silently replace it.
  const firstDestination = (type, ruleName, entries, anyAddress) => {
    if (entries.length <= 1) return entries;
    // A wildcard among them already matches every listed address.
    const wildcard = entries.find(entry => entry.value === anyAddress);
    if (wildcard) return [wildcard];
    const dropped = entries.slice(1).map(entry => entry.value).join(', ');
    warnings.push(createWarning(
      'warning',
      `nat/${type}/${ruleName}`,
      `${type === 'static' ? 'Static' : 'Destination'} NAT rule "${ruleName}" matches several destination addresses, but Junos takes one: kept ${entries[0].value}, dropped ${oneLine(dropped)}`,
      'Add one NAT rule per destination address',
    ));
    return entries.slice(0, 1);
  };
  const caveatComments = rule => (
    rule.caveat ? [`CAVEAT: ${oneLine(rule.caveat)}`] : []
  );

  const planSourceThen = (ruleIndex, rule, comments) => {
    const translated = rule.translated_src;
    const interfaceThen = { kind: 'interface' };
    if (!translated) return interfaceThen;
    // An explicit no-NAT exemption (SRX `source-nat off`) must stay one, not fall through to interface NAT.
    if (translated.type === 'no-nat') return { kind: 'off' };
    if (translated.type === 'interface') {
      const interfaceName = translated.interface || '';
      const providerIp = providerInterfaceIp(interfaceName);
      if (providerIp) {
        comments.push(`NAT: source translated to provider interface ${mapInterface(interfaceName)} (${providerIp})`);
        return {
          kind: 'pool',
          pool: {
            name: naming.generated(`nat_rules[${ruleIndex}]`, 'provider-source-nat-pool'),
            addresses: [{ prefix: providerIp }],
          },
        };
      }
      if (interfaceName) {
        const srxInterface = mapInterface(interfaceName);
        comments.push(`NAT: source translated to interface ${srxInterface} — no static IP found; using egress interface NAT (verify routing sends this traffic out ${srxInterface})`);
      }
      return interfaceThen;
    }
    if (translated.type === 'dynamic-ip-pool') {
      const poolName = naming.generated(`nat_rules[${ruleIndex}]`, 'source-nat-pool');
      const addresses = (translated.addresses || []).map(sourcePoolAddress);
      if (addresses.length > 0 && addresses.every(Boolean)) {
        return { kind: 'pool', pool: { name: poolName, addresses } };
      }
      // Can't resolve pool addresses (e.g. Check Point hide NAT using a gateway name)
      comments.push('NAT pool address could not be resolved — using interface NAT');
      return interfaceThen;
    }
    if (translated.type === 'static') {
      const poolName = naming.generated(`nat_rules[${ruleIndex}]`, 'static-source-nat-pool');
      const resolved = translatedAddress(translated.address);
      if (resolved) {
        return { kind: 'pool', pool: { name: poolName, addresses: [{ prefix: withPrefix(resolved) }] } };
      }
      comments.push(`NAT: translated source "${translated.address}" is not a resolvable IP/prefix — using interface NAT`);
      warnings.push(createWarning('nat', `Source NAT translated address "${translated.address}" could not be resolved to an IP/prefix — fell back to interface NAT`));
      return interfaceThen;
    }
    // Unknown translation type: default to interface NAT (e.g. Check Point hide NAT)
    return interfaceThen;
  };

  const planSourceRuleSets = sourceRules => {
    const ruleSets = [];
    for (const { fromZone, toZone, rules } of groupByZonePair(sourceRules)) {
      const zoneRule = rules[0];
      const zoneRuleIndex = natRuleIndex.get(zoneRule);
      const ruleSet = {
        type: 'source',
        name: ruleSetName('source', fromZone, toZone),
        fromZones: [],
        toZones: [],
        comments: [],
        skipped: false,
        rules: [],
      };
      ruleSets.push(ruleSet);
      if (fromZone === 'any' || toZone === 'any') {
        if (actualZones.length === 0) {
          ruleSet.skipped = true;
          ruleSet.comments.push(`WARNING: NAT rule-set ${fromZone}-to-${toZone} skipped — no defined zones to replace 'any'`);
          warnings.push(createWarning('warning', `nat/source/${fromZone}-to-${toZone}`,
            `NAT rule-set from ${fromZone} to ${toZone} skipped — 'any' is not valid and no zones defined`,
            'Define security zones before NAT rules'));
          continue;
        }
        ruleSet.fromZones = fromZone === 'any'
          ? actualZones : [zoneReference(zoneRuleIndex, zoneRule, 'source', fromZone)];
        ruleSet.toZones = toZone === 'any'
          ? actualZones : [zoneReference(zoneRuleIndex, zoneRule, 'destination', toZone)];
      } else {
        ruleSet.fromZones = [zoneReference(zoneRuleIndex, zoneRule, 'source', fromZone)];
        ruleSet.toZones = [zoneReference(zoneRuleIndex, zoneRule, 'destination', toZone)];
      }

      for (const rule of rules) {
        const ruleIndex = natRuleIndex.get(rule);
        const name = ruleNameFor(ruleIndex, rule, 'source', fromZone, toZone);
        const comments = caveatComments(rule);
        const planned = { name, comments, thenComments: [], skipped: false };
        ruleSet.rules.push(planned);

        const anyAddress = natAnyAddress(rule);
        const options = { anyAddress, allowGroups: true, keepAny: true };
        const source = planMatchField(ruleIndex, rule, 'src_addresses', options);
        const destination = planMatchField(ruleIndex, rule, 'dst_addresses', options);
        const unresolvedField = source.unresolved ? 'src_addresses' : (destination.unresolved ? 'dst_addresses' : null);
        if (unresolvedField) {
          planned.skipped = true;
          comments.push(skipUnresolved('source', name, unresolvedField, rule));
          continue;
        }
        planned.match = {
          source: source.entries,
          destination: destination.entries,
          protocol: planProtocol(rule),
          destinationPort: planPort(rule),
        };
        planned.then = planSourceThen(ruleIndex, rule, planned.thenComments);
        // U-turn/hairpin NAT: persistent-nat for return traffic
        planned.persistent = Boolean(rule._uturn);
      }
    }
    return ruleSets;
  };

  const planDestinationRuleSets = destinationRules => {
    const ruleSets = [];
    for (const { fromZone, toZone, rules } of groupByZonePair(destinationRules)) {
      const zoneRule = rules[0];
      const zoneRuleIndex = natRuleIndex.get(zoneRule);
      const name = ruleSetName('destination', fromZone, toZone);
      const ruleSet = { type: 'destination', name, fromZones: [], toZones: [], comments: [], skipped: false, rules: [] };
      ruleSets.push(ruleSet);
      if (fromZone === 'any') {
        if (actualZones.length === 0) {
          ruleSet.skipped = true;
          ruleSet.comments.push(`WARNING: Destination NAT rule-set ${fromZone}-to-${toZone} skipped — no defined zones`);
          warnings.push(createWarning('warning', `nat/destination/${fromZone}-to-${toZone}`,
            `Destination NAT rule-set from ${fromZone} skipped — 'any' is not valid and no zones defined`,
            'Define security zones before NAT rules'));
          continue;
        }
        ruleSet.fromZones = actualZones;
      } else {
        ruleSet.fromZones = [zoneReference(zoneRuleIndex, zoneRule, 'source', fromZone)];
      }

      for (const advice of planIngressScopeAdvice(rules, zones, mapInterface)) {
        ruleSet.comments.push(`CAVEAT: ${oneLine(advice.caveat)}`);
        const adviceTarget = advice.grouped
          ? name
          : ruleNameFor(natRuleIndex.get(advice.rules[0]), advice.rules[0], 'destination', fromZone, toZone);
        warnings.push(createWarning('warning', `nat/destination/${adviceTarget}`, advice.message, advice.suggestion));
      }

      for (const rule of rules) {
        const ruleIndex = natRuleIndex.get(rule);
        const ruleName = ruleNameFor(ruleIndex, rule, 'destination', fromZone, toZone);
        const comments = [];
        const planned = { name: ruleName, comments, skipped: false };
        ruleSet.rules.push(planned);

        // Resolve the translated destination before any match so an unusable rule is skipped whole.
        let resolvedDestination = null;
        if (rule.translated_dst) {
          const rawDestination = typeof rule.translated_dst === 'string'
            ? rule.translated_dst : rule.translated_dst.address || '';
          if (rawDestination) {
            resolvedDestination = translatedAddress(rawDestination);
            if (!resolvedDestination) {
              planned.skipped = true;
              comments.push(`NAT: destination rule "${ruleName}" skipped — translated destination "${rawDestination}" is not a resolvable IP/prefix`);
              warnings.push(createWarning('nat', `Destination NAT rule "${ruleName}" skipped — translated address "${rawDestination}" could not be resolved to an IP/prefix`));
              continue;
            }
          }
        }

        const destination = planMatchField(ruleIndex, rule, 'dst_addresses',
          { anyAddress: natAnyAddress(rule), allowGroups: false, keepAny: true });
        if (destination.unresolved) {
          planned.skipped = true;
          comments.push(skipUnresolved('destination', ruleName, 'dst_addresses', rule));
          continue;
        }
        planned.match = {
          source: [],
          destination: firstDestination('destination', ruleName, destination.entries, natAnyAddress(rule)),
          protocol: planProtocol(rule),
          destinationPort: planPort(rule),
        };
        planned.then = resolvedDestination
          ? {
            kind: 'destination-pool',
            pool: {
              name: naming.generated(`nat_rules[${ruleIndex}]`, 'destination-nat-pool'),
              prefix: withPrefix(resolvedDestination),
              port: rule.translated_port || null,
            },
          }
          : null;
      }
    }
    return ruleSets;
  };

  const planStaticRuleSets = staticRules => {
    const name = naming.generated(`nat_rules[${natRuleIndex.get(staticRules[0])}]`, 'static-nat-rule-set');
    const ruleSet = { type: 'static', name, fromZones: [], toZones: [], comments: [], skipped: false, rules: [] };
    for (const rule of staticRules) {
      const ruleIndex = natRuleIndex.get(rule);
      const ruleName = ruleNameFor(ruleIndex, rule, 'static', 'STATIC-NAT', '*');
      const comments = [];
      const planned = { name: ruleName, comments, skipped: false };
      ruleSet.rules.push(planned);

      const destination = planMatchField(ruleIndex, rule, 'dst_addresses',
        { anyAddress: natAnyAddress(rule), allowGroups: false, keepAny: false });
      if (destination.unresolved) {
        planned.skipped = true;
        comments.push(skipUnresolved('static', ruleName, 'dst_addresses', rule));
        continue;
      }
      let prefix = null;
      if (rule.translated_src && rule.translated_src.address) {
        prefix = translatedAddress(rule.translated_src.address);
        if (!prefix) {
          planned.skipped = true;
          comments.push(`NAT: static rule "${ruleName}" skipped — translated address "${rule.translated_src.address}" is not a resolvable IP/prefix`);
          warnings.push(createWarning('nat', `Static NAT rule "${ruleName}" skipped — translated address "${rule.translated_src.address}" could not be resolved to an IP/prefix`));
          continue;
        }
      }
      // Junos needs both a destination match and a translated prefix for a static rule.
      if (destination.entries.length === 0 || !prefix) {
        planned.skipped = true;
        comments.push(`NAT: static rule "${ruleName}" skipped — it needs both a destination match and a translated prefix`);
        warnings.push(createWarning('warning', `nat/static/${ruleName}`,
          `Static NAT rule "${ruleName}" skipped — a destination match and a translated prefix could not both be built from the source rule`,
          'Build the static NAT rule manually'));
        continue;
      }
      planned.match = { source: [], destination: firstDestination('static', ruleName, destination.entries, natAnyAddress(rule)), protocol: null, destinationPort: null };
      planned.then = { kind: 'static-prefix', prefix };
    }
    return [ruleSet];
  };

  const rulesOfType = type => natRules.filter(rule => effectiveNatTypes(rule).includes(type));
  const sourceRules = rulesOfType('source');
  const destinationRules = rulesOfType('destination');
  const staticRules = rulesOfType('static');
  return {
    missingZones,
    source: sourceRules.length > 0 ? planSourceRuleSets(sourceRules) : null,
    destination: destinationRules.length > 0 ? planDestinationRuleSets(destinationRules) : null,
    static: staticRules.length > 0 ? planStaticRuleSets(staticRules) : null,
    warnings,
  };
}
