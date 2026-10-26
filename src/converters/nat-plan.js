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
// njsscan regex_dos: false positive. \d excludes the literal dot and hyphen, so no token backtracks.
const IPV4_RANGE = /^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/;  // njsscan-ignore: regex_dos
// Junos accepts at most eight source and eight destination addresses in one source NAT rule.
const NAT_MATCH_ADDRESS_LIMIT = 8;

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

/** Returns '::/0' for rules touching IPv6 addresses, else '0.0.0.0/0'; `valueOf` resolves object names. */
function natAnyAddressWith(rule, valueOf = addr => addr) {
  const allAddrs = [
    ...(rule.src_addresses || []),
    ...(rule.dst_addresses || []),
    ...(rule.translated_src?.addresses || []),
    ...(rule.translated_src?.address ? [rule.translated_src.address] : []),
    ...(rule.translated_dst?.address ? [rule.translated_dst.address] : []),
    ...(typeof rule.translated_dst === 'string' ? [rule.translated_dst] : []),
  ];
  return allAddrs.some(a => a && typeof a === 'string' && String(valueOf(a)).includes(':')) ? '::/0' : '0.0.0.0/0';
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

/** Parses "A.B.C.D/len" into { address, length } (address as an integer), or null for anything else. */
function parseIpv4Prefix(text) {
  const parts = String(text).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!parts) return null;
  const octets = parts.slice(1, 5).map(Number);
  const length = Number(parts[5]);
  if (octets.some(octet => octet > 255) || length > 32) return null;
  return { address: octets.reduce((total, octet) => total * 256 + octet, 0), length };
}

/** First and last address of an IPv4 prefix. */
function prefixBounds({ address, length }) {
  const size = 2 ** (32 - length);
  const first = Math.floor(address / size) * size;
  return { first, last: first + size - 1 };
}

const ipv4ToInteger = text => text.split('.').reduce((total, octet) => total * 256 + Number(octet), 0);
const isIpv4Address = text => /^\d{1,3}(\.\d{1,3}){3}$/.test(text) && text.split('.').every(octet => Number(octet) <= 255);

/**
 * Expands an IPv4 range into the minimal CIDR prefixes that cover it exactly.
 *
 * @param {string} start - First address, dotted quad
 * @param {string} end - Last address, dotted quad
 * @returns {string[]|null} Prefixes ("A.B.C.D/len"), or null when an address is invalid or start > end
 */
export function ipv4RangeToPrefixes(start, end) {
  if (!isIpv4Address(start) || !isIpv4Address(end)) return null;
  let next = ipv4ToInteger(start);
  const last = ipv4ToInteger(end);
  if (next > last) return null;
  const prefixes = [];
  while (next <= last) {
    // Largest power-of-two block that is aligned at `next` and still ends by `last`.
    let size = next === 0 ? 2 ** 32 : Math.abs(next & -next);
    while (next + size - 1 > last) size /= 2;
    const dotted = [24, 16, 8, 0].map(shift => Math.floor(next / 2 ** shift) % 256).join('.');
    prefixes.push(`${dotted}/${32 - Math.log2(size)}`);
    next += size;
  }
  return prefixes;
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
 * - then: { kind: 'interface' } | { kind: 'off' } | { kind: 'pool', pool: { name, addresses: [{ prefix, to? }], noPortTranslation?, hostAddressBase? } }
 *       | { kind: 'destination-pool', pool: { name, prefix, port } } | { kind: 'static-prefix', prefix }
 * - comments are plain text; the emitters add their own comment syntax
 * - proxyArp: [{ interface, address, to? }] host addresses and ranges (/32 forms) the SRX must
 *   answer ARP for, named by the mapped interface whose connected subnet holds them
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
      warnings.push(createWarning('warning', `nat/address/${addr}`,
        `NAT match address "${addr}" is not a known address object — skipped`,
        'Define the address object, or use an IP/prefix in the NAT rule'));
      return null;
    }
    // Skip FQDN / dns-name values (not usable in NAT match)
    if (!/^\d+\.\d+\.\d+\.\d+/.test(resolved) && !/^[0-9a-fA-F:]+/.test(resolved)) {
      warnings.push(createWarning('warning', `nat/address/${addr}`,
        `NAT match address "${addr}" resolves to FQDN "${resolved}" — skipped (Junos NAT requires IP)`,
        'Replace the FQDN with an IP/prefix in the NAT rule'));
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
  // Object names carry no colon, so the wildcard family follows the address each name resolves to.
  const natAnyAddress = rule => natAnyAddressWith(rule, addr => addrLookup[rawAddressNames.get(addr) || addr] || addr);
  const translatedAddress = rawAddress => (
    resolveNatAddress(rawAddressNames.get(rawAddress) || rawAddress)
  );
  // A "start-end" source pool range (FortiGate ippool) is Junos "A/32 to B/32".
  // A range object (ASA `range A B`) resolves to the same "A-B" form.
  const sourcePoolAddress = rawAddress => {
    const literal = String(rawAddress || '');
    const resolved = IPV4_RANGE.test(literal) ? literal : translatedAddress(rawAddress);
    if (!resolved) return null;
    const range = resolved.match(IPV4_RANGE);
    return range ? { prefix: `${range[1]}/32`, to: `${range[2]}/32` } : { prefix: withPrefix(resolved) };
  };
  const providerInterfaceIp = interfaceName => {
    if (!interfaceName) return null;
    const iface = (interfaces || []).find(item => item.name === interfaceName && (item.ip || item.ipv6));
    const host = String((iface && (iface.ip || iface.ipv6)) || '').split('/')[0];
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return `${host}/32`;
    if (host.includes(':')) return `${host}/128`;
    return null;
  };

  // NAT addresses the SRX may have to answer ARP for; narrowed to proxyArp at the end.
  const proxyCandidates = [];
  // Each candidate keeps the zones its traffic uses (egress for pools, ingress for DNAT) so
  // proxy ARP lands only on an interface the rule can actually see.
  const addProxyCandidates = (candidates, scopeZones) => (
    proxyCandidates.push(...candidates.map(candidate => ({ ...candidate, scopeZones })))
  );
  const destinationCandidates = (rule, entries, anyAddress) => (
    rule.arp_reply === false ? [] : entries
      .filter(entry => entry.kind === 'prefix' && entry.value !== anyAddress)
      .map(entry => ({ prefix: withPrefix(entry.value) }))
  );

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
      && (type === 'static' || natDestinationZones(rule).includes(toZone))
    ));
    return naming.generated(`nat_rules[${ownerIndex}]`, `${type}-nat-rule-set:${encodeJunosZonePair(fromZone, toZone)}`);
  };
  const ruleNameFor = (ruleIndex, rule, type, fromZone, toZone) => {
    let occurrence = 0;
    for (const candidateType of effectiveNatTypes(rule)) {
      const pairs = candidateType === 'static'
        ? natSourceZones(rule).map(source => [source, '*'])
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
  const planMatchField = (ruleIndex, rule, field, { anyAddress, allowGroups, keepAny, limit = Infinity }) => {
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
        // Junos NAT match fields take prefixes, not "start-end", so a range becomes its covering prefixes.
        const range = resolved.match(IPV4_RANGE);
        const prefixes = range ? ipv4RangeToPrefixes(range[1], range[2]) : [resolved];
        if (!prefixes || (!range && /^[0-9a-fA-F:]+-[0-9a-fA-F:]+$/.test(resolved))) {
          warnings.push(createWarning(
            'warning',
            `nat/${rule.type || 'source'}/${rule.name || ruleIndex}`,
            `NAT match address "${oneLine(addr)}" is a range (${oneLine(resolved)}) that cannot be expressed as IPv4 prefixes — skipped`,
            'Replace the range with IPv4 prefixes, then add the NAT rule manually',
          ));
          continue;
        }
        entries.push(...prefixes.map(prefix => ({ kind: 'prefix', value: prefix })));
        succeeded += 1;
      }
    }
    // Over the limit the rule can't commit, and dropping addresses would change what it matches.
    if (entries.length > limit) return { entries: [], unresolved: true, overLimit: entries.length };
    return { entries, unresolved: addresses.length > 0 && succeeded === 0 };
  };
  const skipUnresolved = (type, ruleName, field, rule, fieldPlan = {}) => {
    const label = field === 'src_addresses' ? 'source' : 'destination';
    const listed = oneLine(rule[field].join(', '));
    if (fieldPlan.overLimit) {
      warnings.push(createWarning(
        'warning',
        `nat/${type}/${ruleName}`,
        `NAT rule "${ruleName}" skipped — its ${label} addresses (${listed}) need ${fieldPlan.overLimit} prefixes, and Junos allows ${NAT_MATCH_ADDRESS_LIMIT} per rule`,
        `Split the rule so each part matches at most ${NAT_MATCH_ADDRESS_LIMIT} ${label} addresses, then add it manually`,
      ));
      return `NAT: ${type} rule "${ruleName}" skipped — ${fieldPlan.overLimit} ${label} prefixes exceed the Junos limit of ${NAT_MATCH_ADDRESS_LIMIT}`;
    }
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

  // One-way static NAT keeps ports and, for a subnet, host N -> public host N, so both sides must match in size.
  const oneWayPoolMapping = (sourceEntries, publicPrefix) => {
    const privateEntries = sourceEntries.filter(entry => entry.kind === 'prefix');
    if (privateEntries.length !== 1 || privateEntries.length !== sourceEntries.length) {
      return { error: 'its source is not a single address or subnet' };
    }
    const privatePrefix = withPrefix(privateEntries[0].value);
    const lengthOf = prefix => prefix.split('/')[1];
    if (lengthOf(privatePrefix) !== lengthOf(publicPrefix)) {
      return { error: `its private side (${privatePrefix}) and public side (${publicPrefix}) differ in size` };
    }
    const isHost = lengthOf(privatePrefix) === (privatePrefix.includes(':') ? '128' : '32');
    return isHost ? {} : { hostAddressBase: privatePrefix };
  };

  const planSourceThen = (ruleIndex, rule, comments, sourceEntries) => {
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
        // A pool range the source disabled ARP replies for is left to the user's own ARP setup.
        const arpDisabled = translated.arp_reply_disabled || [];
        if (rule.arp_reply !== false) addProxyCandidates(addresses.filter((_, index) => !arpDisabled.includes(translated.addresses[index])), natDestinationZones(rule));
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
        const publicPrefix = withPrefix(resolved);
        const pool = { name: poolName, addresses: [{ prefix: publicPrefix }] };
        if (translated.one_way) {
          const mapping = oneWayPoolMapping(sourceEntries, publicPrefix);
          if (mapping.error) return { kind: 'skip', reason: mapping.error };
          pool.noPortTranslation = true;
          if (mapping.hostAddressBase) pool.hostAddressBase = mapping.hostAddressBase;
        }
        if (rule.arp_reply !== false) addProxyCandidates([{ prefix: publicPrefix }], natDestinationZones(rule));
        return { kind: 'pool', pool };
      }
      if (translated.one_way) return { kind: 'skip', reason: `its translated address "${oneLine(translated.address)}" could not be resolved to an IP/prefix` };
      comments.push(`NAT: translated source "${translated.address}" is not a resolvable IP/prefix — using interface NAT`);
      warnings.push(createWarning('warning', `nat/source/${rule.name || ruleIndex}`,
        `Source NAT translated address "${translated.address}" could not be resolved to an IP/prefix — fell back to interface NAT`,
        'Check the translated address; interface NAT may not match the source rule'));
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
        const options = { anyAddress, allowGroups: true, keepAny: true, limit: NAT_MATCH_ADDRESS_LIMIT };
        const source = planMatchField(ruleIndex, rule, 'src_addresses', options);
        const destination = planMatchField(ruleIndex, rule, 'dst_addresses', options);
        const unresolvedField = source.unresolved ? 'src_addresses' : (destination.unresolved ? 'dst_addresses' : null);
        if (unresolvedField) {
          planned.skipped = true;
          comments.push(skipUnresolved('source', name, unresolvedField, rule, source.unresolved ? source : destination));
          continue;
        }
        planned.match = {
          source: source.entries,
          destination: destination.entries,
          protocol: planProtocol(rule),
          destinationPort: planPort(rule),
        };
        planned.then = planSourceThen(ruleIndex, rule, planned.thenComments, source.entries);
        if (planned.then.kind === 'skip') {
          planned.skipped = true;
          comments.push(`WARNING: Static NAT rule ${name} skipped — ${planned.then.reason}`);
          warnings.push(createWarning('warning', `nat/static/${rule.name || ruleIndex}`,
            `Static NAT rule "${oneLine(rule.name || ruleIndex)}" skipped — ${planned.then.reason}, which a one-way Junos source pool cannot express`,
            'Build the NAT rule manually'));
          continue;
        }
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
              warnings.push(createWarning('warning', `nat/destination/${ruleName}`,
                `Destination NAT rule "${ruleName}" skipped — translated address "${rawDestination}" could not be resolved to an IP/prefix`,
                'Build the destination NAT rule manually'));
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
        if (resolvedDestination) addProxyCandidates(destinationCandidates(rule, planned.match.destination, natAnyAddress(rule)), natSourceZones(rule));
      }
    }
    return ruleSets;
  };

  // Junos static rule-sets take only a "from"; rules group by the zone their traffic arrives from.
  const planStaticRuleSets = staticRules => {
    const groups = new Map();
    for (const rule of staticRules) {
      for (const fromZone of natSourceZones(rule)) {
        if (!groups.has(fromZone)) groups.set(fromZone, []);
        groups.get(fromZone).push(rule);
      }
    }
    const ruleSets = [];
    for (const [fromZone, rules] of groups) {
      const zoneRule = rules[0];
      const name = ruleSetName('static', fromZone, '*');
      const ruleSet = { type: 'static', name, fromZones: [], toZones: [], comments: [], skipped: false, rules: [] };
      ruleSets.push(ruleSet);
      if (fromZone === 'any') {
        if (actualZones.length === 0) {
          ruleSet.skipped = true;
          ruleSet.comments.push(`WARNING: Static NAT rule-set ${fromZone} skipped — no defined zones`);
          warnings.push(createWarning('warning', `nat/static/${fromZone}`,
            `Static NAT rule-set from ${fromZone} skipped — 'any' is not valid and no zones defined`,
            'Define security zones before NAT rules'));
          continue;
        }
        ruleSet.fromZones = actualZones;
      } else {
        ruleSet.fromZones = [zoneReference(natRuleIndex.get(zoneRule), zoneRule, 'source', fromZone)];
      }

      for (const rule of rules) {
        const ruleIndex = natRuleIndex.get(rule);
        const ruleName = ruleNameFor(ruleIndex, rule, 'static', fromZone, '*');
        const comments = [];
        const planned = { name: ruleName, comments, skipped: false };
        ruleSet.rules.push(planned);

        // One mapping in several rule-sets would give the same address two static translations.
        const ruleZones = natSourceZones(rule);
        if (ruleZones.length > 1) {
          planned.skipped = true;
          comments.push(`NAT: static rule "${ruleName}" skipped — it is reached from ${ruleZones.length} zones (${oneLine(ruleZones.join(', '))})`);
          if (fromZone === ruleZones[0]) {
            warnings.push(createWarning('warning', `nat/static/${oneLine(rule.name || ruleIndex)}`,
              `Static NAT rule "${oneLine(rule.name || ruleIndex)}" skipped — it is reached from several zones (${oneLine(ruleZones.join(', '))}), and one mapping must live in one static rule-set`,
              'Build one static NAT rule-set with all of these from zones manually'));
          }
          continue;
        }

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
            warnings.push(createWarning('warning', `nat/static/${ruleName}`,
              `Static NAT rule "${ruleName}" skipped — translated address "${rule.translated_src.address}" could not be resolved to an IP/prefix`,
              'Build the static NAT rule manually'));
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
        const matchEntries = firstDestination('static', ruleName, destination.entries, natAnyAddress(rule))
          .map(entry => ({ ...entry, value: withPrefix(entry.value) }));
        // Static NAT maps one block onto another, so both sides must have the same prefix length.
        const publicLength = withPrefix(matchEntries[0].value).split('/')[1];
        if (publicLength !== withPrefix(prefix).split('/')[1]) {
          planned.skipped = true;
          comments.push(`NAT: static rule "${ruleName}" skipped — public ${matchEntries[0].value} and private ${prefix} differ in prefix length`);
          warnings.push(createWarning('warning', `nat/static/${ruleName}`,
            `Static NAT rule "${ruleName}" skipped — public ${oneLine(matchEntries[0].value)} and private ${oneLine(prefix)} differ in prefix length, and Junos static NAT maps equal-size blocks`,
            'Build the static NAT rule manually'));
          continue;
        }
        planned.match = { source: [], destination: matchEntries, protocol: null, destinationPort: null };
        planned.then = { kind: 'static-prefix', prefix };
        // The SRX must answer ARP for the public address, scoped to the zones the traffic arrives from.
        addProxyCandidates(destinationCandidates(rule, matchEntries, natAnyAddress(rule)), natSourceZones(rule));
      }
    }
    return ruleSets;
  };

  const rulesOfType = type => natRules.filter(rule => effectiveNatTypes(rule).includes(type));
  const sourceRules = rulesOfType('source');
  const destinationRules = rulesOfType('destination');
  const staticRules = rulesOfType('static');
  const source = sourceRules.length > 0 ? planSourceRuleSets(sourceRules) : null;
  const destination = destinationRules.length > 0 ? planDestinationRuleSets(destinationRules) : null;
  const staticSets = staticRules.length > 0 ? planStaticRuleSets(staticRules) : null;
  return {
    missingZones,
    source,
    destination,
    static: staticSets,
    proxyArp: planProxyArp(proxyCandidates, interfaces, zones, mapInterface, warnings),
    warnings,
  };
}

/**
 * Picks the interface each NAT address belongs to by connected subnet, so the
 * SRX answers ARP for it (it commits but passes no traffic otherwise).
 * Skips addresses no interface owns (the upstream router routes them), the
 * interface's own addresses, and anything ambiguous or wider than a host or
 * range, warning where a person has to decide.
 *
 * shortcut: IPv4 only (proxy-ndp is not emitted), and interface ips other than
 * "A.B.C.D/len" (dhcp, bare addresses) are ignored; upgrade if either shows up.
 */
function planProxyArp(candidates, interfaces, zones, mapInterface, warnings) {
  // Zone membership lives on zones for most parsers and on interfaces for some (SonicWall).
  const zoneInterfaces = new Map((zones || []).map(zone => [zone.name, new Set(zone.interfaces || [])]));
  for (const iface of interfaces || []) {
    if (!iface.zone || !iface.name) continue;
    if (!zoneInterfaces.has(iface.zone)) zoneInterfaces.set(iface.zone, new Set());
    zoneInterfaces.get(iface.zone).add(iface.name);
  }
  // Interfaces the candidate's zones hold; null for "any" (subnet alone decides), or the
  // zones with no known member, where guessing could claim an address the rule never sees.
  const eligibleInterfaces = scopeZones => {
    if (!scopeZones || scopeZones.includes('any')) return { eligible: null, unknown: [] };
    const unknown = scopeZones.filter(zoneName => !(zoneInterfaces.get(zoneName)?.size > 0));
    const eligible = new Set(scopeZones.flatMap(zoneName => [...(zoneInterfaces.get(zoneName) || [])]));
    return { eligible, unknown };
  };
  const connected = (interfaces || [])
    // Tunnel and loopback interfaces don't ARP; not every parser types them, so check names too.
    .filter(iface => !['tunnel', 'loopback'].includes(iface.type) && !/^(tunnel|loopback|st\d|lo\d)/i.test(iface.name || ''))
    .map(iface => ({ name: iface.name, ip: parseIpv4Prefix(iface.ip), proxyArp: iface.proxy_arp !== false }))
    // 0.0.0.0/x is an unset address (FortiOS default), not a subnet that holds every NAT address.
    .filter(iface => iface.name && iface.ip && iface.ip.address !== 0)
    .map(iface => ({ ...iface, ...prefixBounds(iface.ip) }));
  const ownAddresses = connected.map(iface => iface.ip.address);
  const inside = (iface, address) => address >= iface.first && address <= iface.last;
  const warned = new Set();
  const warn = message => {
    if (warned.has(message)) return;
    warned.add(message);
    warnings.push(createWarning('warning', 'nat/proxy-arp', message,
      'Add "set security nat proxy-arp interface <ifl> address <address>" by hand if the SRX must answer ARP for it'));
  };

  const proxyArp = [];
  const seen = new Set();
  for (const candidate of candidates) {
    const start = parseIpv4Prefix(candidate.prefix);
    const end = candidate.to ? parseIpv4Prefix(candidate.to) : start;
    if (!start || !end) continue;
    const label = oneLine(candidate.to ? `${candidate.prefix} to ${candidate.to}` : candidate.prefix);
    // A prefix stands for its whole block, a range for its two ends.
    const low = prefixBounds(start).first;
    const high = candidate.to ? prefixBounds(end).first : prefixBounds(start).last;
    // Any overlap counts, including a range that encloses a whole subnet.
    const { eligible, unknown } = eligibleInterfaces(candidate.scopeZones);
    const touching = connected.filter(iface => low <= iface.last && high >= iface.first
      && (!eligible || eligible.has(iface.name)));
    // An address only an unknown zone could reach can't be placed safely.
    if (touching.length === 0 && unknown.length > 0 && connected.some(iface => low <= iface.last && high >= iface.first)) {
      warn(`NAT address ${label} is on a connected subnet, but zone ${oneLine(unknown.join(', '))} has no known interfaces — no proxy ARP emitted`);
      continue;
    }
    if (touching.length === 0) continue;
    if (touching.length > 1) {
      warn(`NAT address ${label} is inside more than one interface subnet (${oneLine(touching.map(iface => iface.name).join(', '))}) — no proxy ARP emitted`);
      continue;
    }
    const [owner] = touching;
    if (!inside(owner, low) || !inside(owner, high)) {
      warn(`NAT address ${label} is only partly inside ${oneLine(owner.name)}'s subnet — no proxy ARP emitted`);
      continue;
    }
    if (!candidate.to && start.length < 32) {
      warn(`NAT address ${label} is a prefix inside ${oneLine(owner.name)}'s subnet — not proxied as a whole (it could capture the upstream gateway's address)`);
      continue;
    }
    // The SRX already answers for its own address; a range around it needs a person to split it.
    if (ownAddresses.some(own => own >= low && own <= high)) {
      if (candidate.to) warn(`NAT address ${label} includes an interface's own address — no proxy ARP emitted`);
      continue;
    }
    // The source turned proxy ARP off on this interface (ASA `sysopt noproxyarp`).
    if (!owner.proxyArp) continue;
    const key = `${owner.name}|${candidate.prefix}|${candidate.to || ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    proxyArp.push({ interface: mapInterface(owner.name), address: candidate.prefix, ...(candidate.to ? { to: candidate.to } : {}) });
  }
  return proxyArp;
}
