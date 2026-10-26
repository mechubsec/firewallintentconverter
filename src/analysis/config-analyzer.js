/**
 * Config Analyzer — Pre-conversion analysis engine.
 *
 * Adapted from fatcat/converter's analysis-engine.js to work with our
 * intermediate config schema. Runs 7 categories of checks.
 *
 * Key schema differences from fatcat IR:
 *   fatcat p.src_zone (string)    → ours p.src_zones (array)
 *   fatcat p.src_addr (array)     → ours p.src_addresses (array)
 *   fatcat p.dst_addr (array)     → ours p.dst_addresses (array)
 *   fatcat p.service (array)      → ours p.services (array)
 *   fatcat p.enabled (bool)       → ours p.disabled (bool, inverted)
 *   fatcat p.log (bool)           → ours p.log_end (bool)
 *   fatcat p.id (number)          → ours p._rule_index (number) or p.name
 *   fatcat r.orig_src             → ours r.src_addresses (array)
 */

import { findPolicyReferenceIssues } from '../security/policy-reference-integrity.js';

/** Heuristic: is this an external/untrusted zone (by name)? */
function isExternalZone(zoneName) {
  return /untrust|internet|outside|\bwan\b|external|public|inet/i.test(String(zoneName || ''));
}

/** Threshold for large group detection (issue #50). */
const LARGE_GROUP_THRESHOLD = 50;

/** Threshold for nested group depth detection (issue #50). */
const NESTED_GROUP_THRESHOLD = 3;

/**
 * True if a crypto token denotes a weak cipher (DES/3DES family).
 * @param {string} token - Crypto token (e.g., "des", "3des-cbc", "des-cbc")
 * @returns {boolean} - True if the token contains 'des'
 */
function isWeakEncToken(token) {
  return token.includes('des');
}

/**
 * True if a token denotes weak integrity/hash (MD5 or SHA-1 family).
 * @param {string} token - Auth token (e.g., "md5", "hmac-md5-96", "sha1", "hmac-sha1-96")
 * @returns {boolean} - True if the token contains 'md5', 'sha1', or 'sha-1'
 */
function isWeakAuthToken(token) {
  return token.includes('md5') || token.includes('sha1') || token.includes('sha-1');
}

/**
 * Parse a Junos/PAN dh-group token like "group14" → 14 (NaN if not parseable).
 * @param {string} v - DH group string (e.g., "group14", "group2")
 * @returns {number} - Group number or NaN
 */
function dhGroupNumber(v) {
  const m = /group\s*(\d+)/i.exec(String(v || ''));
  return m ? parseInt(m[1], 10) : NaN;
}

/**
 * Split a comma/space-joined crypto list into lowercased tokens.
 * @param {string} v - Crypto string (e.g., "aes-256-cbc,3des")
 * @returns {string[]} - Array of lowercased tokens
 */
function cryptoTokens(v) {
  return String(v || '')
    .split(/[,\s]+/)
    .map(s => s.trim().toLowerCase())
    .filter(Boolean);
}

export const AnalysisEngine = {
  _yield() { return new Promise(r => setTimeout(r, 0)); },

  async run(config, onProgress) {
    const step = async (label, fn) => {
      if (onProgress) onProgress(label);
      await this._yield();
      return fn();
    };

    this._markUsed(config);

    return [
      await step('Checking for unused objects...', () => this._unusedObjects(config)),
      await step('Detecting shadowed policies...', () => this._shadowedPolicies(config)),
      await step('Checking for redundant rules...', () => this._redundantRules(config)),
      await step('Detecting shadowed NAT rules...', () => this._shadowedNat(config)),
      await step('Detecting duplicate objects...', () => this._duplicateObjects(config)),
      await step('Checking for disabled policies...', () => this._disabledPolicies(config)),
      await step('Checking logging coverage...', () => this._loggingOff(config)),
      await step('Checking for permissive rules...', () => this._permissivePolicies(config)),
      await step('Checking for empty groups...', () => this._emptyGroups(config)),
      await step('Checking for never-hit policies...', () => this._neverHitPolicies(config)),
      await step('Checking for inbound any-source rules...', () => this._inboundAny(config)),
      await step('Checking for exposed risky services...', () => this._exposedServices(config)),
      await step('Checking for broad addresses...', () => this._broadAddresses(config)),
      await step('Checking for orphan references...', () => this._orphanReferences(config)),
      await step('Checking for deny-all tail rule...', () => this._noDenyAll(config)),
      await step('Checking for empty policy set...', () => this._emptyPolicySet(config)),
      await step('Checking for zones without policy...', () => this._zonesWithoutPolicy(config)),
      await step('Checking for remote logging...', () => this._logCompleteness(config)),
      await step('Checking for large groups...', () => this._largeGroups(config)),
      await step('Checking for nested groups...', () => this._nestedGroups(config)),
      await step('Checking for undescribed objects...', () => this._undescribedObjects(config)),
      await step('Checking for undescribed policies...', () => this._undescribedPolicies(config)),
      await step('Checking for weak IKE crypto...', () => this._weakIke(config)),
      await step('Checking for weak IPsec crypto...', () => this._weakIpsec(config)),
      await step('Checking for zones without screen...', () => this._zonesWithoutScreen(config)),
    ];
  },

  // ── Mark used/unused ──────────────────────────────────────────────────────
  _markUsed(config) {
    const addrObjs = config.address_objects || [];
    const addrGrps = config.address_groups || [];
    const svcObjs = config.service_objects || [];
    const svcGrps = config.service_groups || [];
    const appGrps = config.application_groups || [];

    addrObjs.forEach(o => { o._used = false; });
    addrGrps.forEach(g => { g._used = false; });
    svcObjs.forEach(o => { o._used = false; });
    svcGrps.forEach(g => { g._used = false; });
    appGrps.forEach(g => { g._used = false; });

    const markAddr = (name) => {
      if (!name || name === 'any') return;
      const o = addrObjs.find(x => x.name === name);
      if (o) o._used = true;
      const g = addrGrps.find(x => x.name === name);
      if (g) g._used = true;
    };
    const markSvc = (name) => {
      if (!name || name === 'any' || name === 'application-default') return;
      const o = svcObjs.find(x => x.name === name);
      if (o) o._used = true;
      const g = svcGrps.find(x => x.name === name);
      if (g) g._used = true;
    };
    const markAppGrp = (name) => {
      if (!name) return;
      const g = appGrps.find(x => x.name === name);
      if (g) g._used = true;
    };

    // OUR SCHEMA: src_addresses, dst_addresses, services, applications
    for (const p of (config.security_policies || [])) {
      (p.src_addresses || []).forEach(markAddr);
      (p.dst_addresses || []).forEach(markAddr);
      (p.services || []).forEach(markSvc);
      (p.applications || []).forEach(markAppGrp);
    }

    // NAT rules: OUR SCHEMA uses src_addresses/dst_addresses arrays
    for (const r of (config.nat_rules || [])) {
      (r.src_addresses || []).forEach(markAddr);
      (r.dst_addresses || []).forEach(markAddr);
      // Translated addresses (pools, DNAT targets, the private side of static NAT) are references too.
      markAddr(r.translated_src?.address);
      (r.translated_src?.addresses || []).forEach(markAddr);
      markAddr(typeof r.translated_dst === 'string' ? r.translated_dst : r.translated_dst?.address);
    }

    // Cascade: members of used groups are also "used"
    let changed = true;
    while (changed) {
      changed = false;
      for (const g of addrGrps.filter(x => x._used)) {
        for (const m of (g.members || [])) {
          const o = addrObjs.find(x => x.name === m);
          if (o && !o._used) { o._used = true; changed = true; }
          const sg = addrGrps.find(x => x.name === m);
          if (sg && !sg._used) { sg._used = true; changed = true; }
        }
      }
      for (const g of svcGrps.filter(x => x._used)) {
        for (const m of (g.members || [])) {
          const o = svcObjs.find(x => x.name === m);
          if (o && !o._used) { o._used = true; changed = true; }
          const sg = svcGrps.find(x => x.name === m);
          if (sg && !sg._used) { sg._used = true; changed = true; }
        }
      }
    }
  },

  // ── Unused objects ────────────────────────────────────────────────────────
  _unusedObjects(config) {
    const items = [
      ...(config.address_objects || []).filter(o => !o._used).map(o => ({ key: o.name, label: o.name, kind: 'address object' })),
      ...(config.address_groups || []).filter(g => !g._used).map(g => ({ key: g.name, label: g.name, kind: 'address group' })),
      ...(config.service_objects || []).filter(o => !o._used).map(o => ({ key: o.name, label: o.name, kind: 'service object' })),
      ...(config.service_groups || []).filter(g => !g._used).map(g => ({ key: g.name, label: g.name, kind: 'service group' })),
      ...(config.application_groups || []).filter(g => !g._used).map(g => ({ key: g.name, label: g.name, kind: 'application group' })),
    ];
    const count = items.length;
    if (!count) return { id: 'unused_objects', count: 0, items: [], description: 'No unused objects found.' };
    const names = items.map(i => i.key);
    return {
      id: 'unused_objects', count, items,
      description: `${count} object${count !== 1 ? 's' : ''} not referenced by any security policy, NAT rule, or group: ${names.slice(0, 5).join(', ')}${names.length > 5 ? ` + ${names.length - 5} more` : ''}.`,
    };
  },

  // ── Shadowed policies ─────────────────────────────────────────────────────
  _shadowedPolicies(config) {
    const policies = config.security_policies || [];
    const enabled = policies.filter(p => !p.disabled);
    // Skip shadow detection for very large rulesets (O(n^2))
    if (enabled.length > 2000) {
      return { id: 'shadowed', count: 0, items: [], description: 'Shadow detection skipped for configs with over 2000 enabled rules.' };
    }
    const shadowed = [];
    for (let i = 1; i < enabled.length; i++) {
      for (let j = 0; j < i; j++) {
        if (this._shadows(enabled[j], enabled[i])) {
          shadowed.push({ policy: enabled[i], shadowedBy: enabled[j] });
          break;
        }
      }
    }
    const count = shadowed.length;
    if (!count) return { id: 'shadowed', count: 0, items: [], description: 'No shadowed policies found.' };
    const pKey = (p) => p._rule_index != null ? String(p._rule_index) : p.name;
    const pLabel = (p) => p._rule_index != null ? `#${p._rule_index} ${p.name}` : p.name;
    const items = shadowed.map(s => ({
      key: pKey(s.policy),
      label: `${pLabel(s.policy)} — shadowed by ${pLabel(s.shadowedBy)}`,
    }));
    const desc = shadowed.slice(0, 3)
      .map(s => `${pLabel(s.policy)} shadowed by ${pLabel(s.shadowedBy)}`)
      .join('; ');
    return {
      id: 'shadowed', count, items,
      description: `${count} polic${count !== 1 ? 'ies are' : 'y is'} fully shadowed by an earlier, broader rule. ${desc}.`,
    };
  },

  _shadows(earlier, later) {
    // OUR SCHEMA: src_zones/dst_zones are arrays
    const eZones = earlier.src_zones?.length ? earlier.src_zones : ['any'];
    const lZones = later.src_zones?.length ? later.src_zones : ['any'];
    const eDZones = earlier.dst_zones?.length ? earlier.dst_zones : ['any'];
    const lDZones = later.dst_zones?.length ? later.dst_zones : ['any'];

    const srcZoneOk = eZones.includes('any') || lZones.every(z => eZones.includes(z));
    const dstZoneOk = eDZones.includes('any') || lDZones.every(z => eDZones.includes(z));

    // OUR SCHEMA: src_addresses, dst_addresses, services
    const srcAddrOk = !earlier.negate_source && (earlier.src_addresses || []).includes('any');
    const dstAddrOk = !earlier.negate_destination && (earlier.dst_addresses || []).includes('any');
    const svcOk = (earlier.services || []).includes('any');

    return srcZoneOk && dstZoneOk && srcAddrOk && dstAddrOk && svcOk;
  },

  // ── Shadowed NAT rules (issue #57) ───────────────────────────────────────
  /**
   * True if `earlier` NAT rule shadows `later` NAT rule (conservative).
   * @param {object} earlier - Earlier NAT rule
   * @param {object} later - Later NAT rule
   * @returns {boolean} - True if earlier shadows later
   */
  _natShadows(earlier, later) {
    // Different NAT types never shadow each other
    if (earlier.type !== later.type) return false;

    // Read zones from source_zones/src_zones and destination_zones/dst_zones
    const eSrcZones = (earlier.source_zones || earlier.src_zones || []).length
      ? (earlier.source_zones || earlier.src_zones)
      : ['any'];
    const lSrcZones = (later.source_zones || later.src_zones || []).length
      ? (later.source_zones || later.src_zones)
      : ['any'];
    const eDstZones = (earlier.destination_zones || earlier.dst_zones || []).length
      ? (earlier.destination_zones || earlier.dst_zones)
      : ['any'];
    const lDstZones = (later.destination_zones || later.dst_zones || []).length
      ? (later.destination_zones || later.dst_zones)
      : ['any'];

    // Zone superset checks
    const srcZoneOk = eSrcZones.includes('any') || lSrcZones.every(z => eSrcZones.includes(z));
    const dstZoneOk = eDstZones.includes('any') || lDstZones.every(z => eDstZones.includes(z));

    // Earlier must match any source AND any destination
    const srcAddrOk = (earlier.src_addresses || []).includes('any');
    const dstAddrOk = (earlier.dst_addresses || []).includes('any');

    // Earlier must be protocol/port unconstrained (conservative)
    const serviceOk = !earlier.match_protocol && !earlier.match_port;

    return srcZoneOk && dstZoneOk && srcAddrOk && dstAddrOk && serviceOk;
  },

  /**
   * Detect shadowed NAT rules (issue #57).
   * @param {object} config - Intermediate config
   * @returns {object} - Finding { id, count, items, description }
   */
  _shadowedNat(config) {
    const rules = config.nat_rules || [];

    // Skip shadow detection for very large NAT rulesets (O(n^2))
    if (rules.length > 2000) {
      return {
        id: 'nat_shadowed',
        count: 0,
        items: [],
        description: 'NAT shadow detection skipped for over 2000 rules.',
      };
    }

    const shadowed = [];
    for (let i = 1; i < rules.length; i++) {
      for (let j = 0; j < i; j++) {
        if (this._natShadows(rules[j], rules[i])) {
          shadowed.push({ rule: rules[i], shadowedBy: rules[j] });
          break; // Stop at first shadowing rule for this later rule
        }
      }
    }

    const count = shadowed.length;
    if (!count) {
      return {
        id: 'nat_shadowed',
        count: 0,
        items: [],
        description: 'No shadowed NAT rules found.',
      };
    }

    const nKey = (r) => r._rule_index != null ? String(r._rule_index) : r.name;
    const nLabel = (r) => r._rule_index != null ? `#${r._rule_index} ${r.name}` : r.name;

    const items = shadowed.map(s => ({
      key: nKey(s.rule),
      label: `${nLabel(s.rule)} — shadowed by ${nLabel(s.shadowedBy)}`,
    }));

    const firstFew = shadowed.slice(0, 3)
      .map(s => `${nLabel(s.rule)} shadowed by ${nLabel(s.shadowedBy)}`)
      .join('; ');

    return {
      id: 'nat_shadowed',
      count,
      items,
      description: `${count} NAT rule${count !== 1 ? 's are' : ' is'} fully shadowed by an earlier, broader rule. ${firstFew}.`,
    };
  },

  // ── Duplicate objects ─────────────────────────────────────────────────────
  _duplicateObjects(config) {
    const pairs = [];
    const addrObjs = config.address_objects || [];
    const svcObjs = config.service_objects || [];

    for (let i = 0; i < addrObjs.length; i++) {
      for (let j = i + 1; j < addrObjs.length; j++) {
        const a = addrObjs[i], b = addrObjs[j];
        if (a.type === b.type && a.value && a.value === b.value) {
          pairs.push({ names: [a.name, b.name], value: a.value, type: 'address' });
        }
      }
    }

    for (let i = 0; i < svcObjs.length; i++) {
      for (let j = i + 1; j < svcObjs.length; j++) {
        const a = svcObjs[i], b = svcObjs[j];
        const aPort = a.port_min != null ? `${a.port_min}-${a.port_max || a.port_min}` : (a.ports || '');
        const bPort = b.port_min != null ? `${b.port_min}-${b.port_max || b.port_min}` : (b.ports || '');
        if (a.protocol === b.protocol && aPort && aPort === bPort && a.protocol !== 'ANY') {
          pairs.push({ names: [a.name, b.name], value: `${a.protocol}:${aPort}`, type: 'service' });
        }
      }
    }

    const count = pairs.length;
    if (!count) return { id: 'duplicates', count: 0, items: [], description: 'No duplicate objects found.' };
    const items = pairs.map(p => ({
      key: p.names.join('\x00'),
      label: `${p.names.join(' / ')} [${p.type}: ${p.value}]`,
      names: p.names,
      type: p.type,
    }));
    const examples = pairs.slice(0, 3).map(p => `${p.names.join(' / ')} (${p.value})`).join('; ');
    return {
      id: 'duplicates', count, items,
      description: `${count} pair${count !== 1 ? 's' : ''} of objects share identical values. ${examples}.`,
    };
  },

  // ── Disabled policies ─────────────────────────────────────────────────────
  _disabledPolicies(config) {
    const policies = config.security_policies || [];
    const disabled = policies.filter(p => p.disabled);
    const count = disabled.length;
    if (!count) return { id: 'disabled', count: 0, items: [], description: 'No disabled policies found.' };
    const pKey = (p) => p._rule_index != null ? String(p._rule_index) : p.name;
    const pLabel = (p) => p._rule_index != null ? `#${p._rule_index} ${p.name}` : p.name;
    const items = disabled.map(p => ({ key: pKey(p), label: pLabel(p) }));
    const names = disabled.map(p => pLabel(p));
    return {
      id: 'disabled', count, items,
      description: `${count} polic${count !== 1 ? 'ies are' : 'y is'} disabled/inactive: ${names.slice(0, 5).join(', ')}${names.length > 5 ? ` + ${names.length - 5} more` : ''}.`,
    };
  },

  // ── Logging disabled ──────────────────────────────────────────────────────
  _loggingOff(config) {
    const policies = config.security_policies || [];
    // OUR SCHEMA: p.disabled (inverted), p.log_end / p.log_start
    const noLog = policies.filter(p => !p.disabled && !p._implicit && !p.log_end && !p.log_start);
    const count = noLog.length;
    if (!count) return { id: 'logging_off', count: 0, items: [], description: 'All enabled policies have logging enabled.' };
    const pKey = (p) => p._rule_index != null ? String(p._rule_index) : p.name;
    const pLabel = (p) => p._rule_index != null ? `#${p._rule_index} ${p.name}` : p.name;
    const items = noLog.map(p => ({ key: pKey(p), label: pLabel(p) }));
    const names = noLog.map(p => pLabel(p));
    return {
      id: 'logging_off', count, items,
      description: `${count} enabled polic${count !== 1 ? 'ies have' : 'y has'} logging disabled: ${names.slice(0, 5).join(', ')}${names.length > 5 ? ` + ${names.length - 5} more` : ''}.`,
    };
  },

  // ── Overly permissive ─────────────────────────────────────────────────────
  _permissivePolicies(config) {
    const policies = config.security_policies || [];
    // OUR SCHEMA: p.disabled, p.action ('allow'|'deny'|'reject'), p.src_addresses, p.dst_addresses
    const permissive = policies.filter(p => {
      // Implicit rules model the source platform's defaults (e.g. GCP implied allow-egress); removing them changes behaviour.
      if (p.disabled || p._implicit || p.action !== 'allow') return false;
      const srcAny = !p.negate_source && (p.src_addresses || []).some(a => a === 'any' || a === 'all');
      const dstAny = !p.negate_destination && (p.dst_addresses || []).some(a => a === 'any' || a === 'all');
      return srcAny && dstAny;
    });
    const count = permissive.length;
    if (!count) return { id: 'permissive', count: 0, items: [], description: 'No overly permissive permit rules found.' };
    const pKey = (p) => p._rule_index != null ? String(p._rule_index) : p.name;
    const pLabel = (p) => p._rule_index != null ? `#${p._rule_index} ${p.name}` : p.name;
    const items = permissive.map(p => ({ key: pKey(p), label: pLabel(p) }));
    const names = permissive.map(p => pLabel(p));
    return {
      id: 'permissive', count, items,
      description: `${count} permit polic${count !== 1 ? 'ies match' : 'y matches'} any source and any destination: ${names.slice(0, 5).join(', ')}${names.length > 5 ? ` + ${names.length - 5} more` : ''}.`,
    };
  },

  // ── Empty groups ──────────────────────────────────────────────────────────
  _emptyGroups(config) {
    const empty = [
      ...(config.address_groups || []).filter(g => !g.members || g.members.length === 0),
      ...(config.service_groups || []).filter(g => !g.members || g.members.length === 0),
      ...(config.application_groups || []).filter(g => !g.members || g.members.length === 0),
    ];
    const count = empty.length;
    if (!count) return { id: 'empty_groups', count: 0, items: [], description: 'No empty groups found.' };
    const items = empty.map(g => ({ key: g.name, label: g.name }));
    return {
      id: 'empty_groups', count, items,
      description: `${count} group${count !== 1 ? 's contain' : ' contains'} no members: ${empty.map(g => g.name).join(', ')}.`,
    };
  },

  /**
   * 8. Never-Hit Policies — policies annotated with hit_count === 0.
   * Hit counts are populated from live device statistics via the PyEZ Bridge.
   * Only fires if at least one policy has _hit_count annotated.
   */
  _neverHitPolicies(config) {
    const policies = config.security_policies || [];
    const annotated = policies.filter(p => typeof p._hit_count === 'number');
    if (annotated.length === 0) {
      return {
        id: 'never-hit',
        count: 0,
        items: [],
        description: 'Policies with zero traffic hits. Pull hit counts from a live device to populate.',
      };
    }

    const neverHit = annotated.filter(p => p._hit_count === 0 && !p.disabled && !p._implicit);
    return {
      id: 'never-hit',
      count: neverHit.length,
      items: neverHit.map(p => ({
        key: p._rule_index != null ? String(p._rule_index) : p.name,
        label: p._rule_index != null ? `#${p._rule_index} ${p.name}` : p.name,
        _rule_index: p._rule_index,
      })),
      description: `${neverHit.length} of ${annotated.length} annotated policies have zero hits.`,
    };
  },

  /**
   * 9. Inbound Any (External) — permit rules allowing 'any' source from external zones.
   * Issue #30 Group A check.
   */
  _inboundAny(config) {
    const policies = config.security_policies || [];
    const pKey = (p) => p._rule_index != null ? String(p._rule_index) : p.name;
    const pLabel = (p) => p._rule_index != null ? `#${p._rule_index} ${p.name}` : p.name;

    const flagged = policies.filter(p => {
      if (p.disabled || p.action !== 'allow') return false;
      const srcZones = p.src_zones || [];
      const hasExternalZone = srcZones.some(z => isExternalZone(z));
      if (!hasExternalZone) return false;
      const srcAddrs = p.src_addresses || [];
      return !p.negate_source && srcAddrs.some(a => a === 'any' || a === 'all');
    });

    const count = flagged.length;
    if (!count) {
      return {
        id: 'inbound_any',
        count: 0,
        items: [],
        description: 'No inbound any-source rules from external zones.',
      };
    }

    const items = flagged.map(p => ({ key: pKey(p), label: pLabel(p) }));
    const firstFew = flagged.slice(0, 3).map(p => pLabel(p)).join(', ');
    return {
      id: 'inbound_any',
      count,
      items,
      description: `${count} permit rule${count !== 1 ? 's' : ''} allow${count === 1 ? 's' : ''} ANY source inbound from an external zone: ${firstFew}${count > 3 ? ` + ${count - 3} more` : ''}.`,
    };
  },

  /**
   * 10. Exposed Mgmt/Risky Services — permit rules from external zones allowing dangerous apps/ports.
   * Issue #30 Group A check.
   */
  _exposedServices(config) {
    const RISKY_APPS = new Set([
      'ms-rdp', 'rdp', 'ms-ds-smb', 'ms-ds-smbv3', 'netbios-ss',
      'telnet', 'ssh', 'snmp', 'mysql', 'ms-sql', 'mssql-db',
      'oracle', 'postgres', 'postgresql', 'vnc', 'ftp', 'tftp',
      'rlogin', 'rsh',
    ]);
    const RISKY_PORTS = new Set([
      22, 23, 69, 135, 139, 161, 445, 512, 513, 514,
      1433, 1521, 3306, 3389, 5432, 5900, 21,
    ]);

    const policies = config.security_policies || [];
    const pKey = (p) => p._rule_index != null ? String(p._rule_index) : p.name;
    const pLabel = (p) => p._rule_index != null ? `#${p._rule_index} ${p.name}` : p.name;

    // Build service name → ports map
    const servicePorts = new Map();
    for (const svc of (config.service_objects || [])) {
      if (!svc.name || !svc.port_range) continue;
      const ports = [];
      for (const part of String(svc.port_range).split(',')) {
        const trimmed = part.trim();
        if (trimmed.includes('-')) {
          const low = parseInt(trimmed.split('-')[0], 10);
          if (!isNaN(low)) ports.push(low);
        } else {
          const port = parseInt(trimmed, 10);
          if (!isNaN(port)) ports.push(port);
        }
      }
      if (ports.length) servicePorts.set(svc.name, ports);
    }

    const flagged = [];
    for (const p of policies) {
      if (p.disabled || p.action !== 'allow') continue;
      const srcZones = p.src_zones || [];
      const hasExternalZone = srcZones.some(z => isExternalZone(z));
      if (!hasExternalZone) continue;

      const triggers = [];

      // Check applications
      const apps = p.applications || [];
      for (const app of apps) {
        const appLower = String(app).toLowerCase();
        if (RISKY_APPS.has(appLower)) {
          triggers.push(app);
        }
      }

      // Check services
      const services = p.services || [];
      for (const svcName of services) {
        if (svcName === 'any' || svcName === 'application-default') continue;
        const ports = servicePorts.get(svcName);
        if (ports) {
          for (const port of ports) {
            if (RISKY_PORTS.has(port)) {
              triggers.push(svcName);
              break;
            }
          }
        }
      }

      if (triggers.length) {
        const trigger = triggers[0];
        flagged.push({
          policy: p,
          trigger,
          label: `${pLabel(p)} — exposes ${trigger}`,
        });
      }
    }

    const count = flagged.length;
    if (!count) {
      return {
        id: 'exposed_services',
        count: 0,
        items: [],
        description: 'No exposed management or risky services from external zones.',
      };
    }

    const items = flagged.map(f => ({ key: pKey(f.policy), label: f.label }));
    const firstFew = flagged.slice(0, 3).map(f => f.label).join('; ');
    return {
      id: 'exposed_services',
      count,
      items,
      description: `${count} permit rule${count !== 1 ? 's expose' : ' exposes'} management or risky services from an external zone. ${firstFew}${count > 3 ? ` + ${count - 3} more` : ''}.`,
    };
  },

  /**
   * 11. Broad Source/Destination — permit rules with 0.0.0.0/0, ::/0, or /8 supernets.
   * Issue #30 Group A check. Does NOT flag the literal 'any' keyword (covered by permissive check).
   */
  _broadAddresses(config) {
    const policies = config.security_policies || [];
    const pKey = (p) => p._rule_index != null ? String(p._rule_index) : p.name;
    const pLabel = (p) => p._rule_index != null ? `#${p._rule_index} ${p.name}` : p.name;

    // Build address name → is-broad map
    const isBroadMap = new Map();
    for (const addr of (config.address_objects || [])) {
      if (!addr.name || !addr.value) continue;
      const val = String(addr.value).trim();
      if (val === '0.0.0.0/0' || val === '::/0') {
        isBroadMap.set(addr.name, val);
      } else if (val.includes('/')) {
        const parts = val.split('/');
        if (parts.length === 2 && parts[0].includes('.')) {
          const prefix = parseInt(parts[1], 10);
          if (!isNaN(prefix) && prefix <= 8) {
            isBroadMap.set(addr.name, val);
          }
        }
      }
    }

    const flagged = [];
    for (const p of policies) {
      if (p.disabled || p.action !== 'allow') continue;

      const broadSources = [];
      const broadDests = [];

      const srcAddrs = p.src_addresses || [];
      for (const addr of srcAddrs) {
        if (addr === 'any' || addr === 'all') continue; // covered by permissive check
        if (addr === '0.0.0.0/0' || addr === '::/0') {
          broadSources.push(addr);
        } else if (isBroadMap.has(addr)) {
          broadSources.push(`${addr} (${isBroadMap.get(addr)})`);
        }
      }

      const dstAddrs = p.dst_addresses || [];
      for (const addr of dstAddrs) {
        if (addr === 'any' || addr === 'all') continue;
        if (addr === '0.0.0.0/0' || addr === '::/0') {
          broadDests.push(addr);
        } else if (isBroadMap.has(addr)) {
          broadDests.push(`${addr} (${isBroadMap.get(addr)})`);
        }
      }

      if (broadSources.length || broadDests.length) {
        const parts = [];
        if (broadSources.length) parts.push(`source: ${broadSources[0]}`);
        if (broadDests.length) parts.push(`destination: ${broadDests[0]}`);
        const note = parts.join(', ');
        flagged.push({
          policy: p,
          note,
          label: `${pLabel(p)} — broad ${note}`,
        });
      }
    }

    const count = flagged.length;
    if (!count) {
      return {
        id: 'broad_address',
        count: 0,
        items: [],
        description: 'No permit rules with broad supernets (0.0.0.0/0, ::/0, or /8).',
      };
    }

    const items = flagged.map(f => ({ key: pKey(f.policy), label: f.label }));
    const firstFew = flagged.slice(0, 3).map(f => f.label).join('; ');
    return {
      id: 'broad_address',
      count,
      items,
      description: `${count} permit rule${count !== 1 ? 's have' : ' has'} broad source or destination addresses. ${firstFew}${count > 3 ? ` + ${count - 3} more` : ''}.`,
    };
  },

  /**
   * 12. Orphan References — policies with undefined address/service object references.
   * Issue #49 Group C check.
   * Deactivated policies would fail commit.
   */
  _orphanReferences(config) {
    const policies = config.security_policies || [];
    const pKey = (p) => p._rule_index != null ? String(p._rule_index) : p.name;
    const pLabel = (p) => p._rule_index != null ? `#${p._rule_index} ${p.name}` : p.name;

    const issuesMap = findPolicyReferenceIssues(config);
    if (issuesMap.size === 0) {
      return {
        id: 'orphan_ref',
        count: 0,
        items: [],
        description: 'No policies reference undefined address/service objects.',
      };
    }

    const items = [];
    for (const [policyIndex, { addresses, services }] of issuesMap) {
      const policy = policies[policyIndex];
      if (!policy) continue;

      const parts = [];
      if (addresses.length) {
        parts.push(`address "${addresses.join('", "')}"${addresses.length > 1 ? 's' : ''}`);
      }
      if (services.length) {
        parts.push(`service "${services.join('", "')}"${services.length > 1 ? 's' : ''}`);
      }
      const label = `${pLabel(policy)} — undefined: ${parts.join(', ')}`;
      items.push({ key: pKey(policy), label });
    }

    const count = items.length;
    return {
      id: 'orphan_ref',
      count,
      items,
      description: `${count} polic${count !== 1 ? 'ies' : 'y'} reference${count === 1 ? 's' : ''} undefined address/service objects (would fail commit; deactivated by the converter).`,
    };
  },

  /**
   * 13. No Deny-All — missing explicit logged deny-all at policy tail.
   * Issue #49 Group C check.
   * Advisory check — implicit deny still blocks, but isn't logged.
   */
  _noDenyAll(config) {
    const policies = config.security_policies || [];
    const nonImplicit = policies.filter(p => !p._implicit && !p.disabled);

    if (nonImplicit.length === 0) {
      return { id: 'no_deny_all', count: 0, items: [], description: 'No non-implicit policies to check.' };
    }

    const DENY_ACTIONS = new Set(['deny', 'reject', 'drop']);

    const hasDenyAll = nonImplicit.some(p => {
      if (!DENY_ACTIONS.has(p.action) && !String(p.action || '').startsWith('reset-')) return false;
      const srcAddrs = p.src_addresses || [];
      const dstAddrs = p.dst_addresses || [];
      const hasAnySrc = !p.negate_source && srcAddrs.some(a => a === 'any' || a === 'all');
      const hasAnyDst = !p.negate_destination && dstAddrs.some(a => a === 'any' || a === 'all');
      const logged = p.log_start || p.log_end;
      return hasAnySrc && hasAnyDst && logged;
    });

    if (hasDenyAll) {
      return { id: 'no_deny_all', count: 0, items: [], description: 'Explicit logged deny-all rule found.' };
    }

    return {
      id: 'no_deny_all',
      count: 1,
      items: [{ key: 'no_deny_all', label: 'Missing explicit logged deny-all tail rule' }],
      description: 'No explicit logged deny-all rule at the policy tail — recommended for visibility.',
    };
  },

  /**
   * 14. Redundant Rules — identical match + action as an earlier rule.
   * Issue #49 Group C check.
   */
  _redundantRules(config) {
    const policies = config.security_policies || [];
    const enabled = policies.filter(p => !p._implicit && !p.disabled);
    const pKey = (p) => p._rule_index != null ? String(p._rule_index) : p.name;
    const pLabel = (p) => p._rule_index != null ? `#${p._rule_index} ${p.name}` : p.name;

    const seen = new Map();
    const duplicates = [];

    for (const p of enabled) {
      const matchKey = JSON.stringify({
        action: p.action,
        src_zones: (p.src_zones || []).slice().sort(),
        dst_zones: (p.dst_zones || []).slice().sort(),
        src_addresses: (p.src_addresses || []).slice().sort(),
        dst_addresses: (p.dst_addresses || []).slice().sort(),
        negate_source: !!p.negate_source,
        negate_destination: !!p.negate_destination,
        applications: (p.applications || []).slice().sort(),
        services: (p.services || []).slice().sort(),
      });

      if (seen.has(matchKey)) {
        const earlier = seen.get(matchKey);
        duplicates.push({
          policy: p,
          earlier,
          label: `${pLabel(p)} — duplicates ${pLabel(earlier)}`,
        });
      } else {
        seen.set(matchKey, p);
      }
    }

    const count = duplicates.length;
    if (!count) {
      return {
        id: 'redundant_rule',
        count: 0,
        items: [],
        description: 'No redundant rules found.',
      };
    }

    const items = duplicates.map(d => ({ key: pKey(d.policy), label: d.label }));
    const firstFew = duplicates.slice(0, 3).map(d => d.label).join('; ');
    return {
      id: 'redundant_rule',
      count,
      items,
      description: `${count} rule${count !== 1 ? 's are' : ' is'} redundant (identical match and action as an earlier rule). ${firstFew}${count > 3 ? ` + ${count - 3} more` : ''}.`,
    };
  },

  /**
   * 15. Empty Policy Set — no non-implicit policies defined.
   * Issue #49 Group C check.
   */
  _emptyPolicySet(config) {
    const policies = config.security_policies || [];
    const nonImplicit = policies.filter(p => !p._implicit);

    if (nonImplicit.length === 0) {
      return {
        id: 'empty_policyset',
        count: 1,
        items: [{ key: 'empty', label: 'No security policies defined' }],
        description: 'No security policies defined — the configuration would rely entirely on the default deny (no explicit allow/deny rules).',
      };
    }

    return {
      id: 'empty_policyset',
      count: 0,
      items: [],
      description: 'Policy set is not empty.',
    };
  },

  /**
   * 16. Zones Without Policy — zones not referenced by any policy or NAT rule.
   * Issue #49 Group C check.
   */
  _zonesWithoutPolicy(config) {
    const zones = config.zones || [];
    if (zones.length === 0) {
      return { id: 'zones_no_policy', count: 0, items: [], description: 'No zones defined.' };
    }

    const usedZones = new Set();

    // Collect from non-implicit policies
    const policies = config.security_policies || [];
    for (const p of policies) {
      if (p._implicit) continue;
      const srcZones = p.src_zones || [];
      const dstZones = p.dst_zones || [];
      for (const z of [...srcZones, ...dstZones]) {
        if (z && z !== 'any') usedZones.add(z);
      }
    }

    // Collect from NAT rules
    const natRules = config.nat_rules || [];
    for (const r of natRules) {
      const sourceZones = r.source_zones || r.src_zones || [];
      const destZones = r.destination_zones || r.dst_zones || [];
      for (const z of [...sourceZones, ...destZones]) {
        if (z && z !== 'any') usedZones.add(z);
      }
    }

    const unused = zones.filter(z => z.name && !usedZones.has(z.name));
    const count = unused.length;
    if (!count) {
      return {
        id: 'zones_no_policy',
        count: 0,
        items: [],
        description: 'All zones are referenced in policies or NAT rules.',
      };
    }

    const items = unused.map(z => ({ key: z.name, label: z.name }));
    const names = unused.map(z => z.name).join(', ');
    return {
      id: 'zones_no_policy',
      count,
      items,
      description: `${count} zone${count !== 1 ? 's are' : ' is'} not referenced by any non-implicit security policy or NAT rule: ${names}.`,
    };
  },

  /**
   * 17. Log Completeness — no remote syslog target configured.
   * Issue #49 Group C check.
   */
  _logCompleteness(config) {
    const syslogConfig = config.syslog_config || [];
    const hasRemoteTarget = syslogConfig.some(entry => entry.server || entry.host);

    if (hasRemoteTarget) {
      return {
        id: 'log_completeness',
        count: 0,
        items: [],
        description: 'Remote syslog/security-log target is configured.',
      };
    }

    return {
      id: 'log_completeness',
      count: 1,
      items: [{ key: 'no_remote_log', label: 'No remote syslog target configured' }],
      description: 'No remote syslog/security-log target configured — policy and threat logs are not forwarded off-box.',
    };
  },

  // ── Large Groups (issue #50) ──────────────────────────────────────────────
  /**
   * 18. Large Groups — groups with >= 50 members (operational hygiene).
   * Flags address_groups, service_groups, application_groups.
   */
  _largeGroups(config) {
    const large = [];
    const addressGroups = config.address_groups || [];
    const serviceGroups = config.service_groups || [];
    const applicationGroups = config.application_groups || [];

    for (const g of addressGroups) {
      if ((g.members || []).length >= LARGE_GROUP_THRESHOLD) {
        large.push(g);
      }
    }
    for (const g of serviceGroups) {
      if ((g.members || []).length >= LARGE_GROUP_THRESHOLD) {
        large.push(g);
      }
    }
    for (const g of applicationGroups) {
      if ((g.members || []).length >= LARGE_GROUP_THRESHOLD) {
        large.push(g);
      }
    }

    const count = large.length;
    if (!count) {
      return { id: 'large_group', count: 0, items: [], description: 'No large groups found.' };
    }

    const items = large.map(g => ({
      key: g.name,
      label: `${g.name} (${(g.members || []).length} members)`,
    }));

    return {
      id: 'large_group',
      count,
      items,
      description: `${count} group${count !== 1 ? 's have' : ' has'} >= ${LARGE_GROUP_THRESHOLD} members (may be hard to manage).`,
    };
  },

  // ── Nested Groups (issue #50) ─────────────────────────────────────────────
  /**
   * 19. Nested Groups — groups with nesting depth >= 3.
   * Computes depth per group type independently. Guards against cycles.
   * Depth is deterministic: computed per group with a fresh path set (no cross-group memoization).
   */
  _nestedGroups(config) {
    const flagged = [];

    /**
     * Compute depth for a group type (address, service, or application).
     * Each group's depth is computed independently with a fresh path set for deterministic results.
     * @param {Array} groups - array of group objects with name and members
     * @returns {Map<string, number>} - name → depth
     */
    const computeDepths = (groups) => {
      const nameToGroup = new Map(groups.map(g => [g.name, g]));
      const depths = new Map();

      /**
       * Compute depth for a single group, starting with an empty path.
       * @param {string} groupName - group name
       * @param {Set<string>} path - current path (for cycle detection)
       * @returns {number} - depth
       */
      const getDepth = (groupName, path) => {
        if (path.has(groupName)) return 0; // back-edge: stop (deterministic)
        if (!nameToGroup.has(groupName)) return 0; // leaf/object member

        const group = nameToGroup.get(groupName);
        const members = group.members || [];
        const newPath = new Set(path);
        newPath.add(groupName);

        const memberDepths = [];
        for (const member of members) {
          memberDepths.push(getDepth(member, newPath));
        }

        const maxChildDepth = memberDepths.length > 0 ? Math.max(...memberDepths) : 0;
        return 1 + maxChildDepth;
      };

      // Compute depth(g.name, emptySet) for every group (fresh empty path each time)
      for (const g of groups) {
        depths.set(g.name, getDepth(g.name, new Set()));
      }

      return depths;
    };

    const addressGroups = config.address_groups || [];
    const serviceGroups = config.service_groups || [];
    const applicationGroups = config.application_groups || [];

    const addrDepths = computeDepths(addressGroups);
    const svcDepths = computeDepths(serviceGroups);
    const appDepths = computeDepths(applicationGroups);

    for (const g of addressGroups) {
      const depth = addrDepths.get(g.name) || 1;
      if (depth >= NESTED_GROUP_THRESHOLD) {
        flagged.push({ name: g.name, depth });
      }
    }
    for (const g of serviceGroups) {
      const depth = svcDepths.get(g.name) || 1;
      if (depth >= NESTED_GROUP_THRESHOLD) {
        flagged.push({ name: g.name, depth });
      }
    }
    for (const g of applicationGroups) {
      const depth = appDepths.get(g.name) || 1;
      if (depth >= NESTED_GROUP_THRESHOLD) {
        flagged.push({ name: g.name, depth });
      }
    }

    const count = flagged.length;
    if (!count) {
      return { id: 'nested_group', count: 0, items: [], description: 'No deeply nested groups found.' };
    }

    const items = flagged.map(f => ({
      key: f.name,
      label: `${f.name} (depth ${f.depth})`,
    }));

    return {
      id: 'nested_group',
      count,
      items,
      description: `${count} group${count !== 1 ? 's have' : ' has'} nesting depth >= ${NESTED_GROUP_THRESHOLD} (may be hard to troubleshoot).`,
    };
  },

  // ── Undescribed Objects (issue #50) ───────────────────────────────────────
  /**
   * 20. Undescribed Objects — objects/groups with no description field.
   * Covers address_objects, service_objects, address_groups, service_groups.
   */
  _undescribedObjects(config) {
    const isEmpty = (desc) => !desc || String(desc).trim() === '';

    const undescribed = [];
    const addressObjects = config.address_objects || [];
    const serviceObjects = config.service_objects || [];
    const addressGroups = config.address_groups || [];
    const serviceGroups = config.service_groups || [];

    for (const obj of addressObjects) {
      if (isEmpty(obj.description)) {
        undescribed.push({ name: obj.name, type: 'address object' });
      }
    }
    for (const obj of serviceObjects) {
      if (isEmpty(obj.description)) {
        undescribed.push({ name: obj.name, type: 'service object' });
      }
    }
    for (const grp of addressGroups) {
      if (isEmpty(grp.description)) {
        undescribed.push({ name: grp.name, type: 'address group' });
      }
    }
    for (const grp of serviceGroups) {
      if (isEmpty(grp.description)) {
        undescribed.push({ name: grp.name, type: 'service group' });
      }
    }

    const count = undescribed.length;
    if (!count) {
      return { id: 'undescribed_object', count: 0, items: [], description: 'All objects and groups have descriptions.' };
    }

    const items = undescribed.map(u => ({
      key: u.name,
      label: `${u.name} (${u.type})`,
    }));

    return {
      id: 'undescribed_object',
      count,
      items,
      description: `${count} object${count !== 1 ? 's/groups have' : '/group has'} no description (operational hygiene).`,
    };
  },

  // ── Undescribed Policies (issue #50) ──────────────────────────────────────
  /**
   * 21. Undescribed Policies — non-implicit policies with no description.
   * Excludes _implicit policies.
   */
  _undescribedPolicies(config) {
    const policies = config.security_policies || [];
    const isEmpty = (desc) => !desc || String(desc).trim() === '';

    const undescribed = policies.filter(p => !p._implicit && isEmpty(p.description));
    const count = undescribed.length;

    if (!count) {
      return { id: 'undescribed_policy', count: 0, items: [], description: 'All policies have descriptions.' };
    }

    const pKey = (p) => p._rule_index != null ? String(p._rule_index) : p.name;
    const pLabel = (p) => p._rule_index != null ? `#${p._rule_index} ${p.name}` : p.name;

    const items = undescribed.map(p => ({
      key: pKey(p),
      label: pLabel(p),
    }));

    return {
      id: 'undescribed_policy',
      count,
      items,
      description: `${count} polic${count !== 1 ? 'ies have' : 'y has'} no description (operational hygiene).`,
    };
  },

  /**
   * 22. Weak IKE Crypto — VPN tunnels with weak IKE proposals (issue #48 Group B).
   * Flags tunnels with: DH group < 14, weak encryption (DES/3DES), weak auth (MD5/SHA1).
   */
  _weakIke(config) {
    const tunnels = config.vpn_tunnels || [];
    const flagged = [];

    for (const t of tunnels) {
      if (!t.ike_proposal) continue;

      const weaknesses = [];
      const prop = t.ike_proposal;

      // Check DH group
      const dhNum = dhGroupNumber(prop.dh_group);
      if (!isNaN(dhNum) && dhNum < 14) {
        weaknesses.push(`DH group ${dhNum}`);
      }

      // Check encryption
      const encTokens = cryptoTokens(prop.encryption);
      for (const tok of encTokens) {
        if (isWeakEncToken(tok)) {
          weaknesses.push(tok);
          break; // one per category
        }
      }

      // Check authentication
      const authTokens = cryptoTokens(prop.authentication);
      for (const tok of authTokens) {
        if (isWeakAuthToken(tok)) {
          weaknesses.push(tok);
          break;
        }
      }

      if (weaknesses.length) {
        flagged.push({
          name: t.name,
          weaknesses,
        });
      }
    }

    const count = flagged.length;
    if (!count) {
      return {
        id: 'weak_ike',
        count: 0,
        items: [],
        description: 'No VPN tunnels with weak IKE crypto.',
      };
    }

    const items = flagged.map(f => ({
      key: f.name,
      label: `${f.name} — ${f.weaknesses.join(', ')}`,
    }));

    return {
      id: 'weak_ike',
      count,
      items,
      description: `${count} VPN tunnel${count !== 1 ? 's have' : ' has'} weak IKE crypto (DH < 14, DES/3DES, MD5/SHA1).`,
    };
  },

  /**
   * 23. Weak IPsec Crypto — VPN tunnels with weak IPsec proposals (issue #48 Group B).
   * Flags tunnels with: weak encryption (DES/3DES), weak auth (MD5/SHA1), no PFS.
   */
  _weakIpsec(config) {
    const tunnels = config.vpn_tunnels || [];
    const flagged = [];

    for (const t of tunnels) {
      if (!t.ipsec_proposal) continue;

      const weaknesses = [];
      const prop = t.ipsec_proposal;

      // Check encryption
      const encTokens = cryptoTokens(prop.encryption);
      for (const tok of encTokens) {
        if (isWeakEncToken(tok)) {
          weaknesses.push(tok);
          break;
        }
      }

      // Check authentication
      const authTokens = cryptoTokens(prop.authentication);
      for (const tok of authTokens) {
        if (isWeakAuthToken(tok)) {
          weaknesses.push(tok);
          break;
        }
      }

      // Check PFS
      const pfsGroup = String(prop.pfs_group || '').toLowerCase().trim();
      const noPfs = !prop.pfs_group || pfsGroup === 'none' || pfsGroup === 'disabled' || pfsGroup === 'group0' || dhGroupNumber(prop.pfs_group) === 0;
      if (noPfs) {
        weaknesses.push('no PFS');
      }

      if (weaknesses.length) {
        flagged.push({
          name: t.name,
          weaknesses,
        });
      }
    }

    const count = flagged.length;
    if (!count) {
      return {
        id: 'weak_ipsec',
        count: 0,
        items: [],
        description: 'No VPN tunnels with weak IPsec crypto.',
      };
    }

    const items = flagged.map(f => ({
      key: f.name,
      label: `${f.name} — ${f.weaknesses.join(', ')}`,
    }));

    return {
      id: 'weak_ipsec',
      count,
      items,
      description: `${count} VPN tunnel${count !== 1 ? 's have' : ' has'} weak IPsec crypto (DES/3DES, MD5/SHA1, no PFS).`,
    };
  },

  /**
   * 24. Zones Without Screen — External zones without IDS screen profile (issue #48 Group B).
   * Flags external/untrusted zones that have no screen_config binding.
   */
  _zonesWithoutScreen(config) {
    const zones = config.zones || [];
    if (!zones.length) {
      return { id: 'no_screen', count: 0, items: [], description: 'No zones defined.' };
    }

    const screenConfig = config.screen_config || [];

    // Build set of zones with screen bindings
    const boundZones = new Set();
    for (const sc of screenConfig) {
      if (sc.zone) {
        boundZones.add(sc.zone);
      }
    }

    // Find external zones without screen
    const flagged = [];
    for (const z of zones) {
      if (isExternalZone(z.name) && !boundZones.has(z.name)) {
        flagged.push(z.name);
      }
    }

    const count = flagged.length;
    if (!count) {
      return {
        id: 'no_screen',
        count: 0,
        items: [],
        description: 'All external/untrusted zones have screen profiles bound.',
      };
    }

    const items = flagged.map(name => ({
      key: name,
      label: name,
    }));

    return {
      id: 'no_screen',
      count,
      items,
      description: `${count} external/untrusted zone${count !== 1 ? 's have' : ' has'} no screen (IDS-options) profile bound.`,
    };
  },
};

// ── Analysis Applicator ──────────────────────────────────────────────────────
export const AnalysisApplicator = {
  _getItemAction(finding, itemKey) {
    const overrides = finding.itemOverrides || {};
    if (overrides[itemKey] !== undefined) return overrides[itemKey];
    return finding.selected === 'exclude' ? 'exclude' : 'include';
  },

  apply(config, findings) {
    for (const f of findings) {
      if (!f.count) continue;
      const act = (key) => this._getItemAction(f, key);

      switch (f.id) {
        case 'unused_objects': {
          config.address_objects = (config.address_objects || []).filter(o => o._used || act(o.name) !== 'exclude');
          config.address_groups = (config.address_groups || []).filter(g => g._used || act(g.name) !== 'exclude');
          config.service_objects = (config.service_objects || []).filter(o => o._used || act(o.name) !== 'exclude');
          config.service_groups = (config.service_groups || []).filter(g => g._used || act(g.name) !== 'exclude');
          config.application_groups = (config.application_groups || []).filter(g => g._used || act(g.name) !== 'exclude');
          // Annotate remaining unused objects
          [...(config.address_objects || []), ...(config.address_groups || []),
           ...(config.service_objects || []), ...(config.service_groups || []),
           ...(config.application_groups || [])]
            .filter(o => !o._used)
            .forEach(o => { o._note = 'Unused — not referenced by any security policy, NAT rule, or group'; });
          break;
        }

        case 'shadowed': {
          const shadowedKeys = new Set(f.items.map(i => i.key));
          config.security_policies = (config.security_policies || []).filter(p => {
            const key = p._rule_index != null ? String(p._rule_index) : p.name;
            return !shadowedKeys.has(key) || act(key) !== 'exclude';
          });
          // Annotate remaining
          (config.security_policies || [])
            .filter(p => {
              const key = p._rule_index != null ? String(p._rule_index) : p.name;
              return shadowedKeys.has(key);
            })
            .forEach(p => { p._note = (p._note || '') + '[shadowed by earlier rule] '; });
          break;
        }

        case 'redundant_rule': {
          // Redundant rules are exact duplicates (same match + same action) of an
          // earlier rule. Remove the later duplicate on exclude (keep the original),
          // or annotate it when kept. Mirrors the `shadowed` case.
          const redundantKeys = new Set(f.items.map(i => i.key));
          config.security_policies = (config.security_policies || []).filter(p => {
            const key = p._rule_index != null ? String(p._rule_index) : p.name;
            return !redundantKeys.has(key) || act(key) !== 'exclude';
          });
          (config.security_policies || [])
            .filter(p => {
              const key = p._rule_index != null ? String(p._rule_index) : p.name;
              return redundantKeys.has(key);
            })
            .forEach(p => { p._note = (p._note || '') + '[redundant — duplicate of earlier rule] '; });
          break;
        }

        case 'nat_shadowed': {
          // Shadowed NAT rules: remove the later (shadowed) rule on exclude,
          // keeping the earlier broader rule; annotate when kept.
          const natKeys = new Set(f.items.map(i => i.key));
          const natKey = (r) => r._rule_index != null ? String(r._rule_index) : r.name;
          config.nat_rules = (config.nat_rules || []).filter(r => {
            return !natKeys.has(natKey(r)) || act(natKey(r)) !== 'exclude';
          });
          (config.nat_rules || [])
            .filter(r => natKeys.has(natKey(r)))
            .forEach(r => { r._note = (r._note || '') + '[shadowed by earlier NAT rule] '; });
          break;
        }

        case 'orphan_ref': {
          // Policies that reference undefined address/service objects. Remove the
          // referencing policy on exclude; otherwise leave it and annotate
          // (report-only — the converter still deactivates it on emit).
          const refKeys = new Set(f.items.map(i => i.key));
          config.security_policies = (config.security_policies || []).filter(p => {
            const key = p._rule_index != null ? String(p._rule_index) : p.name;
            return !refKeys.has(key) || act(key) !== 'exclude';
          });
          (config.security_policies || [])
            .filter(p => {
              const key = p._rule_index != null ? String(p._rule_index) : p.name;
              return refKeys.has(key);
            })
            .forEach(p => { p._note = (p._note || '') + '[references undefined object] '; });
          break;
        }

        case 'zones_no_policy': {
          // Zones referenced by no policy/NAT rule. Remove on exclude; annotate
          // when kept (report-only). Items are keyed by zone name.
          const zoneKeys = new Set(f.items.map(i => i.key));
          config.zones = (config.zones || []).filter(z => {
            return !zoneKeys.has(z.name) || act(z.name) !== 'exclude';
          });
          (config.zones || [])
            .filter(z => zoneKeys.has(z.name))
            .forEach(z => { z._note = (z._note || '') + '[no policy references this zone] '; });
          break;
        }

        case 'duplicates': {
          if (f.selected === 'consolidate') {
            const toConsolidate = f.items.filter(i => act(i.key) !== 'include');
            if (toConsolidate.length) this._consolidateDuplicates(config, toConsolidate);
            const kept = f.items.filter(i => act(i.key) === 'include');
            for (const item of kept) {
              if (!item.names) continue;
              const list = item.type === 'address' ? (config.address_objects || []) : (config.service_objects || []);
              list.filter(o => item.names.includes(o.name)).forEach(o => {
                const others = item.names.filter(n => n !== o.name);
                o._note = (o._note || '') + `Duplicate of: ${others.join(', ')} `;
              });
            }
          } else {
            const toRemove = f.items.filter(i => act(i.key) === 'exclude');
            if (toRemove.length) this._consolidateDuplicates(config, toRemove);
            for (const item of f.items.filter(i => act(i.key) !== 'exclude')) {
              if (!item.names) continue;
              const list = item.type === 'address' ? (config.address_objects || []) : (config.service_objects || []);
              list.filter(o => item.names.includes(o.name)).forEach(o => {
                const others = item.names.filter(n => n !== o.name);
                o._note = (o._note || '') + `Duplicate of: ${others.join(', ')} `;
              });
            }
          }
          break;
        }

        case 'disabled': {
          const disabledKeys = new Set(f.items.map(i => i.key));
          const overrides = f.itemOverrides || {};
          config.security_policies = (config.security_policies || []).filter(p => {
            const key = p._rule_index != null ? String(p._rule_index) : p.name;
            if (!disabledKeys.has(key)) return true;
            const action = overrides[key] || f.selected;
            return action !== 'exclude';
          });
          (config.security_policies || []).filter(p => {
            const key = p._rule_index != null ? String(p._rule_index) : p.name;
            return p.disabled && disabledKeys.has(key);
          }).forEach(p => {
            const key = p._rule_index != null ? String(p._rule_index) : p.name;
            const action = overrides[key] || f.selected;
            if (action === 'include_enabled') {
              p.disabled = false;
              p._note = (p._note || '') + '[was disabled — re-enabled by analysis] ';
            }
          });
          break;
        }

        case 'logging_off': {
          const noLogKeys = new Set(f.items.map(i => i.key));
          const overrides = f.itemOverrides || {};
          for (const p of (config.security_policies || [])) {
            const key = p._rule_index != null ? String(p._rule_index) : p.name;
            if (!noLogKeys.has(key)) continue;
            const ov = overrides[key];
            const enable = ov === 'exclude' || (!ov && f.selected === 'enable_all');
            if (enable) {
              // OUR SCHEMA: use log_end for permit, log_start for deny
              if (p.action === 'allow') {
                p.log_end = true;
              } else {
                p.log_start = true;
              }
              p._note = (p._note || '') + '[logging enabled by analysis] ';
            }
          }
          break;
        }

        case 'permissive': {
          const permKeys = new Set(f.items.map(i => i.key));
          const overrides = f.itemOverrides || {};
          config.security_policies = (config.security_policies || []).filter(p => {
            const key = p._rule_index != null ? String(p._rule_index) : p.name;
            if (!permKeys.has(key)) return true;
            const ov = overrides[key];
            const action = ov || (f.selected === 'remove_all' ? 'exclude' : 'include');
            return action !== 'exclude';
          });
          break;
        }

        case 'empty_groups': {
          const isEmpty = g => !g.members || g.members.length === 0;
          config.address_groups = (config.address_groups || []).filter(g => !isEmpty(g) || act(g.name) !== 'exclude');
          config.service_groups = (config.service_groups || []).filter(g => !isEmpty(g) || act(g.name) !== 'exclude');
          config.application_groups = (config.application_groups || []).filter(g => !isEmpty(g) || act(g.name) !== 'exclude');
          [...(config.address_groups || []), ...(config.service_groups || []), ...(config.application_groups || [])]
            .filter(isEmpty)
            .forEach(g => { g._note = 'Empty group'; });
          break;
        }
      }
    }

    config._analysis_applied = { at: new Date().toISOString() };
  },

  _consolidateDuplicates(config, pairs) {
    const remap = {};
    const remove = new Set();
    for (const pair of pairs) {
      if (!pair.names || pair.names.length < 2) continue;
      remap[pair.names[1]] = pair.names[0];
      remove.add(pair.names[1]);
    }

    config.address_objects = (config.address_objects || []).filter(o => !remove.has(o.name));
    config.service_objects = (config.service_objects || []).filter(o => !remove.has(o.name));

    // OUR SCHEMA: src_addresses, dst_addresses, services
    for (const p of (config.security_policies || [])) {
      p.src_addresses = (p.src_addresses || []).map(a => remap[a] || a);
      p.dst_addresses = (p.dst_addresses || []).map(a => remap[a] || a);
      p.services = (p.services || []).map(s => remap[s] || s);
    }

    for (const g of [...(config.address_groups || []), ...(config.service_groups || [])]) {
      g.members = (g.members || []).map(m => remap[m] || m);
    }

    for (const r of (config.nat_rules || [])) {
      r.src_addresses = (r.src_addresses || []).map(a => remap[a] || a);
      r.dst_addresses = (r.dst_addresses || []).map(a => remap[a] || a);
    }
  },
};
