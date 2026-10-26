import { createWarning } from '../parsers/parser-utils.js';
import { mapInterfaceName } from './srx-interface-names.js';

/**
 * Resolves the ONE effective Junos name of each aggregate/redundant interface and
 * folds it into the interface mappings, so zones, addresses, NAT, host-inbound,
 * the ae definition, member bundles and the chassis device-count all agree.
 * A user mapping for the aggregate's source name wins when it is an `aeN[.unit]`
 * name; any other override keeps the generated aeN and warns.
 * @param {{lag_interfaces?: {name: string, source_name?: string}[]}} config - intermediate config
 * @param {Object} [interfaceMappings] - user-defined source -> SRX interface mappings
 * @returns {{interfaceMappings: Object, lagInterfaces: Object[], warnings: Object[]}}
 */
export function resolveLagInterfaces(config, interfaceMappings = {}) {
  const mappings = { ...interfaceMappings };
  const warnings = [];
  const overrideBase = lag => interfaceMappings[lag.source_name]?.split('.')[0];
  const lags = config.lag_interfaces || [];
  // Names already taken: generated names of aggregates that are not being overridden.
  const taken = new Set(lags.filter(lag => !lag.source_name || !overrideBase(lag)).map(lag => lag.name));
  const nextUnusedName = () => {
    let index = 0;
    while (taken.has(`ae${index}`)) index += 1;
    return `ae${index}`;
  };
  const lagInterfaces = lags.map(lag => {
    if (!lag.source_name) return lag;
    if (!overrideBase(lag)) {
      mappings[lag.source_name] = lag.name;
      return lag;
    }
    const override = interfaceMappings[lag.source_name];
    const base = overrideBase(lag);
    const isAeName = /^ae\d+$/.test(base);
    if (isAeName && !taken.has(base)) {
      taken.add(base);
      return { ...lag, name: base };
    }
    // Keep the aggregate on an unused name: its own generated one if free, else the next free aeN.
    const fallbackName = taken.has(lag.name) ? nextUnusedName() : lag.name;
    taken.add(fallbackName);
    warnings.push(createWarning('warning', `lag/${lag.source_name}`,
      `Interface mapping "${override}" for aggregate ${lag.source_name} is ${isAeName ? 'already used by another aggregate' : 'not an aeN name'}; used ${fallbackName}`,
      'Map each aggregate interface to a distinct aeN name'));
    mappings[lag.source_name] = fallbackName;
    return { ...lag, name: fallbackName };
  });
  return { interfaceMappings: mappings, lagInterfaces, warnings };
}

/**
 * Junos `aggregated-devices ethernet device-count`: highest ae index + 1.
 * @param {{name: string}[]} lagInterfaces - resolved aggregates
 * @returns {number} device count (0 when there are no aeN aggregates)
 */
export function lagDeviceCount(lagInterfaces) {
  let count = 0;
  for (const lag of lagInterfaces) {
    const aeMatch = lag.name.match(/^ae(\d+)$/);
    if (aeMatch) count = Math.max(count, parseInt(aeMatch[1], 10) + 1);
  }
  return count;
}

/**
 * Resolves the physical Junos port of aggregate member `index`. A user mapping on
 * the member's source name wins (`source_members[index]`), then `members[index]`
 * goes through the shared vendor-name derivation, so set and XML agree.
 * @param {{members: string[], source_members?: string[]}} lag - aggregate
 * @param {number} index - member position
 * @param {Object} interfaceMappings - effective interface mappings
 * @returns {string} Junos port without unit
 */
export function resolveLagMemberPort(lag, index, interfaceMappings) {
  const sourceName = lag.source_members?.[index];
  const mapped = sourceName && interfaceMappings[sourceName] ? interfaceMappings[sourceName] : mapInterfaceName(lag.members[index], interfaceMappings);
  return mapped.split('.')[0];
}
