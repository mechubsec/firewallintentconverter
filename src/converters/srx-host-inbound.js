/**
 * Shared host-inbound-traffic helpers for the SRX set and XML emitters, so the
 * two outputs stay identical. Access data comes from zone.host_inbound_traffic and
 * zone.interface_host_inbound_traffic.
 *
 * Schema (optional, per zone):
 *   host_inbound_traffic: { system_services: [], protocols: [], system_services_except?: [], protocols_except?: [] }
 *   interface_host_inbound_traffic: { [sourceIfaceName]: <same shape> }
 * Access lists that are present (even empty) mean "access data known"; {} does not.
 */

import { createWarning } from '../parsers/parser-utils.js';

const SAFE_TOKEN = /^[a-z0-9-]+$/;

/**
 * Normalizes one access object into validated entries. Names come from
 * untrusted config text, so anything outside [a-z0-9-] is dropped with a warning.
 * @param {object} [access] - host_inbound_traffic-shaped object
 * @param {string} element - warning element path
 * @param {Array} warnings - warnings sink
 * @returns {{services: {name: string, except: boolean}[], protocols: {name: string, except: boolean}[]}}
 */
export function hostInboundEntries(access, element, warnings) {
  const entries = { services: [], protocols: [] };
  if (!access) return entries;
  const collect = (names, except, target) => {
    for (const name of names || []) {
      if (typeof name === 'string' && SAFE_TOKEN.test(name)) {
        target.push({ name, except });
        continue;
      }
      warnings.push(createWarning('warning', element,
        `Invalid host-inbound-traffic name dropped: ${JSON.stringify(String(name)).slice(0, 60)}`,
        'Only lowercase letters, digits and hyphens are emitted.'));
    }
  };
  collect(access.system_services, false, entries.services);
  collect(access.system_services_except, true, entries.services);
  collect(access.protocols, false, entries.protocols);
  collect(access.protocols_except, true, entries.protocols);
  return entries;
}

/**
 * Pushes ONE warning listing zones that carry no access data at all.
 * @param {Array} zones
 * @param {Array} warnings
 */
export function warnZonesWithoutHostInbound(zones, warnings) {
  // An empty {} (e.g. greenfield add_zone without host_inbound_traffic) is not access data.
  const hasAccessLists = access => Array.isArray(access?.system_services) || Array.isArray(access?.protocols);
  const missing = (zones || [])
    .filter(zone => !hasAccessLists(zone.host_inbound_traffic) && !zone.interface_host_inbound_traffic)
    .map(zone => zone.name);
  if (missing.length === 0) return;
  warnings.push(createWarning('warning', 'zones/host-inbound-traffic',
    `No host-inbound-traffic data for zone(s): ${missing.join(', ')}. The SRX will not answer ping, SSH, HTTPS, etc. on these zones.`,
    'Add host-inbound-traffic system-services/protocols to each zone or interface as needed.'));
}
