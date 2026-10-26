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

const SERVICE_DAEMONS = ['ssh', 'https', 'http', 'netconf'];
// srx_healthcheck is the UI's SRX Best Practice mode, which rewrites source_vendor.
const SRX_SOURCE_VENDORS = ['srx', 'srx_healthcheck'];
const DEFAULT_PORTS = { ssh: 22, https: 443, http: 80 };

/**
 * Determines which `system services` daemons to enable. Host-inbound-traffic only lets
 * packets reach the Routing Engine; the daemon must also be on. Greenfield
 * system_config.management_services wins; otherwise the services are derived from the
 * union of every zone's and interface's host-inbound system-services (not the *_except
 * lists). SNMP and `all` cannot be derived, so they only warn.
 * @param {object[]} configs - intermediate configs (one, or one per merged logical system)
 * @param {Array} warnings - warnings sink
 * @param {string[]} [labels] - slot names for conflict warnings
 * @returns {{ssh?: boolean, https?: boolean, http?: boolean, netconf?: boolean}}
 */
export function deriveManagementServices(configs, warnings, labels = []) {
  const enabled = {};
  const derivedNames = new Set();
  const portsBySlot = {}; // daemon -> [{ label, port }] for each slot that enables it
  configs.forEach((config, index) => {
    const label = labels[index] ?? `config ${index + 1}`;
    const slotEnabled = new Set();
    const explicit = config.system_config?.management_services;
    if (explicit) {
      for (const daemon of SERVICE_DAEMONS) if (explicit[daemon]) slotEnabled.add(daemon);
    } else if (!SRX_SOURCE_VENDORS.includes(config.metadata?.source_vendor)) {
      // SRX sources keep host-inbound but not `system services`, so access data does not imply a daemon.
      for (const zone of config.zones || []) {
        // Only interfaces still in the zone, matching what convertZones emits.
        const interfaceAccess = Object.entries(zone.interface_host_inbound_traffic || {})
          .filter(([iface]) => (zone.interfaces || []).includes(iface))
          .map(([, access]) => access);
        const accessLists = [zone.host_inbound_traffic, ...interfaceAccess];
        for (const access of accessLists) {
          for (const name of access?.system_services || []) {
            derivedNames.add(name);
            if (SERVICE_DAEMONS.includes(name)) slotEnabled.add(name);
          }
        }
      }
    }
    for (const daemon of slotEnabled) {
      enabled[daemon] = true;
      // management_ports only holds non-default ports; a missing entry means the default.
      const value = config.management_ports?.[daemon];
      let port = DEFAULT_PORTS[daemon];
      if (value !== undefined) {
        const parsed = Number(value);
        if (Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535) {
          port = parsed;
        } else {
          warnings.push(createWarning('warning', `system/services/${daemon}-port`,
            `Invalid ${daemon} admin port ${JSON.stringify(String(value)).slice(0, 20)} ignored`,
            'Admin ports must be 1-65535'));
        }
      }
      (portsBySlot[daemon] ||= []).push({ label, port });
    }
  });
  const ports = {};
  for (const [daemon, entries] of Object.entries(portsBySlot)) {
    const distinct = new Set(entries.map(entry => entry.port));
    if (distinct.size > 1) {
      warnings.push(createWarning('warning', `system/services/${daemon}-port`,
        `Conflicting ${daemon} admin ports (${entries.map(entry => `${entry.label}: ${entry.port}`).join(', ')}); system services is root-level, so ${daemon} was not enabled`,
        `Configure system services ${daemon} manually with the port you want`));
      delete enabled[daemon];
      continue;
    }
    const [port] = distinct;
    if (port !== DEFAULT_PORTS[daemon]) ports[daemon] = port;
  }
  if (derivedNames.has('telnet')) {
    // Output validation forbids `system services telnet` (clear-text management), so it is never generated.
    warnings.push(createWarning('warning', 'system/services/telnet',
      'host-inbound-traffic allows telnet, but "system services telnet" is clear-text and is not generated',
      'Use SSH, or enable telnet manually on the SRX if it is truly required'));
  }
  if (derivedNames.has('snmp')) {
    warnings.push(createWarning('warning', 'system/services/snmp',
      'host-inbound-traffic allows SNMP, but SNMP needs community or v3 configuration that cannot be derived',
      'Configure SNMP under "snmp" on the SRX'));
  }
  if (derivedNames.has('all')) {
    warnings.push(createWarning('warning', 'system/services/all',
      'host-inbound-traffic system-services all was converted for host-inbound only; no system services daemons were enabled for it',
      'Enable the daemons you need under "system services" (ssh, web-management, telnet, netconf)'));
  }
  enabled.ports = ports;
  return enabled;
}

/**
 * Junos set lines (without the "set system services " prefix) for the enabled daemons.
 * @param {object} services - result of deriveManagementServices
 * @returns {string[]}
 */
export function managementServiceSetLines(services) {
  const lines = [];
  const ports = services.ports || {};
  if (services.ssh) lines.push('ssh');
  if (ports.ssh) lines.push(`ssh port ${ports.ssh}`);
  if (services.https) lines.push('web-management https system-generated-certificate');
  if (ports.https) lines.push(`web-management https port ${ports.https}`);
  if (services.http) lines.push('web-management http');
  if (ports.http) lines.push(`web-management http port ${ports.http}`);
  if (services.netconf) lines.push('netconf ssh');
  return lines;
}

/**
 * Junos XML children of <services> for the enabled daemons.
 * @param {object} services - result of deriveManagementServices
 * @returns {string[]}
 */
export function managementServiceXmlElements(services) {
  const elements = [];
  const ports = services.ports || {};
  const portElement = port => (port ? `<port>${port}</port>` : '');
  if (services.ssh) elements.push(ports.ssh ? `<ssh>${portElement(ports.ssh)}</ssh>` : '<ssh/>');
  if (services.https || services.http) {
    elements.push('<web-management>');
    if (services.https) elements.push(`  <https>${portElement(ports.https)}<system-generated-certificate/></https>`);
    if (services.http) elements.push(ports.http ? `  <http>${portElement(ports.http)}</http>` : '  <http/>');
    elements.push('</web-management>');
  }
  if (services.netconf) elements.push('<netconf><ssh/></netconf>');
  return elements;
}
