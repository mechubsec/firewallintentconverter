/**
 * Shared parsing utilities used across all vendor parsers.
 *
 * These helpers normalize data from XML parsing libraries (which may return
 * strings instead of arrays for single-element lists) and provide common
 * validation / transformation functions.
 */

import appMappingData from '../data/app-mappings.json' with { type: 'json' };
import { VENDOR_KEY_MAP, normalizeJunosName, getAppOverride } from '../utils/app-mappings.js';

/**
 * Safely parse JSON text, stripping prototype pollution keys (__proto__,
 * constructor, prototype) from all objects in the parsed tree.
 *
 * @param {string} text - Raw JSON string
 * @returns {Object} - Parsed and sanitized object
 * @throws {Error} - If text is not valid JSON
 */
export function safeJsonParse(text) {
  return JSON.parse(text, (key, value) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return undefined; // strip dangerous keys
    }
    return value;
  });
}

/**
 * Ensures the value is always an array.
 * XML parsers often return a single string instead of an array when there is
 * only one <member> element.  This normalizes that behavior.
 *
 * @param {*} value - The value to normalize
 * @returns {Array} - Always returns an array
 */
export function ensureArray(value) {
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) return value;
  return [value];
}

/**
 * Extracts <member> elements from a PAN-OS XML node.
 * Handles both single-member and multi-member cases.
 *
 * @param {Object} node - Parsed XML node that may contain a `member` property
 * @returns {string[]} - Array of member strings
 */
export function extractMembers(node) {
  if (!node) return [];
  if (node.member !== undefined) {
    return ensureArray(node.member).map(String);
  }
  return [];
}

/**
 * Extracts <entry> elements from a PAN-OS XML container node.
 * PAN-OS uses <entry name="..."> extensively throughout its config.
 *
 * @param {Object} node - Parsed XML node that may contain `entry` elements
 * @returns {Array<Object>} - Array of entry objects, each with at least a `name` attribute
 */
export function extractEntries(node) {
  if (!node) return [];
  if (node.entry !== undefined) {
    return ensureArray(node.entry);
  }
  return [];
}

/**
 * Safely retrieves a nested property from an object using a dot-separated path.
 *
 * @param {Object} obj - Source object
 * @param {string} path - Dot-separated path (e.g. "devices.entry.vsys")
 * @param {*} defaultValue - Value to return if path doesn't resolve
 * @returns {*} - The resolved value or defaultValue
 */
export function getNestedValue(obj, path, defaultValue = undefined) {
  const keys = path.split('.');
  let current = obj;
  for (const key of keys) {
    if (current === undefined || current === null) return defaultValue;
    current = current[key];
  }
  return current !== undefined ? current : defaultValue;
}

/**
 * Generates a conversion warning object.
 *
 * @param {'clean'|'warning'|'unsupported'|'interview_required'} severity
 * @param {string} element - The config element this warning pertains to
 * @param {string} message - Human-readable description of the issue
 * @param {string} [suggestion] - Suggested resolution or manual step
 * @returns {Object} - Warning object
 */
export function createWarning(severity, element, message, suggestion = '') {
  return {
    severity,
    element,
    message,
    suggestion,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Builds a bidirectional static NAT rule in the Junos convention the NAT plan reads:
 * `dst_addresses` is the public address, `translated_src.address` the private one,
 * `src_zones` the zone the public address is reached from and `dst_zones` the inside.
 * Returns null, with a warning, for shapes one Junos static NAT rule cannot express.
 * A one-way mapping becomes a source-side rule (zones and addresses not swapped) that the NAT
 * plan renders as a no-port-translation source pool.
 *
 * @param {Object} input
 * @param {string} input.name - Source rule name
 * @param {string[]} input.privateAddresses - Real (inside) addresses
 * @param {string[]} input.publicAddresses - Mapped (outside) addresses
 * @param {string[]} input.destinationFilter - The source rule's destination match
 * @param {string[]} input.insideZones
 * @param {string[]} input.outsideZones
 * @param {boolean} [input.bidirectional=true] - False for a one-way mapping
 * @param {string[]} [input.services=[]] - Services the mapping is scoped to ('any' is unscoped)
 * @param {Object[]} input.warnings - Warning list to append to
 * @returns {Object|null} The rule fields to spread into the NAT rule, or null when skipped
 */
export function buildStaticNatFields({
  name, privateAddresses, publicAddresses, destinationFilter, insideZones, outsideZones,
  bidirectional = true, services = [], warnings,
}) {
  const scopedServices = services.filter((service) => service && service !== 'any');
  let reason = null;
  // Junos static NAT translates both ways on every port, so a narrower source mapping must not widen.
  if (scopedServices.length > 0) reason = `it is scoped to service ${scopedServices.join(', ')}`;
  // A one-way rule is a source rule, and Junos source NAT matches a destination, so only bidirectional rejects it.
  else if (bidirectional && (destinationFilter || []).some((address) => address !== 'any')) reason = 'it matches a specific destination';
  else if (privateAddresses.length !== 1 || publicAddresses.length !== 1) reason = 'it maps more than one address';
  // Identity NAT exempts traffic from other NAT rules; as static NAT it would proxy ARP for an inside host.
  else if (privateAddresses[0] === publicAddresses[0]) reason = 'it maps an address to itself (identity NAT)';
  if (reason) {
    warnings.push(createWarning(
      'warning',
      `nat/static/${name}`,
      `Static NAT rule "${name}" skipped — ${reason}, which one Junos static NAT rule cannot express`,
      'Build the static NAT rule manually',
    ));
    return null;
  }
  if (!bidirectional) {
    return {
      type: 'source',
      src_zones: insideZones,
      dst_zones: outsideZones,
      src_addresses: privateAddresses,
      dst_addresses: (destinationFilter || []).length > 0 ? destinationFilter : ['any'],
      translated_src: { type: 'static', address: publicAddresses[0], addresses: [publicAddresses[0]], one_way: true },
    };
  }
  return {
    src_zones: outsideZones,
    dst_zones: insideZones,
    src_addresses: ['any'],
    dst_addresses: publicAddresses,
    translated_src: { type: 'static', address: privateAddresses[0] },
  };
}

/**
 * Detects the IP version of an address string.
 *
 * @param {string} value - Address string (e.g. "10.0.0.1/24" or "2001:db8::1/64")
 * @returns {'v4'|'v6'|null} - IP version or null if undetermined
 */
export function detectIpVersion(value) {
  if (!value || typeof value !== 'string') return null;
  if (value.includes(':')) return 'v6';
  if (/^\d+\.\d+\.\d+\.\d+/.test(value)) return 'v4';
  return null;
}

/**
 * Sanitizes a name for use in Junos configuration.
 * SRX names must be alphanumeric plus hyphens, underscores, and periods.
 * Max length is 63 characters.
 *
 * @param {string} name - Original name from the source config
 * @returns {string} - Sanitized name safe for Junos
 */
export function sanitizeJunosName(name) {
  if (!name) return 'unnamed';
  // Replace spaces and invalid characters with hyphens
  let sanitized = name.replace(/[^a-zA-Z0-9._-]/g, '-');
  // Collapse consecutive hyphens
  sanitized = sanitized.replace(/-{2,}/g, '-');
  // Remove leading/trailing hyphens and dots
  sanitized = sanitized.replace(/^[-_.]+|[-_.]+$/g, '');
  // Bug 9 fix: Junos names must start with a letter. Prefix with 'n-' if
  // the name starts with a digit (common in SonicWall/Huawei address objects).
  if (/^\d/.test(sanitized)) {
    sanitized = `n-${sanitized}`;
  }
  // Truncate to 63 characters (Junos limit)
  sanitized = sanitized.substring(0, 63);
  return sanitized || 'unnamed';
}

/**
 * Predefined Junos policy application names from official Juniper documentation.
 * Source: https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/policy-predefined-applications.html
 */
export const JUNOS_PREDEFINED_APPS = new Set([
  // Internet
  'junos-aol', 'junos-dhcp-relay', 'junos-dhcp-client', 'junos-dhcp-server',
  'junos-dns-udp', 'junos-dns-tcp', 'junos-ftp', 'junos-ftp-data',
  'junos-gopher', 'junos-http', 'junos-http-ext', 'junos-https',
  'junos-internet-locator-service', 'junos-irc', 'junos-ldap',
  'junos-pc-anywhere', 'junos-tftp', 'junos-wais',
  // Microsoft
  'junos-ms-rpc-epm', 'junos-ms-rpc', 'junos-ms-rpc-msexchange',
  'junos-ms-rpc-msexchange-database', 'junos-ms-rpc-msexchange-directory',
  'junos-ms-rpc-msexchange-info-store', 'junos-ms-rpc-tcp', 'junos-ms-rpc-udp',
  'junos-ms-sql', 'junos-msn',
  // Dynamic Routing
  'junos-rip', 'junos-ospf', 'junos-bgp',
  // Streaming Video
  'junos-h323', 'junos-netmeeting', 'junos-realaudio', 'junos-rtsp',
  'junos-sip', 'junos-vdo-live',
  // Sun RPC
  'junos-sun-rpc-portmapper', 'junos-sun-rpc-any',
  'junos-sun-rpc-program-mountd', 'junos-sun-rpc-program-nfs',
  'junos-sun-rpc-program-nlockmgr', 'junos-sun-rpc-program-rquotad',
  'junos-sun-rpc-program-rstatd', 'junos-sun-rpc-program-ruserd',
  'junos-sun-rpc-program-sadmind', 'junos-sun-rpc-program-sprayd',
  'junos-sun-rpc-program-status', 'junos-sun-rpc-program-walld',
  'junos-sun-rpc-program-ypbind',
  // Security & Tunnel
  'junos-ike', 'junos-ike-nat', 'junos-l2tp', 'junos-pptp', 'junos-gre',
  // IP catch-all
  'junos-tcp-any', 'junos-udp-any',
  // IM / P2P
  'junos-gnutella', 'junos-nntp', 'junos-smb', 'junos-ymsg',
  // Management
  'junos-nbname', 'junos-nbds', 'junos-nfs', 'junos-ns-global',
  'junos-ns-global-pro', 'junos-nsm', 'junos-ntp', 'junos-rlogin',
  'junos-rsh', 'junos-snmp', 'junos-sqlnet-v1', 'junos-sqlnet-v2',
  'junos-ssh', 'junos-syslog', 'junos-talk', 'junos-telnet',
  'junos-winframe', 'junos-x-windows',
  // Mail
  'junos-imap', 'junos-imaps', 'junos-smtp', 'junos-smtps',
  'junos-pop3', 'junos-pop3s',
  // UNIX
  'junos-finger', 'junos-uucp',
  // Misc
  'junos-chargen', 'junos-discard', 'junos-ident', 'junos-lpr',
  'junos-radius', 'junos-radius-accounting', 'junos-sqlmon',
  'junos-vnc', 'junos-whois', 'junos-sccp',
  // ICMP
  'junos-icmp-any', 'junos-icmp-all', 'junos-icmp-address-mask',
  'junos-icmp-dest-unreach', 'junos-icmp-fragment-needed',
  'junos-icmp-fragment-reassembly', 'junos-icmp-host-unreach',
  'junos-icmp-info', 'junos-icmp-parameter-problem',
  'junos-icmp-port-unreach', 'junos-icmp-protocol-unreach',
  'junos-icmp-redirect', 'junos-icmp-redirect-host',
  'junos-icmp-redirect-tos-host', 'junos-icmp-redirect-tos-net',
  'junos-icmp-source-quench', 'junos-icmp-source-route-fail',
  'junos-icmp-time-exceeded', 'junos-icmp-timestamp',
  'junos-ping', 'junos-traceroute',
  // Additional common (widely available on modern Junos)
  'junos-rdp', 'junos-mysql', 'junos-ipsec',
  'junos-smb-session', 'junos-netbios-session', 'junos-twamp',
  'junos-stun', 'junos-quic', 'junos-ocsp',
]);

/** FortiGate predefined service names (case-sensitive). */
const FORTIGATE_SERVICES = {
  'HTTP': 'junos-http',
  'HTTPS': 'junos-https',
  'DNS': 'junos-dns-udp',
  'FTP': 'junos-ftp',
  'FTP_GET': 'junos-ftp',
  'FTP_PUT': 'junos-ftp',
  'TFTP': 'junos-tftp',
  'SSH': 'junos-ssh',
  'TELNET': 'junos-telnet',
  'SMTP': 'junos-smtp',
  'SMTPS': 'junos-smtps',
  'POP3': 'junos-pop3',
  'POP3S': 'junos-pop3s',
  'IMAP': 'junos-imap',
  'IMAPS': 'junos-imaps',
  'SNMP': 'junos-snmp',
  'NTP': 'junos-ntp',
  'SYSLOG': 'junos-syslog',
  'RDP': 'junos-rdp',
  'SIP': 'junos-sip',
  'SIP-MSNmessenger': 'junos-sip',
  'H.323': 'junos-h323',
  'PING': 'junos-ping',
  'PING6': 'junos-icmp-any',
  'TRACEROUTE': 'junos-traceroute',
  'IKE': 'junos-ike',
  'IKE_NAT_TRAVERSAL': 'junos-ike-nat',
  'L2TP': 'junos-l2tp',
  'PPTP': 'junos-pptp',
  'IRC': 'junos-irc',
  'LDAP': 'junos-ldap',
  'LDAP_UDP': 'junos-ldap',
  'SMB': 'junos-smb',
  'SAMBA': 'junos-smb',
  'DCE-RPC': 'junos-ms-rpc-epm',
  'MS-SQL': 'junos-ms-sql',
  'MYSQL': 'junos-mysql',
  'RADIUS': 'junos-radius',
  'RADIUS-OLD': 'junos-radius',
  'WINS': 'junos-nbname',
  'NBNAME': 'junos-nbname',
  'NBDATAGRAM': 'junos-nbds',
  'NBSESSION': 'junos-smb',
  'NFS': 'junos-nfs',
  'X-WINDOWS': 'junos-x-windows',
  'VNC': 'junos-vnc',
  'BGP': 'junos-bgp',
  'OSPF': 'junos-ospf',
  'RIP': 'junos-rip',
  'GRE': 'junos-gre',
  'STUN': 'junos-stun',
  'QUIC': 'junos-quic',
  'FINGER': 'junos-finger',
  'GOPHER': 'junos-gopher',
  'NNTP': 'junos-nntp',
  'WHOIS': 'junos-whois',
  'AH': 'junos-ipsec',
  'ESP': 'junos-ipsec',
  'ALL': 'any',
  'ALL_TCP': 'junos-tcp-any',
  'ALL_UDP': 'junos-udp-any',
  'ALL_ICMP': 'junos-icmp-any',
  'ALL_ICMP6': 'junos-icmp-any',
  'webproxy': 'junos-http',
  'DHCP': 'junos-dhcp-client',
  'SCP': 'junos-ssh',
  'SFTP': 'junos-ssh',
  'TWAMP': 'junos-twamp',
  'SNMP_TRAP': 'junos-snmp',
  'RADIUS_ACCOUNTING': 'junos-radius-accounting',
  'TIMESTAMP': 'junos-icmp-timestamp',
  'INFO_REQUEST': 'junos-icmp-info',
  'INFO_ADDRESS': 'junos-icmp-address-mask',
  'SCCP': 'junos-sccp',
  'PC-Anywhere': 'junos-pc-anywhere',
  'LPR': 'junos-lpr',
  'UUCP': 'junos-uucp',
  'TALK': 'junos-talk',
};

/** Cisco ASA named ports / keywords. */
const ASA_SERVICES = {
  // Bare protocol keywords the ASA parser synthesizes from ACEs
  'icmp': 'junos-icmp-all',
  'icmp6': 'junos-icmp-any',
  'ipsec': 'junos-ipsec',
  'imap4': 'junos-imap',
  'h323': 'junos-h323',
  'www': 'junos-http',
  'domain': 'junos-dns-udp',
  'sunrpc': 'junos-sun-rpc-any',
  'login': 'junos-rlogin',
  'shell': 'junos-rsh',
  'exec': 'junos-rsh',
  'lpd': 'junos-lpr',
};

/** PAN-OS predefined service objects. */
const PANOS_SERVICES = {
  'service-http': 'junos-http',
  'service-https': 'junos-https',
};

/**
 * Multi-vendor application name → Junos predefined application mapping.
 * Covers PAN-OS, FortiGate service names (uppercase), and Cisco ASA names.
 * Returns null if no mapping exists.
 *
 * @param {string} appName - Application or service name from any vendor
 * @returns {string|null} - Junos application name or null
 */
const APP_MAP = {
  // ── Uppercase vendor names (Huawei, FortiGate, etc.) ─────
  'HTTP': 'junos-http',
  'HTTPS': 'junos-https',
  'DNS': 'junos-dns-udp',
  'SSH': 'junos-ssh',
  'FTP': 'junos-ftp',
  'TELNET': 'junos-telnet',
  'SMTP': 'junos-smtp',
  'NTP': 'junos-ntp',
  'SNMP': 'junos-snmp',
  'ICMP': 'junos-icmp-all',
  'PING': 'junos-ping',
  'TRACEROUTE': 'junos-traceroute',
  'RDP': 'junos-rdp',
  'POP3': 'junos-pop3',
  'IMAP': 'junos-imap',
  'TFTP': 'junos-tftp',
  'SYSLOG': 'junos-syslog',
  'DHCP': 'junos-dhcp-client',
  'LDAP': 'junos-ldap',
  'BGP': 'junos-bgp',
  'SIP': 'junos-sip',
  // ── PAN-OS Application Names ──────────────────────────────
  // Web
  'web-browsing': 'junos-http',
  'ssl': 'junos-https',
  'http2': 'junos-http',
  'http': 'junos-http',
  'https': 'junos-https',
  // DNS
  'dns': 'junos-dns-udp',
  'dns-base': 'junos-dns-udp',
  // Mail
  'smtp': 'junos-smtp',
  'smtp-base': 'junos-smtp',
  'pop3': 'junos-pop3',
  'imap': 'junos-imap',
  'imap4': 'junos-imap',
  'pop3s': 'junos-pop3s',
  'imaps': 'junos-imaps',
  'smtps': 'junos-smtps',
  // File transfer
  'ftp': 'junos-ftp',
  'ftp-data': 'junos-ftp-data',
  'tftp': 'junos-tftp',
  // Remote access
  'ssh': 'junos-ssh',
  'telnet': 'junos-telnet',
  'rdp': 'junos-rdp',
  'ms-rdp': 'junos-rdp',
  'rlogin': 'junos-rlogin',
  'rsh': 'junos-rsh',
  'vnc': 'junos-vnc',
  'vnc-base': 'junos-vnc',
  'pc-anywhere': 'junos-pc-anywhere',
  'pcanywhere': 'junos-pc-anywhere',
  // Network services
  'ping': 'junos-ping',
  'traceroute': 'junos-traceroute',
  'ntp': 'junos-ntp',
  'ntp-base': 'junos-ntp',
  'snmp': 'junos-snmp',
  'snmpv1': 'junos-snmp',
  'snmpv2c': 'junos-snmp',
  'snmpv3': 'junos-snmp',
  'syslog': 'junos-syslog',
  'dhcp': 'junos-dhcp-client',
  'dhcp-relay': 'junos-dhcp-relay',
  // VPN / Tunnel
  'ike': 'junos-ike',
  'ike-base': 'junos-ike',
  'ike-nat-traversal': 'junos-ike-nat',
  'ipsec': 'junos-ipsec',
  'ipsec-esp': 'junos-ipsec',
  'l2tp': 'junos-l2tp',
  'pptp': 'junos-pptp',
  // STUN / QUIC
  'stun': 'junos-stun',
  'stun-base': 'junos-stun',
  'quic': 'junos-quic',
  'quic-base': 'junos-quic',
  // Certificate / PKI
  'ocsp': 'junos-ocsp',
  // Database
  'ms-sql-db': 'junos-ms-sql',
  'mssql-db': 'junos-ms-sql',
  'mssql': 'junos-ms-sql',
  'mssql-mon': 'junos-sqlmon',
  'mysql': 'junos-mysql',
  'oracle-db': 'junos-sqlnet-v2',
  'oracle': 'junos-sqlnet-v2',
  'sqlnet': 'junos-sqlnet-v2',
  // Secure file transfer (over SSH)
  'scp': 'junos-ssh',
  'sftp': 'junos-ssh',
  // LDAP / Directory
  'ldap': 'junos-ldap',
  'ldap-base': 'junos-ldap',
  'active-directory': 'junos-ldap',
  'ms-ds-smbv2': 'junos-smb',
  'ms-ds-smbv3': 'junos-smb',
  'ms-ds-smb-base': 'junos-smb',
  // ICMP
  'icmp': 'junos-icmp-all',
  'icmp6': 'junos-icmp-any',
  // Streaming / VoIP
  'sip': 'junos-sip',
  'sip-base': 'junos-sip',
  'h323': 'junos-h323',
  'h.323': 'junos-h323',
  'rtsp': 'junos-rtsp',
  'rtsp-base': 'junos-rtsp',
  'sccp': 'junos-sccp',
  'skinny': 'junos-sccp',
  'netmeeting': 'junos-netmeeting',
  'real-audio': 'junos-realaudio',
  'realaudio': 'junos-realaudio',
  'vdo-live': 'junos-vdo-live',
  // Routing
  'bgp': 'junos-bgp',
  'ospf': 'junos-ospf',
  'rip': 'junos-rip',
  // IM / P2P
  'irc': 'junos-irc',
  'msn-messenger': 'junos-msn',
  'ymsg': 'junos-ymsg',
  'yahoo-messenger': 'junos-ymsg',
  'gnutella': 'junos-gnutella',
  'aol-instant-messenger': 'junos-aol',
  'aim': 'junos-aol',
  // Microsoft RPC
  'ms-rpc': 'junos-ms-rpc-epm',
  'msrpc': 'junos-ms-rpc-epm',
  'ms-exchange': 'junos-ms-rpc-msexchange',
  // NetBIOS / SMB
  'netbios-ns': 'junos-nbname',
  'netbios-dg': 'junos-nbds',
  'netbios-ss': 'junos-smb',
  'netbios-ssn': 'junos-smb',
  'smb': 'junos-smb',
  'cifs': 'junos-smb',
  // Additional management / network
  'radius-accounting': 'junos-radius-accounting',
  'twamp': 'junos-twamp',
  'snmp-trap': 'junos-snmp',
  'dhcp-server': 'junos-dhcp-server',
  'dhcp-client': 'junos-dhcp-client',
  'syslog-ng': 'junos-syslog',
  'citrix': 'junos-winframe',
  'citrix-online': 'junos-winframe',
  'gre': 'junos-gre',  // IP protocol 47 (junos-defaults: application junos-gre term t1 protocol 47)
  // Misc management
  'finger': 'junos-finger',
  'gopher': 'junos-gopher',
  'whois': 'junos-whois',
  'ident': 'junos-ident',
  'lpr': 'junos-lpr',
  'radius': 'junos-radius',
  'nntp': 'junos-nntp',
  'x11': 'junos-x-windows',
  'x-windows': 'junos-x-windows',
  'nfs': 'junos-nfs',
  'sun-rpc': 'junos-sun-rpc-any',
  'rpc-portmapper': 'junos-sun-rpc-portmapper',
  'chargen': 'junos-chargen',
  'discard': 'junos-discard',
  'wais': 'junos-wais',
  'uucp': 'junos-uucp',
  'talk': 'junos-talk',

  ...FORTIGATE_SERVICES,
  ...ASA_SERVICES,
};

/**
 * True when a policy's services restrict the match: at least one entry that is
 * not a vendor wildcard/keyword. An `application any` beside such a service
 * must not widen the policy back to any (PAN-OS: application any AND service S = S).
 * @param {string[]} [services]
 * @returns {boolean}
 */
export function hasSpecificService(services) {
  return (services || []).some(svc => svc !== 'any' && svc !== 'application-default' && svc !== 'service-set');
}

export function mapAppToJunos(appName, sourceVendor = '') {
  if (!appName) return null;

  // Rule 1: passthrough — input is already a valid Junos predefined application
  if (JUNOS_PREDEFINED_APPS.has(appName)) return appName;

  // Rule 2: enhanced app-mappings.json lookup (if loaded, confidence >= 0.8)
  if (sourceVendor) {
    try {
      const result = _mapVendorAppFn?.(appName, sourceVendor);
      if (result && result.confidence >= 0.8) {
        return result.junosApp;
      }
    } catch (_) { /* app mappings not loaded yet, fall through */ }
  }

  // Rule 3: built-in APP_MAP (synchronous, always available)
  if (APP_MAP[appName]) return APP_MAP[appName];
  const normalized = appName.toLowerCase().trim();
  return APP_MAP[normalized] || null;
}

const bundledServiceCatalogs = new Map();

/**
 * Bundled app-mappings.json entries for one vendor whose Junos target is 'any'
 * or a predefined application (confidence >= 0.8, as mapAppToJunos requires).
 * Built from the static import, so it never depends on loadAppMappings().
 * Keys are lower-cased vendor names/aliases; the first app wins, as in the
 * runtime index.
 */
function bundledServiceCatalog(sourceVendor) {
  if (bundledServiceCatalogs.has(sourceVendor)) return bundledServiceCatalogs.get(sourceVendor);
  const catalog = new Map();
  const vendorKey = VENDOR_KEY_MAP[sourceVendor];
  for (const app of vendorKey ? appMappingData.apps : []) {
    const vendorEntry = app.vendors[vendorKey];
    const junosEntry = app.vendors.junos;
    if (!vendorEntry || !junosEntry || junosEntry.confidence < 0.8) continue;
    const target = normalizeJunosName(junosEntry.name);
    if (target !== 'any' && !JUNOS_PREDEFINED_APPS.has(target)) continue;
    for (const key of [vendorEntry.name, ...(vendorEntry.aliases || [])]) {
      if (key && !catalog.has(String(key).toLowerCase())) catalog.set(String(key).toLowerCase(), target);
    }
  }
  bundledServiceCatalogs.set(sourceVendor, catalog);
  return catalog;
}

/**
 * Resolves a policy service reference to a Junos predefined application using
 * only the SOURCE vendor's built-in service catalog. Static (never consults
 * app-mappings.json), so the answer is the same before and after any
 * conversion, and another vendor's names (e.g. PAN-OS "web-browsing" in a
 * FortiGate config) never match. Vendors whose parsers resolve services
 * themselves keep the legacy mapAppToJunos behavior.
 *
 * @param {string} serviceName - Service name from the source config
 * @param {string} [sourceVendor] - Source vendor id (fortigate, cisco_asa, panos, ...)
 * @returns {string|null} Junos application name, 'any', or null when not a built-in
 */
export function mapServiceToJunos(serviceName, sourceVendor = '') {
  if (!serviceName) return null;
  if (JUNOS_PREDEFINED_APPS.has(serviceName)) return serviceName;
  if (['fortigate', 'panos', 'cisco_asa'].includes(sourceVendor)) {
    // User Settings overrides win, with mapVendorApp's semantics (explicit state, not load order)
    const override = getAppOverride(serviceName, sourceVendor);
    if (override) {
      if (override._deleted) return null;
      const target = normalizeJunosName(override.junosApp ?? (override.kind === 'predefined' ? override.name : null));
      return target === 'any' || JUNOS_PREDEFINED_APPS.has(target) ? target : null;
    }
  }
  switch (sourceVendor) {
    case 'fortigate':
      return FORTIGATE_SERVICES[serviceName]
        || bundledServiceCatalog(sourceVendor).get(serviceName.toLowerCase()) || null;
    case 'panos':
      return PANOS_SERVICES[serviceName] || null;
    case 'cisco_asa': {
      if (ASA_SERVICES[serviceName]) return ASA_SERVICES[serviceName];
      const generic = FORTIGATE_SERVICES[serviceName.toUpperCase()];
      if (generic && generic !== 'any') return generic;
      return bundledServiceCatalog(sourceVendor).get(serviceName.toLowerCase()) || null;
    }
    default:
      return mapAppToJunos(serviceName, sourceVendor);
  }
}

// Injected at runtime by engine.js after loadAppMappings() completes
let _mapVendorAppFn = null;
export function setMapVendorApp(fn) {
  _mapVendorAppFn = fn;
}

// Backward-compatible alias
export const mapPanosAppToJunos = mapAppToJunos;

/**
 * Reverse lookup: protocol/port → predefined Junos application name.
 * Used to detect when a custom service object is equivalent to a predefined app
 * so we can skip generating a redundant custom definition.
 * Only covers exact single-port matches (not ranges).
 */
export const WELL_KNOWN_PORTS = {
  'tcp/22':    'junos-ssh',
  'tcp/23':    'junos-telnet',
  'tcp/21':    'junos-ftp',
  'tcp/20':    'junos-ftp-data',
  'tcp/25':    'junos-smtp',
  'tcp/465':   'junos-smtps',
  'tcp/80':    'junos-http',
  'tcp/443':   'junos-https',
  'tcp/53':    'junos-dns-tcp',
  'udp/53':    'junos-dns-udp',
  'tcp/110':   'junos-pop3',
  'tcp/995':   'junos-pop3s',
  'tcp/143':   'junos-imap',
  'tcp/993':   'junos-imaps',
  'udp/69':    'junos-tftp',
  'tcp/3389':  'junos-rdp',
  'tcp/5900':  'junos-vnc',
  'tcp/389':   'junos-ldap',
  'tcp/3306':  'junos-mysql',
  'tcp/1433':  'junos-ms-sql',
  'tcp/1521':  'junos-sqlnet-v2',
  'udp/161':   'junos-snmp',
  'udp/123':   'junos-ntp',
  'udp/514':   'junos-syslog',
  'tcp/514':   'junos-syslog',
  'tcp/79':    'junos-finger',
  'tcp/70':    'junos-gopher',
  'tcp/43':    'junos-whois',
  'tcp/113':   'junos-ident',
  'tcp/515':   'junos-lpr',
  'udp/1812':  'junos-radius',
  'udp/1813':  'junos-radius-accounting',
  'tcp/119':   'junos-nntp',
  'tcp/445':   'junos-smb-session',
  'udp/137':   'junos-nbname',
  'udp/138':   'junos-nbds',
  'tcp/6000':  'junos-x-windows',
  'tcp/179':   'junos-bgp',
  'tcp/5060':  'junos-sip',
  'udp/5060':  'junos-sip',
  'tcp/1720':  'junos-h323',
  'tcp/2000':  'junos-sccp',
  'tcp/554':   'junos-rtsp',
  'udp/500':   'junos-ike',
  'udp/4500':  'junos-ike-nat',
  'udp/1701':  'junos-l2tp',
  'tcp/1723':  'junos-pptp',
  'tcp/513':   'junos-rlogin',
  'tcp/514':   'junos-rsh',
  'udp/520':   'junos-rip',
  'tcp/139':   'junos-netbios-session',
  'tcp/2049':  'junos-nfs',
  'udp/111':   'junos-sun-rpc-portmapper',
  'tcp/111':   'junos-sun-rpc-portmapper',
};

/**
 * Checks if a service object (by name + protocol + port) is equivalent to
 * a predefined Junos application. Returns the Junos app name or null.
 *
 * Checks two paths:
 *   1. Name mapping via mapAppToJunos() (e.g., "ssh" → "junos-ssh")
 *   2. Protocol+port reverse lookup via WELL_KNOWN_PORTS (e.g., tcp/22 → "junos-ssh")
 *
 * @param {string} name - Service object name
 * @param {string} protocol - Protocol (tcp, udp, etc.)
 * @param {string} portRange - Port or port range string
 * @returns {string|null} - Predefined Junos app name, or null if no match
 */
export function isPredefEquivalent(name, protocol, portRange) {
  // 1. Check name mapping first
  const nameMatch = mapAppToJunos(name);
  if (nameMatch && JUNOS_PREDEFINED_APPS.has(nameMatch)) {
    return nameMatch;
  }

  // 2. Check protocol+port reverse lookup (exact single-port only, no ranges/lists)
  if (protocol && portRange && !portRange.includes(',') && !portRange.includes('-')) {
    const key = `${protocol.toLowerCase()}/${portRange}`;
    const portMatch = WELL_KNOWN_PORTS[key];
    if (portMatch) return portMatch;
  }

  return null;
}

/**
 * Maps a PAN-OS security profile type to the corresponding SRX feature and profile name.
 *
 * Security profiles map to SRX as follows:
 *   virus, wildfire-analysis       → UTM anti-virus
 *   url-filtering                  → UTM web-filtering
 *   file-blocking                  → UTM content-filtering
 *   spyware, vulnerability         → IDP
 *   application-control (FortiGate) → AppFW (manual)
 *   email-filter (FortiGate)       → UTM anti-spam
 *   dlp (FortiGate)                → DLP (ICAP)
 *
 * @param {string} profileType - profile type (e.g. 'virus', 'application-control')
 * @param {string} profileName - profile name (e.g. 'default', 'strict')
 * @returns {{ srxFeature: string, srxType: string, srxProfile: string }}
 */
export function mapProfileToSrx(profileType, profileName) {
  const safeName = sanitizeJunosName(profileName).slice(0, 24);
  const mapping = {
    // PAN-OS originated
    'virus':              { srxFeature: 'utm', srxType: 'anti-virus',        srxProfile: `custom-av-${safeName}` },
    'wildfire-analysis':  { srxFeature: 'utm', srxType: 'anti-virus',        srxProfile: `custom-av-${safeName}` },
    'url-filtering':      { srxFeature: 'utm', srxType: 'web-filtering',     srxProfile: `custom-wf-${safeName}` },
    'file-blocking':      { srxFeature: 'unsupported', srxType: 'content-filtering', srxProfile: `junos-cf-${safeName}` },
    'spyware':            { srxFeature: 'idp', srxType: 'idp-policy',        srxProfile: `idp-${safeName}` },
    'vulnerability':      { srxFeature: 'idp', srxType: 'idp-policy',        srxProfile: `idp-${safeName}` },
    // FortiGate originated
    'application-control': { srxFeature: 'appfw', srxType: 'application-firewall', srxProfile: `appfw-${safeName}` },
    'email-filter':        { srxFeature: 'utm',   srxType: 'anti-spam',            srxProfile: `junos-as-${safeName}` },
    'dlp':                 { srxFeature: 'none',  srxType: 'dlp',                  srxProfile: safeName },
    'dns-security':        { srxFeature: 'utm',   srxType: 'dns-security',         srxProfile: `dns-${safeName}` },
  };
  return mapping[profileType] || { srxFeature: 'unknown', srxType: profileType, srxProfile: safeName };
}

// Backward-compatible alias
export const mapPanosProfileToSrx = mapProfileToSrx;

/**
 * Detects the source vendor/format from raw config text.
 * Currently supports PAN-OS XML detection; will be extended for
 * FortiGate, Cisco ASA, and Check Point in later phases.
 *
 * @param {string} configText - Raw configuration text
 * @returns {{ vendor: string, format: string, confidence: number }}
 */
export function detectVendor(configText) {
  const trimmed = configText.trim();

  // PAN-OS: XML with <config> root element and typical PAN-OS markers
  if (trimmed.startsWith('<?xml') || trimmed.startsWith('<config')) {
    if (trimmed.includes('<vsys>') || trimmed.includes('<devices>') || trimmed.includes('<panorama>')) {
      return { vendor: 'panos', format: 'xml', confidence: 0.95 };
    }
    // Generic XML with PAN-OS-like content
    if (trimmed.includes('paloaltonetworks') || trimmed.includes('pan-os')) {
      return { vendor: 'panos', format: 'xml', confidence: 0.85 };
    }
  }

  // FortiGate / FortiOS: config/edit/set/next/end block format
  if (trimmed.includes('config firewall policy') && (trimmed.includes('set srcintf') || trimmed.includes('set dstintf'))) {
    return { vendor: 'fortigate', format: 'fortigate', confidence: 0.95 };
  }
  if (trimmed.includes('config system global') && (trimmed.includes('set hostname') || trimmed.includes('config firewall'))) {
    return { vendor: 'fortigate', format: 'fortigate', confidence: 0.95 };
  }
  if (trimmed.includes('config firewall address') && trimmed.includes('set subnet')) {
    return { vendor: 'fortigate', format: 'fortigate', confidence: 0.9 };
  }
  if (trimmed.includes('config firewall') && /\bedit\s+\d+\b/.test(trimmed) && trimmed.includes('\nnext')) {
    return { vendor: 'fortigate', format: 'fortigate', confidence: 0.85 };
  }
  if (trimmed.includes('set uuid') && trimmed.includes('config firewall')) {
    return { vendor: 'fortigate', format: 'fortigate', confidence: 0.85 };
  }

  // Cisco ASA: access-list + access-group + nameif/security-level markers
  if (trimmed.includes('access-list') && trimmed.includes('access-group') && (trimmed.includes('nameif') || trimmed.includes('security-level'))) {
    return { vendor: 'cisco_asa', format: 'text', confidence: 0.95 };
  }
  if (trimmed.includes('ASA Version') && trimmed.includes('access-list')) {
    return { vendor: 'cisco_asa', format: 'text', confidence: 0.95 };
  }
  if (trimmed.includes('access-list') && trimmed.includes('extended') && (trimmed.includes('nameif') || trimmed.includes('object network'))) {
    return { vendor: 'cisco_asa', format: 'text', confidence: 0.9 };
  }
  if (trimmed.includes('object network') && trimmed.includes('object-group network') && trimmed.includes('access-list')) {
    return { vendor: 'cisco_asa', format: 'text', confidence: 0.85 };
  }
  if (trimmed.includes('access-list') && trimmed.includes('access-group')) {
    return { vendor: 'cisco_asa', format: 'text', confidence: 0.7 };
  }

  // Junos SRX: set commands format
  if (trimmed.includes('set security policies') || trimmed.includes('set security zones')) {
    return { vendor: 'srx', format: 'set', confidence: 0.95 };
  }
  if (trimmed.includes('set logical-systems') || trimmed.includes('set tenants')) {
    return { vendor: 'srx', format: 'set', confidence: 0.95 };
  }
  if (trimmed.includes('set security') && (trimmed.includes('from-zone') || trimmed.includes('address-book'))) {
    return { vendor: 'srx', format: 'set', confidence: 0.9 };
  }

  // Junos SRX: hierarchical format
  if (trimmed.includes('security {') && (trimmed.includes('policies {') || trimmed.includes('zones {'))) {
    return { vendor: 'srx', format: 'hierarchical', confidence: 0.9 };
  }
  if (trimmed.includes('security-zone') && trimmed.includes('interfaces {')) {
    return { vendor: 'srx', format: 'hierarchical', confidence: 0.85 };
  }

  // Junos generic (could be SRX or other Junos device)
  if (/^set\s+(system|interfaces|routing-options|protocols|security|logical-systems|tenants)\s/m.test(trimmed)) {
    return { vendor: 'srx', format: 'set', confidence: 0.7 };
  }

  // Check Point R80+: JSON with objects-dictionary + rulebase
  // SonicWall REST API: JSON with access_rules + address_objects
  // Use a larger probe for Check Point since objects-dictionary can be very long
  try {
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      const probe = trimmed.slice(0, 2000);
      const probeLarge = trimmed.slice(0, 8000);
      if (probe.includes('"objects-dictionary"') && probeLarge.includes('"rulebase"')) {
        return { vendor: 'checkpoint', format: 'json', confidence: 0.95 };
      }
      if (probe.includes('"objects-dictionary"') && (probeLarge.includes('"access-section"') || probeLarge.includes('"access-rule"'))) {
        return { vendor: 'checkpoint', format: 'json', confidence: 0.90 };
      }
      if (probe.includes('"access_rules"') && probe.includes('"address_objects"')) {
        return { vendor: 'sonicwall', format: 'json', confidence: 0.95 };
      }
      if (probe.includes('"zones"') && probe.includes('"address_objects"') && probe.includes('"ipv4"')) {
        return { vendor: 'sonicwall', format: 'json', confidence: 0.90 };
      }
    }
  } catch (e) { /* not JSON — continue */ }

  // SonicWall CLI: address-object + access-rule keywords
  if (trimmed.includes('address-object ipv4') && trimmed.includes('access-rule ipv4')) {
    return { vendor: 'sonicwall', format: 'text', confidence: 0.90 };
  }

  // Huawei USG VRP: security-policy + firewall zone
  if (trimmed.includes('security-policy') && trimmed.includes('firewall zone')) {
    return { vendor: 'huawei_usg', format: 'text', confidence: 0.95 };
  }
  if (trimmed.includes('sysname') && trimmed.includes('firewall zone')) {
    return { vendor: 'huawei_usg', format: 'text', confidence: 0.90 };
  }
  if (trimmed.includes('ip address-set') && trimmed.includes('type object')) {
    return { vendor: 'huawei_usg', format: 'text', confidence: 0.85 };
  }

  // Cloud firewall formats (JSON-based)
  try {
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      const probe = trimmed.slice(0, 3000);
      // AWS Security Groups: SecurityGroups array with GroupId, IpPermissions
      if (probe.includes('"SecurityGroups"') && probe.includes('"GroupId"')) {
        return { vendor: 'aws_sg', format: 'json', confidence: 0.95 };
      }
      if (probe.includes('"IpPermissions"') && probe.includes('"VpcId"')) {
        return { vendor: 'aws_sg', format: 'json', confidence: 0.90 };
      }
      // Azure NSG: securityRules with priority, direction, access
      if (probe.includes('"securityRules"') && (probe.includes('"priority"') || probe.includes('"direction"'))) {
        return { vendor: 'azure_nsg', format: 'json', confidence: 0.95 };
      }
      // GCP Firewall Rules: array with allowed/denied, sourceRanges, network
      if (probe.includes('"sourceRanges"') && (probe.includes('"allowed"') || probe.includes('"denied"'))) {
        return { vendor: 'gcp_fw', format: 'json', confidence: 0.95 };
      }
      if (probe.includes('"IPProtocol"') && probe.includes('"network"')) {
        return { vendor: 'gcp_fw', format: 'json', confidence: 0.85 };
      }
    }
  } catch (e) { /* not JSON — continue */ }

  // Default: assume PAN-OS XML if it looks like XML
  if (trimmed.startsWith('<')) {
    return { vendor: 'panos', format: 'xml', confidence: 0.5 };
  }

  return { vendor: 'unknown', format: 'unknown', confidence: 0 };
}

/**
 * Detects a NAT rule whose original ingress interface is not scoped by its
 * zone-keyed SRX rule-set: either the interface is one of several members of the
 * from-zone (`widened`), or it is no longer a member of that zone at all
 * (`not-member`). Evaluated against the current zone list so zone edits made
 * after parsing are honoured. Zone-less rules (from-zone named after the
 * interface itself) and single-member zones containing the interface return null.
 *
 * @param {Object} rule - NAT rule with optional `ingress_interface` and `src_zones`
 * @param {Object[]} zones - Current config.zones entries
 * @returns {{interfaceName: string, zone: string, kind: 'widened'|'not-member'}|null}
 */
export function findWidenedIngressScope(rule, zones) {
  const interfaceName = rule?.ingress_interface;
  const zone = rule?.src_zones?.[0];
  if (!interfaceName || !zone) return null;
  const zoneEntry = (zones || []).find((candidate) => candidate.name === zone);
  if (!zoneEntry && zone === interfaceName) return null;
  const members = zoneEntry?.interfaces || [];
  if (!members.includes(interfaceName)) return { interfaceName, zone, kind: 'not-member' };
  if (members.length <= 1) return null;
  return { interfaceName, zone, kind: 'widened' };
}

/**
 * Decides, once for all rules, which destination NAT rules can be scoped with
 * `rule-set ... from interface`: a single-source-zone rule whose VIP interface
 * sits in a shared zone (`widened`).
 *
 * Junos evaluates only the most specific matching rule-set (interface over zone),
 * so a zone is split by interface only when EVERY destination rule entering from
 * it qualifies; one broader rule (any interface, several zones, not a member)
 * keeps the whole zone on the zone-scoped rule-set.
 *
 * @param {Object[]} natRules - All NAT rules
 * @param {Object[]} zones - Current config.zones entries
 * @returns {Map<Object, string>} Rule -> source interface name, only for scoped rules
 */
export function planInterfaceScopedIngress(natRules, zones) {
  const candidates = new Map();
  const blockedZones = new Set();
  for (const rule of natRules || []) {
    const isDestination = (rule.type || 'source') === 'destination' || rule.type === 'source-and-destination';
    if (!isDestination) continue;
    const scope = rule.src_zones?.length === 1 ? findWidenedIngressScope(rule, zones) : null;
    if (scope?.kind === 'widened') {
      candidates.set(rule, scope.interfaceName);
      continue;
    }
    const entering = rule.src_zones ?? rule.source_zones;
    for (const zone of Array.isArray(entering) && entering.length > 0 ? entering : ['any']) blockedZones.add(zone);
  }
  if (blockedZones.has('any')) return new Map();
  return new Map([...candidates].filter(([rule]) => !blockedZones.has(rule.src_zones[0])));
}

/**
 * Plans the ingress-scope advice for the rules of ONE destination NAT rule-set.
 * A rule-set's `from` applies to all its rules, so when the flagged rules need
 * different ingress interfaces a single "split the rule-set" item is returned;
 * otherwise one per-rule item suggests `from interface <iface>`.
 *
 * @param {Object[]} rules - NAT rules sharing one rule-set
 * @param {Object[]} zones - Current config.zones entries
 * @param {function(string): string} [mapInterface] - Source -> SRX interface name
 * @returns {{rules: Object[], grouped: boolean, message: string, suggestion: string, caveat: string}[]}
 */
export function planIngressScopeAdvice(rules, zones, mapInterface = (name) => name) {
  const flagged = [];
  for (const rule of rules || []) {
    const scope = findWidenedIngressScope(rule, zones);
    if (scope) flagged.push({ rule, scope, mapped: mapInterface(scope.interfaceName) });
  }
  if (flagged.length === 0) return [];

  // A rule-set's `from` applies to every rule in it, so judge the whole rule-set:
  // unflagged VIPs with another ingress interface would be broken by scoping.
  const ingressRules = (rules || [])
    .filter((rule) => rule?.ingress_interface)
    .map((rule) => ({ rule, mapped: mapInterface(rule.ingress_interface) }));
  const distinctInterfaces = new Set(ingressRules.map((entry) => entry.mapped));
  if (distinctInterfaces.size > 1) {
    const zone = flagged[0].scope.zone;
    const listing = ingressRules.map((entry) => `${entry.rule.name}: ${entry.mapped}`).join(', ');
    return [{
      rules: ingressRules.map((entry) => entry.rule),
      grouped: true,
      message: `VIPs in one destination NAT rule-set (zone ${zone}) have different ingress interfaces (${listing}), but the rule-set is zone-scoped and matches every interface in zone ${zone}`,
      suggestion: 'Split the rule-set by ingress interface, giving each its own "from interface <iface>"',
      caveat: `rule-set for zone ${zone} mixes VIPs with different ingress interfaces (${listing}) — split the rule-set by ingress interface`,
    }];
  }

  return flagged.map(({ rule, scope, mapped }) => {
    const notMember = scope.kind === 'not-member';
    return {
      rules: [rule],
      grouped: false,
      message: notMember
        ? `VIP ${rule.name}'s ingress interface ${scope.interfaceName} is not in zone ${scope.zone}, but the SRX destination NAT rule-set is zone-scoped and matches that zone's interfaces instead`
        : `VIP ${rule.name} was limited to interface ${scope.interfaceName}, but the SRX destination NAT rule-set is zone-scoped and matches all interfaces in zone ${scope.zone}`,
      suggestion: `Scope the rule-set with "from interface ${mapped}"`,
      caveat: notMember
        ? `VIP ${rule.name}'s ingress interface ${scope.interfaceName} is not in zone ${scope.zone}; this rule-set matches that zone's interfaces instead — scope it with "from interface ${mapped}"`
        : `VIP ${rule.name} was limited to interface ${scope.interfaceName}; this rule-set matches all of zone ${scope.zone} — scope it with "from interface ${mapped}"`,
    };
  });
}
