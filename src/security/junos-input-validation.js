import {
  JunosSerializationError,
  assertSafeScalar,
  setAddressOrPrefix,
  setEnum,
  setInteger,
  setPort,
  setToken,
} from './junos-serialization.js';

const POLICY_ACTIONS = [
  'allow',
  'permit',
  'accept',
  'deny',
  'reject',
  'drop',
  'discard',
  'reset-client',
  'reset-server',
  'reset-both',
];

// Transient UI/analysis metadata attached to the working config for display
// only. These never reach the generated Junos config, so the output serializer
// must not police them (e.g. the duplicates finding keys join names with NUL).
const NON_SERIALIZED_METADATA_KEYS = new Set(['_analysisFindings', '_review_status']);

function joinPath(parent, key) {
  if (typeof key === 'number') return `${parent}[${key}]`;
  return parent ? `${parent}.${key}` : key;
}

function walkScalars(value, path) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkScalars(item, joinPath(path, index)));
    return;
  }
  if (value !== null && typeof value === 'object') {
    Object.entries(value).forEach(([key, child]) => {
      if (NON_SERIALIZED_METADATA_KEYS.has(key)) return;
      walkScalars(child, joinPath(path, key));
    });
    return;
  }
  if (value !== null && value !== undefined) assertSafeScalar(value, path);
}

function validateDnsName(value, fieldPath) {
  const text = assertSafeScalar(value, fieldPath);
  const withoutWildcard = text.startsWith('*.') ? text.slice(2) : text;
  if (withoutWildcard.length < 1 || withoutWildcard.length > 253) {
    throw new JunosSerializationError(fieldPath, 'DNS name', 'expected a DNS name up to 253 characters');
  }
  const labels = withoutWildcard.split('.');
  if (labels.some(label => (
    label.length < 1
    || label.length > 63
    || !/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label)
  ))) {
    throw new JunosSerializationError(fieldPath, 'DNS name', 'expected valid DNS labels');
  }
}

function validateNetworkEndpoint(value, fieldPath) {
  try {
    setAddressOrPrefix(value, fieldPath);
    return;
  } catch (error) {
    if (!(error instanceof JunosSerializationError)) throw error;
  }
  validateDnsName(value, fieldPath);
}

function validateAddressOrReference(value, fieldPath) {
  try {
    setAddressOrPrefix(value, fieldPath);
    return;
  } catch (error) {
    if (!(error instanceof JunosSerializationError)) throw error;
  }
  setToken(value, fieldPath, /^[A-Za-z0-9_.:/-]+$/);
}

function validateInterfaceName(value, fieldPath) {
  setToken(value, fieldPath, /^[A-Za-z0-9_.:/-]+$/);
}

function validateSystem(systemConfig, basePath) {
  if (!systemConfig || typeof systemConfig !== 'object') return;
  if (systemConfig.domain_name) validateDnsName(systemConfig.domain_name, `${basePath}.domain_name`);
  (systemConfig.dns_servers || []).forEach((server, index) => (
    validateNetworkEndpoint(server, `${basePath}.dns_servers[${index}]`)
  ));
  (systemConfig.ntp_servers || []).forEach((server, index) => (
    validateNetworkEndpoint(server, `${basePath}.ntp_servers[${index}]`)
  ));
  if (systemConfig.timezone) {
    setToken(systemConfig.timezone, `${basePath}.timezone`, /^[A-Za-z0-9_+/-]+$/);
  }
}

function validateAddressRange(value, fieldPath) {
  const text = assertSafeScalar(value, fieldPath);
  const separator = text.indexOf('-');
  if (separator < 1 || separator !== text.lastIndexOf('-')) {
    throw new JunosSerializationError(fieldPath, 'address range', 'expected two IP addresses separated by one hyphen');
  }
  setAddressOrPrefix(text.slice(0, separator), fieldPath);
  setAddressOrPrefix(text.slice(separator + 1), fieldPath);
}

function validatePortExpression(value, fieldPath) {
  const text = assertSafeScalar(value, fieldPath);
  if (text === '' || text === 'any') return;

  for (const item of text.split(',')) {
    const part = item.trim();
    if (!part) {
      throw new JunosSerializationError(fieldPath, 'port', 'expected ports or inclusive port ranges');
    }
    const range = part.split('-');
    if (range.length === 1) {
      setPort(range[0], fieldPath);
    } else if (range.length === 2) {
      setPort(range[0], fieldPath);
      setPort(range[1], fieldPath);
      if (Number(range[0]) > Number(range[1])) {
        throw new JunosSerializationError(fieldPath, 'port', 'range start must not exceed range end');
      }
    } else {
      throw new JunosSerializationError(fieldPath, 'port', 'expected ports or inclusive port ranges');
    }
  }
}

function addressValue(object) {
  const fields = ['value', 'ip', 'network', 'subnet', 'address'];
  const key = fields.find(candidate => object[candidate] !== undefined && object[candidate] !== '');
  return key ? { key, value: object[key] } : null;
}

function validateAddressObjects(objects, basePath) {
  if (!Array.isArray(objects)) return;
  objects.forEach((object, index) => {
    if (!object || typeof object !== 'object') return;
    const located = addressValue(object);
    if (!located) return;
    const fieldPath = `${basePath}[${index}].${located.key}`;

    if (['host', 'subnet', 'network', 'ip-netmask', 'ip-prefix'].includes(object.type)) {
      setAddressOrPrefix(located.value, fieldPath);
    } else if (object.type === 'range') {
      validateAddressRange(located.value, fieldPath);
    } else if (object.type === 'fqdn') {
      validateDnsName(located.value, fieldPath);
    }
  });
}

function validatePolicies(policies, basePath) {
  if (!Array.isArray(policies)) return;
  policies.forEach((policy, index) => {
    if (policy?.action !== undefined && policy.action !== '') {
      setEnum(
        String(policy.action).toLowerCase(),
        POLICY_ACTIONS,
        `${basePath}[${index}].action`,
      );
    }
  });
}

function validateServicePorts(services, basePath) {
  if (!Array.isArray(services)) return;
  services.forEach((service, index) => {
    if (!service || typeof service !== 'object') return;
    for (const key of ['port', 'port_range', 'source_port', 'src_port', 'dst_port']) {
      if (service[key] !== undefined && service[key] !== null) {
        validatePortExpression(service[key], `${basePath}[${index}].${key}`);
      }
    }
    if (service.protocol !== undefined && service.protocol !== '') {
      const protocol = String(service.protocol).toLowerCase();
      const supported = [
        'tcp', 'udp', 'sctp', 'icmp', 'icmp6', 'ip', 'gre', 'esp', 'ah',
        'ospf', 'igmp', 'pim', 'ipip', 'ipv6', 'any', 'netflow-v9',
        'sflow', 'radius',
      ];
      if (/^\d+$/.test(protocol)) {
        setInteger(protocol, { min: 0, max: 255 }, `${basePath}[${index}].protocol`);
      } else {
        setEnum(protocol, supported, `${basePath}[${index}].protocol`);
      }
    }
  });
}

function validateInterfaces(interfaces, basePath) {
  if (!Array.isArray(interfaces)) return;
  interfaces.forEach((iface, index) => {
    if (!iface || typeof iface !== 'object') return;
    if (iface.name) validateInterfaceName(iface.name, `${basePath}[${index}].name`);
    // NOTE: interface ip/ipv6 are intentionally NOT hard-validated here. A
    // non-literal PAN-OS value (named object ref, scoped link-local, EUI-64
    // suffix, dhcpv6 keyword) must not abort the whole conversion. Control-char
    // injection is already blocked by walkScalars; the converter skips a
    // malformed address with a caveat + warning, and validateSetOutput is the
    // fail-closed backstop on emitted commands.
  });
}

function validateSchedules(schedules, basePath) {
  if (!Array.isArray(schedules)) return;
  const days = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
  schedules.forEach((schedule, index) => {
    const schedulePath = `${basePath}[${index}]`;
    if (schedule.type) setEnum(schedule.type, ['recurring', 'onetime'], `${schedulePath}.type`);
    (schedule.days || []).forEach((day, dayIndex) => (
      setEnum(String(day).toLowerCase(), days, `${schedulePath}.days[${dayIndex}]`)
    ));
    if (schedule.type === 'recurring') {
      for (const key of ['start', 'end']) {
        if (schedule[key]) setToken(schedule[key], `${schedulePath}.${key}`, /^(?:[01]\d|2[0-3]):[0-5]\d$/);
      }
    }
  });
}

function validateOspf(configs, basePath) {
  if (!Array.isArray(configs)) return;
  configs.forEach((ospf, ospfIndex) => {
    const ospfPath = `${basePath}[${ospfIndex}]`;
    if (ospf.router_id) setAddressOrPrefix(ospf.router_id, `${ospfPath}.router_id`);
    if (ospf.reference_bandwidth) setInteger(ospf.reference_bandwidth, { min: 1 }, `${ospfPath}.reference_bandwidth`);
    (ospf.areas || []).forEach((area, areaIndex) => {
      const areaPath = `${ospfPath}.areas[${areaIndex}]`;
      if (area.area_id !== undefined) setToken(area.area_id, `${areaPath}.area_id`, /^(?:\d+|(?:\d{1,3}\.){3}\d{1,3})$/);
      if (area.area_type) setEnum(area.area_type, ['normal', 'stub', 'totally-stub', 'nssa', 'totally-nssa'], `${areaPath}.area_type`);
      (area.interfaces || []).forEach((iface, ifaceIndex) => {
        const ifacePath = `${areaPath}.interfaces[${ifaceIndex}]`;
        if (iface.name) validateInterfaceName(iface.name, `${ifacePath}.name`);
        for (const key of ['cost', 'hello_interval', 'dead_interval', 'instance_id']) {
          if (iface[key] !== undefined && iface[key] !== null) setInteger(iface[key], { min: 0 }, `${ifacePath}.${key}`);
        }
        if (iface.network_type) setToken(iface.network_type, `${ifacePath}.network_type`, /^[A-Za-z0-9-]+$/);
        if (iface.authentication?.key_id) setInteger(iface.authentication.key_id, { min: 0, max: 255 }, `${ifacePath}.authentication.key_id`);
      });
    });
    (ospf.redistribute || []).forEach((item, itemIndex) => {
      const itemPath = `${ospfPath}.redistribute[${itemIndex}]`;
      if (item.protocol) setToken(item.protocol, `${itemPath}.protocol`, /^[A-Za-z0-9-]+$/);
      if (item.metric_type) setToken(item.metric_type, `${itemPath}.metric_type`, /^[A-Za-z0-9-]+$/);
    });
  });
}

function validateBgp(configs, basePath) {
  if (!Array.isArray(configs)) return;
  configs.forEach((bgp, bgpIndex) => {
    const bgpPath = `${basePath}[${bgpIndex}]`;
    if (bgp.local_as) setInteger(bgp.local_as, { min: 1, max: 4294967295 }, `${bgpPath}.local_as`);
    if (bgp.router_id) setAddressOrPrefix(bgp.router_id, `${bgpPath}.router_id`);
    (bgp.peer_groups || []).forEach((group, groupIndex) => {
      const groupPath = `${bgpPath}.peer_groups[${groupIndex}]`;
      if (group.type) setEnum(group.type, ['internal', 'external'], `${groupPath}.type`);
      (group.neighbors || []).forEach((neighbor, neighborIndex) => {
        const neighborPath = `${groupPath}.neighbors[${neighborIndex}]`;
        if (neighbor.address) validateNetworkEndpoint(neighbor.address, `${neighborPath}.address`);
        if (neighbor.local_address) setAddressOrPrefix(neighbor.local_address, `${neighborPath}.local_address`);
        if (neighbor.peer_as) setInteger(neighbor.peer_as, { min: 1, max: 4294967295 }, `${neighborPath}.peer_as`);
        for (const key of ['import_policy', 'export_policy']) {
          if (neighbor[key]) setToken(neighbor[key], `${neighborPath}.${key}`, /^[A-Za-z0-9_.:/-]+$/);
        }
      });
    });
    (bgp.networks || []).forEach((network, networkIndex) => {
      if (network.policy) setToken(network.policy, `${bgpPath}.networks[${networkIndex}].policy`, /^[A-Za-z0-9_.:/-]+$/);
    });
    (bgp.redistribute || []).forEach((item, itemIndex) => {
      if (item.protocol) setToken(item.protocol, `${bgpPath}.redistribute[${itemIndex}].protocol`, /^[A-Za-z0-9-]+$/);
      if (item.policy) setToken(item.policy, `${bgpPath}.redistribute[${itemIndex}].policy`, /^[A-Za-z0-9_.:/-]+$/);
    });
  });
}

function validateVpn(tunnels, basePath) {
  if (!Array.isArray(tunnels)) return;
  tunnels.forEach((vpn, index) => {
    const vpnPath = `${basePath}[${index}]`;
    const gateway = vpn.ike_gateway || {};
    if (gateway.external_interface) validateInterfaceName(gateway.external_interface, `${vpnPath}.ike_gateway.external_interface`);
    if (vpn.tunnel_interface) validateInterfaceName(vpn.tunnel_interface, `${vpnPath}.tunnel_interface`);
    if (gateway.address) validateNetworkEndpoint(gateway.address, `${vpnPath}.ike_gateway.address`);
    if (gateway.local_address && !/^(?:ge|xe|et|ae|lo|irb|reth)-?\d/i.test(gateway.local_address)) {
      setAddressOrPrefix(gateway.local_address, `${vpnPath}.ike_gateway.local_address`);
    }
    (vpn.proxy_id || []).forEach((selector, selectorIndex) => {
      if (selector.local) setAddressOrPrefix(selector.local, `${vpnPath}.proxy_id[${selectorIndex}].local`);
      if (selector.remote) setAddressOrPrefix(selector.remote, `${vpnPath}.proxy_id[${selectorIndex}].remote`);
    });
    for (const [proposalKey, proposal] of [
      ['ike_proposal', vpn.ike_proposal],
      ['ipsec_proposal', vpn.ipsec_proposal],
    ]) {
      if (proposal?.lifetime) {
        setInteger(proposal.lifetime, { min: 1, max: 4294967295 }, `${vpnPath}.${proposalKey}.lifetime`);
      }
      if (proposal) {
        for (const key of ['auth_method', 'dh_group', 'encryption', 'authentication', 'protocol', 'pfs_group']) {
          if (proposal[key]) setToken(proposal[key], `${vpnPath}.${proposalKey}.${key}`, /^[A-Za-z0-9-]+$/);
        }
      }
    }
  });
}

function validateHa(haConfig, basePath) {
  if (!haConfig || typeof haConfig !== 'object') return;
  if (haConfig.group_id !== undefined && haConfig.group_id !== null && haConfig.group_id !== '') {
    setInteger(haConfig.group_id, { min: 0, max: 255 }, `${basePath}.group_id`);
  }
  if (haConfig.priority !== undefined && haConfig.priority !== null && haConfig.priority !== '') {
    setInteger(haConfig.priority, { min: 0, max: 255 }, `${basePath}.priority`);
  }
  if (haConfig.peer_ip) setAddressOrPrefix(haConfig.peer_ip, `${basePath}.peer_ip`);
  if (haConfig.local_ip) setAddressOrPrefix(haConfig.local_ip, `${basePath}.local_ip`);
  for (const key of ['local_id', 'peer_id', 'node_count', 'liveness_interval', 'liveness_multiplier', 'activeness_priority']) {
    if (haConfig[key] !== undefined && haConfig[key] !== null && haConfig[key] !== '') {
      setInteger(haConfig[key], { min: 0 }, `${basePath}.${key}`);
    }
  }
  for (const key of ['icl_interface']) {
    if (haConfig[key]) validateInterfaceName(haConfig[key], `${basePath}.${key}`);
  }
  (haConfig.ha_interfaces || []).forEach((iface, index) => {
    if (iface.interface) validateInterfaceName(iface.interface, `${basePath}.ha_interfaces[${index}].interface`);
    if (iface.ip) setAddressOrPrefix(iface.ip, `${basePath}.ha_interfaces[${index}].ip`);
  });
  (haConfig.additional_peers || []).forEach((peer, index) => {
    const peerPath = `${basePath}.additional_peers[${index}]`;
    if (peer.peer_ip) setAddressOrPrefix(peer.peer_ip, `${peerPath}.peer_ip`);
    if (peer.icl_interface) validateInterfaceName(peer.icl_interface, `${peerPath}.icl_interface`);
    for (const key of ['peer_id', 'liveness_interval', 'liveness_multiplier', 'activeness_priority']) {
      if (peer[key] !== undefined && peer[key] !== null && peer[key] !== '') setInteger(peer[key], { min: 0 }, `${peerPath}.${key}`);
    }
  });
}

function validateNat(rules, basePath) {
  if (!Array.isArray(rules)) return;
  rules.forEach((rule, index) => {
    const rulePath = `${basePath}[${index}]`;
    if (rule.match_port) validatePortExpression(rule.match_port, `${rulePath}.match_port`);
    if (rule.translated_port) validatePortExpression(rule.translated_port, `${rulePath}.translated_port`);
    (rule.match_ports || []).forEach((port, portIndex) => validatePortExpression(port, `${rulePath}.match_ports[${portIndex}]`));
    if (rule.match_protocol) {
      setEnum(String(rule.match_protocol).toLowerCase(), ['tcp', 'udp'], `${rulePath}.match_protocol`);
    }
    const translatedSource = rule.translated_src || {};
    for (const key of ['block_size', 'max_blocks_per_host']) {
      if (translatedSource[key]) setInteger(translatedSource[key], { min: 1 }, `${rulePath}.translated_src.${key}`);
    }
    if (translatedSource.address) validateAddressOrReference(translatedSource.address, `${rulePath}.translated_src.address`);
    (translatedSource.addresses || []).forEach((address, addressIndex) => (
      validateAddressOrReference(address, `${rulePath}.translated_src.addresses[${addressIndex}]`)
    ));
    const translatedDestination = rule.translated_dst;
    if (typeof translatedDestination === 'string') {
      validateAddressOrReference(translatedDestination, `${rulePath}.translated_dst`);
    } else if (translatedDestination?.address) {
      validateAddressOrReference(translatedDestination.address, `${rulePath}.translated_dst.address`);
    }
  });
}

function validateFlow(flowConfig, basePath) {
  if (!flowConfig || typeof flowConfig !== 'object') return;
  if (flowConfig.instance_name) setToken(flowConfig.instance_name, `${basePath}.instance_name`, /^[A-Za-z0-9_.:/-]+$/);
  for (const key of ['input_rate', 'run_length']) {
    if (flowConfig.sampling?.[key]) setInteger(flowConfig.sampling[key], { min: 0 }, `${basePath}.sampling.${key}`);
  }
  (flowConfig.collectors || []).forEach((collector, index) => {
    const collectorPath = `${basePath}.collectors[${index}]`;
    if (collector.address) validateNetworkEndpoint(collector.address, `${collectorPath}.address`);
    if (collector.source_address) setAddressOrPrefix(collector.source_address, `${collectorPath}.source_address`);
    if (collector.port) setPort(collector.port, `${collectorPath}.port`);
    if (collector.protocol) setEnum(collector.protocol, ['ipfix', 'netflow-v10', 'netflow-v9'], `${collectorPath}.protocol`);
  });
  (flowConfig.templates || []).forEach((template, index) => {
    const templatePath = `${basePath}.templates[${index}]`;
    for (const key of ['active_timeout', 'refresh_rate']) {
      if (template[key]) setInteger(template[key], { min: 1 }, `${templatePath}.${key}`);
    }
    if (template.flow_type) setEnum(template.flow_type, ['ipv4', 'ipv6'], `${templatePath}.flow_type`);
  });
}

function validateSyslog(entries, basePath) {
  if (!Array.isArray(entries)) return;
  entries.forEach((entry, index) => {
    const entryPath = `${basePath}[${index}]`;
    if (entry.server && entry.transport !== 'file') validateNetworkEndpoint(entry.server, `${entryPath}.server`);
    if (entry.port) setPort(entry.port, `${entryPath}.port`);
    if (entry.source_address) setAddressOrPrefix(entry.source_address, `${entryPath}.source_address`);
    if (entry.transport) setEnum(entry.transport, ['udp', 'tcp', 'tls', 'file'], `${entryPath}.transport`);
    (entry.facilities || []).forEach((facility, facilityIndex) => {
      if (facility.facility) setToken(facility.facility, `${entryPath}.facilities[${facilityIndex}].facility`, /^[A-Za-z0-9-]+$/);
      if (facility.level) setToken(facility.level, `${entryPath}.facilities[${facilityIndex}].level`, /^[A-Za-z0-9-]+$/);
    });
  });
}

function validateAaa(entries, basePath) {
  if (!Array.isArray(entries)) return;
  entries.forEach((entry, index) => {
    const entryPath = `${basePath}[${index}]`;
    if (entry.type) setEnum(entry.type, ['radius', 'tacplus', 'ldap', 'profile', 'auth-order'], `${entryPath}.type`);
    if (entry.server) validateNetworkEndpoint(entry.server, `${entryPath}.server`);
    if (entry.port) setPort(entry.port, `${entryPath}.port`);
    if (entry.source_address) setAddressOrPrefix(entry.source_address, `${entryPath}.source_address`);
    for (const key of ['timeout', 'retry']) {
      if (entry[key]) setInteger(entry[key], { min: 0 }, `${entryPath}.${key}`);
    }
    (entry.authentication_order || []).forEach((method, methodIndex) => (
      setToken(method, `${entryPath}.authentication_order[${methodIndex}]`, /^[A-Za-z0-9-]+$/)
    ));
  });
}

function validateSnmp(entries, basePath) {
  if (!Array.isArray(entries)) return;
  entries.forEach((entry, index) => {
    const entryPath = `${basePath}[${index}]`;
    (entry.clients || []).forEach((client, clientIndex) => (
      setAddressOrPrefix(client, `${entryPath}.clients[${clientIndex}]`)
    ));
    (entry.targets || []).forEach((target, targetIndex) => (
      validateNetworkEndpoint(target, `${entryPath}.targets[${targetIndex}]`)
    ));
    (entry.categories || []).forEach((category, categoryIndex) => setEnum(
      category,
      ['authentication', 'chassis', 'configuration', 'link', 'remote-operations', 'routing', 'rmon-alarm', 'services', 'startup'],
      `${entryPath}.categories[${categoryIndex}]`,
    ));
    if (entry.version) setToken(entry.version, `${entryPath}.version`, /^[A-Za-z0-9-]+$/);
  });
}

function validateDhcp(entries, basePath) {
  if (!Array.isArray(entries)) return;
  entries.forEach((entry, index) => {
    const entryPath = `${basePath}[${index}]`;
    if (entry.interface) validateInterfaceName(entry.interface, `${entryPath}.interface`);
    (entry.interfaces || []).forEach((iface, ifaceIndex) => validateInterfaceName(iface, `${entryPath}.interfaces[${ifaceIndex}]`));
    (entry.servers || []).forEach((server, serverIndex) => validateNetworkEndpoint(server, `${entryPath}.servers[${serverIndex}]`));
    const network = entry.network || entry.subnet;
    if (network) setAddressOrPrefix(network, `${entryPath}.${entry.network ? 'network' : 'subnet'}`);
    for (const key of ['gateway', 'router']) {
      if (entry[key]) setAddressOrPrefix(entry[key], `${entryPath}.${key}`);
    }
    (entry.dns_servers || []).forEach((server, serverIndex) => validateNetworkEndpoint(server, `${entryPath}.dns_servers[${serverIndex}]`));
    (entry.ranges || []).forEach((range, rangeIndex) => {
      if (range.low) setAddressOrPrefix(range.low, `${entryPath}.ranges[${rangeIndex}].low`);
      if (range.high) setAddressOrPrefix(range.high, `${entryPath}.ranges[${rangeIndex}].high`);
    });
    (entry.pools || []).forEach((range, rangeIndex) => validateAddressRange(range, `${entryPath}.pools[${rangeIndex}]`));
    if (entry.lease_time) setInteger(entry.lease_time, { min: 1 }, `${entryPath}.lease_time`);
  });
}

function validateRate(value, fieldPath) {
  const text = assertSafeScalar(value, fieldPath);
  if (!/^(?:\d+(?:\.\d+)?(?:[kKmMgGtT](?:bps)?|bps|%)?|\d+(?:\.\d+)? percent|remainder)$/.test(text)) {
    throw new JunosSerializationError(fieldPath, 'rate', 'expected a numeric rate, percentage, or remainder');
  }
}

function validateQos(entries, basePath) {
  if (!Array.isArray(entries)) return;
  entries.forEach((entry, index) => {
    const entryPath = `${basePath}[${index}]`;
    if (entry.interface) validateInterfaceName(entry.interface, `${entryPath}.interface`);
    for (const key of ['transmit_rate', 'buffer_size', 'shaping_rate', 'max_bandwidth']) {
      if (entry[key]) validateRate(entry[key], `${entryPath}.${key}`);
    }
    if (entry.priority && entry.priority !== true) {
      setToken(entry.priority, `${entryPath}.priority`, /^[A-Za-z0-9-]+$/);
    }
    (entry.classes || []).forEach((item, classIndex) => {
      for (const key of ['guaranteed_bandwidth', 'maximum_bandwidth', 'police_rate']) {
        if (item[key]) validateRate(item[key], `${entryPath}.classes[${classIndex}].${key}`);
      }
      if (item.priority && item.priority !== true) {
        setToken(item.priority, `${entryPath}.classes[${classIndex}].priority`, /^[A-Za-z0-9-]+$/);
      }
    });
  });
}

function pbfAddressFamily(value, fieldPath) {
  const address = setAddressOrPrefix(value, fieldPath);
  return address.includes(':') ? 6 : 4;
}

function validatePbfService(value, fieldPath) {
  const text = assertSafeScalar(value, fieldPath);
  if (text === 'any' || text === 'application-default') return;
  if (!text.includes('/')) return;

  const pieces = text.split('/');
  if (pieces.length !== 2) {
    throw new JunosSerializationError(fieldPath, 'service', 'expected protocol/port or protocol/port-range');
  }
  setEnum(pieces[0].toLowerCase(), ['tcp', 'udp'], fieldPath);
  validatePortExpression(pieces[1], fieldPath);
}

function validatePbf(rules, basePath, addressObjects = []) {
  if (!Array.isArray(rules)) return;
  const addressesByName = new Map();
  for (const object of addressObjects || []) {
    const located = object && typeof object === 'object' ? addressValue(object) : null;
    if (object?.name && located && ['host', 'subnet', 'network', 'ip-netmask', 'ip-prefix'].includes(object.type)) {
      addressesByName.set(object.name, located.value);
    }
  }

  rules.forEach((rule, index) => {
    const rulePath = `${basePath}[${index}]`;
    if (rule.action) setEnum(rule.action, ['forward', 'discard', 'no-pbf', 'forward-to-vsys'], `${rulePath}.action`);
    const nextHopPath = `${rulePath}.next_hop_value`;
    let nextHopFamily;
    if (rule.next_hop_value) {
      const validatedFamily = pbfAddressFamily(rule.next_hop_value, nextHopPath);
      if (rule.action === 'forward') nextHopFamily = validatedFamily;
    }

    let family;
    for (const field of ['src_addresses', 'dst_addresses']) {
      (rule[field] || []).forEach((value, addressIndex) => {
        if (value === 'any') return;
        const fieldPath = `${rulePath}.${field}[${addressIndex}]`;
        const resolved = addressesByName.get(value);
        const looksLikeAddress = typeof value === 'string' && (
          // njsscan regex_dos: false positive. Bounded {3} repetition over disjoint tokens; cannot backtrack.
          value.includes(':') || value.includes('/') || /^\d+(?:\.\d+){3}$/.test(value)  // njsscan-ignore: regex_dos
        );
        if (resolved === undefined && !looksLikeAddress) return;
        const currentFamily = pbfAddressFamily(resolved ?? value, fieldPath);
        if (family !== undefined && family !== currentFamily) {
          throw new JunosSerializationError(
            fieldPath,
            'address-family',
            'mixed IPv4 and IPv6 address matches are not supported',
          );
        }
        family = currentFamily;
      });
    }
    if (family !== undefined && nextHopFamily !== undefined && family !== nextHopFamily) {
      throw new JunosSerializationError(
        nextHopPath,
        'address-family',
        'PBF matches and next hop must use the same address family',
      );
    }
    (rule.services || []).forEach((service, serviceIndex) => (
      validatePbfService(service, `${rulePath}.services[${serviceIndex}]`)
    ));
  });
}

function validateEvpn(entries, basePath) {
  if (!Array.isArray(entries)) return;
  entries.forEach((entry, index) => {
    const entryPath = `${basePath}[${index}]`;
    for (const key of ['instance_type', 'encapsulation', 'multicast_mode']) {
      if (entry[key]) setToken(entry[key], `${entryPath}.${key}`, /^[A-Za-z0-9-]+$/);
    }
    for (const key of ['route_distinguisher', 'vrf_target']) {
      if (entry[key]) setToken(entry[key], `${entryPath}.${key}`, /^[A-Za-z0-9_.:+-]+$/);
    }
    if (entry.vtep_source_interface) validateInterfaceName(entry.vtep_source_interface, `${entryPath}.vtep_source_interface`);
    (entry.extended_vni_list || []).forEach((vni, vniIndex) => setInteger(vni, { min: 1, max: 16777215 }, `${entryPath}.extended_vni_list[${vniIndex}]`));
    (entry.route_targets || []).forEach((target, targetIndex) => {
      if (target.direction) setEnum(target.direction, ['import', 'export', 'both'], `${entryPath}.route_targets[${targetIndex}].direction`);
      if (target.target) setToken(target.target, `${entryPath}.route_targets[${targetIndex}].target`, /^[A-Za-z0-9_.:+-]+$/);
    });
  });
}

function validateVxlan(entries, basePath) {
  if (!Array.isArray(entries)) return;
  entries.forEach((entry, index) => {
    const entryPath = `${basePath}[${index}]`;
    for (const key of ['vtep_source_interface', 'source_interface']) {
      if (entry[key]) validateInterfaceName(entry[key], `${entryPath}.${key}`);
    }
    if (entry.udp_port) setPort(entry.udp_port, `${entryPath}.udp_port`);
    (entry.vnis || []).forEach((vni, vniIndex) => {
      const vniPath = `${entryPath}.vnis[${vniIndex}]`;
      if (vni.vni) setInteger(vni.vni, { min: 1, max: 16777215 }, `${vniPath}.vni`);
      if (vni.vlan_id) setInteger(vni.vlan_id, { min: 1, max: 4094 }, `${vniPath}.vlan_id`);
      (vni.remote_vteps || []).forEach((vtep, vtepIndex) => setAddressOrPrefix(vtep, `${vniPath}.remote_vteps[${vtepIndex}]`));
    });
  });
}

function validateScreens(entries, basePath) {
  if (!Array.isArray(entries)) return;
  const numericKeys = new Set([
    'flood_threshold', 'syn_flood_threshold', 'syn_flood_alarm_threshold',
    'syn_flood_timeout', 'source_based', 'destination_based',
  ]);
  entries.forEach((entry, index) => {
    const walk = (value, path, key = '') => {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        Object.entries(value).forEach(([childKey, child]) => walk(child, `${path}.${childKey}`, childKey));
      } else if (numericKeys.has(key) && value !== undefined && value !== null && value !== '') {
        setInteger(value, { min: 0, max: 1000000 }, path);
      }
    };
    walk(entry, `${basePath}[${index}]`);
  });
}

function validateL2(config, prefix) {
  (config.bridge_domains || []).forEach((domain, index) => {
    const domainPath = `${joinPath(prefix, 'bridge_domains')}[${index}]`;
    if (domain.vlan_id) setInteger(domain.vlan_id, { min: 1, max: 4094 }, `${domainPath}.vlan_id`);
    if (domain.irb_interface) validateInterfaceName(domain.irb_interface, `${domainPath}.irb_interface`);
  });
  (config.l2_interfaces || []).forEach((iface, index) => {
    const ifacePath = `${joinPath(prefix, 'l2_interfaces')}[${index}]`;
    if (iface.name) validateInterfaceName(iface.name, `${ifacePath}.name`);
    if (iface.vlan) setInteger(iface.vlan, { min: 1, max: 4094 }, `${ifacePath}.vlan`);
  });
  (config.vwire_pairs || []).forEach((pair, index) => {
    const pairPath = `${joinPath(prefix, 'vwire_pairs')}[${index}]`;
    if (pair.interface1) validateInterfaceName(pair.interface1, `${pairPath}.interface1`);
    if (pair.interface2) validateInterfaceName(pair.interface2, `${pairPath}.interface2`);
    (pair.tag_allowed || []).forEach((tag, tagIndex) => setInteger(tag, { min: 0, max: 4094 }, `${pairPath}.tag_allowed[${tagIndex}]`));
  });
}

function validateSecurityProfileDefinitions(definitions, basePath) {
  if (!definitions || typeof definitions !== 'object') return;
  Object.entries(definitions).forEach(([definitionName, definition]) => {
    const definitionPath = `${basePath}.${definitionName}`;
    (definition?.blockedDomains || []).forEach((domain, index) => (
      validateDnsName(domain, `${definitionPath}.blockedDomains[${index}]`)
    ));
  });
}

function validateStaticRoutes(routes, basePath) {
  if (!Array.isArray(routes)) return;
  routes.forEach((route, index) => {
    if (!route || typeof route !== 'object') return;
    if (route.destination) setAddressOrPrefix(route.destination, `${basePath}[${index}].destination`);
    if (route.next_hop && route.next_hop_type !== 'next-vr' && route.next_hop_type !== 'discard') {
      setAddressOrPrefix(route.next_hop, `${basePath}[${index}].next_hop`);
    }
    if (route.metric !== undefined && route.metric !== null && route.metric !== '') {
      setInteger(route.metric, { min: 0, max: 4294967295 }, `${basePath}[${index}].metric`);
    }
  });
}

function validateNumericDomains(config, prefix) {
  const visit = (value, path, key) => {
    if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, joinPath(path, index), key));
      return;
    }
    if (value !== null && typeof value === 'object') {
      Object.entries(value).forEach(([childKey, child]) => (
        visit(child, joinPath(path, childKey), childKey)
      ));
      return;
    }
    if (value === null || value === undefined || value === '') return;
    if (key === 'vlan_id') setInteger(value, { min: 0, max: 4094 }, path);
    if (key === 'vni') setInteger(value, { min: 0, max: 16777215 }, path);
    if (['local_as', 'peer_as', 'asn'].includes(key)) {
      setInteger(value, { min: 1, max: 4294967295 }, path);
    }
  };
  visit(config, prefix, '');
}

/** Validate security-relevant domains without changing the intermediate object. */
export function validateJunosInput(config, rootPath = 'config') {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw new TypeError(`${rootPath} must be an object`);
  }

  const prefix = rootPath === 'config' ? '' : rootPath;
  walkScalars(config, prefix);
  validateSystem(config.system_config, joinPath(prefix, 'system_config'));
  validateAddressObjects(config.address_objects, joinPath(prefix, 'address_objects'));
  validatePolicies(config.security_policies, joinPath(prefix, 'security_policies'));
  validateServicePorts(config.service_objects, joinPath(prefix, 'service_objects'));
  validateServicePorts(config.applications, joinPath(prefix, 'applications'));
  validateInterfaces(config.interfaces, joinPath(prefix, 'interfaces'));
  validateSchedules(config.schedules, joinPath(prefix, 'schedules'));
  validateStaticRoutes(config.static_routes, joinPath(prefix, 'static_routes'));
  validateBgp(config.bgp_config, joinPath(prefix, 'bgp_config'));
  validateOspf(config.ospf_config, joinPath(prefix, 'ospf_config'));
  validateOspf(config.ospf3_config, joinPath(prefix, 'ospf3_config'));
  validateVpn(config.vpn_tunnels, joinPath(prefix, 'vpn_tunnels'));
  validateHa(config.ha_config, joinPath(prefix, 'ha_config'));
  validateEvpn(config.evpn_config, joinPath(prefix, 'evpn_config'));
  validateVxlan(config.vxlan_config, joinPath(prefix, 'vxlan_config'));
  validateScreens(config.screen_config, joinPath(prefix, 'screen_config'));
  validateNat(config.nat_rules, joinPath(prefix, 'nat_rules'));
  validateFlow(config.flow_monitoring_config, joinPath(prefix, 'flow_monitoring_config'));
  validateSyslog(config.syslog_config, joinPath(prefix, 'syslog_config'));
  validateAaa(config.aaa_config, joinPath(prefix, 'aaa_config'));
  validateSnmp(config.snmp_config, joinPath(prefix, 'snmp_config'));
  validateDhcp(config.dhcp_config, joinPath(prefix, 'dhcp_config'));
  validateQos(config.qos_config, joinPath(prefix, 'qos_config'));
  validatePbf(config.pbf_rules, joinPath(prefix, 'pbf_rules'), config.address_objects);
  validateL2(config, prefix);
  validateSecurityProfileDefinitions(
    config.security_profile_definitions,
    joinPath(prefix, 'security_profile_definitions'),
  );
  validateNumericDomains(config, prefix);
  return config;
}
