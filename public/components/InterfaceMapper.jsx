/**
 * InterfaceMapper Component
 *
 * Modal for mapping each zone's PAN-OS interface(s) to SRX interfaces.
 *
 * For each zone, shows:
 *   - Zone name
 *   - PAN-OS interface(s) with type/speed badge (from source model DB)
 *   - Arrow indicator
 *   - Dropdown of available SRX ports (from target model DB) — or tunnel
 *     interface builder for PAN-OS tunnel.X interfaces
 *   - SRX port type/speed badge
 *   - Compatibility indicator (speed mismatch = warning)
 *
 * Tunnel interfaces:
 *   PAN-OS tunnel.X → SRX st0.X (IPsec), gr-0/0/0.X (GRE), or ip-0/0/0.X (IP-IP)
 *   Loopback interfaces:
 *   PAN-OS loopback.X → SRX lo0.X
 *
 * Available ports auto-filter: once a port is assigned to one zone,
 * it's removed from other dropdowns.
 */
import React, { useState, useMemo } from 'react';
import {
  PANOS_MODELS, SRX_MODELS, SRX_SOURCE_MODELS,
  FORTIGATE_SOURCE_MODELS, CISCO_SOURCE_MODELS,
  CHECKPOINT_SOURCE_MODELS, SONICWALL_SOURCE_MODELS, HUAWEI_SOURCE_MODELS,
  getSrx4700Ports,
} from '../data/hardware-db.js';
import { safeJsonParse } from '../utils/safe-json.js';

/** Look up the correct source model database for a given vendor */
function getSourceModelDb(vendor) {
  switch (vendor) {
    case 'srx': return SRX_SOURCE_MODELS;
    case 'fortigate': return FORTIGATE_SOURCE_MODELS;
    case 'cisco_asa': return CISCO_SOURCE_MODELS;
    case 'checkpoint': return CHECKPOINT_SOURCE_MODELS;
    case 'sonicwall': return SONICWALL_SOURCE_MODELS;
    case 'huawei_usg': return HUAWEI_SOURCE_MODELS;
    default: return PANOS_MODELS;
  }
}

/** SRX tunnel interface types for the dropdown */
const SRX_TUNNEL_TYPES = [
  { value: 'st0',       label: 'st0 (IPsec Secure Tunnel)', description: 'Standard IPsec VPN tunnel' },
  { value: 'gr-0/0/0',  label: 'gr-0/0/0 (GRE Tunnel)',     description: 'Generic Routing Encapsulation' },
  { value: 'ip-0/0/0',  label: 'ip-0/0/0 (IP-IP Tunnel)',   description: 'IP-in-IP encapsulation' },
  { value: 'st0-ra',    label: 'st0 (SSL-VPN / Remote Access)', description: 'GlobalProtect → Juniper Secure Connect / IPsec dial-up (manual rebuild)' },
];

/** Detect if a PAN-OS interface is a tunnel */
function isTunnelInterface(ifaceName) {
  return /^tunnel\.\d+$/i.test(ifaceName);
}

/** Detect if an interface is a loopback (PAN-OS loopback.X, Huawei LoopBackN) */
function isLoopbackInterface(ifaceName) {
  return /^loopback\.\d+$/i.test(ifaceName) || /^LoopBack\d+$/i.test(ifaceName);
}

/** Extract unit number from PAN-OS logical interface */
function getUnit(ifaceName) {
  const m = ifaceName.match(/\.(\d+)$/);
  return m ? m[1] : '0';
}

/** PAN-OS logical L3 sub-interface, e.g. ethernet1/13.100 (parent + unit). */
export function isSubInterface(ifaceName) {
  // Exclude SRX-format tunnel/loopback/aggregate units in case this helper is
  // ever reused on SRX-side names (st0.10, lo0.0, ae0.100 are not sub-interfaces).
  if (/^(st0|lo0|ae\d+)\.\d+$/i.test(ifaceName)) return false;
  return /\.\d+$/.test(ifaceName) && !isTunnelInterface(ifaceName) && !isLoopbackInterface(ifaceName);
}

/** Parent physical name of a sub-interface (ethernet1/13.100 → ethernet1/13). */
export function parentInterface(ifaceName) {
  return ifaceName.replace(/\.\d+$/, '');
}

/**
 * Re-point every sub-interface of `parentPanos` to a unit on `srxIface`'s base.
 * @param {{ [k: string]: string }} mappings
 * @param {string} parentPanos - PAN-OS parent name (e.g. ethernet1/13)
 * @param {string} srxIface - the parent's new SRX target (e.g. ge-0/0/5)
 * @returns {{ [k: string]: string }} updated copy
 */
export function deriveSubInterfaceMappings(mappings, parentPanos, srxIface) {
  const base = String(srxIface || '').split('.')[0];
  if (!base) return { ...mappings };
  const updated = { ...mappings };
  for (const key of Object.keys(updated)) {
    if (isSubInterface(key) && parentInterface(key) === parentPanos) {
      updated[key] = `${base}.${key.split('.').pop()}`;
    }
  }
  return updated;
}

/**
 * Resolve the real Junos interface base for a tunnel-type selection.
 * The `st0-ra` value is a UI marker for SSL-VPN intent; it always serializes
 * to a real `st0` interface so the emitted mapping is a valid Junos token.
 * @param {string} tunnelType
 * @returns {string}
 */
export function srxTunnelBase(tunnelType) {
  return tunnelType === 'st0-ra' ? 'st0' : tunnelType;
}

/**
 * Choose the default tunnel-type selection for a PAN-OS tunnel interface.
 * An existing non-st0 mapping prefix wins; otherwise GlobalProtect tunnels
 * default to the SSL-VPN marker, and everything else to plain st0 IPsec.
 * @param {string} ifaceName
 * @param {Set<string>} sslVpnTunnels
 * @param {string} existingMapping
 * @returns {string}
 */
export function defaultTunnelTypeFor(ifaceName, sslVpnTunnels, existingMapping = '') {
  if (existingMapping.startsWith('gr-')) return 'gr-0/0/0';
  if (existingMapping.startsWith('ip-')) return 'ip-0/0/0';
  if (sslVpnTunnels && sslVpnTunnels.has(ifaceName)) return 'st0-ra';
  return 'st0';
}

export default function InterfaceMapper({
  intermediateConfig,
  sourceModel,
  targetModel,
  portProfile,
  interfaceMappings: existingMappings,
  onMappingComplete,
  onClose,
}) {
  /** Resolve target model data, applying SRX4700 port profile override if applicable */
  const targetModelData = useMemo(() => {
    const raw = targetModel ? SRX_MODELS[targetModel] : null;
    if (!raw) return null;
    if (raw.hasPortProfiles && portProfile) {
      return { ...raw, ports: getSrx4700Ports(portProfile) };
    }
    return raw;
  }, [targetModel, portProfile]);

  const sslVpnTunnels = useMemo(
    () => new Set((intermediateConfig?.global_protect?.gateways || []).map(g => g.tunnel_interface)),
    [intermediateConfig],
  );

  // Initialize mappings from existing or build fresh
  const [mappings, setMappings] = useState(() => {
    if (existingMappings && Object.keys(existingMappings).length > 0) {
      const cleaned = cleanMappings(existingMappings, targetModelData);
      if (Object.keys(cleaned).length > 0) {
        return cleaned;
      }
    }
    return buildDefaultMappings(intermediateConfig, targetModelData);
  });

  // Track tunnel type selections separately (prefix before the unit)
  const [tunnelTypes, setTunnelTypes] = useState(() => {
    const types = {};
    for (const zone of (intermediateConfig?.zones || [])) {
      for (const iface of (zone.interfaces || [])) {
        if (isTunnelInterface(iface)) {
          const existing = existingMappings?.[iface] || '';
          types[iface] = defaultTunnelTypeFor(iface, sslVpnTunnels, existing);
        }
      }
    }
    return types;
  });

  // Track custom tunnel unit numbers
  const [tunnelUnits, setTunnelUnits] = useState(() => {
    const units = {};
    for (const zone of (intermediateConfig?.zones || [])) {
      for (const iface of (zone.interfaces || [])) {
        if (isTunnelInterface(iface)) {
          const existing = existingMappings?.[iface] || '';
          const m = existing.match(/\.(\d+)$/);
          units[iface] = m ? m[1] : getUnit(iface);
        }
      }
    }
    return units;
  });

  const sourceVendor = intermediateConfig?.metadata?.source_vendor;
  const sourceModelDb = getSourceModelDb(sourceVendor);
  const sourceModelData = sourceModel ? sourceModelDb[sourceModel] : null;
  const targetPorts = targetModelData?.ports || [];

  // Build parsed interface lookup for IP/IPv6 display
  const parsedIfaceMap = useMemo(() => {
    const m = {};
    for (const iface of (intermediateConfig?.interfaces || [])) {
      m[iface.name || iface.hardware || ''] = iface;
    }
    return m;
  }, [intermediateConfig]);

  // Build L2 interface lookup from intermediateConfig
  const l2InterfaceSet = useMemo(() => {
    const s = new Set();
    for (const l2if of (intermediateConfig?.l2_interfaces || [])) {
      s.add(l2if.name);
    }
    // Also mark interfaces in virtual-wire pairs
    for (const vw of (intermediateConfig?.vwire_pairs || [])) {
      if (vw.interface1) s.add(vw.interface1);
      if (vw.interface2) s.add(vw.interface2);
    }
    return s;
  }, [intermediateConfig]);

  // Build LAG member lookup: source_member → { lagName, lagSourceName }
  const lagMemberMap = useMemo(() => {
    const m = {};
    for (const lag of (intermediateConfig?.lag_interfaces || [])) {
      for (const member of (lag.source_members || [])) {
        m[member] = { lagName: lag.name, lagSourceName: lag.source_name, lacpMode: lag.lacp_mode };
      }
    }
    return m;
  }, [intermediateConfig]);

  // Build LAG parent lookup: source_name → lag object
  const lagParentMap = useMemo(() => {
    const m = {};
    for (const lag of (intermediateConfig?.lag_interfaces || [])) {
      m[lag.source_name] = lag;
    }
    return m;
  }, [intermediateConfig]);

  // Get all PAN-OS interfaces from zones, with LAG grouping
  const zoneInterfaces = useMemo(() => {
    const result = [];
    for (const zone of (intermediateConfig?.zones || [])) {
      for (const iface of (zone.interfaces || [])) {
        const isL2 = l2InterfaceSet.has(iface) || zone.zone_type === 'layer2' || zone.zone_type === 'virtual-wire';
        const lagParent = lagParentMap[iface];
        const lagMember = lagMemberMap[iface];
        result.push({ zoneName: zone.name, panosIface: iface, isL2, isLagParent: !!lagParent, isLagMember: !!lagMember, lagInfo: lagParent || lagMember || null });
      }
    }

    // Inject LAG member rows beneath their parent if members aren't already zone interfaces
    const expanded = [];
    for (const entry of result) {
      expanded.push(entry);
      if (entry.isLagParent) {
        const lag = lagParentMap[entry.panosIface];
        if (lag) {
          for (const member of (lag.source_members || [])) {
            // Only add if this member isn't already in zone interfaces
            if (!result.some(r => r.panosIface === member)) {
              expanded.push({
                zoneName: entry.zoneName,
                panosIface: member,
                isL2: false,
                isLagParent: false,
                isLagMember: true,
                lagInfo: { lagName: lag.name, lagSourceName: lag.source_name, lacpMode: lag.lacp_mode },
              });
            }
          }
        }
      }
    }
    return expanded;
  }, [intermediateConfig, l2InterfaceSet, lagParentMap, lagMemberMap]);

  // Track which SRX ports are already assigned (only physical ones)
  const assignedSrxPorts = useMemo(() => {
    return new Set(
      Object.entries(mappings)
        .filter(([panos]) => !isTunnelInterface(panos) && !isLoopbackInterface(panos))
        .map(([, srx]) => srx)
    );
  }, [mappings]);

  /** Lookup PAN-OS port info from the model DB */
  const getSourcePortInfo = (ifaceName) => {
    if (isTunnelInterface(ifaceName)) return { name: ifaceName, type: 'tunnel', speed: 'virtual', label: ifaceName };
    if (isLoopbackInterface(ifaceName)) return { name: ifaceName, type: 'loopback', speed: 'virtual', label: ifaceName };
    if (!sourceModelData) return null;
    const base = ifaceName.split('.')[0];
    return sourceModelData.ports.find(p => p.name === base) || null;
  };

  /** Lookup SRX port info from the model DB */
  const getTargetPortInfo = (ifaceName) => {
    if (!ifaceName) return null;
    // Virtual/tunnel interfaces
    if (ifaceName.startsWith('st0') || ifaceName.startsWith('gr-') || ifaceName.startsWith('ip-') || ifaceName.startsWith('lo0')) {
      return { name: ifaceName, type: 'tunnel', speed: 'virtual', label: ifaceName };
    }
    if (!targetModelData) return null;
    const base = ifaceName.split('.')[0];
    return targetModelData.ports.find(p => p.name === base) || null;
  };

  /** Update a single physical mapping; auto-map LAG members when parent is mapped */
  const handleMappingChange = (panosIface, srxIface) => {
    setMappings(prev => {
      const updated = { ...prev, [panosIface]: srxIface };

      // If this is a LAG parent, auto-map its members to the ae interface
      const lag = lagParentMap[panosIface];
      if (lag) {
        for (const member of (lag.source_members || [])) {
          // Members get mapped to individual ports by the user, but clear stale mappings
          // The parent ae mapping signals that LAG is configured
          updated[`_lag_parent:${panosIface}`] = srxIface;
        }
      }

      // Re-point this parent's sub-interfaces to the new port.
      const withSubs = deriveSubInterfaceMappings(updated, panosIface, srxIface);
      return withSubs;
    });
  };

  /** Update tunnel type for a tunnel interface */
  const handleTunnelTypeChange = (panosIface, tunnelType) => {
    setTunnelTypes(prev => ({ ...prev, [panosIface]: tunnelType }));
    // Update the mapping with new type + existing unit
    const unit = tunnelUnits[panosIface] || getUnit(panosIface);
    setMappings(prev => ({
      ...prev,
      [panosIface]: `${srxTunnelBase(tunnelType)}.${unit}`,
    }));
  };

  /** Update tunnel unit number */
  const handleTunnelUnitChange = (panosIface, unit) => {
    setTunnelUnits(prev => ({ ...prev, [panosIface]: unit }));
    const tunnelType = tunnelTypes[panosIface] || 'st0';
    setMappings(prev => ({
      ...prev,
      [panosIface]: `${srxTunnelBase(tunnelType)}.${unit}`,
    }));
  };

  // --- Template Save/Load ---
  const [showTemplates, setShowTemplates] = useState(false);
  const TEMPLATE_STORAGE_KEY = 'interface-mapping-templates';

  /** Get all saved templates from localStorage */
  const getSavedTemplates = () => {
    try {
      return safeJsonParse(localStorage.getItem(TEMPLATE_STORAGE_KEY) || '{}');
    } catch { return {}; }
  };

  /** Build a template key from source model → target model */
  const templateKey = `${sourceModel || 'unknown'}->${targetModel || 'unknown'}`;

  /** Save current mappings as a template */
  const handleSaveTemplate = () => {
    const templates = getSavedTemplates();
    templates[templateKey] = {
      mappings: { ...mappings },
      tunnelTypes: { ...tunnelTypes },
      tunnelUnits: { ...tunnelUnits },
      savedAt: new Date().toISOString(),
      sourceModel: sourceModel || 'unknown',
      targetModel: targetModel || 'unknown',
    };
    try {
      localStorage.setItem(TEMPLATE_STORAGE_KEY, JSON.stringify(templates));
    } catch { /* ignore */ }
    setShowTemplates(false);
  };

  /** Load a template by key */
  const handleLoadTemplate = (key) => {
    const templates = getSavedTemplates();
    const tpl = templates[key];
    if (!tpl) return;

    const cleaned = cleanMappings(tpl.mappings, targetModelData);
    setMappings(cleaned);
    if (tpl.tunnelTypes) setTunnelTypes(tpl.tunnelTypes);
    if (tpl.tunnelUnits) setTunnelUnits(tpl.tunnelUnits);
    setShowTemplates(false);
  };

  /** Delete a saved template */
  const handleDeleteTemplate = (key) => {
    const templates = getSavedTemplates();
    delete templates[key];
    try {
      localStorage.setItem(TEMPLATE_STORAGE_KEY, JSON.stringify(templates));
    } catch { /* ignore */ }
  };

  const savedTemplates = getSavedTemplates();
  const savedTemplateKeys = Object.keys(savedTemplates);
  const hasCurrentTemplate = !!savedTemplates[templateKey];

  /** Apply mappings and close */
  const handleApply = () => {
    // Ensure all tunnel mappings are built before applying
    const finalMappings = { ...mappings };
    for (const zone of (intermediateConfig?.zones || [])) {
      for (const iface of (zone.interfaces || [])) {
        if (isTunnelInterface(iface) && !finalMappings[iface]) {
          const type = tunnelTypes[iface] || 'st0';
          const unit = tunnelUnits[iface] || getUnit(iface);
          finalMappings[iface] = `${type}.${unit}`;
        }
        if (isLoopbackInterface(iface) && !finalMappings[iface]) {
          finalMappings[iface] = `lo0.${getUnit(iface)}`;
        }
      }
    }
    onMappingComplete(finalMappings);
  };

  /** Extract max speed from a multi-rate string like "1/2.5/5/10G" → 10 */
  const maxSpeedGbps = (speedStr) => {
    const speedOrder = { '1G': 1, '2.5G': 2.5, '5G': 5, '10G': 10, '25G': 25, '40G': 40, '50G': 50, '100G': 100, '400G': 400 };
    if (speedOrder[speedStr]) return speedOrder[speedStr];
    // Multi-rate: "1/2.5/5/10G" or "40/100G"
    const parts = speedStr.replace(/G$/i, '').split('/');
    return Math.max(...parts.map(Number).filter(n => !isNaN(n)));
  };

  /** CSS-safe speed class from multi-rate string: "1/2.5/5/10G" → "speed-10G" */
  const speedClass = (speedStr) => {
    const gbps = maxSpeedGbps(speedStr);
    return `speed-${gbps}G`;
  };

  /** Check if port speeds are compatible */
  const getCompatibility = (sourcePort, targetPort) => {
    if (!sourcePort || !targetPort) return 'unknown';
    // Tunnel/loopback is always fine
    if (sourcePort.type === 'tunnel' || sourcePort.type === 'loopback') return 'match';
    // Virtual target ports (vSRX) — speed comparison doesn't apply
    if (targetPort.speed === 'virtual' || targetPort.type === 'virtual') return 'virtual';
    if (sourcePort.speed === targetPort.speed) return 'match';
    const srcSpeed = maxSpeedGbps(sourcePort.speed);
    const tgtSpeed = maxSpeedGbps(targetPort.speed);
    if (srcSpeed === tgtSpeed) return 'match';
    if (tgtSpeed >= srcSpeed) return 'upgrade';
    return 'downgrade';
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ width: 750 }}>
        <div className="modal-header">
          <h2>Interface Mapping</h2>
          <button className="modal-close" onClick={onClose}>x</button>
        </div>

        <div className="modal-subheader">
          <span>
            {sourceModel || 'PAN-OS'} <span style={{ color: 'var(--accent)', margin: '0 8px' }}>-&gt;</span> {targetModel || 'SRX'}
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            Map each zone's interface to an SRX port or tunnel
          </span>
        </div>

        <div className="modal-body" style={{ maxHeight: '55vh', overflow: 'auto' }}>
          {zoneInterfaces.length === 0 ? (
            <div className="empty-state">
              <p>No zone interfaces found in the parsed config.</p>
            </div>
          ) : (
            <table className="mapping-table">
              <thead>
                <tr>
                  <th>Zone</th>
                  <th>PAN-OS Interface</th>
                  <th></th>
                  <th>SRX Interface</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {zoneInterfaces.map(({ zoneName, panosIface, isL2, isLagParent, isLagMember, lagInfo }) => {
                  const isTunnel = isTunnelInterface(panosIface);
                  const isLoopback = isLoopbackInterface(panosIface);
                  const currentSrx = mappings[panosIface] || '';
                  const srcPort = getSourcePortInfo(panosIface);
                  const tgtPort = currentSrx ? getTargetPortInfo(currentSrx) : null;
                  const compat = getCompatibility(srcPort, tgtPort);

                  const rowClass = isTunnel ? 'tunnel-row'
                    : isLoopback ? 'loopback-row'
                    : isLagParent ? 'lag-parent-row'
                    : isLagMember ? 'lag-member-row'
                    : '';

                  return (
                    <tr key={`${zoneName}-${panosIface}`} className={rowClass}>
                      <td>
                        <span style={{ fontWeight: 600, color: 'var(--accent)' }}>
                          {isLagMember ? '' : zoneName}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, paddingLeft: isLagMember ? 18 : 0 }}>
                          {isLagMember && (
                            <span style={{ color: 'var(--text-muted)', fontSize: 12, marginRight: 2 }}>&#x2514;</span>
                          )}
                          <code>{panosIface}</code>
                          {isLagParent && (
                            <span className="port-badge" style={{ background: 'color-mix(in srgb, var(--info) 15%, transparent)', color: 'var(--info)', fontSize: 10, padding: '1px 5px' }}>
                              LAG
                            </span>
                          )}
                          {isLagMember && (
                            <span className="port-badge" style={{ background: 'color-mix(in srgb, var(--info) 15%, transparent)', color: 'var(--info)', fontSize: 10, padding: '1px 5px' }}>
                              member
                            </span>
                          )}
                          {srcPort && !isLagParent && (
                            <span className={`port-badge ${speedClass(srcPort.speed)}`}>
                              {srcPort.type === 'tunnel' ? 'Tunnel' : srcPort.type === 'loopback' ? 'Loopback' : `${srcPort.speed} ${srcPort.type}`}
                            </span>
                          )}
                          {isL2 && (
                            <span className="port-badge" style={{ background: '#1e40af', color: '#93c5fd', fontSize: 10, padding: '1px 5px' }}>
                              L2
                            </span>
                          )}
                        </div>
                        {isLagParent && lagInfo && (
                          <div style={{ fontSize: 10, color: 'var(--info)', marginTop: 2 }}>
                            LACP: {lagInfo.lacp_mode || 'static'} | {lagInfo.source_members?.length || 0} member(s) → {lagInfo.name}
                          </div>
                        )}
                        {!isLagParent && (() => {
                          const pIface = parsedIfaceMap[panosIface];
                          if (!pIface) return null;
                          return (
                            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2, fontFamily: 'var(--font-mono)' }}>
                              {pIface.ip && <span>v4: {pIface.ip}</span>}
                              {pIface.ipv6 && <span style={{ marginLeft: pIface.ip ? 8 : 0 }}>v6: {pIface.ipv6}</span>}
                            </div>
                          );
                        })()}
                      </td>
                      <td style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 16 }}>
                        -&gt;
                      </td>
                      <td>
                        {isLagParent ? (
                          /* LAG parent — show auto-generated ae name */
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <code style={{ color: 'var(--info)', fontWeight: 600 }}>{lagInfo?.name || 'ae0'}</code>
                            <span className="port-badge" style={{ background: 'color-mix(in srgb, var(--info) 15%, transparent)', color: 'var(--info)', fontSize: 10, padding: '1px 5px' }}>
                              Aggregate
                            </span>
                          </div>
                        ) : isLagMember ? (
                          /* LAG member — show physical port dropdown + ae membership note */
                          <>
                            <select
                              className="mapping-select"
                              value={currentSrx}
                              onChange={(e) => handleMappingChange(panosIface, e.target.value)}
                            >
                              <option value="">-- Select SRX Port --</option>
                              {targetPorts.map(port => {
                                const isAssigned = assignedSrxPorts.has(port.name) && mappings[panosIface] !== port.name;
                                return (
                                  <option
                                    key={port.name}
                                    value={port.name}
                                    disabled={isAssigned}
                                  >
                                    {port.name} ({port.speed} {port.type}){isAssigned ? ' [assigned]' : ''}
                                  </option>
                                );
                              })}
                            </select>
                            <div style={{ fontSize: 10, color: 'var(--info)', marginTop: 2 }}>
                              802.3ad → {lagInfo?.lagName || 'ae0'}
                            </div>
                          </>
                        ) : isTunnel ? (
                          /* Tunnel interface builder */
                          <div className="tunnel-builder">
                            <select
                              className="mapping-select tunnel-type-select"
                              value={tunnelTypes[panosIface] || 'st0'}
                              onChange={(e) => handleTunnelTypeChange(panosIface, e.target.value)}
                            >
                              {SRX_TUNNEL_TYPES.map(t => (
                                <option key={t.value} value={t.value} title={t.description}>
                                  {t.label}
                                </option>
                              ))}
                            </select>
                            <span className="tunnel-dot">.</span>
                            <input
                              type="number"
                              className="tunnel-unit-input"
                              value={tunnelUnits[panosIface] || getUnit(panosIface)}
                              onChange={(e) => handleTunnelUnitChange(panosIface, e.target.value)}
                              min="0"
                              max="9999"
                              title="Tunnel unit number"
                            />
                            <span className="port-badge speed-virtual" style={{ marginLeft: 6 }}>
                              {tunnelTypes[panosIface] === 'st0-ra' ? 'SSL-VPN'
                                : (tunnelTypes[panosIface] || 'st0') === 'st0' ? 'IPsec'
                                : (tunnelTypes[panosIface] || 'st0').startsWith('gr') ? 'GRE' : 'IP-IP'}
                            </span>
                          </div>
                        ) : isLoopback ? (
                          /* Loopback — auto-mapped to lo0.X */
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <code className="loopback-mapped">lo0.{getUnit(panosIface)}</code>
                            <span className="port-badge speed-virtual">Loopback</span>
                          </div>
                        ) : isSubInterface(panosIface) ? (
                          /* Sub-interface — a unit on its parent's port (no separate port) */
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <code style={{ color: 'var(--accent)', fontWeight: 600 }}>
                              {currentSrx || `${(mappings[parentInterface(panosIface)] || '').split('.')[0]}.${panosIface.split('.').pop()}`}
                            </code>
                            {parsedIfaceMap[panosIface]?.vlan && (
                              <span className="port-badge" style={{ fontSize: 10, padding: '1px 5px' }}>
                                vlan {parsedIfaceMap[panosIface].vlan}
                              </span>
                            )}
                            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                              unit on {parentInterface(panosIface)}
                            </span>
                          </div>
                        ) : (
                          /* Physical port dropdown */
                          <>
                            <select
                              className="mapping-select"
                              value={currentSrx}
                              onChange={(e) => handleMappingChange(panosIface, e.target.value)}
                            >
                              <option value="">-- Select SRX Port --</option>
                              {targetPorts.map(port => {
                                const isAssigned = assignedSrxPorts.has(port.name) && mappings[panosIface] !== port.name;
                                return (
                                  <option
                                    key={port.name}
                                    value={port.name}
                                    disabled={isAssigned}
                                  >
                                    {port.name} ({port.speed} {port.type}){isAssigned ? ' [assigned]' : ''}
                                  </option>
                                );
                              })}
                            </select>
                            {tgtPort && tgtPort.type !== 'tunnel' && (
                              <span className={`port-badge ${speedClass(tgtPort.speed)}`} style={{ marginLeft: 6 }}>
                                {tgtPort.speed} {tgtPort.type}
                              </span>
                            )}
                          </>
                        )}
                      </td>
                      <td>
                        {isLagParent && (
                          <span style={{ color: 'var(--info)', fontSize: 12 }}>LAG parent</span>
                        )}
                        {isLagMember && (
                          <span style={{ color: 'var(--info)', fontSize: 12 }}>LAG member</span>
                        )}
                        {isTunnel && (
                          <span style={{ color: 'var(--info)', fontSize: 12 }}>Create tunnel</span>
                        )}
                        {isLoopback && (
                          <span style={{ color: 'var(--info)', fontSize: 12 }}>Auto-mapped</span>
                        )}
                        {!isTunnel && !isLoopback && !isLagParent && !isLagMember && !currentSrx && (
                          <span style={{ color: 'var(--warning)', fontSize: 12 }}>Unmapped</span>
                        )}
                        {!isTunnel && !isLoopback && !isLagParent && !isLagMember && currentSrx && compat === 'match' && (
                          <span style={{ color: 'var(--success)', fontSize: 12 }}>Match</span>
                        )}
                        {!isTunnel && !isLoopback && !isLagParent && !isLagMember && currentSrx && compat === 'upgrade' && (
                          <span style={{ color: 'var(--info)', fontSize: 12 }}>Upgrade</span>
                        )}
                        {!isTunnel && !isLoopback && !isLagParent && !isLagMember && currentSrx && compat === 'downgrade' && (
                          <span style={{ color: 'var(--warning)', fontSize: 12 }}>Speed down</span>
                        )}
                        {!isTunnel && !isLoopback && !isLagParent && !isLagMember && currentSrx && compat === 'virtual' && (
                          <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>Virtual</span>
                        )}
                        {isL2 && !isTunnel && !isLoopback && (
                          <span style={{ color: '#93c5fd', fontSize: 11, display: 'block' }}>family bridge</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        <div className="modal-footer" style={{ flexDirection: 'column', gap: 8 }}>
          {/* Template management row */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%' }}>
            <button
              className="btn btn-secondary btn-sm"
              onClick={handleSaveTemplate}
              title={`Save current mappings as template for ${templateKey}`}
              style={{ fontSize: 11 }}
            >
              {hasCurrentTemplate ? 'Update' : 'Save'} Template
            </button>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setShowTemplates(!showTemplates)}
              disabled={savedTemplateKeys.length === 0}
              style={{ fontSize: 11 }}
            >
              Load Template ({savedTemplateKeys.length})
            </button>
            <span style={{ flex: 1 }} />
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              {Object.values(mappings).filter(v => v).length} of {zoneInterfaces.length} interfaces mapped
            </span>
          </div>

          {/* Template list dropdown */}
          {showTemplates && savedTemplateKeys.length > 0 && (
            <div style={{
              width: '100%', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius)',
              border: '1px solid var(--border-color)', padding: 8, maxHeight: 160, overflow: 'auto',
            }}>
              {savedTemplateKeys.map(key => {
                const tpl = savedTemplates[key];
                const date = tpl.savedAt ? new Date(tpl.savedAt).toLocaleDateString() : '';
                const mappingCount = Object.keys(tpl.mappings || {}).length;
                return (
                  <div key={key} style={{
                    display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px',
                    borderRadius: 4, cursor: 'pointer', fontSize: 12,
                    background: key === templateKey ? 'var(--accent-glow)' : 'transparent',
                  }}>
                    <span
                      onClick={() => handleLoadTemplate(key)}
                      style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 6 }}
                    >
                      <strong style={{ color: 'var(--accent)' }}>{key}</strong>
                      <span style={{ color: 'var(--text-muted)' }}>
                        {mappingCount} mappings {date && `\u00b7 ${date}`}
                      </span>
                    </span>
                    <button
                      className="btn-icon btn-icon-danger"
                      onClick={(e) => { e.stopPropagation(); handleDeleteTemplate(key); }}
                      title="Delete template"
                      style={{ fontSize: 10 }}
                    >x</button>
                  </div>
                );
              })}
            </div>
          )}

          {/* Action buttons */}
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', width: '100%' }}>
            <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button className="btn btn-primary" onClick={handleApply}>
              Apply Mappings
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Drops stale mappings that point at ports not on the target model. Virtual
 * interfaces (tunnels, loopbacks) and aeN targets (generated or user-chosen
 * aggregate names) are always kept.
 * @param {{ [source: string]: string }} mappings
 * @param {object} targetModelData - { ports: [{ name }] }
 * @returns {{ [source: string]: string }}
 */
export function cleanMappings(mappings, targetModelData) {
  const validPortNames = targetModelData ? new Set(targetModelData.ports.map(p => p.name)) : null;
  const cleaned = {};
  for (const [source, target] of Object.entries(mappings || {})) {
    if (isTunnelInterface(source) || isLoopbackInterface(source) || /^ae\d+(\.\d+)?$/.test(target)
      || !validPortNames || validPortNames.has(target)) {
      cleaned[source] = target;
    }
  }
  return cleaned;
}

/**
 * Build default PAN-OS→SRX interface mappings. Parents and tunnels/loopbacks
 * get their own target; sub-interfaces map to a unit on their parent's port.
 * @param {object} intermediateConfig
 * @param {object} targetModelData - { ports: [{ name, speed, type }] }
 * @returns {{ [panosIface: string]: string }}
 */
export function buildDefaultMappings(intermediateConfig, targetModelData) {
  const mappings = {};
  const availablePorts = targetModelData ? [...targetModelData.ports] : [];
  const usedPorts = new Set();
  // LAG parents (and their units, e.g. PAN-OS ae1.100) map to the generated aeN, never a physical port.
  const lagBySource = new Map((intermediateConfig?.lag_interfaces || []).map(lag => [lag.source_name || lag.name, lag.name]));

  // Pass 1: tunnels, loopbacks, and parent physical interfaces.
  for (const zone of (intermediateConfig?.zones || [])) {
    for (const iface of (zone.interfaces || [])) {
      const [ifaceBase, ...unitParts] = iface.split('.');
      if (lagBySource.has(ifaceBase)) {
        mappings[iface] = unitParts.length > 0 ? `${lagBySource.get(ifaceBase)}.${unitParts.join('.')}` : lagBySource.get(ifaceBase);
      } else if (isTunnelInterface(iface)) {
        mappings[iface] = `st0.${getUnit(iface)}`;
      } else if (isLoopbackInterface(iface)) {
        mappings[iface] = `lo0.${getUnit(iface)}`;
      } else if (isSubInterface(iface)) {
        continue; // handled in pass 2
      } else {
        const port = availablePorts.find(p => !usedPorts.has(p.name));
        if (port) {
          mappings[iface] = port.name;
          usedPorts.add(port.name);
        }
      }
    }
  }

  // LAG members take free physical ports so the UI shows (and the converters bundle) them.
  for (const lag of (intermediateConfig?.lag_interfaces || [])) {
    for (const member of (lag.source_members || [])) {
      if (mappings[member]) continue;
      const port = availablePorts.find(p => !usedPorts.has(p.name));
      if (!port) continue;
      mappings[member] = port.name;
      usedPorts.add(port.name);
    }
  }

  // Pass 2: sub-interfaces → parent's SRX port base + this sub-interface's unit.
  for (const zone of (intermediateConfig?.zones || [])) {
    for (const iface of (zone.interfaces || [])) {
      if (!isSubInterface(iface)) continue;
      const parentSrx = mappings[parentInterface(iface)];
      if (!parentSrx) continue; // parent unmapped → let the converter derive it
      const parentBase = parentSrx.split('.')[0];
      const unit = iface.split('.').pop();
      mappings[iface] = `${parentBase}.${unit}`;
    }
  }

  return mappings;
}
