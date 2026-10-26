/**
 * ZoneEditor Component
 *
 * Editable zone panel for the "Zones" tab in the center panel.
 * Each zone shows: name (editable), description (editable), interfaces (chip editor).
 * Supports adding new zones and deleting existing ones.
 *
 * viewMode: 'panos' shows PAN-OS terms, 'srx' shows SRX security-zone terms.
 */
import React, { useState } from 'react';
import { mapInterfaceToSrx } from '../utils/srx-view-transforms.js';

const HOST_INBOUND_SERVICES = ['ping', 'ssh', 'https', 'dhcp', 'dns', 'snmp'];

/**
 * Add or remove a system-service in a host-inbound access object, keeping
 * protocols and *_except lists intact.
 * @param {{system_services?: string[], protocols?: string[]}|undefined} access
 * @param {string} service
 * @returns {object} new access object
 */
export function toggleHostInboundService(access, service) {
  const current = access || { system_services: [], protocols: [] };
  const services = current.system_services || [];
  const next = services.includes(service)
    ? services.filter(s => s !== service)
    : [...services, service];
  return { protocols: [], ...current, system_services: next };
}

/** Protocol and except entries as display labels. */
function protocolAndExceptLabels(access) {
  return [
    ...(access?.protocols || []).map(p => `protocol ${p}`),
    ...(access?.system_services_except || []).map(s => `except ${s}`),
    ...(access?.protocols_except || []).map(p => `except protocol ${p}`),
  ];
}

/** Zone-level entries not covered by the fixed checkboxes (read-only display). */
function extraHostInboundEntries(access) {
  return [
    ...(access?.system_services || []).filter(s => !HOST_INBOUND_SERVICES.includes(s)),
    ...protocolAndExceptLabels(access),
  ];
}

/** Compact one-line text for a host-inbound access object. */
function describeHostInbound(access) {
  const parts = [...(access?.system_services || []), ...protocolAndExceptLabels(access)];
  return parts.length ? parts.join(', ') : 'none';
}

export default function ZoneEditor({ zones, onZonesUpdate, viewMode, interfaceMappings }) {
  const isSrx = viewMode === 'srx';
  const [editingZone, setEditingZone] = useState(null); // index of zone being edited

  /** Update a single field on a zone */
  const handleFieldChange = (index, field, value) => {
    const updated = zones.map((z, i) =>
      i === index ? { ...z, [field]: value } : z
    );
    onZonesUpdate(updated);
  };

  /** Add a new blank zone */
  const handleAdd = () => {
    onZonesUpdate([
      ...zones,
      { name: `zone-${zones.length + 1}`, description: '', interfaces: [] },
    ]);
  };

  /** Delete a zone */
  const handleDelete = (index) => {
    onZonesUpdate(zones.filter((_, i) => i !== index));
  };

  /** Add an interface to a zone */
  const handleAddInterface = (zoneIndex, ifaceName) => {
    if (!ifaceName.trim()) return;
    const zone = zones[zoneIndex];
    if (zone.interfaces.includes(ifaceName.trim())) return;
    handleFieldChange(zoneIndex, 'interfaces', [...zone.interfaces, ifaceName.trim()]);
  };

  /** Remove an interface from a zone */
  const handleRemoveInterface = (zoneIndex, ifaceName) => {
    const zone = zones[zoneIndex];
    handleFieldChange(zoneIndex, 'interfaces', zone.interfaces.filter(i => i !== ifaceName));
  };

  if (!zones || zones.length === 0) {
    return (
      <div className="panel-body">
        <div className="empty-state">
          <p>No zones defined.</p>
          <button className="btn btn-primary btn-sm" onClick={handleAdd}>Add Zone</button>
        </div>
      </div>
    );
  }

  return (
    <div className="panel-body" style={{ padding: 0 }}>
      <div className="editor-list">
        {zones.map((zone, index) => {
          // In SRX view, display mapped interface names
          const displayInterfaces = isSrx
            ? zone.interfaces.map(iface => mapInterfaceToSrx(iface, interfaceMappings || {}))
            : zone.interfaces;

          return (
            <div key={index} className="editor-card">
              <div className="editor-card-header">
                <div style={{ flex: 1 }}>
                  {isSrx && <div className="srx-zone-label">security-zone</div>}
                  <input
                    className="editor-inline-input editor-name-input"
                    value={zone.name}
                    onChange={(e) => handleFieldChange(index, 'name', e.target.value)}
                    placeholder="Zone name"
                  />
                </div>
                <button
                  className="btn-icon btn-icon-danger"
                  onClick={() => handleDelete(index)}
                  title="Delete zone"
                >
                  x
                </button>
              </div>

              <div className="editor-card-body">
                <div className="editor-field">
                  <label>Description</label>
                  <input
                    className="editor-inline-input"
                    value={zone.description || ''}
                    onChange={(e) => handleFieldChange(index, 'description', e.target.value)}
                    placeholder="Optional description"
                  />
                </div>

                <div className="editor-field">
                  <label>{isSrx ? 'Interfaces (SRX)' : 'Interfaces'}</label>
                  {isSrx ? (
                    <div className="chip-editor">
                      {displayInterfaces.map((iface, i) => (
                        <span key={i} className="chip" style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                          {iface}
                          <button className="chip-remove" onClick={() => handleRemoveInterface(index, zone.interfaces[i])}>x</button>
                        </span>
                      ))}
                      <input
                        className="chip-input"
                        placeholder="Add interface..."
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' && e.target.value.trim()) {
                            handleAddInterface(index, e.target.value.trim());
                            e.target.value = '';
                          }
                        }}
                      />
                    </div>
                  ) : (
                    <ChipEditor
                      values={zone.interfaces}
                      onAdd={(val) => handleAddInterface(index, val)}
                      onRemove={(val) => handleRemoveInterface(index, val)}
                      placeholder="Add interface..."
                    />
                  )}
                </div>

                {isSrx && (
                  <div className="editor-field">
                    <label>host-inbound-traffic</label>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', fontSize: 11, color: 'var(--text-secondary)' }}>
                      {HOST_INBOUND_SERVICES.map(svc => {
                        const access = zone.host_inbound_traffic;
                        // `system-services all` (minus excepts) can't be edited per service, so show its effect read-only.
                        const wildcard = (access?.system_services || []).includes('all');
                        const checked = wildcard
                          ? !(access?.system_services_except || []).includes(svc)
                          : (access?.system_services || []).includes(svc);
                        return (
                          <label key={svc} style={{ display: 'flex', alignItems: 'center', gap: 3, cursor: wildcard ? 'default' : 'pointer' }}>
                            <input
                              type="checkbox"
                              checked={checked}
                              disabled={wildcard}
                              title={wildcard ? 'Set by system-services all' : undefined}
                              onChange={() => handleFieldChange(index, 'host_inbound_traffic', toggleHostInboundService(access, svc))}
                              style={{ accentColor: 'var(--accent)' }}
                            />
                            {svc}
                          </label>
                        );
                      })}
                    </div>
                    {extraHostInboundEntries(zone.host_inbound_traffic).length > 0 && (
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
                        {extraHostInboundEntries(zone.host_inbound_traffic).map(entry => (
                          <span key={entry} className="chip">{entry}</span>
                        ))}
                      </div>
                    )}
                    {/* Converters only read entries for interfaces still in the zone. */}
                    {Object.entries(zone.interface_host_inbound_traffic || {}).filter(([iface]) => zone.interfaces.includes(iface)).map(([iface, access]) => (
                      <div key={iface} style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>
                        {mapInterfaceToSrx(iface, interfaceMappings || {})}: {describeHostInbound(access)}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      <div style={{ padding: '12px 16px' }}>
        <button className="btn btn-secondary btn-sm" onClick={handleAdd}>
          + Add Zone
        </button>
      </div>
    </div>
  );
}

/** Reusable chip editor for string arrays */
export function ChipEditor({ values, onAdd, onRemove, placeholder }) {
  const [inputValue, setInputValue] = useState('');

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && inputValue.trim()) {
      onAdd(inputValue.trim());
      setInputValue('');
    }
  };

  return (
    <div className="chip-editor">
      {(values || []).map((val, i) => (
        <span key={i} className="chip">
          {val}
          <button className="chip-remove" onClick={() => onRemove(val)}>x</button>
        </span>
      ))}
      <input
        className="chip-input"
        value={inputValue}
        onChange={(e) => setInputValue(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder={placeholder || 'Type and press Enter'}
      />
    </div>
  );
}
