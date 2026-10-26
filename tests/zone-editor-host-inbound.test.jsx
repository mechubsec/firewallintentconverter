import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import ZoneEditor, { toggleHostInboundService } from '../public/components/ZoneEditor.jsx';

const render = (zone) => renderToStaticMarkup(
  <ZoneEditor zones={[zone]} onZonesUpdate={() => {}} viewMode="srx" interfaceMappings={{}} />
);
const checkbox = (html, svc) => html.match(new RegExp(`<input[^>]*type="checkbox"[^>]*>(?=${svc}<)`))?.[0];

describe('toggleHostInboundService', () => {
  it('creates access from undefined', () => {
    expect(toggleHostInboundService(undefined, 'ssh')).toEqual({ system_services: ['ssh'], protocols: [] });
  });
  it('adds to empty and removes on second toggle without duplicates', () => {
    const once = toggleHostInboundService({ system_services: [], protocols: [] }, 'ping');
    expect(once.system_services).toEqual(['ping']);
    expect(toggleHostInboundService(once, 'ping').system_services).toEqual([]);
  });
  it('preserves protocols and except lists', () => {
    const access = { system_services: ['ssh'], protocols: ['ospf'], system_services_except: ['ftp'], protocols_except: ['bgp'] };
    expect(toggleHostInboundService(access, 'ssh')).toEqual({ ...access, system_services: [] });
    expect(toggleHostInboundService(access, 'https')).toEqual({ ...access, system_services: ['ssh', 'https'] });
  });
});

describe('ZoneEditor SRX host-inbound display', () => {
  it('renders ping unchecked for a zone without access data', () => {
    const html = render({ name: 'trust', interfaces: [] });
    expect(checkbox(html, 'ping')).toBeDefined();
    expect(checkbox(html, 'ping')).not.toContain('checked');
  });
  it('renders existing services checked', () => {
    const html = render({ name: 'trust', interfaces: [], host_inbound_traffic: { system_services: ['ping', 'ssh'], protocols: [] } });
    expect(checkbox(html, 'ping')).toContain('checked');
    expect(checkbox(html, 'ssh')).toContain('checked');
    expect(checkbox(html, 'https')).not.toContain('checked');
  });
  it('shows extra services and per-interface access', () => {
    const html = render({
      name: 'trust', interfaces: ['port1'],
      host_inbound_traffic: { system_services: ['telnet'], protocols: ['ospf'], system_services_except: ['ftp'] },
      interface_host_inbound_traffic: {
        port1: { system_services: ['ssh', 'https'], protocols: [] },
        port9: { system_services: ['telnet', 'snmp'], protocols: [] },
      },
    });
    expect(html).toContain('telnet');
    expect(html).toContain('protocol ospf');
    expect(html).toContain('except ftp');
    expect(html).toContain('ssh, https');
    expect(html).not.toContain('port9');
  });
  it('shows system-services all as checked, read-only, minus excepts', () => {
    const html = render({
      name: 'trust', interfaces: [],
      host_inbound_traffic: { system_services: ['all'], protocols: [], system_services_except: ['ssh'] },
    });
    expect(checkbox(html, 'ping')).toContain('checked');
    expect(checkbox(html, 'ping')).toContain('disabled');
    expect(checkbox(html, 'ssh')).not.toContain('checked');
  });
});
