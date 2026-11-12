import { describe, it, expect } from 'vitest';
import { generateReportHtml } from '../public/utils/report-generator.js';

const base = {
  sourceVendor: 'panos', targetModel: 'SRX1600',
  intermediateConfig: {
    zones: [], interfaces: [], security_policies: [], nat_rules: [],
    address_objects: [], service_objects: [], static_routes: [],
  },
};

describe('report SSL-VPN section', () => {
  it('renders a Remote Access VPN section when GlobalProtect is present', () => {
    const data = {
      ...base,
      intermediateConfig: {
        ...base.intermediateConfig,
        global_protect: { gateways: [{ name: 'G41-GP-GW', tunnel_interface: 'tunnel.10' }] },
      },
    };
    const html = generateReportHtml(data);
    expect(html).toContain('Remote Access VPN');
    expect(html).toContain('G41-GP-GW');
    expect(html).toContain('tunnel.10');
    expect(html).toMatch(/Secure Connect|manual/i);
  });

  it('omits the section when no GlobalProtect is present', () => {
    const html = generateReportHtml(base);
    expect(html).not.toContain('Remote Access VPN');
  });

  it('places the Remote Access VPN section right after Security Policies (before NAT)', () => {
    const data = {
      ...base,
      intermediateConfig: {
        ...base.intermediateConfig,
        global_protect: { gateways: [{ name: 'G41-GP-GW', tunnel_interface: 'tunnel.10' }] },
      },
    };
    const html = generateReportHtml(data);
    // Anchor on the section-title markup (plain labels like "NAT Rules" also
    // appear in the Executive Summary stats).
    const policiesIdx = html.indexOf('section-title">Security Policies');
    const raIdx = html.indexOf('section-title">Remote Access VPN');
    const natIdx = html.indexOf('section-title">NAT Rules');
    expect(policiesIdx).toBeGreaterThan(-1);
    expect(natIdx).toBeGreaterThan(-1);
    expect(policiesIdx).toBeLessThan(raIdx);   // after Security Policies
    expect(raIdx).toBeLessThan(natIdx);        // before NAT Rules
  });
});

describe('report escaping', () => {
  it('escapes remote-access names exactly once', () => {
    const html = generateReportHtml({
      ...base,
      intermediateConfig: {
        ...base.intermediateConfig,
        global_protect: { gateways: [{ name: 'a&b<script>', tunnel_interface: 'tunnel.1' }] },
      },
    });
    expect(html).toContain('a&amp;b&lt;script&gt;');
    expect(html).not.toContain('&amp;amp;');
    expect(html).not.toContain('<script>');
  });
});
