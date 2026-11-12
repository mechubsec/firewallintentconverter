/**
 * Migration Report Generator — self-contained HTML report from parsed/converted firewall config
 */
import { BRAND, BRAND_COLORS as B, reportBrandLockup } from './brand.js';

const VENDOR_LABELS = {
  panos: 'PAN-OS', srx: 'SRX', fortigate: 'FortiGate',
  cisco_asa: 'Cisco ASA', checkpoint: 'Check Point',
  sonicwall: 'SonicWall', huawei_usg: 'Huawei USG',
  aws_sg: 'AWS Security Groups', azure_nsg: 'Azure NSG', gcp_fw: 'GCP Firewall',
  greenfield: 'Greenfield', srx_healthcheck: 'SRX Best Practice',
};

function esc(str) {
  if (str == null) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function arr(v) { return Array.isArray(v) ? v : []; }

function table(headers, rows) {
  if (!rows.length) return '<p class="empty">None</p>';
  let h = '<table><thead><tr>' + headers.map(h => `<th>${esc(h)}</th>`).join('') + '</tr></thead><tbody>';
  for (const row of rows) {
    h += '<tr>' + row.map(c => `<td>${esc(c)}</td>`).join('') + '</tr>';
  }
  return h + '</tbody></table>';
}

function section(id, title, content, count) {
  const badge = count != null ? ` <span class="badge">${count}</span>` : '';
  return `<div class="section">
    <div class="section-header" onclick="this.parentElement.classList.toggle('collapsed')">
      <span class="arrow">&#9660;</span> <span class="section-title">${esc(title)}${badge}</span>
    </div>
    <div class="section-body">${content}</div>
  </div>`;
}

/**
 * Generate a self-contained HTML migration report
 * @param {Object} data - App state data
 * @returns {string} Complete HTML document
 */
export function generateReportHtml(data) {
  const {
    sourceVendor = '', sourceModel = '', targetModel = '', siteName = '', siteGroup = '',
    intermediateConfig: ic, interfaceMappings = {}, conversionSummary: cs,
    parseWarnings = [], convertWarnings = [], isSanitized = false, ruleGroups = [],
  } = data || {};

  const zones = arr(ic?.zones);
  const interfaces = arr(ic?.interfaces);
  const policies = arr(ic?.security_policies);
  const natRules = arr(ic?.nat_rules);
  const addressObjects = arr(ic?.address_objects);
  const serviceObjects = arr(ic?.service_objects);
  const staticRoutes = arr(ic?.static_routes);
  const routing = ic?.routing || {};
  const bgp = ic?.bgp_config;
  const ospf = ic?.ospf_config;
  const vendorLabel = VENDOR_LABELS[sourceVendor] || sourceVendor || 'Unknown';
  const now = new Date().toLocaleString();

  // --- Build sections ---
  const sections = [];

  // 1. Executive Summary
  let execHtml = '<div class="summary-grid">';
  execHtml += `<div class="summary-item"><span class="label">Source Vendor</span><span class="value">${esc(vendorLabel)}</span></div>`;
  if (sourceModel) execHtml += `<div class="summary-item"><span class="label">Source Model</span><span class="value">${esc(sourceModel)}</span></div>`;
  if (targetModel) execHtml += `<div class="summary-item"><span class="label">Target Model</span><span class="value">${esc(targetModel)}</span></div>`;
  if (siteName) execHtml += `<div class="summary-item"><span class="label">Site Name</span><span class="value">${esc(siteName)}</span></div>`;
  if (siteGroup) execHtml += `<div class="summary-item"><span class="label">Site Group</span><span class="value">${esc(siteGroup)}</span></div>`;
  execHtml += `<div class="summary-item"><span class="label">Sanitized</span><span class="value">${isSanitized ? 'Yes' : 'No'}</span></div>`;
  execHtml += '</div>';
  execHtml += '<div class="summary-grid">';
  execHtml += `<div class="summary-item"><span class="label">Zones</span><span class="value">${zones.length}</span></div>`;
  execHtml += `<div class="summary-item"><span class="label">Interfaces</span><span class="value">${interfaces.length}</span></div>`;
  execHtml += `<div class="summary-item"><span class="label">Security Policies</span><span class="value">${policies.length}</span></div>`;
  execHtml += `<div class="summary-item"><span class="label">NAT Rules</span><span class="value">${natRules.length}</span></div>`;
  execHtml += `<div class="summary-item"><span class="label">Address Objects</span><span class="value">${addressObjects.length}</span></div>`;
  execHtml += `<div class="summary-item"><span class="label">Service Objects</span><span class="value">${serviceObjects.length}</span></div>`;
  execHtml += '</div>';
  sections.push(section('exec', 'Executive Summary', execHtml));

  // 2. Zone Mapping
  const zoneRows = zones.map(z => [
    z.name || '',
    arr(z.interfaces).join(', ') || '-',
    z.description || '',
  ]);
  sections.push(section('zones', 'Zone Mapping', table(['Zone', 'Interfaces', 'Description'], zoneRows), zones.length));

  // 3. Interface Details
  const ifaceRows = interfaces.map(iface => [
    iface.name || '',
    iface.ip || '-',
    iface.ipv6 || '-',
    iface.zone || '-',
    iface.vlan || '-',
    iface.type || '-',
    iface.status || '-',
    interfaceMappings[iface.name] || '-',
  ]);
  sections.push(section('interfaces', 'Interface Details',
    table(['Name', 'IPv4', 'IPv6', 'Zone', 'VLAN', 'Type', 'Status', 'Mapped To'], ifaceRows), interfaces.length));

  // 4. Security Policies
  let policyHtml = '';
  if (ruleGroups.length > 0) {
    // Group-aware display
    const groupedKeys = new Set();
    for (const group of ruleGroups) {
      policyHtml += `<h4 class="group-heading">${esc(group.name || 'Unnamed Group')}</h4>`;
      if (group.description) policyHtml += `<p class="group-desc">${esc(group.description)}</p>`;
      const groupPolicies = arr(group.rules).map(key => policies.find(p => {
        const pk = `${arr(p.src_zones).join(',')}_${arr(p.dst_zones).join(',')}_${p.name}`;
        if (pk === key) { groupedKeys.add(key); return true; }
        return false;
      })).filter(Boolean);
      policyHtml += table(['Name', 'From Zone', 'To Zone', 'Source', 'Destination', 'Services', 'Action', 'Log'],
        groupPolicies.map(p => policyRow(p)));
    }
    // Ungrouped policies
    const ungrouped = policies.filter(p => {
      const pk = `${arr(p.src_zones).join(',')}_${arr(p.dst_zones).join(',')}_${p.name}`;
      return !groupedKeys.has(pk);
    });
    if (ungrouped.length) {
      policyHtml += '<h4 class="group-heading">Ungrouped</h4>';
      policyHtml += table(['Name', 'From Zone', 'To Zone', 'Source', 'Destination', 'Services', 'Action', 'Log'],
        ungrouped.map(p => policyRow(p)));
    }
  } else {
    policyHtml = table(['Name', 'From Zone', 'To Zone', 'Source', 'Destination', 'Services', 'Action', 'Log'],
      policies.map(p => policyRow(p)));
  }
  sections.push(section('policies', 'Security Policies', policyHtml, policies.length));

  // Remote Access VPN (SSL-VPN / GlobalProtect) — manual, not auto-converted.
  // Grouped with the security/connectivity sections, right after Security Policies.
  const gpGateways = arr(ic?.global_protect?.gateways);
  if (gpGateways.length > 0) {
    const raRows = gpGateways.map(g => [
      g.tunnel_interface || '',
      g.name || '',
      'Rebuild as Juniper Secure Connect / IPsec dial-up (re-implement MFA via RADIUS).',
    ]);
    const raHtml = `<p>SSL-VPN remote access is <strong>not auto-converted</strong>. `
      + `The tunnels below map to <code>st0</code> placeholders only.</p>`
      + table(['Tunnel', 'GlobalProtect Gateway', 'Manual action'], raRows);
    sections.push(section('remote-access', 'Remote Access VPN (SSL-VPN)', raHtml, gpGateways.length));
  }

  // 5. NAT Rules
  const natRows = natRules.map(r => [
    r.name || '',
    r.type || '-',
    arr(r.src_addresses).join(', ') || '-',
    arr(r.dst_addresses).join(', ') || '-',
    r.translated_src ? (arr(r.translated_src.addresses).join(', ') || r.translated_src.type || '-') : '-',
    r.translated_dst ? (r.translated_dst.address || r.translated_dst.type || '-') : '-',
    r.description || '',
  ]);
  sections.push(section('nat', 'NAT Rules',
    table(['Name', 'Type', 'Source', 'Destination', 'Translated Src', 'Translated Dst', 'Description'], natRows), natRules.length));

  // 6. Address Objects
  const addrRows = addressObjects.map(a => [
    a.name || '',
    a.type || '-',
    a.value || '-',
    a.ip_version || '-',
  ]);
  sections.push(section('addresses', 'Address Objects',
    table(['Name', 'Type', 'Value', 'IP Version'], addrRows), addressObjects.length));

  // 7. Service Objects
  const svcRows = serviceObjects.map(s => [
    s.name || '',
    s.protocol || '-',
    s.dst_port || s.destination_port || '-',
    s.src_port || s.source_port || '-',
  ]);
  sections.push(section('services', 'Service Objects',
    table(['Name', 'Protocol', 'Dst Port', 'Src Port'], svcRows), serviceObjects.length));

  // 8. Routing
  let routeHtml = '';
  const routeRows = staticRoutes.map(r => [
    r.destination || r.prefix || '-',
    r.next_hop || r.nexthop || '-',
    r.interface || '-',
    r.metric != null ? String(r.metric) : '-',
  ]);
  routeHtml += '<h4>Static Routes</h4>' + table(['Destination', 'Next Hop', 'Interface', 'Metric'], routeRows);
  if (bgp) {
    routeHtml += '<h4>BGP</h4>';
    routeHtml += `<p>Router ID: ${esc(bgp.router_id || '-')} | AS: ${esc(bgp.local_as || '-')}</p>`;
    const bgpNeighbors = arr(bgp.neighbors || bgp.groups?.flatMap(g => arr(g.neighbors)) || []);
    if (bgpNeighbors.length) {
      routeHtml += table(['Neighbor', 'Remote AS', 'Group/Description'],
        bgpNeighbors.map(n => [n.address || n.ip || '-', n.peer_as || n.remote_as || '-', n.group || n.description || '-']));
    }
  }
  if (ospf) {
    routeHtml += '<h4>OSPF</h4>';
    routeHtml += `<p>Router ID: ${esc(ospf.router_id || '-')}</p>`;
    const areas = arr(ospf.areas);
    if (areas.length) {
      routeHtml += table(['Area', 'Interfaces'],
        areas.map(a => [a.id || a.area_id || '-', arr(a.interfaces).map(i => i.name || i).join(', ') || '-']));
    }
  }
  sections.push(section('routing', 'Routing', routeHtml, staticRoutes.length));

  // 9. Warnings
  const allWarnings = [...arr(parseWarnings), ...arr(convertWarnings)];
  let warnHtml = '';
  if (allWarnings.length === 0) {
    warnHtml = '<p class="empty">No warnings</p>';
  } else {
    warnHtml = '<ul class="warnings-list">';
    for (const w of allWarnings) {
      const severity = (typeof w === 'object' && w.severity) || 'info';
      const msg = typeof w === 'object' ? (w.message || w.detail || JSON.stringify(w)) : String(w);
      warnHtml += `<li class="warn-${esc(severity)}">${esc(msg)}</li>`;
    }
    warnHtml += '</ul>';
  }
  sections.push(section('warnings', 'Warnings', warnHtml, allWarnings.length));

  // 10. Conversion Statistics
  let statsHtml = '';
  if (cs) {
    const statsRows = Object.entries(cs)
      .filter(([k]) => !k.startsWith('_'))
      .map(([k, v]) => [k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()), String(v)]);
    statsHtml = table(['Metric', 'Count'], statsRows);
  } else {
    statsHtml = '<p class="empty">No conversion statistics available (convert the config first)</p>';
  }
  sections.push(section('stats', 'Conversion Statistics', statsHtml));

  // --- Assemble HTML ---
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Migration Report — ${esc(siteName || vendorLabel)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Geist Variable', 'Geist', 'Inter', system-ui, sans-serif; background: ${B.ink0}; color: ${B.text1}; padding: 24px; line-height: 1.5; }
  .report-header { text-align: center; padding: 24px 0 16px; border-bottom: 2px solid ${B.border}; margin-bottom: 20px; }
  .report-brand { display: flex; align-items: center; justify-content: center; gap: 8px; margin-bottom: 8px; font-family: 'Geist Variable', 'Inter', system-ui, sans-serif; }
  .mechub-report-mark { width: 34px; height: 34px; }
  .report-brand-name { font-weight: 700; letter-spacing: -.045em; }
  .brand-intent { color: ${B.plum}; }
  .report-endorsement { color: #6B7280; font: 500 10px 'Geist Mono Variable', monospace; }
  .report-header h1 { font-size: 22px; color: ${B.teal}; margin-bottom: 4px; }
  .report-header .subtitle { font-size: 13px; color: ${B.text3}; }
  .target-platform { color: ${B.juniper}; font-weight: 600; }
  .section { border: 1px solid ${B.border}; border-radius: 6px; margin-bottom: 12px; overflow: hidden; background: ${B.ink1}; }
  .section-header { background: ${B.ink2}; padding: 10px 14px; cursor: pointer; user-select: none; display: flex; align-items: center; gap: 8px; }
  .section-header:hover { background: ${B.border}; }
  .section-title { font-weight: 600; font-size: 14px; }
  .arrow { font-size: 10px; transition: transform 0.2s; }
  .collapsed .arrow { transform: rotate(-90deg); }
  .collapsed .section-body { display: none; }
  .section-body { padding: 12px 14px; }
  .badge { background: ${B.teal}; color: ${B.ink0}; font: 600 11px 'Geist Mono Variable', monospace; padding: 1px 7px; border-radius: 999px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 8px; }
  th { background: ${B.ink2}; padding: 6px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid ${B.border}; white-space: nowrap; }
  td { padding: 5px 8px; border-bottom: 1px solid ${B.border}; word-break: break-word; max-width: 300px; }
  tr:hover td { background: rgba(77,208,200,0.05); }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px; margin-bottom: 12px; }
  .summary-item { background: ${B.ink2}; padding: 10px 12px; border-radius: 6px; }
  .summary-item .label { display: block; font-size: 11px; color: ${B.text3}; text-transform: uppercase; letter-spacing: 0.5px; }
  .summary-item .value { display: block; font-size: 16px; font-weight: 600; margin-top: 2px; }
  .empty { color: ${B.text3}; font-style: italic; font-size: 13px; }
  .group-heading { font-size: 13px; color: ${B.teal}; margin: 12px 0 4px; padding-bottom: 4px; border-bottom: 1px solid ${B.border}; }
  .group-heading:first-child { margin-top: 0; }
  .group-desc { font-size: 12px; color: ${B.text3}; margin-bottom: 6px; }
  .warnings-list { list-style: none; padding: 0; }
  .warnings-list li { padding: 6px 10px; border-radius: 4px; margin-bottom: 4px; font-size: 12px; }
  .warn-error, .warn-critical { background: rgba(248,113,113,0.15); color: ${B.error}; }
  .warn-warning { background: rgba(251,191,36,0.15); color: ${B.warning}; }
  .warn-info { background: rgba(96,165,250,0.1); color: ${B.info}; }
  .report-footer { text-align: center; padding: 16px 0; margin-top: 20px; border-top: 1px solid ${B.border}; font-size: 11px; color: ${B.text3}; }

  @media print {
    body { background: #fff; color: #111; padding: 12px; }
    .report-header h1 { color: #1a5276; }
    .section { border-color: #ccc; }
    .section-header { background: #f4f4f4; color: #111; }
    .section-body { display: block !important; }
    .collapsed .section-body { display: block !important; }
    .arrow { display: none; }
    th { background: #e8e8e8; color: #111; border-color: #ccc; }
    td { border-color: #ddd; color: #222; }
    .summary-item { background: #f4f4f4; }
    .summary-item .label { color: #555; }
    .summary-item .value { color: #111; }
    .badge { background: #1a5276; color: #fff; }
    tr:hover td { background: transparent; }
    .warn-error, .warn-critical { background: #fde8e8; color: #c0392b; }
    .warn-warning { background: #fef9e7; color: #7d6608; }
    .warn-info { background: #ebf5fb; color: #1a5276; }
    .report-footer { color: #888; border-color: #ccc; }
  }
</style>
</head>
<body>
<div class="report-header">
  ${reportBrandLockup()}
  <h1>Firewall migration report</h1>
  <div class="subtitle">${esc(vendorLabel)}${sourceModel ? ' (' + esc(sourceModel) + ')' : ''} &rarr; <span class="target-platform">Juniper SRX${targetModel ? ' (' + esc(targetModel) + ')' : ''}</span> | Generated: ${esc(now)}</div>
</div>
${sections.join('\n')}
<div class="report-footer">Generated by ${BRAND.product} &middot; ${BRAND.endorsement} &mdash; ${esc(now)}</div>
</body>
</html>`;
}

function policyRow(p) {
  return [
    p.name || '',
    arr(p.src_zones).join(', ') || '-',
    arr(p.dst_zones).join(', ') || '-',
    arr(p.src_addresses).join(', ') || '-',
    arr(p.dst_addresses).join(', ') || '-',
    arr(p.applications || p.services).join(', ') || '-',
    p.action || '-',
    (p.log_start || p.log_end) ? 'Yes' : 'No',
  ];
}
