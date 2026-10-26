/** Shared vendor-name -> SRX interface derivation, used by the set converter and the LAG member resolver. */

/**
 * Maps PAN-OS interface naming (ethernet1/1, ethernet1/1.100) to
 * SRX interface naming (ge-0/0/0, ge-0/0/0.100).
 *
 * This is a best-effort mapping — real deployments will need the user to
 * confirm interface assignments, which is handled in the interview phase.
 */
export function mapInterfaceName(panosIface, interfaceMappings = {}) {
  // Check user-defined mappings first
  if (interfaceMappings[panosIface]) {
    const srx = interfaceMappings[panosIface];
    // Append .0 unit if not already specified
    return srx.includes('.') ? srx : `${srx}.0`;
  }

  // Strip VLAN unit for lookup, then re-add
  const base = panosIface.split('.')[0];
  const unit = panosIface.includes('.') ? panosIface.split('.')[1] : null;
  if (interfaceMappings[base]) {
    const srx = interfaceMappings[base];
    const srxBase = srx.split('.')[0];
    return `${srxBase}.${unit || '0'}`;
  }

  // Fallback: auto-map vendor interface naming to SRX ge-/xe- naming

  // PAN-OS: ethernet1/2 → ge-0/0/1.0  (slot-1, port-1)
  const panos = panosIface.match(/^ethernet(\d+)\/(\d+)(\.(\d+))?$/i);
  if (panos) {
    const slot = parseInt(panos[1]) - 1;
    const port = parseInt(panos[2]) - 1;
    const u = panos[4] || '0';
    return `ge-0/${slot}/${port}.${u}`;
  }

  // FortiGate: port1 → ge-0/0/0.0  (N-1)
  const forti = panosIface.match(/^port(\d+)(\.(\d+))?$/i);
  if (forti) {
    const port = parseInt(forti[1]) - 1;
    const u = forti[3] || '0';
    return `ge-0/0/${port}.${u}`;
  }

  // Check Point Gaia: eth0 → ge-0/0/0.0, bond0 passes through
  const cpEth = panosIface.match(/^eth(\d+)(\.(\d+))?$/i);
  if (cpEth) {
    const port = parseInt(cpEth[1]);
    const u = cpEth[3] || '0';
    return `ge-0/0/${port}.${u}`;
  }

  // SonicWall: X0 → ge-0/0/0.0
  const swX = panosIface.match(/^X(\d+)(\.(\d+))?$/i);
  if (swX) {
    const port = parseInt(swX[1]);
    const u = swX[3] || '0';
    return `ge-0/0/${port}.${u}`;
  }

  // Huawei: GigabitEthernet0/0/1 → ge-0/0/1.0
  const hwGe = panosIface.match(/^GigabitEthernet(\d+)\/(\d+)\/(\d+)(\.(\d+))?$/i);
  if (hwGe) {
    const slot = parseInt(hwGe[2]);
    const port = parseInt(hwGe[3]);
    const u = hwGe[5] || '0';
    return `ge-0/${slot}/${port}.${u}`;
  }

  // Huawei: XGigabitEthernet0/0/0 → xe-0/0/0.0
  const hwXe = panosIface.match(/^XGigabitEthernet(\d+)\/(\d+)\/(\d+)(\.(\d+))?$/i);
  if (hwXe) {
    const slot = parseInt(hwXe[2]);
    const port = parseInt(hwXe[3]);
    const u = hwXe[5] || '0';
    return `xe-0/${slot}/${port}.${u}`;
  }

  // Cisco ASA/IOS: GigabitEthernet1/1 (2-segment) → ge-0/0/0.0
  const ciscoGe2 = panosIface.match(/^GigabitEthernet(\d+)\/(\d+)(\.(\d+))?$/i);
  if (ciscoGe2) {
    const slot = parseInt(ciscoGe2[1]);
    const port = parseInt(ciscoGe2[2]);
    const u = ciscoGe2[4] || '0';
    return `ge-0/${slot}/${port}.${u}`;
  }

  // Cisco: TenGigabitEthernet1/1 → xe-0/1/1.0
  const ciscoXe = panosIface.match(/^TenGigabitEthernet(\d+)\/(\d+)(\.(\d+))?$/i);
  if (ciscoXe) {
    const slot = parseInt(ciscoXe[1]);
    const port = parseInt(ciscoXe[2]);
    const u = ciscoXe[4] || '0';
    return `xe-0/${slot}/${port}.${u}`;
  }

  // FortiGate named interfaces: internal/dmz/wan → ge-0/0/N.0
  const fortiNamed = panosIface.match(/^(internal|dmz|wan|lan)(\d*)(\.(\d+))?$/i);
  if (fortiNamed) {
    const nameMap = { internal: 1, dmz: 2, wan: 3, lan: 4 };
    const basePort = nameMap[fortiNamed[1].toLowerCase()] || 0;
    const idx = fortiNamed[2] ? parseInt(fortiNamed[2]) : 0;
    const u = fortiNamed[4] || '0';
    return `ge-0/0/${basePort + idx}.${u}`;
  }

  // Cisco: Tunnel interfaces → st0.N
  const tunnelMatch = panosIface.match(/^tunnel(\d+)(\.(\d+))?$/i);
  if (tunnelMatch) {
    const u = tunnelMatch[1] || '0';
    return `st0.${u}`;
  }

  // Bug 1 fix: Map vendor "loopback" interfaces to SRX lo0 naming.
  // Vendor configs use "loopback.X" but SRX expects "lo0.X". Without this,
  // the zone references an undefined interface-range 'loopback.X'.
  const loMatch = panosIface.match(/^loopback(\.(\d+))?$/i);
  if (loMatch) {
    const u = loMatch[2] || '0';
    return `lo0.${u}`;
  }

  // If it doesn't match any known format, return as-is
  return panosIface;
}

