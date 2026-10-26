/**
 * Auto-Split Utility
 *
 * Splits intermediate configs with multiple routing contexts (PAN-OS vsys,
 * FortiGate VDOMs, SRX logical-systems/tenants) into separate config slots
 * for the Multi-LS Merge workflow.
 *
 * Also detects shared zones across logical-systems for cross-LS lt- tunnel
 * interface generation.
 */

/**
 * Splits a single intermediateConfig with multiple routing contexts
 * into an array of config slot objects, one per vsys/VDOM/logical-system.
 *
 * @param {Object} intermediateConfig - Parsed intermediate JSON with routing_contexts.length > 1
 * @returns {Array<{lsName: string, intermediateConfig: Object}>|null} Null if no split needed
 */
export function autoSplitRoutingContexts(intermediateConfig) {
  const contexts = intermediateConfig.routing_contexts || [];
  if (contexts.length <= 1) return null;

  const slots = [];

  for (const ctx of contexts) {
    // Skip default routing context (it has no zone ownership data)
    if (ctx.type === 'default' && ctx.name === 'default') continue;

    const ctxZoneNames = new Set(ctx.zones || []);
    if (ctxZoneNames.size === 0) continue;

    // Filter zones belonging to this context
    const zones = (intermediateConfig.zones || []).filter(z => ctxZoneNames.has(z.name));

    // Filter policies by _vsys/_logical_system tag or zone membership
    const policies = (intermediateConfig.security_policies || []).filter(p => {
      if (p._vsys) return p._vsys === ctx.name;
      if (p._logical_system) return p._logical_system === ctx.name;
      if (p._implicit) return false; // Skip implicit rules, we'll add per-slot later
      // FortiGate: match by zone membership
      const srcMatch = (p.src_zones || []).some(z => z === 'any' || ctxZoneNames.has(z));
      const dstMatch = (p.dst_zones || []).some(z => z === 'any' || ctxZoneNames.has(z));
      return srcMatch || dstMatch;
    });

    // Filter NAT rules similarly
    const natRules = (intermediateConfig.nat_rules || []).filter(r => {
      if (r._vsys) return r._vsys === ctx.name;
      if (r._logical_system) return r._logical_system === ctx.name;
      const srcMatch = (r.src_zones || []).some(z => z === 'any' || ctxZoneNames.has(z));
      const dstMatch = (r.dst_zones || []).some(z => z === 'any' || ctxZoneNames.has(z));
      return srcMatch || dstMatch;
    });

    // Collect all referenced object names from filtered policies and NAT
    const referencedAddresses = new Set();
    const referencedServices = new Set();
    for (const p of [...policies, ...natRules]) {
      (p.src_addresses || []).forEach(a => referencedAddresses.add(a));
      (p.dst_addresses || []).forEach(a => referencedAddresses.add(a));
      (p.nat_src_addresses || []).forEach(a => referencedAddresses.add(a));
      (p.nat_dst_addresses || []).forEach(a => referencedAddresses.add(a));
      (p.services || []).forEach(s => referencedServices.add(s));
      (p.applications || []).forEach(s => referencedServices.add(s));
    }

    // Resolve address groups recursively
    const allAddressGroups = intermediateConfig.address_groups || [];
    const expandGroup = (name) => {
      const grp = allAddressGroups.find(g => g.name === name);
      if (grp) {
        (grp.members || []).forEach(m => {
          referencedAddresses.add(m);
          expandGroup(m); // Recursive for nested groups
        });
      }
    };
    for (const name of [...referencedAddresses]) expandGroup(name);

    // Resolve service groups recursively
    const allServiceGroups = intermediateConfig.service_groups || [];
    const expandServiceGroup = (name) => {
      const grp = allServiceGroups.find(g => g.name === name);
      if (grp) {
        (grp.members || []).forEach(m => {
          referencedServices.add(m);
          expandServiceGroup(m);
        });
      }
    };
    for (const name of [...referencedServices]) expandServiceGroup(name);

    // Filter objects by reference
    const addressObjects = (intermediateConfig.address_objects || []).filter(
      a => referencedAddresses.has(a.name)
    );
    const addressGroups = allAddressGroups.filter(
      g => referencedAddresses.has(g.name)
    );
    const serviceObjects = (intermediateConfig.service_objects || []).filter(
      s => referencedServices.has(s.name)
    );
    const serviceGroups = allServiceGroups.filter(
      g => referencedServices.has(g.name)
    );
    const applications = (intermediateConfig.applications || []).filter(
      a => referencedServices.has(a.name)
    );
    const applicationGroups = (intermediateConfig.application_groups || []).filter(
      g => referencedServices.has(g.name)
    );

    // Filter interfaces belonging to zones in this context
    const interfaces = (intermediateConfig.interfaces || []).filter(iface =>
      zones.some(z => (z.interfaces || []).includes(iface.name))
    );

    // Static routes for this context
    const staticRoutes = (intermediateConfig.static_routes || []).filter(
      r => !r.routing_context || r.routing_context === ctx.name
    );

    // Schedules, screen config, etc. — include all (shared)
    const schedules = intermediateConfig.schedules || [];
    const screenConfig = intermediateConfig.screen_config || [];

    // Sanitize LS name for Junos compatibility
    const lsName = sanitizeLsName(ctx.name);

    slots.push({
      lsName,
      intermediateConfig: {
        zones,
        address_objects: addressObjects,
        address_groups: addressGroups,
        service_objects: serviceObjects,
        service_groups: serviceGroups,
        security_policies: policies,
        nat_rules: natRules,
        applications,
        application_groups: applicationGroups,
        schedules,
        security_profile_objects: intermediateConfig.security_profile_objects || [],
        external_lists: intermediateConfig.external_lists || [],
        vpn_tunnels: [], // VPN is typically per-context
        ha_config: { enabled: false }, // HA is chassis-level
        management_ports: intermediateConfig.management_ports || {}, // device-global admin ports
        screen_config: screenConfig,
        syslog_config: [], // Syslog is typically chassis-level
        dhcp_config: [],
        qos_config: [],
        interfaces,
        routing_contexts: [ctx],
        static_routes: staticRoutes,
        target_context: null,
        transparent_mode: false,
        bridge_domains: [],
        l2_interfaces: [],
        vwire_pairs: [],
        metadata: {
          ...intermediateConfig.metadata,
          zone_count: zones.length,
          rule_count: policies.length,
          nat_rule_count: natRules.length,
          object_count: addressObjects.length + addressGroups.length + serviceObjects.length + serviceGroups.length,
          interface_count: interfaces.length,
          static_route_count: staticRoutes.length,
        },
      },
    });
  }

  return slots.length > 0 ? slots : null;
}

/**
 * Detects shared zone names across config slots and generates
 * lt- (logical tunnel) interface pair definitions for cross-LS routing.
 *
 * @param {Array<{lsName: string, intermediateConfig: Object}>} slots
 * @returns {Array<{ls1: string, ls2: string, sharedZone: string, lt1Unit: number, lt2Unit: number}>}
 */
export function detectCrossLsLinks(slots) {
  const links = [];
  let unitCounter = 0;

  // Build map: zone name → list of LS names that contain it
  const zoneToLs = new Map();
  for (const slot of slots) {
    for (const zone of (slot.intermediateConfig?.zones || [])) {
      if (!zoneToLs.has(zone.name)) zoneToLs.set(zone.name, []);
      zoneToLs.get(zone.name).push(slot.lsName);
    }
  }

  // For each zone that appears in 2+ logical-systems, generate pairwise lt- links
  for (const [zoneName, lsList] of zoneToLs) {
    if (lsList.length < 2) continue;

    for (let i = 0; i < lsList.length; i++) {
      for (let j = i + 1; j < lsList.length; j++) {
        const u1 = unitCounter++;
        const u2 = unitCounter++;
        links.push({
          ls1: lsList[i],
          ls2: lsList[j],
          sharedZone: zoneName,
          lt1Unit: u1,
          lt2Unit: u2,
        });
      }
    }
  }

  return links;
}

/**
 * Sanitizes a name for use as a Junos logical-system name.
 * Replaces spaces and special chars with hyphens.
 */
function sanitizeLsName(name) {
  return name
    .replace(/[^a-zA-Z0-9_-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    || 'LS-unknown';
}
