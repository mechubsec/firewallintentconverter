/**
 * App Mappings — Multi-vendor L7 application mapping table.
 *
 * Adapted from fatcat/converter's app-mappings.json data file.
 * Provides bidirectional lookup: vendorApp → junosApp and vendorApp → canonical.
 */

// Our vendor IDs → fatcat vendor keys
export const VENDOR_KEY_MAP = {
  panos: 'panos',
  fortigate: 'fortios',
  cisco_asa: 'ftd',
  srx: 'junos',
  checkpoint: 'checkpoint',
  sonicwall: 'sonicwall',
  huawei_usg: 'huawei',
};

let _appData = null;
let _vendorIndex = null; // Map<ourVendor, Map<vendorAppNameLower, entry>>

// User-editable overrides persisted in browser localStorage under this key.
// Shape: { <vendorId>: { <vendorAppNameLower>: { _deleted?: true, junosApp?, canonical?, kind?, name?, protocol?, ports?, category?, description? } } }
const OVERRIDES_STORAGE_KEY = 'app-mappings-overrides';
let _overridesCache = null; // null = not yet read; object = cached value

/**
 * Reads the override map from localStorage. Returns {} in Node or when empty.
 * Prototype-pollution safe: strips __proto__/constructor/prototype keys.
 */
function _loadOverrides() {
  if (_overridesCache !== null) return _overridesCache;
  if (typeof localStorage === 'undefined') {
    _overridesCache = {};
    return _overridesCache;
  }
  try {
    const raw = localStorage.getItem(OVERRIDES_STORAGE_KEY);
    if (!raw) {
      _overridesCache = {};
      return _overridesCache;
    }
    _overridesCache = JSON.parse(raw, (key, value) => {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') return undefined;
      return value;
    }) || {};
  } catch {
    _overridesCache = {};
  }
  return _overridesCache;
}

/**
 * Invalidates the cached override map. Call after the Settings UI writes
 * a new override so the next lookup re-reads localStorage.
 */
export function invalidateOverridesCache() {
  _overridesCache = null;
}

/**
 * Returns the override record for (vendor, app) or null.
 * Input is lower-cased before lookup.
 */
function _getOverride(vendorAppName, sourceVendor) {
  if (!vendorAppName || !sourceVendor) return null;
  const overrides = _loadOverrides();
  const vendorMap = overrides[sourceVendor];
  if (!vendorMap || typeof vendorMap !== 'object') return null;
  const record = vendorMap[vendorAppName.toLowerCase()];
  return record || null;
}

/**
 * Synchronous user-override lookup for (vendor, app), safe when localStorage
 * is missing or unreadable. Returns the raw override record or null.
 *
 * @param {string} vendorAppName - App/service name from the source config
 * @param {string} sourceVendor - Our vendor ID
 * @returns {Object|null} Override record, or null
 */
export function getAppOverride(vendorAppName, sourceVendor) {
  try {
    return _getOverride(vendorAppName, sourceVendor);
  } catch {
    return null;
  }
}

/**
 * Adds an indexable key → app entry, lower-cased and de-duplicated.
 * Existing keys are NOT overwritten (first app wins) so a rare-word canonical
 * cannot be hijacked by a later app listing it as an alias.
 */
function _indexKey(map, key, app) {
  if (!key) return;
  const normalized = String(key).toLowerCase();
  if (!map.has(normalized)) {
    map.set(normalized, app);
  }
}

function _buildIndex() {
  _vendorIndex = {};
  for (const [ourVendor, fatcatKey] of Object.entries(VENDOR_KEY_MAP)) {
    if (!fatcatKey) continue;
    const map = new Map();
    for (const app of _appData.apps) {
      const vendorEntry = app.vendors[fatcatKey];
      // 1. Vendor-specific display name (original behavior)
      if (vendorEntry && vendorEntry.name) {
        _indexKey(map, vendorEntry.name, app);
      }
      // 2. Vendor-specific aliases (optional schema field)
      if (vendorEntry && Array.isArray(vendorEntry.aliases)) {
        for (const alias of vendorEntry.aliases) _indexKey(map, alias, app);
      }
      // 3. Canonical name — covers PAN-OS configs that emit the canonical form
      //    (e.g. "facebook") instead of the vendor-specific display ("facebook-base").
      _indexKey(map, app.canonical, app);
      // 4. PAN-OS <canonical>-base fallback: many PA App-IDs follow the
      //    "<canonical>-base" convention. Only applied when the panos block
      //    is absent so we don't shadow a real panos.name value.
      if (fatcatKey === 'panos' && !vendorEntry && app.canonical) {
        _indexKey(map, `${app.canonical}-base`, app);
      }
    }
    _vendorIndex[ourVendor] = map;
  }
}

/**
 * Loads and indexes the app-mappings.json file.
 * Called lazily on first use. Caches the result.
 */
export async function loadAppMappings() {
  if (_appData) return _appData;
  const mod = await import('../data/app-mappings.json', { with: { type: 'json' } });
  _appData = mod.default || mod;
  _buildIndex();
  return _appData;
}

/**
 * Converts fatcat's "junos:HTTPS" format to our "junos-https" style.
 */
export function normalizeJunosName(name) {
  if (!name) return name;
  if (name.startsWith('junos:')) {
    return 'junos-' + name.slice(6).toLowerCase();
  }
  return name;
}

/**
 * Maps a vendor-specific application name to a Junos application name.
 *
 * @param {string} vendorAppName - The app name from the source config
 * @param {string} sourceVendor - Our vendor ID (panos, fortigate, cisco_asa, etc.)
 * @returns {{ junosApp: string, confidence: number, canonical: string, category: string } | null}
 */
export function mapVendorApp(vendorAppName, sourceVendor) {
  if (!vendorAppName || !_vendorIndex) return null;

  // User override takes precedence over the bundled table.
  const override = _getOverride(vendorAppName, sourceVendor);
  if (override) {
    if (override._deleted) return null;
    return {
      junosApp: override.junosApp ?? (override.kind === 'predefined' ? override.name : null),
      confidence: override.confidence ?? 1,
      canonical: override.canonical ?? vendorAppName.toLowerCase(),
      category: override.category ?? 'user-override',
      description: override.description ?? 'User-defined mapping',
      ports: override.ports ?? [],
    };
  }

  const index = _vendorIndex[sourceVendor];
  if (!index) return null;

  const entry = index.get(vendorAppName.toLowerCase());
  if (!entry) return null;

  const junosEntry = entry.vendors.junos;
  if (!junosEntry) return null;

  return {
    junosApp: normalizeJunosName(junosEntry.name),
    confidence: junosEntry.confidence,
    canonical: entry.canonical,
    category: entry.category,
    description: entry.description,
    ports: entry.ports,
  };
}

/**
 * Gets the canonical app info for a vendor-specific app name.
 *
 * @param {string} vendorAppName - App name from source config
 * @param {string} sourceVendor - Our vendor ID
 * @returns {{ canonical: string, ports: string[], category: string, description: string } | null}
 */
export function getCanonicalApp(vendorAppName, sourceVendor) {
  if (!vendorAppName || !_vendorIndex) return null;
  const index = _vendorIndex[sourceVendor];
  if (!index) return null;

  const entry = index.get(vendorAppName.toLowerCase());
  if (!entry) return null;

  return {
    canonical: entry.canonical,
    ports: entry.ports,
    category: entry.category,
    description: entry.description,
    protocols: entry.protocols,
  };
}

/**
 * Returns the total number of mapped applications.
 */
export function getAppCount() {
  return _appData?.apps?.length || 0;
}

/**
 * Returns true if the app mappings have been loaded.
 */
export function isLoaded() {
  return _appData !== null;
}

/**
 * Returns how a vendor app should be emitted as a Junos application reference.
 *
 *   { kind: 'predefined', name: 'junos-https' }
 *     → policy references this name directly; no applications-section emission needed.
 *
 *   { kind: 'custom', protocol: 'tcp', ports: ['5223','2195','2196'], canonical: '...' }
 *     → caller emits `set applications application <name> protocol tcp destination-port <p>`
 *       (for each port, possibly wrapped in an application-set for multi-port).
 *
 *   null
 *     → no knowledge; caller should fall through to sync APP_MAP then INTERVIEW block.
 *
 * Confidence threshold: 0.8, matching mapAppToJunos().
 *
 * @param {string} vendorAppName - The app name from the source config
 * @param {string} sourceVendor - Our vendor ID (panos, fortigate, cisco_asa, etc.)
 * @returns {{ kind: 'predefined', name: string } | { kind: 'custom', protocol: string, ports: string[], canonical: string } | null}
 */
export function getJunosEmission(vendorAppName, sourceVendor) {
  if (!vendorAppName || !_vendorIndex) return null;

  // User override takes precedence.
  const override = _getOverride(vendorAppName, sourceVendor);
  if (override) {
    if (override._deleted) return null;
    if (override.kind === 'predefined' && override.name) {
      return { kind: 'predefined', name: normalizeJunosName(override.name) };
    }
    if (override.kind === 'custom' && override.protocol && Array.isArray(override.ports)) {
      return {
        kind: 'custom',
        protocol: String(override.protocol).toLowerCase(),
        ports: override.ports.slice(),
        canonical: override.canonical ?? vendorAppName.toLowerCase(),
      };
    }
    // Malformed override — fall through to bundled lookup rather than crash
  }

  const index = _vendorIndex[sourceVendor];
  if (!index) return null;
  const entry = index.get(vendorAppName.toLowerCase());
  if (!entry) return null;

  const junosEntry = entry.vendors.junos;
  if (junosEntry && junosEntry.confidence >= 0.8) {
    return { kind: 'predefined', name: normalizeJunosName(junosEntry.name) };
  }

  // No high-confidence Junos predefined — emit as custom app if we know ports/protocols
  if (Array.isArray(entry.protocols) && entry.protocols.length > 0 &&
      Array.isArray(entry.ports) && entry.ports.length > 0) {
    // Prefer TCP if multi-protocol (simpler custom-app emission); protocols are uppercase in JSON
    const protoRaw = entry.protocols.includes('TCP') ? 'TCP' : entry.protocols[0];
    return {
      kind: 'custom',
      protocol: protoRaw.toLowerCase(),
      ports: entry.ports.slice(),
      canonical: entry.canonical,
    };
  }

  return null;
}
