/**
 * useDay2Ops — Day 2 Operations hook
 *
 * Fetches live stats from an SRX device via the PyEZ Bridge, annotates
 * intermediate config policies with hit count data, manages auto-refresh
 * polling, and computes summary statistics.
 *
 * Reads bridge URL and session token through the shared bridge client.
 * Receives configDispatch and intermediateConfig as params to action functions.
 */
import { useState, useRef, useEffect, useCallback } from 'react';
import {
  bridgeErrorMessage,
  bridgeFetch,
  bridgeResponseJson,
  loadBridgeSettings,
} from '../utils/bridge-client.js';

// ---------------------------------------------------------------------------
// Pure functions (exported for testing)
// ---------------------------------------------------------------------------

/**
 * Compute summary statistics from annotated policies.
 * Pure version — accepts app_sessions explicitly instead of reading React state.
 *
 * @param {Array} policies - array of policy objects
 * @param {Array} [appSessions] - app session array from stats (for topApps)
 * @returns {{ total, annotated, active, neverHit, activePercent, totalSessions, topApps }}
 */
export function computeSummaryPure(policies, appSessions = []) {
  if (!Array.isArray(policies)) {
    return { total: 0, annotated: 0, active: 0, neverHit: 0, activePercent: 0, totalSessions: 0, topApps: [] };
  }

  const total = policies.length;
  const annotated = policies.filter(p => p._hit_count !== undefined).length;
  const active = policies.filter(p => (p._hit_count ?? 0) > 0).length;
  const neverHit = policies.filter(p => p._hit_count === 0 && !p.disabled).length;
  const activePercent = annotated > 0 ? Math.round((active / annotated) * 100) : 0;
  const totalSessions = policies.reduce((sum, p) => sum + (p._session_count ?? 0), 0);
  const topApps = [...appSessions]
    .sort((appA, appB) => (appB.sessions ?? 0) - (appA.sessions ?? 0))
    .slice(0, 10);

  return { total, annotated, active, neverHit, activePercent, totalSessions, topApps };
}

/**
 * Build a lookup from config policy to its device stats entry. SRX policy names
 * repeat across zone pairs, so entries that carry from_zone/to_zone only match
 * a policy whose zones include them; entries without zones match by name.
 *
 * @param {Array} statsPolicies - statsData.policies
 * @returns {Function} (configPolicy) => stats entry | undefined
 */
export function buildPolicyStatsLookup(statsPolicies) {
  const statsByName = new Map();
  for (const entry of statsPolicies) {
    if (!statsByName.has(entry.name)) statsByName.set(entry.name, []);
    statsByName.get(entry.name).push(entry);
  }
  return (policy) => (statsByName.get(policy.name) || []).find(entry =>
    (!entry.from_zone || (policy.src_zones || []).includes(entry.from_zone))
    && (!entry.to_zone || (policy.dst_zones || []).includes(entry.to_zone)));
}

/**
 * Annotate config policies with stats data (pure, no React/dispatch).
 *
 * @param {Array} configPolicies - security_policies array from intermediateConfig
 * @param {object} statsData - { policies: [...], app_sessions: [...] }
 * @returns {{ annotatedPolicies: Array, matchCount: number, matchRate: number }}
 */
export function annotateConfigPure(configPolicies, statsData) {
  if (!Array.isArray(configPolicies) || !statsData?.policies) {
    return { annotatedPolicies: configPolicies || [], matchCount: 0, matchRate: 1 };
  }

  const findPolicyStats = buildPolicyStatsLookup(statsData.policies);

  const appSessionMap = new Map();
  for (const appEntry of (statsData.app_sessions || [])) {
    appSessionMap.set(appEntry.application, appEntry.sessions);
  }

  let matchCount = 0;
  const timestamp = new Date().toISOString();

  const annotatedPolicies = configPolicies.map(policy => {
    const policyStats = findPolicyStats(policy);
    if (!policyStats) return policy;

    matchCount++;

    const policyApps = Array.isArray(policy.applications) ? policy.applications : [];
    const matchedApps = policyApps.filter(app => appSessionMap.has(app));

    return {
      ...policy,
      _hit_count: policyStats.hit_count ?? 0,
      _session_count: policyStats.session_count ?? 0,
      _byte_count: policyStats.byte_count ?? 0,
      _matched_apps: matchedApps,
      _stats_timestamp: timestamp,
    };
  });

  const totalPolicies = configPolicies.length;
  const matchRate = totalPolicies > 0 ? matchCount / totalPolicies : 1;

  return { annotatedPolicies, matchCount, matchRate };
}

/**
 * Disable policies where _hit_count === 0 and not already disabled (pure).
 *
 * @param {Array} policies - security_policies array
 * @returns {Array} updated policies
 */
export function disableNeverHitRulesPure(policies) {
  if (!Array.isArray(policies)) return [];
  return policies.map(policy => {
    if (policy._hit_count === 0 && !policy.disabled) {
      return { ...policy, disabled: true };
    }
    return policy;
  });
}

/**
 * Replace 'any' application with matched apps for policies with actual usage (pure).
 *
 * @param {Array} policies - security_policies array
 * @returns {Array} updated policies
 */
export function tightenPermissiveRulesPure(policies) {
  if (!Array.isArray(policies)) return [];
  return policies.map(policy => {
    const hasAny = Array.isArray(policy.applications) && policy.applications.includes('any');
    const hasMatchedApps = Array.isArray(policy._matched_apps) && policy._matched_apps.length > 0;
    if (hasAny && hasMatchedApps) {
      return { ...policy, applications: [...policy._matched_apps] };
    }
    return policy;
  });
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Core hook for Day 2 operations.
 * Provides live stats fetching, policy annotation, polling, and batch actions.
 */
export default function useDay2Ops() {
  const [deviceName, setDeviceName] = useState('');
  const [devices, setDevices] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [lastFetchTime, setLastFetchTime] = useState(null);
  const [stats, setStats] = useState(null);
  const [annotationApplied, setAnnotationApplied] = useState(false);
  const [isPolling, setIsPolling] = useState(false);
  const [pollInterval, setPollInterval] = useState(30000); // 30s default

  const pollIntervalRef = useRef(null);
  const pollIntervalMsRef = useRef(30000);

  // Keep pollIntervalMsRef in sync with pollInterval state
  useEffect(() => {
    pollIntervalMsRef.current = pollInterval;
  }, [pollInterval]);

  // Cleanup polling interval on unmount
  useEffect(() => {
    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  }, []);

  // -----------------------------------------------------------------------
  // refreshDevices
  // -----------------------------------------------------------------------

  /**
   * Fetch the list of devices from the bridge and update `devices` state.
   * Called on mount by the consuming component.
   */
  const refreshDevices = useCallback(async () => {
    const baseUrl = loadBridgeSettings().url;
    if (!baseUrl) return;
    try {
      const resp = await bridgeFetch(baseUrl + '/devices');
      const data = await bridgeResponseJson(resp);
      setDevices(Array.isArray(data) ? data : data.devices || []);
    } catch (error) {
      setError(bridgeErrorMessage(error, 'Failed to refresh devices.'));
    }
  }, []);

  // -----------------------------------------------------------------------
  // fetchStats
  // -----------------------------------------------------------------------

  /**
   * Fetch live policy stats for a device from two endpoints in parallel:
   * - /devices/<device>/policy-stats
   * - /devices/<device>/app-usage
   * Merges results, preferring app-usage data (has zone info).
   * Sets `stats`, `lastFetchTime`, and clears `error` on success.
   * On partial failure, uses available data and sets a non-blocking error.
   *
   * @param {string} device - device name to fetch stats for
   * @returns {Promise<object|null>} merged stats object or null on total failure
   */
  const fetchStats = useCallback(async (device) => {
    const targetDevice = device || deviceName;
    if (!targetDevice) return null;

    const baseUrl = loadBridgeSettings().url;
    if (!baseUrl) {
      setError('No bridge URL configured.');
      return null;
    }

    setIsLoading(true);

    const encodedDevice = encodeURIComponent(targetDevice);
    let policyStats = null;
    let appUsage = null;
    const errors = [];

    const [policyResult, appResult] = await Promise.allSettled([
      bridgeFetch(baseUrl + `/devices/${encodedDevice}/policy-stats`)
        .then(bridgeResponseJson),
      bridgeFetch(baseUrl + `/devices/${encodedDevice}/app-usage`)
        .then(bridgeResponseJson),
    ]);

    if (policyResult.status === 'fulfilled') {
      policyStats = policyResult.value;
    } else {
      errors.push(bridgeErrorMessage(
        policyResult.reason,
        'Policy statistics could not be loaded.',
      ));
    }

    if (appResult.status === 'fulfilled') {
      appUsage = appResult.value;
    } else {
      errors.push(bridgeErrorMessage(
        appResult.reason,
        'Application usage statistics could not be loaded.',
      ));
    }

    if (!policyStats && !appUsage) {
      setIsLoading(false);
      setError(`Failed to fetch stats: ${errors.join('; ')}`);
      return null;
    }

    // Merge: build policy map from policy-stats, overlay with app-usage (has zone info)
    const policyMap = new Map();

    if (policyStats?.policies) {
      for (const policy of policyStats.policies) {
        policyMap.set(policy.name, { ...policy });
      }
    }

    if (appUsage?.policies) {
      for (const policy of appUsage.policies) {
        const existing = policyMap.get(policy.name) || {};
        policyMap.set(policy.name, { ...existing, ...policy });
      }
    }

    const mergedStats = {
      policies: Array.from(policyMap.values()),
      app_sessions: appUsage?.app_sessions || [],
    };

    setStats(mergedStats);
    setLastFetchTime(new Date().toISOString());
    setIsLoading(false);

    if (errors.length > 0) {
      setError(`Partial data — ${errors.join('; ')}`);
    } else {
      setError(null);
    }

    return mergedStats;
  }, [deviceName]);

  // -----------------------------------------------------------------------
  // annotateConfig
  // -----------------------------------------------------------------------

  /**
   * Match fetched stats to config policies and annotate them with hit count data.
   * Dispatches an UPDATE_CONFIG action to the config context.
   * Sets a warning error if match rate is below 50%.
   *
   * @param {Function} configDispatch - dispatch function from useConfigContext
   * @param {object} intermediateConfig - current intermediate config object
   * @param {object} [overrideStats] - optional stats to use instead of state (used during polling)
   */
  const annotateConfig = useCallback((configDispatch, intermediateConfig, overrideStats) => {
    const activeStats = overrideStats || stats;
    if (!activeStats || !intermediateConfig?.security_policies) return;

    const findPolicyStats = buildPolicyStatsLookup(activeStats.policies);

    // Build app session lookup: application → sessions
    const appSessionMap = new Map();
    for (const appEntry of (activeStats.app_sessions || [])) {
      appSessionMap.set(appEntry.application, appEntry.sessions);
    }

    let matchCount = 0;
    const timestamp = new Date().toISOString();

    const annotatedPolicies = intermediateConfig.security_policies.map(policy => {
      const policyStats = findPolicyStats(policy);
      if (!policyStats) return policy;

      matchCount++;

      // Build _matched_apps: intersection of policy.applications and known app sessions
      const policyApps = Array.isArray(policy.applications) ? policy.applications : [];
      const matchedApps = policyApps.filter(app => appSessionMap.has(app));

      return {
        ...policy,
        _hit_count: policyStats.hit_count ?? 0,
        _session_count: policyStats.session_count ?? 0,
        _byte_count: policyStats.byte_count ?? 0,
        _matched_apps: matchedApps,
        _stats_timestamp: timestamp,
      };
    });

    const totalPolicies = intermediateConfig.security_policies.length;
    const matchRate = totalPolicies > 0 ? matchCount / totalPolicies : 1;

    configDispatch({
      type: 'UPDATE_CONFIG',
      updater: (prev) => ({ ...prev, security_policies: annotatedPolicies }),
    });

    setAnnotationApplied(true);

    if (matchRate < 0.5) {
      setError(
        `Low match rate: only ${matchCount}/${totalPolicies} policies matched stats data. ` +
        'Policy names may differ between config and device.'
      );
    }
  }, [stats]);

  // -----------------------------------------------------------------------
  // Polling
  // -----------------------------------------------------------------------

  /**
   * Start auto-refresh polling: fetches stats and annotates config on each interval.
   *
   * @param {string} device - device name to poll
   * @param {Function} configDispatch - dispatch function from useConfigContext
   * @param {object} intermediateConfig - current intermediate config object
   */
  const startPolling = useCallback((device, configDispatch, intermediateConfig) => {
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);

    setIsPolling(true);

    pollIntervalRef.current = setInterval(async () => {
      const freshStats = await fetchStats(device);
      if (freshStats) {
        annotateConfig(configDispatch, intermediateConfig, freshStats);
      }
    }, pollIntervalMsRef.current);
  }, [fetchStats, annotateConfig]);

  /**
   * Stop auto-refresh polling.
   */
  const stopPolling = useCallback(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
    setIsPolling(false);
  }, []);

  // -----------------------------------------------------------------------
  // computeSummary
  // -----------------------------------------------------------------------

  /**
   * Compute summary statistics from annotated policies.
   * Pure function — does not read or set state.
   *
   * @param {Array} policies - array of policy objects from intermediateConfig.security_policies
   * @returns {{ total, annotated, active, neverHit, activePercent, totalSessions, topApps }}
   */
  const computeSummary = useCallback((policies) => {
    if (!Array.isArray(policies)) {
      return {
        total: 0,
        annotated: 0,
        active: 0,
        neverHit: 0,
        activePercent: 0,
        totalSessions: 0,
        topApps: [],
      };
    }

    const total = policies.length;
    const annotated = policies.filter(p => p._hit_count !== undefined).length;
    const active = policies.filter(p => (p._hit_count ?? 0) > 0).length;
    const neverHit = policies.filter(p => p._hit_count === 0 && !p.disabled).length;
    const activePercent = annotated > 0 ? Math.round((active / annotated) * 100) : 0;
    const totalSessions = policies.reduce((sum, p) => sum + (p._session_count ?? 0), 0);

    const topApps = [...(stats?.app_sessions || [])]
      .sort((appA, appB) => (appB.sessions ?? 0) - (appA.sessions ?? 0))
      .slice(0, 10);

    return { total, annotated, active, neverHit, activePercent, totalSessions, topApps };
  }, [stats]);

  // -----------------------------------------------------------------------
  // Batch actions
  // -----------------------------------------------------------------------

  /**
   * Disable all policies where _hit_count === 0 and not already disabled.
   *
   * @param {Function} configDispatch - dispatch function from useConfigContext
   * @param {object} intermediateConfig - current intermediate config object
   */
  const disableNeverHitRules = useCallback((configDispatch, intermediateConfig) => {
    if (!intermediateConfig?.security_policies) return;

    const updatedPolicies = intermediateConfig.security_policies.map(policy => {
      if (policy._hit_count === 0 && !policy.disabled) {
        return { ...policy, disabled: true };
      }
      return policy;
    });

    configDispatch({
      type: 'UPDATE_CONFIG',
      updater: (prev) => ({ ...prev, security_policies: updatedPolicies }),
    });
  }, []);

  /**
   * Replace 'any' application with matched apps for policies that have actual usage data.
   * Only applies to policies where applications includes 'any' AND _matched_apps is non-empty.
   *
   * @param {Function} configDispatch - dispatch function from useConfigContext
   * @param {object} intermediateConfig - current intermediate config object
   */
  const tightenPermissiveRules = useCallback((configDispatch, intermediateConfig) => {
    if (!intermediateConfig?.security_policies) return;

    const updatedPolicies = intermediateConfig.security_policies.map(policy => {
      const hasAny = Array.isArray(policy.applications) && policy.applications.includes('any');
      const hasMatchedApps = Array.isArray(policy._matched_apps) && policy._matched_apps.length > 0;

      if (hasAny && hasMatchedApps) {
        return { ...policy, applications: [...policy._matched_apps] };
      }
      return policy;
    });

    configDispatch({
      type: 'UPDATE_CONFIG',
      updater: (prev) => ({ ...prev, security_policies: updatedPolicies }),
    });
  }, []);

  // -----------------------------------------------------------------------
  // Return public API
  // -----------------------------------------------------------------------
  return {
    // State
    deviceName,
    setDeviceName,
    devices,
    isLoading,
    error,
    lastFetchTime,
    stats,
    annotationApplied,
    isPolling,
    pollInterval,
    setPollInterval,
    // Actions
    refreshDevices,
    fetchStats,
    annotateConfig,
    startPolling,
    stopPolling,
    computeSummary,
    disableNeverHitRules,
    tightenPermissiveRules,
    // Helpers
    bridgeUrl: loadBridgeSettings().url,
  };
}
