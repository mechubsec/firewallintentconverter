/**
 * useConfig — Main config manipulation hook
 *
 * Provides handlers for parsing, sanitizing, editing config text,
 * CRUD operations on security policies, and field-level config updates.
 * Uses ConfigContext, UIContext, UndoContext, and MergeContext.
 */
import { useCallback } from 'react';
import { useConfigContext } from '../contexts/ConfigContext.jsx';
import { useUIContext } from '../contexts/UIContext.jsx';
import { useMergeContext } from '../contexts/MergeContext.jsx';
import { useUndoContext } from '../contexts/UndoContext.jsx';
import useUndoRedo from './useUndoRedo.js';
import { parseConfig, sanitizeConfig } from '../utils/engine.js';

// ---------------------------------------------------------------------------
// Helper: stable rule identity key
// ---------------------------------------------------------------------------
export function makeRuleKey(policy) {
  return `${policy.name}::${policy._rule_index}`;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------
export default function useConfig() {
  const { state: configState, dispatch: configDispatch } = useConfigContext();
  const { state: uiState, dispatch: uiDispatch } = useUIContext();
  const { state: mergeState, dispatch: mergeDispatch } = useMergeContext();
  const { pushSnapshot } = useUndoRedo();
  const { dispatch: undoDispatch } = useUndoContext();

  // -----------------------------------------------------------------------
  // updateConfig — wraps config dispatch with merge mode awareness
  // -----------------------------------------------------------------------
  const updateConfig = useCallback((updaterFn) => {
    pushSnapshot();
    if (mergeState.mergeMode) {
      // Update the active slot's intermediateConfig
      const slotIndex = mergeState.activeSlotIndex;
      mergeDispatch({
        type: 'UPDATE_SLOT',
        index: slotIndex,
        slot: {
          intermediateConfig: updaterFn(
            mergeState.configSlots[slotIndex]?.intermediateConfig,
          ),
        },
      });
    } else {
      configDispatch({ type: 'UPDATE_CONFIG', updater: updaterFn });
    }
  }, [pushSnapshot, mergeState.mergeMode, mergeState.activeSlotIndex, mergeState.configSlots, mergeDispatch, configDispatch]);

  // -----------------------------------------------------------------------
  // handleSanitize — sanitize config text only
  // -----------------------------------------------------------------------
  const handleSanitize = useCallback(() => {
    if (!configState.configText.trim()) return;
    uiDispatch({ type: 'SET_LOADING', isLoading: true, message: 'Sanitizing configuration...' });
    uiDispatch({ type: 'CLEAR_ERROR' });

    try {
      const data = sanitizeConfig(configState.configText);
      configDispatch({
        type: 'SET_SANITIZATION_RESULT',
        configText: data.sanitizedText,
        sanitizationTable: data.replacements,
      });
    } catch (err) {
      uiDispatch({ type: 'SET_FIELD', field: 'error', value: `Sanitize error: ${err.message}` });
    } finally {
      uiDispatch({ type: 'SET_LOADING', isLoading: false });
    }
  }, [configState.configText, configDispatch, uiDispatch]);

  // -----------------------------------------------------------------------
  // handleConfigChange — update configText, reset sanitization if needed
  // -----------------------------------------------------------------------
  const handleConfigChange = useCallback((text) => {
    configDispatch({ type: 'SET_FIELD', field: 'configText', value: text });
    if (configState.isSanitized) {
      configDispatch({ type: 'SET_FIELD', field: 'isSanitized', value: false });
      configDispatch({ type: 'SET_FIELD', field: 'sanitizationTable', value: null });
      uiDispatch({ type: 'SET_FIELD', field: 'llmWarningDismissed', value: false });
    }
  }, [configState.isSanitized, configDispatch, uiDispatch]);

  // -----------------------------------------------------------------------
  // handleParse — sanitize + parse config, set parse result, auto-open
  //               model selector
  // -----------------------------------------------------------------------
  const handleParse = useCallback(async (selectedVendorHint, overrideText) => {
    const rawText = overrideText || configState.configText;
    if (!rawText.trim()) return;

    uiDispatch({ type: 'SET_LOADING', isLoading: true, message: 'Sanitizing & parsing configuration...' });
    uiDispatch({ type: 'CLEAR_ERROR' });

    // Old snapshots belong to the config being replaced; Ctrl+Z must not restore them
    undoDispatch({ type: 'CLEAR' });

    // Reset conversion & translation state
    configDispatch({ type: 'SET_FIELD', field: 'srxTranslatedPolicies', value: null });
    uiDispatch({ type: 'SET_FIELD', field: 'selectedRule', value: null });
    uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'rules' });
    uiDispatch({ type: 'SET_FIELD', field: 'translationError', value: null });

    try {
      // Auto-sanitize before parsing
      let textToParse = rawText;
      if (!configState.isSanitized || overrideText) {
        const sanitized = sanitizeConfig(rawText);
        textToParse = sanitized.sanitizedText;
        configDispatch({
          type: 'SET_SANITIZATION_RESULT',
          configText: textToParse,
          sanitizationTable: sanitized.replacements,
        });
      }

      const data = await parseConfig(textToParse);

      // Inject _review_status on every rule
      const policies = data.intermediateConfig.security_policies || [];
      policies.forEach(rule => {
        rule._review_status = 'unreviewed';
      });

      // Determine effective vendor
      const detectedVendor = data.detectedVendor || data.intermediateConfig?.metadata?.source_vendor || 'panos';
      const effectiveVendor = selectedVendorHint === 'srx_healthcheck' ? 'srx_healthcheck' : detectedVendor;
      if (selectedVendorHint === 'srx_healthcheck') {
        data.intermediateConfig.metadata.source_vendor = 'srx_healthcheck';
      }

      // If source is not PAN-OS, default to 'panos' platform view (shows the "from" tab)
      if (['srx', 'srx_healthcheck', 'fortigate', 'cisco_asa', 'checkpoint', 'sonicwall', 'huawei_usg'].includes(effectiveVendor)) {
        uiDispatch({ type: 'SET_FIELD', field: 'platformView', value: 'panos' });
      }

      // Set the parse result into ConfigContext
      configDispatch({
        type: 'SET_PARSE_RESULT',
        intermediateConfig: data.intermediateConfig,
        warnings: data.warnings || [],
        parseStats: data.parseStats || null,
        sourceVendor: effectiveVendor,
        preserveSanitization: true,
      });
      configDispatch({ type: 'SET_FIELD', field: 'warningStatuses', value: {} });
      configDispatch({ type: 'SET_FIELD', field: 'ruleGroups', value: [] });
      configDispatch({ type: 'SET_FIELD', field: 'sectionAcceptance', value: {} });

      // Auto-open model selector after successful parse
      uiDispatch({ type: 'SHOW_MODAL', name: 'modelSelector' });

      // Detect multi-vsys/VDOM/logical-system configs for auto-split prompt
      const rc = data.intermediateConfig.routing_contexts || [];
      const contextCount = rc.filter(c => !(c.type === 'default' && c.name === 'default')).length;
      if (!mergeState.mergeMode && contextCount > 1) {
        uiDispatch({
          type: 'SHOW_MODAL',
          name: 'autoSplitPrompt',
          value: {
            contexts: rc.filter(c => !(c.type === 'default' && c.name === 'default')),
            config: data.intermediateConfig,
            vendor: effectiveVendor,
          },
        });
      }
    } catch (err) {
      uiDispatch({ type: 'SET_FIELD', field: 'error', value: `Parse error: ${err.message}` });
      configDispatch({ type: 'SET_PARSE_RESULT', intermediateConfig: null, warnings: [], parseStats: null });
      configDispatch({ type: 'SET_FIELD', field: 'warningStatuses', value: {} });
    } finally {
      uiDispatch({ type: 'SET_LOADING', isLoading: false });
    }
  }, [configState.configText, configState.isSanitized, mergeState.mergeMode, undoDispatch, configDispatch, uiDispatch]);

  // -----------------------------------------------------------------------
  // Security policy CRUD
  // -----------------------------------------------------------------------

  const handleUpdateRule = useCallback((index, updatedRule) => {
    updateConfig(prev => {
      const policies = [...prev.security_policies];
      policies[index] = updatedRule;
      return { ...prev, security_policies: policies };
    });
  }, [updateConfig]);

  const handleDeleteRule = useCallback((index) => {
    updateConfig(prev => ({
      ...prev,
      security_policies: prev.security_policies.filter((_, i) => i !== index),
    }));
    uiDispatch({ type: 'SET_FIELD', field: 'selectedRule', value: null });
  }, [updateConfig, uiDispatch]);

  const handleAddRule = useCallback(() => {
    updateConfig(prev => {
      const newIndex = (prev.security_policies?.length || 0) + 1;
      const newRule = {
        name: `new-rule-${newIndex}`,
        _rule_index: newIndex,
        action: 'deny',
        src_zones: [],
        dst_zones: [],
        src_addresses: [],
        dst_addresses: [],
        negate_source: false,
        negate_destination: false,
        applications: [],
        services: [],
        log_start: false,
        log_end: true,
        disabled: false,
        description: '',
        tags: ['added_by_fpic'],
        profile_group: '',
        security_profiles: {},
        _review_status: 'unreviewed',
      };
      return {
        ...prev,
        security_policies: [...(prev.security_policies || []), newRule],
      };
    });
  }, [updateConfig]);

  // -----------------------------------------------------------------------
  // Field-level config update handlers
  // -----------------------------------------------------------------------

  // Field-to-section mapping for generic handleConfigUpdate
  const FIELD_TO_SECTION = {
    address_objects: 'obj:addresses', address_groups: 'obj:groups',
    service_objects: 'obj:services', service_groups: 'obj:services',
    applications: 'obj:applications', application_groups: 'obj:applications',
    security_profile_objects: 'obj:profiles', schedules: 'obj:schedules',
    flow_monitoring_config: 'flow-monitoring',
    static_routes: 'routing', interfaces: 'routing',
    bgp_config: 'routing', ospf_config: 'routing',
    ospf3_config: 'routing', evpn_config: 'routing', vxlan_config: 'routing',
    bridge_domains: 'routing', l2_interfaces: 'routing', vwire_pairs: 'routing',
  };

  const handleZonesUpdate = useCallback((zones) => {
    updateConfig(prev => ({ ...prev, zones }));
    configDispatch({ type: 'REVOKE_SECTION', sectionId: 'zones' });
  }, [updateConfig, configDispatch]);

  const handleNATUpdate = useCallback((natRules) => {
    updateConfig(prev => ({ ...prev, nat_rules: natRules }));
    configDispatch({ type: 'REVOKE_SECTION', sectionId: 'nat' });
  }, [updateConfig, configDispatch]);

  const handleVPNUpdate = useCallback((vpnTunnels) => {
    updateConfig(prev => ({ ...prev, vpn_tunnels: vpnTunnels }));
    configDispatch({ type: 'REVOKE_SECTION', sectionId: 'vpn' });
  }, [updateConfig, configDispatch]);

  const handleHAUpdate = useCallback((haConfig) => {
    updateConfig(prev => ({ ...prev, ha_config: haConfig }));
    configDispatch({ type: 'REVOKE_SECTION', sectionId: 'ha' });
  }, [updateConfig, configDispatch]);

  const handleScreenUpdate = useCallback((screenConfig) => {
    updateConfig(prev => ({ ...prev, screen_config: screenConfig }));
  }, [updateConfig]);

  const handleSyslogUpdate = useCallback((syslogConfig) => {
    updateConfig(prev => ({ ...prev, syslog_config: syslogConfig }));
    configDispatch({ type: 'REVOKE_SECTION', sectionId: 'syslog' });
  }, [updateConfig, configDispatch]);

  const handleSNMPUpdate = useCallback((snmpConfig) => {
    updateConfig(prev => ({ ...prev, snmp_config: snmpConfig }));
    configDispatch({ type: 'REVOKE_SECTION', sectionId: 'snmp' });
  }, [updateConfig, configDispatch]);

  const handleAAAUpdate = useCallback((aaaConfig) => {
    updateConfig(prev => ({ ...prev, aaa_config: aaaConfig }));
    configDispatch({ type: 'REVOKE_SECTION', sectionId: 'aaa' });
  }, [updateConfig, configDispatch]);

  const handleDHCPUpdate = useCallback((dhcpConfig) => {
    updateConfig(prev => ({ ...prev, dhcp_config: dhcpConfig }));
    configDispatch({ type: 'REVOKE_SECTION', sectionId: 'dhcp' });
  }, [updateConfig, configDispatch]);

  const handleQoSUpdate = useCallback((qosConfig) => {
    updateConfig(prev => ({ ...prev, qos_config: qosConfig }));
    configDispatch({ type: 'REVOKE_SECTION', sectionId: 'qos' });
  }, [updateConfig, configDispatch]);

  const handleConfigUpdate = useCallback((field, items) => {
    updateConfig(prev => ({ ...prev, [field]: items }));
    const sectionId = FIELD_TO_SECTION[field];
    if (sectionId) configDispatch({ type: 'REVOKE_SECTION', sectionId });
  }, [updateConfig, configDispatch]);

  // -----------------------------------------------------------------------
  // Analysis engine
  // -----------------------------------------------------------------------
  const handleRunAnalysis = useCallback(async () => {
    const activeConfig = mergeState.mergeMode
      ? mergeState.configSlots?.[mergeState.activeSlotIndex]?.intermediateConfig
      : configState.intermediateConfig;
    if (!activeConfig) return;

    uiDispatch({ type: 'SET_LOADING', isLoading: true, message: 'Running analysis...' });
    try {
      const { AnalysisEngine } = await import('../../src/analysis/config-analyzer.js');
      const findings = await AnalysisEngine.run(activeConfig, (label) => {
        uiDispatch({ type: 'SET_LOADING', isLoading: true, message: label });
      });
      updateConfig(prev => ({ ...prev, _analysisFindings: findings }));
      uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'analysis' });
    } catch (err) {
      uiDispatch({ type: 'SET_FIELD', field: 'error', value: `Analysis error: ${err.message}` });
    } finally {
      uiDispatch({ type: 'SET_LOADING', isLoading: false });
    }
  }, [configState.intermediateConfig, mergeState, updateConfig, uiDispatch]);

  // -----------------------------------------------------------------------
  // Return public API
  // -----------------------------------------------------------------------
  return {
    // Read-only state from ConfigContext
    ...configState,

    // Handlers
    handleParse,
    handleSanitize,
    handleConfigChange,
    updateConfig,
    handleUpdateRule,
    handleDeleteRule,
    handleAddRule,
    handleZonesUpdate,
    handleNATUpdate,
    handleVPNUpdate,
    handleHAUpdate,
    handleScreenUpdate,
    handleSyslogUpdate,
    handleSNMPUpdate,
    handleAAAUpdate,
    handleDHCPUpdate,
    handleQoSUpdate,
    handleConfigUpdate,
    handleRunAnalysis,
    makeRuleKey,
  };
}
