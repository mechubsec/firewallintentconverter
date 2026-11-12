import React, { useMemo, useCallback } from 'react';
import { useConfigContext } from '../../contexts/ConfigContext.jsx';
import { useConversionContext } from '../../contexts/ConversionContext.jsx';
import { useUIContext } from '../../contexts/UIContext.jsx';
import { useMergeContext } from '../../contexts/MergeContext.jsx';
import useConfig from '../../hooks/useConfig.js';
import useLLM from '../../hooks/useLLM.js';
import InterviewPanel from '../InterviewPanel.jsx';

/**
 * RightPanel — Collapsible inspector panel (right side).
 *
 * When collapsed, renders a thin vertical tab so users can re-expand.
 * Renders InterviewPanel with rule details when on the policies tab.
 */
export default function RightPanel() {
  const { state: cfg } = useConfigContext();
  const { state: conv } = useConversionContext();
  const { state: ui, dispatch: uiDispatch } = useUIContext();
  const { state: merge } = useMergeContext();
  const config = useConfig();
  const llm = useLLM();

  const { rightPanelCollapsed, selectedRule, platformView, editTab, isTranslating, translationProgress } = ui;
  const { intermediateConfig, sourceVendor, srxTranslatedPolicies, srxLicense, targetModel } = cfg;
  const { parseWarnings } = cfg;
  const { convertWarnings } = conv;
  const { mergeMode, configSlots, activeSlotIndex } = merge;

  const toggle = () => uiDispatch({ type: 'TOGGLE_INSPECTOR' });

  const isHealthCheckMode = sourceVendor === 'srx_healthcheck';
  const activeConfig = mergeMode
    ? configSlots[activeSlotIndex]?.intermediateConfig
    : intermediateConfig;

  // Compute effective view mode (same logic as ContentRouter)
  const effectiveViewMode = platformView === 'srx' ? 'srx'
    : sourceVendor === 'srx' || isHealthCheckMode ? 'srx'
    : sourceVendor === 'fortigate' ? 'fortigate'
    : sourceVendor === 'cisco_asa' ? 'cisco'
    : sourceVendor === 'checkpoint' ? 'checkpoint'
    : sourceVendor === 'sonicwall' ? 'sonicwall'
    : sourceVendor === 'huawei_usg' ? 'huawei'
    : 'panos';

  const allWarnings = useMemo(
    () => [...(parseWarnings || []), ...(convertWarnings || [])],
    [parseWarnings, convertWarnings],
  );

  const analysisFindings = activeConfig?._analysisFindings || null;
  const analysisTotalCount = analysisFindings
    ? analysisFindings.reduce((s, f) => s + f.count, 0)
    : 0;

  const isTranslated = platformView === 'srx' && !!srxTranslatedPolicies;

  // Locate a rule by identity (rename-proof callers pass the pre-edit rule)
  const findRuleIndex = (rules, rule) => (rules || []).findIndex(
    r => r._rule_index === rule._rule_index && r.name === rule.name,
  );

  const handleUpdateRule = useCallback((updatedRule) => {
    // A rename changes updatedRule.name, so find the row by the pre-edit selection
    const original = selectedRule || updatedRule;
    if (isTranslated) {
      const idx = findRuleIndex(srxTranslatedPolicies, original);
      if (idx >= 0) llm.handleUpdateTranslatedRule(idx, updatedRule);
    } else {
      const idx = findRuleIndex(activeConfig?.security_policies, original);
      if (idx >= 0) config.handleUpdateRule(idx, updatedRule);
    }
    // Keep selectedRule in sync
    uiDispatch({ type: 'SET_FIELD', field: 'selectedRule', value: updatedRule });
  }, [isTranslated, selectedRule, srxTranslatedPolicies, activeConfig, llm, config, uiDispatch]);

  const handleAcceptRule = useCallback(() => {
    if (!selectedRule) return;
    if (isTranslated) {
      const idx = findRuleIndex(srxTranslatedPolicies, selectedRule);
      if (idx >= 0) llm.handleAcceptTranslatedRule(idx);
    } else {
      const idx = findRuleIndex(activeConfig?.security_policies, selectedRule);
      if (idx < 0) return;
      const accepted = { ...selectedRule, _review_status: 'accepted' };
      config.handleUpdateRule(idx, accepted);
      uiDispatch({ type: 'SET_FIELD', field: 'selectedRule', value: accepted });
    }
  }, [selectedRule, isTranslated, srxTranslatedPolicies, activeConfig, llm, config, uiDispatch]);

  if (rightPanelCollapsed) {
    return (
      <div
        className="inspector-collapsed-tab"
        onClick={toggle}
        title="Show inspector (Ctrl+Shift+B)"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="15 18 9 12 15 6" />
        </svg>
      </div>
    );
  }

  return (
    <div className="app-inspector">
      <div className="inspector-header">
        <span>Inspector</span>
        <button
          className="sidebar-toggle"
          onClick={toggle}
          title="Hide inspector (Ctrl+Shift+B)"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="9 18 15 12 9 6" />
          </svg>
        </button>
      </div>
      <div className="inspector-body">
        <InterviewPanel
          selectedRule={editTab === 'rules' ? selectedRule : null}
          intermediateConfig={activeConfig}
          warnings={allWarnings}
          onUpdateRule={handleUpdateRule}
          targetModel={targetModel}
          onAcceptRule={handleAcceptRule}
          viewMode={effectiveViewMode}
          platformView={platformView}
          srxLicense={srxLicense}
          isTranslating={isTranslating}
          translationProgress={translationProgress}
        />
        {analysisFindings && analysisTotalCount > 0 && editTab === 'rules' && (
          <div
            style={{
              padding: '10px 12px', margin: '8px 0', borderRadius: 6,
              background: 'var(--bg-secondary)', cursor: 'pointer',
              border: '1px solid var(--border-color)',
            }}
            onClick={() => uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'analysis' })}
            title="View full analysis"
          >
            <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>Analysis Findings</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {analysisFindings.filter(f => f.count > 0).map(f => {
                const isWarn = f.id === 'shadowed' || f.id === 'permissive';
                return (
                  <span key={f.id} style={{
                    fontSize: 11, padding: '2px 6px', borderRadius: 4,
                    background: isWarn ? 'color-mix(in srgb, var(--caution) 12%, transparent)' : 'var(--bg-tertiary)',
                    color: isWarn ? 'var(--caution)' : 'var(--text-secondary)',
                  }}>
                    {f.id.replace(/_/g, ' ')}: {f.count}
                  </span>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
