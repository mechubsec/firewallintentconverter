/**
 * App — Layout shell for the IDE-style 4-panel UI.
 *
 * All data state lives in contexts (Config, UI, Conversion, Merge, Undo).
 * All complex handlers live in custom hooks (useConfig, useConversion, useLLM, useProject, useUndoRedo).
 * This component:
 *   - Wires keyboard shortcuts
 *   - Contains handlers not yet extracted (greenfield, model/mapping, merge slot CRUD)
 *   - Renders the layout shell + modals
 */
import React, { Suspense, useCallback, useMemo, useRef, useEffect } from 'react';

// Layout components
import TopBar from './components/layout/TopBar.jsx';
import LeftSidebar from './components/layout/LeftSidebar.jsx';
import RightPanel from './components/layout/RightPanel.jsx';
import StatusBar from './components/layout/StatusBar.jsx';
import ResizeHandle from './components/layout/ResizeHandle.jsx';
import Breadcrumb from './components/layout/Breadcrumb.jsx';
import WorkflowStepper from './components/layout/WorkflowStepper.jsx';
import ContentRouter from './components/layout/ContentRouter.jsx';
import CommandPalette from './components/layout/CommandPalette.jsx';

// Modal components — lazy-loaded (only rendered when their modal state is active)
const ModelSelector = React.lazy(() => import('./components/ModelSelector.jsx'));
const InterfaceMapper = React.lazy(() => import('./components/InterfaceMapper.jsx'));
const LLMSettings = React.lazy(() => import('./components/LLMSettings.jsx'));
const AppMappingsEditor = React.lazy(() => import('./components/AppMappingsEditor.jsx'));
const FeedbackModal = React.lazy(() => import('./components/FeedbackModal.jsx'));
const SaveProjectModal = React.lazy(() => import('./components/SaveProjectModal.jsx'));
const loadProjectSecurityImport = () => import('./components/ProjectSecurityImportModal.jsx');
const ProjectSecurityImportModal = React.lazy(loadProjectSecurityImport);
const ProjectSecurityNotice = React.lazy(async () => {
  const module = await loadProjectSecurityImport();
  return { default: module.ProjectSecurityNotice };
});
const ReportModal = React.lazy(() => import('./components/ReportModal.jsx'));
const GuidedTour = React.lazy(() => import('./components/GuidedTour.jsx'));
const PushModal = React.lazy(() => import('./components/PushModal.jsx'));
// LLMRiskDisclaimer stays static — renders before app shell on first visit
import LLMRiskDisclaimer, { RejectedScreen } from './components/LLMRiskDisclaimer.jsx';

// Contexts
import { useConfigContext } from './contexts/ConfigContext.jsx';
import { useUIContext } from './contexts/UIContext.jsx';
import { useConversionContext } from './contexts/ConversionContext.jsx';
import { useMergeContext } from './contexts/MergeContext.jsx';

// Hooks
import useConfig from './hooks/useConfig.js';
import useConversion from './hooks/useConversion.js';
import useLLM from './hooks/useLLM.js';
import useProject from './hooks/useProject.js';
import useUndoRedo from './hooks/useUndoRedo.js';
import useKeyboardShortcuts from './hooks/useKeyboardShortcuts.js';

// Utils
import { GREENFIELD_TEMPLATES } from './data/greenfield-templates.js';
import { applyGreenfieldAction } from './utils/greenfield-actions.js';
import { parseConfig, sanitizeConfig } from './utils/engine.js';
import { isProjectCryptoAvailable } from './utils/project-crypto.js';
import { readProjectSecurityDescriptor } from './components/ProjectSecurityBadge.jsx';

export function deriveSanitizeFirstActions() {
  return [
    { type: 'HIDE_MODAL', name: 'saveModal' },
    { type: 'SET_FIELD', field: 'editTab', value: 'import' },
  ];
}

export default function App() {
  // --- Context access ---
  const { state: cfg, dispatch: cfgDispatch } = useConfigContext();
  const { state: ui, dispatch: uiDispatch } = useUIContext();
  const { state: conv, dispatch: convDispatch } = useConversionContext();
  const { state: merge, dispatch: mergeDispatch } = useMergeContext();

  // --- Custom hooks ---
  const config = useConfig();
  const conversion = useConversion();
  const llm = useLLM();
  const project = useProject();
  const undoRedo = useUndoRedo();
  const { registerHandler, unregisterHandler } = useKeyboardShortcuts();

  // Refs
  const projectFileInputRef = useRef(null);

  // --- Computed ---
  const isHealthCheckMode = cfg.sourceVendor === 'srx_healthcheck';
  const projectSecurityDescriptor = readProjectSecurityDescriptor(
    project.getExportDescriptor,
  );

  // ------------------------------------------------------------------
  // Keyboard shortcut registration
  // ------------------------------------------------------------------
  useEffect(() => {
    const handlers = {
      'command-palette': () => uiDispatch({ type: 'SET_FIELD', field: 'commandPaletteOpen', value: true }),
      'save-project': () => {
        if (!cfg.intermediateConfig && !cfg.configText) return;
        uiDispatch({ type: 'SHOW_MODAL', name: 'saveModal' });
      },
      'load-project': () => projectFileInputRef.current?.click(),
      'undo': () => undoRedo.undo(),
      'redo': () => undoRedo.redo(),
      'parse': () => config.handleParse(),
      'convert': () => conversion.handleConvertClick('set'),
      'translate-llm': () => llm.handleTranslateWithLLM(),
      'toggle-sidebar': () => uiDispatch({ type: 'TOGGLE_SIDEBAR' }),
      'toggle-inspector': () => uiDispatch({ type: 'TOGGLE_INSPECTOR' }),
      'close-modal': () => {
        // Close any open modal
        if (ui.commandPaletteOpen) {
          uiDispatch({ type: 'SET_FIELD', field: 'commandPaletteOpen', value: false });
        }
      },
      'nav-import': () => uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'import' }),
      'nav-policies': () => uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'rules' }),
      'nav-objects': () => uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'objects' }),
      'nav-output': () => uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'output' }),
    };
    Object.entries(handlers).forEach(([name, fn]) => registerHandler(name, fn));
    return () => Object.keys(handlers).forEach(name => unregisterHandler(name));
  }, [registerHandler, unregisterHandler, cfg.intermediateConfig, cfg.configText, ui.commandPaletteOpen, undoRedo, config, conversion, llm, uiDispatch]);

  // ------------------------------------------------------------------
  // Greenfield handlers (not yet in hooks)
  // ------------------------------------------------------------------
  const handleStartGreenfield = useCallback(() => {
    const emptyConfig = {
      metadata: {
        source_vendor: 'greenfield', source_version: '',
        zone_count: 0, rule_count: 0, nat_rule_count: 0,
        object_count: 0, vpn_tunnel_count: 0, static_route_count: 0,
      },
      system_config: {
        hostname: '', domain_name: '', dns_servers: [], ntp_servers: [],
        timezone: '', login_banner: '',
        management_services: { ssh: true, https: false, netconf: false },
      },
      zones: [], security_policies: [], nat_rules: [],
      address_objects: [], address_groups: [],
      service_objects: [], service_groups: [],
      applications: [], application_groups: [],
      vpn_tunnels: [], static_routes: [],
      bgp_config: [], ospf_config: [], ospf3_config: [],
      evpn_config: [], vxlan_config: [],
      interfaces: [], routing_contexts: [],
      ha_config: { enabled: false },
      screen_config: [], syslog_config: [], dhcp_config: [], qos_config: [],
    };
    cfgDispatch({ type: 'LOAD_PROJECT', state: {
      ...emptyConfig,
      intermediateConfig: emptyConfig,
      configText: '',
      sourceVendor: 'greenfield',
      greenfieldMode: true,
      greenfieldTemplate: null,
      parseWarnings: [],
      parseStats: emptyConfig.metadata,
      warningStatuses: {},
      srxTranslatedPolicies: null,
      ruleGroups: [],
      selectedRuleKeys: [],
      lastClickedKey: null,
      isSanitized: false,
      sanitizationTable: null,
      sourceModel: '', targetModel: '', srxLicense: '',
      portProfile: null, siteName: '', siteGroup: '',
      interfaceMappings: {},
    }});
    convDispatch({ type: 'SET_FIELD', field: 'srxOutput', value: null });
    convDispatch({ type: 'SET_FIELD', field: 'convertWarnings', value: [] });
    uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'rules' });
    uiDispatch({ type: 'SET_FIELD', field: 'platformView', value: 'panos' });
    uiDispatch({ type: 'SET_FIELD', field: 'selectedRule', value: null });
    uiDispatch({ type: 'SET_FIELD', field: 'llmWarningDismissed', value: true });
    uiDispatch({ type: 'SHOW_MODAL', name: 'modelSelector' });
  }, [cfgDispatch, convDispatch, uiDispatch]);

  const handleStartGreenfieldWithTemplate = useCallback((templateId) => {
    const template = GREENFIELD_TEMPLATES[templateId];
    if (!template || templateId === 'blank') { handleStartGreenfield(); return; }
    const tplConfig = structuredClone(template.config);
    cfgDispatch({ type: 'LOAD_PROJECT', state: {
      intermediateConfig: tplConfig,
      configText: '',
      sourceVendor: 'greenfield',
      greenfieldMode: true,
      greenfieldTemplate: templateId,
      parseWarnings: [],
      parseStats: tplConfig.metadata,
      warningStatuses: {},
      srxTranslatedPolicies: null,
      ruleGroups: [],
      selectedRuleKeys: [],
      lastClickedKey: null,
      isSanitized: false,
      sanitizationTable: null,
      sourceModel: '', targetModel: '', srxLicense: '',
      portProfile: null, siteName: '', siteGroup: '',
      interfaceMappings: {},
    }});
    convDispatch({ type: 'SET_FIELD', field: 'srxOutput', value: null });
    convDispatch({ type: 'SET_FIELD', field: 'convertWarnings', value: [] });
    uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'rules' });
    uiDispatch({ type: 'SET_FIELD', field: 'platformView', value: 'panos' });
    uiDispatch({ type: 'SET_FIELD', field: 'selectedRule', value: null });
    uiDispatch({ type: 'SET_FIELD', field: 'llmWarningDismissed', value: true });
    uiDispatch({ type: 'SHOW_MODAL', name: 'modelSelector' });
  }, [handleStartGreenfield, cfgDispatch, convDispatch, uiDispatch]);

  const handleGreenfieldAction = useCallback((action, data) => {
    cfgDispatch({ type: 'UPDATE_CONFIG', updater: prev => applyGreenfieldAction(prev, action, data) });
  }, [cfgDispatch]);

  // ------------------------------------------------------------------
  // Model / mapping handlers
  // ------------------------------------------------------------------
  const handleModelSelection = useCallback(({ sourceModel: src, targetModel: tgt, srxLicense: lic, portProfile: pp, siteName: sn, siteGroup: sg }) => {
    if (tgt !== cfg.targetModel || pp !== cfg.portProfile) {
      cfgDispatch({ type: 'SET_FIELD', field: 'interfaceMappings', value: {} });
    }
    cfgDispatch({ type: 'SET_FIELD', field: 'sourceModel', value: src || '' });
    cfgDispatch({ type: 'SET_FIELD', field: 'targetModel', value: tgt || '' });
    cfgDispatch({ type: 'SET_FIELD', field: 'srxLicense', value: lic || '' });
    cfgDispatch({ type: 'SET_FIELD', field: 'portProfile', value: pp || null });
    cfgDispatch({ type: 'SET_FIELD', field: 'siteName', value: sn || '' });
    cfgDispatch({ type: 'SET_FIELD', field: 'siteGroup', value: sg || '' });
  }, [cfg.targetModel, cfg.portProfile, cfgDispatch]);

  const handleModelContinue = useCallback(() => {
    uiDispatch({ type: 'HIDE_MODAL', name: 'modelSelector' });
    if (!cfg.greenfieldMode && !isHealthCheckMode) {
      uiDispatch({ type: 'SHOW_MODAL', name: 'interfaceMapper' });
    }
  }, [cfg.greenfieldMode, isHealthCheckMode, uiDispatch]);

  const handleMappingComplete = useCallback((mappings) => {
    cfgDispatch({ type: 'SET_FIELD', field: 'interfaceMappings', value: mappings });
    uiDispatch({ type: 'HIDE_MODAL', name: 'interfaceMapper' });
  }, [cfgDispatch, uiDispatch]);

  // ------------------------------------------------------------------
  // Merge mode slot CRUD
  // ------------------------------------------------------------------
  const handleModeSwitch = useCallback((enableMerge) => {
    if (enableMerge && !merge.mergeMode) {
      mergeDispatch({ type: 'SET_FIELD', field: 'configSlots', value: [
        { id: crypto.randomUUID(), lsName: 'LS-1', configText: '', intermediateConfig: null, sourceVendor: 'panos', sourceModel: '', interfaceMappings: {}, parseWarnings: [], parseStats: null, isSanitized: false, sanitizationTable: null, srxTranslatedPolicies: null, warningStatuses: {} },
        { id: crypto.randomUUID(), lsName: 'LS-2', configText: '', intermediateConfig: null, sourceVendor: 'panos', sourceModel: '', interfaceMappings: {}, parseWarnings: [], parseStats: null, isSanitized: false, sanitizationTable: null, srxTranslatedPolicies: null, warningStatuses: {} },
      ]});
      mergeDispatch({ type: 'SET_FIELD', field: 'activeSlotIndex', value: 0 });
      mergeDispatch({ type: 'SET_FIELD', field: 'crossLsLinks', value: [] });
    }
    mergeDispatch({ type: 'SET_FIELD', field: 'mergeMode', value: enableMerge });
  }, [merge.mergeMode, mergeDispatch]);

  const handleAddSlot = useCallback(() => {
    const newSlot = {
      id: crypto.randomUUID(),
      lsName: `LS-${merge.configSlots.length + 1}`,
      configText: '', intermediateConfig: null, sourceVendor: 'panos',
      sourceModel: '', interfaceMappings: {}, parseWarnings: [],
      parseStats: null, isSanitized: false, sanitizationTable: null,
      srxTranslatedPolicies: null, warningStatuses: {},
    };
    mergeDispatch({ type: 'ADD_SLOT', slot: newSlot });
  }, [merge.configSlots.length, mergeDispatch]);

  const handleRemoveSlot = useCallback((index) => {
    mergeDispatch({ type: 'REMOVE_SLOT', index });
  }, [mergeDispatch]);

  const handleUpdateSlotLsName = useCallback((index, name) => {
    mergeDispatch({ type: 'UPDATE_SLOT', index, slot: { lsName: name } });
  }, [mergeDispatch]);

  const handleParseSlot = useCallback(async (slotIndex) => {
    const slot = merge.configSlots[slotIndex];
    if (!slot || !slot.configText.trim()) return;
    uiDispatch({ type: 'SET_LOADING', isLoading: true, message: `Parsing config for ${slot.lsName}...` });
    uiDispatch({ type: 'CLEAR_ERROR' });
    try {
      const sanitized = sanitizeConfig(slot.configText);
      const data = await parseConfig(sanitized.sanitizedText);
      (data.intermediateConfig.security_policies || []).forEach(r => { r._review_status = 'unreviewed'; });
      const detectedVendor = data.detectedVendor || data.intermediateConfig?.metadata?.source_vendor || 'panos';
      mergeDispatch({ type: 'UPDATE_SLOT', index: slotIndex, preserveSanitization: true, slot: {
        configText: sanitized.sanitizedText,
        intermediateConfig: data.intermediateConfig,
        isSanitized: true,
        projectSecurityMode: 'sanitized',
        sanitizationTable: sanitized.replacements,
        sourceVendor: detectedVendor,
        parseWarnings: data.warnings || [],
        parseStats: data.parseStats || null,
      }});
      import('./utils/auto-split.js').then(({ detectCrossLsLinks }) => {
        const updatedSlots = merge.configSlots.map((s, i) => i === slotIndex ? { ...s, intermediateConfig: data.intermediateConfig } : s);
        mergeDispatch({ type: 'SET_FIELD', field: 'crossLsLinks', value: detectCrossLsLinks(updatedSlots.filter(s => s.intermediateConfig)) });
      });
    } catch (err) {
      uiDispatch({ type: 'SET_FIELD', field: 'error', value: `Parse error (${slot.lsName}): ${err.message}` });
    } finally {
      uiDispatch({ type: 'SET_LOADING', isLoading: false });
    }
  }, [merge.configSlots, mergeDispatch, uiDispatch]);

  const handleAutoSplitAccept = useCallback(() => {
    const prompt = ui.showAutoSplitPrompt;
    if (!prompt) return;
    import('./utils/auto-split.js').then(({ autoSplitRoutingContexts, detectCrossLsLinks }) => {
      const splits = autoSplitRoutingContexts(prompt.config);
      if (!splits || splits.length === 0) { uiDispatch({ type: 'HIDE_MODAL', name: 'autoSplitPrompt' }); return; }
      const slots = splits.map(s => ({
        id: crypto.randomUUID(), lsName: s.lsName, configText: cfg.configText,
        intermediateConfig: s.intermediateConfig, sourceVendor: prompt.vendor,
        sourceModel: '', interfaceMappings: {}, parseWarnings: [...(cfg.parseWarnings || []), ...(s.warnings || [])],
        parseStats: s.intermediateConfig.metadata, isSanitized: cfg.isSanitized,
        sanitizationTable: cfg.sanitizationTable, srxTranslatedPolicies: null, warningStatuses: {},
      }));
      mergeDispatch({ type: 'LOAD_PROJECT', state: { mergeMode: true, configSlots: slots, activeSlotIndex: 0, crossLsLinks: detectCrossLsLinks(splits) } });
      uiDispatch({ type: 'HIDE_MODAL', name: 'autoSplitPrompt' });
    });
  }, [ui.showAutoSplitPrompt, cfg.configText, cfg.parseWarnings, cfg.isSanitized, cfg.sanitizationTable, mergeDispatch, uiDispatch]);

  // ------------------------------------------------------------------
  // LLM warning modal handlers
  // ------------------------------------------------------------------
  const handleLLMWarningSanitize = useCallback(() => {
    uiDispatch({ type: 'HIDE_MODAL', name: 'llmWarning' });
    config.handleSanitize();
  }, [uiDispatch, config]);

  const handleLLMWarningProceed = useCallback(() => {
    uiDispatch({ type: 'SET_FIELD', field: 'llmWarningDismissed', value: true });
    uiDispatch({ type: 'HIDE_MODAL', name: 'llmWarning' });
  }, [uiDispatch]);

  // ------------------------------------------------------------------
  // Convert confirm handler
  // ------------------------------------------------------------------
  const handleConvertAnyway = useCallback(() => {
    uiDispatch({ type: 'HIDE_MODAL', name: 'convertConfirm' });
    conversion.handleConvert('set');
  }, [uiDispatch, conversion]);

  // ------------------------------------------------------------------
  // Resize handler for sidebar
  // ------------------------------------------------------------------
  const handleLeftResize = useCallback((delta) => {
    uiDispatch({ type: 'SET_PANEL_WIDTH', panel: 'left', width: Math.max(48, Math.min(400, ui.leftSidebarWidth + delta)) });
  }, [ui.leftSidebarWidth, uiDispatch]);

  const handleRightResize = useCallback((delta) => {
    uiDispatch({ type: 'SET_PANEL_WIDTH', panel: 'right', width: Math.max(200, Math.min(500, ui.rightPanelWidth - delta)) });
  }, [ui.rightPanelWidth, uiDispatch]);

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------

  // LLM risk disclaimer — block app until acknowledged
  if (ui.llmRiskAcceptance === 'rejected') {
    return <RejectedScreen onReconsider={() => uiDispatch({ type: 'SET_LLM_RISK_ACCEPTANCE', value: null })} />;
  }

  if (!ui.llmRiskAcceptance) {
    return (
      <LLMRiskDisclaimer
        onAcceptAll={() => uiDispatch({ type: 'SET_LLM_RISK_ACCEPTANCE', value: 'all' })}
        onAcceptLocalOnly={() => uiDispatch({ type: 'SET_LLM_RISK_ACCEPTANCE', value: 'local-only' })}
        onDeterministicMode={() => uiDispatch({ type: 'SET_LLM_RISK_ACCEPTANCE', value: 'deterministic' })}
        onReject={() => uiDispatch({ type: 'SET_LLM_RISK_ACCEPTANCE', value: 'rejected' })}
      />
    );
  }

  return (
    <div className="app-shell">
      <TopBar />

      {/* Error banner */}
      {ui.error && (
        <div style={{
          background: 'rgba(248, 113, 113, 0.1)',
          borderBottom: '1px solid rgba(248, 113, 113, 0.3)',
          padding: '8px 20px', fontSize: '13px', color: 'var(--error)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span>{ui.error}</span>
          <button onClick={() => uiDispatch({ type: 'CLEAR_ERROR' })}
            style={{ background: 'none', border: 'none', color: 'var(--error)', cursor: 'pointer', fontSize: '16px' }}>x</button>
        </div>
      )}

      {/* Loading bar */}
      {ui.isLoading && (
        <div className="progress-bar">
          <div className="progress-bar-fill" style={{ width: '60%', animation: 'indeterminate 1.5s infinite' }} />
        </div>
      )}

      {/* Main 3-column area */}
      <div className="app-main">
        <LeftSidebar />
        <ResizeHandle direction="vertical" onResize={handleLeftResize} onDoubleClick={() => uiDispatch({ type: 'TOGGLE_SIDEBAR' })} />
        <div className="app-workspace">
          <div className="app-center">
            <WorkflowStepper />
            <Breadcrumb />
            <Suspense fallback={<div className="center-content" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 1, color: 'var(--text-muted)' }}><span className="spinner" style={{ marginRight: 8 }} />Loading...</div>}>
              <ContentRouter
                onStartGreenfield={handleStartGreenfield}
                onStartGreenfieldWithTemplate={handleStartGreenfieldWithTemplate}
                onGreenfieldAction={handleGreenfieldAction}
                onModeSwitch={handleModeSwitch}
                onAddSlot={handleAddSlot}
                onRemoveSlot={handleRemoveSlot}
                onUpdateSlotLsName={handleUpdateSlotLsName}
                onParseSlot={handleParseSlot}
              />
            </Suspense>
          </div>
          <ResizeHandle direction="vertical" onResize={handleRightResize} onDoubleClick={() => uiDispatch({ type: 'TOGGLE_INSPECTOR' })} />
          <RightPanel />
        </div>
      </div>

      <StatusBar projectSecurityDescriptor={projectSecurityDescriptor} />

      {/* Command Palette */}
      {ui.commandPaletteOpen && <CommandPalette />}

      {/* Hidden file input for project load */}
      <input
        id="topbar-project-file-input"
        ref={projectFileInputRef}
        type="file"
        accept=".fpic.json,.json"
        style={{ display: 'none' }}
        onChange={project.handleLoadProjectFile}
      />

      {/* --- Modals (lazy-loaded) --- */}
      <Suspense fallback={null}>
      {ui.showFeedback && (
        <FeedbackModal onClose={() => uiDispatch({ type: 'HIDE_MODAL', name: 'feedback' })} />
      )}

      {ui.showSettings && (
        <LLMSettings
          initialTab={ui.showSettings === 'mcp' ? 'mcp' : 'llm'}
          onClose={() => uiDispatch({ type: 'HIDE_MODAL', name: 'settings' })}
        />
      )}

      {ui.showAppMappings && (
        <AppMappingsEditor
          onClose={() => uiDispatch({ type: 'HIDE_MODAL', name: 'appMappings' })}
        />
      )}

      {ui.showModelSelector && cfg.intermediateConfig && (
        <ModelSelector
          intermediateConfig={cfg.intermediateConfig}
          sourceModel={cfg.sourceModel}
          targetModel={cfg.targetModel}
          srxLicense={cfg.srxLicense}
          siteName={cfg.siteName}
          siteGroup={cfg.siteGroup}
          sourceVendor={cfg.sourceVendor}
          greenfieldMode={cfg.greenfieldMode}
          onModelSelection={handleModelSelection}
          onContinue={handleModelContinue}
          onClose={() => uiDispatch({ type: 'HIDE_MODAL', name: 'modelSelector' })}
        />
      )}

      {ui.showInterfaceMapper && cfg.intermediateConfig && (
        <InterfaceMapper
          intermediateConfig={cfg.intermediateConfig}
          sourceModel={cfg.sourceModel}
          targetModel={cfg.targetModel}
          portProfile={cfg.portProfile}
          interfaceMappings={cfg.interfaceMappings}
          onMappingComplete={handleMappingComplete}
          onClose={() => uiDispatch({ type: 'HIDE_MODAL', name: 'interfaceMapper' })}
        />
      )}

      {ui.showSaveModal && (
        <SaveProjectModal
          defaultName={project.generateName()}
          descriptor={project.getExportDescriptor()}
          cryptoAvailable={isProjectCryptoAvailable()}
          onExport={project.handleExportProject}
          onSanitizeFirst={() => {
            deriveSanitizeFirstActions().forEach(action => uiDispatch(action));
          }}
          onClose={() => uiDispatch({ type: 'HIDE_MODAL', name: 'saveModal' })}
        />
      )}

      {ui.showProjectSecurityImport && (
        <ProjectSecurityImportModal
          descriptor={ui.showProjectSecurityImport}
          onConfirm={project.confirmPendingImport}
          onClose={project.cancelPendingImport}
        />
      )}

      {ui.showReportModal && cfg.intermediateConfig && (
        <ReportModal
          data={{
            sourceVendor: cfg.sourceVendor, sourceModel: cfg.sourceModel,
            targetModel: cfg.targetModel, siteName: cfg.siteName, siteGroup: cfg.siteGroup,
            intermediateConfig: cfg.intermediateConfig, interfaceMappings: cfg.interfaceMappings,
            conversionSummary: conv.conversionSummary,
            parseWarnings: cfg.parseWarnings, convertWarnings: conv.convertWarnings,
            isSanitized: cfg.isSanitized, ruleGroups: cfg.ruleGroups,
          }}
          onClose={() => uiDispatch({ type: 'HIDE_MODAL', name: 'reportModal' })}
        />
      )}

      {/* Convert confirmation */}
      {ui.showConvertConfirm && (
        <div className="modal-overlay" onClick={() => uiDispatch({ type: 'HIDE_MODAL', name: 'convertConfirm' })}>
          <div className="modal-content" onClick={e => e.stopPropagation()} style={{ width: 440 }}>
            <div className="modal-header" style={{ borderBottomColor: 'rgba(234, 179, 8, 0.3)' }}>
              <h2 style={{ color: 'var(--warning)' }}>Unaccepted Policies</h2>
              <button className="modal-close" onClick={() => uiDispatch({ type: 'HIDE_MODAL', name: 'convertConfirm' })}>x</button>
            </div>
            <div className="modal-body">
              <p style={{ marginBottom: 8 }}>Some policies have not been accepted yet.</p>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Converting without reviewing all policies may produce output that hasn't been fully validated.</p>
            </div>
            <div className="modal-footer" style={{ gap: 8 }}>
              <button className="btn btn-secondary" onClick={() => uiDispatch({ type: 'HIDE_MODAL', name: 'convertConfirm' })}>Go Back</button>
              <button className="btn btn-primary" onClick={handleConvertAnyway}>Convert Anyway</button>
            </div>
          </div>
        </div>
      )}

      {/* Push coming-soon toast */}
      {ui.showPushToast && (
        <div className="modal-overlay" onClick={() => uiDispatch({ type: 'SET_FIELD', field: 'showPushToast', value: '' })}>
          <div className="modal-content" onClick={e => e.stopPropagation()} style={{ width: 400 }}>
            <div className="modal-header">
              <h2>Push to {ui.showPushToast}</h2>
              <button className="modal-close" onClick={() => uiDispatch({ type: 'SET_FIELD', field: 'showPushToast', value: '' })}>x</button>
            </div>
            <div className="modal-body" style={{ textAlign: 'center', padding: '24px 16px' }}>
              <p style={{ fontWeight: 600, marginBottom: 8 }}>Feature Coming Soon</p>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                {ui.showPushToast === 'SDC'
                  ? 'Push to Security Director Cloud via SDC API — coming in a future release.'
                  : 'Push to Juniper Mist Cloud via Mist API — coming in a future release.'}
              </p>
            </div>
            <div className="modal-footer">
              <button className="btn btn-primary" onClick={() => uiDispatch({ type: 'SET_FIELD', field: 'showPushToast', value: '' })}>OK</button>
            </div>
          </div>
        </div>
      )}

      {/* Push to SRX modal */}
      {ui.showPushModal && (
        <PushModal onClose={() => uiDispatch({ type: 'HIDE_MODAL', name: 'pushModal' })} />
      )}

      {/* Auto-split prompt */}
      {ui.showAutoSplitPrompt && (
        <div className="modal-overlay" onClick={() => uiDispatch({ type: 'HIDE_MODAL', name: 'autoSplitPrompt' })}>
          <div className="modal-content" onClick={e => e.stopPropagation()} style={{ width: 480 }}>
            <div className="modal-header">
              <h2>Multiple Contexts Detected</h2>
              <button className="modal-close" onClick={() => uiDispatch({ type: 'HIDE_MODAL', name: 'autoSplitPrompt' })}>x</button>
            </div>
            <div className="modal-body" style={{ padding: 16 }}>
              <p style={{ marginBottom: 12 }}>This configuration contains <strong>{ui.showAutoSplitPrompt.contexts.length}</strong> routing contexts ({ui.showAutoSplitPrompt.contexts.map(c => c.name).join(', ')}).</p>
              <p style={{ marginBottom: 12 }}>Would you like to split them into separate <strong>SRX logical-systems</strong>?</p>
              <div style={{ background: 'var(--bg-secondary)', padding: 10, borderRadius: 6, fontSize: 12 }}>
                {ui.showAutoSplitPrompt.contexts.map((ctx, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '3px 0' }}>
                    <span className="stat-badge">{ctx.type}</span>
                    <strong>{ctx.name}</strong>
                    <span style={{ color: 'var(--text-muted)' }}>{ctx.zones?.length || 0} zones</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="modal-actions" style={{ padding: '12px 16px', display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="btn btn-secondary btn-sm" onClick={() => uiDispatch({ type: 'HIDE_MODAL', name: 'autoSplitPrompt' })}>Keep as Single Config</button>
              <button className="btn btn-primary btn-sm" onClick={handleAutoSplitAccept}>Split into Logical-Systems</button>
            </div>
          </div>
        </div>
      )}

      {/* Load project confirmation */}
      {ui.showLoadConfirm && (
        <div className="modal-overlay" onClick={project.cancelValidatedImportReview}>
          <div className="modal-content" onClick={e => e.stopPropagation()} style={{ width: 480 }}>
            <div className="modal-header">
              <h2>Load Project</h2>
              <button className="modal-close" onClick={project.cancelValidatedImportReview}>&times;</button>
            </div>
            <div className="modal-body" style={{ padding: '16px 20px' }}>
              <p style={{ fontWeight: 600, marginBottom: 8 }}>{ui.showLoadConfirm.project.name || 'Unnamed Project'}</p>
              <ProjectSecurityNotice descriptor={ui.showLoadConfirm.security} />
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 12 }}>
                <div>Saved: {new Date(ui.showLoadConfirm.project.savedAt).toLocaleString()}</div>
                <div>Vendor: {ui.showLoadConfirm.project.state?.sourceVendor || 'Unknown'}</div>
                <div>Source Model: {ui.showLoadConfirm.project.state?.sourceModel || 'Not set'}</div>
                <div>Target Model: {ui.showLoadConfirm.project.state?.targetModel || 'Not set'}</div>
                {ui.showLoadConfirm.project.state?.intermediateConfig?.security_policies && (
                  <div>Policies: {ui.showLoadConfirm.project.state.intermediateConfig.security_policies.length}</div>
                )}
              </div>
              {(cfg.intermediateConfig || cfg.configText) && (
                <p style={{ color: 'var(--warning)', fontSize: 12, marginBottom: 8 }}>Loading this project will replace your current work. This cannot be undone.</p>
              )}
              {ui.showLoadConfirm.warnings?.length > 0 && (
                <div>{ui.showLoadConfirm.warnings.map((w, i) => <p key={i} style={{ color: 'var(--warning)', fontSize: 12 }}>{w}</p>)}</div>
              )}
            </div>
            <div className="modal-footer" style={{ gap: 8 }}>
              <button className="btn btn-secondary" onClick={project.cancelValidatedImportReview}>Cancel</button>
              <button
                className="btn btn-primary"
                onClick={() => project.applyLoadedProject(
                  ui.showLoadConfirm.project,
                  ui.showLoadConfirm.security,
                )}
              >
                Load Project
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reset workspace confirmation */}
      {ui.showResetConfirm && (
        <div className="modal-overlay" onClick={() => uiDispatch({ type: 'HIDE_MODAL', name: 'resetConfirm' })}>
          <div className="modal-content" onClick={e => e.stopPropagation()} style={{ width: 480 }}>
            <div className="modal-header">
              <h2>Reset Workspace</h2>
              <button className="modal-close" onClick={() => uiDispatch({ type: 'HIDE_MODAL', name: 'resetConfirm' })}>&times;</button>
            </div>
            <div className="modal-body" style={{ padding: '16px 20px' }}>
              <p style={{ color: 'var(--warning)', fontWeight: 600, marginBottom: 8 }}>
                This will clear the current config, conversion output, warnings, and undo history. This cannot be undone.
              </p>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>
                Your settings, LLM configuration, application mappings, theme, and layout are kept.
              </p>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                Save your work first if you want to keep it.
              </p>
            </div>
            <div className="modal-footer" style={{ gap: 8 }}>
              <button
                className="btn btn-secondary"
                onClick={() => uiDispatch({ type: 'HIDE_MODAL', name: 'resetConfirm' })}
              >
                Cancel
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => {
                  uiDispatch({ type: 'HIDE_MODAL', name: 'resetConfirm' });
                  uiDispatch({ type: 'SHOW_MODAL', name: 'saveModal' });
                }}
              >
                Save now
              </button>
              <button
                className="btn btn-primary"
                onClick={() => project.resetWorkspace()}
              >
                Continue without saving
              </button>
            </div>
          </div>
        </div>
      )}

      {/* LLM warning */}
      {ui.showLLMWarning && (
        <div className="modal-overlay" onClick={() => uiDispatch({ type: 'HIDE_MODAL', name: 'llmWarning' })}>
          <div className="modal-content" onClick={e => e.stopPropagation()} style={{ width: 480 }}>
            <div className="modal-header" style={{ borderBottomColor: 'rgba(248, 113, 113, 0.3)' }}>
              <h2 style={{ color: 'var(--warning)' }}>Security Warning</h2>
              <button className="modal-close" onClick={() => uiDispatch({ type: 'HIDE_MODAL', name: 'llmWarning' })}>x</button>
            </div>
            <div className="modal-body">
              <div className="llm-warning-content">
                <p style={{ fontWeight: 600, marginBottom: 8 }}>Your configuration has not been sanitized.</p>
                <p>Sending firewall configurations to LLM providers may expose sensitive information including:</p>
                <ul>
                  <li>Public and private IP addresses</li>
                  <li>Usernames, password hashes, and API keys</li>
                  <li>Network topology and security architecture</li>
                  <li>VPN pre-shared keys and certificates</li>
                </ul>
                <p style={{ marginTop: 8 }}>Use the <strong>Sanitize Configuration</strong> button to replace sensitive data with placeholders before using AI suggestions.</p>
              </div>
            </div>
            <div className="modal-footer" style={{ gap: 8 }}>
              <button className="btn btn-secondary" onClick={handleLLMWarningSanitize}>Sanitize First</button>
              <button className="btn btn-primary" onClick={handleLLMWarningProceed} style={{ background: 'var(--warning)', borderColor: 'var(--warning)' }}>Proceed Without Sanitizing</button>
            </div>
          </div>
        </div>
      )}

      {/* Guided Tour */}
      {ui.showTour && <GuidedTour onClose={() => uiDispatch({ type: 'HIDE_MODAL', name: 'tour' })} />}
      </Suspense>
    </div>
  );
}
