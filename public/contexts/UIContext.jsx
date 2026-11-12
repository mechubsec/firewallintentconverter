/**
 * UIContext — Visual / UI state only
 *
 * Owns modal visibility, loading indicators, panel dimensions,
 * tab selection, and other transient UI state.
 * No data dependencies — purely presentational concerns.
 */
import React, { createContext, useContext, useReducer } from 'react';
import { LLM_RISK_ACCEPTANCE_STORAGE_KEY, getLLMRiskAcceptance } from '../utils/llm-risk-acceptance.js';

/** Read localStorage without throwing when storage is blocked. */
function readStoredItem(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------
const initialState = {
  editTab: 'import',
  bottomTab: 'output',
  platformView: 'panos',
  selectedRule: null,
  isLoading: false,
  loadingMessage: '',
  error: null,
  policyStructure: 'global',
  deploymentMode: 'standalone',

  // Modals / dialogs
  showModelSelector: false,
  showInterfaceMapper: false,
  showSettings: false,
  showAppMappings: false,
  showFeedback: false,
  showConvertConfirm: false,
  showSaveModal: false,
  showResetConfirm: false,
  showReportModal: false,
  showLoadConfirm: null,
  showProjectSecurityImport: null,
  showLLMWarning: false,
  showAutoSplitPrompt: null,
  showPushToast: '',
  showPushModal: false,
  showTour: readStoredItem('tour-completed') !== 'true',

  llmWarningDismissed: false,

  // LLM translation progress
  isTranslating: false,
  translationError: null,
  translationProgress: null,

  // Grouping
  groupingInProgress: false,

  // Layout
  leftSidebarCollapsed: false,
  leftSidebarWidth: 260,
  rightPanelCollapsed: false,
  rightPanelWidth: 320,

  // Command palette
  commandPaletteOpen: false,

  // LLM risk disclaimer acceptance: null | 'all' | 'local-only' | 'deterministic' | 'rejected'
  // Goes through getLLMRiskAcceptance() (not a raw localStorage.getItem) so a
  // stale/invalid stored value — e.g. the literal string "null" written by
  // pre-1.2.3 builds — is treated as undecided and cleared, not as consent.
  llmRiskAcceptance: getLLMRiskAcceptance(),
};

// ---------------------------------------------------------------------------
// Modal name mapping — maps a short name to the state key
// ---------------------------------------------------------------------------
const MODAL_KEYS = {
  modelSelector: 'showModelSelector',
  interfaceMapper: 'showInterfaceMapper',
  settings: 'showSettings',
  appMappings: 'showAppMappings',
  feedback: 'showFeedback',
  convertConfirm: 'showConvertConfirm',
  saveModal: 'showSaveModal',
  resetConfirm: 'showResetConfirm',
  reportModal: 'showReportModal',
  loadConfirm: 'showLoadConfirm',
  projectSecurityImport: 'showProjectSecurityImport',
  llmWarning: 'showLLMWarning',
  autoSplitPrompt: 'showAutoSplitPrompt',
  pushModal: 'showPushModal',
  tour: 'showTour',
};

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------
function uiReducer(state, action) {
  switch (action.type) {
    // Generic single-field setter
    case 'SET_FIELD':
      return { ...state, [action.field]: action.value };

    // Combined loading setter
    case 'SET_LOADING':
      return {
        ...state,
        isLoading: action.isLoading,
        loadingMessage: action.message ?? '',
      };

    // Clear error
    case 'CLEAR_ERROR':
      return { ...state, error: null };

    // Show a named modal (value defaults to true, but can be an object for loadConfirm etc.)
    case 'SHOW_MODAL': {
      const key = MODAL_KEYS[action.name] || action.name;
      return { ...state, [key]: action.value !== undefined ? action.value : true };
    }

    // Hide a named modal
    case 'HIDE_MODAL': {
      const key = MODAL_KEYS[action.name] || action.name;
      // Reset to the "closed" value — null for object-typed modals, false for booleans
      const closed = typeof state[key] === 'boolean' ? false : null;
      return { ...state, [key]: closed };
    }

    // Toggle left sidebar collapsed state
    case 'TOGGLE_SIDEBAR':
      return { ...state, leftSidebarCollapsed: !state.leftSidebarCollapsed };

    // Toggle right inspector/panel collapsed state
    case 'TOGGLE_INSPECTOR':
      return { ...state, rightPanelCollapsed: !state.rightPanelCollapsed };

    // Set panel width by name
    case 'SET_PANEL_WIDTH': {
      if (action.panel === 'left') {
        return { ...state, leftSidebarWidth: action.width };
      }
      if (action.panel === 'right') {
        return { ...state, rightPanelWidth: action.width };
      }
      return state;
    }

    case 'SET_LLM_RISK_ACCEPTANCE':
      // `value` is null when the user is asked to choose again (e.g. "Change
      // mode"). storeItem(key, null) would coerce to the string "null", which
      // is truthy on the next read and silently skips the disclaimer — always
      // clear the key instead so consent is re-asked after a reload.
      if (action.value === null || action.value === undefined) {
        localStorage.removeItem(LLM_RISK_ACCEPTANCE_STORAGE_KEY);
      } else {
        localStorage.setItem(LLM_RISK_ACCEPTANCE_STORAGE_KEY, action.value);
      }
      return { ...state, llmRiskAcceptance: action.value };

    default:
      console.warn(`UIContext: unhandled action "${action.type}"`);
      return state;
  }
}

// ---------------------------------------------------------------------------
// Context + Provider
// ---------------------------------------------------------------------------
const UIContext = createContext(null);

function UIProvider({ children }) {
  const [state, dispatch] = useReducer(uiReducer, initialState);

  const value = React.useMemo(() => ({ state, dispatch }), [state]);

  return (
    <UIContext.Provider value={value}>
      {children}
    </UIContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------
function useUIContext() {
  const ctx = useContext(UIContext);
  if (!ctx) {
    throw new Error('useUIContext must be used within a <UIProvider>');
  }
  return ctx;
}

// Helper functions for conversion mode detection
function isLLMEnabled(acceptance) {
  return acceptance === 'all' || acceptance === 'local-only';
}

function isDeterministicMode(acceptance) {
  return acceptance === 'deterministic';
}

export { UIContext, UIProvider, useUIContext, isLLMEnabled, isDeterministicMode, uiReducer, initialState };
