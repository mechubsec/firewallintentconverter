import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useConfigContext } from '../../contexts/ConfigContext.jsx';
import { useConversionContext } from '../../contexts/ConversionContext.jsx';
import { useUIContext, isDeterministicMode } from '../../contexts/UIContext.jsx';
import { countOverrides } from '../../utils/app-mapping-overrides.js';
import BrandLockup from '../brand/BrandLockup.jsx';

/** Read the stored theme without throwing when storage is blocked. */
function readStoredTheme() {
  try {
    return localStorage.getItem('theme');
  } catch {
    return null;
  }
}

/**
 * Resolves the active theme ('dark' or 'light') based on localStorage and OS preference.
 * @returns {'dark'|'light'}
 */
function getEffectiveTheme() {
  const stored = readStoredTheme();
  if (stored === 'dark' || stored === 'light') return stored;
  // Auto: follow OS preference
  if (typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: light)').matches) {
    return 'light';
  }
  return 'dark';
}

/**
 * Custom hook for theme management (dark/light toggle).
 * Applies data-theme attribute to :root and persists in localStorage.
 */
function useTheme() {
  const [theme, setThemeState] = useState(getEffectiveTheme);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  // Listen for OS preference changes when in auto mode
  useEffect(() => {
    const mq = window.matchMedia?.('(prefers-color-scheme: light)');
    if (!mq) return;
    const handler = () => {
      const stored = readStoredTheme();
      if (!stored) setThemeState(mq.matches ? 'light' : 'dark');
    };
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);

  const toggleTheme = useCallback(() => {
    setThemeState(prev => {
      const next = prev === 'dark' ? 'light' : 'dark';
      try {
        localStorage.setItem('theme', next);
      } catch {
        // Storage blocked: the toggle still applies for this session
      }
      return next;
    });
  }, []);

  return { theme, toggleTheme };
}

/**
 * TopBar — Top navigation bar.
 *
 * Displays brand, stats badges (after parsing), and action buttons.
 * Reads from context instead of props — mirrors the current navbar in app.jsx.
 */

const VENDOR_NAMES = {
  panos: 'PAN-OS',
  srx: 'SRX',
  fortigate: 'FortiGate',
  cisco_asa: 'Cisco ASA',
  checkpoint: 'Check Point',
  sonicwall: 'SonicWall',
  huawei_usg: 'Huawei USG',
  aws_sg: 'AWS Security Groups',
  azure_nsg: 'Azure NSG',
  gcp_fw: 'GCP Firewall',
};

export default function TopBar() {
  const { state: cfg, dispatch: cfgDispatch } = useConfigContext();
  const { state: conv } = useConversionContext();
  const { state: ui, dispatch: uiDispatch } = useUIContext();

  const {
    sourceVendor, sourceModel, targetModel, srxLicense,
    siteName, intermediateConfig, greenfieldMode, warningStatuses,
    configText,
  } = cfg;
  const { convertWarnings } = conv;
  const { isLoading, isTranslating, editTab } = ui;

  // Compute stats
  const displayStats = !!(intermediateConfig || greenfieldMode);
  const policyCount = intermediateConfig?.security_policies?.length || 0;
  const accepted = policyCount > 0
    ? intermediateConfig.security_policies.filter(p => p._review_status === 'accepted').length
    : 0;
  const llmReviewed = policyCount > 0
    ? intermediateConfig.security_policies.filter(p => p._review_status === 'llm_reviewed').length
    : 0;

  // Warning counts
  const allWarnings = convertWarnings || [];
  const statusValues = Object.values(warningStatuses);
  const ackCount = statusValues.filter(s => s === 'acknowledged').length;
  const fixedCount = statusValues.filter(s => s === 'fixed' || s === 'resolved').length;
  const ignoredCount = statusValues.filter(s => s === 'ignored').length;
  const unresolvedWarningCount = allWarnings.length - ackCount - fixedCount - ignoredCount;

  const { theme, toggleTheme } = useTheme();

  // Helpers
  const showModal = (name) => uiDispatch({ type: 'SHOW_MODAL', name });
  const setTab = (tab) => uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: tab });

  // Overflow menu state
  const [overflowOpen, setOverflowOpen] = useState(false);
  const overflowRef = useRef(null);

  // Close overflow on click outside
  useEffect(() => {
    if (!overflowOpen) return;
    const handler = (e) => {
      if (overflowRef.current && !overflowRef.current.contains(e.target)) {
        setOverflowOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [overflowOpen]);

  return (
    <div className="app-topbar">
      {/* Left: Brand */}
      <BrandLockup theme={theme} />

      {/* Center: Consolidated stat badges */}
      {displayStats && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, justifyContent: 'center', flexWrap: 'wrap' }}>
          {/* Combined model + license + site badge */}
          {(sourceModel || greenfieldMode) && (
            <span
              className="stat-badge model-badge"
              onClick={() => showModal('modelSelector')}
              style={{ cursor: 'pointer' }}
            >
              {greenfieldMode ? 'Greenfield' : sourceModel}
              <span style={{ color: 'var(--accent)', margin: '0 4px' }}>&rarr;</span>
              <span style={{ color: 'var(--juniper-green)' }}>{targetModel || '?'}</span>
              {srxLicense && (
                <span style={{ color: 'var(--text-muted)', margin: '0 4px' }}>·</span>
              )}
              {srxLicense && (
                <span className="stat-value">{srxLicense}</span>
              )}
            </span>
          )}

          {/* Simplified warning badge */}
          {allWarnings.length > 0 && (
            <span
              className="stat-badge"
              style={{ cursor: 'pointer' }}
              onClick={() => setTab('warnings')}
            >
              <span style={{ color: unresolvedWarningCount > 0 ? 'var(--caution)' : 'var(--success)' }}>⚠</span>
              {' '}
              <span style={{ color: unresolvedWarningCount > 0 ? 'var(--caution)' : 'var(--text-muted)', fontWeight: 600 }}>
                {unresolvedWarningCount}
              </span>
              <span style={{ color: 'var(--text-secondary)', marginLeft: 4 }}>warnings</span>
            </span>
          )}

          {/* Simplified policy progress */}
          {intermediateConfig && policyCount > 0 && (
            <span
              className="stat-badge"
              onClick={() => setTab('rules')}
              style={{ cursor: 'pointer' }}
            >
              <span style={{ color: 'var(--success)', fontWeight: 600 }}>{accepted}</span>
              <span style={{ color: 'var(--text-muted)' }}>/</span>
              <span style={{ color: 'var(--caution)', fontWeight: 600 }}>{policyCount}</span>
              <span style={{ color: 'var(--text-secondary)', marginLeft: 4 }}>accepted</span>
            </span>
          )}
        </div>
      )}

      {/* Spacer when no stats */}
      {!displayStats && <div style={{ flex: 1 }} />}

      {/* Right: Save, Load, Overflow */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '0 12px', flexShrink: 0 }}>
        {/* Reset workspace — app-driven destructive action: caution (orange), never violet */}
        <button
          className="settings-btn reset-btn"
          onClick={() => uiDispatch({ type: 'SHOW_MODAL', name: 'resetConfirm' })}
          title="Reset workspace"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="23 4 23 10 17 10" />
            <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
          </svg>
        </button>
        <div style={{ width: 1, height: 20, background: 'var(--border-color)', margin: '0 4px' }} />
        {/* Save */}
        <button
          className="settings-btn"
          onClick={() => {
            if (!intermediateConfig && !configText) {
              uiDispatch({ type: 'SET_FIELD', field: 'error', value: 'Nothing to save. Parse a config or start a Greenfield interview first.' });
              return;
            }
            showModal('saveModal');
          }}
          title="Save project to file"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z" />
            <polyline points="17 21 17 13 7 13 7 21" />
            <polyline points="7 3 7 8 15 8" />
          </svg>
        </button>

        {/* Load */}
        <button
          className="settings-btn"
          onClick={() => {
            const input = document.getElementById('topbar-project-file-input');
            if (input) input.click();
          }}
          title="Load project from file"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z" />
            <line x1="12" y1="11" x2="12" y2="17" />
            <polyline points="9 14 12 11 15 14" />
          </svg>
        </button>

        {/* Overflow menu */}
        <div ref={overflowRef} style={{ position: 'relative' }}>
          <button
            className="settings-btn"
            onClick={() => setOverflowOpen(prev => !prev)}
            title="More actions"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="5" r="1.5" fill="currentColor" />
              <circle cx="12" cy="12" r="1.5" fill="currentColor" />
              <circle cx="12" cy="19" r="1.5" fill="currentColor" />
            </svg>
          </button>
          {overflowOpen && (
            <div className="overflow-menu">
              {intermediateConfig && (
                <button className="overflow-item" onClick={() => { showModal('modelSelector'); setOverflowOpen(false); }}>
                  Models
                </button>
              )}
              {intermediateConfig && targetModel && (
                <button className="overflow-item" onClick={() => { showModal('interfaceMapper'); setOverflowOpen(false); }}>
                  Interfaces
                </button>
              )}
              {intermediateConfig && targetModel && (
                <button className="overflow-item" onClick={() => { showModal('reportModal'); setOverflowOpen(false); }}>
                  Report
                </button>
              )}
              {(intermediateConfig && (targetModel || sourceModel)) && <div className="overflow-divider" />}
              <button className="overflow-item" onClick={() => { toggleTheme(); setOverflowOpen(false); }}>
                {theme === 'dark' ? '☀ Light theme' : '🌙 Dark theme'}
              </button>
              <button className="overflow-item" onClick={() => { showModal('tour'); setOverflowOpen(false); }}>
                Guided tour
              </button>
              <button className="overflow-item" onClick={() => { showModal('feedback'); setOverflowOpen(false); }}>
                Feedback
              </button>
              <button
                className="overflow-item"
                onClick={() => { showModal('appMappings'); setOverflowOpen(false); }}
                title="View and edit application name → Junos mappings"
              >
                Application Mappings
                {countOverrides() > 0 && (
                  <span
                    aria-label={`${countOverrides()} overrides active`}
                    style={{
                      display: 'inline-block',
                      marginLeft: 6,
                      width: 8,
                      height: 8,
                      borderRadius: '50%',
                      background: 'var(--caution, #f59e0b)',
                      verticalAlign: 'middle',
                    }}
                  />
                )}
              </button>
              <div className="overflow-divider" />
              {isDeterministicMode(ui.llmRiskAcceptance) ? (
                <button className="overflow-item" onClick={() => { uiDispatch({ type: 'SET_LLM_RISK_ACCEPTANCE', value: null }); setOverflowOpen(false); }}>
                  <span style={{ color: 'var(--success)', fontWeight: 600 }}>No AI</span> — Change mode
                </button>
              ) : (
                <button className="overflow-item" onClick={() => { showModal('settings'); setOverflowOpen(false); }}>
                  Settings
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
