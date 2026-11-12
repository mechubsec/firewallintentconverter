/**
 * PolicyTable Component
 *
 * Sortable, filterable, editable security rules table.
 * Supports inline cell editing (double-click), add/delete rows.
 * Shows review status labels (Disabled/Unreviewed/LLM Reviewed/Accepted).
 *
 * viewMode: 'panos' shows PAN-OS terminology, 'srx' shows SRX terminology.
 *
 * Uses useVirtualScroll for windowed rendering — only ~60-80 rows in the DOM
 * at any time, regardless of total rule count.
 */
import React, { useState, useMemo, useRef, useEffect, useCallback } from 'react';
import { mapActionToSrx, buildApplicationServices } from '../utils/srx-view-transforms.js';
import { computeTriageBucket, computeTriageCounts, TRIAGE_CONFIG } from '../utils/triage.js';
import useVirtualScroll from '../hooks/useVirtualScroll.js';
import AutocompleteInput from './shared/AutocompleteInput.jsx';

/** Security subscription abbreviations, full names, and colors */
const SUBSCRIPTION_DEFS = [
  { key: 'ips',     abbr: 'IP', label: 'IPS',              color: '#f87171' },
  { key: 'cs',      abbr: 'CS', label: 'Content Security', color: '#60a5fa' },
  { key: 'dec',     abbr: 'DE', label: 'Decrypt',          color: '#60A5FA' },
  { key: 'av',      abbr: 'AV', label: 'Flow-based AV',    color: '#34d399' },
  { key: 'am',      abbr: 'AM', label: 'Anti-malware',     color: '#fb923c' },
  { key: 'si',      abbr: 'SI', label: 'SecIntel',         color: '#fbbf24' },
  { key: 'swp',     abbr: 'SW', label: 'Secure Web Proxy', color: '#2dd4bf' },
  { key: 'icap',    abbr: 'IC', label: 'ICAP Redirect',    color: '#4DD0C8' },
];

/** Get active subscription keys for a policy */
function getActiveSubscriptions(policy) {
  const sp = policy.security_profiles || {};
  const active = [];
  if (policy._srx_idp || sp.vulnerability) active.push('ips');
  if (policy._srx_content_security || sp['file-blocking'] || sp['url-filtering']) active.push('cs');
  if (policy._srx_decrypt) active.push('dec');
  if (policy._srx_flow_av || sp.virus) active.push('av');
  if (policy._srx_antimalware || sp.spyware) active.push('am');
  const hasSecIntel = policy._srx_secintel !== undefined
    ? !!policy._srx_secintel
    : (policy._secIntelAddresses?.length > 0);
  if (hasSecIntel) active.push('si');
  if (policy._srx_secure_web_proxy) active.push('swp');
  if (policy._srx_icap_redirect) active.push('icap');
  return active;
}

/**
 * Returns a color for the hit count cell based on value and disabled state.
 * @param {number|undefined} hitCount
 * @param {boolean} disabled
 * @returns {string} CSS color variable
 */
function getHitCountColor(hitCount, disabled) {
  if (typeof hitCount !== 'number') return 'var(--text-muted)';
  if (disabled) return 'var(--text-muted)';
  if (hitCount === 0) return 'var(--error)';
  if (hitCount < 100) return 'var(--caution)';
  return 'var(--juniper-green)';
}

export default function PolicyTable({
  policies,
  warnings,
  intermediateConfig,
  selectedRule,
  onSelectRule,
  onUpdateRule,
  onDeleteRule,
  onAddRule,
  viewMode,
  platformView,
  selectedRuleKeys = new Set(),
  onToggleRuleSelect,
  onSelectAllRules,
  ruleGroups = [],
  onUpdateGroups,
  onGroupWithAI,
  groupingInProgress = false,
  llmColor,
  suggestionsData,
}) {
  const [sortField, setSortField] = useState('_rule_index');
  const [sortDir, setSortDir] = useState('asc');
  const [filter, setFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [triageFilter, setTriageFilter] = useState('all');
  const [editingCell, setEditingCell] = useState(null); // { index, field }
  const [editValue, setEditValue] = useState('');
  const [expandedRows, setExpandedRows] = useState(new Set());
  const [collapsedGroups, setCollapsedGroups] = useState(new Set());
  const [editingGroupName, setEditingGroupName] = useState(null);
  const [newGroupNameValue, setNewGroupNameValue] = useState('');

  const isSrx = viewMode === 'srx';
  const isFortigate = viewMode === 'fortigate';
  const isCisco = viewMode === 'cisco';
  const isCheckpoint = viewMode === 'checkpoint';
  const isSonicwall = viewMode === 'sonicwall';
  const isHuawei = viewMode === 'huawei';

  // Check if any policy uses identity-based matching (conditional Users column)
  const hasIdentityPolicies = useMemo(() => {
    return (policies || []).some(p => p.source_users && p.source_users.length > 0);
  }, [policies]);

  // Check if any policy has been annotated with live hit count data
  const hasHitCounts = useMemo(() => policies.some(p => typeof p._hit_count === 'number'), [policies]);

  // Build a lookup of warning counts per rule
  const warningsByRule = useMemo(() => {
    const map = {};
    for (const w of (warnings || [])) {
      const match = w.element?.match(/security-rule\/(.+)/);
      if (match) {
        const ruleName = match[1];
        if (!map[ruleName]) map[ruleName] = [];
        map[ruleName].push(w);
      }
    }
    return map;
  }, [warnings]);

  /** Get the review status for display */
  const getRuleStatus = (rule) => {
    if (rule.disabled) return 'disabled';
    if (rule._review_status === 'accepted') return 'accepted';
    if (rule._review_status === 'llm_reviewed') return 'llm_reviewed';
    return 'unreviewed';
  };

  /** Get the warning-based sub-status */
  const getWarningStatus = (rule) => {
    const ruleWarnings = warningsByRule[rule.name] || [];
    if (ruleWarnings.some(w => w.severity === 'unsupported')) return 'unsupported';
    if (ruleWarnings.some(w => w.severity === 'interview_required')) return 'interview';
    if (ruleWarnings.some(w => w.severity === 'warning')) return 'warning';
    return 'clean';
  };

  const statusLabels = {
    disabled: 'Disabled',
    unreviewed: 'Unreviewed',
    llm_reviewed: 'LLM Reviewed',
    accepted: 'Accepted',
  };

  const warningTooltips = {
    warning: 'Conversion warning — feature partially supported',
    unsupported: 'Unsupported — feature not available on target platform',
    interview: 'Needs review — manual input required to resolve',
  };

  /** Triage counts for filter bar pills */
  const triageCounts = useMemo(
    () => computeTriageCounts(policies, intermediateConfig),
    [policies, intermediateConfig]
  );

  // --- Grouping helpers ---
  const hasGroups = ruleGroups && ruleGroups.length > 0;

  const toggleGroup = (groupName) => {
    setCollapsedGroups(prev => {
      const next = new Set(prev);
      if (next.has(groupName)) next.delete(groupName);
      else next.add(groupName);
      return next;
    });
  };

  const startGroupRename = (groupName) => {
    setEditingGroupName(groupName);
    setNewGroupNameValue(groupName);
  };

  const commitGroupRename = () => {
    if (!editingGroupName || !onUpdateGroups) return;
    const newName = newGroupNameValue.trim();
    if (!newName || newName === editingGroupName) {
      setEditingGroupName(null);
      return;
    }
    const updated = ruleGroups.map(g =>
      g.group_name === editingGroupName ? { ...g, group_name: newName } : g
    );
    onUpdateGroups(updated);
    setEditingGroupName(null);
    // Update collapsed set
    setCollapsedGroups(prev => {
      const next = new Set(prev);
      if (next.has(editingGroupName)) {
        next.delete(editingGroupName);
        next.add(newName);
      }
      return next;
    });
  };

  const dissolveGroup = (groupName) => {
    if (!onUpdateGroups) return;
    const target = ruleGroups.find(g => g.group_name === groupName);
    if (!target) return;
    // Move all rule indices to "Ungrouped" or remove group
    const ungrouped = ruleGroups.find(g => g.group_name === 'Ungrouped');
    let updated;
    if (ungrouped) {
      updated = ruleGroups.map(g => {
        if (g.group_name === 'Ungrouped') return { ...g, rule_indices: [...g.rule_indices, ...target.rule_indices] };
        return g;
      }).filter(g => g.group_name !== groupName);
    } else {
      updated = [
        ...ruleGroups.filter(g => g.group_name !== groupName),
        { group_name: 'Ungrouped', rule_indices: target.rule_indices, reasoning: '' },
      ];
    }
    onUpdateGroups(updated);
  };

  const clearAllGroups = () => {
    if (onUpdateGroups) onUpdateGroups([]);
    setCollapsedGroups(new Set());
  };

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('asc');
    }
  };

  const displayPolicies = useMemo(() => {
    let result = [...policies];

    // Text filter
    if (filter.trim()) {
      const f = filter.toLowerCase();
      result = result.filter(p =>
        p.name.toLowerCase().includes(f) ||
        p.src_zones.join(' ').toLowerCase().includes(f) ||
        p.dst_zones.join(' ').toLowerCase().includes(f) ||
        p.src_addresses.join(' ').toLowerCase().includes(f) ||
        p.dst_addresses.join(' ').toLowerCase().includes(f) ||
        p.applications.join(' ').toLowerCase().includes(f) ||
        p.action.toLowerCase().includes(f)
      );
    }

    // Status filter (legacy dropdown)
    if (statusFilter !== 'all') {
      result = result.filter(p => getRuleStatus(p) === statusFilter);
    }

    // Triage filter (new pill buttons — SRX view only)
    if (triageFilter !== 'all') {
      if (triageFilter === 'accepted') {
        result = result.filter(p => p._review_status === 'accepted');
      } else {
        result = result.filter(p =>
          p._review_status !== 'accepted' &&
          computeTriageBucket(p, intermediateConfig) === triageFilter
        );
      }
    }

    result.sort((a, b) => {
      // Numeric sort for hit counts — unannotated policies sort to the bottom
      if (sortField === '_hit_count') {
        const aVal = typeof a._hit_count === 'number' ? a._hit_count : -1;
        const bVal = typeof b._hit_count === 'number' ? b._hit_count : -1;
        if (aVal < bVal) return sortDir === 'asc' ? -1 : 1;
        if (aVal > bVal) return sortDir === 'asc' ? 1 : -1;
        return 0;
      }
      let aVal = a[sortField];
      let bVal = b[sortField];
      if (Array.isArray(aVal)) aVal = aVal.join(', ');
      if (Array.isArray(bVal)) bVal = bVal.join(', ');
      if (typeof aVal === 'string') aVal = aVal.toLowerCase();
      if (typeof bVal === 'string') bVal = bVal.toLowerCase();
      if (aVal < bVal) return sortDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [policies, filter, statusFilter, triageFilter, sortField, sortDir, intermediateConfig]);

  /** Build display groups: ordered list of { group_name, policies[], reasoning } */
  const displayGroups = useMemo(() => {
    if (!hasGroups) return [];
    // Build index→group map (rule_indices are 0-based)
    const idxToGroup = {};
    for (const g of ruleGroups) {
      for (const idx of g.rule_indices) {
        idxToGroup[idx] = g.group_name;
      }
    }
    // Tag each display policy with its group
    const tagged = displayPolicies.map(p => {
      // Try _rule_index (1-based) → 0-based, then array position fallback
      const zeroIdx = p._rule_index != null ? p._rule_index - 1 : policies.indexOf(p);
      return { ...p, _group: idxToGroup[zeroIdx] || 'Ungrouped' };
    });
    // Build ordered groups (preserving LLM order)
    const groups = [];
    const seen = new Set();
    for (const g of ruleGroups) {
      const gPols = tagged.filter(p => p._group === g.group_name);
      if (gPols.length > 0) {
        groups.push({ group_name: g.group_name, policies: gPols, reasoning: g.reasoning });
        seen.add(g.group_name);
      }
    }
    // Any unassigned
    const ungrouped = tagged.filter(p => p._group === 'Ungrouped');
    if (ungrouped.length > 0 && !seen.has('Ungrouped')) {
      groups.push({ group_name: 'Ungrouped', policies: ungrouped, reasoning: '' });
    }
    return groups;
  }, [hasGroups, ruleGroups, displayPolicies, policies]);

  // --- Bulk selection helpers ---
  const makeKey = (p) => `${p.name}::${p._rule_index}`;
  const allSelected = displayPolicies.length > 0 && displayPolicies.every(p => selectedRuleKeys.has(makeKey(p)));
  const someSelected = displayPolicies.some(p => selectedRuleKeys.has(makeKey(p)));

  const renderHeaderCheckbox = () => (
    <th style={{ width: 36, textAlign: 'center' }}>
      <input
        type="checkbox"
        className="bulk-checkbox"
        checked={allSelected}
        ref={el => { if (el) el.indeterminate = someSelected && !allSelected; }}
        onChange={() => onSelectAllRules && onSelectAllRules(!allSelected, displayPolicies)}
        onClick={(e) => e.stopPropagation()}
      />
    </th>
  );

  const renderRowCheckbox = (policy, e) => (
    <td style={{ textAlign: 'center' }} onClick={(ev) => ev.stopPropagation()}>
      <input
        type="checkbox"
        className="bulk-checkbox"
        checked={selectedRuleKeys.has(makeKey(policy))}
        onChange={(ev) => {
          ev.stopPropagation();
          onToggleRuleSelect && onToggleRuleSelect(policy, ev.nativeEvent, displayPolicies);
        }}
        onClick={(ev) => ev.stopPropagation()}
      />
    </td>
  );

  const handleRowClick = (policy, isSelected, e) => {
    if (e.ctrlKey || e.metaKey || e.shiftKey) {
      onToggleRuleSelect && onToggleRuleSelect(policy, e, displayPolicies);
    } else {
      onSelectRule(isSelected ? null : policy);
    }
  };

  /** Start editing a cell */
  const startEdit = (realIndex, field, currentValue) => {
    setEditingCell({ index: realIndex, field });
    setEditValue(Array.isArray(currentValue) ? currentValue.join(', ') : String(currentValue || ''));
  };

  const arrayFields = ['src_zones', 'dst_zones', 'src_addresses', 'dst_addresses', 'applications', 'services', 'source_users'];

  /** Commit edit */
  const commitEdit = () => {
    if (!editingCell) return;
    const { index, field } = editingCell;
    const rule = policies[index];
    let value = editValue;

    if (arrayFields.includes(field)) {
      value = editValue.split(',').map(s => s.trim()).filter(Boolean);
    }

    onUpdateRule(index, { ...rule, [field]: value });
    setEditingCell(null);
    setEditValue('');
  };

  const cancelEdit = () => {
    setEditingCell(null);
    setEditValue('');
  };

  const handleEditKeyDown = (e) => {
    if (e.key === 'Enter') commitEdit();
    if (e.key === 'Escape') cancelEdit();
  };

  /** Find real index in policies array for a display policy */
  const getRealIndex = (policy) => {
    return policies.findIndex(p => p === policy || (p.name === policy.name && p._rule_index === policy._rule_index));
  };

  const renderCellValues = (values) => {
    if (!values || values.length === 0) return <span className="cell-chip">any</span>;
    return values.map((v, i) => (
      <span key={i} className="cell-chip">{v}</span>
    ));
  };

  /** Render security profiles / application services for a policy row */
  const renderProfileCell = (policy) => {
    // PAN-OS view: show profile type abbreviations
    const sp = policy.security_profiles || {};
    const profileEntries = Object.entries(sp);
    const hasGroup = !!policy.profile_group;
    const hasProfiles = profileEntries.length > 0;

    if (!hasGroup && !hasProfiles) {
      return <span className="cell-chip" style={{ opacity: 0.4 }}>none</span>;
    }

    const chips = [];

    if (hasProfiles) {
      const shortLabels = {
        'virus': 'AV', 'wildfire-analysis': 'WF', 'url-filtering': 'URL',
        'file-blocking': 'FB', 'spyware': 'AS', 'vulnerability': 'VP',
        // FortiGate-originated
        'application-control': 'App', 'email-filter': 'EM', 'dlp': 'DLP',
        'dns-security': 'DNS', 'decryption': 'SSL', 'waf': 'WAF',
        'casb': 'CASB', 'voip': 'VoIP',
      };
      for (const [pType, pName] of profileEntries) {
        const label = shortLabels[pType] || pType;
        chips.push(
          <span key={pType} className="cell-chip profile-chip" title={`${pType}: ${pName}`}>
            {label}
          </span>
        );
      }
    }

    if (hasGroup && !hasProfiles) {
      chips.push(
        <span key="group" className="cell-chip profile-chip profile-group-chip" title={`Profile group: ${policy.profile_group}`}>
          {policy.profile_group}
        </span>
      );
    }

    return chips;
  };

  /** SRX view: render Security Subscriptions column (vertical label/value pairs) */
  const renderSrxSubscriptions = (policy) => {
    const sp = policy.security_profiles || {};
    const hasSecIntel = policy._srx_secintel !== undefined
      ? !!policy._srx_secintel
      : (policy._secIntelAddresses?.length > 0);
    const rows = [];

    // IPS (PAN-OS Vulnerability Protection → SRX IPS)
    if (policy._srx_idp || sp.vulnerability) {
      const value = policy._srx_idp_profile || sp.vulnerability || 'enabled';
      rows.push({ label: 'IPS', cls: 'ips', value });
    }

    // Content Security (PAN-OS File Blocking → SRX Content Filtering, URL Filtering → destination object)
    if (policy._srx_content_security || sp['file-blocking'] || sp['url-filtering']) {
      const value = policy._srx_content_security_profile || [sp['file-blocking'], sp['url-filtering']].filter(Boolean).join(', ') || 'enabled';
      rows.push({ label: 'Content Security', cls: 'urlfilter', value });
    }

    // Decrypt
    if (policy._srx_decrypt) {
      const value = policy._srx_decrypt_profile || 'SSL Proxy';
      rows.push({ label: 'Decrypt', cls: 'ips', value });
    }

    // Flow-based AV (PAN-OS Antivirus → SRX Flow-based AV)
    if (policy._srx_flow_av || sp.virus) {
      const value = policy._srx_flow_av_profile || sp.virus || 'enabled';
      rows.push({ label: 'Flow-based AV', cls: 'antimalware', value });
    }

    // Anti-malware (PAN-OS Anti-Spyware → SRX Anti-malware)
    if (policy._srx_antimalware || sp.spyware) {
      const value = policy._srx_antimalware_profile || sp.spyware || 'enabled';
      rows.push({ label: 'Anti-malware', cls: 'antimalware', value });
    }

    // SecIntel
    if (hasSecIntel) {
      const value = policy._srx_secintel_profile || 'Security Intelligence';
      rows.push({ label: 'SecIntel', cls: 'secintel', value });
    }

    // Secure Web Proxy
    if (policy._srx_secure_web_proxy) {
      const value = policy._srx_secure_web_proxy_profile || 'enabled';
      rows.push({ label: 'Secure Web Proxy', cls: 'secintel', value });
    }

    // ICAP Redirect
    if (policy._srx_icap_redirect) {
      const value = policy._srx_icap_redirect_profile || 'enabled';
      rows.push({ label: 'ICAP Redirect', cls: 'fileblock', value });
    }

    if (rows.length === 0) {
      return <span className="srx-sub-none">none</span>;
    }

    return (
      <div className="srx-subscriptions">
        {rows.map((r, i) => (
          <div key={i} className="srx-sub-row">
            <span className={`srx-sub-label ${r.cls}`}>{r.label}</span>
            <span className="srx-sub-value">{r.value}</span>
          </div>
        ))}
      </div>
    );
  };

  /** SRX view: render combined source/destination cell with type icons */
  const renderSrxSourceDest = (policy, type) => {
    const zones = type === 'src' ? policy.src_zones : policy.dst_zones;
    const addrs = type === 'src' ? policy.src_addresses : policy.dst_addresses;
    const isNegated = type === 'src' ? policy.negate_source : policy.negate_destination;
    const MAX_SHOW = 2;
    // Content Security (URL filtering) — show under destinations
    const urlFilter = type === 'dst' ? (policy.security_profiles || {})['url-filtering'] : null;

    return (
      <div className="srx-cell-stack">
        {/* Zones */}
        {(zones || []).length === 0 ? (
          <div className="srx-cell-row">
            <span className="srx-cell-icon zone">Z</span>
            <span className="srx-cell-value" style={{ opacity: 0.5 }}>any</span>
          </div>
        ) : (
          zones.map((z, i) => (
            <div key={`z-${i}`} className="srx-cell-row">
              <span className="srx-cell-icon zone">Z</span>
              <span className="srx-cell-value">{z}</span>
            </div>
          ))
        )}
        {/* Negate indicator */}
        {isNegated && (
          <div className="srx-cell-row">
            <span className="srx-cell-icon negate">!</span>
            <span className="srx-cell-value negate-label">EXCEPT</span>
          </div>
        )}
        {/* Addresses */}
        {(addrs || []).length === 0 ? (
          <div className="srx-cell-row">
            <span className="srx-cell-icon addr">A</span>
            <span className="srx-cell-value" style={{ opacity: 0.5 }}>Any</span>
          </div>
        ) : (
          <>
            {addrs.slice(0, MAX_SHOW).map((a, i) => (
              <div key={`a-${i}`} className="srx-cell-row">
                <span className="srx-cell-icon addr">A</span>
                <span className="srx-cell-value">{a}</span>
              </div>
            ))}
            {addrs.length > MAX_SHOW && (
              <div className="srx-cell-row">
                <span className="srx-cell-icon addr">A</span>
                <span className="srx-cell-extra" title={addrs.slice(MAX_SHOW).join(', ')}>
                  +{addrs.length - MAX_SHOW}
                </span>
              </div>
            )}
          </>
        )}
        {/* URL Filtering (destinations only) */}
        {urlFilter && (
          <div className="srx-cell-row">
            <span className="srx-cell-icon url">U</span>
            <span className="srx-cell-value" style={{ fontSize: 11 }}>{urlFilter}</span>
          </div>
        )}
      </div>
    );
  };

  /** SRX view: render action with circle icon */
  const renderSrxAction = (policy) => {
    const action = mapActionToSrx(policy.action);
    const cls = action === 'permit' ? 'permit' : action === 'reject' ? 'reject' : 'deny';
    const icon = action === 'permit' ? '\u2713' : action === 'reject' ? '!' : '\u2715';
    return (
      <div className="srx-action">
        <span className={`srx-action-icon ${cls}`}>{icon}</span>
        <span className={`srx-action-text action-${cls}`}>{action.charAt(0).toUpperCase() + action.slice(1)}</span>
      </div>
    );
  };

  /** SRX view: render applications/services cell — split into Application + Port */
  const renderSrxApps = (policy) => {
    const apps = policy.applications || [];
    const svcs = (policy.services || []).filter(s => s !== 'application-default');
    const hasSvcDefault = (policy.services || []).includes('application-default');
    const MAX_APP = 2;
    const MAX_SVC = 2;

    return (
      <div className="srx-cell-stack">
        {/* Applications section */}
        {apps.length === 0 ? (
          <div className="srx-cell-row">
            <span className="srx-cell-icon app">A</span>
            <span className="srx-cell-value" style={{ opacity: 0.5 }}>any</span>
          </div>
        ) : (
          <>
            {apps.slice(0, MAX_APP).map((a, i) => (
              <div key={`a-${i}`} className="srx-cell-row">
                <span className="srx-cell-icon app">A</span>
                <span className="srx-cell-value">{a}</span>
              </div>
            ))}
            {apps.length > MAX_APP && (
              <div className="srx-cell-row">
                <span className="srx-cell-icon app">A</span>
                <span className="srx-cell-extra" title={apps.slice(MAX_APP).join(', ')}>
                  +{apps.length - MAX_APP}
                </span>
              </div>
            )}
          </>
        )}
        {/* Port / Services section */}
        {svcs.length === 0 && hasSvcDefault ? (
          <div className="srx-cell-row">
            <span className="srx-cell-icon svc">P</span>
            <span className="srx-cell-value" style={{ opacity: 0.5 }}>defaults</span>
          </div>
        ) : svcs.length === 0 ? null : (
          <>
            {svcs.slice(0, MAX_SVC).map((s, i) => (
              <div key={`s-${i}`} className="srx-cell-row">
                <span className="srx-cell-icon svc">P</span>
                <span className="srx-cell-value">{s}</span>
              </div>
            ))}
            {svcs.length > MAX_SVC && (
              <div className="srx-cell-row">
                <span className="srx-cell-icon svc">P</span>
                <span className="srx-cell-extra" title={svcs.slice(MAX_SVC).join(', ')}>
                  +{svcs.length - MAX_SVC}
                </span>
              </div>
            )}
          </>
        )}
      </div>
    );
  };

  /** Render an editable cell */
  const renderEditableCell = (policy, field, content) => {
    const realIndex = getRealIndex(policy);
    const isEditing = editingCell?.index === realIndex && editingCell?.field === field;

    if (isEditing) {
      const fieldSuggestions = suggestionsData?.[field] || [];
      const isArrayField = arrayFields.includes(field);

      if (fieldSuggestions.length > 0) {
        return (
          <AutocompleteInput
            value={editValue}
            onChange={setEditValue}
            onCommit={commitEdit}
            onCancel={cancelEdit}
            suggestions={fieldSuggestions}
            multiToken={isArrayField}
            className="cell-edit-input"
            autoFocus
            onBlur={commitEdit}
          />
        );
      }
      return (
        <input
          className="cell-edit-input"
          value={editValue}
          onChange={(e) => setEditValue(e.target.value)}
          onKeyDown={handleEditKeyDown}
          onBlur={commitEdit}
          autoFocus
          onClick={(e) => e.stopPropagation()}
        />
      );
    }

    return (
      <div
        className="editable-cell"
        onDoubleClick={(e) => {
          e.stopPropagation();
          startEdit(realIndex, field, policy[field]);
        }}
        title="Double-click to edit"
      >
        {content}
      </div>
    );
  };

  const sortIndicator = (field) => {
    if (sortField !== field) return '';
    return sortDir === 'asc' ? ' \u25B2' : ' \u25BC';
  };

  /** Get display action text based on view mode */
  const getDisplayAction = (policy) => {
    if (isSrx) return mapActionToSrx(policy.action);
    return policy.action;
  };

  /** Get display log text based on view mode */
  const getDisplayLog = (policy) => {
    if (isSrx) {
      const parts = [];
      if (policy.log_end) parts.push('close');
      if (policy.log_start) parts.push('init');
      return parts.join('/') || '-';
    }
    return (
      <>
        {policy.log_start && 'S'}
        {policy.log_end && 'E'}
      </>
    );
  };

  /** Group policies by zone-pair for SRX view */
  const groupByZonePair = (pols) => {
    const groups = [];
    const groupMap = {};
    for (const p of pols) {
      const from = (p.src_zones || []).join(', ') || 'any';
      const to = (p.dst_zones || []).join(', ') || 'any';
      const key = `${from} \u2192 ${to}`;
      if (!groupMap[key]) {
        groupMap[key] = { key, from, to, policies: [] };
        groups.push(groupMap[key]);
      }
      groupMap[key].policies.push(p);
    }
    return groups;
  };

  // ---------------------------------------------------------------------------
  // FortiGate helpers
  // ---------------------------------------------------------------------------

  /** FortiGate action display */
  const renderFortigateAction = (policy) => {
    const action = policy.action === 'allow' ? 'ACCEPT' : policy.action === 'deny' ? 'DENY' : policy.action.toUpperCase();
    const cls = policy.action === 'allow' ? 'fg-accept' : 'fg-deny';
    const icon = policy.action === 'allow' ? '\u2713' : '\u2715';
    return (
      <div className={`fg-action ${cls}`}>
        <span className="fg-action-icon">{icon}</span>
        <span className="fg-action-text">{action}</span>
      </div>
    );
  };

  /** FortiGate security profile icons */
  const renderFortigateProfiles = (policy) => {
    const sp = policy.security_profiles || {};
    const fg = policy._fortigate || {};
    if (!fg.utm_status && Object.keys(sp).length === 0 && !policy.profile_group) {
      return <span className="fg-profile-none">-</span>;
    }

    const profiles = [];
    if (sp.virus) profiles.push({ key: 'av', label: 'AV', title: `Antivirus: ${sp.virus}`, cls: 'fg-prof-av' });
    if (sp['url-filtering']) profiles.push({ key: 'wf', label: 'WF', title: `Web Filter: ${sp['url-filtering']}`, cls: 'fg-prof-wf' });
    if (sp.vulnerability) profiles.push({ key: 'ips', label: 'IPS', title: `IPS: ${sp.vulnerability}`, cls: 'fg-prof-ips' });
    if (sp['application-control']) profiles.push({ key: 'app', label: 'App', title: `App Control: ${sp['application-control']}`, cls: 'fg-prof-app' });
    if (sp.decryption) profiles.push({ key: 'ssl', label: 'SSL', title: `SSL Inspection: ${sp.decryption}`, cls: 'fg-prof-ssl' });
    if (sp['dns-security']) profiles.push({ key: 'dns', label: 'DNS', title: `DNS Filter: ${sp['dns-security']}`, cls: 'fg-prof-dns' });
    if (sp['email-filter']) profiles.push({ key: 'email', label: 'EM', title: `Email Filter: ${sp['email-filter']}`, cls: 'fg-prof-email' });
    if (sp['dlp']) profiles.push({ key: 'dlp', label: 'DLP', title: `DLP: ${sp['dlp']}`, cls: 'fg-prof-dlp' });

    if (profiles.length === 0 && policy.profile_group) {
      return <span className="fg-profile-group" title={`Profile Group: ${policy.profile_group}`}>{policy.profile_group}</span>;
    }

    return (
      <div className="fg-profiles">
        {profiles.map(p => (
          <span key={p.key} className={`fg-prof-icon ${p.cls}`} title={p.title}>{p.label}</span>
        ))}
      </div>
    );
  };

  /** FortiGate NAT badge */
  const renderFortigateNat = (policy) => {
    const fg = policy._fortigate || {};
    return fg.nat
      ? <span className="fg-nat-on" title="Source NAT enabled">Enabled</span>
      : <span className="fg-nat-off">-</span>;
  };

  /** FortiGate status toggle indicator */
  const renderFortigateStatus = (policy) => {
    return policy.disabled
      ? <span className="fg-status-disabled" title="Policy disabled">OFF</span>
      : <span className="fg-status-enabled" title="Policy enabled">ON</span>;
  };

  // ---------------------------------------------------------------------------
  // Cisco helpers
  // ---------------------------------------------------------------------------

  /** Cisco ASDM/FMC action display */
  const renderCiscoAction = (policy) => {
    const cisco = policy._cisco || {};
    const isPermit = policy.action === 'allow';
    const label = isPermit ? 'Permit' : 'Deny';
    const cls = isPermit ? 'cisco-permit' : 'cisco-deny';
    const icon = isPermit ? '\u2713' : '\u2715';
    return (
      <div className={`cisco-action ${cls}`}>
        <span className="cisco-action-icon">{icon}</span>
        <span className="cisco-action-text">{label}</span>
      </div>
    );
  };

  /** Cisco protocol display */
  const renderCiscoProtocol = (policy) => {
    const cisco = policy._cisco || {};
    const proto = cisco.protocol || 'ip';
    return <span className="cisco-protocol">{proto.toUpperCase()}</span>;
  };

  /** Cisco security level badge */
  const renderCiscoSecLevel = (policy) => {
    const cisco = policy._cisco || {};
    const level = cisco.securityLevel;
    if (level === undefined || level === null) return null;
    const cls = level >= 80 ? 'cisco-sec-high' : level >= 40 ? 'cisco-sec-med' : 'cisco-sec-low';
    return <span className={`cisco-sec-badge ${cls}`} title={`Security Level ${level}`}>L{level}</span>;
  };

  /** Cisco port/service display */
  const renderCiscoService = (policy) => {
    const cisco = policy._cisco || {};
    const svcs = policy.services || [];
    if (svcs.length === 0) return <span style={{ opacity: 0.5 }}>any</span>;
    return svcs.map((s, i) => (
      <span key={i} className="cisco-svc-chip">{s}</span>
    ));
  };

  /** Cisco log level display */
  const renderCiscoLog = (policy) => {
    const cisco = policy._cisco || {};
    if (!policy.log_end && !policy.log_start) return <span className="cisco-log-off">-</span>;
    return (
      <span className="cisco-log-on" title={cisco.logLevel ? `Level: ${cisco.logLevel}` : 'Logging enabled'}>
        {cisco.logLevel || 'Yes'}
      </span>
    );
  };

  /** Cisco hit count placeholder */
  const renderCiscoHitCount = (policy) => {
    return <span className="cisco-hitcount">-</span>;
  };

  // =========================================================================
  // HEADER RENDERERS — one per vendor view
  // =========================================================================

  const renderPanosHeader = () => (
    <tr>
      {renderHeaderCheckbox()}
      <th onClick={() => handleSort('_rule_index')}>#{sortIndicator('_rule_index')}</th>
      <th onClick={() => handleSort('name')}>Name{sortIndicator('name')}</th>
      {hasIdentityPolicies && <th>Users</th>}
      <th onClick={() => handleSort('src_zones')}>Src Zone{sortIndicator('src_zones')}</th>
      <th onClick={() => handleSort('dst_zones')}>Dst Zone{sortIndicator('dst_zones')}</th>
      <th onClick={() => handleSort('src_addresses')}>Source{sortIndicator('src_addresses')}</th>
      <th onClick={() => handleSort('dst_addresses')}>Destination{sortIndicator('dst_addresses')}</th>
      <th onClick={() => handleSort('applications')}>App / Service{sortIndicator('applications')}</th>
      <th>Profiles</th>
      <th onClick={() => handleSort('action')}>Action{sortIndicator('action')}</th>
      {hasHitCounts && <th onClick={() => handleSort('_hit_count')} style={{ width: 70, cursor: 'pointer' }}>Hits{sortIndicator('_hit_count')}</th>}
      {hasHitCounts && <th style={{ width: 90 }}>Apps</th>}
      <th>Log</th>
      <th style={{ width: 36 }}></th>
    </tr>
  );

  const renderSrxHeader = () => (
    <tr>
      {renderHeaderCheckbox()}
      <th style={{ width: 28 }}></th>
      <th onClick={() => handleSort('_rule_index')} style={{ width: 40 }}>#</th>
      <th onClick={() => handleSort('name')} style={{ minWidth: 140 }}>Name{sortIndicator('name')}</th>
      <th onClick={() => handleSort('src_zones')}>Zones{sortIndicator('src_zones')}</th>
      <th onClick={() => handleSort('src_addresses')}>Src Addr{sortIndicator('src_addresses')}</th>
      <th onClick={() => handleSort('dst_addresses')}>Dst Addr{sortIndicator('dst_addresses')}</th>
      <th onClick={() => handleSort('applications')}>Apps / Svc{sortIndicator('applications')}</th>
      <th>Subs</th>
      <th onClick={() => handleSort('action')} style={{ width: 70 }}>Action{sortIndicator('action')}</th>
      <th style={{ width: 90 }}>Triage</th>
      <th style={{ width: 28 }}></th>
    </tr>
  );

  const renderFortigateHeader = () => (
    <tr>
      {renderHeaderCheckbox()}
      <th onClick={() => handleSort('_rule_index')} style={{ width: 44 }}>Seq{sortIndicator('_rule_index')}</th>
      <th onClick={() => handleSort('name')}>Name{sortIndicator('name')}</th>
      <th onClick={() => handleSort('src_zones')}>From{sortIndicator('src_zones')}</th>
      <th onClick={() => handleSort('dst_zones')}>To{sortIndicator('dst_zones')}</th>
      <th onClick={() => handleSort('src_addresses')}>Source{sortIndicator('src_addresses')}</th>
      <th onClick={() => handleSort('dst_addresses')}>Destination{sortIndicator('dst_addresses')}</th>
      {hasIdentityPolicies && <th>Users</th>}
      <th>Schedule</th>
      <th onClick={() => handleSort('services')}>Service{sortIndicator('services')}</th>
      <th onClick={() => handleSort('action')} style={{ width: 90 }}>Action{sortIndicator('action')}</th>
      {hasHitCounts && <th onClick={() => handleSort('_hit_count')} style={{ width: 70, cursor: 'pointer' }}>Hits{sortIndicator('_hit_count')}</th>}
      {hasHitCounts && <th style={{ width: 90 }}>Apps</th>}
      <th style={{ width: 52 }}>NAT</th>
      <th>Security Profiles</th>
      <th style={{ width: 40 }}>Log</th>
      <th style={{ width: 36 }}></th>
    </tr>
  );

  const renderCheckpointHeader = () => (
    <tr>
      {renderHeaderCheckbox()}
      <th onClick={() => handleSort('_rule_index')} style={{ width: 44 }}>#{sortIndicator('_rule_index')}</th>
      <th onClick={() => handleSort('name')}>Name{sortIndicator('name')}</th>
      <th onClick={() => handleSort('src_addresses')}>Source{sortIndicator('src_addresses')}</th>
      <th onClick={() => handleSort('dst_addresses')}>Destination{sortIndicator('dst_addresses')}</th>
      {hasIdentityPolicies && <th>Users</th>}
      <th onClick={() => handleSort('services')}>Services &amp; Apps{sortIndicator('services')}</th>
      <th onClick={() => handleSort('action')} style={{ width: 80 }}>Action{sortIndicator('action')}</th>
      {hasHitCounts && <th onClick={() => handleSort('_hit_count')} style={{ width: 70, cursor: 'pointer' }}>Hits{sortIndicator('_hit_count')}</th>}
      {hasHitCounts && <th style={{ width: 90 }}>Apps</th>}
      <th>Track</th>
      <th>Install On</th>
      <th style={{ width: 36 }}></th>
    </tr>
  );

  const renderSonicwallHeader = () => (
    <tr>
      {renderHeaderCheckbox()}
      <th onClick={() => handleSort('_rule_index')} style={{ width: 50 }}>Pri{sortIndicator('_rule_index')}</th>
      <th onClick={() => handleSort('name')}>Name{sortIndicator('name')}</th>
      <th onClick={() => handleSort('src_zones')}>From{sortIndicator('src_zones')}</th>
      <th onClick={() => handleSort('dst_zones')}>To{sortIndicator('dst_zones')}</th>
      <th onClick={() => handleSort('src_addresses')}>Source{sortIndicator('src_addresses')}</th>
      <th onClick={() => handleSort('dst_addresses')}>Destination{sortIndicator('dst_addresses')}</th>
      {hasIdentityPolicies && <th>Users</th>}
      <th onClick={() => handleSort('services')}>Service{sortIndicator('services')}</th>
      <th onClick={() => handleSort('action')} style={{ width: 80 }}>Action{sortIndicator('action')}</th>
      {hasHitCounts && <th onClick={() => handleSort('_hit_count')} style={{ width: 70, cursor: 'pointer' }}>Hits{sortIndicator('_hit_count')}</th>}
      {hasHitCounts && <th style={{ width: 90 }}>Apps</th>}
      <th style={{ width: 40 }}>DPI</th>
      <th style={{ width: 40 }}>Log</th>
      <th style={{ width: 36 }}></th>
    </tr>
  );

  const renderHuaweiHeader = () => (
    <tr>
      {renderHeaderCheckbox()}
      <th onClick={() => handleSort('_rule_index')} style={{ width: 44 }}>#{sortIndicator('_rule_index')}</th>
      <th onClick={() => handleSort('name')}>Rule Name{sortIndicator('name')}</th>
      <th onClick={() => handleSort('src_zones')}>Src Zone{sortIndicator('src_zones')}</th>
      <th onClick={() => handleSort('dst_zones')}>Dst Zone{sortIndicator('dst_zones')}</th>
      <th onClick={() => handleSort('src_addresses')}>Source{sortIndicator('src_addresses')}</th>
      <th onClick={() => handleSort('dst_addresses')}>Destination{sortIndicator('dst_addresses')}</th>
      {hasIdentityPolicies && <th>Users</th>}
      <th onClick={() => handleSort('services')}>Service{sortIndicator('services')}</th>
      <th>Profiles</th>
      <th onClick={() => handleSort('action')} style={{ width: 80 }}>Action{sortIndicator('action')}</th>
      {hasHitCounts && <th onClick={() => handleSort('_hit_count')} style={{ width: 70, cursor: 'pointer' }}>Hits{sortIndicator('_hit_count')}</th>}
      {hasHitCounts && <th style={{ width: 90 }}>Apps</th>}
      <th style={{ width: 40 }}>Log</th>
      <th style={{ width: 36 }}></th>
    </tr>
  );

  const renderCiscoHeader = () => (
    <tr>
      {renderHeaderCheckbox()}
      <th onClick={() => handleSort('_rule_index')} style={{ width: 50 }}>#ACE{sortIndicator('_rule_index')}</th>
      <th onClick={() => handleSort('action')} style={{ width: 80 }}>Action{sortIndicator('action')}</th>
      <th onClick={() => handleSort('name')}>Name / Remark{sortIndicator('name')}</th>
      <th>Protocol</th>
      <th onClick={() => handleSort('src_addresses')}>Source{sortIndicator('src_addresses')}</th>
      <th onClick={() => handleSort('dst_addresses')}>Destination{sortIndicator('dst_addresses')}</th>
      {hasIdentityPolicies && <th>Users</th>}
      <th>Service / Port</th>
      <th style={{ width: 52 }}>Log</th>
      {hasHitCounts && <th onClick={() => handleSort('_hit_count')} style={{ width: 70, cursor: 'pointer' }}>Hits{sortIndicator('_hit_count')}</th>}
      {hasHitCounts && <th style={{ width: 90 }}>Apps</th>}
      <th style={{ width: 36 }}></th>
    </tr>
  );

  /** Select the correct header for the current view */
  const renderCurrentViewHeader = () => {
    if (isCisco) return renderCiscoHeader();
    if (isCheckpoint) return renderCheckpointHeader();
    if (isSonicwall) return renderSonicwallHeader();
    if (isHuawei) return renderHuaweiHeader();
    if (isFortigate) return renderFortigateHeader();
    if (isSrx) return renderSrxHeader();
    return renderPanosHeader();
  };

  // =========================================================================
  // ROW RENDERERS — one per vendor view
  // =========================================================================

  const buildRowClass = (policy) => {
    const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
    return `${isSelected ? 'selected' : ''} ${selectedRuleKeys.has(makeKey(policy)) ? 'bulk-selected' : ''} ${policy.disabled ? 'disabled-rule' : ''} ${policy._implicit ? 'implicit-rule' : ''}`;
  };

  const renderPanosRow = (policy, measureRef) => {
    const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
    const realIndex = getRealIndex(policy);
    return (
      <tr
        key={`${policy.name}-${policy._rule_index}`}
        ref={measureRef}
        className={buildRowClass(policy)}
        onClick={(e) => handleRowClick(policy, isSelected, e)}
        style={{ cursor: 'pointer' }}
      >
        {renderRowCheckbox(policy)}
        <td>{policy._rule_index}</td>
        <td title={policy.name}>
          {policy._implicit && <span className="cell-chip implicit-chip">Implicit</span>}
          {renderEditableCell(policy, 'name', policy.name)}
        </td>
        {hasIdentityPolicies && <td>{renderCellValues(policy.source_users || [])}</td>}
        <td>{renderEditableCell(policy, 'src_zones', renderCellValues(policy.src_zones))}</td>
        <td>{renderEditableCell(policy, 'dst_zones', renderCellValues(policy.dst_zones))}</td>
        <td>{renderEditableCell(policy, 'src_addresses', <>{policy.negate_source && <span className="cell-chip negate-chip">NOT</span>}{renderCellValues(policy.src_addresses)}</>)}</td>
        <td>{renderEditableCell(policy, 'dst_addresses', <>{policy.negate_destination && <span className="cell-chip negate-chip">NOT</span>}{renderCellValues(policy.dst_addresses)}</>)}</td>
        <td>{renderEditableCell(policy, 'applications', renderCellValues([...policy.applications, ...policy.services.filter(s => s !== 'application-default')]))}</td>
        <td>{renderProfileCell(policy)}</td>
        <td>
          <span className={`action-${policy.action === 'allow' ? 'permit' : 'deny'}`}>
            {policy.action}
          </span>
        </td>
        {hasHitCounts && (
          <td style={{ textAlign: 'right', fontFamily: 'monospace', fontSize: 12, color: getHitCountColor(policy._hit_count, policy.disabled) }}>
            {typeof policy._hit_count === 'number' ? policy._hit_count.toLocaleString() : '—'}
          </td>
        )}
        {hasHitCounts && (
          <td style={{ fontSize: 11 }} title={policy._matched_apps?.length ? policy._matched_apps.join(', ') : ''}>
            {policy._matched_apps?.length > 0
              ? <span className="chip" style={{ background: 'var(--bg-elevated)', padding: '1px 6px', borderRadius: 8, fontSize: 10 }}>{policy._matched_apps.length} apps</span>
              : <span style={{ color: 'var(--text-muted)' }}>—</span>
            }
          </td>
        )}
        <td style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
          {getDisplayLog(policy)}
        </td>
        <td>
          <button className="btn-icon btn-icon-danger" onClick={(e) => { e.stopPropagation(); onDeleteRule(realIndex); }} title="Delete rule">x</button>
        </td>
      </tr>
    );
  };

  /** Toggle a row's expanded state */
  const toggleRowExpand = useCallback((rowKey) => {
    setExpandedRows(prev => {
      const next = new Set(prev);
      if (next.has(rowKey)) next.delete(rowKey);
      else next.add(rowKey);
      return next;
    });
  }, []);

  const renderSrxRow = (policy, measureRef) => {
    const status = getRuleStatus(policy);
    const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
    const realIndex = getRealIndex(policy);
    const rowKey = `${policy.name}-${policy._rule_index}`;
    const isExpanded = expandedRows.has(rowKey);
    const isAccepted = status === 'accepted';
    const ruleWarnings = warningsByRule[policy.name] || [];

    // Compute triage bucket for non-accepted, non-disabled rules
    const bucket = (status !== 'accepted' && status !== 'disabled')
      ? computeTriageBucket(policy, intermediateConfig)
      : null;
    const triageCfg = bucket ? TRIAGE_CONFIG[bucket] : null;

    const srxAction = mapActionToSrx(policy.action);
    const actionColor = srxAction === 'permit' ? 'var(--success)' : srxAction === 'deny' ? 'var(--error)' : 'var(--warning)';

    return (
      <React.Fragment key={rowKey}>
        {/* Summary row — always visible */}
        <tr
          ref={measureRef}
          className={`${buildRowClass(policy)}${isExpanded ? ' expanded-row' : ''}${isAccepted ? ' accepted-row' : ''}`}
          onClick={(e) => handleRowClick(policy, isSelected, e)}
          style={{ cursor: 'pointer' }}
        >
          {renderRowCheckbox(policy)}
          <td style={{ textAlign: 'center', width: 28 }}>
            {isAccepted ? (
              <span style={{ color: 'var(--success)', fontSize: 12 }}>✓</span>
            ) : (
              <span
                className="expand-chevron"
                onClick={(e) => { e.stopPropagation(); toggleRowExpand(rowKey); }}
              >
                {isExpanded ? '▼' : '▶'}
              </span>
            )}
          </td>
          <td><div className="srx-seq">{policy._rule_index}</div></td>
          <td>
            {policy._implicit && <span className="cell-chip implicit-chip">Implicit</span>}
            <span style={{ fontWeight: 500 }}>{policy.name}</span>
          </td>
          <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
            {(policy.src_zones || ['any']).join(', ')} → {(policy.dst_zones || ['any']).join(', ')}
          </td>
          <td>
            <div className="editable-cell" onDoubleClick={(e) => { e.stopPropagation(); startEdit(realIndex, 'src_addresses', policy.src_addresses); }}>
              {policy.negate_source && <span className="cell-chip negate-chip">NOT</span>}
              {renderCellValues(policy.src_addresses || ['any'])}
            </div>
          </td>
          <td>
            <div className="editable-cell" onDoubleClick={(e) => { e.stopPropagation(); startEdit(realIndex, 'dst_addresses', policy.dst_addresses); }}>
              {policy.negate_destination && <span className="cell-chip negate-chip">NOT</span>}
              {renderCellValues(policy.dst_addresses || ['any'])}
            </div>
          </td>
          <td>
            <div className="editable-cell" onDoubleClick={(e) => { e.stopPropagation(); startEdit(realIndex, 'applications', policy.applications); }}>
              {renderCellValues(policy.applications || ['any'])}
              {(policy.services || []).filter(s => s !== 'any').length > 0 && (
                <span style={{ color: 'var(--text-muted)', fontSize: 10 }}> + {policy.services.filter(s => s !== 'any').length} svc</span>
              )}
            </div>
          </td>
          <td>
            {(() => {
              const activeSubs = getActiveSubscriptions(policy);
              if (activeSubs.length === 0) return <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>—</span>;
              return (
                <div className="sub-icons">
                  {SUBSCRIPTION_DEFS.filter(d => activeSubs.includes(d.key)).map(d => (
                    <span key={d.key} className="sub-icon" style={{ background: d.color }} title={d.label}>{d.abbr}</span>
                  ))}
                </div>
              );
            })()}
          </td>
          <td>
            <span style={{ color: actionColor, fontWeight: 600 }}>{srxAction}</span>
          </td>
          <td>
            {isAccepted ? (
              <span className="status-label status-accepted">Accepted</span>
            ) : status === 'disabled' ? (
              <span className="status-label status-disabled">Disabled</span>
            ) : triageCfg ? (
              <span className={`triage-badge ${triageCfg.cssClass}`}>{triageCfg.icon} {triageCfg.label}</span>
            ) : null}
            {policy._review_status === 'llm_reviewed' && (
              <span className="llm-review-dot" title="LLM reviewed" style={{ marginLeft: 4 }} />
            )}
          </td>
          <td style={{ textAlign: 'center' }}>
            <button className="btn-icon btn-icon-danger" onClick={(e) => { e.stopPropagation(); onDeleteRule(realIndex); }} title="Delete policy">x</button>
          </td>
        </tr>

        {/* Expanded detail row — security profiles, logging, users, warnings */}
        {isExpanded && !isAccepted && (
          <tr className="expanded-detail-row" key={`${rowKey}-detail`}>
            <td colSpan={12} style={{ padding: 0 }}>
              <div className="expanded-detail-panel">
                <div className="expanded-detail-grid">
                  <div className="expanded-detail-cell">
                    <div className="expanded-detail-label">Security Profiles</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {policy.security_profiles && typeof policy.security_profiles === 'object'
                        ? Object.entries(policy.security_profiles).map(([type, val]) => (
                            val && <span key={type} className="cell-chip profile-chip">{type.toUpperCase()}</span>
                          ))
                        : (policy.profiles || []).map((p, i) => (
                            <span key={i} className="cell-chip profile-chip">{p}</span>
                          ))
                      }
                      {(!policy.security_profiles || Object.keys(policy.security_profiles).length === 0) && (!policy.profiles || policy.profiles.length === 0) && (
                        <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>None</span>
                      )}
                    </div>
                  </div>
                  <div className="expanded-detail-cell">
                    <div className="expanded-detail-label">Logging</div>
                    <div style={{ fontSize: 11, color: 'var(--text-primary)' }}>
                      {policy.log_start && policy.log_end ? 'Start + End'
                        : policy.log_start ? 'Start'
                        : policy.log_end ? 'End'
                        : 'Off'}
                    </div>
                  </div>
                  {(policy.services || []).filter(s => s !== 'any').length > 0 && (
                    <div className="expanded-detail-cell">
                      <div className="expanded-detail-label">Services (ports)</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                        {policy.services.filter(s => s !== 'any').map((svc, i) => (
                          <span key={i} className="cell-chip">{svc}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {(policy.source_users || []).some(u => u !== 'any') && (
                    <div className="expanded-detail-cell">
                      <div className="expanded-detail-label">Users</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                        {policy.source_users.filter(u => u !== 'any').map((u, i) => (
                          <span key={i} className="cell-chip">{u}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                {ruleWarnings.length > 0 && (
                  <div className="expanded-detail-warnings">
                    {ruleWarnings.map((w, i) => (
                      <div key={i} className="expanded-warning-item">⚠ {w.message || w.text || w}</div>
                    ))}
                  </div>
                )}
              </div>
            </td>
          </tr>
        )}
      </React.Fragment>
    );
  };

  const renderFortigateRow = (policy, measureRef) => {
    const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
    const realIndex = getRealIndex(policy);
    const fg = policy._fortigate || {};
    return (
      <tr
        key={`${policy.name}-${policy._rule_index}`}
        ref={measureRef}
        className={`${buildRowClass(policy)}${policy.disabled ? ' fg-disabled-row' : ''}`}
        onClick={(e) => handleRowClick(policy, isSelected, e)}
        style={{ cursor: 'pointer' }}
      >
        {renderRowCheckbox(policy)}
        <td>
          <div className="fg-seq">
            {renderFortigateStatus(policy)}
            <span className="fg-seq-id">{fg.policyid || policy._rule_index}</span>
          </div>
        </td>
        <td>
          {policy._implicit && <span className="cell-chip implicit-chip">Implicit</span>}
          {renderEditableCell(policy, 'name', <span className="fg-name">{policy.name}</span>)}
        </td>
        <td>{renderEditableCell(policy, 'src_zones', renderCellValues(policy.src_zones))}</td>
        <td>{renderEditableCell(policy, 'dst_zones', renderCellValues(policy.dst_zones))}</td>
        <td>{renderEditableCell(policy, 'src_addresses', <>{policy.negate_source && <span className="cell-chip negate-chip">NOT</span>}{renderCellValues(policy.src_addresses)}</>)}</td>
        <td>{renderEditableCell(policy, 'dst_addresses', <>{policy.negate_destination && <span className="cell-chip negate-chip">NOT</span>}{renderCellValues(policy.dst_addresses)}</>)}</td>
        {hasIdentityPolicies && <td>{renderCellValues(policy.source_users || [])}</td>}
        <td><span className="fg-schedule">{fg.schedule || 'always'}</span></td>
        <td>{renderEditableCell(policy, 'services', renderCellValues(policy.services))}</td>
        <td>{renderFortigateAction(policy)}</td>
        {hasHitCounts && (
          <td style={{ textAlign: 'right', fontFamily: 'monospace', fontSize: 12, color: getHitCountColor(policy._hit_count, policy.disabled) }}>
            {typeof policy._hit_count === 'number' ? policy._hit_count.toLocaleString() : '—'}
          </td>
        )}
        {hasHitCounts && (
          <td style={{ fontSize: 11 }} title={policy._matched_apps?.length ? policy._matched_apps.join(', ') : ''}>
            {policy._matched_apps?.length > 0
              ? <span className="chip" style={{ background: 'var(--bg-elevated)', padding: '1px 6px', borderRadius: 8, fontSize: 10 }}>{policy._matched_apps.length} apps</span>
              : <span style={{ color: 'var(--text-muted)' }}>—</span>
            }
          </td>
        )}
        <td>{renderFortigateNat(policy)}</td>
        <td>{renderFortigateProfiles(policy)}</td>
        <td style={{ fontSize: '11px', color: 'var(--text-muted)', textAlign: 'center' }}>
          {policy.log_start && policy.log_end ? 'All' : policy.log_end ? 'UTM' : '-'}
        </td>
        <td>
          <button className="btn-icon btn-icon-danger" onClick={(e) => { e.stopPropagation(); onDeleteRule(realIndex); }} title="Delete policy">x</button>
        </td>
      </tr>
    );
  };

  const renderCheckpointRow = (policy, measureRef) => {
    const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
    const realIndex = getRealIndex(policy);
    const cp = policy._checkpoint || {};
    return (
      <tr
        key={`${policy.name}-${policy._rule_index}`}
        ref={measureRef}
        className={buildRowClass(policy)}
        onClick={(e) => handleRowClick(policy, isSelected, e)}
        style={{ cursor: 'pointer' }}
      >
        {renderRowCheckbox(policy)}
        <td>{cp.ruleNumber || policy._rule_index}</td>
        <td>
          {policy._implicit && <span className="cell-chip implicit-chip">Implicit</span>}
          {renderEditableCell(policy, 'name', policy.name)}
          {cp.section && <span className="cell-chip" style={{ background: 'var(--bg-alt)', fontSize: '9px' }}>{cp.section}</span>}
        </td>
        <td>{renderEditableCell(policy, 'src_addresses', <>{policy.negate_source && <span className="cell-chip negate-chip">NOT</span>}{renderCellValues(policy.src_addresses)}</>)}</td>
        <td>{renderEditableCell(policy, 'dst_addresses', <>{policy.negate_destination && <span className="cell-chip negate-chip">NOT</span>}{renderCellValues(policy.dst_addresses)}</>)}</td>
        {hasIdentityPolicies && <td>{renderCellValues(policy.source_users || [])}</td>}
        <td>{renderEditableCell(policy, 'services', renderCellValues(policy.services))}</td>
        <td>
          <span className={`action-${policy.action === 'allow' ? 'permit' : 'deny'}`}>
            {policy.action === 'allow' ? 'Accept' : 'Drop'}
          </span>
        </td>
        {hasHitCounts && (
          <td style={{ textAlign: 'right', fontFamily: 'monospace', fontSize: 12, color: getHitCountColor(policy._hit_count, policy.disabled) }}>
            {typeof policy._hit_count === 'number' ? policy._hit_count.toLocaleString() : '—'}
          </td>
        )}
        {hasHitCounts && (
          <td style={{ fontSize: 11 }} title={policy._matched_apps?.length ? policy._matched_apps.join(', ') : ''}>
            {policy._matched_apps?.length > 0
              ? <span className="chip" style={{ background: 'var(--bg-elevated)', padding: '1px 6px', borderRadius: 8, fontSize: 10 }}>{policy._matched_apps.length} apps</span>
              : <span style={{ color: 'var(--text-muted)' }}>—</span>
            }
          </td>
        )}
        <td style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
          {policy.log_end ? 'Log' : 'None'}
        </td>
        <td style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
          {(cp.installOn || []).join(', ') || 'Policy Targets'}
        </td>
        <td>
          <button className="btn-icon btn-icon-danger" onClick={(e) => { e.stopPropagation(); onDeleteRule(realIndex); }} title="Delete rule">x</button>
        </td>
      </tr>
    );
  };

  const renderSonicwallRow = (policy, measureRef) => {
    const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
    const realIndex = getRealIndex(policy);
    const sw = policy._sonicwall || {};
    return (
      <tr
        key={`${policy.name}-${policy._rule_index}`}
        ref={measureRef}
        className={buildRowClass(policy)}
        onClick={(e) => handleRowClick(policy, isSelected, e)}
        style={{ cursor: 'pointer' }}
      >
        {renderRowCheckbox(policy)}
        <td>{sw.priority || policy._rule_index}</td>
        <td>
          {policy._implicit && <span className="cell-chip implicit-chip">Implicit</span>}
          {renderEditableCell(policy, 'name', policy.name)}
        </td>
        <td>{renderEditableCell(policy, 'src_zones', renderCellValues(policy.src_zones))}</td>
        <td>{renderEditableCell(policy, 'dst_zones', renderCellValues(policy.dst_zones))}</td>
        <td>{renderEditableCell(policy, 'src_addresses', renderCellValues(policy.src_addresses))}</td>
        <td>{renderEditableCell(policy, 'dst_addresses', renderCellValues(policy.dst_addresses))}</td>
        {hasIdentityPolicies && <td>{renderCellValues(policy.source_users || [])}</td>}
        <td>{renderEditableCell(policy, 'services', renderCellValues(policy.services))}</td>
        <td>
          <span className={`action-${policy.action === 'allow' ? 'permit' : 'deny'}`}>
            {policy.action === 'allow' ? 'Allow' : policy.action === 'deny' ? 'Deny' : policy.action}
          </span>
        </td>
        {hasHitCounts && (
          <td style={{ textAlign: 'right', fontFamily: 'monospace', fontSize: 12, color: getHitCountColor(policy._hit_count, policy.disabled) }}>
            {typeof policy._hit_count === 'number' ? policy._hit_count.toLocaleString() : '—'}
          </td>
        )}
        {hasHitCounts && (
          <td style={{ fontSize: 11 }} title={policy._matched_apps?.length ? policy._matched_apps.join(', ') : ''}>
            {policy._matched_apps?.length > 0
              ? <span className="chip" style={{ background: 'var(--bg-elevated)', padding: '1px 6px', borderRadius: 8, fontSize: 10 }}>{policy._matched_apps.length} apps</span>
              : <span style={{ color: 'var(--text-muted)' }}>—</span>
            }
          </td>
        )}
        <td style={{ textAlign: 'center', fontSize: '11px' }}>
          {sw.dpi ? <span style={{ color: 'var(--accent)' }}>On</span> : <span style={{ opacity: 0.4 }}>-</span>}
        </td>
        <td style={{ textAlign: 'center', fontSize: '11px', color: 'var(--text-muted)' }}>
          {policy.log_end ? 'Yes' : '-'}
        </td>
        <td>
          <button className="btn-icon btn-icon-danger" onClick={(e) => { e.stopPropagation(); onDeleteRule(realIndex); }} title="Delete rule">x</button>
        </td>
      </tr>
    );
  };

  const renderHuaweiRow = (policy, measureRef) => {
    const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
    const realIndex = getRealIndex(policy);
    return (
      <tr
        key={`${policy.name}-${policy._rule_index}`}
        ref={measureRef}
        className={buildRowClass(policy)}
        onClick={(e) => handleRowClick(policy, isSelected, e)}
        style={{ cursor: 'pointer' }}
      >
        {renderRowCheckbox(policy)}
        <td>{policy._rule_index}</td>
        <td>
          {policy._implicit && <span className="cell-chip implicit-chip">Implicit</span>}
          {renderEditableCell(policy, 'name', policy.name)}
        </td>
        <td>{renderEditableCell(policy, 'src_zones', renderCellValues(policy.src_zones))}</td>
        <td>{renderEditableCell(policy, 'dst_zones', renderCellValues(policy.dst_zones))}</td>
        <td>{renderEditableCell(policy, 'src_addresses', renderCellValues(policy.src_addresses))}</td>
        <td>{renderEditableCell(policy, 'dst_addresses', renderCellValues(policy.dst_addresses))}</td>
        {hasIdentityPolicies && <td>{renderCellValues(policy.source_users || [])}</td>}
        <td>{renderEditableCell(policy, 'services', renderCellValues(policy.services))}</td>
        <td>{renderProfileCell(policy)}</td>
        <td>
          <span className={`action-${policy.action === 'allow' ? 'permit' : 'deny'}`}>
            {policy.action === 'allow' ? 'Permit' : 'Deny'}
          </span>
        </td>
        {hasHitCounts && (
          <td style={{ textAlign: 'right', fontFamily: 'monospace', fontSize: 12, color: getHitCountColor(policy._hit_count, policy.disabled) }}>
            {typeof policy._hit_count === 'number' ? policy._hit_count.toLocaleString() : '—'}
          </td>
        )}
        {hasHitCounts && (
          <td style={{ fontSize: 11 }} title={policy._matched_apps?.length ? policy._matched_apps.join(', ') : ''}>
            {policy._matched_apps?.length > 0
              ? <span className="chip" style={{ background: 'var(--bg-elevated)', padding: '1px 6px', borderRadius: 8, fontSize: 10 }}>{policy._matched_apps.length} apps</span>
              : <span style={{ color: 'var(--text-muted)' }}>—</span>
            }
          </td>
        )}
        <td style={{ textAlign: 'center', fontSize: '11px', color: 'var(--text-muted)' }}>
          {policy.log_end ? 'Yes' : '-'}
        </td>
        <td>
          <button className="btn-icon btn-icon-danger" onClick={(e) => { e.stopPropagation(); onDeleteRule(realIndex); }} title="Delete rule">x</button>
        </td>
      </tr>
    );
  };

  const renderCiscoRow = (policy, measureRef) => {
    const isSelected = selectedRule?.name === policy.name && selectedRule?._rule_index === policy._rule_index;
    const realIndex = getRealIndex(policy);
    const cisco = policy._cisco || {};
    return (
      <tr
        key={`${policy.name}-${policy._rule_index}`}
        ref={measureRef}
        className={`${buildRowClass(policy)}${policy.disabled ? ' cisco-inactive-row' : ''}`}
        onClick={(e) => handleRowClick(policy, isSelected, e)}
        style={{ cursor: 'pointer' }}
      >
        {renderRowCheckbox(policy)}
        <td>
          <div className="cisco-ace-num">
            {policy._rule_index}
            {policy.disabled && <span className="cisco-inactive-badge">X</span>}
          </div>
        </td>
        <td>{renderCiscoAction(policy)}</td>
        <td>
          <div className="cisco-name-cell">
            {policy._implicit && <span className="cell-chip implicit-chip">Implicit</span>}
            {renderEditableCell(policy, 'name', <span className="cisco-rule-name">{policy.name}</span>)}
            {cisco.aclName && <span className="cisco-acl-badge" title={`ACL: ${cisco.aclName}`}>{cisco.aclName}</span>}
            {renderCiscoSecLevel(policy)}
          </div>
        </td>
        <td>{renderCiscoProtocol(policy)}</td>
        <td>
          {renderEditableCell(policy, 'src_addresses', (
            <div className="cisco-addr-cell">
              {(policy.src_zones || []).length > 0 && (
                <span className="cisco-iface-label" title={`Interface: ${policy.src_zones.join(', ')}`}>{policy.src_zones.join(', ')}</span>
              )}
              {policy.negate_source && <span className="cell-chip negate-chip">NOT</span>}
              {renderCellValues(policy.src_addresses)}
            </div>
          ))}
        </td>
        <td>
          {renderEditableCell(policy, 'dst_addresses', (
            <div className="cisco-addr-cell">
              {(policy.dst_zones || []).length > 0 && (
                <span className="cisco-iface-label" title={`Interface: ${policy.dst_zones.join(', ')}`}>{policy.dst_zones.join(', ')}</span>
              )}
              {policy.negate_destination && <span className="cell-chip negate-chip">NOT</span>}
              {renderCellValues(policy.dst_addresses)}
            </div>
          ))}
        </td>
        {hasIdentityPolicies && <td>{renderCellValues(policy.source_users || [])}</td>}
        <td>{renderEditableCell(policy, 'services', renderCiscoService(policy))}</td>
        <td style={{ textAlign: 'center' }}>{renderCiscoLog(policy)}</td>
        {hasHitCounts && (
          <td style={{ textAlign: 'right', fontFamily: 'monospace', fontSize: 12, color: getHitCountColor(policy._hit_count, policy.disabled) }}>
            {typeof policy._hit_count === 'number' ? policy._hit_count.toLocaleString() : '—'}
          </td>
        )}
        {hasHitCounts && (
          <td style={{ fontSize: 11 }} title={policy._matched_apps?.length ? policy._matched_apps.join(', ') : ''}>
            {policy._matched_apps?.length > 0
              ? <span className="chip" style={{ background: 'var(--bg-elevated)', padding: '1px 6px', borderRadius: 8, fontSize: 10 }}>{policy._matched_apps.length} apps</span>
              : <span style={{ color: 'var(--text-muted)' }}>—</span>
            }
          </td>
        )}
        <td>
          <button className="btn-icon btn-icon-danger" onClick={(e) => { e.stopPropagation(); onDeleteRule(realIndex); }} title="Delete ACE">x</button>
        </td>
      </tr>
    );
  };

  /** Select the correct row renderer for the current view */
  const renderCurrentViewRow = useCallback((policy, measureRef) => {
    if (isCisco) return renderCiscoRow(policy, measureRef);
    if (isCheckpoint) return renderCheckpointRow(policy, measureRef);
    if (isSonicwall) return renderSonicwallRow(policy, measureRef);
    if (isHuawei) return renderHuaweiRow(policy, measureRef);
    if (isFortigate) return renderFortigateRow(policy, measureRef);
    if (isSrx) return renderSrxRow(policy, measureRef);
    return renderPanosRow(policy, measureRef);
  });

  // =========================================================================
  // GROUP HEADER RENDERER
  // =========================================================================

  const renderGroupHeader = (group) => {
    const isCollapsed = collapsedGroups.has(group.group_name);
    const isEditing = editingGroupName === group.group_name;

    return (
      <div
        key={`gh-${group.group_name}`}
        className={`policy-group-header ${isCollapsed ? 'collapsed' : ''}`}
        onClick={() => toggleGroup(group.group_name)}
      >
        <span className="policy-group-arrow">{isCollapsed ? '\u25B6' : '\u25BC'}</span>
        {isEditing ? (
          <input
            className="policy-group-name-input"
            value={newGroupNameValue}
            onChange={(e) => setNewGroupNameValue(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') commitGroupRename(); if (e.key === 'Escape') setEditingGroupName(null); }}
            onBlur={commitGroupRename}
            onClick={(e) => e.stopPropagation()}
            autoFocus
          />
        ) : (
          <span className="policy-group-name">{group.group_name}</span>
        )}
        <span className="policy-group-count">({group.policies.length} {group.policies.length === 1 ? 'rule' : 'rules'})</span>
        {group.reasoning && (
          <span className="policy-group-reasoning" title={group.reasoning}>
            {group.reasoning.length > 60 ? group.reasoning.slice(0, 57) + '...' : group.reasoning}
          </span>
        )}
        <span className="policy-group-actions" onClick={(e) => e.stopPropagation()}>
          {!isEditing && (
            <button
              className="btn-icon"
              onClick={() => startGroupRename(group.group_name)}
              title="Rename group"
              style={{ fontSize: 11, padding: '0 4px' }}
            >
              Rename
            </button>
          )}
          <button
            className="btn-icon"
            onClick={() => dissolveGroup(group.group_name)}
            title="Dissolve group (move rules to Ungrouped)"
            style={{ fontSize: 11, padding: '0 4px' }}
          >
            Dissolve
          </button>
        </span>
      </div>
    );
  };

  // =========================================================================
  // VIRTUAL SCROLL SETUP
  // =========================================================================

  const containerRef = useRef(null);

  /** Flat list of virtual items (rows + headers) for virtual scroll */
  const virtualItems = useMemo(() => {
    if (hasGroups && displayGroups.length > 0) {
      const items = [];
      for (const group of displayGroups) {
        items.push({ type: 'group-header', group });
        if (!collapsedGroups.has(group.group_name)) {
          for (const policy of group.policies) {
            items.push({ type: 'row', policy });
          }
        }
      }
      return items;
    }

    if (isSrx) {
      const zonePairGroups = groupByZonePair(displayPolicies);
      const items = [];
      for (const zpGroup of zonePairGroups) {
        items.push({ type: 'zone-header', group: zpGroup });
        for (const policy of zpGroup.policies) {
          items.push({ type: 'row', policy });
        }
      }
      return items;
    }

    return displayPolicies.map(p => ({ type: 'row', policy: p }));
  }, [hasGroups, displayGroups, collapsedGroups, isSrx, displayPolicies]);

  /** Estimated row height per vendor view */
  const estimatedRowHeight = useMemo(() => {
    if (isSrx) return 72;
    if (isFortigate) return 35;
    return 32;
  }, [isSrx, isFortigate]);

  /** Column count for spacer colSpan */
  const colCount = useMemo(() => {
    const identityCol = hasIdentityPolicies ? 1 : 0;
    const hitCols = hasHitCounts ? 2 : 0;
    if (isSrx) return 9 + identityCol + hitCols;
    if (isFortigate) return 14 + identityCol + hitCols;
    if (isCheckpoint) return 10 + identityCol + hitCols;
    if (isSonicwall) return 12 + identityCol + hitCols;
    if (isHuawei) return 12 + identityCol + hitCols;
    if (isCisco) return 11 + identityCol + hitCols;
    return 12 + identityCol + hitCols; // PAN-OS
  }, [isSrx, isFortigate, isCheckpoint, isSonicwall, isHuawei, isCisco, hasIdentityPolicies, hasHitCounts]);

  /** Table CSS class */
  const tableClass = useMemo(() => {
    if (isSrx) return 'srx-table';
    if (isFortigate) return 'fg-table';
    if (isCheckpoint) return 'cp-table';
    if (isSonicwall) return 'sw-table';
    if (isHuawei) return 'hw-table';
    if (isCisco) return 'cisco-table';
    return '';
  }, [isSrx, isFortigate, isCheckpoint, isSonicwall, isHuawei, isCisco]);

  const {
    visibleItems,
    topSpacerHeight,
    bottomSpacerHeight,
    onScroll,
    measureRow,
    scrollToIndex,
    resetCache,
  } = useVirtualScroll({
    items: virtualItems,
    containerRef,
    estimatedRowHeight,
    overscan: 20,
    getItemKey: (item, idx) => {
      if (item.type === 'group-header') return `gh::${item.group.group_name}`;
      if (item.type === 'zone-header') return `zh::${item.group.key}`;
      return makeKey(item.policy);
    },
    getItemHeight: (item) => {
      if (item.type === 'group-header') return 38;
      if (item.type === 'zone-header') return 34;
      return null; // use estimated/measured height
    },
  });

  // Clear height cache when view mode changes
  useEffect(() => {
    resetCache();
  }, [viewMode, platformView]);

  // Auto-scroll to selected rule when it changes (keyboard nav)
  useEffect(() => {
    if (!selectedRule) return;
    const idx = virtualItems.findIndex(
      item => item.type === 'row' &&
              item.policy.name === selectedRule.name &&
              item.policy._rule_index === selectedRule._rule_index
    );
    if (idx >= 0) scrollToIndex(idx);
  }, [selectedRule]);

  // =========================================================================
  // RENDER
  // =========================================================================

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>
      {/* Triage filter bar (SRX view) */}
      {platformView === 'srx' && (
        <div className="triage-filter-bar">
          <span className="triage-filter-label">Filter:</span>
          {[
            { key: 'all', label: 'All', count: policies.length },
            { key: 'safe', label: `${TRIAGE_CONFIG.safe.icon} Safe`, count: triageCounts.safe },
            { key: 'decision', label: `${TRIAGE_CONFIG.decision.icon} Decision`, count: triageCounts.decision },
            { key: 'unsupported', label: `${TRIAGE_CONFIG.unsupported.icon} Unsupported`, count: triageCounts.unsupported },
            { key: 'blocked', label: `${TRIAGE_CONFIG.blocked.icon} Blocked`, count: triageCounts.blocked },
          ].map(({ key, label, count }) => (
            <button
              key={key}
              className={`triage-pill ${key === 'all' ? '' : TRIAGE_CONFIG[key]?.cssClass || ''}${triageFilter === key ? ' active' : ''}`}
              onClick={() => setTriageFilter(key === triageFilter ? 'all' : key)}
            >
              {label} <span className="triage-pill-count">{count}</span>
            </button>
          ))}
          <span style={{ flex: 1 }} />
          <span className="triage-pill triage-accepted">
            Accepted <span className="triage-pill-count">{triageCounts.accepted}</span>
          </span>
        </div>
      )}

      {/* Filter bar */}
      <div className="filter-toolbar">
        <input
          className="filter-input"
          type="text"
          placeholder={isCisco ? 'Filter ACEs...' : (isFortigate || isSrx || isSonicwall || isHuawei) ? 'Filter policies...' : isCheckpoint ? 'Filter rules...' : 'Filter rules...'}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <span style={{ fontSize: '11px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
          {displayPolicies.length} of {policies.length}
        </span>
        {/* Group controls */}
        {onGroupWithAI && (
          <button
            className={`btn btn-secondary btn-sm btn-translate${llmColor === 'var(--llm-local)' ? ' llm-local' : ''}`}
            onClick={onGroupWithAI}
            disabled={groupingInProgress || policies.length === 0}
            title={llmColor === 'var(--llm-local)' ? 'Note: sending info to Local LLM' : 'Warning: sending info to a Public LLM'}
          >
            {groupingInProgress ? 'Grouping...' : hasGroups ? `Grouped (${displayGroups.length})` : 'Auto-group w/LLM'}
          </button>
        )}
        {hasGroups && (
          <button
            className="btn btn-secondary btn-sm"
            onClick={clearAllGroups}
            title="Remove all groups"
            style={{ fontSize: 11 }}
          >
            Clear Groups
          </button>
        )}
        <button className="btn btn-secondary btn-sm" onClick={onAddRule}>
          {isCisco ? '+ Add ACE' : (isSrx || isFortigate || isSonicwall || isHuawei) ? '+ Add Policy' : '+ Add Rule'}
        </button>
      </div>

      {/* Virtualized table */}
      <div className="policy-table-container" ref={containerRef} onScroll={onScroll}>
        {displayPolicies.length === 0 ? (
          <div className="empty-state">
            <p>{isCisco ? 'No access control entries match your filter.' : (isSrx || isFortigate || isSonicwall || isHuawei) ? 'No security policies match your filter.' : 'No security rules match your filter.'}</p>
          </div>
        ) : (
          <table className={`policy-table ${tableClass}`}>
            <thead>
              {renderCurrentViewHeader()}
            </thead>
            <tbody>
              {/* Top spacer */}
              {topSpacerHeight > 0 && (
                <tr className="virtual-spacer" aria-hidden="true">
                  <td colSpan={colCount} style={{ height: topSpacerHeight }} />
                </tr>
              )}

              {/* Visible items */}
              {visibleItems.map(({ item, index }) => {
                const mRef = (el) => { if (el) measureRow(index, el); };

                if (item.type === 'group-header') {
                  return (
                    <tr key={`gh-${item.group.group_name}`} ref={mRef} className="virtual-group-header-row">
                      <td colSpan={colCount} style={{ padding: 0, border: 'none' }}>
                        {renderGroupHeader(item.group)}
                      </td>
                    </tr>
                  );
                }

                if (item.type === 'zone-header') {
                  const srxColCount = (hasIdentityPolicies ? 9 : 8) + 1;
                  return (
                    <tr key={`zh-${item.group.key}`} ref={mRef} className="srx-zone-group-row">
                      <td colSpan={srxColCount}>
                        <div className="srx-zone-group-label">
                          <span className="srx-zone-group-arrow">{'\u25BC'}</span>
                          <span>ZONE</span>
                          <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{item.group.from}</span>
                          <span style={{ color: 'var(--text-muted)' }}>{'\u2192'}</span>
                          <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{item.group.to}</span>
                          <span className="srx-zone-group-count">({item.group.policies.length} {item.group.policies.length === 1 ? 'Rule' : 'Rules'})</span>
                        </div>
                      </td>
                    </tr>
                  );
                }

                // Regular policy row
                return renderCurrentViewRow(item.policy, mRef);
              })}

              {/* Bottom spacer */}
              {bottomSpacerHeight > 0 && (
                <tr className="virtual-spacer" aria-hidden="true">
                  <td colSpan={colCount} style={{ height: bottomSpacerHeight }} />
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* Subscription legend — SRX view only */}
      {platformView === 'srx' && policies.length > 0 && (
        <div className="sub-legend">
          {SUBSCRIPTION_DEFS.map(d => (
            <span key={d.key} className="sub-legend-item">
              <span className="sub-icon" style={{ background: d.color }}>{d.abbr}</span>
              <span>{d.label}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
