import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// Context hooks are mocked so hooks/components can be rendered once (server
// render) and their handlers invoked against spy dispatchers.
const mocks = vi.hoisted(() => ({
  config: { state: {}, dispatch: null },
  ui: { state: {}, dispatch: null },
  merge: { state: {}, dispatch: null },
  undo: { state: { past: [], future: [] }, dispatch: null },
  conv: { state: {}, dispatch: null },
  interviewProps: null,
  llm: null,
  cfgHook: null,
}));

vi.mock('../public/contexts/ConfigContext.jsx', () => ({ useConfigContext: () => mocks.config }));
vi.mock('../public/contexts/UIContext.jsx', () => ({ useUIContext: () => mocks.ui }));
vi.mock('../public/contexts/MergeContext.jsx', () => ({ useMergeContext: () => mocks.merge }));
vi.mock('../public/contexts/UndoContext.jsx', () => ({ useUndoContext: () => mocks.undo }));
vi.mock('../public/contexts/ConversionContext.jsx', () => ({ useConversionContext: () => mocks.conv }));
vi.mock('../public/utils/engine.js', () => ({
  sanitizeConfig: (text) => ({ sanitizedText: text, replacements: [] }),
  parseConfig: async () => ({ intermediateConfig: { security_policies: [], metadata: {} } }),
}));
vi.mock('../public/components/InterviewPanel.jsx', () => ({
  default: (props) => { mocks.interviewProps = props; return null; },
}));
vi.mock('../public/hooks/useConfig.js', async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, default: (...args) => mocks.cfgHook ?? actual.default(...args) };
});
vi.mock('../public/hooks/useLLM.js', async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, default: (...args) => mocks.llm ?? actual.default(...args) };
});

const { default: useConfig } = await import('../public/hooks/useConfig.js');
const { default: useLLM } = await import('../public/hooks/useLLM.js');
const { default: RightPanel } = await import('../public/components/layout/RightPanel.jsx');

const rule = (name, index) => ({ name, _rule_index: index, src_zones: [], dst_zones: [] });
const key = (r) => `${r.name}::${r._rule_index}`;

/** Render a hook once and return its value. */
function renderHook(hook) {
  let value;
  const Probe = () => { value = hook(); return null; };
  renderToStaticMarkup(<Probe />);
  return value;
}

/** Apply the UPDATE_CONFIG updater captured on a dispatch spy. */
function appliedConfig(dispatch, config) {
  const call = dispatch.mock.calls.map(([a]) => a).find(a => a.type === 'UPDATE_CONFIG');
  return call.updater(config);
}

beforeEach(() => {
  mocks.interviewProps = null;
  mocks.llm = null;
  mocks.cfgHook = null;
  mocks.config = {
    state: { configText: 'x', selectedRuleKeys: new Set(), srxTranslatedPolicies: null, intermediateConfig: null },
    dispatch: vi.fn(),
  };
  mocks.ui = { state: { platformView: 'panos', selectedRule: null, editTab: 'rules' }, dispatch: vi.fn() };
  mocks.merge = { state: { mergeMode: false, configSlots: [], activeSlotIndex: 0 }, dispatch: vi.fn() };
  mocks.undo = { state: { past: [], future: [] }, dispatch: vi.fn() };
  mocks.conv = { state: {}, dispatch: vi.fn() };
});

describe('RightPanel inspector edits', () => {
  const renderPanel = ({ translated, selected, source = [], translatedRules = null }) => {
    const handleUpdateRule = vi.fn();
    const handleUpdateTranslatedRule = vi.fn();
    mocks.cfgHook = { handleUpdateRule };
    mocks.llm = { handleUpdateTranslatedRule };
    mocks.config.state = {
      intermediateConfig: { security_policies: source },
      srxTranslatedPolicies: translatedRules,
    };
    mocks.ui.state = {
      platformView: translated ? 'srx' : 'panos', selectedRule: selected, editTab: 'rules', rightPanelCollapsed: false,
    };
    renderToStaticMarkup(<RightPanel />);
    return { handleUpdateRule, handleUpdateTranslatedRule };
  };

  it('updates a source-view rule by index', () => {
    const source = [rule('a', 1), rule('b', 2)];
    const { handleUpdateRule } = renderPanel({ translated: false, selected: source[1], source });
    const edited = { ...source[1], description: 'edited' };
    mocks.interviewProps.onUpdateRule(edited);
    expect(handleUpdateRule).toHaveBeenCalledWith(1, edited);
  });

  it('accepts a source-view rule by index', () => {
    const source = [rule('a', 1), rule('b', 2)];
    const { handleUpdateRule } = renderPanel({ translated: false, selected: source[1], source });
    mocks.interviewProps.onAcceptRule();
    expect(handleUpdateRule).toHaveBeenCalledWith(1, { ...source[1], _review_status: 'accepted' });
  });

  it('keeps the edit when a translated rule is renamed', () => {
    const translatedRules = [rule('a', 0), rule('b', 1)];
    const { handleUpdateTranslatedRule } = renderPanel({
      translated: true, selected: translatedRules[1], translatedRules,
    });
    const renamed = { ...translatedRules[1], name: 'b-renamed' };
    mocks.interviewProps.onUpdateRule(renamed);
    expect(handleUpdateTranslatedRule).toHaveBeenCalledWith(1, renamed);
  });
});

describe('bulk selection honours the visible rows', () => {
  const all = [rule('a', 1), rule('b', 2), rule('c', 3), rule('d', 4)];

  it('select-all selects only the visible (filtered) rules', () => {
    mocks.config.state.intermediateConfig = { security_policies: all };
    const llm = renderHook(useLLM);
    llm.handleSelectAllRules(true, [all[1], all[3]]);
    expect(mocks.config.dispatch).toHaveBeenCalledWith({ type: 'SET_SELECTED_KEYS', keys: [key(all[1]), key(all[3])] });
  });

  it('shift-range walks the visible order, not the underlying array', () => {
    mocks.config.state.intermediateConfig = { security_policies: all };
    mocks.config.state.lastClickedKey = key(all[3]);
    const llm = renderHook(useLLM);
    // Visible list is filtered to b and d, so the range d..b must not include c
    llm.handleToggleRuleSelect(all[1], { shiftKey: true }, [all[3], all[1]]);
    const selection = mocks.config.dispatch.mock.calls.map(([a]) => a).find(a => a.type === 'SET_SELECTED_KEYS');
    expect(selection.keys.sort()).toEqual([key(all[1]), key(all[3])]);
  });
});

describe('bulk actions', () => {
  it('bulk move keeps the 1-based source _rule_index convention', () => {
    const source = [rule('a', 1), rule('b', 2), rule('c', 3)];
    mocks.config.state.intermediateConfig = { security_policies: source };
    mocks.config.state.selectedRuleKeys = new Set([key(source[1])]);
    const llm = renderHook(useLLM);
    llm.handleBulkMove('up');
    const moved = appliedConfig(mocks.config.dispatch, { security_policies: source }).security_policies;
    expect(moved.map(r => [r.name, r._rule_index])).toEqual([['b', 1], ['a', 2], ['c', 3]]);
  });

  it('bulk move keeps the 0-based translated _rule_index convention', () => {
    const translated = [rule('a', 0), rule('b', 1)];
    mocks.ui.state.platformView = 'srx';
    mocks.config.state.srxTranslatedPolicies = translated;
    mocks.config.state.selectedRuleKeys = new Set([key(translated[1])]);
    renderHook(useLLM).handleBulkMove('up');
    const { policies } = mocks.config.dispatch.mock.calls.map(([a]) => a).find(a => a.type === 'SET_TRANSLATED_POLICIES');
    expect(policies.map(r => [r.name, r._rule_index])).toEqual([['b', 0], ['a', 1]]);
  });

  it('merge mode: bulk delete updates the active slot, not the top-level config', () => {
    const slotRules = [rule('a', 1), rule('b', 2)];
    mocks.merge.state = {
      mergeMode: true,
      activeSlotIndex: 0,
      configSlots: [{ intermediateConfig: { security_policies: slotRules } }],
    };
    mocks.config.state.intermediateConfig = null; // hand-added slots leave this null
    mocks.config.state.selectedRuleKeys = new Set([key(slotRules[0])]);
    renderHook(useLLM).handleBulkDelete();
    expect(mocks.config.dispatch.mock.calls.map(([a]) => a.type)).not.toContain('UPDATE_CONFIG');
    const slotUpdate = mocks.merge.dispatch.mock.calls[0][0];
    expect(slotUpdate.type).toBe('UPDATE_SLOT');
    expect(slotUpdate.slot.intermediateConfig.security_policies.map(r => r.name)).toEqual(['b']);
  });
});

describe('undo history', () => {
  it('handleParse clears undo history from the previous config', async () => {
    const config = renderHook(useConfig);
    await config.handleParse();
    expect(mocks.undo.dispatch).toHaveBeenCalledWith({ type: 'CLEAR' });
  });
});
