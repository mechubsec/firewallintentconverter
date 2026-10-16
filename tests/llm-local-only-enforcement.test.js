/**
 * Tests for local-only LLM mode enforcement (M6, MEC-28)
 *
 * Covers the acceptance criterion: with a saved cloud provider and
 * 'local-only' selected, no request is made to a non-loopback origin — for
 * every entry point, including the internal _callLLM path used by
 * translatePolicies/groupPolicies and the "custom" OpenAI-compatible provider.
 */

// ---------------------------------------------------------------------------
// Minimal DOM/storage/fetch stubs for the browser-side module
// ---------------------------------------------------------------------------
const _store = {};
global.localStorage = {
  getItem: (k) => (Object.prototype.hasOwnProperty.call(_store, k) ? _store[k] : null),
  setItem: (k, v) => { _store[k] = String(v); },
  removeItem: (k) => { delete _store[k]; },
};
const _sessionStore = {};
global.sessionStorage = {
  getItem: (k) => (Object.prototype.hasOwnProperty.call(_sessionStore, k) ? _sessionStore[k] : null),
  setItem: (k, v) => { _sessionStore[k] = String(v); },
  removeItem: (k) => { delete _sessionStore[k]; },
};

let fetchCalls = [];
global.fetch = async (url) => {
  fetchCalls.push(String(url));
  return {
    ok: true,
    status: 200,
    json: async () => ({
      content: [{ text: 'ok' }],
      choices: [{ message: { content: 'ok' } }],
      message: { content: 'ok' },
    }),
  };
};

// ---------------------------------------------------------------------------
// Import the functions under test
// ---------------------------------------------------------------------------
import {
  getLLMSuggestion,
  getLLMChatResponse,
  testLLMConnection,
  translatePolicies,
  groupPolicies,
} from '../public/utils/llm-client.js';
import { saveLLMSettings } from '../public/utils/llm-settings.js';
import { LLM_RISK_ACCEPTANCE_STORAGE_KEY } from '../public/utils/llm-risk-acceptance.js';

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------
let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (condition) {
    passed++;
  } else {
    failed++;
    console.error('FAIL:', msg);
  }
}

async function assertRejects(fn, msg) {
  try {
    await fn();
    failed++;
    console.error('FAIL (expected throw, none occurred):', msg);
  } catch {
    passed++;
  }
}

function setRiskMode(value) {
  if (value === null) global.localStorage.removeItem(LLM_RISK_ACCEPTANCE_STORAGE_KEY);
  else global.localStorage.setItem(LLM_RISK_ACCEPTANCE_STORAGE_KEY, value);
}

const MINIMAL_CONFIG = {
  metadata: { source_vendor: 'panos' },
  zones: [{ name: 'trust' }, { name: 'untrust' }],
  addresses: [],
  address_groups: [],
  security_policies: [{
    name: 'allow-web', _rule_index: 0, action: 'allow',
    src_zones: ['trust'], dst_zones: ['untrust'],
    src_addresses: ['any'], dst_addresses: ['any'],
    applications: ['junos-http'], services: ['any'],
    log_start: false, log_end: true, disabled: false, description: '',
  }],
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
async function run() {
  // llm-client.js fire-and-forget loads /prompts/*.txt on module import;
  // let that settle before counting fetch calls made by the code under test.
  await new Promise((resolve) => setTimeout(resolve, 10));
  fetchCalls = [];

  setRiskMode('local-only');

  // A saved cloud provider, fully configured with an API key.
  saveLLMSettings({ provider: 'claude', apiKey: 'FAKE-TEST-KEY-0001', model: 'claude-sonnet-4-6' });

  fetchCalls = [];
  await assertRejects(() => getLLMSuggestion('hi'), 'getLLMSuggestion rejects a saved cloud provider in local-only mode');
  assert(fetchCalls.length === 0, 'getLLMSuggestion: no request reached fetch');

  fetchCalls = [];
  await assertRejects(
    () => getLLMChatResponse([{ role: 'user', content: 'hi' }]),
    'getLLMChatResponse rejects a saved cloud provider in local-only mode',
  );
  assert(fetchCalls.length === 0, 'getLLMChatResponse: no request reached fetch');

  fetchCalls = [];
  await assertRejects(
    () => testLLMConnection({ provider: 'claude', apiKey: 'FAKE-TEST-KEY-0001' }),
    'testLLMConnection rejects a saved cloud provider in local-only mode',
  );
  assert(fetchCalls.length === 0, 'testLLMConnection: no request reached fetch');

  // translatePolicies/groupPolicies both go through the internal _callLLM path.
  fetchCalls = [];
  await assertRejects(
    () => translatePolicies(MINIMAL_CONFIG, 'SRX345', ''),
    'translatePolicies (via _callLLM) rejects a saved cloud provider in local-only mode',
  );
  assert(fetchCalls.length === 0, 'translatePolicies: no request reached fetch');

  fetchCalls = [];
  await assertRejects(
    () => groupPolicies(MINIMAL_CONFIG.security_policies),
    'groupPolicies (via _callLLM) rejects a saved cloud provider in local-only mode',
  );
  assert(fetchCalls.length === 0, 'groupPolicies: no request reached fetch');

  // The "custom" provider must respect local-only mode too — a non-loopback
  // base URL is rejected even though "custom" isn't in the cloud provider list.
  saveLLMSettings({ provider: 'custom', baseUrl: 'https://my-remote-llm.example.net', apiKey: '' });
  fetchCalls = [];
  await assertRejects(
    () => getLLMSuggestion('hi'),
    'custom provider with a non-loopback baseUrl is rejected in local-only mode',
  );
  assert(fetchCalls.length === 0, 'custom (remote): no request reached fetch');

  // A loopback custom endpoint IS allowed.
  saveLLMSettings({ provider: 'custom', baseUrl: 'http://127.0.0.1:8080', apiKey: '' });
  fetchCalls = [];
  await getLLMSuggestion('hi');
  assert(fetchCalls.length === 1, 'custom (loopback): request was made exactly once');
  assert(fetchCalls[0].startsWith('http://127.0.0.1:8080'), 'custom (loopback): request went to the loopback origin');

  // Ollama's default base URL (when none is configured) is loopback and works.
  saveLLMSettings({ provider: 'ollama', apiKey: '' });
  fetchCalls = [];
  await getLLMSuggestion('hi');
  assert(fetchCalls.length === 1 && fetchCalls[0].startsWith('http://localhost:11434'), 'ollama: default baseUrl is loopback and reachable in local-only mode');

  // F1 (MEC-134): the gate used to check only for the exact string
  // 'local-only' and let every other mode through to the network. Modes
  // other than 'all'/'local-only' — undecided (no stored value), a stale
  // 'null' string, 'deterministic', 'rejected', and any unrecognized value —
  // must fail closed at every entry point, not just be hidden by the UI.
  saveLLMSettings({ provider: 'claude', apiKey: 'FAKE-TEST-KEY-0001', model: 'claude-sonnet-4-6' });

  const DISALLOWED_MODES = [
    [null, 'no stored value'],
    ['null', 'the literal string "null"'],
    ['deterministic', "'deterministic'"],
    ['rejected', "'rejected'"],
    ['bogus-mode', 'an unrecognized value'],
  ];

  for (const [mode, label] of DISALLOWED_MODES) {
    setRiskMode(mode);

    fetchCalls = [];
    await assertRejects(() => getLLMSuggestion('hi'), `getLLMSuggestion rejects when mode is ${label}`);
    assert(fetchCalls.length === 0, `getLLMSuggestion (${label}): no request reached fetch`);

    fetchCalls = [];
    await assertRejects(
      () => getLLMChatResponse([{ role: 'user', content: 'hi' }]),
      `getLLMChatResponse rejects when mode is ${label}`,
    );
    assert(fetchCalls.length === 0, `getLLMChatResponse (${label}): no request reached fetch`);

    fetchCalls = [];
    await assertRejects(
      () => testLLMConnection({ provider: 'claude', apiKey: 'FAKE-TEST-KEY-0001' }),
      `testLLMConnection rejects when mode is ${label}`,
    );
    assert(fetchCalls.length === 0, `testLLMConnection (${label}): no request reached fetch`);

    fetchCalls = [];
    await assertRejects(
      () => translatePolicies(MINIMAL_CONFIG, 'SRX345', ''),
      `translatePolicies rejects when mode is ${label}`,
    );
    assert(fetchCalls.length === 0, `translatePolicies (${label}): no request reached fetch`);

    fetchCalls = [];
    await assertRejects(
      () => groupPolicies(MINIMAL_CONFIG.security_policies),
      `groupPolicies rejects when mode is ${label}`,
    );
    assert(fetchCalls.length === 0, `groupPolicies (${label}): no request reached fetch`);
  }

  // Sanity check: outside local-only mode, the same cloud provider works.
  setRiskMode('all');
  saveLLMSettings({ provider: 'claude', apiKey: 'FAKE-TEST-KEY-0001', model: 'claude-sonnet-4-6' });
  fetchCalls = [];
  await getLLMSuggestion('hi');
  assert(fetchCalls.length === 1 && new URL(fetchCalls[0]).origin === 'https://api.anthropic.com', 'cloud provider remains reachable when risk mode is not local-only');
}

run().then(() => {
  console.log(`\n========================================`);
  console.log(`  Results: ${passed} passed, ${failed} failed`);
  console.log(`========================================\n`);
  if (failed > 0) process.exit(1);
}).catch((err) => {
  console.error('Test runner error:', err);
  process.exit(1);
});
