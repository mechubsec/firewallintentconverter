/**
 * Project Save/Load — Serialization, validation, and migration for .fpic.json files
 */

import {
  ConversionOutputError,
  assertConversionOutput,
  normalizeConversionOutput,
} from '../../src/conversion/conversion-output.js';

export const CURRENT_VERSION = 5;
const RECONVERT_WARNING = 'Generated output from this older project was cleared because it has no validated identifier mapping. Reconvert before export or device push.';

const VENDOR_NAMES = {
  panos: 'PAN-OS', srx: 'SRX', fortigate: 'FortiGate',
  cisco_asa: 'Cisco-ASA', checkpoint: 'CheckPoint',
  sonicwall: 'SonicWall', huawei_usg: 'Huawei-USG',
  greenfield: 'Greenfield', srx_healthcheck: 'SRX-BestPractice',
};

const STATE_KEYS = [
  'configText', 'intermediateConfig', 'sourceVendor', 'sourceModel', 'targetModel',
  'srxLicense', 'portProfile', 'siteName', 'siteGroup', 'interfaceMappings',
  'isSanitized', 'sanitizationTable', 'parseWarnings', 'parseStats',
  'projectSecurityMode',
  'warningStatuses', 'srxTranslatedPolicies', 'srxOutput', 'convertWarnings',
  'conversionSummary', 'outputFormat', 'targetContext', 'greenfieldMode',
  'greenfieldTemplate', 'editTab', 'platformView', 'bottomTab',
  'mergeMode', 'configSlots', 'activeSlotIndex', 'crossLsLinks',
  'ruleGroups', 'sectionAcceptance',
];

const STATE_DEFAULTS = {
  configText: '',
  intermediateConfig: null,
  sourceVendor: 'panos',
  sourceModel: '',
  targetModel: '',
  srxLicense: '',
  portProfile: null,
  siteName: '',
  siteGroup: '',
  interfaceMappings: {},
  isSanitized: false,
  sanitizationTable: null,
  projectSecurityMode: 'unsanitized',
  parseWarnings: [],
  parseStats: null,
  warningStatuses: {},
  srxTranslatedPolicies: null,
  srxOutput: null,
  convertWarnings: [],
  conversionSummary: null,
  outputFormat: 'set',
  targetContext: { type: 'none', name: '' },
  greenfieldMode: false,
  greenfieldTemplate: null,
  editTab: 'rules',
  platformView: 'panos',
  bottomTab: 'output',
  mergeMode: false,
  configSlots: [],
  activeSlotIndex: 0,
  crossLsLinks: [],
  ruleGroups: [],
  sectionAcceptance: {},
};

/**
 * Build a save-ready project JSON payload from current app state.
 */
export function buildProjectCore(stateBag, projectName, security) {
  const state = {};
  for (const key of STATE_KEYS) {
    state[key] = stateBag[key] ?? STATE_DEFAULTS[key];
  }
  if (state.srxOutput !== null) {
    state.srxOutput = assertConversionOutput(state.srxOutput);
    state.outputFormat = state.srxOutput.format;
  }
  if (security?.mode === 'sanitized') delete state.sanitizationTable;
  return {
    fpic_version: CURRENT_VERSION,
    name: projectName,
    savedAt: new Date().toISOString(),
    security,
    state,
  };
}

/**
 * Fail-closed compatibility entry retained until the project hook is moved to
 * the asynchronous security boundary.
 */
export function buildProjectPayload() {
  const error = new Error('Project export must use the secure export boundary.');
  error.name = 'ProjectExportBoundaryError';
  error.code = 'secure_export_required';
  throw error;
}

/**
 * Validate a parsed JSON object as a valid FPIC project file.
 * Returns { valid: true, project, warnings } or { valid: false, error }.
 */
export function validateProjectFile(json) {
  if (!json || typeof json !== 'object') {
    return { valid: false, error: 'File is not a valid JSON object.' };
  }

  if (typeof json.fpic_version !== 'number') {
    return { valid: false, error: 'Not a valid project file (missing fpic_version).' };
  }

  if (json.fpic_version > CURRENT_VERSION) {
    return {
      valid: false,
      error: `Project file version ${json.fpic_version} is newer than this app supports (v${CURRENT_VERSION}). Please update the app.`,
    };
  }

  if (!json.state || typeof json.state !== 'object' || Array.isArray(json.state)) {
    return { valid: false, error: 'Project file is missing state data.' };
  }

  try {
    const result = validateProjectStateCore(json);
    return { valid: true, ...result };
  } catch (error) {
    if (error instanceof ConversionOutputError) {
      return { valid: false, error: `Project conversion output is invalid: ${error.reason}` };
    }
    throw error;
  }
}

/**
 * Validate and migrate only project state and conversion output. Security
 * envelope decisions are owned by project-security.js.
 */
export function validateProjectStateCore(project) {
  if (!project?.state || typeof project.state !== 'object' || Array.isArray(project.state)) {
    throw new TypeError('Project file is missing state data.');
  }
  const warnings = [];
  if (!project.state.intermediateConfig && !project.state.configText) {
    warnings.push('Project has no parsed config or source text. You may need to re-parse.');
  }
  const migration = migrateProject(project);
  if (migration.staleOutputCleared) warnings.push(RECONVERT_WARNING);
  return { project: migration.project, warnings };
}

/**
 * Migrate a project from an older version to the current version.
 * Each version bump adds a migration step.
 */
function migrateProject(project) {
  const p = { ...project, state: { ...project.state } };
  let staleOutputCleared = false;

  // Fill missing keys with defaults
  for (const key of STATE_KEYS) {
    if (!(key in p.state)) {
      p.state[key] = STATE_DEFAULTS[key];
    }
  }

  if (p.fpic_version < 2) {
    // V1 had no merge mode — add defaults
    p.state.mergeMode = false;
    p.state.configSlots = [];
    p.state.activeSlotIndex = 0;
    p.state.crossLsLinks = [];
    p.fpic_version = 2;
  }

  if (p.state.srxOutput !== null
      && p.fpic_version < 4
      && (!p.state.srxOutput
        || typeof p.state.srxOutput !== 'object'
        || !Object.hasOwn(p.state.srxOutput, 'identifierMappings'))) {
    p.state.srxOutput = null;
    p.state.convertWarnings = [];
    p.state.conversionSummary = null;
    staleOutputCleared = true;
  } else if (p.state.srxOutput !== null) {
    p.state.srxOutput = normalizeConversionOutput(
      p.state.srxOutput,
      p.state.outputFormat,
    );
    p.state.outputFormat = p.state.srxOutput.format;
  }

  if (p.fpic_version < 3) {
    p.fpic_version = 3;
  }

  if (p.fpic_version < 4) {
    p.fpic_version = 4;
  }

  if (p.fpic_version < 5) {
    p.fpic_version = 5;
  }

  return { project: p, staleOutputCleared };
}

/**
 * Generate a default project name from current state.
 */
export function generateProjectName(sourceVendor, sourceModel, siteName) {
  const vendor = VENDOR_NAMES[sourceVendor] || sourceVendor || 'Project';
  const model = sourceModel ? `-${sourceModel}` : '';
  const site = siteName ? `-${siteName}` : '';
  const date = new Date().toISOString().slice(0, 10);
  return `${vendor}${model}${site}-${date}`;
}
