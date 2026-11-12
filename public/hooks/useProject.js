/**
 * useProject — Project save/load hook
 *
 * Provides handlers for saving/loading .fpic.json project files
 * and restoring all application state from a loaded project.
 * Uses ConfigContext, UIContext, ConversionContext, MergeContext, and UndoContext.
 */
import { useCallback, useEffect, useMemo, useRef } from 'react';
import { useConfigContext } from '../contexts/ConfigContext.jsx';
import { useUIContext } from '../contexts/UIContext.jsx';
import { useConversionContext } from '../contexts/ConversionContext.jsx';
import { useMergeContext } from '../contexts/MergeContext.jsx';
import { useUndoContext } from '../contexts/UndoContext.jsx';
import { generateProjectName } from '../utils/project-io.js';
import {
  MAX_PROJECT_FILE_BYTES,
  PROJECT_SECURITY_MODES,
  ProjectSecurityError,
  classifyProjectSecurity,
  consumeValidatedProjectDownload,
  inspectProjectImport,
  openProjectImport,
  serializeProjectExport,
} from '../utils/project-security.js';

const PROJECT_ERROR_MESSAGES = Object.freeze({
  unsafe_state: 'Project state contains an unsupported value.',
  invalid_restoration: 'Project restoration data is invalid.',
  unsanitized_source: 'Sanitized export requires every populated source to be sanitized.',
  original_leak: 'Sanitized export was blocked because an original value remains.',
  secret_leak: 'Sanitized export was blocked because secret-bearing content remains.',
  oversized_project: 'Project data exceeds the supported size limit.',
  invalid_confirmation: 'Project export confirmation is invalid.',
  unsupported_mode: 'Project security mode is not supported.',
  unsupported_version: 'Project file version is not supported.',
  invalid_project: 'Project file is invalid.',
  invalid_passphrase: 'Passphrase must contain at least 16 characters.',
  unsupported_crypto: 'Encrypted project export is unavailable in this browser.',
  invalid_envelope: 'Encrypted project file is invalid.',
  decryption_failed: 'Encrypted project could not be opened.',
});

const PROJECT_IMPORT_ERROR_MESSAGES = Object.freeze({
  invalid_confirmation: 'Project import acknowledgement is required.',
  unsupported_crypto: 'Encrypted project import is unavailable in this browser.',
});

const RETRYABLE_IMPORT_CODES = new Set([
  'invalid_confirmation',
  'invalid_passphrase',
  'decryption_failed',
]);
const CLASSIFICATION_UI_STATE = Object.freeze({
  editTab: '',
  platformView: '',
  bottomTab: '',
});

export function assembleProjectStateBag(configState, conversionState, uiState, mergeState) {
  return {
    configText: configState.configText,
    intermediateConfig: configState.intermediateConfig,
    sourceVendor: configState.sourceVendor,
    sourceModel: configState.sourceModel,
    targetModel: configState.targetModel,
    srxLicense: configState.srxLicense,
    portProfile: configState.portProfile,
    siteName: configState.siteName,
    siteGroup: configState.siteGroup,
    interfaceMappings: configState.interfaceMappings,
    isSanitized: configState.isSanitized,
    sanitizationTable: configState.sanitizationTable,
    projectSecurityMode: configState.projectSecurityMode ?? PROJECT_SECURITY_MODES.UNSANITIZED,
    parseWarnings: configState.parseWarnings,
    parseStats: configState.parseStats,
    warningStatuses: configState.warningStatuses,
    srxTranslatedPolicies: configState.srxTranslatedPolicies,
    ruleGroups: configState.ruleGroups,
    sectionAcceptance: configState.sectionAcceptance,
    greenfieldMode: configState.greenfieldMode,
    greenfieldTemplate: configState.greenfieldTemplate,
    srxOutput: conversionState.srxOutput,
    convertWarnings: conversionState.convertWarnings,
    conversionSummary: conversionState.conversionSummary,
    outputFormat: conversionState.outputFormat,
    targetContext: conversionState.targetContext,
    editTab: uiState.editTab,
    platformView: uiState.platformView,
    bottomTab: uiState.bottomTab,
    mergeMode: mergeState.mergeMode,
    configSlots: mergeState.configSlots,
    activeSlotIndex: mergeState.activeSlotIndex,
    crossLsLinks: mergeState.crossLsLinks,
  };
}

function ownDataValue(value, key) {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable) return undefined;
    return descriptor.value;
  } catch {
    return undefined;
  }
}

export function downloadValidatedProject(result, environment = globalThis) {
  const snapshot = consumeValidatedProjectDownload(result);
  const serialized = snapshot.serialized;
  const filename = snapshot.filename;
  const security = snapshot.security;
  const BlobImpl = environment?.Blob;
  const urlApi = environment?.URL;
  const documentApi = environment?.document;

  if (typeof serialized !== 'string'
      || serialized.length > MAX_PROJECT_FILE_BYTES
      || typeof filename !== 'string'
      || filename.length === 0
      || !/^[A-Za-z0-9._-]+\.fpic(?:\.enc)?\.json$/.test(filename)
      || !security
      || typeof security !== 'object'
      || !Object.values(PROJECT_SECURITY_MODES).includes(ownDataValue(security, 'mode'))) {
    throw new ProjectSecurityError('invalid_project');
  }

  const inspected = inspectProjectImport(serialized);
  if (inspected.kind !== ownDataValue(security, 'mode')
      || typeof BlobImpl !== 'function'
      || typeof urlApi?.createObjectURL !== 'function'
      || typeof urlApi?.revokeObjectURL !== 'function'
      || typeof documentApi?.createElement !== 'function') {
    throw new ProjectSecurityError('invalid_project');
  }

  const blob = new BlobImpl([serialized], { type: 'application/json' });
  const url = urlApi.createObjectURL(blob);
  try {
    const anchor = documentApi.createElement('a');
    if (!anchor || typeof anchor.click !== 'function') {
      throw new ProjectSecurityError('invalid_project');
    }
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
  } finally {
    urlApi.revokeObjectURL(url);
  }
}

export function projectSecurityMessage(error, operation = 'export') {
  const code = error && typeof error === 'object'
    ? ownDataValue(error, 'code')
    : undefined;
  if (operation === 'import'
      && typeof code === 'string'
      && Object.hasOwn(PROJECT_IMPORT_ERROR_MESSAGES, code)) {
    return PROJECT_IMPORT_ERROR_MESSAGES[code];
  }
  return typeof code === 'string' && Object.hasOwn(PROJECT_ERROR_MESSAGES, code)
    ? PROJECT_ERROR_MESSAGES[code]
    : 'Project security operation failed.';
}

function prepareValidatedImportCandidate(project, security, warnings) {
  try {
    const snapshot = structuredClone({ project, security, warnings });
    const confirmation = snapshot.security.mode === PROJECT_SECURITY_MODES.REVERSIBLE
      ? {
        project: {
          name: 'Encrypted project',
          savedAt: snapshot.project.savedAt,
          state: {},
        },
        security: structuredClone(snapshot.security),
        warnings: structuredClone(snapshot.warnings),
      }
      : structuredClone(snapshot);
    return {
      candidate: {
        snapshot,
        confirmationProject: confirmation.project,
        confirmationSecurity: confirmation.security,
      },
      confirmation,
    };
  } catch {
    throw new ProjectSecurityError('invalid_project');
  }
}

function safeImportDescriptor(inspected) {
  const security = inspected.security;
  return {
    kind: inspected.kind,
    requiresConfirmation: inspected.requiresConfirmation === true,
    security: {
      schema: security?.schema,
      mode: inspected.kind,
      containsOriginals: security?.containsOriginals === true,
      reversible: security?.reversible === true,
      restorationAvailable: security?.restorationAvailable === true,
    },
  };
}

export default function useProject() {
  const { state: configState, dispatch: configDispatch } = useConfigContext();
  const { state: uiState, dispatch: uiDispatch } = useUIContext();
  const { state: conversionState, dispatch: conversionDispatch } = useConversionContext();
  const { state: mergeState, dispatch: mergeDispatch } = useMergeContext();
  const { dispatch: undoDispatch } = useUndoContext();
  const pendingImportRef = useRef(null);
  const validatedImportRef = useRef(null);
  const readGenerationRef = useRef(0);
  const confirmAttemptRef = useRef(0);

  // -----------------------------------------------------------------------
  // Secure export — serialize through the project security boundary first.
  // -----------------------------------------------------------------------
  const exportDescriptor = useMemo(() => {
    try {
      return classifyProjectSecurity(assembleProjectStateBag(
        configState,
        conversionState,
        CLASSIFICATION_UI_STATE,
        mergeState,
      ));
    } catch {
      return null;
    }
  }, [configState, conversionState, mergeState]);
  const getExportDescriptor = useCallback(
    () => exportDescriptor,
    [exportDescriptor],
  );

  const handleExportProject = useCallback(async request => {
    uiDispatch({ type: 'SET_LOADING', isLoading: true, message: 'Preparing project export...' });
    uiDispatch({ type: 'CLEAR_ERROR' });
    try {
      const stateBag = assembleProjectStateBag(
        configState, conversionState, uiState, mergeState,
      );
      const result = await serializeProjectExport(stateBag, request.name, request);
      downloadValidatedProject(result);
      uiDispatch({ type: 'HIDE_MODAL', name: 'saveModal' });
    } catch (error) {
      uiDispatch({
        type: 'SET_FIELD',
        field: 'error',
        value: projectSecurityMessage(error),
      });
    } finally {
      uiDispatch({ type: 'SET_LOADING', isLoading: false });
    }
  }, [configState, conversionState, uiState, mergeState, uiDispatch]);

  // -----------------------------------------------------------------------
  // Transactional import — inspect before prompting, open before application.
  // -----------------------------------------------------------------------
  const clearPendingImport = useCallback(() => {
    pendingImportRef.current = null;
  }, []);

  const invalidatePendingImport = useCallback(() => {
    readGenerationRef.current += 1;
    confirmAttemptRef.current += 1;
    clearPendingImport();
    validatedImportRef.current = null;
  }, [clearPendingImport]);

  useEffect(() => () => {
    readGenerationRef.current += 1;
    confirmAttemptRef.current += 1;
    pendingImportRef.current = null;
    validatedImportRef.current = null;
  }, []);

  const handleLoadProjectFile = useCallback((e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = '';

    invalidatePendingImport();
    const generation = readGenerationRef.current;
    uiDispatch({ type: 'SET_LOADING', isLoading: false });
    uiDispatch({ type: 'HIDE_MODAL', name: 'projectSecurityImport' });
    uiDispatch({ type: 'HIDE_MODAL', name: 'loadConfirm' });
    uiDispatch({ type: 'CLEAR_ERROR' });

    if (file.size > MAX_PROJECT_FILE_BYTES) {
      uiDispatch({
        type: 'SET_FIELD',
        field: 'error',
        value: projectSecurityMessage({ code: 'oversized_project' }, 'import'),
      });
      return;
    }

    const failImport = error => {
      if (generation !== readGenerationRef.current) return;
      invalidatePendingImport();
      uiDispatch({
        type: 'SET_FIELD',
        field: 'error',
        value: projectSecurityMessage(error, 'import'),
      });
    };

    try {
      const reader = new FileReader();
      reader.onload = (event) => {
        if (generation !== readGenerationRef.current) return;
        try {
          const serialized = event.target.result;
          const inspected = inspectProjectImport(serialized);
          if (inspected.kind === PROJECT_SECURITY_MODES.SANITIZED
              && inspected.requiresConfirmation !== true) {
            clearPendingImport();
            const staged = prepareValidatedImportCandidate(
              inspected.envelope,
              inspected.security,
              inspected.warnings,
            );
            validatedImportRef.current = staged.candidate;
            uiDispatch({
              type: 'SHOW_MODAL',
              name: 'loadConfirm',
              value: staged.confirmation,
            });
          } else {
            pendingImportRef.current = {
              serialized,
              kind: inspected.kind,
              requiresConfirmation: inspected.requiresConfirmation === true,
            };
            uiDispatch({
              type: 'SHOW_MODAL',
              name: 'projectSecurityImport',
              value: safeImportDescriptor(inspected),
            });
          }
        } catch (error) {
          failImport(error);
        }
      };
      reader.onerror = () => {
        failImport({ code: 'invalid_project' });
      };
      reader.readAsText(file);
    } catch {
      failImport({ code: 'invalid_project' });
    }
  }, [clearPendingImport, invalidatePendingImport, uiDispatch]);

  const confirmPendingImport = useCallback(async ({ passphrase, acknowledgement } = {}) => {
    const attempt = confirmAttemptRef.current + 1;
    confirmAttemptRef.current = attempt;
    const pending = pendingImportRef.current;
    if (!pending) {
      uiDispatch({ type: 'SET_LOADING', isLoading: false });
      uiDispatch({
        type: 'SET_FIELD',
        field: 'error',
        value: projectSecurityMessage({ code: 'invalid_project' }, 'import'),
      });
      return;
    }
    if (pending.requiresConfirmation && acknowledgement !== true) {
      uiDispatch({ type: 'SET_LOADING', isLoading: false });
      uiDispatch({
        type: 'SET_FIELD',
        field: 'error',
        value: projectSecurityMessage({ code: 'invalid_confirmation' }, 'import'),
      });
      return;
    }
    const generation = readGenerationRef.current;
    const isCurrentAttempt = () => (
      generation === readGenerationRef.current
      && attempt === confirmAttemptRef.current
    );

    uiDispatch({ type: 'SET_LOADING', isLoading: true, message: 'Opening project...' });
    uiDispatch({ type: 'CLEAR_ERROR' });
    try {
      const options = pending.kind === PROJECT_SECURITY_MODES.REVERSIBLE
        ? { passphrase }
        : {};
      const opened = await openProjectImport(pending.serialized, options);
      if (!isCurrentAttempt()) return;
      const staged = prepareValidatedImportCandidate(
        opened.project,
        opened.security,
        opened.warnings,
      );
      uiDispatch({ type: 'SET_LOADING', isLoading: false });
      invalidatePendingImport();
      validatedImportRef.current = staged.candidate;
      uiDispatch({ type: 'HIDE_MODAL', name: 'projectSecurityImport' });
      uiDispatch({
        type: 'SHOW_MODAL',
        name: 'loadConfirm',
        value: staged.confirmation,
      });
    } catch (error) {
      if (!isCurrentAttempt()) return;
      const errorCode = error && typeof error === 'object'
        ? ownDataValue(error, 'code')
        : undefined;
      if (!RETRYABLE_IMPORT_CODES.has(errorCode)) {
        uiDispatch({ type: 'SET_LOADING', isLoading: false });
        invalidatePendingImport();
        uiDispatch({ type: 'HIDE_MODAL', name: 'projectSecurityImport' });
      }
      uiDispatch({
        type: 'SET_FIELD',
        field: 'error',
        value: projectSecurityMessage(error, 'import'),
      });
    } finally {
      if (isCurrentAttempt()) {
        uiDispatch({ type: 'SET_LOADING', isLoading: false });
      }
    }
  }, [invalidatePendingImport, uiDispatch]);

  const cancelPendingImport = useCallback(() => {
    invalidatePendingImport();
    uiDispatch({ type: 'SET_LOADING', isLoading: false });
    uiDispatch({ type: 'HIDE_MODAL', name: 'projectSecurityImport' });
  }, [invalidatePendingImport, uiDispatch]);

  const cancelValidatedImportReview = useCallback(() => {
    invalidatePendingImport();
    uiDispatch({ type: 'SET_LOADING', isLoading: false });
    uiDispatch({ type: 'HIDE_MODAL', name: 'loadConfirm' });
  }, [invalidatePendingImport, uiDispatch]);

  // -----------------------------------------------------------------------
  // applyLoadedProject — restore all state from a project, dispatch
  //                       LOAD_PROJECT to all contexts
  // -----------------------------------------------------------------------
  const applyLoadedProject = useCallback((project, security) => {
    const validated = validatedImportRef.current;
    if (!validated
        || validated.confirmationProject !== project
        || security !== undefined && validated.confirmationSecurity !== security) {
      invalidatePendingImport();
      uiDispatch({
        type: 'SET_FIELD',
        field: 'error',
        value: projectSecurityMessage({ code: 'invalid_project' }, 'import'),
      });
      return;
    }
    invalidatePendingImport();
    const s = validated.snapshot.project.state;

    // The previous project's undo history must not be restorable over this one
    undoDispatch({ type: 'CLEAR' });

    // Dispatch LOAD_PROJECT to each context with its relevant state subset
    configDispatch({
      type: 'LOAD_PROJECT',
      state: {
        configText: s.configText ?? '',
        intermediateConfig: s.intermediateConfig ?? null,
        sourceVendor: s.sourceVendor ?? 'panos',
        sourceModel: s.sourceModel ?? '',
        targetModel: s.targetModel ?? '',
        srxLicense: s.srxLicense ?? '',
        portProfile: s.portProfile ?? null,
        siteName: s.siteName ?? '',
        siteGroup: s.siteGroup ?? '',
        interfaceMappings: s.interfaceMappings ?? {},
        isSanitized: s.isSanitized ?? false,
        sanitizationTable: s.sanitizationTable ?? null,
        projectSecurityMode: validated.snapshot.security.mode,
        parseWarnings: s.parseWarnings ?? [],
        parseStats: s.parseStats ?? null,
        warningStatuses: s.warningStatuses ?? {},
        srxTranslatedPolicies: s.srxTranslatedPolicies ?? null,
        ruleGroups: s.ruleGroups ?? [],
        sectionAcceptance: s.sectionAcceptance ?? {},
        greenfieldMode: s.greenfieldMode ?? false,
        greenfieldTemplate: s.greenfieldTemplate ?? null,
        selectedRuleKeys: [],
        lastClickedKey: null,
      },
    });

    conversionDispatch({
      type: 'LOAD_PROJECT',
      state: {
        srxOutput: s.srxOutput ?? null,
        convertWarnings: s.convertWarnings ?? [],
        conversionSummary: s.conversionSummary ?? null,
        outputFormat: s.outputFormat ?? 'set',
        targetContext: s.targetContext ?? { type: 'none', name: '' },
      },
    });

    mergeDispatch({
      type: 'LOAD_PROJECT',
      state: {
        mergeMode: s.mergeMode ?? false,
        configSlots: s.configSlots ?? [],
        activeSlotIndex: s.activeSlotIndex ?? 0,
        crossLsLinks: s.crossLsLinks ?? [],
      },
    });

    // Reset transient UI state
    uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: s.editTab ?? 'rules' });
    uiDispatch({ type: 'SET_FIELD', field: 'platformView', value: s.platformView ?? 'panos' });
    uiDispatch({ type: 'SET_FIELD', field: 'bottomTab', value: s.bottomTab ?? 'output' });
    uiDispatch({ type: 'SET_FIELD', field: 'selectedRule', value: null });
    uiDispatch({ type: 'CLEAR_ERROR' });
    uiDispatch({ type: 'SET_LOADING', isLoading: false });
    uiDispatch({ type: 'HIDE_MODAL', name: 'modelSelector' });
    uiDispatch({ type: 'HIDE_MODAL', name: 'interfaceMapper' });
    uiDispatch({ type: 'HIDE_MODAL', name: 'llmWarning' });
    uiDispatch({ type: 'HIDE_MODAL', name: 'loadConfirm' });
    uiDispatch({ type: 'HIDE_MODAL', name: 'projectSecurityImport' });
    uiDispatch({
      type: 'SET_FIELD',
      field: 'llmWarningDismissed',
      value: s.isSanitized || s.greenfieldMode || false,
    });
  }, [configDispatch, conversionDispatch, invalidatePendingImport, mergeDispatch, undoDispatch, uiDispatch]);

  // -----------------------------------------------------------------------
  // resetWorkspace — clear all working-data contexts and transient UI state,
  //                  preserving localStorage-backed preferences
  // -----------------------------------------------------------------------
  const resetWorkspace = useCallback(() => {
    invalidatePendingImport();

    // Working-data contexts -> back to their initial states
    configDispatch({ type: 'RESET' });
    conversionDispatch({ type: 'RESET' });
    mergeDispatch({ type: 'RESET' });
    undoDispatch({ type: 'CLEAR' });

    // Transient UI state -> defaults (does NOT touch llmRiskAcceptance,
    // layout widths/collapse, or other settings-derived UI fields)
    uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'import' });
    uiDispatch({ type: 'SET_FIELD', field: 'platformView', value: 'panos' });
    uiDispatch({ type: 'SET_FIELD', field: 'bottomTab', value: 'output' });
    uiDispatch({ type: 'SET_FIELD', field: 'selectedRule', value: null });
    uiDispatch({ type: 'SET_FIELD', field: 'isTranslating', value: false });
    uiDispatch({ type: 'SET_FIELD', field: 'translationError', value: null });
    uiDispatch({ type: 'SET_FIELD', field: 'translationProgress', value: null });
    uiDispatch({ type: 'SET_FIELD', field: 'groupingInProgress', value: false });
    uiDispatch({ type: 'SET_FIELD', field: 'llmWarningDismissed', value: false });
    uiDispatch({ type: 'CLEAR_ERROR' });
    uiDispatch({ type: 'SET_LOADING', isLoading: false });
    uiDispatch({ type: 'HIDE_MODAL', name: 'modelSelector' });
    uiDispatch({ type: 'HIDE_MODAL', name: 'interfaceMapper' });
    uiDispatch({ type: 'HIDE_MODAL', name: 'llmWarning' });
    uiDispatch({ type: 'HIDE_MODAL', name: 'loadConfirm' });
    uiDispatch({ type: 'HIDE_MODAL', name: 'projectSecurityImport' });
    uiDispatch({ type: 'HIDE_MODAL', name: 'resetConfirm' });
  }, [configDispatch, conversionDispatch, invalidatePendingImport, mergeDispatch, undoDispatch, uiDispatch]);

  // -----------------------------------------------------------------------
  // generateName — convenience wrapper around generateProjectName
  // -----------------------------------------------------------------------
  const generateName = useCallback(() => {
    return generateProjectName(
      configState.sourceVendor,
      configState.sourceModel,
      configState.siteName,
    );
  }, [configState.sourceVendor, configState.sourceModel, configState.siteName]);

  // -----------------------------------------------------------------------
  // Return public API
  // -----------------------------------------------------------------------
  return {
    getExportDescriptor,
    handleExportProject,
    handleLoadProjectFile,
    confirmPendingImport,
    applyLoadedProject,
    cancelPendingImport,
    cancelValidatedImportReview,
    resetWorkspace,
    generateName,
  };
}
