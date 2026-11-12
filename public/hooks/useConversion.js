/**
 * useConversion — Conversion handler hook
 *
 * Provides handlers for converting parsed intermediate configs
 * (single or merged) to SRX set/XML output format.
 * Uses ConfigContext, ConversionContext, UIContext, and MergeContext.
 */
import { useCallback } from 'react';
import { useConfigContext } from '../contexts/ConfigContext.jsx';
import { useConversionContext } from '../contexts/ConversionContext.jsx';
import { useUIContext } from '../contexts/UIContext.jsx';
import { useMergeContext } from '../contexts/MergeContext.jsx';
import { convertConfig, mergeConvert } from '../utils/engine.js';
import { resolveConversionOptions } from '../utils/conversion-options.js';
import { resolveAssistModel } from '../utils/llm-attribution.js';
import { loadLLMSettings } from '../utils/llm-settings.js';
import { validateHardwareCapacity } from '../data/hardware-db.js';
import { JunosIdentifierPlanningError } from '../../src/security/junos-identifiers.js';
import { JunosSerializationError } from '../../src/security/junos-serialization.js';
import {
  ConversionOutputError,
  filterEffectiveSetCommands,
  replaceSetCommands,
} from '../../src/conversion/conversion-output.js';

const SAFE_STRUCTURAL_PATH = /^[A-Za-z_][A-Za-z0-9_]*(?:\[\d+\]|\.[A-Za-z_][A-Za-z0-9_]*)*$/u;

function safeJunosPlanningPath(candidate) {
  if (typeof candidate !== 'string') return undefined;
  const structuralPath = candidate.split('#', 1)[0];
  return SAFE_STRUCTURAL_PATH.test(structuralPath) ? structuralPath : undefined;
}

/**
 * Policies that handleConvert will export: the translated set when present,
 * otherwise the source rules. The acceptance gate must check the same set.
 */
export function getExportPolicies(srxTranslatedPolicies, intermediateConfig) {
  return srxTranslatedPolicies || intermediateConfig?.security_policies || [];
}

export function formatJunosSerializationError(error, prefix) {
  if (error instanceof JunosIdentifierPlanningError) {
    const location = safeJunosPlanningPath(error.referencePaths?.[0])
      || safeJunosPlanningPath(error.definitionPaths?.[0]);
    return `${prefix} blocked: ${error.code}${location ? ` at ${location}` : ''} — ${error.reason}`;
  }
  if (error instanceof JunosSerializationError) {
    return `${prefix} blocked: ${error.fieldPath} — ${error.reason}`;
  }
  if (error instanceof ConversionOutputError) {
    return `${prefix} blocked: ${error.reason}`;
  }
  return `${prefix} error: ${error instanceof Error ? error.message : 'Unexpected conversion failure'}`;
}

export default function useConversion() {
  const { state: configState } = useConfigContext();
  const { state: conversionState, dispatch: conversionDispatch } = useConversionContext();
  const { state: uiState, dispatch: uiDispatch } = useUIContext();
  const { state: mergeState } = useMergeContext();

  const {
    intermediateConfig,
    srxTranslatedPolicies,
    ruleGroups,
    interfaceMappings,
    siteName,
    siteGroup,
    targetModel,
    srxLicense,
  } = configState;

  const { targetContext } = conversionState;

  // -----------------------------------------------------------------------
  // handleConvert — convert a single parsed config to SRX output
  // -----------------------------------------------------------------------
  const handleConvert = useCallback(async (format = 'set', overrides = {}) => {
    if (!intermediateConfig) return;

    uiDispatch({ type: 'SET_LOADING', isLoading: true, message: 'Converting to SRX format...' });
    uiDispatch({ type: 'CLEAR_ERROR' });
    conversionDispatch({ type: 'CLEAR_OUTPUT' });

    try {
      // Merge translated policies into the config for conversion
      let configForConversion = srxTranslatedPolicies
        ? { ...intermediateConfig, security_policies: srxTranslatedPolicies }
        : { ...intermediateConfig };

      // Attach rule groups for group comment output
      if (ruleGroups && ruleGroups.length > 0) {
        configForConversion._rule_groups = ruleGroups;
      }

      // Inject site identification metadata for output headers
      if (siteName || siteGroup) {
        configForConversion.metadata = {
          ...configForConversion.metadata,
          siteName: siteName || undefined,
          siteGroup: siteGroup || undefined,
        };
      }

      const data = await convertConfig(
        configForConversion,
        format,
        interfaceMappings,
        targetContext.type !== 'none' ? targetContext : null,
        // Overrides win over uiState so a just-changed selector takes effect
        // immediately, before its dispatch has propagated (stale-closure fix).
        // llmModel stamps which model assisted (empty when purely deterministic).
        {
          ...resolveConversionOptions(uiState, overrides),
          llmModel: resolveAssistModel(configForConversion.security_policies, loadLLMSettings()),
        },
      );

      // Append hardware capacity warnings if target model is set
      const convWarnings = [...(data.output.warnings || [])];
      const capacityIssues = validateHardwareCapacity(targetModel, configForConversion);
      for (const issue of capacityIssues) {
        convWarnings.push({
          type: issue.severity === 'error' ? 'unsupported' : 'warning',
          category: 'capacity',
          message: `${issue.metric}: ${issue.current.toLocaleString()} of ${issue.limit.toLocaleString()} (${issue.pct}%) — ${issue.severity === 'error' ? 'EXCEEDS' : 'approaching'} ${targetModel} limit`,
          context: issue.metric,
          subType: 'hardware_capacity',
        });
      }

      conversionDispatch({
        type: 'SET_CONVERSION_RESULT',
        output: data.output,
        warnings: convWarnings,
        summary: data.output.summary || null,
        format,
      });

      // Switch to Output > SRX Config in the nav tree
      uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'output' });
    } catch (err) {
      conversionDispatch({ type: 'CLEAR_OUTPUT' });
      uiDispatch({
        type: 'SET_FIELD',
        field: 'error',
        value: formatJunosSerializationError(err, 'Conversion'),
      });
    } finally {
      uiDispatch({ type: 'SET_LOADING', isLoading: false });
    }
  }, [intermediateConfig, interfaceMappings, srxTranslatedPolicies, ruleGroups, siteName, siteGroup, targetModel, targetContext, uiState?.policyStructure, uiState?.deploymentMode, conversionDispatch, uiDispatch]);

  // -----------------------------------------------------------------------
  // handleConvertClick — warn if not all rules accepted, else convert
  // -----------------------------------------------------------------------
  const handleConvertClick = useCallback((format = 'set') => {
    // Check if all rules are accepted
    const policies = getExportPolicies(srxTranslatedPolicies, intermediateConfig);
    const accepted = policies.filter(r => r._review_status === 'accepted' || r.disabled).length;
    const allAccepted = policies.length > 0 && accepted === policies.length;

    if (!allAccepted) {
      uiDispatch({ type: 'SHOW_MODAL', name: 'convertConfirm' });
      return;
    }
    handleConvert(format);
  }, [srxTranslatedPolicies, intermediateConfig, handleConvert, uiDispatch]);

  // -----------------------------------------------------------------------
  // handleMergeConvert — convert all parsed merge-mode slots to SRX output
  // -----------------------------------------------------------------------
  const handleMergeConvert = useCallback(async (format = 'set') => {
    const { configSlots, crossLsLinks } = mergeState;
    const parsedSlots = configSlots.filter(s => s.intermediateConfig);
    if (parsedSlots.length === 0) return;

    uiDispatch({ type: 'SET_LOADING', isLoading: true, message: 'Merging and converting to SRX format...' });
    uiDispatch({ type: 'CLEAR_ERROR' });
    conversionDispatch({ type: 'CLEAR_OUTPUT' });

    try {
      const slotsPayload = parsedSlots.map(slot => ({
        lsName: slot.lsName,
        intermediateConfig: slot.srxTranslatedPolicies
          ? { ...slot.intermediateConfig, security_policies: slot.srxTranslatedPolicies }
          : slot.intermediateConfig,
        interfaceMappings: slot.interfaceMappings,
      }));

      // Extract global config (HA from first slot that has it, syslog aggregated)
      const globalConfig = {
        ha_config: parsedSlots.find(s => s.intermediateConfig.ha_config?.enabled)?.intermediateConfig.ha_config || { enabled: false },
        syslog_config: parsedSlots.flatMap(s => s.intermediateConfig.syslog_config || []),
        llmModel: resolveAssistModel(
          parsedSlots.flatMap(s => s.intermediateConfig.security_policies || []),
          loadLLMSettings(),
        ),
      };

      const data = await mergeConvert(slotsPayload, crossLsLinks, format, globalConfig);

      conversionDispatch({
        type: 'SET_CONVERSION_RESULT',
        output: data.output,
        warnings: data.output.warnings || [],
        summary: data.output.summary || null,
        format,
      });

      uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'output' });
    } catch (err) {
      conversionDispatch({ type: 'CLEAR_OUTPUT' });
      uiDispatch({
        type: 'SET_FIELD',
        field: 'error',
        value: formatJunosSerializationError(err, 'Merge conversion'),
      });
    } finally {
      uiDispatch({ type: 'SET_LOADING', isLoading: false });
    }
  }, [mergeState, conversionDispatch, uiDispatch]);

  // -----------------------------------------------------------------------
  // handleValidate — run SRX validation engine against current output
  // -----------------------------------------------------------------------
  const handleValidate = useCallback(async (enforceLicense = false) => {
    const { srxOutput } = conversionState;
    if (!srxOutput) {
      uiDispatch({ type: 'SET_FIELD', field: 'error', value: 'Validation blocked: No SRX output is available.' });
      return;
    }

    uiDispatch({ type: 'SET_LOADING', isLoading: true, message: 'Running validation checks...' });

    try {
      const [
        { runValidation },
        { SRX_MODELS, SRX_CAPACITY_LIMITS },
      ] = await Promise.all([
        import('../../src/validators/srx-validation-engine.js'),
        import('../data/hardware-db.js'),
      ]);

      const result = runValidation({
        intermediateConfig,
        conversionOutput: srxOutput,
        targetModel,
        srxLicense,
        enforceLicense,
        modelDb: SRX_MODELS,
        capacityLimits: SRX_CAPACITY_LIMITS,
        sourceModel: null,
      });

      // Replace previous validation warnings, keep non-validation warnings
      const existingNonValidation = (conversionState.convertWarnings || []).filter(w => w._source !== 'validation');
      const newWarnings = [...existingNonValidation, ...result.findings];

      if (result.filteredCommands !== null) {
        if (filterEffectiveSetCommands(result.filteredCommands).length === 0) {
          conversionDispatch({ type: 'CLEAR_OUTPUT' });
          conversionDispatch({ type: 'SET_FIELD', field: 'convertWarnings', value: newWarnings });
          conversionDispatch({ type: 'SET_FIELD', field: 'validationFindings', value: result.findings });
          uiDispatch({
            type: 'SET_FIELD',
            field: 'error',
            value: 'License enforcement blocked all generated commands; output, export, and push have been disabled.',
          });
          return;
        }
        const updatedOutput = replaceSetCommands(srxOutput, result.filteredCommands);
        conversionDispatch({
          type: 'SET_CONVERSION_RESULT',
          output: updatedOutput,
          warnings: newWarnings,
          summary: updatedOutput.summary ?? conversionState.conversionSummary,
          validationFindings: result.findings,
        });
      } else {
        conversionDispatch({ type: 'SET_FIELD', field: 'convertWarnings', value: newWarnings });
        conversionDispatch({ type: 'SET_FIELD', field: 'validationFindings', value: result.findings });
      }

      // Navigate to warnings panel
      uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: 'warnings' });
    } catch (err) {
      uiDispatch({
        type: 'SET_FIELD',
        field: 'error',
        value: formatJunosSerializationError(err, 'Validation'),
      });
    } finally {
      uiDispatch({ type: 'SET_LOADING', isLoading: false });
    }
  }, [intermediateConfig, targetModel, srxLicense, conversionState, conversionDispatch, uiDispatch]);

  // -----------------------------------------------------------------------
  // Return public API
  // -----------------------------------------------------------------------
  return {
    // Conversion state (read-only)
    ...conversionState,

    // Handlers
    handleConvertClick,
    handleConvert,
    handleMergeConvert,
    handleValidate,
  };
}
