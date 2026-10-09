/**
 * Unified LLM API Client
 * ========================
 * Phase 3 Feature
 *
 * Provides a unified interface for communicating with different LLM providers.
 * API keys are stored in the browser's localStorage and sent directly from
 * the frontend to the LLM provider — never touching this server.
 *
 * Provider selection and API calls are implemented by the browser-side client
 * in public/utils/llm-client.js. The UI defaults to Claude when AI is enabled,
 * switches to Ollama for local-only mode, and supports a deterministic No-AI
 * mode that makes no LLM calls.
 *
 * This server-side module provides helper functions for prompt construction;
 * actual API calls happen client-side.
 */

/**
 * Builds a system prompt for the interview LLM based on the parsed config context.
 * Phase 3 implementation.
 *
 * @param {Object} intermediateConfig - Parsed intermediate JSON
 * @returns {string} - System prompt for the LLM
 */
export function buildInterviewSystemPrompt(intermediateConfig) {
  return 'You are a firewall policy conversion expert. Help the user resolve ambiguities in their PAN-OS to SRX conversion.';
}
