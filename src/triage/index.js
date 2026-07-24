'use strict';

const { triage, ruleBasedFallback, validateTriageOutputShape } = require('./triage');
const { SYSTEM_PROMPT, buildUserMessage } = require('./prompt');

module.exports = {
  triage,
  // Exposed for callers that want to build/inspect the prompt directly (e.g. tests,
  // or a caller that wants to call the Anthropic API itself with a custom client).
  SYSTEM_PROMPT,
  buildUserMessage,
  // Exposed for callers that want to force the deterministic path, or validate a
  // Triage Output Schema object they got from somewhere else.
  ruleBasedFallback,
  validateTriageOutputShape,
};
