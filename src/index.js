'use strict';

// Orchestrates the full VibeScan pipeline: scanRepo -> triage -> render.
// This is the single programmatic entry point other code (the CLI, tests, a future
// GitHub Action) should call rather than wiring the three stages together itself.

const { scanRepo } = require('./scanners');
const { triage } = require('./triage');
const { renderMarkdown, renderTerminalSummary } = require('./report/render');

/**
 * Run the full VibeScan pipeline against a repo on disk.
 *
 * @param {string} repoPath - absolute (or cwd-relative) path to the target repo.
 * @param {object} [opts]
 * @param {number} [opts.maxCommits] - passed through to scanRepo (git-history cap).
 * @param {string[]} [opts.skip] - scanner module names to skip, passed through to scanRepo.
 * @param {string} [opts.apiKey] - passed through to triage (overrides ANTHROPIC_API_KEY).
 * @param {string} [opts.model] - passed through to triage.
 * @param {number} [opts.maxTokens] - passed through to triage.
 * @param {number} [opts.maxRetries] - passed through to triage.
 * @returns {Promise<{raw: object[], triaged: object, markdown: string, terminalSummary: string}>}
 */
async function run(repoPath, opts = {}) {
  const raw = scanRepo(repoPath, opts);
  const triaged = await triage(raw, opts);
  const markdown = renderMarkdown(triaged);
  const terminalSummary = renderTerminalSummary(triaged);

  return { raw, triaged, markdown, terminalSummary };
}

module.exports = { run };
