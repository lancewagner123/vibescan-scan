'use strict';

// Native scanner core — no external binaries (gitleaks/semgrep are not used; every
// check below is implemented directly in Node.js). Exports scanRepo(repoPath, opts),
// which runs all five scanner modules and returns a flat array of Finding objects
// (matching docs/FINDINGS_SCHEMA.md exactly) plus a warnings array for anything that
// couldn't run.

const path = require('path');
const fs = require('fs');

const secrets = require('./secrets');
const gitHistory = require('./git-history');
const staticChecks = require('./static-checks');
const dependencies = require('./dependencies');

const SCANNER_MODULES = [
  { name: 'secrets', module: secrets },
  { name: 'git-history', module: gitHistory },
  { name: 'static-checks', module: staticChecks },
  { name: 'dependencies', module: dependencies },
];

/**
 * Run every scanner module against a target repo's working tree.
 *
 * Returns a plain array of Finding objects (exactly matching docs/FINDINGS_SCHEMA.md) —
 * `Array.isArray(scanRepo(...))` is true and it iterates/maps/filters like any array of
 * findings. A non-index `warnings` property is attached to that same array (any scanner
 * module that couldn't run, e.g. pip-audit missing, or `git` unavailable) — it rides
 * along on the array object without changing its length or breaking array semantics;
 * JSON.stringify()/for-of/map only ever see the indexed Finding elements.
 *
 * @param {string} repoPath - absolute (or cwd-relative) path to the target repo.
 * @param {object} [opts]
 * @param {number} [opts.maxCommits] - cap on commits walked by git-history.js (default 500).
 * @param {string[]} [opts.skip] - scanner module names to skip entirely, e.g. ['dependencies'].
 * @returns {object[] & { warnings: string[] }}
 */
function scanRepo(repoPath, opts = {}) {
  const resolvedPath = path.resolve(repoPath);
  const warnings = [];
  let findings = [];

  if (!fs.existsSync(resolvedPath) || !fs.statSync(resolvedPath).isDirectory()) {
    warnings.push(`index.js: target path "${resolvedPath}" does not exist or is not a directory — scan aborted.`);
    findings.warnings = warnings;
    return findings;
  }

  const skip = new Set(opts.skip || []);

  for (const { name, module } of SCANNER_MODULES) {
    if (skip.has(name)) {
      warnings.push(`index.js: scanner "${name}" skipped (explicitly requested via opts.skip).`);
      continue;
    }
    try {
      const result = module.scan(resolvedPath, opts);
      const modFindings = (result && result.findings) || [];
      const modWarnings = (result && result.warnings) || [];
      findings = findings.concat(modFindings);
      warnings.push(...modWarnings);
    } catch (err) {
      warnings.push(`index.js: scanner "${name}" threw and was skipped: ${err.message}`);
    }
  }

  findings.warnings = warnings;
  return findings;
}

module.exports = { scanRepo };
