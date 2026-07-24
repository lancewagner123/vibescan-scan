#!/usr/bin/env node
'use strict';

// VibeScan CLI. Usage:
//   vibescan scan [path] [--fail-on <severity>]
//
// Runs the full scan -> triage -> render pipeline against [path] (default: cwd),
// prints a terminal-friendly summary, and writes the full Markdown report to
// ./vibescan-report.md and the raw + triaged JSON to ./vibescan-report.json
// (both written relative to the current working directory, not the scanned path).
//
// --fail-on <critical|high|medium|low> makes the process exit 1 if any finding is at or
// above that severity (opt-in; omitting it preserves the always-exit-0 report-only
// behavior relied on by anyone already using vibescan non-gating).

const fs = require('fs');
const path = require('path');
const { parseArgs } = require('util');

const { run } = require('../src/index');

const USAGE = `Usage: vibescan scan [path] [--fail-on <severity>]

  scan [path]   Scan a repository for security issues (default path: current directory)

  --fail-on <severity>
                Exit with a non-zero status code if any finding is at or above the given
                severity (critical, high, medium, low). Severity ranking, most to least
                severe: critical > high > medium > low. Omit this flag to always exit 0
                (the default, non-gating "just show me a report" behavior).

Writes:
  ./vibescan-report.md    Full Markdown report
  ./vibescan-report.json  Raw + triaged findings as JSON
`;

// Same severity ranking used internally by src/triage/triage.js's reconcileWithSource /
// SEVERITY_RANK -- critical is most severe, low is least. Kept in sync deliberately
// rather than re-derived, since triage.js does not export its rank table.
const FAIL_ON_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

async function main() {
  const argv = process.argv.slice(2);
  const command = argv[0];

  if (!command || command === '--help' || command === '-h') {
    process.stdout.write(USAGE);
    process.exit(command ? 0 : 1);
    return;
  }

  if (command !== 'scan') {
    process.stderr.write(`Unknown command: ${command}\n\n${USAGE}`);
    process.exit(1);
    return;
  }

  const { positionals, values } = parseArgs({
    args: argv.slice(1),
    allowPositionals: true,
    options: {
      'fail-on': { type: 'string' },
    },
  });

  const failOn = values['fail-on'];
  if (failOn !== undefined && !Object.prototype.hasOwnProperty.call(FAIL_ON_RANK, failOn)) {
    process.stderr.write(
      `vibescan: --fail-on must be one of: ${Object.keys(FAIL_ON_RANK).join(', ')} (got "${failOn}")\n`
    );
    process.exit(1);
    return;
  }

  const targetPath = path.resolve(positionals[0] || process.cwd());

  if (!fs.existsSync(targetPath) || !fs.statSync(targetPath).isDirectory()) {
    process.stderr.write(`vibescan: "${targetPath}" does not exist or is not a directory.\n`);
    process.exit(1);
    return;
  }

  let result;
  try {
    result = await run(targetPath);
  } catch (err) {
    process.stderr.write(`vibescan: scan failed: ${err.stack || err.message}\n`);
    process.exit(1);
    return;
  }

  console.log(result.terminalSummary);

  const outDir = process.cwd();
  const mdPath = path.join(outDir, 'vibescan-report.md');
  const jsonPath = path.join(outDir, 'vibescan-report.json');

  fs.writeFileSync(mdPath, result.markdown, 'utf8');
  fs.writeFileSync(
    jsonPath,
    JSON.stringify({ raw: result.raw, triaged: result.triaged }, null, 2),
    'utf8'
  );

  console.log('');
  console.log(`Full report written to ${mdPath}`);
  console.log(`Raw JSON written to ${jsonPath}`);

  if (failOn !== undefined) {
    const summary = (result.triaged && result.triaged.summary) || {};
    const threshold = FAIL_ON_RANK[failOn];
    const shouldFail = Object.keys(FAIL_ON_RANK).some((severity) => {
      return FAIL_ON_RANK[severity] >= threshold && (summary[severity] || 0) > 0;
    });
    if (shouldFail) {
      process.exit(1);
      return;
    }
  }
}

main().catch((err) => {
  process.stderr.write(`vibescan: unexpected error: ${err.stack || err.message}\n`);
  process.exit(1);
});
