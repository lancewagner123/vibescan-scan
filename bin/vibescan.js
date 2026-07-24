#!/usr/bin/env node
'use strict';

// VibeScan CLI. Usage:
//   vibescan scan [path]
//
// Runs the full scan -> triage -> render pipeline against [path] (default: cwd),
// prints a terminal-friendly summary, and writes the full Markdown report to
// ./vibescan-report.md and the raw + triaged JSON to ./vibescan-report.json
// (both written relative to the current working directory, not the scanned path).

const fs = require('fs');
const path = require('path');
const { parseArgs } = require('util');

const { run } = require('../src/index');

const USAGE = `Usage: vibescan scan [path]

  scan [path]   Scan a repository for security issues (default path: current directory)

Writes:
  ./vibescan-report.md    Full Markdown report
  ./vibescan-report.json  Raw + triaged findings as JSON
`;

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

  const { positionals } = parseArgs({
    args: argv.slice(1),
    allowPositionals: true,
    options: {},
  });

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
}

main().catch((err) => {
  process.stderr.write(`vibescan: unexpected error: ${err.stack || err.message}\n`);
  process.exit(1);
});
