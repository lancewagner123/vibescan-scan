'use strict';

// Positive control (regression protection, NOT a false positive): a genuine
// child_process.exec()/execSync() shell-injection risk, sitting in the same folder as the
// RegExp#exec false positives above specifically to prove the receiver-tracing fix in
// checkEvalOnInput() didn't overcorrect into silence. All three call shapes below must
// still produce an eval-on-input finding:
//   1. destructured bare exec() with interpolated input
//   2. destructured bare execSync() with interpolated input
//   3. child_process.exec() via the namespace import, with interpolated input
const { exec, execSync } = require('child_process');
const child_process = require('child_process');

function pingHost(req) {
  // Bare destructured exec(), interpolated request input -- classic shell injection.
  exec(`ping -c 1 ${req.query.host}`, (err, stdout) => stdout);
}

function runDiagnostics(req) {
  return execSync(`traceroute ${req.query.host}`).toString();
}

function listUserDirectory(req) {
  return child_process.exec('ls ' + req.query.dir);
}

module.exports = { pingHost, runDiagnostics, listUserDirectory };
