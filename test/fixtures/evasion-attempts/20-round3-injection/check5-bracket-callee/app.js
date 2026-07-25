'use strict';

// EVASION (round 3): check 5 (eval-on-input) via BRACKET-NOTATION / computed access on the
// child_process module. DANGEROUS_CALLEE_RE is /\b(eval|new\s+Function|exec|execSync)\s*\(/
// -- it requires the callee name to be immediately followed (after optional whitespace) by
// `(`. Reaching execSync through a computed key (`cp['execSync'](...)`) puts a `']` between
// the name and the `(`, so the dangerous call is never recognized. The file still clearly
// references child_process, so the RegExp#exec gating is satisfied.
const cp = require('child_process');

function handler(req, res) {
  const userCmd = req.query.cmd;
  const out = cp['execSync']('ls ' + userCmd);
  res.send(out.toString());
}

module.exports = { handler };
