'use strict';
// Evasion for check 5 (eval-on-input): argLooksInterpolated() only flags eval()/exec()/
// execSync() when the call's argument textually looks like (a) a template literal
// containing ${...}, (b) a direct string-literal + variable concatenation, or (c) a bare
// identifier/member expression. Wrapping the actual interpolation inside a helper
// function call changes the argument's shape to "identifier(identifier)" -- which
// matches none of those three regexes, since it contains parentheses -- while the
// runtime behavior (unsanitized request input flowing into a shell command string) is
// unchanged from the seeded vulnerable-demo-app sample.
const { execSync } = require('child_process');

function buildDiagnosticsScript(hostname) {
  return `ping -n 1 ${hostname}`; // still directly interpolates unsanitized input
}

function runDiagnostics(req) {
  // req.query.host flows into a shell command exactly like the seeded fixture, but the
  // call site argument is `buildDiagnosticsScript(req.query.host)` -- a function-call
  // expression, not a template literal or bare identifier -- which evades every branch
  // of argLooksInterpolated().
  return execSync(buildDiagnosticsScript(req.query.host)).toString();
}

function buildExpression(userCode) {
  return '(' + userCode + ')';
}

function evaluateUserExpression(req) {
  // Same indirection trick against eval() itself.
  return eval(buildExpression(req.body.code));
}

module.exports = { runDiagnostics, evaluateUserExpression };
