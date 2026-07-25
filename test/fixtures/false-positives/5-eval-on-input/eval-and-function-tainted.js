'use strict';

// Positive control (regression protection, NOT a false positive): eval() and
// new Function() called with tainted request input have nothing to do with the
// exec/execSync receiver-tracing fix (they never go through classifyExecReceiver /
// isChildProcessExecCall at all) and must keep firing exactly as before.
function evaluateUserExpression(req) {
  return eval(req.body.expr); // eslint-disable-line no-eval
}

function buildUserFunction(req) {
  return new Function('input', `return ${req.body.code}`);
}

module.exports = { evaluateUserExpression, buildUserFunction };
