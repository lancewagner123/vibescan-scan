'use strict';

// Positive control -- NOT a false positive. Overcorrection guard for the receiver-tracing
// rewrite of checkEvalOnInput(): a real child_process.exec() call reached through ONE HOP
// of same-file indirection (the module itself is obtained from a helper function, not a
// direct `require('child_process')`/`import` binding) must still be flagged. Before this
// fix, isChildProcessModuleVar only recognized a receiver assigned DIRECTLY from
// require('child_process')/an import -- a receiver resolved through a wrapper function
// (as below) traced to nothing and was silently dropped, even though the OLD pre-fix
// "does this file mention child_process anywhere" guard used to catch this exact shape.
function getChildProcessModule() {
  return require('child_process');
}

function runTask(req) {
  const cp = getChildProcessModule();
  // Real shell injection: request input interpolated straight into the command string.
  cp.exec(`run-task ${req.body.command}`, (err, stdout) => stdout);
}

module.exports = { runTask };
