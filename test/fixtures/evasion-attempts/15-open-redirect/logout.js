'use strict';
// Originally an evasion for check 15 (open-redirect): checkOpenRedirect() used to only
// recognize a res.redirect() target that was EITHER a direct req.query/req.body/req.params
// property expression, OR a bare identifier resolved exactly one hop back to one of those.
// Routing the tainted value through a same-file helper function (a call expression, not a
// property access or bare identifier) used to make the check give up before ever resolving
// where the value actually comes from.
//
// Fixed 2026-07-24 (same-day red-team pass) by routing this check through the shared
// lookupFunctionReturnExpr helper (src/scanners/util.js), which resolves same-file helper
// functions' return expressions (both `function name(){}` and arrow-function forms as of
// the follow-up mainstream-style-variant fix). Still regression-tested by
// test/regression.test.js's EVASION_CASES entry for '15-open-redirect'.

function getRedirectTarget(req) {
  return req.query.next || req.query.returnTo; // unvalidated, attacker-controlled
}

function handleLogout(req, res) {
  res.redirect(getRedirectTarget(req)); // now resolved through lookupFunctionReturnExpr
}

module.exports = { handleLogout };
