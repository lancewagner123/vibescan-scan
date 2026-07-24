'use strict';
// Evasion for check 15 (open-redirect): checkOpenRedirect() only recognizes a res.redirect()
// target that is EITHER a direct req.query/req.body/req.params property expression, OR a
// bare identifier resolved exactly one hop back to one of those via resolveVarFromReqSource().
// It never looks inside a called function's return value the way eval-on-input's
// argLooksInterpolated() does for its own check -- so routing the tainted value through a
// same-file helper function makes the call's argument text a call expression
// ("getRedirectTarget(req)"), which matches neither the direct-property regex nor the
// bare-identifier branch, and the check gives up before ever resolving where the value
// actually comes from.

function getRedirectTarget(req) {
  return req.query.next || req.query.returnTo; // unvalidated, attacker-controlled
}

function handleLogout(req, res) {
  res.redirect(getRedirectTarget(req)); // argument is a call expression, not req.query.* or a bare identifier
}

module.exports = { handleLogout };
