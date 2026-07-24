'use strict';
// NEW evasion attempt for check 15 (open-redirect), round 2.
// resolveCallExprFromReqSource() requires the target argument text to match a call
// expression starting IMMEDIATELY at the beginning of the string:
//   /^([A-Za-z_$][\w$]*)\s*\(([^()]*)\)$/
// The already-fixed helper-function evasion (see the 15-open-redirect regression fixture)
// only works because the call is stored in a bare variable/passed synchronously. The
// moment the target is `await getRedirectTarget(req)` -- passed directly as the argument,
// not first assigned to a variable -- the leading "await " text means the argument no
// longer starts with the callee identifier immediately followed by '(', so the regex
// fails to match at all and the whole call-expression resolution path is skipped, even
// though this is completely ordinary async/await usage and the helper is exactly as
// tainted as the synchronous version.
async function getRedirectTarget(req) {
  return req.query.next || req.query.returnTo;
}

async function handleLogout(req, res) {
  res.redirect(await getRedirectTarget(req));
}

module.exports = { handleLogout };
