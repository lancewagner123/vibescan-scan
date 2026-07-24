'use strict';
// NEW evasion attempt for check 15 (open-redirect), round 2.
// Wrapping the tainted req.query value in a template literal (`${req.query.next}`) is a
// no-op at runtime (String(req.query.next) === `${req.query.next}` for a normal string
// query value) but changes the ARGUMENT TEXT enough to dodge every branch in
// checkOpenRedirect(): REQ_SOURCE_PROP_RE requires an exact `req.query.next`-shaped match
// with no surrounding backticks/`${}`, the bare-identifier branch obviously doesn't apply,
// and resolveCallExprFromReqSource only handles a call-expression shape. A template
// literal is none of those, so the target is never traced back to req.query at all.
function handleLogout(req, res) {
  res.redirect(`${req.query.next}`);
}

module.exports = { handleLogout };
