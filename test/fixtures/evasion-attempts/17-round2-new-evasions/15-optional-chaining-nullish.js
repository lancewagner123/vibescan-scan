'use strict';
// NEW evasion attempt for check 15 (open-redirect), round 2.
// REQ_SOURCE_PROP_RE is anchored to an EXACT match of the whole target argument:
//   /^req\.(?:query|body|params)(?:\.[\w$]+)?$/
// It has no allowance for optional chaining ('?.') or a nullish-coalescing fallback
// ('??'). `req.query?.next ?? '/home'` is exactly as attacker-controlled as
// `req.query.next` (an attacker who omits the query param just gets the default; one who
// supplies it gets forwarded to it), but the extra `?.`/`??` punctuation makes the target
// argument's text fail every branch in checkOpenRedirect(): it's not an exact req.*
// match, not a bare identifier, and not a same-file call expression -- so sourceExpr is
// never resolved and the finding never fires.
function handleLogout(req, res) {
  res.redirect(req.query?.next ?? '/home');
}

module.exports = { handleLogout };
