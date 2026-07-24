'use strict';
// NEW evasion attempt for check 15 (open-redirect), round 2.
// resolveVarFromReqSource()'s destructuring regex requires the destructured object's RHS
// to be EXACTLY `req.query` / `req.body` / `req.params` (one specific property of req):
//   (?:const|let|var)\s*\{[^}]*\bNAME\b[^}]*\}\s*=\s*(req\.(?:query|body|params))\s*;
// NESTED destructuring straight off `req` itself (`const { query: { next } } = req;`)
// puts a second, INNER `{...}` inside the outer pattern and assigns from bare `req`, not
// `req.query` -- the regex's single `[^}]*...\}` can't span the nested braces, and the
// captured RHS would be `req` (not one of query/body/params), so this real, if less
// common, destructuring shape is never resolved back to req.query at all.
function handleLogout(req, res) {
  const { query: { next } } = req;
  res.redirect(next);
}

module.exports = { handleLogout };
