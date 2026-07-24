'use strict';
// NEW gap for check 15 (open-redirect), found by a realistic-library-code audit
// (round 2, 2026-07-24). `new URL(req.query.next, baseUrl).toString()` is a real,
// well-known bypass idiom: developers often add it BELIEVING it validates/sandboxes the
// target against baseUrl, but the WHATWG URL parser ignores the base entirely once the
// first argument is itself an absolute URL (e.g. "https://evil.com"), so this "guard"
// does not actually stop the redirect from going anywhere the attacker wants.
// resolveCallExprFromReqSource() only matched a flat `identifier(args)` call with no
// nested parens -- `new URL(...)` (a `new` prefix, a nested call, a chained
// `.toString()`) never matched that shape, so the tainted value was invisible.
function handleLogout(req, res, baseUrl) {
  res.redirect(new URL(req.query.next, baseUrl).toString());
}

module.exports = { handleLogout };
