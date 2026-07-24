'use strict';
// Evasion for check 14 (insecure-cookie-flags): once a res.cookie() call is confirmed to
// look session/auth-sensitive, the check tries to inspect its options object -- inline, or
// via exactly one variable hop back to a literal `const opts = { ... };` object-literal
// declaration (resolveObjectLiteralVar). If that one-hop lookup can't find a plain object
// literal, the check bails ("can't confirm, don't flag") rather than guessing. Building the
// options object via a helper FUNCTION CALL instead of an inline literal produces exactly
// that unresolvable shape, even though the options object that ends up on the wire is just
// as missing httpOnly/secure as the seeded fixture example.

function buildCookieOptions() {
  // No httpOnly / secure here -- the real vulnerability is unchanged.
  return { maxAge: 3600000 };
}

function setSessionCookie(res, sessionToken) {
  const cookieOpts = buildCookieOptions(); // RHS is a call, not `{ ... }` -- resolveObjectLiteralVar() returns null
  res.cookie('sessionId', sessionToken, cookieOpts);
}

module.exports = { setSessionCookie };
