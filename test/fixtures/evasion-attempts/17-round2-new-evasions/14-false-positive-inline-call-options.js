'use strict';
// NEW FALSE-POSITIVE candidate for check 14 (insecure-cookie-flags), round 2.
// This file is SECURE: the third argument passed inline to res.cookie() is a direct call
// expression (not a bare identifier, not an inline object literal) whose helper returns a
// fully-correct { httpOnly: true, secure: true } object. checkInsecureCookieFlags() only
// special-cases the third argument when it's `/^\{/`-shaped (an inline literal) or a BARE
// identifier (`/^[A-Za-z_$][\w$]*$/`, resolved via resolveObjectLiteralVar) -- a call
// expression used directly inline (`buildSecureCookieOptions()`) matches neither branch,
// so `optionsText` is left at its initial value of null. The code then reads:
//   if (optionsText === null) { <push "no options object at all" finding>; continue; }
// which fires unconditionally whenever optionsText is still null for ANY reason --
// including "we simply never looked", not just "we confirmed there's truly no options
// object". The result: a securely-configured cookie call is flagged as if it had NO
// options object at all, which is factually wrong and actively misleading (the rawMessage
// text asserts "with no options object at all", which is false here).
function buildSecureCookieOptions() {
  return { httpOnly: true, secure: true, sameSite: 'strict' };
}

function setSessionCookie(res, sessionToken) {
  // Inline call, not stored in a variable first -- this is fully secure code.
  res.cookie('sessionId', sessionToken, buildSecureCookieOptions());
}

module.exports = { setSessionCookie };
