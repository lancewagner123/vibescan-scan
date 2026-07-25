'use strict';

// Check 14 candidates (both FALSE POSITIVES -- secure code wrongly flagged):

// (A) ES6 shorthand property: `secure` is a shorthand for `secure: secureFlag` where the
// variable is true in production. SECURE_TRUE_RE requires the literal `secure: true`, so
// the shorthand reads as "missing secure:true".
function setSessionA(res, token) {
  const httpOnly = true;
  const secure = true;
  res.cookie('sessionId', token, { httpOnly, secure });
}

// (B) Spread of a shared secure-defaults object. The literal options text is
// `{ ...COOKIE_DEFAULTS, maxAge: 3600000 }`; HTTP_ONLY_TRUE_RE/SECURE_TRUE_RE scan that
// text, don't find the flags (they live in the spread source), and flag both as missing.
const COOKIE_DEFAULTS = { httpOnly: true, secure: true, sameSite: 'strict' };
function setSessionB(res, token) {
  res.cookie('authToken', token, { ...COOKIE_DEFAULTS, maxAge: 3600000 });
}

module.exports = { setSessionA, setSessionB };
