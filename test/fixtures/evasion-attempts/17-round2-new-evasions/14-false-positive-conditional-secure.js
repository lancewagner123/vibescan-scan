'use strict';
// NEW FALSE-POSITIVE candidate for check 14 (insecure-cookie-flags), round 2.
// This file is SECURE and follows one of the most standard, widely-recommended Express
// cookie patterns in existence: `secure` is set conditionally on NODE_ENV, so cookies are
// marked secure in production (HTTPS) but not in local development (plain HTTP, where a
// literal `secure:true` would silently break cookies entirely in a lot of dev setups).
// SECURE_TRUE_RE is a strict literal match:
//   /\bsecure\s*:\s*true\b/i
// It has no allowance for a conditional/expression value, so this textbook-correct,
// environment-aware configuration gets flagged as "missing secure:true" even though the
// flag genuinely is `true` in the deployed (production) environment this code is meant to
// protect -- exactly the config every serious guide (including Express's own docs)
// recommends.
function setSessionCookie(res, sessionToken) {
  res.cookie('sessionId', sessionToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
}

module.exports = { setSessionCookie };
