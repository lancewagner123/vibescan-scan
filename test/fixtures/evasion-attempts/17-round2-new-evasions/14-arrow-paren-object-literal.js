'use strict';
// NEW evasion attempt for check 14 (insecure-cookie-flags), round 2.
// resolveObjectLiteralVar()'s function-call fallback does:
//   const returnExpr = lookupFunctionReturnExpr(clean, cm[1]);
//   if (returnExpr && /^\{/.test(returnExpr.trim())) return returnExpr.trim();
// An arrow function with a concise/implicit-return body that returns an object literal
// MUST wrap it in parens (`() => ({ ... })`) -- otherwise the `{` would be parsed as a
// block body, not an object literal. This is the standard, idiomatic way every JS
// developer (and linter) writes this. lookupFunctionReturnExpr correctly extracts the
// returned text as "({ maxAge: 3600000 })" (parens included), but resolveObjectLiteralVar
// then tests whether that text STARTS WITH '{' literally -- it starts with '(' instead, so
// the check rejects a perfectly good, resolvable object literal and bails ("can't
// confirm"), even though the missing httpOnly/secure flags are just as real as the
// already-fixed helper-FUNCTION-call evasion this is a close cousin of.
const buildCookieOptions = () => ({ maxAge: 3600000 }); // no httpOnly / secure

function setSessionCookie(res, sessionToken) {
  const cookieOpts = buildCookieOptions();
  res.cookie('sessionId', sessionToken, cookieOpts);
}

module.exports = { setSessionCookie };
