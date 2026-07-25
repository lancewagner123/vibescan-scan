'use strict'

// Check 11 candidate: Math.random() one helper-call hop away, but written in
// semicolon-free (Standard.js / prettier `semi:false`) style. This is the SAME
// mainstream-style-variant class that the third-party audit flagged for
// resolveConcatExpression / resolveIdentifierChain (fixture 16) -- but
// TOKEN_ASSIGNED_TO_CALL_RE (checkInsecureRandomTokenViaHelperCall) still ends in
// `\)\s*;`, a REQUIRED literal semicolon, so a no-semicolon call site never matches.

function weakRandomToken() {
  return Math.random().toString(36).slice(2)
}

function issueSession(user) {
  const sessionToken = weakRandomToken()
  return { user, sessionToken }
}

module.exports = { issueSession }
