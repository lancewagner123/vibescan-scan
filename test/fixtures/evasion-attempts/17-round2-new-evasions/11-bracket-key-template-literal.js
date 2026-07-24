'use strict';
// NEW evasion attempt for check 11 (insecure-random-token), round 2.
// The already-fixed bracket-notation evasion (INSECURE_RANDOM_TOKEN_BRACKET_RE) only
// recognizes a bracket key written with single/double quotes:
//   BRACKET_KEY_EXPR_SRC = "(?:['\"][\\w$]*['\"]\\s*\\+\\s*)*['\"][\\w$]*['\"]"
// A bracket key written as a TEMPLATE LITERAL (backticks) instead -- an entirely ordinary
// modern-JS stylistic choice, not exotic obfuscation -- falls outside that character
// class (`'"` only, no backtick) and is invisible to both INSECURE_RANDOM_TOKEN_RE (which
// never handles bracket notation at all) and INSECURE_RANDOM_TOKEN_BRACKET_RE (which only
// handles quote-delimited bracket keys).
function issueSession(user) {
  user[`sessionId`] = Math.random().toString(36).slice(2); // template-literal bracket key
  return user;
}

module.exports = { issueSession };
