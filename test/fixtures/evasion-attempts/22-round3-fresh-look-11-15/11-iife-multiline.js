'use strict';

// Check 11 candidate: Math.random() inside a multi-line IIFE assigned straight to a
// token-ish name. INSECURE_RANDOM_TOKEN_RE only sees the same LINE as the name (the RHS
// up to the first newline is `(() => {`, no Math.random() there), and
// checkInsecureRandomTokenViaHelperCall requires a BARE identifier callee -- an IIFE's
// callee is a parenthesized arrow, not an identifier -- so neither branch fires.

const resetToken = (() => {
  const raw = Math.random().toString(36);
  return raw.slice(2, 12);
})();

module.exports = { resetToken };
