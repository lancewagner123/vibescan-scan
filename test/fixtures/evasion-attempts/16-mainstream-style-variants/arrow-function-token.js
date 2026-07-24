'use strict';
// Mainstream-style variant, NOT an adversarial evasion trick: an arrow-function helper
// with a concise (implicit-return) body is one of the most common ways to write a small
// helper in modern JS/TS -- more common than a `function name() {}` declaration in a lot
// of real (and AI-generated) code. Found by an adversarial audit (2026-07-24) to defeat
// check 11 (insecure-random-token) via lookupFunctionReturnExpr only matching `function`
// declarations. Fixed the same day in src/scanners/util.js.
//
// Expected: an insecure-random-token finding, resolved through the arrow-function body.
const generateWeakValue = () => Math.random().toString(36).substring(2);

function issuePasswordResetToken() {
  const resetToken = generateWeakValue();
  return resetToken;
}

module.exports = { issuePasswordResetToken };
