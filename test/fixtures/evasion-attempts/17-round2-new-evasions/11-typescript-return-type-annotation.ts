'use strict';
// NEW evasion attempt for check 11 (insecure-random-token), round 2 -- TypeScript-flavored
// syntax. lookupFunctionReturnExpr's function-declaration regex is:
//   function\s+NAME\s*\([^)]*\)\s*\{
// It requires the closing ')' of the parameter list to be followed (modulo whitespace)
// directly by '{'. A TypeScript function with an explicit return-type annotation inserts
// ": string" (or any return type) between the ')' and the '{', which this regex has no
// allowance for at all -- so the entire function body lookup fails, even though this is
// completely ordinary, idiomatic TypeScript, not an adversarial trick.
function generateResetToken(): string {
  return Math.random().toString(36).slice(2);
}

function issuePasswordReset(userId: string) {
  const resetToken = generateResetToken(); // never resolved back to Math.random()
  return { userId, resetToken };
}

module.exports = { issuePasswordReset };
