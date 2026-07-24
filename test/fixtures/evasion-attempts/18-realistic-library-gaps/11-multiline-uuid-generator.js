'use strict';
// NEW gap for check 11 (insecure-random-token), found by a realistic-library-code audit
// (round 2, 2026-07-24) -- not an adversarial evasion trick, just the famous
// hand-rolled-UUID Stack Overflow snippet, widely copy-pasted before crypto.randomUUID()
// existed. lookupFunctionReturnExpr's return-expression extraction used to be
// `body.match(/return\s+([^;\n]+)/)` -- it stops at the FIRST NEWLINE. Here, the `return`
// keyword and the opening of the .replace() callback are on line 1, but Math.random() is
// on a LATER line inside that callback -- so the single-line capture never saw it, and
// `apiKey = generateUUID()` was silently missed even though it's exactly as predictable
// as the already-caught inline `Math.random()` case.
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    var r = (Date.now() + Math.random() * 16) % 16 | 0;
    var v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

function issueApiKey(userId) {
  const apiKey = generateUUID();
  return { userId, apiKey };
}

module.exports = { issueApiKey };
