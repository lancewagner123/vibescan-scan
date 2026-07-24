'use strict';
// NEW evasion attempt for check 11 (insecure-random-token), round 2.
// lookupFunctionReturnExpr's arrow-function regexes (both block-body and concise-body
// variants) require the arrow's params to appear IMMEDIATELY after the '=' sign:
//   arrowBlockRe: (?:const|let|var)\s+NAME\s*=\s*PARAMS\s*=>\s*\{
//   arrowExprRe:  (?:const|let|var)\s+NAME\s*=\s*PARAMS\s*=>\s*(...)
// An `async` arrow function inserts the "async" keyword between '=' and the params
// (`const gen = async () => ...`), which neither pattern accounts for -- so an async
// arrow-function helper (an extremely common modern idiom, especially once any real
// crypto/network work is involved) is completely invisible to lookupFunctionReturnExpr,
// even though this one is a pure sync Math.random() wrapper doing no actual async work.
//
// The helper is deliberately named WITHOUT any token/secret/session/etc keyword itself
// (unlike a name such as "generateAsyncToken" would be) so this fixture can't accidentally
// pass by matching TOKEN_ISH_NAME_SRC against the helper's own declaration line, which
// also contains a literal Math.random() call -- that would trigger
// checkInsecureRandomToken() directly via same-line co-occurrence, without ever exercising
// the async-arrow indirection this fixture exists to test. The only way this SHOULD be
// caught is via TOKEN_ASSIGNED_TO_CALL_RE + lookupFunctionReturnExpr resolving the async
// arrow body one hop away, at the `resetToken = await generateWeakValue()` call site.
const generateWeakValue = async () => Math.random().toString(36).slice(2);

async function issuePasswordResetToken(userId) {
  const resetToken = await generateWeakValue();
  return { userId, resetToken };
}

module.exports = { issuePasswordResetToken };
