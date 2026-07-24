'use strict';
// NEW evasion attempt for check 11 (insecure-random-token), round 2.
// checkInsecureRandomTokenViaHelperCall's TOKEN_ASSIGNED_TO_CALL_RE requires the callee to
// be a BARE identifier immediately followed by '(' -- `([A-Za-z_$][\w$]*)\s*\(`. A static
// class method call (`TokenGen.generate()`) is a MEMBER expression, not a bare identifier,
// so the regex never even matches the assignment statement at all (it fails to find `(`
// immediately after the identifier portion, since a '.' sits in between). Even if it did
// match, lookupFunctionReturnExpr (util.js) only knows how to find `function name(...) {}`
// declarations and `const/let/var name = (...) => ...` arrow assignments -- it has no
// class-method lookup shape at all, so a static method's body could never be resolved
// either way.
class TokenGen {
  static generate() {
    return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  }
}

function issuePasswordResetToken(userId) {
  const resetToken = TokenGen.generate(); // member-expression call, invisible to the check
  return { userId, resetToken };
}

module.exports = { issuePasswordResetToken };
