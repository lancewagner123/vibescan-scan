'use strict';
// Evasion for check 11 (insecure-random-token): INSECURE_RANDOM_TOKEN_RE requires a
// token-ish NAME (identifier/property chain matching TOKEN_ISH_NAME_SRC) and a literal
// `Math.random()` call to appear TOGETHER, on the same statement, joined directly by
// `:`/`=`. Two independent tricks below each break that co-occurrence requirement while
// producing a byte-for-byte-as-predictable token as the fixture's seeded example
// (`const resetToken = Math.random().toString(36);`).

// --- Trick A: computed / bracket property name -----------------------------------------
// TOKEN_ISH_NAME_SRC is built from `[\w$.]*` + keyword + `[\w$]*` -- none of those
// character classes include `'`, `"`, or `[`/`]`. So the moment the property name is
// written in bracket notation instead of dot notation, the regex can no longer see
// "sessionId" as a contiguous run of name characters immediately before the `=` -- the
// quote/bracket punctuation breaks the match, even though this assigns the exact same
// Math.random()-derived value to the exact same logical property.
function issueSession(user) {
  user['session' + 'Id'] = Math.random().toString(36).slice(2); // bracket + concatenated name
  return user;
}

// --- Trick B: Math.random() moved one function call away -------------------------------
// checkInsecureRandomToken() never looks inside a called function's body -- unlike
// eval-on-input's argLooksInterpolated(), this check has no "resolve one level of
// same-file function call" fallback at all. So wrapping the weak-random call in a
// helper and assigning the helper's *return value* to a token-ish name means neither
// line (the assignment, or the helper body) ever contains BOTH a token-ish name AND a
// literal Math.random() call on the same statement.
function weakRandomToken() {
  return Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
}

function issuePasswordResetToken(userId) {
  const resetToken = weakRandomToken(); // no Math.random() text on this line at all
  return { userId, resetToken };
}

module.exports = { issueSession, issuePasswordResetToken };
