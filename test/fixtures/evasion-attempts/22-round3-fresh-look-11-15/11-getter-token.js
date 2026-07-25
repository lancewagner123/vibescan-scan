'use strict';

// Check 11 candidate: a token exposed via an object/class getter whose body returns a
// Math.random()-derived value. `get sessionToken()` has no `:` / `=` after the name, so
// INSECURE_RANDOM_TOKEN_RE never matches, and it is not a `name = callee()` shape either.

class Session {
  get sessionToken() {
    return Math.random().toString(36).slice(2);
  }
}

module.exports = { Session };
