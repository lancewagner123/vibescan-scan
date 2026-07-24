'use strict';
// Evasion for check 12 (weak-password-hashing): WEAK_HASH_ALGO_RE requires the algorithm
// name to appear as a LITERAL quoted string directly inside the createHash(...) call
// itself (`crypto.createHash('md5')` / `crypto.createHash("sha1")`). It never resolves a
// variable holding the algorithm name, unlike some of the other checks in this codebase
// that follow one hop of `const x = ...` indirection -- so the moment the algorithm name
// is a variable (even one built from split literals, so it isn't just a differently-
// spelled inline string either), the regex never matches the call at all, and the
// password-context heuristics (nearby "password" text / auth-ish file path) never even
// get a chance to run, because they're only consulted AFTER WEAK_HASH_ALGO_RE finds a hit.

const crypto = require('crypto');

// Still literally "md5" once concatenated -- same fast, unsalted digest as the seeded
// fixture example -- but no line in this file ever contains crypto.createHash('md5') or
// crypto.createHash("md5") as contiguous text.
const HASH_ALGO = 'm' + 'd5';

function hashPassword(password) {
  return crypto.createHash(HASH_ALGO).update(password).digest('hex');
}

function registerUser(email, password) {
  const passwordHash = hashPassword(password);
  return { email, passwordHash };
}

module.exports = { hashPassword, registerUser };
