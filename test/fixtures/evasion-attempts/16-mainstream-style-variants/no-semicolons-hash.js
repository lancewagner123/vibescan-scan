'use strict';
// Mainstream-style variant, NOT an adversarial evasion trick: semicolon-free code (the
// Standard.js style, `semi:false` in Prettier/ESLint, plenty of real and AI-generated
// code) is a completely ordinary formatting choice, not obfuscation. Found by an
// adversarial audit (2026-07-24) to defeat check 12 (weak-password-hashing) via
// resolveConcatExpression/resolveIdentifierChain requiring a literal trailing `;` to
// recognize a const/let/var declaration. Fixed the same day in src/scanners/util.js.
//
// Expected: a weak-password-hashing finding, resolved through the semicolon-free
// HASH_ALGO declaration.
const crypto = require('crypto')

const HASH_ALGO = 'md5'

function hashPassword(password) {
  return crypto.createHash(HASH_ALGO).update(password).digest('hex')
}

module.exports = { hashPassword }
