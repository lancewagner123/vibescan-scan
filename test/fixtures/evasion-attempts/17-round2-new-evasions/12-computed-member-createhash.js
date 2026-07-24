'use strict';
// NEW evasion attempt for check 12 (weak-password-hashing), round 2.
// CREATE_HASH_CALL_RE is a fixed literal-dot pattern:
//   /crypto\s*\.\s*createHash\s*\(\s*([^)]*)\)/gi
// A computed/bracket member access on the METHOD name itself (`crypto['createHash'](...)`)
// never contains the literal text ".createHash(" at all, so the regex never matches the
// call site in the first place -- the password-context / resolveConcatExpression logic
// downstream never even gets a chance to run, because nothing was captured to begin with.
const crypto = require('crypto');

function hashPassword(password) {
  return crypto['createHash']('md5').update(password).digest('hex');
}

function registerUser(email, password) {
  const passwordHash = hashPassword(password);
  return { email, passwordHash };
}

module.exports = { hashPassword, registerUser };
