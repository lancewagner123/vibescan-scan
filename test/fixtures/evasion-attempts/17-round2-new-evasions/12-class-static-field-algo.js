'use strict';
// NEW evasion attempt for check 12 (weak-password-hashing), round 2.
// resolveConcatExpression (util.js) only resolves a bare identifier operand via a
// `const/let/var NAME = ...` declaration lookup -- a class STATIC FIELD accessed as a
// member expression (`HashConfig.ALGO`) is neither a string literal nor a bare identifier
// (it contains a '.'), so resolveConcatExpression's identMatch regex
// (`^[A-Za-z_$][\w$]*$`) rejects it outright and the whole resolution bails (returns
// null) rather than following the member expression back to the class body -- even though
// this is a completely ordinary way to centralize a config constant in modern JS/TS.
class HashConfig {
  static ALGO = 'md5';
}

function hashPassword(password) {
  return crypto.createHash(HashConfig.ALGO).update(password).digest('hex');
}

const crypto = require('crypto');

function registerUser(email, password) {
  const passwordHash = hashPassword(password);
  return { email, passwordHash };
}

module.exports = { hashPassword, registerUser };
