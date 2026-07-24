'use strict';
// Phase 2 of the round-2 audit: "all 15 together" -- one file deliberately packs multiple,
// INDEPENDENT, genuinely-vulnerable code shapes from many different checks side by side, to
// probe for cross-check interaction bugs (a shared module-level `g`-flag regex whose
// lastIndex leaks across an unrelated check's pass, one check's match window accidentally
// swallowing/starving a neighboring check's match, etc.) rather than each check's own
// evasion-resistance in isolation. Every vulnerability below is a plain, unobfuscated,
// should-always-be-caught case -- no evasion tricks -- so any miss here would indicate an
// interaction bug, not a detection-logic gap.

const crypto = require('crypto');
const AWS_KEY = 'AKIAABCDEFGHIJKLMNOP'; // check 1: secret-hardcoded-generic

function runQuery(db, id) {
  return db.query('SELECT * FROM users WHERE id = ' + id); // check 4: sql-string-concatenation
}

function runCommand(userInput) {
  return eval(userInput); // check 5: eval-on-input
}

const corsOptions = { origin: '*', credentials: true }; // check 6: cors-wildcard-with-credentials

function registerAdminRoutes(router) {
  router.get('/admin/dashboard', (req, res) => { // check 7: missing-auth-middleware
    res.send('dashboard');
  });
}

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex'); // check 12: weak-password-hashing
}

function issueResetToken(userId) {
  const resetToken = Math.random().toString(36).slice(2); // check 11: insecure-random-token
  return { userId, resetToken };
}

function createUser(req, res, User) {
  return User.create(req.body); // check 13: mass-assignment
}

function setSessionCookie(res, sessionToken) {
  res.cookie('sessionId', sessionToken); // check 14: insecure-cookie-flags (no options at all)
}

function handleLogout(req, res) {
  res.redirect(req.query.next); // check 15: open-redirect
}

module.exports = {
  runQuery,
  runCommand,
  registerAdminRoutes,
  hashPassword,
  issueResetToken,
  createUser,
  setSessionCookie,
  handleLogout,
  AWS_KEY,
  corsOptions,
};
