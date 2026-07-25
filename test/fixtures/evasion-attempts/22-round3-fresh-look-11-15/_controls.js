'use strict';
// CONTROLS: the plain/obvious version of each evasion above, which the scanner IS
// designed to catch. Each is written as its own file at runtime by _run_controls.js so
// findings can be attributed per-control. Kept as source strings here for clarity.
module.exports = {
  // Check 11 -- helper call WITH a trailing semicolon (only diff vs 11-no-semicolon).
  'c11-semicolon-helper.js':
    `function weakRandomToken() { return Math.random().toString(36).slice(2); }\n` +
    `const sessionToken = weakRandomToken();\n` +
    `module.exports = { sessionToken };\n`,

  // Check 11 -- inline single-line IIFE (only diff vs 11-iife-multiline: one line).
  'c11-inline-iife.js':
    `const resetToken = (() => Math.random().toString(36).slice(2))();\n` +
    `module.exports = { resetToken };\n`,

  // Check 12 -- createHash reached via the crypto object (only diff vs destructured import).
  'c12-crypto-createhash.js':
    `const crypto = require('crypto');\n` +
    `function storePassword(password) { return crypto.createHash('md5').update(password).digest('hex'); }\n` +
    `module.exports = { storePassword };\n`,

  // Check 13 -- plain req.body passed inline (no cast, no spread, no hop).
  'c13-plain-reqbody.js':
    `async function createUser(req, res) { const u = await User.create(req.body); res.json(u); }\n` +
    `module.exports = { createUser };\n`,

  // Check 13 -- spread passed INLINE (only diff vs 13-spread-into-variable: no variable hop).
  'c13-inline-spread.js':
    `async function createUser(req, res) { const u = await User.create({ ...req.body }); res.json(u); }\n` +
    `module.exports = { createUser };\n`,

  // Check 15 -- dot-notation req.query (only diff vs 15-bracket-req-query: dot vs bracket).
  'c15-dot-reqquery.js':
    `function handleRedirect(req, res) { res.redirect(req.query.next); }\n` +
    `module.exports = { handleRedirect };\n`,
};
