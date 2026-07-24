'use strict';
// Originally an evasion for check 13 (mass-assignment): argIsWholeReqBodyOrQuery() used to
// only recognize the WHOLE req.body/req.query object passed either as the literal text
// "req.body"/"req.query" or via exactly ONE variable hop (`const x = req.body;
// Model.create(x)`). Both tricks below produce the exact same real-world vulnerability --
// every field on the incoming body (isAdmin, role, verified, balance, ...) still lands on
// the record unfiltered.
//
// Both fixed 2026-07-24 (same-day red-team pass) by routing this check through the shared
// resolveIdentifierChain helper (src/scanners/util.js), which handles arbitrary-depth
// variable hops, and by recognizing spread-into-object-literal as equivalent to passing
// req.body/req.query directly. Still regression-tested by
// test/regression.test.js's EVASION_CASES entry for '13-mass-assignment'.

const User = require('./models/user');

// --- Trick A: spread-into-object-literal -------------------------------------------------
// `{ ...req.body }` is a shallow copy of every field on req.body, functionally identical
// to passing req.body directly. Now caught.
function createUser(req, res) {
  return User.create({ ...req.body });
}

// --- Trick B: two-hop variable indirection -----------------------------------------------
// `input` is declared from `raw`, and only `raw` is itself declared directly from
// req.body -- one hop past what the check originally looked up. Now caught via
// resolveIdentifierChain's arbitrary-hop-count resolution.
function updateUser(req, res, existingUser) {
  const raw = req.body;
  const input = raw;
  return Object.assign(existingUser, input);
}

module.exports = { createUser, updateUser };
