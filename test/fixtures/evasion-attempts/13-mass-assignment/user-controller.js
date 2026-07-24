'use strict';
// Evasion for check 13 (mass-assignment): argIsWholeReqBodyOrQuery() only recognizes the
// WHOLE req.body/req.query object passed either as the literal text "req.body"/"req.query"
// or via exactly ONE variable hop (`const x = req.body; Model.create(x)`). Two tricks
// below each produce the exact same real-world vulnerability -- every field on the
// incoming body (isAdmin, role, verified, balance, ...) still lands on the record
// unfiltered -- while dodging both recognized shapes.

const User = require('./models/user');

// --- Trick A: spread-into-object-literal -------------------------------------------------
// `{ ...req.body }` is a shallow copy of every field on req.body, functionally identical
// to passing req.body directly. But the call's argument text is "{ ...req.body }", which
// matches neither `/^req\.(?:body|query)$/` (it's not the bare req.body expression) nor
// the bare-identifier branch (it's an object-literal expression, not an identifier) -- so
// argIsWholeReqBodyOrQuery() returns false and the whole call is invisible to this check.
function createUser(req, res) {
  return User.create({ ...req.body });
}

// --- Trick B: two-hop variable indirection -----------------------------------------------
// The check follows exactly one `const/let/var name = req.body;` hop. Here `input` is
// declared from `raw`, and only `raw` (one hop further back) is itself declared directly
// from req.body -- one hop past what the check's declRe looks up, so it can't confirm
// `input` traces back to req.body and (per this codebase's own "bail rather than guess"
// convention) silently lets it through.
function updateUser(req, res, existingUser) {
  const raw = req.body;
  const input = raw;
  return Object.assign(existingUser, input);
}

module.exports = { createUser, updateUser };
