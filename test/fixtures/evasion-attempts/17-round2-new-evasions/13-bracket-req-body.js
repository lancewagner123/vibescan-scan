'use strict';
// NEW evasion attempt for check 13 (mass-assignment), round 2.
// isReqBodyOrQueryExpr() is anchored to exactly `req.body` / `req.query` via dot notation:
//   /^req\.(?:body|query)$/
// Bracket/computed member access (`req['body']`) is semantically identical -- same whole,
// unfiltered object -- but doesn't match the dot-notation-only regex at all, so it's
// passed straight through to Model.create() completely unflagged.
const User = require('./models/user');

function createUser(req, res) {
  return User.create(req['body']);
}

module.exports = { createUser };
