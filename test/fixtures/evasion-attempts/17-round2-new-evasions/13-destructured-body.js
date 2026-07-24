'use strict';
// NEW evasion attempt for check 13 (mass-assignment), round 2.
// argIsWholeReqBodyOrQuery() resolves a bare identifier back to req.body/req.query via
// resolveIdentifierChain (util.js), but resolveIdentifierChain's lookup regex is:
//   (?:const|let|var)\s+NAME\s*=\s*([^;\n]+)
// which requires NAME to be declared as a BARE identifier on the left of '='. Object
// destructuring (`const { body } = req;`) puts a DESTRUCTURING PATTERN on the left, not a
// bare identifier -- so this extremely common, completely ordinary way of pulling
// `req.body` out of `req` is invisible to the lookup, even though `body` here ends up
// holding the exact same whole, unfiltered request body as `const raw = req.body;` would.
const User = require('./models/user');

function createUser(req, res) {
  const { body } = req; // destructuring, not a bare `body = req.body` declaration
  return User.create(body);
}

module.exports = { createUser };
