'use strict';
// NEW evasion attempt for check 13 (mass-assignment), round 2 -- destructuring WITH
// renaming, a step further than the plain-destructuring case in the sibling fixture.
// Same root cause (resolveIdentifierChain never handles destructuring patterns at all),
// but shows the rename form specifically since it's an equally common real-world style
// (`const { body: userData } = req;`) and worth confirming independently rather than
// assuming the plain case covers it.
const User = require('./models/user');

function createUser(req, res) {
  const { body: userData } = req;
  return User.create(userData);
}

module.exports = { createUser };
