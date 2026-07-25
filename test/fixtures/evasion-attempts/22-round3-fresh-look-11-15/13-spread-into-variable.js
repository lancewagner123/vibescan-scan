'use strict';

// Check 13 candidate: the { ...req.body } spread (already recognized when passed INLINE)
// is first stored in a variable, then the variable is passed to the write call. The
// identifier chain resolves `data` -> `{ ...req.body }`, but argIsWholeReqBodyOrQuery then
// only tests that terminal expression with isReqBodyOrQueryExpr (a plain req.body/req.query
// match) -- it never re-runs the spread-object branch on a chain-resolved value -- so the
// combined "spread + one variable hop" shape slips through both halves.

async function createUser(req, res) {
  const data = { ...req.body };
  const user = await User.create(data);
  res.json(user);
}

module.exports = { createUser };
