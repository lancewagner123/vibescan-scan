'use strict';

// EVASION (round 3): check 5 (eval-on-input) where the interpolated code string is built
// by an ASYNC ARROW helper and passed to eval() with a leading `await`. argLooksInterpolated
// tries to inline one level of same-file function call via
//   trimmed.match(/^([A-Za-z_$][\w.$]*)\s*\(/)
// but the `await ` prefix makes the capture start on `await`, whose next char is a space,
// not `(`, so the callMatch fails and the helper's interpolated return is never inspected.
// (Round 2 added `await`-stripping to the open-redirect check for exactly this reason; the
// eval check never got it.)
const buildExpression = async (userCode) => `return (${userCode})`;

async function run(req, res) {
  const result = eval(await buildExpression(req.body.code));
  res.json({ result });
}

module.exports = { run };
