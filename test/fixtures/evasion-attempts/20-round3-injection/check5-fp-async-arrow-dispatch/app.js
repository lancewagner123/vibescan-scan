'use strict';

// FALSE-POSITIVE PROBE (round 3): eval-FREE dispatch through an ASYNC ARROW lookup table.
// User input only selects which pre-defined handler runs; it is never eval'd, Function'd,
// or shelled out. No child_process import. This must NOT be flagged by check 5.
const handlers = {
  add: async (a, b) => a + b,
  sub: async (a, b) => a - b,
  mul: async (a, b) => a * b,
};

async function dispatch(req, res) {
  const op = req.body.op;
  const fn = handlers[op] || handlers.add;
  const result = await fn(Number(req.body.a), Number(req.body.b));
  res.json({ result });
}

module.exports = { dispatch };
