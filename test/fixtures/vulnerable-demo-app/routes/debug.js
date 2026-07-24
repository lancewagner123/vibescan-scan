'use strict';

const express = require('express');
const router = express.Router();

// VULNERABLE (check 5: eval-on-input) -- a debug endpoint that hands a request query
// parameter straight to eval(). Left over from development, mounted under /_debug, and
// never gated behind an environment check or removed before shipping.
router.get('/eval', (req, res) => {
  const expr = req.query.expr;
  const result = eval(expr); // eslint-disable-line no-eval
  res.json({ result });
});

module.exports = router;
