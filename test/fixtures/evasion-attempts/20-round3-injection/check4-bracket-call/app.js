'use strict';

// EVASION (round 3): check 4 (sql-string-concatenation) via BRACKET-NOTATION / computed
// member access on the DB handle. SQL_INLINE_TEMPLATE_RE / SQL_INLINE_CONCAT_RE both
// require a literal `.query(`/`.execute(`/`.raw(` (dot before the method name). Calling
// the same method through a computed key has no dot before the name, so the interpolation
// is invisible even though the vulnerability is identical.
const express = require('express');
const router = express.Router();
const db = require('./db');

const method = 'query';

router.get('/users/:id', async (req, res) => {
  const userId = req.params.id;
  // Bracket/computed access instead of db.query(...) -- same SQL injection.
  const rows = await db['query'](`SELECT * FROM users WHERE id = ${userId}`);
  res.json(rows);
});

module.exports = router;
