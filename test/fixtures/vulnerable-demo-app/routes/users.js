'use strict';

const express = require('express');
const router = express.Router();

// Fake pg-like client so the query-shape pattern is realistic. This fixture never
// actually connects to a database -- it just needs to look like real query code.
const db = {
  query(sql) {
    return Promise.resolve({ rows: [], sql });
  },
};

// VULNERABLE (check 4: sql-string-concatenation) -- the request parameter is
// concatenated directly into the raw SQL string instead of using a parameterized query
// (e.g. db.query('SELECT * FROM users WHERE id = $1', [req.params.id])).
router.get('/:id', async (req, res) => {
  const sql = "SELECT * FROM users WHERE id = '" + req.params.id + "'";
  const result = await db.query(sql);
  res.json(result.rows);
});

// Same mistake, via template-literal interpolation -- the other common shape this check
// should also catch.
router.get('/', async (req, res) => {
  const nameFilter = req.query.name;
  const sql = `SELECT * FROM users WHERE name LIKE '%${nameFilter}%'`;
  const result = await db.query(sql);
  res.json(result.rows);
});

module.exports = router;
