'use strict';

// FALSE-POSITIVE PROBE (round 3): a correctly PARAMETERIZED query whose bind values come
// from DESTRUCTURED request params. There is no string concatenation or interpolation of
// user input into the SQL text at all -- the `$1/$2` placeholders + values array is the
// safe pattern. This must NOT be flagged by check 4.
const express = require('express');
const router = express.Router();
const db = require('./db');

router.post('/users', async (req, res) => {
  const { id, name } = req.body;
  const rows = await db.query(
    'SELECT * FROM users WHERE id = $1 AND name = $2',
    [id, name],
  );
  res.json(rows);
});

module.exports = router;
