'use strict';

// EVASION (round 3): check 4 (sql-string-concatenation) via DESTRUCTURING the query method
// off the client, then calling it as a bare function. The inline regexes require
// `.query(` (a leading dot). A destructured `query` invoked as `query(...)` has no leading
// dot, so the interpolation is invisible.
const { Pool } = require('pg');
const pool = new Pool();
const { query } = pool;

async function findUser(req, res) {
  const id = req.params.id;
  const rows = await query(`SELECT * FROM users WHERE id = ${id}`);
  res.json(rows);
}

module.exports = { findUser };
