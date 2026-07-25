'use strict';

// EVASION (round 3): check 4 (sql-string-concatenation) Case C ("taint-lite" helper) where
// the SQL-building helper is a CLASS STATIC METHOD instead of a `function` declaration.
// findSqlBuildingFunctionNames() only matches FUNCTION_DECL_RE (`function name(...) {`),
// so a static-method builder is never registered and the tainted call site is never
// traced -- even though round 2 taught lookupFunctionReturnExpr to resolve class static
// methods, check 4 does not use that helper.
const db = require('./db');

class QueryBuilder {
  static forUser(id) {
    return "SELECT * FROM users WHERE id = '" + id + "'";
  }
}

async function getUser(req, res) {
  const sql = QueryBuilder.forUser(req.params.id);
  const rows = await db.query(sql);
  res.json(rows);
}

module.exports = { getUser };
