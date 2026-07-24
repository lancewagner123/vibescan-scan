'use strict';
// Evasion for check 4 (sql-string-concatenation): the unsafe concatenation happens
// inside a small helper function, one layer removed from the .query()/.execute()/.raw()
// call site. SQL_INLINE_TEMPLATE_RE / SQL_INLINE_CONCAT_RE only match concatenation
// written directly inside the call's own parentheses, and SQL_BUILT_VAR_RE only matches
// a `const/let/var x = "...SQL..." + something` assignment in the SAME statement --
// moving the string-building into buildLookupQuery() means the call site (`db.query
// (sql)`) sees only a plain identifier returned from a function call, and the
// `return '...' + var` line that actually builds the vulnerable string is a `return`
// statement, not a `const/let/var` declaration, so it never matches the assigned-
// variable regex either. Net effect: identical SQL injection, invisible to check 4.

function buildLookupQuery(table, userSuppliedId) {
  // Still raw string concatenation of unsanitized input -- just relocated one call away.
  return 'SELECT * FROM ' + table + " WHERE id = '" + userSuppliedId + "'";
}

async function getUserById(db, req) {
  const sql = buildLookupQuery('users', req.params.id);
  return db.query(sql);
}

module.exports = { buildLookupQuery, getUserById };
