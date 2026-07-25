// EVASION (round 3): check 4 (sql-string-concatenation) Case C ("taint-lite" helper) with
// a TypeScript RETURN-TYPE ANNOTATION on the builder function. FUNCTION_DECL_RE in
// static-checks.js is /function\s+NAME\s*\([^)]*\)\s*\{/ -- it requires `)` to be followed
// (after optional whitespace) directly by `{`. A `: string` return-type annotation between
// them defeats the match, so the builder is never registered as SQL-building and the
// tainted call site is never traced. (This is the exact bug round 2 fixed in
// lookupFunctionReturnExpr for checks 5/11/14/15 -- but check 4 rolls its own
// FUNCTION_DECL_RE and never got the fix.)
import { db } from './db';

function buildUserQuery(id: string): string {
  return "SELECT * FROM users WHERE id = '" + id + "'";
}

export async function getUser(req: any, res: any) {
  const sql = buildUserQuery(req.params.id);
  const rows = await db.query(sql);
  res.json(rows);
}
