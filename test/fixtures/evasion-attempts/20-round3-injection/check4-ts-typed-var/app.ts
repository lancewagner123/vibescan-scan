// EVASION (round 3): check 4 (sql-string-concatenation) Case B (query built into a
// variable) with a TypeScript TYPE ANNOTATION on the variable. SQL_BUILT_VAR_RE is
// /(?:const|let|var)\s+NAME\s*=\s*.../ -- it requires the identifier to be followed
// (after optional whitespace) directly by `=`. A `: string` type annotation between the
// name and `=` defeats the match entirely, so the concatenated SQL string assigned to a
// typed variable is never seen.
import { db } from './db';

export async function getUser(req: any, res: any) {
  const sql: string = "SELECT * FROM users WHERE id = '" + req.params.id + "'";
  const rows = await db.query(sql);
  res.json(rows);
}
