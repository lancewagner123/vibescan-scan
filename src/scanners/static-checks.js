'use strict';

// Checks 4-9 and 13-15 from docs/CHECK_CATALOG.md, via targeted regex/string-pattern
// heuristics over .js/.ts/.jsx/.tsx source. These are intentionally precision-light — the
// downstream LLM triage layer is responsible for filtering noise — but each pattern is
// aimed at a real, specific signal rather than firing on every file. (Checks 11-12 live in
// secrets.js, not here.)

const path = require('path');
const {
  walkFiles,
  readTextFile,
  makeId,
  stripComments,
  extractBalancedBraceBlock,
  extractBalancedCallArg,
  splitTopLevelArgs,
  lookupFunctionReturnExpr,
  resolveConcatExpression,
  resolveIdentifierChain,
} = require('./util');

const SOURCE_EXTENSIONS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];
// Check 8's sibling SQL-migration pass (see the "Check 8, sibling detection" section
// below) walks the repo a second time restricted to this extension -- real Supabase/
// Postgres RLS policies live in .sql migration files, which SOURCE_EXTENSIONS above never
// includes and every other check in this file has no business reading anyway.
const SQL_EXTENSIONS = ['.sql'];

function lineOfIndex(text, index) {
  return text.slice(0, index).split(/\r?\n/).length;
}

function snippetAt(text, index, len = 160) {
  const lineStart = text.lastIndexOf('\n', index) + 1;
  let lineEnd = text.indexOf('\n', index);
  if (lineEnd === -1) lineEnd = text.length;
  return text.slice(lineStart, lineEnd).trim().slice(0, len);
}

// extractBalancedBraceBlock and resolveConcatExpression now live in ./util.js (moved
// 2026-07-24, evasion-bypass hardening pass) so secrets.js's checks 11-12 can reuse the
// exact same "look inside a same-file function/variable declaration" logic instead of
// duplicating it. Imported above.

// Every check below matches against `clean` (comments blanked out via stripComments)
// but reports line numbers/snippets against `original` (unmodified source), so what a
// reader sees still looks like real code. stripComments() preserves the exact length
// and every newline position, so an index/line found in `clean` maps 1:1 onto
// `original` — this is why it's safe to mix the two rather than re-deriving position.
// Without this, a comment merely *describing* a call (e.g. "never calls
// stripe.webhooks.constructEvent() to verify...") gets mistaken for a real call, and a
// comment that just mentions an unrelated keyword (e.g. explaining what "child_process"
// means) can create a false positive/negative in the checks below that key off it.

// --- Check 4: sql-string-concatenation -----------------------------------------------

// Case A: the unsafe concatenation/interpolation happens right inside the call, e.g.
//   db.query(`SELECT * FROM x WHERE id = ${id}`)
//   db.query("SELECT * FROM x WHERE id = '" + id + "'")
// SQL_METHOD_ACCESS matches the query/execute/raw method either as ordinary dot access
// (`.query`) OR as bracket/computed access (`['query']`) -- the round-3 injection audit
// (gap 4a) found `db['query'](`...`)` completely invisible to the dot-only form.
const SQL_METHOD_ACCESS = "(?:\\.(?:query|execute|raw)|\\[\\s*['\"](?:query|execute|raw)['\"]\\s*\\])";
const SQL_INLINE_TEMPLATE_RE = new RegExp(`${SQL_METHOD_ACCESS}\\s*\\(\\s*\`[^\`]*\\$\\{[^\`]*\\}[^\`]*\``, 'g');
const SQL_INLINE_CONCAT_RE = new RegExp(`${SQL_METHOD_ACCESS}\\s*\\(\\s*(['"])(?:(?!\\1).)*\\1\\s*\\+\\s*[A-Za-z_$][\\w.$]*`, 'g');

// Builds the "variable VARNAME is passed to a .query/.execute/.raw call" usage regex,
// tolerant of bracket/computed method access (gap 4a), shared by Case B and Case C.
function buildSqlUsageRe(varName) {
  return new RegExp(`${SQL_METHOD_ACCESS}\\s*\\(\\s*${varName}\\b`);
}

// Case B: the query string is built into a variable first, then that variable is passed
// to the call later — just as common in real code, and missed entirely by Case A:
//   const sql = "SELECT * FROM x WHERE id = '" + req.params.id + "'";
//   const result = await db.query(sql);
// Captures the assigned variable name so we can confirm it's later handed to a
// query-like call; requires a SQL keyword in the literal portion so this doesn't fire
// on unrelated string-building.
const SQL_KEYWORDS = '(?:SELECT|INSERT|UPDATE|DELETE)';
// NOTE on the quoted-string branch below: it deliberately does NOT use a `[^'"]*`
// character class to skip over the string body. SQL string construction routinely wraps
// a double-quoted JS string around SQL text that itself contains single quotes (SQL's
// own string-literal delimiter), e.g. "SELECT ... WHERE id = '" + id + "'" — excluding
// *both* quote characters would refuse to match past that embedded `'` and silently miss
// exactly the most common shape of this bug. Using `(?!\2)[^\n]` instead only excludes
// the SAME quote character that opened the string (via backreference \2), so the other
// quote type can appear freely inside — and is restricted to `[^\n]` (no newlines) since
// a real single-line string literal never spans multiple lines, which also keeps the
// lazy loop bounded per-line instead of scanning unboundedly across the whole file.
const SQL_BUILT_VAR_RE = new RegExp(
  // `(?::\\s*[^=;\\n]+?)?` tolerates a TS variable type annotation (gap 4c/systemic):
  // `const sql: string = ...`.
  `(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*(?::\\s*[^=;\\n]+?)?\\s*=\\s*` +
    `(?:` +
    // template literal containing a SQL keyword and ${...} interpolation
    `\`[^\`]*\\b${SQL_KEYWORDS}\\b[^\`]*\\$\\{[^\`]*\\}[^\`]*\`` +
    `|` +
    // quoted string containing a SQL keyword, concatenated with a variable
    `(['"])(?:(?!\\2)[^\\n])*?\\b${SQL_KEYWORDS}\\b(?:(?!\\2)[^\\n])*?\\2\\s*\\+\\s*[\\w.$]+` +
    `(?:\\s*\\+\\s*(?:['"][^'"\\n]*['"]|[\\w.$]+))*` +
    `)`,
  'gi',
);

// Case C ("taint-lite"): the concatenation happens inside a helper function's `return`
// statement, one call removed from the eventual .query/.execute/.raw call site, e.g.
//   function buildLookupQuery(table, id) { return 'SELECT * FROM ' + table + ...; }
//   const sql = buildLookupQuery('users', req.params.id);
//   db.query(sql);
// Neither the inline regexes above (concatenation isn't written inside the call) nor
// SQL_BUILT_VAR_RE (the concatenation is a `return` statement, not a `const/let/var =`)
// ever see this. Requires a SQL keyword in the returned literal, same as SQL_BUILT_VAR_RE,
// so this doesn't fire on unrelated string-building helpers.
// `(?::\s*[^{;]+)?` tolerates a TS return-type annotation before the body brace (gap 4b):
// `function buildUserQuery(id): string {` -- mirrors the same tolerance lookupFunctionReturnExpr
// already has.
const FUNCTION_DECL_RE = /function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?::\s*[^{;]+)?\{/g;
const SQL_RETURN_BUILT_RE = new RegExp(
  `return\\s+` +
    `(?:` +
    `\`[^\`]*\\b${SQL_KEYWORDS}\\b[^\`]*\\$\\{[^\`]*\\}[^\`]*\`` +
    `|` +
    `(['"])(?:(?!\\1)[^\\n])*?\\b${SQL_KEYWORDS}\\b(?:(?!\\1)[^\\n])*?\\1\\s*\\+\\s*[\\w.$]+` +
    `(?:\\s*\\+\\s*(?:['"][^'"\\n]*['"]|[\\w.$]+))*` +
    `)`,
  'i',
);

function findSqlBuildingFunctionNames(clean) {
  const names = new Set();
  FUNCTION_DECL_RE.lastIndex = 0;
  let m;
  while ((m = FUNCTION_DECL_RE.exec(clean)) !== null) {
    const braceIndex = m.index + m[0].length - 1;
    const body = extractBalancedBraceBlock(clean, braceIndex);
    if (body && SQL_RETURN_BUILT_RE.test(body)) names.add(m[1]);
  }
  return names;
}

function findSqlTaintedCallSites(clean, original, fnNames) {
  const hits = [];
  for (const fnName of fnNames) {
    const escaped = fnName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const assignRe = new RegExp(`(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*(?:await\\s+)?${escaped}\\s*\\(`, 'g');
    let am;
    while ((am = assignRe.exec(clean)) !== null) {
      const varName = am[1];
      const afterAssignment = clean.slice(assignRe.lastIndex);
      const usageRe = buildSqlUsageRe(varName);
      if (usageRe.test(afterAssignment)) {
        hits.push({
          line: lineOfIndex(original, am.index),
          snippet: snippetAt(original, am.index),
          rawMessage: `SQL string built via concatenation/interpolation inside helper function "${fnName}()" is assigned to variable "${varName}" here and then passed to a .query/.execute/.raw call -- same SQL injection risk as inline concatenation, just one function call removed.`,
        });
      }
    }
  }
  return hits;
}

function checkSqlStringConcatenation(clean, filePath, original) {
  const hits = [];

  for (const re of [SQL_INLINE_TEMPLATE_RE, SQL_INLINE_CONCAT_RE]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(clean)) !== null) {
      hits.push({
        line: lineOfIndex(original, m.index),
        snippet: snippetAt(original, m.index),
        rawMessage: 'SQL-like call (.query/.execute/.raw) built with template-literal interpolation or string concatenation of a variable instead of a parameterized query.',
      });
    }
  }

  SQL_BUILT_VAR_RE.lastIndex = 0;
  let m;
  while ((m = SQL_BUILT_VAR_RE.exec(clean)) !== null) {
    const varName = m[1];
    const afterAssignment = clean.slice(SQL_BUILT_VAR_RE.lastIndex);
    const usageRe = buildSqlUsageRe(varName);
    if (usageRe.test(afterAssignment)) {
      hits.push({
        line: lineOfIndex(original, m.index),
        snippet: snippetAt(original, m.index),
        rawMessage: `SQL string built via concatenation/interpolation into variable "${varName}", which is then passed to a .query/.execute/.raw call instead of using a parameterized query.`,
      });
    }
  }

  const sqlBuildingFnNames = findSqlBuildingFunctionNames(clean);
  if (sqlBuildingFnNames.size > 0) {
    hits.push(...findSqlTaintedCallSites(clean, original, sqlBuildingFnNames));
  }

  return hits;
}

// --- Check 5: eval-on-input -----------------------------------------------------------

const DANGEROUS_CALLEE_RE = /\b(eval|new\s+Function|exec|execSync)\s*\(/g;

// extractBalancedCallArg, splitTopLevelArgs, and lookupFunctionReturnExpr now live in
// ./util.js (moved 2026-07-24, evasion-bypass hardening pass) — imported above. Shared by
// the mass-assignment, insecure-cookie-flags, and open-redirect checks below (which need
// to reason about individual call arguments) and by secrets.js's checks 11-12 (which need
// the same "look inside a same-file function body" resolution these checks already used).

function argLooksInterpolated(arg, clean) {
  const trimmed = arg.trim();
  if (trimmed === '') return false;
  // Template literal containing ${...}
  if (/`[^`]*\$\{[^`]*\}[^`]*`/.test(trimmed)) return true;
  // String concatenation with a variable: "..." + var  or var + "..."
  if (/['"][^'"]*['"]\s*\+\s*[A-Za-z_$]/.test(trimmed) || /[A-Za-z_$][\w.$]*\s*\+\s*['"]/.test(trimmed)) return true;
  // Bare identifier / member expression with no quotes at all — the whole arg is a
  // variable, so whatever built its value happens elsewhere (can't rule out user input).
  if (/^[A-Za-z_$][\w.$[\]]*$/.test(trimmed)) return true;
  // One level of inlining: if the argument is itself a same-file function call (e.g.
  // `eval(buildExpression(req.body.code))`), look up that function's own return
  // expression and test *that* instead of giving up just because the outer argument text
  // contains parentheses. A leading `await` is stripped first (gap 5a): an inlined
  // async-arrow helper (`eval(await buildExpression(req.body.code))`) otherwise broke the
  // call-expression anchor -- same normalization the open-redirect check already applies.
  const callMatch = trimmed.replace(/^await\s+/, '').match(/^([A-Za-z_$][\w.$]*)\s*\(/);
  if (callMatch && clean) {
    const returnExpr = lookupFunctionReturnExpr(clean, callMatch[1]);
    if (returnExpr && argLooksInterpolated(returnExpr, null)) return true; // null: don't recurse a 2nd level
  }
  return false;
}

// `exec`/`execSync` collide with an extremely common, totally unrelated JS idiom:
// RegExp.prototype.exec() (e.g. `while ((m = re.exec(text)) !== null)`), which is not
// child_process at all.
//
// This used to be guarded by "does this FILE mention the substring `child_process`
// anywhere" — which stops a regex-only file with no child_process import at all, but does
// NOT stop the shape the real-world false-positive validation actually found
// (docs/REAL_WORLD_VALIDATION.md §5/§6, all 7 real-world eval-on-input false positives): a
// file that legitimately imports child_process for one thing and ALSO calls RegExp#exec
// somewhere else in that same file (a filename-number extractor, an allowlist validator, a
// pattern-scan over text) — file-wide "mentions child_process" is true, so the old guard
// let every unrelated .exec() in that file straight through. The fix traces each
// exec/execSync CALL SITE back to its own receiver instead of checking the whole file:
//   - a bare call (`exec(cmd)`/`execSync(cmd)`, no receiver) only counts if that exact
//     name was destructured directly off `require('child_process')`/`import ... from
//     'child_process'`;
//   - a member call (`x.exec(cmd)`/`x.execSync(cmd)`) only counts if `x` is `require(
//     'child_process')` written inline, or a variable/namespace import traced back to a
//     `require('child_process')`/`import * as x from 'child_process'`/`import x from
//     'child_process'` declaration.
// Any other receiver shape — a regex literal (`/pattern/.exec(...)`), a variable assigned
// from `new RegExp(...)` or a regex literal, an unrelated object, or anything this can't
// confidently resolve — is left alone (bail rather than guess). That's also what actually
// excludes RegExp#exec: it never satisfies the child_process-traced check below, so no
// separate "is this receiver a regex" test is even needed.
const CHILD_PROCESS_REQUIRE_STRING_RE = "['\"`]child_process['\"`]";

// Classifies what precedes an exec/execSync callee at `calleeIndex` (the index where the
// literal text "exec"/"execSync" itself starts, i.e. DANGEROUS_CALLEE_RE's m.index for
// that branch) into one of:
//   { kind: 'bare' }                    -- exec(...)/execSync(...), no receiver at all
//   { kind: 'inline-require' }          -- require('child_process').exec(...)
//   { kind: 'identifier', name }        -- name.exec(...)/name.execSync(...)
//   { kind: 'other' }                   -- some other/unrecognized receiver shape
// Only looks at a bounded window immediately before calleeIndex — plenty for any real
// receiver expression, and keeps this a cheap per-match check rather than a file-wide scan.
const RECEIVER_WINDOW_CHARS = 400;

function classifyExecReceiver(clean, calleeIndex) {
  const windowStart = Math.max(0, calleeIndex - RECEIVER_WINDOW_CHARS);
  const before = clean.slice(windowStart, calleeIndex);

  if (!/\.\s*$/.test(before)) return { kind: 'bare' };

  const inlineRequireRe = new RegExp(`require\\s*\\(\\s*${CHILD_PROCESS_REQUIRE_STRING_RE}\\s*\\)\\s*\\.\\s*$`);
  if (inlineRequireRe.test(before)) return { kind: 'inline-require' };

  // A single bare identifier immediately before the dot, e.g. `cp.exec(`/
  // `child_process.exec(`. The `(?:^|[^\w$.\])])` alternative requires the character
  // right before the identifier (if any, within the window) to NOT itself be a word/`.`/
  // `)`/`]` character, so a longer chain like `foo.bar.exec(` isn't misread as a bare
  // "bar" receiver — left as 'other' (unresolved) instead.
  const identMatch = /(?:^|[^\w$.\])])\s*([A-Za-z_$][\w$]*)\s*\.\s*$/.exec(before);
  if (identMatch) return { kind: 'identifier', name: identMatch[1] };

  return { kind: 'other' };
}

// True if `callName` (the literal text "exec" or "execSync" that DANGEROUS_CALLEE_RE
// matched with no receiver) was destructured directly off a child_process import in this
// file. No rename-handling needed here: a renamed destructure (`const { exec: run } =
// require('child_process')`) produces a bare call site that literally reads "run(...)",
// which DANGEROUS_CALLEE_RE never matches in the first place — this function is only ever
// asked about the plain, unrenamed form.
function isPlainDestructuredFromChildProcess(clean, callName) {
  const escaped = callName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const requireRe = new RegExp(
    `(?:const|let|var)\\s*\\{[^}]*\\b${escaped}\\b(?!\\s*:)[^}]*\\}\\s*=\\s*require\\(\\s*${CHILD_PROCESS_REQUIRE_STRING_RE}\\s*\\)`,
  );
  if (requireRe.test(clean)) return true;
  const importRe = new RegExp(
    `import\\s*\\{[^}]*\\b${escaped}\\b(?!\\s+as\\b)[^}]*\\}\\s*from\\s*${CHILD_PROCESS_REQUIRE_STRING_RE}`,
  );
  return importRe.test(clean);
}

// True if `varName` was itself assigned/imported from the child_process module in this
// file (`const cp = require('child_process')`, `import * as cp from 'child_process'`,
// `import cp from 'child_process'`) — as opposed to merely being NAMED something
// child_process-ish while actually holding a regex (`new RegExp(...)`, a regex literal) or
// anything else. Traced back to a real declaration rather than trusted by name.
function isChildProcessModuleVar(clean, varName) {
  const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const requireRe = new RegExp(`(?:const|let|var)\\s+${escaped}\\s*=\\s*require\\(\\s*${CHILD_PROCESS_REQUIRE_STRING_RE}\\s*\\)`);
  if (requireRe.test(clean)) return true;
  const importStarRe = new RegExp(`import\\s*\\*\\s*as\\s+${escaped}\\s+from\\s*${CHILD_PROCESS_REQUIRE_STRING_RE}`);
  if (importStarRe.test(clean)) return true;
  const importDefaultRe = new RegExp(`import\\s+${escaped}\\s+from\\s*${CHILD_PROCESS_REQUIRE_STRING_RE}`);
  return importDefaultRe.test(clean);
}

// Ties the receiver classification and the two resolvers above together: true only when
// this SPECIFIC exec/execSync call site traces back to a real child_process import, false
// (bail rather than guess) for every other receiver shape — including a regex literal, a
// regex-holding variable, or any receiver this can't confidently resolve.
function isChildProcessExecCall(clean, calleeIndex, callName) {
  const receiver = classifyExecReceiver(clean, calleeIndex);
  if (receiver.kind === 'bare') return isPlainDestructuredFromChildProcess(clean, callName);
  if (receiver.kind === 'inline-require') return true;
  if (receiver.kind === 'identifier') return isChildProcessModuleVar(clean, receiver.name);
  return false; // 'other' — unrecognized receiver shape, don't guess
}

function checkEvalOnInput(clean, filePath, original) {
  const hits = [];
  DANGEROUS_CALLEE_RE.lastIndex = 0;
  let m;
  while ((m = DANGEROUS_CALLEE_RE.exec(clean)) !== null) {
    const callName = m[1];
    if ((callName === 'exec' || callName === 'execSync') && !isChildProcessExecCall(clean, m.index, callName)) {
      continue; // this call site doesn't trace back to child_process -- almost certainly RegExp#exec or an unrelated exec()
    }
    const openParenIndex = m.index + m[0].length - 1; // position of the '(' itself
    const extracted = extractBalancedCallArg(clean, openParenIndex);
    if (!extracted) continue; // unbalanced parens — bail rather than guess
    if (argLooksInterpolated(extracted.arg, clean)) {
      hits.push({
        line: lineOfIndex(original, m.index),
        snippet: snippetAt(original, m.index),
        rawMessage: `${callName.replace(/\s+/g, ' ')}() called with a variable interpolated into the command/code string instead of a fixed literal.`,
      });
    }
    DANGEROUS_CALLEE_RE.lastIndex = extracted.end; // resume search after this whole call
  }
  return hits;
}

// --- Check 6: cors-wildcard-with-credentials ------------------------------------------

const CORS_WILDCARD_RE = /(?:origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"])/gi;
// The `credentials\s*:\s*[^,}]*(?:\?\?|\|\|)\s*true` alternative (gap 6c) recognizes
// `credentials: options.withCredentials ?? true` / `... || true` -- a nullish/or default
// that still resolves to true, which the literal-only form missed entirely so the whole
// check short-circuited. Low FP risk: this only *enables* a finding, and only when a
// wildcard origin is also present.
const CORS_CREDENTIALS_RE = /(?:credentials\s*:\s*true|credentials\s*:\s*[^,}]*(?:\?\?|\|\|)\s*true|Access-Control-Allow-Credentials['"]?\s*[:,]\s*['"]?true)/i;

// Wildcard-via-variable: `origin: someVar` where `someVar`'s own assignment can resolve
// to '*' (a literal default via `||`/`??`, a ternary branch, etc.) is the same dangerous
// misconfiguration as a literal '*' next to `origin:` -- just one hop further away from
// the call site, which is enough to dodge CORS_WILDCARD_RE's purely positional match.
const CORS_ORIGIN_VAR_RE = /origin\s*:\s*([A-Za-z_$][\w.$]*)\s*[,}]/gi;

function findVarAssignmentContainingWildcard(clean, varName) {
  const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Direct same-file const/let/var declaration whose RHS textually contains a '*' literal
  // (covers `const o = req.query.x || '*'`, ternaries, etc.). `(?::\s*[^=;\n]+?)?` tolerates
  // a TS variable type annotation (gap 6b): `const allowedOrigin: string = '*'`.
  const re = new RegExp(`(?:const|let|var)\\s+${escaped}\\s*(?::\\s*[^=;\\n]+?)?\\s*=\\s*([^;\\n]+)`, 'i');
  const m = clean.match(re);
  if (m && /['"]\*['"]/.test(m[1])) return m;
  // Static class field / variable chain (gap 6a): `static origin = '*'` referenced as
  // `CorsConfig.origin`, or a plain var hop -- resolveConcatExpression (util.js) resolves
  // both a `ClassName.FIELD` static field and a const/let/var chain to their literal value.
  const resolved = resolveConcatExpression(clean, varName);
  if (resolved === '*') return { 0: `${varName} resolves to '*'`, index: 0 };
  return null;
}

function checkCorsWildcardWithCredentials(clean, filePath, original) {
  const hasCredentials = CORS_CREDENTIALS_RE.test(clean);
  if (!hasCredentials) return [];
  const hits = [];

  CORS_WILDCARD_RE.lastIndex = 0;
  let m;
  while ((m = CORS_WILDCARD_RE.exec(clean)) !== null) {
    hits.push({
      line: lineOfIndex(original, m.index),
      snippet: snippetAt(original, m.index),
      rawMessage: "CORS origin set to '*' in a file that also sets credentials:true / Access-Control-Allow-Credentials:true — browsers reject this combination, but some proxies/older clients won't, and it signals a misconfigured CORS policy.",
    });
  }

  CORS_ORIGIN_VAR_RE.lastIndex = 0;
  while ((m = CORS_ORIGIN_VAR_RE.exec(clean)) !== null) {
    const varName = m[1];
    const assignMatch = findVarAssignmentContainingWildcard(clean, varName);
    if (assignMatch) {
      hits.push({
        line: lineOfIndex(original, m.index),
        snippet: snippetAt(original, m.index),
        rawMessage: `CORS origin is set from variable "${varName}", whose own assignment can resolve to the wildcard '*' (${assignMatch[0].trim().slice(0, 120)}) — combined with credentials:true this is the same dangerous misconfiguration as a literal '*', just one variable hop away.`,
      });
    }
  }

  return hits;
}

// --- Check 7: missing-auth-middleware --------------------------------------------------

// Case A: the route's own path literal names a sensitive area directly, e.g.
//   app.get('/admin/dashboard', ...)
const SENSITIVE_ROUTE_INLINE_RE = /\.(get|post|put|delete|patch|all)\s*\(\s*(['"`])(\/(?:admin|internal|_debug|internal-api)[^'"`]*)\2/gi;

// Case B: the sensitive-ness comes from *where the file lives*, not the path literal —
// extremely common with Express Router: the mount prefix ('/admin') is applied in the
// parent file (`app.use('/admin', adminRoutes)`), while the router file itself only
// ever sees relative paths like router.get('/') or router.post('/delete-user'), with no
// "admin" text in the call at all. Any route/all-method call in such a file is treated
// as a sensitive-route candidate.
const SENSITIVE_FILE_PATH_RE = /(^|\/)(admin|internal|_?debug)(s)?([./]|$)/i;
const ANY_ROUTE_CALL_RE = /\.(get|post|put|delete|patch|all)\s*\(\s*(['"`])([^'"`]*)\2/gi;

// Case C: the route path is built via string concatenation instead of a single literal,
// e.g. `router.post(ADMIN_BASE + '/delete-user', ...)` with `const ADMIN_BASE = '/adm' +
// 'in';` declared earlier -- SENSITIVE_ROUTE_INLINE_RE requires the call's first argument
// to be one complete quoted literal, so a binary `+` expression is invisible to it even
// though the resolved path is exactly as sensitive.
const ROUTE_CALL_CONCAT_RE = /\.(get|post|put|delete|patch|all)\s*\(\s*((?:[A-Za-z_$][\w.$]*|['"`](?:[^'"`\\\n]|\\.)*['"`])(?:\s*\+\s*(?:[A-Za-z_$][\w.$]*|['"`](?:[^'"`\\\n]|\\.)*['"`]))+)/gi;
const SENSITIVE_PATH_PREFIX_RE = /^\/(?:admin|internal|_debug|internal-api)(?:\/|$)/;

// AUTH_KEYWORD_RE used to fire on ANY occurrence of one of these words within a wide
// +/-100/2000-char window -- including a merely-decorative import (`require('./auth-
// logger')`) that never actually enforces anything, or a log call that just mentions
// "auth" in passing. Tightened to require the keyword actually look like enforcement:
// either (a) it's one of the arguments passed into the SAME route-registration call
// (`router.get(path, requireAuth, handler)` -- real Express middleware wiring), or (b) a
// termination pattern (401/403 response, or return/throw) appears in the following
// handler-body window, which is the only way a check for auth can actually stop a
// request rather than just mention the word "auth" somewhere nearby.
//
// AUTH_KEYWORD_VOCAB is the single shared word list for "does this identifier look
// auth-ish" -- deliberately unanchored (no leading `\b` on "auth" itself) because the
// single most idiomatic Express middleware-naming style is camelCase with the keyword
// starting mid-identifier (`requireAuth`, `checkAuth`, `ensureLoggedIn`-style), where
// there is no word-boundary transition immediately before "Auth" (`e`->`A`/`k`->`A` are
// both word-to-word). A leading `\b` here previously made AUTH_KEYWORD_AS_ARG_RE invisible
// to exactly that naming style while still matching vocabulary-initial names like
// `authMiddleware`/`isAuthenticated` -- an asymmetry that didn't exist for the
// router.use(requireAuth) guard case below (AUTH_MIDDLEWARE_NAME_RE), which already
// deliberately dropped the anchor for the same reason. Both call sites now share this one
// vocabulary instead of maintaining two divergent patterns for the same "auth-ish
// identifier" test.
const AUTH_KEYWORD_VOCAB = '(auth|session|token|jwt|passport|isAuthenticated|requireLogin|ensureAuth|verifyToken|apikey|api_key|authorize|authenticate)\\w*';
const AUTH_KEYWORD_RE = new RegExp(`\\b${AUTH_KEYWORD_VOCAB}`, 'i');
const AUTH_KEYWORD_AS_ARG_RE = new RegExp(`${AUTH_KEYWORD_VOCAB}\\s*,`, 'i');
// Unanchored vocab match tested against an ALREADY-ISOLATED single middleware-argument
// identifier (see routeArgsHaveAuthMiddleware). Because the candidate is one isolated
// identifier, not a wide text window, a plain substring match can't spill into unrelated
// surrounding code -- and camelCase names like `requireAuth` (no word boundary before
// "Auth") are matched, which a `\b`-anchored version would miss.
const AUTH_KEYWORD_IN_IDENT_RE = new RegExp(AUTH_KEYWORD_VOCAB, 'i');
const AUTH_ENFORCEMENT_RE = /res\.(?:status\(\s*4(?:01|03)|sendStatus\(\s*4(?:01|03))|\bthrow\b/;
const ROUTE_WINDOW_CHARS = 2000; // fallback lookahead window if the call's parens can't be balanced

// Extracts the FULL argument list of the route-registration call starting at `callIndex`
// (path literal/expression, any middleware arguments, and the inline handler function
// body all together) by locating the call's own opening '(' and walking to its balanced
// closing ')' via extractBalancedCallArg (already used by the eval-on-input check above).
// Using the complete call text (rather than just the regex match up to the path literal,
// or a fixed-size forward slice) lets both enforcement checks below see real middleware
// wiring that appears *after* the path argument, e.g. `router.get('/admin', requireAuth,
// handler)`.
function extractRouteCallText(clean, callIndex) {
  const openParenIndex = clean.indexOf('(', callIndex);
  if (openParenIndex === -1) return null;
  const extracted = extractBalancedCallArg(clean, openParenIndex);
  return extracted ? extracted.arg : null;
}

// Tests case (a) -- "is an auth-ish identifier passed as a MIDDLEWARE argument" -- against
// only the middleware argument positions of a balanced route-registration call, NOT the
// whole call text. The first argument (the route path literal/expression) is dropped, and
// each remaining argument is considered only if it is a bare identifier or an array of
// identifiers (`[requireAuth]` / `[requireAuth, requireAdmin]`); an inline handler
// function/arrow is neither, so its BODY is never scanned here. This closes gap 7-A (a
// handler-body local named with a vocab word mid-identifier -- `pageToken`, `sessionCount`
// -- used to spuriously suppress a genuinely-unauthenticated route once AUTH_KEYWORD_AS_ARG_RE
// was unanchored) and gap 7-B (a single-element middleware array `[requireAuth]`, whose
// identifier is followed by `]` not `,`, went unrecognized) in one structural change --
// scoping args-vs-body is the only thing that separates a real middleware arg (`requireAuth`)
// from an identically-shaped handler-body local (`pageToken`).
function routeArgsHaveAuthMiddleware(callText) {
  const args = splitTopLevelArgs(callText);
  // Consider every argument that is a bare identifier or an array of bare identifiers. A
  // route path literal is a quoted string (or a `+`-concat expression) and an inline handler
  // is an arrow/function -- neither is a bare identifier, so both are naturally excluded
  // without special-casing argument position. This matters because argument position is not
  // reliable: `router.get(path, requireAuth, handler)` has the middleware at index 1, but a
  // chained `router.route(path).get(requireAuth, handler)` has it at index 0 (the `.get()`
  // call carries no path argument at all). Not skipping the handler-function body is exactly
  // what keeps a handler-body local named with a vocab word (`pageToken`) from suppressing a
  // finding (gap 7-A) -- the function arg is not a bare identifier, so its body is never read.
  for (const rawArg of args) {
    const arg = rawArg.trim();
    const inner = arg.replace(/^\[\s*/, '').replace(/\s*\]$/, ''); // unwrap a [ ... ] middleware array, if present
    for (const el of inner.split(',')) {
      const ident = el.trim();
      if (/^[A-Za-z_$][\w$.]*$/.test(ident) && AUTH_KEYWORD_IN_IDENT_RE.test(ident)) return true;
    }
  }
  return false;
}

function routeCallHasEnforcedAuth(clean, callIndex) {
  const balanced = extractRouteCallText(clean, callIndex);
  const callText = balanced || clean.slice(callIndex, Math.min(clean.length, callIndex + ROUTE_WINDOW_CHARS));
  // (a) an auth-ish identifier passed as a middleware argument in the call itself, e.g.
  // router.get('/admin', requireAuth, (req, res) => {...}) -- real Express middleware
  // wiring. When we have a balanced call, restrict this to the actual middleware argument
  // positions (routeArgsHaveAuthMiddleware); only fall back to the looser comma-based
  // whole-text scan when the call's parens couldn't be balanced.
  if (balanced) {
    if (routeArgsHaveAuthMiddleware(balanced)) return true;
  } else if (AUTH_KEYWORD_AS_ARG_RE.test(callText)) {
    return true;
  }
  // (b) the handler body actually terminates the request on failure (401/403/throw)
  // somewhere within the call.
  return AUTH_ENFORCEMENT_RE.test(callText);
}

function findMissingAuthHits(clean, original, routeRe, guardIndexes) {
  const hits = [];
  routeRe.lastIndex = 0;
  let m;
  while ((m = routeRe.exec(clean)) !== null) {
    const routePath = m[3];
    if (routeCallHasEnforcedAuth(clean, m.index)) continue;
    if (hasAuthGuardUseBefore(guardIndexes, m.index)) continue;
    hits.push({
      line: lineOfIndex(original, m.index),
      snippet: snippetAt(original, m.index),
      rawMessage: `Route handler for admin/internal-looking path "${routePath}" has no enforced auth/session/token check found in the same call's middleware chain or the handler body (no 401/403 response or throw/return-on-failure pattern nearby).`,
    });
  }
  return hits;
}

function findMissingAuthHitsFromConcatPaths(clean, original, guardIndexes) {
  const hits = [];
  ROUTE_CALL_CONCAT_RE.lastIndex = 0;
  let m;
  while ((m = ROUTE_CALL_CONCAT_RE.exec(clean)) !== null) {
    const resolved = resolveConcatExpression(clean, m[2]);
    if (!resolved || !SENSITIVE_PATH_PREFIX_RE.test(resolved)) continue;
    if (routeCallHasEnforcedAuth(clean, m.index)) continue;
    if (hasAuthGuardUseBefore(guardIndexes, m.index)) continue;
    hits.push({
      line: lineOfIndex(original, m.index),
      snippet: snippetAt(original, m.index),
      rawMessage: `Route handler for admin/internal-looking path "${resolved}" (built via string concatenation rather than a single literal, so it's easy to miss) has no enforced auth/session/token check found nearby.`,
    });
  }
  return hits;
}

// --- Case D (gap A, 2026-07-24 audit): chained `.route(path).method(...)` syntax --------
// Express's chainable Router syntax splits the path literal and the HTTP-method call
// across two separate expressions -- `router.route('/admin/dashboard').get(handler)`
// first registers the path via `.route(path)`, then chains `.get/.post/etc(...)` directly
// off the SAME expression. SENSITIVE_ROUTE_INLINE_RE (and the concat variant) both require
// the path literal and the HTTP-method call to appear together in one `.method(path, ...)`
// invocation, so this idiomatic, extremely common form was invisible to either -- neither
// half of the chain looks like a route registration on its own.
const ROUTE_CHAIN_RE = /\.route\s*\(\s*(['"`])(\/(?:admin|internal|_debug|internal-api)[^'"`]*)\1\s*\)/gi;
const CHAIN_METHOD_RE = /^(\s*\.\s*(get|post|put|delete|patch|all)\s*\()/i;

// Starting immediately after a `.route(path)` call's closing paren, walks forward through
// any directly-chained `.method(...)` calls (`.get(...).post(...)...`), returning each
// one's method name and the index of its own `.method(` segment. That index is a valid
// `callIndex` for routeCallHasEnforcedAuth, which only needs a position at-or-before the
// call's opening paren with no OTHER '(' in between -- true here since CHAIN_METHOD_RE's
// match contains no parens before the final one. Stops the moment the text no longer
// continues the chain (a semicolon, unrelated code, end of file, etc).
function findChainedRouteMethodCalls(clean, fromIndex) {
  const calls = [];
  let pos = fromIndex;
  while (pos < clean.length) {
    const slice = clean.slice(pos);
    const m = CHAIN_METHOD_RE.exec(slice);
    if (!m) break;
    const openParenIndex = pos + m[1].length - 1;
    const extracted = extractBalancedCallArg(clean, openParenIndex);
    if (!extracted) break;
    calls.push({ methodName: m[2].toLowerCase(), callIndex: pos });
    pos = extracted.end + 1;
  }
  return calls;
}

function findMissingAuthHitsFromRouteChains(clean, original, guardIndexes) {
  const hits = [];
  ROUTE_CHAIN_RE.lastIndex = 0;
  let m;
  while ((m = ROUTE_CHAIN_RE.exec(clean)) !== null) {
    const routePath = m[2];
    const chainedCalls = findChainedRouteMethodCalls(clean, m.index + m[0].length);
    for (const call of chainedCalls) {
      if (routeCallHasEnforcedAuth(clean, call.callIndex)) continue;
      if (hasAuthGuardUseBefore(guardIndexes, call.callIndex)) continue;
      hits.push({
        line: lineOfIndex(original, call.callIndex),
        snippet: snippetAt(original, call.callIndex),
        rawMessage: `Route handler for admin/internal-looking path "${routePath}" (registered via chained router.route(path).${call.methodName}(...) syntax) has no enforced auth/session/token check found in the same call's middleware chain or the handler body.`,
      });
    }
  }
  return hits;
}

// --- Case E (gap B, 2026-07-24 audit): router-level `.use(<identifier>)` guard ----------
// A bare-identifier `.use()` call registered on a router/app BEFORE a route is defined
// (`router.use(requireAuth)` followed further down by `router.get('/admin', handler)`) is
// real, idiomatic Express middleware wiring that protects every route registered after it
// -- not just the individual call `routeCallHasEnforcedAuth` already inspects in isolation.
// Restricted to a genuinely BARE identifier argument (no inline arrow/function body, no
// additional arguments) so this can't suppress findings for an unrelated body-parser/
// logging middleware wired the same syntactic way, e.g. `router.use(express.json())` or
// `router.use((req, res, next) => { log(req); next(); })` -- neither is a single bare
// identifier. The identifier itself still has to look auth-ish by name.
const USE_BARE_IDENTIFIER_RE = /\.use\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/g;

// Shares AUTH_KEYWORD_RE's keyword vocabulary but deliberately drops its leading `\b`
// anchor: this is only ever tested against an ALREADY-ISOLATED bare identifier captured by
// USE_BARE_IDENTIFIER_RE above (e.g. "requireAuth", "ensureLoggedIn"), never against a
// wide text window, so a plain substring match can't spill into unrelated surrounding code
// the way the anchored version elsewhere guards against. Anchoring \b before "auth" would
// otherwise miss extremely common camelCase middleware names like "requireAuth" or
// "checkAuth", where "auth"/"Auth" starts mid-identifier rather than at a word boundary --
// exactly the shape of the router.use(requireAuth) idiom this case exists to recognize.
const AUTH_MIDDLEWARE_NAME_RE = /(auth|session|token|jwt|passport|login|guard|protect|apikey|api_key)/i;

function findAuthGuardUseIndexes(clean) {
  const indexes = [];
  USE_BARE_IDENTIFIER_RE.lastIndex = 0;
  let m;
  while ((m = USE_BARE_IDENTIFIER_RE.exec(clean)) !== null) {
    if (AUTH_MIDDLEWARE_NAME_RE.test(m[1])) indexes.push(m.index);
  }
  return indexes;
}

function hasAuthGuardUseBefore(guardIndexes, callIndex) {
  return guardIndexes.some((idx) => idx < callIndex);
}

function checkMissingAuthMiddleware(clean, filePath, original) {
  const normalized = filePath.split(path.sep).join('/');
  const guardIndexes = findAuthGuardUseIndexes(clean);
  if (SENSITIVE_FILE_PATH_RE.test(normalized)) {
    // File itself lives under an admin/internal/debug path (e.g. routes/admin.js,
    // routes/debug.js) — treat every route call in it as a sensitive-route candidate,
    // since the real mount prefix that makes it sensitive typically lives in a
    // different file (the parent app.use('/admin', ...) call).
    return findMissingAuthHits(clean, original, ANY_ROUTE_CALL_RE, guardIndexes);
  }
  return [
    ...findMissingAuthHits(clean, original, SENSITIVE_ROUTE_INLINE_RE, guardIndexes),
    ...findMissingAuthHitsFromConcatPaths(clean, original, guardIndexes),
    ...findMissingAuthHitsFromRouteChains(clean, original, guardIndexes),
  ];
}

// --- Check 8: supabase-rls-disabled ----------------------------------------------------

const RLS_DISABLED_PATTERNS = [
  /ALTER TABLE\s+\S+\s+DISABLE ROW LEVEL SECURITY/i,
  /"?row_level_security"?\s*[:=]\s*false/i,
  /"?rowLevelSecurity"?\s*[:=]\s*false/i,
  /enable_row_level_security\s*=\s*false/i,
  // Was exact-key-name only, missing a differently-nested/abbreviated toggle expressing
  // the identical thing, e.g. `security: { rls: { enabled: false } }`. Matches an "rls" /
  // "row_level_security"-ish leaf key at any nesting depth, opening an object whose body
  // (before the next closing brace) contains `enabled: false`.
  /\b(?:rls|row[_-]?level[_-]?security)\b\s*:\s*\{[^{}]*\benabled\b\s*[:=]\s*false/i,
];

const SERVICE_ROLE_RE = /SUPABASE_SERVICE_ROLE_KEY|service_role/;

// Was a plain substring search for the literal env-var name -- defeated by building the
// name out of separate string parts at runtime (`['SUPABASE','SERVICE','ROLE','KEY'].join
// ('_')`) so the literal text never appears contiguous. A `process.env[<expr>]` computed
// member access (as opposed to the usual static `process.env.NAME`) is itself inherently
// suspicious in code that already looks client-side: bundlers generally can't statically
// inline a computed lookup, so whatever privileged env var name is being resolved here
// only exists at runtime -- exactly the shape this evasion produces regardless of what
// the resolved name turns out to be.
// Was `[A-Za-z_$][\w.$]*` -- a BARE identifier/member-chain key only, which missed the two
// runtime-assembled shapes the check's own comment advertises defending against (round-3
// authz audit, gaps 8-A/8-B): an array `.join()` key (`process.env[['SUPABASE','SERVICE',
// 'ROLE','KEY'].join('_')]`, bracket content starts with `[`) and a split-literal concat
// key (`process.env['SUPABASE_' + 'SERVICE_ROLE_KEY']`, content starts with a quote). Now
// matches ANY `process.env[<expr>]` and the loop excludes only the single static quoted
// literal case (`process.env['NAME']`), whose literal name the SERVICE_ROLE name search
// already covers -- realigning the regex with the comment's stated "any computed access is
// suspicious" intent.
const COMPUTED_ENV_ACCESS_RE = /process\.env\[\s*([^\]]+?)\s*\]/g;
const STATIC_ENV_KEY_LITERAL_RE = /^['"`][A-Za-z_$][\w]*['"`]$/;

function looksLikeClientSideFile(filePath, clean) {
  const normalized = filePath.split(path.sep).join('/');
  if (/\/pages\/api\//.test(normalized) || /\/api\//.test(normalized)) return false; // server route, not client
  if (/^['"]use client['"];?/m.test(clean)) return true;
  if (/\/(components|pages|app)\//.test(normalized) && !/\/(server|api|lib\/server)\//.test(normalized)) return true;
  return false;
}

function checkSupabaseRlsDisabled(clean, filePath, original) {
  const hits = [];

  for (const re of RLS_DISABLED_PATTERNS) {
    const m = clean.match(re);
    if (m) {
      hits.push({
        line: lineOfIndex(original, m.index),
        snippet: snippetAt(original, m.index),
        rawMessage: 'Configuration/SQL indicates row level security (RLS) is disabled on a Supabase table.',
      });
    }
  }

  const serviceRoleMatch = clean.match(SERVICE_ROLE_RE);
  if (serviceRoleMatch && looksLikeClientSideFile(filePath, clean)) {
    hits.push({
      line: lineOfIndex(original, serviceRoleMatch.index),
      snippet: snippetAt(original, serviceRoleMatch.index),
      rawMessage: 'Supabase service_role key referenced from what looks like client-side code — this key bypasses RLS and must never ship to the browser.',
    });
  }

  if (looksLikeClientSideFile(filePath, clean)) {
    COMPUTED_ENV_ACCESS_RE.lastIndex = 0;
    let cm;
    while ((cm = COMPUTED_ENV_ACCESS_RE.exec(clean)) !== null) {
      // A single static quoted literal (`process.env['NAME']`) is a plain named access, not
      // a runtime-assembled key -- its literal name is already covered by the service_role
      // name search above, so don't double-report it here.
      if (STATIC_ENV_KEY_LITERAL_RE.test(cm[1].trim())) continue;
      hits.push({
        line: lineOfIndex(original, cm.index),
        snippet: snippetAt(original, cm.index),
        rawMessage: `Client-side-looking code reads an environment variable via a computed/dynamic key (${cm[0]}) instead of a static process.env.NAME reference — bundlers generally can't statically inline a computed lookup, so the real (possibly privileged, e.g. service_role) env var name and value are only resolved at runtime and may still ship to the browser bundle undetected by a literal-name search.`,
      });
    }
  }

  return hits;
}

// --- Check 8, sibling detection: overly-permissive RLS policy in a .sql migration file --
// Everything above in checkSupabaseRlsDisabled() only ever reads JS/TS config/table-
// definition TEXT (an object literal's rowLevelSecurity:false-shaped key, or a
// service_role key referenced from client code) -- it never looks inside a real Supabase
// migration's own .sql file, which is exactly where an actual RLS policy gets defined.
// This was a real, hand-verified false negative (docs/REAL_WORLD_VALIDATION.md §6): while
// manually triaging a Bolt.new-built reservation app, a migration was found granting the
// public `anon` role unrestricted `SELECT ... USING (true)` access to a table of guest
// names, emails, and phone numbers -- and check 8 never flagged it, because it never read
// .sql files at all. This section closes that gap with a dedicated .sql-file pass, wired
// into scan() below alongside (not instead of) the existing SOURCE_EXTENSIONS pass.

// Blanks out SQL's own comment syntax (`-- line comment`, `/* block comment */`), the same
// "preserve length and every newline, replace comment characters with spaces" convention
// util.js's stripComments() uses for JS -- so a line number computed against the blanked
// text still lines up with the original source, and so a migration note that merely
// *mentions* "DISABLE ROW LEVEL SECURITY" or "USING (true)" in a comment isn't mistaken
// for a live statement.
function stripSqlComments(text) {
  let out = '';
  let state = 'code'; // 'code' | 'string' | 'lineComment' | 'blockComment'
  const n = text.length;
  let i = 0;
  while (i < n) {
    const ch = text[i];
    const next = i + 1 < n ? text[i + 1] : '';
    if (state === 'code') {
      if (ch === '-' && next === '-') { state = 'lineComment'; out += '  '; i += 2; continue; }
      if (ch === '/' && next === '*') { state = 'blockComment'; out += '  '; i += 2; continue; }
      if (ch === "'") { state = 'string'; out += ch; i += 1; continue; }
      out += ch;
      i += 1;
      continue;
    }
    if (state === 'string') {
      // Standard SQL escapes an embedded quote by doubling it ('') rather than a
      // backslash -- keep both characters and stay inside the string state.
      if (ch === "'" && next === "'") { out += "''"; i += 2; continue; }
      if (ch === "'") { state = 'code'; out += ch; i += 1; continue; }
      out += ch;
      i += 1;
      continue;
    }
    if (state === 'lineComment') {
      if (ch === '\n') { state = 'code'; out += '\n'; i += 1; continue; }
      out += ' ';
      i += 1;
      continue;
    }
    // state === 'blockComment'
    if (ch === '*' && next === '/') { state = 'code'; out += '  '; i += 2; continue; }
    out += ch === '\n' ? '\n' : ' ';
    i += 1;
  }
  return out;
}

// Matches a CREATE POLICY statement's header far enough to capture the table it applies
// to -- the policy's own name (quoted or bare, immediately after POLICY) is skipped since
// nothing downstream needs it. Case-insensitive and tolerant of newlines/arbitrary
// whitespace between tokens, since real migrations routinely wrap this across several
// lines (see the fixture under test/fixtures/evasion-attempts/23-supabase-rls-sql/).
const CREATE_POLICY_RE = /CREATE\s+POLICY\s+(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[A-Za-z_][\w]*)\s+ON\s+([A-Za-z_][\w."]*)/gi;

const POLICY_FOR_RE = /\bFOR\s+(SELECT|INSERT|UPDATE|DELETE|ALL)\b/i;
// Stops at the next USING/WITH CHECK clause (or the statement's terminating ';'), so the
// captured role list doesn't swallow the rest of the statement.
const POLICY_TO_RE = /\bTO\s+([^;]+?)(?=\s+USING\b|\s+WITH\s+CHECK\b|;|$)/i;
const POLICY_USING_KEYWORD_RE = /\bUSING\s*\(/i;
// Any policy granting the wildcard `anon` role, or Postgres's own built-in `public`/
// `PUBLIC` pseudo-role, is reachable by literally anyone with network access to the
// Supabase project's anon key (which, per Supabase's own documented architecture, is
// meant to ship in every client bundle -- see REAL_WORLD_VALIDATION.md §5.1). Matching
// both, not just the literal string "anon", avoids missing the equally-dangerous
// `TO public`/`TO PUBLIC` form.
const PERMISSIVE_ROLE_RE = /\b(anon|public)\b/i;

// Given a single statement's text and the RegExp match of a "USING (" keyword+paren found
// inside it, extracts the parenthesized expression via the same balanced-paren walker
// already used above for JS call arguments (extractBalancedCallArg works on any text --
// it only tracks (), quote state, and backslash escapes, none of which are JS-specific).
function extractUsingExpr(stmt, usingKeywordMatch) {
  const openParenIndex = usingKeywordMatch.index + usingKeywordMatch[0].length - 1;
  const extracted = extractBalancedCallArg(stmt, openParenIndex);
  return extracted ? extracted.arg.trim() : null;
}

// Walks forward from `fromIndex` (the start of a CREATE POLICY match) tracking paren depth
// and single-quoted string state to find this statement's own terminating ';' -- needed so
// the TO/USING clauses inspected below belong to THIS policy, not a later one in the same
// migration file. Heuristic, not a real SQL parser, same tradeoff as the rest of this file.
function extractSqlStatementText(text, fromIndex) {
  let depth = 0;
  let inString = false;
  for (let i = fromIndex; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (ch === "'" && text[i + 1] === "'") { i += 1; continue; } // doubled-quote escape
      if (ch === "'") inString = false;
      continue;
    }
    if (ch === "'") { inString = true; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') depth--;
    else if (ch === ';' && depth <= 0) return text.slice(fromIndex, i + 1);
  }
  return text.slice(fromIndex); // unterminated statement (e.g. missing trailing ';') -- take the rest of the file
}

function checkSupabaseRlsPermissivePolicySql(clean, original) {
  const hits = [];
  CREATE_POLICY_RE.lastIndex = 0;
  let m;
  while ((m = CREATE_POLICY_RE.exec(clean)) !== null) {
    const tableName = m[1];
    const stmt = extractSqlStatementText(clean, m.index);

    const toMatch = stmt.match(POLICY_TO_RE);
    if (!toMatch || !PERMISSIVE_ROLE_RE.test(toMatch[1])) continue; // scoped to a named/authenticated role only -- not this pattern

    const forMatch = stmt.match(POLICY_FOR_RE);
    const operation = forMatch ? forMatch[1].toUpperCase() : null; // an omitted FOR clause defaults to ALL in Postgres

    const usingKeywordMatch = POLICY_USING_KEYWORD_RE.exec(stmt);
    const usingExpr = usingKeywordMatch ? extractUsingExpr(stmt, usingKeywordMatch) : null;

    const triviallyPermissive = usingExpr !== null && /^true$/i.test(usingExpr);
    // INSERT-only policies use WITH CHECK to gate the *new* row, not USING -- omitting
    // USING there isn't the same "every existing row is now readable/writable" shape as
    // omitting it for SELECT/UPDATE/DELETE/ALL, where Postgres treats a missing USING
    // clause as an implicit `USING (true)` (unrestricted) by default.
    const missingUsingIsPermissive = !usingKeywordMatch && operation !== 'INSERT';

    if (!triviallyPermissive && !missingUsingIsPermissive) continue;

    const anchorIndex = usingKeywordMatch ? m.index + usingKeywordMatch.index : m.index;
    const reason = triviallyPermissive
      ? `its USING (${usingExpr}) clause imposes no real row filter`
      : `it has no USING clause at all, which Postgres/Supabase treats as unrestricted access to every row for ${operation || 'ALL'} operations`;

    hits.push({
      line: lineOfIndex(original, anchorIndex),
      snippet: snippetAt(original, m.index, 200),
      rawMessage: `CREATE POLICY on "${tableName}" grants the public/anon role ${operation || 'ALL'} access with no real restriction -- ${reason}. Any anonymous client can read (or write, depending on the operation) every row in this table, not just rows the requester is actually entitled to -- exactly the shape of a real Supabase data-exposure bug (see docs/REAL_WORLD_VALIDATION.md §6).`,
    });
  }
  return hits;
}

function checkSupabaseRlsSqlMigration(original) {
  const clean = stripSqlComments(original);
  const hits = [];

  // RLS_DISABLED_PATTERNS[0] (`ALTER TABLE ... DISABLE ROW LEVEL SECURITY`) was already
  // written for exactly this SQL shape, but before this .sql pass existed it could only
  // ever match if that literal text happened to appear inside a scanned .js/.ts file (e.g.
  // a template-literal migration string) -- a real .sql migration file was invisible to
  // it, same root cause as the missing CREATE POLICY coverage above. Reused unchanged, now
  // that .sql files are actually being read.
  const alterMatch = clean.match(RLS_DISABLED_PATTERNS[0]);
  if (alterMatch) {
    hits.push({
      line: lineOfIndex(original, alterMatch.index),
      snippet: snippetAt(original, alterMatch.index),
      rawMessage: 'SQL migration explicitly disables row level security (RLS) on a Supabase/Postgres table.',
    });
  }

  hits.push(...checkSupabaseRlsPermissivePolicySql(clean, original));
  return hits;
}

// --- Check 9: stripe-webhook-unverified -------------------------------------------------

// Was "does the text `constructEvent` appear anywhere in this file" -- true the moment
// the call exists, regardless of whether a failed verification actually stops the
// request. Evaded by calling constructEvent inside a try, then swallowing the thrown
// error in the catch (just logging it) and falling through to trust the raw body anyway.
// Fixed with two independent checks run once constructEvent is confirmed present:
//   (a) the catch block immediately following the constructEvent call must itself
//       terminate the request (return / throw / a 4xx response) -- otherwise a caught
//       verification failure is silently ignored and execution continues.
//   (b) even when the catch DOES terminate correctly, still flag a fallback pattern like
//       `const payload = event || JSON.parse(req.body)` -- combining the verified result
//       with a raw-body fallback reintroduces the exact risk verification exists to close.
const CATCH_BLOCK_START_RE = /\}\s*catch\s*(?:\([^)]*\))?\s*\{/g;
const CATCH_ENFORCEMENT_RE = /\b(?:return|throw)\b|res\.(?:status\(\s*4|sendStatus\(\s*4)/;
const FALLBACK_TO_RAW_BODY_RE = /=\s*[\w.$]+\s*\|\|\s*(?:JSON\.parse\s*\(\s*)?(?:req|request)\.body/;
// Matches a request-body read in any of the three shapes real code uses -- dot access
// (`req.body`/`request.body`), bracket/computed access (`req['body']`, gap 9-B), or object
// destructuring straight off req/request (`const { body } = req` / `const { body: raw } =
// request`, gap 9-A).
const REQ_BODY_READ_RE = /(?:req|request)(?:\.body|\[\s*['"`]body['"`]\s*\])|(?:const|let|var)\s*\{[^}]*\bbody\b[^}]*\}\s*=\s*(?:req|request)\b/;
const MAX_CATCH_SEARCH_DISTANCE = 500; // catch must belong to the SAME try, not some unrelated later one

function extractCatchBlockAfter(clean, fromIndex) {
  CATCH_BLOCK_START_RE.lastIndex = fromIndex;
  const m = CATCH_BLOCK_START_RE.exec(clean);
  if (!m || m.index - fromIndex > MAX_CATCH_SEARCH_DISTANCE) return null;
  const openBraceIndex = m.index + m[0].length - 1;
  return extractBalancedBraceBlock(clean, openBraceIndex);
}

function checkStripeWebhookUnverified(clean, filePath, original) {
  const normalized = filePath.split(path.sep).join('/');
  const mentionsStripe = /stripe/i.test(clean) || /stripe/i.test(normalized);
  const mentionsWebhook = /webhook/i.test(clean) || /webhook/i.test(normalized);
  if (!mentionsStripe || !mentionsWebhook) return [];

  const constructMatch = clean.match(/constructEvent/);
  if (constructMatch) {
    const catchBody = extractCatchBlockAfter(clean, constructMatch.index);
    const catchEnforces = !!(catchBody && CATCH_ENFORCEMENT_RE.test(catchBody));
    const fallbackMatch = clean.match(FALLBACK_TO_RAW_BODY_RE);
    if (catchEnforces && !fallbackMatch) {
      return []; // verification present, its failure path actually aborts, no raw-body fallback either
    }
    // Anchor to the fallback pattern when that's the reason for the finding, otherwise to
    // the constructEvent() call itself -- a generic /webhook/i word search (the previous
    // fallback here) can land on an unrelated occurrence of the substring "webhook"
    // elsewhere in the file (see the analogous fix a few lines down for the no-constructEvent
    // branch, which is where this exact imprecision was first caught).
    const anchor = fallbackMatch || { index: constructMatch.index };
    const reason = !catchEnforces
      ? "its catch block does not reject/abort the request on verification failure (no return/throw/4xx response found) — the request may proceed unverified"
      : "the verified event is still combined with a fallback to the raw, unverified request body (e.g. `event || JSON.parse(req.body)`), reintroducing the same risk verification was meant to close";
    return [
      {
        line: lineOfIndex(original, anchor.index),
        snippet: snippetAt(original, anchor.index),
        rawMessage: `Stripe webhook handler calls stripe.webhooks.constructEvent(), but ${reason}.`,
      },
    ];
  }

  // Anchor to the actual request-body read that made this a finding, not a generic
  // `webhook` word search -- the file's first "webhook" substring can land anywhere (a
  // route path, an import, an unrelated SQL table name like `webhook_events` on a
  // completely different line/statement) and previously produced a finding that pointed at
  // code with no real connection to the unverified-body read. REQ_BODY_READ_RE recognizes
  // the body read via dot (`req.body`), bracket (`req['body']`, gap 9-B) OR destructuring
  // (`const { body } = req` / `const { body: raw } = req`, gap 9-A) -- the same dot/bracket/
  // destructure taint-source coverage check 13 already has, retrofitted here so two of the
  // most common ways to read a request body no longer silently hide a payment-verification
  // bypass.
  const rawBodyMatch = clean.match(REQ_BODY_READ_RE);
  if (!rawBodyMatch) return [];

  const anchor = rawBodyMatch;
  return [
    {
      line: lineOfIndex(original, anchor.index),
      snippet: snippetAt(original, anchor.index),
      rawMessage: 'Stripe webhook handler trusts the request body without calling stripe.webhooks.constructEvent to verify the signature.',
    },
  ];
}

// --- Check 13: mass-assignment ----------------------------------------------------------

// Three call shapes, all sharing the same underlying bug: the ENTIRE req.body/req.query
// object is handed to something that writes it onto a model/record, with no intermediate
// destructuring/allowlist of individual fields in between. An attacker can then set any
// field the model has -- isAdmin, role, verified, balance -- not just the ones the form
// on the page intended to expose.
//   Model.create(req.body)              -- method-call form (also covers .update/.save
//                                           and, as of 2026-07-24, Mongoose's other
//                                           common single-call write methods below)
//   new Model(req.body)                 -- constructor form
//   Object.assign(existingRecord, req.body) -- merge-onto-existing-record form
//
// Method-name alternation extended 2026-07-24 (round 2, realistic-library-code audit):
// was exactly `create|update|save`, which never matches Mongoose's `findByIdAndUpdate`/
// `findOneAndUpdate` (arguably the single most common Mongoose write method for this
// exact bug shape) or their delete/bulk siblings -- the arg-extraction logic below
// already handles multi-arg calls fine once the callee name itself is recognized.
const MODEL_METHOD_CALL_RE = /\.(create|update|save|findByIdAndUpdate|findOneAndUpdate|findByIdAndDelete|findOneAndDelete|findByIdAndRemove|updateOne|updateMany|bulkCreate)\s*\(/g;
const NEW_MODEL_CALL_RE = /\bnew\s+[A-Za-z_$][\w.$]*\s*\(/g;
const OBJECT_ASSIGN_CALL_RE = /\bObject\.assign\s*\(/g;

// Confirms an individual (already top-level-split) call argument is the WHOLE req.body/
// req.query object, not a specific field pulled off it (`req.body.name` doesn't match --
// that's a single field, not mass assignment) and not something already destructured into
// an allowlist. Resolves ANY number of variable hops via resolveIdentifierChain (util.js)
// -- `const raw = req.body; const input = raw; Model.create(input)` is exactly as
// dangerous as passing req.body inline, just two assignments further away, and is now
// followed all the way back rather than bailing after one hop. Requires the ENTIRE
// declaration to be `identifier = req.body;` (or req.query) with nothing else on the RHS --
// a destructuring assignment (`const { name, email } = req.body;`) has an object pattern on
// the LHS, not a bare identifier, so it never matches this and is correctly treated as
// already-allowlisted.
//
// Also recognizes `{ ...req.body }` / `{ ...someVar }` (spread-only object literals, where
// someVar itself resolves back to req.body/req.query via the same chain) -- a shallow copy
// of every field, functionally identical to passing req.body directly, but syntactically an
// object-literal expression rather than a bare identifier or the literal text "req.body". An
// object literal that spreads req.body/req.query *alongside other explicit keys*
// (`{ ...req.body, id }`) is arguably a partial allowlist and deliberately left out of scope
// here, same as the original red-team suggestion.
// Was dot-notation only (`^req\.(?:body|query)$`) -- bracket/computed access
// (`req['body']`) is semantically identical (the same whole, unfiltered object) but
// didn't match at all. Fixed 2026-07-24 (round 2 evasion audit).
function isReqBodyOrQueryExpr(text) {
  return /^req(?:\.(?:body|query)|\[\s*['"](?:body|query)['"]\s*\])$/.test(text.trim());
}

// Resolves a bare identifier back to a same-file req.body/req.query origin via object
// DESTRUCTURING (with or without renaming) straight off `req` itself:
//   const { body } = req;              -- plain
//   const { body: userData } = req;    -- renamed
// resolveIdentifierChain (util.js) only recognizes a bare-identifier declaration LHS
// (`name = req.body;`); a destructuring pattern on the LHS is a categorically different
// shape it was never meant to handle, so this extremely common way of pulling req.body
// out of req was invisible to argIsWholeReqBodyOrQuery entirely. Fixed 2026-07-24 (round
// 2 evasion audit). Returns 'body'/'query' if resolved, else null.
function resolveDestructuredReqSource(clean, varName) {
  const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  // Renamed form: const { body: userData } = req;  (varName === "userData")
  const renamedRe = new RegExp(
    `(?:const|let|var)\\s*\\{[^}]*\\b(body|query)\\s*:\\s*${escaped}\\b[^}]*\\}\\s*=\\s*req\\b`,
  );
  const renamedMatch = renamedRe.exec(clean);
  if (renamedMatch) return renamedMatch[1];

  // Plain form: const { body } = req;  (varName IS the source property name itself)
  // `(?!\s*:)` excludes matching "body"/"query" when it's actually the SOURCE key of a
  // renamed destructure elsewhere in the pattern (already handled by renamedRe above).
  if (varName === 'body' || varName === 'query') {
    const plainRe = new RegExp(`(?:const|let|var)\\s*\\{[^}]*\\b${escaped}\\b(?!\\s*:)[^}]*\\}\\s*=\\s*req\\b`);
    if (plainRe.test(clean)) return varName;
  }

  return null;
}

// Strips trailing TypeScript type assertions from an argument before the mass-assignment
// branches inspect it (round-3 fresh-look, gaps #2/#3): a `as` cast (`req.body as
// CreateUserDto`) and a non-null assertion (`req.body!`) are both extremely common,
// idiomatic TS and both a runtime no-op for this purpose, but each defeated the exact-text/
// bare-identifier branches, hiding the whole-object pass-through. Order: strip a trailing
// `as Type` first, then any trailing `!`.
function stripTsAssertions(text) {
  let t = text.trim();
  t = t.replace(/\s+as\s+[A-Za-z_$][\w$.<>[\]| ]*$/, '');
  t = t.replace(/!+$/, '');
  return t.trim();
}

// True if `text` is a spread-only object literal (`{ ...req.body }` / `{ ...someVar }`)
// whose spread target resolves back to req.body/req.query -- shared by the inline-arg case
// and the resolved-identifier case (`const data = { ...req.body }; Model.create(data)`,
// gap #4), where resolveIdentifierChain returns the terminal spread literal that then needs
// this same check rather than a bare isReqBodyOrQueryExpr test.
function spreadOnlyOfReqSource(clean, text) {
  const spreadMatch = text.trim().match(/^\{\s*\.\.\.\s*([A-Za-z_$][\w.$]*)\s*\}$/);
  if (!spreadMatch) return false;
  const spreadTarget = spreadMatch[1];
  if (isReqBodyOrQueryExpr(spreadTarget)) return true;
  if (/^[A-Za-z_$][\w$]*$/.test(spreadTarget)) {
    const resolved = resolveIdentifierChain(clean, spreadTarget);
    if (resolved && isReqBodyOrQueryExpr(resolved)) return true;
  }
  return false;
}

function argIsWholeReqBodyOrQuery(arg, clean) {
  const trimmed = stripTsAssertions(arg);
  if (isReqBodyOrQueryExpr(trimmed)) return true;

  if (spreadOnlyOfReqSource(clean, trimmed)) return true;

  // Prisma's entire write-call shape nests the actual payload one level down under a
  // `data:` key (`prisma.user.create({ data: req.body })` / `{ where, data: req.body }`)
  // instead of passing req.body as the top-level argument -- Prisma is one of the three
  // ORMs this check explicitly targets (per its own doc comment), but this shape was
  // completely unreachable before. Fixed 2026-07-24 (round 2, realistic-library-code
  // audit). Matches a `data:` key anywhere in the object literal, independent of other
  // keys (`where`, `select`, ...) present alongside it.
  if (/^\{/.test(trimmed)) {
    const dataMatch = trimmed.match(/\bdata\s*:\s*([^,}]+)/);
    if (dataMatch && argIsWholeReqBodyOrQuery(dataMatch[1].trim(), clean)) return true;
  }

  const identMatch = trimmed.match(/^[A-Za-z_$][\w$]*$/);
  if (identMatch) {
    const resolved = resolveIdentifierChain(clean, trimmed);
    if (resolved && isReqBodyOrQueryExpr(resolved)) return true;
    // The resolved terminal may itself be a spread-only object literal
    // (`const data = { ...req.body }; Model.create(data)`, gap #4).
    if (resolved && spreadOnlyOfReqSource(clean, resolved)) return true;
    if (resolveDestructuredReqSource(clean, trimmed)) return true;
  }
  return false;
}

function checkMassAssignment(clean, filePath, original) {
  const hits = [];

  MODEL_METHOD_CALL_RE.lastIndex = 0;
  let m;
  while ((m = MODEL_METHOD_CALL_RE.exec(clean)) !== null) {
    const methodName = m[1];
    const openParenIndex = m.index + m[0].length - 1;
    const extracted = extractBalancedCallArg(clean, openParenIndex);
    if (!extracted) continue;
    const args = splitTopLevelArgs(extracted.arg);
    if (args.some((a) => argIsWholeReqBodyOrQuery(a, clean))) {
      hits.push({
        line: lineOfIndex(original, m.index),
        snippet: snippetAt(original, m.index),
        rawMessage: `.${methodName}() is called with req.body/req.query passed through in its entirety, with no destructuring/allowlist of specific fields -- an attacker can set any field the model has (e.g. isAdmin, role, verified, balance), not just the ones the form intended.`,
      });
    }
    MODEL_METHOD_CALL_RE.lastIndex = extracted.end;
  }

  NEW_MODEL_CALL_RE.lastIndex = 0;
  while ((m = NEW_MODEL_CALL_RE.exec(clean)) !== null) {
    const openParenIndex = m.index + m[0].length - 1;
    const extracted = extractBalancedCallArg(clean, openParenIndex);
    if (!extracted) continue;
    const args = splitTopLevelArgs(extracted.arg);
    if (args.some((a) => argIsWholeReqBodyOrQuery(a, clean))) {
      hits.push({
        line: lineOfIndex(original, m.index),
        snippet: snippetAt(original, m.index),
        rawMessage: 'new Model(req.body) constructs a model instance directly from the raw request body/query with no destructuring/allowlist -- an attacker can set any field the model has, including ones never meant to be user-settable.',
      });
    }
    NEW_MODEL_CALL_RE.lastIndex = extracted.end;
  }

  OBJECT_ASSIGN_CALL_RE.lastIndex = 0;
  while ((m = OBJECT_ASSIGN_CALL_RE.exec(clean)) !== null) {
    const openParenIndex = m.index + m[0].length - 1;
    const extracted = extractBalancedCallArg(clean, openParenIndex);
    if (!extracted) continue;
    const args = splitTopLevelArgs(extracted.arg);
    if (args.length >= 2 && args.slice(1).some((a) => argIsWholeReqBodyOrQuery(a, clean))) {
      hits.push({
        line: lineOfIndex(original, m.index),
        snippet: snippetAt(original, m.index),
        rawMessage: 'Object.assign(existingRecord, req.body) merges the raw request body/query directly onto an existing record with no destructuring/allowlist -- an attacker can overwrite any field on that record, including ones never meant to be user-settable.',
      });
    }
    OBJECT_ASSIGN_CALL_RE.lastIndex = extracted.end;
  }

  return hits;
}

// --- Check 14: insecure-cookie-flags -----------------------------------------------------

// res.cookie(name, value[, options]) where the options object is either absent entirely,
// or present but missing httpOnly:true/secure:true (or explicitly sets either to false),
// for what looks like a session/auth cookie -- judged by the cookie's own name (e.g.
// "sessionId", "authToken") or by the value expression looking security-sensitive (e.g.
// assigning the result of something token/session/jwt-shaped). Architecturally similar to
// the CORS check above: a config-shaped misconfiguration on a call whose options can be
// inline or one variable hop away.
const RES_COOKIE_CALL_RE = /\bres\.cookie\s*\(/g;
// "auth"'s bare-substring match collides with "author" -- a false-positive audit (round
// 2, 2026-07-24) found a blog "author theme preference" cookie flagged purely because
// "auth" is a literal substring of "author". A blanket word-boundary fix would also break
// legitimate "authenticate"/"authorize"/"authentication" names (there's no real
// word-boundary between "auth" and those suffixes either -- camelCase compounds are one
// continuous run of letters, same as "author"), so this targets the SPECIFIC collision
// instead: "auth" immediately followed by "or" and then a segment-ending character (a
// capital letter/non-letter/end-of-string) is excluded -- matching "author"/
// "authorTheme"/"author_id" but NOT "authorize"/"authorization"/"authority" (all continue
// with a lowercase letter after "or", which this negative lookahead deliberately still
// lets through as auth-related). Fixed 2026-07-24 (round 2 evasion audit).
const COOKIE_AUTH_KEYWORD_SRC = 'auth(?!or(?:[A-Z]|[^a-zA-Z]|$))';
const COOKIE_SENSITIVE_NAME_RE = new RegExp(`session|token|${COOKIE_AUTH_KEYWORD_SRC}`, 'i');
const COOKIE_SENSITIVE_VALUE_RE = new RegExp(`session|token|jwt|secret|${COOKIE_AUTH_KEYWORD_SRC}`, 'i');
const HTTP_ONLY_TRUE_RE = /\bhttpOnly\s*:\s*true\b/i;
const SECURE_TRUE_RE = /\bsecure\s*:\s*true\b/i;
// ES6 shorthand property recognition (round-3 fresh-look, FP #9): `const secure = true;
// res.cookie('sid', t, { httpOnly, secure })` -- fully-secure, idiomatic code that the
// literal-`: true` regexes read as "missing both flags". A bare `httpOnly`/`secure` key
// terminated by `,`/`}` (i.e. NOT followed by a `:`) is treated as present. `secure: false`
// still reads as insecure (it's followed by `:`, so the shorthand regex doesn't match and
// SECURE_TRUE_RE doesn't either).
const HTTP_ONLY_SHORTHAND_RE = /\bhttpOnly\s*(?:,|\})/i;
const SECURE_SHORTHAND_RE = /\bsecure\s*(?:,|\})/i;
// A false-positive audit (round 2, 2026-07-24) found `secure: process.env.NODE_ENV ===
// 'production'` -- a near-universal, textbook-correct Express idiom (secure in
// production/HTTPS, not secure in local dev/plain HTTP, where a literal `secure:true`
// would silently break cookies) -- flagged as "missing secure:true" purely because
// SECURE_TRUE_RE only recognizes the literal boolean. Recognized here as an equally
// satisfying signal for the secure flag, alongside the literal.
const SECURE_ENV_CONDITIONAL_RE = /\bsecure\s*:\s*[^,}]*NODE_ENV[^,}]*production/i;

// Resolves `optionsVar` back to its own object-literal declaration (`const opts = {
// httpOnly: true, ... };`), so `res.cookie('sid', id, cookieOpts)` can be checked just as
// well as an inline options object. Also follows one further step when the declaration's
// RHS is a call to a same-file, zero-argument function (`const cookieOpts =
// buildCookieOptions();`) by looking up that function's own `return` expression
// (lookupFunctionReturnExpr, shared with checks 11-12 via util.js) and using *that* if it
// is itself an object literal -- closing the "options object built by a helper function
// instead of an inline literal" gap, the same "one hop isn't enough" shape as the
// mass-assignment and open-redirect checks. Returns null (rather than guessing) if neither
// shape resolves -- e.g. the variable is imported from another module, built
// conditionally, or the helper function's return isn't a plain object literal -- so an
// unresolvable options variable is treated as "can't confirm" and not flagged, matching
// this codebase's existing bail-rather-than-guess convention.
// Strips one layer of wrapping parens (`(EXPR)` -> `EXPR`), if present. An arrow
// function's concise/implicit-return body MUST wrap a returned object literal in parens
// (`() => ({ ... })`) -- otherwise the `{` parses as a block body, not an object literal
// -- so lookupFunctionReturnExpr correctly returns the text WITH its wrapping parens
// intact, and callers that only test `/^\{/` need this to see through them.
function stripWrappingParens(text) {
  const t = text.trim();
  if (t[0] === '(' && t[t.length - 1] === ')') return t.slice(1, -1).trim();
  return t;
}

function resolveObjectLiteralVar(clean, varName) {
  const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  const objDeclRe = new RegExp(`(?:const|let|var)\\s+${escaped}\\s*=\\s*\\{`);
  const om = objDeclRe.exec(clean);
  if (om) {
    const braceIndex = om.index + om[0].length - 1; // index of the declaration's opening '{'
    return extractBalancedBraceBlock(clean, braceIndex);
  }

  const callDeclRe = new RegExp(`(?:const|let|var)\\s+${escaped}\\s*=\\s*([A-Za-z_$][\\w$]*)\\s*\\(\\s*\\)\\s*;`);
  const cm = callDeclRe.exec(clean);
  if (cm) {
    const returnExpr = lookupFunctionReturnExpr(clean, cm[1]);
    // Was `/^\{/.test(returnExpr.trim())` -- rejected an arrow helper with a concise
    // implicit-return object literal (`const buildCookieOptions = () => ({ ... });`,
    // the standard, idiomatic way every JS dev/linter writes this) because its returned
    // text starts with '(' (the required wrapping parens), not '{'. Fixed 2026-07-24
    // (round 2 evasion audit): strip a wrapping paren layer before the shape test.
    if (returnExpr) {
      const stripped = stripWrappingParens(returnExpr);
      if (/^\{/.test(stripped)) return stripped;
    }
  }

  return null;
}

// Resolves an INLINE call expression used directly as the options argument (e.g.
// `res.cookie('sid', t, buildSecureCookieOptions())`) by looking up the callee's own
// `return` expression, the same way resolveObjectLiteralVar resolves a call stored in a
// variable first. Returns the object-literal text if resolved, else null. Added
// 2026-07-24 (round 2 evasion audit) to close a false-positive: previously an inline call
// expression matched neither the `/^\{/` (inline literal) nor bare-identifier (resolved
// via resolveObjectLiteralVar) branches, so `optionsText` stayed null for ANY unrecognized
// shape -- including a perfectly secure inline call -- and the code unconditionally
// reported "no options object at all", which is factually false when an options argument
// IS present, just not in a shape this check used to look inside.
function resolveInlineCallOptionsArg(clean, optionsArg) {
  const callMatch = optionsArg.match(/^([A-Za-z_$][\w$]*)\s*\(([^()]*)\)$/);
  if (!callMatch) return null;
  const returnExpr = lookupFunctionReturnExpr(clean, callMatch[1]);
  if (!returnExpr) return null;
  const stripped = stripWrappingParens(returnExpr);
  return /^\{/.test(stripped) ? stripped : null;
}

// Resolves every `...spreadVar` inside an options-object text to its own object-literal
// declaration and appends the resolved text, so flag detection can see flags that live in a
// spread-in defaults object (FP #10). Unresolvable spreads are left as-is (their absence
// just means those flags aren't counted as present -- bail-rather-than-guess, consistent
// with the rest of this check).
function expandSpreadsInOptions(clean, optionsText) {
  let expanded = optionsText;
  const spreadRe = /\.\.\.\s*([A-Za-z_$][\w$]*)/g;
  let sm;
  while ((sm = spreadRe.exec(optionsText)) !== null) {
    const resolved = resolveObjectLiteralVar(clean, sm[1]);
    if (resolved) expanded += ` ${resolved}`;
  }
  return expanded;
}

function checkInsecureCookieFlags(clean, filePath, original) {
  const hits = [];
  RES_COOKIE_CALL_RE.lastIndex = 0;
  let m;
  while ((m = RES_COOKIE_CALL_RE.exec(clean)) !== null) {
    const openParenIndex = m.index + m[0].length - 1;
    const extracted = extractBalancedCallArg(clean, openParenIndex);
    if (!extracted) { RES_COOKIE_CALL_RE.lastIndex = openParenIndex + 1; continue; }
    const args = splitTopLevelArgs(extracted.arg);
    RES_COOKIE_CALL_RE.lastIndex = extracted.end;
    if (args.length < 2) continue; // need at least name + value to reason about this call

    const nameArg = args[0].trim();
    const valueArg = args[1].trim();
    const looksSensitive = COOKIE_SENSITIVE_NAME_RE.test(nameArg) || COOKIE_SENSITIVE_VALUE_RE.test(valueArg);
    if (!looksSensitive) continue;

    // optionsText: the resolved options-object text, once confirmed. null throughout
    // this block is ambiguous on purpose ("not yet resolved") -- optionsArgPresent and
    // optionsUnresolvable disambiguate "there really is no 3rd argument at all" (a real
    // "missing options object entirely" finding) from "there IS a 3rd argument but this
    // check can't confirm its contents" (bail, don't guess -- fixed 2026-07-24, round 2
    // evasion audit: the old code conflated these two and reported "no options object at
    // all" for a securely-configured inline call expression it simply never looked
    // inside, which is a false positive, not a confirmed finding).
    let optionsText = null;
    const optionsArgPresent = args.length >= 3;
    let optionsUnresolvable = false;

    if (optionsArgPresent) {
      const optionsArg = args[2].trim();
      if (/^\{/.test(optionsArg)) {
        optionsText = optionsArg;
      } else if (/^[A-Za-z_$][\w$]*$/.test(optionsArg)) {
        const resolved = resolveObjectLiteralVar(clean, optionsArg);
        if (resolved === null) optionsUnresolvable = true; // unresolvable variable -- can't confirm, don't guess
        else optionsText = resolved;
      } else {
        const resolved = resolveInlineCallOptionsArg(clean, optionsArg);
        if (resolved === null) optionsUnresolvable = true; // some other unrecognized shape -- can't confirm, don't guess
        else optionsText = resolved;
      }
    }

    if (optionsArgPresent && optionsUnresolvable) continue;

    if (!optionsArgPresent) {
      hits.push({
        line: lineOfIndex(original, m.index),
        snippet: snippetAt(original, m.index),
        rawMessage: `res.cookie() sets what looks like a session/auth cookie ("${nameArg}") with no options object at all -- httpOnly and secure both default to unset, so the cookie is readable via XSS and can be sent over plain HTTP.`,
      });
      continue;
    }

    // Expand any `...spreadVar` inside the options object by resolving the spread source to
    // its own object-literal declaration and appending its text, so a shared secure-defaults
    // object (`res.cookie('authToken', t, { ...COOKIE_DEFAULTS, maxAge })` where
    // COOKIE_DEFAULTS = { httpOnly: true, secure: true }) is recognized as secure rather than
    // flagged (round-3 fresh-look, FP #10 -- centralizing cookie defaults is best practice).
    const flagText = expandSpreadsInOptions(clean, optionsText);
    const missingHttpOnly = !HTTP_ONLY_TRUE_RE.test(flagText) && !HTTP_ONLY_SHORTHAND_RE.test(flagText);
    const missingSecure = !SECURE_TRUE_RE.test(flagText) && !SECURE_ENV_CONDITIONAL_RE.test(flagText) && !SECURE_SHORTHAND_RE.test(flagText);
    if (missingHttpOnly || missingSecure) {
      const missing = [missingHttpOnly && 'httpOnly:true', missingSecure && 'secure:true'].filter(Boolean).join(' and ');
      hits.push({
        line: lineOfIndex(original, m.index),
        snippet: snippetAt(original, m.index),
        rawMessage: `res.cookie() sets what looks like a session/auth cookie ("${nameArg}") without ${missing} -- missing httpOnly allows theft via XSS, missing secure allows transmission over plain HTTP.`,
      });
    }
  }
  return hits;
}

// --- Check 15: open-redirect --------------------------------------------------------------

// res.redirect([status,] target) called with a target that flows directly, or via one
// same-file variable hop (same one-hop precedent as the CORS/mass-assignment checks
// above), from req.query/req.body/req.params, with no allowlist/validation against a fixed
// set of internal paths in sight. Lets an attacker craft a link on the trusted domain that
// silently forwards a victim to an attacker-controlled site -- a common phishing vector.
const RES_REDIRECT_CALL_RE = /\bres\.redirect\s*\(/g;
// Optional `(?:\?\.[\w$]+)?` (was `(?:\.[\w$]+)?`, dot-only) and the trailing
// `(?:\s*\?\?\s*.+)?$` allowance added 2026-07-24 (round 2 evasion audit): optional
// chaining + a nullish-coalescing fallback (`req.query?.next ?? '/home'`) is exactly as
// attacker-influenced as `req.query.next` -- an attacker who omits the query param just
// gets the default; one who supplies it gets forwarded to it -- but the extra `?.`/`??`
// punctuation defeated the old exact-match regex entirely.
// Bracket/computed access support added round-3 (fresh-look, gap #8): `req['query'].next`
// -- check 13 already recognized `req['body']`, but that fix was never mirrored onto the
// open-redirect taint source, an asymmetry between two checks that share the same
// "req.query/body/params" concept. Both the `req` root and the trailing property may now be
// written as dot OR bracket access.
const REQ_SOURCE_PROP_RE = /^req(?:\.(?:query|body|params)|\[\s*['"`](?:query|body|params)['"`]\s*\])(?:\??\.[\w$]+|\[\s*['"`][\w$]+['"`]\s*\])?(?:\s*\?\?\s*.+)?$/;
// Looser than REQ_SOURCE_PROP_RE: matches a req.query/body/params reference ANYWHERE in an
// arbitrary expression, not just as the expression's entire text -- needed for the
// function-return-expression case just below, where the resolved expression is often a
// short-circuit chain (`req.query.next || req.query.returnTo`) rather than a single bare
// property access.
const REQ_SOURCE_PROP_ANYWHERE_RE = /\breq(?:\.(?:query|body|params)\b|\[\s*['"`](?:query|body|params)['"`]\s*\])/;

// Normalizes a res.redirect() target argument's raw text before any of the resolution
// branches below see it -- two round-2 evasion-audit findings (2026-07-24) turned out to
// be pure TEXT-shape dodges that vanish once undone, rather than needing their own
// resolution branch:
//   - a leading `await` (`await getRedirectTarget(req)` passed directly as the argument,
//     not first assigned to a variable) breaks the call-expression regex's anchor;
//   - a single-interpolation template literal (`` `${req.query.next}` ``) is a runtime
//     no-op (String(x) === `${x}` for a normal string) but is textually neither an exact
//     req.* match, a bare identifier, nor a call expression.
function normalizeRedirectTarget(text) {
  let t = text.trim();
  t = t.replace(/^await\s+/, '');
  const templateMatch = t.match(/^`\$\{([\s\S]*)\}`$/);
  if (templateMatch) t = templateMatch[1].trim();
  return t;
}

// Resolves a bare identifier back to a same-file req.query/req.body/req.params origin, in
// any of the shapes real code actually uses:
//   const url = req.query.redirect;              -- direct property/whole-object assignment
//     (any number of further `const x = y;` variable hops away, via resolveIdentifierChain)
//   const { redirect: url } = req.query;          -- destructured (with or without rename)
//   const { query: { redirect: url } } = req;     -- NESTED destructuring straight off req
// Returns the source expression string (e.g. "req.query.redirect") if resolved, else null.
function resolveVarFromReqSource(clean, varName) {
  const resolved = resolveIdentifierChain(clean, varName);
  if (resolved && REQ_SOURCE_PROP_RE.test(resolved)) return resolved;

  const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const destructureRe = new RegExp(
    `(?:const|let|var)\\s*\\{[^}]*\\b(?:${escaped}|[\\w$]+\\s*:\\s*${escaped})\\b[^}]*\\}\\s*=\\s*(req\\.(?:query|body|params))\\s*;`,
  );
  const destM = clean.match(destructureRe);
  if (destM) return destM[1];

  // Nested destructuring straight off `req` itself: const { query: { next } } = req;
  // -- the source property (query/body/params) lives as an outer key in the pattern, the
  // bound name is nested one level deeper, and the RHS is bare `req`, not
  // req.query/body/params -- a shape the flat destructureRe above (which requires the RHS
  // to be exactly one of those three) can't span. Added 2026-07-24 (round 2 evasion audit).
  const nestedDestructureRe = new RegExp(
    `(?:const|let|var)\\s*\\{\\s*(query|body|params)\\s*:\\s*\\{[^{}]*\\b${escaped}\\b[^{}]*\\}\\s*\\}\\s*=\\s*req\\b`,
  );
  const nestedM = clean.match(nestedDestructureRe);
  if (nestedM) return `req.${nestedM[1]}.${varName}`;

  return null;
}

// Resolves a call expression (e.g. `getRedirectTarget(req)`, or `await
// getRedirectTarget(req)` -- a leading await is stripped defensively here too, though
// normalizeRedirectTarget above already handles it for the primary call site) back to a
// same-file function's return expression (lookupFunctionReturnExpr, shared with checks
// 11-12/14 via util.js) and checks whether THAT expression references req.query/body/
// params anywhere -- closes the "route the tainted value through a same-file helper
// function" gap, the same "one hop isn't enough" shape as the mass-assignment and
// insecure-cookie-flags checks. Deliberately loose (REQ_SOURCE_PROP_ANYWHERE_RE, not the
// anchored REQ_SOURCE_PROP_RE) since a helper's return is often a short-circuit chain
// (`req.query.next || req.query.returnTo`), not a single bare property access. Returns
// the resolved return-expression text if it looks req-sourced, else null.
function resolveCallExprFromReqSource(clean, targetArg) {
  const stripped = targetArg.trim().replace(/^await\s+/, '');
  const callMatch = stripped.match(/^([A-Za-z_$][\w$]*)\s*\(([^()]*)\)$/);
  if (!callMatch) return null;
  const returnExpr = lookupFunctionReturnExpr(clean, callMatch[1]);
  if (returnExpr && REQ_SOURCE_PROP_ANYWHERE_RE.test(returnExpr)) return returnExpr.trim();
  return null;
}

// Resolves a `new URL(<reqSourceExpr>, <base>)` redirect target -- a known, well-known
// "looks safe, isn't" bypass idiom: `new URL(untrustedInput, base)` is often added as if
// it were a validation guard, but if the first argument is an absolute URL, the WHATWG URL
// parser ignores the base entirely and resolves to the attacker's URL. Since developers who
// write this pattern often BELIEVE they've fixed the open-redirect, it's worth its own
// explicit recognition rather than being just another missed call shape. Added 2026-07-24
// (round 2, realistic-library-code audit). Returns the resolved req-source expression
// (e.g. "req.query.next") if the URL constructor's first argument traces back to one,
// else null.
const NEW_URL_CALL_RE = /new\s+URL\s*\(/;

function resolveNewUrlFromReqSource(clean, targetArg) {
  const idx = targetArg.search(NEW_URL_CALL_RE);
  if (idx === -1) return null;
  const openParenIdx = targetArg.indexOf('(', idx);
  const extracted = extractBalancedCallArg(targetArg, openParenIdx);
  if (!extracted) return null;
  const urlArgs = splitTopLevelArgs(extracted.arg);
  if (urlArgs.length === 0) return null;
  const firstArg = urlArgs[0].trim();
  if (REQ_SOURCE_PROP_RE.test(firstArg)) return firstArg;
  if (/^[A-Za-z_$][\w$]*$/.test(firstArg)) {
    const resolved = resolveVarFromReqSource(clean, firstArg);
    if (resolved) return resolved;
  }
  return null;
}

// Best-effort "this looks validated" guard, checked in a window immediately before the
// res.redirect() call, so an app that DOES check its redirect target isn't flagged just
// because the check happens to live a few lines above the call rather than inline in it.
// Deliberately loose (matches this file's existing "precision-light, downstream triage
// filters noise" philosophy) -- a real allowlist function this heuristic doesn't recognize
// will still slip through as a false positive, which the triage layer is expected to catch.
const REDIRECT_VALIDATION_WINDOW_CHARS = 400;

function hasNearbyRedirectValidation(clean, callIndex, varName) {
  if (!varName) return false;
  const windowStart = Math.max(0, callIndex - REDIRECT_VALIDATION_WINDOW_CHARS);
  const window = clean.slice(windowStart, callIndex);
  const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const patterns = [
    new RegExp(`${escaped}\\s*\\.\\s*startsWith\\s*\\(`), // e.g. url.startsWith('/')
    // Was `(?:allow(?:list|ed)|whitelist)\w*\.includes(VAR)` -- required the array's own
    // name to start with an allow/whitelist-ish prefix. A false-positive audit (round 2,
    // 2026-07-24) found an equally-safe allowlist check named "internalPaths" (or any
    // other reasonable name) went unrecognized purely because of that naming requirement.
    // Dropped: any `ARRAY.includes(VAR)` shape is treated as a plausible guard regardless
    // of the array's name -- the risk of over-broadening is low since this only
    // *suppresses* a finding, it never creates one.
    new RegExp(`[A-Za-z_$][\\w$]*\\s*\\.\\s*includes\\s*\\(\\s*${escaped}\\b`),
    new RegExp(`${escaped}\\s*\\.\\s*includes\\s*\\(`), // weaker signal, still a plausible guard
    // `new URL(target, base)` followed by an `.origin` comparison -- a standard, robust
    // open-redirect guard (resolve against the site's own origin, reject anything that
    // resolves elsewhere) that a false-positive audit (round 2, 2026-07-24) found wasn't
    // recognized at all. Deliberately loose: just requires a same-window `.origin`
    // comparison after constructing a URL from the target, not a specific comparison
    // target -- this is a suppression-only heuristic, same tradeoff as above.
    new RegExp(`new\\s+URL\\s*\\(\\s*${escaped}\\b[\\s\\S]*?\\.origin\\s*(?:!==|===)`),
  ];
  return patterns.some((re) => re.test(window));
}

function checkOpenRedirect(clean, filePath, original) {
  const hits = [];
  RES_REDIRECT_CALL_RE.lastIndex = 0;
  let m;
  while ((m = RES_REDIRECT_CALL_RE.exec(clean)) !== null) {
    const openParenIndex = m.index + m[0].length - 1;
    const extracted = extractBalancedCallArg(clean, openParenIndex);
    if (!extracted) { RES_REDIRECT_CALL_RE.lastIndex = openParenIndex + 1; continue; }
    RES_REDIRECT_CALL_RE.lastIndex = extracted.end;

    const args = splitTopLevelArgs(extracted.arg);
    if (args.length === 0) continue;
    // Last argument is the actual redirect target in both res.redirect(url) and the
    // two-arg res.redirect(statusCode, url) form. Normalized (leading `await` stripped, a
    // single-interpolation template-literal wrapper unwrapped) before any resolution
    // branch sees it -- see normalizeRedirectTarget's own doc comment.
    const targetArg = normalizeRedirectTarget(args[args.length - 1]);

    let sourceExpr = null;
    let resolvedVarName = null;
    let viaNewUrl = false;
    if (REQ_SOURCE_PROP_RE.test(targetArg)) {
      sourceExpr = targetArg;
    } else if (/^[A-Za-z_$][\w$]*$/.test(targetArg)) {
      const resolved = resolveVarFromReqSource(clean, targetArg);
      if (resolved) {
        sourceExpr = resolved;
        resolvedVarName = targetArg;
      }
    } else {
      const resolved = resolveCallExprFromReqSource(clean, targetArg);
      if (resolved) {
        sourceExpr = resolved;
      } else {
        const urlResolved = resolveNewUrlFromReqSource(clean, targetArg);
        if (urlResolved) {
          sourceExpr = urlResolved;
          viaNewUrl = true;
        }
      }
    }

    // Fallback: the expression clearly references req.query/body/params somewhere but
    // isn't one of the specific recognized shapes above -- still attacker-influenced.
    // Same "precision-light, downstream triage filters noise" philosophy as the rest of
    // this file.
    if (!sourceExpr && REQ_SOURCE_PROP_ANYWHERE_RE.test(targetArg)) {
      sourceExpr = targetArg;
    }

    if (!sourceExpr) continue;
    if (hasNearbyRedirectValidation(clean, m.index, resolvedVarName || targetArg)) continue;

    const newUrlNote = viaNewUrl
      ? ' (wrapped in `new URL(..., base).toString()` -- if this value can be an absolute URL, the base argument is ignored entirely by the WHATWG URL parser and the redirect still goes wherever the attacker points it, so this is NOT actually a validation guard despite looking like one)'
      : '';

    hits.push({
      line: lineOfIndex(original, m.index),
      snippet: snippetAt(original, m.index),
      rawMessage: `res.redirect() target comes directly from ${sourceExpr}${resolvedVarName ? ` (via variable "${resolvedVarName}")` : ''}${newUrlNote} with no allowlist/validation against a fixed set of internal paths -- an attacker can craft a link on this trusted domain that silently forwards victims to an attacker-controlled site.`,
    });
  }
  return hits;
}

// --- Wiring ----------------------------------------------------------------------------

const CHECKS = [
  { checkId: 'sql-string-concatenation', severity: 'high', category: 'injection', run: checkSqlStringConcatenation },
  { checkId: 'eval-on-input', severity: 'critical', category: 'injection', run: checkEvalOnInput },
  { checkId: 'cors-wildcard-with-credentials', severity: 'high', category: 'config', run: checkCorsWildcardWithCredentials },
  { checkId: 'missing-auth-middleware', severity: 'high', category: 'authz', run: checkMissingAuthMiddleware },
  { checkId: 'supabase-rls-disabled', severity: 'critical', category: 'authz', run: checkSupabaseRlsDisabled },
  { checkId: 'stripe-webhook-unverified', severity: 'high', category: 'crypto', run: checkStripeWebhookUnverified },
  { checkId: 'mass-assignment', severity: 'high', category: 'injection', run: checkMassAssignment },
  { checkId: 'insecure-cookie-flags', severity: 'high', category: 'config', run: checkInsecureCookieFlags },
  { checkId: 'open-redirect', severity: 'medium', category: 'injection', run: checkOpenRedirect },
];

function scan(repoPath, opts = {}) {
  const warnings = [];
  const findings = [];

  let files;
  try {
    files = walkFiles(repoPath, { extensions: SOURCE_EXTENSIONS });
  } catch (err) {
    warnings.push(`static-checks.js: failed to walk repo tree: ${err.message}`);
    return { findings, warnings };
  }

  for (const filePath of files) {
    const original = readTextFile(filePath);
    if (!original) continue;
    const clean = stripComments(original);
    const repoRelPath = path.relative(repoPath, filePath).split(path.sep).join('/');

    for (const check of CHECKS) {
      let hits;
      try {
        hits = check.run(clean, filePath, original);
      } catch (err) {
        warnings.push(`static-checks.js: ${check.checkId} failed on ${repoRelPath}: ${err.message}`);
        continue;
      }
      for (const hit of hits) {
        findings.push({
          id: makeId(check.checkId, [repoRelPath, String(hit.line), hit.snippet]),
          checkId: check.checkId,
          severity: check.severity,
          category: check.category,
          file: repoRelPath,
          line: hit.line,
          snippet: hit.snippet.slice(0, 200),
          rawMessage: hit.rawMessage,
        });
      }
    }
  }

  // --- .sql migration pass (check 8's sibling detection) -------------------------------
  // A second, separate walk restricted to .sql files -- deliberately not folded into the
  // SOURCE_EXTENSIONS loop above, since every other check in CHECKS targets JS/TS call
  // shapes (`.query(`, `res.cookie(`, `eval(`, ...) that have no business running against
  // raw SQL text, and folding .sql into SOURCE_EXTENSIONS would run all nine of them
  // against every migration file for no benefit.
  let sqlFiles;
  try {
    sqlFiles = walkFiles(repoPath, { extensions: SQL_EXTENSIONS });
  } catch (err) {
    warnings.push(`static-checks.js: failed to walk repo tree for .sql files: ${err.message}`);
    sqlFiles = [];
  }

  for (const filePath of sqlFiles) {
    const original = readTextFile(filePath);
    if (!original) continue;
    const repoRelPath = path.relative(repoPath, filePath).split(path.sep).join('/');

    let hits;
    try {
      hits = checkSupabaseRlsSqlMigration(original);
    } catch (err) {
      warnings.push(`static-checks.js: supabase-rls-disabled (sql migration pass) failed on ${repoRelPath}: ${err.message}`);
      continue;
    }
    for (const hit of hits) {
      findings.push({
        id: makeId('supabase-rls-disabled', [repoRelPath, String(hit.line), hit.snippet]),
        checkId: 'supabase-rls-disabled',
        severity: 'critical',
        category: 'authz',
        file: repoRelPath,
        line: hit.line,
        snippet: hit.snippet.slice(0, 200),
        rawMessage: hit.rawMessage,
      });
    }
  }

  return { findings, warnings };
}

module.exports = { scan };
