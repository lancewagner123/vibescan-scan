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
const SQL_INLINE_TEMPLATE_RE = /\.(?:query|execute|raw)\s*\(\s*`[^`]*\$\{[^`]*\}[^`]*`/g;
const SQL_INLINE_CONCAT_RE = /\.(?:query|execute|raw)\s*\(\s*(['"])(?:(?!\1).)*\1\s*\+\s*[A-Za-z_$][\w.$]*/g;

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
  `(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*` +
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
const FUNCTION_DECL_RE = /function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{/g;
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
      const usageRe = new RegExp(`\\.(?:query|execute|raw)\\s*\\(\\s*${varName}\\b`);
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
    const usageRe = new RegExp(`\\.(?:query|execute|raw)\\s*\\(\\s*${varName}\\b`);
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
  // contains parentheses.
  const callMatch = trimmed.match(/^([A-Za-z_$][\w.$]*)\s*\(/);
  if (callMatch && clean) {
    const returnExpr = lookupFunctionReturnExpr(clean, callMatch[1]);
    if (returnExpr && argLooksInterpolated(returnExpr, null)) return true; // null: don't recurse a 2nd level
  }
  return false;
}

// `exec`/`execSync` collide with an extremely common, totally unrelated JS idiom:
// RegExp.prototype.exec() (e.g. `while ((m = re.exec(text)) !== null)`), which is not
// child_process at all. Requiring the file to actually reference the child_process
// module before treating exec/execSync as the dangerous shell-spawning call filters
// that out — a regex-heavy file that never imports child_process can't be doing shell
// command injection via exec() in the first place.
const CHILD_PROCESS_REFERENCE_RE = /child_process/;

function checkEvalOnInput(clean, filePath, original) {
  const hits = [];
  const referencesChildProcess = CHILD_PROCESS_REFERENCE_RE.test(clean);
  DANGEROUS_CALLEE_RE.lastIndex = 0;
  let m;
  while ((m = DANGEROUS_CALLEE_RE.exec(clean)) !== null) {
    const callName = m[1];
    if ((callName === 'exec' || callName === 'execSync') && !referencesChildProcess) {
      continue; // almost certainly RegExp#exec, not child_process.exec/execSync
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
const CORS_CREDENTIALS_RE = /(?:credentials\s*:\s*true|Access-Control-Allow-Credentials['"]?\s*[:,]\s*['"]?true)/i;

// Wildcard-via-variable: `origin: someVar` where `someVar`'s own assignment can resolve
// to '*' (a literal default via `||`/`??`, a ternary branch, etc.) is the same dangerous
// misconfiguration as a literal '*' next to `origin:` -- just one hop further away from
// the call site, which is enough to dodge CORS_WILDCARD_RE's purely positional match.
const CORS_ORIGIN_VAR_RE = /origin\s*:\s*([A-Za-z_$][\w.$]*)\s*[,}]/gi;

function findVarAssignmentContainingWildcard(clean, varName) {
  const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`(?:const|let|var)\\s+${escaped}\\s*=\\s*([^;\\n]+)`, 'i');
  const m = clean.match(re);
  if (!m) return null;
  return /['"]\*['"]/.test(m[1]) ? m : null;
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
const AUTH_KEYWORD_RE = /\b(auth|session|token|jwt|passport|isAuthenticated|requireLogin|ensureAuth|verifyToken|apikey|api_key|authorize|authenticate)\w*/i;
const AUTH_KEYWORD_AS_ARG_RE = new RegExp(`${AUTH_KEYWORD_RE.source}\\s*,`, 'i');
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

function routeCallHasEnforcedAuth(clean, callIndex) {
  const callText = extractRouteCallText(clean, callIndex)
    || clean.slice(callIndex, Math.min(clean.length, callIndex + ROUTE_WINDOW_CHARS));
  // (a) an auth-ish identifier passed as one of the arguments in the call itself, e.g.
  // router.get('/admin', requireAuth, (req, res) => {...}) -- real Express middleware
  // wiring, not just the word "auth" appearing somewhere nearby (a decorative import, an
  // unrelated log call, etc, which is exactly what used to slip past the old wide-window
  // substring check).
  if (AUTH_KEYWORD_AS_ARG_RE.test(callText)) return true;
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
const COMPUTED_ENV_ACCESS_RE = /process\.env\[\s*[A-Za-z_$][\w.$]*\s*\]/g;

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
      hits.push({
        line: lineOfIndex(original, cm.index),
        snippet: snippetAt(original, cm.index),
        rawMessage: `Client-side-looking code reads an environment variable via a computed/dynamic key (${cm[0]}) instead of a static process.env.NAME reference — bundlers generally can't statically inline a computed lookup, so the real (possibly privileged, e.g. service_role) env var name and value are only resolved at runtime and may still ship to the browser bundle undetected by a literal-name search.`,
      });
    }
  }

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
    const anchor = fallbackMatch || clean.match(/webhook/i) || { index: constructMatch.index };
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

  const usesRawBodyAsEvent = /req\.body|request\.body/.test(clean);
  if (!usesRawBodyAsEvent) return [];

  const anchor = clean.match(/webhook/i) || { index: 0 };
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
//   Model.create(req.body)              -- method-call form (also covers .update/.save)
//   new Model(req.body)                 -- constructor form
//   Object.assign(existingRecord, req.body) -- merge-onto-existing-record form
const MODEL_METHOD_CALL_RE = /\.(create|update|save)\s*\(/g;
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
function isReqBodyOrQueryExpr(text) {
  return /^req\.(?:body|query)$/.test(text.trim());
}

function argIsWholeReqBodyOrQuery(arg, clean) {
  const trimmed = arg.trim();
  if (isReqBodyOrQueryExpr(trimmed)) return true;

  const spreadMatch = trimmed.match(/^\{\s*\.\.\.\s*([A-Za-z_$][\w.$]*)\s*\}$/);
  if (spreadMatch) {
    const spreadTarget = spreadMatch[1];
    if (isReqBodyOrQueryExpr(spreadTarget)) return true;
    if (/^[A-Za-z_$][\w$]*$/.test(spreadTarget)) {
      const resolved = resolveIdentifierChain(clean, spreadTarget);
      if (resolved && isReqBodyOrQueryExpr(resolved)) return true;
    }
    return false;
  }

  const identMatch = trimmed.match(/^[A-Za-z_$][\w$]*$/);
  if (identMatch) {
    const resolved = resolveIdentifierChain(clean, trimmed);
    if (resolved && isReqBodyOrQueryExpr(resolved)) return true;
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
const COOKIE_SENSITIVE_NAME_RE = /session|token|auth/i;
const COOKIE_SENSITIVE_VALUE_RE = /session|token|jwt|auth|secret/i;
const HTTP_ONLY_TRUE_RE = /\bhttpOnly\s*:\s*true\b/i;
const SECURE_TRUE_RE = /\bsecure\s*:\s*true\b/i;

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
    if (returnExpr && /^\{/.test(returnExpr.trim())) return returnExpr.trim();
  }

  return null;
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

    let optionsText = null; // null means "no options object could be confirmed present"
    if (args.length >= 3) {
      const optionsArg = args[2].trim();
      if (/^\{/.test(optionsArg)) {
        optionsText = optionsArg;
      } else if (/^[A-Za-z_$][\w$]*$/.test(optionsArg)) {
        const resolved = resolveObjectLiteralVar(clean, optionsArg);
        if (resolved === null) continue; // options passed via an unresolvable variable -- can't confirm, don't guess
        optionsText = resolved;
      }
    }

    if (optionsText === null) {
      hits.push({
        line: lineOfIndex(original, m.index),
        snippet: snippetAt(original, m.index),
        rawMessage: `res.cookie() sets what looks like a session/auth cookie ("${nameArg}") with no options object at all -- httpOnly and secure both default to unset, so the cookie is readable via XSS and can be sent over plain HTTP.`,
      });
      continue;
    }

    const missingHttpOnly = !HTTP_ONLY_TRUE_RE.test(optionsText);
    const missingSecure = !SECURE_TRUE_RE.test(optionsText);
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
const REQ_SOURCE_PROP_RE = /^req\.(?:query|body|params)(?:\.[\w$]+)?$/;
// Looser than REQ_SOURCE_PROP_RE: matches a req.query/body/params reference ANYWHERE in an
// arbitrary expression, not just as the expression's entire text -- needed for the
// function-return-expression case just below, where the resolved expression is often a
// short-circuit chain (`req.query.next || req.query.returnTo`) rather than a single bare
// property access.
const REQ_SOURCE_PROP_ANYWHERE_RE = /\breq\.(?:query|body|params)\b/;

// Resolves a bare identifier back to a same-file req.query/req.body/req.params origin, in
// either of the two shapes real code actually uses:
//   const url = req.query.redirect;              -- direct property/whole-object assignment
//     (any number of further `const x = y;` variable hops away, via resolveIdentifierChain)
//   const { redirect: url } = req.query;          -- destructured (with or without rename)
// Returns the source expression string (e.g. "req.query.redirect") if resolved, else null.
function resolveVarFromReqSource(clean, varName) {
  const resolved = resolveIdentifierChain(clean, varName);
  if (resolved && REQ_SOURCE_PROP_RE.test(resolved)) return resolved;

  const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const destructureRe = new RegExp(
    `(?:const|let|var)\\s*\\{[^}]*\\b(?:${escaped}|[\\w$]+\\s*:\\s*${escaped})\\b[^}]*\\}\\s*=\\s*(req\\.(?:query|body|params))\\s*;`,
  );
  const destM = clean.match(destructureRe);
  return destM ? destM[1] : null;
}

// Resolves a call expression (e.g. `getRedirectTarget(req)`) back to a same-file function's
// return expression (lookupFunctionReturnExpr, shared with checks 11-12/14 via util.js)
// and checks whether THAT expression references req.query/body/params anywhere -- closes
// the "route the tainted value through a same-file helper function" gap, the same "one hop
// isn't enough" shape as the mass-assignment and insecure-cookie-flags checks. Deliberately
// loose (REQ_SOURCE_PROP_ANYWHERE_RE, not the anchored REQ_SOURCE_PROP_RE) since a helper's
// return is often a short-circuit chain (`req.query.next || req.query.returnTo`), not a
// single bare property access. Returns the resolved return-expression text if it looks
// req-sourced, else null.
function resolveCallExprFromReqSource(clean, targetArg) {
  const callMatch = targetArg.match(/^([A-Za-z_$][\w$]*)\s*\(([^()]*)\)$/);
  if (!callMatch) return null;
  const returnExpr = lookupFunctionReturnExpr(clean, callMatch[1]);
  if (returnExpr && REQ_SOURCE_PROP_ANYWHERE_RE.test(returnExpr)) return returnExpr.trim();
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
    new RegExp(`(?:allow(?:list|ed)|whitelist)\\w*\\s*\\.\\s*includes\\s*\\(\\s*${escaped}\\b`, 'i'),
    new RegExp(`${escaped}\\s*\\.\\s*includes\\s*\\(`), // weaker signal, still a plausible guard
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
    // two-arg res.redirect(statusCode, url) form.
    const targetArg = args[args.length - 1].trim();

    let sourceExpr = null;
    let resolvedVarName = null;
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
      if (resolved) sourceExpr = resolved;
    }
    if (!sourceExpr) continue;
    if (hasNearbyRedirectValidation(clean, m.index, resolvedVarName || targetArg)) continue;

    hits.push({
      line: lineOfIndex(original, m.index),
      snippet: snippetAt(original, m.index),
      rawMessage: `res.redirect() target comes directly from ${sourceExpr}${resolvedVarName ? ` (via variable "${resolvedVarName}")` : ''} with no allowlist/validation against a fixed set of internal paths -- an attacker can craft a link on this trusted domain that silently forwards victims to an attacker-controlled site.`,
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

  return { findings, warnings };
}

module.exports = { scan };
