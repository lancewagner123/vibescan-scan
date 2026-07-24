'use strict';

// Checks 4-9 from docs/CHECK_CATALOG.md, via targeted regex/string-pattern heuristics
// over .js/.ts/.jsx/.tsx source. These are intentionally precision-light — the
// downstream LLM triage layer is responsible for filtering noise — but each pattern is
// aimed at a real, specific signal rather than firing on every file.

const path = require('path');
const { walkFiles, readTextFile, makeId, stripComments } = require('./util');

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

  return hits;
}

// --- Check 5: eval-on-input -----------------------------------------------------------

const DANGEROUS_CALLEE_RE = /\b(eval|new\s+Function|exec|execSync)\s*\(/g;

/**
 * Given text and the index of an opening '(', walk forward tracking paren depth to find
 * the matching ')', treating quoted/template-literal content as opaque (so parens inside
 * a string or inside a `${...}` don't throw off the depth count). A naive `[^)]*` regex
 * breaks the moment the argument itself contains a nested call, e.g.
 * `eval(\`console.log(${x})\`)` — the first `)` it sees is the one that closes
 * `console.log(...)`, not the one that closes `eval(...)`. Returns null if unbalanced.
 */
function extractBalancedCallArg(text, openParenIndex) {
  let depth = 0;
  let inString = null; // one of ' " ` while inside a string/template literal
  for (let i = openParenIndex; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (ch === '\\') { i++; continue; } // skip escaped char, including escaped quote
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { inString = ch; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return { end: i, arg: text.slice(openParenIndex + 1, i) };
    }
  }
  return null;
}

function argLooksInterpolated(arg) {
  const trimmed = arg.trim();
  if (trimmed === '') return false;
  // Template literal containing ${...}
  if (/`[^`]*\$\{[^`]*\}[^`]*`/.test(trimmed)) return true;
  // String concatenation with a variable: "..." + var  or var + "..."
  if (/['"][^'"]*['"]\s*\+\s*[A-Za-z_$]/.test(trimmed) || /[A-Za-z_$][\w.$]*\s*\+\s*['"]/.test(trimmed)) return true;
  // Bare identifier / member expression with no quotes at all — the whole arg is a
  // variable, so whatever built its value happens elsewhere (can't rule out user input).
  if (/^[A-Za-z_$][\w.$[\]]*$/.test(trimmed)) return true;
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
    if (argLooksInterpolated(extracted.arg)) {
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

function checkCorsWildcardWithCredentials(clean, filePath, original) {
  const hasCredentials = CORS_CREDENTIALS_RE.test(clean);
  if (!hasCredentials) return [];
  CORS_WILDCARD_RE.lastIndex = 0;
  const hits = [];
  let m;
  while ((m = CORS_WILDCARD_RE.exec(clean)) !== null) {
    hits.push({
      line: lineOfIndex(original, m.index),
      snippet: snippetAt(original, m.index),
      rawMessage: "CORS origin set to '*' in a file that also sets credentials:true / Access-Control-Allow-Credentials:true — browsers reject this combination, but some proxies/older clients won't, and it signals a misconfigured CORS policy.",
    });
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

const AUTH_KEYWORD_RE = /\b(auth|session|token|jwt|passport|isAuthenticated|requireLogin|ensureAuth|verifyToken|apikey|api_key|authorize|authenticate)\b/i;
const ROUTE_WINDOW_CHARS = 2000; // lookahead window used to find the handler body / middleware chain

function findMissingAuthHits(clean, original, routeRe) {
  const hits = [];
  routeRe.lastIndex = 0;
  let m;
  while ((m = routeRe.exec(clean)) !== null) {
    const routePath = m[3];
    const windowEnd = Math.min(clean.length, m.index + ROUTE_WINDOW_CHARS);
    // Also look a little behind the match, in case auth middleware is declared as a
    // preceding argument on the same call, e.g. router.get('/admin', requireAuth, fn).
    const windowStart = Math.max(0, m.index - 100);
    const window = clean.slice(windowStart, windowEnd);
    if (AUTH_KEYWORD_RE.test(window)) continue;
    hits.push({
      line: lineOfIndex(original, m.index),
      snippet: snippetAt(original, m.index),
      rawMessage: `Route handler for admin/internal-looking path "${routePath}" has no auth/session/token check heuristically found nearby in the handler or middleware chain.`,
    });
  }
  return hits;
}

function checkMissingAuthMiddleware(clean, filePath, original) {
  const normalized = filePath.split(path.sep).join('/');
  if (SENSITIVE_FILE_PATH_RE.test(normalized)) {
    // File itself lives under an admin/internal/debug path (e.g. routes/admin.js,
    // routes/debug.js) — treat every route call in it as a sensitive-route candidate,
    // since the real mount prefix that makes it sensitive typically lives in a
    // different file (the parent app.use('/admin', ...) call).
    return findMissingAuthHits(clean, original, ANY_ROUTE_CALL_RE);
  }
  return findMissingAuthHits(clean, original, SENSITIVE_ROUTE_INLINE_RE);
}

// --- Check 8: supabase-rls-disabled ----------------------------------------------------

const RLS_DISABLED_PATTERNS = [
  /ALTER TABLE\s+\S+\s+DISABLE ROW LEVEL SECURITY/i,
  /"?row_level_security"?\s*[:=]\s*false/i,
  /"?rowLevelSecurity"?\s*[:=]\s*false/i,
  /enable_row_level_security\s*=\s*false/i,
];

const SERVICE_ROLE_RE = /SUPABASE_SERVICE_ROLE_KEY|service_role/;

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

  return hits;
}

// --- Check 9: stripe-webhook-unverified -------------------------------------------------

function checkStripeWebhookUnverified(clean, filePath, original) {
  const normalized = filePath.split(path.sep).join('/');
  const mentionsStripe = /stripe/i.test(clean) || /stripe/i.test(normalized);
  const mentionsWebhook = /webhook/i.test(clean) || /webhook/i.test(normalized);
  if (!mentionsStripe || !mentionsWebhook) return [];
  if (/constructEvent/.test(clean)) return []; // signature verification present — not a finding

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

// --- Wiring ----------------------------------------------------------------------------

const CHECKS = [
  { checkId: 'sql-string-concatenation', severity: 'high', category: 'injection', run: checkSqlStringConcatenation },
  { checkId: 'eval-on-input', severity: 'critical', category: 'injection', run: checkEvalOnInput },
  { checkId: 'cors-wildcard-with-credentials', severity: 'high', category: 'config', run: checkCorsWildcardWithCredentials },
  { checkId: 'missing-auth-middleware', severity: 'high', category: 'authz', run: checkMissingAuthMiddleware },
  { checkId: 'supabase-rls-disabled', severity: 'critical', category: 'authz', run: checkSupabaseRlsDisabled },
  { checkId: 'stripe-webhook-unverified', severity: 'high', category: 'crypto', run: checkStripeWebhookUnverified },
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
