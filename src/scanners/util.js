'use strict';

// Shared helpers for every scanner module. Kept dependency-free (Node builtins only) —
// no gitleaks/semgrep/anything shelled out to, per project constraints.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

// Directories we never want to walk into: node_modules/.git are the hard requirement,
// the rest are common generated-output dirs that would otherwise blow up scan time and
// findings volume with nothing but bundled/vendored noise.
const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.next',
  '.nuxt',
  'dist',
  'build',
  'out',
  'coverage',
  '.cache',
  '.turbo',
  'vendor',
]);

/**
 * Recursively walk a directory tree, skipping SKIP_DIRS, returning absolute file paths.
 * @param {string} rootDir
 * @param {{ extensions?: string[] }} [opts] - if given, only files whose extension
 *   (lowercased, with leading dot) is in this list are returned.
 * @returns {string[]}
 */
function walkFiles(rootDir, opts = {}) {
  const { extensions } = opts;
  const results = [];

  function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // unreadable dir (permissions, race, symlink loop) — skip, don't crash the scan
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        walk(path.join(dir, entry.name));
      } else if (entry.isFile()) {
        if (extensions) {
          const ext = path.extname(entry.name).toLowerCase();
          if (!extensions.includes(ext)) continue;
        }
        results.push(path.join(dir, entry.name));
      }
    }
  }

  walk(rootDir);
  return results;
}

/**
 * Read a file as utf8 text, returning null instead of throwing on binary/unreadable files.
 */
function readTextFile(filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    // Cheap binary sniff: a NUL byte in the first 8KB means "not text", skip it.
    const sample = buf.subarray(0, 8192);
    if (sample.includes(0)) return null;
    return buf.toString('utf8');
  } catch {
    return null;
  }
}

/**
 * Deterministic stable slug id for a finding: checkId + short hash of the parts that
 * identify *this* occurrence (file, line, matched text). Uses crypto, never Math.random,
 * so the same finding produces the same id across repeated scans.
 */
function makeId(checkId, parts) {
  const hash = crypto.createHash('sha256').update(parts.join(' ')).digest('hex').slice(0, 10);
  return `${checkId}-${hash}`;
}

/**
 * Redact a secret value for safe display: first 8 chars + a fixed marker. Never return
 * the full secret. Handles short secrets gracefully (fewer than 8 chars available).
 */
function redactSecret(value) {
  if (typeof value !== 'string') return '***redacted';
  const visible = value.slice(0, 8);
  return `${visible}***redacted`;
}

/**
 * Shannon entropy in bits/char, used as a cheap heuristic to separate "looks like a real
 * random secret" from "looks like a placeholder/word" for the generic key/secret/token
 * heuristic in secrets.js.
 */
function shannonEntropy(str) {
  if (!str) return 0;
  const counts = new Map();
  for (const ch of str) counts.set(ch, (counts.get(ch) || 0) + 1);
  const len = str.length;
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Obvious placeholder values that should never be flagged as real secrets. */
const PLACEHOLDER_RE = /^(x+|0+|1+|changeme|placeholder|example|your[-_]?.*(key|secret|token)|xxx+|<.*>|\{\{.*\}\}|dummy|fake|test[-_]?key|sample)$/i;

function looksLikePlaceholder(value) {
  if (PLACEHOLDER_RE.test(value)) return true;
  // Repeated single character e.g. "aaaaaaaaaaaaaaaaaaaa"
  if (/^(.)\1+$/.test(value)) return true;
  return false;
}

/**
 * Run a git command in repoPath and return stdout as a string, or null if the directory
 * isn't a git repo / git isn't available / the command failed. Never throws.
 */
function tryGit(repoPath, args, opts = {}) {
  try {
    return execFileSync('git', args, {
      cwd: repoPath,
      encoding: 'utf8',
      maxBuffer: opts.maxBuffer || 200 * 1024 * 1024,
      windowsHide: true,
    });
  } catch (err) {
    // Some git commands (rare) still write useful stdout even on a non-zero exit.
    if (err && typeof err.stdout === 'string' && err.stdout.length > 0) return err.stdout;
    return null;
  }
}

function isGitRepo(repoPath) {
  return tryGit(repoPath, ['rev-parse', '--is-inside-work-tree']) !== null;
}

/**
 * Normalize a filesystem path for equality comparison across the two different shapes
 * a path can arrive in here: a Node-side path (`path.resolve()`'d, using the platform's
 * separator) and git's own output (`git rev-parse --show-toplevel` always prints
 * forward-slash paths, even on Windows). `path.resolve()` already normalizes slash style
 * and `.`/`..` segments, so running both sides through it is enough to make the
 * separators match; on Windows the filesystem is also case-insensitive, so the two paths
 * can legitimately differ only in case (e.g. a drive letter) and still refer to the same
 * directory, hence the lowercase fold on win32 only.
 */
function normalizeGitPathForCompare(p) {
  let norm = path.resolve(p).replace(/[\\/]+$/, ''); // drop a trailing separator, if any
  if (process.platform === 'win32') norm = norm.toLowerCase();
  return norm;
}

/**
 * Guard for any check that depends on `git log`/`git diff`-style history commands
 * (currently: git-history.js's full secret-git-history scan, and secrets.js's
 * git-history sub-scan for previously-committed-then-deleted .env files).
 *
 * Why this is needed beyond isGitRepo(): `git rev-parse --is-inside-work-tree` returns
 * true for ANY path under ANY repo, at any depth — it just walks up parent directories
 * looking for a `.git`. But git history commands run with `cwd` set to a subdirectory
 * still operate against the ENCLOSING repository's *entire* history and print
 * repo-root-relative paths, not paths scoped to that subdirectory. So scanning a
 * subdirectory that is not itself a repo root would silently walk and report on an
 * ancestor repo's commits — including files entirely outside the folder the caller
 * actually asked VibeScan to scan, and (worse) tagging any secrets found in that
 * unrelated history as if they belonged to the scanned target. This guard makes that
 * distinction explicit by comparing the scanned path against
 * `git rev-parse --show-toplevel` instead of merely checking "is this inside *a*
 * repo".
 *
 * @param {string} repoPath - the path VibeScan was asked to scan
 * @param {string} checkLabel - human-readable name of the check being guarded, folded
 *   into the warning message (e.g. "check 3: secret-git-history")
 * @returns {{ ok: true } | { ok: false, warning: string }}
 */
function guardGitHistoryScope(repoPath, checkLabel) {
  const resolvedTarget = path.resolve(repoPath);
  const topLevelRaw = tryGit(repoPath, ['rev-parse', '--show-toplevel']);

  if (topLevelRaw === null || topLevelRaw.trim() === '') {
    // Defensive fallback only — callers are expected to have already checked isGitRepo()
    // before reaching here, so this path shouldn't normally be hit.
    return {
      ok: false,
      warning: `${checkLabel}: skipped — target is not a git repository (or git is unavailable).`,
    };
  }

  const topLevel = topLevelRaw.trim();
  const normalizedTop = normalizeGitPathForCompare(topLevel);
  const normalizedTarget = normalizeGitPathForCompare(resolvedTarget);

  if (normalizedTop !== normalizedTarget) {
    return {
      ok: false,
      warning:
        `⚠ SKIPPED git-history secret scanning (${checkLabel}): the scanned path is not its own ` +
        'git repository root, so historical-secret results would be misattributed to unrelated ' +
        `code outside the scanned folder (git resolved the enclosing repository root as ` +
        `"${topLevel}", not the scanned path "${resolvedTarget}"). Scan the actual repository ` +
        "root, or run `git init` in this folder if it's meant to be standalone, to enable this " +
        'check.',
    };
  }

  return { ok: true };
}

// Characters after which a `/` is ambiguous-but-plausibly a regex-literal opener rather
// than division, e.g. `= /foo/`, `(/foo/)`, `, /foo/`, `return /foo/`. This is the same
// last-meaningful-token heuristic real syntax highlighters use — not a full parser, but
// it covers the code shapes this codebase (and most real-world source) actually uses.
const REGEX_ALLOWED_AFTER = new Set(['(', '[', '{', ',', ';', ':', '=', '!', '&', '|', '?', '+', '-', '*', '%', '^', '~', '<', '>', '\n', '']);

/**
 * Try to consume a `/regex literal/flags` starting at index i (text[i] === '/'). Returns
 * the end index (exclusive) if one was found, or null if this isn't actually a regex
 * literal (e.g. no unescaped closing `/` before a newline — division, not regex).
 */
function matchRegexLiteralEnd(text, i) {
  const n = text.length;
  let j = i + 1;
  let inClass = false;
  while (j < n) {
    const c = text[j];
    if (c === '\\') { j += 2; continue; }
    if (c === '\n') return null; // regex literals can't contain a literal newline
    if (c === '[') { inClass = true; j += 1; continue; }
    if (c === ']') { inClass = false; j += 1; continue; }
    if (c === '/' && !inClass) {
      j += 1;
      while (j < n && /[a-z]/i.test(text[j])) j += 1; // trailing flags
      return j;
    }
    j += 1;
  }
  return null;
}

/**
 * Blank out `//` and `/* *‍/` comment content (replacing comment characters with spaces,
 * preserving every newline and the overall string length) so line numbers / offsets
 * computed against the result still line up with the original source. Used by
 * static-checks.js so a comment that merely *describes* a call (e.g. "never calls
 * stripe.webhooks.constructEvent() to verify...") isn't mistaken for the call itself —
 * and so a comment that happens to mention an unrelated keyword (e.g. explaining what
 * "child_process" means) doesn't create a false negative/positive either.
 *
 * Deliberately NOT used by secrets.js: a secret accidentally left in a comment is still
 * a real leaked secret and must still be caught.
 *
 * Heuristic, not a real parser: tracks `//` comments, block comments, `'"/`` string
 * content, and — importantly — regex literals (`/pattern/flags`), copying the latter
 * through untouched rather than treating the quote/backtick characters *inside* the
 * pattern as if they opened a real string. Without that, a regex literal like
 * `` /`[^`]*`/ `` (a pattern that matches backticks, written using backticks) throws the
 * naive quote-tracking permanently out of sync for the rest of the file — not a rare
 * edge case, since regex-heavy source (including this scanner's own code) hits it
 * constantly. Division-vs-regex-literal disambiguation is itself an unsolvable-without-
 * a-real-parser problem in JS; the REGEX_ALLOWED_AFTER heuristic covers common shapes
 * and accepts rare misfires as a static-heuristic limitation.
 */
function stripComments(text) {
  let out = '';
  let state = 'code'; // 'code' | 'string' | 'lineComment' | 'blockComment'
  let stringChar = null;
  let prevMeaningful = ''; // last non-whitespace char emitted in 'code' state
  const n = text.length;
  let i = 0;
  while (i < n) {
    const ch = text[i];
    const next = i + 1 < n ? text[i + 1] : '';

    if (state === 'code') {
      if (ch === '/' && next === '/') { state = 'lineComment'; out += '  '; i += 2; continue; }
      if (ch === '/' && next === '*') { state = 'blockComment'; out += '  '; i += 2; continue; }
      if (ch === '/' && REGEX_ALLOWED_AFTER.has(prevMeaningful)) {
        const end = matchRegexLiteralEnd(text, i);
        if (end !== null) {
          out += text.slice(i, end); // copy the regex literal through verbatim — it's real code
          prevMeaningful = '/';
          i = end;
          continue;
        }
        // not actually a regex literal (no closing `/` before a newline) — fall through
        // and treat this `/` as an ordinary character (division).
      }
      if (ch === '"' || ch === "'" || ch === '`') { state = 'string'; stringChar = ch; out += ch; i += 1; continue; }
      out += ch;
      if (!/\s/.test(ch)) prevMeaningful = ch;
      else if (ch === '\n') prevMeaningful = '\n'; // newline resets regex-allowed context like most punctuation
      i += 1;
      continue;
    }

    if (state === 'string') {
      if (ch === '\\') { out += ch + next; i += 2; continue; }
      if (ch === stringChar) { state = 'code'; out += ch; prevMeaningful = ch; i += 1; continue; }
      out += ch; i += 1; continue;
    }

    if (state === 'lineComment') {
      if (ch === '\n') { state = 'code'; out += '\n'; i += 1; continue; }
      out += ' '; i += 1; continue;
    }

    // state === 'blockComment'
    if (ch === '*' && next === '/') { state = 'code'; out += '  '; i += 2; continue; }
    out += ch === '\n' ? '\n' : ' ';
    i += 1;
  }
  return out;
}

/**
 * Given text and the index of an opening '{', walk forward tracking brace depth to find
 * the matching '}', returning the full block (including both braces). Heuristic, not a
 * real parser -- doesn't treat quoted/template-literal content as opaque the way
 * extractBalancedCallArg does, but it's only ever called against comment-stripped,
 * narrow, function-body-shaped text, where a stray brace inside a string is rare enough
 * to accept as a v1 limitation. Returns null if unbalanced.
 *
 * Shared by static-checks.js (checks 4-9, 13-15) and secrets.js (checks 11-12) — moved
 * here (2026-07-24 evasion-bypass hardening pass) so every check that needs "look inside
 * a same-file function body" reuses one implementation instead of five bespoke ones.
 */
function extractBalancedBraceBlock(text, openBraceIndex) {
  let depth = 0;
  for (let i = openBraceIndex; i < text.length; i++) {
    const ch = text[i];
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return text.slice(openBraceIndex, i + 1);
    }
  }
  return null;
}

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

/**
 * Split a call's argument-list text (the contents extracted by extractBalancedCallArg,
 * i.e. everything between the outer parens) into its top-level comma-separated arguments.
 * Tracks (), {}, [] nesting depth and quoted/template-literal string content so a comma
 * *inside* a nested call/object/array/string (e.g. `Model.create({ a: 1, b: 2 }, opts)`'s
 * first argument) isn't mistaken for an argument separator.
 * @param {string} argsText
 * @returns {string[]}
 */
function splitTopLevelArgs(argsText) {
  const parts = [];
  let depth = 0;
  let inString = null; // one of ' " ` while inside a string/template literal
  let current = '';
  for (let i = 0; i < argsText.length; i++) {
    const ch = argsText[i];
    if (inString) {
      current += ch;
      if (ch === '\\') { i++; current += argsText[i] || ''; continue; }
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { inString = ch; current += ch; continue; }
    if (ch === '(' || ch === '{' || ch === '[') depth++;
    if (ch === ')' || ch === '}' || ch === ']') depth--;
    if (ch === ',' && depth === 0) { parts.push(current); current = ''; continue; }
    current += ch;
  }
  if (current.trim() !== '') parts.push(current);
  return parts;
}

// Extracts the expression following a `return` keyword inside `body` (a balanced brace
// block's text -- a function/arrow-block body), tracking (), {}, [] depth and quoted-
// string state instead of stopping at the first newline the way a naive
// `return\s+([^;\n]+)` regex does. Needed for return statements whose expression itself
// spans multiple lines inside balanced delimiters -- the classic hand-rolled
// `generateUUID()` idiom (`return 'xxxx'.replace(/[xy]/g, function (c) { ... multi-line
// body ... });`) has `Math.random()` several lines below the `return` keyword itself, so
// the old single-line capture never saw it even though the whole statement is one
// expression. Stops at the first top-level `;`, or at the enclosing block's own closing
// brace if the return has no trailing semicolon. Returns null if no `return` is found.
function extractReturnExpression(body) {
  const m = /return\s+/.exec(body);
  if (!m) return null;
  const start = m.index + m[0].length;
  let depth = 0;
  let inString = null;
  let i = start;
  for (; i < body.length; i++) {
    const ch = body[i];
    if (inString) {
      if (ch === '\\') { i++; continue; }
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { inString = ch; continue; }
    if (ch === '(' || ch === '{' || ch === '[') { depth++; continue; }
    if (ch === ')' || ch === '}' || ch === ']') {
      if (depth === 0) break; // hit the enclosing block's own closing delimiter
      depth--;
      continue;
    }
    if (ch === ';' && depth === 0) break;
  }
  return body.slice(start, i).trim() || null;
}

// Looks up a same-file `class ClassName { static methodName(...) { ... return expr; ... }
// }` static method and returns its return expression, or null if the class/method/return
// can't be found. Regex-located, one level deep, same convention as
// lookupFunctionReturnExpr's other shapes below -- added 2026-07-24 (round 2 evasion
// audit) after a class-static-method call (`TokenGen.generate()`) was found to be
// completely invisible to the bare-identifier-only helper-call resolution used elsewhere.
function lookupStaticMethodReturnExpr(clean, className, methodName) {
  const classEsc = className.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const methodEsc = methodName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const classRe = new RegExp(`class\\s+${classEsc}\\b[^{]*\\{`);
  const classMatch = classRe.exec(clean);
  if (!classMatch) return null;
  const classBraceIndex = classMatch.index + classMatch[0].length - 1;
  const classBody = extractBalancedBraceBlock(clean, classBraceIndex);
  if (!classBody) return null;
  const methodRe = new RegExp(`static\\s+${methodEsc}\\s*\\([^)]*\\)\\s*\\{`);
  const methodMatch = methodRe.exec(classBody);
  if (!methodMatch) return null;
  const methodBraceIndex = methodMatch.index + methodMatch[0].length - 1;
  const methodBody = extractBalancedBraceBlock(classBody, methodBraceIndex);
  if (!methodBody) return null;
  return extractReturnExpression(methodBody);
}

// Looks up a same-file helper named `calleeName` -- as a classic `function name(...) {}`
// declaration OR an arrow function assigned to const/let/var (block body with an explicit
// `return`, or a concise/expression body with an implicit return, e.g.
// `const gen = () => Math.random()...`) -- and returns the expression it returns, or null
// if none of these shapes can be found. Regex-located, not a real parser -- deliberately
// only one level (callers don't recurse through this a second time), which is cheap and
// enough to catch the common "wrap the interpolation in a same-file helper" evasion
// without the complexity of real dataflow analysis.
//
// Arrow-function support added 2026-07-24 after an adversarial audit found the
// function-declaration-only version missed the identical evasion shape when written as an
// arrow function -- arrow functions are, if anything, more common than `function`
// declarations in modern JS/TS (including AI-generated code), so this was a mainstream
// style gap, not just a deeper adversarial evasion.
//
// Round-2 additions (2026-07-24, same day): `calleeName` may now be a dotted
// `ClassName.methodName` (a static-method call site), dispatched to
// lookupStaticMethodReturnExpr; the function-declaration regex now tolerates a
// TypeScript return-type annotation between the params and the opening `{`
// (`function name(): string {`); and both arrow-function regexes now tolerate a leading
// `async` keyword before the params (`const name = async () => ...`).
function lookupFunctionReturnExpr(clean, calleeName) {
  const dotIndex = calleeName.indexOf('.');
  if (dotIndex !== -1) {
    return lookupStaticMethodReturnExpr(clean, calleeName.slice(0, dotIndex), calleeName.slice(dotIndex + 1));
  }

  const escaped = calleeName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const paramsPattern = '(?:\\([^)]*\\)|[A-Za-z_$][\\w$]*)'; // (a, b) or a bare single param

  // Classic function declaration: function name(...) { ... return expr; ... }
  // Optional `(?:\s*:\s*[^{]+)?` between the params and `{` tolerates a TypeScript
  // return-type annotation (`function name(): string {`) -- ordinary, idiomatic
  // TypeScript, not an adversarial trick.
  const declRe = new RegExp(`function\\s+${escaped}\\s*\\([^)]*\\)\\s*(?::\\s*[^{]+)?\\{`);
  const declMatch = declRe.exec(clean);
  if (declMatch) {
    const braceIndex = declMatch.index + declMatch[0].length - 1;
    const body = extractBalancedBraceBlock(clean, braceIndex);
    if (body) {
      const expr = extractReturnExpression(body);
      if (expr) return expr;
    }
  }

  // Arrow function, block body: const name = (...) => { ... return expr; ... }
  // Optional `(?:async\s+)?` tolerates `const name = async (...) => { ... }`.
  const arrowBlockRe = new RegExp(`(?:const|let|var)\\s+${escaped}\\s*=\\s*(?:async\\s+)?${paramsPattern}\\s*=>\\s*\\{`);
  const arrowBlockMatch = arrowBlockRe.exec(clean);
  if (arrowBlockMatch) {
    const braceIndex = arrowBlockMatch.index + arrowBlockMatch[0].length - 1;
    const body = extractBalancedBraceBlock(clean, braceIndex);
    if (body) {
      const expr = extractReturnExpression(body);
      if (expr) return expr;
    }
  }

  // Arrow function, concise/expression body (implicit return, no braces):
  // const name = (...) => expr   or   const name = x => expr
  // Optional `(?:async\s+)?` tolerates `const name = async (...) => expr`.
  const arrowExprRe = new RegExp(`(?:const|let|var)\\s+${escaped}\\s*=\\s*(?:async\\s+)?${paramsPattern}\\s*=>\\s*([^;\\n{][^;\\n]*)`);
  const arrowExprMatch = arrowExprRe.exec(clean);
  if (arrowExprMatch) return arrowExprMatch[1].trim();

  return null;
}

/**
 * Resolve a simple `identifier + identifier`/`identifier + 'literal'`/`'literal' + ...`
 * chain (as found in `expr`) to a single string, following `const/let/var` lookups
 * recursively for any bare identifier operand (so `const a = b; const b = 'x' + 'y';`
 * resolves `a` all the way down to "xy", not just one hop). Returns null (rather than
 * guessing) the moment it hits anything it can't confidently resolve -- a function call, a
 * member expression it can't find a declaration for, etc. Used to defeat "value built via
 * concatenation, then routed through one or more variable hops" evasions without needing a
 * real parser.
 */
function resolveConcatExpression(clean, expr) {
  const parts = expr.split('+').map((p) => p.trim());
  let resolved = '';
  for (const part of parts) {
    const litMatch = part.match(/^['"`]((?:[^'"`\\\n]|\\.)*)['"`]$/);
    if (litMatch) {
      resolved += litMatch[1];
      continue;
    }
    const identMatch = part.match(/^[A-Za-z_$][\w$]*$/);
    if (identMatch) {
      const escaped = part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      // No trailing `;` required -- [^;\n]+ already stops at the first `;` or newline on
      // its own, so requiring a literal `;` immediately after only served to reject
      // semicolon-free declarations (Standard.js style, `semi:false`, plenty of
      // AI-generated code), not to bound the capture. Fixed 2026-07-24 after an
      // adversarial audit found this was a mainstream style gap, not just a deeper
      // evasion: `const HASH_ALGO = 'md5'` (no semicolon) was invisible to this resolver.
      const declRe = new RegExp(`(?:const|let|var)\\s+${escaped}\\s*=\\s*([^;\\n]+)`);
      const dm = clean.match(declRe);
      if (!dm) return null;
      const subResolved = resolveConcatExpression(clean, dm[1]);
      if (subResolved === null) return null;
      resolved += subResolved;
      continue;
    }
    // Static class field, accessed as a member expression: `HashConfig.ALGO`. Neither a
    // plain literal nor a bare identifier (it contains a '.'), so the two branches above
    // both reject it outright -- added 2026-07-24 (round 2 evasion audit) after a
    // class-static-field config constant (a completely ordinary way to centralize a
    // config value in modern JS/TS, not an adversarial trick) was found to defeat this
    // resolver entirely.
    const memberMatch = part.match(/^([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)$/);
    if (memberMatch) {
      const [, className, fieldName] = memberMatch;
      const classEsc = className.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const fieldEsc = fieldName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const classRe = new RegExp(`class\\s+${classEsc}\\b[^{]*\\{`);
      const classMatch = classRe.exec(clean);
      if (!classMatch) return null;
      const classBraceIndex = classMatch.index + classMatch[0].length - 1;
      const classBody = extractBalancedBraceBlock(clean, classBraceIndex);
      if (!classBody) return null;
      const fieldDeclRe = new RegExp(`static\\s+${fieldEsc}\\s*=\\s*([^;\\n]+)`);
      const fieldMatch = classBody.match(fieldDeclRe);
      if (!fieldMatch) return null;
      const subResolved = resolveConcatExpression(clean, fieldMatch[1]);
      if (subResolved === null) return null;
      resolved += subResolved;
      continue;
    }
    return null; // not a plain literal or a resolvable identifier -- bail rather than guess
  }
  return resolved;
}

/**
 * Follow a chain of `const/let/var <name> = <rhs>;` declarations, one hop at a time,
 * for as long as each `<rhs>` is itself just a bare identifier -- e.g.
 *   const raw = req.body;
 *   const input = raw;
 * resolveIdentifierChain(clean, 'input') returns "req.body" (two hops: input -> raw ->
 * "req.body", the first non-bare-identifier RHS it finds). This generalizes the "one
 * variable hop" precedent used throughout this codebase (mass-assignment,
 * insecure-cookie-flags, open-redirect, CORS) to an arbitrary (but bounded) number of
 * hops, closing evasions that route a tainted value through two or more reassignments
 * instead of one.
 *
 * Returns the terminal RHS expression text (untouched, whatever shape it is -- a literal,
 * a `req.*` expression, an object literal, a call expression, ...) the moment that RHS is
 * anything other than a bare identifier. Returns null if `name`'s own declaration can't be
 * found at all, or if `maxHops` is exceeded (bail rather than guess/loop forever on a
 * pathological chain).
 *
 * @param {string} clean - comment-stripped source text to search
 * @param {string} name - identifier to start resolving from
 * @param {number} [maxHops] - maximum number of `const/let/var` hops to follow
 * @returns {string|null}
 */
function resolveIdentifierChain(clean, name, maxHops = 6) {
  let current = name;
  const seen = new Set();
  for (let hop = 0; hop < maxHops; hop++) {
    if (seen.has(current)) return null; // cyclical/self-referential chain -- bail
    seen.add(current);
    const escaped = current.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // Same fix as resolveConcatExpression above: no trailing `;` required, so
    // semicolon-free declarations resolve too, not just semicolon-terminated ones.
    const declRe = new RegExp(`(?:const|let|var)\\s+${escaped}\\s*=\\s*([^;\\n]+)`);
    const m = clean.match(declRe);
    if (!m) return null; // declaration not found -- can't confirm, don't guess
    const rhs = m[1].trim();
    const identMatch = rhs.match(/^[A-Za-z_$][\w$]*$/);
    if (identMatch) {
      current = rhs;
      continue; // RHS is itself a bare identifier -- keep following the chain
    }
    return rhs; // terminal: a non-bare-identifier expression, whatever shape it is
  }
  return null; // too many hops -- bail rather than guess
}

/**
 * Find simple string-literal concatenation chains on a single line, e.g. 'a' + 'b' + "c"
 * -- two or more quoted literals joined only by '+' -- and return the joined literal
 * value for each chain found. This is a plain-text heuristic (no real parser): it doesn't
 * understand operator precedence or non-literal operands mixed into the chain, but it's
 * enough to defeat the common "split a known secret format (or a sensitive route path)
 * across two or three string literals so no single regex-matchable literal ever appears"
 * evasion, since joining the literal parts back together and re-testing the known-format
 * regex against the joined value recovers the original contiguous text.
 * @param {string} line - text to search (intended to be a single line, no newlines)
 * @returns {Array<{ index: number, raw: string, value: string }>}
 */
function findStringConcatChains(line) {
  const CHAIN_RE = /(?:['"](?:[^'"\\\n]|\\.)*['"]\s*\+\s*){1,}['"](?:[^'"\\\n]|\\.)*['"]/g;
  const PART_RE = /['"]((?:[^'"\\\n]|\\.)*)['"]/g;
  const results = [];
  let m;
  CHAIN_RE.lastIndex = 0;
  while ((m = CHAIN_RE.exec(line)) !== null) {
    const raw = m[0];
    let value = '';
    PART_RE.lastIndex = 0;
    let pm;
    while ((pm = PART_RE.exec(raw)) !== null) {
      value += pm[1];
    }
    results.push({ index: m.index, raw, value });
  }
  return results;
}

module.exports = {
  SKIP_DIRS,
  walkFiles,
  readTextFile,
  makeId,
  redactSecret,
  shannonEntropy,
  looksLikePlaceholder,
  tryGit,
  isGitRepo,
  guardGitHistoryScope,
  stripComments,
  findStringConcatChains,
  extractBalancedBraceBlock,
  extractBalancedCallArg,
  splitTopLevelArgs,
  lookupFunctionReturnExpr,
  resolveConcatExpression,
  resolveIdentifierChain,
};
