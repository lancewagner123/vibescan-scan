'use strict';

// Checks 1 & 2 from docs/CHECK_CATALOG.md:
//   1. secret-hardcoded-generic
//   2. secret-env-committed
//
// Also exports scanTextForSecrets()/SINGLE_LINE_PATTERNS/MULTILINE_PATTERNS so
// git-history.js can reuse exactly the same detection logic against diff text
// instead of duplicating the regex set.

const path = require('path');
const {
  walkFiles,
  readTextFile,
  makeId,
  redactSecret,
  shannonEntropy,
  looksLikePlaceholder,
  tryGit,
  isGitRepo,
  guardGitHistoryScope,
  findStringConcatChains,
  stripComments,
} = require('./util');

const CHECK_HARDCODED = 'secret-hardcoded-generic';
const CHECK_ENV_COMMITTED = 'secret-env-committed';
const CHECK_INSECURE_RANDOM_TOKEN = 'insecure-random-token';
const CHECK_WEAK_PASSWORD_HASHING = 'weak-password-hashing';

// --- Known key-format patterns (checked one line at a time) --------------------------

const SINGLE_LINE_PATTERNS = [
  {
    name: 'aws-access-key',
    regex: /AKIA[0-9A-Z]{16}/,
    describe: () => 'AWS access key ID (AKIA...)',
  },
  {
    name: 'stripe-key',
    regex: /\b(?:sk_live_|sk_test_|rk_live_)[0-9A-Za-z]{10,}\b/,
    describe: (m) => `Stripe ${m.startsWith('sk_live_') ? 'live secret' : m.startsWith('rk_live_') ? 'live restricted' : 'test secret'} key`,
  },
  {
    name: 'google-api-key',
    regex: /AIza[0-9A-Za-z_-]{35}/,
    describe: () => 'Google API key (AIza...)',
  },
  {
    name: 'slack-token',
    regex: /xox[baprs]-[0-9A-Za-z-]{10,}/,
    describe: () => 'Slack token (xox...)',
  },
  {
    name: 'jwt-shaped-token',
    regex: /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
    describe: () => 'JWT-shaped token (possible Supabase service_role key or other signed session token)',
  },
];

// --- Patterns that span multiple lines (checked against the whole file) --------------

const MULTILINE_PATTERNS = [
  {
    name: 'pem-private-key',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]{0,20000}?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/,
    describe: () => 'PEM private key block',
  },
];

// --- Generic high-entropy key/secret/token/password literal heuristic ----------------

// Matches `<name containing key/secret/token/password>: "<long literal>"` style
// assignments/object properties in any language-ish source (JS/TS/JSON/YAML/etc.).
const GENERIC_ENTROPY_RE = /[\w.$]*(?:key|secret|token|password|passwd|pwd)[\w]*\s*[:=]\s*["'`]([A-Za-z0-9+/_=-]{20,})["'`]/gi;
const ENTROPY_THRESHOLD = 3.0; // bits/char — placeholders/words fall well below this

function scanLineGenericEntropy(line) {
  const hits = [];
  GENERIC_ENTROPY_RE.lastIndex = 0;
  let m;
  while ((m = GENERIC_ENTROPY_RE.exec(line)) !== null) {
    const value = m[1];
    if (looksLikePlaceholder(value)) continue;
    if (shannonEntropy(value) < ENTROPY_THRESHOLD) continue;
    hits.push({ value, matchedText: m[0] });
  }
  return hits;
}

// Same key/secret/token/password-ish-name heuristic as GENERIC_ENTROPY_RE, but for
// UNQUOTED `KEY=value` assignments (classic dotenv shape) instead of quoted `key: "value"`
// object/JS literals. Anchored to the WHOLE line (only optional leading/trailing
// whitespace allowed) so it can't accidentally match a JS statement like
// `const password = someLongVariableName;` -- that line has a `const ` prefix before the
// key (breaking the required contiguous `[\w.$]*` + keyword run) and/or a trailing `;`
// that the value's character class deliberately excludes, so ordinary source statements
// fall through untouched while real `KEY=value`-shaped lines (as found in .env-style
// files, regardless of filename) still match.
const GENERIC_ENTROPY_UNQUOTED_RE = /^[ \t]*[\w.$]*(?:key|secret|token|password|passwd|pwd)[\w]*\s*=\s*([^\s#'"`;(){}[\]]{16,})[ \t]*$/gi;

function scanLineGenericEntropyUnquoted(line) {
  const hits = [];
  GENERIC_ENTROPY_UNQUOTED_RE.lastIndex = 0;
  let m;
  while ((m = GENERIC_ENTROPY_UNQUOTED_RE.exec(line)) !== null) {
    const value = m[1];
    if (looksLikePlaceholder(value)) continue;
    if (shannonEntropy(value) < ENTROPY_THRESHOLD) continue;
    hits.push({ value, matchedText: m[0] });
  }
  return hits;
}

// --- Evasion-resistance pass 1: string-literal concatenation joining -----------------
//
// Defeats "split a known-format secret across two or three string literals joined with
// `+` on the same line" (e.g. `'AKIA' + 'Q3FAKE7EXAMPLE9Z'`), which slips past every
// SINGLE_LINE_PATTERNS regex above because none of them ever appears contiguous on the
// line as written. Joins each concatenation chain found on the line back into a single
// value and re-tests every known-format regex against that joined value.
function scanLineConcatChains(line) {
  const hits = [];
  for (const chain of findStringConcatChains(line)) {
    if (chain.value.length < 6) continue; // too short to be any known secret format
    for (const pattern of SINGLE_LINE_PATTERNS) {
      const m = chain.value.match(pattern.regex);
      if (m) {
        hits.push({
          name: pattern.name,
          matchedText: chain.raw,
          secretValue: chain.value,
          describeText: `${pattern.describe(m[0])} (reassembled from concatenated string literals: ${chain.raw.slice(0, 80)})`,
        });
      }
    }
  }
  return hits;
}

// --- Evasion-resistance pass 2: base64 decode-and-recheck ----------------------------
//
// Defeats "base64-encode the secret and decode it at runtime, under an innocuous variable
// name" -- base64 encoding removes every recognizable prefix (sk_live_, AKIA, etc.) so
// none of the known-format regexes match the encoded literal itself, and using a variable
// name with no key/secret/token/password substring keeps GENERIC_ENTROPY_RE from even
// looking at it. Any quoted literal that looks base64-shaped gets decoded and the decoded
// text re-run through the known-format regexes; a round-trip re-encode check guards
// against "decoding" an unrelated long alphanumeric literal (a hex hash, an id, etc.)
// into meaningless bytes that coincidentally matched something.
const BASE64_LITERAL_RE = /['"]([A-Za-z0-9+/]{20,}={0,2})['"]/g;

function scanLineBase64Encoded(line) {
  const hits = [];
  BASE64_LITERAL_RE.lastIndex = 0;
  let m;
  while ((m = BASE64_LITERAL_RE.exec(line)) !== null) {
    const encoded = m[1];
    let decoded;
    try {
      decoded = Buffer.from(encoded, 'base64').toString('utf8');
    } catch {
      continue;
    }
    const reencoded = Buffer.from(decoded, 'utf8').toString('base64').replace(/=+$/, '');
    if (reencoded !== encoded.replace(/=+$/, '')) continue; // not actually valid base64 round-trip
    for (const pattern of SINGLE_LINE_PATTERNS) {
      const dm = decoded.match(pattern.regex);
      if (dm) {
        hits.push({
          name: pattern.name,
          matchedText: m[0],
          secretValue: dm[0],
          describeText: `${pattern.describe(dm[0])} (base64-encoded in source, decoded at scan time)`,
        });
      }
    }
  }
  return hits;
}

/**
 * Scan arbitrary text (a file's contents, or a git diff's added-line text) for every
 * known secret pattern. Returns raw hits — not yet Finding objects — so callers (this
 * module and git-history.js) can attach their own file/line/commit context.
 *
 * @param {string} text
 * @returns {Array<{ name: string, line: number, matchedText: string, describe: string, secretValue: string }>}
 */
function scanTextForSecrets(text) {
  const hits = [];
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of SINGLE_LINE_PATTERNS) {
      const m = line.match(pattern.regex);
      if (m) {
        hits.push({
          name: pattern.name,
          line: i + 1,
          matchedText: m[0],
          secretValue: m[0],
          describe: pattern.describe(m[0]),
        });
      }
    }
    for (const hit of scanLineGenericEntropy(line)) {
      hits.push({
        name: 'generic-high-entropy',
        line: i + 1,
        matchedText: hit.matchedText,
        secretValue: hit.value,
        describe: 'high-entropy literal assigned to a key/secret/token/password-like name',
      });
    }
    for (const hit of scanLineGenericEntropyUnquoted(line)) {
      hits.push({
        name: 'generic-high-entropy-unquoted',
        line: i + 1,
        matchedText: hit.matchedText,
        secretValue: hit.value,
        describe: 'high-entropy unquoted KEY=value assignment (dotenv-style) to a key/secret/token/password-like name',
      });
    }
    for (const hit of scanLineConcatChains(line)) {
      hits.push({
        name: hit.name,
        line: i + 1,
        matchedText: hit.matchedText,
        secretValue: hit.secretValue,
        describe: hit.describeText,
      });
    }
    for (const hit of scanLineBase64Encoded(line)) {
      hits.push({
        name: hit.name,
        line: i + 1,
        matchedText: hit.matchedText,
        secretValue: hit.secretValue,
        describe: hit.describeText,
      });
    }
  }

  // Multiline patterns run against the full text; compute the line number from the
  // match's character offset by counting newlines before it.
  for (const pattern of MULTILINE_PATTERNS) {
    const m = text.match(pattern.regex);
    if (m) {
      const line = text.slice(0, m.index).split(/\r?\n/).length;
      hits.push({
        name: pattern.name,
        line,
        matchedText: m[0].slice(0, 60),
        secretValue: m[0],
        describe: pattern.describe(),
      });
    }
  }

  return hits;
}

function buildHardcodedFinding(filePath, repoRelPath, hit) {
  const snippet = redactSecret(hit.secretValue).slice(0, 200);
  return {
    id: makeId(CHECK_HARDCODED, [repoRelPath, String(hit.line), hit.name, hit.matchedText]),
    checkId: CHECK_HARDCODED,
    severity: 'critical',
    category: 'secret',
    file: repoRelPath,
    line: hit.line,
    snippet,
    rawMessage: `Possible ${hit.describe} found in ${repoRelPath}:${hit.line}`,
  };
}

// --- Check 2: .env* files present in the working tree or tracked in git --------------

// Conventionally-safe template files — not real secrets, so don't flag them.
const SAFE_ENV_TEMPLATE_NAMES = new Set([
  '.env.example',
  '.env.sample',
  '.env.template',
  '.env.dist',
]);

// Was /^\.env(\..+)?$/ -- required a literal dot before any suffix, so a filename like
// ".env-production" (hyphen instead of dot) or ".env_local" (underscore) slipped through
// even though it's the same real dotenv file loaded the same way at runtime. Broadened to
// accept '.', '-', or '_' as the separator before the suffix, while still anchoring on
// the leading ".env" so unrelated filenames (e.g. a hypothetical ".environment") aren't
// swept in: after ".env" the next character must be one of [.\-_] or end-of-string, not
// just any word character.
const ENV_FILE_RE = /^\.env([.\-_].*)?$/;

function isFlaggableEnvFilename(basename) {
  return ENV_FILE_RE.test(basename) && !SAFE_ENV_TEMPLATE_NAMES.has(basename);
}

function scanEnvFilesWorkingTree(repoPath) {
  const findings = [];
  const allFiles = walkFiles(repoPath); // no extension filter — .env files have none
  for (const filePath of allFiles) {
    const basename = path.basename(filePath);
    if (!isFlaggableEnvFilename(basename)) continue;
    const repoRelPath = path.relative(repoPath, filePath).split(path.sep).join('/');
    findings.push({
      id: makeId(CHECK_ENV_COMMITTED, [repoRelPath, 'working-tree']),
      checkId: CHECK_ENV_COMMITTED,
      severity: 'high',
      category: 'secret',
      file: repoRelPath,
      line: null,
      snippet: `${basename} present in working tree`,
      rawMessage: `Env file "${repoRelPath}" is present in the working tree — verify it is not tracked by git and never gets committed.`,
    });
  }
  return findings;
}

/**
 * Beyond what's on disk right now, look for .env* files that were ever *added* in git
 * history across any branch — this catches the case where a secret-bearing .env file
 * was committed once and later deleted, which still leaks the file (and often its
 * contents) via history.
 *
 * @returns {{ findings: object[], warnings: string[] }}
 */
function scanEnvFilesGitHistory(repoPath, workingTreeFindings) {
  if (!isGitRepo(repoPath)) return { findings: [], warnings: [] };

  // Guard against the ancestor-repo misattribution bug: `isGitRepo` above only proves
  // repoPath is *somewhere inside* a git work tree, not that it's the repo's own root.
  // See guardGitHistoryScope's docstring in util.js for the full "why".
  const scope = guardGitHistoryScope(repoPath, "secret-env-committed's git-history scan");
  if (!scope.ok) {
    return { findings: [], warnings: [scope.warning] };
  }

  const alreadyFlagged = new Set(workingTreeFindings.map((f) => f.file));
  const out = tryGit(repoPath, [
    'log', '--all', '--diff-filter=A', '--name-only', '--pretty=format:',
  ]);
  if (out === null) return { findings: [], warnings: [] };

  const findings = [];
  const seen = new Set();
  for (const rawLine of out.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const basename = path.basename(line);
    if (!isFlaggableEnvFilename(basename)) continue;
    const repoRelPath = line.split(path.sep).join('/');
    if (alreadyFlagged.has(repoRelPath) || seen.has(repoRelPath)) continue;
    seen.add(repoRelPath);
    findings.push({
      id: makeId(CHECK_ENV_COMMITTED, [repoRelPath, 'git-history']),
      checkId: CHECK_ENV_COMMITTED,
      severity: 'high',
      category: 'secret',
      file: repoRelPath,
      line: null,
      snippet: `${basename} found in git history (not in current working tree)`,
      rawMessage: `Env file "${repoRelPath}" was committed at some point in git history and later removed — its contents may still be recoverable from history.`,
    });
  }
  return { findings, warnings: [] };
}

// --- Check 1: hardcoded secrets across the working tree ------------------------------

const SOURCE_EXTENSIONS = [
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.json', '.env', '.yml', '.yaml', '.txt', '.md',
  '.py', '.rb', '.go', '.php', '.html', '.sh', '.ps1',
];

function scanHardcodedSecrets(repoPath) {
  const findings = [];
  const allFiles = walkFiles(repoPath); // no extension filter: secrets hide in any file type
  for (const filePath of allFiles) {
    const text = readTextFile(filePath);
    if (!text) continue;
    const repoRelPath = path.relative(repoPath, filePath).split(path.sep).join('/');
    const hits = scanTextForSecrets(text);
    for (const hit of hits) {
      findings.push(buildHardcodedFinding(filePath, repoRelPath, hit));
    }
  }
  return findings;
}

// --- Check 11: insecure-random-token -------------------------------------------------
//
// Math.random() is not cryptographically secure -- it's seeded from predictable state
// and its output can be reconstructed/guessed given enough samples, so anything built
// from it (session ids, password-reset tokens, API keys, CSRF nonces, ...) can be
// forged or predicted by an attacker. This check flags Math.random() -- including the
// extremely common `Math.random().toString(36)` idiom used to turn the float into an
// alphanumeric-looking string -- flowing into an assignment/property whose name
// suggests it's meant to be a security-sensitive token.
//
// Only JS/TS source is scanned: Math.random()/crypto are Node/browser JS APIs, so
// other languages walked by the hardcoded-secret check above can't produce this pattern.
const RANDOM_TOKEN_SOURCE_EXTENSIONS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];

// Deliberately loose substring match, same style as GENERIC_ENTROPY_RE above: matches
// any identifier/property chain containing one of these security-token-ish words,
// however it's cased (resetToken, reset_token, sessionId, session_id, apiKey, api_key,
// authToken, csrfToken, mySecret, nonce, ...). `session[_-]?id` and `api[_-]?key` need
// their own alternatives (neither substring is covered by the others); the rest
// (token/secret/nonce/csrf) already cover every other name in the spec as a plain
// substring, including "resetToken"/"authToken"/"csrfToken" (all contain "token").
const TOKEN_ISH_NAME_SRC = '[\\w$.]*(?:token|session[_-]?id|api[_-]?key|secret|nonce|csrf)[\\w$]*';

// Captures (1) the assigned name and (2) everything up to the end of the statement
// (next `;` or newline), so the Math.random() call can appear anywhere in the RHS
// (`Math.random()`, `Math.random().toString(36)`, `Math.random().toString(36).slice(2)`,
// etc.) without needing a separate pattern per chained-method variant. `=(?!=|>)` keeps
// this from matching `==`/`===` comparisons or `=>` arrow functions; `:` additionally
// covers object-literal property shorthand (`resetToken: Math.random()...`).
const INSECURE_RANDOM_TOKEN_RE = new RegExp(
  `(${TOKEN_ISH_NAME_SRC})\\s*(?::|=(?!=|>))\\s*([^;\\n]*\\bMath\\.random\\(\\)[^;\\n]*)`,
  'gi',
);

function lineOfIndex(text, index) {
  return text.slice(0, index).split(/\r?\n/).length;
}

function snippetAt(text, index, len = 200) {
  const lineStart = text.lastIndexOf('\n', index) + 1;
  let lineEnd = text.indexOf('\n', index);
  if (lineEnd === -1) lineEnd = text.length;
  return text.slice(lineStart, lineEnd).trim().slice(0, len);
}

function checkInsecureRandomToken(clean, original) {
  const hits = [];
  INSECURE_RANDOM_TOKEN_RE.lastIndex = 0;
  let m;
  while ((m = INSECURE_RANDOM_TOKEN_RE.exec(clean)) !== null) {
    const name = m[1];
    hits.push({
      line: lineOfIndex(original, m.index),
      snippet: snippetAt(original, m.index),
      rawMessage: `Math.random() is used to build the value assigned to "${name}", a name that suggests a security-sensitive token (session id, reset token, API key, secret, nonce, or CSRF token). Math.random() is not cryptographically secure and its output is predictable, so tokens built from it can be guessed -- use crypto.randomBytes(n).toString('hex') or crypto.randomUUID() instead.`,
    });
  }
  return hits;
}

function scanInsecureRandomTokens(repoPath) {
  const findings = [];
  const files = walkFiles(repoPath, { extensions: RANDOM_TOKEN_SOURCE_EXTENSIONS });
  for (const filePath of files) {
    const original = readTextFile(filePath);
    if (!original) continue;
    const clean = stripComments(original);
    const repoRelPath = path.relative(repoPath, filePath).split(path.sep).join('/');
    for (const hit of checkInsecureRandomToken(clean, original)) {
      findings.push({
        id: makeId(CHECK_INSECURE_RANDOM_TOKEN, [repoRelPath, String(hit.line), hit.snippet]),
        checkId: CHECK_INSECURE_RANDOM_TOKEN,
        severity: 'high',
        category: 'crypto',
        file: repoRelPath,
        line: hit.line,
        snippet: hit.snippet.slice(0, 200),
        rawMessage: hit.rawMessage,
      });
    }
  }
  return findings;
}

// --- Check 12: weak-password-hashing --------------------------------------------------
//
// crypto.createHash('md5')/crypto.createHash('sha1') are fast, unsalted digests -- fine
// for checksums/cache-busting, but catastrophic for password storage: a breached user
// database becomes fully crackable via rainbow tables/GPU brute force, not just
// partially. Only flag this in a context that actually looks password-related, so a
// checksum helper hashing file contents with md5 elsewhere in the codebase isn't swept
// in.
const WEAK_HASH_ALGO_RE = /crypto\s*\.\s*createHash\s*\(\s*(['"`])(md5|sha1)\1\s*\)/gi;
const PASSWORD_CONTEXT_RE = /\b(password|passwd|pwd)\b/i;
const AUTH_FILE_PATH_RE = /(^|\/)(auth|login|log-in|signup|sign-up|register|registration)([./]|$)/i;

// Scoped to the current statement only (previous ';' up to the next ';', inclusive of
// the whole chain in between -- so a multi-line `.createHash(...).update(...).digest
// (...)` chain is still captured whole) rather than a blind fixed-size character window.
// A window measured in raw characters bleeds into whatever unrelated code/comments
// happen to sit within N chars before/after in a densely-packed file (e.g. the next
// function over, or a comment mentioning "password" in passing) -- statement scoping
// ties the check to "is the actual value being hashed here named password-ish", which is
// what the check is meant to detect.
function currentStatementWindow(text, index) {
  const priorSemi = text.lastIndexOf(';', index);
  const start = priorSemi === -1 ? 0 : priorSemi + 1;
  let end = text.indexOf(';', index);
  if (end === -1) end = text.length;
  return text.slice(start, end + 1);
}

function checkWeakPasswordHashing(clean, original, repoRelPath) {
  const hits = [];
  const fileLooksAuthy = AUTH_FILE_PATH_RE.test(repoRelPath);
  WEAK_HASH_ALGO_RE.lastIndex = 0;
  let m;
  while ((m = WEAK_HASH_ALGO_RE.exec(clean)) !== null) {
    const algo = m[2].toLowerCase();
    const statement = currentStatementWindow(clean, m.index);
    const nearbyLooksPasswordy = PASSWORD_CONTEXT_RE.test(statement);
    if (!nearbyLooksPasswordy && !fileLooksAuthy) continue; // no password-ish signal at all -- likely a checksum/etag use, leave it alone
    const reason = nearbyLooksPasswordy
      ? 'a nearby variable/argument name suggests it is hashing a password'
      : `the file ("${repoRelPath}") looks like an auth/login/signup/register route or module`;
    hits.push({
      line: lineOfIndex(original, m.index),
      snippet: snippetAt(original, m.index),
      rawMessage: `crypto.createHash('${algo}') is used where ${reason} -- ${algo.toUpperCase()} is fast and unsalted, so a breached password database hashed this way is fully crackable at scale. Use bcrypt, scrypt, or argon2 instead.`,
    });
  }
  return hits;
}

function scanWeakPasswordHashing(repoPath) {
  const findings = [];
  const files = walkFiles(repoPath, { extensions: RANDOM_TOKEN_SOURCE_EXTENSIONS });
  for (const filePath of files) {
    const original = readTextFile(filePath);
    if (!original) continue;
    const clean = stripComments(original);
    const repoRelPath = path.relative(repoPath, filePath).split(path.sep).join('/');
    for (const hit of checkWeakPasswordHashing(clean, original, repoRelPath)) {
      findings.push({
        id: makeId(CHECK_WEAK_PASSWORD_HASHING, [repoRelPath, String(hit.line), hit.snippet]),
        checkId: CHECK_WEAK_PASSWORD_HASHING,
        severity: 'high',
        category: 'crypto',
        file: repoRelPath,
        line: hit.line,
        snippet: hit.snippet.slice(0, 200),
        rawMessage: hit.rawMessage,
      });
    }
  }
  return findings;
}

/**
 * @param {string} repoPath - absolute path to the target repo's working tree
 * @param {object} [opts]
 * @returns {{ findings: object[], warnings: string[] }}
 */
function scan(repoPath, opts = {}) {
  const warnings = [];
  let findings = [];

  try {
    findings = findings.concat(scanHardcodedSecrets(repoPath));
  } catch (err) {
    warnings.push(`secrets.js: hardcoded-secret scan failed: ${err.message}`);
  }

  try {
    const workingTreeEnvFindings = scanEnvFilesWorkingTree(repoPath);
    findings = findings.concat(workingTreeEnvFindings);
    const gitHistoryEnvResult = scanEnvFilesGitHistory(repoPath, workingTreeEnvFindings);
    findings = findings.concat(gitHistoryEnvResult.findings);
    warnings.push(...gitHistoryEnvResult.warnings);
  } catch (err) {
    warnings.push(`secrets.js: env-file scan failed: ${err.message}`);
  }

  try {
    findings = findings.concat(scanInsecureRandomTokens(repoPath));
  } catch (err) {
    warnings.push(`secrets.js: insecure-random-token scan failed: ${err.message}`);
  }

  try {
    findings = findings.concat(scanWeakPasswordHashing(repoPath));
  } catch (err) {
    warnings.push(`secrets.js: weak-password-hashing scan failed: ${err.message}`);
  }

  return { findings, warnings };
}

module.exports = {
  scan,
  scanTextForSecrets,
  SINGLE_LINE_PATTERNS,
  MULTILINE_PATTERNS,
  CHECK_HARDCODED,
  CHECK_ENV_COMMITTED,
  CHECK_INSECURE_RANDOM_TOKEN,
  CHECK_WEAK_PASSWORD_HASHING,
};
