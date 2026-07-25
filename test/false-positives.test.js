'use strict';

// Regression gate for confirmed false positives found by a round-2 false-positive audit
// (2026-07-24) that were judged fixable (as opposed to accepted, documented limitations --
// see SECURITY_SCOPE.md for the ones left open on purpose). Each fixture here is SAFE code
// that must produce ZERO findings for the checkId named; a regression that reopens any of
// these would otherwise only be caught by another manual audit, the exact failure mode
// test/regression.test.js already exists to close for evasion attempts and
// prompt-injection variants -- this file applies the same lesson to false positives.
//
// Fixtures that are NOT here (secret-santa.js/board-game-token.js/ui-animation-dedup-key.js
// under 11-insecure-random-token; rate-limit-cache-key.js and routes/auth/session-cache.js
// under 12-weak-password-hashing; routes/contact.js under 13-mass-assignment) are
// deliberate: those false positives were judged NOT cleanly fixable without either
// reopening a real evasion this scanner was hardened against, or requiring schema/semantic
// awareness this regex-based tool doesn't have. They're documented as accepted tradeoffs in
// SECURITY_SCOPE.md instead of asserted here -- asserting "zero findings" for them would
// pin in a fix that was deliberately not made.

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { scanRepo } = require('../src/scanners');

const FALSE_POSITIVES_ROOT = path.join(__dirname, 'fixtures', 'false-positives');

// scanRepo() requires a directory, not a single file, so each case is scanned at its
// containing check-subfolder level (memoized per subfolder so a shared folder with
// multiple fixtures -- e.g. 11-insecure-random-token/, which has four -- is only scanned
// once) and then filtered down to the one file/checkId pair the case cares about.
const scanCache = new Map();
async function scanSubfolder(subfolder) {
  if (!scanCache.has(subfolder)) {
    scanCache.set(subfolder, scanRepo(path.join(FALSE_POSITIVES_ROOT, subfolder)));
  }
  return scanCache.get(subfolder);
}

const FIXED_FALSE_POSITIVE_CASES = [
  [
    '11-insecure-random-token',
    'nlp-tokenizer-mock-data.js',
    'insecure-random-token',
    'tokenizerSeed -- "token" is embedded inside "tokenizer", not a real security-token name',
  ],
  [
    '14-insecure-cookie-flags',
    'author-theme-preference.js',
    'insecure-cookie-flags',
    'authorThemePreference/authorTheme -- "auth" is embedded inside "author", not a real auth cookie',
  ],
  [
    '15-open-redirect',
    'url-origin-validated-redirect.js',
    'open-redirect',
    'redirect target validated via new URL(...) + .origin comparison (a standard, robust guard)',
  ],
  [
    '15-open-redirect',
    'named-allowlist-not-recognized.js',
    'open-redirect',
    'redirect target validated via an allowlist array named "internalPaths" (not allowlist/whitelist-prefixed)',
  ],
  // --- Real-world false-positive validation fixes (2026-07-24, docs/REAL_WORLD_VALIDATION.md) ---
  [
    '23-real-world-secrets',
    'supabase-anon-key-client.js',
    'secret-hardcoded-generic',
    'Supabase publishable/anon key (JWT decodes to "role":"anon") -- safe by design, RLS enforces access server-side',
  ],
  [
    '23-real-world-secrets',
    'supabase-anon-key.env',
    'secret-hardcoded-generic',
    'Supabase anon key in unquoted dotenv-shape KEY=value form -- same "role":"anon" JWT as above',
  ],
  [
    '23-real-world-secrets',
    'env-var-reference.js',
    'secret-hardcoded-generic',
    'variable/property name contains "key"/"secret"/"token" but the RHS is an env-var reference (import.meta.env.X / process.env.X), not a literal value',
  ],
  // --- Real-world false-positive validation: eval-on-input / RegExp#exec (2026-07-24,
  // docs/REAL_WORLD_VALIDATION.md §5.4, §6) ---
  // All 7 real-world eval-on-input false positives were RegExp.prototype.exec() calls --
  // a filename-number extractor, an allowlist validator, a pattern-scan over text --
  // mistaken for child_process.exec()/execSync() purely because both share the literal
  // substring "exec". A prior fix guarded on "does this FILE mention child_process
  // anywhere", which still let an unrelated .exec() through in any file that also
  // legitimately imports child_process for something else -- exactly the shape
  // filename-number-extractor.js reconstructs. checkEvalOnInput() now traces each
  // exec/execSync call site back to its own receiver (bare destructured import, or a
  // variable/`require('child_process')` traced back to the child_process module) instead
  // of scanning the whole file for the substring.
  [
    '5-eval-on-input',
    'filename-number-extractor.js',
    'eval-on-input',
    'RegExp.prototype.exec() extracting a leading number from a filename, in a file that also legitimately imports child_process for an unrelated purpose',
  ],
  [
    '5-eval-on-input',
    'allowlist-validator.js',
    'eval-on-input',
    'RegExp.prototype.exec() validating a plugin name against an allowlist pattern',
  ],
  // --- Round-2 real-world false-positive re-validation fixes (2026-07-24,
  // docs/REAL_WORLD_VALIDATION.md "Re-validation (post-fix)" section) -- four NEW
  // false-positive shapes surfaced on a fresh re-clone/re-scan of the same 20 repos after
  // the first round of fixes above, all in secret-hardcoded-generic's generic-entropy/
  // name-based heuristic path. See src/scanners/secrets.js's inline comments (search
  // "Real-world FP fix (2026-07-24, docs/REAL_WORLD_VALIDATION.md re-validation") for the
  // full reasoning behind each fix.
  [
    '25-real-world-secrets-round2',
    'supabase-generated-types-fkey.ts',
    'secret-hardcoded-generic',
    'Bug A: auto-generated Supabase types.ts foreignKeyName constraint-name field (react-gantt-lovable-starter)',
  ],
  [
    '25-real-world-secrets-round2',
    'auto-generated-orm-constraint-name.ts',
    'secret-hardcoded-generic',
    'Bug A secondary signal: auto-generated-file header + a snake_case DB-identifier-shaped value on a non-"*KeyName" field',
  ],
  [
    '25-real-world-secrets-round2',
    'config-array-bare-key.js',
    'secret-hardcoded-generic',
    'Bug B: bare, standalone `key` property name in a plain config array (career-ops)',
  ],
  [
    '25-real-world-secrets-round2',
    'env-example-non-english.md',
    'secret-hardcoded-generic',
    'Bug C: non-English (Portuguese) placeholder value inside a README fenced code block (doutor-tabajara)',
  ],
  [
    '25-real-world-secrets-round2',
    'flask-self-attribute-references.py',
    'secret-hardcoded-generic',
    'Bug D: self.access_key/self.secret_key dotted attribute references passed as kwargs (Vibelens, Python/Flask)',
  ],
];

for (const [subfolder, filename, checkId, description] of FIXED_FALSE_POSITIVE_CASES) {
  test(`false-positives/${subfolder}/${filename}: ${checkId} does NOT fire (${description})`, async () => {
    const findings = await scanSubfolder(subfolder);
    const hits = findings.filter((f) => f.checkId === checkId && f.file.includes(filename));
    assert.equal(
      hits.length,
      0,
      `expected zero ${checkId} findings on ${subfolder}/${filename} (${description}) -- a false-positive fix may have regressed. ` +
        `Found: ${JSON.stringify(hits.map((h) => ({ file: h.file, line: h.line, snippet: h.snippet })))}`
    );
  });
}

// --- Positive controls: overcorrection guards for the real-world secrets fixes --------
// The two false-positive fixes above (Supabase anon-key JWT recognition, env-var-reference
// rejection) must not swallow genuinely dangerous findings. These assert the opposite of
// the cases above: secret-hardcoded-generic MUST still fire on (1) a real Supabase
// service_role key (bypasses RLS -- a real leaked credential, distinguished from the safe
// anon key purely by its JWT "role" claim) and (2) an ordinary hardcoded literal secret
// with no JWT/env-var-reference shape at all.
const POSITIVE_CONTROL_CASES = [
  [
    '23-real-world-secrets',
    '_control-service-role-key-still-fires.js',
    'secret-hardcoded-generic',
    'a service_role JWT (role !== anon) must still be flagged at full severity',
  ],
  [
    '23-real-world-secrets',
    '_control-literal-secret-still-fires.js',
    'secret-hardcoded-generic',
    'an ordinary hardcoded high-entropy literal (not a JWT, not an env-var reference) must still be flagged',
  ],
  // Round-4 adversarial fix (2026-07-24): CODE_REFERENCE_VALUE_RE used to match ANY
  // dot-separated identifier-charset value, not just an actual known-safe env-access root
  // -- so a real unquoted-dotenv-style secret containing literal dots (and no other
  // non-identifier characters) was silently dropped. looksLikeCodeReference now also
  // requires the value to start with a known-safe root (process.env./import.meta.env./
  // Deno.env./Bun.env.) before the shape check even applies.
  [
    '23-real-world-secrets',
    '_control-dotted-literal-secret-still-fires.env',
    'secret-hardcoded-generic',
    'an unquoted dotenv-shape high-entropy secret whose value happens to contain literal dots (not an env-var reference) must still be flagged',
  ],
  // The eval-on-input receiver-tracing fix (above) must not overcorrect into silence: real
  // child_process.exec()/execSync() calls with interpolated input, and eval()/new Function()
  // on tainted input (which never go through the receiver-tracing logic at all), must all
  // still fire exactly as before.
  [
    '5-eval-on-input',
    'child-process-exec-real.js',
    'eval-on-input',
    'real child_process.exec()/execSync() calls (bare destructured, and via a require(\'child_process\')-traced variable) with interpolated request input must still be flagged',
  ],
  [
    '5-eval-on-input',
    'eval-and-function-tainted.js',
    'eval-on-input',
    'eval()/new Function() on tainted request input must still be flagged',
  ],
  // Round-4 adversarial fix (2026-07-24): isChildProcessModuleVar only traced a receiver
  // assigned DIRECTLY from require('child_process')/an import, not one obtained through one
  // hop of same-file indirection (a wrapper function that itself returns
  // require('child_process')) -- a real regression versus the coarser pre-fix "file mentions
  // child_process" guard, which used to catch this shape.
  [
    '5-eval-on-input',
    'indirect-cp-wrapper.js',
    'eval-on-input',
    'child_process.exec() reached via a same-file helper function (const cp = getChildProcessModule()) with interpolated request input must still be flagged',
  ],
  // --- Round-2 real-world false-positive re-validation: overcorrection guards -----------
  // Each of the four round-2 fixes above (Bugs A-D) only ever narrows an EXISTING
  // suppression path further -- these confirm none of them accidentally swallow a genuine
  // secret in the process.
  [
    '25-real-world-secrets-round2',
    '_control-real-secret-in-generated-file-still-fires.ts',
    'secret-hardcoded-generic',
    'Bug A: a real high-entropy secret (not a snake_case DB identifier) inside an auto-generated-labeled file must still be flagged',
  ],
  [
    '25-real-world-secrets-round2',
    '_control-bare-key-real-secret-still-fires.js',
    'secret-hardcoded-generic',
    'Bug B: a bare `key` property name with a genuinely high-entropy, digit-bearing value must still be flagged',
  ],
  [
    '25-real-world-secrets-round2',
    '_control-secret-in-readme-fence-still-fires.md',
    'secret-hardcoded-generic',
    'Bug C: a real-looking secret pasted into a README fenced code block must still be flagged (the placeholder suppression is shape-scoped, not fence-scoped)',
  ],
  [
    '25-real-world-secrets-round2',
    '_control-non-english-placeholder-outside-doc-scope-still-fires.js',
    'secret-hardcoded-generic',
    'Bug C: the same word-shaped placeholder value must still fire OUTSIDE a Markdown doc-fence context (an ordinary .js source file)',
  ],
  [
    '25-real-world-secrets-round2',
    '_control-dotted-jwt-secret-still-fires.env',
    'secret-hardcoded-generic',
    'Bug D: THE historical regression-guard case -- a genuine high-entropy secret containing literal dots (JWT/base64-shaped, digit-dense per-segment) must still be flagged, not misread as a self./this.-style code reference',
  ],
  [
    '25-real-world-secrets-round2',
    '_control-trailing-comma-dotted-secret-still-fires.py',
    'secret-hardcoded-generic',
    'Bug D: a real dotted high-entropy secret written in the same trailing-comma kwarg-line shape as the self.access_key fix must still be flagged',
  ],
  // --- Round-6 adversarial fix (2026-07-25, independent re-verification of the round-5
  // fixes) -- two REAL regressions found and closed. See src/scanners/secrets.js's inline
  // comments (search "Round-6 adversarial fix") for the full reasoning behind each.
  [
    '25-real-world-secrets-round2',
    '_control-random-dotted-secret-still-fires.env',
    'secret-hardcoded-generic',
    'Bug D regression: ordinary random base62 dot-chain secrets (not maximally digit-dense/case-chaotic) that happened to pass the old per-segment digit-density/case-transition-only shape check must still be flagged',
  ],
  [
    '25-real-world-secrets-round2',
    '_control-keyname-suffix-real-secret-still-fires.ts',
    'secret-hardcoded-generic',
    'Bug A regression: a real secret assigned to a *KeyName-suffixed variable in ordinary, hand-written (non-auto-generated) source must still be flagged -- the name-suffix signal alone was never sufficient without a value-shape check',
  ],
];

for (const [subfolder, filename, checkId, description] of POSITIVE_CONTROL_CASES) {
  test(`false-positives/${subfolder}/${filename}: ${checkId} STILL fires (${description})`, async () => {
    const findings = await scanSubfolder(subfolder);
    const hits = findings.filter((f) => f.checkId === checkId && f.file.includes(filename));
    assert.ok(
      hits.length > 0,
      `expected at least one ${checkId} finding on ${subfolder}/${filename} (${description}) -- ` +
        'a false-positive fix may have overcorrected and suppressed a real secret.'
    );
  });
}

// --- Round 3 (2026-07-24) false positives ---------------------------------------------
// These live under evasion-attempts/{19,20,22}-round3-* alongside their evasion siblings
// (each round-3 tester kept its false-positive controls in the same folder as its evasion
// fixtures), so unlike the cases above they aren't under false-positives/. Scanned once per
// folder and filtered down to the one file/checkId that must stay clean.
const { scanRepo: scanRepoR3 } = require('../src/scanners');
const EVASION_ROOT = path.join(__dirname, 'fixtures', 'evasion-attempts');
const r3Cache = new Map();
async function scanR3(folder) {
  if (!r3Cache.has(folder)) r3Cache.set(folder, scanRepoR3(path.join(EVASION_ROOT, folder), { skip: ['git-history'] }));
  return r3Cache.get(folder);
}

const ROUND3_FALSE_POSITIVE_CASES = [
  ['19-round3-secrets', '06-placeholder-suffix-false-positive.env.example', 'secret-hardcoded-generic', 'your-*-here / replace-with-* / set-your-* placeholder env values that keep a descriptive suffix after the key/secret/token/password word'],
  ['19-round3-secrets', 'env-template-false-positives/.env-example', 'secret-env-committed', 'a hyphen-separated env template filename (.env-example)'],
  ['19-round3-secrets', 'env-template-false-positives/.env.local.example', 'secret-env-committed', 'a compound env template filename (.env.local.example)'],
  ['19-round3-secrets', 'env-template-false-positives/.env.production.template', 'secret-env-committed', 'a compound env template filename (.env.production.template)'],
  ['20-round3-injection', 'check4-fp-parameterized-destructured', 'sql-string-concatenation', 'a parameterized query with destructured req.body params'],
  ['20-round3-injection', 'check5-fp-async-arrow-dispatch', 'eval-on-input', 'an eval-free async-arrow lookup-table dispatch'],
  ['20-round3-injection', 'check6-fp-static-config-method', 'cors-wildcard-with-credentials', 'a safe origin via a static config method returning a real domain'],
  ['22-round3-fresh-look-11-15', '14-shorthand-and-spread.js', 'insecure-cookie-flags', 'ES6 shorthand { httpOnly, secure } and spread of a shared secure-defaults object'],
];

for (const [folder, filename, checkId, description] of ROUND3_FALSE_POSITIVE_CASES) {
  test(`evasion-attempts/${folder}/${filename}: ${checkId} does NOT fire (${description})`, async () => {
    const findings = await scanR3(folder);
    const hits = findings.filter((f) => f.checkId === checkId && f.file.includes(filename));
    assert.equal(
      hits.length,
      0,
      `expected zero ${checkId} findings on ${folder}/${filename} (${description}) -- a round-3 false-positive fix may have regressed. ` +
        `Found: ${JSON.stringify(hits.map((h) => ({ file: h.file, line: h.line, snippet: h.snippet })))}`
    );
  });
}
