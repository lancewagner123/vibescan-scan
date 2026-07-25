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
