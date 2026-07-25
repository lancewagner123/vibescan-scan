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
  lookupFunctionReturnExpr,
  resolveConcatExpression,
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

// --- Supabase anon/publishable-key JWT recognition (real-world FP fix, 2026-07-24) -----
//
// The real-world false-positive validation exercise (docs/REAL_WORLD_VALIDATION.md, §5.1)
// found this was the single largest source of false positives (~14 of 45): across
// multiple independently-sourced Lovable/Bolt/Supabase-stack repos,
// secret-hardcoded-generic/secret-git-history flagged the Supabase client's
// publishable/anon key -- either because it's JWT-shaped (matches SINGLE_LINE_PATTERNS'
// jwt-shaped-token) or because its variable name contains "key"
// (SUPABASE_PUBLISHABLE_KEY / SUPABASE_ANON_KEY, matching the generic name-based
// heuristic below). Supabase's own documented architecture *designs* this key to ship in
// client bundles -- access control is enforced server-side by Row Level Security policies,
// not by keeping the string secret -- so flagging it as a leaked credential is simply
// wrong, not just noisy.
//
// The fix: when a candidate secret value is JWT-shaped, decode the middle (payload)
// segment and check its `role` claim. `"role":"anon"`/`"anonymous"` is the public,
// by-design key -- suppress it. `"role":"service_role"` (or any other/missing role) is
// NOT suppressed -- a service_role key genuinely bypasses RLS and is a real leaked
// credential, so it must keep firing at full severity. Decode failures (malformed
// base64, non-JSON payload, no `role` claim) also fall through to normal flagging --
// this only ever *suppresses* a finding on a confirmed-safe decode, never on a guess.
const JWT_SHAPE_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function decodeJwtPayloadRole(value) {
  if (typeof value !== 'string' || !JWT_SHAPE_RE.test(value)) return null;
  const payloadSegment = value.split('.')[1];
  try {
    const normalized = payloadSegment.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
    const decoded = Buffer.from(padded, 'base64').toString('utf8');
    const payload = JSON.parse(decoded);
    if (payload && typeof payload.role === 'string') return payload.role;
    return null;
  } catch {
    return null; // malformed base64/JSON -- can't confirm anything, fall through to flagging
  }
}

function isSupabaseAnonRoleJwt(value) {
  const role = decodeJwtPayloadRole(value);
  return role === 'anon' || role === 'anonymous';
}

// --- Generic high-entropy key/secret/token/password literal heuristic ----------------

// Matches `<name containing key/secret/token/password>: "<long literal>"` style
// assignments/object properties in any language-ish source (JS/TS/JSON/YAML/etc.).
// The separator is either a bare `:`/`=` (object property or plain assignment) OR a
// TypeScript-annotated assignment `: <Type> =` -- the round-3 secrets audit found that a
// generic secret written with an idiomatic TS type annotation
// (`const apiSecret: string = '...'`, incl. `static apiSecret: string = '...'`) slipped
// past entirely: the bare `[:=]` bound to the *annotation* colon, then demanded a quote and
// saw the type name (`string`) instead, so it never reached the real `=`. The added
// alternative lets the type annotation sit between the name-colon and the value `=`. Scoped
// to the generic-entropy path only; vendor-format regexes (SINGLE_LINE_PATTERNS) already
// match a known-prefix literal anywhere on the line regardless of annotation.
const GENERIC_ENTROPY_RE = /([\w.$]*(?:key|secret|token|password|passwd|pwd)[\w]*)\s*(?:[:=]|:\s*[A-Za-z_$][\w$.<>[\]| ]*=)\s*["'`]([A-Za-z0-9+/_=-]{20,})["'`]/gi;
const ENTROPY_THRESHOLD = 3.0; // bits/char — placeholders/words fall well below this

// --- Real-world FP fix (2026-07-24, docs/REAL_WORLD_VALIDATION.md re-validation §1) ------
//
// Bug A: react-gantt-lovable-starter. Auto-generated Supabase/Postgres `types.ts` files
// (and equivalent Prisma/Drizzle/TypeORM codegen output) commonly emit foreign-key
// CONSTRAINT NAMES as string properties: `foreignKeyName: "tasks_project_id_fkey"`. The
// property name contains "Key" (matches the keyword vocabulary above) and the value is
// long/underscore-heavy enough to clear the entropy gate below -- so this reads exactly
// like a high-entropy secret even though it's neither secret nor random: it's a
// deterministic, predictable, database-generated identifier (`<table>_<column>_fkey`), and
// its value grants no capability if known.
//
// Excluding the literal substring "fkey" was considered and rejected: too narrow (any
// constraint-naming convention that doesn't literally end in "_fkey" -- a different ORM, a
// custom naming strategy -- would still slip through) and does nothing for the equally
// common primaryKeyName/indexKeyName/uniqueKeyName siblings. The real distinguishing signal
// is in the PROPERTY NAME's own shape, not the value's: any identifier ending in
// "KeyName"/"ConstraintName"/"IndexName" describes the NAME of a database key/constraint/
// index, not a secret key's VALUE -- a real secret is never itself "the name of a key," so
// this is a structural signal that generalizes across ORMs/codegens rather than a hardcoded
// list of the specific identifiers one repo happened to use.
const KEY_NAME_DESCRIPTOR_SUFFIXES = ['keyname', 'constraintname', 'indexname'];

// Round-6 adversarial fix (2026-07-25, independent re-verification of the round-5 fixes):
// this used to suppress on the NAME suffix alone, with no check on the VALUE at all -- so
// `const secretKeyName = "<any real secret>"` in perfectly ordinary, hand-written source
// (src/config.ts, no auto-generated marker in sight) went completely invisible, regardless
// of how obviously high-entropy the value was. The name-suffix signal alone was never
// actually sufficient: "ends in KeyName" tells you the property is describing the NAME of
// some key/constraint/index, but says nothing about whether the code that assigned it
// actually put a real DB-identifier-shaped name there versus a secret that merely got
// mis-named. The value still has to look like what a `foreignKeyName`/`constraintName`/
// `indexName` field actually holds: a snake_case DB identifier (letters/digits/underscores
// only, at least one underscore -- looksLikeGeneratedDbIdentifier, the same value-shape
// check already used as the secondary auto-generated-file signal below). A real secret
// assigned to a `*KeyName` variable virtually never happens to also be underscore-separated
// snake_case with no base64 `+/=` punctuation, so this only ever narrows the existing
// suppression, it doesn't newly misclassify anything the old (name-only) version wasn't
// already misclassifying.
function isKnownSafeKeyDescriptorName(name, value) {
  if (typeof name !== 'string') return false;
  const folded = name.replace(/[^A-Za-z0-9]/g, '').toLowerCase();
  if (!KEY_NAME_DESCRIPTOR_SUFFIXES.some((suffix) => folded.endsWith(suffix))) return false;
  return looksLikeGeneratedDbIdentifier(value);
}

// Secondary, lower-confidence signal for the same underlying pattern: a file whose own
// header explicitly says it's generated (Supabase/Prisma/Drizzle/TypeORM/protoc/OpenAPI
// codegen all emit some variant of this convention) is far less likely to contain a
// hand-pasted literal secret than hand-written source -- generated output is deterministic
// scaffolding, not where a developer pastes a credential. Deliberately combined with a
// VALUE-SHAPE check (looks like a snake_case database identifier: letters/digits/
// underscores only, at least one underscore, no base64 `+/=` punctuation) rather than
// suppressing every candidate in a generated file regardless of shape -- that would repeat
// the "too broad" mistake this file's own history already made once (see the
// looksLikeCodeReference comment above): a genuine secret accidentally checked into a
// generated file must still fire.
const AUTO_GENERATED_HEADER_RE = /(?:this file is (?:automatically )?generated|automatically generated|do not edit|@generated|code generated by)/i;
const AUTO_GENERATED_HEADER_SCAN_CHARS = 1000; // header comments live at the top of the file
const DB_IDENTIFIER_SHAPE_RE = /^[A-Za-z0-9]+(?:_[A-Za-z0-9]+)+$/;

function looksLikeAutoGeneratedFile(text) {
  return AUTO_GENERATED_HEADER_RE.test(text.slice(0, AUTO_GENERATED_HEADER_SCAN_CHARS));
}

function looksLikeGeneratedDbIdentifier(value) {
  return DB_IDENTIFIER_SHAPE_RE.test(value);
}

// --- Real-world FP fix (2026-07-24, docs/REAL_WORLD_VALIDATION.md re-validation §1) ------
//
// Bug B: career-ops. `{ key: 'respondedToInterview', ... }` -- a bare, standalone `key`
// property name (a dictionary/lookup-array key, the same idiom as a React list `key` prop),
// completely unrelated to API keys/secrets. Unlike "secret"/"token"/"password"/"apikey",
// the bare English word "key" is extremely ambiguous in ordinary code. The value itself
// ('respondedToInterview', a camelCase English phrase) turns out to clear the general
// ENTROPY_THRESHOLD (its per-character Shannon entropy is ~3.5 bits/char -- mixed-case
// English phrases are diverse enough at 20+ characters to score deceptively high on a
// pure character-frequency measure, even though they're not remotely random). So the
// entropy gate genuinely was being applied here -- it just isn't a strong enough signal on
// its own for a name this ambiguous.
//
// Fix: a BARE `key` name (no other qualifying word attached -- NOT `apiKey`/`api_key`/
// `secretKey`/`accessKey`, all of which keep the general, lower bar) requires a stronger
// secondary signal: genuinely high entropy (a stricter threshold than the general case)
// AND at least one digit. Real API keys/tokens are drawn from a wide alphanumeric-or-wider
// alphabet and essentially always contain a digit somewhere across 20+ characters; an
// ordinary English camelCase phrase essentially never does.
const BARE_KEY_MIN_ENTROPY = 4.0;
const BARE_KEY_DIGIT_RE = /[0-9]/;

function isBareKeyName(name) {
  if (typeof name !== 'string') return false;
  const lastSegment = name.split(/[.[\]'"]+/).filter(Boolean).pop();
  return /^key$/i.test(lastSegment || '');
}

function passesEntropyGate(name, value) {
  if (isBareKeyName(name)) {
    return BARE_KEY_DIGIT_RE.test(value) && shannonEntropy(value) >= BARE_KEY_MIN_ENTROPY;
  }
  return shannonEntropy(value) >= ENTROPY_THRESHOLD;
}

// Real-world FP fix (2026-07-24, docs/REAL_WORLD_VALIDATION.md §5.2): several
// secret-hardcoded-generic hits on real code were lines like
// `const KEY = import.meta.env.VITE_SUPABASE_KEY` or `PINECONE_KEY = process.env.PINECONE_KEY`
// -- the heuristic matched a variable/property *name* containing "key"/"secret"/"token",
// but the RHS is a reference to an environment variable (a plain dotted identifier/
// property-access chain, e.g. `process.env.X`, `import.meta.env.X`, `config.apiKey`), not
// an actual literal value. Referencing an env var by name is the SAFE pattern (the real
// secret lives in the environment, never in source) -- there is nothing hardcoded on that
// line at all, so it must not fire. A real hardcoded secret/token virtually never
// round-trips as a bare, all-word-characters, dot-separated identifier chain like this
// (it's typically base64/hex/JWT-shaped with characters this pattern excludes), so
// rejecting this shape is safe: it only ever suppresses a code reference, not a genuine
// high-entropy literal.
// Round-4 adversarial fix (2026-07-24): the original CODE_REFERENCE_VALUE_RE matched ANY
// dot-separated, identifier-charset value -- shape alone, with no requirement that it
// actually be a known-safe reference idiom. That's too broad: a real high-entropy secret
// assigned via the UNQUOTED dotenv-style path (GENERIC_ENTROPY_UNQUOTED_RE) can legitimately
// contain a literal `.` and nothing else outside `[A-Za-z0-9_$]`, e.g.
//   DB_ADMIN_SECRET=xK2mQ9pL4vR8tY1wZ3aB5cD7eF.gH0iJ6kL2mN4oP8qR1sT3uV5wX7yZ9a.bC1dE3fG5hI7jK9lM1nO3pQ5rS7tU9vW
// -- three base64-ish segments joined by dots, indistinguishable by shape alone from a real
// property-access chain. That case was silently dropped with no fallback detection: a real
// regression, not a hardening. Fixed (at the time) by anchoring the suppression to a small
// set of hardcoded known-safe env-var-access ROOTS (process.env.*, import.meta.env.*, the
// Deno/Bun equivalents) instead of accepting any dot-separated identifier shape.
//
// Round-5 real-world FP fix (2026-07-24, docs/REAL_WORLD_VALIDATION.md re-validation §1,
// Vibelens): the four-root allowlist was itself too narrow. `self.access_key`/
// `self.secret_key` (Python's idiom for "read my own instance attribute" -- the exact same
// *conceptual* shape as `process.env.X`, a reference rather than a literal) doesn't start
// with any of the four roots, so it slipped through untouched. Extending the root list
// (`self.`, `this.`, ...) would just be the same ad hoc, gameable, never-quite-complete
// approach one level further down -- the next framework's own accessor convention
// (`config.`, `settings.`, any arbitrary class instance name) would still evade it.
//
// The actual distinguishing signal was never the ROOT -- it's what each dot-separated
// SEGMENT individually looks like. A genuine code reference is a chain of short, ordinary
// identifier words (`self`, `access_key`, `process`, `env`, `VITE_SUPABASE_KEY`) -- the
// same vocabulary a programmer types for a variable/attribute/env-var name: low digit
// density, and case that changes rarely (camelCase/PascalCase word boundaries, or a single
// consistent case for ALL_CAPS_SNAKE / all_lower_snake -- never a chaotic per-character
// mix). A genuine high-entropy secret's dot-separated segments, by contrast, are themselves
// high-entropy blobs -- "xK2mQ9pL4vR8tY1wZ3aB5cD7eF" is digit-dense (8 of 26 characters) and
// case-flips almost every character, because the dots in that value are incidental to how a
// random secret happened to be typed, not real property-access syntax. Checking each
// segment individually (rather than the value as a whole, and rather than a fixed list of
// acceptable roots) generalizes to `self.`/`this.`/`config.`/any receiver name without
// needing to enumerate them, while still rejecting the exact regression case this file's
// history already hit once: see isLowEntropyIdentifierSegment below, and the positive
// control fixture `_control-dotted-literal-secret-still-fires.env`, which this design was
// verified against directly (each of its three segments is digit-dense enough to fail the
// segment check, so the value is correctly NOT treated as a reference).
const CODE_REFERENCE_VALUE_RE = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/;

// Real identifiers are short; a single dot-separated segment longer than this reads as an
// encoded blob, not a word a person typed as a variable/attribute/env-var name.
const MAX_IDENTIFIER_SEGMENT_LENGTH = 32;
// A real 20+ char random secret drawn from a base62-ish alphabet contains a digit roughly
// 1 character in 6 on average; an ordinary identifier occasionally has a digit
// (`oauth2Token`, `sha256Hash`) but nowhere near that density.
const MAX_IDENTIFIER_DIGIT_DENSITY = 0.15;
// A real identifier's case only changes at deliberate word boundaries (camelCase/
// PascalCase), so the number of upper/lower transitions is bounded by the number of
// "words" in the name -- realistically never more than a handful. A truly random secret's
// case is effectively an independent coin flip per character, so a run of 20+ characters
// with 3 or fewer case transitions is vanishingly unlikely by chance.
const MAX_IDENTIFIER_CASE_TRANSITIONS = 3;

function digitDensity(segment) {
  const digitCount = (segment.match(/[0-9]/g) || []).length;
  return digitCount / segment.length;
}

function countCaseTransitions(segment) {
  let transitions = 0;
  for (let i = 1; i < segment.length; i++) {
    const prev = segment[i - 1];
    const curr = segment[i];
    if (!/[A-Za-z]/.test(prev) || !/[A-Za-z]/.test(curr)) continue; // only letter-to-letter transitions count
    if (/[A-Z]/.test(prev) !== /[A-Z]/.test(curr)) transitions++;
  }
  return transitions;
}

function isLowEntropyIdentifierSegment(segment) {
  if (!segment || segment.length > MAX_IDENTIFIER_SEGMENT_LENGTH) return false;
  if (digitDensity(segment) > MAX_IDENTIFIER_DIGIT_DENSITY) return false;
  if (countCaseTransitions(segment) > MAX_IDENTIFIER_CASE_TRANSITIONS) return false;
  return true;
}

// --- Round-6 adversarial fix (2026-07-25, independent re-verification of the round-5 fixes):
// Bug D regression. isLowEntropyIdentifierSegment's digit-density/case-transition shape test
// is a real signal but not a rare enough one on its own: a Monte Carlo over 200,000 realistic
// random base62 dot-chain secrets (the exact shape this file's own history keeps hitting --
// SendGrid-style `SG.<part>.<part>`, HMAC `id.sig` tokens) found ~1.06% pass BOTH the digit-
// density and case-transition gates purely by chance -- e.g. `vgbMLqt7Kyi.GopxURSG1`,
// `A9OWETPC.RFpwTs5TTXEI`. That's a baseline false-negative rate for a mainstream secret
// shape, not a crafted adversarial edge case -- confirmed against the actual exported
// `scanTextForSecrets` pipeline, not a standalone unit.
//
// Narrowing back toward a fixed set of known-safe roots (process./self./this./config./...)
// was considered and rejected -- that's the exact approach this file's history already
// outgrew twice (the four-hardcoded-root version, then the root-list-extension idea for
// self./this.) and would just reintroduce the next framework's own accessor convention as a
// gap. The actual missing signal is WORD SHAPE: a real identifier segment isn't just "low
// digit density, few case transitions" -- when split at its own underscore/camelCase word
// boundaries (the same boundaries a person actually typed), each resulting "word" reads as
// pronounceable English-identifier text (a vowel present, no implausible run of consonants),
// and a real segment decomposes into only a handful of such words. A random base62 blob has
// no real word boundaries to speak of -- splitWords() only ever finds boundaries in it by
// accident (an incidental case flip), so either it comes out as one long ungrammatical "word"
// that fails the vowel/consonant check, or it fragments into many tiny pieces, which the word-
// count cap below rejects. Verified by Monte Carlo (same 200,000-sample methodology) to cut
// the false-negative rate roughly 5x (~1.06% -> ~0.2%) for two-segment dot-chains, while every
// known real-world code-reference shape (self.access_key, process.env.VITE_SUPABASE_KEY,
// import.meta.env.PINECONE_KEY, this.config.apiKey, options.secretToken,
// app.state.auth.secretToken, settings.database.password, env.SECRET_KEY, and short
// abbreviations like cfg/ctx/fs/db/id/api/key) keeps passing -- see the regression fixtures
// added alongside this fix. The residual ~0.2% is a documented, accepted tradeoff (same
// posture as Bug B's bare-`key`-needs-a-digit rule): tightening further to zero, in testing,
// only did so by also rejecting real identifiers (`config`, `settings`, `password`,
// `oauth2Token` all broke under stricter variants tried).
//
// Word boundaries: split on '_' first, then on a lowercase-or-digit-to-uppercase transition
// (camelCase: "accessKey" -> "access","Key") and on an uppercase-run-to-uppercase+lowercase
// transition (acronym boundary: "HTTPServer" -> "HTTP","Server").
function splitIdentifierWords(segment) {
  const words = [];
  for (const part of segment.split('_')) {
    if (!part) continue;
    const marked = part
      .replace(/([a-z0-9])([A-Z])/g, '$1\x00$2')
      .replace(/([A-Z]+)([A-Z][a-z])/g, '$1\x00$2');
    for (const word of marked.split('\x00')) {
      if (word) words.push(word);
    }
  }
  return words;
}

// Short abbreviations (cfg, ctx, fs, db, id, api, key, env, ...) are common, legitimate, and
// too short for vowel/consonant shape to mean anything -- exempt from the word-shape check.
const IDENTIFIER_WORD_SHORT_EXEMPT_LENGTH = 3;
const IDENTIFIER_WORD_MAX_LENGTH = 15;
// A real word's vowel ratio sits in a moderate band -- English/identifier words are never
// vowel-free past a few letters, nor mostly vowels. The known real-world identifier corpus
// this was tuned against (access, process, config, settings, database, password, secret,
// token, auth, state, options, oauth2, VITE, SUPABASE) ranges 0.20-0.50; the band below keeps
// clear margin on both sides while still rejecting most random draws.
const IDENTIFIER_WORD_MIN_VOWEL_RATIO = 0.20;
const IDENTIFIER_WORD_MAX_VOWEL_RATIO = 0.60;
// "settings" (ttl) and "password" (ssw) are real 3-consonant runs -- can't tighten below 3
// without rejecting real identifiers.
const IDENTIFIER_WORD_MAX_CONSONANT_RUN = 3;
// Real multi-word identifiers realistically top out around 3 words
// (VITE_SUPABASE_KEY -> VITE/SUPABASE/KEY); a segment that fragments into more than that is
// far more likely to be a random blob that happened to case-flip a few times than something a
// person actually typed as a name.
const IDENTIFIER_MAX_WORD_COUNT = 3;

function countMaxConsonantRun(word) {
  let max = 0;
  let run = 0;
  for (const ch of word) {
    if (/[A-Za-z]/.test(ch) && !/[aeiouAEIOU]/.test(ch)) {
      run++;
      max = Math.max(max, run);
    } else {
      run = 0;
    }
  }
  return max;
}

function countVowels(word) {
  return (word.match(/[aeiouAEIOU]/g) || []).length;
}

function isPronounceableIdentifierWord(word) {
  if (word.length <= IDENTIFIER_WORD_SHORT_EXEMPT_LENGTH) return true;
  if (word.length > IDENTIFIER_WORD_MAX_LENGTH) return false;
  const vowelRatio = countVowels(word) / word.length;
  if (vowelRatio < IDENTIFIER_WORD_MIN_VOWEL_RATIO || vowelRatio > IDENTIFIER_WORD_MAX_VOWEL_RATIO) return false;
  if (countMaxConsonantRun(word) > IDENTIFIER_WORD_MAX_CONSONANT_RUN) return false;
  return true;
}

// Combines with isLowEntropyIdentifierSegment (AND, not instead-of) in looksLikeCodeReference
// below -- this only ever narrows an existing suppression further, so it can't newly
// misclassify a real secret that the digit-density/case-transition check wasn't already
// letting through.
function hasIdentifierWordShape(segment) {
  const words = splitIdentifierWords(segment);
  if (words.length === 0 || words.length > IDENTIFIER_MAX_WORD_COUNT) return false;
  return words.every(isPronounceableIdentifierWord);
}

// GENERIC_ENTROPY_UNQUOTED_RE's value char class doesn't exclude a comma (a real dotenv
// value could theoretically contain one), so a reference sitting inside a multi-line
// function call -- the actual real-world Bug D shape, a Python kwarg written one per line
// (`aws_access_key_id=self.access_key,`) -- gets captured WITH its trailing comma still
// attached. Stripped only for the purposes of THIS shape/entropy check, never from what
// gets reported: this can only ever make a reference-shaped value get recognized as one
// (suppression), it can't newly misclassify a real secret, since a genuine high-entropy
// literal ending in a bare trailing comma is not a realistic shape to begin with.
function looksLikeCodeReference(value) {
  const candidate = value.replace(/[,;]+$/, '');
  if (!CODE_REFERENCE_VALUE_RE.test(candidate)) return false;
  const segments = candidate.split('.');
  if (segments.length < 2) return false; // need an actual dot chain to read as "a reference" at all
  return segments.every((segment) => isLowEntropyIdentifierSegment(segment) && hasIdentifierWordShape(segment));
}

function scanLineGenericEntropy(line, isAutoGenerated) {
  const hits = [];
  GENERIC_ENTROPY_RE.lastIndex = 0;
  let m;
  while ((m = GENERIC_ENTROPY_RE.exec(line)) !== null) {
    const name = m[1];
    const value = m[2];
    if (isKnownSafeKeyDescriptorName(name, value)) continue;
    if (isAutoGenerated && looksLikeGeneratedDbIdentifier(value)) continue;
    if (looksLikePlaceholder(value)) continue;
    if (looksLikeCodeReference(value)) continue;
    if (!passesEntropyGate(name, value)) continue;
    if (isSupabaseAnonRoleJwt(value)) continue;
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
const GENERIC_ENTROPY_UNQUOTED_RE = /^[ \t]*([\w.$]*(?:key|secret|token|password|passwd|pwd)[\w]*)\s*=\s*([^\s#'"`;(){}[\]]{16,})[ \t]*$/gi;

function scanLineGenericEntropyUnquoted(line, isAutoGenerated) {
  const hits = [];
  GENERIC_ENTROPY_UNQUOTED_RE.lastIndex = 0;
  let m;
  while ((m = GENERIC_ENTROPY_UNQUOTED_RE.exec(line)) !== null) {
    const name = m[1];
    const value = m[2];
    if (isKnownSafeKeyDescriptorName(name, value)) continue;
    if (isAutoGenerated && looksLikeGeneratedDbIdentifier(value)) continue;
    if (looksLikePlaceholder(value)) continue;
    if (looksLikeCodeReference(value)) continue;
    if (!passesEntropyGate(name, value)) continue;
    if (isSupabaseAnonRoleJwt(value)) continue;
    hits.push({ value, matchedText: m[0] });
  }
  return hits;
}

// --- Bracket-notation / computed-key generic secret (round-3 secrets audit, gap #2) ----
//
// GENERIC_ENTROPY_RE's name portion is `[\w.$]*` -- it excludes `[`, `]`, `'`, `"`, so a
// secret assigned to a bracket-notation/computed property (`config['apiSecret'] = '...'`,
// including a concatenated key `store['api' + 'Token'] = '...'`) is invisible to it even
// though it assigns the identical high-entropy literal to the identical logical name. This
// mirrors the exact defense already in place for check 11 (checkInsecureRandomTokenBracket,
// closed in round 2 but never mirrored back onto checks 1/3): match a
// `[<quoted-or-concat-literal-key>]` assignment, join the key's literal parts, and if the
// joined name contains a key/secret/token/password keyword, run the same placeholder/
// entropy gate.
const BRACKET_SECRET_KEY_SRC = "(?:['\"`][\\w$]*['\"`]\\s*\\+\\s*)*['\"`][\\w$]*['\"`]";
const GENERIC_ENTROPY_BRACKET_RE = new RegExp(
  `\\[\\s*(${BRACKET_SECRET_KEY_SRC})\\s*\\]\\s*=\\s*["'\`]([A-Za-z0-9+/_=-]{20,})["'\`]`,
  'g',
);
const KEYWORDISH_NAME_RE = /(?:key|secret|token|password|passwd|pwd)/i;

function scanLineGenericEntropyBracket(line, isAutoGenerated) {
  const hits = [];
  GENERIC_ENTROPY_BRACKET_RE.lastIndex = 0;
  let m;
  while ((m = GENERIC_ENTROPY_BRACKET_RE.exec(line)) !== null) {
    const keyExpr = m[1];
    const joined = [...keyExpr.matchAll(/['"`]([\w$]*)['"`]/g)].map((mm) => mm[1]).join('');
    if (!KEYWORDISH_NAME_RE.test(joined)) continue;
    const value = m[2];
    if (isKnownSafeKeyDescriptorName(joined, value)) continue;
    if (isAutoGenerated && looksLikeGeneratedDbIdentifier(value)) continue;
    if (looksLikePlaceholder(value)) continue;
    if (looksLikeCodeReference(value)) continue;
    if (!passesEntropyGate(joined, value)) continue;
    if (isSupabaseAnonRoleJwt(value)) continue;
    hits.push({ value, matchedText: m[0] });
  }
  return hits;
}

// --- Real-world FP fix (2026-07-24, docs/REAL_WORLD_VALIDATION.md re-validation §1) ------
//
// Bug C: doutor-tabajara. A README code-fence example `GROQ_API_KEY=sua_chave_groq_aqui`
// (Portuguese for "your_groq_key_here"). looksLikePlaceholder() (util.js) only recognizes
// ENGLISH placeholder conventions (`your...`, `replace-with...`) -- a README written in
// another language uses its own idiom that no English wordlist covers, and hardcoding one
// translated phrase wouldn't generalize to the next language either (the value's Shannon
// entropy, ~3.5 bits/char, also clears the general threshold the same way Bug B's phrase
// did -- underscore-separated lowercase word chunks read as more "diverse" per-character
// than they are truly random).
//
// Rather than translate placeholder vocabulary, this recognizes the CONTEXT a doc example
// lives in: a fenced code block inside a Markdown/MDX file. A documentation example is
// inherently more likely to show a fake/illustrative value than application source code is
// -- and, independent of language, a hand-typed placeholder overwhelmingly reads as
// pronounceable, underscore/hyphen-separated word-shaped text (each segment pure lowercase
// ASCII letters, no digits, no case-mixing, no base64 `+/=` punctuation) -- the opposite
// shape of a real generated secret, which is essentially never composed of multiple
// all-lowercase dictionary-word-length chunks in ANY human language. This is a SHAPE
// signal, language-agnostic by construction, not a vocabulary list: it fixes the
// Portuguese repro without an English/Portuguese/Spanish/... wordlist that would only ever
// cover the languages someone thought to add. Scoped to the generic-entropy heuristic
// specifically (vendor-format patterns like AKIA/sk_live_ are precise signatures and keep
// firing regardless of file/context), and to fenced-code-block lines specifically within
// `.md`/`.mdx` files (prose text describing a real incident, or a real secret pasted
// outside a fence, is left to the normal checks).
const WORD_SHAPED_SEGMENT_RE = /^[a-z]{2,}$/; // ASCII-lowercase-only "word", no digits/case-mixing
const CODE_FENCE_RE = /^\s*(```|~~~)/;
const DOC_FILE_PATH_RE = /\.mdx?$/i;

function looksLikeWordShapedPlaceholder(value) {
  const segments = value.split(/[_-]/);
  if (segments.length < 2) return false; // need 2+ word-ish chunks to call this "word-shaped" rather than one ambiguous token
  return segments.every((seg) => WORD_SHAPED_SEGMENT_RE.test(seg));
}

function isDocFilePath(repoRelPath) {
  return typeof repoRelPath === 'string' && DOC_FILE_PATH_RE.test(repoRelPath);
}

// Returns the set of 1-indexed line numbers that fall strictly inside a ``` or ~~~ fenced
// code block. Heuristic, not a full Markdown parser -- doesn't handle indented code blocks
// or nested fences, which is an accepted limitation shared with the rest of this codebase's
// text-heuristic checks.
function computeFencedLineNumbers(text) {
  const fenced = new Set();
  const lines = text.split(/\r?\n/);
  let inFence = false;
  for (let i = 0; i < lines.length; i++) {
    if (CODE_FENCE_RE.test(lines[i])) {
      inFence = !inFence;
      continue;
    }
    if (inFence) fenced.add(i + 1);
  }
  return fenced;
}

// --- Template-literal interpolation split of a known-format secret (gap #3) -------------
//
// scanLineConcatChains only reassembles quoted literals joined with `+`. A known-format
// secret split with a template-literal placeholder (`` `AKIA${''}Q3FAKE7EXAMPLE9Z` ``,
// `` `sk_live_${''}51H8...` ``) keeps no contiguous vendor-format shape and no `+` chain,
// so it slips past every SINGLE_LINE_PATTERNS regex. This strips `${...}` placeholders out
// of each template literal on the line and re-tests the concatenated static parts against
// the known-format regexes -- the template-literal analog of the existing `+`-concat
// defense, same class as the check-15 template-literal fix (normalizeRedirectTarget).
const TEMPLATE_LITERAL_RE = /`(?:[^`\\]|\\.)*`/g;

function scanLineTemplateLiteralSplit(line) {
  const hits = [];
  TEMPLATE_LITERAL_RE.lastIndex = 0;
  let m;
  while ((m = TEMPLATE_LITERAL_RE.exec(line)) !== null) {
    const raw = m[0];
    // Only interesting when the template actually splices something out -- a plain
    // `${...}`-free template literal is already covered by the per-line SINGLE_LINE_PATTERNS
    // pass in scanTextForSecrets against the whole line.
    if (!/\$\{[^}]*\}/.test(raw)) continue;
    const stripped = raw.slice(1, -1).replace(/\$\{[^}]*\}/g, '');
    if (stripped.length < 6) continue;
    for (const pattern of SINGLE_LINE_PATTERNS) {
      const pm = stripped.match(pattern.regex);
      if (pm) {
        hits.push({
          name: pattern.name,
          matchedText: raw.slice(0, 80),
          secretValue: pm[0],
          describeText: `${pattern.describe(pm[0])} (reassembled from a template literal with the \${...} interpolation stripped: ${raw.slice(0, 80)})`,
        });
      }
    }
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
 * @param {{ filePath?: string }} [opts] - `filePath` (repo-relative) enables two
 *   file-context-aware signals: auto-generated-file detection (Bug A's secondary signal)
 *   and Markdown/MDX fenced-code-block placeholder detection (Bug C). Omitted by
 *   git-history.js's diff-line scanning, where no whole-file context is available --
 *   both signals simply don't apply there, same as before this fix.
 * @returns {Array<{ name: string, line: number, matchedText: string, describe: string, secretValue: string }>}
 */
function scanTextForSecrets(text, opts = {}) {
  const hits = [];
  const lines = text.split(/\r?\n/);
  const isAutoGenerated = looksLikeAutoGeneratedFile(text);
  const isDocFile = isDocFilePath(opts.filePath);
  const fencedLines = isDocFile ? computeFencedLineNumbers(text) : null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const inDocCodeExample = isDocFile && fencedLines.has(i + 1);
    for (const pattern of SINGLE_LINE_PATTERNS) {
      const m = line.match(pattern.regex);
      if (m) {
        if (isSupabaseAnonRoleJwt(m[0])) continue; // Supabase anon/publishable key -- safe by design, see decodeJwtPayloadRole above
        hits.push({
          name: pattern.name,
          line: i + 1,
          matchedText: m[0],
          secretValue: m[0],
          describe: pattern.describe(m[0]),
        });
      }
    }
    for (const hit of scanLineGenericEntropy(line, isAutoGenerated)) {
      if (inDocCodeExample && looksLikeWordShapedPlaceholder(hit.value)) continue;
      hits.push({
        name: 'generic-high-entropy',
        line: i + 1,
        matchedText: hit.matchedText,
        secretValue: hit.value,
        describe: 'high-entropy literal assigned to a key/secret/token/password-like name',
      });
    }
    for (const hit of scanLineGenericEntropyUnquoted(line, isAutoGenerated)) {
      if (inDocCodeExample && looksLikeWordShapedPlaceholder(hit.value)) continue;
      hits.push({
        name: 'generic-high-entropy-unquoted',
        line: i + 1,
        matchedText: hit.matchedText,
        secretValue: hit.value,
        describe: 'high-entropy unquoted KEY=value assignment (dotenv-style) to a key/secret/token/password-like name',
      });
    }
    for (const hit of scanLineGenericEntropyBracket(line, isAutoGenerated)) {
      if (inDocCodeExample && looksLikeWordShapedPlaceholder(hit.value)) continue;
      hits.push({
        name: 'generic-high-entropy',
        line: i + 1,
        matchedText: hit.matchedText,
        secretValue: hit.value,
        describe: 'high-entropy literal assigned to a bracket-notation key/secret/token/password-like property',
      });
    }
    for (const hit of scanLineTemplateLiteralSplit(line)) {
      if (isSupabaseAnonRoleJwt(hit.secretValue)) continue;
      hits.push({
        name: hit.name,
        line: i + 1,
        matchedText: hit.matchedText,
        secretValue: hit.secretValue,
        describe: hit.describeText,
      });
    }
    for (const hit of scanLineConcatChains(line)) {
      if (isSupabaseAnonRoleJwt(hit.secretValue)) continue;
      hits.push({
        name: hit.name,
        line: i + 1,
        matchedText: hit.matchedText,
        secretValue: hit.secretValue,
        describe: hit.describeText,
      });
    }
    for (const hit of scanLineBase64Encoded(line)) {
      if (isSupabaseAnonRoleJwt(hit.secretValue)) continue;
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

// Conventionally-safe template files — not real secrets, so don't flag them. Was an
// exact-match Set of only the four dot-forms (`.env.example`/`.sample`/`.template`/`.dist`),
// but round-2 broadened ENV_FILE_RE to also accept `-`/`_` separators and compound
// suffixes -- introducing an asymmetry the round-3 secrets audit caught (FP #7):
// `.env-example` (hyphen variant of a template), `.env.local.example` (compound template),
// `.env.production.template`, `.env.dist.local` etc. were all flagged as real committed
// secrets because they weren't the four literal dot-forms. Replaced the exact Set with a
// marker regex that recognizes an example/sample/template/dist token anywhere in the
// suffix, regardless of separator. Safe to broaden: this only ever *suppresses* a
// filename finding.
const SAFE_ENV_TEMPLATE_RE = /(^|[.\-_])(example|sample|template|dist)([.\-_]|$)/i;

// Was /^\.env(\..+)?$/ -- required a literal dot before any suffix, so a filename like
// ".env-production" (hyphen instead of dot) or ".env_local" (underscore) slipped through
// even though it's the same real dotenv file loaded the same way at runtime. Broadened to
// accept '.', '-', or '_' as the separator before the suffix, while still anchoring on
// the leading ".env" so unrelated filenames (e.g. a hypothetical ".environment") aren't
// swept in: after ".env" the next character must be one of [.\-_] or end-of-string, not
// just any word character.
const ENV_FILE_RE = /^\.env([.\-_].*)?$/;

function isFlaggableEnvFilename(basename) {
  return ENV_FILE_RE.test(basename) && !SAFE_ENV_TEMPLATE_RE.test(basename);
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
    const hits = scanTextForSecrets(text, { filePath: repoRelPath });
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

// A false-positive audit (round 2, 2026-07-24) found the substring vocabulary above
// flagging names like "tokenizerSeed" (an NLP mock-data seed -- "token" is just the start
// of "tokenizer") purely on incidental overlap. The fix is a post-filter, not a regex
// lookahead baked into TOKEN_ISH_NAME_SRC itself: `(?![a-z])` inside a pattern compiled
// with the 'i' flag doesn't do what it looks like it does, since `[a-z]` under
// case-insensitive matching ALSO matches uppercase letters -- it would incorrectly block
// legitimate names like "resetTokenValue" (the letter after "Token" is a real, wanted
// uppercase 'V'). Re-checking against the ORIGINAL (un-folded) captured text here keeps
// the outer regex's case-insensitivity for finding candidates while still doing a real
// case-SENSITIVE "is this followed by a lowercase letter" check: a keyword occurrence
// followed by a lowercase letter is embedded inside a longer word (tokenizer, secretary)
// rather than ending at a real camelCase/separator boundary, and is rejected; a keyword
// occurrence followed by end-of-name/a digit/an underscore/an uppercase letter is a real
// boundary and is kept. A name is accepted if ANY of its keyword occurrences clears this
// check (so "csrfToken" -- where the first, "csrf", already clears it -- doesn't get
// rejected just because a *different* substring elsewhere wouldn't).
//
// This is a real but partial fix: a keyword that lands at a genuine camelCase SEGMENT
// boundary on BOTH sides (e.g. "gameToken", "animationToken" -- a board-game piece color
// / a UI animation dedup key, both real false positives found in the same audit) is
// syntactically indistinguishable from a real "sessionToken"/"authToken" and is not fixed
// here -- see SECURITY_SCOPE.md's check-11 entry for why that's left as a documented,
// accepted tradeoff rather than forced closed.
const TOKEN_ISH_KEYWORD_SEARCH_RE = /(?:token|session[_-]?id|api[_-]?key|secret|nonce|csrf)/gi;

function hasTokenIshKeywordAtBoundary(name) {
  TOKEN_ISH_KEYWORD_SEARCH_RE.lastIndex = 0;
  let km;
  while ((km = TOKEN_ISH_KEYWORD_SEARCH_RE.exec(name)) !== null) {
    const after = name[km.index + km[0].length];
    if (!after || !/[a-z]/.test(after)) return true; // real boundary -- not embedded in a longer lowercase word
    if (km.index === TOKEN_ISH_KEYWORD_SEARCH_RE.lastIndex) TOKEN_ISH_KEYWORD_SEARCH_RE.lastIndex++; // guard zero-width
  }
  return false;
}

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
    if (!hasTokenIshKeywordAtBoundary(name)) continue;
    hits.push({
      line: lineOfIndex(original, m.index),
      snippet: snippetAt(original, m.index),
      rawMessage: `Math.random() is used to build the value assigned to "${name}", a name that suggests a security-sensitive token (session id, reset token, API key, secret, nonce, or CSRF token). Math.random() is not cryptographically secure and its output is predictable, so tokens built from it can be guessed -- use crypto.randomBytes(n).toString('hex') or crypto.randomUUID() instead.`,
    });
  }
  return hits;
}

// --- Evasion-resistance: bracket-notation / concatenated property name -----------------
//
// TOKEN_ISH_NAME_SRC is built entirely from `[\w$.]*`/`[\w$]*` character classes, which
// don't include `'`, `"`, `[`, or `]` -- so a property name written in bracket notation
// (`user['sessionId'] = ...`), or worse, a bracket key itself built from concatenated
// string literals (`user['session' + 'Id'] = ...`), is invisible to INSECURE_RANDOM_TOKEN_RE
// even though it assigns the identical Math.random()-derived value to the identical logical
// property. Matches any `[<quoted-literal-or-concat-chain>]` immediately followed by `:`/`=`
// and a same-statement Math.random() call, then joins the bracket key's literal parts back
// together (same join approach as findStringConcatChains) and tests the joined name against
// the same token-ish keyword vocabulary TOKEN_ISH_NAME_SRC uses.
// Was quote-only (`'`/`"`) -- a bracket key written as a template literal (`` user[`sessionId`]
// = ... ``, an entirely ordinary modern-JS stylistic choice, not exotic obfuscation) fell
// outside that character class and was invisible here. Fixed 2026-07-24 (round 2 evasion
// audit): backtick added to both quote-char classes.
const BRACKET_KEY_EXPR_SRC = "(?:['\"`][\\w$]*['\"`]\\s*\\+\\s*)*['\"`][\\w$]*['\"`]";
const INSECURE_RANDOM_TOKEN_BRACKET_RE = new RegExp(
  `\\[\\s*(${BRACKET_KEY_EXPR_SRC})\\s*\\]\\s*(?::|=(?!=|>))\\s*([^;\\n]*\\bMath\\.random\\(\\)[^;\\n]*)`,
  'g',
);
function checkInsecureRandomTokenBracket(clean, original) {
  const hits = [];
  INSECURE_RANDOM_TOKEN_BRACKET_RE.lastIndex = 0;
  let m;
  while ((m = INSECURE_RANDOM_TOKEN_BRACKET_RE.exec(clean)) !== null) {
    const keyExpr = m[1];
    const joined = [...keyExpr.matchAll(/['"`]([\w$]*)['"`]/g)].map((mm) => mm[1]).join('');
    if (!hasTokenIshKeywordAtBoundary(joined)) continue;
    hits.push({
      line: lineOfIndex(original, m.index),
      snippet: snippetAt(original, m.index),
      rawMessage: `Math.random() is used to build the value assigned to a bracket-notation property that resolves to "${joined}" -- a name that suggests a security-sensitive token (session id, reset token, API key, secret, nonce, or CSRF token). Math.random() is not cryptographically secure and its output is predictable, so tokens built from it can be guessed -- use crypto.randomBytes(n).toString('hex') or crypto.randomUUID() instead.`,
    });
  }
  return hits;
}

// --- Evasion-resistance: Math.random() moved one function call away --------------------
//
// checkInsecureRandomToken() above requires the token-ish name and a literal Math.random()
// call to appear together, on the SAME statement -- it has no same-file function-body
// lookup at all (unlike eval-on-input's argLooksInterpolated, which resolves one level of
// same-file function call). So wrapping Math.random() in a helper function and assigning
// the helper's *return value* to a token-ish name (`const resetToken = weakRandomToken();`)
// defeats it completely, even though the token is exactly as predictable. Matches a
// token-ish name assigned to a bare same-file function call, resolves that function's
// return expression (lookupFunctionReturnExpr, shared with static-checks.js's checks 5/13/
// 14/15 via util.js), and flags it if the return expression itself contains Math.random().
// Callee capture group allows one optional `.member` hop (`ClassName.method`) as well as
// a bare identifier -- added 2026-07-24 (round 2 evasion audit) so a static-class-method
// call site (`const resetToken = TokenGen.generate();`) is recognized at all; previously
// the bare-identifier-only pattern never matched the statement in the first place since a
// member expression has a '.' where the regex expected '(' to follow immediately.
// lookupFunctionReturnExpr (util.js) dispatches a dotted callee name to its own
// class-static-method lookup.
// The trailing `\)` no longer requires a following `;` -- a required literal semicolon
// silently defeated every semicolon-free codebase (Standard.js, `semi:false`, much
// AI-generated code): `const sessionToken = weakRandomToken()` (no `;`) was invisible even
// though the identical `;`-terminated form was caught. This is the same no-semicolon gap
// already closed for resolveConcatExpression/resolveIdentifierChain in round 2, just never
// mirrored onto this regex (round-3 fresh-look, gap #5). `([^()]*)` already bounds the arg
// capture at the call's own closing paren, so the `;` was never load-bearing for scoping.
const TOKEN_ASSIGNED_TO_CALL_RE = new RegExp(
  `(${TOKEN_ISH_NAME_SRC})\\s*(?::|=(?!=|>))\\s*(?:await\\s+)?([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)?)\\s*\\(([^()]*)\\)`,
  'gi',
);

function checkInsecureRandomTokenViaHelperCall(clean, original) {
  const hits = [];
  TOKEN_ASSIGNED_TO_CALL_RE.lastIndex = 0;
  let m;
  while ((m = TOKEN_ASSIGNED_TO_CALL_RE.exec(clean)) !== null) {
    const name = m[1];
    if (!hasTokenIshKeywordAtBoundary(name)) continue;
    const calleeName = m[2];
    const returnExpr = lookupFunctionReturnExpr(clean, calleeName);
    if (!returnExpr || !/\bMath\.random\(\)/.test(returnExpr)) continue;
    hits.push({
      line: lineOfIndex(original, m.index),
      snippet: snippetAt(original, m.index),
      rawMessage: `Math.random() is used (inside same-file helper function "${calleeName}()") to build the value assigned to "${name}", a name that suggests a security-sensitive token (session id, reset token, API key, secret, nonce, or CSRF token). Math.random() is not cryptographically secure and its output is predictable, so tokens built from it can be guessed -- use crypto.randomBytes(n).toString('hex') or crypto.randomUUID() instead.`,
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
    const hits = [
      ...checkInsecureRandomToken(clean, original),
      ...checkInsecureRandomTokenBracket(clean, original),
      ...checkInsecureRandomTokenViaHelperCall(clean, original),
    ];
    for (const hit of hits) {
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
//
// The algorithm argument is captured as raw text (CREATE_HASH_CALL_RE, below) rather than
// requiring a literal quoted 'md5'/'sha1' directly inside the call -- the previous
// literal-only regex (WEAK_HASH_ALGO_RE) never matched a variable holding the algorithm
// name at all, even a trivially-obfuscated one built from split literals
// (`const HASH_ALGO = 'm' + 'd5';`), so the password-context heuristics below never even
// got a chance to run. resolveConcatExpression (util.js, shared with static-checks.js's
// SQL and route-path checks) already resolves both a bare literal argument AND an
// identifier chain through any number of `const/let/var` hops and `+` concatenations back
// to a single string, so it's reused here rather than duplicating that resolution logic.
// Was dot-notation only (`crypto.createHash(`) -- a computed/bracket member access on the
// METHOD NAME itself (`crypto['createHash'](...)`) never contains that literal text, so
// the whole call was invisible before the password-context heuristics below even got a
// chance to run. Fixed 2026-07-24 (round 2 evasion audit): also matches
// `crypto['createHash'](...)` / `crypto["createHash"](...)`.
const CREATE_HASH_CALL_RE = /crypto\s*(?:\.\s*createHash|\[\s*['"]createHash['"]\s*\])\s*\(\s*([^)]*)\)/gi;
// Bare `createHash('md5')` with no `crypto.` receiver -- the shape produced by the single
// most common way this API is actually imported: `const { createHash } = require('crypto')`
// or `import { createHash } from 'crypto'`. CREATE_HASH_CALL_RE hard-codes a literal
// `crypto` receiver, so a destructured-import call was completely invisible (round-3
// fresh-look, gap #1 -- a mainstream idiom, not adversarial obfuscation). Only scanned when
// the file actually destructures createHash from crypto (below), so an unrelated same-named
// helper elsewhere can't trigger it. `(?<![.\w])` prevents matching `crypto.createHash`
// (already covered) or a `.createHash`/`fooCreateHash` member/identifier suffix.
const BARE_CREATE_HASH_CALL_RE = /(?<![.\w])createHash\s*\(\s*([^)]*)\)/gi;
const DESTRUCTURED_CREATEHASH_IMPORT_RE = /(?:(?:const|let|var)\s*\{[^}]*\bcreateHash\b[^}]*\}\s*=\s*require\s*\(\s*['"]crypto['"]\s*\)|import\s*\{[^}]*\bcreateHash\b[^}]*\}\s*from\s*['"]crypto['"])/;
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
  // Scan `crypto.createHash(...)` always; additionally scan bare `createHash(...)` when the
  // file destructures createHash from the crypto module (see BARE_CREATE_HASH_CALL_RE).
  const callRegexes = [CREATE_HASH_CALL_RE];
  if (DESTRUCTURED_CREATEHASH_IMPORT_RE.test(clean)) callRegexes.push(BARE_CREATE_HASH_CALL_RE);
  for (const callRe of callRegexes) {
  callRe.lastIndex = 0;
  let m;
  while ((m = callRe.exec(clean)) !== null) {
    const rawArg = m[1].trim();
    if (!rawArg) continue;
    const resolved = resolveConcatExpression(clean, rawArg);
    if (resolved === null) continue; // can't confirm the algorithm name -- bail rather than guess
    const algo = resolved.toLowerCase();
    if (algo !== 'md5' && algo !== 'sha1') continue;
    const statement = currentStatementWindow(clean, m.index);
    const nearbyLooksPasswordy = PASSWORD_CONTEXT_RE.test(statement);
    if (!nearbyLooksPasswordy && !fileLooksAuthy) continue; // no password-ish signal at all -- likely a checksum/etag use, leave it alone
    const reason = nearbyLooksPasswordy
      ? 'a nearby variable/argument name suggests it is hashing a password'
      : `the file ("${repoRelPath}") looks like an auth/login/signup/register route or module`;
    const viaVariable = rawArg !== `'${algo}'` && rawArg !== `"${algo}"` && rawArg !== `\`${algo}\``;
    const algoDescription = viaVariable
      ? `resolves (via "${rawArg}") to '${algo}'`
      : `is called with '${algo}'`;
    hits.push({
      line: lineOfIndex(original, m.index),
      snippet: snippetAt(original, m.index),
      rawMessage: `crypto.createHash(...) ${algoDescription} where ${reason} -- ${algo.toUpperCase()} is fast and unsalted, so a breached password database hashed this way is fully crackable at scale. Use bcrypt, scrypt, or argon2 instead.`,
    });
  }
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
  decodeJwtPayloadRole,
  isSupabaseAnonRoleJwt,
  looksLikeCodeReference,
  isKnownSafeKeyDescriptorName,
  looksLikeAutoGeneratedFile,
  isBareKeyName,
  looksLikeWordShapedPlaceholder,
  CHECK_HARDCODED,
  CHECK_ENV_COMMITTED,
  CHECK_INSECURE_RANDOM_TOKEN,
  CHECK_WEAK_PASSWORD_HASHING,
};
