'use strict';

// End-to-end test: runs the real scanner pipeline (src/scanners) against the seeded
// vulnerable-demo-app fixture in test/fixtures/, then feeds the raw findings through the
// real triage pipeline (src/triage) and checks the output against the Triage Output
// Schema documented in docs/FINDINGS_SCHEMA.md.
//
// NOTE: src/scanners and src/triage were built by other agents in earlier Build phases;
// this file's assertions are exact about which checkIds must be found. As of v0.2.0 the
// fixture seeds all 15 checks from docs/CHECK_CATALOG.md (the original 10, plus checks
// 11-15 added in routes/auth.js, routes/profile.js, and routes/redirect.js).

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { scanRepo } = require('../src/scanners');
const { triage } = require('../src/triage');

const FIXTURE_PATH = path.join(__dirname, 'fixtures', 'vulnerable-demo-app');

// Exactly the 15 checkIds in docs/CHECK_CATALOG.md, no more, no less -- the fixture
// seeds at least one clear instance of each.
const EXPECTED_CHECK_IDS = [
  'secret-hardcoded-generic',
  'secret-env-committed',
  'secret-git-history',
  'sql-string-concatenation',
  'eval-on-input',
  'cors-wildcard-with-credentials',
  'missing-auth-middleware',
  'supabase-rls-disabled',
  'stripe-webhook-unverified',
  'vulnerable-dependency',
  'insecure-random-token',
  'weak-password-hashing',
  'mass-assignment',
  'insecure-cookie-flags',
  'open-redirect',
];

const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);

test('scanRepo() finds all 15 seeded VibeScan checks in the vulnerable-demo-app fixture', async () => {
  const findings = await scanRepo(FIXTURE_PATH);

  assert.ok(Array.isArray(findings), 'scanRepo() must resolve to an array of raw findings');
  assert.ok(findings.length > 0, 'scanRepo() must return at least one finding for a deliberately vulnerable fixture');

  const foundCheckIds = new Set(findings.map((finding) => finding.checkId));
  const missing = EXPECTED_CHECK_IDS.filter((checkId) => !foundCheckIds.has(checkId));

  assert.deepEqual(
    missing,
    [],
    `expected all 15 checkIds to be found at least once; missing: [${missing.join(', ')}]. ` +
      `Found: [${[...foundCheckIds].join(', ')}]`
  );

  // Every raw finding should at least carry the fields the Raw Finding Schema requires,
  // so downstream triage has something well-formed to consolidate.
  for (const finding of findings) {
    assert.equal(typeof finding.checkId, 'string', 'each finding must have a string checkId');
    assert.equal(typeof finding.file, 'string', 'each finding must have a string file path');
  }
});

test('triage() produces Triage-Output-Schema-shaped output from the fixture findings, with ANTHROPIC_API_KEY unset (deterministic fallback path)', async () => {
  const findings = await scanRepo(FIXTURE_PATH);

  const hadKey = Object.prototype.hasOwnProperty.call(process.env, 'ANTHROPIC_API_KEY');
  const previousKey = process.env.ANTHROPIC_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;

  let result;
  try {
    result = await triage(findings);
  } finally {
    if (hadKey) {
      process.env.ANTHROPIC_API_KEY = previousKey;
    } else {
      delete process.env.ANTHROPIC_API_KEY;
    }
  }

  // -- Triage Output Schema shape (docs/FINDINGS_SCHEMA.md) --
  assert.ok(result && typeof result === 'object', 'triage() must resolve to an object');

  assert.ok(result.summary && typeof result.summary === 'object', 'triage output must have a summary object');
  for (const level of ['critical', 'high', 'medium', 'low']) {
    assert.equal(
      typeof result.summary[level],
      'number',
      `triage output summary.${level} must be a number`
    );
  }

  assert.ok(Array.isArray(result.findings), 'triage output must have a findings array');
  assert.ok(
    result.findings.length > 0,
    'triage output findings array must not be empty for a fixture with 15 seeded issues'
  );

  for (const finding of result.findings) {
    assert.equal(typeof finding.title, 'string', 'each triaged finding needs a string title');
    assert.ok(
      VALID_SEVERITIES.has(finding.severity),
      `each triaged finding's severity must be one of ${[...VALID_SEVERITIES].join(', ')}, got: ${finding.severity}`
    );
    assert.equal(typeof finding.explanation, 'string', 'each triaged finding needs a string explanation');
    assert.equal(typeof finding.attackerImpact, 'string', 'each triaged finding needs a string attackerImpact');
    assert.equal(typeof finding.file, 'string', 'each triaged finding needs a string file path');
    assert.ok(
      finding.line === null || typeof finding.line === 'number',
      'each triaged finding\'s line must be a number or null'
    );

    assert.ok(finding.fix && typeof finding.fix === 'object', 'each triaged finding needs a fix object');
    assert.equal(typeof finding.fix.description, 'string', 'fix.description must be a string');
    assert.ok(
      finding.fix.diff === null || typeof finding.fix.diff === 'string',
      'fix.diff must be a string or null'
    );

    assert.ok(
      Array.isArray(finding.sourceCheckIds),
      'each triaged finding needs a sourceCheckIds array'
    );
    assert.ok(
      finding.sourceCheckIds.length > 0,
      'sourceCheckIds must not be empty -- every triaged finding traces back to at least one raw check'
    );
  }

  // Every raw checkId the scanner found should be traceable to at least one triaged
  // finding's sourceCheckIds -- triage may consolidate, but it must not silently drop one
  // of the 15 seeded issues.
  const rawCheckIds = new Set(findings.map((finding) => finding.checkId));
  const triagedCheckIds = new Set(result.findings.flatMap((finding) => finding.sourceCheckIds));
  const dropped = [...rawCheckIds].filter((checkId) => !triagedCheckIds.has(checkId));

  assert.deepEqual(
    dropped,
    [],
    `triage() must not drop any raw checkId; dropped: [${dropped.join(', ')}]`
  );
});
