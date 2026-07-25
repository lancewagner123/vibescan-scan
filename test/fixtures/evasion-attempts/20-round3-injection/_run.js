'use strict';
const path = require('path');
const fs = require('fs');
const { scanRepo } = require('../../../../src/scanners');

const root = __dirname;
const dirs = fs.readdirSync(root, { withFileTypes: true })
  .filter((e) => e.isDirectory())
  .map((e) => e.name)
  .sort();

// Only care about the three checks in scope.
const IN_SCOPE = new Set(['sql-string-concatenation', 'eval-on-input', 'cors-wildcard-with-credentials']);

for (const d of dirs) {
  const findings = scanRepo(path.join(root, d), { skip: ['git-history', 'dependencies'] });
  const scoped = findings.filter((f) => IN_SCOPE.has(f.checkId));
  const expectFinding = !d.includes('-fp-'); // -fp- dirs must produce NO scoped finding
  const got = scoped.length > 0;
  let verdict;
  if (expectFinding && got) verdict = 'DETECTED (gap closed / not a gap)';
  else if (expectFinding && !got) verdict = '*** MISSED (real false-negative gap) ***';
  else if (!expectFinding && got) verdict = '*** FALSE POSITIVE ***';
  else verdict = 'clean (no FP) OK';

  console.log(`\n=== ${d} ===`);
  console.log(`  verdict: ${verdict}`);
  for (const f of scoped) {
    console.log(`   - ${f.checkId} @ ${f.file}:${f.line}  ${JSON.stringify(f.snippet).slice(0, 80)}`);
  }
}
