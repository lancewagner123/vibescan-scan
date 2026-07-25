'use strict';
const path = require('path');
const { scanRepo } = require('../../../../src/scanners');

const dir = __dirname;
const findings = scanRepo(dir, { skip: ['git-history', 'dependencies'] });

// Group by file (basename), only the fixture files (ignore this harness).
const byFile = {};
for (const f of findings) {
  if (f.file.startsWith('_run')) continue;
  (byFile[f.file] ||= []).push(`${f.checkId} @ line ${f.line}`);
}

const allFiles = require('fs').readdirSync(dir)
  .filter((n) => (n.endsWith('.js') || n.endsWith('.ts')) && !n.startsWith('_run'))
  .sort();

for (const file of allFiles) {
  const hits = byFile[file] || [];
  console.log(`\n### ${file}`);
  if (hits.length === 0) console.log('  (no findings)');
  else for (const h of hits) console.log('  - ' + h);
}
console.log('\nTotal findings:', findings.filter((f) => !f.file.startsWith('_run')).length);
if (findings.warnings && findings.warnings.length) {
  console.log('\nWarnings:');
  for (const w of findings.warnings) console.log('  ! ' + w.slice(0, 120));
}
