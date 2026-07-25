'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scanRepo } = require('../../../../src/scanners');
const controls = require('./_controls');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vibescan-controls-'));
for (const [name, src] of Object.entries(controls)) {
  fs.writeFileSync(path.join(tmp, name), src);
}
const findings = scanRepo(tmp, { skip: ['git-history', 'dependencies'] });
const byFile = {};
for (const f of findings) (byFile[f.file] ||= []).push(`${f.checkId} @ line ${f.line}`);
for (const name of Object.keys(controls).sort()) {
  console.log(`\n### ${name}`);
  const hits = byFile[name] || [];
  if (hits.length === 0) console.log('  (no findings)  <-- UNEXPECTED for a control');
  else for (const h of hits) console.log('  - ' + h);
}
fs.rmSync(tmp, { recursive: true, force: true });
