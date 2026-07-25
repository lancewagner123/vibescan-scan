'use strict';
const path = require('path');
const { scanRepo } = require('../../../../src/scanners');

const dir = __dirname;
const findings = scanRepo(dir, { skip: ['dependencies', 'git-history', 'secrets'] });

const byFile = {};
for (const f of findings) {
  if (f.file === '_run.js') continue;
  (byFile[f.file] = byFile[f.file] || []).push(f);
}

const fs = require('fs');
const files = fs.readdirSync(dir).filter((n) => n.endsWith('.js') && n !== '_run.js').sort();
for (const file of files) {
  const fs2 = byFile[file] || [];
  console.log('\n=== ' + file + ' ===');
  if (fs2.length === 0) {
    console.log('  (no findings)');
  } else {
    for (const f of fs2) {
      console.log(`  [${f.checkId}] line ${f.line}: ${f.rawMessage.slice(0, 130)}`);
    }
  }
}
console.log('\nTOTAL static findings:', findings.filter((f) => f.file !== '_run.js').length);
