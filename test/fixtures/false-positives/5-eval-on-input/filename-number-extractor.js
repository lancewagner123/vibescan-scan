'use strict';

// Reconstructs a real-world eval-on-input false positive (docs/REAL_WORLD_VALIDATION.md
// §5.4): a filename-number extractor built with RegExp.prototype.exec(), in a file that
// ALSO legitimately imports child_process for an unrelated purpose (checking the current
// git commit count for a build-info banner). The old file-wide "does this file mention
// child_process anywhere" guard would have let the .exec() below straight through, since
// it never looked at what the .exec() call was actually invoked ON -- only whether the
// substring "child_process" appeared anywhere in the file. This is the specific
// manifestation of the exec()/execSync() vs RegExp.prototype.exec() collision that
// survived the first attempted fix.
const { execSync } = require('child_process');

function getBuildCommitCount() {
  // Legitimate, unrelated child_process usage -- a fixed literal command, no user input
  // anywhere near it.
  return execSync('git rev-list --count HEAD').toString().trim();
}

const LEADING_NUMBER_RE = /^(\d+)[-_]/;

// Extracts a leading sequence number from an asset filename, e.g. "003-hero-banner.webp"
// -> "003". Ordinary RegExp.prototype.exec() usage, nothing to do with shelling out.
function extractLeadingNumber(filename) {
  const match = LEADING_NUMBER_RE.exec(filename);
  return match ? match[1] : null;
}

module.exports = { getBuildCommitCount, extractLeadingNumber };
