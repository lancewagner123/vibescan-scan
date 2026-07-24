'use strict';

// Check 3 from docs/CHECK_CATALOG.md: secret-git-history
//
// Runs `git log -p --all` (capped to --max-commits, default 500) and applies the same
// secret regexes from secrets.js against added ("+") lines in the diff text, tagging
// each match with the commit hash it was introduced in — even if the secret has since
// been removed from HEAD.

const path = require('path');
const { makeId, redactSecret, tryGit, isGitRepo, guardGitHistoryScope } = require('./util');
const {
  SINGLE_LINE_PATTERNS,
  MULTILINE_PATTERNS,
  scanTextForSecrets,
} = require('./secrets');

const CHECK_ID = 'secret-git-history';
const DEFAULT_MAX_COMMITS = 500;

// Unique delimiter for splitting `git log -p` output into per-commit chunks. Using a
// custom pretty-format marker (instead of matching on the literal "commit <hash>" line
// git prints by default) avoids any ambiguity with the word "commit" appearing inside a
// commit message body or inside diff content itself.
const COMMIT_MARKER = '@@VIBESCAN_COMMIT@@';

function runGitLogP(repoPath, maxCommits) {
  return tryGit(
    repoPath,
    [
      'log',
      '--all',
      `--max-count=${maxCommits}`,
      '-p',
      `--pretty=format:${COMMIT_MARKER}%H`,
    ],
    { maxBuffer: 500 * 1024 * 1024 },
  );
}

/**
 * Scan a single line (one "+" line from a diff) against the known single-line secret
 * patterns and the generic high-entropy heuristic, reusing secrets.js's exact logic by
 * delegating to scanTextForSecrets on that one line.
 */
function scanAddedLine(lineText) {
  return scanTextForSecrets(lineText).filter((hit) =>
    // scanTextForSecrets also runs MULTILINE_PATTERNS per call; on a single line those
    // essentially never match (a PEM block doesn't fit on one line) so filtering them
    // out here just avoids double-reporting — the multiline pass below handles PEM.
    !MULTILINE_PATTERNS.some((p) => p.name === hit.name),
  );
}

/**
 * Parse `git log -p --all` output into findings. Walks line by line, tracking the
 * current commit hash, current file (from the "+++ b/<path>" diff header), and the
 * running new-file line number (from "@@ -a,b +c,d @@" hunk headers), so every added
 * line can be attributed to a real file + line number.
 */
function parseLogForSecrets(logText) {
  const findings = [];
  const lines = logText.split(/\r?\n/);

  let commitHash = null;
  let currentFile = null;
  let newLineNo = null;
  // Buffer of added lines for the *current file within the current commit*, used for
  // the multiline (PEM) pattern pass once a file/commit boundary is crossed.
  let addedBuffer = []; // { lineNo, text }

  function flushMultiline() {
    if (!commitHash || !currentFile || addedBuffer.length === 0) {
      addedBuffer = [];
      return;
    }
    const joined = addedBuffer.map((l) => l.text).join('\n');
    for (const pattern of MULTILINE_PATTERNS) {
      const m = joined.match(pattern.regex);
      if (m) {
        const secretValue = m[0];
        const approxLine = addedBuffer[0].lineNo;
        findings.push({
          id: makeId(CHECK_ID, [currentFile, String(approxLine), commitHash, pattern.name]),
          checkId: CHECK_ID,
          severity: 'critical',
          category: 'secret',
          file: currentFile,
          line: approxLine,
          snippet: redactSecret(secretValue).slice(0, 200),
          rawMessage: `Possible ${pattern.describe()} added in commit ${commitHash} (approx. line ${approxLine} of ${currentFile} at that commit) — check history even though it may be gone from HEAD.`,
        });
      }
    }
    addedBuffer = [];
  }

  for (const line of lines) {
    if (line.startsWith(COMMIT_MARKER)) {
      flushMultiline();
      commitHash = line.slice(COMMIT_MARKER.length).trim();
      currentFile = null;
      newLineNo = null;
      continue;
    }

    if (line.startsWith('diff --git ')) {
      flushMultiline();
      currentFile = null;
      newLineNo = null;
      continue;
    }

    if (line.startsWith('+++ ')) {
      flushMultiline();
      const p = line.slice(4).trim();
      if (p === '/dev/null') {
        currentFile = null; // file deleted in this commit — nothing new was added here
      } else {
        currentFile = p.replace(/^b\//, '').split(path.sep).join('/');
      }
      continue;
    }

    if (line.startsWith('@@ ')) {
      const m = line.match(/@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      newLineNo = m ? parseInt(m[1], 10) : null;
      continue;
    }

    if (!currentFile || newLineNo === null) continue;

    if (line.startsWith('+') && !line.startsWith('+++')) {
      const text = line.slice(1);
      for (const hit of scanAddedLine(text)) {
        findings.push({
          id: makeId(CHECK_ID, [currentFile, String(newLineNo), commitHash, hit.name, hit.matchedText]),
          checkId: CHECK_ID,
          severity: 'critical',
          category: 'secret',
          file: currentFile,
          line: newLineNo,
          snippet: redactSecret(hit.secretValue).slice(0, 200),
          rawMessage: `Possible ${hit.describe} added in commit ${commitHash} at ${currentFile}:${newLineNo} — present in git history even if no longer in HEAD.`,
        });
      }
      addedBuffer.push({ lineNo: newLineNo, text });
      newLineNo++;
    } else if (line.startsWith('-') && !line.startsWith('---')) {
      // removed line — doesn't consume a new-file line number
      continue;
    } else {
      // context line — present in both old and new versions
      newLineNo++;
    }
  }

  flushMultiline();
  return findings;
}

/**
 * @param {string} repoPath
 * @param {{ maxCommits?: number }} [opts]
 * @returns {{ findings: object[], warnings: string[] }}
 */
function scan(repoPath, opts = {}) {
  const warnings = [];
  const maxCommits = opts.maxCommits || DEFAULT_MAX_COMMITS;

  if (!isGitRepo(repoPath)) {
    warnings.push('git-history.js: target is not a git repository (or git is unavailable) — check 3 (secret-git-history) skipped.');
    return { findings: [], warnings };
  }

  // Guard against the ancestor-repo misattribution bug: `isGitRepo` above only proves
  // repoPath is *somewhere inside* a git work tree, not that it's the repo's own root.
  // See guardGitHistoryScope's docstring in util.js for the full "why".
  const scope = guardGitHistoryScope(repoPath, 'check 3: secret-git-history');
  if (!scope.ok) {
    warnings.push(scope.warning);
    return { findings: [], warnings };
  }

  const logText = runGitLogP(repoPath, maxCommits);
  if (logText === null) {
    warnings.push('git-history.js: `git log -p --all` failed to run — check 3 (secret-git-history) skipped.');
    return { findings: [], warnings };
  }
  if (logText.trim() === '') {
    // Valid repo with no commits yet — not an error, just nothing to scan.
    return { findings: [], warnings };
  }

  let findings = [];
  try {
    findings = parseLogForSecrets(logText);
  } catch (err) {
    warnings.push(`git-history.js: failed to parse git log output: ${err.message}`);
  }

  return { findings, warnings };
}

module.exports = { scan, DEFAULT_MAX_COMMITS };
