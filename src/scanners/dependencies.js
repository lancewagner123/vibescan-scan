'use strict';

// Check 10 from docs/CHECK_CATALOG.md: vulnerable-dependency
//
// If package.json exists: run `npm audit --json` and parse high/critical advisories.
// If requirements.txt exists: attempt `pip-audit --format json`; if pip-audit isn't
// installed, skip gracefully (warning only, never fails the whole scan).

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { makeId } = require('./util');

const CHECK_ID = 'vulnerable-dependency';
const NPM_SEVERITIES_TO_REPORT = new Set(['high', 'critical']);

// On Windows, `npm` resolves to `npm.cmd` (a batch file) — execFileSync spawns via
// CreateProcess directly and can't launch a .cmd without going through a shell, so
// `execFileSync('npm', ...)` throws ENOENT even though `npm` works fine at a prompt.
// Using the explicit .cmd name sidesteps that without needing shell:true (which would
// otherwise open a command-injection surface via argument string-building).
const NPM_BIN = process.platform === 'win32' ? 'npm.cmd' : 'npm';

function runCaptureJson(cmd, args, cwd, maxBuffer, opts = {}) {
  // npm audit / pip-audit both exit non-zero when vulnerabilities are found — that's
  // normal, not a failure. execFileSync throws on non-zero exit, so on throw we still
  // try to use whatever stdout the process produced before deciding it really failed.
  try {
    const out = execFileSync(cmd, args, {
      cwd,
      encoding: 'utf8',
      maxBuffer,
      windowsHide: true,
      shell: !!opts.shell,
    });
    return { ok: true, raw: out, err: null };
  } catch (err) {
    if (err && typeof err.stdout === 'string' && err.stdout.trim() !== '') {
      return { ok: true, raw: err.stdout, err };
    }
    return { ok: false, raw: null, err };
  }
}

function isCommandNotFound(err) {
  if (!err) return false;
  if (err.code === 'ENOENT') return true;
  const msg = `${err.message || ''} ${err.stderr || ''}`;
  return /not recognized as an internal or external command|command not found|no such file or directory/i.test(msg);
}

// --- npm audit --------------------------------------------------------------------------

function extractAdvisoryTitles(via) {
  if (!Array.isArray(via)) return [];
  return via
    .map((v) => (typeof v === 'string' ? v : v && v.title))
    .filter(Boolean);
}

function parseNpmAuditJson(raw, warnings) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    warnings.push(`dependencies.js: could not parse npm audit --json output: ${err.message}`);
    return [];
  }

  const vulnerabilities = parsed.vulnerabilities || {};
  const findings = [];

  for (const [pkgName, advisory] of Object.entries(vulnerabilities)) {
    const severity = advisory.severity;
    if (!NPM_SEVERITIES_TO_REPORT.has(severity)) continue;

    const titles = extractAdvisoryTitles(advisory.via);
    const rangeStr = advisory.range || 'unknown range';
    const titleText = titles.length ? titles.join('; ') : `${pkgName} has a known ${severity} severity vulnerability`;

    findings.push({
      id: makeId(CHECK_ID, [pkgName, rangeStr, severity]),
      checkId: CHECK_ID,
      severity,
      category: 'dependency',
      file: 'package.json',
      line: null,
      snippet: `${pkgName}@${rangeStr}`.slice(0, 200),
      rawMessage: `npm audit: ${titleText} (package "${pkgName}", vulnerable range ${rangeStr}, severity ${severity}).`,
    });
  }

  return findings;
}

// shell:true works around a Node/Windows quirk where spawning a .cmd file directly
// (npm.cmd) can throw EINVAL even once the ENOENT-from-missing-extension issue is
// fixed via NPM_BIN. Safe here: every arg is a fixed literal, nothing from user/repo
// input is interpolated into the command line.
const NPM_SHELL_OPT = { shell: process.platform === 'win32' };

const LOCKFILE_NAMES = ['package-lock.json', 'npm-shrinkwrap.json'];

function scanNpmAudit(repoPath, warnings) {
  const packageJsonPath = path.join(repoPath, 'package.json');
  if (!fs.existsSync(packageJsonPath)) return [];

  const hasLockfile = LOCKFILE_NAMES.some((name) => fs.existsSync(path.join(repoPath, name)));

  if (hasLockfile) {
    // A lockfile already exists — `npm audit` is read-only against it, so it's safe to
    // run directly in the target repo without touching anything.
    const result = runCaptureJson(NPM_BIN, ['audit', '--json'], repoPath, 50 * 1024 * 1024, NPM_SHELL_OPT);
    if (!result.ok) {
      if (isCommandNotFound(result.err)) {
        warnings.push('dependencies.js: npm is not available on PATH — skipped npm audit (check 10 for JS deps).');
      } else {
        warnings.push(`dependencies.js: npm audit failed to run: ${result.err ? result.err.message : 'unknown error'}`);
      }
      return [];
    }
    return parseNpmAuditJson(result.raw, warnings);
  }

  // No lockfile committed (common for a freshly-scaffolded/AI-generated project that
  // never had `npm install` run against it) — `npm audit` refuses to run at all without
  // one ("This command requires an existing lockfile"). Generate an ephemeral lockfile
  // in a throwaway temp copy of package.json rather than writing into the target repo,
  // audit against that, then clean up. Requires network access to resolve versions,
  // same as npm audit itself already requires to check advisories.
  let tempDir;
  try {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vibescan-npm-audit-'));
    fs.copyFileSync(packageJsonPath, path.join(tempDir, 'package.json'));

    const installResult = runCaptureJson(
      NPM_BIN,
      ['install', '--package-lock-only', '--no-audit', '--ignore-scripts'],
      tempDir,
      50 * 1024 * 1024,
      NPM_SHELL_OPT,
    );
    if (!installResult.ok) {
      if (isCommandNotFound(installResult.err)) {
        warnings.push('dependencies.js: npm is not available on PATH — skipped npm audit (check 10 for JS deps).');
      } else {
        warnings.push('dependencies.js: no package-lock.json in target repo, and generating a temporary one failed (likely no network access) — skipped npm audit (check 10 for JS deps).');
      }
      return [];
    }

    const auditResult = runCaptureJson(NPM_BIN, ['audit', '--json'], tempDir, 50 * 1024 * 1024, NPM_SHELL_OPT);
    if (!auditResult.ok) {
      warnings.push(`dependencies.js: npm audit failed to run against generated lockfile: ${auditResult.err ? auditResult.err.message : 'unknown error'}`);
      return [];
    }
    return parseNpmAuditJson(auditResult.raw, warnings);
  } catch (err) {
    warnings.push(`dependencies.js: could not audit package.json without a committed lockfile: ${err.message}`);
    return [];
  } finally {
    if (tempDir) {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // best-effort cleanup only — a leftover temp dir isn't worth failing the scan over
      }
    }
  }
}

// --- pip-audit --------------------------------------------------------------------------

function normalizePipAuditDeps(parsed) {
  if (Array.isArray(parsed)) return parsed;
  if (parsed && Array.isArray(parsed.dependencies)) return parsed.dependencies;
  return [];
}

function scanPipAudit(repoPath, warnings) {
  const requirementsPath = path.join(repoPath, 'requirements.txt');
  if (!fs.existsSync(requirementsPath)) return [];

  const result = runCaptureJson(
    'pip-audit',
    ['--format', 'json', '-r', 'requirements.txt'],
    repoPath,
    50 * 1024 * 1024,
  );

  if (!result.ok) {
    if (isCommandNotFound(result.err)) {
      warnings.push('dependencies.js: pip-audit is not installed — skipped check 10 for Python dependencies (requirements.txt found but not scanned).');
    } else {
      warnings.push(`dependencies.js: pip-audit failed to run: ${result.err ? result.err.message : 'unknown error'}`);
    }
    return [];
  }

  let parsed;
  try {
    parsed = JSON.parse(result.raw);
  } catch (err) {
    warnings.push(`dependencies.js: could not parse pip-audit --format json output: ${err.message}`);
    return [];
  }

  const deps = normalizePipAuditDeps(parsed);
  const findings = [];

  for (const dep of deps) {
    const vulns = Array.isArray(dep.vulns) ? dep.vulns : [];
    for (const vuln of vulns) {
      // pip-audit's default JSON output does not include a severity gradient the way
      // npm audit does — every reported vuln is a confirmed known advisory (PYSEC/CVE),
      // so we conservatively report these as "high" rather than guessing at a scale
      // pip-audit doesn't give us. Documented assumption, not a measured severity.
      const severity = 'high';
      const vulnId = vuln.id || 'unknown-id';
      const fixVersions = Array.isArray(vuln.fix_versions) ? vuln.fix_versions.join(', ') : 'none listed';

      findings.push({
        id: makeId(CHECK_ID, [dep.name, dep.version, vulnId]),
        checkId: CHECK_ID,
        severity,
        category: 'dependency',
        file: 'requirements.txt',
        line: null,
        snippet: `${dep.name}==${dep.version} (${vulnId})`.slice(0, 200),
        rawMessage: `pip-audit: ${dep.name}==${dep.version} has known advisory ${vulnId}${vuln.description ? ` — ${vuln.description}` : ''}. Fix versions: ${fixVersions}.`,
      });
    }
  }

  return findings;
}

/**
 * @param {string} repoPath
 * @param {object} [opts]
 * @returns {{ findings: object[], warnings: string[] }}
 */
function scan(repoPath, opts = {}) {
  const warnings = [];
  let findings = [];

  try {
    findings = findings.concat(scanNpmAudit(repoPath, warnings));
  } catch (err) {
    warnings.push(`dependencies.js: npm audit scan crashed: ${err.message}`);
  }

  try {
    findings = findings.concat(scanPipAudit(repoPath, warnings));
  } catch (err) {
    warnings.push(`dependencies.js: pip-audit scan crashed: ${err.message}`);
  }

  return { findings, warnings };
}

module.exports = { scan };
