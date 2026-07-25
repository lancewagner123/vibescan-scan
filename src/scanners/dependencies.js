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
const semver = require('semver');
const { makeId, walkFiles } = require('./util');

const CHECK_ID = 'vulnerable-dependency';
const NPM_SEVERITIES_TO_REPORT = new Set(['high', 'critical']);
const SEVERITY_RANK = { info: 0, low: 1, moderate: 2, high: 3, critical: 4 };

// On Windows, `npm` resolves to `npm.cmd` (a batch file) — execFileSync spawns via
// CreateProcess directly and can't launch a .cmd without going through a shell, so
// `execFileSync('npm', ...)` throws ENOENT even though `npm` works fine at a prompt.
// Using the explicit .cmd name sidesteps that without needing shell:true (which would
// otherwise open a command-injection surface via argument string-building).
const NPM_BIN = process.platform === 'win32' ? 'npm.cmd' : 'npm';

// Upper bound on any single npm/pip child process. Without it, a stalled `npm install`/
// `npm audit` on the temp-install path (slow/flaky network, huge cold-cache monorepo, a
// private-registry auth prompt) blocks the ENTIRE scan indefinitely (round-3 dependency
// stress-test, scenario 7). execFileSync throws ETIMEDOUT past this, which degrades to a
// warning like any other failure rather than hanging.
const CHILD_PROCESS_TIMEOUT_MS = 120000;

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
      // Capture stderr into the result (fd 2 = 'pipe') instead of letting execFileSync's
      // default 'inherit' splatter raw `npm error 404 ...`/`EUNSUPPORTEDPROTOCOL ...` spew
      // straight onto the user's terminal (round-3 dependency stress-test, defect A) --
      // alarming, unactionable noise for a non-technical user on any monorepo/offline run.
      // The captured stderr is still available on err.stderr for the warning-wording logic.
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: opts.timeout || CHILD_PROCESS_TIMEOUT_MS,
    });
    return { ok: true, raw: out, err: null };
  } catch (err) {
    if (err && typeof err.stdout === 'string' && err.stdout.trim() !== '') {
      return { ok: true, raw: err.stdout, err };
    }
    return { ok: false, raw: null, err };
  }
}

// The temp-install path can fail for several very different reasons that each need a
// different remediation -- the old hardcoded "(likely no network access)" message
// misattributed all of them to one cause (round-3 dependency stress-test, defect B).
// Inspect the captured stderr to name the actual cause when we can tell.
function describeInstallFailure(err) {
  const stderr = (err && typeof err.stderr === 'string') ? err.stderr : '';
  if (err && (err.signal === 'SIGTERM' || err.code === 'ETIMEDOUT')) {
    return 'the operation timed out';
  }
  if (/EUNSUPPORTEDPROTOCOL|workspace:/i.test(stderr)) {
    return 'the package uses a workspace:/internal dependency protocol that npm cannot resolve for an isolated audit (common in pnpm/yarn/Turborepo/Nx monorepos)';
  }
  if (/E404|not in this registry/i.test(stderr)) {
    return 'it references a dependency not published to the registry (e.g. an internal/workspace package resolved in isolation)';
  }
  if (/ENOTFOUND|ETIMEDOUT|EAI_AGAIN|network|getaddrinfo/i.test(stderr)) {
    return 'the registry could not be reached (likely no network access)';
  }
  if (/JSON|Unexpected|parse|EJSONPARSE/i.test(stderr)) {
    return 'the package.json could not be parsed (malformed manifest)';
  }
  return 'the cause is unknown (could be no network access, an unpublished/workspace dependency, or a malformed package.json)';
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

// Round-4 real-world validation (docs/REAL_WORLD_VALIDATION.md, "Re-validation (post-fix)",
// item 4) surfaced a genuine false-positive shape on a real repo: `npm audit`'s per-package
// entry in `vulnerabilities` aggregates EVERY advisory that has ever applied to that package
// name across its whole version history into one top-level `severity`/`range`, and
// parseNpmAuditJson() used to trust that aggregate blindly -- it never checked whether the
// package's ACTUAL resolved installed version (from the lockfile) still falls inside any of
// those advisories' own ranges. A package can appear as a `vulnerabilities` key with
// severity "high" while the specific version genuinely installed sits outside every one of
// the individual advisory ranges that produced that aggregate (npm still lists the entry
// because a *different* resolved copy elsewhere in the tree is the one that's vulnerable, or
// because of an aggregation edge case) -- reporting it anyway is exactly the "installed
// version is the patched release itself" false positive the validation exercise found.
//
// Fix: resolve the real installed version(s) for the package from the lockfile that was
// actually audited, and cross-check each advisory's own `range` string against those
// versions using semver's own range parser (correct `<` vs `<=` handling, not a hand-rolled
// string comparison that could get the boundary wrong). Only suppress a finding when this
// check can *positively confirm* non-applicability for every advisory in `via` -- if we can't
// resolve an installed version, or a range string doesn't parse, fall back to npm's own
// aggregate determination rather than risk silently dropping a real vulnerability. See
// resolveInstalledVersions() and filterApplicableAdvisories() below.

// Reads a package-lock.json/npm-shrinkwrap.json and returns a Map of package name ->
// Set of every version actually resolved for that name anywhere in the tree (a package can
// legitimately be installed at multiple versions simultaneously via nested/undeduped
// transitive copies -- e.g. brace-expansion@1.1.12 at the top level and an older
// brace-expansion@1.1.10 nested under some other dependency's own node_modules -- and ALL of
// them matter: the package is genuinely vulnerable if ANY resolved copy falls in an
// advisory's range, not just the top-level one).
function resolveInstalledVersions(lockfilePath) {
  const versionsByName = new Map();
  const addVersion = (name, version) => {
    if (!name || typeof version !== 'string' || !version) return;
    if (!versionsByName.has(name)) versionsByName.set(name, new Set());
    versionsByName.get(name).add(version);
  };

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(lockfilePath, 'utf8'));
  } catch {
    return versionsByName;
  }

  // lockfileVersion 2/3 (npm 7+): flat "packages" map keyed by node_modules path, e.g.
  // "node_modules/brace-expansion" or "node_modules/foo/node_modules/brace-expansion" for a
  // nested/undeduped copy. The package name is everything after the LAST "node_modules/"
  // segment, which correctly recovers scoped names too (node_modules/@scope/name).
  if (parsed.packages && typeof parsed.packages === 'object') {
    for (const [pkgPath, meta] of Object.entries(parsed.packages)) {
      if (!pkgPath || !meta || typeof meta.version !== 'string') continue;
      const marker = 'node_modules/';
      const idx = pkgPath.lastIndexOf(marker);
      if (idx === -1) continue;
      addVersion(pkgPath.slice(idx + marker.length), meta.version);
    }
  }

  // lockfileVersion 1 (legacy npm 5/6, still occasionally seen): nested "dependencies" tree.
  // Also present as a redundant legacy mirror alongside "packages" in v2 lockfiles, so this
  // safely runs in addition to the block above rather than instead of it.
  if (parsed.dependencies && typeof parsed.dependencies === 'object') {
    const walk = (deps) => {
      for (const [name, meta] of Object.entries(deps)) {
        if (!meta) continue;
        addVersion(name, meta.version);
        if (meta.dependencies && typeof meta.dependencies === 'object') walk(meta.dependencies);
      }
    };
    walk(parsed.dependencies);
  }

  return versionsByName;
}

// Given one advisory's `via` array and the set of versions actually resolved for this
// package, returns { applicable, confident }:
//   - confident: true only if EVERY object-shaped via entry's applicability could be
//     positively determined (its range parsed, and at least one installed version resolved).
//     False otherwise -- meaning "don't trust this narrowing, fall back to npm's aggregate."
//   - applicable: the subset of via entries that genuinely apply to a resolved installed
//     version (only meaningful when confident is true).
function filterApplicableAdvisories(viaEntries, installedVersions) {
  const objectEntries = viaEntries.filter((v) => v && typeof v === 'object');
  if (objectEntries.length === 0 || !installedVersions || installedVersions.size === 0) {
    return { applicable: objectEntries, confident: false };
  }

  const applicable = [];
  for (const entry of objectEntries) {
    if (typeof entry.range !== 'string' || !semver.validRange(entry.range)) {
      // Can't parse this advisory's range at all -- don't guess, defer to npm's aggregate.
      return { applicable: objectEntries, confident: false };
    }
    let matched = false;
    for (const rawVersion of installedVersions) {
      const version = semver.valid(rawVersion) ? rawVersion : semver.coerce(rawVersion);
      if (!version) continue;
      if (semver.satisfies(version, entry.range, { includePrerelease: true })) {
        matched = true;
        break;
      }
    }
    if (matched) applicable.push(entry);
  }

  return { applicable, confident: true };
}

function maxSeverity(entries, fallback) {
  let best = null;
  for (const entry of entries) {
    const s = entry && entry.severity;
    if (!s) continue;
    if (!best || (SEVERITY_RANK[s] || 0) > (SEVERITY_RANK[best] || 0)) best = s;
  }
  return best || fallback;
}

function parseNpmAuditJson(raw, warnings, fileForId, installedVersionsByPkg) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    warnings.push(`dependencies.js: could not parse npm audit --json output: ${err.message}`);
    return [];
  }

  const vulnerabilities = parsed.vulnerabilities || {};
  const findings = [];
  const installedVersions = installedVersionsByPkg instanceof Map ? installedVersionsByPkg : new Map();

  for (const [pkgName, advisory] of Object.entries(vulnerabilities)) {
    if (!NPM_SEVERITIES_TO_REPORT.has(advisory.severity)) continue;

    const viaEntries = Array.isArray(advisory.via) ? advisory.via : [];
    const { applicable, confident } = filterApplicableAdvisories(viaEntries, installedVersions.get(pkgName));

    // Only narrow when we could POSITIVELY confirm applicability for every object-shaped
    // advisory in `via` -- otherwise keep npm's own full aggregate (objectEntries filtered
    // out of `applicable` above are dropped only when `confident` is true; when it's false,
    // `filterApplicableAdvisories` already returns the unfiltered set).
    const usableEntries = confident ? applicable : viaEntries.filter((v) => v && typeof v === 'object');
    if (confident && applicable.length === 0) {
      // Every advisory that produced this aggregate genuinely does not apply to any version
      // of this package actually resolved in the lockfile -- e.g. the installed version is
      // the patched release itself, not one preceding it. Suppress: this is the false
      // positive shape docs/REAL_WORLD_VALIDATION.md's re-validation pass found on Vibelens
      // (brace-expansion, postcss both pinned exactly on their own fix commit).
      continue;
    }

    // Recompute severity from the entries we're actually reporting, not npm's blanket
    // top-level aggregate -- if narrowing dropped the entry that carried the worst severity,
    // the effective severity for what's left may now be lower (and could fall below the
    // high/critical threshold entirely).
    const severity = maxSeverity(usableEntries, advisory.severity);
    if (!NPM_SEVERITIES_TO_REPORT.has(severity)) continue;

    // String-shaped via entries (a transitive reference to another vulnerable package's
    // name, not an advisory object with its own range) carry no range to verify against this
    // package directly -- always keep them in the message, same as before this fix.
    const titleSource = viaEntries.filter((v) => typeof v === 'string' || usableEntries.includes(v));
    const titles = extractAdvisoryTitles(titleSource);
    const rangeStr = usableEntries.map((e) => e.range).filter(Boolean).join(' || ') || advisory.range || 'unknown range';
    const titleText = titles.length ? titles.join('; ') : `${pkgName} has a known ${severity} severity vulnerability`;

    findings.push({
      // `fileForId` (the package.json's repo-relative path) is part of the id so the SAME
      // CVE reported against two different package.json files in a workspace produces two
      // DISTINCT ids -- omitting it made both collide on one id (round-3 dependency
      // stress-test, scenario 6), contradicting makeId's own "parts that identify *this*
      // occurrence (file, line...)" contract and double-counting under heuristic triage.
      id: makeId(CHECK_ID, [fileForId, pkgName, rangeStr, severity]),
      checkId: CHECK_ID,
      severity,
      category: 'dependency',
      file: fileForId,
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

// Was: only ever checked path.join(repoPath, 'package.json') at the exact scanned root,
// with no recursive/workspace-aware search. A monorepo/workspaces layout (Turborepo, npm/
// yarn/pnpm workspaces, Nx, Lerna) with the vulnerable dependency pinned inside a nested
// package (e.g. packages/api/package.json) rather than at the repo root was therefore
// entirely unscanned, even with no package.json at the root at all. Fixed by walking the
// whole tree (reusing walkFiles's existing node_modules/.git/etc exclusions) for every
// package.json found, auditing each one from its own directory.
function findNestedPackageJsonDirs(repoPath) {
  return walkFiles(repoPath, { extensions: ['.json'] })
    .filter((f) => path.basename(f) === 'package.json')
    .map((f) => path.dirname(f));
}

function scanNpmAuditForPackageDir(pkgDir, repoPath, warnings) {
  const packageJsonPath = path.join(pkgDir, 'package.json');
  const repoRelPackageJson = path.relative(repoPath, packageJsonPath).split(path.sep).join('/');

  const lockfileName = LOCKFILE_NAMES.find((name) => fs.existsSync(path.join(pkgDir, name)));

  if (lockfileName) {
    // A lockfile already exists — `npm audit` is read-only against it, so it's safe to
    // run directly in the target directory without touching anything.
    const result = runCaptureJson(NPM_BIN, ['audit', '--json'], pkgDir, 50 * 1024 * 1024, NPM_SHELL_OPT);
    if (!result.ok) {
      if (isCommandNotFound(result.err)) {
        warnings.push('dependencies.js: npm is not available on PATH — skipped npm audit (check 10 for JS deps).');
      } else {
        warnings.push(`dependencies.js: npm audit failed to run for ${repoRelPackageJson}: ${result.err ? result.err.message : 'unknown error'}`);
      }
      return [];
    }
    const installedVersions = resolveInstalledVersions(path.join(pkgDir, lockfileName));
    return parseNpmAuditJson(result.raw, warnings, repoRelPackageJson, installedVersions);
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
        warnings.push(`dependencies.js: no lockfile for ${repoRelPackageJson}, and generating a temporary one failed — ${describeInstallFailure(installResult.err)}. Skipped npm audit for this package.`);
      }
      return [];
    }

    const auditResult = runCaptureJson(NPM_BIN, ['audit', '--json'], tempDir, 50 * 1024 * 1024, NPM_SHELL_OPT);
    if (!auditResult.ok) {
      warnings.push(`dependencies.js: npm audit failed to run against generated lockfile for ${repoRelPackageJson}: ${auditResult.err ? auditResult.err.message : 'unknown error'}`);
      return [];
    }
    const installedVersions = resolveInstalledVersions(path.join(tempDir, 'package-lock.json'));
    return parseNpmAuditJson(auditResult.raw, warnings, repoRelPackageJson, installedVersions);
  } catch (err) {
    warnings.push(`dependencies.js: could not audit ${repoRelPackageJson} without a committed lockfile: ${err.message}`);
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

function scanNpmAudit(repoPath, warnings) {
  const pkgDirs = new Set();
  if (fs.existsSync(path.join(repoPath, 'package.json'))) pkgDirs.add(repoPath);
  for (const dir of findNestedPackageJsonDirs(repoPath)) pkgDirs.add(dir);
  if (pkgDirs.size === 0) return [];

  let findings = [];
  for (const pkgDir of pkgDirs) {
    findings = findings.concat(scanNpmAuditForPackageDir(pkgDir, repoPath, warnings));
  }
  return findings;
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

// parseNpmAuditJson, describeInstallFailure, and resolveInstalledVersions are exported for
// deterministic, network-free regression tests (the scenario-6 id-collision fix, the defect-B
// warning-attribution fix, and the round-4 version-boundary fix) -- the full scan path needs
// npm + network, which is too flaky to assert on directly.
module.exports = { scan, parseNpmAuditJson, describeInstallFailure, resolveInstalledVersions };
