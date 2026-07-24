'use strict';

// Renders a Triage Output Schema object (docs/FINDINGS_SCHEMA.md) into:
//   (a) a full Markdown report, grouped by severity, one section per finding
//   (b) a short terminal-friendly summary string (counts by severity + top 3 titles)
//
// Pure, synchronous, no I/O -- callers (src/index.js, bin/vibescan.js) decide what to
// do with the returned strings (print them, write them to disk, etc.).

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

const SEVERITY_LABELS = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

// checkIds whose suggested fixes get an extra, stronger warning beyond the generic
// "unreviewed, verify before applying" note every fix gets. Per docs/CHECK_CATALOG.md /
// docs/FINDINGS_SCHEMA.md's category field: missing-auth-middleware and
// supabase-rls-disabled are both category "authz"; sql-string-concatenation and
// stripe-webhook-unverified are named explicitly because an incomplete fix in either can
// *look* successful (still-injectable SQL hidden inside a quoted literal; a webhook
// handler that now calls something but not the real signature check) while leaving the
// vulnerability open, or can break legitimate access. mass-assignment (check 13, added in
// v0.2.0) joins this list for the same underlying reason as the authz checks above: an
// attacker who can mass-assign arbitrary fields onto a model (isAdmin, role, verified,
// balance) is exploiting a privilege-escalation/access-control gap, not a plain data-shape
// bug, and an incomplete fix (e.g. an allowlist that misses one sensitive field) can look
// like it closed the hole while leaving exactly that field still overwritable.
// weak-password-hashing (check 12) joins this list for the same "looks successful but
// isn't" shape as sql-string-concatenation/stripe-webhook-unverified: a diff that swaps
// the hash-creation call (e.g. crypto.createHash('md5') -> bcrypt.hash) only touches the
// snippet the fix generator can see, not the corresponding login/verify code path
// elsewhere in the file or codebase that still compares against the old hash format —
// an incomplete fix here can look like it closed the hole while login silently breaks or
// still accepts the weak hash. insecure-random-token (check 11) joins for the same
// reason plus its own auth-adjacent angle: the values this check flags (session ids,
// password-reset tokens, API keys, CSRF nonces) are themselves part of an
// authentication/access-control mechanism, so swapping in crypto.randomBytes/randomUUID
// without checking every place that consumes the old token's length/encoding/format
// assumptions can silently break session/reset/CSRF flows elsewhere in the codebase.
// This list is render-level and does not depend on the model remembering or restating
// anything.
const HIGH_RISK_FIX_CHECK_IDS = new Set([
  'missing-auth-middleware',
  'supabase-rls-disabled',
  'sql-string-concatenation',
  'stripe-webhook-unverified',
  'mass-assignment',
  'weak-password-hashing',
  'insecure-random-token',
]);

const SCOPE_DISCLAIMER =
  '_VibeScan checks for 15 specific, high-signal static-analysis patterns only — not a ' +
  'full security audit, not dynamic testing, no compliance coverage. See SECURITY_SCOPE.md._';

const TERMINAL_SCOPE_NOTE = '(VibeScan checks 15 known patterns only — not a full audit. See SECURITY_SCOPE.md.)';

/**
 * @param {{summary?: object, findings?: object[]}} triageOutput
 * @returns {{critical:number, high:number, medium:number, low:number}}
 */
function getSummary(triageOutput) {
  const summary = (triageOutput && triageOutput.summary) || {};
  const result = {};
  for (const level of SEVERITY_ORDER) {
    result[level] = typeof summary[level] === 'number' ? summary[level] : 0;
  }
  return result;
}

function groupBySeverity(findings) {
  const groups = { critical: [], high: [], medium: [], low: [] };
  for (const finding of findings) {
    const severity = groups[finding.severity] ? finding.severity : 'low';
    groups[severity].push(finding);
  }
  return groups;
}

/**
 * Render a Markdown "Warnings" section for anything a scanner module reported via its
 * `warnings` array (e.g. a check that had to be skipped) — kept visually prominent (its
 * own heading, right under the top-of-report disclaimer) rather than folded into a
 * footnote, since a skipped check can mean "no issues found" is misleading, not reassuring.
 *
 * @param {string[]} warnings
 * @returns {string} Markdown, or '' if there are no warnings.
 */
function renderWarningsMarkdown(warnings) {
  if (!Array.isArray(warnings) || warnings.length === 0) return '';
  const lines = [];
  lines.push('## ⚠ Warnings');
  lines.push('');
  lines.push(
    '_One or more checks did not run at full scope this scan. Read these before treating ' +
    'the findings below (or their absence) as complete:_'
  );
  lines.push('');
  for (const warning of warnings) {
    lines.push(`- ${warning}`);
  }
  lines.push('');
  return lines.join('\n');
}

function formatLocation(finding) {
  if (finding.line === null || finding.line === undefined) return finding.file;
  return `${finding.file}:${finding.line}`;
}

function renderFindingSection(finding, index) {
  const lines = [];
  lines.push(`### ${index}. ${finding.title}`);
  lines.push('');
  lines.push(`- **Severity:** ${SEVERITY_LABELS[finding.severity] || finding.severity}`);
  lines.push(`- **Location:** \`${formatLocation(finding)}\``);
  lines.push(`- **Source check(s):** ${finding.sourceCheckIds.join(', ')}`);
  lines.push('');
  lines.push(`**What's wrong:** ${finding.explanation}`);
  lines.push('');
  lines.push(`**Attacker impact:** ${finding.attackerImpact}`);
  lines.push('');
  lines.push(`**Suggested fix:** ${finding.fix.description}`);
  if (finding.fix.diff) {
    const isHighRisk = (finding.sourceCheckIds || []).some((id) => HIGH_RISK_FIX_CHECK_IDS.has(id));
    lines.push('');
    lines.push(
      '**⚠ Suggested diff — unreviewed, verify before applying.** VibeScan never applies ' +
      'this for you; a human must read it, confirm it actually fixes the issue in the ' +
      'context of the real codebase, and apply it by hand.'
    );
    if (isHighRisk) {
      lines.push('');
      lines.push(
        '**⚠ This fix touches authentication/access-control or injection-prevention ' +
        'logic.** An incomplete or subtly wrong fix here can look successful while ' +
        'leaving the vulnerability open, or can break legitimate access. A human who ' +
        'understands this codebase must review and test this change before merging.'
      );
    }
    lines.push('');
    lines.push('```diff');
    lines.push(finding.fix.diff.replace(/\n+$/, ''));
    lines.push('```');
  }
  return lines.join('\n');
}

/**
 * Render a full Markdown security report from a Triage Output Schema object.
 *
 * @param {object} triageOutput - matches the Triage Output Schema in docs/FINDINGS_SCHEMA.md
 * @returns {string} Markdown report text
 */
function renderMarkdown(triageOutput) {
  const findings = (triageOutput && Array.isArray(triageOutput.findings)) ? triageOutput.findings : [];
  const summary = getSummary(triageOutput);
  const total = SEVERITY_ORDER.reduce((sum, level) => sum + summary[level], 0);
  const groups = groupBySeverity(findings);

  const lines = [];
  lines.push('# VibeScan Security Report');
  lines.push('');
  lines.push(SCOPE_DISCLAIMER);
  lines.push('');
  if (triageOutput && triageOutput.degraded) {
    lines.push(
      '> _Generated using VibeScan\'s deterministic rule-based triage (no LLM was available). ' +
      'Findings are still accurate; wording is templated rather than model-generated._'
    );
    lines.push('');
  }

  const warningsMarkdown = renderWarningsMarkdown(triageOutput && triageOutput.warnings);
  if (warningsMarkdown) {
    lines.push(warningsMarkdown);
  }

  if (total === 0) {
    lines.push('No issues found among VibeScan\'s 15 static checks.');
    lines.push('');
    lines.push(
      'This does not mean your app is secure — VibeScan only looks for a fixed, narrow ' +
      'catalog of known mistakes (see docs/CHECK_CATALOG.md and SECURITY_SCOPE.md). It ' +
      'does not run your app, does not test business logic, and makes no compliance claim.'
    );
    return lines.join('\n') + '\n';
  }

  lines.push('## Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('| --- | --- |');
  for (const level of SEVERITY_ORDER) {
    lines.push(`| ${SEVERITY_LABELS[level]} | ${summary[level]} |`);
  }
  lines.push(`| **Total** | **${total}** |`);
  lines.push('');

  for (const level of SEVERITY_ORDER) {
    const group = groups[level];
    if (group.length === 0) continue;
    lines.push(`## ${SEVERITY_LABELS[level]} (${group.length})`);
    lines.push('');
    group.forEach((finding, i) => {
      lines.push(renderFindingSection(finding, i + 1));
      lines.push('');
    });
  }

  return lines.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd() + '\n';
}

/**
 * Render a short terminal-friendly summary: counts by severity, plus the titles of the
 * top 3 findings (ranked by severity, most severe first; ties keep original order).
 *
 * @param {object} triageOutput - matches the Triage Output Schema in docs/FINDINGS_SCHEMA.md
 * @returns {string}
 */
function renderTerminalSummary(triageOutput) {
  const findings = (triageOutput && Array.isArray(triageOutput.findings)) ? triageOutput.findings : [];
  const summary = getSummary(triageOutput);
  const total = SEVERITY_ORDER.reduce((sum, level) => sum + summary[level], 0);
  const warnings = (triageOutput && Array.isArray(triageOutput.warnings)) ? triageOutput.warnings : [];

  const lines = [];

  // Printed first and unconditionally (even on the "no issues found" path below) — a
  // skipped check can be exactly why nothing was found, so it must not read as an
  // afterthought or get lost after a reassuring "no issues" line.
  if (warnings.length > 0) {
    lines.push('⚠ WARNINGS:');
    for (const warning of warnings) {
      lines.push(`  - ${warning}`);
    }
    lines.push('');
  }

  if (total === 0) {
    lines.push('VibeScan: no issues found.');
    lines.push(TERMINAL_SCOPE_NOTE);
    return lines.join('\n');
  }

  const countsStr = SEVERITY_ORDER
    .filter((level) => summary[level] > 0)
    .map((level) => `${summary[level]} ${SEVERITY_LABELS[level].toLowerCase()}`)
    .join(', ');

  lines.push(`VibeScan found ${total} issue${total === 1 ? '' : 's'}: ${countsStr}.`);

  const rank = { critical: 4, high: 3, medium: 2, low: 1 };
  const top3 = findings
    .map((finding, i) => ({ finding, i }))
    .sort((a, b) => {
      const diff = (rank[b.finding.severity] || 0) - (rank[a.finding.severity] || 0);
      return diff !== 0 ? diff : a.i - b.i;
    })
    .slice(0, 3)
    .map(({ finding }) => finding);

  if (top3.length > 0) {
    lines.push('');
    lines.push('Top findings:');
    for (const finding of top3) {
      lines.push(`  [${SEVERITY_LABELS[finding.severity] || finding.severity}] ${finding.title} (${formatLocation(finding)})`);
    }
  }

  if (triageOutput && triageOutput.degraded) {
    lines.push('');
    lines.push('(deterministic rule-based triage -- no LLM was available)');
  }

  lines.push('');
  lines.push(TERMINAL_SCOPE_NOTE);

  return lines.join('\n');
}

module.exports = {
  renderMarkdown,
  renderTerminalSummary,
};
