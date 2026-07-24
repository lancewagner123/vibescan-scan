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
// vulnerability open, or can break legitimate access. This list is render-level and does
// not depend on the model remembering or restating anything.
const HIGH_RISK_FIX_CHECK_IDS = new Set([
  'missing-auth-middleware',
  'supabase-rls-disabled',
  'sql-string-concatenation',
  'stripe-webhook-unverified',
]);

const SCOPE_DISCLAIMER =
  '_VibeScan checks for 10 specific, high-signal static-analysis patterns only — not a ' +
  'full security audit, not dynamic testing, no compliance coverage. See SECURITY_SCOPE.md._';

const TERMINAL_SCOPE_NOTE = '(VibeScan checks 10 known patterns only — not a full audit. See SECURITY_SCOPE.md.)';

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

  if (total === 0) {
    lines.push('No issues found among VibeScan\'s 10 static checks.');
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

  const lines = [];

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
