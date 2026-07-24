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
  if (triageOutput && triageOutput.degraded) {
    lines.push(
      '> _Generated using VibeScan\'s deterministic rule-based triage (no LLM was available). ' +
      'Findings are still accurate; wording is templated rather than model-generated._'
    );
    lines.push('');
  }

  if (total === 0) {
    lines.push('No issues found.');
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

  return lines.join('\n');
}

module.exports = {
  renderMarkdown,
  renderTerminalSummary,
};
