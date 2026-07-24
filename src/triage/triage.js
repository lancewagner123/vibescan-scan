'use strict';

const { SYSTEM_PROMPT, buildUserMessage } = require('./prompt');

const DEFAULT_MODEL = 'claude-sonnet-5';
const DEFAULT_MAX_TOKENS = 4096;
// "fail after one retry" -> two total attempts against the API before falling back.
const DEFAULT_MAX_RETRIES = 1;

const VALID_OUTPUT_SEVERITIES = ['critical', 'high', 'medium', 'low'];

// Raw Finding severities (docs/FINDINGS_SCHEMA.md) include "info", which has no
// equivalent slot in the Triage Output Schema's severity enum — it collapses to "low".
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function rankToOutputSeverity(rank) {
  if (rank >= SEVERITY_RANK.critical) return 'critical';
  if (rank === SEVERITY_RANK.high) return 'high';
  if (rank === SEVERITY_RANK.medium) return 'medium';
  return 'low'; // rank 1 ("low") and rank 0 ("info") both collapse to "low"
}

/**
 * Compute { critical, high, medium, low } counts from a list of already-finalized
 * triage findings (i.e. findings whose .severity has already been validated/enforced).
 *
 * @param {object[]} findings
 * @returns {{critical:number, high:number, medium:number, low:number}}
 */
function computeSummary(findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    summary[finding.severity] += 1;
  }
  return summary;
}

/**
 * Validate that `output` matches the Triage Output Schema in docs/FINDINGS_SCHEMA.md
 * exactly, at the structural/type level. Throws a single Error listing every problem
 * found (not just the first) if anything doesn't match — this function is the "throw a
 * clear error if the model's JSON doesn't match, don't silently pass through" contract
 * called for by the build instructions. It does NOT know about the original raw
 * findings; cross-checking severities/coverage against those happens separately in
 * reconcileWithSource(), because that step needs the raw findings and this one doesn't.
 *
 * @param {*} output
 * @throws {Error} if output does not match the schema
 */
function validateTriageOutputShape(output) {
  const errors = [];

  if (!output || typeof output !== 'object' || Array.isArray(output)) {
    throw new Error('Triage output must be a JSON object matching the Triage Output Schema.');
  }

  if (!output.summary || typeof output.summary !== 'object' || Array.isArray(output.summary)) {
    errors.push('summary must be an object with critical/high/medium/low number fields');
  } else {
    for (const key of VALID_OUTPUT_SEVERITIES) {
      const value = output.summary[key];
      if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
        errors.push(`summary.${key} must be a non-negative integer`);
      }
    }
  }

  if (!Array.isArray(output.findings)) {
    errors.push('findings must be an array');
  } else {
    output.findings.forEach((finding, i) => {
      const p = `findings[${i}]`;
      if (!finding || typeof finding !== 'object' || Array.isArray(finding)) {
        errors.push(`${p} must be an object`);
        return;
      }
      if (typeof finding.title !== 'string' || finding.title.trim() === '') {
        errors.push(`${p}.title must be a non-empty string`);
      }
      if (!VALID_OUTPUT_SEVERITIES.includes(finding.severity)) {
        errors.push(`${p}.severity must be one of: ${VALID_OUTPUT_SEVERITIES.join(', ')} (got ${JSON.stringify(finding.severity)})`);
      }
      if (typeof finding.explanation !== 'string' || finding.explanation.trim() === '') {
        errors.push(`${p}.explanation must be a non-empty string`);
      }
      if (typeof finding.attackerImpact !== 'string' || finding.attackerImpact.trim() === '') {
        errors.push(`${p}.attackerImpact must be a non-empty string`);
      }
      if (typeof finding.file !== 'string' || finding.file === '') {
        errors.push(`${p}.file must be a non-empty string`);
      }
      if (!(finding.line === null || typeof finding.line === 'number')) {
        errors.push(`${p}.line must be a number or null`);
      }
      if (!finding.fix || typeof finding.fix !== 'object' || Array.isArray(finding.fix)) {
        errors.push(`${p}.fix must be an object with description/diff fields`);
      } else {
        if (typeof finding.fix.description !== 'string') {
          errors.push(`${p}.fix.description must be a string`);
        }
        if (!(finding.fix.diff === null || typeof finding.fix.diff === 'string')) {
          errors.push(`${p}.fix.diff must be a string or null`);
        }
      }
      if (
        !Array.isArray(finding.sourceCheckIds) ||
        finding.sourceCheckIds.length === 0 ||
        !finding.sourceCheckIds.every((c) => typeof c === 'string' && c !== '')
      ) {
        errors.push(`${p}.sourceCheckIds must be a non-empty array of non-empty strings`);
      }
    });
  }

  if (errors.length > 0) {
    throw new Error(`Triage output failed schema validation:\n  - ${errors.join('\n  - ')}`);
  }
}

/**
 * SECURITY-CRITICAL: reconcile the model's output against the ORIGINAL raw findings.
 *
 * This is the code-level half of the prompt-injection defense described in prompt.js.
 * It does two things, neither of which trusts anything the model said beyond the shape
 * already validated by validateTriageOutputShape():
 *
 *   1. For every output finding, recompute its severity from the scanner-assigned
 *      severities of the raw findings referenced in its sourceCheckIds (taking the
 *      highest/most-severe among them), and OVERWRITE whatever severity the model
 *      chose. The model's stated severity is advisory at best and is never used
 *      directly in the returned result.
 *   2. Verify that every distinct checkId present in the raw findings is referenced by
 *      at least one output finding's sourceCheckIds — i.e. no category of finding was
 *      silently dropped. If the model referenced a sourceCheckIds value that doesn't
 *      correspond to any raw finding (hallucinated, or copied from injected content),
 *      that's treated as invalid output and throws, triggering the retry/fallback path
 *      in triage() rather than being trusted.
 *
 * Mutates `output` in place (overwriting finding.severity and output.summary) and
 * returns it for convenience.
 *
 * @param {object} output - already shape-validated via validateTriageOutputShape
 * @param {object[]} rawFindings - the original raw Findings passed in to triage()
 * @returns {object} output, mutated
 * @throws {Error} if the model referenced a checkId not present in rawFindings, or if
 *   any raw finding's checkId is not represented in the output at all
 */
function reconcileWithSource(output, rawFindings) {
  const checkIdMaxRank = new Map();
  const allInputCheckIds = new Set();

  for (const raw of rawFindings) {
    allInputCheckIds.add(raw.checkId);
    const rank = SEVERITY_RANK[raw.severity] ?? SEVERITY_RANK.info;
    const prevRank = checkIdMaxRank.get(raw.checkId);
    if (prevRank === undefined || rank > prevRank) {
      checkIdMaxRank.set(raw.checkId, rank);
    }
  }

  const coveredCheckIds = new Set();

  for (const finding of output.findings) {
    let maxRank = -1;
    for (const checkId of finding.sourceCheckIds) {
      if (!checkIdMaxRank.has(checkId)) {
        throw new Error(
          `Model output referenced sourceCheckIds entry ${JSON.stringify(checkId)} which does not match ` +
          'the checkId of any raw finding that was provided. Refusing to trust unverifiable model output ' +
          '(this is exactly the kind of thing prompt-injected content could try to produce).'
        );
      }
      coveredCheckIds.add(checkId);
      maxRank = Math.max(maxRank, checkIdMaxRank.get(checkId));
    }
    // Overwrite the model's severity claim unconditionally. See the function docstring.
    finding.severity = rankToOutputSeverity(maxRank);
  }

  const missingCheckIds = [...allInputCheckIds].filter((c) => !coveredCheckIds.has(c));
  if (missingCheckIds.length > 0) {
    throw new Error(
      `Model output dropped finding(s) for checkId(s): ${missingCheckIds.join(', ')}. ` +
      'Every raw finding must be represented in the output — refusing to return output that ' +
      'silently omits findings.'
    );
  }

  output.summary = computeSummary(output.findings);
  return output;
}

/**
 * Strip an optional markdown code fence and parse the remaining text as JSON.
 *
 * @param {string} text
 * @returns {*}
 * @throws {Error} with a clear message if the text is not valid JSON
 */
function parseModelJSON(text) {
  let cleaned = String(text).trim();
  const fenceMatch = cleaned.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  if (fenceMatch) {
    cleaned = fenceMatch[1].trim();
  }
  try {
    return JSON.parse(cleaned);
  } catch (err) {
    throw new Error(`Model output was not valid JSON (${err.message}). Raw output began with: ${cleaned.slice(0, 200)}`);
  }
}

/**
 * Call the Anthropic Messages API once and return the raw text of the model's response.
 * The @anthropic-ai/sdk package is required lazily, right here, so that the fallback
 * (no-API-key) path in triage() never needs the package to be installed or reachable —
 * per the build requirement that the fallback path "must work standalone and must not
 * require network access."
 *
 * @param {object} params
 * @param {object[]} params.findings
 * @param {string} params.apiKey
 * @param {string} params.model
 * @param {number} params.maxTokens
 * @returns {Promise<string>}
 */
async function callAnthropic({ findings, apiKey, model, maxTokens }) {
  // eslint-disable-next-line global-require -- intentionally lazy, see docstring above
  const Anthropic = require('@anthropic-ai/sdk');
  const client = new Anthropic({ apiKey });

  const response = await client.messages.create({
    model,
    max_tokens: maxTokens,
    system: SYSTEM_PROMPT,
    messages: [{ role: 'user', content: buildUserMessage(findings) }],
  });

  const textBlock = (response.content || []).find((block) => block.type === 'text');
  if (!textBlock || typeof textBlock.text !== 'string' || textBlock.text.trim() === '') {
    throw new Error('Model response contained no text content to parse as JSON.');
  }
  return textBlock.text;
}

// --- Deterministic, no-LLM fallback --------------------------------------------------

/**
 * Short, genuinely useful plain-English templates keyed by checkId, used when there is
 * no LLM available (see ruleBasedFallback below). Every checkId in docs/CHECK_CATALOG.md
 * has an entry. These intentionally do NOT attempt to generate a diff — a generic,
 * out-of-context template has no business guessing at a code change, so fix.diff is
 * always null in this path; only fix.description gives generic remediation guidance.
 */
const CANNED_TEMPLATES = {
  'secret-hardcoded-generic': {
    title: 'A secret API key or credential is hardcoded in your code',
    explanation:
      'We found a string in your code that matches the pattern of a real API key, access token, or private key ' +
      '(things like AWS keys, Stripe keys, or Slack tokens). Hardcoded secrets get committed to your repository ' +
      'and can end up anywhere the code goes — a public GitHub repo, a teammate\'s laptop, a CI log.',
    attackerImpact:
      'Anyone who can read this file — including anyone who finds the repo, a leaked ZIP, or an old commit — can ' +
      'copy this key and use it as if they were you: draining your cloud bill, sending emails from your account, ' +
      'or reading your database. This is one of the most common ways real apps get breached.',
    fixDescription:
      'Move the secret into an environment variable (or your host\'s secrets manager) and read it via ' +
      'process.env / os.environ at runtime instead of writing it in the file. Then revoke and rotate the exposed ' +
      'key immediately — removing it from the current file does not undo the exposure if it was ever pushed to git.',
  },
  'secret-env-committed': {
    title: 'A .env file with secrets is checked into git',
    explanation:
      'A file like .env, .env.local, or .env.production — the kind of file meant to hold local secrets — is ' +
      'tracked by git, either right now or at some point in the past. That means its contents (API keys, ' +
      'database passwords, etc.) are stored in your repository\'s history.',
    attackerImpact:
      'Anyone with read access to the repository (including anyone it\'s ever been shared with, or a public ' +
      'fork) can read every secret in that file, even ones you\'ve since "removed" — git keeps history. This is ' +
      'one of the most common causes of real-world credential leaks.',
    fixDescription:
      'Add the file to .gitignore, remove it from git tracking with `git rm --cached <file>`, and rotate every ' +
      'secret it contained. Deleting it from the latest commit does not remove it from history, so any leaked ' +
      'value must be treated as compromised.',
  },
  'secret-git-history': {
    title: 'A secret was committed to git history, even though it\'s not in the code now',
    explanation:
      'We found what looks like a real credential in an old commit. It may have been deleted from the current ' +
      'version of the file, but git keeps every version by default, so the secret is still retrievable by ' +
      'anyone with a copy of the repository.',
    attackerImpact:
      'Deleting a line and committing again does not erase it — anyone who clones the repository gets the full ' +
      'history, including the deleted secret. An attacker (or an automated secret-scanning bot — many exist) can ' +
      'pull it straight out of `git log -p`.',
    fixDescription:
      'Treat this credential as permanently compromised and rotate it right away. Removing it from history ' +
      '(e.g. with git-filter-repo or the BFG Repo-Cleaner) only helps going forward — it does not undo any ' +
      'exposure that has already happened, especially if the repo was ever public or forked.',
  },
  'sql-string-concatenation': {
    title: 'A database query is built by pasting a variable directly into the SQL string',
    explanation:
      'Instead of using a parameterized query (the safe way to include a value in SQL), this code builds the ' +
      'query by concatenating a variable straight into the SQL text. That opens the door to SQL injection — a ' +
      'decades-old, very well understood class of vulnerability.',
    attackerImpact:
      'An attacker who controls that variable — often something as simple as a form field, URL parameter, or ' +
      'search box — can inject their own SQL: reading every row in your database, bypassing login entirely, or ' +
      'in the worst case deleting or modifying data.',
    fixDescription:
      'Use your database driver\'s parameterized query / prepared statement feature (e.g. `?` or `$1` ' +
      'placeholders with pg/mysql, or an ORM\'s query builder) instead of building the SQL string yourself. ' +
      'Never interpolate a variable directly into a raw SQL string.',
  },
  'eval-on-input': {
    title: 'User-controlled input is passed to eval(), new Function(), or a shell command',
    explanation:
      'This code takes a variable and interpolates it directly into eval(), new Function(), or a shell command ' +
      '(exec/execSync). Those run whatever text they\'re given as real code or a real shell command.',
    attackerImpact:
      'If an attacker can influence that variable at all, they can run arbitrary code on your server — read ' +
      'your files, steal your other secrets, install malware, or use your server to attack other systems. This ' +
      'is typically a full remote-code-execution vulnerability, one of the most severe classes there is.',
    fixDescription:
      'Avoid eval/new Function/exec entirely for anything derived from user input. If you need dynamic ' +
      'behavior, use a safe, explicit alternative — a lookup table of allowed operations, a proper templating ' +
      'library, or execFile with a fixed argument list instead of a shell string.',
  },
  'cors-wildcard-with-credentials': {
    title: 'Your API allows requests from any website while also allowing credentials',
    explanation:
      'CORS is configured with the origin set to \'*\' (any website) at the same time credentials ' +
      '(cookies/auth headers) are allowed. Browsers normally block this exact combination for good reason, and ' +
      'some setups work around that in ways that quietly defeat the protection.',
    attackerImpact:
      'Any malicious website a logged-in user visits can make authenticated requests to your API on that user\'s ' +
      'behalf and read the response — silently stealing their data or performing actions as them, with the user ' +
      'never knowing.',
    fixDescription:
      'Replace the wildcard with an explicit allowlist of the specific origins that should be allowed to make ' +
      'credentialed requests, and only enable credentials for those origins.',
  },
  'missing-auth-middleware': {
    title: 'An admin or internal-looking page has no visible login check',
    explanation:
      'This route looks like it\'s meant for administrators or internal use only (the path contains something ' +
      'like /admin, /internal, or /_debug), but we couldn\'t find any authentication or session check guarding ' +
      'it or its middleware chain.',
    attackerImpact:
      'If this route really has no auth check, anyone who guesses or finds the URL — which is often trivial, ' +
      'since admin paths are commonly scanned for on the internet — gets the same access an administrator ' +
      'would, with no login required.',
    fixDescription:
      'Add an authentication/authorization check (a session check, an auth middleware, or a role check) at the ' +
      'very top of this route handler, or apply it via your framework\'s route-group / middleware mechanism, ' +
      'before it does anything else.',
  },
  'supabase-rls-disabled': {
    title: 'A Supabase table has Row Level Security disabled (or the service-role key is exposed to the client)',
    explanation:
      'Supabase\'s Row Level Security (RLS) is what stops one user from reading or editing another user\'s rows ' +
      'directly through the API. We found either a table with RLS turned off, or the powerful service_role key ' +
      'referenced from client-side code — both bypass Supabase\'s normal per-row access rules.',
    attackerImpact:
      'With RLS off (or the service key exposed to the browser), anyone who can call your Supabase API — which ' +
      'is often anyone on the internet, since that API is public by default — can read or modify every row in ' +
      'that table, not just their own.',
    fixDescription:
      'Enable Row Level Security on the table and write policies that scope access to each row\'s owner (e.g. ' +
      '`auth.uid() = user_id`). Never reference the service_role key anywhere that ships to the browser — it ' +
      'belongs only in trusted server-side code.',
  },
  'stripe-webhook-unverified': {
    title: 'A Stripe webhook endpoint doesn\'t verify the request actually came from Stripe',
    explanation:
      'This webhook handler processes incoming Stripe events (like "payment succeeded") without first calling ' +
      'stripe.webhooks.constructEvent to verify the request\'s signature. Without that check, the endpoint will ' +
      'trust any request that looks like a Stripe event, from anyone.',
    attackerImpact:
      'An attacker who finds this endpoint\'s URL can send a fake "payment succeeded" event directly, tricking ' +
      'your app into granting paid access, shipping an order, or unlocking a feature — without ever actually ' +
      'paying.',
    fixDescription:
      'Call `stripe.webhooks.constructEvent(payload, signatureHeader, endpointSecret)` at the very start of the ' +
      'handler and reject the request if verification fails, before trusting or acting on any of the event\'s ' +
      'contents.',
  },
  'vulnerable-dependency': {
    title: 'One of your dependencies has a known high/critical security vulnerability',
    explanation:
      '`npm audit` (or pip-audit) reports that a package your project depends on has a publicly known ' +
      'vulnerability (CVE) rated high or critical severity. This is a documented issue in the package itself, ' +
      'not in your own code.',
    attackerImpact:
      'Depending on the specific CVE, an attacker could exploit this to run code on your server, read data they ' +
      'shouldn\'t, or crash your application — and because the vulnerability is public, it\'s often actively ' +
      'scanned for and exploited automatically at scale.',
    fixDescription:
      'Run `npm audit fix` (or update the specific package to the patched version named in the audit output) ' +
      'and re-test. If no fixed version exists yet, check whether the vulnerable code path is actually reachable ' +
      'in your usage and consider a temporary workaround or an alternative package.',
  },
};

/**
 * Fallback template for a checkId this file doesn't have a canned entry for (e.g. a
 * future check added to CHECK_CATALOG.md without an update here). Keeps the fallback
 * path from crashing on an unrecognized checkId; still produces valid, honest output.
 *
 * @param {string} checkId
 */
function genericTemplate(checkId) {
  return {
    title: `Potential issue detected (${checkId})`,
    explanation:
      `Our scanner flagged this using the "${checkId}" check, but no plain-English template exists yet for ` +
      'this specific check in the current build. Treat this as a signal to investigate manually.',
    attackerImpact:
      'Impact depends on the specific issue — review the raw scanner message and code snippet directly to ' +
      'assess it.',
    fixDescription:
      'No automated fix guidance is available yet for this check; consult the code snippet and raw scanner ' +
      'message to determine an appropriate remediation.',
  };
}

/**
 * Deterministic, rule-based triage used when no LLM is available (no API key configured)
 * or the LLM path failed even after a retry. Groups raw findings that share the same
 * checkId and file into a single triage finding (a lightweight, no-LLM approximation of
 * "consolidate related findings"), and fills in each finding's plain-English fields from
 * CANNED_TEMPLATES. Always sets `degraded: true` at the top level so callers can tell
 * they got this path rather than a full LLM triage.
 *
 * This path never calls the network and never requires @anthropic-ai/sdk to be
 * installed or reachable.
 *
 * @param {object[]} findings - raw Findings matching docs/FINDINGS_SCHEMA.md
 * @returns {object} a Triage Output Schema object with degraded: true
 */
function ruleBasedFallback(findings) {
  const groups = new Map(); // key: `${checkId}::${file}` -> { checkId, file, lines: number[], maxRank: number }

  for (const raw of findings) {
    const key = `${raw.checkId}::${raw.file}`;
    let group = groups.get(key);
    if (!group) {
      group = { checkId: raw.checkId, file: raw.file, lines: [], maxRank: SEVERITY_RANK.info };
      groups.set(key, group);
    }
    if (typeof raw.line === 'number' && !group.lines.includes(raw.line)) {
      group.lines.push(raw.line);
    }
    const rank = SEVERITY_RANK[raw.severity] ?? SEVERITY_RANK.info;
    if (rank > group.maxRank) group.maxRank = rank;
  }

  const outputFindings = [];
  for (const group of groups.values()) {
    const template = CANNED_TEMPLATES[group.checkId] || genericTemplate(group.checkId);
    group.lines.sort((a, b) => a - b);
    const line = group.lines.length > 0 ? group.lines[0] : null;
    const extraLines = group.lines.length > 1 ? ` (also seen at line(s): ${group.lines.slice(1).join(', ')})` : '';

    outputFindings.push({
      title: template.title,
      severity: rankToOutputSeverity(group.maxRank),
      explanation: template.explanation + extraLines,
      attackerImpact: template.attackerImpact,
      file: group.file,
      line,
      fix: { description: template.fixDescription, diff: null },
      sourceCheckIds: [group.checkId],
    });
  }

  const result = {
    summary: computeSummary(outputFindings),
    findings: outputFindings,
    degraded: true,
  };

  // Defensive: validate our own deterministic output before returning it. This should
  // always pass — if it doesn't, that's a bug in this function, not bad input, and it's
  // better to throw loudly here than to silently hand render.js something malformed.
  validateTriageOutputShape(result);
  return result;
}

/**
 * Triage an array of raw Findings into the plain-English Triage Output Schema.
 *
 * Behavior:
 *  - If `findings` is empty, returns an empty (non-degraded) result without calling
 *    anything.
 *  - If ANTHROPIC_API_KEY (or opts.apiKey) is not set, falls back to a deterministic,
 *    rule-based triage (see ruleBasedFallback) — no network access, no LLM.
 *  - Otherwise calls the Anthropic API, validates + reconciles the model's JSON against
 *    the original findings (see validateTriageOutputShape / reconcileWithSource), and
 *    retries once on any failure (bad JSON, schema mismatch, network/API error). If both
 *    attempts fail, falls back to the same deterministic rule-based triage rather than
 *    throwing.
 *
 * @param {object[]} findings - raw Findings matching docs/FINDINGS_SCHEMA.md
 * @param {object} [opts]
 * @param {string} [opts.apiKey] - overrides process.env.ANTHROPIC_API_KEY
 * @param {string} [opts.model] - overrides process.env.ANTHROPIC_TRIAGE_MODEL / the default model
 * @param {number} [opts.maxTokens] - max_tokens for the Messages API call (default 4096)
 * @param {number} [opts.maxRetries] - additional attempts after the first failed call (default 1)
 * @returns {Promise<object>} a Triage Output Schema object (see docs/FINDINGS_SCHEMA.md),
 *   with an additional top-level `degraded` boolean: false when the LLM path produced
 *   the result, true when the deterministic fallback was used.
 */
async function triage(findings, opts = {}) {
  if (!Array.isArray(findings)) {
    throw new TypeError('triage(findings, opts): findings must be an array of raw Finding objects');
  }

  if (findings.length === 0) {
    return { summary: { critical: 0, high: 0, medium: 0, low: 0 }, findings: [], degraded: false };
  }

  const apiKey = opts.apiKey || process.env.ANTHROPIC_API_KEY;
  const model = opts.model || process.env.ANTHROPIC_TRIAGE_MODEL || DEFAULT_MODEL;
  const maxTokens = opts.maxTokens || DEFAULT_MAX_TOKENS;
  const maxRetries = opts.maxRetries === undefined ? DEFAULT_MAX_RETRIES : opts.maxRetries;

  if (!apiKey) {
    return ruleBasedFallback(findings);
  }

  const totalAttempts = 1 + Math.max(0, maxRetries);
  for (let attempt = 1; attempt <= totalAttempts; attempt++) {
    try {
      const rawText = await callAnthropic({ findings, apiKey, model, maxTokens });
      const parsed = parseModelJSON(rawText);
      validateTriageOutputShape(parsed);
      reconcileWithSource(parsed, findings);
      parsed.degraded = false;
      return parsed;
    } catch (err) {
      if (attempt >= totalAttempts) {
        // Every attempt (including retries) failed — never throw out of triage();
        // fall back to the deterministic path so callers always get valid output.
        return ruleBasedFallback(findings);
      }
      // otherwise: fall through and retry
    }
  }

  // Unreachable in practice (the loop above always returns), but keeps the function
  // total in case totalAttempts is ever computed as 0.
  return ruleBasedFallback(findings);
}

module.exports = {
  triage,
  // exported for testing / reuse, not part of the "public API" surface callers need
  validateTriageOutputShape,
  reconcileWithSource,
  computeSummary,
  ruleBasedFallback,
  parseModelJSON,
};
