# VibeScan

Security **scanning** — not a security guarantee — for people who didn't write their own
code. VibeScan runs a fixed catalog of 15 static, pattern-based checks (see
`docs/CHECK_CATALOG.md`) against a codebase: the specific, high-signal mistakes AI coding
assistants (Claude Code, Cursor, Replit, Lovable, Bolt) tend to leave in shipped apps —
leaked secrets, disabled database row-level security, unverified payment webhooks, and a
short list of others — and explains each one it finds in plain English, with a suggested
(never auto-applied) fix for a human to review.

**Read [`SECURITY_SCOPE.md`](./SECURITY_SCOPE.md) before you trust anything this tool
tells you.** In short: this is static analysis only (no dynamic testing/fuzzing), it does
not find business-logic bugs, it makes no compliance/regulatory claims, and a clean
report means "none of our 15 known patterns matched" — not "your app is secure."

### Not all 15 checks carry the same confidence

Fixture-based adversarial hardening (three rounds) is not the same evidence as real-world
accuracy, so this section is grounded in both. A validation pass hand-triaged 253 findings
across 17 real, public AI-generated repos (Lovable/Bolt/v0/Claude Code output found on
GitHub) — see [`docs/REAL_WORLD_VALIDATION.md`](./docs/REAL_WORLD_VALIDATION.md) for the
full methodology and numbers. The honest picture that came back does **not** split cleanly
along the "checks 1–10 vs. checks 11–15" line the numbering might suggest:

- **`vulnerable-dependency` (check 10) is genuinely high-confidence.** It matches installed
  package versions against real CVE data, and it was right 79% of the time on real code
  (165 of 208 real-world findings), including several current, serious CVEs in production
  dependencies (a Next.js middleware auth-bypass advisory among them). Believe this one.
- **The other checks in the "1–10" bucket — leaked secrets (3 checks), `eval`/RCE, missing
  auth, and unverified Stripe webhooks — were wrong every single time they fired on real
  code in that validation pass (45 findings, 45 false positives, 0 true positives).** The
  dominant real-world pattern: Supabase's `anon`/publishable key (which Supabase's own
  architecture is designed to ship in client bundles, protected by Row Level Security, not
  secrecy) repeatedly triggered the secret checks; `eval-on-input` repeatedly matched
  `RegExp.prototype.exec()` calls, which share the substring `exec` with
  `child_process.exec` but do nothing of the sort. These checks still match real,
  structural signatures — an AWS key *does* look like an AWS key — so they aren't being
  removed, but "when one of these fires, it's almost certainly real" is not what real code
  showed. Treat a finding from `secret-hardcoded-generic`, `secret-env-committed`,
  `secret-git-history`, `eval-on-input`, `missing-auth-middleware`, or
  `stripe-webhook-unverified` as a lead to verify, not a verdict.
- **`sql-string-concatenation`, `cors-wildcard-with-credentials`, and
  `supabase-rls-disabled`** never fired at all across the 20 repos in the validation sample
  — there is no real-world evidence yet either way for these three.
- **Checks 11–15** (insecure random tokens, weak password hashing, mass assignment,
  insecure cookie flags, open redirect) are newer, lean more on naming/judgment heuristics —
  "does this variable name look security-sensitive?" — and are expected to false-positive on
  innocuous names (a recipe app's `secretIngredient`, a board game's `gameToken`). That
  expectation also has **no real-world data yet**: none of these five checks fired on any of
  the 20 validation repos either. Treat a finding from checks 11–15 as "worth a quick look,"
  not an automatic verdict, same as before — just know that's currently a fixture-based
  judgment call, not yet a real-code-tested one. See `SECURITY_SCOPE.md`'s per-check
  limitations for the specific known false-positive patterns.

### Framework coverage

Checks 7, 9, 13, 14, and 15 are shaped around **Express**-style route/middleware code;
checks 11–12 are plain JS/TS pattern matches with no framework assumption. On a
Next.js/Fastify/NestJS API, or a non-JS backend (Django, Flask, Rails, etc.), those
Express-shaped checks will typically find nothing to report — not because the code is
safe, but because the pattern they look for doesn't exist in that framework's idioms.
VibeScan does not yet detect its target's framework or warn when a check's shape doesn't
apply — assume Express-oriented checks are silent, not confirmed-clean, on other stacks.

## Usage

    npx vibescan-scan scan [path]

`path` defaults to the current directory. VibeScan will:

1. Run its 15 static checks (`docs/CHECK_CATALOG.md`) against the target repo.
2. If `ANTHROPIC_API_KEY` is set, rewrite the raw findings into a plain-English report
   via an LLM triage step; otherwise fall back to a deterministic, template-based report
   (no network access required).
3. Print a terminal summary and write the full report to `./vibescan-report.md` and
   `./vibescan-report.json`.

Every suggested fix is a **diff to review, not a change VibeScan applies for you** — see
"Suggested fixes are suggestions, not verified patches" in `SECURITY_SCOPE.md`.

### CI gating with `--fail-on`

By default `vibescan scan` always exits `0`, even when it finds issues — it's a report,
not a gate, unless you opt in. Add `--fail-on <severity>` to make it exit non-zero when
any finding is at or above that severity, so a CI job can fail the build on it:

    npx vibescan-scan scan . --fail-on critical

Severity ranking, most to least severe: `critical > high > medium > low`. `--fail-on high`
fails on critical or high findings, `--fail-on low` fails on any finding at all. Omitting
`--fail-on` entirely preserves the always-exit-0 behavior.
