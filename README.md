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
