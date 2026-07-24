# VibeScan

Security **scanning** — not a security guarantee — for people who didn't write their own
code. VibeScan runs a fixed catalog of 10 static, pattern-based checks (see
`docs/CHECK_CATALOG.md`) against a codebase: the specific, high-signal mistakes AI coding
assistants (Claude Code, Cursor, Replit, Lovable, Bolt) tend to leave in shipped apps —
leaked secrets, disabled database row-level security, unverified payment webhooks, and a
short list of others — and explains each one it finds in plain English, with a suggested
(never auto-applied) fix for a human to review.

**Read [`SECURITY_SCOPE.md`](./SECURITY_SCOPE.md) before you trust anything this tool
tells you.** In short: this is static analysis only (no dynamic testing/fuzzing), it does
not find business-logic bugs, it makes no compliance/regulatory claims, and a clean
report means "none of our 10 known patterns matched" — not "your app is secure."

## Usage

    npx vibescan scan [path]

`path` defaults to the current directory. VibeScan will:

1. Run its 10 static checks (`docs/CHECK_CATALOG.md`) against the target repo.
2. If `ANTHROPIC_API_KEY` is set, rewrite the raw findings into a plain-English report
   via an LLM triage step; otherwise fall back to a deterministic, template-based report
   (no network access required).
3. Print a terminal summary and write the full report to `./vibescan-report.md` and
   `./vibescan-report.json`.

Every suggested fix is a **diff to review, not a change VibeScan applies for you** — see
"Suggested fixes are suggestions, not verified patches" in `SECURITY_SCOPE.md`.
