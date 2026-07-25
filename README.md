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
accuracy, so this section is grounded in both — and grounded twice: once before four known
bugs were fixed, once after, on the **same 20 real repos re-cloned from scratch and re-triaged
from zero**. See [`docs/REAL_WORLD_VALIDATION.md`](./docs/REAL_WORLD_VALIDATION.md) for the
full methodology, both passes' numbers, and the specific quoted per-repo evidence behind every
claim below.

- **`vulnerable-dependency` (check 10) is genuinely high-confidence.** It matches installed
  package versions against real CVE data. Original pass: 79% right (165/208). Re-validation
  pass: 96% right (162/169), including several current, serious CVEs in production
  dependencies (a Next.js middleware auth-bypass advisory among them). Believe this one —
  and read the re-validation doc's caveat on *why* the FP rate improved before assuming an
  8x jump in accuracy; one repo (and a genuinely new dependency-boundary bug it surfaced)
  accounts for the FP count on the second pass almost by itself.
- **`supabase-rls-disabled` (check 8) now has real-world evidence, and it's strong: 5/5
  TRUE_POSITIVE (0% FP) on re-validation**, including catching the exact real vulnerability
  (an anonymous-readable Supabase policy exposing every guest's name/email/phone in a
  Bolt.new-built reservation app) that a *human* had to find by hand in the original
  validation pass because the pre-fix version of this check had no `.sql`-migration coverage
  at all. That gap is closed — this check now reads `.sql` migration files, not just
  application source.
- **The secret checks and `eval-on-input` were wrong every single time they fired on real
  code in the original pass (45/45 false positives across those checks plus
  `missing-auth-middleware`/`stripe-webhook-unverified`).** Re-validation, repo by repo:
  - `eval-on-input`'s specific real-world failure mode (matching `RegExp.prototype.exec()`
    because it shares the substring `exec` with `child_process.exec`) is **confirmed fixed**:
    100% FP (7/7) → 0% FP, verified on a repo with 15+ real `.exec()` call sites that used to
    misfire and now don't.
  - The Supabase anon-key false positive is **confirmed fixed on the exact three repos** that
    produced it in the original pass — each one re-triaged, each one re-confirmed to contain
    the anon key, each one confirmed to no longer flag it.
  - But `secret-hardcoded-generic`/`secret-git-history`'s *overall* real-world FP rate did
    **not** improve (100% → 100%, 17/17) on re-validation, because other false-positive
    shapes the fix didn't target — auto-generated Supabase FK-constraint names, plain
    config-array strings, README placeholder text, and an object-attribute-reference variant
    (`self.access_key`) that's a near-miss of the "env-var reference" fix — filled the gap.
    **Treat these checks as still unreliable in practice**, even though the specific bug that
    motivated the fix is genuinely gone.
  - `missing-auth-middleware` and `stripe-webhook-unverified` were not part of this fix round
    (structural cross-file tracing gaps, not quick regex tweaks) and the data reflects that:
    `stripe-webhook-unverified` recurred at 100% FP on re-validation with the identical root
    cause (evaluating a helper function without following its caller's try/catch).
    `missing-auth-middleware` didn't fire on either pass's re-validation sample size — no
    updated evidence either way. Treat a finding from either as a lead to verify, not a
    verdict.
- **`sql-string-concatenation` and `cors-wildcard-with-credentials`** never fired at all
  across either pass — still no real-world evidence either way for these two.
- **Checks 11–15** (insecure random tokens, weak password hashing, mass assignment,
  insecure cookie flags, open redirect) are newer, lean more on naming/judgment heuristics —
  "does this variable name look security-sensitive?" — and are expected to false-positive on
  innocuous names (a recipe app's `secretIngredient`, a board game's `gameToken`). That
  expectation also has **no real-world data yet**: none of these five checks fired on any of
  the 20 validation repos in either pass. Treat a finding from checks 11–15 as "worth a quick
  look," not an automatic verdict, same as before — just know that's currently a fixture-based
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
