# VibeScan v1 Check Catalog (exactly these 10 checks, no more, no less, for v1)

1. secret-hardcoded-generic — high-entropy string literals matching known key formats: AWS (AKIA...), Stripe (sk_live_/sk_test_/rk_live_), generic Bearer tokens, PEM private key blocks, Supabase service_role JWT, Google API keys (AIza...), Slack tokens (xox...).
2. secret-env-committed — a .env/.env.local/.env.production file tracked in git (working tree OR history).
3. secret-git-history — a check-1-style secret pattern found in any past commit via git log -p, even if removed from HEAD.
4. sql-string-concatenation — SQL query built by string concatenation or template-literal interpolation of a variable directly into a raw query call (pg/mysql/sqlite/knex.raw patterns).
5. eval-on-input — eval()/new Function()/child_process exec()/execSync() called with a variable interpolated into the command/code string.
6. cors-wildcard-with-credentials — CORS origin set to '*' (literal or via a variable that resolves to '*') combined with credentials:true / Access-Control-Allow-Credentials: true.
7. missing-auth-middleware — route handlers on admin/internal-looking paths (e.g. /admin, /internal, /_debug) with no auth/session/token check heuristically present in the handler or its middleware chain.
8. supabase-rls-disabled — Supabase config/table definition indicating row level security disabled, or the service_role key referenced from client-side code.
9. stripe-webhook-unverified — a Stripe webhook route handler that does not call stripe.webhooks.constructEvent (signature verification) before trusting the payload.
10. vulnerable-dependency — npm audit (or pip-audit if present) reports a known CVE at high/critical severity.

Each check has a stable checkId matching the number prefix above, e.g. "secret-hardcoded-generic", "sql-string-concatenation", etc. Non-goals (do not attempt in v1, and say so explicitly in SECURITY_SCOPE.md): no DAST/runtime fuzzing, no business-logic vulnerability detection, no compliance/regulatory coverage claims, no auto-merge of any fix (fixes are suggestions/diffs only, never auto-applied).

## Severity ranking

Every triaged finding carries one of four severities: `critical`, `high`, `medium`, `low`
(see the Triage Output Schema in `docs/FINDINGS_SCHEMA.md`). Ranked most to least severe:

    critical > high > medium > low

This is the same rank order enforced internally by `src/triage/triage.js`'s
`SEVERITY_RANK` / `reconcileWithSource` (which recomputes and overwrites each finding's
severity from its source checks rather than trusting the model's stated severity), and it
is the ranking `vibescan scan --fail-on <severity>` uses to decide whether to exit
non-zero — see the README's "CI gating with `--fail-on`" section.
