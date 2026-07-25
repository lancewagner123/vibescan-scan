# VibeScan v2 Check Catalog (15 checks as of v0.2.0 — see below for the version history)

1. secret-hardcoded-generic — high-entropy string literals matching known key formats: AWS (AKIA...), Stripe (sk_live_/sk_test_/rk_live_), generic Bearer tokens, PEM private key blocks, Supabase service_role JWT, Google API keys (AIza...), Slack tokens (xox...).
2. secret-env-committed — a .env/.env.local/.env.production file tracked in git (working tree OR history).
3. secret-git-history — a check-1-style secret pattern found in any past commit via git log -p, even if removed from HEAD.
4. sql-string-concatenation — SQL query built by string concatenation or template-literal interpolation of a variable directly into a raw query call (pg/mysql/sqlite/knex.raw patterns).
5. eval-on-input — eval()/new Function()/child_process exec()/execSync() called with a variable interpolated into the command/code string.
6. cors-wildcard-with-credentials — CORS origin set to '*' (literal or via a variable that resolves to '*') combined with credentials:true / Access-Control-Allow-Credentials: true.
7. missing-auth-middleware — route handlers on admin/internal-looking paths (e.g. /admin, /internal, /_debug) with no auth/session/token check heuristically present in the handler or its middleware chain.
8. supabase-rls-disabled — Supabase config/table definition indicating row level security disabled, or the service_role key referenced from client-side code. Also scans `.sql` migration files directly (added after a real-world false-negative — see `docs/REAL_WORLD_VALIDATION.md` §6): flags `ALTER TABLE ... DISABLE ROW LEVEL SECURITY`, and `CREATE POLICY` statements that grant the `anon`/`public` role access with a trivially permissive `USING (true)` clause or no `USING` clause at all (which Postgres/Supabase treats as unrestricted for `SELECT`/`UPDATE`/`DELETE`/`ALL` policies) — tolerant of multi-line formatting and keyword case, and silent on policies scoped with a real condition (e.g. `USING (auth.uid() = user_id)`).
9. stripe-webhook-unverified — a Stripe webhook route handler that does not call stripe.webhooks.constructEvent (signature verification) before trusting the payload.
10. vulnerable-dependency — npm audit (or pip-audit if present) reports a known CVE at high/critical severity.
11. insecure-random-token — `Math.random()` (in any chained form, e.g. `.toString(36).substring(2)`) used to build the value assigned to a name that looks security-sensitive (`token`, `sessionId`/`session_id`, `apiKey`/`api_key`, `secret`, `nonce`, or `csrf`, as a substring). `Math.random()` is not cryptographically secure, so a session id, password-reset token, API key, or CSRF nonce built from it can be predicted/forged.
12. weak-password-hashing — `crypto.createHash('md5')` or `crypto.createHash('sha1')` used to hash something that looks like a password (a nearby password/passwd/pwd-named variable in the same statement, or the file itself looks like an auth/login/signup/register module). MD5/SHA-1 are fast, unsalted digests — fine for checksums, catastrophic for password storage.
13. mass-assignment — the entire `req.body`/`req.query` object (directly, or via one same-file variable hop) passed whole into `Model.create/update/save(...)`, `new Model(...)`, or `Object.assign(existingRecord, ...)`, with no destructuring/allowlist of individual fields — lets an attacker set/overwrite any field the model has, not just the ones a form intended to expose.
14. insecure-cookie-flags — `res.cookie(name, value[, options])` setting what looks like a session/auth cookie (by name or value expression) with no options object, or an options object/one-hop-resolved variable missing `httpOnly:true`/`secure:true`.
15. open-redirect — `res.redirect(...)` (including the two-arg `res.redirect(status, url)` form) with a target that comes directly, or via one same-file variable hop, from `req.query`/`req.body`/`req.params`, with no nearby allowlist/validation guard (`.startsWith('/')`, an allowlist `.includes()` check, etc).

Each check has a stable checkId matching the number prefix above, e.g. "secret-hardcoded-generic", "sql-string-concatenation", etc. Non-goals (do not attempt in v2, and say so explicitly in SECURITY_SCOPE.md): no DAST/runtime fuzzing, no business-logic vulnerability detection, no compliance/regulatory coverage claims, no auto-merge of any fix (fixes are suggestions/diffs only, never auto-applied).

## Version history

- **v1 (0.1.0):** checks 1-10 above.
- **v2 (0.2.0):** added checks 11-15 above (5 new checks: `insecure-random-token`,
  `weak-password-hashing` — both in `src/scanners/secrets.js`; `mass-assignment`,
  `insecure-cookie-flags`, `open-redirect` — all three in `src/scanners/static-checks.js`).
  Coverage is now 15 checks, no more, no less, for v2 — the same "closed list" contract
  that applied to the original 10 still applies, just with a longer list.

## Severity ranking

Every triaged finding carries one of four severities: `critical`, `high`, `medium`, `low`
(see the Triage Output Schema in `docs/FINDINGS_SCHEMA.md`). Ranked most to least severe:

    critical > high > medium > low

This is the same rank order enforced internally by `src/triage/triage.js`'s
`SEVERITY_RANK` / `reconcileWithSource` (which recomputes and overwrites each finding's
severity from its source checks rather than trusting the model's stated severity), and it
is the ranking `vibescan scan --fail-on <severity>` uses to decide whether to exit
non-zero — see the README's "CI gating with `--fail-on`" section.
