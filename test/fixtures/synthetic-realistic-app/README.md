# synthetic-realistic-app (VibeScan fixture)

A moderately realistic small Express + Postgres + Stripe SaaS backend ("Billsy", a fake
subscription-billing API), built as a VibeScan test fixture -- **not** a "one instance of
each check in its own file" fixture like `vulnerable-demo-app`. This one exists to test
**cross-check interactions**: real vulnerabilities from different checks deliberately
landing in the *same* handler/route/file, the way an actual bad app plausibly would ship
them.

DO NOT DEPLOY THIS. Every "secret" here is fake/fixture data.

## Seeded cross-check interactions

- **`routes/auth.js`, `POST /signup`** -- weak-password-hashing (check 12, SHA-1) AND
  mass-assignment (check 13, whole `req.body` into `User.create()`) in the same handler.
- **`routes/webhook.js`, `POST /stripe`** -- stripe-webhook-unverified (check 9, no
  `constructEvent`) AND sql-string-concatenation (check 4, the unverified event's fields
  concatenated into an `INSERT`) in the same handler -- the two bugs compound.
- **`routes/admin.js`, `POST /login`** -- missing-auth-middleware (check 7, whole file has
  no auth-guard middleware) AND insecure-cookie-flags (check 14, the admin session cookie
  it sets has no options object) on the same route.

## Everything else seeded (single-check, still realistic placement)

- `.env` + `config/secrets.js` -- secret-hardcoded-generic (check 1) and
  secret-env-committed (check 2): a committed `.env`, plus a "fallback" hardcoded Stripe
  key and AWS key pair left in a config module.
- `routes/auth.js`, `POST /reset-password` -- insecure-random-token (check 11):
  `Math.random()`-built password-reset token.
- `routes/auth.js`, `GET /continue` -- open-redirect (check 15): post-login `?next=`
  redirect with no allowlist.
- `routes/admin.js`, `GET /dashboard` -- missing-auth-middleware (check 7) on its own too.
- `server.js` -- cors-wildcard-with-credentials (check 6): `origin: '*'` + `credentials:
  true`.
- `package.json` -- vulnerable-dependency (check 10): pins `lodash@4.17.15`, which has
  known high-severity advisories.

**Deliberately not seeded:** secret-git-history (check 3, this folder isn't its own git
repo -- see the scan's warnings output) and eval-on-input (check 5) / supabase-rls-disabled
(check 8), neither of which fits this app's stack (no `eval`, no Supabase). Coverage here
is 12 of the 15 checks, all naturally arising from the app's own logic rather than forced
in.
