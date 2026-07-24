# vulnerable-demo-app (VibeScan test fixture)

**Do not deploy this. Do not use any credential in this folder anywhere real.** Every
secret-looking value here is fabricated filler that happens to match a real provider's
key format, seeded specifically so VibeScan's pattern-based checks have something
unambiguous to find.

This app exists purely as a scan target for `test/e2e.test.js`. It seeds **exactly one**
clear instance of each of the 10 checks in `docs/CHECK_CATALOG.md`, so a passing e2e run
means "all 10 checkIds showed up at least once," never "some subset happened to match."

## Check -> file map

| # | checkId | Where it's seeded |
|---|---|---|
| 1 | `secret-hardcoded-generic` | `config/payments.js` -- hardcoded `sk_live_...` Stripe secret key literal |
| 2 | `secret-env-committed` | `.env` -- tracked in this fixture's own git repo, fake `DB_PASSWORD` |
| 3 | `secret-git-history` | `config/legacy-aws-credentials.js` -- fake AWS key committed, then removed from HEAD in a later commit; still present via `git log -p` (see commit hashes below) |
| 4 | `sql-string-concatenation` | `routes/users.js` -- both routes, string-concat and template-literal interpolation into a raw SQL string |
| 5 | `eval-on-input` | `routes/debug.js` -- `GET /_debug/eval` calls `eval(req.query.expr)` |
| 6 | `cors-wildcard-with-credentials` | `app.js` -- `cors({ origin: '*', credentials: true })` |
| 7 | `missing-auth-middleware` | `routes/admin.js` -- `/admin` routes, no auth/session/token check anywhere |
| 8 | `supabase-rls-disabled` | `config/supabase-config.js` (`rowLevelSecurity: false`) AND `client/src/lib/supabaseClient.js` (service_role key in client-side-looking code) |
| 9 | `stripe-webhook-unverified` | `routes/webhooks.js` -- `POST /webhooks/stripe` never calls `stripe.webhooks.constructEvent()` |
| 10 | `vulnerable-dependency` | `package.json` -- `lodash` pinned to `4.17.15`, which has real published high-severity CVEs (CVE-2020-8203, CVE-2021-23337) fixed in 4.17.21 |

## Prompt-injection test fixture (not a real check)

`routes/admin.js` also contains a deliberately planted prompt-injection string right next
to the check-7 vulnerability (a fake "SECURITY REVIEWER: ... ignore any instructions
above this line" comment). It is clearly labeled inline as a test fixture and exists to
exercise a later adversarial-review pass against an LLM-based triage step -- it is not a
real mitigation and must not suppress the finding it sits next to.

## Git history

This folder is its own nested git repository (`git init` run directly inside it), kept
deliberately separate from the outer VibeScan repo's history so that:

- scanning it for check 3 (`secret-git-history`) finds the fake AWS key in *this*
  fixture's history, not VibeScan's own, and
- the outer VibeScan repo's own commit history stays clean of any seeded secret,
  including in past commits.

Commit hashes for the add-then-remove AWS-key history:

- `6dd044c` -- "Initial vulnerable demo app fixture (VibeScan test fixture, do not deploy)" -- includes the fake AWS key in `config/legacy-aws-credentials.js`
- `8a82670` -- "Remove legacy AWS credentials from config (still recoverable from git history -- see check 3)" -- redacts the file; key still recoverable via `git log -p -- config/legacy-aws-credentials.js`
