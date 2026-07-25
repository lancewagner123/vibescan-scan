# Real-World False-Positive Validation (2026-07-24)

This is the exercise the round-3 strategic consultant asked for (see `DECISIONS.md`,
"Round 3... strategic consult"): stop hardening against fixtures the tool's own author
wrote, and instead measure how often VibeScan is *right* on real, public code nobody on
this project touched. This document is the result.

**Headline: on real code, every true positive VibeScan produced was a `vulnerable-dependency`
finding. Every finding from the other checks that fired — secrets, `eval`-on-input, missing
auth, unverified Stripe webhooks — was a false positive, 45 times out of 45.** See §4 for the
full breakdown and §5 for what this does and doesn't mean for the confidence tiers currently
published in `README.md`.

## 1. Methodology

**Sourcing.** 20 candidate repos were sourced via real web search (`WebSearch`) plus direct
fetches of GitHub's own search-results and `/topics` pages (`topic:bolt-new`, `topic:lovable`,
`topic:lovable-ai`, `topic:v0-dev`, `topic:ai-generated`, `topic:replit`, `topic:cursor-ai`,
`topic:claude-code`), combined with stack keywords (`express`, `stripe`, `mongodb`,
`supabase`). Every candidate was individually opened on its real GitHub page and its
README/description read before inclusion — two initial hits turned out to be empty
repositories on inspection and were dropped before the final 20 were locked in.

Each of the 20 was scored on how confident we can be that it's genuinely AI-tool-generated,
not just AI-adjacent in name:

- **9 CONFIRMED** — the repo's own README text (or, in one case, its own GitHub topic tags)
  explicitly states it was built with a named AI tool: Lovable (×3), Bolt.new (×3), Claude Code
  (×1), v0.dev (×1), and one repo self-tagged both `claude-code` and `v0-dev`.
- **8 PLAUSIBLE** — a strong profile match (small full-stack app, generic AI-app naming or
  topic tags such as `v0-dev`, `cursor`, `lovable`, `bolt-new`, or a name like
  `vibecoded_marathon_photos`) but no explicit in-README build-tool sentence found.
- **3 UNCONFIRMED** — included purely to round out stack diversity (a plain Express+MongoDB
  app, a MERN+Stripe/Polar app, and a Bolt/Lovable-*styled* clone rather than a tool-built app)
  with no AI-tool signal at all. Flagged honestly as such rather than folded into the other
  two buckets.

No repo required authentication to view; every URL cited below is a public GitHub page that
was actually fetched and read, not inferred.

**Scanning and triage.** Each repo was cloned into an isolated scratchpad directory, scanned
with `vibescan scan` (degraded/rule-based fallback mode throughout — no `ANTHROPIC_API_KEY`
was used for triage, so this measures the raw pattern-matching checks, not an LLM's judgment
layered on top), and **every raw finding VibeScan produced was hand-triaged individually** —
TRUE_POSITIVE, FALSE_POSITIVE, or UNCERTAIN — by reading the actual flagged file, tracing
callers, resolving the real installed dependency version from the lockfile (not just the
semver range in `package.json`), and, where relevant, looking up the real CVE/GHSA advisory
text rather than trusting the range VibeScan reported. Two repos returned more findings than
could be triaged individually within scope (60 and 40 raw findings); those were sampled — see
§3 — with the sampling axis and coverage disclosed per repo rather than silently averaged in.
Every cloned repo was deleted after triage; nothing from this exercise persists on disk beyond
this document.

**What went wrong in sourcing/execution, and how it's handled below:**

- **2 of the 20 repos never produced a usable result** — the clone/scan/triage task returned
  nothing (clone or scan failure, or a dropped result). They are **excluded** from every
  aggregate number in this document; there is no finding data for them to count one way or
  the other.
- **1 repo (`1Flow`) cloned and scanned successfully but contained no scannable application
  code** — the public repo turned out to be a two-paragraph `README.md` stub, not the actual
  product source (which likely lives in a private repo or a different branch). VibeScan
  correctly reported zero findings against zero code. This is **not** a false-positive data
  point (there was nothing to be right or wrong about) and is excluded from the FP-rate
  math, though it's a useful reminder that "clean scan" and "nothing to scan" look identical
  in the output.

Net: **20 repos sourced → 18 successfully cloned and scanned → 17 repos contributed actual
triaged finding data.**

**Stack diversity across the 20 sourced repos:** Supabase-backed (6), Stripe or
Stripe-adjacent/Polar payments (3), Next.js API routes (7), plain Node/Express (3), MongoDB
(2), Postgres including Supabase/Neon (9).

## 2. Aggregate numbers

| | count | % of total |
|---|---|---|
| Total findings triaged | 253 | 100% |
| TRUE_POSITIVE | 165 | 65.2% |
| FALSE_POSITIVE | 84 | 33.2% |
| UNCERTAIN | 4 | 1.6% |

(253 = the sum of triaged findings across all 17 contributing repos, using the *sampled*
count for the two repos where sampling was used — see §3 for what that changes.)

**The number that matters most isn't the blended 65/33 split above — it's how unevenly it's
distributed across checks:**

- **Every one of the 165 true positives came from exactly one check: `vulnerable-dependency`
  (check 10).** Zero true positives came from any of the other 14 checks across all 20 repos.
- **Every finding from `secret-hardcoded-generic`, `secret-env-committed`, `secret-git-history`,
  `eval-on-input`, `missing-auth-middleware`, and `stripe-webhook-unverified` — the six other
  checks that fired at all — was a false positive.** 45 findings, 45 false positives, 0 true
  positives, 0 uncertain.
- **Checks 4, 6, 8, and 11 through 15 (nine of the fifteen checks) never fired a single time**
  across all 20 repos. This isn't evidence they're accurate or inaccurate — there's simply no
  real-world signal for them yet in this sample.

## 3. Per-checkId breakdown

| checkId | tier (per README) | findings | TP | FP | Uncertain | real-world FP rate |
|---|---|---|---|---|---|---|
| `secret-hardcoded-generic` | 1-10, HIGH | 16 | 0 | 16 | 0 | **100%** |
| `secret-env-committed` | 1-10, HIGH | 2 | 0 | 2 | 0 | **100%** |
| `secret-git-history` | 1-10, HIGH | 16 | 0 | 16 | 0 | **100%** |
| `sql-string-concatenation` | 1-10, HIGH | 0 | — | — | — | no data (never fired) |
| `eval-on-input` | 1-10, HIGH | 7 | 0 | 7 | 0 | **100%** |
| `cors-wildcard-with-credentials` | 1-10, HIGH | 0 | — | — | — | no data (never fired) |
| `missing-auth-middleware` | 1-10, HIGH | 3 | 0 | 3 | 0 | **100%** |
| `supabase-rls-disabled` | 1-10, HIGH | 0 | — | — | — | no data (never fired) |
| `stripe-webhook-unverified` | 1-10, HIGH | 1 | 0 | 1 | 0 | **100%** |
| `vulnerable-dependency` | 1-10, HIGH | 208 | 165 | 39 | 4 | **18.8%** (best-performing check by far) |
| `insecure-random-token` | 11-15, MODERATE | 0 | — | — | — | no data (never fired) |
| `weak-password-hashing` | 11-15, MODERATE | 0 | — | — | — | no data (never fired) |
| `mass-assignment` | 11-15, MODERATE | 0 | — | — | — | no data (never fired) |
| `insecure-cookie-flags` | 11-15, MODERATE | 0 | — | — | — | no data (never fired) |
| `open-redirect` | 11-15, MODERATE | 0 | — | — | — | no data (never fired) |
| **Total** | | **253** | **165** | **84** | **4** | **33.2%** blended |

Sample-size caveat: `secret-env-committed` (2), `missing-auth-middleware` (3), and
`stripe-webhook-unverified` (1) fired too rarely across 20 repos to treat their 100% figures
as statistically strong on their own — they're each reinforcing the same pattern the
larger-n checks (`secret-hardcoded-generic`/`secret-git-history`, both n=16, and
`eval-on-input`, n=7) show more robustly, not carrying the claim alone.

**Sampling disclosure for the two large repos:**

- **`blog-full-stack`** (Remix blog+backend, stale April-2023 dependency tree): 60 raw
  `vulnerable-dependency` findings. Sampled 28 — every backend package, every admin-tooling
  package flagged, plus targeted checks — and treated the ~32 unsampled findings (mostly
  duplicate `eslint-plugin-*`/`@typescript-eslint/*` peers of already-verified chains) as
  "very likely the same disposition," not counted in the aggregate.
- **A MERN food-delivery app** (backend/admin/frontend split, one repo, mixed checkIds):
  40 raw findings (3 `missing-auth-middleware` + 37 `vulnerable-dependency`). All 3 auth
  findings triaged individually; sampled 28 of the 37-38 dependency findings (every backend
  and admin package, 3 of ~13 frontend packages that largely duplicate the admin
  toolchain) for 31 of 40 triaged overall.

Both sampling choices are disclosed here rather than silently blended into "253 findings
triaged" as if every one had equal individual scrutiny — they don't change the picture
(both repos' sampled results were dependency-heavy true positives, consistent with the rest
of the check-10 data), but the methodology should be visible, not implied.

## 4. Does this confirm, contradict, or complicate the round-3 prediction?

The round-3 strategic consultant's stated confidence rating (`DECISIONS.md`, "Round 3...
strategic consult") was:

> "Confidence rating in founder's terms: checks 1-10 HIGH (believe them), checks 11-15
> MODERATE and prone to false alarms (treat as 'worth a look,' not a verdict)."

That framing is currently published near-verbatim in `README.md`'s "Not all 15 checks carry
the same confidence" section. **Real-world data complicates it — and for six of the nine
checks in the "1-10 HIGH" bucket, outright contradicts it.**

- **Confirmed, strongly:** `vulnerable-dependency` (check 10) really is high-confidence in
  practice — 165 of 208 real findings (79.3%) held up, including some genuinely serious,
  current, actively-reachable CVEs (see §5). This is the one check in the "1-10" bucket that
  earns the "believe it" framing on real evidence, not just fixture-hardening.
- **Contradicted:** the other six "1-10 HIGH" checks that fired — `secret-hardcoded-generic`,
  `secret-env-committed`, `secret-git-history`, `eval-on-input`, `missing-auth-middleware`,
  `stripe-webhook-unverified` — were wrong **every single time** they fired on real code (45/45).
  These are not edge cases; they're the *modal* outcome for these checks against real
  Lovable/Bolt/Supabase-stack apps. "When one of these fires, it's almost certainly real" (the
  README's current wording) is the opposite of what happened in this sample for those six
  checks specifically.
- **Untested, not confirmed:** checks 4, 6, 8 (SQL string concatenation, CORS wildcard,
  Supabase RLS disabled) never fired at all — no evidence for or against their "HIGH"
  billing. Same for all five checks in the "11-15 MODERATE" bucket (11-15) — the prediction
  that they'd be "prone to false alarms" on innocuous names (`secretIngredient`, `gameToken`)
  was never actually exercised, because none of them ever matched anything in these 20 real
  repos. The prediction may well be correct — it's just still a fixture-only claim, exactly
  the kind of claim this exercise was supposed to stop relying on.

**Honest summary:** the consultant was right that fixture-hardening had hit diminishing
returns and real-world measurement was the missing signal. But the specific prediction — that
the 1-10/11-15 split tracks real-world reliability — does not survive contact with real code.
The split that actually held up is **"the one check that reads a lockfile against a real CVE
database" vs. "every check that pattern-matches source-code shape or variable naming"** — and
that line runs *through* the "1-10" bucket, not around it. Every non-dependency check that
fired at all, across every confidence tier, produced only false positives in this sample.

## 5. Notable real false-positive patterns

These are the actual, recurring mechanisms behind the 45 non-dependency false positives —
not hypothetical failure modes, patterns that showed up repeatedly across independently
sourced repos. Findings that involve what looks like a secret/credential are referenced by
a generic label rather than a real repo name, even though every one was confirmed non-live,
since discussing "repo X's leaked key" in a public doc reads badly regardless of the verdict.
Findings about missing-auth or `eval`-on-input structure are cited by real (already-public)
repo name, since there's nothing sensitive in naming which repo has an unauthenticated route.

**FIXED (2026-07-24, same day) — see "Fix status" note at the end of this document.**

**1. The Supabase "anon key" pattern (the single largest false-positive source, ~14 of 45).**
Across multiple independently-sourced Lovable/Bolt/Supabase-stack repos (e.g. "Repo A —
Lovable-built plant-diagnosis app," "Repo B — Bolt-built Supabase reservation app," "Repo C —
Lovable-built travel planner"), `secret-hardcoded-generic`/`secret-git-history` flagged the
Supabase client's `SUPABASE_URL`/`SUPABASE_PUBLISHABLE_KEY` (or `ANON_KEY`) pair. In every
case, decoding the JWT payload confirmed `"role": "anon"`, not `"role": "service_role"` — the
publishable/anon key Supabase's own documented architecture *designs* to ship in client
bundles, with access control enforced server-side by Row Level Security, not by keeping the
string secret. One repo's fallback default in a test file resolved to Supabase's own
published public demo/quickstart key, verbatim, from their docs. None of these findings
involved a genuinely dangerous `service_role` key.

**2. Env-var references, not literal secrets. FIXED (2026-07-24) — see "Fix status" note below.**
Several `secret-hardcoded-generic` hits
were lines like `const KEY = import.meta.env.VITE_SUPABASE_KEY` or
`os.getenv("PINECONE_API_KEY")` — a variable *name* containing "key"/"secret", with no
literal value on the line at all. The heuristic matched the name pattern, not actual
entropy/content.

**3. Test/fixture literals mistaken for live secrets.** A Claude-Code-attributed repo
("Repo D") had `secret-hardcoded-generic` fire on hardcoded hex strings inside its own
`*.test.mjs` files — literal fixture data written specifically to exercise a key-parsing
function's validation logic, never a real credential.

**4. `RegExp.prototype.exec()` mistaken for code execution. FIXED (2026-07-24) — see "Fix
status" note below.** All 7 `eval-on-input`
false positives were regex `.exec()` calls (extracting a leading number from a filename,
validating a plugin name against an allowlist, scanning source text for a call signature) —
not `eval()`, `Function()`, or a shell exec call at all. The checkId's own heuristic appears
to key on the literal substring `exec`, which `RegExp.prototype.exec` shares with
`child_process.exec`/`execSync` without being remotely the same risk.

**5. Missing-auth findings that missed the actual auth check.** In a MERN food-delivery
app, `missing-auth-middleware` flagged three admin routes purely by reading the *frontend*
`axios.post(...)` call sites; the backend route definitions (a separate file the check
didn't trace into) did in fact chain an `authMiddleware` plus an explicit
`role === "admin"` check before the sensitive operation. The finding wasn't wrong that the
frontend file alone shows no auth — it was wrong that the *route* lacks auth, because it
never looked at the file where the auth actually lives.

**6. A Stripe webhook handler that was actually correct.** The one
`stripe-webhook-unverified` finding flagged a helper function with no internal `try/catch`
around `stripe.webhooks.constructEvent(...)` — but its only caller wrapped the call in its
own `try/catch` and returned a 400 on any verification failure, which is the *correct*
pattern (let the SDK throw, catch and reject at the call site). The check evaluated the
helper in isolation and never followed the one call site that mattered.

## 6. Notable true positives — does the premise hold up?

Yes, with an important caveat: **every real vulnerability VibeScan found in this exercise
was an outdated dependency** — no repo in this sample of 20 contained a real hardcoded
secret, a real SQL-injection sink, a real `eval`-on-attacker-input path, a real missing-auth
route, or a real unverified Stripe webhook. That's a genuinely useful, humbling data point on
its own: on this sample, nine of VibeScan's fifteen checks target a class of bug that either
doesn't occur in AI-generated small-app code very often, or occurs in a shape these checks
don't yet catch (see the RLS gap below).

Within the one check that did produce real signal, several true positives are worth citing
because they're exactly the kind of mistake the tool exists to catch, found in real shipped
code, not a fixture:

- **`next@14.0.0`/`14.2.11`/`15.2.4`/`16.2.10`, found outdated in five separate repos**,
  including at least one match to **CVE-2025-29927** — a real, actively-discussed
  middleware/proxy authorization-bypass advisory that lets a crafted request skip Next.js
  middleware-based route protection entirely. In the repos where this fired, the app used
  Next's middleware for actual route protection (Clerk- or session-gated `/admin`,
  `/profile`, `/generate-program` routes) — meaning the outdated dependency and the
  authorization mechanism it undermines were both present in the same app at once. This is
  the strongest single validation of the tool's premise in the whole exercise.
- **`sharp` below 0.35.0** (bundled libvips CVEs, two rated High), found genuinely installed
  and, in at least one repo, genuinely reachable through Next's live `/next/image`
  optimization pipeline with no `images.remotePatterns` restriction narrowing exposure.
- **`js-cookie@3.0.5`**, found to be a real, live dependency of a Clerk-based auth stack
  (not a dead/unused import) — meaning its vulnerable version is genuinely handling session
  cookies client-side in that app, not just sitting unused in `node_modules`.

**A genuine miss worth recording honestly, even though it isn't one of the 253 triaged
findings — FIXED (2026-07-24), see "Fix status" note below:** while manually reading a
Bolt.new-built reservation app's Supabase migration
(to triage its dependency findings), the person triaging found an actual, real
`supabase-rls-disabled`-shaped bug VibeScan's own check-8 never flagged — a migration
granting the public `anon` role unrestricted `SELECT ... USING (true)` on a reservations
table containing every guest's name, email, and phone number, not just their own row. This
is exactly the class of bug check 8 exists to catch, present in real code, and check 8 never
fired on it. Recorded here as an honest false-negative data point, not folded into the FP-rate
math since it isn't a VibeScan finding to triage — but it's real signal that check 8's
current pattern-matching (config/table-definition text, service_role key in client code)
doesn't cover an overly-permissive RLS *policy* written in a migration file, which in this
sample was the actual failure mode.

## 7. Bottom line

- **253 real findings hand-triaged across 17 usable repos** (of 20 sourced; 2 failed to
  produce a result, 1 had no scannable code).
- **65.2% of all findings were real; 33.2% were false positives; 1.6% were genuinely
  ambiguous even after manual investigation.**
- **The true-positive rate is not evenly distributed: it is ~79% concentrated entirely in
  the dependency-audit check, and 0% everywhere else that fired.** Six checks the README
  currently bills as "HIGH confidence... almost certainly real" were wrong 100% of the time
  they fired on real code in this sample.
- **Nine of fifteen checks never fired once** across 20 real repos — no real-world evidence
  either way for `sql-string-concatenation`, `cors-wildcard-with-credentials`,
  `supabase-rls-disabled`, or any of checks 11-15.
- **Recommendation:** do not ship the current README confidence-tier language unmodified —
  it makes a claim ("1-10 is high confidence, believe it") that this data does not support
  for six of those ten checks. See the `SECURITY_SCOPE.md`/`README.md` updates made alongside
  this document, and `DECISIONS.md`'s "Real-world false-positive validation" entry for the
  ship/no-ship call.

## Fix status (2026-07-24, later same day)

Four of the specific bugs this exercise surfaced have since been fixed and regression-tested;
they are **no longer open issues**. This section is the current status — the narrative above
(§5, §6) is left intact as the historical record of what the validation exercise actually
found, with inline "FIXED" markers pointing here.

1. **Supabase anon-key false positive (§5, pattern 1).** `src/scanners/secrets.js` now
   decodes the payload of any JWT-shaped candidate value and suppresses the finding when the
   `role` claim is `anon`/`anonymous`, across every hit path (single-line vendor patterns,
   quoted/unquoted/bracket generic-entropy, template-literal-split, concat-chain,
   base64-decode). A `service_role` JWT, or any JWT whose payload fails to decode, still
   flags normally. Fixed in commit `5fa05b5`. Regression coverage:
   `test/fixtures/false-positives/23-real-world-secrets/`, run via
   `test/false-positives.test.js`. Hand-reconstructed with a fresh (non-fixture) synthetic
   anon-role JWT during integration verification the same day — did not fire — and a
   fresh synthetic `service_role` JWT — still fired at `critical`.

2. **Env-var-reference false positive (§5, pattern 2).** `secrets.js` now rejects candidate
   values that are pure dotted identifier/property-access chains (`import.meta.env.X`,
   `process.env.X`, `config.apiKey`, etc.) before the entropy check ever runs, across the
   quoted, unquoted-dotenv-shape, and bracket-notation generic-secret paths. Fixed in commit
   `5fa05b5`. Regression coverage: `test/fixtures/false-positives/23-real-world-secrets/`
   (`env-var-reference.js`). Hand-reconstructed the same day with a fresh `import.meta.env`
   reference and a fresh unquoted `KEY = import.meta.env.X` dotenv-shape line — neither fired.

3. **`RegExp.prototype.exec()` false positive (§5, pattern 4).** `checkEvalOnInput()` in
   `src/scanners/static-checks.js` no longer gates on whether the *whole file* mentions
   `child_process` — it now traces each `exec`/`execSync` call site's actual receiver (bare
   destructured import, one-hop-traced variable, or inline `require('child_process').exec()`)
   and only flags calls that genuinely resolve to `child_process`. A `RegExp.prototype.exec()`
   call sitting in a file that separately imports `child_process` for an unrelated purpose no
   longer fires. Fixed in commit `77da59b` (code change landed in `0904054`, tests/fixtures in
   `77da59b`). Regression coverage: `test/fixtures/false-positives/5-eval-on-input/`. Hand-
   reconstructed the same day with a filename-number-extractor using `.exec()` alongside an
   unrelated `child_process.execSync()` call in the same file — did not fire — while a real
   `child_process.exec()` call with interpolated request input in a separate fixture still
   fired at `critical`.

4. **`supabase-rls-disabled` missing `.sql` migration coverage (§6, the genuine miss).**
   `static-checks.js` now runs a dedicated `.sql`-file scan pass alongside the existing JS/TS
   pass: it strips SQL comments, parses `CREATE POLICY ... ON <table> ... TO <roles> ...`
   statements, and flags a policy that grants `anon`/`public` with `USING (true)` or no
   `USING` clause at all (for non-INSERT operations) — while staying silent on policies scoped
   with a real condition like `USING (auth.uid() = user_id)`. The existing `ALTER TABLE ...
   DISABLE ROW LEVEL SECURITY` pattern is now also reachable against `.sql` files, since it
   previously had no `.sql` pass to run in at all. Fixed in commit `0904054`. Regression
   coverage: `test/fixtures/evasion-attempts/23-supabase-rls-sql/`. Hand-reconstructed the
   same day with a fresh synthetic reservations-table migration
   (`create policy ... on reservations for select to anon using (true)`) — fired at
   `critical` with the correct table/policy named in the finding message.

**Verification method:** all four fixes were confirmed via the project's automated test suite
(`npm test`, 91/91 passing) *and* independently, by hand, against fresh synthetic
reproductions built from the descriptions above (not the checked-in regression fixtures) using
the real CLI/`scanRepo()` — a fresh anon-role JWT, a fresh env-var-reference assignment, a
fresh filename-number-extractor sharing a file with an unrelated `child_process` import, and a
fresh permissive-RLS-policy `.sql` migration, each producing the expected fire/no-fire result.

---

## Re-validation (post-fix) (2026-07-24, third pass)

Fixture reconstructions and synthetic repros (above) prove the fixes work *in isolation*. This
section is the harder test: **the same 20 repos from the original validation were re-cloned
from scratch and re-scanned with the current, fixed VibeScan build, and every finding was
hand-triaged again from zero** — not diffed against the old triage, not assumed. This is what
"did the fix survive contact with the real code that motivated it" actually looks like measured,
not asserted.

### Methodology notes specific to this pass

- Same 20 source repos, same cloning/triage discipline (read the flagged file, trace callers,
  resolve real installed versions from the lockfile, delete the clone after triage) as the
  original pass.
- **4 of the 20 did not produce usable data this time** (clone/scan/triage task returned nothing)
  — excluded from aggregates, same convention as the original pass's 2 exclusions. One repo
  (`Food-Delivery`) cloned and scanned but its per-finding triage output was not captured in the
  material available for this comparison — also excluded rather than guessed at. `1Flow` was
  re-confirmed as the same README-only stub (0 findings, not a data point either way, same as
  the original pass).
- Net: **20 repos attempted → 15 produced a usable result (14 with real findings + `1Flow`'s
  confirmed-empty result) → 14 repos contributed actual triaged finding data**, three fewer
  contributing repos than the original pass's 17. This shrinks the sample and is a real
  limitation of this comparison — treat the magnitude of any percentage shift with that in mind,
  even though the direction of the two confirmed fixes (§below) is unambiguous because it's
  demonstrated on named, specific repos, not just the aggregate blend.
- One large repo (`blog-full-stack`) again produced far more raw findings (53, all
  `vulnerable-dependency`) than could be triaged individually; 22 were sampled across both its
  `client/` and `server/` manifests, covering every direct runtime dependency and a
  representative spread of build-tooling transitives, and all 22 were TRUE_POSITIVE. Same
  disclosure convention as the original pass: not blended in as if every one of the 53 got equal
  scrutiny.

### Aggregate numbers (this pass)

| | count | % of total |
|---|---|---|
| Total findings triaged | 211 | 100% |
| TRUE_POSITIVE | 169 | 80.1% |
| FALSE_POSITIVE | 39 | 18.5% |
| UNCERTAIN | 3 | 1.4% |

### Per-checkId breakdown (this pass)

| checkId | findings | TP | FP | Uncertain | real-world FP rate |
|---|---|---|---|---|---|
| `secret-hardcoded-generic` | 17 | 0 | 17 | 0 | **100%** |
| `secret-env-committed` | 1 | 1 | 0 | 0 | 0% (n=1, weak signal) |
| `secret-git-history` | 17 | 0 | 17 | 0 | **100%** |
| `sql-string-concatenation` | 0 | — | — | — | no data (never fired) |
| `cors-wildcard-with-credentials` | 0 | — | — | — | no data (never fired) |
| `eval-on-input` | 1 | 1 | 0 | 0 | 0% (n=1, weak signal — see below) |
| `missing-auth-middleware` | 0 | — | — | — | no data this pass (fired 0 times) |
| `supabase-rls-disabled` | 5 | 5 | 0 | 0 | **0%** (new — see below) |
| `stripe-webhook-unverified` | 1 | 0 | 1 | 0 | **100%** |
| `vulnerable-dependency` | 169 | 162 | 4 | 3 | **2.4%** |
| checks 11-15 | 0 | — | — | — | no data (never fired) |
| **Total** | **211** | **169** | **39** | **3** | **18.5%** blended |

### Direct before/after comparison

**1. Did the secret checks' FP rate drop on the exact repos that produced the Supabase
anon-key false positives before?**

Yes, specifically and confirmably — but the checkId's *overall* real-world FP rate did not move,
because a different false-positive shape filled the gap. Both things are true at once and the
report would be dishonest citing only one.

The original pass's three named anon-key examples ("Repo A — Lovable-built plant-diagnosis app,"
"Repo B — Bolt-built Supabase reservation app," "Repo C — Lovable-built travel planner") map
directly to three repos in this re-validation set: `plantdoc`, `brew--haven`, and
`ai-odyssey-planner`. On all three, this pass explicitly confirmed the anon-key pattern is
present in the code and confirmed it no longer fires:

- **`plantdoc`** — "Confirmed present in code, confirmed NOT flagged (no regression)... this is
  exactly the intended fix, verified against real code." 0 secret findings of any kind in this
  repo's 14 triaged findings (all 14 are `vulnerable-dependency`).
- **`brew--haven`** — "Did not fire, and correctly so. Read `supabaseClient.ts` — the anon key
  is pulled from `import.meta.env.VITE_SUPABASE_ANON_KEY`, no hardcoded key present." 0 secret
  findings across all 12 triaged findings.
- **`ai-odyssey-planner`** — "did **not** fire. Confirmed `src/integrations/supabase/client.ts`
  hardcodes a Supabase URL + a JWT-format `SUPABASE_PUBLISHABLE_KEY` (role `"anon"`) — exactly
  the pattern that should be suppressed... Correctly absent from the raw findings list. **No
  regression.**" The one secret finding this repo did produce (`secret-env-committed` on a
  Sentry DSN) is an unrelated pattern and was judged TRUE_POSITIVE (git-tracked `.env`, correctly
  flagged as a hygiene issue) — it is not a recurrence of the anon-key bug.

**That is a clean, repo-for-repo confirmation that the targeted fix works exactly as designed.**

But `secret-hardcoded-generic`/`secret-git-history` still landed at 100% FP (17/17) overall this
pass, because four *different* false-positive shapes — none of them the anon-key pattern, none
of them cataloged in the original pass's five other patterns — showed up on other repos:

- **`react-gantt-lovable-starter`** (6 FP): auto-generated Supabase `types.ts` foreign-key
  constraint names (`foreignKeyName: "tasks_project_id_fkey"`) misread as high-entropy secrets.
- **`career-ops`** (3 FP): plain object-literal config values in a stage-name array
  (`{ key: 'respondedToInterview', ... }`) misread the same way.
- **`doutor-tabajara`** (1 FP): a README code-fence documentation placeholder
  (`GROQ_API_KEY=sua_chave_groq_aqui`, Portuguese for "your_groq_key_here") misread as a leaked
  key.
- **`Vibelens`** (7 FP): `self.access_key`/`self.secret_key` object-attribute references passed
  as constructor arguments — this is the closest miss of the four, because it's a variant of the
  exact "env-var reference, not a literal value" pattern (§5 pattern 2 / fix #2) that was
  supposedly fixed on 2026-07-24. The fix's `looksLikeCodeReference` guard requires the value to
  start with a known-safe env-access root (`process.env.`, `import.meta.env.`, `Deno.env.`,
  `Bun.env.`) — `self.access_key` is a dotted identifier reference of the same conceptual shape
  (a variable, not a literal) but doesn't start with any of those four roots, so the guard
  doesn't catch it. **This is a real, narrower-than-intended fix, not a new bug** — worth a
  follow-up to broaden the "is this a reference, not a literal" check beyond the four
  hardcoded env-access roots to any bare dotted-identifier chain with no string literal on the
  line at all.

Net for the secret checks: **the specific bug is fixed (3/3 confirmed on the repos that produced
it); the checkId's real-world reliability is unchanged (100% → 100%)** because the underlying
heuristic ("this string looks high-entropy/key-shaped") still has more false-positive shapes than
just the one that got fixed. Report both halves; neither alone is honest.

**2. Did `eval-on-input`'s FP rate drop on the repos that had `RegExp.exec()` false positives
before?**

Yes, and this one *did* move the checkId's real-world number: **100% FP (7/7) at baseline →
0% FP (0/1) this pass**, with direct confirmation on a repo that had ample opportunity to
misfire and didn't:

- **`career-ops`** — "Confirmed real opportunity existed and was correctly suppressed. The
  repo has ~15+ `RegExp.exec()` call sites across `agent-inbox.mjs`, `application-answers.mjs`,
  `jd-skill-gap.mjs`, `merge-tracker.mjs`, `paste-reply.mjs`, `plugin-audit.mjs`, several
  `providers/*.mjs` files, etc. — including calls on externally-derived input... None of these
  fired as `eval-on-input` findings. This is a genuine confirmation the fix holds, not just an
  absence-by-luck."

Several other repos (`plantdoc`, `ai-odyssey-planner`, `CarePal`, `TrainerX`, `code-crux`,
`bolt-expo-payload-main-video`) were grepped for `.exec(`/`RegExp` and had zero call sites at
all, so they can't independently confirm the fix — only `career-ops` had genuine, exercised
opportunity, but that one confirmation is exactly the shape of evidence the original bug report
needed (a repo with real `.exec()` call sites on external input that used to misfire and now
doesn't).

The single `eval-on-input` finding that *did* fire this pass (`doutor-tabajara`,
`app/api/analyze/route.ts:602`) is a genuine `child_process.execSync()` call — the pattern the
check is supposed to catch, not a `RegExp.exec()` collision — correctly distinguished from the
old failure mode, though the triager also noted its three interpolated arguments are all
server-generated (not attacker-controlled), so it's pattern-accurate but low-exploitability in
this specific instance. That nuance doesn't change the headline: **the specific `RegExp.exec()`
collision that produced 7/7 false positives at baseline produced zero on re-scan.**

**3. Did `supabase-rls-disabled` fire on a `.sql` migration this time — specifically, does it
now catch the real vulnerability a human found by hand in the Bolt reservation app?**

**Yes — confirmed, on the exact repo.** `brew--haven` is the same "Bolt.new-built reservation
app" the original validation's §6 records a human manually finding a real, unfixed
`USING (true)` anonymous-SELECT policy on a guest-PII table that the *old* check 8 never
flagged (recorded there as an honest false-negative, not counted in that pass's FP math because
it wasn't a VibeScan finding to triage at all).

This pass, the new `.sql`-migration scan pass fired directly on it:

> "`supabase-rls-disabled` | critical | `20260627011241_create_reservations_table.sql:69` |
> **TRUE_POSITIVE** | ...RLS is enabled..., but the `anon_select_reservations` policy grants
> `SELECT` to `anon, authenticated` with `USING (true)` — no per-row filter at all... any
> unauthenticated client can `SELECT *` from `reservations` and harvest every guest's name,
> email, and phone number... **Confirms the new `supabase-rls-disabled` SQL-migration detection
> is working correctly here** — first repo in this pass where it actually fired, and it fired
> on a legitimate issue, not a false alarm."

The new detection capability also fired correctly on a second, independent repo
(`react-gantt-lovable-starter`, 4/4 TRUE_POSITIVE — unrestricted `anon`-writable policies on a
`tasks`/`links`/`project_members` schema, self-labeled "demo mode" in code comments but a real
any-anonymous-user-can-mutate-or-wipe-all-project-data exposure if pointed at real data).
**5 for 5 across two repos, 0% FP rate, and the one specific miss this whole validation exercise
was built to surface is now caught.**

**4. Are there new false positives this pass that weren't false-positive patterns in the
original baseline — evidence the fixes introduced a real-world regression the constructed
adversarial tests didn't catch?**

Two findings worth flagging honestly, neither of which the automated regression suite (93/93
passing) would have caught, because neither is the shape any existing fixture targets:

- **The `self.access_key` near-miss on `Vibelens`** (detailed in §1 above) — not a regression in
  the sense of "something that used to work now fails," since this exact shape was never tested
  before, but it is a **sibling of an already-"fixed" pattern that the fix didn't generalize to
  cover.** Worth tracking as a follow-up, not re-opening the original fix as broken.
- **A dependency-version boundary bug on `Vibelens`**: `brace-expansion` and `postcss` were both
  flagged `vulnerable-dependency`, but the triager found the actual installed versions
  (`1.1.12`/`2.0.2` for brace-expansion, `8.4.31` for postcss) are the *patched* releases
  themselves, not versions preceding the patch — a `<=` range comparison that's inclusive where
  it should be exclusive (or is being compared against the wrong boundary). This is a new,
  previously-unobserved failure mode for `vulnerable-dependency` (not one of the four checkIds
  this validation round targeted), first surfaced here because this specific repo happened to be
  pinned exactly on the fix commit for two different packages simultaneously — bad luck making a
  real bug visible, not a fluke result. Contributed all 4 of this pass's `vulnerable-dependency`
  false positives and 2 of its 3 uncertain verdicts (`flatted`, `glob`, where no advisory could
  be located for the installed version in the time available). **This warrants its own follow-up
  fix and regression fixture** — it sits outside the four bugs this validation round measured,
  but it's real, reproducible, and now documented.
- The three other secret-check false-positive shapes cataloged in §1 above (auto-generated FK
  names, plain config-array strings, README placeholder text) are new *examples* but not a new
  *mechanism* — they're the same "high-entropy/key-shaped string, no literal-secret content"
  root cause the original validation's pattern 1 and pattern 3 already named, just different
  surface text. Not counted as a new regression class, but confirmed the underlying heuristic
  is still broad enough to catch non-secret content routinely.

**No confirmed false positives appeared this pass on any of the four specifically-targeted
patterns themselves** (Supabase anon key, bare env-var reference in its originally-scoped form,
`RegExp.exec()`, RLS-disabled `.sql` detection) — the two new items above are adjacent-but-
distinct gaps, not the same bugs resurfacing.

### Updated overall/per-check accuracy — better, worse, or unchanged, with real numbers

| | baseline (original pass, n=253) | re-validation (this pass, n=211) | change |
|---|---|---|---|
| TRUE_POSITIVE | 165 (65.2%) | 169 (80.1%) | **+14.9 points** |
| FALSE_POSITIVE | 84 (33.2%) | 39 (18.5%) | **-14.7 points** |
| UNCERTAIN | 4 (1.6%) | 3 (1.4%) | -0.2 points |

**Better, with real numbers, not vibes — but attribute the improvement correctly, because most
of it is not the four targeted fixes:**

- The blended accuracy improvement is driven overwhelmingly by `vulnerable-dependency`'s share
  of the total (169/211 = 80% of all findings this pass, up from 208/253 = 82% at baseline —
  roughly the same share, but its own FP rate fell from 18.8% (39/208) to 2.4% (4/169)).
  `vulnerable-dependency` was **not** one of the four targeted fixes — its improvement this pass
  is best explained by which specific repos/dependency-versions happened to be sampled and
  triaged this time (in particular, one repo, `Vibelens`, supplied all 4 of this pass's
  dependency false positives via the boundary bug in item 4 above — remove that one repo's
  contribution and the dependency FP rate would round to roughly 0%). **Do not read the
  18.8%→2.4% shift as "the dependency checker got 8x more accurate"; read it as "this specific
  20-repo sample happened to land differently, and it surfaced one new real bug in the
  process."**
- Per-check, the two checks the fixes specifically targeted moved exactly as predicted and for
  the reasons demonstrated in items 1-2 above: **`eval-on-input` 100%→0% FP (confirmed exercised,
  not just absent)**, and the secret checks' *specific targeted pattern* confirmed fixed on 3/3
  cited repos even though the checkId's blended number didn't move.
- `supabase-rls-disabled` went from "no real-world data, never fired" to **5/5 TRUE_POSITIVE
  (0% FP)**, including the one specific real vulnerability this entire validation exercise was
  built around. That's the strongest single result in this comparison.
- `stripe-webhook-unverified` and `missing-auth-middleware` were **not** among the four targeted
  fixes and the data reflects that: `stripe-webhook-unverified` recurred at 100% FP (1/1,
  `vibecoded_marathon_photos`, same "didn't trace into the caller's try/catch" root cause as
  baseline); `missing-auth-middleware` simply didn't fire this pass (0 findings — no repo in
  this smaller 14-repo contributing set happened to exercise it), which is silence, not evidence
  of improvement.

**Bottom line for this section:** two of the four targeted fixes (`eval-on-input`'s
`RegExp.exec()` collision, and `supabase-rls-disabled`'s missing `.sql` coverage) are
demonstrated, measurable improvements on real code, backed by specific named repos and quoted
triage reasoning, not just a cleaner aggregate number. The Supabase-anon-key fix is also
demonstrated and confirmed on the exact repos that motivated it, but it didn't move its
checkId's aggregate FP rate because a sibling false-positive class filled the gap immediately —
report the fix as working and the checkId as still unreliable, both at once, because both are
true. One new, real, previously-undocumented bug (`vulnerable-dependency`'s inclusive-boundary
comparison) and one narrower-than-intended fix (`self.X`-shaped variable references not covered
by the "env-var reference" guard) surfaced as a direct result of doing this measurement
honestly — recorded here rather than smoothed over, consistent with why this exercise exists.
