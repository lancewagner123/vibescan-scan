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

**2. Env-var references, not literal secrets.** Several `secret-hardcoded-generic` hits
were lines like `const KEY = import.meta.env.VITE_SUPABASE_KEY` or
`os.getenv("PINECONE_API_KEY")` — a variable *name* containing "key"/"secret", with no
literal value on the line at all. The heuristic matched the name pattern, not actual
entropy/content.

**3. Test/fixture literals mistaken for live secrets.** A Claude-Code-attributed repo
("Repo D") had `secret-hardcoded-generic` fire on hardcoded hex strings inside its own
`*.test.mjs` files — literal fixture data written specifically to exercise a key-parsing
function's validation logic, never a real credential.

**4. `RegExp.prototype.exec()` mistaken for code execution.** All 7 `eval-on-input`
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
findings:** while manually reading a Bolt.new-built reservation app's Supabase migration
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
