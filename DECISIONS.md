# Autonomous build decisions

This file logs every product/scope decision made by agent panels during the build of
VibeScan without direct user input at the time the decision was made. Each entry records
what was decided and why, so a later reader (human or agent) can see what latitude was
taken and reconstruct the reasoning without having to guess or re-derive it.

## Log

- **2026-07-24** — Scaffolded project skeleton — no decision required.
- **2026-07-24** — Punch-list items 1 (npm package name) and 4 (license), resolved
  autonomously per the ship-readiness panel's prioritized list. See "Package name and
  license" below for the reasoning.

## Package name and license

**2026-07-24.** Resolves punch-list items 1 and 4 from the ship-readiness panel above.

**License: MIT.** `package.json`'s `"license"` was `UNLICENSED` with no `LICENSE` file.
Added a standard MIT `LICENSE` (copyright holder "Lance Wagner", 2026) and set
`"license": "MIT"` in `package.json`. MIT is the right default here: VibeScan's own pitch
is distribution-driven (GitHub Marketplace, `npx`, build-in-public), and a restrictive or
unlicensed package works against that — `UNLICENSED` in particular tells npm/GitHub
tooling the code is technically not redistributable/usable by anyone, which is a direct
contradiction of a "spread via npx" strategy. This is a real product decision made without
Lance's direct sign-off; flagging it here so it's visible and reversible rather than
buried in a diff.

**Package registry name: `vibescan-scan`.** The plain name `vibescan` is already taken on
the public npm registry by a real, unrelated published package (confirmed live via
`npm view vibescan`, not a cached/stale result). The brand name "VibeScan" and the
installed CLI command (`vibescan`, via the `bin` field) are unchanged — only the registry
package-identifier had to move. Checked candidates in order via `npm view <name>`:

- `vibescan-cli` — **also taken** (a real, unrelated published package,
  `vibescan-cli@0.1.0`, "Audit AI-generated code for security issues..." — note this is
  an uncomfortably close README description to our own, but it's a different codebase/
  author and not something we can or should contest by picking a name; just ruling it out
  as unavailable).
- `vibescan-scan` — **available** (registry returned a genuine `E404`/"not found," not a
  network error — confirmed npm registry connectivity was working, since the two prior
  lookups above returned real package data).

Chose `vibescan-scan`. Updated:
- `package.json` (`"name"`) and `package-lock.json` (both `name` fields) to
  `vibescan-scan`. Version, `bin`, dependencies untouched.
- `README.md`'s install/usage line, `npx vibescan scan [path]` →
  `npx vibescan-scan scan [path]`. No other README prose changed — brand references to
  "VibeScan" stand as-is.

**Not touched, on purpose:** `.github/workflows/vibescan.yml` (punch-list item 2, a
separate broken-CI-example fix, out of scope for this pass) and the historical mention of
`vibescan@0.0.5`/`npx vibescan scan` in the ship-readiness panel entry above — that text
describes what reviewers saw at the time of that panel and is left as an accurate record
of the past, not live instructions to keep in sync.

Registry availability for `vibescan-scan` was confirmed against the real, live npm
registry (network access to registry.npmjs.org was working in this session) — this does
not need to be re-verified before publishing, but a final `npm publish --dry-run` is
still good practice immediately before the actual publish in case the name is claimed
between now and then.

## Final v1 ship-readiness panel

**2026-07-24.** Five independent reviewers (PM, Security Engineer, Founder/Distribution,
Skeptical Buyer, Final Auditor) each read the codebase directly and cross-checked the prior
verification report's claims against the actual code and CLI rather than trusting its prose.

### Converged verdict: **NOT READY — do not publish, post, or point real users at this yet.**

Three of five reviewers (PM, Security Engineer, Final Auditor) landed on "ship with named
caveats." Two (Founder/Distribution, Skeptical Buyer) landed on "not ready," and the Final
Auditor's own write-up separately labeled the CI-workflow bug a "blocking issue" while still
recommending ship. The disagreement is not a misunderstanding — the "not ready" findings are
independently reproduced, concrete, and confirmed by three of the five reviewers in total:

- `npm view vibescan` shows the package name is already taken by an unrelated, real,
  published package (`vibescan@0.0.5`). The README's own `npx vibescan scan [path]`
  instruction — the literal first command a new user or a Reddit/PH reader would run —
  would install someone else's software, not this tool.
- `.github/workflows/vibescan.yml`, explicitly presented as copy-paste documentation
  ("Copy it into your project's own `.github/workflows/` directory"), calls
  `--repo`, `--out`, `--report`, `--format`, and `--fail-on` flags that do not exist
  anywhere in `bin/vibescan.js`. Running it verbatim fails immediately (`Unknown command`).
  This was independently reproduced by three reviewers (Founder, Skeptical Buyer, Final
  Auditor), not just claimed by one.
- There is no `--fail-on`/exit-code contract at all — `vibescan scan` exits `0`
  unconditionally regardless of findings (confirmed against a fixture with 9 critical
  findings), so the CI use case the workflow file itself describes ("fail the build on
  critical findings") cannot work even once the flags above are fixed.
- `package.json` declares `"license": "UNLICENSED"` with no `LICENSE` file — not yet
  legally distributable to the public.

Per this panel's own resolution rule (favor the more conservative verdict unless the
disagreement is clearly a misunderstanding), these are real, reproduced, code-level facts,
not a misread — so the converged verdict is **not ready**, not "ship with caveats."

**Important nuance, so this isn't misread as "start over":** every reviewer, including the
two "not ready" votes, affirms the *scanning engine itself* — the 10-check catalog, the
severity-integrity guarantees in `reconcileWithSource`, the prompt-injection defenses, the
now-closed evasion bypasses, the honesty of `SECURITY_SCOPE.md` — is sound, verified against
the actual source (not just the report's prose), and does not need to be rebuilt. What's
"not ready" is narrowly the *launch surface*: the package identity, the CI documentation
example, the exit-code contract, and the license file. These are fast, mechanical fixes, not
a redesign, and none of them touch the scanner or triage logic.

### Caveats / known limitations now made visible to users

Folded into `SECURITY_SCOPE.md` directly (edited as part of this panel, not just recorded
here) — the check-7 (`missing-auth-middleware`) section now also documents two gaps the
Final Auditor found on ordinary, non-adversarial Express code:
- **False negative:** `router.route('/path').get(handler)` (Express's standard chained
  route syntax) produces zero findings even with no auth check present, because the path
  literal and the HTTP-method call are only matched when they appear in the same
  `.method(...)` invocation.
- **False positive:** `router.use(requireAuth)` applied once at the top of a router file
  is not recognized, so every route below it — even though correctly secured — gets
  flagged as missing auth.

Already present in `SECURITY_SCOPE.md` before this panel (confirmed still accurate, no
changes needed) and worth restating as load-bearing for the ship decision:
- The `secret-git-history` / git-history-sourced `secret-env-committed` ancestor-repo bug:
  scanning a non-repo-root subdirectory silently walks and reports on an ancestor repo's
  history. Documented, **not fixed**. Treat any finding from this path as suspect until
  `git rev-parse --show-toplevel` is confirmed to equal the scanned path.
- All ten checks are regex/text heuristics, not a parser or dataflow engine, and every one
  has a documented, still-open "next-level" evasion (see the per-check list already in
  `SECURITY_SCOPE.md`).
- Evasion-attempt and prompt-injection-variant fixtures exist on disk but are **not**
  wired into `npm test` (which runs only `test/e2e.test.js`) or any CI — the guarantees
  this panel verified by hand are not regression-protected.

Not folded into `SECURITY_SCOPE.md` (these are distribution/packaging facts, not scanning
scope, so they belong in README/launch collateral instead, as punch-list items below):
package name collision, broken CI example, missing exit-code contract, `UNLICENSED` license.

### Prioritized punch list (not built now — recorded for whoever picks this up next)

1. **Resolve the npm package identity** — rename or scope (`@you/vibescan`), confirm
   availability, and make the README's install command match reality before any public
   post. Blocks everything else about public distribution.
2. **Fix or delete `.github/workflows/vibescan.yml`** — replace the fake flags with the
   real `vibescan scan .` invocation and reading `./vibescan-report.json`/`.md` off disk,
   or remove the file until it's accurate. It is currently the single most likely piece of
   collateral to get screenshotted and it fails on line 1.
3. **Add a real `--fail-on <severity>` flag with a non-zero exit code** — the CI/gating use
   case (the main argument for a recurring subscription rather than a one-off scan) does
   not exist yet; `scan` exits 0 unconditionally today.
4. **Pick a real license and add a `LICENSE` file** — replace `UNLICENSED` before any public
   repo push or npm publish.
5. **Add a runtime guard to `secret-git-history`/`secret-env-committed`** — detect when the
   scanned path isn't its own git repo root (`git rev-parse --show-toplevel`) and warn or
   skip that check with a plain-English message, instead of relying on users reading
   `SECURITY_SCOPE.md`.
6. **Wire `test/fixtures/evasion-attempts/` and `test/fixtures/prompt-injection-variants/`
   into `npm test`/CI** — turn the one-time manual red-team verification into a permanent
   regression gate so the next scanner refactor can't silently reopen a closed evasion or
   weaken the severity/prompt-injection integrity guarantees.
7. **Fix the two `missing-auth-middleware` gaps** documented above (chained-route false
   negative, `router.use()` false positive) — both are common, idiomatic Express patterns,
   not corner cases.
8. **Some evidence of an operated product, not a solo pre-alpha repo**, before charging
   money — a support/on-call story, and a case for what recurs monthly beyond re-running a
   free `npx` command (dashboard, historical diffing, team seats, integrations) — raised by
   the Skeptical Buyer and out of scope for a v1 CLI but relevant if this becomes a paid
   product per the original pitch.

**Reviewers:** PM, Security Engineer, Founder/Distribution, Skeptical Buyer, Final Auditor —
each read the source independently and cross-checked claims against `README.md`,
`SECURITY_SCOPE.md`, `docs/CHECK_CATALOG.md`, `package.json`, `.github/workflows/vibescan.yml`,
`bin/vibescan.js`, and `src/`.

## Punch-list closure and re-verification

**2026-07-24.** A fix pass addressed all 8 items above, followed by a skeptical-buyer
adversarial redux, followed by this independent re-verification pass (re-running the actual
commands one more time rather than trusting either prior pass's prose). Findings below are
from commands run in *this* pass, not copied from the redux's report.

**Final package identity:** name `vibescan-scan`, license `MIT` (`LICENSE` file present,
copyright "Lance Wagner", 2026). `bin` field still installs the `vibescan` command via
`npx vibescan-scan scan [path]`.

### Status of the 7 fix-pass punch-list items (1-7 above; item 8 was out-of-scope-for-v1, not attempted)

1. **Package identity — CLOSED.** `package.json` name/license confirmed as above.
2. **CI workflow — CLOSED.** `.github/workflows/vibescan.yml` read directly: it now calls
   `npx vibescan-scan@latest scan . --fail-on high`, real flags matching `bin/vibescan.js`,
   headed explicitly as consumer-facing example documentation, not this repo's own CI.
3. **`--fail-on` / exit code — CLOSED, re-verified live.** Ran
   `node bin/vibescan.js scan test/fixtures/vulnerable-demo-app --fail-on critical` myself:
   9 critical / 7 high findings, **exit code 1**. Ran the same flag against a freshly created
   empty non-git temp directory: no issues found, **exit code 0**. Both directions hold.
4. **License — CLOSED.** Verified above.
5. **Git-history ancestor-scope guard — CLOSED, re-verified live.** Ran a scan against
   `test/fixtures/evasion-attempts` (a subdirectory of this repo, not a repo root): got the
   explicit "SKIPPED git-history secret scanning... scanned path is not its own git
   repository root" warning for both the `secret-env-committed` and `secret-git-history`
   sub-scans, surfaced up front in the terminal output, not buried in JSON. No misattributed
   findings were produced.
6. **Evasion/prompt-injection fixtures wired into `npm test` — CLOSED, re-verified live.** Ran
   `npm test` myself: 13/13 tests pass, including one per `evasion-attempts` subfolder
   (checks 1-10) and the `prompt-injection-variants` escaping test. Not a rubber stamp — this
   is a real regression gate now.
7. **`missing-auth-middleware` gaps (chained-route false negative, `router.use()` false
   positive) — LOGIC CLOSED, but test coverage still OPEN.** Ran
   `node bin/vibescan.js scan test/fixtures/regression-samples` myself: exactly 1 finding,
   from `chained-route-no-auth.js` (the chained-route case correctly flagged); zero findings
   from `router-use-guard-protected.js` (the guarded case correctly suppressed). The detection
   logic is genuinely fixed. **But** `grep -rn "regression-samples" test/` returns nothing —
   these two fixtures are not wired into `npm test` or CI, unlike the evasion/prompt-injection
   fixtures in item 6. This is the same regression-coverage lesson item 6 already applied,
   not yet applied to item 7's own fixtures. Concretely: a future refactor of
   `checkMissingAuthMiddleware` could silently reopen either gap and nothing in `npm test`
   would catch it. Low severity (doesn't break anything working today), but genuinely
   unresolved — do not mark this item fully closed.

### Overall ship verdict

**Ship now, with one named caveat.** All four of the original "not ready" blockers (package
identity, CI documentation, exit-code contract, license) are independently re-verified fixed.
The evasion/prompt-injection regression-test gap the original panel flagged is also
independently re-verified fixed. The one remaining open item is narrow and low-risk: wire
`test/fixtures/regression-samples/{chained-route-no-auth.js,router-use-guard-protected.js}`
into `npm test` the same way `evasion-attempts`/`prompt-injection-variants` were wired in
(estimated 15 minutes of work) — until that lands, the `missing-auth-middleware` fixes for
chained routes and `router.use()` guards are correct today but not regression-protected against
a future refactor. This does not block using or publishing v1; it's a follow-up, not a
blocker.

## Final closure: regression-samples test wiring

Closed the one remaining named caveat above. Added two tests to `test/regression.test.js`
(`chained-route-no-auth.js` gap-A case, `router-use-guard-protected.js` gap-B case), scanning
`test/fixtures/regression-samples/` once and filtering findings by `finding.file` per test
(`scanRepo()` has no per-file include filter — confirmed by reading `src/scanners/index.js`
directly before assuming one existed). `npm test` now runs **15/15 passing**, independently
re-run and confirmed, not taken on faith from any prior agent's report. Also independently
re-verified, directly, rather than trusting the punch-list/redux reports: `git log` shows all
12 commits from this session in the expected order with a clean working tree; `package.json`
has `name: "vibescan-scan"`, `license: "MIT"`; `node bin/vibescan.js scan
test/fixtures/vulnerable-demo-app --fail-on critical` exits `1` as documented.

**All 7 original punch-list items are now genuinely closed**, each independently re-verified
by running the actual commands rather than trusting any single report:
1. Package name collision — resolved (`vibescan-scan` on the registry, `vibescan` command via
   `bin`).
2. CI workflow example — rewritten against the real CLI, locally proven to produce exit code 1
   on findings.
3. `--fail-on`/exit-code contract — implemented and verified in both directions (findings /
   no findings).
4. License — MIT, `LICENSE` file present.
5. Git-history ancestor-repo misattribution — runtime-guarded, skips with a surfaced warning
   instead of misattributing.
6. Evasion/prompt-injection fixtures wired into `npm test` — 13 tests, all passing.
7. `missing-auth-middleware` chained-route and `router.use()` gaps — logic fixed **and** now
   regression-tested (this entry).

### Final ship verdict: **Ship now.** No remaining named caveats from this session's punch list.

## v1.1: 5 new checks (insecure-random-token, weak-password-hashing, mass-assignment, insecure-cookie-flags, open-redirect)

**2026-07-24.** Five independent reviewers (PM, Security Engineer, Founder/Distribution,
Skeptical Buyer, Final Auditor) evaluated v1.1 — the five checks added on top of the v1.0
ten, taking `v0.2.0` from 10 to 15 total checks. Each read `docs/CHECK_CATALOG.md`,
`SECURITY_SCOPE.md`, `README.md`, `package.json`, and `src/` directly and built their own
adversarial test cases rather than trusting the prior verification report's prose.

### Converged verdict: **Ship with named caveats.**

All five reviewers independently landed on the same top-line verdict — not a split this
time. `npm test` is 20/20 (independently re-run in this pass, matches). The demo-app
fixture yields exactly 9 critical / 11 high / 1 medium / 0 low across all 15 unique
checkIds (independently reproduced by two reviewers). All 15 evasion-attempts fixtures
fire. No stale "10 checks" language anywhere in scope. Version is correctly `0.2.0`.

**However, the Final Auditor found a real, blocking-grade gap the other four reviewers'
adversarial tests happened not to hit, and per this project's own conflict-resolution rule
(favor the conservative reading unless a disagreement is clearly a misunderstanding), that
finding is treated as authoritative rather than averaged away.** This pass independently
re-ran the Final Auditor's exact repro before writing it into `SECURITY_SCOPE.md` (not
taken on faith):

- An arrow-function helper (`const generateWeakValue = () => Math.random()...; const
  resetToken = generateWeakValue();`) — the *identical* pattern
  `SECURITY_SCOPE.md` already claims is closed for check 11, just spelled as an arrow
  function instead of a `function` declaration — produces **zero findings**. Confirmed
  live: `VibeScan: no issues found.`
- A semicolon-free variable declaration (`const HASH_ALGO = 'md5'` then
  `crypto.createHash(HASH_ALGO)`, no semicolons anywhere in the file) — produces **zero
  findings** for check 12, while the identical semicoloned case still fires correctly.
  Confirmed live.

Root cause (read directly in `src/scanners/util.js`): `lookupFunctionReturnExpr` (line
418) only matches a `function name(...) { ... }` declaration via regex — an arrow-function
assignment is a different textual shape it was never written to recognize, not merely "one
hop further." `resolveConcatExpression` and `resolveIdentifierChain` both require a
literal trailing `;` in their declaration-matching regex, so semicolon-free code (a common,
non-adversarial style — Standard.js, `semi:false`, plenty of AI-generated code) silently
defeats the variable-hop resolution both helpers provide. These three shared helpers back
the "same-day fixes" `SECURITY_SCOPE.md` credits to checks 5, 11, 12, 13, 14, and 15 — so
this is a shared-root-cause gap across six claimed fixes, not an isolated miss in one
check, and it is triggered by mainstream style choices, not adversarial obfuscation.

This does not overturn the "ship with named caveats" verdict — every reviewer, including
the Final Auditor, agreed the engineering bar (tests, fixture coverage, doc consistency,
scope discipline) is genuinely met and the five checks are a real, honest addition, not
scope creep. But it does mean the caveat has to be sharper than "these are heuristics with
some documented limits" — `SECURITY_SCOPE.md` was, until this pass, actively overstating
what got closed for six of its "same-day fixed" claims.

### Caveats now made visible to users

**Folded into `SECURITY_SCOPE.md` directly, as part of this entry (not just recorded
here):** a new disclosure block immediately after the two red-team-pass paragraphs states,
in the checks' own words, that (a) `lookupFunctionReturnExpr` only recognizes `function`
declarations and is blind to arrow-function helpers for checks 5/11/14/15, (b)
`resolveConcatExpression`/`resolveIdentifierChain` require a literal trailing `;` and are
defeated by semicolon-free code for checks 12/13, and (c) every "closed the same day" claim
for 5/11/12/13/14/15 should be read as "closed for `function`-declaration-and-semicolon
styled code only" until both gaps are fixed.

Already accurately disclosed before this pass, reaffirmed as still true:
- All five new checks lean on naming/vocabulary heuristics (variable names, file-path
  shape, literal algorithm names) more than the original ten's structural checks did —
  documented per-check in `SECURITY_SCOPE.md`, and independently reproduced by the
  Skeptical Buyer with two fresh hand-written bypasses (`magicLinkToken` naming evades
  check 11; unsalted `sha256` evades check 12) that aren't even adversarial, just
  differently-named ordinary code.
- Three of the five (`mass-assignment`, `insecure-cookie-flags`, `open-redirect`) are
  Express-API-shaped and detect nothing in Fastify/Koa/Next.js API routes/Django/Flask/
  Rails — noted by the Skeptical Buyer, not yet called out as loudly in the README as the
  "15 checks" headline is.
- `mass-assignment`'s schema `category` is `injection` but it's operationally grouped with
  the `authz` checks for extra-scrutiny purposes in `SECURITY_SCOPE.md`'s prose — the
  mismatch is self-disclosed there but not reflected in `docs/FINDINGS_SCHEMA.md` itself,
  so anything filtering findings programmatically by `category: authz` will silently miss
  it (PM finding, minor, not blocking).
- `insecure-random-token` and `weak-password-hashing` shipped as `critical` and were
  downgraded to `high` in a same-day follow-up commit after an audit — a real
  severity-rubric correction, caught same-day rather than by a customer, but a sign the
  initial severity call wasn't fully settled before the first commit (Skeptical Buyer).

### Prioritized punch list

1. **Fix the two shared-helper gaps this pass found and disclosed** — extend
   `lookupFunctionReturnExpr` (`src/scanners/util.js`) to also match
   `const/let/var name = (...) => ...` arrow-function assignments, and loosen
   `resolveConcatExpression`/`resolveIdentifierChain`'s declaration regex to accept
   end-of-line/`\n` as an implicit terminator in addition to `;`. Add regression fixtures
   for both the arrow-function and no-semicolon variants of checks 5/11/12/13/14/15. This
   is the top-priority item — it's the gap between what `SECURITY_SCOPE.md` currently
   claims and what the code actually does. (Adversarial repro scripts from the Final
   Auditor's own pass were left in a scratch temp directory, not this repo, per the
   review's file listing — not carried forward as fixtures automatically; write fresh ones
   alongside the fix.)
2. **Add a README-visible callout that checks 11-15 are judgment-heavier than 1-10** — the
   PM and Founder both flagged that this risk currently only surfaces in
   `SECURITY_SCOPE.md`'s per-check bullets, not in the top-line pitch a buyer reads first.
3. **Make the AI-assistant-specific case for checks 11-15 explicit in the README/marketing
   copy** — one sentence per new check tying it to a vibe-coding failure mode (Founder),
   so the pitch doesn't read as generic OWASP-Top-10 feature-count competition.
4. **Reconcile `mass-assignment`'s category classification** — either change its schema
   `category` to something authz-adjacent or document the exception directly in
   `docs/FINDINGS_SCHEMA.md`, not only in `SECURITY_SCOPE.md`'s prose (PM, minor).
5. **Write down an explicit bar for check #16+** before adding more — AI-assistant-specific
   pattern, evasion-tested, false-positive-audited against real (non-fixture) repos, not
   just fixtures — so "narrow, closed list" doesn't quietly become "narrow this release"
   (Founder).
6. **Refresh stale inline comments in two evasion fixtures**
   (`test/fixtures/evasion-attempts/13-mass-assignment/user-controller.js` and
   `15-open-redirect/logout.js`) that still describe pre-fix behavior even though the
   regression/e2e tests now assert the fix — internal-only, not a user-facing honesty
   problem, but misleading to a future contributor skimming the fixture instead of running
   the tests (Security Engineer).
7. **One more red-team round before advertising checks 11-15 with the same confidence as
   1-10** — five "found-and-fixed same day" cycles in a row, now including the gap this
   pass itself found, is one hardening pass, not the track record 1-10 earned over time
   (PM).

**Reviewers:** PM, Security Engineer, Founder/Distribution, Skeptical Buyer, Final Auditor
— each read `docs/CHECK_CATALOG.md`, `SECURITY_SCOPE.md`, `README.md`, `package.json`, and
`src/` directly, independently ran `npm test` and the CLI against fixtures and their own
hand-written adversarial samples.

### Ready to push?

Not this agent's call — per this task's instructions, pushing to GitHub or npm is left to
the orchestrator to decide separately. This entry records the converged verdict and the
punch list a push decision should weigh, not the push decision itself.

## Punch-list item 1 closed: mainstream-style-variant detection gap (2026-07-24)

Fixed the top-priority item from the v0.2.0 panel's punch list — the gap between what
`SECURITY_SCOPE.md` claimed was "closed the same day" and what the shared helpers in
`src/scanners/util.js` actually resolved. Verified independently (not taking the prior
report on faith) by reproducing both bypasses live before fixing:

1. **`lookupFunctionReturnExpr`** only matched `function name(...) { ... }` declarations —
   an arrow-function helper (`const gen = () => Math.random()...`, both concise/implicit-return
   and block-body-with-`return` forms) was invisible to it, defeating checks 5, 11, 14, 15.
   Fixed: now resolves both arrow-function forms in addition to the original `function`
   declaration form.
2. **`resolveConcatExpression`/`resolveIdentifierChain`** required a literal trailing `;` to
   recognize a `const/let/var` declaration — semicolon-free code (Standard.js style,
   `semi:false`) defeated checks 12 and 13. Fixed: the trailing `;` requirement was removed
   (it was never load-bearing — `[^;\n]+` already stops at the first `;` or newline on its
   own, so requiring a literal `;` right after only rejected semicolon-free declarations
   without changing what got captured in the semicolon-present case).

Also fixed while in the same file: a pre-existing, previously-deferred bug (`makeId()` had
a stray literal NUL byte where a space was intended, causing `grep`/most text tooling to
treat `util.js` as a binary file — noted as an incidental finding during the original build
and explicitly deferred as "unrelated to this task" at the time; fixed now as a one-line,
zero-risk cleanup while already touching this file).

**Verification (real commands, not summarized from an agent report):** both original
bypasses re-tested directly against the fixed helpers and confirmed resolved, with
regression checks confirming the semicolon-present/`function`-declaration cases still work
identically (no behavior change for the previously-working case). Added
`test/fixtures/evasion-attempts/16-mainstream-style-variants/` (two files, one per gap) and
wired both into `test/regression.test.js` — full suite now 22/22 passing (up from 20).
`SECURITY_SCOPE.md`'s "Known evasion limitations" section rewritten to record this as
found-and-fixed rather than an open gap.

**Also closed, smaller punch-list items:**
- Item 4 (mass-assignment category reconciliation) — documented the `category: injection`
  vs. operational-`authz`-tier exception directly in `docs/FINDINGS_SCHEMA.md`, rather than
  changing the actual `category` value (which existing code/tests depend on).
- Item 6 (stale evasion-fixture comments) — `test/fixtures/evasion-attempts/13-mass-assignment/
  user-controller.js` and `15-open-redirect/logout.js` had comments describing bypasses as
  still-open when both are in fact now caught (confirmed by direct scan before editing);
  rewritten to describe the fix, matching the "originally evaded, now fixed" convention
  used elsewhere in this fixtures directory.

**Left open, not addressed this pass** (lower priority, more judgment-dependent — punch-list
items 2, 3, 5, 7): README-visible callout that checks 11-15 are judgment-heavier than 1-10;
explicit per-check AI-codegen framing in marketing copy; a written bar for check #16+; one
more full red-team round before advertising 11-15 with full confidence. These are copy/process
decisions, not correctness bugs, and are reasonable to leave for whenever this ships toward
real users rather than fix reflexively now.

`npm test`: 22/22 passing. Committed on top of a clean tree.

## Round-2 deep testing: checks 11-15, then all 15 together (2026-07-24)

A full second-round testing cycle: first an adversarial deep-dive on checks 11-15 alone
(three independent testers — an evasion hunter, a false-positive hunter, and a
realistic-library tester exercising real Mongoose/Sequelize/Prisma/Express call shapes),
then a follow-up pass across all 15 checks together (checks 1-10 included) to catch any
interaction or regression the checks-11-15-only pass might have missed in isolation.

**What was tested:** every finding from all three round-2 reports against checks 11-15 (14
evasion gaps, 3 false-positive gaps, 4 realistic-library gaps) plus the follow-up
all-15-checks sweep, triaged directly against `src/scanners/{secrets.js,static-checks.js,
util.js}` rather than taken on faith.

**Real bugs found and fixed (25 total, all with regression tests):**
- **Checks 11-15 (20 fixes):** shared-helper gaps in `util.js` (async-arrow and
  TypeScript-return-type helper resolution, class-static-method dispatch, multi-line
  return-expression extraction, class-static-field resolution) that fed forward into
  check 11 (bracket-key template literals, computed `crypto['createHash']`,
  static-method/async-arrow token generators, static-field hash algorithms), check 13
  (bracket `req['body']` access, plain/renamed/nested destructuring, Mongoose
  `findByIdAndUpdate`-family calls, Prisma's `{ data: req.body }` shape), check 14
  (paren-wrapped arrow object literals), and check 15 (optional chaining/nullish
  coalescing, template-literal targets, awaited helper calls, the `new URL(...)`
  base-argument redirect bypass). Plus 5 false-positive fixes: `secure:`
  NODE_ENV-conditional cookies, inline-call cookie-options resolution, the
  `author`/`auth` substring collision, `new URL` + `.origin` redirect guards, and
  non-prefixed allowlist array names — and a `tokenizerSeed`-style token-keyword false
  positive fixed via a JS-side boundary post-filter (a naive regex lookahead was found to
  be actively wrong under the pattern's own `i` flag).
- **Checks 1-10 (2 fixes), found by the all-15 follow-up pass:**
  1. **Check 7 (`missing-auth-middleware`) camelCase false positive** —
     `AUTH_KEYWORD_AS_ARG_RE` inherited a `\b` word-boundary anchor from
     `AUTH_KEYWORD_RE`, so idiomatic camelCase middleware names (`requireAuth`,
     `checkAuth` — "Auth" starting mid-identifier, not at a word boundary) were invisible
     to the inline-argument, concat-path, and chained-route auth checks, causing real
     middleware to be reported as missing. Fixed by extracting a shared, unanchored
     `AUTH_KEYWORD_VOCAB` both regexes now build from, mirroring the precedent already
     set by `AUTH_MIDDLEWARE_NAME_RE`.
  2. **Check 9 (`stripe-webhook-unverified`) imprecise anchor** — both the
     no-`constructEvent` and `constructEvent`-present-but-unenforced code paths anchored
     their finding to the first `/webhook/i` substring match anywhere in the file (which
     could land on unrelated code, e.g. a `webhook_events` SQL table name), causing
     visual collision with unrelated findings on the same line. Fixed by anchoring to the
     actual `req.body`/`request.body` or `constructEvent`/fallback match that drives each
     finding.

**Documented as accepted limitations instead of force-fixed:**
- Check 11: `secretIngredient`/`gameToken`/`animationToken` — syntactically identical to
  real token names at a genuine camelCase segment boundary; no regex/boundary heuristic
  can distinguish them without semantic understanding of the code.
- Check 12: a password-hashing check's route-path/file-path collision (an unrelated
  `createHash('md5')` call flagged because "password" appears incidentally nearby, or
  because the file lives under an auth-ish path) — a deliberate recall-over-precision
  tradeoff, not worth chasing with more context-window tightening.
- Check 13: mass-assignment's lack of model-schema awareness (a call flagged even when
  the target model has no privileged fields to smuggle in) — inherent to a
  regex/text-based scanner with no access to the actual schema definition.
- Check 9: a borderline false positive where a fake bcrypt-shaped password *hash* trips
  the unrelated `secret-hardcoded-generic` generic-entropy heuristic — same category as
  the already-documented substring/entropy tradeoffs above.

**Before/after test count:** 22/22 passing at the start of this round → **48/48 passing**
at the end (20 new regression tests for the checks-11-15 gaps/false-positives, plus 1 new
regression test for the check 7 camelCase fix). Independently re-run and confirmed, not
just taken from agent reports.

**Independent verification performed directly (not trusting prior session reports):**
`npm test` re-run clean at 48/48; `git log`/`git status` confirmed a clean tree with 5
logical commits for the checks-11-15 pass; `bin/vibescan.js scan` re-run against
`test/fixtures/vulnerable-demo-app` and all 15 original `checkId`s confirmed present in
the raw JSON output; every new fixture/test file inventoried directly from the filesystem
(`test/fixtures/evasion-attempts/17-round2-new-evasions/` — 17 files,
`test/fixtures/evasion-attempts/18-realistic-library-gaps/` — 4 files,
`test/fixtures/regression-samples/inline-camelcase-auth-arg.js`,
`test/false-positives.test.js`, and `test/fixtures/synthetic-realistic-app/`).

**Confidence assessment after this round:** checks 1-10 — high; both bugs found were
narrow anchor/word-boundary issues in already-solid detection logic, not shape-level
gaps, and this round specifically added a cross-check pass they hadn't had before. Checks
11-15 — moderate-to-high; two independent adversarial rounds (red-team + evasion/FP/
library-realism) have now been run against them versus one for 1-10, and the remaining
open items are all documented, judgment-dependent tradeoffs rather than known-exploitable
blind spots, but they are newer code with less real-world mileage than 1-10.

## Round 3 (Opus-powered): checks 1-9 retrofit, fresh look at 11-15, adversarial audit + strategic consult (2026-07-24)

Opus-powered round. Five distinct passes: a testing sweep across all 15 checks, a fix
pass, an independent adversarial technical audit, a strategic consult, and a final
fix-from-review pass. Independently verified at close (not taken from agent reports):
`npm test` re-run clean, `git log`/`git status` confirm a clean tree at `a6aa715` with
four logical round-3 commits, and `bin/vibescan.js scan test/fixtures/vulnerable-demo-app`
re-run with all 15 `checkId`s confirmed present in the raw JSON output.

**What was tested:** the round-2 sophisticated-evasion catalog — which had only ever been
applied to checks 11-15 — was retrofitted onto checks 1-9, plus a fresh adversarial look
at 11-15 and a dedicated stress pass on check 10 (dependencies).

**What was found and FIXED (21 false negatives + ~3 false positives + 4 check-10 defects):**
- *Checks 1/3 (secrets):* TS type annotation on a generic secret, bracket/computed key
  (`config['apiSecret']=…`), known-format secret split with a `${…}` template placeholder.
- *Check 4 (SQL):* `db['query'](…)` bracket method, TS return-type on a builder helper,
  SQL built into a TS-typed variable.
- *Check 5 (eval):* `eval(await asyncArrowHelper(…))` (leading `await` stripped).
- *Check 6 (CORS):* `credentials: x ?? true`/`|| true`; wildcard origin in a class static
  field / TS-typed variable.
- *Check 7 (auth):* genuinely-unauthed route with a `pageToken` handler-body local, plus a
  single-element `[requireAuth]` array FP — one structural change restricting the auth-arg
  test to middleware argument positions fixed a real two-way bug (was flagging the SAFE
  route and missing the dangerous one).
- *Check 8 (Supabase):* `process.env[[…].join('_')]` and `process.env['A'+'B']` computed keys.
- *Check 9 (Stripe):* `req['body']` bracket read and `const { body } = req` destructured read.
- *Checks 11/12:* no-semicolon helper-call token; destructured `const { createHash } = require('crypto')`.
- *Checks 13/15:* `req.body as Dto` / `req.body!`; spread-into-create mass assignment;
  `res.redirect(req['query'].next)`.
- *Systemic:* shared resolvers now tolerate a TS variable annotation before `=`.
- *False positives fixed:* `your-*-here`/`replace-with-*` placeholder env values; hyphen/
  compound env-template filenames (`.env-example`); ES6 shorthand `{ httpOnly, secure }`.
- *Check 10:* colliding finding ids across workspace package.json files, raw npm stderr
  leaking to terminal, missing child-process timeout, misleading hardcoded "no network
  access" warning now attributes the real cause.

**Documented as accepted scope limits (not force-fixed):** base64+split-literal secret
combo; keyword-named-LHS non-adjacency; check-4 class-static/bare SQL builders; check-5
computed `eval`/`exec` callees; check-11 IIFE/getter token sources; check-10 dev-vs-prod
severity, lockfile/package.json divergence, and pnpm/yarn + `workspace:` monorepo gaps
(npm audit cannot read pnpm/yarn lockfiles — a workspace-aware rewrite is out of scope).

**Before/after test count:** 48/48 at the start of the round → **80/80 at the end** (32 new
regression + false-positive tests, incl. two network-free unit tests for the check-10 fixes).
Zero skips/todos.

**Adversarial auditor's verdict — NO blocking issues.** The auditor did not trust the fix
report: they read every scanner in full, authored their *own* bypass fixtures (not the
repo's), and ran them against both the current HEAD and a worktree checked out at the
pre-round-3 commit `b82d2a3` to get true before/after deltas. Five of the most consequential
fixes were independently reproduced with real before/after output (eval-on-input, bracket/
concat secrets, Stripe `req['body']`/destructure, Supabase computed env key, and the check-7
two-way auth bug). The shared `stripComments` chokepoint — the single-point-of-failure that
every static check runs against — was stress-tested against 15 adversarial inputs and
preserved length + newline count exactly on all of them (a latent fragility, not an active
bug). Only three non-blocking polish notes: a raw `git` stderr leak on non-git targets, an
unguarded `stripComments` call site, and a destructured/aliased `Math.random` doc-completeness
nit. Verdict: "Trustworthy to ship as a fast first-pass scanner within the limits
`SECURITY_SCOPE.md` already discloses." The final fix-from-review pass declined to
manufacture fixes for the three accepted-limitation polish notes and left the tree clean.

**Strategic consultant's recommendation — stop hardening, measure real-world FP rate, ship.**
Quoted directly, not paraphrased:

> "The scanning engine is sound and has been verified sound by five independent panels and
> three hardening rounds. You are now well past the point of diminishing returns on
> regex-hardening, the raw finding counts are misleading you into thinking otherwise, and the
> single most valuable thing you have never done — run this against a real repo you didn't
> write — is the one thing standing between 'verified against fixtures' and 'survives a real
> user.' Stop hardening. Measure the real-world false-positive rate, fix the README's one
> honesty gap, and ship."

> "Direct recommendation: stop hardening and get this in front of real code. Specifically —
> clone 15-30 real, public AI-generated apps (Lovable/Bolt/Replit/Cursor output on GitHub),
> run VibeScan, hand-triage every single finding as true-or-false-positive, and measure the
> real-world false-positive rate. Then publish."

The consultant's rationale: round 3's 21 findings were a one-time backlog flush (the round-2
catalog finally applied to the nine checks that had never seen it), not fresh discovery — new
vulnerability *classes* per round are collapsing and what remains are architectural limits a
regex tool structurally cannot close. Every round so far has been a closed loop (the same
process invents the evasions and closes them against its own fixtures), which says nothing
about the only metric that decides adoption: how often the tool cries wolf on code someone
else wrote. The consultant also flagged three README/docs honesty drifts to fix before any
public post: checks 11-15 are billed identically to 1-10 despite being judgment-heavier with
unfixable false positives (`secretIngredient`, `gameToken`); the Express/JS framework
limitation isn't in the README; and (now addressed by this entry) DECISIONS.md was a full
round behind. Confidence rating in founder's terms: checks 1-10 HIGH (believe them), checks
11-15 MODERATE and prone to false alarms (treat as "worth a look," not a verdict).

**Actionable next step for the human:** do NOT run a round 4 of fixture hardening. Fix the
README honesty gap (distinguish the 1-10 vs 11-15 confidence tiers; disclose the Express/JS
framework scope), then run VibeScan against 15-30 real public AI-generated repos and
hand-triage every finding to measure the real-world false-positive rate. Publish once that
number is known.

## Real-world false-positive validation (20 real repos) (2026-07-24)

Did exactly what the round-3 consultant asked instead of a round 4 of fixture hardening: 20
real, public AI-generated repos (Lovable ×3, Bolt.new ×3, Claude Code ×1, v0.dev ×1, one
dual-tagged, 8 profile-match "plausible," 3 included only for stack diversity with no AI-tool
signal) were sourced via real GitHub search, cloned, scanned with `vibescan scan`, and every
finding hand-triaged (file read, caller traced, real installed version resolved from the
lockfile, real CVE/GHSA text checked where relevant) as TRUE_POSITIVE / FALSE_POSITIVE /
UNCERTAIN. 2 of the 20 failed to produce a usable clone/scan result and were excluded; 1
more (`1Flow`) turned out to be a README-only stub with no scannable code (0 findings, not a
data point either way). 17 repos produced real triaged findings. Full writeup, per-checkId
table, real false-positive patterns, and real true positives found: `docs/REAL_WORLD_VALIDATION.md`.

**Headline numbers:** 253 findings triaged. 165 TRUE_POSITIVE (65.2%), 84 FALSE_POSITIVE
(33.2%), 4 UNCERTAIN (1.6%). But the blended number hides the real story: **all 165 true
positives came from exactly one check, `vulnerable-dependency`** (165/208 on that check
alone, 79.3%) — **and every other check that fired at all was wrong 100% of the time**:
`secret-hardcoded-generic` (0/16), `secret-env-committed` (0/2), `secret-git-history` (0/16),
`eval-on-input` (0/7), `missing-auth-middleware` (0/3), `stripe-webhook-unverified` (0/1) — 45
findings, 45 false positives, 0 true positives, across six different checks in six
independently-sourced repos each. `sql-string-concatenation`, `cors-wildcard-with-credentials`,
`supabase-rls-disabled`, and all five v0.2.0 checks (11-15) never fired once across all 20
repos — no real-world evidence either way for nine of the fifteen checks.

**Does this confirm the round-3 confidence-tier prediction ("1-10 HIGH, 11-15 MODERATE")?**
No — it complicates it for the untested checks and directly contradicts it for six of the
ten checks in the "1-10 HIGH" bucket. The dependency check earns "HIGH, believe it" on real
evidence now, not just fixture-hardening. But `secret-hardcoded-generic`,
`secret-env-committed`, `secret-git-history`, `eval-on-input`, `missing-auth-middleware`, and
`stripe-webhook-unverified` — six of the nine non-dependency "1-10" checks — were wrong every
single time they fired on real code. The dominant cause wasn't a broken regex (each matched
exactly the shape it was designed to match) but a mismatch between "this shape exists" and
"this shape is dangerous here": Supabase's `anon`/publishable key is designed by Supabase's
own architecture to be public (RLS enforces access, not secrecy) and accounted for the
majority of the secret-check false positives across independently-sourced repos;
`RegExp.prototype.exec()` shares the substring `exec` with `child_process.exec`/`execSync`
and repeatedly, wrongly tripped `eval-on-input`. The 11-15 "MODERATE, prone to false alarms
on innocuous names" prediction is still untested, not confirmed — none of those five checks
fired on any of the 20 repos.

One genuine miss surfaced during triage, not itself a VibeScan finding: a Bolt.new
reservation app had a real Supabase RLS policy granting the public `anon` role unrestricted
`SELECT` on a table of guest names/emails/phone numbers — exactly what check 8 exists to
catch — and check 8 never flagged it (its current pattern covers config/table-definition
text and a `service_role` key in client code, not an overly-permissive policy body in a
migration file). Recorded as an honest false-negative, not counted in the FP-rate math.

**Does the premise hold up?** Partially, and worth being honest about both halves. Every real
vulnerability found in this sample was an outdated dependency — several genuinely serious,
including a Next.js middleware-authorization-bypass CVE match in an app that was actually
using Next middleware for route protection, and a `sharp` CVE reachable through a live,
unrestricted `/next/image` pipeline. No repo in this sample of 20 contained a real hardcoded
secret, a real SQL-injection sink, a real `eval`-on-attacker-input path, a real missing-auth
route, or a real unverified Stripe webhook — so on this sample, nine of fifteen checks target
bug classes that either don't occur often in AI-generated small-app code, or occur in a shape
these particular checks don't yet catch.

**README.md and SECURITY_SCOPE.md updated same day** to replace the "1-10 HIGH / 11-15
MODERATE" framing with the real breakdown: `vulnerable-dependency` called out on its own as
the one check validated by real evidence; the other five non-dependency "1-10" checks now
explicitly flagged as "wrong 100% of the time they fired in the validation sample, treat as a
lead not a verdict"; `sql-string-concatenation`/`cors-wildcard-with-credentials`/
`supabase-rls-disabled` and checks 11-15 flagged as "no real-world data yet" rather than
silently inheriting a confidence label from the bucket they happen to be numbered into.

**Verdict — ship, with the doc fix, not blocked on more scanner work.** The scanning engine
itself doesn't need a round 4: the checks that fired matched exactly the code shapes they
were built to match, every time, in real code — this was a *precision* problem (the shape
existing doesn't always mean the shape is dangerous), not a matching-accuracy problem, and
narrowing that gap further (teaching the secret checks to recognize a Supabase anon-key JWT
shape specifically, teaching `eval-on-input` to exclude `RegExp.prototype.exec`) is future
work, not a blocker — those are known, well-understood, fixable false-positive *sources*, not
open-ended fragility. What this validation actually demanded, and got, was a documentation
fix: the tool was one honest paragraph away from telling users something the real data
doesn't support. With that paragraph now rewritten in both `README.md` and
`SECURITY_SCOPE.md`, and this entry as the permanent record of why, the tool is honest about
exactly one thing being reliable (dependency findings) and everything else being a lead worth
a human's five minutes, which is what it was always supposed to be. Ship it.

## `eval-on-input` receiver-tracing fix for `RegExp.prototype.exec()` (2026-07-24)

Closes the "future work" item this entry itself flagged above (line 696): teaching
`eval-on-input` to exclude `RegExp.prototype.exec()`. This had already been attempted once
before the real-world validation ran (a same-day comment in `static-checks.js` describes "an
exec()/execSync() vs RegExp.prototype.exec() collision" fix), but the guard it left behind —
"does this FILE mention the substring `child_process` anywhere" — was file-wide, not call-site
specific. All 7 real-world false positives (`docs/REAL_WORLD_VALIDATION.md` §5.4/§6: a
filename-number extractor, an allowlist validator, a pattern-scan over text, all built with
`.exec()` on a regex) came from exactly the shape that guard couldn't see: a file that
legitimately imports `child_process` for one thing and separately calls `RegExp#exec` for
something unrelated. Since the file genuinely mentions `child_process`, the old guard let the
unrelated `.exec()` straight through.

**Fix:** `checkEvalOnInput()` now traces each `exec`/`execSync` *call site* back to its own
receiver instead of scanning the whole file for a substring — a bare call only counts if that
exact name was destructured off `require('child_process')`/`import ... from 'child_process'`;
a member call (`x.exec(...)`) only counts if `x` resolves to `require('child_process')` inline
or a variable/namespace import traced back to a `child_process` declaration. Any other receiver
(a regex literal, a variable holding `new RegExp(...)` or a regex literal, or anything
unresolvable) is left alone — this falls out of requiring positive evidence rather than needing
a separate "is this a regex" check.

Two new fixtures reconstruct the real-world shapes under
`test/fixtures/false-positives/5-eval-on-input/` (`filename-number-extractor.js`,
`allowlist-validator.js`), asserted to produce zero `eval-on-input` findings in
`test/false-positives.test.js`. Positive controls in the same folder
(`child-process-exec-real.js`: bare-destructured, `execSync`, and `child_process.exec()`-via-
namespace-import calls with interpolated input; `eval-and-function-tainted.js`: `eval()`/`new
Function()` on tainted input) confirm the fix didn't overcorrect into silence. Full suite:
91/91 passing after this fix (adds 4 new tests: 2 false-positive fixtures + 2 positive
controls).

## Fixed 4 real-world bugs (Supabase anon key, literal-value requirement, exec() collision, RLS SQL migrations)

An adversarial verification pass re-read the actual diffs for these four real-world-bug
fixes (`git show 5fa05b5`, `git show 0904054`) and built fresh, non-fixture repros run
through the real CLI (`node bin/vibescan.js scan .`), rather than trusting the integration
report. Verdict: two of the four fixes were solid as shipped; two had real, reproducible
regressions. Both regressions are now fixed, with new regression tests.

**1. Supabase JWT role fix (`secrets.js`) — solid, no changes needed.** `service_role` JWTs
still fire at `critical`; `anon`/`anonymous` roles are correctly suppressed; an unrecognized
custom role or a malformed/non-JSON payload segment both fail safe (still fire). No
overcorrection found.

**2. "Literal value required" / `looksLikeCodeReference` fix (`secrets.js`) — real
regression, now fixed.** `CODE_REFERENCE_VALUE_RE` matched *any* dot-separated,
identifier-charset value — shape alone, with no requirement that it actually be a
known-safe reference idiom. A real high-entropy secret assigned via the unquoted
dotenv-style path that happened to contain literal dots and no other non-identifier
characters (e.g. `DB_ADMIN_SECRET=xK2mQ9pL...gH0...bC1...`) was silently dropped with zero
findings, while the intended target case (`SUPABASE_KEY=import.meta.env.VITE_SUPABASE_KEY`)
still correctly suppressed. **Fix:** `looksLikeCodeReference` now also requires the value to
start with a known-safe env-access root (`process.env.`, `import.meta.env.`, `Deno.env.`,
`Bun.env.`) before the shape check even applies — scoped to what the exclusion was actually
designed for. New positive-control fixture
`test/fixtures/false-positives/23-real-world-secrets/_control-dotted-literal-secret-still-fires.env`
asserts the dotted-literal case still fires.

**3. `exec()` receiver-tracing fix (`static-checks.js`) — real regression, now fixed.** The
positive control (bare destructured `exec()`/`execSync()`, and `child_process.exec()` via a
direct `require`/import-traced variable) still fired correctly. But a receiver resolved
through one hop of same-file indirection — `function getChildProcessModule() { return
require('child_process'); } const cp = getChildProcessModule(); cp.exec(...)` — produced
zero findings, because `isChildProcessModuleVar` only recognized a variable assigned
*directly* from `require('child_process')`/an import. The old, coarser pre-fix "does this
file mention `child_process` anywhere" guard used to catch this exact shape, so this was a
real loss of coverage, not a wash. **Fix:** added `isChildProcessModuleVarViaHelper`, which
mirrors the one-hop function-call resolution already used elsewhere in this file
(`argLooksInterpolated`'s inlined-helper case, the `Math.random()`-via-helper check) — it
looks up the callee's own return expression via the existing `lookupFunctionReturnExpr` and
checks whether *that* is a `require('child_process')` call, deliberately not recursed a
second level, same convention as the other call sites. New positive-control fixture
`test/fixtures/false-positives/5-eval-on-input/indirect-cp-wrapper.js` asserts this shape
still fires.

**4. RLS `.sql` migration check (`static-checks.js`) — solid, no changes needed.** Fires
correctly on an unsafe policy, stays silent on a properly-scoped policy and on an
`INSERT ... WITH CHECK` with no `USING` clause. One honest, inherent false-positive class was
noted (an intentionally-public `FOR SELECT TO anon USING (true)` catalog table fires the
same as a genuinely unsafe policy, since the check has no way to know a table's data is
meant to be public) — a documentation gap in `SECURITY_SCOPE.md`, not a code bug, and not
fixed here since it's a known, accepted tradeoff class already documented for several other
checks.

Full suite: 93/93 passing after these fixes (adds 2 new regression tests: one positive
control per fixed regression).

## Re-validation: measuring the effect of the 4 bug fixes (2026-07-24)

Fixture regression tests prove a fix works in isolation; they don't prove it survives contact
with the real code that motivated it. So the same 20 real repos from the original real-world
validation (`docs/REAL_WORLD_VALIDATION.md`) were **re-cloned from scratch and re-triaged from
zero** against the current, fixed VibeScan build — not diffed against the old triage, a fresh
hand-triage of every finding. Full comparison, per-repo quotes, and the two new issues this
surfaced: `docs/REAL_WORLD_VALIDATION.md`'s "Re-validation (post-fix)" section.

**Headline numbers:** 4 of 20 repos didn't produce usable data this pass (down from 17
contributing repos to 14) — a real limitation of this comparison, disclosed rather than
papered over. Of the 14 that did: **211 findings triaged, 169 TRUE_POSITIVE (80.1%), 39
FALSE_POSITIVE (18.5%), 3 UNCERTAIN (1.4%)** — versus the original pass's 253/165(65.2%)/
84(33.2%)/4(1.6%). Better in the aggregate, but the improvement is **not evenly earned by the
four fixes** — attribute it correctly:

- **`eval-on-input`: confirmed fixed, checkId-level.** 100% FP (7/7) at baseline → 0% FP (0/1)
  this pass, with direct confirmation on a repo (`career-ops`) that has 15+ real `RegExp.exec()`
  call sites on external input that used to misfire and now don't — not just an absence of the
  pattern.
- **`supabase-rls-disabled`: confirmed fixed, and it's the best result in the whole exercise.**
  0 real-world findings ever → 5/5 TRUE_POSITIVE (0% FP) this pass, including catching, on
  `brew--haven`, the *exact* real vulnerability (anonymous-readable Supabase policy exposing
  every guest's name/email/phone in a Bolt.new reservation app) a human had to find manually
  in the original pass because the old check had zero `.sql`-migration coverage. The specific
  gap this whole validation exercise exists to close is now closed, on the same repo, verified.
- **Supabase anon-key fix: confirmed fixed on the exact 3 repos that produced the bug
  (`plantdoc`, `brew--haven`, `ai-odyssey-planner`) — but the checkId's overall FP rate didn't
  move (100%→100%, 17/17).** Different false-positive shapes (auto-generated FK constraint
  names, config-array strings, README placeholders, and a `self.access_key`-style near-miss of
  the "env-var reference" fix that doesn't start with one of the four hardcoded safe-root
  prefixes) filled the gap immediately. Report both halves honestly: the targeted bug is dead,
  the checkId is still unreliable in practice.
- **`vulnerable-dependency`'s FP rate also fell (18.8%→2.4%) despite not being one of the four
  targeted fixes** — mostly sample variation, plus one new, real, previously-undocumented bug
  this pass surfaced: a `<=`-range comparison that's inclusive of the *patched* version itself
  (caught two packages, `brace-expansion` and `postcss`, both pinned exactly on their own fix
  commit, on one repo — `Vibelens`). That one repo supplied all 4 of this pass's dependency
  false positives. Worth its own follow-up fix; out of scope for this measurement round but too
  real to leave undocumented.
- **`missing-auth-middleware`/`stripe-webhook-unverified` were not part of this fix round and
  the data reflects that** — `stripe-webhook-unverified` recurred at 100% FP with the identical
  root cause (evaluating a helper without tracing its caller's try/catch); `missing-auth-
  middleware` simply didn't fire in this smaller contributing sample, which is silence, not
  improvement.

**No confirmed regressions on the four targeted patterns themselves.** The two new issues found
(the `self.X`-shaped secret near-miss, the dependency-boundary bug) are adjacent gaps the fixes
never claimed to cover, not the original bugs resurfacing — recorded as follow-up work, not
reopened fixes. `npm test`: 93/93 passing throughout. `README.md` and
`docs/REAL_WORLD_VALIDATION.md` updated with the real before/after numbers in place of the
stale pre-fix figures.

## Fixed 5 newly-found false-positive patterns (FK names, config-array keys, non-English placeholders, attribute references, dependency version boundary)

The re-validation pass above and a follow-up real-world sweep surfaced 5 new false-positive
shapes across `secrets.js` and `dependencies.js`, on top of the 4 already closed. All 5 were
fixed (commits `9149490`, `c8db4c2`):

- **Bug A** — auto-generated FK/constraint-name properties (`foreignKeyName: "tasks_project_id_fkey"`)
  read as a high-entropy secret because the property name contains "Key". Fixed by recognizing
  any name ending `KeyName`/`ConstraintName`/`IndexName` as describing the *name* of a
  key/constraint, not a secret's value, plus a secondary auto-generated-file-header + DB-
  identifier-shape signal.
- **Bug B** — a bare, standalone `key` property in a plain config array/object
  (`{ key: 'respondedToInterview' }`) misread as an API key because English camelCase phrases
  score deceptively high on raw Shannon entropy. Fixed by requiring a stricter entropy bar plus
  at least one digit specifically for a bare `key` name (not `apiKey`/`secretKey`/etc., which
  keep the general bar).
- **Bug C** — non-English placeholder values in doc fenced code blocks (`GROQ_API_KEY=sua_chave_groq_aqui`,
  Portuguese) weren't recognized by the English-only placeholder wordlist. Fixed with a
  language-agnostic shape signal (word-shaped: lowercase-only, multi-segment, no digits/case-
  mixing) scoped to fenced code blocks in `.md`/`.mdx` files.
- **Bug D** — dotted attribute/env-var references (`self.access_key`, `process.env.X`) misread
  as hardcoded secrets. Fixed with a per-segment low-entropy-identifier shape check
  (`isLowEntropyIdentifierSegment`).
- **Check 10** — a vulnerable-dependency version comparison used an inclusive `<=` boundary that
  still flagged a package pinned exactly on its own patched version. Fixed with a strict
  boundary comparison.

**Independent adversarial re-verification (2026-07-25)** read the code directly (not fixtures)
and ran live reproductions against the actual exported functions. Verdict: **2 of the 5 were
real regressions, blocking; 1 had a minor documented gap; 2 were solid.**

- **Bug D — REAL REGRESSION, now fixed.** `isLowEntropyIdentifierSegment`'s digit-density
  (≤15%) + case-transition (≤3) shape test, while a real signal, wasn't rare enough on its own:
  a Monte Carlo over 200,000 realistic random base62 dot-chain secrets found ~1.06% passed by
  chance (e.g. `vgbMLqt7Kyi.GopxURSG1`), silently suppressing them as "code references." Per the
  task's explicit constraint, the fix does **not** narrow back to a hardcoded-root allowlist
  (`self.`/`this.`/`process.`/...) — that's the exact approach this file's history already
  outgrew twice. Instead, `looksLikeCodeReference` now also requires each dot-segment to
  decompose (at its own underscore/camelCase word boundaries) into a small number (≤3) of
  individually pronounceable identifier-shaped words (vowel ratio in a moderate band, no
  implausible consonant run) — `hasIdentifierWordShape`, combined with the existing shape check
  via AND. Re-measured by the same Monte Carlo methodology: false-negative rate for two-segment
  random dot-chains drops from ~1.06% to ~0.18% (a ~5.7x reduction), with zero regressions
  against every known real-world code-reference shape (`self.access_key`,
  `process.env.VITE_SUPABASE_KEY`, `import.meta.env.PINECONE_KEY`, `this.config.apiKey`,
  `options.secretToken`, `app.state.auth.secretToken`, `settings.database.password`,
  `env.SECRET_KEY`, plus short abbreviations `cfg`/`ctx`/`fs`/`db`/`id`/`api`/`key`/`env`). The
  residual ~0.18% is a documented, accepted tradeoff, same posture as Bug B's own bare-`key`
  digit requirement — tightening further, in testing, only did so by also rejecting real
  identifiers (`config`, `settings`, `password`, `oauth2Token` all broke under stricter variants
  tried).
- **Bug A — REAL REGRESSION, now fixed.** `isKnownSafeKeyDescriptorName` suppressed on the
  property-name suffix (`*KeyName`/`*ConstraintName`/`*IndexName`) alone, with no check on the
  *value* at all and no gating by `isAutoGenerated` — so a real secret hand-assigned to a
  `*KeyName`-suffixed variable in ordinary, hand-written source (no auto-generated marker in
  sight) was completely invisible. Fixed by also requiring the value to look like a snake_case
  DB identifier (`looksLikeGeneratedDbIdentifier` — letters/digits/underscores only, at least
  one underscore), the same value-shape check already used as the secondary auto-generated-file
  signal. A real secret almost never happens to also be underscore-separated snake_case with no
  base64 punctuation, so this only narrows the existing suppression.
- **Bug B — minor gap, not blocking, left as documented tradeoff.** A real high-entropy secret
  assigned to a bare `key` name with *zero digits* is still wrongly suppressed (the fix's own
  comment already frames "real API keys essentially always contain a digit" as an assumption,
  not a guarantee). Narrower and already-implicit; not fixed this round.
- **Bug C and Check 10 — confirmed solid** on fresh variations (Spanish/German placeholders in
  fences vs. outside fences; `minimist@1.2.5` vs `@1.2.6` boundary, both directions) with no
  regressions found.

Two new regression-test fixtures added (both under
`test/fixtures/false-positives/25-real-world-secrets-round2/`):
`_control-random-dotted-secret-still-fires.env` (Bug D — the reviewer's exact ordinary-random
dot-chain reproductions) and `_control-keyname-suffix-real-secret-still-fires.ts` (Bug A — a
real secret on a `*KeyName`-suffixed variable in non-generated source), both asserting the
secret still fires post-fix.

**Final test count: `npm test` → 111/111 passing, 0 failures** (109 pre-existing + 2 new
positive-control regression tests for the two fixed regressions).
