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
