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
