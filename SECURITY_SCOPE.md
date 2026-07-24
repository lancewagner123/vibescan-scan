# Security Scope

**Read this before you trust anything VibeScan tells you.**

## What VibeScan is NOT

- **VibeScan is not a replacement for a professional security audit or penetration test.**
  It is an automated pattern-matching tool. A human security engineer looking at your
  actual system, with actual threat modeling, will find things this tool cannot.
- **VibeScan does not perform dynamic analysis (DAST) or fuzzing.** It reads source code
  and configuration statically. It never runs your application, never sends it crafted
  input, and will not find vulnerabilities that only manifest at runtime.
- **VibeScan does not detect business-logic vulnerabilities.** Things like "a user can
  apply a discount code twice," "the checkout flow lets you skip payment," or "this
  endpoint leaks other users' data because of a missing ownership check in application
  logic" are exactly the kind of bugs this tool will not catch. Those require a human
  who understands what your app is supposed to do.
- **VibeScan makes no compliance or regulatory-coverage claims.** A clean scan is not
  SOC2 evidence, not a HIPAA risk assessment, not a PCI-DSS attestation, and should not
  be represented as any of those things to auditors, regulators, or customers.
- **Coverage is strictly limited to the checks listed in `docs/CHECK_CATALOG.md`.**
  There are exactly fifteen checks as of v0.2.0 (the original ten from v1, plus five more
  added in v0.2.0). If a class of vulnerability isn't on that list, VibeScan does not look
  for it — full stop.
- **False negatives are possible and expected.** Pattern-based static checks miss things:
  obfuscated secrets, unusual code structure, novel frameworks, cleverly hidden logic.
  A clean report means "we didn't find any of our fifteen known patterns," not "your app
  is secure."

## Who should not rely on this tool alone

If you handle **regulated or high-sensitivity data** — health records, financial account
data, payment card data, PII at meaningful scale, or anything else with legal or
regulatory exposure — get a professional security audit. Do not treat VibeScan as
sufficient due diligence for that kind of system. Use it as a fast first pass to catch
obvious, high-signal mistakes before an app ships, not as the last word on whether it's
safe.

## Suggested fixes are suggestions, not verified patches

Some findings include a `fix.diff` — a unified diff the plain-English triage step is
"genuinely confident" is a correct, minimal fix. Treat that confidence as an educated
guess, not a verification:

- **The model that writes a diff sees a short code snippet, not your whole file or
  project.** It cannot know your database driver's exact parameter-binding syntax,
  whether an auth/session helper already exists elsewhere in your codebase for it to
  reuse, or how a change to one file affects another. A fix that looks right can fail to
  apply, fail to compile, silently leave the vulnerability open, or break working
  functionality (a Row Level Security policy that's too strict locks out real users; one
  that's too loose "fixes" the finding without closing the hole).
- **VibeScan never applies a fix for you, and never opens a pull request on your
  behalf.** Every `fix.diff` is inert text in a report for a human to read, evaluate, and
  apply by hand (or reject). There is no "auto-fix" button and no planned version of
  this tool that merges code without a human in the loop.
- **Findings tagged `authz` (missing-auth-middleware, supabase-rls-disabled), the
  `sql-string-concatenation` and `stripe-webhook-unverified` checks, and (as of v0.2.0)
  `mass-assignment`, `weak-password-hashing`, and `insecure-random-token` deserve extra
  scrutiny before you apply a suggested diff.** These are exactly the categories where an
  incomplete fix is most likely to *look* successful while leaving a real hole open (or
  breaking legitimate access) — get a second, human set of eyes on any diff in these
  categories specifically, not just a glance. `mass-assignment` is grouped with the authz
  checks here (even though its own `category` field is `injection`, per
  `docs/FINDINGS_SCHEMA.md`) because the underlying risk is the same shape: an attacker
  using the finding to set fields they were never meant to control (`isAdmin`, `role`,
  `verified`, `balance`), which is privilege escalation in effect even though the raw
  pattern being matched is "unallowlisted assignment," not an auth check.
  `weak-password-hashing` and `insecure-random-token` (both `category: 'crypto'`) join for
  the same "looks successful but isn't" reason: a diff that swaps the hash-creation call
  or the random-token source only touches the snippet the fix generator can see, not the
  corresponding login/verify code path (for `weak-password-hashing`) or every other place
  that consumes the token's length/encoding/format assumptions (for
  `insecure-random-token`) — either can leave the real vulnerability open, or break a
  working login/session/reset flow, while the diff itself looks like a clean fix.
- If a future version of VibeScan adds automatic pull-request creation, that PR will be
  clearly labeled as an unreviewed, AI-generated suggestion requiring human security
  review before merge, and will not be opened automatically for high/critical
  authz/injection/crypto findings without an explicit opt-in.

## Known evasion limitations (adversarial red-team pass, 2026-07-24)

An internal red-team exercise deliberately built evasion samples against all 10 v1
checks (see `test/fixtures/evasion-attempts/`) and confirmed every pattern-matched check
(1-9) could be bypassed with simple, realistic code shapes — split string-literal
concatenation, base64 encoding, one level of function-call indirection, variable-routed
config values, and similar tricks. Each of those specific bypasses has since been closed
(see the fixtures directory and the corresponding scanner source for what's now
detected). But closing a *specific sample* is not the same as closing the *general
technique* — every fix below is still a regex/text heuristic, not a real parser or a
dataflow engine, and each one has a next-level evasion that would still get through.
Documented here so the tool never silently implies more coverage than it has. (Checks
11-15, added in v0.2.0, were not part of this specific red-team pass — see their own
limitations entries below instead, written at build time rather than found by a later
adversarial audit.)

- **Secrets (checks 1-3):** literal-splitting and base64 decoding are now caught, but
  only one level deep and only via `+` concatenation or single-pass base64. A secret
  built from an array of characters and `.join('')`, hex/ROT13/XOR-obfuscated, decoded
  through a second custom function, or split across multiple *statements* instead of one
  expression, is not decoded or reassembled by this scanner and will not be found.
  Unquoted `KEY=value` detection only recognizes the classic dotenv line shape — a
  secret embedded in YAML, TOML, or a custom config format under a different syntax is
  not covered.
- **SQL injection (check 4):** the "taint-lite" pass that follows concatenation into a
  helper function's `return` statement only recognizes classic `function name(...) {}`
  declarations, one call deep. An arrow-function-assigned builder
  (`const buildQuery = (id) => ...`), a builder that itself calls another builder, or a
  builder in a different file/module, is not traced.
- **eval-on-input (check 5):** the one-level "inline the called function's return
  expression" check stops at one level of indirection by design. Wrapping the
  interpolation in a second layer of function calls (`eval(a(b(input)))`) evades it
  again.
- **CORS wildcard (check 6):** wildcard-via-variable resolution only follows one
  `const/let/var` declaration in the same file. A value imported from another module, or
  produced by a function call rather than a literal `||`/ternary default, is not
  resolved.
- **Missing auth (check 7):** the concatenated-route-path resolver only follows
  same-file `const` declarations built from literals or other resolvable identifiers —
  not values from another module, a config file, or a computed/templated expression. All
  auth-*presence* detection in this check (including the tightened "keyword must be a
  call argument or the handler must contain a 401/403/throw" version) is still a textual
  heuristic: a real auth check spelled with words outside `AUTH_KEYWORD_RE`'s list (e.g.
  a custom `gatekeeper()` helper) will still be reported as *missing* auth (a false
  positive), and, symmetrically, a decorative helper that happens to `throw` for
  unrelated reasons could still suppress a genuinely unauthenticated route (a false
  negative). Neither direction is verified against what the "auth" code actually does.
  Two further gaps found in a follow-up audit (2026-07-24), on ordinary idiomatic
  Express code rather than a crafted evasion sample, were **fixed in a same-day follow-up
  pass** (regression samples: `test/fixtures/regression-samples/chained-route-no-auth.js`
  and `test/fixtures/regression-samples/router-use-guard-protected.js`):
  - ~~False negative on chained route syntax~~ — **fixed.** `router.route('/admin/dashboard')
    .get(handler)` (Express's standard chainable form) is now recognized: a sensitive-looking
    path literal inside a `.route(...)` call is matched, and any `.get/.post/.put/.delete
    /.patch/.all(...)` chained directly off that same expression is treated as an instance of
    that route, subject to the same enforced-auth check as the inline form.
  - ~~False positive on router-level middleware~~ — **fixed.** A `router.use(<identifier>)` /
    `app.use(<identifier>)` call with a bare, auth-ish-named identifier argument (extended
    name heuristic: `auth|session|token|jwt|passport|login|guard|protect|apikey|api_key`,
    unanchored so common camelCase names like `requireAuth` match) occurring before a route's
    position in the file now suppresses the missing-auth finding for every route after it —
    matching the real Express semantics of router-level middleware.

  Both fixes are now regression-tested (`test/regression.test.js`, added the same day as a
  same-day follow-up to the follow-up — a skeptical-buyer re-audit caught that these two
  fixtures existed on disk but weren't wired into `npm test`, the exact gap this project had
  already fixed for `evasion-attempts`/`prompt-injection-variants` a few commits earlier): a
  future refactor of `checkMissingAuthMiddleware` that reopens either gap will now fail
  `npm test`, not just wait to be caught by another manual audit.

  Remaining limitations in these two fixes, not yet covered:
  - The chained-route fix only covers the literal-sensitive-path shape
    (`.route('/admin/...')`) and only directly-adjacent `.method(...)` links off that same
    expression. A route object captured in a variable first (`const r = router.route('/admin');
    r.get(...)`), or a chained path built via concatenation (`.route(ADMIN_BASE + '/x')`), is
    not recognized.
  - The `router.use(<identifier>)` guard is applied purely positionally (index of the `.use()`
    call vs. index of the route call in the same file) — it does not verify the `.use()` call
    and the later route actually share the same router/app object, and does not account for
    the guard being registered inside a conditional branch that may never execute. A guard
    wired as a member expression (`router.use(mw.requireAuth)`) or passed as an array
    (`router.use([a, b])`) is not recognized as a bare identifier and such routes will still
    (conservatively) be flagged. And as always, the identifier's name is still just a naming
    heuristic, not confirmation that the referenced function actually enforces anything.
- **Supabase RLS (check 8):** the nested-key RLS pattern only matches one level of `{
  ... }` nesting with `enabled: false` textually close to the `rls`/`row_level_security`
  key; a differently-shaped toggle (a string value like `"disabled"`, a boolean stored
  under a name not matching that pattern, or a deeper nesting path) still evades. The
  computed-`process.env[...]`-access check only runs inside files this scanner already
  heuristically classifies as client-side (`'use client'`, or a `/components//pages//app/`
  path) — a client bundle built with a framework/convention this heuristic doesn't
  recognize is not covered, and the check does not attempt to verify the *resolved* env
  var name is actually privileged (any computed `process.env[...]` read in such a file
  is flagged, which can also mean occasional false positives on legitimate dynamic config
  reads).
- **Stripe webhook verification (check 9):** the catch-block-enforcement check only looks
  at the `catch` block textually closest to (within ~500 characters of) the
  `constructEvent` call, and only recognizes `return`/`throw`/`res.status(4../sendStatus(4..`
  as "the request was actually stopped." Verification logic split across multiple
  functions, a `.catch()` promise-chain instead of `try/catch`, or a custom
  error-handling wrapper, is not traced.
- **Vulnerable dependencies (check 10):** nested/workspace `package.json` discovery
  closes the "vulnerable package pinned in a sub-package, not the scanned root" gap, but
  each discovered `package.json` without a committed lockfile still requires live network
  access to generate a temporary one and run `npm audit` — offline, this degrades to a
  warning rather than a finding, same limitation the root-only version already had. This
  version also runs one audit per discovered `package.json` rather than detecting a
  `workspaces`/`pnpm-workspace.yaml`/`lerna.json` root config and issuing a single
  workspace-aware audit call, so a large monorepo with many packages will be slower than
  necessary (a real inefficiency, not a coverage gap).
- **Insecure random token (check 11):** only recognizes `Math.random()` — a value built
  from another weak-but-not-obviously-named source (a custom PRNG, `Date.now()` alone, a
  poorly-seeded third-party library) is not detected. Name matching is a substring
  heuristic (`token`/`session[_-]?id`/`api[_-]?key`/`secret`/`nonce`/`csrf`); a
  security-sensitive value assigned to a name outside that list (e.g. `magicLink`,
  `oneTimeCode`) is not flagged even though the same predictability risk applies. Only
  JS/TS-family files are scanned — the same weak pattern in Python (`random.random()`),
  Ruby, PHP, etc. is not covered.
- **Weak password hashing (check 12):** only recognizes `crypto.createHash('md5'|'sha1')`
  by name — a password hashed with a different fast/unsalted primitive (e.g. a single
  round of `sha256` with no salt, or a non-Node crypto library in a polyglot codebase) is
  not detected, since context/statement scoping is specific to this exact call shape. The
  "does this look password-related" heuristic (a password-ish variable name in the same
  statement, or an auth-looking file path) can both under- and over-fire: a password
  variable named something this check doesn't recognize (e.g. `secret_phrase`) can evade
  it, and a checksum helper that happens to hash a variable literally named `password` for
  an unrelated reason could still be flagged.
- **Mass assignment (check 13):** only recognizes the three call shapes explicitly listed
  (`.create/update/save(req.body)`, `new Model(req.body)`, `Object.assign(existing,
  req.body)`) and only resolves one same-file variable hop between `req.body`/`req.query`
  and the call site. An ORM-specific bulk-write method this check doesn't know the name of
  (e.g. a raw `.updateMany()`, a GraphQL resolver's input object, or a framework's own
  "update from params" helper), a value passed through a second intermediate variable, or
  `req.body` spread into an object literal (`{ ...req.body, id }`) instead of passed as a
  whole argument, is not detected.
- **Insecure cookie flags (check 14):** only inspects `res.cookie(...)` calls directly —
  a cookie set via a different mechanism (a raw `Set-Cookie` header string, a
  framework-specific session-cookie configuration object set once at app setup rather than
  per-call, or a non-Express server framework's own cookie API) is not covered. The
  sensitive-cookie judgment is a name/value substring heuristic
  (`session`/`token`/`auth`/`jwt`/`secret`); a session cookie given an unrelated name
  (e.g. `sid`, `uid`) can evade detection entirely.
- **Open redirect (check 15):** only resolves a redirect target one same-file variable hop
  from `req.query`/`req.body`/`req.params`, and only recognizes a narrow set of guard
  patterns (`.startsWith('/')`, an `allowlist`/`whitelist`-named `.includes()` check, or a
  bare `.includes()` call) as "this looks validated" — a real validation function with a
  different name or shape (e.g. a same-file `isSafeRedirect(url)` helper, or validation
  performed in a different file/middleware) is invisible to this heuristic and will still
  be flagged as a false positive. Symmetrically, a redirect target built through two or
  more variable hops, or arriving via a header (`Referer`) instead of
  query/body/params, is not traced and will not be flagged (a false negative).
- **Ancestor-repo scope bug — now guarded, not open (not part of the 10 checks):**
  `secret-git-history` and `secret-env-committed`'s git-history sub-scan both run git
  commands with `cwd` set to the scanned path. If that path is a subdirectory of a larger
  git repository rather than a repo root itself, git commands there resolve against the
  *ancestor* repository's `.git` and its entire history — not an error, just a result the
  caller likely didn't intend ("scan this folder" could end up reporting on unrelated
  sibling content via repo-root-relative paths that don't even correspond to files under
  the scanned path). This was found during the same red-team pass that found the checks
  below. It is now guarded at runtime (`src/scanners/util.js`'s `guardGitHistoryScope`,
  used by both `git-history.js` and `secrets.js`): before either git-history-dependent
  scan runs, VibeScan compares `git rev-parse --show-toplevel` for the scanned path
  against the scanned path itself. If they don't match, both scans are **skipped
  entirely** for that run (no misattributed findings are produced) and a prominent
  warning is added to the scan's `warnings` array — surfaced in both the Markdown report
  (its own "⚠ Warnings" section, right under the top disclaimer) and the terminal summary
  (printed first, before the issue counts), not just left in the JSON output. The warning
  names the enclosing repository root git actually resolved and tells the user to either
  scan the real repository root or run `git init` in the target folder if it's meant to be
  standalone. Net effect: a `secret-git-history` or git-history-sourced
  `secret-env-committed` finding appearing in a report can now be trusted to have come from
  the scanned path's own history — if the scope guard had tripped instead, there would be
  no such finding, only the warning.

## Why this file exists

This tool is aimed at people who did not write their own code and may not have the
background to know what "security scanning" can and cannot mean. It is easy for a
product like this to imply more coverage than it has. This document exists to keep
VibeScan's own marketing honest. If any copy, landing page, or CLI output ever contradicts
what's written here, this file wins and the copy needs to be fixed.
