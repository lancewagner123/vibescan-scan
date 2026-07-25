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
Documented here so the tool never silently implies more coverage than it has.

A second, same-day follow-up red-team pass (also 2026-07-24) ran the identical exercise
against the five checks added in v0.2.0 (checks 11-15; see
`test/fixtures/evasion-attempts/11-*` through `15-*`) and found all five bypassable too —
bracket-notation/concatenated property names and one-hop function-call indirection (11), a
variable holding the hash algorithm name (12), spread-into-object-literal and two-hop
variable indirection (13), an options object built by a helper function call (14), and a
redirect target routed through a helper function (15). All five were fixed the same day
(see each check's own entry below); the fixes share a common shape — resolving an
identifier or call expression back through same-file `const/let/var` chains and function
`return` statements — factored into three reusable helpers in `src/scanners/util.js`
(`resolveIdentifierChain`, `lookupFunctionReturnExpr`, `resolveConcatExpression`) used by
both `secrets.js` (checks 11-12) and `static-checks.js` (checks 4-9, 13-15) rather than
duplicated per check. As with checks 1-9 above, closing these specific samples is not the
same as closing the general technique; each check's entry below documents what's still
open.

**Third-party audit finding (2026-07-24, same day): two of those three shared helpers had
a mainstream-style-variant gap, not just a "next-level adversarial evasion" gap — flagged
as more serious than ordinary evasion framing, since it hit common code style rather than
deliberate obfuscation. Fixed the same day (see below) — kept here as a "found honestly,
fixed honestly" record, not as an open gap.**

- **`lookupFunctionReturnExpr` originally only matched a `function name(...) { ... }`
  declaration.** An arrow-function helper written the *exact same shape* the original
  same-day fix claimed to resolve — `const generateWeakValue = () => Math.random()...`
  (concise/implicit-return body) or with an explicit block body and `return` — was invisible
  to it, defeating checks **5 (eval-on-input), 11 (insecure-random-token), 14
  (insecure-cookie-flags), and 15 (open-redirect)**. **Fixed 2026-07-24:**
  `lookupFunctionReturnExpr` now also matches `const/let/var name = (...) => { ... return
  expr; ... }` and the concise-body form `const/let/var name = (...) => expr` (including a
  bare single param with no parens, `x => expr`). Regression-tested via
  `test/fixtures/evasion-attempts/16-mainstream-style-variants/arrow-function-token.js`
  (wired into `test/regression.test.js`).
- **`resolveConcatExpression` and `resolveIdentifierChain` originally required a literal
  trailing `;` to recognize a `const/let/var` declaration.** Any codebase not using
  semicolons (Standard.js style, `semi:false`, plenty of AI-generated code) silently
  defeated the variable-hop resolution these helpers provide, affecting checks 12
  (weak-password-hashing) and 13 (mass-assignment). **Fixed 2026-07-24:** both regexes no
  longer require a trailing `;` — `[^;\n]+` already stops at the first `;` or newline on its
  own, so the literal `;` requirement was only ever rejecting semicolon-free declarations,
  not bounding the capture. Regression-tested via
  `test/fixtures/evasion-attempts/16-mainstream-style-variants/no-semicolons-hash.js` (wired
  into `test/regression.test.js`).

Net effect: both gaps were real (ordinary style variation, not adversarial obfuscation, defeating
6 checks' worth of "same-day fixed" claims), and both are now closed and regression-tested,
not just documented. As with checks 1-9's own follow-up fixes, closing these specific
samples is still not the same as closing the general technique — see the per-check bullets
below for what's still open at the next level of indirection.

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

  A third gap, found in an independent false-positive sweep the same day (2026-07-24), was
  **also fixed**: `AUTH_KEYWORD_AS_ARG_RE` (case (a) of `routeCallHasEnforcedAuth` — "is an
  auth-ish identifier passed as one of the arguments in the route-registration call itself")
  had kept `AUTH_KEYWORD_RE`'s leading `\b` word-boundary anchor. `\b` requires a
  word/non-word transition, but a camelCase identifier like `requireAuth` or `checkAuth` has
  no such transition immediately before "Auth" (`e`->`A`/`k`->`A` are both word-to-word), so
  the single most idiomatic Express middleware-naming style was invisible to the inline-arg,
  concat-path, and chained-route auth-argument checks — `router.get('/admin/x', requireAuth,
  handler)` was reported as **missing** auth despite real middleware being passed inline. Only
  vocabulary-*initial* names (`authMiddleware`, `isAuthenticated`) matched. The
  `router.use(requireAuth)` guard case (immediately above) was already immune, because
  `AUTH_MIDDLEWARE_NAME_RE` for that specific case had deliberately dropped the anchor — but
  the fix was never mirrored onto the inline-argument/concat/chained-route shapes it
  conceptually shares vocabulary with, an asymmetry `SECURITY_SCOPE.md` didn't disclose.
  **Fixed** by extracting a single shared, unanchored `AUTH_KEYWORD_VOCAB` word list that both
  `AUTH_KEYWORD_RE` (still `\b`-anchored, used only for its own doc comment now) and
  `AUTH_KEYWORD_AS_ARG_RE` (unanchored, matching the precedent already set by
  `AUTH_MIDDLEWARE_NAME_RE`) build from — rather than maintaining two divergent patterns for
  the same "does this identifier look auth-ish" test. Regression-tested:
  `test/fixtures/regression-samples/inline-camelcase-auth-arg.js`.
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
  A follow-up red-team pass (2026-07-24) found and closed two specific bypasses **same
  day**: (1) a bracket-notation/computed property name, including one built from
  concatenated string literals (`user['session' + 'Id'] = Math.random()...`), which the
  original name regex couldn't see at all since its character classes excluded quotes and
  brackets — now matched, joined, and re-tested against the same keyword vocabulary; (2)
  `Math.random()` moved one function call away (`const resetToken = weakRandomToken();`
  where the helper's own body calls `Math.random()`) — now resolved by looking up the
  helper's `return` expression (one hop, same convention as `eval-on-input`'s own
  same-file-function resolution) and re-testing that. **Not closed, by design (a next-level
  evasion of the same technique, not a fresh gap):** a *second* layer of function-call
  indirection (`const t = outer(); function outer() { return inner(); } function inner() {
  return Math.random()...; }`) is not traced — the helper-call resolution is exactly one
  hop deep, same limit this codebase applies everywhere else it does this kind of
  resolution. A bracket key built from a *variable* holding the property name
  (`user[nameVar] = Math.random()...`) rather than a string literal is also not resolved —
  only literal (or concatenated-literal) bracket keys are.
- **Weak password hashing (check 12):** only recognizes `crypto.createHash('md5'|'sha1')`
  by name — a password hashed with a different fast/unsalted primitive (e.g. a single
  round of `sha256` with no salt, or a non-Node crypto library in a polyglot codebase) is
  not detected, since context/statement scoping is specific to this exact call shape. The
  "does this look password-related" heuristic (a password-ish variable name in the same
  statement, or an auth-looking file path) can both under- and over-fire: a password
  variable named something this check doesn't recognize (e.g. `secret_phrase`) can evade
  it, and a checksum helper that happens to hash a variable literally named `password` for
  an unrelated reason could still be flagged.
  A follow-up red-team pass (2026-07-24) found and closed **same day**: the algorithm
  argument no longer has to be a literal quoted string directly inside the call — a
  variable holding the algorithm name (including one built from split string literals,
  e.g. `const HASH_ALGO = 'm' + 'd5';`) is now resolved via `resolveConcatExpression`
  (shared with the SQL-injection and missing-auth checks), which follows both `+`
  concatenation and `const/let/var` identifier chains of arbitrary depth back to a single
  string before testing it against `md5`/`sha1`. **Not closed:** the call's argument is
  still extracted with a naive `[^)]*` regex, so an algorithm name computed by a *nested
  call* (`crypto.createHash(getAlgo())`) is not resolved (the argument text itself is a
  call expression, which `resolveConcatExpression` correctly declines to guess at rather
  than silently assuming a result).
- **Mass assignment (check 13):** only recognizes the three call shapes explicitly listed
  (`.create/update/save(req.body)`, `new Model(req.body)`, `Object.assign(existing,
  req.body)`). An ORM-specific bulk-write method this check doesn't know the name of (e.g.
  a raw `.updateMany()`, a GraphQL resolver's input object, or a framework's own "update
  from params" helper) is not detected.
  A follow-up red-team pass (2026-07-24) found and closed **same day**: variable
  resolution between `req.body`/`req.query` and the call site is no longer limited to one
  hop — `resolveIdentifierChain` (util.js) now follows a chain of `const/let/var`
  reassignments of arbitrary depth (bounded at 6 hops, to bail rather than loop forever on
  a pathological chain), closing the "`const raw = req.body; const input = raw;
  Model.create(input)`" gap. `{ ...req.body }` / `{ ...someVar }` (a spread-only object
  literal — a shallow copy of every field, functionally identical to passing req.body
  directly) is now also recognized, whereas before it matched neither the bare-`req.body`
  text check nor the bare-identifier check. **Not closed, by design:** an object literal
  that spreads req.body/req.query *alongside other explicit keys* (`{ ...req.body, id }`)
  is treated as a partial allowlist and deliberately left out of scope, per the original
  red-team suggestion — this is a real judgment call, not a proven-safe pattern, since the
  explicit keys don't actually *remove* anything from the spread.
- **Insecure cookie flags (check 14):** only inspects `res.cookie(...)` calls directly —
  a cookie set via a different mechanism (a raw `Set-Cookie` header string, a
  framework-specific session-cookie configuration object set once at app setup rather than
  per-call, or a non-Express server framework's own cookie API) is not covered. The
  sensitive-cookie judgment is a name/value substring heuristic
  (`session`/`token`/`auth`/`jwt`/`secret`); a session cookie given an unrelated name
  (e.g. `sid`, `uid`) can evade detection entirely.
  A follow-up red-team pass (2026-07-24) found and closed **same day**: an options object
  built by a same-file, zero-argument helper function (`const cookieOpts =
  buildCookieOptions();`) is now resolved by looking up that function's `return`
  expression and inspecting it directly if it's itself an object literal — before, any
  non-object-literal declaration RHS (including a function call) made the check bail
  entirely ("can't confirm, don't flag"). **Not closed:** a helper function that takes
  arguments, builds its returned object conditionally, or itself calls a second helper is
  not traced (one hop only, same limit applied throughout this codebase).
- **Open redirect (check 15):** only recognizes a narrow set of guard patterns
  (`.startsWith('/')`, an `allowlist`/`whitelist`-named `.includes()` check, or a bare
  `.includes()` call) as "this looks validated" — a real validation function with a
  different name or shape (e.g. a same-file `isSafeRedirect(url)` helper, or validation
  performed in a different file/middleware) is invisible to this heuristic and will still
  be flagged as a false positive. A redirect target arriving via a header (`Referer`)
  instead of query/body/params is not traced and will not be flagged (a false negative).
  A follow-up red-team pass (2026-07-24) found and closed **same day**: the redirect target
  variable is no longer limited to one hop back to `req.query`/`req.body`/`req.params` —
  `resolveIdentifierChain` (util.js, shared with check 13) now follows a chain of
  `const/let/var` reassignments of arbitrary depth. A redirect target routed through a
  same-file helper function (`res.redirect(getRedirectTarget(req))` where the helper
  returns `req.query.next || req.query.returnTo`) is also now resolved — by looking up the
  helper's `return` expression and checking whether *any part of it* references
  req.query/body/params, deliberately loose since a helper's return is often a
  short-circuit `||` chain rather than one bare property access. **Not closed:** the
  function-call resolution is one hop only, same limit applied throughout this codebase —
  a second layer of function-call indirection is not traced. The "looks validated" guard
  check is still applied to the raw call-expression text in this case (there's no resolved
  variable name to check it against), so a validation guard written to check the
  *helper's* return value rather than the outer call site is not recognized either.
## Round 2 audit (2026-07-24, same day) — deeper evasion/false-positive pass on checks 11-15

A second, deeper round of adversarial and false-positive testing against checks 11-15
specifically (three independent testers: an evasion hunter building 16 new fixtures, a
false-positive hunter building 11 realistic-code samples, and a realistic-library-code
tester exercising actual Mongoose/Sequelize/Prisma/Express shapes) found **14 new
false-negative gaps**, **2 new false-positive gaps** (both check 14), and **4 additional
gaps against real ORM/library call shapes** the first round hadn't exercised. All 20 were
fixed the same day; three additional confirmed false positives were judged not cleanly
fixable and are documented below as accepted tradeoffs instead. Regression fixtures live
under `test/fixtures/evasion-attempts/17-round2-new-evasions/`,
`test/fixtures/evasion-attempts/18-realistic-library-gaps/`, and (for the false positives)
`test/fixtures/false-positives/`, wired into `test/regression.test.js` and
`test/false-positives.test.js` respectively.

**Fixed (false negatives):**
- Check 11: a bracket-notation property key written as a template literal
  (`` user[`sessionId`] ``) — the quote-character class only recognized `'`/`"`.
- Check 11: `Math.random()` reached via a static-class-method call (`TokenGen.generate()`)
  — neither the callee regex (bare identifier only) nor `lookupFunctionReturnExpr`
  (no class-method lookup shape) could see it. `lookupFunctionReturnExpr` (util.js) now
  dispatches a dotted `ClassName.method` callee to a dedicated class-static-method lookup.
- Check 11: `Math.random()` reached via an `async` arrow-function helper (`const gen =
  async () => Math.random()...`) — the arrow regexes required params immediately after
  `=`, with no allowance for `async` in between.
- Check 11: `Math.random()` reached via a function with a TypeScript return-type
  annotation (`function generateResetToken(): string { ... }`) — the function-declaration
  regex required `)` immediately followed by `{`.
- Check 11: `Math.random()` buried inside a multi-line hand-rolled UUID generator callback
  (the classic Stack Overflow `generateUUID()` snippet) — `lookupFunctionReturnExpr`'s
  return-expression extraction stopped at the first newline; it now tracks bracket/string
  depth (`extractReturnExpression`, util.js) so a multi-line return expression is captured
  in full.
- Check 12: `crypto['createHash'](...)` computed-member call — the call regex was
  dot-notation only.
- Check 12: the hash algorithm resolved via a class static field (`HashConfig.ALGO`) —
  `resolveConcatExpression` (util.js) only resolved bare identifiers; it now also resolves
  a `ClassName.FIELD` member expression back to a `static FIELD = ...` class member.
  Same fix, one shared helper (`extractReturnExpression`) also closed the multi-line
  return-expression gap above, since both are used by `lookupFunctionReturnExpr`.
- Check 13: `req['body']` bracket/computed access — `isReqBodyOrQueryExpr` was
  dot-notation only.
- Check 13: plain and renamed destructuring (`const { body } = req;` / `const { body:
  userData } = req;`) — `resolveIdentifierChain` only recognized a bare-identifier
  declaration LHS; a new `resolveDestructuredReqSource` helper handles both forms.
- Check 13: Mongoose's `findByIdAndUpdate`/`findOneAndUpdate` (and siblings
  `findByIdAndDelete`/`findOneAndDelete`/`findByIdAndRemove`/`updateOne`/`updateMany`/
  `bulkCreate`) — the method-name alternation was exactly `create|update|save`.
- Check 13: Prisma's `{ data: req.body }` call shape — the whole ORM's write API nests
  the payload under a `data:` key one level down, a shape `argIsWholeReqBodyOrQuery`
  couldn't see at all before.
- Check 14: an arrow helper with a paren-wrapped implicit-return object literal (`() =>
  ({ maxAge: 3600000 })`, the mandatory idiomatic form) — `resolveObjectLiteralVar` tested
  `/^\{/` against text that actually starts with `(`; a new `stripWrappingParens` helper
  fixes this.
- Check 15: optional chaining + nullish coalescing (`req.query?.next ?? '/home'`) —
  `REQ_SOURCE_PROP_RE` required an exact match with no `?.`/`??` allowance.
- Check 15: a template-literal-wrapped redirect target (`` res.redirect(`${req.query.next}`) ``)
  — no branch unwrapped a template literal; `normalizeRedirectTarget` now does.
- Check 15: nested destructuring straight off `req` (`const { query: { next } } = req;`)
  — the existing destructure regex required the RHS to be exactly `req.query`/etc.
- Check 15: an awaited helper call passed inline (`res.redirect(await
  getRedirectTarget(req))`) — the call-expression regex was anchored and the leading
  `await ` text broke it.
- Check 15: a redirect target wrapped in `new URL(req.query.next, base).toString()` — a
  real, well-known "looks safe, isn't" bypass idiom (the WHATWG URL parser ignores `base`
  entirely if the first argument is itself an absolute URL); a dedicated
  `resolveNewUrlFromReqSource` now recognizes it, and the resulting finding's message
  explicitly explains why the `new URL(...)` wrapping is not actually a validation guard.

**Fixed (false positives):**
- Check 14: `secure: process.env.NODE_ENV === 'production'` — a near-universal,
  textbook-correct Express idiom — was flagged as "missing secure:true" since
  `SECURE_TRUE_RE` only recognized the literal boolean. A new `SECURE_ENV_CONDITIONAL_RE`
  recognizes this pattern as an equally satisfying signal.
- Check 14: an inline call expression used directly as the options argument
  (`res.cookie('sid', t, buildSecureCookieOptions())`, where the helper returns a fully
  correct `{ httpOnly: true, secure: true }`) was flagged as having "no options object at
  all" — the code matched neither the inline-object nor bare-identifier branches, left
  `optionsText` at its initial `null`, and then treated *any* reason for `optionsText`
  being null as proof of absence. Restructured to distinguish "no 3rd argument at all"
  (a real finding) from "a 3rd argument is present but unresolvable" (bail, don't guess) —
  and added a resolution path (`resolveInlineCallOptionsArg`) for the inline-call shape
  itself, so a securely-configured inline call is now recognized as secure rather than
  reported as absent.
- Check 15: a redirect target validated via `new URL(target, origin)` + an `.origin`
  comparison (a standard, robust guard) wasn't in `hasNearbyRedirectValidation`'s
  recognized-pattern list at all; added.
- Check 15: a redirect target validated via an allowlist array named `internalPaths`
  (equally safe, just not prefixed `allow(list|ed)`/`whitelist`) went unrecognized because
  the `ARRAY.includes(VAR)` guard pattern required that specific naming prefix; dropped —
  any `ARRAY.includes(VAR)` shape now suppresses the finding regardless of the array's
  name (safe to broaden since this only *suppresses* a finding, never creates one).
- Check 14: `res.cookie('authorTheme', authorThemePreference)` (a blog author's UI theme
  preference, cosmetic-only) was flagged purely because `auth` is a literal substring of
  `author`. Fixed narrowly, not with a blanket word-boundary change (which would also
  have broken legitimate `authenticate`/`authorize`/`authentication` names — there's no
  real word-boundary between "auth" and those suffixes either, camelCase compounds being
  one continuous run of letters): `COOKIE_AUTH_KEYWORD_SRC` now excludes "auth" only when
  immediately followed by "or" + a segment-ending character (a capital letter, non-letter,
  or end-of-string) — matching "author"/"authorTheme" but not "authorize"/"authority",
  which still read as auth-related and are still recognized.
- Check 11: `tokenizerSeed` (an NLP mock-data seed; "token" is just the start of
  "tokenizer") was flagged purely on substring overlap. A regex-inline lookahead fix was
  tried first and found to be actively wrong under the pattern's own `i` (case-insensitive)
  flag — `(?![a-z])` under `i` also excludes uppercase letters, since `[a-z]` itself gets
  case-folded, which would have incorrectly blocked legitimate names like
  `resetTokenValue`. Fixed instead with a JS-side post-filter
  (`hasTokenIshKeywordAtBoundary`) that re-checks the ORIGINAL (un-folded) captured text:
  a keyword occurrence immediately followed by a lowercase letter is treated as embedded
  in a longer word and rejected; one followed by end-of-name/a digit/underscore/uppercase
  letter is treated as a real boundary and kept.

**Not fixed — new accepted limitations, documented rather than forced:**
- Check 11: `secretIngredient` (a recipe app's "secret ingredient"), `gameToken` (a
  board-game piece color), and `animationToken` (a UI animation dedup key) all remain
  false positives. Unlike `tokenizerSeed` above, these keywords sit at a genuine camelCase
  SEGMENT boundary on both sides (`secret` + capital `I`; `game` + capital `T`, ending at
  end-of-name) — syntactically indistinguishable from a real `sessionSecret`/`authToken`.
  No regex or boundary heuristic can tell these apart from real security-token names
  without semantic understanding of what the code does; the substring vocabulary is core
  to this check's design (it exists specifically to catch `resetToken`/`csrfToken`-style
  names that a `\b`-anchored exact-word match would miss).
- Check 12: a rate-limiter cache-key hash flagged because the word "password" appeared
  incidentally in an unrelated route-path literal (`/reset-password`) in the same
  statement as an unrelated `createHash('md5')` call. A narrow, low-frequency collision,
  not worth chasing with more context-window tightening.
- Check 12: a file living under `routes/auth/` gets any `createHash('md5'|'sha1')` call in
  it flagged via the `AUTH_FILE_PATH_RE` fallback, even when hashing something unrelated
  to a password (here, a cache key). This is a deliberate recall-over-precision tradeoff
  for files that live under an auth-ish path with no password-ish signal nearby — tightening
  it would risk reopening the evasion it exists to catch (password hashing that never says
  "password" anywhere near the call).
- Check 13: `Message.create(req.body)` on a public contact-form route is flagged even
  though the target model genuinely has no privileged fields (no `isAdmin`/`role`/
  `balance`) for an attacker to smuggle in. This check has zero schema/model awareness by
  design — a regex/text scanner without semantic access to the model definition cannot
  know which fields exist, so it flags the call SHAPE unconditionally. Not fixable without
  adding real schema inspection, which is out of scope for this tool's architecture.

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

## Round 3 audit (2026-07-24, same day) — sophisticated-technique catalog on checks 1-9, fresh look at 11-15, dependency scope stress-test

A third pass retrofitted the round-2 evasion catalog (TS type/return annotations,
bracket/computed access, template-literal splitting, destructured imports, no-semicolon
style, class static members) onto checks 1-9 (which had never seen it), took a fresh
independent look at 11-15, and stress-tested check 10's dependency scope. **28 confirmed
issues triaged: 21 fixed + regression-tested, 7 documented below as accepted limits.**
Fixtures live under `test/fixtures/evasion-attempts/{19,20,21,22}-round3-*`, wired into
`test/regression.test.js` and `test/false-positives.test.js`.

**Fixed (false negatives now caught):**
- Checks 1/3: a generic high-entropy secret written with a TS type annotation
  (`const apiSecret: string = '...'`); a secret on a bracket-notation/concatenated computed
  key (`config['apiSecret'] = '...'`); a known-format secret split with a `${...}`
  template-literal placeholder. (Bracket-notation and template-literal splitting were both
  already closed for checks 11/15 but never mirrored back onto checks 1/3.)
- Check 4: `db['query'](...)` bracket method access; a SQL-builder helper with a TS
  return-type annotation; a SQL string built into a TS-typed variable.
- Check 5: `eval(await asyncArrowHelper(...))` — a leading `await` on an inlined async-arrow
  helper.
- Check 6: `credentials: x ?? true` / `|| true`; a wildcard origin held in a class static
  field or a TS-typed variable.
- Check 7: a genuinely-unauthenticated route whose handler body contains a vocab-word local
  (`pageToken`) no longer spuriously suppressed — the auth-argument test now scans only
  middleware argument positions, not the handler body (this also fixed the single-element
  `[requireAuth]` middleware-array false positive).
- Check 8: `process.env[[...].join('_')]` array-join and `process.env['A' + 'B']`
  split-literal computed env-var keys (the exact evasions the check's own comment cited).
- Check 9: `req['body']` bracket read and `const { body } = req` destructured read in the
  no-`constructEvent` branch (the same dot/bracket/destructure taint-source coverage check
  13 already had — the check-9 section above no longer overstates coverage for these two
  shapes).
- Check 11: a helper-call token assignment with no trailing semicolon.
- Check 12: `md5`/`sha1` hashing via a destructured `const { createHash } = require('crypto')`
  import.
- Check 13: `req.body as Dto` cast and `req.body!` non-null assertion; `const data = {
  ...req.body }; Model.create(data)` (spread into a variable, then passed).
- Check 15: `res.redirect(req['query'].next)` bracket-notation redirect source (check 13 had
  bracket support; check 15 didn't — asymmetry closed).
- Systemic: `resolveConcatExpression`/`resolveIdentifierChain` (util.js) now tolerate a TS
  variable type annotation before the `=`, closing the annotation gap for every check that
  routes a value through a `const/let/var` hop.

**Fixed (false positives):**
- Checks 1/3: `.env.example` placeholder values that keep a descriptive suffix after the
  keyword (`your-api-key-here`, `replace-with-your-own-secret-value`,
  `set-your-database-password-here`) — the single most common example-env convention, now
  recognized as placeholders.
- Check 2: hyphen/compound env template filenames (`.env-example`, `.env.local.example`,
  `.env.production.template`, `.env.dist.local`) — an asymmetry left over from round 2's
  `ENV_FILE_RE` broadening; the safe-template exact-name Set is now a marker regex.
- Check 14: ES6 shorthand cookie flags (`{ httpOnly, secure }` where `const secure = true`)
  and a spread of a shared secure-defaults object (`{ ...COOKIE_DEFAULTS, maxAge }`) — both
  are *more* careful patterns than an inline literal, so an FP on them was especially bad
  for trust.

**Check 10 (vulnerable-dependency):** the id-collision (same CVE in two workspace
package.json files), raw-npm-stderr terminal leak, missing child-process timeout, and the
misattributing "(likely no network access)" warning were all fixed (see `dependencies.js`).

**Not fixed — new accepted limitations, documented rather than forced:**
- **Secrets (checks 1/3) — base64 + split-literal combo.** A secret base64-encoded AND then
  split across `+`-concatenated literals at a non-4-char-aligned boundary is not recovered:
  the base64 pass decodes each fragment individually (each is invalid base64), and the
  concat pass re-tests only the raw joined value, never base64-decoding it. This is two
  independently-defended techniques deliberately stacked — a next-level adversarial evasion,
  not a mainstream shape, and consistent with the existing "base64 only one level deep"
  limitation above.
- **Secrets (checks 1/3) — keyword-named LHS with a non-adjacent literal.** A generic secret
  kept on the line but with no keyword-ish name *adjacent* to the literal
  (`apiKey = getKey() ?? 'literal'`, `const { data: apiSecret } = { data: 'literal' }`,
  `` sessionToken = `${''}literal` ``) is not flagged — the generic-entropy heuristic only
  matches a keyword name immediately next to the literal. Genuinely closing this needs light
  dataflow (associate a keyword-named LHS with a non-adjacent literal RHS), beyond a regex.
- **Check 4 — class static-method / bare SQL builder.** A SQL builder written as a class
  static method (`QueryBuilder.forUser(id)`) or called with no receiver after being
  destructured off an object (`const { query } = pool; query(\`...${id}\`)`) is not traced.
  Same one-hop-`function`-declaration limit already documented for check 4's arrow-function
  builders; the bare-call form is additionally too false-positive-prone (any `query(`/
  `execute(` with no receiver) to match safely.
- **Check 5 — bracket/computed dangerous callee.** `cp['execSync'](...)`, `global['eval'](...)`
  — computed access to eval/exec/Function is real obfuscation but uncommon in vibe-coded
  apps, and the receiver/callee-name matching is dot-notation-shaped; left as a documented
  gap rather than broadened.
- **Check 11 — IIFE and getter token sources.** `Math.random()` inside a multi-line IIFE
  assigned to a token-ish name (`const resetToken = (() => { ... })()`), and a getter that
  mints a fresh `Math.random()` value per access (`get sessionToken() { return
  Math.random()... }`), are not flagged — the callee-resolution requires a bare-identifier
  callee (an IIFE's callee is a parenthesized arrow), and a getter is neither a `name = ...`
  nor `name: ...` shape. Both are less common than the six check-11 shapes fixed this round.
- **Check 10 — dev vs prod severity, and lockfile/package.json divergence.** A vulnerability
  in a `devDependencies`-only (build/test-only) package is reported at full high/critical
  severity indistinguishable from a production-runtime vuln (no `--omit=dev` split). And the
  audit reflects the *resolved lockfile tree*, never comparing it to `package.json` — when
  the two disagree (stale lockfile the dev already bumped in package.json, or vice versa) the
  reported severity can mislead, with no "lockfile out of date" warning. Both are
  recall-over-precision judgment calls, not crashes; documented rather than changed.
- **Check 10 — pnpm/yarn lockfiles and workspace/internal-dep packages.** Only
  `package-lock.json`/`npm-shrinkwrap.json` are recognized as committed lockfiles, so every
  pnpm/yarn project is forced onto the network-dependent temp-install path even though it
  has a perfectly good lockfile — and any nested package that references a sibling via
  `workspace:*`, `*`, `file:`, or an unpublished version cannot be installed in isolation, so
  its (possibly genuinely-vulnerable) dependencies are silently skipped (false negatives in
  pnpm/Turborepo/Nx monorepos). Additionally, an npm-workspaces root audit already covers the
  whole workspace, making the per-nested-package re-audit redundant. Closing these properly
  needs a workspace-aware audit (detect `pnpm-workspace.yaml`/`workspaces`/`lerna.json` and
  issue one audit at the root, and/or teach the tool to read pnpm/yarn lockfiles) — real
  work, out of scope for this pass. `npm audit` itself cannot read a pnpm/yarn lockfile, so
  merely adding those filenames to the recognized set would not help. The failure mode
  throughout is silent under-reporting, never a crash.

## Why this file exists

This tool is aimed at people who did not write their own code and may not have the
background to know what "security scanning" can and cannot mean. It is easy for a
product like this to imply more coverage than it has. This document exists to keep
VibeScan's own marketing honest. If any copy, landing page, or CLI output ever contradicts
what's written here, this file wins and the copy needs to be fixed.
