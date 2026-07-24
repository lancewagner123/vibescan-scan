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
  There are exactly ten checks in v1. If a class of vulnerability isn't on that list,
  VibeScan does not look for it — full stop.
- **False negatives are possible and expected.** Pattern-based static checks miss things:
  obfuscated secrets, unusual code structure, novel frameworks, cleverly hidden logic.
  A clean report means "we didn't find any of our ten known patterns," not "your app is
  secure."

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
- **Findings tagged `authz` (missing-auth-middleware, supabase-rls-disabled), or the
  `sql-string-concatenation` and `stripe-webhook-unverified` checks, deserve extra
  scrutiny before you apply a suggested diff.** These are exactly the categories where an
  incomplete fix is most likely to *look* successful while leaving a real hole open (or
  breaking legitimate access) — get a second, human set of eyes on any diff in these
  categories specifically, not just a glance.
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
Documented here so the tool never silently implies more coverage than it has:

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
- **Known, still-open scope bug (not part of the 10 checks):** `secret-git-history` and
  `secret-env-committed`'s git-history sub-scan both run git commands with `cwd` set to
  the scanned path. If that path is a subdirectory of a larger git repository rather than
  a repo root itself, git silently resolves to the *ancestor* repository's `.git` and its
  entire history — not an error, just a result the caller likely didn't intend ("scan
  this folder" can end up reporting on unrelated sibling content via repo-root-relative
  paths that don't even correspond to files under the scanned path). This was found
  during the same red-team pass and is **not yet fixed** — treat any `secret-git-history`
  or git-history-sourced `secret-env-committed` finding as suspect until you've confirmed
  the scanned path is itself a git repository root (`git rev-parse --show-toplevel`
  equals the path you passed to VibeScan).

## Why this file exists

This tool is aimed at people who did not write their own code and may not have the
background to know what "security scanning" can and cannot mean. It is easy for a
product like this to imply more coverage than it has. This document exists to keep
VibeScan's own marketing honest. If any copy, landing page, or CLI output ever contradicts
what's written here, this file wins and the copy needs to be fixed.
