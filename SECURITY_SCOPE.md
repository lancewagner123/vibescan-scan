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

## Why this file exists

This tool is aimed at people who did not write their own code and may not have the
background to know what "security scanning" can and cannot mean. It is easy for a
product like this to imply more coverage than it has. This document exists to keep
VibeScan's own marketing honest. If any copy, landing page, or CLI output ever contradicts
what's written here, this file wins and the copy needs to be fixed.
