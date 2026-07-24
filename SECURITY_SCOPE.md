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

## Why this file exists

This tool is aimed at people who did not write their own code and may not have the
background to know what "security scanning" can and cannot mean. It is easy for a
product like this to imply more coverage than it has. This document exists to keep
VibeScan's own marketing honest. If any copy, landing page, or CLI output ever contradicts
what's written here, this file wins and the copy needs to be fixed.
