# Raw Finding Schema (output of src/scanners/*)

Each scanner module returns an array of objects matching exactly:

{
  "id": "string, stable slug, e.g. 'secret-hardcoded-stripe-key-a1b2'",
  "checkId": "string, one of the 15 ids in CHECK_CATALOG.md",
  "severity": "critical" | "high" | "medium" | "low" | "info",
  "category": "secret" | "injection" | "authz" | "config" | "dependency" | "crypto",
  "file": "path relative to scanned repo root",
  "line": "number or null",
  "snippet": "short code excerpt, max 200 chars, secrets MUST be redacted/truncated e.g. sk_live_AB12***redacted",
  "rawMessage": "terse machine-oriented description of what matched"
}

# Triage Output Schema (output of src/triage/*, consumed by src/report/render.js)

{
  "summary": { "critical": "number", "high": "number", "medium": "number", "low": "number" },
  "findings": [
    {
      "title": "plain English one-liner, no jargon",
      "severity": "critical" | "high" | "medium" | "low",
      "explanation": "what's wrong, written for a reader with no security background",
      "attackerImpact": "concretely what an attacker does with this and what it costs the builder",
      "file": "path",
      "line": "number or null",
      "fix": { "description": "string", "diff": "unified diff string, or null if not auto-fixable" },
      "sourceCheckIds": ["array of raw checkIds this finding consolidates"]
    }
  ]
}

Both schemas are contracts. Every module that produces or consumes these must match them exactly so the pipeline composes without glue-code guessing.
