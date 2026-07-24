'use strict';
// Evasion for check 7 (missing-auth-middleware). This file deliberately lives at a path
// that does NOT contain "admin"/"internal"/"debug" (so SENSITIVE_FILE_PATH_RE's
// any-route-call fallback for admin-directory files never engages) and demonstrates two
// separate bypasses of the remaining literal-path heuristic:

const express = require('express');
const router = express.Router();

// --- Technique A: build the sensitive path via concatenation, not a single literal ---
// SENSITIVE_ROUTE_INLINE_RE requires the route call's FIRST argument to be a single
// quoted string literal starting with /admin, /internal, /_debug, or /internal-api.
// Splitting the literal so the call site sees `ADMIN_BASE + '/delete-user'` (a binary
// expression, not a bare string literal) means the regex never matches this call at
// all -- it is completely invisible to check 7, not merely suppressed by a nearby
// keyword.
const ADMIN_BASE = '/adm' + 'in'; // never appears as a single literal "/admin..." anywhere

router.post(ADMIN_BASE + '/delete-user', (req, res) => {
  deleteUserById(req.body.userId); // no auth/session/token check anywhere nearby
  res.sendStatus(204);
});

// --- Technique B: a decoy "auth-sounding" import that never actually enforces anything ---
// AUTH_KEYWORD_RE only checks whether one of a handful of auth-ish WORDS appears within
// roughly +/-100/2000 chars of the route call -- it never confirms that word is wired
// into actual enforcement (a middleware argument, an early return/401, etc). Here the
// literal path DOES match SENSITIVE_ROUTE_INLINE_RE (starts with /internal), so the
// check does look at it -- but the merely-decorative `auth-logger` import sitting next
// to it satisfies the keyword heuristic and suppresses the finding even though the
// handler performs zero authentication or authorization.
const { record } = require('./auth-logger'); // only logs; never blocks the request

router.get('/internal/export-all-users', (req, res) => {
  record(req); // decoy: satisfies the "auth" keyword heuristic, enforces nothing
  res.json(exportAllUsers());
});

module.exports = router;
