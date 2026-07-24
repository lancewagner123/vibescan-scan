'use strict';
// Regression sample for the missing-auth-middleware (check 7) gap A found in the
// 2026-07-24 follow-up audit: this is ordinary, non-adversarial Express code using the
// standard chainable Router syntax -- `router.route(path)` followed by a chained
// `.method(...)` call -- NOT an evasion attempt. Before the fix, SENSITIVE_ROUTE_INLINE_RE
// only matched a path literal and its HTTP-method call when both appeared in the SAME
// `.method(...)` invocation, so this idiomatic form produced zero findings even though
// there is no auth/session/token check anywhere near it.
//
// Expected: a missing-auth-middleware finding on the `.get(...)` call below.

const express = require('express');
const router = express.Router();

router.route('/admin/dashboard').get((req, res) => {
  res.json({ ok: true, message: 'admin dashboard', stats: computeStats() });
});

module.exports = router;
