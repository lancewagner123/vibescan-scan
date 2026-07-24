'use strict';
// FALSE POSITIVE for check 15 (open-redirect).
//
// Post-login redirect, validated via the URL constructor + origin comparison -- a
// standard, robust open-redirect guard: resolve the candidate against the site's
// own origin (using it as the base so relative paths resolve safely) and reject
// anything that resolves to a different origin. This is a well-known best-practice
// pattern, but hasNearbyRedirectValidation() only recognizes `.startsWith(`,
// `allowlist/whitelist....includes(`, and `var.includes(`) shapes in the ~400 chars
// before the res.redirect() call -- a `new URL(...)` + `.origin !==` guard isn't in
// that list, so this legitimately-validated redirect is flagged as unguarded.
const express = require('express');
const router = express.Router();

router.get('/post-login-redirect', (req, res) => {
  const target = req.query.next;
  let resolved;
  try {
    resolved = new URL(target, `https://${req.headers.host}`);
  } catch {
    return res.redirect('/dashboard');
  }
  if (resolved.origin !== `https://${req.headers.host}`) {
    return res.redirect('/dashboard');
  }
  res.redirect(target);
});

module.exports = router;
