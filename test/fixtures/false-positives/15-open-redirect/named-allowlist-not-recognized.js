'use strict';
// FALSE POSITIVE for check 15 (open-redirect).
//
// Post-checkout redirect, validated against an explicit allowlist of internal
// paths -- properly guarded, just named "internalPaths" rather than
// "allowlist"/"allowedX"/"whitelist". hasNearbyRedirectValidation()'s array.includes
// (var) pattern only fires when the array identifier itself starts with
// allow(list|ed)/whitelist, so this equally-safe allowlist check (same shape, just
// a different, equally reasonable variable name) is not recognized and the redirect
// is flagged as unguarded.
const express = require('express');
const router = express.Router();

const internalPaths = ['/checkout/success', '/checkout/cancelled', '/dashboard'];

router.get('/post-checkout-redirect', (req, res) => {
  const target = req.query.next;
  if (!internalPaths.includes(target)) {
    return res.redirect('/dashboard');
  }
  res.redirect(target);
});

module.exports = router;
