'use strict';
// Regression sample for the missing-auth-middleware (check 7) gap found in the
// false-positive sweep audit (2026-07-24): AUTH_KEYWORD_AS_ARG_RE kept AUTH_KEYWORD_RE's
// leading `\b` word-boundary anchor, so a camelCase middleware name like `requireAuth` or
// `checkAuth` -- where "Auth" starts mid-identifier rather than at a word boundary -- was
// invisible to the inline-argument, concat-path, and chained-route auth-argument checks.
// This is ordinary, non-adversarial Express code using the single most idiomatic
// middleware-naming style in real codebases -- NOT an evasion attempt.
//
// Expected: ZERO missing-auth-middleware findings for any route below (all three are
// protected by real middleware passed inline; only the naming style differs from
// vocabulary-initial names like `authMiddleware`/`isAuthenticated`).

const express = require('express');
const router = express.Router();
const { requireAuth } = require('./mw');

const ADMIN_BASE = '/adm' + 'in';

// Case A: inline middleware argument, camelCase name starting mid-identifier.
router.get('/admin/dashboard', requireAuth, (req, res) => {
  res.json({ ok: true, message: 'admin dashboard', stats: computeStats() });
});

// Case C: concatenated route path, same camelCase middleware name.
router.post(ADMIN_BASE + '/delete-user', requireAuth, (req, res) => {
  deleteUserById(req.body.userId);
  res.sendStatus(204);
});

// Case D: chained router.route(path).method(...) syntax, same camelCase middleware name.
router
  .route('/admin/users')
  .get(requireAuth, (req, res) => {
    res.json({ ok: true, users: listUsers() });
  })
  .post(requireAuth, (req, res) => {
    createUser(req.body);
    res.sendStatus(201);
  });

module.exports = router;
