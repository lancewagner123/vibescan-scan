'use strict';
// Regression sample for the missing-auth-middleware (check 7) gap B found in the
// 2026-07-24 follow-up audit: this is ordinary, non-adversarial Express code using the
// extremely common "guard the whole router once" idiom -- NOT an evasion attempt. Before
// the fix, each `.get`/`.post` call was inspected in total isolation, with no awareness of
// a preceding `router.use(<authMiddleware>)` call that protects every route registered
// after it, so both admin routes below were incorrectly flagged as missing auth even
// though they are, in fact, protected.
//
// Expected: ZERO missing-auth-middleware findings for either route below.

const express = require('express');
const router = express.Router();

// Real auth middleware, wired once for the whole router -- every route registered below
// this line is protected by it.
router.use(requireAuth);

router.get('/admin/dashboard', (req, res) => {
  res.json({ ok: true, message: 'admin dashboard', stats: computeStats() });
});

router.post('/admin/delete-user', (req, res) => {
  deleteUserById(req.body.userId);
  res.sendStatus(204);
});

module.exports = router;
