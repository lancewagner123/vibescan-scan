'use strict';

// Internal ops dashboard for Billsy staff. Mounted at /admin in server.js. This file is
// the fixture's second deliberate CROSS-CHECK interaction: the /login route below sets
// the admin session cookie AND (like every route in this file) has no enforced auth check
// of its own -- realistic, since this whole file was thrown together for an internal tool
// and nobody added session-guard middleware before wiring up routes.

const express = require('express');
const router = express.Router();

const ADMIN_ACCOUNTS = [
  { id: 1, username: 'ops-admin', passwordHash: 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4' },
];

// VULNERABLE (check 7: missing-auth-middleware) -- the actual admin data endpoint. Anyone
// who can reach this server can call it directly and read live revenue/customer figures;
// nothing here checks a session, token, or role before returning them.
router.get('/dashboard', (req, res) => {
  res.json({ ok: true, totalCustomers: 128, mrrCents: 4820000 });
});

// VULNERABLE (check 7: missing-auth-middleware, same route) -- also has no enforced auth
// check itself, which is expected for a login endpoint (that's the chicken-and-egg point
// of a login route) -- but VibeScan's heuristic is path/file-based, not semantic, so it
// still (correctly, in the sense that this file genuinely has zero auth-guard middleware
// wired anywhere) flags every route here, login included.
//
// VULNERABLE (check 14: insecure-cookie-flags, same route) -- the admin session cookie
// this route sets has no options object at all: no httpOnly (stealable via any XSS
// elsewhere on the page), no secure (sent in the clear over plain HTTP), no SameSite.
router.post('/login', (req, res) => {
  const admin = ADMIN_ACCOUNTS.find((a) => a.username === req.body.username);
  if (!admin) {
    res.json({ ok: false, error: 'invalid credentials' });
    return;
  }
  const adminSessionId = admin.id + '-' + Date.now().toString(36);
  res.cookie('adminSessionId', adminSessionId);
  res.json({ ok: true });
});

module.exports = router;
