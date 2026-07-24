'use strict';

// Signup / login / password-reset for Billsy. This file is the fixture's first deliberate
// CROSS-CHECK interaction: the /signup handler below seeds a weak-password-hashing finding
// (check 12) and a mass-assignment finding (check 13) in the very same function, the way a
// rushed real-world signup endpoint plausibly would -- one author focused on "hash the
// password" and never noticed the ORM call two lines later takes the whole request body.

const crypto = require('crypto');
const express = require('express');
const router = express.Router();

// Fake ORM-style User model, just enough shape (`.create`) to look like a real
// Sequelize/Mongoose model without this fixture needing a real ORM dependency installed.
const User = {
  create(data) {
    return Promise.resolve({ id: Date.now(), ...data });
  },
};

// In-memory password-reset token store, standing in for a real `password_resets` table.
const resetTokens = new Map();

// VULNERABLE (check 12: weak-password-hashing + check 13: mass-assignment, SAME HANDLER) --
//   - the password is hashed with SHA-1 (fast, unsalted -- fine for a checksum, catastrophic
//     for password storage) instead of bcrypt/scrypt/argon2.
//   - immediately after, req.body is passed to User.create() in its entirety, with no
//     destructuring/allowlist -- an attacker can set fields the signup form never exposed
//     (e.g. { "email": "x@example.com", "password": "hunter2", "isAdmin": true,
//     "planTier": "enterprise" }), independent of the hashing bug above.
router.post('/signup', async (req, res) => {
  const passwordHash = crypto.createHash('sha1').update(req.body.password || '').digest('hex');
  const newUser = await User.create(req.body);
  newUser.passwordHash = passwordHash;
  res.status(201).json({ id: newUser.id, email: newUser.email });
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  const passwordHash = crypto.createHash('sha1').update(password || '').digest('hex');
  // (fake lookup -- real app would query the users table here)
  if (!email || !passwordHash) {
    res.status(401).json({ error: 'invalid credentials' });
    return;
  }
  res.json({ ok: true });
});

// VULNERABLE (check 11: insecure-random-token) -- the password-reset token is built from
// Math.random(), which is not cryptographically secure. An attacker who can observe or
// guess enough issued tokens can predict a future one and take over another user's
// account via the reset flow -- one of the highest-impact places this bug can land.
router.post('/reset-password', (req, res) => {
  const email = req.body.email;
  const resetToken = Math.random().toString(36).slice(2);
  resetTokens.set(email, resetToken);
  res.json({ ok: true });
});

// VULNERABLE (check 15: open-redirect) -- after finishing a login/reset flow, Billsy sends
// the user on to wherever they were headed via a `next` query param, with no allowlist or
// same-origin check. An attacker can send a victim a Billsy link like
// /auth/continue?next=https://evil.example.com/phishing that looks trustworthy (real
// billsy.example.com domain) but silently forwards them off-site.
router.get('/continue', (req, res) => {
  const next = req.query.next;
  res.redirect(next);
});

module.exports = router;
